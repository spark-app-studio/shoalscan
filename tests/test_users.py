"""Who may use the dashboard: the access rules, the command line, the setup wizard, and real sign-ins."""

import contextlib
import io
import json
import os
import ssl
import stat
import tempfile
import threading
import time
import types
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from unittest import mock

import helpers  # noqa: F401 - puts src/ on the import path
from fake_idp import FakeIdP, dashboard, sign_in
from history_fixtures import sample_history

from shoalscan import history
from shoalscan.cli import main
from shoalscan.dashboard import auth, oidc, server, tlsgen, users
from shoalscan.errors import SetupError


def claims(email="alice@example.com", sub="s-alice", verified=True):
    return {"email": email, "sub": sub, "email_verified": verified}


class RuleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state = Path(self.tmp.name) / "state"
        self.conn = users.open_users(self.state)

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def refused(self, code, *args):
        with self.assertRaises(users.SignInRefusedError) as ctx:
            users.sign_in(self.conn, *args)
        self.assertEqual(ctx.exception.code, code)

    def test_the_database_is_private_and_current(self):
        self.assertEqual(stat.S_IMODE(os.stat(self.state / users.USERS_FILE).st_mode), 0o600)
        self.assertEqual(self.conn.execute("PRAGMA user_version").fetchone()[0], users.SCHEMA_VERSION)

    def test_admins_come_from_the_claim_and_others_must_be_allowed(self):
        admin = users.sign_in(self.conn, claims("Alice@Example.com"), admin=True)
        self.assertEqual((admin.email, admin.role), ("alice@example.com", "admin"))
        self.refused("not_allowed", claims("bob@example.com", "s-bob"), False)
        users.allow(self.conn, "bob@example.com", "alice@example.com")
        self.assertEqual(users.sign_in(self.conn, claims("bob@example.com", "s-bob"), False).role, "member")
        # The provider decides admin at every sign-in: without the claim, an unallowed former admin is refused.
        self.refused("not_allowed", claims(), False)

    def test_email_must_be_verified_and_stays_with_its_account(self):
        users.allow(self.conn, "bob@example.com", "alice@example.com")
        self.refused("unverified", claims("bob@example.com", verified=False), False)
        self.refused("no_email", {"sub": "x", "email_verified": True}, False)
        users.sign_in(self.conn, claims("bob@example.com", "s-bob"), False)
        self.refused("other_account", claims("bob@example.com", "s-someone-else"), False)

    def test_disabling_and_taking_back_access(self):
        users.allow(self.conn, "bob@example.com", "alice@example.com")
        bob = users.sign_in(self.conn, claims("bob@example.com", "s-bob"), False)
        self.assertTrue(users.current(self.conn, bob.email, bob.role, bob.version))
        users.set_disabled(self.conn, "bob@example.com", True, "alice@example.com")
        self.assertFalse(users.current(self.conn, bob.email, bob.role, bob.version))
        self.refused("disabled", claims("bob@example.com", "s-bob"), True)  # even an admin claim
        users.set_disabled(self.conn, "bob@example.com", False, "alice@example.com")
        bob = users.sign_in(self.conn, claims("bob@example.com", "s-bob"), False)
        users.disallow(self.conn, "bob@example.com", "alice@example.com")
        self.assertFalse(users.current(self.conn, bob.email, bob.role, bob.version))
        with self.assertRaises(SetupError):
            users.set_disabled(self.conn, "alice@example.com", True, "alice@example.com")
        with self.assertRaises(SetupError):
            users.allow(self.conn, "not an email", "alice@example.com")

    def test_only_ascii_email_addresses(self):
        # U+212A (the Kelvin sign) folds to "k": such addresses are refused rather than folded onto another.
        for bad in ("\u212aelvin@example.com", "kelvin@ex\u00e4mple.com", "j\u00fcrgen@example.com"):
            with self.subTest(bad=bad):
                with self.assertRaisesRegex(SetupError, "ASCII"):
                    users.normalise_email(bad)
                with self.assertRaises(SetupError):
                    users.allow(self.conn, bad, "alice@example.com")
                self.refused("no_email", claims(bad, "s-k"), True)
        self.assertEqual(users.normalise_email(" Kelvin@Example.com "), "kelvin@example.com")
        self.assertFalse(hasattr(users, "has_admin"))

    def test_changes_are_recorded(self):
        users.sign_in(self.conn, claims(), True)
        users.allow(self.conn, "bob@example.com", "alice@example.com")
        users.set_disabled(self.conn, "bob@example.com", True, "alice@example.com")
        self.assertEqual(
            [(e["who"], e["user"], e["action"]) for e in users.events(self.conn)],
            [
                ("alice@example.com", "bob@example.com", "disable"),
                ("alice@example.com", "bob@example.com", "allow"),
                ("alice@example.com", "alice@example.com", "first-login"),
            ],
        )


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.sessions = auth.Sessions(lambda session: True)

    def age(self, sid, seconds):
        session = self.sessions._items[auth.sha256_hex(sid)]
        session.created -= seconds

    def test_admin_sessions_are_short(self):
        admin = self.sessions.create("root@example.com", "admin", 0)
        member = self.sessions.create("bob@example.com", "member", 0)
        self.assertEqual(auth.ADMIN_SESSION_MAX_SECONDS, 3600)
        self.age(admin, auth.ADMIN_SESSION_MAX_SECONDS + 1)
        self.age(member, auth.ADMIN_SESSION_MAX_SECONDS + 1)
        self.assertIsNone(self.sessions.get(admin))  # the admin signs in again, which reads the claim again
        self.assertIsNotNone(self.sessions.get(member))
        self.age(member, auth.SESSION_MAX_SECONDS)
        self.assertIsNone(self.sessions.get(member))
        self.assertIn(f"Max-Age={auth.ADMIN_SESSION_MAX_SECONDS};", auth.session_cookie("x", "admin") + ";")
        self.assertIn(f"Max-Age={auth.SESSION_MAX_SECONDS};", auth.session_cookie("x", "member") + ";")

    def test_one_person_cannot_crowd_out_others(self):
        others = [self.sessions.create(f"p{i}@example.com", "member", 0) for i in range(auth.MAX_SESSIONS - 10)]
        mine = [self.sessions.create("greedy@example.com", "member", 0) for _ in range(auth.MAX_SESSIONS * 2)]
        self.assertTrue(all(self.sessions.get(sid) for sid in others))
        live = [sid for sid in mine if self.sessions.get(sid)]
        self.assertEqual(live, mine[-auth.MAX_SESSIONS_PER_USER :])  # the person's own oldest go first
        # With the dashboard full, a person within their cap still gets in, at the cost of the least recent session.
        self.assertEqual(len(self.sessions._items), auth.MAX_SESSIONS)
        self.sessions.get(others[0])
        self.sessions.create("new@example.com", "member", 0)
        self.assertEqual(len(self.sessions._items), auth.MAX_SESSIONS)
        self.assertIsNotNone(self.sessions.get(others[0]))

    def test_expired_sessions_make_room_first(self):
        old = [self.sessions.create(f"p{i}@example.com", "member", 0) for i in range(auth.MAX_SESSIONS)]
        keep = old[0]
        for sid in old[1:]:
            self.age(sid, auth.SESSION_MAX_SECONDS + 1)
        self.sessions.create("new@example.com", "member", 0)
        self.assertIsNotNone(self.sessions.get(keep))
        self.assertEqual(len(self.sessions._items), 2)


class StartLimitTests(unittest.TestCase):
    def test_addresses_do_not_affect_each_other(self):
        # The reviewer's case: 25 IPv6 addresses each start 20 sign-ins; nobody else is held off.
        bucket = auth.TokenBucket(server.LOGIN_START_BURST, server.LOGIN_START_REFILL_SECONDS)
        now = 1000.0
        self.assertTrue(bucket.take("2001:db8::ffff", now))
        for i in range(25):
            for _ in range(20):
                self.assertTrue(bucket.take(f"2001:db8::{i:x}", now))
        self.assertTrue(bucket.take("2001:db8::ffff", now))
        self.assertTrue(bucket.take("192.0.2.1", now))
        for _ in range(server.LOGIN_START_BURST * 4):
            bucket.take("198.51.100.9", now)
        self.assertFalse(bucket.take("198.51.100.9", now))
        self.assertTrue(bucket.take("192.0.2.2", now))

    def test_a_shared_address_recovers_as_tokens_refill(self):
        bucket = auth.TokenBucket(server.LOGIN_START_BURST, server.LOGIN_START_REFILL_SECONDS)
        now = 1000.0
        for _ in range(server.LOGIN_START_BURST):  # a team behind one proxy signs in together
            self.assertTrue(bucket.take("10.0.0.1", now))
        self.assertFalse(bucket.take("10.0.0.1", now))
        self.assertFalse(bucket.take("10.0.0.1", now + server.LOGIN_START_REFILL_SECONDS / 2))
        self.assertTrue(bucket.take("10.0.0.1", now + server.LOGIN_START_REFILL_SECONDS))
        later = now + server.LOGIN_START_REFILL_SECONDS * server.LOGIN_START_BURST * 2
        self.assertTrue(all(bucket.take("10.0.0.1", later) for _ in range(server.LOGIN_START_BURST)))
        self.assertFalse(bucket.take("10.0.0.1", later))  # never more than the burst

    def test_the_buckets_are_bounded(self):
        bucket = auth.TokenBucket(2, 10.0, max_addresses=5)
        for i in range(50):
            bucket.take(f"a{i}", 1000.0)
        self.assertLessEqual(len(bucket._buckets), 5)
        bucket.take("busy", 1000.0)
        bucket.take("busy", 1000.0)
        self.assertFalse(bucket.take("busy", 1000.0))  # an emptied bucket is kept while full ones are dropped
        for i in range(10):
            bucket.take(f"b{i}", 1000.0 + 100 + i)
        self.assertLessEqual(len(bucket._buckets), 5)


class ProviderCacheTests(unittest.TestCase):
    def app(self, provider=None):
        return types.SimpleNamespace(
            oidc=object(),
            provider=provider,
            _provider_lock=threading.Lock(),
            _discovery_lock=threading.Lock(),
            _provider_failure=None,
        )

    def test_a_failed_discovery_is_remembered_briefly(self):
        app = self.app()
        calls = []

        def failing(config):
            calls.append(config)
            raise oidc.OidcError("not reachable")

        with mock.patch.object(oidc, "discover", failing):
            for _ in range(3):
                with self.assertRaisesRegex(oidc.OidcError, "not reachable"):
                    server.App.provider_now(app)
            self.assertEqual(len(calls), 1)
            app._provider_failure = (time.monotonic() - 1, "old")  # PROVIDER_RETRY_SECONDS later
            with self.assertRaises(oidc.OidcError):
                server.App.provider_now(app)
            self.assertEqual(len(calls), 2)
        good = oidc.Provider("https://idp.example", "a", "t", "k", fetched_at=time.monotonic())
        with mock.patch.object(oidc, "discover", lambda config: good):
            app._provider_failure = None
            self.assertIs(server.App.provider_now(app), good)
            self.assertIsNone(app._provider_failure)

    def test_a_slow_refresh_does_not_hold_up_sign_ins(self):
        stale = oidc.Provider("https://idp.example", "a", "t", "k", fetched_at=time.monotonic() - 7200)
        fresh = oidc.Provider("https://idp.example", "a", "t", "k", fetched_at=time.monotonic())
        app = self.app(stale)
        entered, release = threading.Event(), threading.Event()

        def slow(config):
            entered.set()
            release.wait(10)
            return fresh

        with mock.patch.object(oidc, "discover", slow):
            worker = threading.Thread(target=server.App.provider_now, args=(app,))
            worker.start()
            self.assertTrue(entered.wait(10))
            started = time.monotonic()
            self.assertIs(server.App.provider_now(app), stale)  # served at once, not after the refresh
            self.assertLess(time.monotonic() - started, 1)
            self.assertFalse(app._provider_lock.locked())
            release.set()
            worker.join(10)
        self.assertIs(app.provider, fresh)


class CommandTests(unittest.TestCase):
    def run_cli(self, state, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["serve", *args, "--state-dir", str(state)])
        return code, out.getvalue(), err.getvalue()

    def test_people_and_settings_from_the_command_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            self.assertEqual(self.run_cli(state, "user", "allow", "Bob@Example.com")[0], 0)
            self.assertIn("bob@example.com", self.run_cli(state, "user", "list")[1])
            self.assertEqual(self.run_cli(state, "user", "disable", "bob@example.com")[0], 0)
            self.assertEqual(self.run_cli(state, "user", "allow", "nope")[0], 2)
            self.assertIn("not set up", self.run_cli(state, "oidc", "show")[1])
            idp = FakeIdP()
            try:
                oidc.save(state, idp.config())
                code, out, _ = self.run_cli(state, "oidc", "show", "--test")
            finally:
                idp.close()
            self.assertEqual(code, 0)
            self.assertIn("accepted the client", out)
            self.assertNotIn(FakeIdP.CLIENT_SECRET, out)
            self.assertEqual(self.run_cli(state, "oidc", "reset")[0], 0)
            self.assertFalse((state / oidc.CONFIG_FILE).exists())
            code, _, err = self.run_cli(state, "token")
            self.assertEqual(code, 2)
            self.assertIn("OpenID Connect", err)


class ServerCase(unittest.TestCase):
    """A real dashboard over TLS and a fake provider."""

    configured = True

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls._log = server.Handler._log
        server.Handler._log = lambda self, status: None
        base = Path(cls._tmp.name)
        cls.tls = tlsgen.generate(base / "tls", ["127.0.0.1"], [])
        conn = history.open_for_write(base / "history.sqlite3")
        sample_history(conn, base)
        conn.close()
        cls.idp = FakeIdP()
        cls.state = base / "state"
        cls.state.mkdir()
        if cls.configured:
            oidc.save(cls.state, cls.idp.config())
        config = server.ServeConfig(
            db=base / "history.sqlite3",
            cert=cls.tls["cert"],
            key=cls.tls["key"],
            auth_dir=cls.state,
            bind="127.0.0.1",
            port=0,
            hosts=("127.0.0.1",),
        )
        cls.httpd = server.build_server(config)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
        cls.thread.start()
        cls.ctx = ssl.create_default_context(cafile=str(cls.tls["ca"]))
        cls.origin = f"https://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=10)
        cls.idp.close()
        cls._tmp.cleanup()
        server.Handler._log = cls._log

    def setUp(self):
        self.httpd.app.limiter = auth.LoginLimiter()
        self.httpd.app.start_limiter = auth.TokenBucket(server.LOGIN_START_BURST, server.LOGIN_START_REFILL_SECONDS)
        self.idp.misbehave = None

    def request(self, method, path, body=None, headers=None, cookie=None):
        all_headers = dict(headers or {})
        if cookie:
            all_headers["Cookie"] = f"{auth.COOKIE_NAME}={cookie}"
        if body is not None:
            all_headers.setdefault("Content-Type", "application/json")
            all_headers.setdefault("Origin", self.origin)
        import http.client

        conn = http.client.HTTPSConnection("127.0.0.1", self.port, context=self.ctx, timeout=10)
        try:
            conn.request(method, path, body=body, headers=all_headers)
            res = conn.getresponse()
            raw = res.read()
            return res.status, dict(res.getheaders()), raw
        finally:
            conn.close()

    def get(self, path, cookie):
        status, _, raw = self.request("GET", path, cookie=cookie)
        return status, json.loads(raw) if raw else None

    def post(self, path, payload, cookie):
        csrf = self.get("/api/session", cookie)[1]["csrf"]
        status, _, raw = self.request("POST", path, json.dumps(payload), {"X-CSRF-Token": csrf}, cookie)
        return status, json.loads(raw) if raw else None


class SetupWizardTests(ServerCase):
    configured = False

    def setUp(self):
        super().setUp()
        # Each test starts in setup mode, with a fresh code, as after a restart.
        (self.state / oidc.CONFIG_FILE).unlink(missing_ok=True)
        app = self.httpd.app
        app.oidc, app.provider, app.setup_code = None, None, "test-setup-code"
        app.setup_code_expires = time.monotonic() + server.SETUP_CODE_SECONDS

    def test_setup_mode_serves_only_the_wizard_and_needs_the_console_code(self):
        self.assertEqual(self.request("GET", "/")[1]["Location"], "/setup")
        self.assertEqual(self.request("GET", "/login")[1]["Location"], "/setup")
        self.assertEqual(self.request("GET", "/api/repos")[0], 503)
        status, _, page = self.request("GET", "/setup")
        self.assertEqual(status, 200)
        self.assertIn(b"setup.js", page)
        settings = {"issuer": self.idp.issuer, "client_id": FakeIdP.CLIENT_ID, "client_secret": FakeIdP.CLIENT_SECRET}
        status, _, raw = self.request("POST", "/setup/test", json.dumps({**settings, "setup_code": "guess"}))
        self.assertEqual(status, 403)
        code = self.httpd.app.setup_code
        status, _, raw = self.request(
            "POST", "/setup/test", json.dumps({**settings, "client_secret": "the-wrong-secret", "setup_code": code})
        )
        self.assertEqual((status, json.loads(raw)["ok"]), (400, False))
        self.assertIn("invalid_client", json.loads(raw)["error"])
        status, _, raw = self.request("POST", "/setup/test", json.dumps({**settings, "setup_code": code}))
        result = json.loads(raw)
        self.assertEqual((status, result["ok"]), (200, True), raw)
        self.assertEqual(result["redirect_uri"], f"https://127.0.0.1:{self.port}/oidc/callback")
        self.assertTrue(any("accepted the client" in c for c in result["checks"]))
        self.assertFalse((self.state / oidc.CONFIG_FILE).exists())  # testing saves nothing
        status, _, raw = self.request("POST", "/setup/save", json.dumps({**settings, "setup_code": code}))
        self.assertEqual((status, json.loads(raw)["redirect"]), (200, "/login"))
        self.assertEqual(oidc.load(self.state).redirect_uri, f"https://127.0.0.1:{self.port}/oidc/callback")
        # Set up: the wizard is gone, sign-in works.
        self.assertEqual(self.request("GET", "/setup")[1]["Location"], "/login")
        self.assertEqual(self.request("POST", "/setup/save", json.dumps({**settings, "setup_code": code}))[0], 404)
        cookie, _ = sign_in(self.port, self.ctx, self.idp, groups=["shoal-admin"])
        self.assertIsNotNone(cookie)

    def test_the_ca_comes_as_a_certificate_never_a_path(self):
        code = self.httpd.app.setup_code
        settings = {
            "issuer": self.idp.issuer,
            "client_id": FakeIdP.CLIENT_ID,
            "client_secret": FakeIdP.CLIENT_SECRET,
            "setup_code": code,
        }
        status, _, raw = self.request("POST", "/setup/test", json.dumps({**settings, "ca_file": "/etc/passwd"}))
        self.assertEqual(status, 400)
        self.assertIn("not a path", json.loads(raw)["error"])
        for bad in ("not a certificate", "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----", "x" * 70000):
            status, _, raw = self.request("POST", "/setup/test", json.dumps({**settings, "ca_pem": bad}))
            self.assertIn(status, (400, 413), bad[:20])  # refused, whether by its content or its size
        pem = Path(self.tls["ca"]).read_text()
        status, _, raw = self.request("POST", "/setup/save", json.dumps({**settings, "ca_pem": pem}))
        self.assertEqual(status, 200, raw)
        saved = self.state / oidc.CA_FILE
        self.assertEqual(oidc.load(self.state).ca_file, str(saved))
        self.assertEqual(saved.read_text().strip(), pem.strip())
        self.assertEqual(stat.S_IMODE(os.stat(saved).st_mode), 0o600)

    def test_wrong_setup_codes_are_rate_limited(self):
        for _ in range(5):
            self.assertEqual(self.request("POST", "/setup/test", json.dumps({"setup_code": "nope"}))[0], 403)
        self.assertEqual(
            self.request("POST", "/setup/test", json.dumps({"setup_code": self.httpd.app.setup_code or "x"}))[0], 429
        )

    def test_a_setup_code_outside_ascii_is_a_counted_failure(self):
        for _ in range(5):
            status, _, raw = self.request("POST", "/setup/test", json.dumps({"setup_code": "c\u00f6de-\u212a"}))
            self.assertEqual(status, 403, raw)
        self.assertEqual(
            self.request("POST", "/setup/test", json.dumps({"setup_code": self.httpd.app.setup_code}))[0], 429
        )

    def test_the_setup_code_is_in_a_private_file_and_expires(self):
        app = self.httpd.app
        app.new_setup_code()
        path = self.state / server.SETUP_CODE_FILE
        self.assertEqual(path.read_text().strip(), app.setup_code)
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        code = app.setup_code
        app.setup_code_expires = time.monotonic() - 1
        status, _, raw = self.request("POST", "/setup/test", json.dumps({"setup_code": code}))
        self.assertEqual(status, 403)
        self.assertIn("expired", json.loads(raw)["error"])
        self.assertFalse(path.exists())
        self.assertIsNone(app.setup_code)

    def test_an_expired_setup_code_file_is_deleted_without_a_post(self):
        app = self.httpd.app
        path = self.state / server.SETUP_CODE_FILE
        app.new_setup_code()
        app.setup_code_expires = time.monotonic() - 1
        self.assertEqual(self.request("GET", "/setup")[0], 200)  # reading the wizard page deletes it
        self.assertFalse(path.exists())
        self.assertIsNone(app.setup_code)
        app.new_setup_code()
        self.httpd.service_actions()  # the server's poll loop
        self.assertTrue(path.exists())  # not expired yet
        app.setup_code_expires = time.monotonic() - 1
        self.httpd.service_actions()
        self.assertFalse(path.exists())
        self.assertIsNone(app.setup_code)

    def test_the_console_names_the_file_not_the_code(self):
        path = self.state / server.SETUP_CODE_FILE

        def stop():
            raise KeyboardInterrupt

        fake = types.SimpleNamespace(
            server_address=("127.0.0.1", 8443),
            app=types.SimpleNamespace(setup_code="the-secret-setup-code", setup_code_path=path),
            serve_forever=lambda poll_interval: stop(),
            server_close=lambda: None,
        )
        out = io.StringIO()
        config = types.SimpleNamespace(hosts=("127.0.0.1",), bind="127.0.0.1")
        with mock.patch.object(server, "build_server", lambda config: fake), contextlib.redirect_stdout(out):
            server.serve(config)
        self.assertIn(str(path), out.getvalue())
        self.assertIn("30 minutes", out.getvalue())
        self.assertNotIn("the-secret-setup-code", out.getvalue())


class SignInTests(ServerCase):
    def test_an_admin_signs_in_with_a_strict_session_cookie(self):
        status, headers, _ = self.request("GET", "/oidc/start")
        self.assertEqual(status, 303)
        self.assertTrue(headers["Location"].startswith(f"{self.idp.issuer}/auth?"))
        self.assertIn("SameSite=Lax", headers["Set-Cookie"])
        cookie, where = sign_in(self.port, self.ctx, self.idp, "root@example.com", groups=["shoal-admin"])
        self.assertIsNotNone(cookie, where)
        session = self.get("/api/session", cookie)[1]
        self.assertEqual((session["user"], session["role"]), ("root@example.com", "admin"))
        status, headers, _ = dashboard(self.port, self.ctx, "GET", "/oidc/start")
        cookie_line = [v for k, v in headers if k.lower() == "set-cookie"][0]
        for part in ("Secure", "HttpOnly", "Path=/", f"Max-Age={oidc.LOGIN_SECONDS}"):
            self.assertIn(part, cookie_line)

    def test_people_who_were_not_let_in_are_refused(self):
        cookie, where = sign_in(self.port, self.ctx, self.idp, "stranger@example.com")
        self.assertEqual((cookie, where), (None, "/login?error=not_allowed"))
        cookie, where = sign_in(
            self.port, self.ctx, self.idp, "unverified@example.com", groups=["shoal-admin"], verified=False
        )
        self.assertEqual(where, "/login?error=unverified")

    def test_an_admin_lets_a_member_in_and_out(self):
        admin, _ = sign_in(self.port, self.ctx, self.idp, "root2@example.com", groups=["shoal-admin"])
        self.assertEqual(self.post("/api/users/allow", {"email": "Member@Example.com"}, admin)[0], 200)
        member, _ = sign_in(self.port, self.ctx, self.idp, "member@example.com")
        self.assertEqual(self.get("/api/session", member)[1]["role"], "member")
        self.assertEqual(self.get("/api/repos", member)[0], 200)
        for path in ("/api/users", "/api/config", "/api/scan/status"):
            self.assertEqual(self.get(path, member)[0], 403, path)
        self.assertEqual(self.post("/api/users/allow", {"email": "x@example.com"}, member)[0], 403)
        listing = self.get("/api/users", admin)[1]
        self.assertEqual(listing["provider"]["admin_value"], "shoal-admin")
        self.assertIn("member@example.com", [u["email"] for u in listing["users"]])
        self.assertEqual(
            self.post("/api/users/change", {"email": "member@example.com", "action": "disable"}, admin)[0], 200
        )
        self.assertEqual(self.get("/api/repos", member)[0], 401)  # the session ends at once
        self.assertEqual(sign_in(self.port, self.ctx, self.idp, "member@example.com")[1], "/login?error=disabled")
        self.assertEqual(
            self.post("/api/users/change", {"email": "root2@example.com", "action": "disable"}, admin)[0], 400
        )

    def test_forged_and_replayed_logins_fail(self):
        for bad in (
            "bad_signature",
            "alg_none",
            "wrong_audience",
            "expired",
            "wrong_nonce",
            "wrong_issuer",
            "unknown_key",
        ):
            self.idp.misbehave = bad
            with self.subTest(bad=bad):
                cookie, where = sign_in(self.port, self.ctx, self.idp, "root3@example.com", groups=["shoal-admin"])
                self.assertEqual((cookie, where), (None, "/login?error=provider"))
            self.httpd.app.limiter = auth.LoginLimiter()
        self.idp.misbehave = None
        # A callback without the browser's login cookie, or with another one, is refused.
        status, headers, _ = self.request("GET", "/oidc/start")
        state = headers["Location"].split("state=")[1].split("&")[0]
        status, headers, _ = self.request("GET", f"/oidc/callback?code=x&state={state}")
        self.assertEqual(headers["Location"], "/login?error=state")
        status, headers, _ = self.request(
            "GET", f"/oidc/callback?code=x&state={state}", headers={"Cookie": "__Host-shoalscan-login=other"}
        )
        self.assertEqual(headers["Location"], "/login?error=state")

    def test_an_admin_session_cookie_is_short(self):
        headers = []
        cookie, _ = sign_in(
            self.port, self.ctx, self.idp, "root4@example.com", groups=["shoal-admin"], headers_out=headers
        )
        line = [v for k, v in headers if k.lower() == "set-cookie" and v.startswith(auth.COOKIE_NAME + "=")][0]
        self.assertIn(f"Max-Age={auth.ADMIN_SESSION_MAX_SECONDS}", line)
        self.assertEqual(self.get("/api/session", cookie)[0], 200)
        self.httpd.app.sessions._items[auth.sha256_hex(cookie)].created -= auth.ADMIN_SESSION_MAX_SECONDS + 1
        self.assertEqual(self.get("/api/session", cookie)[0], 401)

    def test_a_replayed_callback_fails(self):
        self.idp.user = {
            "sub": "sub-r",
            "email": "root5@example.com",
            "email_verified": True,
            "groups": ["shoal-admin"],
        }
        status, headers, _ = dashboard(self.port, self.ctx, "GET", "/oidc/start")
        found = dict(headers)
        login_cookie = found["Set-Cookie"].split(";")[0]

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None

        opener = urllib.request.build_opener(NoRedirect, urllib.request.ProxyHandler({}))
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            opener.open(found["Location"], timeout=10)
        with ctx.exception:
            back = urllib.parse.urlsplit(ctx.exception.headers["Location"])
        callback = f"{back.path}?{back.query}"
        status, headers, _ = dashboard(self.port, self.ctx, "GET", callback, {"Cookie": login_cookie})
        self.assertEqual(status, 200)
        cleared = [v for k, v in headers if k.lower() == "set-cookie" and v.startswith(server.LOGIN_COOKIE)]
        self.assertIn("Max-Age=0", cleared[0])
        status, headers, _ = dashboard(self.port, self.ctx, "GET", callback, {"Cookie": login_cookie})
        self.assertEqual(dict(headers)["Location"], "/login?error=state")

    def test_starting_sign_ins_is_rate_limited(self):
        for _ in range(server.LOGIN_START_BURST):
            self.assertTrue(self.request("GET", "/oidc/start")[1]["Location"].startswith(self.idp.issuer))
        self.assertEqual(self.request("GET", "/oidc/start")[1]["Location"], "/login?error=starts")
        # Callbacks are not starts: a sign-in already under way still finishes.
        self.httpd.app.start_limiter = auth.TokenBucket(1, 3600)
        cookie, _ = sign_in(self.port, self.ctx, self.idp, "root6@example.com", groups=["shoal-admin"])
        self.assertIsNotNone(cookie)
        self.assertEqual(self.request("GET", "/oidc/start")[1]["Location"], "/login?error=starts")

    def test_a_full_used_state_set_refuses_sign_ins(self):
        before = oidc.MAX_USED_STATES
        oidc.MAX_USED_STATES = 0
        try:
            cookie, where = sign_in(self.port, self.ctx, self.idp, "root7@example.com", groups=["shoal-admin"])
        finally:
            oidc.MAX_USED_STATES = before
        self.assertEqual((cookie, where), (None, "/login?error=busy"))

    def test_failed_callbacks_are_rate_limited(self):
        for _ in range(5):
            self.request("GET", "/oidc/callback?code=x&state=y")
        cookie, where = sign_in(self.port, self.ctx, self.idp, "root@example.com", groups=["shoal-admin"])
        self.assertEqual((cookie, where), (None, "/login?error=limit"))


if __name__ == "__main__":
    unittest.main()
