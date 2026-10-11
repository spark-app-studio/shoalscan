"""Named dashboard users: the store, the command line, and the server's sign-in, invites and roles."""

import contextlib
import http.client
import io
import json
import os
import re
import sqlite3
import ssl
import stat
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock
from urllib.parse import urlencode

import helpers  # noqa: F401 - puts src/ on the import path
from history_fixtures import sample_history

from shoalscan import history
from shoalscan.cli import main
from shoalscan.dashboard import auth, server, tlsgen, users
from shoalscan.errors import SetupError


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state = Path(self.tmp.name) / "state"
        self.conn = users.open_users(self.state)

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def join(self, name, role="admin"):
        code, _ = users.add_user(self.conn, name, role, "root (command line)")
        return users.redeem(self.conn, code)[1]

    def test_the_database_is_private(self):
        mode = stat.S_IMODE(os.stat(self.state / users.USERS_FILE).st_mode)
        self.assertEqual(mode, 0o600)
        self.assertEqual(self.conn.execute("PRAGMA user_version").fetchone()[0], users.SCHEMA_VERSION)

    def test_an_invite_works_once_and_stores_only_hashes(self):
        code, expires = users.add_user(self.conn, "alice", "admin", "root")
        self.assertRegex(expires, r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertIsNone(users.check(self.conn, "alice", "anything"))
        self.assertFalse(users.has_active_users(self.conn))
        name, token = users.redeem(self.conn, code)
        self.assertEqual(name, "alice")
        self.assertIsNone(users.redeem(self.conn, code))
        self.assertEqual(users.check(self.conn, "alice", token).role, "admin")
        self.assertTrue(users.has_active_users(self.conn))
        dump = "\n".join(self.conn.iterdump())
        self.assertNotIn(token, dump)
        self.assertNotIn(code, dump)

    def test_an_expired_invite_is_refused(self):
        code, _ = users.add_user(self.conn, "bob", "member", "root")
        self.conn.execute("UPDATE users SET invite_expires_at = '2000-01-01T00:00:00Z'")
        self.assertIsNone(users.redeem(self.conn, code))
        self.assertEqual(users.list_users(self.conn)[0]["status"], "invite expired")

    def test_wrong_names_and_tokens(self):
        token = self.join("alice")
        for name, guess in (("alice", token + "x"), ("alice", ""), ("bob", token), ("", token), ("alice", "x" * 500)):
            self.assertIsNone(users.check(self.conn, name, guess), (name, guess[:10]))

    def test_names_and_roles_are_checked(self):
        for bad in ("Alice", "a b", "", "-x", "x" * 65, "../x"):
            with self.subTest(bad=bad), self.assertRaises(SetupError):
                users.add_user(self.conn, bad, "member", "root")
        with self.assertRaises(SetupError):
            users.add_user(self.conn, "carol", "owner", "root")
        users.add_user(self.conn, "carol", "member", "root")
        with self.assertRaises(SetupError):
            users.add_user(self.conn, "carol", "member", "root")

    def test_reinvite_disable_and_role_end_or_change_a_session(self):
        self.join("alice")
        token = self.join("bob", "member")
        bob = users.check(self.conn, "bob", token)
        self.assertIsNotNone(users.current(self.conn, "bob", bob.credential_version))
        users.set_role(self.conn, "bob", "admin", "alice")
        self.assertEqual(users.current(self.conn, "bob", bob.credential_version).role, "admin")
        users.set_disabled(self.conn, "bob", True, "alice")
        self.assertIsNone(users.current(self.conn, "bob", bob.credential_version))
        self.assertIsNone(users.check(self.conn, "bob", token))
        users.set_disabled(self.conn, "bob", False, "alice")
        self.assertIsNotNone(users.check(self.conn, "bob", token))
        code, _ = users.reinvite(self.conn, "bob", "alice")
        self.assertIsNone(users.check(self.conn, "bob", token))
        self.assertNotEqual(users.redeem(self.conn, code)[1], token)

    def test_there_is_always_an_active_admin(self):
        self.join("alice")
        for change in (
            lambda: users.set_disabled(self.conn, "alice", True, "x"),
            lambda: users.set_role(self.conn, "alice", "member", "x"),
            lambda: users.reinvite(self.conn, "alice", "x"),
        ):
            with self.assertRaisesRegex(SetupError, "only active admin"):
                change()
        self.join("bob")
        users.set_role(self.conn, "alice", "member", "bob")
        self.assertEqual(self.conn.execute("SELECT role FROM users WHERE name = 'alice'").fetchone()[0], "member")

    def test_every_change_is_recorded(self):
        token = self.join("alice")
        users.add_user(self.conn, "bob", "member", "alice")
        users.set_disabled(self.conn, "bob", True, "alice")
        self.assertIsNotNone(token)
        self.assertEqual(
            [(e["who"], e["user"], e["action"]) for e in users.events(self.conn)],
            [
                ("alice", "bob", "disable"),
                ("alice", "bob", "invite"),
                ("alice", "alice", "join"),
                ("root (command line)", "alice", "invite"),
            ],
        )


class CommandTests(unittest.TestCase):
    def test_add_list_and_reset_from_the_command_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = str(Path(tmp) / "state")

            def run(*args):
                out, err = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    code = main(["serve", "user", *args, "--state-dir", state])
                return code, out.getvalue(), err.getvalue()

            code, out, _ = run("add", "alice", "--admin", "--url", "https://dash.example:8443")
            self.assertEqual(code, 0)
            self.assertRegex(out, r"https://dash\.example:8443/invite#[A-Za-z0-9_-]{40,}")
            self.assertIn("alice                    admin   invited until", run("list")[1])
            self.assertEqual(run("add", "bob", "--url", "http://dash.example")[0], 2)
            code, out, _ = run("reset", "alice")
            self.assertIn("https://<the dashboard's address>/invite#", out)
            self.assertEqual(run("role", "alice", "member")[0], 0)
            self.assertEqual(run("disable", "nobody")[0], 2)


class ServerTests(unittest.TestCase):
    """A real dashboard over TLS, with named users."""

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
        cls.state = base / "state"
        cls.shared = auth.create_token(cls.state / "token.sha256")
        config = server.ServeConfig(
            db=base / "history.sqlite3",
            cert=cls.tls["cert"],
            key=cls.tls["key"],
            token_hash=cls.state / "token.sha256",
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
        cls._tmp.cleanup()
        server.Handler._log = cls._log

    def setUp(self):
        # Every test starts with no users; the shared token signs in.
        (self.state / users.USERS_FILE).unlink(missing_ok=True)
        self.httpd.app.limiter = auth.LoginLimiter()

    def request(self, method, path, body=None, headers=None, cookie=None):
        conn = http.client.HTTPSConnection("127.0.0.1", self.port, context=self.ctx, timeout=10)
        try:
            all_headers = dict(headers or {})
            if cookie:
                all_headers["Cookie"] = f"{auth.COOKIE_NAME}={cookie}"
            conn.request(method, path, body=body, headers=all_headers)
            res = conn.getresponse()
            return res.status, dict(res.getheaders()), res.read()
        finally:
            conn.close()

    def login(self, name, token):
        body = urlencode({"name": name, "token": token})
        status, headers, _ = self.request(
            "POST", "/login", body, {"Content-Type": "application/x-www-form-urlencoded", "Origin": self.origin}
        )
        self.assertEqual(status, 303)
        match = re.match(rf"{auth.COOKIE_NAME}=([^;]+)", headers.get("Set-Cookie", ""))
        return match.group(1) if match else None

    def get(self, path, cookie):
        status, _, body = self.request("GET", path, cookie=cookie)
        return status, json.loads(body) if body else None

    def post(self, path, payload, cookie):
        csrf = self.get("/api/session", cookie)[1]["csrf"]
        headers = {"Content-Type": "application/json", "Origin": self.origin, "X-CSRF-Token": csrf}
        status, _, body = self.request("POST", path, json.dumps(payload), headers, cookie)
        return status, json.loads(body) if body else None

    def join(self, code):
        headers = {"Content-Type": "application/json", "Origin": self.origin}
        status, _, body = self.request("POST", "/invite", json.dumps({"invite": code}), headers)
        return status, json.loads(body)

    def add(self, name, role="admin"):
        conn = users.open_users(self.state)
        try:
            code, _ = users.add_user(conn, name, role, "root (command line)")
        finally:
            conn.close()
        return code

    def test_the_invite_page_is_public_and_gives_the_token_once(self):
        status, _, page = self.request("GET", "/invite")
        self.assertEqual(status, 200)
        self.assertIn(b"invite.js", page)
        code = self.add("alice")
        status, body = self.join(code)
        self.assertEqual((status, body["name"]), (200, "alice"))
        self.assertEqual(self.join(code)[0], 404)
        self.assertIsNotNone(self.login("alice", body["token"]))

    def test_the_shared_token_works_only_until_someone_joins(self):
        shared = self.login("", self.shared)
        self.assertIsNotNone(shared)
        self.assertEqual(self.get("/api/session", shared)[1]["role"], "admin")
        self.add("alice")  # invited, not joined: the shared token still works
        self.assertEqual(self.get("/api/repos", shared)[0], 200)
        token = self.join(self.add("bob", "member"))[1]["token"]
        self.assertEqual(self.get("/api/repos", shared)[0], 401)
        self.assertIsNone(self.login("", self.shared))
        self.assertIsNotNone(self.login("bob", token))

    def test_members_read_and_review_but_do_not_administer(self):
        admin = self.login("alice", self.join(self.add("alice"))[1]["token"])
        member = self.login("bob", self.join(self.add("bob", "member"))[1]["token"])
        self.assertEqual(self.get("/api/session", member)[1], {"csrf": mock.ANY, "user": "bob", "role": "member"})
        self.assertEqual(self.get("/api/repos", member)[0], 200)
        for path in ("/api/users", "/api/config", "/api/scan/status"):
            self.assertEqual(self.get(path, member)[0], 403, path)
        for path, payload in (
            ("/api/users/invite", {"name": "eve", "role": "admin"}),
            ("/api/scan", {"target": "x"}),
            ("/api/config/enable", {"name": "x", "enabled": False}),
        ):
            self.assertEqual(self.post(path, payload, member)[0], 403, path)
        status, body = self.post(
            "/api/review",
            {
                "repo": "acme/app",
                "finding_key": ["opengrep", "community.python.eval", "src/d.py", "dddd:0"],
                "status": "false_positive",
                "description": "Constant input only.",
            },
            member,
        )
        self.assertEqual(status, 200, body)
        conn = sqlite3.connect(self.httpd.app.config.db)
        try:
            self.assertEqual(conn.execute("SELECT updated_by FROM finding_reviews").fetchone()[0], "bob")
        finally:
            conn.close()
        self.assertEqual(self.get("/api/users", admin)[0], 200)

    def test_admins_invite_and_disable_and_sessions_follow(self):
        admin = self.login("alice", self.join(self.add("alice"))[1]["token"])
        status, body = self.post("/api/users/invite", {"name": "bob", "role": "member"}, admin)
        self.assertEqual(status, 200, body)
        self.assertRegex(body["invite_path"], r"^/invite#[A-Za-z0-9_-]{40,}$")
        token = self.join(body["invite_path"].split("#")[1])[1]["token"]
        bob = self.login("bob", token)
        self.assertEqual(
            self.post("/api/users/change", {"name": "bob", "action": "role", "role": "admin"}, admin)[0], 200
        )
        self.assertEqual(self.get("/api/users", bob)[0], 200)  # the new role holds at once
        self.assertEqual(self.post("/api/users/change", {"name": "bob", "action": "disable"}, admin)[0], 200)
        self.assertEqual(self.get("/api/repos", bob)[0], 401)
        self.assertIsNone(self.login("bob", token))
        self.assertEqual(self.post("/api/users/change", {"name": "alice", "action": "disable"}, admin)[0], 400)
        listing = self.get("/api/users", admin)[1]
        self.assertEqual({u["name"]: u["status"] for u in listing["users"]}, {"alice": "active", "bob": "disabled"})
        self.assertFalse(listing["shared_token"])
        self.assertEqual(listing["events"][0]["who"], "alice")

    def test_bad_invites_are_rate_limited(self):
        for _ in range(5):
            self.assertEqual(self.join("x" * 43)[0], 404)
        self.assertEqual(self.join(self.add("alice"))[0], 429)


if __name__ == "__main__":
    unittest.main()
