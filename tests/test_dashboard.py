"""The dashboard server, started on an ephemeral port with TLS made by `init-tls`."""

import http.client
import json
import os
import re
import socket
import ssl
import stat
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from urllib.parse import urlencode

import helpers  # noqa: F401
from history_fixtures import MALICIOUS, sample_history

from shoalscan import history
from shoalscan.dashboard import auth, server, tlsgen

OPENSSL = tlsgen.find_openssl()
STATIC = Path(server.STATIC_DIR)


@unittest.skipIf(OPENSSL is None, "the openssl command is not installed, so no test certificate can be made")
class DashboardServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls._log = server.Handler._log
        server.Handler._log = lambda self, status: None  # keep the test output readable
        base = Path(cls._tmp.name)
        cls.tls = tlsgen.generate(base / "tls", ["127.0.0.1"], [])
        conn = history.open_for_write(base / "history.sqlite3")
        sample_history(conn, base)
        conn.close()
        cls.token_path = base / "state" / "token.sha256"
        cls.token = auth.create_token(cls.token_path)
        config = server.ServeConfig(
            db=base / "history.sqlite3",
            cert=cls.tls["cert"],
            key=cls.tls["key"],
            token_hash=cls.token_path,
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

    # ------------------------------------------------------------ helpers

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

    def login(self, token=None, origin=None):
        body = urlencode({"token": self.token if token is None else token})
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if origin is not False:
            headers["Origin"] = origin or self.origin
        return self.request("POST", "/login", body, headers)

    def session(self):
        status, headers, _ = self.login()
        self.assertEqual(status, 303)
        return re.match(rf"{auth.COOKIE_NAME}=([^;]+)", headers["Set-Cookie"]).group(1)

    def get_json(self, path, cookie, expect=200):
        status, headers, body = self.request("GET", path, cookie=cookie)
        self.assertEqual(status, expect, body[:200])
        self.assertTrue(headers["Content-Type"].startswith("application/json"))
        return json.loads(body)

    # ------------------------------------------------------------ TLS

    def test_the_certificate_verifies_and_the_ca_key_is_gone(self):
        tls_dir = self.tls["cert"].parent
        self.assertFalse((tls_dir / "ca.key").exists())
        self.assertEqual(sorted(p.name for p in tls_dir.iterdir()), ["ca.pem", "server.key", "server.pem"])
        self.assertEqual(stat.S_IMODE(os.stat(self.tls["key"]).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(tls_dir).st_mode), 0o700)
        status, _, _ = self.request("GET", "/login")  # the context verifies the chain and the name
        self.assertEqual(status, 200)

    def test_plain_http_gets_no_answer(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            with self.assertRaises((http.client.HTTPException, OSError)):
                conn.request("GET", "/login")
                conn.getresponse().read()
        finally:
            conn.close()

    def test_init_tls_refuses_bad_names_and_overwrites(self):
        with self.assertRaises(Exception):
            tlsgen.generate(self.tls["cert"].parent, ["127.0.0.1"], [])
        for bad in ("a,b", "x\ny", "*.example.com", "-bad"):
            with self.subTest(bad=bad), self.assertRaises(Exception):
                tlsgen.check_dns(bad)
        with self.assertRaises(Exception):
            tlsgen.check_ip("0.0.0.0")

    # ------------------------------------------------------------ headers

    def test_security_headers_on_every_response(self):
        for path in ("/login", "/static/app.css", "/api/repos", "/nope"):
            with self.subTest(path=path):
                _, headers, _ = self.request("GET", path)
                csp = headers["Content-Security-Policy"]
                self.assertIn("default-src 'none'", csp)
                self.assertIn("script-src 'self'", csp)
                self.assertIn("style-src 'self'", csp)
                self.assertIn("frame-ancestors 'none'", csp)
                self.assertNotIn("unsafe-inline", csp)
                self.assertNotIn("unsafe-eval", csp)
                self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
                self.assertEqual(headers["Referrer-Policy"], "same-origin")
                self.assertIn("max-age=", headers["Strict-Transport-Security"])
                self.assertEqual(headers["X-Frame-Options"], "DENY")

    def test_pages_have_no_inline_script_or_style(self):
        for name in ("index.html", "login.html"):
            text = (STATIC / name).read_text(encoding="utf-8")
            with self.subTest(name=name):
                self.assertNotRegex(text, r"<script(?![^>]*\bsrc=)")
                self.assertNotIn("<style", text)
                self.assertNotRegex(text, r"\sstyle=")
                self.assertNotRegex(text, r"\son[a-z]+=")

    def test_scripts_never_insert_html(self):
        for name in ("app.js", "model.js", "login.js"):
            text = (STATIC / name).read_text(encoding="utf-8")
            code = "\n".join(line for line in text.splitlines() if not line.strip().startswith("//"))
            with self.subTest(name=name):
                for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
                    self.assertNotIn(sink, code)

    # ------------------------------------------------------------ authentication

    def test_every_private_endpoint_needs_a_session(self):
        private = [p for p, (_, _, public) in server.ROUTES.items() if not public]
        api = [
            "/api/session",
            "/api/repos",
            "/api/about",
            "/api/overview?repo=acme/app",
            "/api/findings?repo=acme/app",
            "/api/rule?repo=acme/app&rule=x",
            "/api/runs?repo=acme/app",
            "/api/unknown",
        ]
        for path in private + api:
            for cookie in (None, "forged-session-id"):
                with self.subTest(path=path, cookie=cookie):
                    status, headers, body = self.request("GET", path, cookie=cookie)
                    if path == "/":
                        self.assertEqual((status, headers["Location"]), (303, "/login"))
                    else:
                        self.assertEqual(status, 401)
                    self.assertNotIn(b"acme", body)
        status, _, _ = self.request("POST", "/logout", headers={"Origin": self.origin})
        self.assertEqual(status, 401)

    def test_public_files_answer_without_a_session(self):
        for path in ("/login", "/static/app.css", "/static/login.js", "/static/shoalscan-icon.svg", "/favicon.ico"):
            with self.subTest(path=path):
                status, headers, body = self.request("GET", path)
                self.assertEqual(status, 200)
        icon = (helpers.ROOT / "assets" / "shoalscan-icon.svg").read_bytes()
        self.assertEqual(self.request("GET", "/static/shoalscan-icon.svg")[2], icon)

    def test_login_sets_a_strict_host_cookie(self):
        status, headers, _ = self.login()
        self.assertEqual((status, headers["Location"]), (303, "/"))
        cookie = headers["Set-Cookie"]
        self.assertTrue(cookie.startswith(auth.COOKIE_NAME + "="))
        for part in ("Path=/", "Secure", "HttpOnly", "SameSite=Strict"):
            self.assertIn(part, cookie)
        self.assertNotIn("Domain", cookie)

    def test_wrong_token_and_cross_origin_logins_fail(self):
        self.httpd.app.limiter = auth.LoginLimiter()
        status, headers, _ = self.login(token="not-the-token")
        self.assertEqual((status, headers["Location"]), (303, "/login?error=token"))
        self.assertNotIn("Set-Cookie", headers)
        for origin in ("https://evil.example", "null", f"http://127.0.0.1:{self.port}"):
            with self.subTest(origin=origin):
                status, headers, _ = self.login(origin=origin)
                self.assertEqual(status, 403)
                self.assertNotIn("Set-Cookie", headers)
        status, _, _ = self.login(origin=False)
        self.assertEqual(status, 403)
        status, _, _ = self.request(
            "POST", "/login", "token=" + self.token, {"Origin": self.origin, "Content-Type": "text/plain"}
        )
        self.assertEqual(status, 415)
        self.httpd.app.limiter = auth.LoginLimiter()

    def test_login_is_rate_limited(self):
        self.httpd.app.limiter = auth.LoginLimiter()
        try:
            for _ in range(5):
                self.assertEqual(self.login(token="wrong")[1]["Location"], "/login?error=token")
            status, headers, _ = self.login()  # even the right token waits now
            self.assertEqual((status, headers["Location"]), (303, "/login?error=limit"))
            self.assertNotIn("Set-Cookie", headers)
        finally:
            self.httpd.app.limiter = auth.LoginLimiter()

    def test_logout_needs_the_csrf_token(self):
        cookie = self.session()
        csrf = self.get_json("/api/session", cookie)["csrf"]
        for headers in ({"Origin": self.origin}, {"Origin": self.origin, "X-CSRF-Token": "wrong"}):
            with self.subTest(headers=headers):
                self.assertEqual(self.request("POST", "/logout", headers=headers, cookie=cookie)[0], 403)
        # The right CSRF token from another origin is still refused.
        self.assertEqual(
            self.request(
                "POST", "/logout", headers={"Origin": "https://evil.example", "X-CSRF-Token": csrf}, cookie=cookie
            )[0],
            403,
        )
        status, headers, _ = self.request(
            "POST", "/logout", headers={"Origin": self.origin, "X-CSRF-Token": csrf}, cookie=cookie
        )
        self.assertEqual(status, 204)
        self.assertIn("Max-Age=0", headers["Set-Cookie"])
        self.assertEqual(self.request("GET", "/api/repos", cookie=cookie)[0], 401)

    def test_rotating_the_token_ends_sessions(self):
        cookie = self.session()
        self.assertEqual(self.request("GET", "/api/repos", cookie=cookie)[0], 200)
        old = type(self).token
        type(self).token = auth.create_token(self.token_path)
        try:
            self.assertEqual(self.request("GET", "/api/repos", cookie=cookie)[0], 401)
            self.assertEqual(self.login(token=old)[1]["Location"], "/login?error=token")
        finally:
            self.httpd.app.limiter = auth.LoginLimiter()

    # ------------------------------------------------------------ request checks

    def test_a_wrong_host_is_refused(self):
        cookie = self.session()
        for host in ("evil.example", f"localhost:{self.port}", "127.0.0.1", f"127.0.0.1:{self.port + 1}"):
            with self.subTest(host=host):
                self.assertEqual(self.request("GET", "/api/repos", headers={"Host": host}, cookie=cookie)[0], 421)
                self.assertEqual(self.request("GET", "/login", headers={"Host": host})[0], 421)
                status, _, _ = self.request(
                    "POST",
                    "/login",
                    urlencode({"token": self.token}),
                    {"Host": host, "Origin": f"https://{host}", "Content-Type": "application/x-www-form-urlencoded"},
                )
                self.assertEqual(status, 421)

    def test_no_path_traversal_on_static_files(self):
        cookie = self.session()
        for path in (
            "/static/../server.py",
            "/static/%2e%2e/server.py",
            "/static/app.js/../../auth.py",
            "/static/",
            "//etc/passwd",
            "/static/..%2fserver.py",
            "/static/app.js%00",
            "/../../../../etc/passwd",
            "/static/index.html",
        ):
            with self.subTest(path=path):
                status, _, body = self.request("GET", path, cookie=cookie)
                self.assertEqual(status, 404)
                self.assertNotIn(b"import ", body)
                self.assertNotIn(b"root:", body)

    def test_bounded_requests_and_methods(self):
        cookie = self.session()
        self.assertEqual(self.request("GET", "/api/repos?" + "a" * 5000, cookie=cookie)[0], 414)
        status, _, _ = self.request(
            "POST",
            "/login",
            "token=" + "x" * 5000,
            {"Origin": self.origin, "Content-Type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(status, 413)
        for method in ("PUT", "DELETE", "PATCH", "OPTIONS"):
            with self.subTest(method=method):
                self.assertEqual(self.request(method, "/api/repos", cookie=cookie)[0], 405)

    def test_bad_parameters_are_refused(self):
        cookie = self.session()
        self.get_json("/api/overview", cookie, 400)
        self.get_json("/api/overview?repo=nobody/none", cookie, 404)
        self.get_json("/api/findings?repo=acme/app&severity=CRITICAL", cookie, 400)
        self.get_json("/api/findings?repo=acme/app&limit=ten", cookie, 400)
        self.get_json("/api/findings?repo=acme/app&run=-1", cookie, 400)
        self.get_json("/api/rule?repo=acme/app", cookie, 400)
        self.assertEqual(
            self.get_json("/api/findings?repo=acme/app&limit=ten", cookie, 400), {"error": "invalid query parameter"}
        )
        self.get_json("/api/unknown", cookie, 404)
        self.get_json("/api/unknown?repo=acme/app", cookie, 404)
        other = self.get_json("/api/runs?repo=acme/other", cookie)["runs"][0]["id"]
        self.get_json(f"/api/findings?repo=acme/app&run={other}", cookie, 404)
        self.get_json("/api/findings?repo=acme/app&path=" + "%27%20OR%201=1--", cookie)

    def raw_tls(self, data: bytes) -> bytes:
        with socket.create_connection(("127.0.0.1", self.port), timeout=10) as raw:
            with self.ctx.wrap_socket(raw, server_hostname="127.0.0.1") as tls:
                tls.sendall(data)
                chunks = []
                while True:
                    try:
                        chunk = tls.recv(65536)
                    except (ssl.SSLError, OSError):
                        break
                    if not chunk:
                        break
                    chunks.append(chunk)
                return b"".join(chunks)

    def test_errors_from_the_http_parser_carry_the_security_headers(self):
        for request, code in (
            (b"FOO / HTTP/1.1\r\nHost: x\r\n\r\n", b"501"),
            (b"GET /" + b"a" * 70000 + b" HTTP/1.1\r\n\r\n", b"414"),
            (b"GET / HTTP/9.9\r\n\r\n", b"505"),
            (b"GARBAGE\r\n\r\n", b"400"),
        ):
            with self.subTest(code=code):
                reply = self.raw_tls(request)
                head, _, body = reply.partition(b"\r\n\r\n")
                self.assertIn(b" " + code + b" ", head.split(b"\r\n")[0])
                self.assertIn(b"Content-Security-Policy: default-src 'none'", head)
                self.assertIn(b"X-Content-Type-Options: nosniff", head)
                self.assertIn(b"Strict-Transport-Security", head)
                self.assertIn(b"application/json", head)
                self.assertNotIn(b"<", body)

    def test_unfinished_handshakes_are_capped_per_address(self):
        idle = []
        try:
            for _ in range(server.MAX_HANDSHAKING_PER_ADDRESS):
                idle.append(socket.create_connection(("127.0.0.1", self.port), timeout=5))
            time.sleep(0.2)
            extra = socket.create_connection(("127.0.0.1", self.port), timeout=2)
            idle.append(extra)
            self.assertEqual(extra.recv(1), b"", "a connection past the cap must be closed at once")
        finally:
            for sock in idle:
                sock.close()
        self.assertLessEqual(server.HANDSHAKE_TIMEOUT, 5)
        for _ in range(50):  # the server notices the closed sockets and frees their places
            if not self.httpd.handshaking:
                break
            time.sleep(0.1)
        self.assertEqual(self.request("GET", "/login")[0], 200)

    def test_a_chunked_post_closes_the_connection(self):
        reply = self.raw_tls(
            f"POST /login HTTP/1.1\r\nHost: 127.0.0.1:{self.port}\r\nOrigin: {self.origin}\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: chunked\r\n\r\n"
            "5\r\ntoken\r\n0\r\n\r\nGET /api/repos HTTP/1.1\r\n\r\n".encode()
        )
        self.assertEqual(reply.count(b"HTTP/1.1 "), 1, "nothing after the chunked body may be read as a request")
        self.assertIn(b" 400 ", reply.split(b"\r\n")[0])
        self.assertIn(b"Connection: close", reply)

    def test_a_successful_login_clears_the_address_failures(self):
        self.httpd.app.limiter = auth.LoginLimiter()
        try:
            for _ in range(4):
                self.login(token="wrong")
            self.assertEqual(self.login()[0], 303)
            for _ in range(4):
                self.assertEqual(self.login(token="wrong")[1]["Location"], "/login?error=token")
            self.assertIn("Set-Cookie", self.login()[1])
        finally:
            self.httpd.app.limiter = auth.LoginLimiter()

    # ------------------------------------------------------------ API shapes and escaping

    def test_api_shapes(self):
        cookie = self.session()
        repos = self.get_json("/api/repos", cookie)["repos"]
        self.assertEqual([r["name"] for r in repos], ["acme/app", "acme/other"])
        self.assertEqual(set(repos[0]), {"name", "runs", "latest"})

        o = self.get_json("/api/overview?repo=acme/app", cookie)
        self.assertEqual(
            set(o),
            {
                "repo",
                "trend_kind",
                "latest_run",
                "latest_trend_run",
                "series",
                "weekly",
                "time_to_fix",
                "age_buckets",
                "by_component",
                "blocking",
                "reviews",
            },
        )
        self.assertEqual(
            set(o["series"][0]),
            {
                "run",
                "scanned_at",
                "commit",
                "open",
                "baseline_size",
                "suppressions",
                "suppressed_findings",
                "unscanned_skipped",
                "unscanned_errored",
                "blocking",
                "lists",
            },
        )
        self.assertEqual(set(o["blocking"]), {"run", "known", "total", "new", "baselined", "top"})
        self.assertEqual(set(o["weekly"][0]), {"week", "new", "fixed"})
        self.assertEqual(set(o["time_to_fix"]), {"fixed", "mean_days", "median_days"})
        self.assertEqual(set(o["by_component"]), {"run", "severities", "max_cell", "rows"})
        self.assertEqual(
            set(o["by_component"]["rows"][0]), {"component", "cells", "levels", "new", "new_blocking", "score"}
        )
        run_keys = {
            "id",
            "kind",
            "ref",
            "commit",
            "scanned_at",
            "recorded_at",
            "result",
            "outcome",
            "check_exit",
            "status",
            "lists",
            "findings",
            "by_severity",
            "by_severity_non_blocking_paths",
            "new",
            "new_blocking",
            "new_in_non_blocking_paths",
            "stale",
            "baseline_size",
            "baseline_additions",
            "suppressions",
            "unscanned",
            "policy_ref",
            "shoalscan_version",
            "duration_seconds",
            "blocking_class",
            "rescanned",
        }
        self.assertEqual(set(o["latest_run"]), run_keys)

        f = self.get_json("/api/findings?repo=acme/app", cookie)
        self.assertEqual(set(f), {"repo", "run", "total", "limit", "offset", "sort", "facets", "findings"})
        self.assertEqual(set(f["facets"]), {"severities", "rules", "components"})
        self.assertEqual(
            set(f["findings"][0]),
            {
                "severity",
                "tool",
                "rule",
                "path",
                "line",
                "fingerprint",
                "component",
                "message",
                "first_seen",
                "new",
                "new_blocking",
                "blocking_class",
                "key",
                "review",
            },
        )

        r = self.get_json("/api/rule?" + urlencode({"repo": "acme/app", "rule": "shoalscan.secret-in-log"}), cookie)
        self.assertEqual(set(r), {"repo", "run", "rule", "total", "messages", "locations"})
        self.assertEqual(r["total"], 1)

        runs = self.get_json("/api/runs?repo=acme/app&limit=2", cookie)
        self.assertEqual(runs["deletions"], {"count": 0, "items": []})
        self.assertEqual((runs["total"], len(runs["runs"])), (5, 2))
        self.assertEqual(set(runs["runs"][0]), run_keys)

        about = self.get_json("/api/about", cookie)
        self.assertEqual(set(about), {"shoalscan", "scanners", "rule_sources", "scanners_in_use"})
        self.assertEqual(about["scanners"][0]["name"], "Opengrep")
        self.assertRegex(about["scanners"][0]["version"], r"^\d+\.\d+\.\d+$")
        self.assertEqual(
            [s["name"] for s in about["scanners"]], ["Opengrep", "cosign", "Gitleaks", "Hadolint", "zizmor", "Trivy"]
        )
        self.assertEqual(about["scanners"][2]["licence"], "MIT")
        self.assertIn("Commons Clause", about["rule_sources"][0]["licence"])
        self.assertEqual(self.get_json("/api/session", cookie).keys(), {"csrf"})

    def test_lists_behind_the_counts(self):
        cookie = self.session()
        runs = self.get_json("/api/runs?repo=acme/app", cookie)["runs"]
        last = [r for r in runs if r["kind"] == "scheduled"][0]
        self.assertEqual(last["status"]["label"], "Blocked: 2 new blocking findings")
        run = self.get_json(f"/api/run?repo=acme/app&run={last['id']}", cookie)["run"]
        self.assertEqual(run["id"], last["id"])
        self.assertEqual(
            self.get_json(f"/api/findings?repo=acme/app&run={last['id']}&new_blocking=1", cookie)["total"], 2
        )
        self.assertEqual(self.get_json(f"/api/findings?repo=acme/app&run={last['id']}&age=0", cookie)["total"], 1)
        self.assertEqual(self.get_json(f"/api/stale?repo=acme/app&run={last['id']}", cookie)["total"], 1)
        self.assertEqual(self.get_json(f"/api/files?repo=acme/app&run={last['id']}&kind=skipped", cookie)["total"], 2)
        self.assertEqual(self.get_json(f"/api/suppressions?repo=acme/app&run={last['id']}", cookie)["total"], 1)
        changes = self.get_json("/api/changes?repo=acme/app&week=2026-09-14&change=fixed", cookie)
        self.assertEqual([f["path"] for f in changes["findings"]], ["src/a.py"])
        for bad in (
            "/api/files?repo=acme/app&kind=../x",
            "/api/changes?repo=acme/app&week=x&change=new",
            "/api/changes?repo=acme/app&week=2026-09-14&change=gone",
            "/api/findings?repo=acme/app&new=yes",
            "/api/findings?repo=acme/app&age=x",
        ):
            with self.subTest(bad=bad):
                self.assertEqual(self.get_json(bad, cookie, 400), {"error": "invalid query parameter"})
        for bad in ("99", "5", "-1", "1.5"):
            with self.subTest(age=bad):
                self.assertEqual(
                    self.get_json(f"/api/findings?repo=acme/app&age={bad}", cookie, 400),
                    {"error": "invalid query parameter"},
                )
        older = [r for r in runs if r["kind"] == "scheduled"][1]["id"]
        self.assertIn(
            "latest trend run", self.get_json(f"/api/findings?repo=acme/app&run={older}&age=0", cookie, 400)["error"]
        )

    def test_blocking_filter_and_priority_sort(self):
        cookie = self.session()
        res = self.get_json("/api/findings?repo=acme/app&blocking=1", cookie)
        self.assertEqual(res["sort"], "priority")  # the default when the blocking filter is on
        self.assertEqual([f["path"] for f in res["findings"]], ["src/d.py", "web/b.js"])
        self.assertTrue(all(f["blocking_class"] for f in res["findings"]))
        self.assertEqual(self.get_json("/api/findings?repo=acme/app&blocking=1&baselined=1", cookie)["total"], 0)
        self.assertIsNone(self.get_json("/api/findings?repo=acme/app", cookie)["sort"])
        self.assertEqual(self.get_json("/api/findings?repo=acme/app&sort=priority", cookie)["sort"], "priority")
        for bad in (
            "/api/findings?repo=acme/app&sort=path",
            "/api/findings?repo=acme/app&blocking=2",
            "/api/findings?repo=acme/app&baselined=x",
        ):
            with self.subTest(bad=bad):
                self.get_json(bad, cookie, 400)
        panel = self.get_json("/api/overview?repo=acme/app", cookie)["blocking"]
        self.assertEqual((panel["known"], panel["total"], panel["new"], panel["baselined"]), (True, 2, 2, 0))
        self.assertEqual([f["path"] for f in panel["top"]], ["src/d.py", "web/b.js"])

    def test_weekly_changes_are_cached_and_paginated(self):
        from shoalscan.dashboard.data import Data

        cookie = self.session()
        calls = []
        original = Data.change_keys

        def counting(self_, *args):
            calls.append(args)
            return original(self_, *args)

        Data.change_keys = counting
        try:
            first = self.get_json("/api/changes?repo=acme/app&week=2026-09-21&change=new&limit=1", cookie)
            again = self.get_json("/api/changes?repo=acme/app&week=2026-09-21&change=new&limit=1&offset=1", cookie)
        finally:
            Data.change_keys = original
        self.assertEqual(len(calls), 1, "the second page must come from the cache")
        self.assertEqual((first["total"], first["limit"], first["offset"], len(first["findings"])), (1, 1, 0, 1))
        self.assertEqual((again["offset"], again["findings"]), (1, []))

    def post_json(self, payload, cookie=None, csrf=None, origin="own"):
        headers = {"Content-Type": "application/json"}
        if csrf:
            headers["X-CSRF-Token"] = csrf
        if origin == "own":
            headers["Origin"] = self.origin
        elif origin:
            headers["Origin"] = origin
        status, _, body = self.request("POST", "/api/review", json.dumps(payload), headers, cookie=cookie)
        return status, json.loads(body) if body else {}

    def test_reviews(self):
        cookie = self.session()
        csrf = self.get_json("/api/session", cookie)["csrf"]
        findings = self.get_json("/api/findings?repo=acme/app&severity=ERROR", cookie)["findings"]
        key = findings[0]["key"]
        self.assertEqual(findings[0]["review"]["status"], "open")
        good = {
            "repo": "acme/app",
            "finding_key": key,
            "status": "false_positive",
            "description": "Constant input; never user controlled.",
        }
        # Session, CSRF and the exact Origin.
        self.assertEqual(self.post_json(good)[0], 401)
        self.assertEqual(self.post_json(good, cookie)[0], 403)
        self.assertEqual(self.post_json(good, cookie, "wrong")[0], 403)
        self.assertEqual(self.post_json(good, cookie, csrf, origin="https://evil.example")[0], 403)
        self.assertEqual(self.post_json(good, cookie, csrf, origin=None)[0], 403)
        # What may not be set.
        for change in (
            {"status": "verified_fixed"},
            {"status": "regression"},
            {"status": "closed"},
            {"description": "short"},
            {"description": ""},
            {"description": None},
            {"finding_key": ["a", "b"]},
            {"finding_key": "x"},
            {"run_id": "1"},
            {"repo": "../x"},
            {"surprise": 1},
        ):
            with self.subTest(change=change):
                self.assertEqual(self.post_json({**good, **change}, cookie, csrf)[0], 400)
        no_description = dict(good)
        del no_description["description"]
        self.assertEqual(self.post_json(no_description, cookie, csrf)[0], 400)
        self.assertEqual(
            self.post_json({**good, "finding_key": ["opengrep", "r", "nope.py", "x:0"]}, cookie, csrf)[0], 404
        )
        bulk = {
            "repo": "acme/app",
            "finding_keys": [key] * 501,
            "status": "fixed",
            "description": "Bulk fix of the eval calls.",
        }
        self.assertEqual(self.post_json(bulk, cookie, csrf)[0], 400)
        self.assertEqual(self.post_json({**bulk, "finding_keys": [key, key]}, cookie, csrf)[0], 400)
        # A hostile description is stored as text and only ever sent as JSON.
        status, body = self.post_json({**good, "description": MALICIOUS}, cookie, csrf)
        self.assertEqual(status, 200, body)
        q = urlencode({"repo": "acme/app", "finding_key": json.dumps(key)})
        detail = self.get_json(f"/api/finding?{q}", cookie)
        self.assertEqual(detail["finding"]["review"]["status"], "false_positive")
        self.assertEqual(detail["finding"]["review"]["description"], MALICIOUS)
        self.assertTrue(detail["finding"]["review"]["resolved_at"].endswith("Z"))
        self.assertEqual(detail["history"][0]["to_status"], "false_positive")
        self.assertTrue(detail["history"][0]["who"].startswith("dashboard user (session "))
        self.assertEqual(self.get_json(f"/api/review/history?{q}", cookie)["history"][0]["description"], MALICIOUS)
        self.get_json("/api/review/history?repo=acme/app&finding_key=%5B1%5D", cookie, 400)
        # Filters and the overview's counts.
        self.assertEqual(self.get_json("/api/findings?repo=acme/app&review=false_positive", cookie)["total"], 1)
        self.get_json("/api/findings?repo=acme/app&review=bogus", cookie, 400)
        reviews = self.get_json("/api/overview?repo=acme/app", cookie)["reviews"]
        self.assertEqual(set(reviews), {"run", "untriaged_blocking", "regressions"})

    def test_a_malicious_message_is_only_ever_json(self):
        cookie = self.session()
        status, headers, body = self.request("GET", "/api/findings?repo=acme/app&severity=INFO", cookie=cookie)
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "application/json; charset=utf-8")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(json.loads(body)["findings"][0]["message"], MALICIOUS)
        # No HTML page the server sends contains finding data; the page code
        # inserts it with textContent (see test_scripts_never_insert_html).
        for path in ("/", "/static/app.js"):
            self.assertNotIn(b"onerror", self.request("GET", path, cookie=cookie)[2])


def _openssl_binaries() -> list[str]:
    """Every openssl on this machine: OpenSSL 3 and LibreSSL behave differently."""
    found = []
    for candidate in (OPENSSL, "/usr/bin/openssl", "/opt/homebrew/bin/openssl", "/usr/local/bin/openssl"):
        if (
            candidate
            and os.path.exists(candidate)
            and os.path.realpath(candidate) not in {os.path.realpath(f) for f in found}
        ):
            found.append(candidate)
    return found


FOREIGN = (
    "[foreign_dns]\nbasicConstraints = critical,CA:FALSE\nextendedKeyUsage = serverAuth\nsubjectAltName = "
    "DNS:evil.example\n"
    "[foreign_ip]\nbasicConstraints = critical,CA:FALSE\nextendedKeyUsage = serverAuth\nsubjectAltName = IP:10.9.8.7\n"
    "[foreign_ip6]\nbasicConstraints = critical,CA:FALSE\nextendedKeyUsage = serverAuth\nsubjectAltName = "
    "IP:2001:db8::7\n"
)


@unittest.skipIf(OPENSSL is None, "the openssl command is not installed, so no test certificate can be made")
class LoginLimiterTests(unittest.TestCase):
    def test_a_full_global_window_does_not_block_a_clean_address(self):
        limiter = auth.LoginLimiter(per_address=5, overall=3)
        for n in range(3):
            limiter.failed(f"192.0.2.{n}")
        self.assertFalse(limiter.allowed("192.0.2.0"))
        self.assertTrue(limiter.allowed("198.51.100.1"))

    def test_success_clears_failures(self):
        limiter = auth.LoginLimiter(per_address=2, overall=100)
        limiter.failed("192.0.2.1")
        limiter.failed("192.0.2.1")
        self.assertFalse(limiter.allowed("192.0.2.1"))
        limiter.succeeded("192.0.2.1")
        self.assertTrue(limiter.allowed("192.0.2.1"))


@unittest.skipIf(OPENSSL is None, "the openssl command is not installed, so no test certificate can be made")
class NameConstraintTests(unittest.TestCase):
    """The CA must refuse every name it was not made for, whatever types were given."""

    def verify(self, openssl: str, work: Path, cert: str) -> bool:
        proc = subprocess.run(
            [openssl, "verify", "-CAfile", "ca.pem", cert], cwd=work, capture_output=True, text=True, timeout=60
        )
        return proc.returncode == 0 and ": OK" in proc.stdout

    def test_foreign_names_fail_for_every_kind_of_name_list(self):
        cases = {
            "ip only": (["127.0.0.1"], []),
            "dns only": ([], ["scans.example.internal"]),
            "both": (["192.0.2.10"], ["scans.example.internal"]),
            "ipv6 only": (["2001:db8::10"], []),
        }
        for openssl in _openssl_binaries():
            for label, (ips, names) in cases.items():
                with self.subTest(openssl=openssl, case=label), tempfile.TemporaryDirectory() as tmp:
                    work = Path(tmp)
                    tlsgen.make_ca(openssl, work, ips, names)
                    text = subprocess.run(
                        [openssl, "x509", "-in", "ca.pem", "-noout", "-text"],
                        cwd=work,
                        capture_output=True,
                        text=True,
                        timeout=60,
                        check=True,
                    ).stdout
                    self.assertRegex(text, r"Name Constraints: critical")
                    self.assertIn("Permitted", text)
                    self.assertIn("DNS:" + (names[0] if names else tlsgen.NO_DNS_NAME), text)
                    eku = re.search(r"Extended Key Usage:\s*\n\s*(.+)", text)
                    self.assertIsNotNone(eku)
                    self.assertEqual(eku.group(1).strip(), "TLS Web Server Authentication")
                    if not any(":" not in v for v in ips):
                        self.assertIn("IP:0.0.0.0/0.0.0.0", text)  # no IPv4 given: IPv4 excluded
                    tlsgen.sign_leaf(openssl, work, "ok.key", "ok.pem")
                    self.assertTrue(
                        self.verify(openssl, work, "ok.pem"), "the certificate for the given names must verify"
                    )
                    (work / "foreign.cnf").write_text(FOREIGN, encoding="ascii")
                    for section in ("foreign_dns", "foreign_ip", "foreign_ip6"):
                        tlsgen.sign_leaf(openssl, work, f"{section}.key", f"{section}.pem", "foreign.cnf", section)
                        self.assertFalse(self.verify(openssl, work, f"{section}.pem"), f"{section} must not verify")

    def test_constraints_cover_both_types(self):
        self.assertEqual(
            tlsgen.name_constraints(["127.0.0.1"], []),
            "permitted;DNS:shoalscan.invalid,permitted;IP:127.0.0.1/255.255.255.255,excluded;IP:::/::",
        )
        self.assertEqual(
            tlsgen.name_constraints([], ["a.example"]),
            "permitted;DNS:a.example,excluded;IP:0.0.0.0/0.0.0.0,excluded;IP:::/::",
        )

    def test_a_stale_work_directory_is_removed(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "tls"
            stale = out / (tlsgen.WORK_PREFIX + "deadbeef")
            stale.mkdir(parents=True)
            (stale / "ca.key").write_text("leftover", encoding="ascii")
            tlsgen.generate(out, ["127.0.0.1"], [])
            self.assertFalse(stale.exists())
            self.assertEqual(sorted(p.name for p in out.iterdir()), ["ca.pem", "server.key", "server.pem"])


if __name__ == "__main__":
    unittest.main()
