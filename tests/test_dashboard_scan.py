"""Starting scans from the dashboard: POST /api/scan and GET /api/scan/status."""

import http.client
import json
import os
import re
import signal
import ssl
import tempfile
import threading
import time
import unittest
from pathlib import Path
from urllib.parse import urlencode

import helpers  # noqa: F401
from test_scanjob import Fixture

from shoalscan import history
from shoalscan.dashboard import auth, scanning, server, tlsgen
from shoalscan.errors import SetupError


class DashboardHarness:
    """A dashboard on an ephemeral port, with TLS made by init-tls and a state directory."""

    def __init__(self, base: Path, state: Path, db: Path, allow_config: bool = False):
        self.tls = tlsgen.generate(base / "tls", ["127.0.0.1"], [])
        self.token = auth.create_token(base / "token.sha256")
        if not db.exists():
            history.open_for_write(db).close()
        config = server.ServeConfig(db=db, cert=self.tls["cert"], key=self.tls["key"], token_hash=base / "token.sha256",
                                    bind="127.0.0.1", port=0, hosts=("127.0.0.1",), state_dir=state, allow_config=allow_config)
        self.httpd = server.build_server(config)
        self.port = self.httpd.server_address[1]
        self.origin = f"https://127.0.0.1:{self.port}"
        self.ctx = ssl.create_default_context(cafile=str(self.tls["ca"]))
        self.thread = threading.Thread(target=self.httpd.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
        self.thread.start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=10)

    def request(self, method, path, body=None, headers=None, cookie=None):
        conn = http.client.HTTPSConnection("127.0.0.1", self.port, context=self.ctx, timeout=20)
        try:
            h = dict(headers or {})
            if cookie:
                h["Cookie"] = f"{auth.COOKIE_NAME}={cookie}"
            conn.request(method, path, body=body, headers=h)
            res = conn.getresponse()
            return res.status, dict(res.getheaders()), res.read()
        finally:
            conn.close()

    def login(self):
        _, headers, _ = self.request("POST", "/login", urlencode({"token": self.token}),
                                     {"Origin": self.origin, "Content-Type": "application/x-www-form-urlencoded"})
        sid = re.match(rf"{auth.COOKIE_NAME}=([^;]+)", headers["Set-Cookie"]).group(1)
        status, _, body = self.request("GET", "/api/session", cookie=sid)
        return sid, json.loads(body)["csrf"]

    def post(self, path, payload, sid=None, csrf=None, origin="own", content_type="application/json"):
        headers = {"Content-Type": content_type}
        if csrf:
            headers["X-CSRF-Token"] = csrf
        if origin == "own":
            headers["Origin"] = self.origin
        elif origin:
            headers["Origin"] = origin
        body = payload if isinstance(payload, (bytes, str)) else json.dumps(payload)
        status, _, raw = self.request("POST", path, body, headers, cookie=sid)
        return status, json.loads(raw) if raw else {}

    def get(self, path, sid):
        status, _, raw = self.request("GET", path, cookie=sid)
        return status, json.loads(raw) if raw else {}


def kill_scan(f: Fixture, state: Path) -> None:
    """Stop a running worker and its scan child; each runs in its own session."""
    holder = scanning.read_json(state / scanning.LOCK_FILE)
    for pid in (holder.get("pid"), int((f.bin / "scan.pid").read_text()) if (f.bin / "scan.pid").exists() else None):
        if pid:
            try:
                os.killpg(pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass


@unittest.skipIf(tlsgen.find_openssl() is None, "the openssl command is not installed, so no test certificate can be made")
class ScanEndpointTests(unittest.TestCase):
    def setUp(self):
        server.Handler._log, self._log = (lambda self, status: None), server.Handler._log
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name)
        self.f = Fixture(self.base)
        self.dash = DashboardHarness(self.base, self.f.state, self.f.db)
        self.sid, self.csrf = self.dash.login()

    def tearDown(self):
        kill_scan(self.f, self.f.state)
        self.dash.close()
        server.Handler._log = self._log
        self._tmp.cleanup()

    def wait_idle(self, timeout=120):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            status, body = self.dash.get("/api/scan/status", self.sid)
            if not body["running"] and body["triggers"] and body["triggers"][0]["outcome"] != "running":
                return body
            time.sleep(0.5)
        self.fail("the scan did not finish")

    def test_post_needs_a_session_csrf_and_the_exact_origin(self):
        d = self.dash
        self.assertEqual(d.post("/api/scan", {"target": "acme/app"})[0], 401)
        self.assertEqual(d.post("/api/scan", {"target": "acme/app"}, sid=self.sid)[0], 403)
        self.assertEqual(d.post("/api/scan", {"target": "acme/app"}, sid=self.sid, csrf="wrong")[0], 403)
        self.assertEqual(d.post("/api/scan", {"target": "acme/app"}, sid=self.sid, csrf=self.csrf, origin="https://evil.example")[0], 403)
        # A Referer alone is enough for logout, not for starting a scan.
        status, _, _ = d.request("POST", "/api/scan", json.dumps({"target": "acme/app"}),
                                 {"Content-Type": "application/json", "X-CSRF-Token": self.csrf, "Referer": d.origin + "/"}, cookie=self.sid)
        self.assertEqual(status, 403)
        self.assertEqual(d.post("/api/scan", "target=acme/app", sid=self.sid, csrf=self.csrf, content_type="text/plain")[0], 415)
        self.assertEqual(self.f.calls(), [])

    def test_unknown_and_injected_targets_are_refused(self):
        d = self.dash
        self.assertEqual(d.post("/api/scan", {"target": "acme/other"}, sid=self.sid, csrf=self.csrf)[0], 404)
        for target in ("../acme/app", "--help", "acme/app;id", "acme/app\n", "a b", "/etc/passwd", 5, ["acme/app"], None):
            with self.subTest(target=target):
                self.assertEqual(d.post("/api/scan", {"target": target}, sid=self.sid, csrf=self.csrf)[0], 400)
        for payload in ({"target": "acme/app", "branch": "x"}, {"target": "acme/app", "clone": "/tmp"}, [], "null"):
            with self.subTest(payload=payload):
                self.assertEqual(d.post("/api/scan", payload, sid=self.sid, csrf=self.csrf)[0], 400)
        self.assertEqual(self.f.calls(), [])

    def test_rescan_requests(self):
        d = self.dash
        conn = history.open_for_write(self.f.db)
        try:
            other = history.record_run(conn, history.RunInfo("acme/other", "main", "a" * 40, "scheduled", "2026-09-01T00:00:00Z"),
                                       [], {}, {"result": "pass", "findings": 0}).run_id
        finally:
            conn.close()
        for payload in ({"target": "acme/app", "run_id": "1"}, {"target": "acme/app", "run_id": -1}, {"target": "acme/app", "run_id": 1.5},
                        {"target": "acme/app", "run_id": True}, {"target": "acme/app", "run_id": 2**70}, {"target": "acme/app", "rescan": 1},
                        {"target": "acme/app", "rescan": True, "run_id": 1}, {"target": "acme/app", "commit": "a" * 40},
                        {"target": "acme/app", "run_id": "1; DROP TABLE runs"}):
            with self.subTest(payload=payload):
                self.assertEqual(d.post("/api/scan", payload, sid=self.sid, csrf=self.csrf)[0], 400)
        self.assertEqual(d.post("/api/scan", {"target": "acme/app", "run_id": other}, sid=self.sid, csrf=self.csrf)[0], 404)
        self.assertEqual(d.post("/api/scan", {"target": "acme/app", "run_id": 999999}, sid=self.sid, csrf=self.csrf)[0], 404)
        conn = history.open_for_write(self.f.db)
        try:
            pr = history.record_run(conn, history.RunInfo("acme/app", "refs/pull/4/merge", "b" * 40, "pr", "2026-09-01T00:00:00Z"),
                                    [], {}, {"result": "pass", "findings": 0}).run_id
        finally:
            conn.close()
        self.assertEqual(d.post("/api/scan", {"target": "acme/app", "run_id": pr}, sid=self.sid, csrf=self.csrf)[0], 409)
        self.assertEqual(self.f.calls(), [])
        status, body = d.post("/api/scan", {"target": "acme/app", "rescan": True}, sid=self.sid, csrf=self.csrf)
        self.assertEqual(status, 202, body)
        body = self.wait_idle()
        self.assertEqual((body["triggers"][0]["trigger"], body["triggers"][0]["outcome"]), ("rescan", "passed"))

    def test_scans_are_refused_when_git_ignores_the_attribute_source(self):
        from unittest import mock

        with mock.patch.object(scanning, "git_attr_probe", return_value=False):
            status, body = self.dash.get("/api/scan/status", self.sid)
            self.assertEqual((body["git_ok"], body["git_error"]), (False, scanning.GIT_TOO_OLD))
            status, body = self.dash.post("/api/scan", {"target": "acme/app"}, sid=self.sid, csrf=self.csrf)
            self.assertEqual((status, body["error"]), (503, scanning.GIT_TOO_OLD))
        self.assertEqual(self.f.calls(), [])
        self.assertTrue(self.dash.get("/api/scan/status", self.sid)[1]["git_ok"])

    def test_single_flight(self):
        (self.f.bin / "slow").write_text("1")
        status, body = self.dash.post("/api/scan", {"target": "acme/app"}, sid=self.sid, csrf=self.csrf)
        self.assertEqual(status, 202, body)
        for _ in range(200):
            if (self.f.bin / "scan.pid").exists():
                break
            time.sleep(0.05)
        status, body = self.dash.post("/api/scan", {"target": "acme/app"}, sid=self.sid, csrf=self.csrf)
        self.assertEqual(status, 409)
        self.assertTrue(body["status"]["running"])
        status, body = self.dash.get("/api/scan/status", self.sid)
        self.assertEqual(body["current"]["target"], "acme/app")
        self.assertTrue(body["running"])
        for line in body["log"]:
            self.assertNotIn(str(self.base), line, "absolute paths never leave the server")

    def test_a_finished_scan_is_audited_and_cools_down(self):
        status, body = self.dash.post("/api/scan", {"target": "acme/app"}, sid=self.sid, csrf=self.csrf)
        self.assertEqual(status, 202, body)
        body = self.wait_idle()
        self.assertEqual(body["current"]["outcome"], "passed", body)
        trigger = body["triggers"][0]
        self.assertEqual((trigger["target"], trigger["who"], trigger["outcome"]), ("acme/app", "dashboard user", "passed"))
        self.assertEqual(trigger["run_id"], body["current"]["run_id"])
        self.assertGreater(body["targets"][0]["cooldown_remaining"], 500)
        status, body = self.dash.post("/api/scan", {"target": "acme/app"}, sid=self.sid, csrf=self.csrf)
        self.assertEqual(status, 429)
        self.assertGreater(body["retry_after"], 0)


class StatusOrderTests(unittest.TestCase):
    def test_running_is_decided_before_the_status_and_audit_are_read(self):
        from shoalscan.dashboard.scancontrol import ScanControl

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            f = Fixture(base)
            control = ScanControl(f.state, f.db)
            order = []
            control.running = lambda: order.append("running") or False

            def read_triggers():
                order.append("triggers")
                return []

            control.status(read_triggers)
            self.assertEqual(order, ["running", "triggers"])


@unittest.skipIf(tlsgen.find_openssl() is None, "the openssl command is not installed, so no test certificate can be made")
class ScansOffTests(unittest.TestCase):
    def test_no_targets_file_means_no_scans(self):
        server.Handler._log, log = (lambda self, status: None), server.Handler._log
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "state").mkdir()
            dash = DashboardHarness(base, base / "state", base / "h.sqlite3")
            try:
                sid, csrf = dash.login()
                self.assertEqual(dash.get("/api/scan/status", sid)[0], 404)
                self.assertEqual(dash.post("/api/scan", {"target": "acme/app"}, sid=sid, csrf=csrf)[0], 404)
            finally:
                dash.close()
                server.Handler._log = log

    def test_a_targets_file_for_another_database_is_refused_at_start(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            f = Fixture(base)
            with self.assertRaisesRegex(SetupError, "history_db"):
                DashboardHarness(base, f.state, base / "other.sqlite3")


if __name__ == "__main__":
    unittest.main()
