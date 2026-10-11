"""The Configuration page: strict validation, CSRF-protected writes, atomic files, audit."""

import json
import os
import sqlite3
import stat
import tempfile
import tomllib
import unittest
from pathlib import Path

import helpers  # noqa: F401

from shoalscan import history
from shoalscan.dashboard import scanning, server, tlsgen
from shoalscan.errors import SetupError
from test_dashboard_scan import DashboardHarness
from test_scanjob import Fixture

HOSTS = scanning.DEFAULT_HOSTS


class ValidationTests(unittest.TestCase):
    def test_urls(self):
        for good in (
            "https://github.com/acme/app.git",
            "https://github.com/acme/app",
            "https://gitlab.com/group/sub/project",
        ):
            with self.subTest(good=good):
                self.assertEqual(scanning.validate_url(good, HOSTS), good)
        hostile = [
            "file:///etc/passwd",
            "ext::sh -c id",
            "http://github.com/acme/app",
            "ssh://git@github.com/acme/app",
            "git://github.com/acme/app",
            "https://user:secret@github.com/acme/app",
            "https://token@github.com/acme/app",
            "https://evil.example/acme/app",
            "https://github.com.evil.example/acme/app",
            "https://github.com:443/acme/app",
            "--upload-pack=touch /tmp/pwned",
            "https://github.com/acme/app --upload-pack=x",
            "https://github.com/acme/app?x=1",
            "https://github.com/acme/app#frag",
            "https://gіthub.com/acme/app",
            "https://github.com/acme/app\n",
            " https://github.com/acme/app",
            "https://github.com/../etc",
            "https://github.com/-x/app",
            "https://github.com/acme",
            "HTTPS://github.com/acme/app",
            "https://GitHub.com/acme/app",
            "https://github.com//acme/app",
            "https://github.com/acme/app/%2e%2e",
            "",
            None,
            7,
            "https://" + "a" * 400,
        ]
        for bad in hostile:
            with self.subTest(bad=bad), self.assertRaises(SetupError):
                scanning.validate_url(bad, HOSTS)

    def test_branches(self):
        for good in ("main", "release/1.2", "feature-x", "v2"):
            self.assertEqual(scanning.validate_branch(good), good)
        for bad in (
            "-x",
            "--upload-pack=x",
            "a..b",
            "a b",
            "a~1",
            "a^",
            "a:b",
            "main\n",
            "a.lock",
            "@",
            "",
            "x/",
            "/x",
            "a\\b",
            "refs/heads/../x",
            "mäin",
            None,
            "a" * 300,
        ):
            with self.subTest(bad=bad), self.assertRaises(SetupError):
                scanning.validate_branch(bad)

    def test_names(self):
        for bad in ("../x", "-x", "a b", "a/b\n", "<script>", "", "a//b", "a/", None):
            with self.subTest(bad=bad), self.assertRaises(SetupError):
                scanning.validate_name(bad)

    def test_policy(self):
        self.assertEqual(scanning.validate_policy('excludes = ["vendor"]\n'), 'excludes = ["vendor"]\n')
        self.assertEqual(scanning.validate_policy(""), "")
        for bad in (
            "excludes = [",
            "surprise = 1\n",
            'baseline = "x.toml"\n',
            'blocking = ["WARNING"]\n',
            "x" * 40000,
            'excludes = ["**"]\n',
            'excludes = ["vendor", "*"]\n',
        ):
            with self.subTest(bad=bad[:30]), self.assertRaises(SetupError):
                scanning.validate_policy(bad)


@unittest.skipIf(
    tlsgen.find_openssl() is None, "the openssl command is not installed, so no test certificate can be made"
)
class ConfigApiTests(unittest.TestCase):
    def setUp(self):
        server.Handler._log, self._log = (lambda self, status: None), server.Handler._log
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name)
        self.state = self.base / "state"
        self.state.mkdir(mode=0o700)
        mirrors = self.state / scanning.SOURCES_FILE
        mirrors.write_text(f'[[mirror]]\nname = "private-app"\npath = "{self.base}"\n', encoding="utf-8")
        mirrors.chmod(0o600)
        self.db = self.base / "history.sqlite3"
        self.dash = DashboardHarness(self.base, self.state, self.db, allow_config=True)
        self.sid, self.csrf = self.dash.login()

    def tearDown(self):
        self.dash.close()
        server.Handler._log = self._log
        self._tmp.cleanup()

    def post(self, path, payload, **kw):
        return self.dash.post(
            path, payload, sid=kw.get("sid", self.sid), csrf=kw.get("csrf", self.csrf), origin=kw.get("origin", "own")
        )

    def target(self, **changes):
        body = {
            "original": None,
            "name": "acme/app",
            "source": {"kind": "url", "url": "https://github.com/acme/app.git"},
            "branch": "main",
            "enabled": True,
            "nightly": True,
            "policy": "",
            "scanners": None,
        }
        body.update(changes)
        return body

    def file(self) -> dict:
        return tomllib.loads((self.state / scanning.TARGETS_FILE).read_text())

    def audit(self) -> list:
        conn = sqlite3.connect(self.db)
        try:
            return conn.execute(
                "SELECT who, target, action, diff, policy_before, policy_after FROM config_changes ORDER BY id"
            ).fetchall()
        finally:
            conn.close()

    def managed(self) -> Path:
        return self.state / "targets" / scanning.slug("acme/app") / "shoalscan.toml"

    def test_scanners_are_chosen_on_the_page_and_reach_the_scan_policy(self):
        from shoalscan.config import config_from_bytes
        from shoalscan.dashboard.configedit import ConfigEditor

        body = 'excludes = ["vendor"]\n'
        status, reply = self.post(
            "/api/config/target", self.target(policy=body, scanners=["zizmor", "opengrep", "gitleaks"])
        )
        self.assertEqual(status, 200, reply)
        text = self.managed().read_text()
        self.assertTrue(text.startswith(scanning.SCANNERS_HEADER))
        config = config_from_bytes(text.encode(), "managed")
        self.assertEqual(config.scanners, ("opengrep", "gitleaks", "zizmor"))
        self.assertEqual(config.excludes, ("vendor",))
        editor = ConfigEditor(self.state, self.db)
        page = editor.page(lambda name: None, [])
        t = page["targets"][0]
        self.assertEqual(
            (t["scanners"], t["policy"], t["policy_scanners"]),
            (["opengrep", "gitleaks", "zizmor"], body, ["opengrep", "gitleaks", "zizmor"]),
        )
        self.assertEqual([s["name"] for s in page["scanners"]], ["opengrep", "gitleaks", "hadolint", "zizmor", "trivy"])
        self.assertTrue(all(set(s) == {"name", "version", "installed"} for s in page["scanners"]))
        diff = json.loads(self.audit()[-1][3])
        self.assertEqual(diff["scanners"], [None, ["opengrep", "gitleaks", "zizmor"]])
        # Back to "as the policy says": the header goes, the policy text stays.
        self.assertEqual(
            self.post("/api/config/target", self.target(original="acme/app", policy=body, scanners=None))[0], 200
        )
        self.assertEqual(self.managed().read_text(), body)
        # Chosen with no policy text: a policy that sets only the scanners.
        self.assertEqual(
            self.post("/api/config/target", self.target(original="acme/app", policy="", scanners=["hadolint"]))[0], 200
        )
        self.assertEqual(config_from_bytes(self.managed().read_bytes(), "managed").scanners, ("hadolint",))
        self.assertEqual(editor.page(lambda name: None, [])["targets"][0]["policy"], "")

    def test_bad_scanner_choices_are_refused(self):
        bad = [[], ["opengrep", "opengrep"], ["trufflehog"], "opengrep", [1], {"opengrep": True}]
        for choice in bad:
            with self.subTest(choice=choice):
                status, reply = self.post("/api/config/target", self.target(scanners=choice))
                self.assertEqual(status, 400, reply)
        status, reply = self.post(
            "/api/config/target", self.target(policy='scanners = ["gitleaks"]\n', scanners=["opengrep"])
        )
        self.assertEqual(status, 400)
        self.assertIn("sets scanners too", reply["error"])
        request = self.target()
        del request["scanners"]
        self.assertEqual(self.post("/api/config/target", request)[0], 400)
        self.assertFalse((self.state / scanning.TARGETS_FILE).exists())

    def test_every_post_needs_a_session_csrf_and_the_exact_origin(self):
        for path, payload in (
            ("/api/config/target", self.target()),
            ("/api/config/enable", {"name": "acme/app", "enabled": False}),
            ("/api/config/remove", {"name": "acme/app", "confirm": "acme/app"}),
        ):
            with self.subTest(path=path):
                self.assertEqual(self.dash.post(path, payload)[0], 401)
                self.assertEqual(self.post(path, payload, csrf=None)[0], 403)
                self.assertEqual(self.post(path, payload, csrf="wrong")[0], 403)
                self.assertEqual(self.post(path, payload, origin="https://evil.example")[0], 403)
        self.assertFalse((self.state / scanning.TARGETS_FILE).exists())

    def test_create_update_enable_and_remove_are_atomic_and_audited(self):
        status, body = self.post("/api/config/target", self.target())
        self.assertEqual(status, 200, body)
        path = self.state / scanning.TARGETS_FILE
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        self.assertEqual(
            [p.name for p in self.state.iterdir() if p.name.startswith(".")], [], "no temporary files are left"
        )
        data = self.file()
        self.assertEqual(data["history_db"], str(self.db))
        self.assertEqual(
            data["target"],
            [
                {
                    "name": "acme/app",
                    "source": "https://github.com/acme/app.git",
                    "branch": "main",
                    "enabled": True,
                    "nightly": True,
                }
            ],
        )
        policy = 'excludes = ["vendor"]\n'
        status, body = self.post(
            "/api/config/target", self.target(original="acme/app", branch="develop", policy=policy)
        )
        self.assertEqual(status, 200, body)
        managed = self.state / "targets" / scanning.slug("acme/app") / "shoalscan.toml"
        self.assertEqual(managed.read_text(), policy)
        self.assertEqual(stat.S_IMODE(os.stat(managed).st_mode), 0o600)
        self.assertEqual(self.post("/api/config/enable", {"name": "acme/app", "enabled": False})[0], 200)
        self.assertEqual(self.file()["target"][0]["enabled"], False)
        rows = self.audit()
        self.assertEqual([r[2] for r in rows], ["create", "update", "disable"])
        self.assertEqual(rows[0][0], "admin@example.com")  # changes name the person who signed in
        update_diff = json.loads(rows[1][3])
        self.assertEqual(update_diff["branch"], ["main", "develop"])
        self.assertEqual((rows[1][4], rows[1][5]), (None, scanning.policy_sha256(policy)))
        conn = sqlite3.connect(self.db)
        try:
            policy_diff = conn.execute("SELECT policy_diff FROM config_changes WHERE action = 'update'").fetchone()[0]
        finally:
            conn.close()
        self.assertIn('+excludes = ["vendor"]', policy_diff)
        # Remove asks for the name again, and keeps the history.
        conn = history.open_for_write(self.db)
        try:
            history.record_run(
                conn,
                history.RunInfo("acme/app", "main", "a" * 40, "scheduled", "2026-09-01T00:00:00Z"),
                [],
                {},
                {"result": "pass", "findings": 0},
            )
        finally:
            conn.close()
        self.assertEqual(self.post("/api/config/remove", {"name": "acme/app", "confirm": "acme/ap"})[0], 400)
        self.assertEqual(self.post("/api/config/remove", {"name": "acme/app", "confirm": "acme/app"})[0], 200)
        self.assertEqual(self.file().get("target", []), [])
        conn = sqlite3.connect(self.db)
        try:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0], 1)
        finally:
            conn.close()
        self.assertEqual(self.audit()[-1][2], "remove")
        status, page = self.dash.get("/api/config", self.sid)
        self.assertEqual([c["action"] for c in page["changes"]], ["remove", "disable", "update", "create"])

    def test_what_the_browser_may_not_set(self):
        self.assertEqual(self.post("/api/config/target", self.target())[0], 200)
        before = (self.state / scanning.TARGETS_FILE).read_text()
        refused = [
            {**self.target(original="acme/app"), "baseline": "/tmp/b.toml"},
            {**self.target(original="acme/app"), "clone": "/tmp"},
            {**self.target(original="acme/app"), "python": "/bin/sh"},
            {**self.target(original="acme/app"), "config": "/tmp/c.toml"},
            self.target(original="acme/app", policy='baseline = "other.toml"\n'),
            self.target(original="acme/app", policy="not = [valid"),
            self.target(name="acme/new", source={"kind": "clone"}),
            self.target(name="acme/new", source={"kind": "url", "url": "file:///etc"}),
            self.target(name="acme/new", source={"kind": "url", "url": "https://github.com/a/b", "clone": "/x"}),
            self.target(name="acme/new", source={"kind": "mirror", "mirror": "unknown"}),
            self.target(name="acme/new", source={"kind": "mirror", "mirror": "../private-app"}),
            self.target(name="acme/new", branch="--upload-pack=x"),
            self.target(name="../acme"),
            self.target(name="acme/new", enabled="yes"),
            self.target(original="acme/app", name="acme/renamed"),
        ]
        for payload in refused:
            with self.subTest(payload={k: v for k, v in payload.items() if k != "policy"}):
                self.assertEqual(self.post("/api/config/target", payload)[0], 400)
        self.assertEqual((self.state / scanning.TARGETS_FILE).read_text(), before)
        # There is no way to write a baseline.
        self.assertEqual(self.post("/api/config/baseline", {"target": "acme/app", "entries": []})[0], 404)
        status, _, _ = self.dash.request("PUT", "/api/config/baseline?target=acme/app", cookie=self.sid)
        self.assertEqual(status, 405)
        # A registered mirror is fine.
        self.assertEqual(
            self.post(
                "/api/config/target",
                self.target(name="acme/private", source={"kind": "mirror", "mirror": "private-app"}),
            )[0],
            200,
        )

    def test_the_baseline_is_shown_read_only(self):
        self.assertEqual(self.post("/api/config/target", self.target())[0], 200)
        managed = self.state / "targets" / scanning.slug("acme/app") / "baseline.toml"
        managed.parent.mkdir(parents=True, exist_ok=True)
        managed.write_text(
            'version = 1\n\n[[finding]]\ntool = "opengrep"\nrule = "r"\npath = "a.py"\nfingerprint = "f:0"\n'
            'issue = "#1"\nreason = "accepted"\n',
            encoding="utf-8",
        )
        status, body = self.dash.get("/api/config/baseline?target=acme/app", self.sid)
        self.assertEqual(status, 200)
        self.assertEqual((body["size"], body["entries"][0]["path"]), (1, "a.py"))
        self.assertIn("shoalscan baseline init", body["command"])
        self.assertNotIn(str(self.base), json.dumps(body), "absolute paths stay on the server")
        self.assertEqual(self.dash.get("/api/config/baseline?target=acme/none", self.sid)[0], 404)

    def test_hand_set_keys_are_kept(self):
        (self.base / "fx").mkdir()
        f = Fixture(self.base / "fx")
        (self.state / scanning.TARGETS_FILE).write_text(
            f'history_db = "{self.db}"\ncooldown_minutes = 3\n\n[[target]]\nname = "acme/hand"\nclone = '
            f'"{f.clone}"\nbranch = "main"\n'
            f'python = "{f.python}"\nconfig = "{self.base}/hand.toml"\n',
            encoding="utf-8",
        )
        (self.state / scanning.TARGETS_FILE).chmod(0o600)
        self.assertEqual(self.post("/api/config/enable", {"name": "acme/hand", "enabled": False})[0], 200)
        data = self.file()
        self.assertEqual(data["cooldown_minutes"], 3)
        self.assertEqual(
            {k: data["target"][0][k] for k in ("clone", "python", "config", "enabled")},
            {"clone": str(f.clone), "python": str(f.python), "config": f"{self.base}/hand.toml", "enabled": False},
        )
        # Its policy file is set by hand, so the page cannot replace it.
        payload = self.target(
            original="acme/hand", name="acme/hand", source={"kind": "clone"}, policy='excludes = ["x"]\n'
        )
        self.assertEqual(self.post("/api/config/target", payload)[0], 400)
        self.assertEqual(
            self.post("/api/config/target", {**payload, "policy": "", "scanners": ["opengrep", "gitleaks"]})[0], 400
        )
        self.assertEqual(self.post("/api/config/target", {**payload, "policy": ""})[0], 200)


class WriteOrderTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name)
        self.state = self.base / "state"
        self.state.mkdir(mode=0o700)
        self.db = self.base / "h.sqlite3"
        history.open_for_write(self.db).close()
        from shoalscan.dashboard.configedit import ConfigEditor

        self.editor = ConfigEditor(self.state, self.db)
        self.request = {
            "original": None,
            "name": "acme/app",
            "source": {"kind": "url", "url": "https://github.com/acme/app.git"},
            "branch": "main",
            "enabled": True,
            "nightly": True,
            "policy": 'excludes = ["vendor"]\n',
            "scanners": None,
        }

    def tearDown(self):
        self._tmp.cleanup()

    def audit_count(self) -> int:
        conn = sqlite3.connect(self.db)
        try:
            return conn.execute("SELECT COUNT(*) FROM config_changes").fetchone()[0]
        finally:
            conn.close()

    def test_audit_first_then_policy_then_targets(self):
        from unittest import mock

        order = []
        real_audit, real_policy, real_save = history.append_config_change, scanning.write_policy, scanning.save_targets
        with (
            mock.patch.object(
                history, "append_config_change", lambda *a, **k: order.append("audit") or real_audit(*a, **k)
            ),
            mock.patch.object(scanning, "write_policy", lambda *a, **k: order.append("policy") or real_policy(*a, **k)),
            mock.patch.object(scanning, "save_targets", lambda *a, **k: order.append("targets") or real_save(*a, **k)),
        ):
            self.assertEqual(self.editor.save_target(dict(self.request), "who")[0], 200)
        self.assertEqual(order, ["audit", "policy", "targets"])

    def test_a_failed_write_takes_the_audit_back_and_restores_the_policy(self):
        from unittest import mock

        self.assertEqual(self.editor.save_target(dict(self.request), "who")[0], 200)
        targets_before = (self.state / scanning.TARGETS_FILE).read_text()
        policy_path = self.state / "targets" / scanning.slug("acme/app") / "shoalscan.toml"
        update = dict(self.request, original="acme/app", branch="develop", policy='excludes = ["dist"]\n')
        with mock.patch.object(scanning, "save_targets", side_effect=OSError("disk full")):
            status, body = self.editor.save_target(update, "who")
            self.assertEqual(status, 500, body)
            self.assertEqual(self.editor.set_enabled({"name": "acme/app", "enabled": False}, "who")[0], 500)
            self.assertEqual(self.editor.remove({"name": "acme/app", "confirm": "acme/app"}, "who")[0], 500)
        self.assertEqual(self.audit_count(), 1, "only the change that was written stays in the audit")
        self.assertEqual((self.state / scanning.TARGETS_FILE).read_text(), targets_before)
        self.assertEqual(policy_path.read_text(), 'excludes = ["vendor"]\n')


@unittest.skipIf(
    tlsgen.find_openssl() is None, "the openssl command is not installed, so no test certificate can be made"
)
class ConfigOffTests(unittest.TestCase):
    def test_the_page_is_off_without_a_targets_file_or_allow_config(self):
        server.Handler._log, log = (lambda self, status: None), server.Handler._log
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "state").mkdir()
            dash = DashboardHarness(base, base / "state", base / "h.sqlite3")
            try:
                sid, csrf = dash.login()
                self.assertEqual(dash.get("/api/config", sid)[0], 404)
                self.assertEqual(dash.post("/api/config/target", {}, sid=sid, csrf=csrf)[0], 404)
                self.assertFalse((base / "state" / scanning.TARGETS_FILE).exists())
            finally:
                dash.close()
                server.Handler._log = log


if __name__ == "__main__":
    unittest.main()
