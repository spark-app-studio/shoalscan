"""A scanner that fails must fail the run. Stand-in executables play Opengrep here."""

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

import helpers

from shoalscan import opengrep
from shoalscan.config import Config, Limits, OpengrepSettings
from shoalscan.errors import ScanError
from shoalscan.scan import FINDINGS_JSON, Tools, run_scan

GOOD_JSON = json.dumps({"version": "1.30.2", "results": [], "errors": [], "paths": {"scanned": ["x"]}})


class StandInScanner:
    """Writes a small shell script that behaves like a misbehaving Opengrep."""

    def __init__(self, directory: Path):
        self.directory = directory

    def make(self, body: str) -> Path:
        path = self.directory / "opengrep"
        path.write_text("#!/bin/sh\n" + body + "\n", encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
        return path


class ExecuteTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.scanner = StandInScanner(self.dir)

    def tearDown(self):
        self.tmp.cleanup()

    def run_standin(self, body: str, timeout: int = 30) -> dict:
        binary = self.scanner.make(body)
        return opengrep.execute([str(binary)], self.dir, timeout)

    def test_exit_0_with_json_is_accepted(self):
        doc = self.run_standin(f"echo '{GOOD_JSON}'; exit 0")
        self.assertEqual(doc["results"], [])

    def test_exit_1_with_json_is_accepted(self):
        self.run_standin(f"echo '{GOOD_JSON}'; exit 1")

    def test_error_exit_fails_even_with_json(self):
        for code in (2, 3, 7, 127):
            with self.subTest(code=code), self.assertRaises(ScanError) as ctx:
                self.run_standin(f"echo '{GOOD_JSON}'; echo 'boom' >&2; exit {code}")
            self.assertIn(f"exit code {code}", str(ctx.exception))

    def test_crash_fails(self):
        with self.assertRaises(ScanError) as ctx:
            self.run_standin("kill -SEGV $$")
        self.assertIn("signal", str(ctx.exception))

    def test_timeout_fails(self):
        with self.assertRaises(ScanError) as ctx:
            self.run_standin("sleep 20", timeout=1)
        self.assertIn("timed out", str(ctx.exception))

    def test_garbage_output_fails(self):
        for body in ("echo 'not json'", "true", "echo '[]'", "echo '{\"results\": []}'"):
            with self.subTest(body=body), self.assertRaises(ScanError):
                self.run_standin(body)

    def test_missing_binary_fails(self):
        with self.assertRaises(ScanError):
            opengrep.execute([str(self.dir / "absent")], self.dir, 5)

    def test_error_level_entry_fails(self):
        doc = self.run_standin(
            "echo '"
            + json.dumps({"results": [], "errors": [{"level": "error", "type": "Rule parse error", "message": "bad"}]})
            + "'"
        )
        with self.assertRaises(ScanError):
            opengrep.check_errors(doc)


class RunScanTests(unittest.TestCase):
    """run_scan must fail closed and never leave an old findings file behind."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.repo = base / "repo"
        self.repo.mkdir()
        (self.repo / "a.py").write_text("x = 1\n", encoding="utf-8")
        self.out = base / "out"
        self.out.mkdir()
        (self.out / FINDINGS_JSON).write_text("{\"stale\": true}", encoding="utf-8")
        self.bin_dir = base / "bin"
        self.bin_dir.mkdir()
        self.scanner = StandInScanner(self.bin_dir)
        self.config = Config(
            opengrep=OpengrepSettings(community_rules=False, shoalscan_rules=True),
            limits=Limits(scan_timeout_seconds=30),
        )

    def tearDown(self):
        self.tmp.cleanup()

    def tools(self, binary: Path, sha=None) -> Tools:
        return Tools(
            opengrep=binary,
            opengrep_sha256=sha,
            opengrep_version="test",
            community_rules=None,
            community_commit=None,
            shoalscan_rules=helpers.ROOT / "rules",
        )

    def test_scanner_error_leaves_no_findings_file(self):
        binary = self.scanner.make("echo 'fatal' >&2; exit 2")
        with self.assertRaises(ScanError):
            run_scan(self.repo, self.config, self.tools(binary), self.out)
        self.assertFalse((self.out / FINDINGS_JSON).exists())

    def test_nothing_scanned_fails(self):
        empty = json.dumps({"results": [], "errors": [], "paths": {"scanned": []}, "time": {"rules": []}})
        binary = self.scanner.make(f"echo '{empty}'")
        with self.assertRaises(ScanError) as ctx:
            run_scan(self.repo, self.config, self.tools(binary), self.out)
        self.assertIn("no files", str(ctx.exception))

    def test_rules_that_ran_must_have_been_staged(self):
        opengrep.check_rules_ran({"time": {"rules": ["shoalscan.a"]}}, {"shoalscan.a", "shoalscan.b"})
        with self.assertRaises(ScanError):
            opengrep.check_rules_ran({"time": {"rules": ["shoalscan.a", "community.extra"]}}, {"shoalscan.a"})
        with self.assertRaises(ScanError):
            opengrep.check_rules_ran({}, {"shoalscan.a"})
        planted = json.dumps(
            {"results": [], "errors": [], "paths": {"scanned": []}, "time": {"rules": ["community.planted.rule"]}}
        )
        binary = self.scanner.make(f"echo '{planted}'")
        with self.assertRaises(ScanError) as ctx:
            run_scan(self.repo, self.config, self.tools(binary), self.out)
        self.assertIn("not selected", str(ctx.exception))

    def test_missing_sarif_output_fails(self):
        binary = self.scanner.make(f"echo '{GOOD_JSON}'")
        with self.assertRaises(ScanError):
            run_scan(self.repo, self.config, self.tools(binary), self.out)
        self.assertFalse((self.out / FINDINGS_JSON).exists())

    def test_binary_not_matching_pin_is_refused(self):
        binary = self.scanner.make(f"echo '{GOOD_JSON}'")
        with self.assertRaises(Exception) as ctx:
            run_scan(self.repo, self.config, self.tools(binary, sha="0" * 64), self.out)
        self.assertIn("SHA-256 mismatch", str(ctx.exception))

    def test_scanner_environment_is_filtered(self):
        os.environ["SEMGREP_RULES"] = "https://example.com/rules.yaml"
        try:
            env = opengrep._scanner_env()
        finally:
            del os.environ["SEMGREP_RULES"]
        self.assertNotIn("SEMGREP_RULES", env)


if __name__ == "__main__":
    unittest.main()
