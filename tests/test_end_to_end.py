"""End-to-end: the real, installed Opengrep on the sample repository in tests/data.

Run `shoalscan install` first (or set SHOALSCAN_TOOLS_DIR). Without installed
tools these tests are skipped, and the skip message says so.
"""

import contextlib
import hashlib
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path

import helpers

from shoalscan.cli import main
from shoalscan.lockfile import current_platform, load_lock, sha256_file

TOOLS = helpers.tools_dir()
SAMPLE = helpers.DATA / "sample_repo"


def tools_ready() -> bool:
    binary = TOOLS / "opengrep"
    if not binary.is_file():
        return False
    lock = load_lock(helpers.ROOT / "tools.lock")
    entry = lock.opengrep.get(current_platform())
    return entry is not None and sha256_file(binary) == entry.binary.sha256


@unittest.skipUnless(
    tools_ready(), f"Opengrep is not installed in {TOOLS}; run `shoalscan install` to enable the end-to-end tests"
)
class EndToEndTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.repo = base / "repo"
        shutil.copytree(SAMPLE, self.repo)
        self.out = base / "out"

    def tearDown(self):
        self.tmp.cleanup()

    def cli(self, *args: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(list(args))
        return code, out.getvalue(), err.getvalue()

    def scan(self) -> dict:
        code, out, err = self.cli("scan", "--repo", str(self.repo), "--tools-dir", str(TOOLS), "--out", str(self.out))
        self.assertEqual(code, 0, err)
        return json.loads((self.out / "findings.json").read_text(encoding="utf-8"))

    def check(self) -> tuple[int, dict, str]:
        code, out, err = self.cli("check", "--repo", str(self.repo), "--out", str(self.out), "--no-git")
        line = [x for x in out.splitlines() if x.startswith("SHOALSCAN_SUMMARY ")]
        self.assertEqual(len(line), 1, out + err)
        return code, json.loads(line[0][len("SHOALSCAN_SUMMARY ") :]), out

    def test_scan_baseline_check_cycle(self):
        doc = self.scan()
        # The sample policy's jobs, applied to the matching and to the rule loading alike.
        self.assertEqual(doc["scanners"]["opengrep"]["jobs"], 2)
        self.assertEqual(doc["scanners"]["opengrep"]["python_cpu_count"], 2)
        rules = sorted({(f["rule"], f["path"]) for f in doc["findings"]})
        self.assertIn(("shoalscan.python-tls-verification-disabled", "src/client.py"), rules)
        self.assertIn(("shoalscan.node-tls-verification-disabled", "src/server.js"), rules)
        self.assertIn(("shoalscan.python-secret-in-log", "src/client.py"), rules)
        # The suppressed plain-http URL is silenced and its comment is valid.
        self.assertNotIn(("shoalscan.plain-http-url", "src/client.py"), rules)
        self.assertEqual(doc["suppressions"], {"total": 1, "invalid": 0, "suppressed_findings": 1})
        self.assertTrue(all(f["component"] == "app" for f in doc["findings"]))
        sarif = json.loads((self.out / "findings.sarif").read_text(encoding="utf-8"))
        uris = {
            loc["physicalLocation"]["artifactLocation"]["uri"]
            for run in sarif["runs"]
            for r in run["results"]
            for loc in r["locations"]
        }
        self.assertTrue(uris <= {"src/client.py", "src/server.js"}, uris)

        code, summary, _ = self.check()
        self.assertEqual(code, 1)
        self.assertEqual(summary["new_blocking"], len(doc["findings"]))

        code, out, err = self.cli(
            "baseline",
            "init",
            "--repo",
            str(self.repo),
            "--tools-dir",
            str(TOOLS),
            "--out",
            str(self.out),
            "--issue",
            "#1",
            "--reason",
            "initial baseline",
        )
        self.assertEqual(code, 0, err)
        first = (self.repo / "baseline.toml").read_text(encoding="utf-8")
        code, summary, _ = self.check()
        self.assertEqual((code, summary["result"], summary["baseline_size"]), (0, "pass", len(doc["findings"])))

        # Refuses to overwrite without --force.
        code, _, err = self.cli(
            "baseline",
            "init",
            "--repo",
            str(self.repo),
            "--tools-dir",
            str(TOOLS),
            "--out",
            str(self.out),
            "--issue",
            "#1",
            "--reason",
            "again",
        )
        self.assertEqual(code, 2)
        self.assertIn("--force", err)

        # Shifting every line keeps every fingerprint: the check still passes.
        client = self.repo / "src" / "client.py"
        client.write_text("# header\n\n\n\n" + client.read_text(encoding="utf-8"), encoding="utf-8")
        shifted = self.scan()
        self.assertEqual(
            sorted((f["rule"], f["fingerprint"]) for f in shifted["findings"]),
            sorted((f["rule"], f["fingerprint"]) for f in doc["findings"]),
        )
        self.assertNotEqual(
            sorted(f["line"] for f in shifted["findings"] if f["path"] == "src/client.py"),
            sorted(f["line"] for f in doc["findings"] if f["path"] == "src/client.py"),
        )
        code, summary, _ = self.check()
        self.assertEqual(code, 0)

        # Fixing a finding makes its baseline entry stale, which fails.
        server = self.repo / "src" / "server.js"
        server.write_text(
            server.read_text(encoding="utf-8").replace("rejectUnauthorized: false", "ca: privateCa"), encoding="utf-8"
        )
        self.scan()
        code, summary, out = self.check()
        self.assertEqual((code, summary["stale"]), (1, 1))
        self.assertIn("Stale baseline entries", out)

        # Deterministic baseline: the same scan writes the same file.
        server.write_text((SAMPLE / "src" / "server.js").read_text(encoding="utf-8"), encoding="utf-8")
        code, _, err = self.cli(
            "baseline",
            "init",
            "--repo",
            str(self.repo),
            "--tools-dir",
            str(TOOLS),
            "--out",
            str(self.out),
            "--issue",
            "#1",
            "--reason",
            "initial baseline",
            "--force",
        )
        self.assertEqual(code, 0, err)
        self.assertEqual((self.repo / "baseline.toml").read_text(encoding="utf-8"), first)

    def test_rename_path_follows_a_moved_file(self):
        self.scan()
        code, _, err = self.cli(
            "baseline",
            "init",
            "--repo",
            str(self.repo),
            "--tools-dir",
            str(TOOLS),
            "--out",
            str(self.out),
            "--issue",
            "#1",
            "--reason",
            "initial",
        )
        self.assertEqual(code, 0, err)
        (self.repo / "lib").mkdir()
        (self.repo / "src" / "client.py").rename(self.repo / "lib" / "client.py")
        self.scan()
        code, summary, _ = self.check()
        self.assertEqual(code, 1)
        self.assertGreater(summary["stale"], 0)
        code, out, err = self.cli("baseline", "rename-path", "src/client.py", "lib/client.py", "--repo", str(self.repo))
        self.assertEqual(code, 0, err)
        code, summary, out = self.check()
        self.assertEqual((code, summary["stale"], summary["new"]), (0, 0, 0), out)

    def test_new_finding_and_bad_suppression_fail(self):
        self.scan()
        self.cli(
            "baseline",
            "init",
            "--repo",
            str(self.repo),
            "--tools-dir",
            str(TOOLS),
            "--out",
            str(self.out),
            "--issue",
            "https://tracker.example.org/issues/1",
            "--reason",
            "initial",
        )
        (self.repo / "src" / "new.py").write_text(
            'import requests\nrequests.get("https://example.com", verify=False)  # ' + "no" + "semgrep\n",
            encoding="utf-8",
        )
        doc = self.scan()
        self.assertEqual(doc["suppressions"]["invalid"], 1)
        code, summary, out = self.check()
        self.assertEqual(code, 1)
        self.assertEqual(summary["new_blocking"], 1)
        self.assertIn("shoalscan.suppression-without-rule-and-issue", out)

    def test_check_writes_the_details_behind_its_counts(self):
        doc = self.scan()
        self.assertIn("shoalscan.python-tls-verification-disabled", doc["rule_ids"])
        self.assertTrue({f["rule"] for f in doc["findings"] if f["tool"] == "opengrep"} <= set(doc["rule_ids"]))
        (listed,) = doc["suppression_list"]
        self.assertEqual(
            (listed["path"], listed["line"], listed["issue"], listed["valid"]), ("src/client.py", 15, "#42", True)
        )
        self.assertEqual(listed["rules"][0], "shoalscan.plain-http-url")
        self.cli(
            "baseline",
            "init",
            "--repo",
            str(self.repo),
            "--tools-dir",
            str(TOOLS),
            "--out",
            str(self.out),
            "--issue",
            "#1",
            "--reason",
            "initial",
        )
        (self.repo / "src" / "new.py").write_text(
            'import requests\nrequests.get("https://example.com", verify=False)\n', encoding="utf-8"
        )
        (self.repo / "src" / "client.py").unlink()  # its baseline entries go stale
        self.scan()
        code, summary, _ = self.check()
        self.assertEqual(code, 1)
        details = json.loads((self.out / "check.json").read_text(encoding="utf-8"))
        self.assertEqual(
            details["findings_sha256"], hashlib.sha256((self.out / "findings.json").read_bytes()).hexdigest()
        )
        self.assertEqual(details["summary"], summary)
        self.assertEqual(len(details["new_blocking"]), summary["new_blocking"])
        self.assertEqual([k[2] for k in details["new_blocking"]], ["src/new.py"])
        self.assertEqual(len(details["stale"]), summary["stale"])
        self.assertTrue(all(e["path"] == "src/client.py" and e["issue"] == "#1" for e in details["stale"]))
        # A new scan removes the old details; a broken check writes none.
        self.scan()
        self.assertFalse((self.out / "check.json").exists())

    def write_config(self, extra_top: str = "", opengrep: str = "") -> None:
        (self.repo / ".shoalscan.toml").write_text(
            f'{extra_top}\nbaseline = "baseline.toml"\n[opengrep]\n{opengrep}\n[limits]\nscan_timeout_seconds = '
            "600\njobs = 2\n",
            encoding="utf-8",
        )

    @unittest.skipUnless((TOOLS / "rules" / "opengrep-rules").is_dir(), "community rules are not installed")
    def test_community_categories_and_exclude_rules(self):
        # Default categories: security only.
        self.write_config(opengrep="community_rules = true")
        doc = self.scan()
        rules = {f["rule"] for f in doc["findings"]}
        self.assertIn("community.python.requests.security.disabled-cert-validation", rules)
        self.assertNotIn("community.python.requests.best-practice.use-timeout", rules)
        self.assertGreater(doc["scanners"]["opengrep"]["rules_left_out"], 0)
        self.assertEqual(doc["scanners"]["opengrep"]["community_categories"], ["security"])

        # Adding a category brings its rules in; exclude_rules takes rules out.
        self.write_config(
            opengrep='community_rules = true\ncategories = ["security", "best-practice"]\n'
            'exclude_rules = ["community.python.requests.security.*", "shoalscan.node-tls-verification-disabled"]'
        )
        doc = self.scan()
        rules = {f["rule"] for f in doc["findings"]}
        self.assertIn("community.python.requests.best-practice.use-timeout", rules)
        self.assertNotIn("community.python.requests.security.disabled-cert-validation", rules)
        self.assertNotIn("shoalscan.node-tls-verification-disabled", rules)
        self.assertIn("shoalscan.python-tls-verification-disabled", rules)

    def test_non_blocking_paths(self):
        self.write_config(extra_top='non_blocking_paths = ["src/"]', opengrep="community_rules = false")
        doc = self.scan()
        self.assertTrue(doc["findings"])
        code, summary, out = self.check()
        self.assertEqual((code, summary["new_blocking"]), (0, 0))
        self.assertEqual(summary["new_in_non_blocking_paths"], len(doc["findings"]))
        self.assertIn("New findings in non-blocking paths", out)

    def test_bare_suppression_forms_against_the_real_binary(self):
        marker = "no" + "semgrep"
        (self.repo / "src" / "spaced.py").write_text(
            "import requests\n"
            f'requests.get("https://a.vendor.io", verify=False)  # {marker} : '
            "shoalscan.python-tls-verification-disabled #1\n"
            f'requests.get("https://b.vendor.io", verify=False)  # {marker}:  '
            "shoalscan.python-tls-verification-disabled #1\n"
            f'requests.get("https://c.vendor.io", verify=False)  # {marker}: '
            "shoalscan.python-tls-verification-disabled #1\n",
            encoding="utf-8",
        )
        doc = self.scan()
        spaced = [f for f in doc["findings"] if f["path"] == "src/spaced.py"]
        # Opengrep honours all three as suppressions: the TLS finding is gone on every line.
        self.assertFalse([f for f in spaced if f["rule"] == "shoalscan.python-tls-verification-disabled"])
        # The first two are bare in Opengrep's grammar, and the lint says so.
        lint = sorted(f["line"] for f in spaced if f["rule"] == "shoalscan.suppression-without-rule-and-issue")
        self.assertEqual(lint, [2, 3])
        self.assertTrue(all("bare suppression" in f["message"] for f in spaced))

    def test_non_ascii_next_to_the_marker_against_the_real_binary(self):
        marker = "no" + "semgrep"
        (self.repo / "src" / "accent.py").write_text(
            "import requests\n"
            f'requests.get("https://a.vendor.io", verify=False)  # \u00e9{marker}\n'
            f'requests.get("https://b.vendor.io", verify=False)  # {marker}\u00e9\n',
            encoding="utf-8",
        )
        doc = self.scan()
        found = [f for f in doc["findings"] if f["path"] == "src/accent.py"]
        # Opengrep treats both as bare suppressions ...
        self.assertFalse([f for f in found if f["rule"] == "shoalscan.python-tls-verification-disabled"])
        # ... and so does the lint.
        self.assertEqual(
            sorted(f["line"] for f in found if f["rule"] == "shoalscan.suppression-without-rule-and-issue"), [2, 3]
        )

    def test_long_s_marker_against_the_real_binary(self):
        marker = ("no" + "semgrep").replace("s", "\u017f")
        (self.repo / "src" / "longs.py").write_text(
            "import requests\n"
            f'requests.get("https://a.vendor.io", verify=False)  # {marker}\n'
            f'requests.get("https://b.vendor.io", verify=False)  # {marker.upper()}\n'
            'requests.get("https://c.vendor.io", verify=False)  # no\u212asemgrep\n',
            encoding="utf-8",
        )
        doc = self.scan()
        found = [f for f in doc["findings"] if f["path"] == "src/longs.py"]
        # Opengrep folds the long s to s: lines 2 and 3 are silenced; the
        # Kelvin sign spells no marker, so line 4 is reported.
        tls = sorted(f["line"] for f in found if f["rule"] == "shoalscan.python-tls-verification-disabled")
        self.assertEqual(tls, [4])
        lint = sorted(f["line"] for f in found if f["rule"] == "shoalscan.suppression-without-rule-and-issue")
        self.assertEqual(lint, [2, 3])

    def test_check_outside_git_needs_no_git(self):
        self.scan()
        code, _, err = self.cli("check", "--repo", str(self.repo), "--out", str(self.out))
        self.assertEqual(code, 2)
        self.assertIn("--no-git", err)

    def test_broken_config_exits_2(self):
        (self.repo / ".shoalscan.toml").write_text('blockng = ["ERROR"]\n', encoding="utf-8")
        code, _, err = self.cli("scan", "--repo", str(self.repo), "--tools-dir", str(TOOLS), "--out", str(self.out))
        self.assertEqual(code, 2)
        self.assertIn("unknown keys", err)


if __name__ == "__main__":
    unittest.main()
