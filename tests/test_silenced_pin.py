"""A self-test of the pinned Opengrep: findings an inline comment silenced reach `silenced_list`.

`check --changed-since` fails new code under an old marker only because Opengrep reports silenced results
(`is_ignored`), and it does so only with --sarif-output. A tools.lock bump that changed either would make that
check pass silently; this test fails loudly instead. Needs the installed Opengrep (see test_end_to_end.py).
"""

import contextlib
import io
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from test_end_to_end import TOOLS, tools_ready

from shoalscan import opengrep
from shoalscan.cli import main

RULE = """rules:
- id: no-eval
  pattern: eval(...)
  message: Do not eval.
  languages: [python]
  severity: ERROR
"""
# Spelled in pieces, like Shoalscan's own sources, so this file carries no marker.
MARKER = "no" + "semgrep"


@unittest.skipUnless(shutil.which("git") and tools_ready(), "needs git and the installed Opengrep")
class SilencedPinTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name)
        self.repo = self.base / "repo"
        (self.repo / "rules").mkdir(parents=True)
        (self.repo / "rules" / "eval.yaml").write_text(RULE, encoding="utf-8")
        (self.repo / "app.py").write_text(
            f"def run(x):\n    # {MARKER}: repo.rules.no-eval #12 trusted input\n    return eval(x)\n", encoding="utf-8"
        )

    def tearDown(self):
        self._tmp.cleanup()

    def opengrep(self, *extra: str) -> dict:
        rules = self.repo / "rules" / "eval.yaml"
        proc = subprocess.run(
            [
                str(TOOLS / "opengrep"),
                "scan",
                "--config",
                str(rules),
                "--json",
                "--disable-version-check",
                *extra,
                str(self.repo / "app.py"),
            ],
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
        self.assertIn(proc.returncode, (0, 1), proc.stderr[-2000:])
        return json.loads(proc.stdout)

    def test_the_pinned_opengrep_reports_silenced_results_only_with_sarif_output(self):
        with_sarif = self.opengrep(f"--sarif-output={self.base / 'out.sarif'}")
        self.assertEqual(opengrep.ignored_count(with_sarif), 1)
        (span,) = opengrep.ignored_spans(with_sarif, self.repo)
        self.assertEqual((span["path"], span["start"]), ("app.py", 3))
        # Without --sarif-output the silenced result is not reported at all: Shoalscan must keep passing it.
        self.assertEqual(opengrep.ignored_count(self.opengrep()), 0)
        command = opengrep.build_command(Path("opengrep"), [], self.repo, _Limits(), [], self.base / "x.sarif")
        self.assertTrue(any(arg.startswith("--sarif-output=") for arg in command))

    def test_a_silenced_finding_reaches_silenced_list(self):
        (self.repo / ".shoalscan.toml").write_text(
            '[opengrep]\ncommunity_rules = false\nshoalscan_rules = false\nrule_dirs = ["rules"]\n', encoding="utf-8"
        )
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True, timeout=60)
        out = self.base / "out"
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as err:
            code = main(["scan", "--repo", str(self.repo), "--out", str(out), "--tools-dir", str(TOOLS)])
        self.assertEqual(code, 0, err.getvalue())
        findings = json.loads((out / "findings.json").read_text())
        self.assertEqual(findings["silenced_total"], 1)
        self.assertEqual(
            [(s["tool"], s["rule"], s["path"], s["start"]) for s in findings["silenced_list"]],
            [("opengrep", "repo.rules.no-eval", "app.py", 3)],
        )


class _Limits:
    jobs = 1
    rule_timeout_seconds = 30
    max_target_bytes = 1_000_000


if __name__ == "__main__":
    unittest.main()
