"""Run Shoalscan's own rule tests (`ruleid:`/`ok:` annotations) with the installed Opengrep."""

import subprocess
import unittest

import helpers

from test_end_to_end import TOOLS, tools_ready


@unittest.skipUnless(tools_ready(), f"Opengrep is not installed in {TOOLS}")
class RuleTests(unittest.TestCase):
    def test_rule_annotations(self):
        proc = subprocess.run(
            [str(TOOLS / "opengrep"), "scan", "--test", "--disable-version-check", str(helpers.ROOT / "rules")],
            capture_output=True, text=True, timeout=300,
        )  # fmt: skip
        output = (proc.stdout + proc.stderr)[-3000:]
        self.assertEqual(proc.returncode, 0, output)
        self.assertIn("All tests passed", output)


if __name__ == "__main__":
    unittest.main()
