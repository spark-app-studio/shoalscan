"""The baseline file `check` reads is left out of the tree binding.

`scan`, then `baseline init`, then `check` must work without a commit in
between: writing the baseline cannot change what was scanned. Every other
change after the scan, the configuration included, must still make `check`
refuse the findings, and under --policy-ref the binding stays fully strict.

The end-to-end tests need git and the installed Opengrep (see
test_end_to_end.py); the others need git only.
"""

import contextlib
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import helpers  # noqa: F401 - puts src/ on the import path
from test_end_to_end import SAMPLE, TOOLS, tools_ready

from shoalscan import gitref
from shoalscan.cli import _same_tree, main
from shoalscan.findings import Finding

HAS_GIT = shutil.which("git") is not None


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-c", "user.name=test", "-c", "user.email=test@example.invalid", "-c", "commit.gpgsign=false", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    ).stdout


@unittest.skipUnless(HAS_GIT and tools_ready(), "needs git and the installed Opengrep")
class BaselineEditAfterScanTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.repo = base / "repo"
        shutil.copytree(SAMPLE, self.repo)
        self.out = base / "out"
        git(self.repo, "init", "-q", "-b", "main")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "base")

    def tearDown(self):
        self.tmp.cleanup()

    def cli(self, *args: str, policy: bool = False) -> tuple[int, str, str]:
        common = ["--repo", str(self.repo), "--out", str(self.out)]
        if args[0] in ("scan", "baseline"):
            common += ["--tools-dir", str(TOOLS)]
        if policy:
            common += ["--policy-ref", "refs/heads/main"]
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main([*args, *common])
        return code, out.getvalue(), err.getvalue()

    def scan(self, policy: bool = False) -> None:
        code, _, err = self.cli("scan", policy=policy)
        self.assertEqual(code, 0, err)

    def baseline_init(self) -> None:
        code, _, err = self.cli("baseline", "init", "--issue", "#1", "--reason", "accepted at adoption")
        self.assertEqual(code, 0, err)

    def assert_check_passes(self) -> None:
        code, out, err = self.cli("check")
        self.assertEqual(code, 0, out + err)

    def assert_check_refuses(self, policy: bool = False) -> str:
        code, _, err = self.cli("check", policy=policy)
        self.assertEqual(code, 2, err)
        return err

    def test_scan_then_baseline_init_then_check_passes_without_a_commit(self):
        self.scan()
        self.baseline_init()
        self.assertIn("?? baseline.toml", git(self.repo, "status", "--porcelain"))
        self.assert_check_passes()
        # A later edit to the baseline alone is accepted too: it is check's input.
        (self.repo / "baseline.toml").write_text((self.repo / "baseline.toml").read_text() + "# reviewed\n")
        self.assert_check_passes()

    def test_editing_another_file_after_the_scan_is_still_refused(self):
        self.scan()
        self.baseline_init()
        self.assert_check_passes()
        (self.repo / "docs" / "notes.md").write_text("edited after the scan\n", encoding="utf-8")
        self.assertIn("do not match the current tree", self.assert_check_refuses())
        # So is a new untracked file next to the baseline.
        (self.repo / "docs" / "notes.md").write_text(
            (SAMPLE / "docs" / "notes.md").read_text(encoding="utf-8"), encoding="utf-8"
        )
        self.assert_check_passes()
        (self.repo / "baseline.toml.orig").write_text("x\n", encoding="utf-8")
        self.assertIn("do not match the current tree", self.assert_check_refuses())

    def test_editing_the_configuration_after_the_scan_is_still_refused(self):
        self.scan()
        self.baseline_init()
        self.assert_check_passes()
        config = self.repo / ".shoalscan.toml"
        config.write_text(config.read_text(encoding="utf-8") + "\n# edited after the scan\n", encoding="utf-8")
        self.assert_check_refuses()

    def test_policy_ref_binding_is_unchanged(self):
        # Without a policy ref, an edit to the baseline alone is accepted ...
        self.baseline_init()
        self.commit_all("baseline")
        self.scan()
        self.append_to_baseline()
        self.assert_check_passes()
        git(self.repo, "checkout", "-q", "--", "baseline.toml")
        # ... under --policy-ref it still makes check refuse the findings.
        git(self.repo, "checkout", "-q", "-b", "change")
        self.scan(policy=True)
        code, out, err = self.cli("check", policy=True)
        self.assertEqual(code, 0, out + err)
        self.append_to_baseline()
        self.assertIn("do not match the current tree", self.assert_check_refuses(policy=True))
        findings = json.loads((self.out / "findings.json").read_text(encoding="utf-8"))
        self.assertNotIn("without_baseline", findings["worktree"])

    def commit_all(self, message: str) -> None:
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", message)

    def append_to_baseline(self) -> None:
        path = self.repo / "baseline.toml"
        path.write_text(path.read_text(encoding="utf-8") + "# edited after the scan\n", encoding="utf-8")


@unittest.skipUnless(HAS_GIT, "needs git")
class BindingPathTests(unittest.TestCase):
    """Which baseline paths may be left out, and what leaving one out still notices."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name).resolve() / "repo"
        (self.repo / "src").mkdir(parents=True)
        (self.repo / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")
        (self.repo / "baseline.toml").write_text("version = 1\n", encoding="utf-8")
        git(self.repo, "init", "-q", "-b", "main")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "base")

    def tearDown(self):
        self.tmp.cleanup()

    def path(self, value) -> str | None:
        return gitref.baseline_binding_path(self.repo, Path(value))

    def test_paths_inside_the_repository(self):
        self.assertEqual(self.path(self.repo / "baseline.toml"), "baseline.toml")
        self.assertEqual(self.path(self.repo / "src" / ".." / "baseline.toml"), "baseline.toml")
        self.assertEqual(self.path(self.repo / "new" / "baseline.toml"), "new/baseline.toml")

    def test_paths_that_are_never_left_out(self):
        self.assertIsNone(self.path(self.repo / ".." / "baseline.toml"))
        self.assertIsNone(self.path(self.repo.parent / "elsewhere.toml"))
        self.assertIsNone(self.path(self.repo))
        self.assertIsNone(self.path(self.repo / "src"))
        self.assertIsNone(self.path(self.repo / ".git" / "config"))
        os.symlink("src/app.py", self.repo / "link.toml")
        self.assertIsNone(self.path(self.repo / "link.toml"))
        os.symlink("src", self.repo / "linkdir")
        self.assertIsNone(self.path(self.repo / "linkdir" / "app.py"))

    def state(self, baseline: str | None = "baseline.toml") -> dict:
        return gitref.worktree_state(self.repo, baseline)

    def test_only_the_baseline_is_left_out(self):
        before = self.state()
        (self.repo / "baseline.toml").write_text("version = 1\n# edited\n", encoding="utf-8")
        after = self.state()
        self.assertNotEqual(before["changes_sha256"], after["changes_sha256"])
        self.assertEqual(before["without_baseline"], after["without_baseline"])
        (self.repo / "src" / "app.py").write_text("x = 2\n", encoding="utf-8")
        self.assertNotEqual(before["without_baseline"], self.state()["without_baseline"])

    def test_a_path_in_another_case_leaves_nothing_out(self):
        # Git matches the path exactly, even with core.ignorecase, so it can never hide another file.
        before = self.state("BASELINE.toml")
        (self.repo / "baseline.toml").write_text("version = 1\n# edited\n", encoding="utf-8")
        self.assertNotEqual(before["without_baseline"], self.state("BASELINE.toml")["without_baseline"])

    def test_a_file_moved_onto_the_baseline_path_is_still_noticed(self):
        before = self.state("src/app.py.toml")
        git(self.repo, "mv", "src/app.py", "src/app.py.toml")
        self.assertNotEqual(before["without_baseline"], self.state("src/app.py.toml")["without_baseline"])

    def test_check_accepts_a_baseline_edit_only_when_the_scan_reported_nothing_in_it(self):
        meta = {"worktree": self.state(), "unscanned": {"skipped": [], "errors": []}, "suppression_list": []}
        (self.repo / "baseline.toml").write_text("version = 1\n# edited\n", encoding="utf-8")
        now = self.state()
        self.assertTrue(_same_tree(meta, now, [], "baseline.toml"))
        # Not when check reads another baseline, or none in the repository.
        self.assertFalse(_same_tree(meta, self.state("other.toml"), [], "other.toml"))
        self.assertFalse(_same_tree(meta, self.state(None), [], None))
        # Not when the scan reported anything in the baseline file: it is then a scanned file like any other.
        finding = Finding(
            tool="opengrep",
            rule="r",
            severity="ERROR",
            path="baseline.toml",
            line=1,
            fingerprint="f" * 16,
            component="",
            message="m",
        )
        self.assertFalse(_same_tree(meta, now, [finding], "baseline.toml"))
        for where in (
            {"unscanned": {"skipped": [{"path": "baseline.toml"}], "errors": []}},
            {"suppression_list": [{"path": "baseline.toml"}]},
        ):
            self.assertFalse(_same_tree({**meta, **where}, now, [], "baseline.toml"))
        # Not when the scan was taken without the baseline left out (as under --policy-ref).
        strict = {k: v for k, v in meta["worktree"].items() if k != "without_baseline"}
        self.assertFalse(_same_tree({**meta, "worktree": strict}, now, [], "baseline.toml"))


if __name__ == "__main__":
    unittest.main()
