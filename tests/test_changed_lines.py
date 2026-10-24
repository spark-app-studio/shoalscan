"""Which lines a change added, and which inline suppressions it added, when the file is not plain text."""

import io
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

import helpers  # noqa: F401 - puts src/ on the import path

from shoalscan import gitref
from shoalscan.cli import _new_suppressions
from shoalscan.suppressions import find_trivy_suppressions

# Spelled in pieces, like Shoalscan's own sources, so this file carries no marker.
TRIVY = "tri" + "vy:ignore:AVD-DS-0002 #12 accepted"


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    ).stdout


def chart(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


class ChangedLinesTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self._tmp.name)
        git(self.repo, "init", "-q", "-b", "main")
        (self.repo / "Dockerfile").write_bytes(b"FROM alpine\nRUN true\n")
        (self.repo / "same.txt").write_text("one\ntwo\n")
        (self.repo / "chart.tgz").write_bytes(chart({"c/templates/a.yaml": b"kind: Pod\n"}))
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "base")
        self.base = git(self.repo, "rev-parse", "HEAD").strip()
        git(self.repo, "checkout", "-q", "-b", "change")

    def tearDown(self):
        self._tmp.cleanup()

    def commit(self) -> None:
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "change")

    def test_a_nul_byte_does_not_hide_the_added_lines_or_a_suppression_on_them(self):
        # The NUL makes git call the file binary; without --text its diff has no lines at all.
        (self.repo / "Dockerfile").write_bytes(b"FROM alpine\nRUN true\n# \x00\nUSER root  # " + TRIVY.encode() + b"\n")
        self.commit()
        added = gitref.added_lines(self.repo, self.base, "Dockerfile")
        self.assertEqual(added, {3, 4})
        found = find_trivy_suppressions(self.repo, ["Dockerfile"], 1024 * 1024)
        listed = [{"path": s.path, "line": s.line, "rules": list(s.rule_ids)} for s in found]
        meta = {"suppressions": {"total": len(listed)}, "suppression_list": listed}
        new = _new_suppressions(meta, {"Dockerfile"}, lambda path: gitref.added_lines(self.repo, self.base, path))
        self.assertEqual([(e["path"], e["line"]) for e in new], [("Dockerfile", 4)])

    def test_a_marker_in_a_changed_chart_archive_is_new(self):
        member = b"kind: Pod\n# " + TRIVY.encode() + b"\n"
        (self.repo / "chart.tgz").write_bytes(chart({"c/templates/a.yaml": member}))
        self.commit()
        found = find_trivy_suppressions(self.repo, ["chart.tgz"], 1024 * 1024)
        self.assertEqual([(s.path, s.line, s.member) for s in found], [("chart.tgz", 2, "c/templates/a.yaml")])
        listed = [{"path": s.path, "line": s.line, "rules": list(s.rule_ids), "member": s.member} for s in found]
        meta = {"suppressions": {"total": 1}, "suppression_list": listed}
        # Whatever lines the archive's (compressed) diff shows, the member's marker counts as new.
        self.assertEqual(len(_new_suppressions(meta, {"chart.tgz"}, lambda path: set())), 1)
        self.assertEqual(_new_suppressions(meta, set(), lambda path: set()), [])

    def test_a_change_with_no_hunk_or_an_empty_diff_counts_the_whole_file(self):
        (self.repo / "same.txt").chmod(0o755)
        self.commit()
        self.assertEqual(gitref.added_lines(self.repo, self.base, "same.txt"), {1, 2, 3})
        # An empty diff for a file the caller says changed is suspicious, so it counts in full too.
        self.assertEqual(gitref.added_lines(self.repo, self.base, "Dockerfile"), {1, 2, 3})

    def test_file_names_are_never_pathspec_magic(self):
        names = [":(exclude)*.py", ":(glob)**", ":/x", ":start.py", ":(icase)A.PY"]
        for name in names:
            (self.repo / name).parent.mkdir(parents=True, exist_ok=True)
            (self.repo / name).write_text("one\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "odd names on the base")
        base = git(self.repo, "rev-parse", "HEAD").strip()
        for name in names:
            (self.repo / name).write_text("one\ntwo\nthree\n")
        (self.repo / ":new(glob)").write_text("a\nb\n")
        self.commit()
        changed = gitref.changed_files(self.repo, base)
        self.assertEqual(sorted(changed), sorted([*names, ":new(glob)"]))
        for name in names:
            with self.subTest(name=name):
                self.assertEqual(gitref.added_lines(self.repo, base, name), {2, 3})
        self.assertEqual(gitref.added_lines(self.repo, base, ":new(glob)"), {1, 2})
        # The tree binding still leaves out only the baseline it names.
        state = gitref.worktree_state(self.repo, ":(exclude)*.py")
        self.assertFalse(state["without_baseline"]["dirty"])


if __name__ == "__main__":
    unittest.main()
