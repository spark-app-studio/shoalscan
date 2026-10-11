import re
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

import helpers

EXAMPLES = helpers.ROOT / "examples"

STAND_IN_PYTHON = """#!/bin/sh
# Stands in for python3: `python3 -m venv DIR` makes a venv whose python and
# shoalscan are stand-ins too, and records each creation.
if [ "$1" = "-m" ] && [ "$2" = "venv" ]; then
  mkdir -p "$3/bin"
  echo created >> "$LOG"
  printf '#!/bin/sh\\nexit 0\\n' > "$3/bin/python"
  printf '#!/bin/sh\\nexit 0\\n' > "$3/bin/shoalscan"
  chmod +x "$3/bin/python" "$3/bin/shoalscan"
  exit 0
fi
exit 1
"""


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.text = (EXAMPLES / "github-actions" / "shoalscan.yml").read_text(encoding="utf-8")

    def test_sarif_upload_does_not_depend_on_hashfiles_outside_the_workspace(self):
        # hashFiles() cannot see runner.temp, so a condition built on it
        # never let the upload run.
        conditions = [line for line in self.text.splitlines() if line.strip().startswith("if:")]
        self.assertFalse([c for c in conditions if "hashFiles(" in c])
        self.assertIn("steps.sarif.outputs.present == 'true'", self.text)

    def test_actions_are_pinned_by_sha_and_pull_requests_use_the_base_policy(self):
        for ref in re.findall(r"uses:\s*\S+@(\S+)", self.text):
            self.assertRegex(ref, r"^[0-9a-f]{40}$")
        self.assertIn('--policy-ref "$BASE_SHA"', self.text)
        self.assertIn("BASE_SHA: ${{ github.event.pull_request.base.sha }}", self.text)
        self.assertNotIn("base_ref", self.text)


class SelfHostedScriptTests(unittest.TestCase):
    def run_script(self, spec: str, home: Path, bin_dir: Path, log: Path) -> None:
        env = {
            "PATH": f"{bin_dir}:/usr/bin:/bin",
            "HOME": str(home),
            "SHOALSCAN_HOME": str(home / "sh"),
            "SHOALSCAN_OUT": str(home / "out"),
            "SHOALSCAN_SPEC": spec,
            "LOG": str(log),
        }
        subprocess.run(
            ["bash", str(EXAMPLES / "self-hosted.sh"), str(home)], env=env, check=True, capture_output=True, timeout=60
        )

    def test_reinstalls_when_the_spec_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            bin_dir = base / "bin"
            bin_dir.mkdir()
            python = bin_dir / "python3"
            python.write_text(STAND_IN_PYTHON, encoding="utf-8")
            python.chmod(python.stat().st_mode | stat.S_IXUSR)
            log = base / "venv.log"
            self.run_script("shoalscan @ git+https://example.invalid/a@1111", base, bin_dir, log)
            self.run_script("shoalscan @ git+https://example.invalid/a@1111", base, bin_dir, log)
            self.assertEqual(log.read_text().count("created"), 1)
            self.run_script("shoalscan @ git+https://example.invalid/a@2222", base, bin_dir, log)
            self.assertEqual(log.read_text().count("created"), 2)


STAND_IN_SHOALSCAN_PYTHON = """#!/bin/sh
# Stands in for python3: the venv it makes holds a stand-in shoalscan that
# logs its arguments and exits with $SCAN_EXIT for scan, $CHECK_EXIT for check.
if [ "$1" = "-c" ]; then
  case "$2" in
    *">="*) exit "${PY_TOO_OLD:-0}" ;;
    *) echo 3.9; exit 0 ;;
  esac
fi
if [ "$1" = "-m" ] && [ "$2" = "venv" ]; then
  echo created >> "$VENV_LOG"
  mkdir -p "$3/bin"
  printf '#!/bin/sh\\nexit 0\\n' > "$3/bin/python"
  cat > "$3/bin/shoalscan" <<'INNER'
#!/bin/sh
echo "$@" >> "$LOG"
case "$1" in
  scan) exit "${SCAN_EXIT:-0}" ;;
  check) echo 'SHOALSCAN_SUMMARY {}'; exit "${CHECK_EXIT:-0}" ;;
esac
exit 0
INNER
  chmod +x "$3/bin/python" "$3/bin/shoalscan"
  exit 0
fi
exit 1
"""


class ScheduledScanScriptTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name)
        bin_dir = self.base / "bin"
        bin_dir.mkdir()
        python = bin_dir / "python3"
        python.write_text(STAND_IN_SHOALSCAN_PYTHON, encoding="utf-8")
        python.chmod(python.stat().st_mode | stat.S_IXUSR)
        git = ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "init.defaultBranch=main"]
        origin = self.base / "origin"
        subprocess.run([*git, "init", "-q", str(origin)], check=True, timeout=30)
        (origin / "a.py").write_text("x = 1\n", encoding="utf-8")
        subprocess.run([*git, "-C", str(origin), "add", "a.py"], check=True, timeout=30)
        subprocess.run([*git, "-C", str(origin), "commit", "-q", "-m", "one"], check=True, timeout=30)
        self.sha = subprocess.run(
            ["git", "-C", str(origin), "rev-parse", "HEAD"], check=True, capture_output=True, text=True, timeout=30
        ).stdout.strip()
        self.clone = self.base / "clone"
        subprocess.run(["git", "clone", "-q", str(origin), str(self.clone)], check=True, timeout=30)
        (self.clone / "local-change.txt").write_text("keep me\n", encoding="utf-8")
        self.log = self.base / "calls.log"
        self.env = {
            "PATH": f"{bin_dir}:/usr/bin:/bin",
            "HOME": str(self.base),
            "SHOALSCAN_HOME": str(self.base / "sh"),
            "SHOALSCAN_SPEC": "shoalscan @ git+https://example.invalid/a@1111",
            "SHOALSCAN_REPO_NAME": "acme/app",
            "LOG": str(self.log),
            "VENV_LOG": str(self.base / "venv.log"),
        }

    def tearDown(self):
        self._tmp.cleanup()

    def test_an_old_python_is_refused(self):
        old = self.base / "bin" / "old-python"
        old.write_text((self.base / "bin" / "python3").read_text(), encoding="utf-8")
        old.chmod(0o755)
        proc = self.run_script(SHOALSCAN_PYTHON=str(old), PY_TOO_OLD="1")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("needs Python 3.11 or later", proc.stderr)
        self.assertIn("3.9", proc.stderr)
        self.assertFalse((self.base / "venv.log").exists(), "no virtual environment may be made with an old Python")
        self.assertFalse(self.log.exists())

    def test_shoalscan_python_makes_the_venv(self):
        other = self.base / "bin" / "python3.12"
        other.write_text((self.base / "bin" / "python3").read_text(), encoding="utf-8")
        other.chmod(0o755)
        (self.base / "bin" / "python3").write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
        proc = self.run_script(SHOALSCAN_PYTHON=str(other))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual((self.base / "venv.log").read_text().count("created"), 1)

    def run_script(self, **env):
        return subprocess.run(
            ["bash", str(EXAMPLES / "scheduled-scan.sh"), str(self.clone)],
            env={**self.env, **env},
            capture_output=True,
            text=True,
            timeout=60,
        )

    def calls(self):
        return self.log.read_text().splitlines()

    def assert_clone_untouched(self):
        self.assertEqual((self.clone / "local-change.txt").read_text(), "keep me\n")
        worktrees = subprocess.run(
            ["git", "-C", str(self.clone), "worktree", "list"], capture_output=True, text=True, timeout=30
        ).stdout
        self.assertEqual(len(worktrees.splitlines()), 1)

    def test_records_the_default_branch_head_as_a_scheduled_run(self):
        for check_exit in ("0", "1"):
            with self.subTest(check_exit=check_exit):
                self.log.unlink(missing_ok=True)
                proc = self.run_script(CHECK_EXIT=check_exit)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                record = [c for c in self.calls() if c.startswith("record ")]
                self.assertEqual(len(record), 1)
                for part in (
                    "--kind scheduled",
                    f"--commit {self.sha}",
                    "--ref main",
                    "--repo-name acme/app",
                    "--scanned-at 20",
                    f"--check-exit {check_exit}",
                ):
                    self.assertIn(part, record[0])
                self.assert_clone_untouched()

    def test_a_stale_worktree_from_an_interrupted_run_is_pruned(self):
        stale = self.base / "gone"
        subprocess.run(
            ["git", "-C", str(self.clone), "worktree", "add", "-q", "--detach", str(stale), "HEAD"],
            check=True,
            timeout=30,
        )
        for child in sorted(stale.rglob("*"), reverse=True):
            child.unlink() if child.is_file() or child.is_symlink() else child.rmdir()
        stale.rmdir()
        proc = self.run_script()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assert_clone_untouched()

    def test_the_systemd_unit_uses_a_private_tmp(self):
        unit = (EXAMPLES / "scheduled" / "shoalscan-scan.service").read_text(encoding="utf-8")
        self.assertIn("\nPrivateTmp=yes\n", unit)
        self.assertIn("\nNoNewPrivileges=yes\n", unit)

    def test_a_failed_scan_or_broken_check_records_nothing(self):
        for env in ({"SCAN_EXIT": "2"}, {"CHECK_EXIT": "2"}):
            with self.subTest(env=env):
                self.log.unlink(missing_ok=True)
                proc = self.run_script(**env)
                self.assertEqual(proc.returncode, 2)
                self.assertIn("nothing was recorded", proc.stderr)
                self.assertFalse([c for c in self.calls() if c.startswith("record ")])
                self.assert_clone_untouched()


class ProjectUrlTests(unittest.TestCase):
    def test_no_placeholder_project_url_is_left(self):
        tracked = subprocess.run(
            ["git", "-C", str(helpers.ROOT), "ls-files"], capture_output=True, text=True, timeout=30, check=True
        ).stdout.split()
        offenders = []
        for name in tracked:
            path = helpers.ROOT / name
            if name.startswith("tests/") or not path.is_file() or path.stat().st_size > 2_000_000:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            if "github.com/OWNER/" in text:
                offenders.append(name)
        self.assertEqual(offenders, [])
        from shoalscan.dashboard import server

        self.assertEqual(server.PROJECT_URL, "https://github.com/spark-app-studio/shoalscan")


class NightlyTargetsUnitTests(unittest.TestCase):
    def test_the_units_run_the_nightly_worker(self):
        for name in ("local.shoalscan.nightly-targets.plist", "shoalscan-nightly-targets.service"):
            with self.subTest(name=name):
                text = (EXAMPLES / "scheduled" / name).read_text(encoding="utf-8")
                self.assertIn("scanjob", text)
                self.assertIn("--nightly", text)
                self.assertIn("--state-dir", text)
        service = (EXAMPLES / "scheduled" / "shoalscan-nightly-targets.service").read_text(encoding="utf-8")
        self.assertIn("\nPrivateTmp=yes\n", service)
        self.assertIn("\nNoNewPrivileges=yes\n", service)
        self.assertIn(
            "OnCalendar=", (EXAMPLES / "scheduled" / "shoalscan-nightly-targets.timer").read_text(encoding="utf-8")
        )


if __name__ == "__main__":
    unittest.main()
