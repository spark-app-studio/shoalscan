"""The scan worker: registered targets only, single flight, timeouts, audit, nightly order."""

import io
import json
import os
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from unittest import mock

import helpers

from shoalscan import history, process, pullrequests, scanjob
from shoalscan.dashboard import scancontrol, scanning
from shoalscan.dashboard.data import Data
from shoalscan.errors import SetupError

# Stands in for the interpreter that runs `python -m shoalscan`. `scan` writes
# an empty findings file tied to the real worktree and policy (or sleeps when
# the `slow` marker exists); everything else is handed to the real Shoalscan.
STAND_IN = """#!{python}
import hashlib, json, os, sys, time
from pathlib import Path
here = Path(__file__).resolve().parent
with open(here / "calls.jsonl", "a") as log:
    log.write(json.dumps([a for a in sys.argv[1:] if a != "-P"]) + "\\n")
args = sys.argv[1:]
if args[:1] == ["-P"]:
    (here / "saw-P").write_text("1")
    args = args[1:]
if args[:3] == ["-m", "shoalscan", "scan"]:
    (here / "scan.pid").write_text(str(os.getpid()))
    (here / "env.json").write_text(json.dumps(dict(os.environ)))
    if (here / "slow").exists():
        time.sleep(60)
    sys.path.insert(0, {src!r})
    from shoalscan.findings import findings_to_json
    from shoalscan.gitref import worktree_state
    opts = dict(zip(args[3::2], args[4::2]))
    repo, out = Path(opts["--repo"]), Path(opts["--out"])
    if (repo / "app.py").exists():
        (here / "seen_app.txt").write_bytes((repo / "app.py").read_bytes())
    config = Path(opts["--config"]) if "--config" in opts else repo / ".shoalscan.toml"
    data = config.read_bytes() if config.is_file() else b""
    with open(here / "seen_config.jsonl", "a") as seen:
        seen.write(json.dumps([str(config), data.decode()]) + "\\n")
    digest = hashlib.sha256(data).hexdigest()
    skipped = [{{"path": "app.py", "reason": "too large"}}] if (here / "skip_app").exists() else []
    meta = {{"policy": {{"ref": None, "commit": None, "config_sha256": digest, "adoption": False}},
            "worktree": worktree_state(repo), "suppressions": {{"total": 0, "invalid": 0, "suppressed_findings": 0}},
            "unscanned": {{"skipped": skipped, "errors": []}}, "scanners": {{}}, "shoalscan_version": "test",
            "suppression_list": [], "silenced_total": 0, "silenced_list": []}}
    (out / "findings.json").write_text(findings_to_json([], meta))
    sys.exit(2 if (here / "scanfail").exists() else 0)
os.execv({python!r}, [{python!r}, *args])
"""


def git(*args, cwd=None):
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        timeout=60,
    )


class Fixture:
    """A state directory with registered targets, an origin repository and clones."""

    def __init__(self, base: Path, targets_toml: str = "", mirror: bool = False):
        self.base = base
        self.state = base / "state"
        self.state.mkdir(mode=0o700)
        self.origin = base / "origin"
        git("init", "-q", "-b", "main", str(self.origin))
        (self.origin / "app.py").write_text("x = 1\n", encoding="utf-8")
        git("add", "app.py", cwd=self.origin)
        git("commit", "-q", "-m", "one", cwd=self.origin)
        self.clone = base / "clone"
        git("clone", "-q", str(self.origin), str(self.clone))
        self.bin = base / "bin"
        self.bin.mkdir()
        self.python = self.bin / "python"
        self.python.write_text(STAND_IN.format(python=sys.executable, src=str(helpers.SRC)), encoding="utf-8")
        self.python.chmod(0o755)
        self.db = base / "history.sqlite3"
        self.write(
            targets_toml
            or f"""
            [[target]]
            name = "acme/app"
            clone = "{self.clone}"
            branch = "main"
            python = "{self.python}"
            nightly = true
            """
        )
        if mirror:
            path = self.state / scanning.SOURCES_FILE
            path.write_text(f'[[mirror]]\nname = "mirror1"\npath = "{self.clone}"\n', encoding="utf-8")
            path.chmod(0o600)

    def write(self, body: str) -> None:
        path = self.state / scanning.TARGETS_FILE
        path.write_text(f'history_db = "{self.db}"\n' + textwrap.dedent(body), encoding="utf-8")
        path.chmod(0o600)

    def targets(self) -> scanning.Targets:
        return scanning.load_targets(self.state)

    def calls(self) -> list[list[str]]:
        path = self.bin / "calls.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def rows(self, sql: str) -> list:
        conn = sqlite3.connect(self.db)
        try:
            return conn.execute(sql).fetchall()
        finally:
            conn.close()


class WorkerTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name)
        self._env = dict(os.environ)
        os.environ["PYTHONPATH"] = str(helpers.SRC)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._env)
        self._tmp.cleanup()


class TargetsFileTests(WorkerTestCase):
    def test_no_file_means_scans_are_off(self):
        self.assertIsNone(scanning.load_targets(self.base))

    def test_a_writable_file_is_refused(self):
        f = Fixture(self.base)
        (f.state / scanning.TARGETS_FILE).chmod(0o620)
        with self.assertRaisesRegex(SetupError, "writable by group or others"):
            f.targets()

    def test_strict_validation(self):
        f = Fixture(self.base)
        bad = {
            "unknown key": f'[[target]]\nname = "a/b"\nclone = "{f.clone}"\nbranch = "main"\nshell = "rm"\n',
            "relative clone": '[[target]]\nname = "a/b"\nclone = "clone"\nbranch = "main"\n',
            "two sources": (
                f'[[target]]\nname = "a/b"\nclone = "{f.clone}"\nsource = "https://github.com/a/b"\nbranch = "main"\n'
            ),
            "config in clone": (
                f'[[target]]\nname = "a/b"\nclone = "{f.clone}"\nbranch = "main"\nconfig = "{f.clone}/x.toml"\n'
            ),
            "path name": f'[[target]]\nname = "../etc"\nclone = "{f.clone}"\nbranch = "main"\n',
            "option name": f'[[target]]\nname = "-x"\nclone = "{f.clone}"\nbranch = "main"\n',
            "markup name": f'[[target]]\nname = "<img src=x onerror=alert(1)>"\nclone = "{f.clone}"\nbranch = "main"\n',
            "newline name": f'[[target]]\nname = "a/b\\n"\nclone = "{f.clone}"\nbranch = "main"\n',
            "option branch": f'[[target]]\nname = "a/b"\nclone = "{f.clone}"\nbranch = "--upload-pack=x"\n',
            "file url": '[[target]]\nname = "a/b"\nsource = "file:///etc"\nbranch = "main"\n',
            "unknown mirror": '[[target]]\nname = "a/b"\nmirror = "nope"\nbranch = "main"\n',
            "timeout": "timeout_minutes = 0\n",
        }
        for label, body in bad.items():
            with self.subTest(label=label):
                f.write(body)
                with self.assertRaises(SetupError):
                    f.targets()


class WorkerTests(WorkerTestCase):
    def test_the_worker_uses_only_registered_values(self):
        f = Fixture(self.base)
        outcome = scanjob.run_one(f.state, f.targets(), "acme/app", scanjob.WHO["dashboard"], io.StringIO())
        self.assertEqual(outcome, "passed")
        calls = f.calls()
        self.assertEqual([c[2] for c in calls], ["scan", "check", "record"])
        record = calls[2]
        opts = dict(zip(record[3::2], record[4::2], strict=True))
        head = subprocess.run(
            ["git", "-C", str(f.clone), "rev-parse", "refs/remotes/origin/main"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        self.assertEqual(
            (opts["--repo-name"], opts["--ref"], opts["--commit"], opts["--kind"], opts["--check-exit"], opts["--db"]),
            ("acme/app", "main", head, "scheduled", "0", str(f.db)),
        )
        # The scan ran in a temporary worktree of the registered clone, which is gone again.
        # The scan ends with a flag that takes no value, so the pairs are uneven.
        scan_repo = Path(dict(zip(calls[0][3::2], calls[0][4::2], strict=False))["--repo"])
        self.assertFalse(scan_repo.exists())
        self.assertNotIn(str(f.clone), json.dumps(calls[0]))
        self.assertEqual(
            len(
                subprocess.run(
                    ["git", "-C", str(f.clone), "worktree", "list"], capture_output=True, text=True
                ).stdout.splitlines()
            ),
            1,
        )
        self.assertIsNone(scanning.lock_holder(f.state))

    def test_an_unregistered_or_injected_name_is_refused(self):
        f = Fixture(self.base)
        for name in ("acme/other", "../acme/app", "--help", "acme/app; rm -rf /"):
            with self.subTest(name=name):
                code = scanjob.main(["--state-dir", str(f.state), "--target=" + name])
                self.assertEqual(code, 2)
        self.assertEqual(f.calls(), [])

    def test_the_audit_row_names_the_run(self):
        f = Fixture(self.base)
        scanjob.run_one(f.state, f.targets(), "acme/app", scanjob.WHO["dashboard"], io.StringIO())
        (trigger,) = f.rows("SELECT target, who, outcome, run_id, finished_at FROM scan_triggers")
        (run_id,) = f.rows("SELECT id FROM runs")[0]
        self.assertEqual(trigger[:4], ("acme/app", "dashboard user", "passed", run_id))
        self.assertTrue(trigger[4])
        status = json.loads((f.state / scanning.STATUS_FILE).read_text())
        self.assertEqual((status["outcome"], status["run_id"]), ("passed", run_id))

    def test_a_timeout_kills_the_scan_and_records_nothing(self):
        f = Fixture(self.base)
        (f.bin / "slow").write_text("1")
        targets = replace(f.targets(), timeout_seconds=2)
        started = time.monotonic()
        outcome = scanjob.run_one(f.state, targets, "acme/app", scanjob.WHO["dashboard"], io.StringIO())
        self.assertEqual(outcome, "timeout")
        self.assertLess(time.monotonic() - started, 30)
        self.assertEqual(f.rows("SELECT COUNT(*) FROM runs"), [(0,)])
        self.assertEqual(f.rows("SELECT outcome FROM scan_triggers"), [("timeout",)])
        pid = int((f.bin / "scan.pid").read_text())
        time.sleep(0.2)
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)
        self.assertNotIn("record", [c[2] for c in f.calls()])
        self.assertIsNone(scanning.lock_holder(f.state))

    def test_a_failed_scan_is_recorded_as_a_scan_error(self):
        f = Fixture(self.base)
        (f.bin / "scanfail").write_text("1")
        outcome = scanjob.run_one(f.state, f.targets(), "acme/app", scanjob.WHO["cli"], io.StringIO())
        self.assertEqual(outcome, "scan_error")
        self.assertEqual(f.rows("SELECT outcome FROM runs"), [("scan_error",)])


class RescanTests(WorkerTestCase):
    def commit_on_origin(self, f: Fixture, text: str) -> None:
        (f.origin / "app.py").write_text(text, encoding="utf-8")
        git("commit", "-q", "-am", text.strip(), cwd=f.origin)

    def test_rescan_commit_replaces_the_right_run(self):
        f = Fixture(self.base)
        scanjob.run_one(f.state, f.targets(), "acme/app", "x", io.StringIO())
        ((first_id, first_commit, first_scanned),) = f.rows("SELECT id, commit_sha, scanned_at FROM runs")
        time.sleep(1.1)  # scan times have one-second resolution: keep the two runs apart
        self.commit_on_origin(f, "x = 2\n")
        scanjob.run_one(f.state, f.targets(), "acme/app", "x", io.StringIO())
        ((second_id, second_commit),) = f.rows(f"SELECT id, commit_sha FROM runs WHERE id != {first_id}")
        self.assertNotEqual(first_commit, second_commit)
        outcome = scanjob.run_one(
            f.state, f.targets(), "acme/app", "dashboard user", io.StringIO(), "rescan-commit", first_id
        )
        self.assertEqual(outcome, "passed")
        runs = {c: (i, t) for c, i, t in f.rows("SELECT commit_sha, id, scanned_at FROM runs")}
        self.assertEqual(len(runs), 2)
        self.assertEqual(runs[second_commit][0], second_id, "the other run is untouched")
        self.assertEqual(runs[first_commit][1], first_scanned, "the rescan keeps the earlier run's time")
        self.assertLess(first_scanned, runs[second_commit][1])
        latest = f.rows("SELECT commit_sha FROM runs WHERE kind = 'scheduled' ORDER BY scanned_at DESC LIMIT 1")[0][0]
        self.assertEqual(latest, second_commit, "the trend's newest point is still the tip")
        trigger = f.rows("SELECT trigger, run_id, outcome FROM scan_triggers ORDER BY id DESC LIMIT 1")[0]
        self.assertEqual(trigger, ("rescan-commit", runs[first_commit][0], "passed"))
        record = [c for c in f.calls() if c[2] == "record"][-1]
        self.assertIn("--commit-rescan", record)
        # The scan ran the old commit, not the branch tip.
        record = [c for c in f.calls() if c[2] == "record"][-1]
        # This record ends with a flag that takes no value, so the pairs are uneven.
        self.assertEqual(dict(zip(record[3::2], record[4::2], strict=False))["--commit"], first_commit)

    def seen_configs(self, f: Fixture) -> list[list[str]]:
        return [json.loads(line) for line in (f.bin / "seen_config.jsonl").read_text().splitlines()]

    def test_the_branch_head_policy_decides_even_for_an_older_commit(self):
        f = Fixture(self.base)
        (f.origin / ".shoalscan.toml").write_text('scanners = ["opengrep", "gitleaks"]\n', encoding="utf-8")
        git("add", ".shoalscan.toml", cwd=f.origin)
        git("commit", "-q", "-m", "policy", cwd=f.origin)
        log = io.StringIO()
        scanjob.run_one(f.state, f.targets(), "acme/app", "x", log)
        ((first_id,),) = f.rows("SELECT id FROM runs")
        self.assertIn("policy: .shoalscan.toml at the head of main", log.getvalue())
        # The commit's own file is not what the scan reads: the head's copy is passed explicitly.
        path, text = self.seen_configs(f)[-1]
        self.assertTrue(path.endswith("branch-policy.toml"), path)
        self.assertEqual(text, 'scanners = ["opengrep", "gitleaks"]\n')
        for call in f.calls()[:2]:
            self.assertIn("--config", call)
        # The head now drops gitleaks; a rescan of the older commit follows the head.
        (f.origin / ".shoalscan.toml").write_text('scanners = ["opengrep"]\n', encoding="utf-8")
        git("commit", "-q", "-am", "narrower", cwd=f.origin)
        time.sleep(1.1)
        scanjob.run_one(f.state, f.targets(), "acme/app", "x", io.StringIO(), "rescan-commit", first_id)
        self.assertEqual(self.seen_configs(f)[-1][1], 'scanners = ["opengrep"]\n')

    def test_the_scan_requires_a_sandbox_and_keeps_its_temporary_files_in_the_work_directory(self):
        f = Fixture(self.base)
        # A work directory a killed worker of this state directory left behind, and one of another's.
        stale = Path(tempfile.mkdtemp(prefix=scanjob.WORK_PREFIX))
        (stale / scanjob.OWNER_FILE).write_text(str(f.state.resolve()))
        other = Path(tempfile.mkdtemp(prefix=scanjob.WORK_PREFIX))
        (other / scanjob.OWNER_FILE).write_text("/somewhere/else")
        try:
            scanjob.run_one(f.state, f.targets(), "acme/app", "x", io.StringIO())
            self.assertFalse(stale.exists())
            self.assertTrue(other.exists())
        finally:
            for d in (stale, other):
                shutil.rmtree(d, ignore_errors=True)
        scan = f.calls()[0]
        self.assertIn("--require-network-sandbox", scan)
        # Children ran with TMPDIR inside the job's work directory, which is gone again.
        work = Path(dict(zip(scan[3::2], scan[4::2], strict=False))["--out"]).parent
        self.assertEqual(json.loads((f.bin / "env.json").read_text())["TMPDIR"], str(work / "tmp"))
        self.assertFalse(work.exists())
        f.write(f"""
            require_network_sandbox = false
            [[target]]
            name = "acme/app"
            clone = "{f.clone}"
            branch = "main"
            python = "{f.python}"
            """)
        self.assertFalse(f.targets().require_network_sandbox)
        scanjob.run_one(f.state, f.targets(), "acme/app", "x", io.StringIO())
        self.assertNotIn("--require-network-sandbox", f.calls()[-3])

    def test_a_head_policy_that_is_not_a_regular_file_is_refused(self):
        f = Fixture(self.base)
        (f.origin / ".shoalscan.toml").symlink_to("/etc/hosts")
        git("add", ".shoalscan.toml", cwd=f.origin)
        git("commit", "-q", "-m", "link", cwd=f.origin)
        log = io.StringIO()
        self.assertEqual(scanjob.run_one(f.state, f.targets(), "acme/app", "x", log), "failed")
        self.assertIn("is not a regular file", log.getvalue())
        self.assertEqual(f.rows("SELECT COUNT(*) FROM runs"), [(0,)])

    def test_a_commit_that_is_gone_records_nothing(self):
        f = Fixture(self.base)
        conn = history.open_for_write(f.db)
        try:
            info = history.RunInfo("acme/app", "main", "f" * 40, "scheduled", "2026-09-01T00:00:00Z")
            run_id = history.record_run(conn, info, [], {}, {"result": "pass", "findings": 0}).run_id
        finally:
            conn.close()
        outcome = scanjob.run_one(
            f.state, f.targets(), "acme/app", "dashboard user", io.StringIO(), "rescan-commit", run_id
        )
        self.assertEqual(outcome, "failed")
        self.assertEqual(f.rows("SELECT COUNT(*) FROM runs"), [(1,)])
        detail = f.rows("SELECT detail FROM scan_triggers")[0][0]
        self.assertIn("no longer in the clone", detail)
        self.assertNotIn("record", [c[2] for c in f.calls()])

    def test_a_run_of_another_repository_is_refused(self):
        f = Fixture(self.base)
        conn = history.open_for_write(f.db)
        try:
            info = history.RunInfo("acme/other", "main", "a" * 40, "scheduled", "2026-09-01T00:00:00Z")
            other = history.record_run(conn, info, [], {}, {"result": "pass", "findings": 0}).run_id
        finally:
            conn.close()
        with self.assertRaisesRegex(SetupError, "has no run"):
            scanjob.run_one(f.state, f.targets(), "acme/app", "dashboard user", io.StringIO(), "rescan-commit", other)
        self.assertEqual(scanjob.main(["--state-dir", str(f.state), "--target=acme/app", "--run-id=-3"]), 2)
        self.assertEqual(f.calls(), [])

    def test_a_pull_request_run_is_not_rescanned_by_commit(self):
        f = Fixture(self.base)
        head = subprocess.run(
            ["git", "-C", str(f.clone), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
        ).stdout.strip()
        conn = history.open_for_write(f.db)
        try:
            pr = history.record_run(
                conn,
                history.RunInfo("acme/app", "refs/pull/4/merge", head, "pr", "2026-09-01T00:00:00Z"),
                [],
                {},
                {"result": "pass", "findings": 0},
            ).run_id
        finally:
            conn.close()
        with self.assertRaisesRegex(SetupError, "only scheduled runs"):
            scanjob.run_one(f.state, f.targets(), "acme/app", "dashboard user", io.StringIO(), "rescan-commit", pr)
        self.assertEqual(f.calls(), [])

    def test_the_trigger_type_is_audited(self):
        f = Fixture(self.base)
        scanjob.run_one(f.state, f.targets(), "acme/app", "dashboard user", io.StringIO(), "rescan")
        scanjob.run_nightly(f.state, f.targets(), io.StringIO(), wait_seconds=1)
        self.assertEqual(f.rows("SELECT trigger FROM scan_triggers ORDER BY id"), [("rescan",), ("nightly",)])


class CloneSizeTests(WorkerTestCase):
    def test_low_disk_space_refuses_the_scan_clearly(self):
        f = Fixture(self.base)
        f.write(
            f'min_free_mb = 10000000\n[[target]]\nname = "acme/app"\nclone = "{f.clone}"\nbranch = "main"\npython = '
            f'"{f.python}"\n'
        )
        self.assertEqual(scanjob.run_one(f.state, f.targets(), "acme/app", "x", io.StringIO()), "failed")
        self.assertIn("not enough free disk space", f.rows("SELECT detail FROM scan_triggers")[0][0])
        self.assertEqual(f.rows("SELECT COUNT(*) FROM runs"), [(0,)])
        self.assertEqual(f.calls(), [])
        self.assertEqual(json.loads((f.state / scanning.STATUS_FILE).read_text())["outcome"], "failed")

    def test_only_the_registered_branch_is_fetched(self):
        f = Fixture(self.base)
        git("checkout", "-q", "-b", "other", cwd=f.origin)
        (f.origin / "other.py").write_text("y = 2\n", encoding="utf-8")
        git("add", "other.py", cwd=f.origin)
        git("commit", "-q", "-m", "other", cwd=f.origin)
        git("checkout", "-q", "main", cwd=f.origin)
        self.assertEqual(scanjob.run_one(f.state, f.targets(), "acme/app", "x", io.StringIO()), "passed")
        refs = subprocess.run(
            ["git", "-C", str(f.clone), "for-each-ref", "--format=%(refname)", "refs/remotes"],
            capture_output=True,
            text=True,
        ).stdout
        self.assertIn("refs/remotes/origin/main", refs)
        self.assertNotIn("refs/remotes/origin/other", refs)

    def test_a_clone_over_its_size_cap_is_not_scanned(self):
        f = Fixture(self.base)
        (f.origin / "big.dat").write_bytes(os.urandom(2 * 1024 * 1024))
        git("add", "big.dat", cwd=f.origin)
        git("commit", "-q", "-m", "big", cwd=f.origin)
        f.write(
            f'[[target]]\nname = "acme/app"\nclone = "{f.clone}"\nbranch = "main"\npython = "{f.python}"\nmax_clone_mb '
            "= 1\n"
        )
        self.assertEqual(scanjob.run_one(f.state, f.targets(), "acme/app", "x", io.StringIO()), "failed")
        self.assertIn("max_clone_mb", f.rows("SELECT detail FROM scan_triggers")[0][0])
        self.assertEqual(f.rows("SELECT COUNT(*) FROM runs"), [(0,)])

    def test_the_clone_size_is_enforced_while_git_fetches(self):
        f = Fixture(self.base)
        real = subprocess.run(["which", "git"], capture_output=True, text=True, check=True).stdout.strip()
        fake_dir = self.base / "slowgit"
        fake_dir.mkdir()
        # A fetch that keeps writing: 3 MB of pack data, then it hangs.
        (fake_dir / "git").write_text(
            "#!/bin/sh\n"
            'case " $* " in *" fetch "*)\n'
            '  clone=""; prev=""; for a in "$@"; do [ "$prev" = "-C" ] && clone="$a"; prev="$a"; done\n'
            '  head -c 3145728 /dev/zero > "$clone/.git/objects/pack/tmp_pack_growing"; sleep 60; exit 0 ;;\n'
            "esac\n"
            f'exec "{real}" "$@"\n',
            encoding="utf-8",
        )
        (fake_dir / "git").chmod(0o755)
        os.environ["PATH"] = f"{fake_dir}:{os.environ['PATH']}"
        f.write(
            f'max_clone_mb = 1\n[[target]]\nname = "acme/app"\nclone = "{f.clone}"\nbranch = "main"\npython = '
            f'"{f.python}"\n'
        )
        self.assertEqual(f.targets().max_clone_mb, 1)
        started = time.monotonic()
        outcome = scanjob.run_one(f.state, f.targets(), "acme/app", "x", io.StringIO())
        self.assertLess(time.monotonic() - started, 20, "the fetch was stopped, not waited for")
        self.assertEqual(outcome, "failed")
        self.assertIn("max_clone_mb", f.rows("SELECT detail FROM scan_triggers")[0][0])
        self.assertFalse(
            (f.clone / ".git" / "objects" / "pack" / "tmp_pack_growing").exists(), "the partial fetch is cleaned up"
        )
        self.assertEqual(f.calls(), [])

    def test_the_default_clone_limit(self):
        f = Fixture(self.base)
        self.assertEqual(f.targets().max_clone_mb, 2048)

    def test_a_url_source_is_cloned_with_one_branch(self):
        f = Fixture(self.base)
        f.write('[[target]]\nname = "acme/web"\nsource = "https://github.com/acme/web.git"\nbranch = "trunk"\n')
        targets = f.targets()
        job = scanjob.Job(f.state, targets, targets.targets["acme/web"], "x", io.StringIO())
        seen = []
        job.git = lambda *args, **kw: seen.append(args) or 1
        with self.assertRaisesRegex(SetupError, "git clone failed"):
            job.prepare_clone()
        job.cleanup()
        self.assertEqual(seen[0][:6], ("clone", "--quiet", "--no-checkout", "--single-branch", "--branch", "trunk"))


class IsolationTests(WorkerTestCase):
    def test_children_start_with_dash_p_and_the_log_is_bounded(self):
        f = Fixture(self.base)
        scanjob.run_one(f.state, f.targets(), "acme/app", "x", io.StringIO())
        self.assertTrue((f.bin / "saw-P").exists(), "the children run python -P")
        targets = f.targets()
        log = io.StringIO()
        job = scanjob.Job(f.state, targets, targets.targets["acme/app"], "x", log)
        try:
            original = scanning.MAX_LOG_BYTES
            scanning.MAX_LOG_BYTES = 300
            for n in range(100):
                job.say(f"line {n} " + "x" * 40)
        finally:
            scanning.MAX_LOG_BYTES = original
            job.cleanup()
        self.assertLess(len(log.getvalue()), 400)
        self.assertIn("the log is full", log.getvalue())

    def test_a_module_planted_in_the_state_directory_is_never_imported(self):
        from shoalscan.dashboard.scancontrol import ScanControl

        f = Fixture(self.base)
        marker = self.base / "planted-ran"
        for package in ("shoalscan", "shoalscan/scanjob"):
            (f.state / package).mkdir(parents=True, exist_ok=True)
        (f.state / "shoalscan" / "__init__.py").write_text(f"open({str(marker)!r}, 'w').write('1')\n", encoding="utf-8")
        (f.state / "shoalscan" / "scanjob.py").write_text(f"open({str(marker)!r}, 'w').write('1')\n", encoding="utf-8")
        control = ScanControl(f.state, f.db)
        control._spawn("acme/app")
        control._worker.wait(timeout=60)
        self.assertFalse(marker.exists(), "the worker imported a module from the state directory")
        self.assertEqual(f.rows("SELECT outcome FROM scan_triggers"), [("passed",)])


class LogTests(WorkerTestCase):
    def test_control_and_escape_sequences_never_reach_the_log(self):
        f = Fixture(self.base)
        log = io.StringIO()
        targets = f.targets()
        job = scanjob.Job(f.state, targets, targets.targets["acme/app"], "x", log)
        try:
            job.say("file \x1b[2J\x1b]0;owned\x07evil\r\nname\x9b31m \u202etxt.exe\tend")
        finally:
            job.cleanup()
        line = log.getvalue().split(" ", 1)[1]
        self.assertEqual(line, "file [2J]0;ownedevilname31m txt.exe end\n")
        self.assertEqual(scanning.sanitise_log(["a\x1b[31mb\u2066c"], None), ["a[31mbc"])


class GitProbeTests(WorkerTestCase):
    def test_the_real_git_honours_the_attribute_source(self):
        self.assertTrue(scanning.git_attr_probe(), "this git must honour GIT_ATTR_SOURCE")

    def test_a_git_that_ignores_it_makes_the_worker_refuse(self):
        f = Fixture(self.base)
        real = subprocess.run(["which", "git"], capture_output=True, text=True, check=True).stdout.strip()
        fake_dir = self.base / "oldgit"
        fake_dir.mkdir()
        calls = self.base / "git-calls"
        fake = fake_dir / "git"
        # Behaves like git, but like git before 2.40 it ignores GIT_ATTR_SOURCE.
        fake.write_text(
            f'#!/bin/sh\necho "$*" >> "{calls}"\nunset GIT_ATTR_SOURCE\nexec "{real}" "$@"\n', encoding="utf-8"
        )
        fake.chmod(0o755)
        os.environ["PATH"] = f"{fake_dir}:{os.environ['PATH']}"
        self.assertFalse(scanning.git_attr_probe())
        outcome = scanjob.run_one(f.state, f.targets(), "acme/app", "x", io.StringIO())
        self.assertEqual(outcome, "failed")
        self.assertEqual(f.rows("SELECT detail FROM scan_triggers")[0][0], scanning.GIT_TOO_OLD)
        made = calls.read_text()
        for operation in ("fetch", "worktree", "clone"):
            self.assertNotIn(operation, made, "nothing may be fetched or checked out")
        self.assertEqual(f.calls(), [])
        self.assertEqual(f.rows("SELECT COUNT(*) FROM runs"), [(0,)])


class GitHardeningTests(WorkerTestCase):
    def test_no_filter_lfs_download_or_hook_runs_during_checkout(self):
        f = Fixture(self.base)
        marks = self.base / "marks"
        marks.mkdir()

        def touch(name):
            return f"sh -c 'touch {marks}/{name}; cat'"

        # The repository asks for filters, an LFS download from a URL of its choosing, and carries an LFS pointer.
        (f.origin / ".gitattributes").write_text(
            "* filter=evil\n*.bin filter=lfs diff=lfs merge=lfs -text\n", encoding="utf-8"
        )
        (f.origin / ".lfsconfig").write_text("[lfs]\n\turl = http://127.0.0.1:9/attacker-lfs\n", encoding="utf-8")
        (f.origin / "big.bin").write_text(
            "version https://git-lfs.github.com/spec/v1\noid sha256:" + "0" * 64 + "\nsize 12345678\n", encoding="utf-8"
        )
        git("add", "-A", cwd=f.origin)
        git("commit", "-q", "-m", "filters", cwd=f.origin)
        # The user's global configuration defines those drivers and a hooks directory.
        home = self.base / "home"
        hooks = home / "hooks"
        hooks.mkdir(parents=True)
        for hook in ("post-checkout", "reference-transaction"):
            (hooks / hook).write_text(f"#!/bin/sh\ntouch {marks}/global-{hook}\n", encoding="utf-8")
            (hooks / hook).chmod(0o755)
        (home / ".gitconfig").write_text(
            f'[filter "evil"]\n\tsmudge = {touch("global-evil-smudge")}\n\tprocess = {touch("global-evil-process")}\n'
            f'[filter "lfs"]\n\tsmudge = {touch("global-lfs-smudge")}\n\tprocess = '
            f"{touch('global-lfs-process')}\n\trequired = true\n"
            f"[core]\n\thooksPath = {hooks}\n",
            encoding="utf-8",
        )
        os.environ["HOME"] = str(home)
        # The clone's own configuration defines the driver too, as required, and has a hook.
        git("-C", str(f.clone), "config", "filter.evil.process", touch("local-evil-process"))
        git("-C", str(f.clone), "config", "filter.evil.required", "true")
        local_hook = f.clone / ".git" / "hooks" / "post-checkout"
        local_hook.write_text(f"#!/bin/sh\ntouch {marks}/local-post-checkout\n", encoding="utf-8")
        local_hook.chmod(0o755)

        log = io.StringIO()
        outcome = scanjob.run_one(f.state, f.targets(), "acme/app", "x", log)
        self.assertEqual(outcome, "passed", log.getvalue())
        self.assertEqual(sorted(p.name for p in marks.iterdir()), [], "no filter, LFS download or hook may run")
        self.assertEqual((f.bin / "seen_app.txt").read_text(), "x = 1\n", "the checkout still worked")


HOLD_LOCK = """
import sys, time
sys.path.insert(0, {src!r})
from pathlib import Path
from shoalscan.dashboard import scanning
got = scanning.acquire_lock(Path({state!r}), sys.argv[1])
print("got" if got else "busy", flush=True)
time.sleep(float(sys.argv[2]))
"""


class LockTests(WorkerTestCase):
    def test_single_flight_in_one_process(self):
        state = self.base
        self.assertIsNone(scanning.lock_holder(state))
        self.assertTrue(scanning.acquire_lock(state, "a"))
        self.assertFalse(scanning.acquire_lock(state, "b"), "the holder keeps the lock")
        self.assertEqual(scanning.lock_holder(state)["target"], "a")
        scanning.release_lock(state)
        self.assertIsNone(scanning.lock_holder(state))
        self.assertTrue(scanning.acquire_lock(state, "c"))
        scanning.release_lock(state)

    def test_parallel_acquisition_from_separate_processes(self):
        script = HOLD_LOCK.format(src=str(helpers.SRC), state=str(self.base))
        procs = [
            subprocess.Popen([sys.executable, "-c", script, f"t{n}", "2"], stdout=subprocess.PIPE, text=True)
            for n in range(6)
        ]
        results = [p.communicate(timeout=60)[0].strip() for p in procs]
        self.assertEqual(sorted(results), ["busy"] * 5 + ["got"], results)
        self.assertIsNone(scanning.lock_holder(self.base), "the lock is free once its holder has gone")

    def test_nightly_waits_for_and_then_skips_a_dashboard_scan(self):
        f = Fixture(self.base)
        script = HOLD_LOCK.format(src=str(helpers.SRC), state=str(f.state))
        holder = subprocess.Popen([sys.executable, "-c", script, "acme/app", "5"], stdout=subprocess.PIPE, text=True)
        try:
            self.assertEqual(holder.stdout.readline().strip(), "got")
            results = scanjob.run_nightly(f.state, f.targets(), io.StringIO(), wait_seconds=1)
            self.assertEqual(results["acme/app"], "skipped: another scan is running")
            self.assertEqual(f.calls(), [])
        finally:
            holder.kill()
            holder.wait()

    def test_a_crashed_worker_leaves_no_lock(self):
        f = Fixture(self.base)
        (f.bin / "slow").write_text("1")
        env = {**os.environ, "PYTHONPATH": str(helpers.SRC)}
        worker = subprocess.Popen(
            [sys.executable, "-m", "shoalscan.scanjob", "--state-dir", str(f.state), "--target", "acme/app"],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        try:
            for _ in range(200):
                if (f.bin / "scan.pid").exists():
                    break
                time.sleep(0.05)
            self.assertEqual(scanning.lock_holder(f.state)["pid"], worker.pid)
            self.assertFalse(scanjob_can_start(f))
            os.kill(worker.pid, signal.SIGKILL)  # a crash: no cleanup runs
            worker.wait()
        finally:
            scan_pid = int((f.bin / "scan.pid").read_text()) if (f.bin / "scan.pid").exists() else None
            if scan_pid:
                try:
                    os.killpg(scan_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        self.assertIsNone(scanning.lock_holder(f.state), "the kernel released the crashed worker's lock")
        (f.bin / "slow").unlink()
        self.assertEqual(scanjob.run_one(f.state, f.targets(), "acme/app", scanjob.WHO["cli"], io.StringIO()), "passed")
        # The next worker swept the crashed one's work directory.
        owner = str(f.state.resolve())
        left = [
            d
            for d in Path(tempfile.gettempdir()).glob(scanjob.WORK_PREFIX + "*")
            if (d / scanjob.OWNER_FILE).is_file() and (d / scanjob.OWNER_FILE).read_text() == owner
        ]
        self.assertEqual(left, [])


def scanjob_can_start(f: Fixture) -> bool:
    try:
        scanjob.run_one(f.state, f.targets(), "acme/app", scanjob.WHO["cli"], io.StringIO())
    except SetupError:
        return False
    return True


class NightlyTests(WorkerTestCase):
    def test_nightly_order_and_skips(self):
        f = Fixture(self.base, mirror=True)
        f.write(f"""
            [[target]]
            name = "acme/first"
            clone = "{f.clone}"
            branch = "main"
            python = "{f.python}"
            nightly = true

            [[target]]
            name = "acme/disabled"
            clone = "{f.clone}"
            branch = "main"
            python = "{f.python}"
            nightly = true
            enabled = false

            [[target]]
            name = "acme/daytime"
            clone = "{f.clone}"
            branch = "main"
            python = "{f.python}"

            [[target]]
            name = "acme/mirrored"
            mirror = "mirror1"
            branch = "main"
            python = "{f.python}"
            nightly = true
            """)
        results = scanjob.run_nightly(f.state, f.targets(), io.StringIO(), wait_seconds=1)
        self.assertEqual(list(results), ["acme/first", "acme/disabled", "acme/daytime", "acme/mirrored"])
        self.assertEqual(results["acme/first"], "passed")
        self.assertEqual(results["acme/disabled"], "skipped: disabled")
        self.assertEqual(results["acme/daytime"], "skipped: not nightly")
        self.assertEqual(results["acme/mirrored"], "passed")
        names = [dict(zip(c[3::2], c[4::2], strict=True))["--repo-name"] for c in f.calls() if c[2] == "record"]
        self.assertEqual(names, ["acme/first", "acme/mirrored"])
        self.assertEqual(f.rows("SELECT who FROM scan_triggers"), [("nightly job",), ("nightly job",)])


def rev(repo: Path, ref: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), "rev-parse", ref], capture_output=True, text=True, check=True, timeout=60
    ).stdout.strip()


def permissive_pairs(job, admin_fetch: bool = False):
    """The worker's git settings, with the file protocol allowed: the tests' origin is a local repository."""
    pairs = scanning.GIT_ADMIN_FETCH if admin_fetch else scanning.GIT_HARDENED + scanning.GIT_URL_ONLY
    kept = tuple(p for p in pairs if p[0] not in ("protocol.file.allow", "protocol.allow"))
    return (*kept, ("protocol.allow", "always"))


class PullRequestTests(WorkerTestCase):
    """`scanjob --pull-requests`: the listing, dedupe, limits, failing closed, and the policy from the base."""

    def setUp(self):
        super().setUp()
        self.f = Fixture(self.base)
        f = self.f
        # The targets are https sources, as pull requests need; here the origin is a local repository, so these
        # tests alone let git use the file protocol too.
        patcher = mock.patch.object(scanjob.Job, "git_pairs", permissive_pairs)
        patcher.start()
        self.addCleanup(patcher.stop)
        (f.origin / ".shoalscan.toml").write_text("# BASE POLICY\n", encoding="utf-8")
        git("add", ".shoalscan.toml", cwd=f.origin)
        git("commit", "-q", "-m", "policy", cwd=f.origin)
        self.base_head = rev(f.origin, "HEAD")
        self.pr7 = self.open_pull_request(7, "x = 7  # pull request\n")

    def open_pull_request(self, number: int, app: str, merge_ref: bool = True) -> str:
        """A pull request on the origin, as GitHub keeps one: refs/pull/N/head, and refs/pull/N/merge while open.
        The change also tries to relax its own policy."""
        f = self.f
        git("checkout", "-q", "-b", f"pr{number}", "main", cwd=f.origin)
        (f.origin / "app.py").write_text(app, encoding="utf-8")
        (f.origin / ".shoalscan.toml").write_text("# PR POLICY\nscanners = []\n", encoding="utf-8")
        git("commit", "-q", "-am", f"pull request {number}", cwd=f.origin)
        head = rev(f.origin, "HEAD")
        git("checkout", "-q", "main", cwd=f.origin)
        git("branch", "-q", "-D", f"pr{number}", cwd=f.origin)
        git("update-ref", f"refs/pull/{number}/head", head, cwd=f.origin)
        if merge_ref:
            git("update-ref", f"refs/pull/{number}/merge", head, cwd=f.origin)
        return head

    def targets(self, **top) -> scanning.Targets:
        targets = self.f.targets()
        target = replace(
            targets.targets["acme/app"], kind="url", source=self.f.origin.as_uri(), clone=None, pull_requests=True
        )
        return replace(targets, targets={"acme/app": target}, **top)

    @property
    def clone(self) -> Path:
        targets = self.targets()
        return targets.clone_dir(targets.targets["acme/app"])

    def discover(self, targets, target):
        # The real listing of the origin, as `git ls-remote` shows it (the origin is local here, not https).
        return pullrequests.discover(["git"], dict(os.environ), str(self.f.origin), target.branch, 30)

    def poll(self, targets=None, discover=None) -> dict:
        targets = targets or self.targets()
        return scanjob.run_pull_requests(
            self.f.state, targets, io.StringIO(), wait_seconds=1, discover=discover or self.discover
        )

    def test_a_pull_request_is_scanned_with_the_base_policy_and_recorded_as_a_pr_run(self):
        f = self.f
        results = self.poll()
        self.assertEqual(results["acme/app#7"], "passed")
        self.assertTrue(results["acme/app"].startswith("listed: 1 to scan"), results)
        self.assertEqual(f.rows("SELECT kind, ref, commit_sha FROM runs"), [("pr", "refs/pull/7/head", self.pr7)])
        scan, check, record = f.calls()
        self.assertEqual([scan[2], check[2], record[2]], ["scan", "check", "record"])
        # The pull request's code was scanned, with the policy at the head of main, never the change's own.
        self.assertEqual((f.bin / "seen_app.txt").read_text(), "x = 7  # pull request\n")
        seen = json.loads((f.bin / "seen_config.jsonl").read_text().splitlines()[-1])
        self.assertEqual(seen[1], "# BASE POLICY\n")
        self.assertEqual(scan[scan.index("--rules-commit") + 1], self.base_head)
        self.assertEqual(check[check.index("--changed-since") + 1], self.base_head)
        baseline = Path(check[check.index("--baseline") + 1])
        self.assertTrue(baseline.is_relative_to(f.state), baseline)
        opts = dict(zip(record[3::2], record[4::2], strict=False))
        self.assertEqual((opts["--kind"], opts["--ref"], opts["--commit"]), ("pr", "refs/pull/7/head", self.pr7))
        # The pull request never entered the branch clone: no ref, no branch, not even its objects.
        refs = subprocess.run(
            ["git", "-C", str(self.clone), "for-each-ref", "--format=%(refname)"], capture_output=True, text=True
        ).stdout
        self.assertNotIn("pull", refs)
        missing = subprocess.run(
            ["git", "-C", str(self.clone), "cat-file", "-e", f"{self.pr7}^{{commit}}"], capture_output=True
        )
        self.assertNotEqual(missing.returncode, 0)
        (trigger,) = f.rows("SELECT who, trigger, outcome, detail FROM scan_triggers")
        self.assertEqual(trigger[:3], ("pull-request poll", "pull-request", "passed"))
        self.assertEqual(trigger[3], f"pull request #7 at {self.pr7[:12]}")
        self.assertIsNone(scanning.lock_holder(f.state))

    def test_a_registered_policy_decides_for_pull_requests_too(self):
        f = self.f
        targets = self.targets()
        scanning.write_policy(targets, targets.targets["acme/app"], "# MANAGED POLICY\n")
        self.assertEqual(self.poll(targets)["acme/app#7"], "passed")
        seen = json.loads((f.bin / "seen_config.jsonl").read_text().splitlines()[-1])
        self.assertEqual(seen[1], "# MANAGED POLICY\n")

    def test_the_real_check_fails_a_changed_file_that_was_not_scanned(self):
        f = self.f
        # The stand-in scan reports app.py as skipped. The pull request changed it since the merge base, so the
        # real check fails the change; a scheduled scan of main only reports it.
        (f.bin / "skip_app").write_text("1")
        self.assertEqual(self.poll()["acme/app#7"], "blocked")
        self.assertEqual(f.rows("SELECT kind, changed_unscanned FROM runs"), [("pr", 1)])
        self.assertEqual(scanjob.run_one(f.state, f.targets(), "acme/app", "x", io.StringIO()), "passed")
        self.assertEqual(f.rows("SELECT kind, changed_unscanned FROM runs ORDER BY id"), [("pr", 1), ("scheduled", 0)])

    def test_a_head_with_a_recorded_run_is_not_scanned_again_and_polls_wait_out_the_cooldown(self):
        f = self.f
        self.assertEqual(self.poll()["acme/app#7"], "passed")
        again = self.poll()
        self.assertTrue(again["acme/app"].startswith("skipped: cooldown"), again)
        self.assertNotIn("acme/app#7", again)
        again = self.poll(self.targets(cooldown_seconds=0))
        self.assertEqual(again["acme/app"], "listed: 0 to scan, 1 already scanned, 0 over max_pull_requests")
        self.assertEqual(len([c for c in f.calls() if c[2] == "scan"]), 1)
        # A new head of the same pull request waits an hour since the pull request's last scan, then is scanned.
        self.pr7 = self.open_pull_request(7, "x = 77\n")
        self.assertTrue(self.poll(self.targets(cooldown_seconds=0))["acme/app#7"].startswith("deferred: this pull"))
        with mock.patch.object(pullrequests, "PER_PULL_INTERVAL", timedelta(0)):
            self.assertEqual(self.poll(self.targets(cooldown_seconds=0))["acme/app#7"], "passed")
        self.assertEqual(len(f.rows("SELECT id FROM runs WHERE kind = 'pr'")), 2)

    def test_a_pull_request_without_a_merge_ref_is_not_scanned(self):
        f = self.f
        git("update-ref", "-d", "refs/pull/7/merge", cwd=f.origin)
        results = self.poll()
        self.assertEqual(results["acme/app"], "listed: 0 to scan, 0 already scanned, 0 over max_pull_requests")
        self.assertEqual(f.calls(), [])

    def test_a_failed_listing_is_a_scan_error_never_nothing_to_scan(self):
        f = self.f

        def broken(targets, target):
            raise pullrequests.DiscoveryError("git ls-remote failed (exit 128): fatal: unable to access")

        results = self.poll(discover=broken)
        self.assertTrue(results["acme/app"].startswith("scan_error: pull-request discovery failed"), results)
        self.assertFalse(scanjob.poll_ok(results["acme/app"]))
        self.assertEqual(f.calls(), [])
        (row,) = f.rows("SELECT target, who, trigger, outcome, run_id, detail FROM scan_triggers")
        self.assertEqual(row[:5], ("acme/app", "pull-request poll", "pull-request", "scan_error", None))
        self.assertIn("unable to access", row[5])

    def test_an_error_text_from_the_remote_cannot_drive_the_terminal(self):
        def hostile(targets, target):
            raise pullrequests.DiscoveryError("fatal: \x1b]0;owned\x07remote said \x1b[2Jno\u202e")

        log = io.StringIO()
        scanjob.run_pull_requests(self.f.state, self.targets(), log, wait_seconds=1, discover=hostile)
        self.assertIn("remote said [2Jno", log.getvalue())
        self.assertNotIn("\x1b", log.getvalue())
        self.assertNotIn("\u202e", log.getvalue())

    def test_a_listing_that_does_not_show_the_branch_is_a_scan_error(self):
        def elsewhere(targets, target):
            return pullrequests.discover(["git"], dict(os.environ), str(self.f.origin), "no-such-branch", 30)

        results = self.poll(discover=elsewhere)
        self.assertIn("does not show the branch", results["acme/app"])
        self.assertEqual(self.f.calls(), [])

    def test_the_command_line_exits_non_zero_when_the_listing_fails(self):
        f = self.f
        f.write(
            f'[[target]]\nname = "acme/web"\nsource = "https://github.com/acme/web.git"\nbranch = "main"\n'
            f'pull_requests = true\npython = "{f.python}"\n'
        )
        failure = pullrequests.DiscoveryError("git ls-remote did not finish within 300 seconds")
        with mock.patch.object(scanjob, "discover_pull_requests", side_effect=failure), mock.patch("sys.stdout"):
            code = scanjob.main(["--pull-requests", "--state-dir", str(f.state)])
        self.assertEqual(code, 1)
        self.assertEqual(f.rows("SELECT target, outcome FROM scan_triggers"), [("acme/web", "scan_error")])
        self.assertFalse((f.state / "clones").exists())

    def test_a_pull_request_that_moved_after_the_listing_is_scanned_at_its_fetched_head(self):
        f = self.f
        # The listing shows an older head; by the fetch the pull request has moved to pr7.
        stale = pullrequests.Listing(self.base_head, {7: pullrequests.PullRequest(7, self.base_head, True)})
        targets = self.targets(cooldown_seconds=0)
        results = self.poll(targets, discover=lambda targets, target: stale)
        self.assertEqual(results["acme/app#7"], "passed")
        self.assertEqual(f.rows("SELECT ref, commit_sha FROM runs"), [("refs/pull/7/head", self.pr7)])
        (detail,) = f.rows("SELECT detail FROM scan_triggers")[0]
        self.assertEqual(detail, f"pull request #7 at {self.pr7[:12]}")
        # The attempt counts against the pull request's hourly limit, whatever the listing says next.
        state = json.loads((f.state / "pull_requests" / f"{scanning.slug('acme/app')}.json").read_text())
        self.assertIn("7", state["attempts"])
        again = self.poll(targets, discover=lambda targets, target: stale)
        self.assertTrue(again["acme/app#7"].startswith("deferred: this pull request was scanned"), again)

    def test_the_hourly_limit_and_the_per_poll_cap(self):
        f = self.f
        self.open_pull_request(8, "x = 8\n")
        self.open_pull_request(9, "x = 9\n")
        results = self.poll(self.targets(max_pull_requests=2, max_pr_scans_per_hour=1, max_scans_per_hour=1))
        # Never-scanned pull requests, lowest number first: #7 is scanned, #8 waits for the hourly limit, #9 is
        # over the cap.
        self.assertEqual(results["acme/app#7"], "passed")
        self.assertTrue(results["acme/app#8"].startswith("deferred: the hourly limit"), results)
        self.assertTrue(results["acme/app#9"].startswith("deferred: over max_pull_requests"), results)
        self.assertTrue(all(scanjob.poll_ok(o) for o in results.values()), results)
        self.assertEqual(f.rows("SELECT ref FROM runs"), [("refs/pull/7/head",)])
        # Pull-request scans have a budget of their own: the dashboard's is untouched.
        requests = scanning.read_requests(f.state)
        self.assertEqual((len(requests["pr_recent"]), len(requests["recent"])), (1, 0))
        control = scancontrol.ScanControl(f.state, f.db)
        self.assertEqual(control.global_remaining(self.targets(max_scans_per_hour=1)), 0)

    def test_disabled_targets_and_targets_without_pull_requests_are_left_alone(self):
        targets = self.targets()
        disabled = replace(targets, targets={"acme/app": replace(targets.targets["acme/app"], enabled=False)})
        self.assertEqual(self.poll(disabled), {"acme/app": "skipped: disabled"})
        self.assertEqual(self.poll(self.f.targets()), {})
        self.assertEqual(self.f.calls(), [])

    def test_discovery_and_fetches_never_see_the_home_directory(self):
        f = self.f
        seen = {}

        def fake_discover(git_argv, env, source, branch, timeout):
            seen["discover"] = env
            raise pullrequests.DiscoveryError("stop here")

        f.write('[[target]]\nname = "acme/web"\nsource = "https://github.com/acme/web.git"\nbranch = "main"\n')
        targets = f.targets()
        target = replace(targets.targets["acme/web"], pull_requests=True)
        with mock.patch.object(pullrequests, "discover", side_effect=fake_discover):
            with self.assertRaises(pullrequests.DiscoveryError):
                scanjob.discover_pull_requests(targets, target)
        self.assertEqual(seen["discover"]["HOME"], scanjob.NO_HOME)
        self.assertNotIn("XDG_CONFIG_HOME", seen["discover"])
        self.assertEqual(seen["discover"]["GIT_CONFIG_GLOBAL"], "/dev/null")
        job = scanjob.Job(f.state, targets, target, "x", io.StringIO())
        try:
            job.run = lambda argv, **kw: seen.setdefault("git", kw["env"]) and 0
            job.git("fetch", "origin")
            self.assertEqual(seen["git"]["HOME"], scanjob.NO_HOME)
        finally:
            job.cleanup()

    def test_a_pull_request_with_too_many_objects_is_stopped_and_the_clone_is_untouched(self):
        f = self.f
        git("checkout", "-q", "-b", "big", "main", cwd=f.origin)
        (f.origin / "noise.bin").write_bytes(os.urandom(3 * 1024 * 1024))  # does not compress
        git("add", "noise.bin", cwd=f.origin)
        git("commit", "-q", "-m", "big", cwd=f.origin)
        big = rev(f.origin, "HEAD")
        git("checkout", "-q", "main", cwd=f.origin)
        git("update-ref", "refs/pull/8/head", big, cwd=f.origin)
        git("update-ref", "refs/pull/8/merge", big, cwd=f.origin)
        targets = self.targets()
        targets = replace(targets, targets={"acme/app": replace(targets.targets["acme/app"], max_clone_mb=1)})
        results = self.poll(targets)
        self.assertNotIn(results["acme/app#8"], ("passed", "blocked"))
        self.assertEqual(results["acme/app#7"], "passed")
        detail = [r[0] for r in f.rows("SELECT detail FROM scan_triggers") if r[0] and "#8" in r[0]]
        self.assertIn("needs more than max_clone_mb", detail[0])
        # The branch clone is still there, still small, and still scans.
        self.assertTrue((self.clone / "HEAD").is_file() or (self.clone / ".git").is_dir())
        self.assertLess(scanjob.tree_size(self.clone), 1024 * 1024)
        self.assertEqual(scanjob.run_one(f.state, targets, "acme/app", "x", io.StringIO()), "passed")

    def pull_request_with(self, number: int, files: dict) -> str:
        f = self.f
        git("checkout", "-q", "-b", f"files{number}", "main", cwd=f.origin)
        for name, data in files.items():
            (f.origin / name).parent.mkdir(parents=True, exist_ok=True)
            (f.origin / name).write_bytes(data)
            git("add", name, cwd=f.origin)
        git("commit", "-q", "-m", f"files {number}", cwd=f.origin)
        head = rev(f.origin, "HEAD")
        git("checkout", "-q", "main", cwd=f.origin)
        git("update-ref", f"refs/pull/{number}/head", head, cwd=f.origin)
        git("update-ref", f"refs/pull/{number}/merge", head, cwd=f.origin)
        return head

    def checkout_refusal(self, results: dict, number: int) -> str:
        self.assertNotIn(results[f"acme/app#{number}"], ("passed", "blocked"))
        (detail,) = [r[0] for r in self.f.rows("SELECT detail FROM scan_triggers") if r[0] and f"#{number} " in r[0]]
        return detail

    def test_a_highly_compressible_pull_request_is_refused_before_it_is_checked_out(self):
        # 3 MB of zeros compress to a few KB: within max_clone_mb, but the checkout would be large.
        self.pull_request_with(8, {"zeros.bin": bytes(3 * 1024 * 1024)})
        targets = replace(self.targets(), max_checkout_mb=1)
        targets = replace(targets, targets={"acme/app": replace(targets.targets["acme/app"], max_clone_mb=1)})
        started = []
        real_run = scanjob.Job.run

        def spy(job, argv, **kw):
            if "worktree" in argv and "add" in argv and "pull.git" in " ".join(argv):
                started.append(argv)
            return real_run(job, argv, **kw)

        with mock.patch.object(scanjob.Job, "run", spy):
            results = self.poll(targets)
        self.assertIn("would be 3 MB, more than max_checkout_mb (1 MB)", self.checkout_refusal(results, 8))
        # #8 was never checked out; #7 (small) was.
        self.assertEqual(len(started), 1)
        self.assertEqual(results["acme/app#7"], "passed")
        # The refused attempt ran no scan, so it gave its place in max_pr_scans_per_hour back.
        self.assertEqual(len(scanning.read_requests(self.f.state)["pr_recent"]), 1)

    def test_too_many_files_or_too_deep_a_path_is_refused(self):
        self.pull_request_with(8, {f"many/{n}.txt": b"x" for n in range(5)})
        self.pull_request_with(9, {"/".join(["d"] * 70) + "/deep.txt": b"x"})
        results = self.poll(replace(self.targets(), max_checkout_files=4))
        self.assertIn("more than max_checkout_files (4)", self.checkout_refusal(results, 8))
        self.assertIn("deeper than 64 directories", self.checkout_refusal(results, 9))

    def test_the_checkout_is_also_measured_while_and_after_git_writes_it(self):
        self.pull_request_with(8, {"zeros.bin": bytes(3 * 1024 * 1024)})
        with mock.patch.object(scanjob.Job, "check_checkout", return_value=0):
            results = self.poll(replace(self.targets(), max_checkout_mb=1))
        self.assertIn("grew to more than max_checkout_mb", self.checkout_refusal(results, 8))

    def test_the_room_for_the_checkout_counts_whole_blocks_and_each_file(self):
        # 2,000 one-byte files: 2 KB of content, but about 16 MB on disk, twice.
        self.pull_request_with(8, {f"tiny/{n}.txt": b"x" for n in range(2000)})
        usage = mock.Mock(free=(100 + 10) * 1024 * 1024)
        with (
            mock.patch.object(scanjob, "check_free_space"),
            mock.patch.object(scanjob.shutil, "disk_usage", return_value=usage),
        ):
            results = self.poll(replace(self.targets(), min_free_mb=100))
        self.assertIn("16 MB on disk twice", self.checkout_refusal(results, 8))

    def test_the_checkout_needs_room_for_the_gitleaks_copy(self):
        self.pull_request_with(8, {"zeros.bin": bytes(3 * 1024 * 1024)})
        # Room for min_free_mb and one copy of the 3 MB checkout, not two.
        usage = mock.Mock(free=(100 + 4) * 1024 * 1024)
        with (
            mock.patch.object(scanjob, "check_free_space"),
            mock.patch.object(scanjob.shutil, "disk_usage", return_value=usage),
        ):
            results = self.poll(replace(self.targets(), min_free_mb=100))
        self.assertIn("twice (for the Gitleaks staging copy)", self.checkout_refusal(results, 8))

    def test_a_failed_or_timed_out_scan_is_recorded_as_a_scan_error_and_not_retried(self):
        f = self.f
        (f.bin / "slow").write_text("1")
        targets = self.targets(timeout_seconds=2, cooldown_seconds=0)
        results = self.poll(targets)
        self.assertEqual(results["acme/app#7"], "timeout")
        self.assertFalse(scanjob.poll_ok(results["acme/app#7"]))
        (run,) = f.rows("SELECT id, kind, ref, commit_sha, outcome FROM runs")
        self.assertEqual(run[1:], ("pr", "refs/pull/7/head", self.pr7, "scan_error"))
        (trigger,) = f.rows("SELECT outcome, run_id, detail FROM scan_triggers")
        self.assertEqual(trigger[:2], ("timeout", run[0]))
        self.assertIn("recorded as a scan error", trigger[2])
        # The next poll does not spend its budget on the same head again.
        (f.bin / "slow").unlink()
        again = self.poll(targets)
        self.assertTrue(again["acme/app#7"].startswith("deferred: its last scan was a scan error"), again)
        self.assertEqual(len([c for c in f.calls() if c[2] == "scan"]), 1)
        # The Runs page shows the failure and why.
        data = Data(history.open_read_only(f.db))
        try:
            (item,) = data.pull_requests(data.repo_id("acme/app"))["items"]
        finally:
            data.conn.close()
        self.assertEqual((item["number"], item["latest"]["outcome"]), (7, "scan_error"))
        self.assertIn("stopped after", item["error"])
        # A size refusal is recorded the same way.
        self.pull_request_with(8, {"zeros.bin": bytes(3 * 1024 * 1024)})
        self.poll(replace(targets, max_checkout_mb=1, timeout_seconds=60))
        self.assertEqual(f.rows("SELECT outcome FROM runs WHERE ref = 'refs/pull/8/head'"), [("scan_error",)])

    def test_a_pull_request_that_conflicts_from_its_first_push_is_scanned(self):
        f = self.f
        old = self.open_pull_request(3, "x = 3\n", merge_ref=False)  # closed long ago: a head ref only
        targets = self.targets(cooldown_seconds=0)
        first = self.poll(targets)
        self.assertEqual(first["acme/app#7"], "passed")
        self.assertNotIn("acme/app#3", first)
        state = json.loads((f.state / "pull_requests" / f"{scanning.slug('acme/app')}.json").read_text())
        self.assertEqual((state["mark"], state["heads"]["3"]), (7, old))
        # #8 is opened with conflicts: GitHub gives it no merge ref. It is above the mark, so it is scanned.
        pr8 = self.open_pull_request(8, "x = 8\n", merge_ref=False)
        self.assertEqual(self.poll(targets)["acme/app#8"], "passed")
        self.assertIn(("refs/pull/8/head", pr8), f.rows("SELECT ref, commit_sha FROM runs"))
        # The old head-only #3 is left alone until its head moves.
        self.assertNotIn("acme/app#3", self.poll(targets))
        self.open_pull_request(3, "x = 33\n", merge_ref=False)
        self.assertEqual(self.poll(targets)["acme/app#3"], "passed")

    def test_an_unreadable_poll_state_is_a_scan_error(self):
        f = self.f
        path = f.state / "pull_requests" / f"{scanning.slug('acme/app')}.json"
        path.parent.mkdir(mode=0o700)
        path.write_text("{not json")
        results = self.poll()
        self.assertIn("cannot be read", results["acme/app"])
        self.assertFalse(scanjob.poll_ok(results["acme/app"]))
        self.assertEqual(f.calls(), [])

    def test_a_head_is_scanned_again_when_the_policy_or_the_branch_changes(self):
        f = self.f
        targets = self.targets(cooldown_seconds=0)
        self.assertEqual(self.poll(targets)["acme/app#7"], "passed")
        with mock.patch.object(pullrequests, "PER_PULL_INTERVAL", timedelta(0)):
            self.assertEqual(self.poll(targets)["acme/app"][:31], "listed: 0 to scan, 1 already sc")
            scanning.write_policy(targets, targets.targets["acme/app"], "# MANAGED POLICY\n")
            self.assertEqual(self.poll(targets)["acme/app#7"], "passed")
            self.assertEqual(self.poll(targets)["acme/app"][:31], "listed: 0 to scan, 1 already sc")
            (f.origin / "other.py").write_text("y = 1\n", encoding="utf-8")
            git("add", "other.py", cwd=f.origin)
            git("commit", "-q", "-m", "main moves", cwd=f.origin)
            self.assertEqual(self.poll(targets)["acme/app#7"], "passed")
        # Each scan replaced the run of the same head.
        self.assertEqual(f.rows("SELECT COUNT(*) FROM runs"), [(1,)])
        self.assertEqual(len([c for c in f.calls() if c[2] == "scan"]), 3)

    def test_a_scan_that_never_started_gives_its_reservation_back(self):
        f = self.f
        self.assertTrue(scanning.acquire_lock(f.state, "acme/other"))
        try:
            results = self.poll()
        finally:
            scanning.release_lock(f.state)
        self.assertEqual(results["acme/app#7"], "skipped: another scan is running")
        self.assertEqual(scanning.read_requests(f.state)["pr_recent"], [])
        self.assertEqual(f.rows("SELECT COUNT(*) FROM runs"), [(0,)])

    def test_scan_requests_are_changed_under_a_lock_both_sides_take(self):
        f = self.f
        probe = (
            "import fcntl, os, sys; fd = os.open(sys.argv[1], os.O_RDWR)\n"
            "try:\n    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)\nexcept BlockingIOError:\n    sys.exit(3)\n"
        )
        with scanning.locked_requests(f.state) as requests:
            requests["pr_recent"].append(time.time())
            busy = subprocess.run([sys.executable, "-c", probe, str(f.state / scanning.REQUESTS_LOCK)], timeout=30)
        self.assertEqual(busy.returncode, 3)
        self.assertEqual(len(scanning.read_requests(f.state)["pr_recent"]), 1)
        # A body that fails writes nothing.
        with self.assertRaises(RuntimeError), scanning.locked_requests(f.state) as requests:
            requests["pr_recent"].clear()
            raise RuntimeError("stop")
        self.assertEqual(len(scanning.read_requests(f.state)["pr_recent"]), 1)

    def test_a_failure_of_this_machine_is_not_held_against_the_pull_request(self):
        f = self.f
        targets = self.targets(cooldown_seconds=0)
        full = SetupError("not enough free disk space: 1 MB free where the scan works")
        with mock.patch.object(scanjob, "check_free_space", side_effect=full):
            results = self.poll(targets)
        self.assertEqual(results["acme/app#7"], "failed")
        self.assertFalse(scanjob.poll_ok(results["acme/app#7"]))
        # Nothing recorded against the head, the reservation given back, and tried again once the hour is over.
        self.assertEqual(f.rows("SELECT COUNT(*) FROM runs"), [(0,)])
        self.assertEqual(scanning.read_requests(f.state)["pr_recent"], [])
        with mock.patch.object(pullrequests, "PER_PULL_INTERVAL", timedelta(0)):
            self.assertEqual(self.poll(targets)["acme/app#7"], "passed")

    def test_a_path_that_is_not_utf8_refuses_the_pull_request(self):
        # Built with git plumbing: macOS cannot hold such a name in a work tree, Linux can. Opengrep would list it
        # as U+FFFD and never match it, so its code would pass unscanned.
        f = self.f
        blob = subprocess.run(
            ["git", "-C", str(f.origin), "hash-object", "-w", "--stdin"], input=b"eval(x)\n", capture_output=True
        ).stdout.strip()
        tree = subprocess.run(
            ["git", "-C", str(f.origin), "ls-tree", "-z", "main"], capture_output=True, check=True
        ).stdout
        tree += b"100644 blob " + blob + b"\tbad\xff.py\0"
        tree_sha = (
            subprocess.run(["git", "-C", str(f.origin), "mktree", "-z"], input=tree, capture_output=True, check=True)
            .stdout.decode()
            .strip()
        )
        commit = subprocess.run(
            [
                "git",
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@example.invalid",
                "-C",
                str(f.origin),
                "commit-tree",
                tree_sha,
                "-p",
                "main",
                "-m",
                "bad name",
            ],
            capture_output=True,
            check=True,
            text=True,
        ).stdout.strip()
        git("update-ref", "refs/pull/8/head", commit, cwd=f.origin)
        git("update-ref", "refs/pull/8/merge", commit, cwd=f.origin)
        results = self.poll()
        self.assertEqual(results["acme/app#7"], "passed")
        self.assertEqual(results["acme/app#8"], "failed")
        self.assertIn("not valid UTF-8 or holds a control character", self.checkout_refusal(results, 8))
        self.assertEqual(f.rows("SELECT outcome FROM runs WHERE ref = 'refs/pull/8/head'"), [("scan_error",)])

    def test_run_one_refuses_a_pull_request_for_a_target_that_does_not_scan_them(self):
        pull = pullrequests.PullRequest(7, self.pr7, True)
        with self.assertRaisesRegex(SetupError, "does not scan pull requests"):
            scanjob.run_one(self.f.state, self.f.targets(), "acme/app", "x", io.StringIO(), pull=pull)
        # A hand-set clone (only reachable around the loader, which refuses it) is refused by name.
        targets = self.f.targets()
        clone = replace(targets, targets={"acme/app": replace(targets.targets["acme/app"], pull_requests=True)})
        with self.assertRaisesRegex(SetupError, "fetched anonymously from an https source, and this target's source"):
            scanjob.run_one(self.f.state, clone, "acme/app", "x", io.StringIO(), pull=pull)
        self.assertEqual(self.f.calls(), [])

    def test_pull_requests_need_an_https_source(self):
        f = self.f
        f.write(f'[[target]]\nname = "acme/app"\nclone = "{f.clone}"\nbranch = "main"\npull_requests = true\n')
        with self.assertRaisesRegex(SetupError, "needs an https source"):
            f.targets()
        f.write('[[target]]\nname = "a/b"\nsource = "https://github.com/a/b"\nbranch = "main"\npull_requests = 1\n')
        with self.assertRaisesRegex(SetupError, "true or false"):
            f.targets()
        for value in (0, 101):
            f.write(f"max_pull_requests = {value}\n")
            with self.assertRaisesRegex(SetupError, "max_pull_requests"):
                f.targets()
        f.write(
            'max_pull_requests = 3\n[[target]]\nname = "a/b"\nsource = "https://github.com/a/b"\nbranch = "main"\n'
            "pull_requests = true\n"
        )
        targets = f.targets()
        self.assertEqual((targets.max_pull_requests, targets.targets["a/b"].pull_requests), (3, True))
        # The dashboard keeps the hand-set line when it rewrites the file.
        scanning.save_targets(f.state, targets)
        text = (f.state / scanning.TARGETS_FILE).read_text()
        self.assertIn("pull_requests = true", text)
        self.assertIn("max_pull_requests = 3", text)
        self.assertEqual(f.targets(), targets)


@unittest.skipUnless(
    (helpers.tools_dir() / "opengrep").exists(), "the pinned scanners are not installed (run shoalscan install)"
)
class EndToEndWorkerTests(WorkerTestCase):
    def test_a_real_scan_of_a_tiny_repository(self):
        f = Fixture(self.base)
        rules = self.base / "rules"
        rules.mkdir()
        (rules / "eval.yaml").write_text(
            "rules:\n  - id: no-eval\n    languages: [python]\n    severity: ERROR\n    message: eval is dangerous\n   "
            " pattern: eval(...)\n",
            encoding="utf-8",
        )
        policy = self.base / "policy.toml"
        policy.write_text(
            '[opengrep]\ncommunity_rules = false\nshoalscan_rules = false\nrule_dirs = ["rules"]\n', encoding="utf-8"
        )
        # The rule directory is read from the scanned tree, so it is committed there.
        (f.origin / "rules").mkdir()
        (f.origin / "rules" / "eval.yaml").write_text((rules / "eval.yaml").read_text(), encoding="utf-8")
        (f.origin / "app.py").write_text("eval(input())\n", encoding="utf-8")
        git("add", "-A", cwd=f.origin)
        git("commit", "-q", "-m", "eval", cwd=f.origin)
        # The worker requires a network sandbox by default; a machine without one turns that off here.
        required = "false" if process.network_sandbox()[1] == process.NO_SANDBOX else "true"
        f.write(f"""
            tools_dir = "{helpers.tools_dir().resolve()}"
            require_network_sandbox = {required}

            [[target]]
            name = "acme/real"
            clone = "{f.clone}"
            branch = "main"
            config = "{policy}"
            """)
        outcome = scanjob.run_one(f.state, f.targets(), "acme/real", scanjob.WHO["cli"], io.StringIO())
        self.assertEqual(outcome, "blocked")
        self.assertEqual(
            f.rows("SELECT fk.path FROM run_findings rf JOIN finding_keys fk ON fk.id = rf.key_id"), [("app.py",)]
        )
        self.assertEqual(f.rows("SELECT outcome, run_id IS NOT NULL FROM scan_triggers"), [("blocked", 1)])


if __name__ == "__main__":
    unittest.main()
