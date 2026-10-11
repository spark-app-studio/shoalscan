"""The scan worker: `python -m shoalscan.scanjob` or `shoalscan scanjob`.

The dashboard starts this as a separate, detached process to run one scan of
a registered target; a nightly job starts it with `--nightly` to scan every
enabled nightly target, one after another. Either way the worker:

- reads `scan_targets.toml` itself and takes nothing from its caller but a
  target name, which must be registered;
- holds the scan lock, so only one scan runs at a time on this machine;
- fetches the clone and scans the head of the branch in a temporary
  worktree, so the clone's own checkout is never touched;
- runs `scan`, `check` and `record` as child processes with fixed argument
  lists, no shell, an allowlisted environment and a deadline; at the
  deadline the whole process group is killed and nothing is recorded;
- writes a row in `scan_triggers` and a status file for the dashboard, and
  cleans up on every exit path.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from shoalscan import history
from shoalscan.dashboard import scanning
from shoalscan.errors import SetupError, ShoalscanError

WHO = {
    "dashboard": "dashboard user",
    "rescan": "dashboard user",
    "rescan-commit": "dashboard user",
    "cli": "command line",
    "nightly": "nightly job",
}
TRIGGER = {
    "dashboard": "scan",
    "rescan": "rescan",
    "rescan-commit": "rescan-commit",
    "cli": "command line",
    "nightly": "nightly",
}
_FULL_SHA = re.compile(r"[0-9a-f]{40}")
STEP_OUTPUT_LINES = 20
ENV_ALLOW = (
    "PATH",
    "HOME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TMPDIR",
    "USER",
    "LOGNAME",
    "SSL_CERT_FILE",
    "PYTHONPATH",
    "XDG_CACHE_HOME",
    "XDG_DATA_HOME",
    "XDG_CONFIG_HOME",
)
_RUN_ID = re.compile(r"\brun (\d+)\b")


class ScanTimeout(Exception):  # noqa: N818 - a signal to stop the scan, not an error
    pass


class CloneTooLargeError(SetupError):
    pass


def _kill_group(pid: int) -> None:
    """Kill a child's whole process group; it may already be gone."""
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def tree_size(path: Path, limit: int | None = None) -> int:
    """Bytes under `path`; stops counting once past `limit`."""
    total = 0
    for root, _dirs, files in os.walk(path):
        for name in files:
            try:
                total += os.lstat(os.path.join(root, name)).st_size
            except OSError:
                pass
        if limit is not None and total > limit:
            break
    return total


class Stop(Exception):  # noqa: N818 - a signal to stop, not an error
    """SIGTERM or SIGINT: stop, clean up, record nothing."""


def base_env() -> dict:
    env = {k: os.environ[k] for k in ENV_ALLOW if k in os.environ}
    env.setdefault("PATH", "/usr/bin:/bin")
    return env


def child_env() -> dict:
    """For scan, check and record: every git command they run is hardened too."""
    return scanning.git_env(base_env(), scanning.GIT_HARDENED + scanning.GIT_URL_ONLY)


class Job:
    def __init__(
        self,
        state_dir: Path,
        targets: scanning.Targets,
        target: scanning.Target,
        who: str,
        log,
        pinned: tuple[str, str] | None = None,
    ):
        self.pinned = pinned  # (commit, ref) of a run to scan again, from the history database
        self.state_dir = state_dir
        self.targets = targets
        self.target = target
        self.who = who
        self.log = log
        self.deadline = time.monotonic() + targets.timeout_seconds
        self.work = Path(tempfile.mkdtemp(prefix="shoalscan-scan-"))
        self.db = targets.history_db or history.default_db_path()
        self.clone = targets.clone_dir(target)
        self.env = child_env()
        self.logged = 0
        self.log_full = False

    def say(self, text: str) -> None:
        """One log line, while the log stays under MAX_LOG_BYTES."""
        line = f"{time.strftime('%Y-%m-%dT%H:%M:%S')} {text}\n"
        if self.logged + len(line) > scanning.MAX_LOG_BYTES:
            if not self.log_full:
                self.log.write("... the log is full; later lines are left out\n")
                self.log_full = True
            return
        self.logged += len(line)
        self.log.write(line)
        self.log.flush()

    def run(
        self,
        argv: list[str],
        cwd: Path | None = None,
        stdout_to: Path | None = None,
        env: dict | None = None,
        watch: Path | None = None,
    ) -> int:
        """Run one child in its own process group, with what is left of the deadline.
        With `watch`, the directory's size is checked every second, and the child is
        killed with its group as soon as it passes the clone size limit."""
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise ScanTimeout()
        out_path = self.work / "step.log"
        with open(out_path, "wb") as out, open(stdout_to, "wb") if stdout_to else open(os.devnull, "wb") as stdout:
            proc = subprocess.Popen(
                argv,
                cwd=str(cwd) if cwd else str(self.work),
                stdin=subprocess.DEVNULL,
                stdout=stdout if stdout_to else out,
                stderr=out,
                env=env or self.env,
                start_new_session=True,
            )
            try:
                code = None
                deadline = time.monotonic() + remaining
                while code is None:
                    left = deadline - time.monotonic()
                    if left <= 0:
                        raise subprocess.TimeoutExpired(argv, remaining)
                    try:
                        code = proc.wait(timeout=min(1.0, left) if watch else left)
                    except subprocess.TimeoutExpired:
                        if watch is None or time.monotonic() >= deadline:
                            raise
                        if tree_size(watch, self.clone_limit()) > self.clone_limit():
                            _kill_group(proc.pid)
                            proc.wait()
                            raise CloneTooLargeError(
                                f"the clone grew past max_clone_mb ({self.clone_limit() // (1024 * 1024)} MB); "
                                "the fetch was stopped and nothing was scanned"
                            ) from None
            except subprocess.TimeoutExpired:
                _kill_group(proc.pid)
                proc.wait()
                raise ScanTimeout() from None
            except BaseException:
                _kill_group(proc.pid)
                proc.wait()
                raise
        tail = out_path.read_text(encoding="utf-8", errors="replace").splitlines()[-STEP_OUTPUT_LINES:]
        for line in tail:
            self.say("  " + line[:300])
        return code

    def git_pairs(self, admin_fetch: bool = False):
        if admin_fetch:
            return scanning.GIT_ADMIN_FETCH
        return scanning.GIT_HARDENED + scanning.GIT_URL_ONLY

    def git(self, *args: str, cwd: Path | None = None, admin_fetch: bool = False, watch: bool = False) -> int:
        """Every git command, hardened; only an administrator's clone is fetched with its own configuration.
        With `watch`, the clone's size is enforced while git runs."""
        pairs = self.git_pairs(admin_fetch)
        env = scanning.git_env(base_env(), pairs, hardened=not admin_fetch)
        try:
            return self.run(
                ["git", *scanning.git_args(pairs), *args], cwd=cwd, env=env, watch=self.clone if watch else None
            )
        except CloneTooLargeError:
            self.discard_partial_clone()
            raise

    def clone_limit(self) -> int:
        mb = self.target.max_clone_mb if self.target.max_clone_mb is not None else self.targets.max_clone_mb
        return mb * 1024 * 1024

    def discard_partial_clone(self) -> None:
        """After a stopped clone or fetch: a clone Shoalscan manages is removed (it is cloned
        again next time); in a clone set by hand only git's temporary pack files go."""
        if self.target.kind == "url":
            shutil.rmtree(self.clone, ignore_errors=True)
            return
        for objects in (self.clone / ".git" / "objects", self.clone / "objects"):
            for leftover in list(objects.glob("pack/tmp_*")) + list(objects.glob("incoming-*")):
                if leftover.is_dir():
                    shutil.rmtree(leftover, ignore_errors=True)
                else:
                    leftover.unlink(missing_ok=True)

    def git_out(self, *args: str) -> str:
        """A hardened git query in the clone, in its own session, killed with its group at the deadline."""
        pairs = self.git_pairs()
        proc = subprocess.Popen(
            ["git", *scanning.git_args(pairs), "-C", str(self.clone), *args],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=scanning.git_env(base_env(), pairs),
            start_new_session=True,
            text=True,
        )
        try:
            out, _ = proc.communicate(timeout=max(1, self.deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            _kill_group(proc.pid)
            proc.communicate()
            raise ScanTimeout() from None
        return out.strip() if proc.returncode == 0 else ""

    def prepare_clone(self) -> str:
        """Fetch the clone and return the commit at the head of the branch."""
        t = self.target
        if t.kind == "url":
            if self.clone.exists() and self.git_out("config", "--get", "remote.origin.url") != t.source:
                self.say("the source changed; cloning again")
                shutil.rmtree(self.clone)
            if not self.clone.exists():
                self.clone.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                self.say(f"cloning {t.source}")
                # One branch only, but its full history, so earlier commits can be rescanned.
                if (
                    self.git(
                        "clone",
                        "--quiet",
                        "--no-checkout",
                        "--single-branch",
                        "--branch",
                        t.branch,
                        "--",
                        t.source,
                        str(self.clone),
                        watch=True,
                    )
                    != 0
                ):
                    raise SetupError("git clone failed")
        if not (self.clone / ".git").exists() and not (self.clone / "HEAD").exists():
            raise SetupError("the clone is not a git repository")
        # A mirror is kept up to date by its owner, outside Shoalscan, and is never fetched here.
        if t.kind != "mirror" and self.git_out("remote", "get-url", "origin"):
            self.say("fetching")
            refspec = f"+refs/heads/{t.branch}:refs/remotes/origin/{t.branch}"
            if (
                self.git(
                    "-C",
                    str(self.clone),
                    "fetch",
                    "--quiet",
                    "--no-tags",
                    "origin",
                    refspec,
                    admin_fetch=t.kind == "clone",
                    watch=True,
                )
                != 0
            ):
                raise SetupError("git fetch failed")
        self.check_clone_size()
        if self.pinned is not None:
            commit = self.pinned[0]
            missing = self.git("-C", str(self.clone), "cat-file", "-e", f"{commit}^{{commit}}") != 0
            if missing and t.kind != "mirror" and self.git_out("remote", "get-url", "origin"):
                # The commit may have left the branch: ask the origin for that commit alone.
                self.git(
                    "-C",
                    str(self.clone),
                    "fetch",
                    "--quiet",
                    "--no-tags",
                    "origin",
                    commit,
                    admin_fetch=t.kind == "clone",
                    watch=True,
                )
                self.check_clone_size()
                missing = self.git("-C", str(self.clone), "cat-file", "-e", f"{commit}^{{commit}}") != 0
            if missing:
                raise SetupError(
                    f"commit {commit[:12]} is no longer in the clone (it may have been rewritten away); nothing was "
                    "scanned"
                )
            return commit
        for ref in (f"refs/remotes/origin/{t.branch}", f"refs/heads/{t.branch}"):
            commit = self.git_out("rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}")
            if re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", commit):
                return commit
        raise SetupError(f"the branch {t.branch} does not exist in the clone")

    def check_clone_size(self) -> None:
        if tree_size(self.clone, self.clone_limit()) > self.clone_limit():
            raise SetupError(
                f"the clone is larger than max_clone_mb ({self.clone_limit() // (1024 * 1024)} MB); nothing was scanned"
            )

    def shoalscan(self, *args: str) -> list[str]:
        python = str(self.target.python) if self.target.python else sys.executable
        return [python, "-P", "-m", "shoalscan", *args]

    def execute(self) -> tuple[str, int | None]:
        """Scan, check and record. Returns the outcome and the recorded run id."""
        t = self.target
        # Before anything is fetched or checked out: the filter protection needs a git that honours GIT_ATTR_SOURCE.
        if not scanning.git_attr_probe(self.env.get("PATH")):
            raise SetupError(scanning.GIT_TOO_OLD)
        check_free_space(self.state_dir, self.targets)
        commit = self.prepare_clone()
        self.say(f"scanning {t.name} {t.branch} at {commit[:12]}")
        self.git("-C", str(self.clone), "worktree", "prune")
        src = self.work / "src"
        if self.git("-C", str(self.clone), "worktree", "add", "--quiet", "--detach", str(src), commit) != 0:
            raise SetupError("git worktree add failed")
        out = self.work / "out"
        out.mkdir(mode=0o700)
        policy = self.targets.policy_path(t)
        config = ["--config", str(policy)] if policy else []
        baseline = ["--baseline", str(self.targets.baseline_path(t))] if t.baseline or t.kind != "clone" else []
        tools = ["--tools-dir", str(self.targets.tools_dir)] if self.targets.tools_dir else []
        # A rescan of an earlier commit keeps that run's time, so it replaces the run where it
        # was and never becomes the newest point of the trend.
        started = self.pinned[2] if self.pinned else history.parse_timestamp(None)
        code = self.run(self.shoalscan("scan", "--repo", str(src), "--out", str(out), *tools, *config))
        check_txt = self.work / "check.txt"
        if code == 0:
            code = self.run(
                self.shoalscan("check", "--repo", str(src), "--out", str(out), *config, *baseline), stdout_to=check_txt
            )
        else:
            self.say(f"the scan failed (exit {code})")
            code = 2
        if code not in (0, 1):
            code = 2
        ref = self.pinned[1] if self.pinned else t.branch
        record = [
            "record",
            "--repo-name",
            t.name,
            "--ref",
            ref,
            "--commit",
            commit,
            "--kind",
            "scheduled",
            "--scanned-at",
            started,
            "--check-exit",
            str(code),
            "--db",
            str(self.db),
            "--findings",
            str(out / "findings.json"),
        ]
        if self.pinned:
            record.append("--commit-rescan")
        if code != 2:
            record += ["--check-output", str(check_txt)]
        record_log = self.work / "record.txt"
        if self.run(self.shoalscan(*record), stdout_to=record_log) != 0:
            raise SetupError("shoalscan record failed")
        match = _RUN_ID.search(record_log.read_text(encoding="utf-8", errors="replace"))
        return {0: "passed", 1: "blocked", 2: "scan_error"}[code], int(match.group(1)) if match else None

    def cleanup(self) -> None:
        src = self.work / "src"
        if src.exists():
            pairs = self.git_pairs()
            subprocess.run(
                ["git", *scanning.git_args(pairs), "-C", str(self.clone), "worktree", "remove", "--force", str(src)],
                capture_output=True,
                stdin=subprocess.DEVNULL,
                env=scanning.git_env(base_env(), pairs),
                timeout=60,
                check=False,
                start_new_session=True,
            )
        shutil.rmtree(self.work, ignore_errors=True)


def check_free_space(state_dir: Path, targets: scanning.Targets) -> None:
    """Refuse to start when the clones or the temporary worktree could fill the disk."""
    need = targets.min_free_mb * 1024 * 1024
    for place in {state_dir.resolve(), Path(tempfile.gettempdir()).resolve()}:
        free = shutil.disk_usage(place).free
        if free < need:
            raise SetupError(
                f"not enough free disk space: {free // (1024 * 1024)} MB free where the scan works; "
                f"min_free_mb in scan_targets.toml asks for {targets.min_free_mb} MB"
            )


def _write_status(state_dir: Path, **status) -> None:
    scanning.write_private(state_dir / scanning.STATUS_FILE, json.dumps(status))


def run_one(
    state_dir: Path,
    targets: scanning.Targets,
    name: str,
    who: str,
    log,
    trigger: str = "scan",
    run_id: int | None = None,
) -> str:
    """Scan one registered target under the lock. Returns the outcome.

    With `run_id`, scan again the exact commit that run of this repository
    scanned, looked up in the history database; the new record replaces it.
    """
    target = targets.targets.get(name)
    if target is None:
        raise SetupError(f"{name!r} is not a registered scan target")
    pinned = None
    if run_id is not None:
        db = targets.history_db or history.default_db_path()
        lookup = history.open_read_only(db)
        try:
            pinned = history.run_commit(lookup, name, run_id)
        finally:
            lookup.close()
        if pinned is None:
            raise SetupError(f"{name} has no run {run_id}")
        if pinned[2] != "scheduled":  # pinned is (commit, ref, kind, scanned_at)
            # A pull-request run scanned a merge ref; recording it again as scheduled would mislabel it.
            raise SetupError(f"run {run_id} is a {pinned[2]} run; only scheduled runs can be rescanned by commit")
        pinned = (pinned[0], pinned[1], pinned[3])
        if not _FULL_SHA.fullmatch(pinned[0]):
            raise SetupError(f"run {run_id} does not name a full commit SHA, so it cannot be scanned again")
    if not scanning.acquire_lock(state_dir, name):
        raise SetupError("another scan is running")
    job = None
    trigger_id = None
    conn = None
    outcome, run_id, detail = "failed", None, None
    started = history.parse_timestamp(None)
    try:
        job = Job(state_dir, targets, target, who, log, pinned)
        conn = history.open_for_write(job.db)
        trigger_id = history.start_trigger(conn, name, who, started, trigger)
        _write_status(
            state_dir, target=name, started=started, finished=None, outcome="running", run_id=None, pid=os.getpid()
        )
        job.say(f"scan of {name} started by {who}")
        outcome, run_id = job.execute()
    except ScanTimeout:
        outcome, detail = "timeout", f"stopped after {targets.timeout_seconds // 60} minutes; nothing was recorded"
    except Stop:
        outcome, detail = "failed", "stopped by a signal; nothing was recorded"
    except (ShoalscanError, OSError, subprocess.SubprocessError) as exc:
        outcome, detail = "failed", str(exc)[:300]
    finally:
        if job is not None:
            job.say(f"finished: {outcome}" + (f" ({detail})" if detail else "") + (f", run {run_id}" if run_id else ""))
            job.cleanup()
        finished = history.parse_timestamp(None)
        if conn is not None:
            if trigger_id is not None:
                history.finish_trigger(
                    conn,
                    trigger_id,
                    outcome,
                    run_id,
                    scanning.sanitise_log([detail], job.clone if job else None)[0] if detail else None,
                    finished,
                )
            conn.close()
        _write_status(
            state_dir, target=name, started=started, finished=finished, outcome=outcome, run_id=run_id, pid=None
        )
        scanning.release_lock(state_dir)
    return outcome


def run_nightly(state_dir: Path, targets: scanning.Targets, log, wait_seconds: int | None = None) -> dict[str, str]:
    """Scan every enabled target with nightly = true, in file order, one after another."""
    results: dict[str, str] = {}
    wait = targets.timeout_seconds if wait_seconds is None else wait_seconds
    for target in targets.targets.values():
        if not target.enabled or not target.nightly:
            results[target.name] = "skipped: " + ("disabled" if not target.enabled else "not nightly")
            log.write(f"nightly: skipping {target.name} ({results[target.name][9:]})\n")
            continue
        deadline = time.monotonic() + wait
        while scanning.lock_holder(state_dir) is not None and time.monotonic() < deadline:
            time.sleep(2)
        try:
            results[target.name] = run_one(state_dir, targets, target.name, WHO["nightly"], log, TRIGGER["nightly"])
        except SetupError as exc:
            results[target.name] = f"skipped: {exc}"
            log.write(f"nightly: {target.name}: {exc}\n")
        log.flush()
    return results


def _on_signal(signum, frame):
    raise Stop()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="shoalscan scanjob", description="Run a scan of a registered target (see scan_targets.toml)."
    )
    add_arguments(parser)
    return run(parser.parse_args(argv))


def add_arguments(p: argparse.ArgumentParser) -> None:
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--target", help="the registered target to scan, by name")
    group.add_argument(
        "--nightly", action="store_true", help="scan every enabled target with nightly = true, one after another"
    )
    p.add_argument("--state-dir", required=True, help="the dashboard's state directory, which holds scan_targets.toml")
    p.add_argument("--trigger", choices=tuple(WHO), default="cli", help=argparse.SUPPRESS)
    p.add_argument("--who", help=argparse.SUPPRESS)  # the signed-in person's email, from the dashboard
    p.add_argument(
        "--run-id", type=int, help="scan again the exact commit of this run of the target (the new record replaces it)"
    )


def run(args: argparse.Namespace) -> int:
    signal.signal(signal.SIGTERM, _on_signal)
    signal.signal(signal.SIGINT, _on_signal)
    try:
        os.nice(10)
    except OSError:
        pass
    state_dir = Path(args.state_dir)
    try:
        targets = scanning.load_targets(state_dir)
        if targets is None:
            raise SetupError(f"{state_dir / scanning.TARGETS_FILE} does not exist: no scan targets are registered")
        if args.nightly:
            results = run_nightly(state_dir, targets, sys.stdout)
            for name, outcome in results.items():
                print(f"shoalscan scanjob: {name}: {outcome}")
            return (
                0
                if all(
                    o in ("passed", "blocked") or o.startswith("skipped: dis") or o.startswith("skipped: not")
                    for o in results.values()
                )
                else 1
            )
        if not scanning.valid_name(args.target):
            raise SetupError("invalid target name")
        if args.run_id is not None and not 0 < args.run_id < 2**62:
            raise SetupError("invalid run id")
        who = WHO[args.trigger]
        if args.who is not None and args.trigger in ("dashboard", "rescan", "rescan-commit"):
            from shoalscan.dashboard.users import normalise_email

            who = normalise_email(args.who)
        outcome = run_one(state_dir, targets, args.target, who, sys.stdout, TRIGGER[args.trigger], args.run_id)
        print(f"shoalscan scanjob: {args.target}: {outcome}")
        return 0 if outcome in ("passed", "blocked") else 1
    except ShoalscanError as exc:
        print(f"shoalscan scanjob: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
