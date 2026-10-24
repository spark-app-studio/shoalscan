"""The scan worker: `python -m shoalscan.scanjob` or `shoalscan scanjob`.

The dashboard starts this as a separate, detached process to run one scan of
a registered target; a nightly job starts it with `--nightly` to scan every
enabled nightly target, one after another; a frequent job starts it with
`--pull-requests` to scan the new heads of the open pull requests of every
enabled target with `pull_requests = true` (see `shoalscan.pullrequests`).
Either way the worker:

- reads `scan_targets.toml` itself and takes nothing from its caller but a
  target name, which must be registered;
- holds the scan lock, so only one scan runs at a time on this machine;
- fetches the clone and scans the head of the branch in a temporary
  worktree, so the clone's own checkout is never touched;
- always passes the policy explicitly: the managed policy when there is
  one, else the `.shoalscan.toml` at the head of the registered branch,
  read from git, so the commit being scanned (an older one, on a rescan, or
  a pull request's head) never chooses its own scanners; a pull request's
  repository rule dirs come from the head of the registered branch too, and
  its changed files are listed against the merge base with that head;
- runs `scan`, `check` and `record` as child processes with fixed argument
  lists, no shell, an allowlisted environment and a deadline; at the
  deadline the whole process group is killed and nothing is recorded;
- writes a row in `scan_triggers` and a status file for the dashboard, and
  cleans up on every exit path.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import re
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from shoalscan import history, pullrequests
from shoalscan.config import CONFIG_NAME
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
# Scans of pull requests, by `scanjob --pull-requests`; not a --trigger a caller can choose.
PR_WHO = "pull-request poll"
PR_TRIGGER = "pull-request"
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
MAX_POLICY_BYTES = 1024 * 1024
MB = 1024 * 1024
# A path deeper than this in the commit being scanned refuses the scan: no real repository needs it.
MAX_PATH_DEPTH = 64
WORK_PREFIX = "shoalscan-scan-"
OWNER_FILE = ".shoalscan-state-dir"


def sweep_stale_work(state_dir: Path) -> int:
    """Remove work directories an earlier worker of this state directory left behind (killed, say).

    Called with the scan lock held, so no other worker of this state directory is running.
    """
    removed = 0
    owner = str(state_dir.resolve())
    for path in Path(tempfile.gettempdir()).glob(WORK_PREFIX + "*"):
        try:
            if path.is_symlink() or not path.is_dir() or path.stat().st_uid != os.getuid():
                continue
            if (path / OWNER_FILE).read_text(encoding="utf-8") != owner:
                continue
        except OSError:
            continue
        shutil.rmtree(path, ignore_errors=True)
        removed += 1
    return removed


class ScanTimeout(Exception):  # noqa: N818 - a signal to stop the scan, not an error
    pass


class TooLargeError(SetupError):
    """A directory a git command writes grew past its limit; the command was stopped."""


class CloneTooLargeError(TooLargeError):
    pass


@dataclass(frozen=True)
class Watch:
    """A directory whose size is enforced while a child runs: past `limit` bytes the child is killed."""

    path: Path
    limit: int
    error: type[TooLargeError]
    message: str


def _kill_group(pid: int) -> None:
    """Kill a child's whole process group; it may already be gone."""
    try:
        os.killpg(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):  # gone, or (macOS) only a zombie is left
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


# The home directory of every hardened git command that may reach the network: git reads no global
# configuration under it (GIT_CONFIG_GLOBAL is /dev/null), and curl must not find a ~/.netrc there either.
NO_HOME = "/nonexistent"


def network_git_env(pairs) -> dict:
    """The environment of a hardened git command that talks to a source a browser or scan_targets.toml named."""
    env = scanning.git_env(base_env(), pairs)
    env["HOME"] = NO_HOME
    env.pop("XDG_CONFIG_HOME", None)
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
        pull: pullrequests.PullRequest | None = None,
    ):
        self.pinned = pinned  # (commit, ref) of a run to scan again, from the history database
        self.pull = pull  # a pull request to scan, from the listing of the target's source
        self.scan_started = False  # whether `shoalscan scan` was started: the attempt used a scan
        self.state_dir = state_dir
        self.targets = targets
        self.target = target
        self.who = who
        self.log = log
        self.deadline = time.monotonic() + targets.timeout_seconds
        self.work = Path(tempfile.mkdtemp(prefix=WORK_PREFIX))
        # Which state directory this work belongs to, so a later worker can sweep it if it is left behind.
        (self.work / OWNER_FILE).write_text(str(state_dir.resolve()), encoding="utf-8")
        self.db = targets.history_db or history.default_db_path()
        self.clone = targets.clone_dir(target)
        self.env = child_env()
        # The scan's own temporary files (its stage holds Gitleaks's report) live in the work
        # directory, which is removed on every exit path, even when the scan is killed at the deadline.
        tmp = self.work / "tmp"
        tmp.mkdir(mode=0o700)
        self.env["TMPDIR"] = str(tmp)
        self.logged = 0
        self.log_full = False

    def say(self, text: str) -> None:
        """One log line, while the log stays under MAX_LOG_BYTES. Control and escape sequences are dropped:
        scanner output names files of the scanned repository, which chose them."""
        text = scanning.plain_text(text)
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
        watch: Watch | None = None,
    ) -> int:
        """Run one child in its own process group, with what is left of the deadline.
        With `watch`, the directory's size is checked every second, and the child is
        killed with its group as soon as it passes the watch's limit."""
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
                        if tree_size(watch.path, watch.limit) > watch.limit:
                            _kill_group(proc.pid)
                            proc.wait()
                            raise watch.error(watch.message) from None
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

    def git(self, *args: str, cwd: Path | None = None, admin_fetch: bool = False, watch: bool | Watch = False) -> int:
        """Every git command, hardened; only an administrator's clone is fetched with its own configuration.
        With `watch` True, the clone's size is enforced while git runs (and a clone that grows past it is
        discarded); with a Watch, that directory's size."""
        pairs = self.git_pairs(admin_fetch)
        # Only an administrator's clone keeps the home directory, where its credentials may live.
        env = scanning.git_env(base_env(), pairs, hardened=False) if admin_fetch else network_git_env(pairs)
        if watch is True:
            watch = Watch(
                self.clone,
                self.clone_limit(),
                CloneTooLargeError,
                f"the clone grew past max_clone_mb ({self.clone_limit() // (1024 * 1024)} MB); "
                "the fetch was stopped and nothing was scanned",
            )
        try:
            return self.run(["git", *scanning.git_args(pairs), *args], cwd=cwd, env=env, watch=watch or None)
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

    def git_out(self, *args: str, repo: Path | None = None) -> str:
        """A hardened git query in the clone (or `repo`), in its own session, killed with its group at the
        deadline."""
        pairs = self.git_pairs()
        proc = subprocess.Popen(
            ["git", *scanning.git_args(pairs), "-C", str(repo or self.clone), *args],
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
        if self.pull is not None:
            return self.fetch_pull()
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
        return self.branch_head()

    @property
    def pull_repo(self) -> Path:
        """The throwaway repository a pull request is fetched into, in the work directory."""
        return self.work / "pull.git"

    def fetch_pull(self) -> str:
        """Fetch a pull request's head and return its commit, which must be the commit the listing showed.

        The head is fetched into a throwaway bare repository in the work directory that borrows the branch
        clone's objects read-only (objects/info/alternates), so the pull request's objects never enter the
        branch clone or count against its size; they have a limit of their own (max_clone_mb) and go with
        the work directory. Only objects are fetched; nothing is checked out here."""
        pull = self.pull
        t = self.target
        if t.kind != "url" or not t.source:
            raise SetupError("pull requests are fetched anonymously from an https source only")
        source = t.source
        objects = self.clone / ".git" / "objects" if (self.clone / ".git").is_dir() else self.clone / "objects"
        if not objects.is_dir():
            raise SetupError("the clone has no object store")
        repo = self.pull_repo
        if self.git("init", "--quiet", "--bare", str(repo)) != 0:
            raise SetupError("git init of the pull request's repository failed")
        (repo / "objects" / "info").mkdir(parents=True, exist_ok=True)
        (repo / "objects" / "info" / "alternates").write_text(f"{objects.resolve()}\n", encoding="utf-8")
        self.say(f"fetching pull request #{pull.number}")
        limit = self.clone_limit()
        watch = Watch(
            repo,
            limit,
            TooLargeError,
            f"pull request #{pull.number} needs more than max_clone_mb ({limit // (1024 * 1024)} MB) of objects; "
            "the fetch was stopped and nothing was scanned",
        )
        fetched = self.git(
            "-C",
            str(repo),
            "fetch",
            "--quiet",
            "--no-tags",
            "--",
            source,
            f"+{pull.ref}:{pull.fetch_ref}",
            watch=watch,
        )
        if fetched != 0:
            raise SetupError(f"git fetch of pull request #{pull.number} failed; nothing was scanned")
        if tree_size(repo, limit) > limit:
            raise TooLargeError(watch.message)
        commit = self.git_out("rev-parse", "--verify", "--quiet", f"{pull.fetch_ref}^{{commit}}", repo=repo)
        if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", commit):
            raise SetupError(f"the fetched head of pull request #{pull.number} is not a commit")
        if commit != pull.head:
            # Pushed to after the listing: what was fetched is its real head now, so that is what is scanned and
            # recorded, rather than a stale head nobody can fetch.
            self.say(f"pull request #{pull.number} moved after it was listed; scanning its head {commit[:12]}")
            self.pull = dataclasses.replace(pull, head=commit)
        return commit

    def checkout_message(self, size: int | None) -> str:
        what = f"would be {size // MB} MB, more" if size is not None else "grew to more"
        return (
            f"the checkout of the commit {what} than max_checkout_mb ({self.targets.max_checkout_mb} MB); "
            "nothing was scanned"
        )

    def check_checkout(self, repo: Path, commit: str) -> int:
        """Before anything is written: the commit's tree, as `git ls-tree` lists it, must stay within
        max_checkout_mb, max_checkout_files and MAX_PATH_DEPTH, and the disk must hold the checkout twice
        (Gitleaks may copy every file where a hard link fails) besides min_free_mb. Objects compress, so a
        small fetch can still expand to a huge checkout. Returns the checkout's size in bytes."""
        limit = self.targets.max_checkout_mb * MB
        max_files = self.targets.max_checkout_files
        pairs = self.git_pairs()
        proc = subprocess.Popen(
            ["git", *scanning.git_args(pairs), "-C", str(repo), "ls-tree", "-r", "-l", "-z", "--full-tree", commit],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=scanning.git_env(base_env(), pairs),
            start_new_session=True,
        )
        timer = threading.Timer(max(1.0, self.deadline - time.monotonic()), _kill_group, (proc.pid,))
        timer.daemon = True
        timer.start()
        total = files = 0
        problem = None
        rest = b""
        try:
            while problem is None:
                chunk = proc.stdout.read(65536)
                if not chunk:
                    break
                records = (rest + chunk).split(b"\0")
                rest = records.pop()
                for record in records:
                    meta, _, path = record.partition(b"\t")
                    fields = meta.split()
                    if len(fields) != 4 or not path:
                        problem = SetupError("git ls-tree printed an entry that could not be read")
                        break
                    files += 1
                    total += int(fields[3]) if fields[3].isdigit() else 0
                    if files > max_files:
                        problem = TooLargeError(
                            f"the commit has more than max_checkout_files ({max_files}) files; nothing was scanned"
                        )
                    elif total > limit:
                        problem = TooLargeError(self.checkout_message(total))
                    elif path.count(b"/") >= MAX_PATH_DEPTH or len(path) > 4096:
                        problem = TooLargeError(
                            f"the commit has a path deeper than {MAX_PATH_DEPTH} directories or longer than 4096 "
                            "bytes; nothing was scanned"
                        )
                    if problem is not None:
                        break
        finally:
            timer.cancel()
            if problem is not None:
                _kill_group(proc.pid)
            proc.stdout.close()
            proc.wait()
        if problem is not None:
            raise problem
        if time.monotonic() >= self.deadline:
            raise ScanTimeout()
        if proc.returncode != 0 or rest:
            raise SetupError(f"could not list the tree of {commit[:12]}")
        need = 2 * total + self.targets.min_free_mb * MB
        free = shutil.disk_usage(self.work).free
        if free < need:
            raise SetupError(
                f"not enough free disk space for the checkout: it needs {total // MB} MB twice (for the Gitleaks "
                f"staging copy) and min_free_mb ({self.targets.min_free_mb} MB) besides; {free // MB} MB is free"
            )
        return total

    def branch_head(self) -> str:
        """The commit at the head of the registered branch in the clone."""
        t = self.target
        for ref in (f"refs/remotes/origin/{t.branch}", f"refs/heads/{t.branch}"):
            commit = self.git_out("rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}")
            if re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", commit):
                return commit
        raise SetupError(f"the branch {t.branch} does not exist in the clone")

    def git_blob(self, blob: str, limit: int) -> bytes:
        """A blob's exact bytes from the clone, refused past `limit`."""
        pairs = self.git_pairs()
        proc = subprocess.Popen(
            ["git", *scanning.git_args(pairs), "-C", str(self.clone), "cat-file", "blob", blob],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=scanning.git_env(base_env(), pairs),
            start_new_session=True,
        )
        try:
            out, _ = proc.communicate(timeout=max(1, self.deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            _kill_group(proc.pid)
            proc.communicate()
            raise ScanTimeout() from None
        if proc.returncode != 0:
            raise SetupError(f"could not read {CONFIG_NAME} from the clone")
        if len(out) > limit:
            raise SetupError(f"{CONFIG_NAME} at the head of the branch is larger than {limit} bytes")
        return out

    def branch_policy(self) -> Path:
        """The repository's own policy, from the head of the registered branch, as a private file.

        A missing file is an empty policy (Shoalscan's defaults). Anything
        other than a regular file there (a link, a directory) is refused.
        """
        head = self.branch_head()
        # An empty answer must mean "no such file", never "git failed": check the tree first.
        if not self.git_out("rev-parse", "--verify", "--quiet", f"{head}^{{tree}}"):
            raise SetupError(f"could not read the tree at the head of {self.target.branch}")
        entry = self.git_out("ls-tree", "--full-tree", head, "--", CONFIG_NAME)
        data = b""
        if entry:
            fields = entry.split(None, 3)
            if len(fields) != 4 or fields[0] not in ("100644", "100755") or fields[1] != "blob":
                raise SetupError(f"{CONFIG_NAME} at the head of {self.target.branch} is not a regular file")
            data = self.git_blob(fields[2], MAX_POLICY_BYTES)
        path = self.work / "branch-policy.toml"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        self.say(f"policy: {CONFIG_NAME} at the head of {self.target.branch} ({head[:12]})")
        return path

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
        # For a pull request: the head of the registered branch, which gives the policy (unless one is
        # registered), the repository rule dirs and the merge base the changed files are listed against.
        base = self.branch_head() if self.pull is not None else None
        if base is not None:
            self.say(
                f"scanning {t.name} pull request #{self.pull.number} at {commit[:12]}, base {t.branch} {base[:12]}"
            )
        else:
            self.say(f"scanning {t.name} {t.branch} at {commit[:12]}")
        # A pull request is checked out from its throwaway repository, never from the branch clone.
        repo = self.pull_repo if self.pull is not None else self.clone
        self.git("-C", str(repo), "worktree", "prune")
        src = self.work / "src"
        size = self.check_checkout(repo, commit)
        # Enforced while git writes too, and once more after: the tree's sizes are what git will write.
        limit = self.targets.max_checkout_mb * MB
        watch = Watch(src, limit + MB, TooLargeError, self.checkout_message(None))
        if self.git("-C", str(repo), "worktree", "add", "--quiet", "--detach", str(src), commit, watch=watch) != 0:
            raise SetupError("git worktree add failed")
        if tree_size(src, limit + MB) > limit + MB:
            raise TooLargeError(self.checkout_message(None))
        self.say(f"checkout: {size // MB} MB")
        out = self.work / "out"
        out.mkdir(mode=0o700)
        # The policy is always explicit: the managed one, else the branch head's own file.
        policy = self.targets.policy_path(t)
        if policy is not None:
            self.say("policy: the policy registered for this repository")
        else:
            policy = self.branch_policy()
        config = ["--config", str(policy)]
        # The baseline is always a file outside the clone for a pull request, never the one in the change.
        explicit = t.baseline or t.kind != "clone" or self.pull is not None
        baseline = ["--baseline", str(self.targets.baseline_path(t))] if explicit else []
        tools = ["--tools-dir", str(self.targets.tools_dir)] if self.targets.tools_dir else []
        # A rescan of an earlier commit keeps that run's time, so it replaces the run where it
        # was and never becomes the newest point of the trend.
        started = self.pinned[2] if self.pinned else history.parse_timestamp(None)
        sandbox = ["--require-network-sandbox"] if self.targets.require_network_sandbox else []
        rules = ["--rules-commit", base] if base is not None else []
        changed = ["--changed-since", base] if base is not None else []
        self.scan_started = True
        code = self.run(
            self.shoalscan("scan", "--repo", str(src), "--out", str(out), *tools, *config, *rules, *sandbox)
        )
        check_txt = self.work / "check.txt"
        if code == 0:
            code = self.run(
                self.shoalscan("check", "--repo", str(src), "--out", str(out), *config, *baseline, *changed),
                stdout_to=check_txt,
            )
        else:
            self.say(f"the scan failed (exit {code})")
            code = 2
        if code not in (0, 1):
            code = 2
        ref = self.pull.ref if self.pull else self.pinned[1] if self.pinned else t.branch
        record = [
            "record",
            "--repo-name",
            t.name,
            "--ref",
            ref,
            "--commit",
            commit,
            "--kind",
            "pr" if self.pull else "scheduled",
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
        # A pull request's worktree belongs to the throwaway repository, which goes with the work directory.
        if src.exists() and self.pull is None:
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
    pull: pullrequests.PullRequest | None = None,
    report: dict | None = None,
) -> str:
    """Scan one registered target under the lock. Returns the outcome.

    With `run_id`, scan again the exact commit that run of this repository
    scanned, looked up in the history database; the new record replaces it.
    With `pull`, scan that pull request's head and record it as a pull-request run. `report`, when given, is
    filled with whether a scan was started ("scanned") and, for a pull request, the head scanned ("head"),
    which is the head fetched when the pull request moved after it was listed.
    """
    target = targets.targets.get(name)
    if target is None:
        raise SetupError(f"{name!r} is not a registered scan target")
    if pull is not None and (run_id is not None or not target.pull_requests):
        raise SetupError(f"{name} does not scan pull requests (pull_requests = true in {scanning.TARGETS_FILE})")
    if pull is not None and target.kind != "url":
        # Pull requests are fetched anonymously, never with an administrator's git configuration (credentials,
        # insteadOf rules), which a mirror or a hand-set clone would need.
        raise SetupError(
            f"{name}: pull requests are fetched anonymously from an https source, and this target's source is a "
            f"{target.kind}"
        )
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
    record_failure = False  # a pull request whose scan failed is recorded as a scan error
    started = history.parse_timestamp(None)
    try:
        sweep_stale_work(state_dir)
        job = Job(state_dir, targets, target, who, log, pinned, pull)
        conn = history.open_for_write(job.db)
        trigger_id = history.start_trigger(conn, name, who, started, trigger)
        _write_status(
            state_dir, target=name, started=started, finished=None, outcome="running", run_id=None, pid=os.getpid()
        )
        job.say(f"scan of {name}" + (f" pull request #{pull.number}" if pull else "") + f" started by {who}")
        outcome, run_id = job.execute()
    except ScanTimeout:
        outcome, detail = "timeout", f"stopped after {targets.timeout_seconds // 60} minutes; nothing was recorded"
        record_failure = job is not None
    except Stop:
        outcome, detail = "failed", "stopped by a signal; nothing was recorded"
    except (ShoalscanError, OSError, subprocess.SubprocessError) as exc:
        outcome, detail = "failed", str(exc)[:300]
        record_failure = job is not None
    finally:
        if job is not None and job.pull is not None:
            pull = job.pull  # the head fetched, if it moved after the listing
        if report is not None:
            report["scanned"] = bool(job is not None and job.scan_started)
            report["head"] = pull.head if pull is not None else None
        if pull is not None and record_failure and conn is not None:
            # Visible on the dashboard, and not tried again until the head changes (or RETRY_AFTER).
            run_id = _record_pull_failure(conn, name, pull, started, job)
            if run_id is not None and detail:
                detail = detail.replace("; nothing was recorded", "; recorded as a scan error")
        if pull is not None:
            # Which pull request, in the audit row too: scan_triggers has no ref of its own.
            detail = f"pull request #{pull.number} at {pull.head[:12]}" + (f": {detail}" if detail else "")
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


def _record_pull_failure(conn, name: str, pull: pullrequests.PullRequest, started: str, job) -> int | None:
    """Record a pull request's failed scan (fetch, size limits, scan or deadline) as a scan-error run."""
    try:
        return history.record_run(
            conn, history.RunInfo(name, pull.ref, pull.head, "pr", started), [], {}, {}, check_exit=2
        ).run_id
    except (ShoalscanError, sqlite3.Error) as exc:
        if job is not None:
            job.say(f"the scan error could not be recorded: {str(exc)[:200]}")
        return None


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


DISCOVERY_TIMEOUT_SECONDS = 300


def discover_pull_requests(targets: scanning.Targets, target: scanning.Target) -> pullrequests.Listing:
    """List the target's open pull requests with one anonymous `git ls-remote` of its https source."""
    if target.kind != "url" or not target.source:
        raise pullrequests.DiscoveryError("pull requests are listed only for an https source")
    pairs = scanning.GIT_HARDENED + scanning.GIT_URL_ONLY
    return pullrequests.discover(
        ["git", *scanning.git_args(pairs)],
        network_git_env(pairs),
        target.source,
        target.branch,
        min(DISCOVERY_TIMEOUT_SECONDS, targets.timeout_seconds),
    )


def scan_key(targets: scanning.Targets, target: scanning.Target, listing: pullrequests.Listing) -> str:
    """What a pull request's results depend on besides its head: the registered branch's head (its policy, rule
    dirs and merge base) and the target's own policy and baseline files. A head is scanned again when it changes."""
    digest = hashlib.sha256(listing.branch_head.encode("ascii"))
    for path in (targets.policy_path(target), targets.baseline_path(target)):
        digest.update(b"\0")
        if path is not None and path.is_file():
            digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def _recorded_pull_runs(targets: scanning.Targets, name: str) -> list[pullrequests.Recorded]:
    conn = history.open_for_write(targets.history_db or history.default_db_path())
    try:
        return [pullrequests.Recorded(*row) for row in history.pull_request_runs(conn, name)]
    finally:
        conn.close()


def _audit_discovery_failure(targets: scanning.Targets, name: str, detail: str) -> None:
    """A failed listing is a scan error in the audit, never "nothing to scan"."""
    conn = history.open_for_write(targets.history_db or history.default_db_path())
    try:
        now = history.parse_timestamp(None)
        trigger_id = history.start_trigger(conn, name, PR_WHO, now, PR_TRIGGER)
        history.finish_trigger(conn, trigger_id, "scan_error", None, scanning.sanitise_log([detail], None)[0], now)
    finally:
        conn.close()


def run_pull_requests(
    state_dir: Path, targets: scanning.Targets, log, wait_seconds: int | None = None, discover=None
) -> dict[str, str]:
    """Poll every enabled target with pull_requests = true, in file order: list its open pull requests and scan
    each new head as a pull-request run, one after another (see `shoalscan.pullrequests`).

    A target's poll waits out cooldown_minutes since its last poll; every scan counts against, and stops at,
    max_pr_scans_per_hour, a budget apart from the dashboard's; one poll scans at most max_pull_requests.
    Results are keyed by target name (the poll) and by `name#N` (one pull request).
    """
    discover = discover or discover_pull_requests
    results: dict[str, str] = {}
    wait = targets.timeout_seconds if wait_seconds is None else wait_seconds
    for target in targets.targets.values():
        if not target.pull_requests:
            continue
        name = target.name
        if not target.enabled:
            results[name] = "skipped: disabled"
            log.write(f"pull requests: skipping {name} (disabled)\n")
            continue
        key = name + scanning.PULL_REQUESTS_KEY
        with scanning.locked_requests(state_dir) as requests:
            cooldown = scanning.cooldown_wait(targets, key, requests)
            if not cooldown:
                requests["targets"][key] = time.time()
        if cooldown:
            results[name] = f"skipped: cooldown, polled less than cooldown_minutes ago (next poll in {cooldown} s)"
            log.write(f"pull requests: {name}: {results[name][9:]}\n")
            continue
        try:
            listing = discover(targets, target)
            recorded = _recorded_pull_runs(targets, name)
        except (ShoalscanError, OSError, sqlite3.Error) as exc:
            detail = f"pull-request discovery failed: {str(exc)[:250]}"
            results[name] = f"scan_error: {detail}"
            log.write(f"pull requests: {name}: {detail}\n")
            try:
                _audit_discovery_failure(targets, name, detail)
            except (ShoalscanError, OSError, sqlite3.Error) as audit_exc:
                log.write(f"pull requests: {name}: the failure could not be audited either: {audit_exc}\n")
            log.flush()
            continue
        state_path = state_dir / "pull_requests" / f"{scanning.slug(name)}.json"
        try:
            state = pullrequests.load_state(state_path)
            extra = pullrequests.eligible(listing, state)
            new_state = pullrequests.next_state(listing, state, extra)
            scanning.write_private(state_path, pullrequests.state_json(new_state))
            key = scan_key(targets, target, listing)
        except (ShoalscanError, OSError) as exc:
            detail = f"pull-request discovery failed: {str(exc)[:250]}"
            results[name] = f"scan_error: {detail}"
            log.write(f"pull requests: {name}: {detail}\n")
            _audit_discovery_failure(targets, name, detail)
            continue
        if state is None:
            log.write(
                f"pull requests: {name}: first poll; pull requests above #{max(listing.pulls, default=0)} and heads "
                "that move are scanned even without a merge ref from now on\n"
            )
        chosen = pullrequests.select(
            listing,
            recorded,
            targets.max_pull_requests,
            without_merge_ref=extra,
            key=key,
            scanned=new_state.scanned,
            attempts=new_state.attempts,
        )
        mergeable = sum(1 for p in listing.pulls.values() if p.has_merge_ref)
        results[name] = (
            f"listed: {len(chosen.to_scan)} to scan, {len(chosen.already_scanned)} already scanned, "
            f"{len(chosen.deferred)} over max_pull_requests"
        )
        log.write(
            f"pull requests: {name}: {len(listing.pulls)} pull request refs, {mergeable} with a merge ref; "
            f"{results[name][8:]}, {len(chosen.failed)} waiting to retry a scan error, {len(chosen.throttled)} "
            f"scanned within the hour, {chosen.not_open} closed, or older and unchanged without a merge ref\n"
        )
        for pull in chosen.deferred:
            results[f"{name}#{pull.number}"] = "deferred: over max_pull_requests, next poll"
        for pull in chosen.throttled:
            results[f"{name}#{pull.number}"] = "deferred: this pull request was scanned less than an hour ago"
        for pull in chosen.failed:
            results[f"{name}#{pull.number}"] = "deferred: its last scan was a scan error, tried again after a day"
        for pull in chosen.to_scan:
            label = f"{name}#{pull.number}"
            deadline = time.monotonic() + wait
            while scanning.lock_holder(state_dir) is not None and time.monotonic() < deadline:
                time.sleep(2)
            # Checked and reserved together, under the lock the dashboard takes too, just before the scan.
            stamp = time.time()
            with scanning.locked_requests(state_dir) as requests:
                over = scanning.hourly_wait(targets, requests, pull_requests=True)
                if not over:
                    requests["pr_recent"].append(stamp)
            if over:
                results[label] = "deferred: the hourly limit (max_pr_scans_per_hour) is reached, next poll"
                log.write(f"pull requests: {label}: {results[label][10:]}\n")
                continue
            try:
                report: dict = {}
                results[label] = run_one(state_dir, targets, name, PR_WHO, log, PR_TRIGGER, pull=pull, report=report)
                # Every attempt counts against PER_PULL_INTERVAL, whether or not it recorded anything.
                new_state.attempts[pull.number] = history.parse_timestamp(None)
                if results[label] in ("passed", "blocked") and report.get("head"):
                    new_state.scanned[report["head"]] = key
                scanning.write_private(state_path, pullrequests.state_json(new_state))
                if not report.get("scanned"):
                    _refund(state_dir, stamp)
            except SetupError as exc:
                # The scan never started (another scan holds the lock, say): its reservation goes back.
                _refund(state_dir, stamp)
                results[label] = f"skipped: {exc}"
                log.write(f"pull requests: {label}: {exc}\n")
            log.flush()
    return results


def _refund(state_dir: Path, stamp: float) -> None:
    """Give back a reservation in max_pr_scans_per_hour whose attempt ran no scan."""
    with scanning.locked_requests(state_dir) as requests:
        if stamp in requests["pr_recent"]:
            requests["pr_recent"].remove(stamp)


def poll_ok(outcome: str) -> bool:
    """A poll result that is not a failure: a recorded pass or block, a listing, or a skip by design."""
    return outcome in ("passed", "blocked") or outcome.startswith(
        ("listed: ", "deferred: ", "skipped: disabled", "skipped: cooldown")
    )


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
    group.add_argument(
        "--pull-requests",
        action="store_true",
        help="scan the new heads of the open pull requests of every enabled target with pull_requests = true",
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
        if args.pull_requests:
            results = run_pull_requests(state_dir, targets, sys.stdout)
            if not results:
                print("shoalscan scanjob: no enabled target has pull_requests = true; nothing was polled")
            for name, outcome in results.items():
                print(f"shoalscan scanjob: {name}: {outcome}")
            return 0 if all(poll_ok(o) for o in results.values()) else 1
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
