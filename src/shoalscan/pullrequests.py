"""Find the open pull requests of a public repository, without credentials, for `scanjob --pull-requests`.

The listing comes from one `git ls-remote` of the target's https source,
anonymous and with no credential helper, never from a forge's API (that would
need a token, and its rate limits are low without one). It asks for three
patterns: the registered branch, `refs/pull/*/head` and `refs/pull/*/merge`.

How "open" is decided, and its limits (checked against github.com):

- GitHub keeps `refs/pull/N/head` for every pull request ever opened, closed
  and merged ones included, so a head ref alone says nothing.
- GitHub keeps `refs/pull/N/merge`, the test merge with the base branch, for
  open pull requests it can merge. A pull request with conflicts may have no
  merge ref, or an old one. Some closed pull requests, and pull requests
  GitHub has deleted, keep theirs.
- So a pull request is a candidate when it has a merge ref, when an earlier
  pull-request run of the same `refs/pull/N/head` is recorded (an open pull
  request with conflicts that was scanned before still gets its new heads
  scanned), or when the poll state says it is worth a look without a merge
  ref (a pull request that conflicts from its first push has none): its
  number is above the high-water mark (the highest number the first poll of
  the target saw, so every pull request opened since polling began), or its
  head changed since the previous poll's listing (a closed pull request's
  head never changes). Once eligible, a number stays eligible. This bounds
  the churn of the hundreds of closed pull requests whose head refs GitHub
  keeps: the first poll never scans them, and later polls only when one moves.
  A head that already has a recorded pull-request run with results
  is skipped. A head whose run was a scan error is tried again only after
  RETRY_AFTER, after every other candidate. A closed pull request that kept
  its merge ref is scanned at most once, because its head never changes again.

Fairness, because anyone can open or push to a pull request: a pull request
is scanned at most once per PER_PULL_INTERVAL, however often it is pushed to,
and candidates go in order of when their pull request was last scanned
(never first, then the longest ago; lower numbers first among equals), so one
busy pull request cannot keep the others waiting. A poll scans at most
`max_pull_requests`.

Fail closed: when `git ls-remote` fails, times out, writes more than
MAX_LISTING_BYTES, prints a line that is not `<sha>\\t<ref>`, lists a ref twice,
or does not list the registered branch (proof that the listing really is of
that repository), discovery raises DiscoveryError, and the caller records a
scan error instead of reporting nothing to scan.
"""

from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from shoalscan.errors import SetupError

MAX_LISTING_BYTES = 32 * 1024 * 1024
MAX_PULL_NUMBER = 10**9
_SHA = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_PULL_REF = re.compile(r"refs/pull/([1-9][0-9]*)/(head|merge)")
_HEAD_REF = re.compile(r"refs/pull/([1-9][0-9]{0,9})/head")
# A head whose run was a scan error is tried again after this long; a pull request is scanned at most once per
# PER_PULL_INTERVAL.
RETRY_AFTER = timedelta(hours=24)
PER_PULL_INTERVAL = timedelta(hours=1)


class DiscoveryError(SetupError):
    """The open pull requests could not be listed; nothing may be concluded from it."""


@dataclass(frozen=True)
class PullRequest:
    number: int
    head: str  # the head commit, as the listing showed it
    has_merge_ref: bool = False

    @property
    def ref(self) -> str:
        return f"refs/pull/{self.number}/head"

    @property
    def fetch_ref(self) -> str:
        """Where the worker keeps the fetched head, in the throwaway repository it fetches the pull request into."""
        return f"refs/shoalscan/pull/{self.number}"


@dataclass(frozen=True)
class Listing:
    branch_head: str
    pulls: dict[int, PullRequest]


@dataclass(frozen=True)
class Recorded:
    """A recorded pull-request run of this repository, as `history.pull_request_runs` lists it."""

    ref: str
    commit: str
    outcome: str
    scanned_at: str  # 2026-10-24T10:00:00Z


@dataclass
class Selection:
    to_scan: list[PullRequest] = field(default_factory=list)
    deferred: list[PullRequest] = field(default_factory=list)  # over the cap; next poll
    already_scanned: list[PullRequest] = field(default_factory=list)  # the head has a run with results
    failed: list[PullRequest] = field(default_factory=list)  # a scan error, tried again after RETRY_AFTER
    throttled: list[PullRequest] = field(default_factory=list)  # scanned less than PER_PULL_INTERVAL ago
    not_open: int = 0  # head refs without a merge ref and never scanned: closed, or unknown


def ls_remote_args(source: str, branch: str) -> list[str]:
    """The `git ls-remote` arguments after the hardening options. `--` keeps the source from being an option."""
    return ["ls-remote", "--", source, f"refs/heads/{branch}", "refs/pull/*/head", "refs/pull/*/merge"]


def parse_listing(text: str, branch: str) -> Listing:
    """Parse `git ls-remote` output strictly. Refs other than the three patterns are ignored
    (ls-remote matches patterns against the end of a ref name), anything malformed is refused."""
    branch_ref = f"refs/heads/{branch}"
    branch_head = None
    heads: dict[int, str] = {}
    merges: set[int] = set()
    lines = text.split("\n")
    if lines[-1] == "":
        lines.pop()  # the end of the last line
    for n, line in enumerate(lines, 1):
        sha, tab, ref = line.partition("\t")
        if not tab or not _SHA.fullmatch(sha) or not ref or any(c <= " " or c == "\x7f" for c in ref):
            raise DiscoveryError(f"git ls-remote printed a line that is not a ref (line {n})")
        if ref == branch_ref:
            if branch_head is not None:
                raise DiscoveryError(f"git ls-remote listed {branch_ref} twice")
            branch_head = sha
            continue
        match = _PULL_REF.fullmatch(ref)
        if match is None:
            continue
        digits = match.group(1)
        if len(digits) > len(str(MAX_PULL_NUMBER)) or int(digits) > MAX_PULL_NUMBER:
            raise DiscoveryError(f"git ls-remote listed an implausible pull request number: {digits[:20]}")
        number = int(digits)
        if match.group(2) == "head":
            if number in heads:
                raise DiscoveryError(f"git ls-remote listed {ref} twice")
            heads[number] = sha
        else:
            if number in merges:
                raise DiscoveryError(f"git ls-remote listed {ref} twice")
            merges.add(number)
    if branch_head is None:
        raise DiscoveryError(
            f"the listing does not show the branch {branch}, so it is not a listing of the registered repository"
        )
    # A merge ref without a head ref names nothing that can be scanned.
    pulls = {number: PullRequest(number, sha, number in merges) for number, sha in heads.items()}
    return Listing(branch_head, pulls)


def head_ref_number(ref: str) -> int | None:
    """N for `refs/pull/N/head`, else None."""
    match = _HEAD_REF.fullmatch(ref)
    return int(match.group(1)) if match else None


def _time(stamp: str) -> datetime:
    return datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def select(
    listing: Listing,
    recorded: list[Recorded],
    cap: int,
    now: datetime | None = None,
    without_merge_ref: set[int] | frozenset[int] = frozenset(),
    key: str | None = None,
    scanned: dict[str, str] | None = None,
    attempts: dict[int, str] | None = None,
) -> Selection:
    """What one poll scans, given every recorded pull-request run of this repository (see the module's notes).

    A candidate has a merge ref, a recorded run of its head ref, or a number in `without_merge_ref`.
    A head commit with a recorded run that has results is skipped, whatever its ref, as long as its results
    were recorded under `key` (the scan key: the registered branch's head and the target's policy and baseline
    files; `scanned` maps heads to the key of their results) and goes again otherwise, after the never-scanned
    heads; one whose runs are all scan errors waits RETRY_AFTER and then goes last. A pull request scanned less
    than PER_PULL_INTERVAL ago waits. The rest go in order of when their pull
    request was last scanned (never first), lower numbers first among equals, at most `cap`.
    """
    now = now or datetime.now(timezone.utc)
    by_commit: dict[str, list[Recorded]] = {}
    last_scan: dict[int, datetime] = {}
    for run in recorded:
        by_commit.setdefault(run.commit, []).append(run)
        number = head_ref_number(run.ref)
        if number is not None:
            when = _time(run.scanned_at)
            last_scan[number] = max(when, last_scan.get(number, when))
    # An attempt that recorded nothing (the head moved, say) still counts: PER_PULL_INTERVAL is per attempt.
    for number, stamp in (attempts or {}).items():
        when = _time(stamp)
        last_scan[number] = max(when, last_scan.get(number, when))
    never = datetime.min.replace(tzinfo=timezone.utc)
    out = Selection()
    candidates = []
    for number in sorted(listing.pulls):
        pull = listing.pulls[number]
        runs = by_commit.get(pull.head, [])
        # Looks open now: a merge ref, or eligible by the poll state (above the mark, or its head moved). Only such a
        # pull request has a scanned head scanned again or a scan error retried; a closed one never changes again.
        active = pull.has_merge_ref or number in without_merge_ref
        results = any(r.outcome != "scan_error" for r in runs)
        if not pull.has_merge_ref and number not in last_scan and number not in without_merge_ref:
            out.not_open += 1
        elif results and (key is None or (scanned or {}).get(pull.head) == key or not active):
            out.already_scanned.append(pull)
        elif runs and not results and (not active or now - max(_time(r.scanned_at) for r in runs) < RETRY_AFTER):
            out.failed.append(pull)
        elif number in last_scan and now - last_scan[number] < PER_PULL_INTERVAL:
            out.throttled.append(pull)
        else:
            # Never-scanned heads first, then heads whose results predate the scan key, then scan-error retries.
            tier = 0 if not runs else (2 if all(r.outcome == "scan_error" for r in runs) else 1)
            candidates.append((tier, last_scan.get(number, never), number, pull))
    candidates.sort(key=lambda c: c[:3])
    ordered = [c[3] for c in candidates]
    out.to_scan, out.deferred = ordered[:cap], ordered[cap:]
    return out


MAX_STATE_BYTES = 16 * 1024 * 1024


@dataclass
class PollState:
    """What a target's previous poll saw, kept in the state directory between polls."""

    mark: int  # the highest pull request number the first poll saw
    heads: dict[int, str]  # every pull request's head, as the previous listing showed it
    tracked: set[int]  # numbers that became eligible without a merge ref
    # The scan key each head's latest results were recorded under (see `select`), for heads still listed.
    scanned: dict[str, str] = field(default_factory=dict)
    # When each listed pull request was last attempted (scanned or not), so PER_PULL_INTERVAL counts attempts.
    attempts: dict[int, str] = field(default_factory=dict)


def load_state(path: Path) -> PollState | None:
    """The previous poll's state; None before the first poll. A state that cannot be read fails closed."""
    try:
        if path.stat().st_size > MAX_STATE_BYTES:
            raise DiscoveryError(f"the poll state {path.name} is larger than {MAX_STATE_BYTES} bytes")
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, ValueError, RecursionError) as exc:
        raise DiscoveryError(f"the poll state {path.name} cannot be read ({exc}); remove it to start again") from None
    try:
        mark = data["mark"]
        heads = {int(n): sha for n, sha in data["heads"].items()}
        tracked = {int(n) for n in data["tracked"]}
        attempts = {int(n): when for n, when in data.get("attempts", {}).items()}
        for when in attempts.values():
            _time(when)
        scanned = data.get("scanned", {})
        if not isinstance(scanned, dict) or not all(
            isinstance(k, str) and _SHA.fullmatch(k) and isinstance(v, str) and len(v) <= 128
            for k, v in scanned.items()
        ):
            raise ValueError
        if (
            isinstance(mark, bool)
            or not isinstance(mark, int)
            or not 0 <= mark <= MAX_PULL_NUMBER
            or not all(isinstance(sha, str) and _SHA.fullmatch(sha) for sha in heads.values())
        ):
            raise ValueError
    except (KeyError, TypeError, ValueError, AttributeError):
        raise DiscoveryError(f"the poll state {path.name} is malformed; remove it to start again") from None
    return PollState(mark, heads, tracked, scanned, attempts)


def eligible(listing: Listing, state: PollState | None) -> set[int]:
    """Pull request numbers that are candidates even without a merge ref (see the module's notes)."""
    if state is None:
        return set()
    out = {n for n in state.tracked if n in listing.pulls}
    for number, pull in listing.pulls.items():
        before = state.heads.get(number)
        if number > state.mark or (before is not None and before != pull.head):
            out.add(number)
    return out


def next_state(
    listing: Listing, state: PollState | None, tracked: set[int], recorded_heads: set[str] | frozenset = frozenset()
) -> PollState:
    """The state to keep after this poll. A tracked number goes once its current head has a recorded run (its new
    heads are candidates anyway, as an earlier run of its ref is recorded), or once it is no longer listed."""
    tracked = {n for n in tracked if n in listing.pulls and listing.pulls[n].head not in recorded_heads}
    mark = state.mark if state is not None else max(listing.pulls, default=0)
    heads = {p.head for p in listing.pulls.values()}
    scanned = {h: k for h, k in (state.scanned if state is not None else {}).items() if h in heads}
    attempts = {n: w for n, w in (state.attempts if state is not None else {}).items() if n in listing.pulls}
    return PollState(mark, {n: p.head for n, p in listing.pulls.items()}, set(tracked), scanned, attempts)


def state_json(state: PollState) -> str:
    return json.dumps(
        {
            "scanned": dict(sorted(state.scanned.items())),
            "attempts": {str(n): when for n, when in sorted(state.attempts.items())},
            "mark": state.mark,
            "heads": {str(n): sha for n, sha in sorted(state.heads.items())},
            "tracked": sorted(state.tracked),
        }
    )


def list_remote(argv: list[str], env: dict, timeout: float) -> str:
    """Run `git ls-remote` (the full argument list) in its own session, with a deadline and a cap on its output.

    Any failure is a DiscoveryError: a non-zero exit, the deadline, too much output or output that is not UTF-8.
    """
    with (
        tempfile.TemporaryDirectory(prefix="shoalscan-ls-remote-") as tmp,
        tempfile.TemporaryFile() as out,
        tempfile.TemporaryFile() as err,
    ):
        try:
            proc = subprocess.Popen(
                argv,
                cwd=tmp,  # outside every repository, so no repository configuration is read
                stdin=subprocess.DEVNULL,
                stdout=out,
                stderr=err,
                env=env,
                start_new_session=True,
            )
        except OSError as exc:
            raise DiscoveryError(f"git could not run: {exc}") from None
        deadline = time.monotonic() + timeout
        problem = None
        while proc.poll() is None:
            if time.monotonic() >= deadline:
                problem = f"git ls-remote did not finish within {int(timeout)} seconds"
            elif os.fstat(out.fileno()).st_size > MAX_LISTING_BYTES:
                problem = f"git ls-remote printed more than {MAX_LISTING_BYTES // (1024 * 1024)} MB"
            if problem:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.wait()
                break
            time.sleep(0.05)
        err.seek(0)
        stderr = err.read(4096).decode("utf-8", "replace")
        if problem:
            raise DiscoveryError(problem)
        if proc.returncode != 0:
            last = stderr.strip().splitlines()[-1:] or [""]
            raise DiscoveryError(f"git ls-remote failed (exit {proc.returncode}): {last[0][:200]}")
        if os.fstat(out.fileno()).st_size > MAX_LISTING_BYTES:
            raise DiscoveryError(f"git ls-remote printed more than {MAX_LISTING_BYTES // (1024 * 1024)} MB")
        out.seek(0)
        try:
            return out.read().decode("utf-8")
        except UnicodeDecodeError:
            raise DiscoveryError("git ls-remote printed something that is not UTF-8") from None


def discover(git_argv: list[str], env: dict, source: str, branch: str, timeout: float) -> Listing:
    """List the open pull requests of `source`. `git_argv` is git and its hardening options."""
    return parse_listing(list_remote([*git_argv, *ls_remote_args(source, branch)], env, timeout), branch)
