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
- So a pull request is a candidate when it has a merge ref, or when an earlier
  pull-request run of the same `refs/pull/N/head` is recorded (an open pull
  request with conflicts that was scanned before still gets its new heads
  scanned). A head that already has a recorded pull-request run is skipped.
  Candidates go newest first, and a poll scans at most `max_pull_requests`.
  A closed pull request that kept its merge ref is scanned at most once,
  because its head never changes again.

Fail closed: when `git ls-remote` fails, times out, writes more than
MAX_LISTING_BYTES, prints a line that is not `<sha>\\t<ref>`, lists a ref twice,
or does not list the registered branch (proof that the listing really is of
that repository), discovery raises DiscoveryError, and the caller records a
scan error instead of reporting nothing to scan.
"""

from __future__ import annotations

import os
import re
import signal
import subprocess
import tempfile
import time
from dataclasses import dataclass, field

from shoalscan.errors import SetupError

MAX_LISTING_BYTES = 32 * 1024 * 1024
MAX_PULL_NUMBER = 10**9
_SHA = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_PULL_REF = re.compile(r"refs/pull/([1-9][0-9]*)/(head|merge)")
_HEAD_REF = re.compile(r"refs/pull/([1-9][0-9]{0,9})/head")


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


@dataclass
class Selection:
    to_scan: list[PullRequest] = field(default_factory=list)
    deferred: list[PullRequest] = field(default_factory=list)  # over the cap; next poll
    already_scanned: list[PullRequest] = field(default_factory=list)  # the head has a recorded run
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


def select(listing: Listing, recorded: list[tuple[str, str]], cap: int) -> Selection:
    """What one poll scans. `recorded` is the (ref, commit) of every pull-request run of this repository.

    A candidate has a merge ref, or a recorded run of its head ref; a head commit that already has a recorded
    pull-request run is skipped, whatever its ref. Newest first, at most `cap`.
    """
    commits = {commit for _ref, commit in recorded}
    seen = {n for n in (head_ref_number(ref) for ref, _commit in recorded) if n is not None}
    out = Selection()
    candidates = []
    for number in sorted(listing.pulls, reverse=True):
        pull = listing.pulls[number]
        if not pull.has_merge_ref and number not in seen:
            out.not_open += 1
        elif pull.head in commits:
            out.already_scanned.append(pull)
        else:
            candidates.append(pull)
    out.to_scan, out.deferred = candidates[:cap], candidates[cap:]
    return out


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
