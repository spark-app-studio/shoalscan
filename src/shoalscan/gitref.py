"""Read policy files from a git ref, and list the files a change touches.

On a pull request the configuration, the baseline and the repository's own
rules must come from the base branch, not from the change under review;
otherwise a pull request could relax its own checks. These helpers read them
with `git show` and `git archive`.
"""

from __future__ import annotations

import hashlib
import io
import os
import re
import subprocess
import tarfile
from pathlib import Path, PurePosixPath

from shoalscan.errors import SetupError

GIT_TIMEOUT_SECONDS = 120
MAX_GIT_OUTPUT = 256 * 1024 * 1024
_REF_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_./@{}^~\-]{0,250}$")


def validate_ref(ref: str) -> str:
    if not _REF_RE.match(ref) or ".." in ref:
        raise SetupError(f"invalid --policy-ref: {ref!r}")
    return ref


def _git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    cmd = ["git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-C", str(repo), *args]
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=GIT_TIMEOUT_SECONDS, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        raise SetupError(f"git timed out: {' '.join(args[:2])}") from None
    except OSError as exc:
        raise SetupError(f"git could not run: {exc}") from None
    if len(proc.stdout) > MAX_GIT_OUTPUT:
        raise SetupError("git output is larger than allowed")
    if check and proc.returncode != 0:
        detail = proc.stderr.decode("utf-8", errors="replace").strip()[-500:]
        raise SetupError(f"git {' '.join(args[:2])} failed: {detail}")
    return proc


_FULL_SHA = re.compile(r"^[0-9a-f]{40}$|^[0-9a-f]{64}$")


def resolve_commit(repo: Path, ref: str) -> str:
    """Resolve the policy ref to a commit, refusing anything that could be shadowed.

    Only two forms are accepted: a full commit SHA, or a fully qualified
    `refs/heads/...` or `refs/remotes/...` ref that exists. A short name such
    as `origin/main` is refused: git prefers a tag of that name over the
    remote-tracking branch, so a pushed tag could pick the policy.
    """
    validate_ref(ref)
    if _FULL_SHA.match(ref):
        kind = _git(repo, "cat-file", "-t", ref, check=False)
        if kind.returncode != 0 or kind.stdout.decode().strip() != "commit":
            raise SetupError(f"--policy-ref {ref} is not a commit in this repository")
        return ref
    if not ref.startswith(("refs/heads/", "refs/remotes/")) or any(c in ref for c in "^~@{}"):
        raise SetupError(
            f"--policy-ref {ref!r} is ambiguous: pass the base commit's full SHA (in GitHub Actions, "
            "github.event.pull_request.base.sha) or a fully qualified refs/remotes/... or refs/heads/... ref"
        )
    shown = _git(repo, "show-ref", "--verify", ref, check=False)
    if shown.returncode != 0:
        raise SetupError(f"--policy-ref {ref} does not exist")
    sha = shown.stdout.decode().split()[0]
    out = _git(repo, "rev-parse", "--verify", "--end-of-options", f"{sha}^{{commit}}").stdout.decode().strip()
    if not _FULL_SHA.match(out):
        raise SetupError(f"--policy-ref {ref} does not name a commit")
    return out


def show_file(repo: Path, commit: str, path: str) -> bytes | None:
    """Return a file's content at `commit`, or None if the file does not exist there."""
    exists = _git(repo, "cat-file", "-e", f"{commit}:{path}", check=False)
    if exists.returncode != 0:
        return None
    return _git(repo, "cat-file", "blob", f"{commit}:{path}").stdout


def archive_dirs(repo: Path, commit: str, dirs: list[str], dest: Path) -> None:
    """Extract the regular files of `dirs` at `commit` into `dest`. Links are skipped."""
    if not dirs:
        return
    for d in dirs:
        if _git(repo, "cat-file", "-e", f"{commit}:{d}", check=False).returncode != 0:
            raise SetupError(f"rule directory {d} does not exist at the policy ref")
    data = _git(repo, "archive", "--format=tar", commit, "--", *dirs).stdout
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as tar:
        for member in tar:
            parts = PurePosixPath(member.name).parts
            if member.name.startswith("/") or ".." in parts:
                raise SetupError(f"unexpected path in git archive: {member.name!r}")
            if not member.isreg():
                continue
            handle = tar.extractfile(member)
            if handle is None:
                continue
            target = dest.joinpath(*parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(handle.read())


def merge_base(repo: Path, commit: str) -> str:
    out = _git(repo, "merge-base", commit, "HEAD").stdout.decode().strip()
    if not _FULL_SHA.match(out):
        raise SetupError("could not find the merge base of the policy ref and HEAD")
    return out


def changed_files(repo: Path, commit: str) -> list[str]:
    """Files the change adds, copies, modifies, renames or retypes, compared
    with the merge base of `commit` and HEAD. The working tree counts,
    untracked files included, so a local run sees uncommitted edits."""
    base = merge_base(repo, commit)
    out = _git(repo, "diff", "--name-only", "-z", "--no-renames", "--diff-filter=ACMRT", base).stdout
    untracked = _git(repo, "ls-files", "--others", "--exclude-standard", "-z").stdout
    names = (out + b"\0" + untracked).decode("utf-8", errors="replace").split("\0")
    return sorted({p for p in names if p})


def diff_against(repo: Path, commit: str, paths: list[str], max_lines: int = 400) -> str:
    """The working tree's diff against `commit` for `paths`, cut to `max_lines` lines."""
    if not paths:
        return ""
    out = _git(repo, "diff", "--no-color", "--no-ext-diff", commit, "--", *paths).stdout
    lines = out.decode("utf-8", errors="replace").splitlines()
    if len(lines) > max_lines:
        lines = lines[:max_lines] + [f"... ({len(lines) - max_lines} more lines)"]
    return "\n".join(lines)


def baseline_binding_path(repo: Path, baseline: Path) -> str | None:
    """The baseline file's path relative to `repo`, if it may be left out of the tree binding.

    Returns None (nothing is left out, the binding stays strict) when the path
    is outside the repository, inside `.git`, not a regular file, or reached
    through a symbolic link below the repository root: then the path git sees
    and the file `check` reads could differ. `..` is resolved lexically first.
    """
    root = repo.resolve()
    lexical = Path(os.path.normpath(os.path.abspath(baseline)))
    for base in (Path(os.path.normpath(os.path.abspath(repo))), root):
        try:
            rel = lexical.relative_to(base)
            break
        except ValueError:
            continue
    else:
        return None
    if not rel.parts or rel.parts[0] == ".git":
        return None
    target = root / rel
    try:
        if target.resolve() != target or target.is_symlink():
            return None
        if target.exists() and not target.is_file():
            return None
    except (OSError, RuntimeError):
        return None
    return rel.as_posix()


def _changes_digest(repo: Path, tree: str | None, options: tuple[str, ...], pathspec: tuple[str, ...]) -> tuple[bool, str]:
    status = _git(repo, "status", "--porcelain=v1", "-z", "--untracked-files=all", *options, *pathspec).stdout
    digest = hashlib.sha256(status)
    if tree is not None:
        digest.update(_git(repo, "diff", "--no-ext-diff", "--binary", *options, "HEAD", *pathspec).stdout)
    for entry in status.split(b"\0"):
        if entry.startswith(b"?? "):
            path = repo / entry[3:].decode("utf-8", errors="surrogateescape")
            if path.is_file() and not path.is_symlink():
                digest.update(entry[3:] + b"\0" + hashlib.sha256(path.read_bytes()).digest())
    return bool(status), digest.hexdigest()


def worktree_state(repo: Path, baseline: str | None = None) -> dict | None:
    """Identify what was scanned: the HEAD tree, and whether the working tree differs.

    Returns None outside a git work tree. `changes_sha256` hashes the status
    (untracked files included) and the full diff against HEAD, so any edit
    after the scan is noticed even in a dirty tree.

    With `baseline` (a path from `baseline_binding_path`), the state also
    carries `without_baseline`: the same dirty flag and digest computed with
    that one file left out, so `check` can accept an edit to the baseline it
    reads and nothing else. Renames are not paired there, so a file renamed
    to the baseline's path still shows as deleted.
    """
    inside = _git(repo, "rev-parse", "--is-inside-work-tree", check=False)
    if inside.returncode != 0 or inside.stdout.decode().strip() != "true":
        return None
    head = _git(repo, "rev-parse", "--verify", "--quiet", "HEAD^{tree}", check=False)
    tree = head.stdout.decode().strip() if head.returncode == 0 else None
    head_commit = _git(repo, "rev-parse", "--verify", "--quiet", "HEAD^{commit}", check=False)
    commit = head_commit.stdout.decode().strip() if head_commit.returncode == 0 else None
    dirty, changes = _changes_digest(repo, tree, (), ())
    state = {"commit": commit, "tree": tree, "dirty": dirty, "changes_sha256": changes}
    if baseline is not None:
        spec = ("--", ":/", f":(exclude,literal){baseline}")
        dirty, changes = _changes_digest(repo, tree, ("--no-renames",), spec)
        state["without_baseline"] = {"path": baseline, "dirty": dirty, "changes_sha256": changes}
    return state


_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def added_lines(repo: Path, commit: str, path: str) -> set[int]:
    """Line numbers (in the current file) that the change added or modified."""
    tracked = _git(repo, "ls-files", "--error-unmatch", "--", path, check=False).returncode == 0
    if not tracked:
        full = repo / path
        try:
            count = len(full.read_bytes().split(b"\n"))
        except OSError:
            return set()
        return set(range(1, count + 1))
    out = _git(repo, "diff", "--no-color", "--no-ext-diff", "--no-renames", "-U0", merge_base(repo, commit), "--", path).stdout
    lines: set[int] = set()
    for line in out.decode("utf-8", errors="replace").split("\n"):
        match = _HUNK.match(line)
        if match:
            start, count = int(match.group(1)), int(match.group(2) if match.group(2) is not None else 1)
            lines.update(range(start, start + count))
    return lines


def renames(repo: Path, commit: str) -> list[tuple[str, str]]:
    """(old, new) pairs that git reports as renames with at least 90% similarity."""
    out = _git(repo, "diff", "-M90%", "--name-status", "-z", merge_base(repo, commit)).stdout.decode("utf-8", errors="replace")
    parts = out.split("\0")
    pairs = []
    i = 0
    while i < len(parts) and parts[i]:
        status = parts[i]
        if status.startswith(("R", "C")):
            if status.startswith("R"):
                pairs.append((parts[i + 1], parts[i + 2]))
            i += 3
        else:
            i += 2
    return pairs
