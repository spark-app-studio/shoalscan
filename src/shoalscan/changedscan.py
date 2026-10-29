"""A pull request scan of its changed files only (`shoalscan scan --changed-only`).

Opengrep reads each file on its own, so for a changed file a scan of the
changed files reports exactly what a full scan reports. Opengrep still walks
the repository as in a full scan, with the same excludes, size limit and
handling of symbolic links; `--include` patterns narrow the walk to the
changed files. Naming the files as explicit targets instead would not be the
same: Opengrep scans an explicit target even when an `--exclude` pattern or
`--max-target-bytes` would have left it out.

The list of changed files comes from git, never from the change: every path
that differs between the policy commit and the working tree, with renames
split into a deletion and an addition, plus untracked files. `check` lists
them again and refuses findings whose list differs.
"""

from __future__ import annotations

import fnmatch
import hashlib
import os
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from shoalscan import gitref, opengrep_langs
from shoalscan.errors import ScanError, SetupError
from shoalscan.excludes import ExcludeMatcher

MODE_FULL = "full"
MODE_CHANGED = "changed"
# More targets than this are refused: a change that large is scanned in full.
MAX_TARGETS = 2000
# Characters an --include pattern would read as a glob or an escape.
_GLOB_CHARS = frozenset("*?[]\\")
# Opengrep's skip reason for a file the --include patterns leave out.
_INCLUDE_SKIP = "cli_include_flags_do_not_match"


@dataclass(frozen=True)
class ChangedFiles:
    """What a change touches, sorted out the way the scan treats each path.

    `targets` are the regular files Opengrep is asked to scan. `deleted` are
    paths the change removed (a rename's old path among them). `excluded` match
    the configuration's excludes, `links` are symbolic links (a full scan does
    not follow them either), and `other` exist but are not regular files, such
    as a submodule. `paths` is every path the change touches, whatever its kind.
    """

    base: str
    targets: tuple[str, ...]
    deleted: tuple[str, ...]
    excluded: tuple[str, ...]
    links: tuple[str, ...]
    other: tuple[str, ...]

    @property
    def paths(self) -> frozenset[str]:
        return frozenset((*self.targets, *self.deleted, *self.excluded, *self.links, *self.other))

    def targets_sha256(self) -> str:
        return hashlib.sha256("\0".join(self.targets).encode("utf-8")).hexdigest()

    def record(self) -> dict:
        return {
            "base": self.base,
            "targets": list(self.targets),
            "targets_sha256": self.targets_sha256(),
            "deleted": list(self.deleted),
            "excluded": list(self.excluded),
            "links": list(self.links),
            "other": list(self.other),
        }


def changed_files(repo: Path, commit: str, excludes: tuple[str, ...] | list[str]) -> ChangedFiles:
    """Every path that differs between `commit` and the working tree, sorted by kind.

    `commit` must be an ancestor of HEAD: a scan of changed files is judged
    against it, so a commit the change does not build on is refused.
    """
    root = repo.resolve()
    if not gitref.is_ancestor(root, commit):
        raise SetupError(f"--changed-only: the policy commit {commit[:12]} is not an ancestor of HEAD")
    matcher = ExcludeMatcher(list(excludes))
    targets, deleted, excluded, links, other = [], [], [], [], []
    for path in gitref.touched_paths(root, commit):
        full = root / path
        if not os.path.lexists(full):
            deleted.append(path)
        elif matcher.excluded(path):
            excluded.append(path)
        elif full.is_symlink():
            links.append(path)
        elif not full.is_file():
            other.append(path)
        else:
            targets.append(path)
    # The excluded files are passed too, so that the scan proves Opengrep leaves them out as well.
    unsafe = [p for p in (*targets, *excluded) if set(p) & _GLOB_CHARS or p != p.strip()]
    if unsafe:
        raise SetupError(
            f"--changed-only: {len(unsafe)} changed file names cannot be passed to Opengrep as exact --include "
            f"patterns (glob characters or edge spaces), such as {unsafe[0]!r}; scan the whole repository"
        )
    if len(targets) + len(excluded) > MAX_TARGETS:
        raise SetupError(
            f"--changed-only: the change has {len(targets) + len(excluded)} files, more than {MAX_TARGETS}; "
            "scan the whole repository"
        )
    return ChangedFiles(commit, tuple(targets), tuple(deleted), tuple(excluded), tuple(links), tuple(other))


def include_patterns(changed: ChangedFiles) -> list[str]:
    """One anchored --include pattern per target and per excluded file: `/path` matches that path from the scan
    root only. Opengrep's own excludes still apply, and an excluded file it scans anyway stops the scan."""
    return [f"/{path}" for path in sorted((*changed.targets, *changed.excluded))]


@dataclass(frozen=True)
class LoadedRules:
    """What the staged rules read: their languages, and the `paths: include` globs of their
    `generic`, `aliengrep` and `regex` rules."""

    languages: frozenset[str]
    include_globs: tuple[str, ...]


def loaded_languages(rules_stage: Path) -> LoadedRules | None:
    """What the rules staged for Opengrep read, or None when every file counts as read.

    None is returned when a rule's languages cannot be read, when a `generic`, `aliengrep` or `regex` rule has
    no `paths: include` that can be read (Opengrep then runs it on every file), and when the stage holds a
    link: staging copies files and directories and never links one, so a link is not something Shoalscan
    staged, and a linked directory is not walked.
    """
    from shoalscan.opengrep import is_rule_file
    from shoalscan.rulesets import rule_include_globs, rule_languages, split_rules

    found: set[str] = set()
    globs: list[str] = []
    for dirpath, dirnames, filenames in os.walk(rules_stage, followlinks=False):
        if any((Path(dirpath) / d).is_symlink() for d in dirnames):
            return None
        dirnames.sort()
        for name in sorted(filenames):
            path = Path(dirpath) / name
            if not is_rule_file(name):
                continue
            if path.is_symlink():
                return None
            for rule in split_rules(path.read_text(encoding="utf-8"), str(path.relative_to(rules_stage))):
                languages = rule_languages(rule)
                if languages is None:
                    return None
                if languages & opengrep_langs.ANY_FILE:
                    include = rule_include_globs(rule)
                    if include is None:
                        return None
                    globs.extend(include)
                found |= languages - opengrep_langs.ANY_FILE
    return LoadedRules(frozenset(found), tuple(dict.fromkeys(globs)))


def matches_include(path: str, globs: tuple[str, ...]) -> bool:
    """Whether a repository path may match one of Opengrep's `paths: include` globs.

    This errs toward a match, so a dropped file is refused rather than passed: case is ignored, `*` crosses
    `/`, a leading or trailing `/` is dropped, and a glob is tried against every trailing part of the path and
    every directory above the file (`sites-enabled/*` matches `etc/nginx/sites-enabled/x`, `docs/` matches
    `docs/a.md`). A rule's `exclude` is not applied.
    """
    parts = PurePosixPath(path.lower()).parts
    candidates = set()
    for start in range(len(parts)):
        for stop in range(start + 1, len(parts) + 1):
            candidates.add("/".join(parts[start:stop]))
    for glob in globs:
        pattern = glob.lower().strip("/")
        if pattern and any(fnmatch.fnmatchcase(c, pattern) for c in candidates):
            return True
    return False


def refuse_silent_drops(unread: list[str], root: Path, loaded: LoadedRules | None) -> None:
    """Stop the scan when Opengrep left out a changed file that a loaded rule reads.

    A file no loaded rule reads is listed nowhere by Opengrep, and is only named. A file one of them reads (by
    its language's extension, its name, or, with no extension, its shebang; see `opengrep_langs`; or by a
    `generic`, `aliengrep` or `regex` rule's `paths: include`) should have been scanned or skipped with a
    reason, so its absence means Opengrep dropped it without saying so.
    """
    for path in unread:
        if (
            loaded is None
            or opengrep_langs.reads(root / path, path, loaded.languages)
            or matches_include(path, loaded.include_globs)
        ):
            raise ScanError(
                f"--changed-only: opengrep did not account for {path!r}, a changed file the loaded rules read "
                "(not scanned, skipped or errored); nothing is known about it"
            )


def account_for_targets(doc: dict, root: Path, changed: ChangedFiles) -> list[str]:
    """Fail unless Opengrep scanned nothing but targets and the walk kept every target; return the targets no
    rule read.

    Opengrep lists a file as scanned only when a rule's language applies to it, and lists a file that no rule
    can read nowhere at all, in a full scan as in this one (a Markdown file with only Python rules, say). Such a
    target is returned, so the scan reports it; a full scan says nothing about it. What would make a scan of
    changed files differ from a full scan stops the scan: a scanned file that is not a target, a target the
    --include filter left out, and an excluded file that was scanned.
    """
    from shoalscan.opengrep import relative_path

    def rel(path: object) -> str | None:
        if not isinstance(path, str):
            return None
        try:
            return relative_path(path, root)
        except ScanError:
            return None

    paths = doc.get("paths") if isinstance(doc.get("paths"), dict) else {}
    scanned = {rel(p) for p in paths.get("scanned") or []}
    skipped = {rel(e.get("path")) for e in paths.get("skipped") or [] if isinstance(e, dict)}
    left_out = {
        rel(e.get("path"))
        for e in paths.get("skipped") or []
        if isinstance(e, dict) and e.get("reason") == _INCLUDE_SKIP
    }
    errored = {rel(e.get("path")) for e in doc.get("errors") or [] if isinstance(e, dict)}
    targets = set(changed.targets)
    disagree = sorted(scanned & set(changed.excluded))
    if disagree:
        raise ScanError(
            f"--changed-only: opengrep scanned {disagree[0]!r}, which Shoalscan reads as excluded; the two exclude "
            "matchers disagree, so a scan of changed files would not match a full scan"
        )
    outside = sorted(p for p in scanned - targets if p is not None)
    if None in scanned or outside:
        raise ScanError(
            f"--changed-only: opengrep scanned files that are not changed targets, such as {(outside or ['?'])[0]!r}"
        )
    filtered = sorted(targets & left_out)
    if filtered:
        raise ScanError(f"--changed-only: the --include patterns left out a changed file: {filtered[0]!r}")
    return sorted(targets - scanned - (skipped - left_out) - errored)
