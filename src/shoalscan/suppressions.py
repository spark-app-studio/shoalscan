"""The suppression lint.

Opengrep skips a finding on a line that carries one of its suppression
markers (the word "no" joined to "sem", "semgrep" or "opengrep"), or on the
line after one. This module mirrors Opengrep 1.30.2's grammar exactly
(src/reporting/Nosemgrep.ml):

    (?:\\b<marker>\\b)(?:[:=][\\s]?(?P<ids>([^,\\s](?:[,\\s]+)?)+))?   (case-insensitive)

That is: the marker, then `:` or `=` directly after it, then at most one
whitespace character, then the rule ids. The ids text is split on commas;
each piece is stripped of spaces and only its first space-separated word,
stripped of double quotes, is a rule id. When a marker has no ids, for
example `<marker> : rule` (space before the colon) or `<marker>:  rule` (two
spaces), Opengrep treats it as a bare suppression that silences every rule
on the line. The marker is matched anywhere on a line, even inside a string.

Shoalscan requires every marker to name valid rule ids and an issue (`#123`
or a URL), as in `<marker>: shoalscan.plain-http-url #123 local test server`.
Anything else is a finding that blocks; a bare marker is reported as bare.
Every suppression is counted. This module spells the markers in pieces so
that its own source carries none.

Trivy has its own inline markers, and cannot be told to disregard them.
Trivy 0.74.0 (pkg/iac/ignore/parse.go) splits each line on spaces, trims
leading `#`, `/` and `*` from each word, and takes a word that starts with
"trivy:" or with the legacy "tfsec:" prefix. The rest of the word is split
on `:` into key and value pairs, and the value after an "ignore" key is the
check id (anything from a `[` on is a parameter); "exp", "ws" and other keys
may come before or after it, as in "trivy:exp:2030-01-01:ignore:AVD-AWS-0089".
A `*` anywhere in the id is a wildcard, and ids match case-insensitively.
Shoalscan holds these markers to the same rule as Opengrep's: one specific
check id and an issue on the same line, or a blocking finding. To miss
none, it looks for either prefix anywhere in a line, in any letter case,
and treats every word with an "ignore" key as a marker. A wildcard is
reported like a bare marker.
"""

from __future__ import annotations

import re
import tarfile
import zlib
from dataclasses import dataclass
from pathlib import Path

from shoalscan.config import component_for
from shoalscan.findings import Finding, assign_fingerprints, split_lines

LINT_RULE = "shoalscan.suppression-without-rule-and-issue"
LINT_TOOL = "shoalscan"
_MARKER_WORDS = ("no" + "sem", "no" + "semgrep", "no" + "opengrep")
EXAMPLE = "no" + "semgrep: <rule-id> #<issue> <reason>"

# The same expression as Opengrep's get_nosem_inline_re with the default
# ignore patterns, translated to Python's re:
# - Opengrep matches the marker letters case-insensitively with Unicode case
#   folding, so "\u017f" (long s) matches "s"; Python's IGNORECASE in Unicode
#   mode does the same. (The Kelvin sign and the dotted and dotless i fold to
#   k and i, which no marker contains.)
# - Its \b, \s and \w are ASCII-only (no Unicode properties): "\u00e9" next to
#   the marker is a boundary and a no-break space is not whitespace. These
#   are spelled as explicit, case-sensitive ASCII classes.
_WORD = r"(?-i:[A-Za-z0-9_])"
_SPACE = r" \t\n\r\f\v"
_RULE_ID_RE = rf"(?:[:=][{_SPACE}]?(?P<ids>([^,{_SPACE}](?:[,{_SPACE}]+)?)+))?"
_INLINE = re.compile(
    "(?:" + "|".join(rf"(?<!{_WORD}){w}(?!{_WORD})" for w in _MARKER_WORDS) + ")" + _RULE_ID_RE,
    re.IGNORECASE,
)
_VALID_ID = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.\-/:]*$", re.ASCII)
TRIVY_MARKER = "trivy" + ":ignore:"
TRIVY_EXAMPLE = "#" + TRIVY_MARKER + "<check-id> #<issue> <reason>"
# Both prefixes Trivy accepts, matched anywhere on a line and in any case: reporting
# a marker Trivy would not honour is safer than missing one it would.
_TRIVY_PREFIXES = ("trivy", "tf" + "sec")
# Trivy splits a line on spaces only, so a tab or other white space stays inside the word.
_TRIVY = re.compile("(?:" + "|".join(_TRIVY_PREFIXES) + r"):(?P<rest>[^ \n]*)", re.ASCII | re.IGNORECASE)
_TRIVY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]*$", re.ASCII)
_ISSUE = re.compile(r"(?<![\w&])#\d+\b|https?://[^\s)\]>\"']+", re.ASCII)


@dataclass(frozen=True)
class Suppression:
    path: str
    line: int
    text: str
    rule_ids: tuple[str, ...]
    issue: str | None
    bare: bool
    kind: str = "opengrep"  # whose marker: "opengrep" or "trivy"

    @property
    def valid(self) -> bool:
        return (
            not self.bare
            and bool(self.rule_ids)
            and all(_VALID_ID.match(i) for i in self.rule_ids)
            and (self.issue is not None)
        )

    def problem(self) -> str:
        if self.bare and self.kind == "trivy":
            return "a Trivy suppression with a wildcard, of every check (*) or of several"
        if self.bare:
            return "a bare suppression (it silences every rule on the line)"
        if not self.rule_ids or not all(_VALID_ID.match(i) for i in self.rule_ids):
            return "a suppression with an invalid rule id"
        return "a suppression without an issue reference"


def opengrep_ids(ids_text: str) -> tuple[str, ...]:
    """Turn the `ids` group into rule ids the way Opengrep does."""
    out = []
    for piece in ids_text.split(","):
        piece = piece.strip(" ")
        word = piece.split(" ")[0]
        out.append(word.strip('"'))
    return tuple(out)


def parse_line(text: str) -> list[tuple[tuple[str, ...], str | None, bool]]:
    """Return (rule ids, issue, bare) for each suppression marker on a line."""
    out = []
    for match in _INLINE.finditer(text):
        ids_text = match.group("ids")
        if ids_text is None:
            out.append(((), None, True))
            continue
        issue = _ISSUE.search(text, match.start())
        out.append((opengrep_ids(ids_text), issue.group(0) if issue else None, False))
    return out


def find_suppressions(root: Path, rel_paths: list[str], max_bytes: int) -> list[Suppression]:
    """Find markers in the given files: every file Opengrep scanned."""
    found = []
    for rel in sorted(set(rel_paths)):
        full = root / rel
        try:
            if full.is_symlink() or not full.is_file() or full.stat().st_size > max_bytes:
                continue
            data = full.read_bytes()
        except OSError:
            continue
        text = data.decode("utf-8", errors="replace")
        # casefold() maps the long s and other folds, so this quick filter
        # never skips a file the expression would match.
        folded = text.casefold()
        if not any(word in folded for word in _MARKER_WORDS):
            continue
        for number, line in enumerate(split_lines(text), start=1):
            for ids, issue, bare in parse_line(line):
                found.append(Suppression(rel, number, line.strip(), ids, issue, bare))
    return found


def parse_trivy_line(text: str) -> list[tuple[tuple[str, ...], str | None, bool]]:
    """Return (check ids, issue, bare) for each Trivy marker on a line.

    A word with no "ignore" key (such as an image tag, `aquasec/trivy:0.74.0`)
    is not a marker. A marker whose check id is missing, malformed or given
    more than once has the id "", which is invalid; one with a wildcard is bare.
    """
    out: list[tuple[tuple[str, ...], str | None, bool]] = []
    for match in _TRIVY.finditer(text):
        segments = [s.strip() for s in match.group("rest").split(":")]
        keys = [i for i, s in enumerate(segments) if s.lower() == "ignore"]
        if not keys:
            continue
        ids = [segments[i + 1].split("[", 1)[0] for i in keys if i + 1 < len(segments)]
        if any("*" in i for i in ids):
            out.append(((), None, True))
            continue
        issue = _ISSUE.search(text, match.end())
        check = ids[0].strip() if len(ids) == 1 and _TRIVY_ID.match(ids[0]) else ""
        out.append(((check,), issue.group(0) if issue else None, False))
    return out


def _trivy_markers(rel: str, data: bytes, member: str = "") -> list[Suppression]:
    lowered = data.lower()
    if not any(p.encode() + b":" in lowered for p in _TRIVY_PREFIXES):
        return []
    found = []
    # Trivy numbers lines by "\n" alone, so this does too.
    for number, line in enumerate(data.decode("utf-8", errors="replace").split("\n"), start=1):
        for ids, issue, bare in parse_trivy_line(line):
            text = f"{member}: {line.strip()}" if member else line.strip()
            found.append(Suppression(rel, number, text, ids, issue, bare, kind="trivy"))
    return found


TRIVY_ARCHIVES = (".tgz", ".tar.gz", ".tar")
MAX_ARCHIVE_MEMBERS = 10_000


def _archive_markers(rel: str, full: Path, max_bytes: int) -> list[Suppression]:
    """Markers in the files of a packaged Helm chart, which Trivy reads too.

    An archive that cannot be read is skipped, as Trivy skips it. Its
    members are read up to `max_bytes` in all.
    """
    found: list[Suppression] = []
    budget = max_bytes
    try:
        with tarfile.open(full, mode="r:*") as tar:
            for count, info in enumerate(tar):
                if count >= MAX_ARCHIVE_MEMBERS or budget <= 0:
                    break
                if not info.isreg() or info.size > budget:
                    continue
                handle = tar.extractfile(info)
                if handle is None:
                    continue
                data = handle.read(info.size + 1)
                budget -= len(data)
                found += _trivy_markers(rel, data, member=info.name[:200])
    except (OSError, tarfile.TarError, EOFError, zlib.error):
        return found
    return found


def neutralise_trivy_markers(line: str) -> str:
    """The line with every Trivy marker defused: the colon after its prefix becomes a dash.

    Only words with an `ignore` key are touched, so an image tag such as
    `aquasec/trivy:0.74.0` keeps its meaning.
    """
    out, last = [], 0
    for match in _TRIVY.finditer(line):
        if any(s.strip().lower() == "ignore" for s in match.group("rest").split(":")):
            colon = match.start("rest") - 1
            out.append(line[last:colon] + "-")
            last = colon + 1
    return "".join(out) + line[last:]


MAX_MARKER_LINT_BYTES = 64 * 1024 * 1024


def _mentions_prefix(full: Path) -> bool:
    """Whether a file holds either Trivy prefix anywhere, read in chunks (the file may be large)."""
    needles = [p.encode() + b":" for p in _TRIVY_PREFIXES]
    overlap = max(len(n) for n in needles) - 1
    tail = b""
    with open(full, "rb") as handle:
        while block := handle.read(1024 * 1024):
            window = (tail + block).lower()
            if any(n in window for n in needles):
                return True
            tail = window[-overlap:]
    return False


def find_trivy_suppressions(root: Path, rel_paths: list[str], max_bytes: int) -> list[Suppression]:
    """Find Trivy markers in the given files, and in the files of chart archives among them.

    Trivy reads files of any size, so a file over `max_bytes` is still searched.
    One too large to read whole (over MAX_MARKER_LINT_BYTES) that mentions a
    Trivy prefix cannot be checked, and is reported as an invalid marker.
    """
    found = []
    for rel in sorted(set(rel_paths)):
        full = root / rel
        try:
            if full.is_symlink() or not full.is_file():
                continue
            size = full.stat().st_size
            if rel.lower().endswith(TRIVY_ARCHIVES):
                if size <= max_bytes:
                    found += _archive_markers(rel, full, max_bytes)
                continue
            if size > max_bytes and not _mentions_prefix(full):
                continue
            if size > MAX_MARKER_LINT_BYTES:
                found.append(
                    Suppression(rel, 1, "a file too large to check for Trivy markers", ("",), None, False, kind="trivy")
                )
                continue
            data = full.read_bytes()
        except OSError:
            continue
        found += _trivy_markers(rel, data)
    return found


def lint_findings(suppressions: list[Suppression], components: dict[str, str]) -> list[Finding]:
    bad = [s for s in suppressions if not s.valid]
    items = [{"tool": LINT_TOOL, "rule": LINT_RULE, "path": s.path, "code": s.text, "line": s.line} for s in bad]
    prints = assign_fingerprints(items)
    return [
        Finding(
            tool=LINT_TOOL,
            rule=LINT_RULE,
            severity="ERROR",
            path=s.path,
            line=s.line,
            fingerprint=fp,
            component=component_for(s.path, components),
            message=(
                f"This line holds {s.problem()}. Write it as `{TRIVY_EXAMPLE}`, naming one check."
                if s.kind == "trivy"
                else f"This line holds {s.problem()}. Write it as `{EXAMPLE}`, with the colon right after the "
                "marker and one space before the rule id."
            ),
        )
        for s, fp in zip(bad, prints, strict=True)
    ]
