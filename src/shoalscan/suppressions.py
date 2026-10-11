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

Trivy has its own inline marker, the word "trivy" then ":ignore:" and a
check id, in a comment in the file it applies to; `*` in place of the id
silences every check. Trivy cannot be told to disregard these, so Shoalscan
holds them to the same rule: a specific check id and an issue on the same
line, or a blocking finding. A `*` is reported like a bare marker.
"""

from __future__ import annotations

import re
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
# Matched anywhere on a line: reporting a marker Trivy would not honour is safer than missing one it would.
_TRIVY = re.compile(re.escape(TRIVY_MARKER) + r"(?P<id>[^\s:\[\]]*)", re.ASCII)
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
            return "a Trivy suppression of every check (*)"
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
    """Return (check ids, issue, bare) for each Trivy marker on a line."""
    out = []
    for match in _TRIVY.finditer(text):
        check = match.group("id")
        issue = _ISSUE.search(text, match.end())
        if check == "*":
            out.append(((), None, True))
        else:
            out.append(((check,) if _TRIVY_ID.match(check) else ("",), issue.group(0) if issue else None, False))
    return out


def find_trivy_suppressions(root: Path, rel_paths: list[str], max_bytes: int) -> list[Suppression]:
    """Find Trivy markers in the given files."""
    found = []
    for rel in sorted(set(rel_paths)):
        full = root / rel
        try:
            if full.is_symlink() or not full.is_file() or full.stat().st_size > max_bytes:
                continue
            data = full.read_bytes()
        except OSError:
            continue
        if TRIVY_MARKER.encode() not in data:
            continue
        for number, line in enumerate(split_lines(data.decode("utf-8", errors="replace")), start=1):
            for ids, issue, bare in parse_trivy_line(line):
                found.append(Suppression(rel, number, line.strip(), ids, issue, bare, kind="trivy"))
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
        for s, fp in zip(bad, prints)
    ]
