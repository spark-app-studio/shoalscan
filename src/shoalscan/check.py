"""`shoalscan check`: compare findings with the baseline and decide pass or fail."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field

from shoalscan import markdown as md
from shoalscan.baseline import Entry
from shoalscan.config import component_for, under_prefix
from shoalscan.excludes import ExcludeMatcher, FileGlobMatcher
from shoalscan.findings import Finding, sort_findings
from shoalscan.rulesets import RuleIdFilter
from shoalscan.testscope import eligible, never_test_code

SUMMARY_PREFIX = "SHOALSCAN_SUMMARY "
# Written next to findings.json: the lists behind the summary's counts, for
# `shoalscan record` and the dashboard.
CHECK_JSON = "check.json"
# Opengrep's error types for a file it could not parse at all, as happens to
# template files (Helm templates are Go templates, not YAML).
SYNTAX_ERROR_TYPES = ("Syntax error", "Other syntax error", "Lexical error")
DETAILS_FORMAT = 1


@dataclass
class CheckResult:
    findings: list[Finding]
    new: list[Finding]
    new_blocking: list[Finding]
    stale: list[Entry]
    baseline_size: int
    blocking: tuple[str, ...]
    suppressions: dict = field(default_factory=dict)
    baseline_found: bool = True
    non_blocking_paths: tuple[str, ...] = ()
    unscanned: dict = field(default_factory=dict)
    changed_unscanned: list[dict] = field(default_factory=list)
    baseline_additions: list[Entry] = field(default_factory=list)
    policy_ref: str | None = None
    partial_warnings: list[dict] = field(default_factory=list)
    excluded_changed: list[str] = field(default_factory=list)
    moves: list[dict] = field(default_factory=list)
    adoption: bool = False
    partial_warn_only: list[dict] = field(default_factory=list)
    syntax_warn_only: list[dict] = field(default_factory=list)
    # Findings the baseline accepts, with the entry that accepts each.
    matched: list = field(default_factory=list)
    # Findings labelled as test code (a `#[cfg(test)]` item) for a rule [test_code] lists. A label groups a
    # finding for triage; it never changes whether the finding blocks.
    test_code: list[Finding] = field(default_factory=list)
    test_code_rules: tuple[str, ...] = ()
    # Inline suppressions on lines the change added (`check --changed-since`): each one fails the check.
    new_suppressions: list[dict] = field(default_factory=list)
    # False for a pull request checked with `--changed-since`: its baseline is managed outside the change, so a
    # stale entry (the change fixed a baselined finding) is reported but is no new risk and does not fail it.
    stale_blocks: bool = True

    def __post_init__(self) -> None:
        self._labelled = set(self.test_code)

    def is_test_code(self, f: Finding) -> bool:
        return f in self._labelled

    def in_non_blocking_path(self, f: Finding) -> bool:
        return under_prefix(f.path, self.non_blocking_paths)

    @property
    def passed(self) -> bool:
        return (
            not self.new_blocking
            and not (self.stale and self.stale_blocks)
            and not self.changed_unscanned
            and not self.baseline_additions
            and not self.new_suppressions
        )


def compare(
    findings: list[Finding],
    baseline: list[Entry] | None,
    blocking: tuple[str, ...],
    suppressions: dict | None = None,
    non_blocking_paths: tuple[str, ...] = (),
    unscanned: dict | None = None,
    changed_files: list[str] | None = None,
    excludes: tuple[str, ...] = (),
    base_baseline: list[Entry] | None = None,
    policy_ref: str | None = None,
    added_lines=None,
    renames: list[tuple[str, str]] | None = None,
    components: dict[str, str] | None = None,
    adoption: bool = False,
    parse_warn_only: tuple[str, ...] = (),
    test_code_rules: tuple[str, ...] = (),
    new_suppressions: list[dict] | None = None,
    stale_blocks: bool = True,
) -> CheckResult:
    """Compare findings with the baseline.

    With `changed_files` (from a policy ref), a changed file that is not
    excluded fails when Opengrep skipped it (for example over the size limit)
    or reported an error other than PartialParsing (Timeout, OutOfMemory and
    so on). A PartialParsing error fails only when an unparsed span overlaps
    a line the change added (`added_lines(path)`), or covers more than half
    the file; otherwise it is a warning. A changed file that matches a
    `parse_warn_only` glob only warns about PartialParsing gaps, whatever
    their size or place; its other errors, and skipping it, still fail.

    With `base_baseline`, the baseline may only lose entries compared with
    it; an added or changed entry fails. The one exception is a pure move:
    git reports a rename (`renames`), every base entry of the old path moves
    to the new path unchanged and one-to-one, and the component and
    non-blocking status stay the same.

    A test code label only groups a finding for the report: it never changes
    whether the finding blocks. A label counts only when this check's own
    policy lists the rule under `[test_code] rules`, it is an Opengrep finding
    in a Rust file, and its path can carry a label; any other mark is ignored.
    """
    listed = RuleIdFilter(test_code_rules)
    labelled = [
        f
        for f in sort_findings(findings)
        if f.test_code is not None
        and eligible(f.tool, f.rule, f.path, listed)
        and not never_test_code(f.path)
        and not never_test_code(f.test_code.path)
    ]
    entries = baseline or []
    known = {e.key() for e in entries}
    by_key = {e.key(): e for e in entries}
    present = {f.key() for f in findings}
    new = [f for f in sort_findings(findings) if f.key() not in known]
    # INFO never blocks, whatever the configuration says, and nothing under a
    # non-blocking path blocks. Stale entries fail everywhere.
    new_blocking = [
        f
        for f in new
        if f.severity in blocking and f.severity != "INFO" and not under_prefix(f.path, non_blocking_paths)
    ]
    stale = sorted((e for e in entries if e.key() not in present), key=lambda e: (e.path, e.rule, e.fingerprint))
    unscanned = unscanned or {"skipped": [], "errors": []}
    changed_unscanned: list[dict] = []
    partial_warnings: list[dict] = []
    excluded_changed: list[str] = []
    partial_warn_only: list[dict] = []
    syntax_warn_only: list[dict] = []
    if changed_files is not None:
        warn_only = FileGlobMatcher(parse_warn_only)
        matcher = ExcludeMatcher(excludes)
        changed = {p for p in changed_files if not matcher.excluded(p)}
        excluded_changed = sorted(p for p in changed_files if matcher.excluded(p))
        for entry in unscanned.get("skipped", []):
            if entry.get("path") in changed:
                changed_unscanned.append({**entry, "kind": "skipped"})
        for entry in unscanned.get("errors", []):
            if entry.get("path") not in changed:
                continue
            if entry.get("type") in SYNTAX_ERROR_TYPES and warn_only.matches(entry["path"]):
                # A template file: language-aware rules could not read it, generic rules still ran.
                syntax_warn_only.append(entry)
                continue
            if entry.get("type") != "PartialParsing":
                changed_unscanned.append({**entry, "kind": "errors"})
                continue
            gap = {n for start, end in entry.get("spans", []) for n in range(start, end + 1)}
            added = added_lines(entry["path"]) if added_lines else set()
            total = entry.get("file_lines", 0)
            if warn_only.matches(entry["path"]):
                percent = round(100 * len(gap) / total) if total else 100
                partial_warn_only.append(
                    {**entry, "unparsed_percent": min(percent, 100), "overlaps_added_lines": bool(gap & added)}
                )
                continue
            if gap & added:
                changed_unscanned.append({**entry, "kind": "errors", "why": "unparsed lines overlap added lines"})
            elif not gap or total == 0 or len(gap) * 2 > total:
                changed_unscanned.append({**entry, "kind": "errors", "why": "more than half the file is unparsed"})
            else:
                partial_warnings.append(entry)
    additions: list[Entry] = []
    moves: list[dict] = []
    if base_baseline is not None:
        allowed = set(base_baseline)
        additions = [e for e in entries if e not in allowed]
        for old, new_path in renames or []:
            moved = _pure_move(old, new_path, base_baseline, entries, components, non_blocking_paths)
            if moved:
                additions = [e for e in additions if e not in moved]
                moves.append({"from": old, "to": new_path, "entries": len(moved)})
    return CheckResult(
        matched=[(f, by_key[f.key()]) for f in sort_findings(findings) if f.key() in by_key],
        excluded_changed=excluded_changed,
        partial_warnings=partial_warnings,
        partial_warn_only=partial_warn_only,
        syntax_warn_only=syntax_warn_only,
        moves=moves,
        unscanned=unscanned,
        changed_unscanned=changed_unscanned,
        baseline_additions=additions,
        policy_ref=policy_ref,
        findings=findings,
        new=new,
        new_blocking=new_blocking,
        stale=stale,
        baseline_size=len(entries),
        blocking=blocking,
        suppressions=suppressions or {},
        baseline_found=baseline is not None,
        non_blocking_paths=non_blocking_paths,
        adoption=adoption,
        test_code=labelled,
        test_code_rules=tuple(test_code_rules),
        new_suppressions=list(new_suppressions or []),
        stale_blocks=stale_blocks,
    )


def _pure_move(
    old: str,
    new: str,
    base: list[Entry],
    entries: list[Entry],
    components: dict[str, str] | None,
    non_blocking_paths: tuple[str, ...],
) -> set[Entry]:
    """Return the moved entries if `old` -> `new` is a pure move, else an empty set."""
    from dataclasses import replace

    base_old = {e for e in base if e.path == old}
    if not base_old:
        return set()
    if any(e.path == old for e in entries):
        return set()
    now_new = {e for e in entries if e.path == new}
    if now_new != {replace(e, path=new) for e in base_old} or len(now_new) != len(base_old):
        return set()
    comps = components or {}
    if component_for(old, comps) != component_for(new, comps):
        return set()
    if under_prefix(old, non_blocking_paths) != under_prefix(new, non_blocking_paths):
        return set()
    return now_new


def _by_severity(findings: list[Finding]) -> dict:
    return {k: sum(1 for f in findings if f.severity == k) for k in ("ERROR", "WARNING", "INFO")}


def summary(result: CheckResult) -> dict:
    return {
        "result": "pass" if result.passed else "fail",
        "findings": len(result.findings),
        "by_severity": _by_severity(result.findings),
        "by_severity_non_blocking_paths": _by_severity([f for f in result.findings if result.in_non_blocking_path(f)]),
        "by_component": dict(sorted(Counter(f.component for f in result.findings).items())),
        "by_rule": dict(sorted(Counter(f.rule for f in result.findings).items())),
        "new": len(result.new),
        "new_blocking": len(result.new_blocking),
        "new_in_non_blocking_paths": sum(1 for f in result.new if result.in_non_blocking_path(f)),
        "stale": len(result.stale),
        "baseline_size": result.baseline_size,
        "suppressions": result.suppressions,
        "unscanned": {
            "skipped": len(result.unscanned.get("skipped", [])),
            "errored": len(result.unscanned.get("errors", [])),
            "changed_and_unscanned": len(result.changed_unscanned),
            "changed_partially_parsed_warnings": len(result.partial_warnings),
            "changed_partially_parsed_warn_only": len(result.partial_warn_only),
            "changed_syntax_error_warn_only": len(result.syntax_warn_only),
            "changed_but_excluded": len(result.excluded_changed),
        },
        "baseline_moves": len(result.moves),
        "adoption": result.adoption,
        "baseline_additions": len(result.baseline_additions),
        "policy_ref": result.policy_ref,
        "test_code": len(result.test_code),
        "new_test_code": sum(1 for f in result.new if result.is_test_code(f)),
        "new_blocking_test_code": sum(1 for f in result.new_blocking if result.is_test_code(f)),
        "new_suppressions": len(result.new_suppressions),
    }


def is_blocking_class(result: CheckResult, f: Finding) -> bool:
    """Would this finding block if it were new? The same test `compare` uses for new findings."""
    return f.severity in result.blocking and f.severity != "INFO" and not result.in_non_blocking_path(f)


def details(result: CheckResult, findings_sha256: str) -> dict:
    """The lists behind the summary: which findings are new and blocking,
    which baseline entries are stale, and what happened to changed files.
    `findings_sha256` ties them to the findings file they were made from."""

    def key(f: Finding) -> list[str]:
        return [f.tool, f.rule, f.path, f.fingerprint]

    def entry(e: Entry) -> dict:
        return {
            "tool": e.tool,
            "rule": e.rule,
            "path": e.path,
            "fingerprint": e.fingerprint,
            "issue": e.issue,
            "reason": e.reason,
        }

    def file_detail(e: dict) -> dict:
        return {
            k: e[k]
            for k in ("path", "kind", "type", "reason", "why", "spans", "unparsed_percent", "overlaps_added_lines")
            if k in e
        }

    return {
        "format": DETAILS_FORMAT,
        "findings_sha256": findings_sha256,
        "result": "pass" if result.passed else "fail",
        "new": [key(f) for f in result.new],
        "new_blocking": [key(f) for f in result.new_blocking],
        # Every finding the policy treats as blocking, baselined or not: a
        # blocking severity (never INFO) outside the non-blocking paths.
        "blocking_class": [key(f) for f in sort_findings(result.findings) if is_blocking_class(result, f)],
        "blocking": list(result.blocking),
        # The baseline entry behind each accepted finding: its issue and reason.
        "baselined": [{"key": key(f), "issue": e.issue, "reason": e.reason} for f, e in result.matched],
        "non_blocking_paths": list(result.non_blocking_paths),
        "stale": [entry(e) for e in result.stale],
        "baseline_additions": [entry(e) for e in result.baseline_additions],
        "changed_unscanned": [file_detail(e) for e in result.changed_unscanned],
        "partial_warnings": [file_detail(e) for e in result.partial_warnings],
        "partial_warn_only": [file_detail(e) for e in result.partial_warn_only],
        "syntax_warn_only": [file_detail(e) for e in result.syntax_warn_only],
        "excluded_changed": list(result.excluded_changed),
        # Findings labelled as test code, with the label, and the
        # baseline entries they make unnecessary.
        "test_code_rules": list(result.test_code_rules),
        "test_code": [{"key": key(f), **f.test_code.as_json()} for f in result.test_code],
        "new_suppressions": [
            {"path": e.get("path"), "line": e.get("line"), "rules": e.get("rules")} for e in result.new_suppressions
        ],
        "summary": summary(result),
    }


def summary_line(result: CheckResult) -> str:
    return SUMMARY_PREFIX + json.dumps(summary(result), sort_keys=True, separators=(",", ":"))


def render_report(result: CheckResult, max_items: int = 200) -> str:
    """The check's report for a terminal or a CI log. Text from the scanned repository (paths, rules,
    messages, issues) is folded onto one line with control and bidirectional characters removed, so it
    can neither add lines that look like Shoalscan's own nor send escape sequences to the terminal."""
    t = md.one_line
    s = summary(result)
    sev = s["by_severity"]
    no_file = "" if result.baseline_found else " (no baseline file)"
    blocking = ", ".join(result.blocking) or "none"
    out = [
        f"Shoalscan check: {'PASSED' if result.passed else 'FAILED'}",
        f"  Findings: {s['findings']} (ERROR {sev['ERROR']}, WARNING {sev['WARNING']}, INFO {sev['INFO']})",
        f"  Baseline: {result.baseline_size} entries{no_file}",
        f"  New findings: {len(result.new)}, of which blocking: {len(result.new_blocking)} (blocking severities: "
        f"{blocking})",
        f"  Stale baseline entries: {len(result.stale)}",
    ]
    if result.test_code_rules:
        out.append(
            f"  Labelled as test code (a label only; they block like any other finding): {len(result.test_code)}, "
            f"of which new: {s['new_test_code']}, new and blocking: {s['new_blocking_test_code']}"
        )
    if result.suppressions:
        out.append(
            f"  Inline suppressions: {result.suppressions.get('total', 0)}"
            f" (without a rule and an issue: {result.suppressions.get('invalid', 0)};"
            f" findings they silence: {result.suppressions.get('suppressed_findings', 0)})"
        )

    def finding_lines(title: str, items: list[Finding]) -> None:
        if not items:
            return
        out.append("")
        out.append(f"{title} ({len(items)}):")
        for f in items[:max_items]:
            out.append(f"  {f.severity:<7} {t(f.path)}:{f.line}  {t(f.rule)}")
            if f.message:
                out.append(f"          {t(f.message.splitlines()[0], 200)}")
            out.append(f"          fingerprint {t(f.fingerprint)}")
        if len(items) > max_items:
            out.append(f"  ... and {len(items) - max_items} more (see findings.json)")

    labelled_blocking = [f for f in result.new_blocking if result.is_test_code(f)]
    unlabelled_blocking = [f for f in result.new_blocking if not result.is_test_code(f)]
    if labelled_blocking:
        # The heading gives the full count: a label never takes a finding out of the blocking total.
        out.append("")
        out.append(
            f"New blocking findings ({len(result.new_blocking)}, of which {len(labelled_blocking)} labelled as test "
            "code below):"
        )
        for f in unlabelled_blocking[:max_items]:
            out.append(f"  {f.severity:<7} {t(f.path)}:{f.line}  {t(f.rule)}")
            if f.message:
                out.append(f"          {t(f.message.splitlines()[0], 200)}")
            out.append(f"          fingerprint {t(f.fingerprint)}")
        if len(unlabelled_blocking) > max_items:
            out.append(f"  ... and {len(unlabelled_blocking) - max_items} more (see findings.json)")
    else:
        finding_lines("New blocking findings", unlabelled_blocking)
    if labelled_blocking:
        out.append("")
        out.append(
            f"New blocking findings in code labelled as test code ({len(labelled_blocking)}): the label is triage "
            "help, not a proof that the code never ships. They block until a person accepts them, for example with "
            "`shoalscan baseline accept --test-code --fingerprint <fingerprint> --by <you> --issue <issue>`, "
            "committed through a reviewed change on the base branch."
        )
        for f in labelled_blocking[:max_items]:
            out.append(f"  {f.severity:<7} {t(f.path)}:{f.line}  {t(f.rule)}")
            out.append(f"          {t(f.test_code.description())}")
            out.append(f"          fingerprint {t(f.fingerprint)}")
        if len(labelled_blocking) > max_items:
            out.append(f"  ... and {len(labelled_blocking) - max_items} more (see check.json)")
    if result.non_blocking_paths:
        out.insert(
            5,
            f"  Non-blocking paths: {t(', '.join(result.non_blocking_paths))}"
            f" ({sum(1 for f in result.new if result.in_non_blocking_path(f))} new findings there)",
        )
    finding_lines(
        "New findings that do not block",
        [f for f in result.new if f not in result.new_blocking and not result.in_non_blocking_path(f)],
    )
    finding_lines(
        "New findings in non-blocking paths",
        [f for f in result.new if result.in_non_blocking_path(f)],
    )
    if result.stale:
        out.append("")
        if result.stale_blocks:
            out.append(f"Stale baseline entries ({len(result.stale)}): these no longer match a finding; remove them.")
        else:
            out.append(
                f"Stale baseline entries ({len(result.stale)}): these no longer match a finding. They do not fail "
                "this change, whose baseline is managed outside it; remove them from that baseline once it is merged."
            )
        for e in result.stale[:max_items]:
            out.append(f"  {t(e.path)}  {t(e.rule)}  fingerprint {t(e.fingerprint)}  issue {t(e.issue)}")
    skipped, errored = result.unscanned.get("skipped", []), result.unscanned.get("errors", [])
    if skipped or errored:
        out.append("")
        out.append(f"Files not fully scanned: {len(skipped)} skipped, {len(errored)} with scanner errors.")
        for e in (skipped + errored)[:50]:
            out.append(f"  {t(e['path'])}  ({t(e.get('reason') or e.get('type'))})")
        if len(skipped) + len(errored) > 50:
            out.append(f"  ... and {len(skipped) + len(errored) - 50} more (see findings.json)")
    if result.new_suppressions:
        out.append("")
        out.append(
            f"New inline suppressions on lines the change added ({len(result.new_suppressions)}): this fails. "
            "A change from outside cannot silence findings itself; fix the finding, or accept it on the base branch."
        )
        for e in result.new_suppressions[:max_items]:
            rules = ", ".join(t(r) for r in e.get("rules") or []) or "no rule"
            out.append(f"  {t(e.get('path'))}:{e.get('line')}  ({rules})")
    if result.changed_unscanned:
        out.append("")
        out.append(
            f"Changed files that were not fully scanned ({len(result.changed_unscanned)}): this fails. "
            "Make them scannable (smaller, parseable) or exclude them in the configuration on the base branch."
        )
        for e in result.changed_unscanned[:max_items]:
            why = f"; {t(e['why'])}" if e.get("why") else ""
            out.append(f"  {t(e['path'])}  ({t(e.get('reason') or e.get('type'))}{why})")
    if result.excluded_changed:
        bar = "!" * 78
        out.append("")
        out.append(bar)
        out.append(
            f"CHANGED BUT NOT SCANNED: {len(result.excluded_changed)} changed files are under the configured excludes."
        )
        out.append("They were not checked. Make sure that is intended.")
        for p in result.excluded_changed[:max_items]:
            out.append(f"  {t(p)}")
        out.append(bar)
    if result.partial_warnings:
        out.append("")
        out.append(
            "Warning: changed files with small parse gaps away from the changed lines "
            f"({len(result.partial_warnings)}):"
        )
        for e in result.partial_warnings[:max_items]:
            out.append(f"  {t(e['path'])}  unparsed lines {t(e.get('spans'))}")
    if result.partial_warn_only:
        bar = "!" * 78
        out.append("")
        out.append(bar)
        out.append(
            f"PARTIALLY PARSED changed files that only warn under parse_warn_only ({len(result.partial_warn_only)}). "
            "Their unparsed lines were not checked by any rule:"
        )
        for e in result.partial_warn_only[:max_items]:
            overlap = "yes" if e["overlaps_added_lines"] else "no"
            out.append(
                f"  PARTIALLY PARSED (warn-only by policy): {t(e['path'])} \u2014 {e['unparsed_percent']}% unparsed, "
                f"overlaps added lines: {overlap}"
            )
        out.append(bar)
    if result.syntax_warn_only:
        bar = "!" * 78
        out.append("")
        out.append(bar)
        out.append(
            f"SYNTAX ERRORS in changed files that only warn under parse_warn_only ({len(result.syntax_warn_only)}). "
            "Language-aware rules could not read them; generic rules still ran:"
        )
        for e in result.syntax_warn_only[:max_items]:
            out.append(
                f"  SYNTAX ERROR (warn-only by policy): {t(e['path'])} \u2014 {t(e.get('type'))}; the whole file "
                "could not be parsed"
            )
        out.append(bar)
    if result.moves:
        bar = "!" * 78
        out.append("")
        out.append(bar)
        out.append("BASELINE MOVES: git reports these renames, and every baseline entry moved unchanged:")
        for m in result.moves:
            out.append(f"  {t(m['from'])}  ->  {t(m['to'])}  ({m['entries']} entries)")
        out.append(bar)
    if result.baseline_additions:
        out.append("")
        out.append(
            f"Baseline entries added or changed compared with {result.policy_ref} ({len(result.baseline_additions)}): "
            "this fails. A change may only remove baseline entries; adding or changing one needs a separate, "
            "reviewed change on the base branch."
        )
        for e in result.baseline_additions[:max_items]:
            out.append(f"  {t(e.path)}  {t(e.rule)}  fingerprint {t(e.fingerprint)}  issue {t(e.issue)}")
    if not result.passed:
        out.append("")
        out.append(
            "To pass: fix the new blocking findings, or suppress a false positive inline with its rule id "
            "and an issue, and remove stale entries from the baseline."
        )
    return "\n".join(out)
