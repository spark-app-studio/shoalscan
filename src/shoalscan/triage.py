"""`shoalscan triage`: a prioritised work list of a scan's findings.

The list is read from the last `shoalscan scan` and the repository's
baseline, on a developer machine, offline. Findings are grouped by rule
family (the CWE a rule names, or the rule itself when it names none), and
within a family by component, so that one pull request can fix one family.

Order, in both the groups and the findings inside them, follows the
dashboard's Fix priority: new blocking findings first, then ERROR before
WARNING before INFO, then the hottest component. Stale baseline entries come
before everything else: removing them is the quickest work there is, and
they fail the check until they are gone.

The list is advice. It never changes the baseline, the configuration or what
blocks CI.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path

from shoalscan import PROJECT_URL, __version__
from shoalscan import markdown as md
from shoalscan.baseline import Entry, load_baseline
from shoalscan.check import CheckResult, compare, is_blocking_class
from shoalscan.config import CONFIG_NAME, load_config
from shoalscan.dashboard.data import HEAT_WEIGHTS, SEVERITY_RANK
from shoalscan.errors import SetupError
from shoalscan.findings import Finding, load_findings
from shoalscan.gitref import baseline_binding_path, worktree_state
from shoalscan.locations import default_out_dir, refuse_inside_repo
from shoalscan.scan import FINDINGS_JSON, write_atomic

FORMAT = 1
DEFAULT_PER_GROUP = 25
COMMUNITY_RULES_URL = "https://github.com/opengrep/opengrep-rules"
STATUSES = ("new_blocking", "new", "baselined")
_CWE = re.compile(r"^CWE-(\d{1,6})\b")
_VERSION = re.compile(r"^\d+\.\d+\.\d+$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_SAFE_PATH = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_./\-]*$")


def family(rule: str, info: dict) -> tuple[str, str]:
    """The rule family: (key, title). The first CWE the rule names, else the rule id."""
    for label in info.get("cwe") or []:
        match = _CWE.match(label) if isinstance(label, str) else None
        if match:
            return f"CWE-{int(match.group(1))}", label
    return rule, rule


def explanation(info: dict, meta: dict) -> dict:
    """Where a rule is explained: a link to its file for community and Shoalscan
    rules, or its path in the repository for the repository's own rules."""
    file = info.get("file")
    if not isinstance(file, str) or ".." in file.split("/") or not _SAFE_PATH.match(file):
        return {"url": None, "path": None}
    source, _, rel = file.partition("/")
    if source == "community":
        scanners = meta.get("scanners") if isinstance(meta.get("scanners"), dict) else {}
        og = scanners.get("opengrep") if isinstance(scanners.get("opengrep"), dict) else {}
        commit = og.get("community_rules_commit")
        if isinstance(commit, str) and _COMMIT.match(commit):
            return {"url": f"{COMMUNITY_RULES_URL}/blob/{commit}/{rel}", "path": None}
    elif source == "shoalscan":
        version = meta.get("shoalscan_version")
        if isinstance(version, str) and _VERSION.match(version):
            return {"url": f"{PROJECT_URL}/blob/v{version}/rules/{rel}", "path": None}
    elif source == "repo":
        return {"url": None, "path": rel}
    return {"url": None, "path": None}


def _heat(findings: list[Finding]) -> int:
    return sum(HEAT_WEIGHTS.get(f.severity, 0) for f in findings)


def build(
    findings: list[Finding],
    meta: dict,
    result: CheckResult,
    blocking_only: bool = False,
    warnings: list[str] | None = None,
) -> dict:
    """The work list as a JSON-ready dict. Every finding is listed; nothing is cut here."""
    rules_meta = meta.get("rules") if isinstance(meta.get("rules"), dict) else {}
    baselined = {f.key(): e for f, e in result.matched}
    new_blocking = {f.key() for f in result.new_blocking}
    new = {f.key() for f in result.new}
    items = [f for f in findings if not blocking_only or is_blocking_class(result, f)]

    component_heat: dict[str, int] = Counter()
    for f in items:
        component_heat[f.component] += HEAT_WEIGHTS.get(f.severity, 0)

    def status(f: Finding) -> str:
        if f.key() in new_blocking:
            return "new_blocking"
        return "new" if f.key() in new else "baselined"

    def order(f: Finding) -> tuple:
        return (
            0 if f.key() in new_blocking else 1,
            SEVERITY_RANK.get(f.severity, 3),
            -component_heat[f.component],
            f.path,
            f.line,
            f.rule,
            f.fingerprint,
        )

    families: dict[str, dict] = {}
    for f in sorted(items, key=order):
        info = rules_meta.get(f.rule) if isinstance(rules_meta.get(f.rule), dict) else {}
        key, title = family(f.rule, info)
        group = families.setdefault(key, {"family": key, "title": title, "findings": []})
        group["findings"].append(f)

    groups = []
    for group in families.values():
        members: list[Finding] = group.pop("findings")
        statuses = Counter(status(f) for f in members)
        severities = Counter(f.severity for f in members)
        rules = []
        for rule, count in Counter(f.rule for f in members).items():
            info = rules_meta.get(rule) if isinstance(rules_meta.get(rule), dict) else {}
            of_rule = [f for f in members if f.rule == rule]
            message = Counter(f.message for f in of_rule if f.message).most_common(1)
            rules.append(
                {
                    "rule": rule,
                    "findings": count,
                    "severity": min((f.severity for f in of_rule), key=lambda s: SEVERITY_RANK.get(s, 3)),
                    "message": message[0][0] if message else "",
                    "fix": info.get("fix"),
                    "cwe": list(info.get("cwe") or []),
                    "owasp": list(info.get("owasp") or []),
                    "confidence": info.get("confidence"),
                    "references": list(info.get("references") or []),
                    "explanation": explanation(info, meta),
                }
            )
        rules.sort(key=lambda r: (SEVERITY_RANK.get(r["severity"], 3), -r["findings"], r["rule"]))
        components: dict[str, list[Finding]] = {}
        for f in members:
            components.setdefault(f.component, []).append(f)
        groups.append(
            {
                "family": group["family"],
                "title": group["title"],
                "heat": _heat(members),
                "counts": {
                    "findings": len(members),
                    **{s: statuses.get(s, 0) for s in STATUSES},
                    "by_severity": {s: severities.get(s, 0) for s in ("ERROR", "WARNING", "INFO")},
                },
                "rules": rules,
                "components": [
                    {
                        "component": name,
                        "heat": _heat(found),
                        "findings": [
                            _finding(f, status(f), baselined.get(f.key()), is_blocking_class(result, f)) for f in found
                        ],
                    }
                    for name, found in sorted(components.items(), key=lambda kv: (min(order(f) for f in kv[1]), kv[0]))
                ],
            }
        )
    groups.sort(
        key=lambda g: (
            0 if g["counts"]["new_blocking"] else 1,
            min(SEVERITY_RANK.get(s, 3) for s, n in g["counts"]["by_severity"].items() if n),
            -g["heat"],
            -g["counts"]["findings"],
            g["family"],
        )
    )
    for rank, group in enumerate(groups, start=1):
        group["rank"] = rank
    statuses = Counter(status(f) for f in items)
    worktree = meta.get("worktree") if isinstance(meta.get("worktree"), dict) else {}
    return {
        "format": FORMAT,
        "shoalscan_version": __version__,
        "scan": {
            "commit": worktree.get("commit"),
            "dirty": worktree.get("dirty"),
            "shoalscan_version": meta.get("shoalscan_version"),
        },
        "blocking_only": blocking_only,
        "warnings": list(warnings or []),
        "totals": {
            "findings": len(items),
            **{s: statuses.get(s, 0) for s in STATUSES},
            "blocking_class": sum(1 for f in items if is_blocking_class(result, f)),
            "groups": len(groups),
            "stale": len(result.stale),
            "baseline_size": result.baseline_size,
        },
        "stale": [_entry(e) for e in result.stale],
        "groups": groups,
    }


def _finding(f: Finding, status: str, entry: Entry | None, blocking: bool) -> dict:
    return {
        "key": [f.tool, f.rule, f.path, f.fingerprint],
        "severity": f.severity,
        "rule": f.rule,
        "path": f.path,
        "line": f.line,
        "fingerprint": f.fingerprint,
        "message": f.message,
        "status": status,
        "blocking_class": blocking,
        "baseline": {"issue": entry.issue, "reason": entry.reason} if entry else None,
    }


def _entry(e: Entry) -> dict:
    return {
        "tool": e.tool,
        "rule": e.rule,
        "path": e.path,
        "fingerprint": e.fingerprint,
        "issue": e.issue,
        "reason": e.reason,
    }


# ------------------------------------------------------------------ Markdown

_STATUS_LABEL = {"new_blocking": "**new, blocks**", "new": "new", "baselined": "baselined"}


def _plural(n: int, one: str, many: str | None = None) -> str:
    return f"{n} {one if n == 1 else (many or one + 's')}"


def _severity_counts(counts: dict) -> str:
    return ", ".join(f"{s} {n}" for s, n in counts.items() if n)


def render_markdown(doc: dict, per_group: int = DEFAULT_PER_GROUP) -> str:
    """The work list as Markdown. Every value from the scan is escaped (see `shoalscan.markdown`)."""
    t = doc["totals"]
    out = ["# Shoalscan triage work list", ""]
    scan = doc["scan"]
    where = (
        f"commit {md.code(scan['commit'][:12])}" if isinstance(scan.get("commit"), str) else "a directory outside git"
    )
    dirty = " with uncommitted changes" if scan.get("dirty") else ""
    out.append(
        f"From the scan of {where}{dirty}, made by Shoalscan {md.text(scan.get('shoalscan_version') or 'unknown')}."
    )
    scope = "blocking findings" if doc["blocking_only"] else "findings"
    out.append(
        f"{_plural(t['findings'], scope[:-1], scope)} in {_plural(t['groups'], 'group')}: "
        f"{t['new_blocking']} new and blocking, {t['new']} new but not blocking, {t['baselined']} baselined. "
        f"{_plural(t['stale'], 'stale baseline entry', 'stale baseline entries')}."
    )
    for warning in doc["warnings"]:
        out += ["", f"> **Warning:** {md.text(warning)}"]
    out += [
        "",
        "Work from the top. Fix one group per pull request, remove the fixed findings' baseline entries in the same "
        "change, "
        "and add a test or a rule that keeps each fix in place. A false positive gets an inline suppression that names "
        "the rule "
        "and an issue; an accepted risk stays in the baseline with its reason. The baseline guide explains both: "
        f"{md.link('The baseline and the check', PROJECT_URL + '/blob/main/docs/baseline-and-check.md')}.",
    ]
    if not t["findings"] and not t["stale"]:
        out += ["", "Nothing to do: the scan has no findings and the baseline has no stale entries."]
    step = 0
    if doc["stale"]:
        step += 1
        out += [
            "",
            f"## {step}. Remove {_plural(len(doc['stale']), 'stale baseline entry', 'stale baseline entries')}",
            "",
        ]
        out.append(
            "These entries match no finding any more, so `shoalscan check` fails until they are removed from the "
            "baseline file."
        )
        out.append("")
        for e in doc["stale"][:per_group]:
            out.append(
                f"- {md.code(e['path'])} {md.code(e['rule'])}, fingerprint {md.code(e['fingerprint'])} (issue "
                f"{md.issue(e['issue'])})"
            )
        if len(doc["stale"]) > per_group:
            out.append(f"- … and {len(doc['stale']) - per_group} more (see `--format json`)")
    for group in doc["groups"]:
        step += 1
        c = group["counts"]
        parts = [_plural(c["findings"], "finding")]
        if c["new_blocking"]:
            parts.append(f"{c['new_blocking']} new and blocking")
        parts.append(_severity_counts(c["by_severity"]))
        out += [
            "",
            f"## {step}. {md.text(group['title'], 200)}",
            "",
            f"{'; '.join(parts)}. Heat score {group['heat']}.",
            "",
        ]
        out.append("Rules:")
        out.append("")
        for r in group["rules"]:
            line = f"- {md.code(r['rule'])}: {r['severity']}, {_plural(r['findings'], 'finding')}"
            if r["confidence"]:
                line += f", confidence {md.text(r['confidence'])}"
            if r["explanation"]["url"]:
                line += f", {md.link('rule', r['explanation']['url'])}"
            elif r["explanation"]["path"]:
                line += f", rule file {md.code(r['explanation']['path'])}"
            out.append(line)
            if r["message"]:
                out.append(f"  - {md.text(r['message'], 600)}")
            if r["fix"]:
                out.append(f"  - Fix: {md.text(r['fix'])}")
            labels = [*r["cwe"], *r["owasp"]]
            if labels:
                out.append(f"  - {'; '.join(md.text(x, 200) for x in labels)}")
            if r["references"]:
                out.append(
                    "  - References: " + ", ".join(md.link(str(n), u) for n, u in enumerate(r["references"], start=1))
                )
        shown = 0
        hidden = 0
        for comp in group["components"]:
            if shown >= per_group:
                hidden += len(comp["findings"])
                continue
            out += [
                "",
                f"### {md.text(comp['component'], 200)} ({_plural(len(comp['findings']), 'finding')}, heat "
                f"{comp['heat']})",
                "",
            ]
            for f in comp["findings"]:
                if shown >= per_group:
                    hidden += 1
                    continue
                shown += 1
                where = md.code(f"{f['path']}:{f['line']}")
                note = ""
                if f["baseline"]:
                    note = f" ({md.issue(f['baseline']['issue'])}: {md.text(f['baseline']['reason'], 200)})"
                out.append(f"- {f['severity']} {where} {md.code(f['rule'])}: {_STATUS_LABEL[f['status']]}{note}")
        if hidden:
            out.append(f"- … and {hidden} more in this group (see `--format json`, or raise `--max-per-group`)")
    return "\n".join(out) + "\n"


# ------------------------------------------------------------------ command


def _warnings(repo: Path, meta: dict, config_path: Path, baseline_path: Path, baseline_found: bool) -> list[str]:
    """Reasons the list may not describe the code as it is now. Triage is advice, so these warn instead of failing.

    The tree comparison is the one `check` makes: an edit to the baseline file
    alone does not make the findings out of date.
    """
    out = []
    recorded = meta.get("worktree") if isinstance(meta.get("worktree"), dict) else None
    state = worktree_state(repo.resolve(), baseline_binding_path(repo, baseline_path))
    if recorded and state:
        if (recorded.get("commit"), recorded.get("tree")) != (state.get("commit"), state.get("tree")):
            head = state.get("commit") or "no commit"
            out.append(
                f"the scan was made at another commit than HEAD ({head[:12]}); run `shoalscan scan` again for an "
                "up-to-date list"
            )
        elif recorded.get("changes_sha256") != state.get("changes_sha256") and (
            recorded.get("without_baseline") is None
            or recorded.get("without_baseline") != state.get("without_baseline")
        ):
            out.append("the working tree changed after the scan; run `shoalscan scan` again for an up-to-date list")
    policy = meta.get("policy") if isinstance(meta.get("policy"), dict) else {}
    local = hashlib.sha256(config_path.read_bytes() if config_path.is_file() else b"").hexdigest()
    if policy.get("ref") is not None:
        out.append(
            f"the scan read its policy from {policy['ref']}; this list uses the working tree's configuration and "
            "baseline"
        )
    elif policy.get("config_sha256") not in (None, local):
        out.append(f"{CONFIG_NAME} changed after the scan; run `shoalscan scan` again")
    if not baseline_found:
        out.append(f"there is no baseline file at {baseline_path}, so every finding counts as new")
    return out


def run(args: argparse.Namespace) -> int:
    repo = Path(args.repo)
    config_path = Path(args.config) if args.config else repo / CONFIG_NAME
    if args.config and not config_path.is_file():
        raise SetupError(f"configuration file not found: {config_path}")
    config = load_config(config_path)
    out_dir = Path(args.out) if args.out else default_out_dir(repo)
    refuse_inside_repo(out_dir, repo, "output directory", "--out")
    if args.max_per_group < 1:
        raise SetupError("--max-per-group must be at least 1")
    findings, meta = load_findings(out_dir / FINDINGS_JSON)
    baseline_path = Path(args.baseline) if args.baseline else repo / config.baseline
    baseline = load_baseline(baseline_path)
    result = compare(
        findings,
        baseline,
        config.blocking,
        meta.get("suppressions"),
        config.non_blocking_paths,
        unscanned=meta.get("unscanned"),
        components=config.components,
        test_code_rules=config.test_code.rules,
    )
    warnings = _warnings(repo, meta, config_path, baseline_path, baseline is not None)
    doc = build(findings, meta, result, blocking_only=args.blocking_only, warnings=warnings)
    if args.format == "json":
        text = json.dumps(doc, indent=2, sort_keys=True) + "\n"
    else:
        text = render_markdown(doc, per_group=args.max_per_group)
    for warning in warnings:
        print(f"shoalscan triage: warning: {warning}", file=sys.stderr)
    if args.output:
        target = Path(args.output)
        write_atomic(target, text)
        t = doc["totals"]
        print(
            f"shoalscan triage: wrote {t['findings']} findings in {t['groups']} groups and {t['stale']} stale entries "
            f"to {target}",
            file=sys.stderr,
        )
    else:
        sys.stdout.write(text)
    return 0


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("--repo", default=".", help="repository root (default: the current directory)")
    p.add_argument("--config", help=f"configuration file (default: <repo>/{CONFIG_NAME})")
    p.add_argument("--out", help="directory with findings.json (default: the same default as `scan`)")
    p.add_argument("--baseline", help="baseline file (default: from the configuration)")
    p.add_argument(
        "--format", choices=("markdown", "json"), default="markdown", help="output format (default: markdown)"
    )
    p.add_argument("--output", help="write the list to this file instead of standard output")
    p.add_argument("--blocking-only", action="store_true", help="list only the findings the policy treats as blocking")
    p.add_argument(
        "--max-per-group",
        type=int,
        default=DEFAULT_PER_GROUP,
        help=f"findings listed per group in Markdown (default: {DEFAULT_PER_GROUP}); JSON always lists every finding",
    )
