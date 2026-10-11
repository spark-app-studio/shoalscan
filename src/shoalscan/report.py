"""`shoalscan report`: a dated security report from the run history.

The report covers one repository and one period of whole UTC days. It is
built from the history database that `shoalscan record` writes, read-only:
the posture at the end of the period (the newest trend run in it), how it
moved since the start (the newest trend run before it), what was found and
fixed, what the baseline accepts and why, how findings were reviewed, and
what the scan could not see. Trend runs are the scheduled scans of the
default branch, or every run when a repository has no scheduled runs, as on
the dashboard.

Every value that came from a scanned repository is escaped (see
`shoalscan.markdown`).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from shoalscan import PROJECT_URL, __version__, history
from shoalscan import markdown as md
from shoalscan.dashboard.data import MAX_TREND_RUNS, SEVERITIES, Data
from shoalscan.errors import SetupError
from shoalscan.scan import write_atomic

FORMAT = 1
DEFAULT_DAYS = 30
MAX_DAYS = 366
MAX_LISTED = 100
MAX_COMPONENTS = 20
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
REVIEW_LABELS = {
    "open": "Open",
    "false_positive": "False positive",
    "accepted_risk": "Accepted risk",
    "wont_fix": "Won't fix",
    "fixed": "Fixed (claimed)",
    "verified_fixed": "Verified fixed",
    "regression": "Regression",
}
BASELINE_KINDS = {"false_positive": "False positive", "accepted_risk": "Accepted risk", "baselined": "Baselined"}
OUTCOME_LABELS = {"passed": "passed", "blocked": "blocked", "scan_error": "scan error"}


def _day(value: str, flag: str) -> date:
    if not _DATE.match(value):
        raise SetupError(f"{flag} must be a date such as 2026-09-30")
    try:
        return date.fromisoformat(value)
    except ValueError:
        raise SetupError(f"{flag} is not a valid date: {value}") from None


def period(since: str | None, until: str | None, today: date) -> tuple[date, date]:
    """The report's first and last day. Default: the DEFAULT_DAYS days ending today (UTC)."""
    last = _day(until, "--until") if until else today
    first = _day(since, "--since") if since else last - timedelta(days=DEFAULT_DAYS - 1)
    if first > last:
        raise SetupError("--since must not be after --until")
    if (last - first).days >= MAX_DAYS:
        raise SetupError(f"a report covers at most {MAX_DAYS} days")
    return first, last


def baseline_kind(reason: str) -> str:
    """What a baseline entry's reason says it is, as on the dashboard."""
    if reason.startswith("False positive:"):
        return "false_positive"
    if reason.startswith("Accepted:"):
        return "accepted_risk"
    return "baselined"


def _run_summary(run: dict | None) -> dict | None:
    if run is None:
        return None
    return {
        "id": run["id"],
        "kind": run["kind"],
        "ref": run["ref"],
        "commit": run["commit"],
        "scanned_at": run["scanned_at"],
        "outcome": run["outcome"],
        "status": run["status"]["label"],
        "findings": run["findings"],
        "by_severity": run["by_severity"],
        "baseline_size": run["baseline_size"],
        "stale": run["stale"],
        "new_blocking": run["new_blocking"],
        "blocking_class": run["blocking_class"],
        "suppressions": run["suppressions"],
        "unscanned": {"skipped": run["unscanned"]["skipped"], "errored": run["unscanned"]["errored"]},
    }


def build(conn, repo: str, first: date, last: date, generated_at: str) -> dict:
    """The report as a JSON-ready dict."""
    data = Data(conn)
    repo_id = data.repo_id(repo)
    if repo_id is None:
        raise SetupError(f"the history database has no runs of {repo} (`shoalscan record` adds them)")
    since = f"{first.isoformat()}T00:00:00Z"
    until = f"{last.isoformat()}T23:59:59Z"
    changes = data.period(repo_id, since, until, limit=MAX_LISTED)
    if not changes["complete"]:
        raise SetupError(
            f"the period holds more trend runs than a report can walk ({MAX_TREND_RUNS}), so its counts would be "
            "incomplete; "
            "choose a shorter period"
        )
    end, start = changes["end"], changes["start"]
    doc: dict = {
        "format": FORMAT,
        "repository": repo,
        "period": {"first_day": first.isoformat(), "last_day": last.isoformat()},
        "generated_at": generated_at,
        "shoalscan_version": __version__,
        "trend_runs": "scheduled" if data._trend_kinds(repo_id) == ("scheduled",) else "all",
        "start": _run_summary(start),
        "end": _run_summary(end),
        "changes": {k: changes[k] for k in ("new", "fixed", "weekly", "time_to_fix")},
        "blocking": None,
        "reviews_now": None,
        "baselined": {"total": 0, "groups": 0, "by_kind": {}, "reasons": []},
        "components": [],
        "scanners": {},
    }
    if end is not None:
        run_id = end["id"]
        if end["blocking_class"] is not None:
            total, new = conn.execute(
                "SELECT COUNT(*), COALESCE(SUM(is_new), 0) FROM run_findings WHERE run_id = ? AND blocking_class = 1",
                (run_id,),
            ).fetchone()
            doc["blocking"] = {"total": total, "new": new, "baselined": total - new}
        doc["reviews_now"] = data.review_counts(repo_id, run_id)
        doc["baselined"] = _baselined(conn, run_id)
        doc["components"] = [
            {
                "component": r["component"],
                "by_severity": dict(zip(SEVERITIES, r["cells"])),
                "new_blocking": r["new_blocking"],
                "heat": r["score"],
            }
            for r in data.by_component(run_id)["rows"][:MAX_COMPONENTS]
        ]
        row = conn.execute("SELECT scanners FROM runs WHERE id = ?", (run_id,)).fetchone()
        try:
            scanners = json.loads(row[0]) if row and row[0] else {}
        except ValueError:
            scanners = {}
        doc["scanners"] = scanners if isinstance(scanners, dict) else {}
    doc["runs"] = _runs(conn, repo_id, repo, since, until)
    doc["reviews"] = _reviews(conn, repo, since, until)
    return doc


def _baselined(conn, run_id: int) -> dict:
    """The end run's baselined findings, grouped by the issue and reason of their baseline entries."""
    rows = conn.execute(
        "SELECT baseline_issue, baseline_reason, COUNT(*) AS n, SUM(severity = 'ERROR'), SUM(severity = 'WARNING'), "
        "SUM(severity = 'INFO') "
        "FROM run_findings WHERE run_id = ? AND baseline_reason IS NOT NULL GROUP BY baseline_issue, baseline_reason "
        "ORDER BY n DESC, baseline_issue, baseline_reason",
        (run_id,),
    ).fetchall()
    by_kind: Counter = Counter()
    reasons = []
    for issue, reason, n, error, warning, info in rows:
        kind = baseline_kind(reason)
        by_kind[kind] += n
        if len(reasons) < MAX_LISTED:
            reasons.append(
                {
                    "issue": issue,
                    "reason": reason,
                    "kind": kind,
                    "findings": n,
                    "by_severity": {"ERROR": error or 0, "WARNING": warning or 0, "INFO": info or 0},
                }
            )
    return {
        "total": sum(by_kind.values()),
        "groups": len(rows),
        "by_kind": {k: by_kind.get(k, 0) for k in BASELINE_KINDS},
        "reasons": reasons,
    }


def _runs(conn, repo_id: int, repo: str, since: str, until: str) -> dict:
    counts: dict[str, dict[str, int]] = {kind: {o: 0 for o in OUTCOME_LABELS} for kind in history.KINDS}
    for kind, outcome, n in conn.execute(
        "SELECT kind, COALESCE(outcome, CASE result WHEN 'pass' THEN 'passed' ELSE 'blocked' END), COUNT(*) FROM runs "
        "WHERE repo_id = ? AND scanned_at BETWEEN ? AND ? GROUP BY 1, 2",
        (repo_id, since, until),
    ):
        if kind in counts and outcome in counts[kind]:
            counts[kind][outcome] = n
    deleted = conn.execute(
        "SELECT COUNT(*) FROM deletions WHERE repo_name = ? AND scanned_at BETWEEN ? AND ?", (repo, since, until)
    ).fetchone()[0]
    return {"by_kind": counts, "deleted": deleted}


def _reviews(conn, repo: str, since: str, until: str) -> dict:
    """Review statuses now, and every review change made in the period."""
    now = dict(
        conn.execute(
            "SELECT status, COUNT(*) FROM finding_reviews WHERE repo_name = ? GROUP BY status", (repo,)
        ).fetchall()
    )
    total = conn.execute(
        "SELECT COUNT(*) FROM finding_review_events WHERE repo_name = ? AND at BETWEEN ? AND ?", (repo, since, until)
    ).fetchone()[0]
    by_status = dict(
        conn.execute(
            "SELECT to_status, COUNT(*) FROM finding_review_events WHERE repo_name = ? AND at BETWEEN ? AND ? GROUP BY "
            "to_status",
            (repo, since, until),
        ).fetchall()
    )
    rows = conn.execute(
        "SELECT at, who, from_status, to_status, description, rule, path FROM finding_review_events "
        "WHERE repo_name = ? AND at BETWEEN ? AND ? ORDER BY at, id LIMIT ?",
        (repo, since, until, MAX_LISTED),
    ).fetchall()
    return {
        "now": {s: now.get(s, 0) for s in REVIEW_LABELS if s != "open"},
        "changes": {
            "total": total,
            "by_status": {s: by_status.get(s, 0) for s in REVIEW_LABELS},
            "items": [
                {"at": at, "who": who, "from": a, "to": b, "description": d, "rule": rule, "path": path}
                for at, who, a, b, d, rule, path in rows
            ],
        },
    }


# ------------------------------------------------------------------ Markdown


def _plural(n: int, one: str, many: str | None = None) -> str:
    return f"{n} {one if n == 1 else (many or one + 's')}"


def _severities(counts: dict) -> str:
    return ", ".join(f"{s} {counts.get(s, 0)}" for s in SEVERITIES)


def _change(before: int, after: int) -> str:
    diff = after - before
    return "no change" if diff == 0 else f"{'+' if diff > 0 else '−'}{abs(diff)}"


def _run_line(run: dict) -> str:
    return (
        f"{run['scanned_at'][:10]}, commit {md.code(run['commit'][:12])} on {md.code(run['ref'])} "
        f"({md.text(run['kind'])} run {run['id']}): {md.text(run['status'])}"
    )


def render_markdown(doc: dict) -> str:
    p = doc["period"]
    end, start = doc["end"], doc["start"]
    ch = doc["changes"]
    out = [
        f"# Security report: {md.text(doc['repository'], 200)}",
        "",
        f"**Period:** {p['first_day']} to {p['last_day']} (UTC). **Generated:** {doc['generated_at']} by Shoalscan "
        f"{doc['shoalscan_version']}.",
        "",
        "Trends come from "
        + (
            "the scheduled scans of the default branch."
            if doc["trend_runs"] == "scheduled"
            else "every recorded run: this repository has no scheduled scans, so pull-request runs are included."
        ),
    ]

    out += ["", "## Summary", ""]
    if end is None:
        out.append("- No scan with results was recorded in this period, so there is no posture to report.")
    else:
        out.append(f"- Latest scan in the period: {_run_line(end)}.")
        line = f"- Open findings: {end['findings']} ({_severities(end['by_severity'])})"
        if start:
            line += f"; at the start of the period {start['findings']} ({_change(start['findings'], end['findings'])})"
        out.append(line + ".")
        b = doc["blocking"]
        if b is None:
            out.append("- Blocking findings: unknown for this run (recorded without the check's details).")
        else:
            out.append(
                f"- Blocking findings: {b['total']}, of which {b['new']} new and {b['baselined']} in the baseline."
            )
        line = f"- Baseline: {_plural(end['baseline_size'], 'entry', 'entries')}"
        if start:
            line += f" ({_change(start['baseline_size'], end['baseline_size'])} since the start)"
        out.append(line + f"; {_plural(end['stale'], 'stale entry', 'stale entries')}.")
        r = doc["reviews_now"]
        untriaged = "unknown" if doc["blocking"] is None else r["untriaged_blocking"]
        out.append(f"- Untriaged blocking findings: {untriaged}; regressions: {r['regressions']}.")
    ttf = ch["time_to_fix"]
    line = f"- In the period: {_plural(ch['new']['total'], 'new finding')}, {ch['fixed']['total']} fixed"
    if ttf["fixed"]:
        line += f"; median time to fix {ttf['median_days']} days (mean {ttf['mean_days']})"
    out.append(line + ".")

    out += ["", "## Trend", ""]
    if end and start:
        out += ["| Severity | Start | End | Change |", "|---|---:|---:|---|"]
        for s in SEVERITIES:
            out.append(
                f"| {s} | {start['by_severity'][s]} | {end['by_severity'][s]} | "
                f"{_change(start['by_severity'][s], end['by_severity'][s])} |"
            )
        out.append(
            f"| Baseline entries | {start['baseline_size']} | {end['baseline_size']} | "
            f"{_change(start['baseline_size'], end['baseline_size'])} |"
        )
        out += [
            "",
            f"Start: the scan of {start['scanned_at'][:10]}, the last before the period. End: the scan of "
            f"{end['scanned_at'][:10]}.",
            "",
        ]
    elif end:
        out += ["No scan was recorded before the period, so it has no starting point to compare with.", ""]
    out += ["| Week of | New | Fixed |", "|---|---:|---:|"]
    out += [f"| {w['week']} | {w['new']} | {w['fixed']} |" for w in ch["weekly"]]

    for key, title in (("fixed", "Fixed in the period"), ("new", "New in the period")):
        part = ch[key]
        out += ["", f"## {title} ({part['total']})", ""]
        if not part["total"]:
            out.append("None.")
        for f in part["findings"]:
            where = md.code(f"{f['path']}:{f['line']}")
            out.append(
                f"- {f['when'][:10]} {f['severity']} {where} {md.code(f['rule'])} ({md.text(f['component'], 200)})"
            )
        if part["total"] > len(part["findings"]):
            out.append(f"- … and {part['total'] - len(part['findings'])} more (see `--format json`, or the dashboard)")

    out += ["", "## Accepted risks and false positives", ""]
    base = doc["baselined"]
    if end is None:
        out.append("No scan in the period, so the baseline cannot be described.")
    else:
        kinds = ", ".join(f"{BASELINE_KINDS[k].lower()} {n}" for k, n in base["by_kind"].items())
        out.append(
            f"The baseline accepts {_plural(base['total'], 'finding')} in the latest scan ({kinds}), under "
            f"{_plural(base['groups'], 'issue and reason', 'issues and reasons')}:"
        )
        out.append("")
        for g in base["reasons"]:
            out.append(
                f"- {_plural(g['findings'], 'finding')} ({_severities(g['by_severity'])}), {md.text(g['issue'])}: "
                f"{md.text(g['reason'], 400)}"
            )
        if base["groups"] > len(base["reasons"]):
            out.append(f"- … and {base['groups'] - len(base['reasons'])} more reasons")
    rv = doc["reviews"]
    now = ", ".join(f"{REVIEW_LABELS[s].lower()} {n}" for s, n in rv["now"].items())
    out += [
        "",
        f"Dashboard reviews now: {now}. Reviews help triage but never change what blocks CI; the baseline does.",
    ]
    changes = rv["changes"]
    out += ["", f"Review changes in the period: {changes['total']}."]
    if changes["items"]:
        out.append("")
        for e in changes["items"]:
            out.append(
                f"- {e['at'][:10]} {md.text(e['who'], 100)}: {REVIEW_LABELS.get(e['from'], md.text(e['from']))} to "
                f"{REVIEW_LABELS.get(e['to'], md.text(e['to']))}, {md.code(e['path'])} {md.code(e['rule'])}: "
                f"{md.text(e['description'], 300)}"
            )
        if changes["total"] > len(changes["items"]):
            out.append(f"- … and {changes['total'] - len(changes['items'])} more")

    if doc["components"]:
        out += [
            "",
            "## Components",
            "",
            "In the latest scan, hottest first (heat: ERROR ×10, WARNING ×3, INFO ×1).",
            "",
        ]
        out += ["| Component | ERROR | WARNING | INFO | New blocking | Heat |", "|---|---:|---:|---:|---:|---:|"]
        for c in doc["components"]:
            s = c["by_severity"]
            out.append(
                f"| {md.text(c['component'], 200)} | {s['ERROR']} | {s['WARNING']} | {s['INFO']} | {c['new_blocking']} "
                f"| {c['heat']} |"
            )

    out += ["", "## Coverage", ""]
    runs = doc["runs"]
    for kind, label in (("scheduled", "Scheduled scans"), ("pr", "Pull-request runs")):
        c = runs["by_kind"][kind]
        out.append(
            f"- {label} in the period: {sum(c.values())} "
            f"({', '.join(f'{OUTCOME_LABELS[o]} {n}' for o, n in c.items())})."
        )
    if runs["deleted"]:
        out.append(
            f"- {_plural(runs['deleted'], 'run')} scanned in the period {'was' if runs['deleted'] == 1 else 'were'} "
            "later deleted from the history."
        )
    if end:
        u, s = end["unscanned"], end["suppressions"]
        out.append(f"- Files not fully scanned in the latest scan: {u['skipped']} skipped, {u['errored']} with errors.")
        out.append(
            f"- Inline suppressions: {s['total']} ({s['invalid']} without a rule and an issue), silencing "
            f"{_plural(s['suppressed_findings'], 'finding')}."
        )
    for name, info in sorted(doc["scanners"].items()):
        if not isinstance(info, dict):
            continue
        line = f"- Scanner {md.code(name)} {md.text(info.get('version', 'unknown version'), 50)}"
        if "signature_verified" in info:
            line += ", signature verified" if info["signature_verified"] is True else ", **signature not verified**"
        sources = info.get("rule_sources")
        if isinstance(sources, list) and sources:
            line += f"; rule sources: {', '.join(md.text(x, 100) for x in sources[:20])}"
        commit = info.get("community_rules_commit")
        if isinstance(commit, str):
            line += f"; community rules at {md.code(commit[:12])}"
        out.append(line + ".")

    out += [
        "",
        "## Limits",
        "",
        "This report covers what the configured scanners and rules can see in the scanned files. Static analysis "
        "misses flaws "
        "that need data flow across files, runtime behaviour or business logic, and it does not replace code review, "
        "tests or "
        f"dependency audits. See {md.link('Limits', PROJECT_URL + '/blob/main/docs/limits.md')}.",
    ]
    return "\n".join(out) + "\n"


# ------------------------------------------------------------------ command


def run(args: argparse.Namespace) -> int:
    from shoalscan.dashboard.commands import _db

    now = datetime.now(timezone.utc).replace(microsecond=0)
    first, last = period(args.since, args.until, now.date())
    db = _db(args)
    if not db.is_file():
        raise SetupError(f"history database not found: {db}")
    conn = history.open_read_only(db)
    try:
        doc = build(conn, args.repo_name, first, last, now.strftime("%Y-%m-%dT%H:%M:%SZ"))
    finally:
        conn.close()
    text = json.dumps(doc, indent=2, sort_keys=True) + "\n" if args.format == "json" else render_markdown(doc)
    if args.output:
        write_atomic(Path(args.output), text)
        print(
            f"shoalscan report: wrote the report on {args.repo_name} for {first} to {last} to {args.output}",
            file=sys.stderr,
        )
    else:
        sys.stdout.write(text)
    return 0


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("--repo-name", required=True, help="the repository's name in the history, such as owner/project")
    p.add_argument(
        "--since", help=f"the first day, YYYY-MM-DD, UTC (default: {DEFAULT_DAYS} days before --until, inclusive)"
    )
    p.add_argument("--until", help="the last day, YYYY-MM-DD, UTC (default: today)")
    p.add_argument(
        "--format", choices=("markdown", "json"), default="markdown", help="output format (default: markdown)"
    )
    p.add_argument("--output", help="write the report to this file instead of standard output")
    p.add_argument("--db", help="history database (default: the same default as `record`)")
