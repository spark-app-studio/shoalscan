"""Synthetic runs for the history and dashboard tests."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path

import helpers  # noqa: F401 - puts src/ on the import path

from shoalscan import history
from shoalscan.baseline import Entry
from shoalscan.check import CHECK_JSON, SUMMARY_PREFIX, compare, details, render_report, summary_line
from shoalscan.findings import Finding, findings_to_json

MALICIOUS = '<img src=x onerror="alert(1)"></script><script>alert(2)</script>'


def finding(
    rule: str,
    path: str,
    fp: str,
    severity: str = "ERROR",
    component: str = "api",
    message: str = "a problem",
    line: int = 3,
) -> Finding:
    return Finding(
        tool="opengrep",
        rule=rule,
        severity=severity,
        path=path,
        line=line,
        fingerprint=fp,
        component=component,
        message=message,
    )


def summary(
    findings: list[Finding],
    result: str = "pass",
    baseline_size: int = 0,
    suppressions: int = 0,
    skipped: int = 0,
    errored: int = 0,
    new: int = 0,
) -> dict:
    sev = Counter(f.severity for f in findings)
    return {
        "result": result,
        "findings": len(findings),
        "by_severity": {k: sev.get(k, 0) for k in ("ERROR", "WARNING", "INFO")},
        "by_severity_non_blocking_paths": {"ERROR": 0, "WARNING": 0, "INFO": 0},
        "by_component": dict(Counter(f.component for f in findings)),
        "by_rule": dict(Counter(f.rule for f in findings)),
        "new": new,
        "new_blocking": 0,
        "new_in_non_blocking_paths": 0,
        "stale": 0,
        "baseline_size": baseline_size,
        "suppressions": {"total": suppressions, "invalid": 0, "suppressed_findings": suppressions},
        "unscanned": {"skipped": skipped, "errored": errored, "changed_and_unscanned": 0},
        "baseline_additions": 0,
        "policy_ref": None,
    }


def check_output(doc: dict) -> str:
    return "Shoalscan check: PASSED\n  Findings: ...\n" + SUMMARY_PREFIX + json.dumps(doc, sort_keys=True) + "\n"


def write_findings(directory: Path, findings: list[Finding], extra_meta: dict | None = None) -> Path:
    path = directory / "findings.json"
    meta = {
        "counts": dict(Counter(f.severity for f in findings)),
        "duration_seconds": 1.5,
        "scanners": {"opengrep": {"version": "1.30.2", "rule_sources": ["community", "shoalscan"]}},
        "shoalscan_version": "0.1.0",
        "suppressions": {"total": 0, "invalid": 0, "suppressed_findings": 0},
        **(extra_meta or {}),
    }
    path.write_text(findings_to_json(findings, meta), encoding="utf-8")
    return path


def checked(
    directory: Path,
    findings: list[Finding],
    baseline: list[Entry],
    extra_meta: dict | None = None,
    changed_files: list[str] | None = None,
    parse_warn_only: tuple[str, ...] = (),
    non_blocking_paths: tuple[str, ...] = (),
) -> tuple[Path, str]:
    """Run the real check comparison and write findings.json and check.json, as `scan` and `check` do."""
    meta = extra_meta or {}
    path = write_findings(directory, findings, meta)
    result = compare(
        findings,
        baseline,
        ("ERROR", "WARNING"),
        meta.get("suppressions"),
        non_blocking_paths,
        unscanned=meta.get("unscanned"),
        changed_files=changed_files,
        added_lines=lambda p: set(),
        parse_warn_only=parse_warn_only,
    )
    sha = hashlib.sha256(path.read_bytes()).hexdigest()
    (directory / CHECK_JSON).write_text(json.dumps(details(result, sha), sort_keys=True), encoding="utf-8")
    return path, render_report(result) + "\n" + summary_line(result) + "\n"


def record(
    conn,
    tmp: Path,
    repo: str,
    commit: str,
    day: int,
    findings: list[Finding],
    kind: str = "scheduled",
    baseline: list[Entry] | None = None,
    extra_meta: dict | None = None,
    check_exit: int | None = None,
    non_blocking_paths: tuple[str, ...] = (),
    **summary_args,
) -> history.RecordResult:
    directory = tmp / f"{repo.replace('/', '_')}-{commit}-{kind}"
    directory.mkdir(exist_ok=True)
    info = history.RunInfo(repo=repo, ref="main", commit=commit, kind=kind, scanned_at=f"2026-09-{day:02d}T02:00:00Z")
    if baseline is not None:
        path, output = checked(directory, findings, baseline, extra_meta, non_blocking_paths=non_blocking_paths)
        found, meta, doc = history.read_inputs(path, output)
        found_details = history.read_details(directory / CHECK_JSON, path, doc, found)
        return history.record_run(conn, info, found, meta, doc, details=found_details, check_exit=check_exit)
    path = write_findings(directory, findings, extra_meta)
    found, meta, doc = history.read_inputs(path, check_output(summary(findings, **summary_args)))
    return history.record_run(conn, info, found, meta, doc, check_exit=check_exit)


def entry(f: Finding, issue: str = "#1") -> Entry:
    return Entry(f.tool, f.rule, f.path, f.fingerprint, issue, "accepted for now")


def sample_history(conn, tmp: Path) -> None:
    """Four weekly scheduled runs of `acme/app`, a pull-request run, and a second repository.

    - A: present on 09-01 and 09-08, fixed on 09-15 (14 days to fix).
    - B: new on 09-08 and still open.
    - C: present since 09-01 and still open; it carries a malicious message.
    - D: open 09-01, fixed 09-08, back on 09-22 (a second episode).
    """
    a = finding("community.python.eval", "src/a.py", "aaaa:0", "ERROR", "api")
    b = finding("shoalscan.plain-http-url", "web/b.js", "bbbb:0", "WARNING", "web")
    c = finding("shoalscan.secret-in-log", "src/c.py", "cccc:0", "INFO", "api", message=MALICIOUS)
    d = finding("community.python.eval", "src/d.py", "dddd:0", "ERROR", "api")
    record(conn, tmp, "acme/app", "1" * 40, 1, [a, c, d], baseline_size=3)
    record(conn, tmp, "acme/app", "2" * 40, 8, [a, b, c], baseline_size=3, new=1, result="fail")
    record(conn, tmp, "acme/app", "3" * 40, 15, [b, c], baseline_size=2, suppressions=1)
    # The last scheduled run went through the real check: C is accepted in the
    # baseline, an entry for a deleted file is stale, B and D are new and blocking.
    gone = Entry("opengrep", "community.python.eval", "src/old.py", "old0:0", "#9", "accepted")
    meta = {
        "suppressions": {"total": 1, "invalid": 0, "suppressed_findings": 1},
        "suppression_list": [
            {
                "path": "web/b.js",
                "line": 4,
                "rules": ["shoalscan.plain-http-url"],
                "issue": "#5",
                "valid": True,
                "problem": None,
            }
        ],
        "unscanned": {
            "skipped": [
                {"path": "big/huge.min.js", "reason": "exceeded_size_limit"},
                {"path": "big/other.bin", "reason": "binary"},
            ],
            "errors": [{"path": "deploy/Dockerfile", "type": "PartialParsing", "spans": [[2, 9]], "file_lines": 10}],
        },
    }
    record(conn, tmp, "acme/app", "4" * 40, 22, [b, c, d], baseline=[entry(c), gone], extra_meta=meta)
    record(conn, tmp, "acme/app", "5" * 40, 23, [b, c], kind="pr")
    record(conn, tmp, "acme/other", "6" * 40, 20, [finding("shoalscan.tls-off", "x.py", "eeee:0")])
