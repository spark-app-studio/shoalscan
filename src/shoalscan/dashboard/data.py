"""Read-only queries and derived metrics for the dashboard.

Every query is parameterised. Trend charts use a repository's scheduled
runs (the nightly scan of the default branch); a repository that has no
scheduled runs uses all of its runs instead. Runs whose check could not run
(scan errors) hold no results, so they never feed a trend or a default view.

First seen and fixed are derived by walking the trend runs in time order: a
finding identity (tool, rule, path, fingerprint) that appears in a run but
not in the one before is new there; one that was in the run before but not
in this one is fixed there. A finding that comes back opens a new episode.
Findings already present in the first run walked count from that run, so
their age and time to fix are lower bounds. The walk covers at most the
newest MAX_TREND_RUNS trend runs and holds two runs' findings at a time.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections import Counter
from datetime import date, datetime, timedelta

from shoalscan import embeddings
from shoalscan.testscope import scope_from_json

SEVERITIES = ("ERROR", "WARNING", "INFO")
AGE_BUCKETS = ((7, "0-7 days"), (30, "8-30 days"), (90, "31-90 days"), (365, "91-365 days"), (None, "over a year"))
MAX_WEEKS = 52
MAX_COMPONENTS = 500
MAX_PAGE = 500
MAX_GROUPS = 100  # groups of similar findings listed at once
MAX_GROUP_MEMBERS_SHOWN = 10  # findings listed under each group; the Findings view lists them all
# The new, fixed, time-to-fix and age figures walk at most this many of the
# newest trend runs (about a year of nightly scans).
MAX_TREND_RUNS = 400
# Heat score weights for the component heatmap.
HEAT_WEIGHTS = {"ERROR": 10, "WARNING": 3, "INFO": 1}
HEAT_LEVELS = 5
FILE_KINDS = ("skipped", "error", "changed_unscanned", "partial_warning", "partial_warn_only", "excluded_changed")

_RUN_COLUMNS = (
    "id, kind, ref, commit_sha, scanned_at, recorded_at, result, findings, error, warning, info, "
    "nb_error, nb_warning, nb_info, new, new_blocking, new_non_blocking_paths, stale, baseline_size, "
    "baseline_additions, suppressions, suppressions_invalid, suppressed_findings, unscanned_skipped, "
    "unscanned_errored, changed_unscanned, policy_ref, shoalscan_version, duration_seconds, outcome, check_exit, "
    "details_known, files_known, suppressions_known, partial_warnings, partial_warn_only, excluded_changed, "
    "blocking_class_count, scanners, test_code, "
    "EXISTS (SELECT 1 FROM scan_triggers st WHERE st.run_id = runs.id AND st.trigger = 'rescan-commit') AS rescanned"
)
SORTS = ("priority",)
REVIEW_FILTERS = (
    "untriaged",
    "open",
    "false_positive",
    "accepted_risk",
    "wont_fix",
    "fixed",
    "verified_fixed",
    "regression",
    "baselined",
    "suggested",
    "test_code",
)
# The neighbour's decision, now: its dashboard review, else its baseline reason in its newest scheduled run.
# A pull-request run's baseline reason is never a decision: the change under review has not been accepted.
_NEIGHBOUR_REVIEW = (
    "LEFT JOIN finding_reviews nr ON nr.repo_name = (SELECT name FROM repos WHERE id = nk.repo_id) "
    "AND nr.tool = nk.tool "
    "AND nr.rule = nk.rule AND nr.path = nk.path AND nr.fingerprint = nk.fingerprint"
)
_NEIGHBOUR_BASELINE = (
    f"LEFT JOIN run_findings nb ON nb.key_id = nk.id AND nb.run_id = {embeddings.DECISION_RUN.format(key='nk.id')} "
    "LEFT JOIN runs nbr ON nbr.id = nb.run_id"
)
# The stored suggestions of some findings, with their neighbours' decisions now and where they come from.
_SUGGESTIONS = (
    "SELECT s.key_id, s.score, s.computed_at, nk.tool, nk.rule, nk.path, nk.fingerprint, nr.status, "
    "nr.description, nr.updated_by, nr.updated_at, nb.baseline_issue, nb.baseline_reason, nbr.id, nbr.commit_sha, "
    "nbr.scanned_at "
    f"FROM finding_suggestions s JOIN finding_keys nk ON nk.id = s.neighbour_id {_NEIGHBOUR_REVIEW} "
    f"{_NEIGHBOUR_BASELINE} "
    "WHERE s.model = ? AND s.key_id IN (SELECT value FROM json_each(?))"
)
# Untriaged, with a suggestion whose neighbour still has a decision that suggests a status.
_SUGGESTED = (
    "fr.status IS NULL AND rf.baseline_reason IS NULL AND EXISTS (SELECT 1 FROM finding_suggestions s "
    f"JOIN finding_keys nk ON nk.id = s.neighbour_id {_NEIGHBOUR_REVIEW} {_NEIGHBOUR_BASELINE} "
    "WHERE s.key_id = rf.key_id AND s.model = ? AND "
    "(nr.status IN ('false_positive', 'accepted_risk', 'wont_fix') OR (nr.status IS NULL AND "
    "(substr(nb.baseline_reason, 1, 15) = 'False positive:' OR substr(nb.baseline_reason, 1, 9) = 'Accepted:'))))"
)
# A finding's review status: a review made on the dashboard, else what its
# baseline entry's reason says, else open.
_REVIEW_STATUS = (
    "CASE WHEN fr.status IS NOT NULL THEN fr.status "
    "WHEN substr(rf.baseline_reason, 1, 15) = 'False positive:' THEN 'false_positive' "
    "WHEN substr(rf.baseline_reason, 1, 9) = 'Accepted:' THEN 'accepted_risk' "
    "WHEN rf.baseline_reason IS NOT NULL THEN 'baselined' ELSE 'open' END"
)
_REVIEW_JOIN = (
    "LEFT JOIN finding_reviews fr ON fr.repo_name = (SELECT name FROM repos WHERE id = ?) AND fr.tool = fk.tool "
    "AND fr.rule = fk.rule AND fr.path = fk.path AND fr.fingerprint = fk.fingerprint"
)
# The untriaged findings of a run that have a vector, most important first.
_UNTRIAGED_VECTORS = (
    f"SELECT rf.key_id, e.vector, e.dims FROM run_findings rf JOIN finding_keys fk ON fk.id = rf.key_id {_REVIEW_JOIN} "
    "JOIN finding_embeddings e ON e.key_id = rf.key_id AND e.model = ? "
    "WHERE rf.run_id = ? AND fr.status IS NULL AND rf.baseline_reason IS NULL "
    "ORDER BY CASE rf.severity WHEN 'ERROR' THEN 0 WHEN 'WARNING' THEN 1 ELSE 2 END, "
    "fk.path, rf.line, fk.rule, rf.key_id"
)
_UNTRIAGED_COUNT = (
    f"SELECT COUNT(*) FROM run_findings rf JOIN finding_keys fk ON fk.id = rf.key_id {_REVIEW_JOIN} "
    "WHERE rf.run_id = ? AND fr.status IS NULL AND rf.baseline_reason IS NULL"
)
_SUGGESTED_COUNT = (
    f"SELECT COUNT(*) FROM run_findings rf JOIN finding_keys fk ON fk.id = rf.key_id {_REVIEW_JOIN} "
    f"WHERE rf.run_id = ? AND {_SUGGESTED}"
)
_GROUP_DETAILS = (
    "SELECT rf.key_id, rf.severity, fk.tool, fk.rule, fk.path, fk.fingerprint, rf.line, rf.component, m.text "
    "FROM run_findings rf JOIN finding_keys fk ON fk.id = rf.key_id JOIN messages m ON m.id = rf.message_id "
    "WHERE rf.run_id = ? AND rf.key_id IN (SELECT value FROM json_each(?))"
)


def _review(r) -> dict:
    source = (
        "review" if r["review_status_raw"] is not None else ("baseline" if r["baseline_reason"] is not None else "none")
    )
    return {
        "status": r["review_status"],
        "source": source,
        "description": r["review_description"],
        "resolved_at": r["review_resolved_at"],
        "updated_at": r["review_updated_at"],
        "updated_by": r["review_updated_by"],
        "baseline_issue": r["baseline_issue"],
        "baseline_reason": r["baseline_reason"],
    }


def _test_code(value: str | None) -> dict | None:
    """A finding's test code label, with its description; None when it has none."""
    if value is None:
        return None
    try:
        scope = scope_from_json(json.loads(value))
    except ValueError:
        return None
    return None if scope is None else {**scope.as_json(), "description": scope.description()}


SEVERITY_RANK = {"ERROR": 0, "WARNING": 1, "INFO": 2}
TOP_BLOCKING = 10
_TREND = "outcome != 'scan_error'"


def _parse(ts: str) -> datetime:
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")


def _week(ts: str) -> date:
    d = _parse(ts).date()
    return d - timedelta(days=d.weekday())


def _median(counts: Counter) -> float:
    """The median of values given as {value: how many}."""
    total = sum(counts.values())
    ordered = sorted(counts)

    def nth(n: int) -> int:
        seen = 0
        for value in ordered:
            seen += counts[value]
            if seen > n:
                return value
        return ordered[-1]

    if total % 2:
        return nth(total // 2)
    return (nth(total // 2 - 1) + nth(total // 2)) / 2


def _count(n: int, one: str, many: str) -> str:
    return f"{n} {one if n == 1 else many}"


def run_status(d: dict) -> dict:
    """What a run's result means, in words: Passed, Blocked (and why) or Scan error."""
    outcome = d.get("outcome") or ("passed" if d.get("result") == "pass" else "blocked")
    if outcome == "scan_error":
        return {
            "outcome": outcome,
            "label": "Scan error",
            "details": ["The check could not run: the setup was broken or the scan failed. This run has no results."],
            "explanation": None,
        }
    reasons = [
        _count(d["new_blocking"], "new blocking finding", "new blocking findings") if d["new_blocking"] else None,
        _count(d["stale"], "stale baseline entry", "stale baseline entries") if d["stale"] else None,
        _count(d["changed_unscanned"], "changed file not fully scanned", "changed files not fully scanned")
        if d["changed_unscanned"]
        else None,
        _count(d["baseline_additions"], "baseline entry added", "baseline entries added")
        if d["baseline_additions"]
        else None,
    ]
    reasons = [r for r in reasons if r]
    notes = []
    if d.get("partial_warn_only"):
        notes.append(
            _count(
                d["partial_warn_only"],
                "changed file partially parsed (warn-only by policy)",
                "changed files partially parsed (warn-only by policy)",
            )
        )
    if outcome == "passed":
        return {"outcome": outcome, "label": "Passed", "details": notes, "explanation": None}
    return {
        "outcome": outcome,
        "label": f"Blocked: {reasons[0]}" if reasons else "Blocked",
        "details": reasons[1:] + notes,
        "explanation": (
            "The check blocks a change that adds findings the baseline does not accept, leaves stale baseline "
            "entries, or changes files that could not be fully scanned."
        ),
    }


def _scanners_ran(text: object) -> list[dict]:
    """Which scanners a run used, with their versions, from the run's stored scanner metadata."""
    try:
        doc = json.loads(text) if isinstance(text, str) else {}
    except ValueError:
        return []
    if not isinstance(doc, dict):
        return []
    out = []
    for name, info in sorted(doc.items()):
        info = info if isinstance(info, dict) else {}
        version = info.get("version")
        out.append({"name": str(name)[:40], "version": str(version)[:40] if isinstance(version, str) else None})
    return out[:20]


def _run_dict(row: sqlite3.Row) -> dict:
    d = dict(row)
    out = {
        "id": d["id"],
        "kind": d["kind"],
        "ref": d["ref"],
        "commit": d["commit_sha"],
        "scanned_at": d["scanned_at"],
        "recorded_at": d["recorded_at"],
        "result": d["result"],
        "outcome": d["outcome"] or ("passed" if d["result"] == "pass" else "blocked"),
        "check_exit": d["check_exit"],
        "findings": d["findings"],
        "by_severity": {"ERROR": d["error"], "WARNING": d["warning"], "INFO": d["info"]},
        "by_severity_non_blocking_paths": {"ERROR": d["nb_error"], "WARNING": d["nb_warning"], "INFO": d["nb_info"]},
        "new": d["new"],
        "new_blocking": d["new_blocking"],
        "new_in_non_blocking_paths": d["new_non_blocking_paths"],
        "stale": d["stale"],
        "baseline_size": d["baseline_size"],
        "baseline_additions": d["baseline_additions"],
        "suppressions": {
            "total": d["suppressions"],
            "invalid": d["suppressions_invalid"],
            "suppressed_findings": d["suppressed_findings"],
        },
        "unscanned": {
            "skipped": d["unscanned_skipped"],
            "errored": d["unscanned_errored"],
            "changed_and_unscanned": d["changed_unscanned"],
            "changed_partially_parsed_warnings": d["partial_warnings"],
            "changed_partially_parsed_warn_only": d["partial_warn_only"],
            "changed_but_excluded": d["excluded_changed"],
        },
        # Findings the policy treats as blocking, baselined or not; None when unknown.
        "blocking_class": d["blocking_class_count"],
        # Which lists can be shown for this run (older runs have counts only).
        "lists": {
            "blocking": d["blocking_class_count"] is not None,
            "new": bool(d["details_known"]),
            "stale": bool(d["details_known"]),
            "files": bool(d["files_known"]),
            "suppressions": bool(d["suppressions_known"]),
        },
        "policy_ref": d["policy_ref"],
        "shoalscan_version": d["shoalscan_version"],
        "duration_seconds": d["duration_seconds"],
        "rescanned": bool(d["rescanned"]),
        # Findings labelled as test code: a triage label, which never changes whether a finding blocks.
        "test_code": d["test_code"],
        "scanners": _scanners_ran(d.get("scanners")),
    }
    out["status"] = run_status(d)
    return out


def heat_rows(counts: dict[str, Counter]) -> list[dict]:
    """Component rows for the heatmap, hottest first.

    The score is ERROR x10 + WARNING x3 + INFO x1. Components with any new
    blocking findings come first; within each group, the highest score first.
    """
    rows = []
    for component, c in counts.items():
        cells = [c[s] for s in SEVERITIES]
        score = sum(HEAT_WEIGHTS[s] * c[s] for s in SEVERITIES)
        rows.append(
            {"component": component, "cells": cells, "new": c["new"], "new_blocking": c["new_blocking"], "score": score}
        )
    rows.sort(key=lambda r: (r["new_blocking"] == 0, -r["score"], r["component"]))
    return rows


def heat_level(value: int, maximum: int) -> int:
    """0 for an empty cell, else 1..HEAT_LEVELS in proportion to the largest cell."""
    if value <= 0 or maximum <= 0:
        return 0
    return min(HEAT_LEVELS, 1 + (value - 1) * HEAT_LEVELS // maximum)


def priority_key(row, scores: dict[str, int], first_seen: dict[int, str]) -> tuple:
    """Fix-first order: new blocking findings, then ERROR before WARNING, then the
    component's heat score (highest first), then the oldest first seen."""
    return (
        0 if row["new_blocking"] else 1,
        SEVERITY_RANK.get(row["severity"], 3),
        -scores.get(row["component"], 0),
        first_seen.get(row["key_id"]) or "9999",
        row["path"],
        row["line"],
        row["rule"],
    )


class Data:
    """Queries over one read-only connection. Not shared between threads."""

    def __init__(self, conn: sqlite3.Connection):
        conn.row_factory = sqlite3.Row
        self.conn = conn

    # -------------------------------------------------------- repositories

    def repo_id(self, name: str) -> int | None:
        row = self.conn.execute("SELECT id FROM repos WHERE name = ?", (name,)).fetchone()
        return row[0] if row else None

    def repos(self) -> list[dict]:
        out = []
        for row in self.conn.execute("SELECT id, name FROM repos ORDER BY name"):
            latest = self.conn.execute(
                f"SELECT {_RUN_COLUMNS} FROM runs WHERE repo_id = ? ORDER BY scanned_at DESC, id DESC LIMIT 1",
                (row["id"],),
            ).fetchone()
            count = self.conn.execute("SELECT COUNT(*) FROM runs WHERE repo_id = ?", (row["id"],)).fetchone()[0]
            out.append({"name": row["name"], "runs": count, "latest": _run_dict(latest) if latest else None})
        return out

    def version(self, repo_id: int) -> tuple:
        """Changes whenever the repository's runs change; used as a cache key."""
        return tuple(
            self.conn.execute(
                "SELECT COUNT(*), COALESCE(MAX(id), 0), COALESCE(MAX(recorded_at), ''), COALESCE(SUM(id), 0) FROM runs "
                "WHERE repo_id = ?",
                (repo_id,),
            ).fetchone()
        )

    def _trend_kinds(self, repo_id: int) -> tuple[str, ...]:
        has = self.conn.execute(
            f"SELECT 1 FROM runs WHERE repo_id = ? AND kind = 'scheduled' AND {_TREND} LIMIT 1", (repo_id,)
        ).fetchone()
        return ("scheduled",) if has else ("scheduled", "pr")

    def _trend_runs(self, repo_id: int) -> list[sqlite3.Row]:
        kinds = self._trend_kinds(repo_id)
        marks = ", ".join("?" for _ in kinds)
        return self.conn.execute(
            f"SELECT {_RUN_COLUMNS} FROM runs WHERE repo_id = ? AND kind IN ({marks}) AND {_TREND} ORDER BY scanned_at, id",  # noqa: E501 - one literal, so Opengrep's raw-query rule still sees it
            (repo_id, *kinds),
        ).fetchall()

    def run(self, repo_id: int, run_id: int) -> dict | None:
        row = self.conn.execute(
            f"SELECT {_RUN_COLUMNS} FROM runs WHERE id = ? AND repo_id = ?", (run_id, repo_id)
        ).fetchone()
        return _run_dict(row) if row else None

    # -------------------------------------------------------- overview

    def overview(self, repo_id: int) -> dict:
        runs = self._trend_runs(repo_id)
        latest_any = self.conn.execute(
            f"SELECT {_RUN_COLUMNS} FROM runs WHERE repo_id = ? ORDER BY scanned_at DESC, id DESC LIMIT 1", (repo_id,)
        ).fetchone()
        result: dict = {
            "trend_kind": "scheduled" if self._trend_kinds(repo_id) == ("scheduled",) else "all",
            "latest_run": _run_dict(latest_any) if latest_any else None,
            "latest_trend_run": _run_dict(runs[-1]) if runs else None,
            "series": [
                {
                    "run": r["id"],
                    "scanned_at": r["scanned_at"],
                    "commit": r["commit_sha"],
                    "open": {"ERROR": r["error"], "WARNING": r["warning"], "INFO": r["info"]},
                    "baseline_size": r["baseline_size"],
                    "suppressions": r["suppressions"],
                    "suppressed_findings": r["suppressed_findings"],
                    "unscanned_skipped": r["unscanned_skipped"],
                    "unscanned_errored": r["unscanned_errored"],
                    "blocking": r["blocking_class_count"],
                    "lists": {"files": bool(r["files_known"]), "suppressions": bool(r["suppressions_known"])},
                }
                for r in runs
            ],
            "weekly": [],
            "time_to_fix": {"fixed": 0, "mean_days": None, "median_days": None},
            "age_buckets": [{"label": label, "count": 0} for _, label in AGE_BUCKETS],
            "by_component": {"run": None, "severities": list(SEVERITIES), "max_cell": 0, "rows": []},
            "blocking": {"run": None, "known": False, "total": None, "new": None, "baselined": None, "top": []},
            "reviews": {"run": None, "untriaged_blocking": 0, "regressions": 0, "test_code": 0},
            "embeddings": None,
        }
        if not runs:
            return result
        result["blocking"] = self.blocking_summary(repo_id, runs[-1])
        result["reviews"] = self.review_counts(repo_id, runs[-1]["id"])
        timeline = self._timeline(runs)
        result["weekly"] = timeline["weekly"]
        result["time_to_fix"] = timeline["time_to_fix"]
        buckets = Counter(self._age_bucket(start, runs[-1]["scanned_at"]) for start in timeline["open_since"].values())
        result["age_buckets"] = [{"label": label, "count": buckets[i]} for i, (_, label) in enumerate(AGE_BUCKETS)]
        result["by_component"] = self.by_component(runs[-1]["id"])
        result["embeddings"] = self.embedding_status(repo_id, runs[-1]["id"])
        return result

    @staticmethod
    def _age_bucket(start: str, now: str) -> int:
        age = (_parse(now) - _parse(start)).days
        for index, (limit, _) in enumerate(AGE_BUCKETS):
            if limit is None or age <= limit:
                return index
        return len(AGE_BUCKETS) - 1

    def _walk(self, runs: list[sqlite3.Row]):
        """Yield (index, run, current keys, previous keys) for the newest trend runs, two runs at a time."""
        previous: set[int] = set()
        for index, run in enumerate(runs[-MAX_TREND_RUNS:]):
            current = {
                key for (key,) in self.conn.execute("SELECT key_id FROM run_findings WHERE run_id = ?", (run["id"],))
            }
            yield index, run, current, previous
            previous = current

    def _timeline(self, runs: list[sqlite3.Row]) -> dict:
        new_by_week: Counter = Counter()
        fixed_by_week: Counter = Counter()
        fix_days: Counter = Counter()  # time to fix in tenths of a day, for the mean and median
        open_since: dict[int, str] = {}
        for index, run, current, previous in self._walk(runs):
            when = run["scanned_at"]
            for key in current - previous:
                open_since[key] = when
                if index > 0:
                    new_by_week[_week(when)] += 1
            for key in previous - current:
                fixed_by_week[_week(when)] += 1
                started = open_since.pop(key)
                fix_days[round((_parse(when) - _parse(started)).total_seconds() / 8640)] += 1
        walked = runs[-MAX_TREND_RUNS:]
        first, last = _week(walked[0]["scanned_at"]), _week(walked[-1]["scanned_at"])
        weeks = []
        week = max(first, last - timedelta(weeks=MAX_WEEKS - 1))
        while week <= last:
            weeks.append({"week": week.isoformat(), "new": new_by_week[week], "fixed": fixed_by_week[week]})
            week += timedelta(weeks=1)
        fixed = sum(fix_days.values())
        ttf = {
            "fixed": fixed,
            "mean_days": round(sum(k * n for k, n in fix_days.items()) / fixed / 10, 1) if fixed else None,
            "median_days": round(_median(fix_days) / 10, 1) if fixed else None,
        }
        return {"weekly": weeks, "time_to_fix": ttf, "open_since": open_since}

    def blocking_summary(self, repo_id: int, run: sqlite3.Row) -> dict:
        """The blocking-class findings of one run: how many, new versus baselined, and the top ones by priority."""
        out = {
            "run": run["id"],
            "known": run["blocking_class_count"] is not None,
            "total": None,
            "new": None,
            "baselined": None,
            "top": [],
        }
        if not out["known"]:
            return out
        total, new = self.conn.execute(
            "SELECT COUNT(*), COALESCE(SUM(is_new), 0) FROM run_findings WHERE run_id = ? AND blocking_class = 1",
            (run["id"],),
        ).fetchone()
        out.update(total=total, new=new, baselined=total - new)
        out["top"] = self.findings(repo_id, run["id"], blocking=True, sort="priority", limit=TOP_BLOCKING)["findings"]
        return out

    def component_scores(self, run_id: int) -> dict[str, int]:
        """The heatmap's heat score of every component in one run."""
        return {r["component"]: r["score"] for r in self.by_component(run_id)["rows"]}

    def by_component(self, run_id: int) -> dict:
        counts: dict[str, Counter] = {}
        for component, severity, n, new, new_blocking in self.conn.execute(
            "SELECT component, severity, COUNT(*), SUM(is_new), SUM(new_blocking) FROM run_findings "
            "WHERE run_id = ? GROUP BY component, severity",
            (run_id,),
        ):
            c = counts.setdefault(component, Counter())
            c[severity] += n
            c["new"] += new or 0
            c["new_blocking"] += new_blocking or 0
        rows = heat_rows(counts)[:MAX_COMPONENTS]
        maximum = max((v for r in rows for v in r["cells"]), default=0)
        for r in rows:
            r["levels"] = [heat_level(v, maximum) for v in r["cells"]]
        return {"run": run_id, "severities": list(SEVERITIES), "max_cell": maximum, "rows": rows}

    # -------------------------------------------------------- findings

    def resolve_run(self, repo_id: int, run_id: int | None) -> int | None:
        if run_id is not None:
            row = self.conn.execute("SELECT id FROM runs WHERE id = ? AND repo_id = ?", (run_id, repo_id)).fetchone()
            return row[0] if row else None
        return embeddings.latest_trend_run(self.conn, repo_id)

    def _age_keys(self, repo_id: int, run_id: int, bucket: int) -> list[int] | None:
        """Key ids of the open findings in one age bucket; None unless `run_id` is the latest trend run."""
        runs = self._trend_runs(repo_id)
        if not runs or runs[-1]["id"] != run_id:
            return None
        timeline = self._timeline(runs)
        now = runs[-1]["scanned_at"]
        return [k for k, start in timeline["open_since"].items() if self._age_bucket(start, now) == bucket]

    def findings(
        self,
        repo_id: int,
        run_id: int,
        severity: str | None = None,
        rule: str | None = None,
        component: str | None = None,
        path: str | None = None,
        new: bool = False,
        new_blocking: bool = False,
        age: int | None = None,
        blocking: bool = False,
        baselined: bool = False,
        sort: str | None = None,
        review: str | None = None,
        keys: list[int] | None = None,
        limit: int = 200,
        offset: int = 0,
    ) -> dict:
        """One page of a run's findings. With `blocking`, only the blocking class,
        sorted by priority unless another sort is asked for."""
        where = ["rf.run_id = ?"]
        params: list = [repo_id, run_id]  # the first is the review join's repository
        if severity:
            where.append("rf.severity = ?")
            params.append(severity)
        if rule:
            where.append("fk.rule = ?")
            params.append(rule)
        if component:
            where.append("rf.component = ?")
            params.append(component)
        if path:
            where.append("instr(fk.path, ?) > 0")
            params.append(path)
        if new:
            where.append("rf.is_new = 1")
        if new_blocking:
            where.append("rf.new_blocking = 1")
        if blocking:
            where.append("rf.blocking_class = 1")
        if baselined:
            where.append("rf.is_new = 0")
        if blocking and sort is None:
            sort = "priority"
        if age is not None:
            keys = self._age_keys(repo_id, run_id, age)
            where.append("rf.key_id IN (SELECT value FROM json_each(?))")
            params.append(json.dumps(keys or []))
        if keys is not None:  # a group of similar findings
            where.append("rf.key_id IN (SELECT value FROM json_each(?))")
            params.append(json.dumps(keys))
        if review == "untriaged":
            where.append("fr.status IS NULL AND rf.baseline_reason IS NULL")
        elif review == "test_code":
            where.append("rf.test_code IS NOT NULL")
        elif review == "suggested":
            where.append(_SUGGESTED)
            params.append(embeddings.DEFAULT_MODEL)
        elif review:
            where.append(f"({_REVIEW_STATUS}) = ?")
            params.append(review)
        clause = " AND ".join(where)
        base = (
            "FROM run_findings rf JOIN finding_keys fk ON fk.id = rf.key_id JOIN messages m ON m.id = rf.message_id "
            f"{_REVIEW_JOIN}"
        )
        total = self.conn.execute(f"SELECT COUNT(*) {base} WHERE {clause}", params).fetchone()[0]
        limit = max(1, min(limit, MAX_PAGE))
        offset = max(0, offset)
        columns = (
            f"SELECT rf.key_id, rf.severity, fk.tool, fk.rule, fk.path, fk.fingerprint, rf.line, rf.component, m.text, "
            "rf.is_new, rf.new_blocking, rf.blocking_class, rf.baseline_issue, rf.baseline_reason, rf.test_code, "
            "fr.status AS "
            "review_status_raw, "
            f"({_REVIEW_STATUS}) AS review_status, fr.description AS review_description, fr.resolved_at AS "
            "review_resolved_at, "
            f"fr.updated_at AS review_updated_at, fr.updated_by AS review_updated_by {base} WHERE {clause}"
        )
        if sort == "priority":
            # The run holds at most MAX_FINDINGS_PER_RUN findings, so sorting them here is bounded.
            everything = self.conn.execute(columns, params).fetchall()
            first_seen = self._first_seen(repo_id, [r["key_id"] for r in everything])
            scores = self.component_scores(run_id)
            everything.sort(key=lambda r: priority_key(r, scores, first_seen))
            rows = everything[offset : offset + limit]
        else:
            rows = self.conn.execute(
                f"{columns} ORDER BY CASE rf.severity WHEN 'ERROR' THEN 0 WHEN 'WARNING' THEN 1 ELSE 2 END, "
                f"fk.path, rf.line, fk.rule LIMIT ? OFFSET ?",
                (*params, limit, offset),
            ).fetchall()
            first_seen = self._first_seen(repo_id, [r["key_id"] for r in rows])
        facets = {
            "severities": [
                s
                for (s,) in self.conn.execute("SELECT DISTINCT severity FROM run_findings WHERE run_id = ?", (run_id,))
            ],
            "rules": [
                {"rule": name, "count": n}
                for name, n in self.conn.execute(
                    "SELECT fk.rule, COUNT(*) FROM run_findings rf JOIN finding_keys fk ON fk.id = rf.key_id "
                    "WHERE rf.run_id = ? GROUP BY fk.rule ORDER BY fk.rule",
                    (run_id,),
                )
            ],
            "components": [
                c
                for (c,) in self.conn.execute(
                    "SELECT DISTINCT component FROM run_findings WHERE run_id = ? ORDER BY component", (run_id,)
                )
            ],
        }
        facets["severities"].sort(key=SEVERITIES.index)
        untriaged = [r["key_id"] for r in rows if r["review_status_raw"] is None and r["baseline_reason"] is None]
        suggestions = self.suggestions(untriaged)
        return {
            "run": run_id,
            "total": total,
            "limit": limit,
            "offset": offset,
            "sort": sort,
            "facets": facets,
            "findings": [
                {
                    "severity": r["severity"],
                    "tool": r["tool"],
                    "rule": r["rule"],
                    "path": r["path"],
                    "line": r["line"],
                    "fingerprint": r["fingerprint"],
                    "component": r["component"],
                    "message": r["text"],
                    "first_seen": first_seen.get(r["key_id"]),
                    "new": bool(r["is_new"]),
                    "new_blocking": bool(r["new_blocking"]),
                    "blocking_class": None if r["blocking_class"] is None else bool(r["blocking_class"]),
                    "key": [r["tool"], r["rule"], r["path"], r["fingerprint"]],
                    "review": _review(r),
                    "test_code": _test_code(r["test_code"]),
                    "suggestion": suggestions.get(r["key_id"]),
                }
                for r in rows
            ],
        }

    def suggestions(self, key_ids: list[int], model: str = embeddings.DEFAULT_MODEL) -> dict[int, dict]:
        """The stored suggestion for each of these (untriaged) findings, with its neighbour's decision now
        and where that decision comes from: a review (who, when) or the baseline of a scheduled run (which
        run, commit and time). A suggestion whose neighbour no longer has a decision that suggests a status
        is left out. The neighbour's description is for reference only; a reviewer writes their own."""
        if not key_ids:
            return {}
        rows = self.conn.execute(
            _SUGGESTIONS,
            (model, json.dumps(key_ids)),
        ).fetchall()
        out = {}
        for key_id, score, computed, tool, rule, path, fp, *decided in rows:
            suggested = embeddings.decision_status(decided[0], decided[5])
            found = embeddings.decision(tuple(decided))
            if suggested is None or found is None:
                continue
            out[key_id] = {
                "status": suggested,
                "score": score,
                "computed_at": computed,
                "like": [tool, rule, path, fp],
                "source": found["source"],
                "description": found["description"],
                "by": found.get("by"),
                "at": found["at"],
                "issue": found.get("issue"),
                "run": found.get("run"),
                "commit": found.get("commit"),
            }
        return out

    def finding(self, repo_id: int, run_id: int, key: list[str]) -> dict | None:
        """One finding of a run, with its review."""
        found = self.findings(repo_id, run_id, rule=key[1], path=key[2], limit=MAX_PAGE)["findings"]
        for f in found:
            if f["key"] == key:
                return f
        return None

    def similar(
        self, repo_id: int, key: list[str], threshold: float, all_repos: bool, model: str = embeddings.DEFAULT_MODEL
    ) -> dict:
        """The findings most like one finding, from stored embeddings; the dashboard never calls Ollama."""
        row = self.conn.execute(
            "SELECT id FROM finding_keys WHERE repo_id = ? AND tool = ? AND rule = ? AND path = ? AND fingerprint = ?",
            (repo_id, *key),
        ).fetchone()
        found = (
            embeddings.similar(self.conn, row[0], model, threshold, embeddings.DEFAULT_LIMIT, all_repos)
            if row
            else None
        )
        return {"model": model, "threshold": threshold, "embedded": found is not None, "similar": found or []}

    def groups_version(self, repo_id: int, run_id: int, model: str = embeddings.DEFAULT_MODEL) -> tuple:
        """Changes whenever the groups of a run could: its findings' embeddings (a new or re-embedded
        finding) or the repository's reviews. Used with `version` as a cache key."""
        digest = hashlib.sha256()
        for key_id, text_sha in self.conn.execute(
            "SELECT e.key_id, e.text_sha256 FROM run_findings rf JOIN finding_embeddings e ON e.key_id = rf.key_id "
            "AND e.model = ? WHERE rf.run_id = ? ORDER BY e.key_id",
            (model, run_id),
        ):
            digest.update(f"{key_id}:{text_sha};".encode())
        reviews = self.conn.execute(
            "SELECT COALESCE(MAX(id), 0) FROM finding_review_events WHERE repo_name = (SELECT name FROM repos WHERE "
            "id = ?)",
            (repo_id,),
        ).fetchone()[0]
        return (digest.hexdigest(), reviews)

    def group_members(
        self, repo_id: int, run_id: int, threshold: float, model: str = embeddings.DEFAULT_MODEL
    ) -> tuple[list[list[int]], dict]:
        """The run's untriaged findings that have a vector, in groups of two or more alike, largest first."""
        rows = self.conn.execute(_UNTRIAGED_VECTORS, (repo_id, model, run_id)).fetchall()
        items = [(key_id, embeddings.unpack(blob, dims)) for key_id, blob, dims in rows[: embeddings.MAX_GROUPED]]
        groups = [g for g in embeddings.group(items, threshold) if len(g) > 1]
        groups.sort(key=len, reverse=True)  # stable: equal sizes keep their leaders' priority order
        counts = {
            "untriaged": self.conn.execute(_UNTRIAGED_COUNT, (repo_id, run_id)).fetchone()[0],
            "embedded": len(rows),
            "considered": len(items),
        }
        return groups, counts

    def groups(
        self,
        repo_id: int,
        run_id: int,
        threshold: float,
        model: str = embeddings.DEFAULT_MODEL,
        grouped: tuple[list[list[int]], dict] | None = None,
    ) -> dict:
        """Groups of similar untriaged findings in a run, to review together. Only stored vectors are used.
        `grouped` is a result of `group_members` worked out earlier (the server caches it)."""
        groups, counts = grouped or self.group_members(repo_id, run_id, threshold, model)
        shown = groups[:MAX_GROUPS]
        ids = [key_id for g in shown for key_id in g]
        details = {r["key_id"]: r for r in self.conn.execute(_GROUP_DETAILS, (run_id, json.dumps(ids)))}
        suggestions = self.suggestions(ids, model)
        out = []
        for members in shown:
            rows = [details[k] for k in members if k in details]
            leader = rows[0]
            suggested = Counter(suggestions[k]["status"] for k in members if k in suggestions)
            out.append(
                {
                    "key": [leader["tool"], leader["rule"], leader["path"], leader["fingerprint"]],
                    "size": len(members),
                    "severities": dict(Counter(r["severity"] for r in rows)),
                    "rules": [{"rule": rule, "count": n} for rule, n in Counter(r["rule"] for r in rows).most_common()],
                    "components": sorted({r["component"] for r in rows}),
                    "suggested": [{"status": s, "count": n} for s, n in suggested.most_common()],
                    "members": [
                        {
                            "key": [r["tool"], r["rule"], r["path"], r["fingerprint"]],
                            "severity": r["severity"],
                            "path": r["path"],
                            "line": r["line"],
                            "message": r["text"],
                        }
                        for r in rows[:MAX_GROUP_MEMBERS_SHOWN]
                    ],
                }
            )
        return {
            "run": run_id,
            "model": model,
            "threshold": threshold,
            **counts,
            "max_grouped": embeddings.MAX_GROUPED,
            "grouped": sum(len(g) for g in groups),
            "more_groups": len(groups) - len(shown),
            "groups": out,
        }

    def group_keys(
        self,
        repo_id: int,
        run_id: int,
        leader: list[str],
        threshold: float,
        model: str = embeddings.DEFAULT_MODEL,
        grouped: tuple[list[list[int]], dict] | None = None,
    ) -> list[int]:
        """The findings of the group this finding leads, now; empty when it no longer leads one."""
        row = self.conn.execute(
            "SELECT id FROM finding_keys WHERE repo_id = ? AND tool = ? AND rule = ? AND path = ? AND fingerprint = ?",
            (repo_id, *leader),
        ).fetchone()
        if row is None:
            return []
        groups, _ = grouped or self.group_members(repo_id, run_id, threshold, model)
        return next((g for g in groups if g[0] == row[0]), [])

    def embedding_status(self, repo_id: int, run_id: int, model: str = embeddings.DEFAULT_MODEL) -> dict:
        """How much of a run the stored embeddings and suggestions cover, for the Overview."""
        total = embedded = stale = 0
        last = None
        for tool, rule, path, component, text, stored, created in self.conn.execute(
            "SELECT fk.tool, fk.rule, fk.path, rf.component, m.text, e.text_sha256, e.created_at "
            "FROM run_findings rf JOIN finding_keys fk ON fk.id = rf.key_id JOIN messages m ON m.id = rf.message_id "
            "LEFT JOIN finding_embeddings e ON e.key_id = rf.key_id AND e.model = ? WHERE rf.run_id = ?",
            (model, run_id),
        ):
            total += 1
            if stored is None:
                continue
            embedded += 1
            last = max(last or created, created)
            if stored != embeddings.text_sha256(embeddings.finding_text(tool, rule, path, component, text)):
                stale += 1
        suggestions_at = self.conn.execute(
            "SELECT MAX(s.computed_at) FROM finding_suggestions s JOIN finding_keys fk ON fk.id = s.key_id "
            "WHERE fk.repo_id = ? AND s.model = ?",
            (repo_id, model),
        ).fetchone()[0]
        return {
            "model": model,
            "run": run_id,
            "findings": total,
            "embedded": embedded,
            "missing": total - embedded,
            "stale": stale,
            "embedded_at": last,
            "untriaged": self.conn.execute(_UNTRIAGED_COUNT, (repo_id, run_id)).fetchone()[0],
            "suggested": self.conn.execute(_SUGGESTED_COUNT, (repo_id, run_id, model)).fetchone()[0],
            "suggestions_at": suggestions_at,
        }

    def review_history(self, repo_name: str, key: list[str], limit: int = 200) -> list[dict]:
        rows = self.conn.execute(
            "SELECT who, at, from_status, to_status, description, run_id FROM finding_review_events "
            "WHERE repo_name = ? AND tool = ? AND rule = ? AND path = ? AND fingerprint = ? ORDER BY id DESC LIMIT ?",
            (repo_name, *key, limit),
        ).fetchall()
        return [dict(r) for r in rows]

    def review_counts(self, repo_id: int, run_id: int) -> dict:
        """Untriaged blocking findings in a run, and regressions in the repository."""
        untriaged = self.conn.execute(
            f"SELECT COUNT(*) FROM run_findings rf JOIN finding_keys fk ON fk.id = rf.key_id {_REVIEW_JOIN} "
            "WHERE rf.run_id = ? AND rf.blocking_class = 1 AND fr.status IS NULL AND rf.baseline_reason IS NULL",
            (repo_id, run_id),
        ).fetchone()[0]
        regressions = self.conn.execute(
            f"SELECT COUNT(*) FROM run_findings rf JOIN finding_keys fk ON fk.id = rf.key_id {_REVIEW_JOIN} "
            "WHERE rf.run_id = ? AND fr.status = 'regression'",
            (repo_id, run_id),
        ).fetchone()[0]
        test_code = self.conn.execute(
            "SELECT COUNT(*) FROM run_findings WHERE run_id = ? AND test_code IS NOT NULL", (run_id,)
        ).fetchone()[0]
        return {"run": run_id, "untriaged_blocking": untriaged, "regressions": regressions, "test_code": test_code}

    def _first_seen(self, repo_id: int, key_ids: list[int]) -> dict[int, str]:
        if not key_ids:
            return {}
        kinds = self._trend_kinds(repo_id)
        kind_marks = ", ".join("?" for _ in kinds)
        return dict(
            self.conn.execute(
                f"SELECT rf.key_id, MIN(r.scanned_at) FROM run_findings rf JOIN runs r ON r.id = rf.run_id "
                f"WHERE rf.key_id IN (SELECT value FROM json_each(?)) AND r.kind IN ({kind_marks}) GROUP BY rf.key_id",
                (json.dumps(key_ids), *kinds),
            ).fetchall()
        )

    def rule(self, repo_id: int, run_id: int, rule: str, limit: int = MAX_PAGE) -> dict:
        rows = self.conn.execute(
            "SELECT rf.severity, fk.path, rf.line, rf.component, m.text FROM run_findings rf "
            "JOIN finding_keys fk ON fk.id = rf.key_id JOIN messages m ON m.id = rf.message_id "
            "WHERE rf.run_id = ? AND fk.rule = ? ORDER BY fk.path, rf.line LIMIT ?",
            (run_id, rule, max(1, min(limit, MAX_PAGE))),
        ).fetchall()
        total = self.conn.execute(
            "SELECT COUNT(*) FROM run_findings rf JOIN finding_keys fk ON fk.id = rf.key_id WHERE rf.run_id = ? AND "
            "fk.rule = ?",
            (run_id, rule),
        ).fetchone()[0]
        return {
            "run": run_id,
            "rule": rule,
            "total": total,
            "messages": sorted({r["text"] for r in rows}),
            "locations": [
                {"severity": r["severity"], "path": r["path"], "line": r["line"], "component": r["component"]}
                for r in rows
            ],
        }

    # -------------------------------------------------------- lists behind a run's counts

    def stale(self, run_id: int, limit: int = MAX_PAGE, offset: int = 0) -> dict:
        total = self.conn.execute("SELECT COUNT(*) FROM run_stale WHERE run_id = ?", (run_id,)).fetchone()[0]
        rows = self.conn.execute(
            "SELECT tool, rule, path, fingerprint, issue, reason FROM run_stale WHERE run_id = ? "
            "ORDER BY path, rule, fingerprint LIMIT ? OFFSET ?",
            (run_id, max(1, min(limit, MAX_PAGE)), max(0, offset)),
        ).fetchall()
        return {"run": run_id, "total": total, "entries": [dict(r) for r in rows]}

    def files(self, run_id: int, kind: str | None = None, limit: int = MAX_PAGE, offset: int = 0) -> dict:
        where, params = "run_id = ?", [run_id]
        if kind:
            where += " AND kind = ?"
            params.append(kind)
        total = self.conn.execute(f"SELECT COUNT(*) FROM run_files WHERE {where}", params).fetchone()[0]
        counts = dict(
            self.conn.execute(
                "SELECT kind, COUNT(*) FROM run_files WHERE run_id = ? GROUP BY kind", (run_id,)
            ).fetchall()
        )
        rows = self.conn.execute(
            f"SELECT kind, path, detail FROM run_files WHERE {where} ORDER BY kind, path LIMIT ? OFFSET ?",
            (*params, max(1, min(limit, MAX_PAGE)), max(0, offset)),
        ).fetchall()
        files = []
        for r in rows:
            try:
                detail = json.loads(r["detail"])
            except ValueError:
                detail = {}
            files.append({"kind": r["kind"], "path": r["path"], "detail": detail if isinstance(detail, dict) else {}})
        return {"run": run_id, "total": total, "counts": {k: counts.get(k, 0) for k in FILE_KINDS}, "files": files}

    def suppressions(self, run_id: int, limit: int = MAX_PAGE, offset: int = 0) -> dict:
        total = self.conn.execute("SELECT COUNT(*) FROM run_suppressions WHERE run_id = ?", (run_id,)).fetchone()[0]
        rows = self.conn.execute(
            "SELECT path, line, rules, issue, valid, problem FROM run_suppressions WHERE run_id = ? "
            "ORDER BY valid, path, line LIMIT ? OFFSET ?",
            (run_id, max(1, min(limit, MAX_PAGE)), max(0, offset)),
        ).fetchall()
        return {
            "run": run_id,
            "total": total,
            "suppressions": [
                {
                    "path": r["path"],
                    "line": r["line"],
                    "rules": r["rules"].split(),
                    "issue": r["issue"],
                    "valid": bool(r["valid"]),
                    "problem": r["problem"],
                }
                for r in rows
            ],
        }

    def change_keys(self, repo_id: int, week: str, change: str) -> list[tuple[int, int, str]]:
        """(run the finding is shown from, key id, when) for every finding that appeared
        (change="new") or went away (change="fixed") in one week's trend runs.

        The counts match the weekly chart exactly: the same walk produces both.
        A fixed finding is shown as it was in the last run that had it.
        """
        runs = self._trend_runs(repo_id)
        picked: list[tuple[int, int, str]] = []  # (run the finding is shown from, key id, when)
        for index, run, current, previous in self._walk(runs):
            if _week(run["scanned_at"]).isoformat() != week:
                continue
            if change == "new" and index > 0:
                picked += [(run["id"], k, run["scanned_at"]) for k in sorted(current - previous)]
            elif change == "fixed":
                before = runs[-MAX_TREND_RUNS:][index - 1]["id"] if index > 0 else None
                picked += [(before, k, run["scanned_at"]) for k in sorted(previous - current)]
        return picked

    def changes(
        self,
        repo_id: int,
        week: str,
        change: str,
        limit: int = MAX_PAGE,
        offset: int = 0,
        picked: list[tuple[int, int, str]] | None = None,
    ) -> dict:
        """One page of `change_keys`, with each finding's details. `picked` may come from a cache."""
        if picked is None:
            picked = self.change_keys(repo_id, week, change)
        limit = max(1, min(limit, MAX_PAGE))
        offset = max(0, offset)
        items = self._change_items(picked[offset : offset + limit])
        return {
            "week": week,
            "change": change,
            "total": len(picked),
            "limit": limit,
            "offset": offset,
            "findings": items,
        }

    def _change_items(self, picked: list[tuple[int, int, str]]) -> list[dict]:
        """Each (run the finding is shown from, key id, when) with the finding's details from that run."""
        items = []
        for shown_run, key_id, when in picked:
            r = self.conn.execute(
                "SELECT rf.severity, fk.rule, fk.path, rf.line, rf.component, m.text FROM run_findings rf "
                "JOIN finding_keys fk ON fk.id = rf.key_id JOIN messages m ON m.id = rf.message_id "
                "WHERE rf.run_id = ? AND rf.key_id = ?",
                (shown_run, key_id),
            ).fetchone()
            if r:
                items.append(
                    {
                        "when": when,
                        "run": shown_run,
                        "severity": r["severity"],
                        "rule": r["rule"],
                        "path": r["path"],
                        "line": r["line"],
                        "component": r["component"],
                        "message": r["text"],
                    }
                )
        return items

    @staticmethod
    def _period_weeks(since: str, until: str, counts: dict[str, dict]) -> list[dict]:
        """Every week of the period, empty ones included. The caller bounds the period."""
        last = _week(until)
        week = _week(since)
        weeks = []
        while week <= last:
            weeks.append({"week": week.isoformat(), **counts.get(week.isoformat(), {"new": 0, "fixed": 0})})
            week += timedelta(weeks=1)
        return weeks

    def period(self, repo_id: int, since: str, until: str, limit: int = MAX_PAGE) -> dict:
        """What changed in the trend runs scanned from `since` to `until` (UTC timestamps, both included).

        The walk is the Overview's: a finding is new in the run where it
        appears and fixed in the run where it goes away. It starts from the
        repository's first walked trend run, so the time to fix of a finding
        fixed in the period counts from when it really appeared (within the
        MAX_TREND_RUNS bound). `start` is the newest trend run before the
        period, the state it began from; `end` is the newest trend run in it.
        At most `limit` new and fixed findings are listed, oldest change
        first, ERROR first within one run.

        `complete` is False when the walk does not reach back to the run
        before the period's first run: the changes early in the period are
        then missing, and the counts must not be presented as complete.
        """
        runs = [r for r in self._trend_runs(repo_id) if r["scanned_at"] <= until]
        walked = runs[-MAX_TREND_RUNS:]
        before = [r for r in runs if r["scanned_at"] < since]
        inside = [r for r in runs if r["scanned_at"] >= since]
        # The first run inside needs the run before it in the walk, unless it is the first run of all.
        complete = not inside or len(inside) + (1 if before else 0) <= len(walked)
        new: list[tuple[int, int, str]] = []
        fixed: list[tuple[int, int, str]] = []
        fix_days: Counter = Counter()
        open_since: dict[int, str] = {}
        for index, run, current, previous in self._walk(runs):
            when = run["scanned_at"]
            for key in sorted(current - previous):
                open_since[key] = when
                if index > 0 and when >= since:
                    new.append((run["id"], key, when))
            for key in sorted(previous - current):
                started = open_since.pop(key)
                if when >= since:
                    fixed.append((walked[index - 1]["id"], key, when))
                    fix_days[round((_parse(when) - _parse(started)).total_seconds() / 8640)] += 1
        weekly: dict[str, dict] = {}
        for change, picked in (("new", new), ("fixed", fixed)):
            for _, _, when in picked:
                week = weekly.setdefault(_week(when).isoformat(), {"new": 0, "fixed": 0})
                week[change] += 1

        def listed(picked: list[tuple[int, int, str]]) -> list[dict]:
            # The walk yields changes oldest first, so the cut keeps the oldest.
            items = self._change_items(picked[: max(0, limit)])
            items.sort(key=lambda i: (i["when"], SEVERITY_RANK.get(i["severity"], 3), i["path"], i["line"], i["rule"]))
            return items

        count = sum(fix_days.values())
        return {
            "since": since,
            "until": until,
            "runs": len(inside),
            "complete": complete,
            "start": _run_dict(before[-1]) if before else None,
            "end": _run_dict(inside[-1]) if inside else None,
            "new": {"total": len(new), "findings": listed(new)},
            "fixed": {"total": len(fixed), "findings": listed(fixed)},
            "weekly": self._period_weeks(since, until, weekly),
            "time_to_fix": {
                "fixed": count,
                "mean_days": round(sum(k * n for k, n in fix_days.items()) / count / 10, 1) if count else None,
                "median_days": round(_median(fix_days) / 10, 1) if count else None,
            },
        }

    # -------------------------------------------------------- runs

    def runs(self, repo_id: int, limit: int = 100, offset: int = 0) -> dict:
        limit = max(1, min(limit, MAX_PAGE))
        offset = max(0, offset)
        total = self.conn.execute("SELECT COUNT(*) FROM runs WHERE repo_id = ?", (repo_id,)).fetchone()[0]
        rows = self.conn.execute(
            f"SELECT {_RUN_COLUMNS} FROM runs WHERE repo_id = ? ORDER BY scanned_at DESC, id DESC LIMIT ? OFFSET ?",
            (repo_id, limit, offset),
        ).fetchall()
        return {"total": total, "limit": limit, "offset": offset, "runs": [_run_dict(r) for r in rows]}

    def deletions(self, repo_name: str, limit: int = 20) -> dict:
        """Runs of this repository deleted with `shoalscan history delete-run`, newest first."""
        count = self.conn.execute("SELECT COUNT(*) FROM deletions WHERE repo_name = ?", (repo_name,)).fetchone()[0]
        rows = self.conn.execute(
            "SELECT run_id, kind, ref, commit_sha, scanned_at, outcome, findings, deleted_at, deleted_by FROM "
            "deletions "
            "WHERE repo_name = ? ORDER BY deleted_at DESC, id DESC LIMIT ?",
            (repo_name, limit),
        ).fetchall()
        return {"count": count, "items": [dict(r) for r in rows]}

    def config_changes(self, limit: int = 50) -> list[dict]:
        rows = self.conn.execute(
            "SELECT who, changed_at, target, action, diff, policy_before, policy_after, policy_diff FROM "
            "config_changes ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["diff"] = json.loads(d["diff"])
            except ValueError:
                d["diff"] = {}
            out.append(d)
        return out

    def latest_run_of(self, name: str) -> dict | None:
        row = self.conn.execute(
            f"SELECT {_RUN_COLUMNS} FROM runs WHERE repo_id = (SELECT id FROM repos WHERE name = ?) ORDER BY scanned_at DESC, id DESC LIMIT 1",  # noqa: E501 - one literal, so Opengrep's raw-query rule still sees it
            (name,),
        ).fetchone()
        return _run_dict(row) if row else None

    def scan_triggers(self, limit: int = 20) -> list[dict]:
        """Scans started from the dashboard, the command line or the nightly job, newest first."""
        rows = self.conn.execute(
            "SELECT target, who, trigger, started_at, finished_at, outcome, run_id, detail FROM scan_triggers ORDER BY "
            "id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    def latest_scanners(self) -> dict:
        row = self.conn.execute(
            f"SELECT scanners FROM runs WHERE {_TREND} ORDER BY scanned_at DESC, id DESC LIMIT 1"
        ).fetchone()
        if not row:
            return {}
        try:
            value = json.loads(row[0])
        except ValueError:
            return {}
        return value if isinstance(value, dict) else {}
