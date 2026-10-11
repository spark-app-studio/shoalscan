"""The run history: a SQLite database that `shoalscan record` writes and the dashboard reads.

One database can hold several repositories. Each run stores its check
summary and its findings. A finding's identity is its tool, rule, path and
fingerprint, interned per repository in `finding_keys`, so the dashboard can
work out when a finding was first seen and when it was fixed by comparing
runs. Messages are stored once in `messages` and shared between runs.

The schema has a version (`PRAGMA user_version`) and a list of migrations.
Opening the database for writing applies the missing ones in order; a
database newer than this Shoalscan is refused.
"""

from __future__ import annotations

import getpass
import hashlib
import json
import os
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from shoalscan.check import SUMMARY_PREFIX
from shoalscan.errors import SetupError
from shoalscan.findings import Finding, load_findings

KINDS = ("pr", "scheduled")
SEVERITIES = ("ERROR", "WARNING", "INFO")

# Size caps. A run larger than these is refused rather than stored in part.
MAX_FINDINGS_FILE_BYTES = 64 * 1024 * 1024
MAX_CHECK_OUTPUT_BYTES = 16 * 1024 * 1024
MAX_FINDINGS_PER_RUN = 100_000
MAX_MESSAGE_CHARS = 4000
MAX_FIELD_CHARS = 1024
DEFAULT_MAX_RUNS = 2000
DEFAULT_KEEP_PR_DAYS = 90
MAX_FUTURE = timedelta(hours=24)

_REPO_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/@:+-]{0,199}$")
_REF = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_./@+-]{0,250}$")
_COMMIT = re.compile(r"^[0-9a-f]{7,64}$")

# Each entry upgrades the schema by one version. Never edit a shipped entry;
# add a new one.
MIGRATIONS: tuple[str, ...] = (
    # 1: repositories, runs, finding identities, messages and per-run findings.
    """
    CREATE TABLE repos (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL UNIQUE
    );
    CREATE TABLE runs (
        id INTEGER PRIMARY KEY,
        repo_id INTEGER NOT NULL REFERENCES repos(id) ON DELETE CASCADE,
        kind TEXT NOT NULL CHECK (kind IN ('pr', 'scheduled')),
        ref TEXT NOT NULL,
        commit_sha TEXT NOT NULL,
        scanned_at TEXT NOT NULL,
        recorded_at TEXT NOT NULL,
        result TEXT NOT NULL CHECK (result IN ('pass', 'fail')),
        findings INTEGER NOT NULL,
        error INTEGER NOT NULL,
        warning INTEGER NOT NULL,
        info INTEGER NOT NULL,
        nb_error INTEGER NOT NULL,
        nb_warning INTEGER NOT NULL,
        nb_info INTEGER NOT NULL,
        new INTEGER NOT NULL,
        new_blocking INTEGER NOT NULL,
        new_non_blocking_paths INTEGER NOT NULL,
        stale INTEGER NOT NULL,
        baseline_size INTEGER NOT NULL,
        baseline_additions INTEGER NOT NULL,
        suppressions INTEGER NOT NULL,
        suppressions_invalid INTEGER NOT NULL,
        suppressed_findings INTEGER NOT NULL,
        unscanned_skipped INTEGER NOT NULL,
        unscanned_errored INTEGER NOT NULL,
        changed_unscanned INTEGER NOT NULL,
        policy_ref TEXT,
        shoalscan_version TEXT,
        scanners TEXT NOT NULL,
        duration_seconds REAL,
        content_sha256 TEXT NOT NULL,
        UNIQUE (repo_id, commit_sha, kind)
    );
    CREATE TABLE finding_keys (
        id INTEGER PRIMARY KEY,
        repo_id INTEGER NOT NULL REFERENCES repos(id) ON DELETE CASCADE,
        tool TEXT NOT NULL,
        rule TEXT NOT NULL,
        path TEXT NOT NULL,
        fingerprint TEXT NOT NULL,
        UNIQUE (repo_id, tool, rule, path, fingerprint)
    );
    CREATE TABLE messages (
        id INTEGER PRIMARY KEY,
        sha256 TEXT NOT NULL UNIQUE,
        text TEXT NOT NULL
    );
    CREATE TABLE run_findings (
        run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
        key_id INTEGER NOT NULL REFERENCES finding_keys(id),
        severity TEXT NOT NULL CHECK (severity IN ('ERROR', 'WARNING', 'INFO')),
        line INTEGER NOT NULL,
        component TEXT NOT NULL,
        message_id INTEGER NOT NULL REFERENCES messages(id),
        PRIMARY KEY (run_id, key_id)
    ) WITHOUT ROWID;
    """,
    # 2: indexes for the dashboard's per-repository timelines and pruning.
    """
    CREATE INDEX runs_by_repo_time ON runs (repo_id, kind, scanned_at);
    CREATE INDEX run_findings_by_key ON run_findings (key_id);
    CREATE INDEX run_findings_by_message ON run_findings (message_id);
    """,
    # 3: the run's outcome and check exit status, which findings were new and
    # blocking, and the lists behind the counts. Older runs keep their counts;
    # their outcome follows from their pass or fail result, and their lists
    # are marked unknown.
    """
    ALTER TABLE runs ADD COLUMN outcome TEXT CHECK (outcome IN ('passed', 'blocked', 'scan_error'));
    UPDATE runs SET outcome = CASE result WHEN 'pass' THEN 'passed' ELSE 'blocked' END;
    ALTER TABLE runs ADD COLUMN check_exit INTEGER CHECK (check_exit IN (0, 1, 2));
    ALTER TABLE runs ADD COLUMN details_known INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE runs ADD COLUMN files_known INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE runs ADD COLUMN suppressions_known INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE runs ADD COLUMN partial_warnings INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE runs ADD COLUMN partial_warn_only INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE runs ADD COLUMN excluded_changed INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE run_findings ADD COLUMN is_new INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE run_findings ADD COLUMN new_blocking INTEGER NOT NULL DEFAULT 0;
    CREATE TABLE run_stale (
        run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
        tool TEXT NOT NULL,
        rule TEXT NOT NULL,
        path TEXT NOT NULL,
        fingerprint TEXT NOT NULL,
        issue TEXT NOT NULL,
        reason TEXT NOT NULL
    );
    CREATE INDEX run_stale_by_run ON run_stale (run_id);
    CREATE TABLE run_files (
        run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
        kind TEXT NOT NULL CHECK (kind IN ('skipped', 'error', 'changed_unscanned', 'partial_warning', 'partial_warn_only', 'excluded_changed')),
        path TEXT NOT NULL,
        detail TEXT NOT NULL
    );
    CREATE INDEX run_files_by_run ON run_files (run_id, kind);
    CREATE TABLE run_suppressions (
        run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
        path TEXT NOT NULL,
        line INTEGER NOT NULL,
        rules TEXT NOT NULL,
        issue TEXT,
        valid INTEGER NOT NULL,
        problem TEXT
    );
    CREATE INDEX run_suppressions_by_run ON run_suppressions (run_id);
    """,
    # 4: which findings the policy treats as blocking, baselined or not, as
    # the check decided it. NULL means unknown (runs recorded before this, or
    # without a check.json that lists them).
    """
    ALTER TABLE run_findings ADD COLUMN blocking_class INTEGER CHECK (blocking_class IN (0, 1));
    ALTER TABLE runs ADD COLUMN blocking_class_count INTEGER;
    CREATE INDEX run_findings_by_blocking ON run_findings (run_id, blocking_class);
    """,
    # 5: a record of every run deleted with `shoalscan history delete-run`.
    """
    CREATE TABLE deletions (
        id INTEGER PRIMARY KEY,
        repo_name TEXT NOT NULL,
        run_id INTEGER NOT NULL,
        kind TEXT NOT NULL,
        ref TEXT NOT NULL,
        commit_sha TEXT NOT NULL,
        scanned_at TEXT NOT NULL,
        outcome TEXT,
        findings INTEGER NOT NULL,
        deleted_at TEXT NOT NULL,
        deleted_by TEXT NOT NULL
    );
    CREATE INDEX deletions_by_repo ON deletions (repo_name, deleted_at);
    """,
    # 6: scans started from the dashboard, written by the scan worker.
    """
    CREATE TABLE scan_triggers (
        id INTEGER PRIMARY KEY,
        target TEXT NOT NULL,
        who TEXT NOT NULL,
        started_at TEXT NOT NULL,
        finished_at TEXT,
        outcome TEXT NOT NULL CHECK (outcome IN ('running', 'passed', 'blocked', 'scan_error', 'timeout', 'failed')),
        run_id INTEGER,
        detail TEXT
    );
    CREATE INDEX scan_triggers_by_target ON scan_triggers (target, started_at);
    """,
    # 7: what kind of request started a scan: a fresh scan, a rescan of the
    # branch, a rescan of one run's commit, the command line or the nightly job.
    """
    ALTER TABLE scan_triggers ADD COLUMN trigger TEXT NOT NULL DEFAULT 'scan';
    """,
    # 8: every change the Configuration page makes to scan_targets.toml.
    """
    CREATE TABLE config_changes (
        id INTEGER PRIMARY KEY,
        who TEXT NOT NULL,
        changed_at TEXT NOT NULL,
        target TEXT NOT NULL,
        action TEXT NOT NULL CHECK (action IN ('create', 'update', 'enable', 'disable', 'remove')),
        diff TEXT NOT NULL,
        policy_before TEXT,
        policy_after TEXT
    );
    """,
    # 9: the policy text's changes, as a bounded unified diff.
    """
    ALTER TABLE config_changes ADD COLUMN policy_diff TEXT;
    """,
    # 10: reviews of findings, kept per repository and finding identity (not per
    # run), an append-only history of review changes, and the baseline entry
    # behind each baselined finding of a run.
    """
    ALTER TABLE run_findings ADD COLUMN baseline_issue TEXT;
    ALTER TABLE run_findings ADD COLUMN baseline_reason TEXT;
    CREATE TABLE finding_reviews (
        id INTEGER PRIMARY KEY,
        repo_name TEXT NOT NULL,
        tool TEXT NOT NULL,
        rule TEXT NOT NULL,
        path TEXT NOT NULL,
        fingerprint TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('open', 'false_positive', 'accepted_risk', 'wont_fix', 'fixed', 'verified_fixed', 'regression')),
        description TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        updated_by TEXT NOT NULL,
        resolved_at TEXT,
        UNIQUE (repo_name, tool, rule, path, fingerprint)
    );
    CREATE TABLE finding_review_events (
        id INTEGER PRIMARY KEY,
        repo_name TEXT NOT NULL,
        tool TEXT NOT NULL,
        rule TEXT NOT NULL,
        path TEXT NOT NULL,
        fingerprint TEXT NOT NULL,
        who TEXT NOT NULL,
        at TEXT NOT NULL,
        from_status TEXT NOT NULL,
        to_status TEXT NOT NULL,
        description TEXT NOT NULL,
        run_id INTEGER
    );
    CREATE INDEX finding_review_events_by_finding ON finding_review_events (repo_name, tool, rule, path, fingerprint, id);
    """,
    # 11: the rules each run applied (stored once per distinct ruleset) and its excludes.
    """
    CREATE TABLE rulesets (
        id INTEGER PRIMARY KEY,
        sha256 TEXT NOT NULL UNIQUE,
        rules TEXT NOT NULL
    );
    ALTER TABLE runs ADD COLUMN ruleset_id INTEGER REFERENCES rulesets(id);
    ALTER TABLE runs ADD COLUMN excludes TEXT;
    """,
)
REVIEW_STATUSES = ("open", "false_positive", "accepted_risk", "wont_fix", "fixed", "verified_fixed", "regression")
USER_STATUSES = ("open", "false_positive", "accepted_risk", "wont_fix", "fixed")
RESOLVED_STATUSES = frozenset({"false_positive", "accepted_risk", "wont_fix", "fixed", "verified_fixed"})
MIN_DESCRIPTION, MAX_DESCRIPTION = 10, 2000
MAX_BULK_REVIEWS = 500
OUTCOMES = ("passed", "blocked", "scan_error")
MAX_LIST_ITEMS = 100_000  # stale entries, files or suppressions per run
MAX_DETAILS_BYTES = 64 * 1024 * 1024
SCHEMA_VERSION = len(MIGRATIONS)


def data_home() -> Path:
    xdg = os.environ.get("XDG_DATA_HOME", "")
    if xdg and os.path.isabs(xdg):
        return Path(xdg)
    return Path.home() / ".local" / "share"


def default_db_path() -> Path:
    """`$XDG_DATA_HOME/shoalscan/history.sqlite3`, or `~/.local/share/shoalscan/history.sqlite3`."""
    return data_home() / "shoalscan" / "history.sqlite3"


def migrate(conn: sqlite3.Connection) -> int:
    """Bring the schema up to SCHEMA_VERSION. Returns the version found before."""
    found = conn.execute("PRAGMA user_version").fetchone()[0]
    if found > SCHEMA_VERSION:
        raise SetupError(
            f"the history database has schema version {found}, newer than this Shoalscan understands "
            f"({SCHEMA_VERSION}); upgrade Shoalscan"
        )
    for version in range(found, SCHEMA_VERSION):
        # executescript commits first, so run each migration in its own explicit transaction.
        conn.executescript(f"BEGIN IMMEDIATE;\n{MIGRATIONS[version]}\nPRAGMA user_version = {version + 1};\nCOMMIT;")
    return found


def open_for_write(path: Path) -> sqlite3.Connection:
    """Open (creating if needed) the history database for `record`, in WAL mode, migrated."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    old = os.umask(0o077)
    try:
        conn = sqlite3.connect(str(path), timeout=30, isolation_level=None)
    finally:
        os.umask(old)
    try:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA busy_timeout = 30000")
        migrate(conn)
    except BaseException:
        conn.close()
        raise
    return conn


def open_read_only(path: Path) -> sqlite3.Connection:
    """Open the history database read-only. The dashboard never writes."""
    if not path.is_file():
        raise SetupError(f"history database not found: {path} (record a run with `shoalscan record` first)")
    conn = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True, timeout=10, check_same_thread=False)
    conn.execute("PRAGMA query_only = ON")
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    if version != SCHEMA_VERSION:
        conn.close()
        raise SetupError(
            f"the history database has schema version {version}; this Shoalscan needs {SCHEMA_VERSION}. "
            "Run `shoalscan record` with this version once to migrate it."
        )
    return conn


# ---------------------------------------------------------------- inputs


def parse_summary(text: str) -> dict:
    """Return the JSON of the last `SHOALSCAN_SUMMARY` line in `shoalscan check` output."""
    lines = [line for line in text.splitlines() if line.startswith(SUMMARY_PREFIX)]
    if not lines:
        raise SetupError("the check output has no SHOALSCAN_SUMMARY line (pass the output of `shoalscan check`)")
    try:
        doc = json.loads(lines[-1][len(SUMMARY_PREFIX) :])
    except json.JSONDecodeError as exc:
        raise SetupError(f"the SHOALSCAN_SUMMARY line is not valid JSON: {exc}") from None
    if not isinstance(doc, dict) or doc.get("result") not in ("pass", "fail"):
        raise SetupError("the SHOALSCAN_SUMMARY line has no pass or fail result")
    return doc


def _int(doc: dict, *path: str) -> int:
    value: object = doc
    for key in path:
        value = value.get(key) if isinstance(value, dict) else None
    if value is None:
        return 0
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise SetupError(f"the check summary has an invalid value for {'.'.join(path)}: {value!r}"[:200])
    return value


def parse_timestamp(value: str | None) -> str:
    """Normalise an ISO 8601 timestamp with a time zone to `YYYY-MM-DDTHH:MM:SSZ` (UTC)."""
    if value is None:
        moment = datetime.now(timezone.utc)
    else:
        try:
            moment = datetime.fromisoformat(value)
        except ValueError:
            raise SetupError(f"invalid timestamp {value!r}: use ISO 8601, for example 2026-10-10T02:00:00Z") from None
        if moment.tzinfo is None:
            raise SetupError(f"timestamp {value!r} has no time zone: add Z or an offset such as +02:00")
    return moment.astimezone(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _text(value: str, limit: int) -> str:
    # Control characters other than newline and tab are dropped; the dashboard
    # escapes everything anyway, this only keeps the stored data tidy.
    cleaned = "".join(c for c in value if c >= " " or c in "\n\t")
    return cleaned[:limit]


def _label(value: str, limit: int) -> str:
    """A rule id or component name: a single line of text. Control characters
    (tabs and newlines included) become U+FFFD, so they can never break a
    link or a page on the dashboard."""
    return "".join("\ufffd" if c < " " or c == "\x7f" else c for c in value)[:limit]


@dataclass(frozen=True)
class RunInfo:
    repo: str
    ref: str
    commit: str
    kind: str
    scanned_at: str

    def validate(self) -> None:
        if not _REPO_NAME.fullmatch(self.repo):
            raise SetupError(f"invalid repository name {self.repo!r}: letters, digits and . _ / @ : + - only, up to 200 characters")
        if not _REF.fullmatch(self.ref) or ".." in self.ref:
            raise SetupError(f"invalid ref {self.ref!r}")
        if not _COMMIT.fullmatch(self.commit):
            raise SetupError(f"invalid commit {self.commit!r}: a lowercase hexadecimal SHA")
        if self.kind not in KINDS:
            raise SetupError(f"invalid kind {self.kind!r}: pr or scheduled")
        try:
            valid_time = parse_timestamp(self.scanned_at) == self.scanned_at
        except SetupError:
            valid_time = False
        if not valid_time:
            raise SetupError(f"invalid scan time {self.scanned_at!r}: expected YYYY-MM-DDTHH:MM:SSZ in UTC")
        # A run stamped far ahead would sit at the end of every trend and
        # survive pruning, so a clock or input mistake is refused.
        if datetime.strptime(self.scanned_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc) > datetime.now(timezone.utc) + MAX_FUTURE:
            raise SetupError(f"scan time {self.scanned_at} is more than 24 hours in the future")


def read_details(path: Path, findings_path: Path, summary: dict, findings: list[Finding]) -> dict:
    """Read check.json and make sure it belongs to this findings file and check output."""
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise SetupError(f"check details not found: {path}: {exc.strerror}") from None
    if size > MAX_DETAILS_BYTES:
        raise SetupError(f"check details file is larger than {MAX_DETAILS_BYTES} bytes: {path}")
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SetupError(f"check details file is unreadable: {path}: {exc}") from None
    if not isinstance(doc, dict) or doc.get("format") != 1:
        raise SetupError(f"check details file has an unknown format: {path}")
    if doc.get("findings_sha256") != hashlib.sha256(findings_path.read_bytes()).hexdigest():
        raise SetupError(f"{path} was made from another findings file than {findings_path}; run `shoalscan check` again")
    if doc.get("summary") != summary:
        raise SetupError(f"{path} does not match the check output: they come from different checks")
    keys = {(f.tool, f.rule, f.path, f.fingerprint) for f in findings}
    if "blocking_class" not in doc:
        doc["blocking_class"] = None  # an older check: the blocking class is unknown
    for name in ("new", "new_blocking", "blocking_class"):
        items = doc.get(name)
        if name == "blocking_class" and items is None:
            continue
        if not isinstance(items, list) or not all(isinstance(k, list) and len(k) == 4 and tuple(k) in keys for k in items):
            raise SetupError(f"{path}: {name} lists findings that are not in {findings_path}")
    doc.setdefault("baselined", [])
    baselined = doc["baselined"]
    if not isinstance(baselined, list) or not all(
        isinstance(e, dict) and isinstance(e.get("key"), list) and len(e["key"]) == 4 and tuple(e["key"]) in keys
        and isinstance(e.get("issue"), str) and isinstance(e.get("reason"), str) for e in baselined
    ):
        raise SetupError(f"{path}: baselined lists entries that are not findings in {findings_path}")
    for name in ("stale", "baseline_additions", "changed_unscanned", "partial_warnings", "partial_warn_only", "excluded_changed"):
        items = doc.get(name)
        if not isinstance(items, list) or len(items) > MAX_LIST_ITEMS:
            raise SetupError(f"{path}: {name} is missing or too long")
    if not all(isinstance(e, dict) and all(isinstance(e.get(k), str) for k in ("tool", "rule", "path", "fingerprint", "issue", "reason")) for e in doc["stale"]):
        raise SetupError(f"{path}: a stale entry is malformed")
    for name in ("changed_unscanned", "partial_warnings", "partial_warn_only"):
        if not all(isinstance(e, dict) and isinstance(e.get("path"), str) for e in doc[name]):
            raise SetupError(f"{path}: an entry in {name} has no path")
    new = {tuple(k) for k in doc["new"]}
    new_blocking = {tuple(k) for k in doc["new_blocking"]}
    if len(new) != len(doc["new"]) or len(new_blocking) != len(doc["new_blocking"]):
        raise SetupError(f"{path}: a finding is listed twice")
    if not new_blocking <= new:
        raise SetupError(f"{path}: a new blocking finding is not in the new findings")
    for name in ("new", "new_blocking", "stale"):
        if len(doc[name]) != _int(summary, name):
            raise SetupError(f"{path} lists {len(doc[name])} {name.replace('_', ' ')} entries but the check summary counts {_int(summary, name)}")
    if doc["blocking_class"] is not None and not {tuple(k) for k in doc["new_blocking"]} <= {tuple(k) for k in doc["blocking_class"]}:
        raise SetupError(f"{path}: a new blocking finding is missing from blocking_class")
    if not all(isinstance(p, str) for p in doc["excluded_changed"]):
        raise SetupError(f"{path}: excluded_changed must list paths")
    return doc


def check_commit(meta: dict, commit: str, allow_no_git: bool) -> None:
    """The run must be recorded under the commit that was scanned.

    `scan` writes the HEAD commit into findings.json. Findings without one
    (a `--no-git` scan, or an older Shoalscan) are recorded only with
    `allow_no_git`, because nothing ties them to the commit given.
    """
    worktree = meta.get("worktree")
    scanned = worktree.get("commit") if isinstance(worktree, dict) else None
    if isinstance(scanned, str) and scanned:
        if scanned != commit:
            raise SetupError(f"the findings were scanned at commit {scanned}, not {commit}; pass the commit that was scanned")
        return
    if not allow_no_git:
        raise SetupError(
            "the findings do not say which commit was scanned (a --no-git scan, or an older Shoalscan); "
            "pass --allow-no-git to record them under --commit anyway"
        )


def read_inputs(findings_path: Path, check_output: str) -> tuple[list[Finding], dict, dict]:
    try:
        size = findings_path.stat().st_size
    except OSError as exc:
        raise SetupError(f"findings file not found: {findings_path}: {exc.strerror}") from None
    if size > MAX_FINDINGS_FILE_BYTES:
        raise SetupError(f"findings file is larger than {MAX_FINDINGS_FILE_BYTES} bytes: {findings_path}")
    if len(check_output.encode("utf-8")) > MAX_CHECK_OUTPUT_BYTES:
        raise SetupError("the check output is too large")
    findings, meta = load_findings(findings_path)
    if len(findings) > MAX_FINDINGS_PER_RUN:
        raise SetupError(f"the run has {len(findings)} findings; the history keeps at most {MAX_FINDINGS_PER_RUN} per run")
    summary = parse_summary(check_output)
    if _int(summary, "findings") != len(findings):
        raise SetupError(
            f"the check summary counts {_int(summary, 'findings')} findings but {findings_path} has {len(findings)}: "
            "they come from different runs"
        )
    return findings, meta, summary


# ---------------------------------------------------------------- recording


def _content_sha256(findings: list[Finding], summary: dict, meta: dict, info: RunInfo, details: dict | None, outcome: str, check_exit: int | None) -> str:
    doc = {
        "info": [info.ref, info.scanned_at],
        "outcome": [outcome, check_exit],
        "details": details,
        "suppression_list": meta.get("suppression_list"),
        "unscanned": meta.get("unscanned"),
        "summary": summary,
        "scanners": meta.get("scanners"),
        "findings": sorted([f.tool, f.rule, f.path, f.fingerprint, f.severity, f.line, f.component, f.message] for f in findings),
    }
    return hashlib.sha256(json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _row(info: RunInfo, summary: dict, meta: dict, content: str, outcome: str, check_exit: int | None, details: dict | None) -> dict:
    sev = summary.get("by_severity") or {}
    nb = summary.get("by_severity_non_blocking_paths") or {}
    duration = meta.get("duration_seconds")
    version = meta.get("shoalscan_version")
    policy_ref = summary.get("policy_ref")
    return {
        "kind": info.kind,
        "ref": info.ref,
        "commit_sha": info.commit,
        "scanned_at": info.scanned_at,
        "recorded_at": parse_timestamp(None),
        "result": "pass" if outcome == "passed" else "fail",
        "outcome": outcome,
        "check_exit": check_exit,
        "details_known": 1 if details is not None else 0,
        "files_known": 1 if isinstance(meta.get("unscanned"), dict) else 0,
        "suppressions_known": 1 if isinstance(meta.get("suppression_list"), list) else 0,
        "partial_warnings": _int(summary, "unscanned", "changed_partially_parsed_warnings"),
        "partial_warn_only": _int(summary, "unscanned", "changed_partially_parsed_warn_only"),
        "excluded_changed": _int(summary, "unscanned", "changed_but_excluded"),
        "findings": _int(summary, "findings"),
        "error": _int(sev, "ERROR"),
        "warning": _int(sev, "WARNING"),
        "info": _int(sev, "INFO"),
        "nb_error": _int(nb, "ERROR"),
        "nb_warning": _int(nb, "WARNING"),
        "nb_info": _int(nb, "INFO"),
        "new": _int(summary, "new"),
        "new_blocking": _int(summary, "new_blocking"),
        "new_non_blocking_paths": _int(summary, "new_in_non_blocking_paths"),
        "stale": _int(summary, "stale"),
        "baseline_size": _int(summary, "baseline_size"),
        "baseline_additions": _int(summary, "baseline_additions"),
        "suppressions": _int(summary, "suppressions", "total"),
        "suppressions_invalid": _int(summary, "suppressions", "invalid"),
        "suppressed_findings": _int(summary, "suppressions", "suppressed_findings"),
        "unscanned_skipped": _int(summary, "unscanned", "skipped"),
        "unscanned_errored": _int(summary, "unscanned", "errored"),
        "changed_unscanned": _int(summary, "unscanned", "changed_and_unscanned"),
        "policy_ref": _text(policy_ref, 256) if isinstance(policy_ref, str) else None,
        "shoalscan_version": _text(version, 64) if isinstance(version, str) else None,
        "scanners": json.dumps(meta.get("scanners") if isinstance(meta.get("scanners"), dict) else {}, sort_keys=True)[:20000],
        "duration_seconds": float(duration) if isinstance(duration, (int, float)) and not isinstance(duration, bool) else None,
        "content_sha256": content,
    }


def run_outcome(summary: dict, check_exit: int | None) -> str:
    """passed, blocked or scan_error, from the check's exit status and summary; they must agree."""
    if check_exit is not None and check_exit not in (0, 1, 2):
        raise SetupError(f"--check-exit must be 0, 1 or 2, not {check_exit}")
    if check_exit == 2:
        return "scan_error"
    result = summary.get("result")
    if result not in ("pass", "fail"):
        raise SetupError("the check summary has no pass or fail result")
    outcome = "passed" if result == "pass" else "blocked"
    if check_exit is not None and (check_exit == 0) != (outcome == "passed"):
        raise SetupError(f"the check exited with {check_exit} but its summary says {result}")
    return outcome


def _file_rows(unscanned: dict, details: dict | None) -> list[tuple[str, str, str]]:
    rows = []

    def add(kind: str, entry: dict) -> None:
        path = entry.get("path")
        if isinstance(path, str):
            detail = {k: v for k, v in entry.items() if k != "path" and k != "spans"}
            rows.append((kind, _text(path, MAX_FIELD_CHARS), json.dumps(detail, sort_keys=True)[:2000]))

    for entry in unscanned.get("skipped", []) if isinstance(unscanned.get("skipped"), list) else []:
        if isinstance(entry, dict):
            add("skipped", entry)
    for entry in unscanned.get("errors", []) if isinstance(unscanned.get("errors"), list) else []:
        if isinstance(entry, dict):
            add("error", entry)
    if details:
        for kind, name in (("changed_unscanned", "changed_unscanned"), ("partial_warning", "partial_warnings"), ("partial_warn_only", "partial_warn_only")):
            for entry in details[name]:
                add(kind, entry)
        for path in details["excluded_changed"]:
            add("excluded_changed", {"path": path})
    return rows


def _suppression_row(run_id: int, item: object) -> tuple:
    if not isinstance(item, dict) or not isinstance(item.get("path"), str):
        raise SetupError("findings.json has a malformed suppression_list entry")
    rules = item.get("rules") if isinstance(item.get("rules"), list) else []
    line = item.get("line") if isinstance(item.get("line"), int) and not isinstance(item.get("line"), bool) else 0
    issue = item.get("issue") if isinstance(item.get("issue"), str) else None
    problem = item.get("problem") if isinstance(item.get("problem"), str) else None
    return (
        run_id,
        _text(item["path"], MAX_FIELD_CHARS),
        max(line, 0),
        _text(" ".join(r for r in rules if isinstance(r, str)), MAX_FIELD_CHARS),
        _text(issue, 500) if issue else None,
        1 if item.get("valid") is True else 0,
        _text(problem, 300) if problem else None,
    )


@dataclass(frozen=True)
class RecordResult:
    run_id: int
    status: str  # "recorded", "replaced" or "unchanged"
    pruned: int


def record_run(
    conn: sqlite3.Connection,
    info: RunInfo,
    findings: list[Finding],
    meta: dict,
    summary: dict,
    details: dict | None = None,
    check_exit: int | None = None,
    review_transitions: bool = True,
    max_runs: int = DEFAULT_MAX_RUNS,
    keep_pr_days: int = DEFAULT_KEEP_PR_DAYS,
) -> RecordResult:
    """Store one run. Recording the same (repo, commit, kind) again replaces it,
    or does nothing when the content is the same, so a retried job is harmless.

    `check_exit` is the exit status of `shoalscan check`: 0 passed, 1 blocked,
    2 a scan error (broken setup or failed scan). A scan error is stored with
    no findings and never replaces a run that was recorded with results.
    `details` is check.json from the same check (see `read_details`).
    """
    info.validate()
    outcome = run_outcome(summary, check_exit)
    if outcome == "scan_error" and (findings or details):
        raise SetupError("a scan-error run is recorded without findings or check details")
    for f in findings:
        if f.severity not in SEVERITIES:
            raise SetupError(f"finding has an unknown severity: {f.severity!r}"[:200])
    suppressions = meta.get("suppression_list") if isinstance(meta.get("suppression_list"), list) else []
    unscanned = meta.get("unscanned") if isinstance(meta.get("unscanned"), dict) else {}
    files = _file_rows(unscanned, details)
    if len(suppressions) > MAX_LIST_ITEMS or len(files) > MAX_LIST_ITEMS:
        raise SetupError(f"the run lists more than {MAX_LIST_ITEMS} suppressions or files")
    new = {tuple(k) for k in details["new"]} if details else set()
    new_blocking = {tuple(k) for k in details["new_blocking"]} if details else set()
    blocking_class = {tuple(k) for k in details["blocking_class"]} if details and details.get("blocking_class") is not None else None
    baselined = {tuple(e["key"]): e for e in details.get("baselined", [])} if details else {}
    content = _content_sha256(findings, summary, meta, info, details, outcome, check_exit)
    row = _row(info, summary, meta, content, outcome, check_exit, details)
    row["blocking_class_count"] = len(blocking_class) if blocking_class is not None else None
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute("INSERT OR IGNORE INTO repos (name) VALUES (?)", (info.repo,))
        repo_id = conn.execute("SELECT id FROM repos WHERE name = ?", (info.repo,)).fetchone()[0]
        existing = conn.execute(
            "SELECT id, content_sha256, outcome FROM runs WHERE repo_id = ? AND commit_sha = ? AND kind = ?",
            (repo_id, info.commit, info.kind),
        ).fetchone()
        if existing and existing[1] == content:
            conn.execute("COMMIT")
            return RecordResult(existing[0], "unchanged", 0)
        if existing and outcome == "scan_error" and existing[2] != "scan_error":
            raise SetupError(
                f"run {existing[0]} already holds results for this commit and kind; a scan error does not replace it"
            )
        if existing:
            conn.execute("DELETE FROM runs WHERE id = ?", (existing[0],))
        columns = ["repo_id", *row]
        cur = conn.execute(
            f"INSERT INTO runs ({', '.join(columns)}) VALUES ({', '.join('?' for _ in columns)})",
            (repo_id, *row.values()),
        )
        run_id = cur.lastrowid
        seen: set[tuple[str, str, str, str]] = set()
        for f in findings:
            key = (_label(f.tool, 64), _label(f.rule, MAX_FIELD_CHARS), _text(f.path, MAX_FIELD_CHARS), _text(f.fingerprint, 128))
            if key in seen:
                raise SetupError(f"the findings file lists one finding twice: {key[1]} in {key[2]}"[:300])
            seen.add(key)
            conn.execute(
                "INSERT OR IGNORE INTO finding_keys (repo_id, tool, rule, path, fingerprint) VALUES (?, ?, ?, ?, ?)",
                (repo_id, *key),
            )
            key_id = conn.execute(
                "SELECT id FROM finding_keys WHERE repo_id = ? AND tool = ? AND rule = ? AND path = ? AND fingerprint = ?",
                (repo_id, *key),
            ).fetchone()[0]
            message = _text(f.message, MAX_MESSAGE_CHARS)
            digest = hashlib.sha256(message.encode("utf-8")).hexdigest()
            conn.execute("INSERT OR IGNORE INTO messages (sha256, text) VALUES (?, ?)", (digest, message))
            message_id = conn.execute("SELECT id FROM messages WHERE sha256 = ?", (digest,)).fetchone()[0]
            line = f.line if isinstance(f.line, int) and not isinstance(f.line, bool) and f.line >= 0 else 0
            raw_key = (f.tool, f.rule, f.path, f.fingerprint)
            conn.execute(
                "INSERT INTO run_findings (run_id, key_id, severity, line, component, message_id, is_new, new_blocking, blocking_class, "
                "baseline_issue, baseline_reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (run_id, key_id, f.severity, line, _label(f.component, 200), message_id,
                 int(raw_key in new), int(raw_key in new_blocking), None if blocking_class is None else int(raw_key in blocking_class),
                 _text(baselined[raw_key]["issue"], 500) if raw_key in baselined else None,
                 _text(baselined[raw_key]["reason"], 2000) if raw_key in baselined else None),
            )
        if details:
            conn.executemany(
                "INSERT INTO run_stale (run_id, tool, rule, path, fingerprint, issue, reason) VALUES (?, ?, ?, ?, ?, ?, ?)",
                [(run_id, _text(e["tool"], 64), _text(e["rule"], MAX_FIELD_CHARS), _text(e["path"], MAX_FIELD_CHARS),
                  _text(e["fingerprint"], 128), _text(e["issue"], 500), _text(e["reason"], 2000)) for e in details["stale"]],
            )
        conn.executemany(
            "INSERT INTO run_files (run_id, kind, path, detail) VALUES (?, ?, ?, ?)",
            [(run_id, kind, path, detail) for kind, path, detail in files],
        )
        conn.executemany(
            "INSERT INTO run_suppressions (run_id, path, line, rules, issue, valid, problem) VALUES (?, ?, ?, ?, ?, ?, ?)",
            [_suppression_row(run_id, item) for item in suppressions],
        )
        rule_ids = meta.get("rule_ids")
        if isinstance(rule_ids, list) and all(isinstance(r, str) for r in rule_ids):
            text = json.dumps(sorted(set(rule_ids)))
            digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
            conn.execute("INSERT OR IGNORE INTO rulesets (sha256, rules) VALUES (?, ?)", (digest, text))
            conn.execute("UPDATE runs SET ruleset_id = (SELECT id FROM rulesets WHERE sha256 = ?) WHERE id = ?", (digest, run_id))
        if isinstance(meta.get("excludes"), list):
            conn.execute("UPDATE runs SET excludes = ? WHERE id = ?", (json.dumps(meta["excludes"])[:20000], run_id))
        # Only a scan of the branch's tip moves reviews; a rescan of an earlier commit never does.
        if review_transitions and info.kind == "scheduled" and outcome != "scan_error":
            apply_review_transitions(conn, info, run_id, {k for k in seen}, meta)
        pruned = prune(conn, repo_id, max_runs, keep_pr_days)
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    return RecordResult(run_id, "replaced" if existing else "recorded", pruned)


def prune(conn: sqlite3.Connection, repo_id: int, max_runs: int, keep_pr_days: int) -> int:
    """Drop old runs of one repository: pull-request runs older than `keep_pr_days`
    before the newest run, then all but the newest `max_runs` runs. Finding
    identities and messages that no run uses any more go too."""
    if max_runs < 1 or keep_pr_days < 0:
        raise SetupError("--max-runs must be at least 1 and --keep-pr-days at least 0")
    newest = conn.execute("SELECT MAX(scanned_at) FROM runs WHERE repo_id = ?", (repo_id,)).fetchone()[0]
    if newest is None:
        return 0
    cutoff = (datetime.strptime(newest, "%Y-%m-%dT%H:%M:%SZ") - timedelta(days=keep_pr_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    before = conn.total_changes
    conn.execute("DELETE FROM runs WHERE repo_id = ? AND kind = 'pr' AND scanned_at < ?", (repo_id, cutoff))
    conn.execute(
        "DELETE FROM runs WHERE repo_id = ? AND id NOT IN "
        "(SELECT id FROM runs WHERE repo_id = ? ORDER BY scanned_at DESC, id DESC LIMIT ?)",
        (repo_id, repo_id, max_runs),
    )
    pruned = conn.total_changes - before
    if pruned:
        _drop_orphans(conn, repo_id)
    return pruned


def _drop_orphans(conn: sqlite3.Connection, repo_id: int) -> None:
    """Remove finding identities and messages that no run uses any more."""
    conn.execute(
        "DELETE FROM finding_keys WHERE repo_id = ? AND NOT EXISTS "
        "(SELECT 1 FROM run_findings WHERE run_findings.key_id = finding_keys.id)",
        (repo_id,),
    )
    conn.execute("DELETE FROM messages WHERE NOT EXISTS (SELECT 1 FROM run_findings WHERE run_findings.message_id = messages.id)")


def _who() -> str:
    """The local account that deleted a run, for the deletions record."""
    try:
        name = getpass.getuser()
    except Exception:  # noqa: BLE001 - no account name is not a reason to refuse
        name = ""
    return _label(name, 100) or "unknown"


def start_trigger(conn: sqlite3.Connection, target: str, who: str, started_at: str, trigger: str = "scan") -> int:
    """Audit a scan started from the dashboard, the command line or the nightly job."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        cur = conn.execute(
            "INSERT INTO scan_triggers (target, who, started_at, outcome, trigger) VALUES (?, ?, ?, 'running', ?)",
            (_label(target, 200), _label(who, 100), started_at, _label(trigger, 40)),
        )
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    return cur.lastrowid


def finish_trigger(conn: sqlite3.Connection, trigger_id: int, outcome: str, run_id: int | None, detail: str | None, finished_at: str) -> None:
    conn.execute(
        "UPDATE scan_triggers SET outcome = ?, run_id = ?, detail = ?, finished_at = ? WHERE id = ?",
        (outcome, run_id, _text(detail, 300) if detail else None, finished_at, trigger_id),
    )


MAX_POLICY_DIFF = 8000


def append_config_change(db: Path, who: str, target: str, action: str, diff: dict, policy_before: str | None,
                         policy_after: str | None, policy_diff: str | None = None) -> int:
    """Audit a change to the scan targets. This is the dashboard's only write to the
    database: one INSERT on a short-lived connection; everything it shows is read-only."""
    conn = open_for_write(db)
    try:
        cur = conn.execute(
            "INSERT INTO config_changes (who, changed_at, target, action, diff, policy_before, policy_after, policy_diff) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (_label(who, 100), parse_timestamp(None), _label(target, 200), action, json.dumps(diff, sort_keys=True)[:20000], policy_before,
             policy_after, policy_diff[:MAX_POLICY_DIFF] if policy_diff else None),
        )
        return cur.lastrowid
    finally:
        conn.close()


# ---------------------------------------------------------------- reviews


def clean_description(value: object) -> str:
    """A review description: plain text of 10 to 2000 characters; control characters other
    than newlines and tabs are replaced, never silently dropped."""
    if not isinstance(value, str):
        raise SetupError(f"a description of {MIN_DESCRIPTION} to {MAX_DESCRIPTION} characters is required")
    text = "".join("\ufffd" if (c < " " and c not in "\n\t") or c == "\x7f" else c for c in value).strip()
    # Only visible characters count toward the minimum: not spaces, not replaced control characters.
    visible = sum(1 for c in text if not c.isspace() and c != "\ufffd")
    if visible < MIN_DESCRIPTION or len(text) > MAX_DESCRIPTION:
        raise SetupError(f"a description of {MIN_DESCRIPTION} to {MAX_DESCRIPTION} characters is required")
    return text


def _review_row(conn: sqlite3.Connection, repo: str, key: tuple) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT status, resolved_at FROM finding_reviews WHERE repo_name = ? AND tool = ? AND rule = ? AND path = ? AND fingerprint = ?",
        (repo, *key),
    ).fetchone()


def _change_review(conn: sqlite3.Connection, repo: str, key: tuple, status: str, description: str, who: str,
                   run_id: int | None, at: str) -> None:
    current = _review_row(conn, repo, key)
    before = current[0] if current else "open"
    resolved_at = at if status in RESOLVED_STATUSES else None
    if resolved_at and current and current[0] in RESOLVED_STATUSES and current[1]:
        resolved_at = current[1]  # moving between resolved statuses keeps the first resolution time
    conn.execute(
        "INSERT INTO finding_reviews (repo_name, tool, rule, path, fingerprint, status, description, updated_at, updated_by, resolved_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (repo_name, tool, rule, path, fingerprint) DO UPDATE SET "
        "status = excluded.status, description = excluded.description, updated_at = excluded.updated_at, "
        "updated_by = excluded.updated_by, resolved_at = excluded.resolved_at",
        (repo, *key, status, description, at, who, resolved_at),
    )
    conn.execute(
        "INSERT INTO finding_review_events (repo_name, tool, rule, path, fingerprint, who, at, from_status, to_status, description, run_id) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (repo, *key, who, at, before, status, description, run_id),
    )


def set_reviews(db: Path, repo: str, keys: list, status: str, description: object, who: str, run_id: int | None = None) -> int:
    """A person's review of one or more findings. Only open, false_positive,
    accepted_risk, wont_fix and fixed can be set by hand; verified_fixed and
    regression come only from scheduled runs. Every change needs a description.
    This writes on its own short-lived connection."""
    if status not in USER_STATUSES:
        raise SetupError(f"status must be one of {', '.join(USER_STATUSES)}; verified_fixed and regression are set by scheduled runs")
    text = clean_description(description)
    if not isinstance(keys, list) or not 1 <= len(keys) <= MAX_BULK_REVIEWS:
        raise SetupError(f"review 1 to {MAX_BULK_REVIEWS} findings at a time")
    identities = []
    for key in keys:
        if not (isinstance(key, list) and len(key) == 4 and all(isinstance(p, str) and 0 < len(p) <= MAX_FIELD_CHARS for p in key)):
            raise SetupError("a finding key is [tool, rule, path, fingerprint]")
        identities.append(tuple(key))
    if len(set(identities)) != len(identities):
        raise SetupError("a finding is listed twice")
    conn = open_for_write(db)
    try:
        conn.execute("BEGIN IMMEDIATE")
        try:
            repo_row = conn.execute("SELECT id FROM repos WHERE name = ?", (repo,)).fetchone()
            if repo_row is None:
                raise LookupError(repo)
            for key in identities:
                known = conn.execute(
                    "SELECT 1 FROM finding_keys WHERE repo_id = ? AND tool = ? AND rule = ? AND path = ? AND fingerprint = ?",
                    (repo_row[0], *key),
                ).fetchone()
                if known is None:
                    raise LookupError(key)
            at = parse_timestamp(None)
            for key in identities:
                _change_review(conn, repo, key, status, text, _label(who, 100), run_id, at)
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
    finally:
        conn.close()
    return len(identities)


def _covered(meta: dict, tool: str, rule: str, path: str, line: int | None) -> bool:
    """Did this run look at this finding's file with this finding's rule? Only then
    is the finding's absence evidence that it is fixed."""
    from shoalscan.excludes import ExcludeMatcher

    unscanned = meta.get("unscanned")
    if not isinstance(unscanned, dict):
        return False  # nothing says which files were fully scanned
    if tool != "shoalscan":
        # A scanner's finding is evidence only if that scanner ran this time
        # (scanners can be turned off) and, for scanners that list their
        # rules, with this rule. Shoalscan's own lint always runs.
        scanners = meta.get("scanners")
        if not isinstance(scanners, dict) or tool not in scanners:
            return False
    if tool in ("opengrep", "gitleaks"):
        rules = meta.get("rule_ids")
        if not isinstance(rules, list) or rule not in rules:
            return False
    excludes = meta.get("excludes")
    if isinstance(excludes, list):
        try:
            if ExcludeMatcher([e for e in excludes if isinstance(e, str)]).excluded(path):
                return False
        except SetupError:
            return False
    for entry in unscanned.get("skipped", []) or []:
        if isinstance(entry, dict) and entry.get("path") == path:
            return False
    for entry in unscanned.get("errors", []) or []:
        if not isinstance(entry, dict) or entry.get("path") != path:
            continue
        if entry.get("type") != "PartialParsing" or line is None:
            return False
        for span in entry.get("spans", []) or []:
            if isinstance(span, list) and len(span) == 2 and span[0] <= line <= span[1]:
                return False
    return True


def apply_review_transitions(conn: sqlite3.Connection, info: RunInfo, run_id: int, present: set, meta: dict | None = None) -> None:
    """What a scheduled run of the branch's tip tells about reviewed findings.

    A finding claimed fixed is verified only when this run fully scanned its
    file with its rule and did not find it; a skipped or errored file, a parse
    gap over its line, an exclude or a rule that no longer runs leaves it as it
    is. A fixed finding found again is a regression. Only the newest scheduled
    run of a repository moves reviews, so recording an older run later changes nothing."""
    meta = meta or {}
    newer = conn.execute(
        "SELECT 1 FROM runs JOIN repos ON repos.id = runs.repo_id WHERE repos.name = ? AND runs.kind = 'scheduled' "
        "AND runs.outcome != 'scan_error' AND runs.id != ? AND runs.scanned_at > ? LIMIT 1",
        (info.repo, run_id, info.scanned_at),
    ).fetchone()
    if newer:
        return
    where = f"the scheduled run of {info.scanned_at} at {info.commit[:12]}"
    at = parse_timestamp(None)
    rows = conn.execute(
        "SELECT tool, rule, path, fingerprint, status FROM finding_reviews WHERE repo_name = ? AND status IN ('fixed', 'verified_fixed')",
        (info.repo,),
    ).fetchall()
    for tool, rule, path, fingerprint, status in rows:
        key = (tool, rule, path, fingerprint)
        if key in present:
            _change_review(conn, info.repo, key, "regression", f"Found again in {where}.", "shoalscan", run_id, at)
        elif status == "fixed":
            last_line = conn.execute(
                "SELECT rf.line FROM run_findings rf JOIN finding_keys fk ON fk.id = rf.key_id JOIN runs r ON r.id = rf.run_id "
                "JOIN repos rp ON rp.id = r.repo_id WHERE rp.name = ? AND fk.tool = ? AND fk.rule = ? AND fk.path = ? AND fk.fingerprint = ? "
                "ORDER BY r.scanned_at DESC LIMIT 1",
                (info.repo, *key),
            ).fetchone()
            if _covered(meta, tool, rule, path, last_line[0] if last_line else None):
                _change_review(conn, info.repo, key, "verified_fixed", f"No longer found in {where}.", "shoalscan", run_id, at)


def delete_config_change(db: Path, change_id: int) -> None:
    """Take back an audit row whose change could not be written."""
    conn = open_for_write(db)
    try:
        conn.execute("DELETE FROM config_changes WHERE id = ?", (change_id,))
    finally:
        conn.close()


def run_commit(conn: sqlite3.Connection, repo: str, run_id: int) -> tuple[str, str, str, str] | None:
    """The commit, ref, kind and scan time of a run of this repository; None for a run of another repository."""
    row = conn.execute(
        "SELECT runs.commit_sha, runs.ref, runs.kind, runs.scanned_at FROM runs JOIN repos ON repos.id = runs.repo_id "
        "WHERE repos.name = ? AND runs.id = ?",
        (repo, run_id),
    ).fetchone()
    return (row[0], row[1], row[2], row[3]) if row else None


def list_runs(conn: sqlite3.Connection, repo: str) -> list[dict]:
    """The runs of one repository, newest first."""
    rows = conn.execute(
        "SELECT runs.id, scanned_at, kind, ref, commit_sha, outcome, findings FROM runs JOIN repos ON repos.id = runs.repo_id "
        "WHERE repos.name = ? ORDER BY scanned_at DESC, runs.id DESC",
        (repo,),
    ).fetchall()
    keys = ("id", "scanned_at", "kind", "ref", "commit", "outcome", "findings")
    return [dict(zip(keys, row)) for row in rows]


def delete_run(conn: sqlite3.Connection, repo: str, run_id: int) -> dict:
    """Delete one run with everything recorded for it, and return what it was.

    First seen, fixed, ages and times to fix are worked out from the runs
    that remain every time they are shown, so they stay consistent. Finding
    identities and messages that only this run used are removed; so is the
    repository when this was its last run.
    """
    conn.execute("BEGIN IMMEDIATE")
    try:
        row = conn.execute(
            "SELECT runs.id, runs.repo_id, scanned_at, kind, ref, commit_sha, outcome, findings FROM runs "
            "JOIN repos ON repos.id = runs.repo_id WHERE repos.name = ? AND runs.id = ?",
            (repo, run_id),
        ).fetchone()
        if row is None:
            raise SetupError(f"{repo} has no run {run_id} (`shoalscan history list-runs --repo-name {repo}` lists them)")
        repo_id = row[1]
        conn.execute(
            "INSERT INTO deletions (repo_name, run_id, kind, ref, commit_sha, scanned_at, outcome, findings, deleted_at, deleted_by) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (repo, run_id, row[3], row[4], row[5], row[2], row[6], row[7], parse_timestamp(None), _who()),
        )
        conn.execute("DELETE FROM runs WHERE id = ?", (run_id,))
        _drop_orphans(conn, repo_id)
        left = conn.execute("SELECT COUNT(*) FROM runs WHERE repo_id = ?", (repo_id,)).fetchone()[0]
        if left == 0:
            conn.execute("DELETE FROM repos WHERE id = ?", (repo_id,))
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    keys = ("id", "repo_id", "scanned_at", "kind", "ref", "commit", "outcome", "findings")
    return {**dict(zip(keys, row)), "runs_left": left}
