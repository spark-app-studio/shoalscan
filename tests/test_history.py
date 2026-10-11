import contextlib
import io
import json
import os
import sqlite3
import stat
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

import helpers  # noqa: F401
from history_fixtures import MALICIOUS, check_output, checked, entry, finding, record, sample_history, summary, write_findings

from shoalscan import history
from shoalscan.cli import main
from shoalscan.baseline import Entry
from shoalscan.dashboard.data import Data
from shoalscan.errors import SetupError


class HistoryTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.db = self.tmp / "data" / "history.sqlite3"
        self.conn = history.open_for_write(self.db)

    def tearDown(self):
        self.conn.close()
        self._tmp.cleanup()

    def count(self, table: str) -> int:
        return self.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


class RecordTests(HistoryTestCase):
    def test_new_database_is_private_versioned_and_in_wal_mode(self):
        self.assertEqual(stat.S_IMODE(os.stat(self.db).st_mode) & 0o077, 0)
        self.assertEqual(self.conn.execute("PRAGMA user_version").fetchone()[0], history.SCHEMA_VERSION)
        self.assertEqual(self.conn.execute("PRAGMA journal_mode").fetchone()[0], "wal")

    def test_recording_the_same_run_twice_changes_nothing(self):
        items = [finding("r1", "a.py", "f1:0"), finding("r2", "b.py", "f2:0", "INFO")]
        first = record(self.conn, self.tmp, "acme/app", "a" * 40, 1, items)
        second = record(self.conn, self.tmp, "acme/app", "a" * 40, 1, items)
        self.assertEqual((first.status, second.status), ("recorded", "unchanged"))
        self.assertEqual(first.run_id, second.run_id)
        self.assertEqual((self.count("runs"), self.count("run_findings"), self.count("finding_keys")), (1, 2, 2))

    def test_recording_the_same_commit_and_kind_with_new_content_replaces_it(self):
        record(self.conn, self.tmp, "acme/app", "a" * 40, 1, [finding("r1", "a.py", "f1:0")])
        again = record(self.conn, self.tmp, "acme/app", "a" * 40, 1, [finding("r1", "a.py", "f1:0"), finding("r3", "c.py", "f3:0")])
        self.assertEqual(again.status, "replaced")
        self.assertEqual((self.count("runs"), self.count("run_findings")), (1, 2))
        # A different kind for the same commit is a separate run.
        record(self.conn, self.tmp, "acme/app", "a" * 40, 1, [finding("r1", "a.py", "f1:0")], kind="pr")
        self.assertEqual(self.count("runs"), 2)

    def test_control_characters_never_reach_rule_ids_or_components(self):
        record(self.conn, self.tmp, "acme/app", "a" * 40, 1, [finding("rule\twith\ntab", "a.py", "f1:0", component="api\x7f\x00")])
        rule, component = self.conn.execute(
            "SELECT fk.rule, rf.component FROM run_findings rf JOIN finding_keys fk ON fk.id = rf.key_id"
        ).fetchone()
        self.assertEqual(rule, "rule\ufffdwith\ufffdtab")
        self.assertEqual(component, "api\ufffd\ufffd")

    def test_messages_are_stored_once(self):
        record(self.conn, self.tmp, "acme/app", "a" * 40, 1, [finding("r1", "a.py", "f1:0"), finding("r1", "b.py", "f2:0")])
        record(self.conn, self.tmp, "acme/app", "b" * 40, 2, [finding("r1", "a.py", "f1:0")])
        self.assertEqual(self.count("messages"), 1)

    def test_summary_from_another_run_is_refused(self):
        path = write_findings(self.tmp, [finding("r1", "a.py", "f1:0")])
        with self.assertRaisesRegex(SetupError, "different runs"):
            history.read_inputs(path, check_output(summary([])))

    def test_check_output_without_a_summary_is_refused(self):
        path = write_findings(self.tmp, [])
        with self.assertRaisesRegex(SetupError, "SHOALSCAN_SUMMARY"):
            history.read_inputs(path, "Shoalscan check: PASSED\n")
        with self.assertRaisesRegex(SetupError, "invalid value"):
            doc = summary([])
            doc["baseline_size"] = -1
            found, meta, parsed = history.read_inputs(path, check_output(doc))
            history.record_run(self.conn, history.RunInfo("acme/app", "main", "a" * 40, "pr", "2026-09-01T00:00:00Z"), found, meta, parsed)

    def test_invalid_run_details_are_refused(self):
        good = dict(repo="acme/app", ref="main", commit="a" * 40, kind="scheduled", scanned_at="2026-09-01T00:00:00Z")
        for field, value in (("repo", "../x"), ("repo", "a\nb"), ("ref", "a..b"), ("commit", "XYZ"), ("kind", "nightly"),
                             ("repo", "acme/app\n"), ("commit", "a" * 40 + "\n"), ("ref", "main\n"),
                             ("scanned_at", "2026-08-33T02:00:00Z"), ("scanned_at", "2026-09-01 02:00")):
            with self.subTest(field=field, value=value), self.assertRaises(SetupError):
                history.record_run(self.conn, history.RunInfo(**{**good, field: value}), [], {}, summary([]))
        with self.assertRaisesRegex(SetupError, "time zone"):
            history.parse_timestamp("2026-09-01T00:00:00")
        self.assertEqual(history.parse_timestamp("2026-09-01T04:00:00+02:00"), "2026-09-01T02:00:00Z")

    def test_a_scan_time_far_in_the_future_is_refused(self):
        from datetime import datetime, timedelta, timezone

        def stamp(delta):
            return (datetime.now(timezone.utc) + delta).strftime("%Y-%m-%dT%H:%M:%SZ")

        info = dict(repo="acme/app", ref="main", commit="a" * 40, kind="scheduled")
        with self.assertRaisesRegex(SetupError, "24 hours in the future"):
            history.record_run(self.conn, history.RunInfo(**info, scanned_at=stamp(timedelta(hours=25))), [], {}, summary([]))
        result = history.record_run(self.conn, history.RunInfo(**info, scanned_at=stamp(timedelta(hours=23))), [], {}, summary([]))
        self.assertEqual(result.status, "recorded")

    def test_pruning_keeps_the_newest_runs_and_drops_orphans(self):
        for day in range(1, 7):
            record(self.conn, self.tmp, "acme/app", f"{day:040x}", day, [finding("r", f"f{day}.py", f"{day}:0")])
        repo_id = self.conn.execute("SELECT id FROM repos").fetchone()[0]
        self.conn.execute("BEGIN")
        history.prune(self.conn, repo_id, max_runs=3, keep_pr_days=90)
        self.conn.execute("COMMIT")
        days = [r[0] for r in self.conn.execute("SELECT scanned_at FROM runs ORDER BY scanned_at")]
        self.assertEqual(days, ["2026-09-04T02:00:00Z", "2026-09-05T02:00:00Z", "2026-09-06T02:00:00Z"])
        self.assertEqual((self.count("finding_keys"), self.count("run_findings")), (3, 3))

    def test_old_pull_request_runs_are_pruned(self):
        record(self.conn, self.tmp, "acme/app", "a" * 40, 1, [], kind="pr")
        record(self.conn, self.tmp, "acme/app", "b" * 40, 1, [], kind="scheduled")
        result = record(self.conn, self.tmp, "acme/app", "c" * 40, 20, [], kind="scheduled")
        self.assertEqual(result.pruned, 0)
        repo_id = self.conn.execute("SELECT id FROM repos").fetchone()[0]
        self.conn.execute("BEGIN")
        history.prune(self.conn, repo_id, max_runs=100, keep_pr_days=10)
        self.conn.execute("COMMIT")
        self.assertEqual([r[0] for r in self.conn.execute("SELECT kind FROM runs ORDER BY id")], ["scheduled", "scheduled"])

    def test_too_many_findings_are_refused(self):
        items = [finding("r", "a.py", "1:0"), finding("r", "b.py", "2:0")]
        path = write_findings(self.tmp, items)
        original = history.MAX_FINDINGS_PER_RUN
        history.MAX_FINDINGS_PER_RUN = 1
        try:
            with self.assertRaisesRegex(SetupError, "at most 1"):
                history.read_inputs(path, check_output(summary(items)))
        finally:
            history.MAX_FINDINGS_PER_RUN = original


class MigrationTests(unittest.TestCase):
    def test_a_version_1_database_is_migrated_with_its_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "h.sqlite3"
            conn = sqlite3.connect(db, isolation_level=None)
            conn.executescript(history.MIGRATIONS[0] + "\nPRAGMA user_version = 1;")
            conn.execute("INSERT INTO repos (name) VALUES ('acme/old')")
            conn.close()
            conn = history.open_for_write(db)
            try:
                self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], history.SCHEMA_VERSION)
                self.assertEqual(conn.execute("SELECT name FROM repos").fetchall(), [("acme/old",)])
                indexes = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'index'")}
                self.assertIn("runs_by_repo_time", indexes)
            finally:
                conn.close()

    def test_a_newer_database_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "h.sqlite3"
            conn = sqlite3.connect(db)
            conn.execute(f"PRAGMA user_version = {history.SCHEMA_VERSION + 1}")
            conn.close()
            with self.assertRaisesRegex(SetupError, "newer"):
                history.open_for_write(db)
            with self.assertRaisesRegex(SetupError, "schema version"):
                history.open_read_only(db)


class DerivedMetricsTests(HistoryTestCase):
    def setUp(self):
        super().setUp()
        sample_history(self.conn, self.tmp)
        self.data = Data(history.open_read_only(self.db))
        self.repo = self.data.repo_id("acme/app")

    def tearDown(self):
        self.data.conn.close()
        super().tearDown()

    def test_the_read_only_connection_cannot_write(self):
        with self.assertRaises(sqlite3.OperationalError):
            self.data.conn.execute("DELETE FROM runs")

    def test_trends_use_scheduled_runs_only(self):
        o = self.data.overview(self.repo)
        self.assertEqual(o["trend_kind"], "scheduled")
        self.assertEqual([p["scanned_at"][:10] for p in o["series"]], ["2026-09-01", "2026-09-08", "2026-09-15", "2026-09-22"])
        self.assertEqual([p["baseline_size"] for p in o["series"]], [3, 3, 2, 2])
        self.assertEqual(o["series"][-1]["open"], {"ERROR": 1, "WARNING": 1, "INFO": 1})
        self.assertEqual((o["series"][-1]["unscanned_skipped"], o["series"][-1]["unscanned_errored"]), (2, 1))
        # The latest run of any kind is the pull-request run.
        self.assertEqual(o["latest_run"]["kind"], "pr")

    def test_new_fixed_time_to_fix_and_ages(self):
        o = self.data.overview(self.repo)
        weekly = {w["week"]: (w["new"], w["fixed"]) for w in o["weekly"]}
        # Weeks start on Monday: 09-01 is a Tuesday, so its week is 08-31.
        self.assertEqual(weekly, {"2026-08-31": (0, 0), "2026-09-07": (1, 1), "2026-09-14": (0, 1), "2026-09-21": (1, 0)})
        # A was fixed after 14 days, D after 7.
        self.assertEqual(o["time_to_fix"], {"fixed": 2, "mean_days": 10.5, "median_days": 10.5})
        ages = {b["label"]: b["count"] for b in o["age_buckets"]}
        # On 09-22: B open 14 days, C 21 days, D reopened that day.
        self.assertEqual(ages, {"0-7 days": 1, "8-30 days": 2, "31-90 days": 0, "91-365 days": 0, "over a year": 0})
        comp = o["by_component"]
        self.assertEqual([r["component"] for r in comp["rows"]], ["api", "web"])
        self.assertEqual([r["cells"] for r in comp["rows"]], [[1, 0, 1], [0, 1, 0]])

    def test_the_timeline_walks_only_the_newest_trend_runs(self):
        from shoalscan.dashboard import data as data_module

        original = data_module.MAX_TREND_RUNS
        data_module.MAX_TREND_RUNS = 2
        try:
            o = self.data.overview(self.repo)
        finally:
            data_module.MAX_TREND_RUNS = original
        # All four runs still draw the series; only 09-15 and 09-22 feed the timeline.
        self.assertEqual(len(o["series"]), 4)
        self.assertEqual([w["week"] for w in o["weekly"]], ["2026-09-14", "2026-09-21"])
        self.assertEqual({w["week"]: (w["new"], w["fixed"]) for w in o["weekly"]}, {"2026-09-14": (0, 0), "2026-09-21": (1, 0)})
        self.assertEqual(o["time_to_fix"]["fixed"], 0)

    def test_a_repository_without_scheduled_runs_uses_all_runs(self):
        record(self.conn, self.tmp, "acme/prs", "7" * 40, 3, [finding("r", "a.py", "1:0")], kind="pr")
        o = self.data.overview(self.data.repo_id("acme/prs"))
        self.assertEqual((o["trend_kind"], len(o["series"])), ("all", 1))

    def test_findings_filters_and_first_seen(self):
        run = self.data.resolve_run(self.repo, None)
        everything = self.data.findings(self.repo, run)
        self.assertEqual(everything["total"], 3)
        self.assertEqual([f["severity"] for f in everything["findings"]], ["ERROR", "WARNING", "INFO"])
        first = {f["path"]: f["first_seen"][:10] for f in everything["findings"]}
        self.assertEqual(first, {"src/d.py": "2026-09-01", "web/b.js": "2026-09-08", "src/c.py": "2026-09-01"})
        self.assertEqual(self.data.findings(self.repo, run, severity="INFO")["findings"][0]["message"], MALICIOUS)
        self.assertEqual(self.data.findings(self.repo, run, component="web")["total"], 1)
        self.assertEqual(self.data.findings(self.repo, run, rule="community.python.eval")["total"], 1)
        self.assertEqual(self.data.findings(self.repo, run, path="src/")["total"], 2)
        # A path filter is a plain substring, not a LIKE pattern.
        self.assertEqual(self.data.findings(self.repo, run, path="%")["total"], 0)
        self.assertEqual(self.data.findings(self.repo, run, limit=1, offset=1)["findings"][0]["path"], "web/b.js")

    def test_a_run_of_another_repository_is_not_found(self):
        other = self.data.resolve_run(self.data.repo_id("acme/other"), None)
        self.assertIsNone(self.data.resolve_run(self.repo, other))


class RecordCommandTests(unittest.TestCase):
    def test_record_from_the_command_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            items = [finding("r1", "a.py", "f1:0")]
            path = write_findings(base, items, {"worktree": {"commit": "a" * 40, "tree": "t", "dirty": False}})
            (base / "check.txt").write_text(check_output(summary(items)), encoding="utf-8")
            args = ["record", "--findings", str(path), "--check-output", str(base / "check.txt"), "--repo-name", "acme/app",
                    "--ref", "main", "--commit", "A" * 40, "--kind", "scheduled", "--scanned-at", "2026-10-01T02:00:00Z",
                    "--db", str(base / "h.sqlite3")]
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(args), 0)
                self.assertEqual(main(args), 0)
                self.assertEqual(main([*args[:-2], "--db", str(base / "h2.sqlite3"), "--kind", "pr", "--commit", "zz"]), 2)
            self.assertIn("already had scheduled run", out.getvalue())
            conn = sqlite3.connect(base / "h.sqlite3")
            self.assertEqual(conn.execute("SELECT commit_sha, scanned_at FROM runs").fetchall(), [("a" * 40, "2026-10-01T02:00:00Z")])
            conn.close()


class DetailsAndOutcomeTests(HistoryTestCase):
    def setUp(self):
        super().setUp()
        sample_history(self.conn, self.tmp)
        self.data = Data(history.open_read_only(self.db))
        self.repo = self.data.repo_id("acme/app")
        self.last = self.data.resolve_run(self.repo, None)

    def tearDown(self):
        self.data.conn.close()
        super().tearDown()

    def test_the_lists_behind_the_counts_are_stored(self):
        run = self.data.run(self.repo, self.last)
        self.assertEqual(run["lists"], {"blocking": True, "new": True, "stale": True, "files": True, "suppressions": True})
        self.assertEqual(run["outcome"], "blocked")
        self.assertEqual(run["status"]["label"], "Blocked: 2 new blocking findings")
        self.assertEqual(run["status"]["details"], ["1 stale baseline entry"])
        blocking = self.data.findings(self.repo, self.last, new_blocking=True)
        self.assertEqual(sorted(f["path"] for f in blocking["findings"]), ["src/d.py", "web/b.js"])
        self.assertEqual(self.data.findings(self.repo, self.last, new=True)["total"], 2)
        self.assertEqual(self.data.stale(self.last)["entries"][0]["path"], "src/old.py")
        files = self.data.files(self.last)
        self.assertEqual(files["counts"]["skipped"], 2)
        self.assertEqual(files["counts"]["error"], 1)
        self.assertEqual(self.data.files(self.last, "error")["files"][0]["detail"]["type"], "PartialParsing")
        self.assertEqual(self.data.suppressions(self.last)["suppressions"][0]["issue"], "#5")
        # A run recorded without check.json says so, and lists nothing.
        older = self.data.runs(self.repo)["runs"][2]
        self.assertEqual(older["lists"]["new"], False)

    def test_details_from_another_check_are_refused(self):
        directory = self.tmp / "mismatch"
        directory.mkdir()
        items = [finding("r", "a.py", "1:0")]
        path, output = checked(directory, items, [])
        found, meta, doc = history.read_inputs(path, output)
        history.read_details(directory / "check.json", path, doc, found)  # the matching pair is fine
        other = dict(doc, stale=5)
        with self.assertRaisesRegex(SetupError, "different checks"):
            history.read_details(directory / "check.json", path, other, found)
        with self.assertRaisesRegex(SetupError, "not in"):
            history.read_details(directory / "check.json", path, doc, [])
        path.write_text(path.read_text() + " ", encoding="utf-8")
        with self.assertRaisesRegex(SetupError, "another findings file"):
            history.read_details(directory / "check.json", path, doc, found)

    def test_details_must_agree_with_the_summary_counts(self):
        directory = self.tmp / "counts"
        directory.mkdir()
        a, b = finding("r", "a.py", "1:0"), finding("r", "b.py", "2:0", "INFO")
        gone = Entry("opengrep", "r", "gone.py", "g:0", "#1", "x")
        path, output = checked(directory, [a, b], [gone])
        found, meta, doc = history.read_inputs(path, output)
        original = json.loads((directory / "check.json").read_text())

        def tampered(change):
            details = json.loads(json.dumps(original))
            change(details)
            (directory / "check.json").write_text(json.dumps(details))
            return lambda: history.read_details(directory / "check.json", path, doc, found)

        history.read_details(directory / "check.json", path, doc, found)
        for label, change, message in (
            ("new dropped", lambda d: d["new"].pop(), "new entries"),
            ("new blocking dropped", lambda d: (d["new_blocking"].pop(), d["blocking_class"].clear()), "new blocking entries"),
            ("new blocking not new", lambda d: d["new"].remove(d["new_blocking"][0]), "not in the new findings"),
            ("stale dropped", lambda d: d["stale"].clear(), "stale entries"),
            ("listed twice", lambda d: d["new"].append(d["new"][0]), "listed twice"),
        ):
            with self.subTest(label=label), self.assertRaisesRegex(SetupError, message):
                tampered(change)()

    def test_the_check_exit_must_agree_with_the_summary(self):
        with self.assertRaisesRegex(SetupError, "exited with 0"):
            record(self.conn, self.tmp, "acme/x", "a" * 40, 1, [], check_exit=0, result="fail")
        self.assertEqual(history.run_outcome({"result": "pass"}, None), "passed")
        self.assertEqual(history.run_outcome({"result": "fail"}, 1), "blocked")
        self.assertEqual(history.run_outcome({}, 2), "scan_error")

    def test_a_scan_error_is_shown_but_feeds_no_trend(self):
        before = self.data.overview(self.repo)
        info = history.RunInfo("acme/app", "main", "9" * 40, "scheduled", "2026-09-29T02:00:00Z")
        history.record_run(self.conn, info, [], {}, {}, check_exit=2)
        after = self.data.overview(self.repo)
        self.assertEqual(after["latest_run"]["status"]["label"], "Scan error")
        self.assertEqual(after["series"], before["series"])
        self.assertEqual(self.data.resolve_run(self.repo, None), self.last)
        # It never replaces a run that holds results.
        existing = history.RunInfo("acme/app", "main", "4" * 40, "scheduled", "2026-09-22T02:00:00Z")
        with self.assertRaisesRegex(SetupError, "does not replace"):
            history.record_run(self.conn, existing, [], {}, {}, check_exit=2)

    def test_heatmap_rows_and_levels(self):
        from collections import Counter

        from shoalscan.dashboard.data import heat_level, heat_rows

        rows = heat_rows({
            "infos": Counter(INFO=30),            # score 30
            "errors": Counter(ERROR=2),           # score 20
            "mixed": Counter(WARNING=5, INFO=1),  # score 16
            "fresh": Counter(INFO=1, new_blocking=1),
            "hot": Counter(ERROR=1, new_blocking=3),  # score 10
        })
        # New blocking first, by score within the group; then by score.
        self.assertEqual([r["component"] for r in rows], ["hot", "fresh", "infos", "errors", "mixed"])
        self.assertEqual([r["score"] for r in rows], [10, 1, 30, 20, 16])
        self.assertEqual([heat_level(v, 30) for v in (0, 1, 6, 7, 12, 13, 30)], [0, 1, 1, 2, 2, 3, 5])
        self.assertEqual(heat_level(5, 0), 0)
        comp = self.data.overview(self.repo)["by_component"]
        self.assertEqual([r["new_blocking"] for r in comp["rows"]], [1, 1])

    def test_age_filter_and_weekly_changes_match_the_charts(self):
        o = self.data.overview(self.repo)
        for index, bucket in enumerate(o["age_buckets"]):
            self.assertEqual(self.data.findings(self.repo, self.last, age=index)["total"], bucket["count"], bucket["label"])
        for week in o["weekly"]:
            self.assertEqual(self.data.changes(self.repo, week["week"], "new")["total"], week["new"])
            self.assertEqual(self.data.changes(self.repo, week["week"], "fixed")["total"], week["fixed"])
        fixed = self.data.changes(self.repo, "2026-09-14", "fixed")["findings"]
        self.assertEqual([f["path"] for f in fixed], ["src/a.py"])


class RecordDetailsCommandTests(unittest.TestCase):
    def run_cli(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()) as err:
            code = main(list(args))
        return code, out.getvalue(), err.getvalue()

    def test_check_json_is_found_next_to_the_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            items = [finding("r1", "a.py", "f1:0")]
            path, output = checked(base, items, [])
            (base / "check.txt").write_text(output, encoding="utf-8")
            common = ["record", "--allow-no-git", "--findings", str(path), "--check-output", str(base / "check.txt"), "--repo-name", "acme/app",
                      "--ref", "main", "--kind", "scheduled", "--db", str(base / "h.sqlite3")]
            code, out, err = self.run_cli(*common, "--commit", "a" * 40, "--check-exit", "1")
            self.assertEqual(code, 0, err)
            self.assertNotIn("no check.json", out)
            conn = sqlite3.connect(base / "h.sqlite3")
            self.assertEqual(conn.execute("SELECT outcome, check_exit, details_known FROM runs").fetchall(), [("blocked", 1, 1)])
            self.assertEqual(conn.execute("SELECT new_blocking FROM run_findings").fetchall(), [(1,)])
            conn.close()
            # A check exit that contradicts the summary is refused.
            self.assertEqual(self.run_cli(*common, "--commit", "b" * 40, "--check-exit", "0")[0], 2)
            # Without check.json the run is recorded with counts only, and record says so.
            (base / "check.json").unlink()
            code, out, _ = self.run_cli(*common, "--commit", "c" * 40)
            self.assertEqual(code, 0)
            self.assertIn("no check.json", out)

    def test_a_scan_error_needs_no_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            code, out, err = self.run_cli("record", "--findings", str(base / "missing.json"), "--check-exit", "2",
                                          "--repo-name", "acme/app", "--ref", "main", "--commit", "d" * 40, "--kind", "scheduled",
                                          "--db", str(base / "h.sqlite3"))
            self.assertEqual(code, 0, err)
            self.assertIn("a scan error", out)
            self.assertEqual(self.run_cli("record", "--repo-name", "acme/app", "--ref", "main", "--commit", "e" * 40,
                                          "--kind", "scheduled", "--db", str(base / "h.sqlite3"))[0], 2)


class HistoryCommandTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.db = self.tmp / "h.sqlite3"
        conn = history.open_for_write(self.db)
        sample_history(conn, self.tmp)
        conn.close()

    def tearDown(self):
        self._tmp.cleanup()

    def cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["history", *args, "--db", str(self.db)])
        return code, out.getvalue(), err.getvalue()

    def run_id(self, scanned_on: str, kind: str = "scheduled") -> int:
        conn = sqlite3.connect(self.db)
        try:
            return conn.execute("SELECT id FROM runs WHERE scanned_at LIKE ? AND kind = ?", (scanned_on + "%", kind)).fetchone()[0]
        finally:
            conn.close()

    def overview(self, repo: str = "acme/app") -> dict:
        data = Data(history.open_read_only(self.db))
        try:
            return data.overview(data.repo_id(repo))
        finally:
            data.conn.close()

    def test_list_runs_shows_the_ids(self):
        code, out, _ = self.cli("list-runs", "--repo-name", "acme/app")
        self.assertEqual(code, 0)
        lines = out.splitlines()
        self.assertTrue(lines[0].split()[:2] == ["ID", "SCANNED"])
        self.assertEqual(len(lines), 6)
        self.assertIn(str(self.run_id("2026-09-15")), out)
        self.assertEqual(self.cli("list-runs", "--repo-name", "nobody/none")[0], 2)

    def test_delete_needs_yes_and_says_what_it_deleted(self):
        run = self.run_id("2026-09-15")
        code, out, err = self.cli("delete-run", "--repo-name", "acme/app", "--run", str(run))
        self.assertEqual(code, 2)
        self.assertIn("nothing was deleted", err)
        self.assertIn(f"run {run}: scheduled main at 333333333333", err)
        self.assertEqual(len(self.overview()["series"]), 4)
        code, out, _ = self.cli("delete-run", "--repo-name", "acme/app", "--run", str(run), "--yes")
        self.assertEqual(code, 0)
        self.assertIn(f"deleted acme/app run {run}: scheduled main at 333333333333, scanned 2026-09-15T02:00:00Z, passed, 2 findings", out)
        # A run of another repository, or one that is gone, is refused.
        other = self.run_id("2026-09-20")
        self.assertEqual(self.cli("delete-run", "--repo-name", "acme/app", "--run", str(other), "--yes")[0], 2)
        self.assertEqual(self.cli("delete-run", "--repo-name", "acme/app", "--run", str(run), "--yes")[0], 2)

    def test_derived_metrics_stay_consistent_after_a_delete(self):
        self.cli("delete-run", "--repo-name", "acme/app", "--run", str(self.run_id("2026-09-15")), "--yes")
        o = self.overview()
        self.assertEqual([p["scanned_at"][:10] for p in o["series"]], ["2026-09-01", "2026-09-08", "2026-09-22"])
        weekly = {w["week"]: (w["new"], w["fixed"]) for w in o["weekly"]}
        # A is now fixed on 09-22 (21 days), in the same run where D comes back.
        self.assertEqual(weekly["2026-09-14"], (0, 0))
        self.assertEqual(weekly["2026-09-21"], (1, 1))
        self.assertEqual(o["time_to_fix"], {"fixed": 2, "mean_days": 14.0, "median_days": 14.0})
        conn = sqlite3.connect(self.db)
        try:
            orphans = conn.execute(
                "SELECT COUNT(*) FROM finding_keys WHERE NOT EXISTS (SELECT 1 FROM run_findings WHERE key_id = finding_keys.id)"
            ).fetchone()[0]
            self.assertEqual(orphans, 0)
        finally:
            conn.close()

    def test_a_deletion_is_recorded(self):
        run = self.run_id("2026-09-15")
        self.cli("delete-run", "--repo-name", "acme/app", "--run", str(run), "--yes")
        conn = sqlite3.connect(self.db)
        try:
            row = conn.execute("SELECT repo_name, run_id, kind, commit_sha, findings, outcome, deleted_at, deleted_by FROM deletions").fetchone()
        finally:
            conn.close()
        self.assertEqual(row[:6], ("acme/app", run, "scheduled", "3" * 40, 2, "passed"))
        self.assertRegex(row[6], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
        self.assertTrue(row[7])
        data = Data(history.open_read_only(self.db))
        try:
            self.assertEqual(data.deletions("acme/app")["count"], 1)
            self.assertEqual(data.deletions("acme/other")["count"], 0)
        finally:
            data.conn.close()

    def test_deleting_the_last_run_removes_the_repository(self):
        code, out, _ = self.cli("delete-run", "--repo-name", "acme/other", "--run", str(self.run_id("2026-09-20")), "--yes")
        self.assertEqual(code, 0)
        self.assertIn("last run of acme/other", out)
        conn = sqlite3.connect(self.db)
        try:
            self.assertEqual(conn.execute("SELECT name FROM repos").fetchall(), [("acme/app",)])
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM finding_keys WHERE rule = 'shoalscan.tls-off'").fetchone()[0], 0)
        finally:
            conn.close()


class BlockingClassTests(HistoryTestCase):
    """The blocking class comes from check.json: what the check decided, never re-derived."""

    def record_mix(self):
        accepted = finding("r.err", "src/accepted.py", "acc:0", "ERROR", "api")
        accepted_warn = finding("r.warn", "web/w.js", "accw:0", "WARNING", "web")
        new_error = finding("r.err", "src/new.py", "new:0", "ERROR", "api")
        new_warning = finding("r.warn", "src/neww.py", "neww:0", "WARNING", "api")
        info = finding("r.info", "src/i.py", "inf:0", "INFO", "api")
        demo = finding("r.err", "demo/d.py", "dem:0", "ERROR", "demo")
        for day, items in ((1, [accepted, accepted_warn, info, demo]), (8, [accepted, accepted_warn, new_error, new_warning, info, demo])):
            record(self.conn, self.tmp, "acme/mix", f"{day:040x}", day, items, baseline=[entry(accepted), entry(accepted_warn)],
                   non_blocking_paths=("demo/",))
        self.data = Data(history.open_read_only(self.db))
        self.addCleanup(self.data.conn.close)
        self.repo = self.data.repo_id("acme/mix")
        return self.data.resolve_run(self.repo, None)

    def test_flag_and_counts_follow_the_check(self):
        run = self.record_mix()
        flags = dict(self.conn.execute(
            "SELECT fk.path, rf.blocking_class FROM run_findings rf JOIN finding_keys fk ON fk.id = rf.key_id WHERE rf.run_id = ?", (run,)
        ).fetchall())
        # Baselined or new, a blocking severity outside the non-blocking paths is in the class; INFO and demo/ are not.
        self.assertEqual(flags, {"src/accepted.py": 1, "web/w.js": 1, "src/new.py": 1, "src/neww.py": 1, "src/i.py": 0, "demo/d.py": 0})
        panel = self.data.overview(self.repo)["blocking"]
        self.assertEqual((panel["known"], panel["total"], panel["new"], panel["baselined"]), (True, 4, 2, 2))
        self.assertEqual(self.data.findings(self.repo, run, blocking=True, baselined=True)["total"], 2)
        self.assertEqual([p["blocking"] for p in self.data.overview(self.repo)["series"]], [2, 4])

    def test_priority_order(self):
        run = self.record_mix()
        order = [f["path"] for f in self.data.findings(self.repo, run, blocking=True)["findings"]]
        # New blocking first (ERROR before WARNING); then the baselined ones, ERROR before WARNING.
        self.assertEqual(order, ["src/new.py", "src/neww.py", "src/accepted.py", "web/w.js"])
        self.assertEqual([f["path"] for f in self.data.overview(self.repo)["blocking"]["top"]], order)

    def test_priority_key_breaks_ties_by_heat_then_age(self):
        from shoalscan.dashboard.data import priority_key

        def row(key, severity, component, new_blocking=0, path="p"):
            return {"key_id": key, "severity": severity, "component": component, "new_blocking": new_blocking, "path": path, "line": 1, "rule": "r"}

        rows = [row(1, "ERROR", "cold"), row(2, "ERROR", "hot"), row(3, "WARNING", "hot", new_blocking=1),
                row(4, "ERROR", "hot"), row(5, "WARNING", "hot")]
        scores = {"hot": 50, "cold": 5}
        first_seen = {1: "2026-01-01T00:00:00Z", 2: "2026-03-01T00:00:00Z", 4: "2026-02-01T00:00:00Z", 5: "2026-01-01T00:00:00Z"}
        ordered = sorted(rows, key=lambda r: priority_key(r, scores, first_seen))
        self.assertEqual([r["key_id"] for r in ordered], [3, 4, 2, 1, 5])

    def test_an_older_check_json_leaves_the_class_unknown(self):
        directory = self.tmp / "old-check"
        directory.mkdir()
        items = [finding("r", "a.py", "1:0")]
        path, output = checked(directory, items, [])
        doc = json.loads((directory / "check.json").read_text())
        for key in ("blocking_class", "blocking", "non_blocking_paths"):
            doc.pop(key)
        (directory / "check.json").write_text(json.dumps(doc))
        found, meta, summary_doc = history.read_inputs(path, output)
        details = history.read_details(directory / "check.json", path, summary_doc, found)
        info = history.RunInfo("acme/old", "main", "a" * 40, "scheduled", "2026-09-01T00:00:00Z")
        history.record_run(self.conn, info, found, meta, summary_doc, details=details)
        self.assertEqual(self.conn.execute("SELECT blocking_class FROM run_findings").fetchall(), [(None,)])
        self.assertEqual(self.conn.execute("SELECT blocking_class_count FROM runs").fetchall(), [(None,)])

    def test_a_blocking_class_without_its_new_blocking_findings_is_refused(self):
        directory = self.tmp / "bad-check"
        directory.mkdir()
        path, output = checked(directory, [finding("r", "a.py", "1:0")], [])
        doc = json.loads((directory / "check.json").read_text())
        doc["blocking_class"] = []
        (directory / "check.json").write_text(json.dumps(doc))
        found, meta, summary_doc = history.read_inputs(path, output)
        with self.assertRaisesRegex(SetupError, "missing from blocking_class"):
            history.read_details(directory / "check.json", path, summary_doc, found)


class MigrationToVersion4Tests(unittest.TestCase):
    def test_version_3_runs_read_as_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "h.sqlite3"
            conn = sqlite3.connect(db, isolation_level=None)
            conn.executescript("".join(history.MIGRATIONS[:3]) + "\nPRAGMA user_version = 3;")
            conn.executescript(
                "INSERT INTO repos (id, name) VALUES (1, 'acme/v3');"
                "INSERT INTO runs (id, repo_id, kind, ref, commit_sha, scanned_at, recorded_at, result, findings, error, warning, info, "
                "nb_error, nb_warning, nb_info, new, new_blocking, new_non_blocking_paths, stale, baseline_size, baseline_additions, "
                "suppressions, suppressions_invalid, suppressed_findings, unscanned_skipped, unscanned_errored, changed_unscanned, "
                "scanners, content_sha256, outcome, details_known) VALUES (1, 1, 'scheduled', 'main', '" + "a" * 40 + "', "
                "'2026-09-01T00:00:00Z', '2026-09-01T00:00:00Z', 'fail', 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, '{}', 'x', 'blocked', 1);"
                "INSERT INTO finding_keys (id, repo_id, tool, rule, path, fingerprint) VALUES (1, 1, 'opengrep', 'r', 'a.py', 'f:0');"
                "INSERT INTO messages (id, sha256, text) VALUES (1, 'x', 'm');"
                "INSERT INTO run_findings (run_id, key_id, severity, line, component, message_id, is_new, new_blocking) VALUES (1, 1, 'ERROR', 1, 'api', 1, 1, 1);"
            )
            conn.close()
            history.open_for_write(db).close()
            data = Data(history.open_read_only(db))
            try:
                run = data.run(1, 1)
                self.assertIsNone(run["blocking_class"])
                self.assertFalse(run["lists"]["blocking"])
                overview = data.overview(1)
                self.assertEqual(overview["blocking"]["known"], False)
                self.assertEqual([p["blocking"] for p in overview["series"]], [None])
                found = data.findings(1, 1)["findings"][0]
                self.assertIsNone(found["blocking_class"])
                self.assertTrue(found["new_blocking"])
                self.assertEqual(data.findings(1, 1, blocking=True)["total"], 0)
            finally:
                data.conn.close()


class CommitBindingTests(unittest.TestCase):
    def run_cli(self, *args):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as err:
            return main(list(args)), err.getvalue()

    def test_record_refuses_another_commit_than_the_scanned_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            items = [finding("r1", "a.py", "f1:0")]
            (base / "check.txt").write_text(check_output(summary(items)), encoding="utf-8")
            common = ["record", "--check-output", str(base / "check.txt"), "--repo-name", "acme/app", "--ref", "main",
                      "--kind", "scheduled", "--db", str(base / "h.sqlite3")]
            scanned = write_findings(base, items, {"worktree": {"commit": "b" * 40, "tree": "t", "dirty": False}})
            code, err = self.run_cli(*common, "--findings", str(scanned), "--commit", "c" * 40)
            self.assertEqual(code, 2)
            self.assertIn("scanned at commit " + "b" * 40, err)
            self.assertEqual(self.run_cli(*common, "--findings", str(scanned), "--commit", "b" * 40)[0], 0)
            # A scan without git is recorded only when asked for.
            (base / "nogit").mkdir()
            no_git = write_findings(base / "nogit", items, {"worktree": None})
            code, err = self.run_cli(*common, "--findings", str(no_git), "--commit", "d" * 40)
            self.assertEqual(code, 2)
            self.assertIn("--allow-no-git", err)
            self.assertEqual(self.run_cli(*common, "--findings", str(no_git), "--commit", "d" * 40, "--allow-no-git")[0], 0)

    def test_scan_records_the_head_commit(self):
        from shoalscan import gitref

        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            git = ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-C", str(repo)]
            subprocess.run(["git", "init", "-q", str(repo)], check=True, timeout=30)
            (repo / "a.txt").write_text("x\n", encoding="utf-8")
            subprocess.run([*git, "add", "a.txt"], check=True, timeout=30)
            subprocess.run([*git, "commit", "-q", "-m", "one"], check=True, timeout=30)
            head = subprocess.run([*git, "rev-parse", "HEAD"], check=True, capture_output=True, text=True, timeout=30).stdout.strip()
            self.assertEqual(gitref.worktree_state(repo)["commit"], head)


class ReviewTests(HistoryTestCase):
    def setUp(self):
        super().setUp()
        self.a = finding("r.a", "src/a.py", "aa:0")
        self.b = finding("r.b", "src/b.py", "bb:0", "WARNING")
        record(self.conn, self.tmp, "acme/app", "1" * 40, 1, [self.a, self.b])

    @staticmethod
    def key(f):
        return [f.tool, f.rule, f.path, f.fingerprint]

    def review(self, f):
        return self.conn.execute(
            "SELECT status, description, resolved_at, updated_by FROM finding_reviews WHERE path = ?", (f.path,)
        ).fetchone()

    def events(self, f):
        return self.conn.execute(
            "SELECT who, from_status, to_status, description, at, run_id FROM finding_review_events WHERE path = ? ORDER BY id", (f.path,)
        ).fetchall()

    def test_who_may_set_what(self):
        good = "Reviewed: the input is a constant."
        for status in ("verified_fixed", "regression", "closed", None):
            with self.subTest(status=status), self.assertRaises(SetupError):
                history.set_reviews(self.db, "acme/app", [self.key(self.a)], status, good, "me")
        for status in history.USER_STATUSES:
            for description in (None, "", "too short", " " * 30, "x" * 2001, 12345, "\x00" * 12 + "abc", "a b c d e f g h i",
                                "\ufffd" * 10 + "ab"):
                with self.subTest(status=status, description=description), self.assertRaises(SetupError):
                    history.set_reviews(self.db, "acme/app", [self.key(self.a)], status, description, "me")
        with self.assertRaises(LookupError):
            history.set_reviews(self.db, "acme/app", [["opengrep", "r.x", "x.py", "x:0"]], "fixed", good, "me")
        with self.assertRaises(LookupError):
            history.set_reviews(self.db, "acme/other", [self.key(self.a)], "fixed", good, "me")
        with self.assertRaisesRegex(SetupError, "500"):
            history.set_reviews(self.db, "acme/app", [self.key(self.a)] * 501, "fixed", good, "me")
        self.assertIsNone(self.review(self.a))

    def test_timestamps_are_set_and_cleared(self):
        history.set_reviews(self.db, "acme/app", [self.key(self.a)], "false_positive", "The value is never user input.", "me")
        status, description, resolved, who = self.review(self.a)
        self.assertEqual((status, description, who), ("false_positive", "The value is never user input.", "me"))
        self.assertRegex(resolved, r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
        first_resolved = self.review(self.a)[2]
        time.sleep(1.1)
        history.set_reviews(self.db, "acme/app", [self.key(self.a)], "wont_fix", "Not worth changing this code.", "me")
        self.assertEqual(self.review(self.a)[2], first_resolved, "moving between resolved statuses keeps the first time")
        history.set_reviews(self.db, "acme/app", [self.key(self.a)], "open", "Reopened: the input changed.", "me")
        self.assertIsNone(self.review(self.a)[2])
        events = self.events(self.a)
        self.assertEqual([(e[1], e[2]) for e in events], [("open", "false_positive"), ("false_positive", "wont_fix"), ("wont_fix", "open")])
        self.assertTrue(all(e[4].endswith("Z") for e in events))
        # Control characters are replaced, not dropped.
        history.set_reviews(self.db, "acme/app", [self.key(self.b)], "wont_fix", "Legacy\x00code\x1b[31m kept\non purpose", "me")
        self.assertEqual(self.review(self.b)[1], "Legacy\ufffdcode\ufffd[31m kept\non purpose")

    def test_scheduled_runs_verify_fixes_and_find_regressions(self):
        history.set_reviews(self.db, "acme/app", [self.key(self.a)], "fixed", "Fixed by escaping the input.", "me")
        history.set_reviews(self.db, "acme/app", [self.key(self.b)], "false_positive", "Only a test fixture uses it.", "me")
        # A pull-request run without the finding changes nothing.
        record(self.conn, self.tmp, "acme/app", "9" * 40, 5, [self.b], kind="pr")
        self.assertEqual(self.review(self.a)[0], "fixed")
        covered = {"rule_ids": ["r.a", "r.b"], "unscanned": {"skipped": [], "errors": []}, "excludes": []}
        record(self.conn, self.tmp, "acme/app", "2" * 40, 8, [self.b], extra_meta=covered)
        status, description, resolved, who = self.review(self.a)
        self.assertEqual((status, who), ("verified_fixed", "shoalscan"))
        self.assertEqual(description, "No longer found in the scheduled run of 2026-09-08T02:00:00Z at 222222222222.")
        self.assertTrue(resolved)
        # An older scheduled run recorded late changes nothing either.
        record(self.conn, self.tmp, "acme/app", "8" * 40, 4, [self.a, self.b])
        self.assertEqual(self.review(self.a)[0], "verified_fixed")
        record(self.conn, self.tmp, "acme/app", "3" * 40, 15, [self.a, self.b])
        status, description, resolved, who = self.review(self.a)
        self.assertEqual((status, resolved), ("regression", None))
        self.assertEqual(description, "Found again in the scheduled run of 2026-09-15T02:00:00Z at 333333333333.")
        auto = [e for e in self.events(self.a) if e[0] == "shoalscan"]
        self.assertEqual([(e[1], e[2]) for e in auto], [("fixed", "verified_fixed"), ("verified_fixed", "regression")])
        self.assertTrue(all(e[5] for e in auto), "automatic events name their run")
        # A false positive stays one, run after run.
        self.assertEqual(self.review(self.b)[0], "false_positive")

    def test_absence_is_proof_only_when_the_file_and_rule_were_covered(self):
        history.set_reviews(self.db, "acme/app", [self.key(self.a)], "fixed", "Fixed by escaping the input.", "me")
        clean = {"skipped": [], "errors": []}
        not_proof = [
            ("no record of what ran", {}),
            ("rule left the ruleset", {"rule_ids": ["r.b"], "unscanned": clean}),
            ("file skipped", {"rule_ids": ["r.a", "r.b"], "unscanned": {"skipped": [{"path": "src/a.py", "reason": "exceeded_size_limit"}], "errors": []}}),
            ("file errored", {"rule_ids": ["r.a", "r.b"], "unscanned": {"skipped": [], "errors": [{"path": "src/a.py", "type": "Timeout"}]}}),
            ("parse gap over its line", {"rule_ids": ["r.a", "r.b"], "unscanned": {"skipped": [], "errors": [
                {"path": "src/a.py", "type": "PartialParsing", "spans": [[1, 5]], "file_lines": 10}]}}),
            ("excluded", {"rule_ids": ["r.a", "r.b"], "unscanned": clean, "excludes": ["src"]}),
        ]
        for day, (label, meta) in enumerate(not_proof, start=2):
            with self.subTest(label=label):
                record(self.conn, self.tmp, "acme/app", f"{day:040x}", day, [self.b], extra_meta=meta)
                self.assertEqual(self.review(self.a)[0], "fixed")
        # A parse gap elsewhere in the file does not stop a genuine fix from verifying.
        record(self.conn, self.tmp, "acme/app", "f" * 40, 20, [self.b], extra_meta={"rule_ids": ["r.a", "r.b"], "unscanned": {
            "skipped": [], "errors": [{"path": "src/a.py", "type": "PartialParsing", "spans": [[7, 9]], "file_lines": 10}]}})
        self.assertEqual(self.review(self.a)[0], "verified_fixed")

    def test_a_commit_rescan_never_moves_reviews(self):
        history.set_reviews(self.db, "acme/app", [self.key(self.a)], "fixed", "Fixed by escaping the input.", "me")
        covered = {"rule_ids": ["r.a", "r.b"], "unscanned": {"skipped": [], "errors": []}}
        directory = self.tmp / "rescan"
        directory.mkdir()
        path = write_findings(directory, [self.b], covered)
        found, meta, doc = history.read_inputs(path, check_output(summary([self.b])))
        info = history.RunInfo("acme/app", "main", "1" * 40, "scheduled", "2026-09-01T02:00:00Z")
        history.record_run(self.conn, info, found, meta, doc, review_transitions=False)
        self.assertEqual(self.review(self.a)[0], "fixed")
        # The fixed finding found again by a commit rescan is not a regression either.
        history.set_reviews(self.db, "acme/app", [self.key(self.b)], "fixed", "Fixed by removing the URL.", "me")
        history.record_run(self.conn, history.RunInfo("acme/app", "main", "1" * 40, "scheduled", "2026-09-01T02:00:00Z"),
                           found, meta, doc, review_transitions=False)
        self.assertEqual(self.review(self.b)[0], "fixed")

    def test_baseline_reasons_are_stored_per_run(self):
        from shoalscan.baseline import Entry

        c = finding("r.c", "src/c.py", "cc:0")
        entries = [Entry(self.a.tool, self.a.rule, self.a.path, self.a.fingerprint, "#4", "False positive: constant input"),
                   Entry(self.b.tool, self.b.rule, self.b.path, self.b.fingerprint, "#5", "Accepted: legacy module")]
        record(self.conn, self.tmp, "acme/app", "4" * 40, 22, [self.a, self.b, c], baseline=entries)
        rows = dict((r[0], (r[1], r[2])) for r in self.conn.execute(
            "SELECT fk.path, rf.baseline_issue, rf.baseline_reason FROM run_findings rf JOIN finding_keys fk ON fk.id = rf.key_id "
            "JOIN runs ON runs.id = rf.run_id WHERE runs.commit_sha = ?", ("4" * 40,)))
        self.assertEqual(rows, {"src/a.py": ("#4", "False positive: constant input"), "src/b.py": ("#5", "Accepted: legacy module"),
                                "src/c.py": (None, None)})
        data = Data(history.open_read_only(self.db))
        try:
            repo = data.repo_id("acme/app")
            run = data.resolve_run(repo, None)
            shown = {f["path"]: (f["review"]["status"], f["review"]["source"]) for f in data.findings(repo, run)["findings"]}
            self.assertEqual(shown, {"src/a.py": ("false_positive", "baseline"), "src/b.py": ("accepted_risk", "baseline"),
                                     "src/c.py": ("open", "none")})
            self.assertEqual([f["path"] for f in data.findings(repo, run, review="untriaged")["findings"]], ["src/c.py"])
            # A dashboard review wins over the baseline's reason.
            history.set_reviews(self.db, "acme/app", [self.key(self.b)], "wont_fix", "Kept deliberately for now.", "me")
            self.assertEqual(data.findings(repo, run, path="src/b.py")["findings"][0]["review"]["status"], "wont_fix")
        finally:
            data.conn.close()


class TriageExportTests(HistoryTestCase):
    def test_export_prints_a_valid_baseline_and_needs_an_issue(self):
        from shoalscan.baseline import baseline_from_bytes

        a, b, c = finding("r.a", "src/a.py", "aa:0"), finding("r.b", "src/b.py", "bb:0"), finding("r.c", "src/c.py", "cc:0")
        record(self.conn, self.tmp, "acme/app", "1" * 40, 1, [a, b, c])
        history.set_reviews(self.db, "acme/app", [[a.tool, a.rule, a.path, a.fingerprint]], "false_positive",
                            'Constant "input"\nnever from users.', "dashboard user (session 1234abcd)")
        history.set_reviews(self.db, "acme/app", [[b.tool, b.rule, b.path, b.fingerprint]], "fixed", "Escaped in the template.", "me")
        history.set_reviews(self.db, "acme/app", [[c.tool, c.rule, c.path, c.fingerprint]], "accepted_risk", "Internal tool only.", "me")

        def run(*args):
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = main(["triage", "export", "--repo", "acme/app", "--db", str(self.db), *args])
            return code, out.getvalue(), err.getvalue()

        code, _, err = run()
        self.assertEqual(code, 2)
        self.assertIn("--issue is required", err)
        self.assertEqual(run("--issue", "not an issue")[0], 2)
        code, out, err = run("--issue", "#77", "--suppressions")
        self.assertEqual(code, 0, err)
        entries = baseline_from_bytes(out.encode("utf-8"), "export")
        self.assertEqual([e.path for e in entries], ["src/a.py", "src/c.py"], "fixed findings are not exported")
        self.assertTrue(all(e.issue == "#77" for e in entries))
        resolved = self.conn.execute("SELECT resolved_at FROM finding_reviews WHERE path = 'src/a.py'").fetchone()[0]
        self.assertEqual(entries[0].reason, f'False positive: Constant "input" never from users. (reviewed in dashboard by dashboard user (session 1234abcd) on {resolved})')
        self.assertTrue(entries[1].reason.startswith("Accepted: Internal tool only."))
        self.assertIn('# "src/a.py" line 3:  # nosemgrep: r.a #77', out)
        self.assertIn("never change what blocks CI", err)


class TriageExportPathTests(HistoryTestCase):
    def test_a_newline_in_a_file_name_cannot_inject_lines(self):
        from shoalscan.baseline import baseline_from_bytes

        evil = finding("r.a", 'x.py\n[[finding]]\ntool = "forged"\n#', "ev:0")
        record(self.conn, self.tmp, "acme/app", "1" * 40, 1, [evil])
        history.set_reviews(self.db, "acme/app", [[evil.tool, evil.rule, evil.path, evil.fingerprint]], "wont_fix", "Kept on purpose for now.", "me")
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(["triage", "export", "--repo", "acme/app", "--issue", "#9", "--suppressions", "--db", str(self.db)]), 0)
        entries = baseline_from_bytes(out.getvalue().encode("utf-8"), "export")
        self.assertEqual([e.tool for e in entries], ["opengrep"])
        suppression_lines = out.getvalue().split("# Or, instead of baseline entries")[1].splitlines()[1:]
        self.assertTrue(suppression_lines and all(line.startswith("#") for line in suppression_lines), suppression_lines)


class MigrationToVersion10Tests(unittest.TestCase):
    def test_version_9_data_is_kept(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "h.sqlite3"
            conn = sqlite3.connect(db, isolation_level=None)
            conn.executescript("".join(history.MIGRATIONS[:9]) + "\nPRAGMA user_version = 9;")
            conn.close()
            conn = sqlite3.connect(db, isolation_level=None)
            conn.executescript(
                "INSERT INTO repos (id, name) VALUES (1, 'acme/v9');"
                "INSERT INTO runs (id, repo_id, kind, ref, commit_sha, scanned_at, recorded_at, result, findings, error, warning, info, "
                "nb_error, nb_warning, nb_info, new, new_blocking, new_non_blocking_paths, stale, baseline_size, baseline_additions, "
                "suppressions, suppressions_invalid, suppressed_findings, unscanned_skipped, unscanned_errored, changed_unscanned, "
                "scanners, content_sha256, outcome) VALUES (1, 1, 'scheduled', 'main', '" + "a" * 40 + "', '2026-09-01T00:00:00Z', "
                "'2026-09-01T00:00:00Z', 'pass', 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, '{}', 'x', 'passed');"
                "INSERT INTO finding_keys (id, repo_id, tool, rule, path, fingerprint) VALUES (1, 1, 'opengrep', 'r', 'a.py', 'f:0');"
                "INSERT INTO messages (id, sha256, text) VALUES (1, 'x', 'm');"
                "INSERT INTO run_findings (run_id, key_id, severity, line, component, message_id, is_new, new_blocking, blocking_class) "
                "VALUES (1, 1, 'ERROR', 1, 'api', 1, 0, 0, 1);"
                "INSERT INTO config_changes (who, changed_at, target, action, diff) VALUES ('me', '2026-09-01T00:00:00Z', 'acme/v9', 'create', '{}');"
            )
            conn.close()
            history.open_for_write(db).close()
            conn = sqlite3.connect(db)
            try:
                self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], history.SCHEMA_VERSION)
                self.assertEqual(conn.execute("SELECT severity, blocking_class, baseline_reason FROM run_findings").fetchall(), [("ERROR", 1, None)])
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0], 1)
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM config_changes").fetchone()[0], 1)
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM finding_reviews").fetchone()[0], 0)
            finally:
                conn.close()


class MigrationToVersion3Tests(unittest.TestCase):
    def test_old_runs_stay_readable_with_an_outcome(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "h.sqlite3"
            conn = sqlite3.connect(db, isolation_level=None)
            conn.executescript(history.MIGRATIONS[0] + history.MIGRATIONS[1] + "\nPRAGMA user_version = 2;")
            conn.execute("INSERT INTO repos (id, name) VALUES (1, 'acme/old')")
            cols = "repo_id, kind, ref, commit_sha, scanned_at, recorded_at, result, findings, error, warning, info, nb_error, nb_warning, nb_info, new, new_blocking, new_non_blocking_paths, stale, baseline_size, baseline_additions, suppressions, suppressions_invalid, suppressed_findings, unscanned_skipped, unscanned_errored, changed_unscanned, scanners, content_sha256"
            for n, result in ((1, "pass"), (2, "fail")):
                conn.execute(
                    f"INSERT INTO runs ({cols}) VALUES (1, 'scheduled', 'main', ?, ?, ?, ?, 0, 0, 0, 0, 0, 0, 0, 0, ?, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, '{{}}', 'x')",
                    (str(n) * 40, f"2026-09-0{n}T00:00:00Z", f"2026-09-0{n}T00:00:00Z", result, 3 if result == "fail" else 0),
                )
            conn.close()
            history.open_for_write(db).close()
            data = Data(history.open_read_only(db))
            try:
                runs = data.runs(1)["runs"]
                self.assertEqual([(r["outcome"], r["status"]["label"]) for r in runs],
                                 [("blocked", "Blocked: 3 new blocking findings"), ("passed", "Passed")])
                self.assertEqual(runs[0]["lists"], {"blocking": False, "new": False, "stale": False, "files": False, "suppressions": False})
            finally:
                data.conn.close()


if __name__ == "__main__":
    unittest.main()
