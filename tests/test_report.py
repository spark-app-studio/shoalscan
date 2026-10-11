"""`shoalscan report`: the dated security report built from the run history."""

import contextlib
import io
import json
import tempfile
import unittest
from datetime import date
from pathlib import Path
from unittest import mock

import helpers  # noqa: F401 - puts src/ on the import path
from history_fixtures import MALICIOUS, finding, record, sample_history

from shoalscan import history, report
from shoalscan.baseline import Entry
from shoalscan.cli import main
from shoalscan.dashboard.data import Data
from shoalscan.errors import SetupError

B_KEY = ("opengrep", "shoalscan.plain-http-url", "web/b.js", "bbbb:0")
GENERATED = "2026-10-11T12:00:00Z"


def quiet(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


class PeriodTests(unittest.TestCase):
    TODAY = date(2026, 10, 11)

    def test_defaults_to_thirty_days_ending_today(self):
        self.assertEqual(report.period(None, None, self.TODAY), (date(2026, 9, 12), date(2026, 10, 11)))
        self.assertEqual(report.period(None, "2026-09-30", self.TODAY), (date(2026, 9, 1), date(2026, 9, 30)))
        self.assertEqual(report.period("2026-09-05", "2026-09-05", self.TODAY), (date(2026, 9, 5), date(2026, 9, 5)))

    def test_a_period_is_at_most_366_days(self):
        self.assertEqual(report.period("2025-10-01", "2026-10-01", self.TODAY), (date(2025, 10, 1), date(2026, 10, 1)))
        with self.assertRaises(SetupError):
            report.period("2025-09-30", "2026-10-01", self.TODAY)

    def test_refuses_bad_periods(self):
        for since, until in (
            ("2026-9-5", None),
            ("2026-02-30", None),
            ("yesterday", None),
            ("2026-10-01", "2026-09-01"),
            ("2010-01-01", "2026-01-01"),
            (None, "2026-09-30T00:00:00Z"),
        ):
            with self.assertRaises(SetupError, msg=(since, until)):
                report.period(since, until, self.TODAY)


class HistoryCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.db = self.dir / "history.sqlite3"
        conn = history.open_for_write(self.db)
        try:
            sample_history(conn, self.dir)
            self.prepare(conn)
            conn.commit()
        finally:
            conn.close()

    def prepare(self, conn):
        pass

    def tearDown(self):
        self.tmp.cleanup()

    def build(self, first="2026-09-05", last="2026-09-30", repo="acme/app"):
        conn = history.open_read_only(self.db)
        try:
            return report.build(conn, repo, date.fromisoformat(first), date.fromisoformat(last), GENERATED)
        finally:
            conn.close()


class BuildTests(HistoryCase):
    def prepare(self, conn):
        # One review inside the period and one after it.
        history._change_review(
            conn,
            "acme/app",
            B_KEY,
            "false_positive",
            "Only an example URL in docs",
            "alice",
            None,
            "2026-09-20T10:00:00Z",
        )
        history._change_review(
            conn, "acme/app", B_KEY, "accepted_risk", "Changed our mind later on", "bob", None, "2026-10-05T10:00:00Z"
        )

    def test_start_end_and_changes(self):
        doc = self.build()
        self.assertEqual(doc["start"]["scanned_at"], "2026-09-01T02:00:00Z")
        self.assertEqual(doc["end"]["scanned_at"], "2026-09-22T02:00:00Z")
        self.assertEqual(doc["end"]["by_severity"], {"ERROR": 1, "WARNING": 1, "INFO": 1})
        ch = doc["changes"]
        self.assertEqual((ch["new"]["total"], ch["fixed"]["total"]), (2, 2))
        self.assertEqual([f["path"] for f in ch["fixed"]["findings"]], ["src/d.py", "src/a.py"])
        # A was open 14 days (09-01 to 09-15), D 7 days (09-01 to 09-08); D's return on 09-22 is a new episode.
        self.assertEqual(ch["time_to_fix"], {"fixed": 2, "mean_days": 10.5, "median_days": 10.5})
        self.assertEqual(
            [w["week"] for w in ch["weekly"]], ["2026-08-31", "2026-09-07", "2026-09-14", "2026-09-21", "2026-09-28"]
        )
        self.assertEqual(sum(w["new"] for w in ch["weekly"]), 2)

    def test_a_period_after_the_first_run_counts_fixes_from_the_real_start(self):
        ch = self.build(first="2026-09-10")["changes"]
        self.assertEqual(ch["fixed"]["total"], 1)
        self.assertEqual(ch["time_to_fix"]["mean_days"], 14.0)

    def test_blocking_baseline_and_reviews(self):
        doc = self.build()
        self.assertEqual(doc["blocking"], {"total": 2, "new": 2, "baselined": 0})
        self.assertEqual(doc["baselined"]["total"], 1)
        self.assertEqual(doc["baselined"]["reasons"][0]["issue"], "#1")
        self.assertEqual(doc["reviews_now"]["untriaged_blocking"], 1)
        rv = doc["reviews"]
        self.assertEqual(rv["now"]["accepted_risk"], 1)  # the current status, whenever it was set
        self.assertEqual(rv["changes"]["total"], 1)  # only the change inside the period
        self.assertEqual(rv["changes"]["items"][0]["who"], "alice")

    def test_runs_in_the_period(self):
        runs = self.build()["runs"]
        self.assertEqual(sum(runs["by_kind"]["scheduled"].values()), 3)
        self.assertEqual(runs["by_kind"]["pr"]["passed"], 1)
        self.assertEqual(runs["deleted"], 0)

    def test_scanners_and_components(self):
        doc = self.build()
        self.assertEqual(doc["scanners"]["opengrep"]["version"], "1.30.2")
        self.assertEqual([c["component"] for c in doc["components"]], ["api", "web"])

    def test_unknown_repository(self):
        with self.assertRaises(SetupError):
            self.build(repo="acme/missing")

    def test_a_period_without_runs(self):
        doc = self.build(first="2026-08-01", last="2026-08-20")
        self.assertIsNone(doc["end"])
        self.assertIsNone(doc["start"])
        self.assertIn("No scan with results was recorded in this period", report.render_markdown(doc))

    def test_refuses_a_period_longer_than_the_walk(self):
        # Three trend runs in the period and one before it need a walk of four.
        with mock.patch("shoalscan.dashboard.data.MAX_TREND_RUNS", 3):
            with self.assertRaisesRegex(SetupError, "more trend runs than a report can walk"):
                self.build()
        with mock.patch("shoalscan.dashboard.data.MAX_TREND_RUNS", 4):
            self.assertEqual(self.build()["changes"]["fixed"]["total"], 2)

    def test_untriaged_is_unknown_when_blocking_is(self):
        doc = self.build(first="2026-09-10", last="2026-09-16")  # ends with a run recorded without check details
        self.assertIsNone(doc["blocking"])
        out = report.render_markdown(doc)
        self.assertIn("- Blocking findings: unknown for this run", out)
        self.assertIn("- Untriaged blocking findings: unknown;", out)

    def test_listing_is_cut_but_counts_are_not(self):
        conn = history.open_read_only(self.db)
        try:
            data = Data(conn)
            p = data.period(data.repo_id("acme/app"), "2026-09-01T00:00:00Z", "2026-09-30T23:59:59Z", limit=1)
        finally:
            conn.close()
        self.assertEqual(p["fixed"]["total"], 2)
        self.assertEqual(len(p["fixed"]["findings"]), 1)


class BaselineKindsTests(HistoryCase):
    def prepare(self, conn):
        fp = finding("community.python.eval", "src/z.py", "zzzz:0", "ERROR", "api")
        ok = finding("shoalscan.tls-off", "src/y.py", "yyyy:0", "WARNING", "api")
        base = [
            Entry(fp.tool, fp.rule, fp.path, fp.fingerprint, "#4", "False positive: test fixture only"),
            Entry(ok.tool, ok.rule, ok.path, ok.fingerprint, "#5", "Accepted: internal network, see #5"),
        ]
        record(conn, self.dir, "acme/app", "7" * 40, 29, [fp, ok], baseline=base)
        history.delete_run(conn, "acme/app", 3)

    def test_baseline_reasons_are_classified(self):
        doc = self.build()
        self.assertEqual(doc["baselined"]["by_kind"], {"false_positive": 1, "accepted_risk": 1, "baselined": 0})
        self.assertEqual({r["kind"] for r in doc["baselined"]["reasons"]}, {"false_positive", "accepted_risk"})

    def test_deleted_runs_are_reported(self):
        doc = self.build()
        self.assertEqual(doc["runs"]["deleted"], 1)
        self.assertIn("1 run scanned in the period was later deleted from the history", report.render_markdown(doc))


class HostileTextTests(HistoryCase):
    def prepare(self, conn):
        bad = finding("shoalscan.x", "src/<img src=x>.py", "hhhh:0", "ERROR", MALICIOUS[:60])
        record(
            conn,
            self.dir,
            "acme/app",
            "8" * 40,
            25,
            [bad],
            baseline=[Entry(bad.tool, bad.rule, bad.path, bad.fingerprint, "#6", MALICIOUS + "\n# heading")],
        )
        history._change_review(
            conn, "acme/app", B_KEY, "wont_fix", MALICIOUS + "\n## injected", MALICIOUS, None, "2026-09-26T00:00:00Z"
        )

    def test_values_from_the_repository_stay_text(self):
        out = report.render_markdown(self.build())
        self.assertIn("\\<script\\>alert(2)", out)
        self.assertNotIn("\n# heading", out)
        self.assertNotIn("\n## injected", out)
        # Raw < appears only inside code spans (paths) and in our own links.
        for line in out.splitlines():
            stripped = line
            while "`" in stripped:
                head, _, rest = stripped.partition("`")
                _, _, stripped = rest.partition("`")
                stripped = head + stripped
            self.assertNotRegex(stripped.replace("](<https://", ""), r"(?<!\\)<", line)


class CommandTests(HistoryCase):
    def cli(self, *extra):
        return quiet(
            [
                "report",
                "--db",
                str(self.db),
                "--repo-name",
                "acme/app",
                "--since",
                "2026-09-05",
                "--until",
                "2026-09-30",
                *extra,
            ]
        )

    def test_markdown_report(self):
        code, out, err = self.cli()
        self.assertEqual(code, 0, err)
        self.assertTrue(out.startswith("# Security report: acme/app\n"))
        self.assertIn("**Period:** 2026-09-05 to 2026-09-30 (UTC).", out)
        for heading in (
            "## Summary",
            "## Trend",
            "## Fixed in the period (2)",
            "## New in the period (2)",
            "## Accepted risks and false positives",
            "## Components",
            "## Coverage",
            "## Limits",
        ):
            self.assertIn(heading, out)
        self.assertIn("| ERROR | 2 | 1 | −1 |", out)

    def test_json_report_to_a_file(self):
        target = self.dir / "report.json"
        code, out, err = self.cli("--format", "json", "--output", str(target))
        self.assertEqual(code, 0, err)
        self.assertEqual(out, "")
        self.assertIn("wrote the report on acme/app for 2026-09-05 to 2026-09-30", err)
        doc = json.loads(target.read_text())
        self.assertEqual(doc["format"], report.FORMAT)
        self.assertEqual(doc["period"], {"first_day": "2026-09-05", "last_day": "2026-09-30"})

    def test_errors_exit_2(self):
        self.assertEqual(quiet(["report", "--db", str(self.db), "--repo-name", "nope/nope"])[0], 2)
        self.assertEqual(quiet(["report", "--db", str(self.dir / "missing.db"), "--repo-name", "acme/app"])[0], 2)
        self.assertEqual(self.cli("--since", "2026-10-01")[0], 2)


if __name__ == "__main__":
    unittest.main()
