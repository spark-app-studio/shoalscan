import json
import tempfile
import tomllib
import unittest
from pathlib import Path

import helpers  # noqa: F401

from shoalscan.baseline import (
    Entry,
    entries_from_findings,
    load_baseline,
    parse_baseline,
    rename_path,
    render_baseline,
    write_baseline,
)
from shoalscan.check import SUMMARY_PREFIX, compare, details, render_report, summary, summary_line
from shoalscan.errors import SetupError
from shoalscan.findings import Finding


def finding(rule="r1", severity="ERROR", path="a.py", fp="f1:0", component="app"):
    return Finding("opengrep", rule, severity, path, 3, fp, component, "message")


def entry(f: Finding, issue="#1", reason="known"):
    return Entry(f.tool, f.rule, f.path, f.fingerprint, issue, reason)


BLOCKING = ("ERROR", "WARNING")


class CompareTests(unittest.TestCase):
    def test_known_findings_pass(self):
        f = finding()
        result = compare([f], [entry(f)], BLOCKING)
        self.assertTrue(result.passed)
        self.assertEqual(result.new, [])

    def test_new_blocking_finding_fails(self):
        known = finding()
        new = finding(rule="r2", severity="WARNING", fp="f2:0")
        result = compare([known, new], [entry(known)], BLOCKING)
        self.assertFalse(result.passed)
        self.assertEqual(result.new_blocking, [new])

    def test_new_info_finding_never_blocks(self):
        info = finding(rule="r3", severity="INFO", fp="f3:0")
        result = compare([info], [], BLOCKING)
        self.assertTrue(result.passed)
        self.assertEqual(result.new, [info])
        # Even a configuration that names INFO cannot make it block.
        self.assertTrue(compare([info], [], ("ERROR", "WARNING", "INFO")).passed)

    def test_non_blocking_severity_reported_not_failing(self):
        warn = finding(severity="WARNING")
        result = compare([warn], [], ("ERROR",))
        self.assertTrue(result.passed)
        self.assertEqual(len(result.new), 1)

    def test_non_blocking_paths_report_but_never_fail(self):
        demo = finding(path="demo/app.py", fp="d:0")
        demo_dir = finding(path="demo", fp="dd:0")
        lookalike = finding(path="demonstration/app.py", fp="x:0")
        result = compare([demo, demo_dir], [], BLOCKING, non_blocking_paths=("demo",))
        self.assertTrue(result.passed)
        self.assertEqual(len(result.new), 2)
        self.assertIn("New findings in non-blocking paths (2)", render_report(result))
        data = json.loads(summary_line(result)[len(SUMMARY_PREFIX) :])
        self.assertEqual(data["new_in_non_blocking_paths"], 2)
        self.assertEqual(data["by_severity_non_blocking_paths"], {"ERROR": 2, "WARNING": 0, "INFO": 0})
        self.assertFalse(compare([lookalike], [], BLOCKING, non_blocking_paths=("demo/",)).passed)
        # A stale entry still fails inside a non-blocking path.
        self.assertFalse(compare([], [entry(demo)], BLOCKING, non_blocking_paths=("demo",)).passed)

    def test_baseline_additions_against_base_fail(self):
        f = finding()
        base = [entry(f)]
        self.assertTrue(compare([f], [entry(f)], BLOCKING, base_baseline=base).passed)
        self.assertTrue(compare([], [], BLOCKING, base_baseline=base).passed)
        added = compare([f, finding(fp="n:0")], [entry(f), entry(finding(fp="n:0"))], BLOCKING, base_baseline=base)
        self.assertFalse(added.passed)
        self.assertEqual(len(added.baseline_additions), 1)
        changed = compare([f], [entry(f, reason="other")], BLOCKING, base_baseline=base)
        self.assertFalse(changed.passed)

    def test_changed_unscanned_files_fail_unless_excluded(self):
        unscanned = {
            "skipped": [{"path": "big.py", "reason": "exceeded_size_limit"}],
            "errors": [{"path": "gen/x.py", "type": "Timeout"}],
        }
        self.assertTrue(compare([], [], BLOCKING, unscanned=unscanned).passed)
        self.assertTrue(compare([], [], BLOCKING, unscanned=unscanned, changed_files=["other.py"]).passed)
        failing = compare([], [], BLOCKING, unscanned=unscanned, changed_files=["big.py", "gen/x.py"])
        self.assertFalse(failing.passed)
        self.assertEqual(len(failing.changed_unscanned), 2)
        self.assertIn("Changed files that were not fully scanned", render_report(failing))
        excluded = compare(
            [], [], BLOCKING, unscanned=unscanned, changed_files=["big.py", "gen/x.py"], excludes=("gen", "big.py")
        )
        self.assertTrue(excluded.passed)
        self.assertEqual(excluded.excluded_changed, ["big.py", "gen/x.py"])
        self.assertIn("CHANGED BUT NOT SCANNED", render_report(excluded))

    def test_partial_parsing_fails_only_near_added_lines_or_when_large(self):
        def unscanned(spans, lines=100, kind="PartialParsing"):
            return {"skipped": [], "errors": [{"path": "a.js", "type": kind, "spans": spans, "file_lines": lines}]}

        def run(u, added):
            return compare([], [], BLOCKING, unscanned=u, changed_files=["a.js"], added_lines=lambda p: added)

        small_away = run(unscanned([[10, 12]]), {50, 51})
        self.assertTrue(small_away.passed)
        self.assertEqual(len(small_away.partial_warnings), 1)
        self.assertIn("small parse gaps", render_report(small_away))
        self.assertFalse(run(unscanned([[10, 12]]), {11}).passed)
        self.assertFalse(run(unscanned([[1, 60]]), {90}).passed)
        for kind in ("Timeout", "OutOfMemory", "Other syntax error"):
            self.assertFalse(run(unscanned([], kind=kind), set()).passed, kind)
        big = {"skipped": [{"path": "a.js", "reason": "exceeded_size_limit"}], "errors": []}
        self.assertFalse(run(big, set()).passed)

    def test_parse_warn_only_turns_partial_parsing_into_a_warning(self):
        # A Dockerfile whose experimental parser left 70% unparsed, over the added lines.
        dockerfile = {
            "path": "services/api/Dockerfile",
            "type": "PartialParsing",
            "spans": [[1, 70]],
            "file_lines": 100,
        }
        unscanned = {"skipped": [], "errors": [dockerfile]}

        def run(u, warn_only=()):
            return compare(
                [],
                [],
                BLOCKING,
                unscanned=u,
                changed_files=["services/api/Dockerfile"],
                added_lines=lambda p: {5, 6},
                parse_warn_only=warn_only,
            )

        self.assertFalse(run(unscanned).passed)
        warned = run(unscanned, ("**/Dockerfile",))
        self.assertTrue(warned.passed)
        self.assertEqual(warned.changed_unscanned, [])
        self.assertEqual(len(warned.partial_warn_only), 1)
        report = render_report(warned)
        self.assertIn(
            "PARTIALLY PARSED (warn-only by policy): services/api/Dockerfile \u2014 70% unparsed, overlaps added "
            "lines: yes",
            report,
        )
        self.assertEqual(summary(warned)["unscanned"]["changed_partially_parsed_warn_only"], 1)
        # A glob that does not match the file changes nothing.
        self.assertFalse(run(unscanned, ("*.sh",)).passed)
        # A skipped file, or an error that is not PartialParsing, still fails.
        skipped = {"skipped": [{"path": "services/api/Dockerfile", "reason": "exceeded_size_limit"}], "errors": []}
        self.assertFalse(run(skipped, ("**/Dockerfile",)).passed)
        for kind in ("Timeout", "OutOfMemory"):
            other = {"skipped": [], "errors": [{**dockerfile, "type": kind}]}
            self.assertFalse(run(other, ("**/Dockerfile",)).passed, kind)

    def test_parse_warn_only_covers_whole_file_syntax_errors_of_templates(self):
        template = "deploy/chart/templates/deployment.yaml"

        def run(errors=(), skipped=(), warn_only=("deploy/**/templates/*.yaml",)):
            unscanned = {"skipped": list(skipped), "errors": list(errors)}
            return compare(
                [],
                [],
                BLOCKING,
                unscanned=unscanned,
                changed_files=[template],
                added_lines=lambda p: {3},
                parse_warn_only=warn_only,
            )

        syntax = {"path": template, "type": "Other syntax error"}
        warned = run([syntax])
        self.assertTrue(warned.passed)
        self.assertEqual(len(warned.syntax_warn_only), 1)
        self.assertIn(f"SYNTAX ERROR (warn-only by policy): {template}", render_report(warned))
        self.assertEqual(summary(warned)["unscanned"]["changed_syntax_error_warn_only"], 1)
        self.assertTrue(run([{"path": template, "type": "Syntax error"}]).passed)
        # Not listed: it fails. A timeout, running out of memory or a skip still fail when listed.
        self.assertFalse(run([syntax], warn_only=()).passed)
        for kind in ("Timeout", "OutOfMemory", "Fatal error"):
            self.assertFalse(run([{"path": template, "type": kind}]).passed, kind)
        self.assertFalse(run(skipped=[{"path": template, "reason": "exceeded_size_limit"}]).passed)

    def test_parse_warn_only_matches_file_names_not_directories(self):
        def gap(path):
            return {
                "skipped": [],
                "errors": [{"path": path, "type": "PartialParsing", "spans": [[1, 90]], "file_lines": 100}],
            }

        def passes(path, globs):
            return compare(
                [],
                [],
                BLOCKING,
                unscanned=gap(path),
                changed_files=[path],
                added_lines=lambda p: {1},
                parse_warn_only=globs,
            ).passed

        self.assertTrue(passes("deploy/run.sh", ("*.sh",)))
        # A directory named like the glob does not make the Python file in it warn-only.
        self.assertFalse(passes("tools.sh/main.py", ("*.sh",)))
        self.assertFalse(passes("Dockerfile/app.py", ("Dockerfile",)))
        self.assertTrue(passes("services/api/Dockerfile.prod", ("Dockerfile.*",)))
        self.assertTrue(passes("deploy/charts/app/templates/svc.yaml", ("deploy/**/templates/*.yaml",)))
        self.assertFalse(passes("other/templates/svc.yaml", ("deploy/**/templates/*.yaml",)))

    def test_details_list_what_the_summary_counts(self):
        a, b = finding(path="src/a.py", fp="a:0"), finding(path="src/b.py", fp="b:0", severity="INFO")
        gone = Entry("opengrep", "r", "src/gone.py", "g:0", "#7", "accepted")
        result = compare([a, b], [gone], BLOCKING)
        doc = details(result, "f" * 64)
        self.assertEqual(doc["findings_sha256"], "f" * 64)
        self.assertEqual(doc["new"], [[a.tool, a.rule, "src/a.py", "a:0"], [b.tool, b.rule, "src/b.py", "b:0"]])
        self.assertEqual(doc["new_blocking"], [[a.tool, a.rule, "src/a.py", "a:0"]])
        self.assertEqual(
            doc["stale"],
            [
                {
                    "tool": "opengrep",
                    "rule": "r",
                    "path": "src/gone.py",
                    "fingerprint": "g:0",
                    "issue": "#7",
                    "reason": "accepted",
                }
            ],
        )
        self.assertEqual(doc["summary"], summary(result))
        self.assertEqual(doc["result"], "fail")

    def test_details_mark_the_blocking_class_whether_baselined_or_not(self):
        accepted = finding(path="src/old.py", fp="o:0", severity="WARNING")
        new = finding(path="src/new.py", fp="n:0")
        info = finding(path="src/i.py", fp="i:0", severity="INFO")
        demo = finding(path="demo/x.py", fp="d:0")
        result = compare([accepted, new, info, demo], [entry(accepted)], BLOCKING, non_blocking_paths=("demo/",))
        doc = details(result, "0" * 64)
        self.assertEqual([k[2] for k in doc["blocking_class"]], ["src/new.py", "src/old.py"])
        self.assertEqual([k[2] for k in doc["new_blocking"]], ["src/new.py"])
        self.assertEqual(doc["blocking"], list(BLOCKING))
        self.assertEqual(doc["non_blocking_paths"], ["demo/"])
        # With only ERROR blocking, the accepted WARNING is not in the class.
        only_error = details(compare([accepted, new], [entry(accepted)], ("ERROR",)), "0" * 64)
        self.assertEqual([k[2] for k in only_error["blocking_class"]], ["src/new.py"])

    def test_pure_move_is_allowed_and_reported(self):
        a = finding(path="src/a.py", fp="a:0")
        moved = Entry(a.tool, a.rule, "src/b.py", a.fingerprint, "#1", "known")
        base = [entry(a)]
        ok = compare([], [moved], BLOCKING, base_baseline=base, renames=[("src/a.py", "src/b.py")])
        self.assertEqual((ok.baseline_additions, len(ok.moves)), ([], 1))
        self.assertIn("BASELINE MOVES", render_report(ok))
        # No rename reported by git: an addition.
        self.assertTrue(compare([], [moved], BLOCKING, base_baseline=base, renames=[]).baseline_additions)
        # Changed reason on the way: an addition.
        changed = Entry(a.tool, a.rule, "src/b.py", a.fingerprint, "#1", "other")
        self.assertTrue(
            compare([], [changed], BLOCKING, base_baseline=base, renames=[("src/a.py", "src/b.py")]).baseline_additions
        )
        # Into another component, or out of a non-blocking path: an addition.
        self.assertTrue(
            compare(
                [],
                [moved],
                BLOCKING,
                base_baseline=base,
                renames=[("src/a.py", "src/b.py")],
                components={"src/b.py": "x"},
            ).baseline_additions
        )
        self.assertTrue(
            compare(
                [],
                [moved],
                BLOCKING,
                base_baseline=base,
                renames=[("src/a.py", "src/b.py")],
                non_blocking_paths=("src/a.py",),
            ).baseline_additions
        )
        # Only part of the entries moved: an addition.
        a2 = finding(path="src/a.py", fp="a2:0")
        self.assertTrue(
            compare(
                [], [moved], BLOCKING, base_baseline=base + [entry(a2)], renames=[("src/a.py", "src/b.py")]
            ).baseline_additions
        )

    def test_stale_entry_fails(self):
        gone = finding(fp="gone:0")
        result = compare([], [entry(gone)], BLOCKING)
        self.assertFalse(result.passed)
        self.assertEqual(len(result.stale), 1)

    def test_summary_line(self):
        a = finding()
        b = finding(rule="r2", severity="INFO", fp="b:0", component="web")
        result = compare([a, b], [entry(a), entry(finding(fp="old:0"))], BLOCKING, {"total": 2, "invalid": 0})
        line = summary_line(result)
        self.assertTrue(line.startswith(SUMMARY_PREFIX))
        self.assertNotIn("\n", line)
        data = json.loads(line[len(SUMMARY_PREFIX) :])
        self.assertEqual(data["result"], "fail")
        self.assertEqual(data["by_severity"], {"ERROR": 1, "WARNING": 0, "INFO": 1})
        self.assertEqual(data["by_component"], {"app": 1, "web": 1})
        self.assertEqual(data["by_rule"], {"r1": 1, "r2": 1})
        self.assertEqual((data["new"], data["new_blocking"], data["stale"], data["baseline_size"]), (1, 0, 1, 2))
        self.assertEqual(data["suppressions"], {"total": 2, "invalid": 0})
        self.assertIn("Stale baseline entries (1)", render_report(result))


class BaselineFileTests(unittest.TestCase):
    def test_render_is_sorted_deterministic_and_round_trips(self):
        findings = [finding(path="z.py", fp="z:0"), finding(path="a.py", fp="a:0"), finding(path="a.py", fp="a:0")]
        entries = entries_from_findings(findings, "#12", 'accepted "for now"\nsee issue')
        text = render_baseline(entries)
        self.assertEqual(text, render_baseline(list(reversed(entries))))
        parsed = parse_baseline(tomllib.loads(text))
        self.assertEqual([e.path for e in parsed], ["a.py", "z.py"])
        self.assertEqual(parsed[0].reason, 'accepted "for now"\nsee issue')

    def test_issue_must_be_reference_or_url(self):
        for issue in ("#12", "https://tracker.example.org/browse/SEC-1"):
            entries_from_findings([finding()], issue, "r")
        for issue in ("12", "SEC-1", "", "ftp://x"):
            with self.subTest(issue=issue), self.assertRaises(SetupError):
                entries_from_findings([finding()], issue, "r")
        with self.assertRaises(SetupError):
            entries_from_findings([finding()], "#1", "  ")

    def test_strict_parsing(self):
        good = {"tool": "opengrep", "rule": "r", "path": "a", "fingerprint": "f", "issue": "#1", "reason": "x"}
        parse_baseline({"version": 1, "finding": [good]})
        bad_cases = [
            {"finding": [{**good, "severity": "ERROR"}]},
            {"finding": [{k: v for k, v in good.items() if k != "reason"}]},
            {"finding": [{**good, "issue": "none"}]},
            {"finding": [good, dict(good)]},
            {"findings": [good]},
            {"version": 2, "finding": [good]},
        ]
        for data in bad_cases:
            with self.subTest(data=data), self.assertRaises(SetupError):
                parse_baseline(data)

    def test_write_refuses_overwrite_without_force(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sub" / "baseline.toml"
            write_baseline(path, entries_from_findings([finding()], "#1", "r"), force=False)
            self.assertEqual(len(load_baseline(path)), 1)
            with self.assertRaises(SetupError):
                write_baseline(path, [], force=False)
            write_baseline(path, [], force=True)
            self.assertEqual(load_baseline(path), [])

    def test_rename_path(self):
        a, b, c = (
            finding(path="src/a.py", fp="a:0"),
            finding(path="src/sub/b.py", fp="b:0"),
            finding(path="srcx/c.py", fp="c:0"),
        )
        entries = [entry(a), entry(b), entry(c)]
        renamed, changed = rename_path(entries, "src/a.py", "lib/a.py")
        self.assertEqual((changed, [e.path for e in renamed]), (1, ["lib/a.py", "src/sub/b.py", "srcx/c.py"]))
        renamed, changed = rename_path(entries, "src/", "pkg")
        self.assertEqual((changed, [e.path for e in renamed]), (2, ["pkg/a.py", "pkg/sub/b.py", "srcx/c.py"]))
        with self.assertRaises(SetupError):
            rename_path(entries, "../x", "y")
        with self.assertRaises(SetupError):
            rename_path([entry(a), entry(finding(path="lib/a.py", fp="a:0"))], "src/a.py", "lib/a.py")

    def test_missing_baseline_is_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(load_baseline(Path(tmp) / "nope.toml"))


if __name__ == "__main__":
    unittest.main()
