import tempfile
import unittest
from pathlib import Path

import helpers  # noqa: F401

from shoalscan import opengrep
from shoalscan.errors import ScanError
from shoalscan.findings import assign_fingerprints, enclosing_context, normalise_severity, split_lines


def item(line, code="eval(x)", path="a.py", rule="r"):
    return {"tool": "opengrep", "rule": rule, "path": path, "line": line, "code": code}


def result(path, line, start, end, rule="shoalscan.r", severity="ERROR", ignored=False, lines="x"):
    return {
        "check_id": rule,
        "path": str(path),
        "start": {"line": line, "col": 1, "offset": start},
        "end": {"line": line, "col": 1, "offset": end},
        "extra": {"severity": severity, "message": "msg", "lines": lines, "is_ignored": ignored},
    }


class FingerprintTests(unittest.TestCase):
    def test_stable_across_line_shifts(self):
        before = assign_fingerprints([item(3)])
        after = assign_fingerprints([item(40)])
        self.assertEqual(before, after)

    def test_whitespace_does_not_matter(self):
        self.assertEqual(
            assign_fingerprints([item(1, "eval( x )\n")]), assign_fingerprints([item(9, "eval(  x  )")])
        )

    def test_rule_code_and_context_matter_but_not_path(self):
        base = assign_fingerprints([item(1)])[0]
        self.assertNotEqual(base, assign_fingerprints([item(1, rule="other")])[0])
        self.assertNotEqual(base, assign_fingerprints([item(1, code="eval(y)")])[0])
        self.assertNotEqual(base, assign_fingerprints([{**item(1), "context": "def:run"}])[0])
        # The path is not hashed, so `baseline rename-path` can follow a move.
        self.assertEqual(base, assign_fingerprints([item(1, path="moved/b.py")])[0])

    def test_same_method_name_in_two_classes_is_told_apart(self):
        source = ["class A:", "    def run(self):", "        eval(x)", "class B:", "    def run(self):", "        eval(x)"]
        self.assertEqual(enclosing_context(source, 3), "class:A/def:run")
        self.assertEqual(enclosing_context(source, 6), "class:B/def:run")

    def test_lines_split_on_newline_only(self):
        text = "a = 1\x0c b = 2\r\nc\u2028d\n"
        self.assertEqual(split_lines(text), ["a = 1\x0c b = 2", "c\u2028d"])

    def test_identical_code_in_other_functions_is_independent(self):
        # Before contexts, removing the first of two identical matches shifted
        # the second from :1 to :0, so it looked new and the old entry stale.
        source = [
            "class Svc:",
            "    def first(self, x):",
            "        return eval(x)",
            "",
            "def second(x):",
            "    return eval(x)",
            "",
            "eval(z)",
        ]
        self.assertEqual(enclosing_context(source, 3), "class:Svc/def:first")
        self.assertEqual(enclosing_context(source, 2), "class:Svc")
        self.assertEqual(enclosing_context(source, 6), "def:second")
        self.assertEqual(enclosing_context(source, 8), "")
        both = assign_fingerprints(
            [{**item(3, "eval(x)"), "context": "def:first"}, {**item(6, "eval(x)"), "context": "def:second"}]
        )
        only_second = assign_fingerprints([{**item(2, "eval(x)"), "context": "def:second"}])
        self.assertEqual(both[1], only_second[0])
        rust = ["impl Client {", "    pub async fn connect(&self) {", "        danger(true);", "    }", "}"]
        self.assertEqual(enclosing_context(rust, 3), "impl:Client/fn:connect")
        js = ["export default async function load() {", "  fetch(u);", "}"]
        self.assertEqual(enclosing_context(js, 2), "function:load")

    def test_identical_matches_get_occurrence_suffix_in_line_order(self):
        prints = assign_fingerprints([item(20), item(5)])
        self.assertTrue(prints[1].endswith(":0"))
        self.assertTrue(prints[0].endswith(":1"))
        self.assertEqual(prints[0].split(":")[0], prints[1].split(":")[0])

    def test_severity_mapping(self):
        self.assertEqual(normalise_severity("ERROR"), "ERROR")
        self.assertEqual(normalise_severity("high"), "ERROR")
        self.assertEqual(normalise_severity("MEDIUM"), "WARNING")
        self.assertEqual(normalise_severity("INFO"), "INFO")
        self.assertEqual(normalise_severity("LOW"), "INFO")
        # Unknown severities are treated as the most severe, never dropped.
        self.assertEqual(normalise_severity("SOMETHING"), "ERROR")
        self.assertEqual(normalise_severity(None), "ERROR")


class NormaliseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        (self.root / "src").mkdir()
        self.file = self.root / "src" / "a.py"
        self.file.write_bytes(b"import os\nx = eval(data)\n")

    def tearDown(self):
        self.tmp.cleanup()

    def test_normalise_relative_paths_components_and_code(self):
        start = self.file.read_bytes().index(b"eval")
        doc = {"results": [result(self.file, 2, start, start + len("eval(data)"))], "errors": []}
        findings, index = opengrep.normalise(doc, self.root, {"src": "app"})
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual((f.tool, f.rule, f.path, f.line, f.component), ("opengrep", "shoalscan.r", "src/a.py", 2, "app"))
        expected = assign_fingerprints([{"tool": "opengrep", "rule": "shoalscan.r", "path": "src/a.py", "line": 2, "code": "eval(data)", "context": ""}])
        self.assertEqual(f.fingerprint, expected[0])
        self.assertEqual(index[("shoalscan.r", "src/a.py", 2, 1)], f.fingerprint)

    def test_ignored_results_are_not_findings(self):
        doc = {"results": [result(self.file, 2, 0, 4, ignored=True)], "errors": []}
        findings, _ = opengrep.normalise(doc, self.root, {})
        self.assertEqual(findings, [])
        self.assertEqual(opengrep.ignored_count(doc), 1)

    def test_path_outside_target_fails(self):
        doc = {"results": [result("/etc/passwd", 1, 0, 1)], "errors": []}
        with self.assertRaises(ScanError):
            opengrep.normalise(doc, self.root, {})

    def test_malformed_result_fails(self):
        with self.assertRaises(ScanError):
            opengrep.normalise({"results": [{"check_id": "x"}], "errors": []}, self.root, {})

    def test_unscanned_files(self):
        doc = {
            "results": [],
            "errors": [
                {
                    "level": "warn",
                    "type": ["PartialParsing", [{"path": str(self.file)}]],
                    "path": str(self.file),
                    "spans": [{"start": {"line": 2}, "end": {"line": 2}}],
                },
                {"level": "warn", "type": "Timeout", "path": str(self.file)},
            ],
            "paths": {
                "skipped": [
                    {"path": str(self.root / "big.py"), "reason": "exceeded_size_limit"},
                    {"path": str(self.root / "vendor" / "x.py"), "reason": "cli_exclude_flags_match"},
                    {"path": str(self.file), "reason": "analysis_failed_parser_or_internal_error"},
                    {"path": str(self.root / "other.py"), "reason": "analysis_failed_parser_or_internal_error"},
                ]
            },
        }
        found = opengrep.unscanned(doc, self.root)
        self.assertEqual(
            found["skipped"],
            [{"path": "big.py", "reason": "exceeded_size_limit"}, {"path": "other.py", "reason": "analysis_failed_parser_or_internal_error"}],
        )
        self.assertEqual(
            found["errors"],
            [
                {"path": "src/a.py", "type": "PartialParsing", "spans": [[2, 2]], "file_lines": 2},
                {"path": "src/a.py", "type": "Timeout"},
            ],
        )

    def test_error_entries(self):
        warn = {"level": "warn", "type": "Syntax error", "message": "partial"}
        self.assertEqual(opengrep.check_errors({"errors": [warn]}), [warn])
        with self.assertRaises(ScanError):
            opengrep.check_errors({"errors": [warn, {"level": "error", "type": "Rule parse error", "message": "bad"}]})
        # An entry without a level is treated as an error.
        with self.assertRaises(ScanError):
            opengrep.check_errors({"errors": [{"message": "something"}]})


if __name__ == "__main__":
    unittest.main()
