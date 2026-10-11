import tempfile
import unittest
from pathlib import Path

import helpers  # noqa: F401

from shoalscan.errors import SetupError
from shoalscan.excludes import ExcludeMatcher
from shoalscan.suppressions import LINT_RULE, Suppression, find_suppressions, lint_findings, parse_line

# Spelled in pieces: Opengrep treats any line that contains a marker as a
# suppression, so this test file must not carry one literally.
NS = "no" + "semgrep"
NSEM = "no" + "sem"
NOG = "no" + "opengrep"


class ParseLineTests(unittest.TestCase):
    def test_valid_forms(self):
        cases = {
            f"x = 1  # {NS}: shoalscan.plain-http-url #42 test double": (("shoalscan.plain-http-url",), "#42"),
            f"// {NS}: a.b, c.d https://tracker.example.org/1": (("a.b", "c.d"), "https://tracker.example.org/1"),
            f"# {NOG}: rule-x #7": (("rule-x",), "#7"),
            f"# {NS.upper()}:rule-x #7": (("rule-x",), "#7"),
            f"# {NS}=rule-x #7": (("rule-x",), "#7"),
            f'<div data-x="{NS}: "rule-x" #7">': (("rule-x",), "#7"),
        }
        for line, (ids, issue) in cases.items():
            with self.subTest(line=line):
                self.assertEqual(parse_line(line), [(ids, issue, False)])
                self.assertTrue(Suppression("p", 1, line, ids, issue, False).valid)

    def test_bare_forms_follow_opengrep_grammar(self):
        # Opengrep requires `:` or `=` right after the marker and at most one
        # space before the id; anything else is a bare suppression.
        for line in (
            f"x = 1  # {NS}",
            f"x = 1  # {NSEM}",
            f"x = 1  # {NOG}",
            f"x = 1  # {NS} : x.y #1",
            f"x = 1  # {NS}:  x.y #1",
            f"x = 1  # {NS}: ",
            f"x = 1  # {NS} x.y #1",
        ):
            with self.subTest(line=line):
                parsed = parse_line(line)
                self.assertEqual(len(parsed), 1)
                self.assertTrue(parsed[0][2], "must be reported as bare")

    def test_invalid_but_not_bare(self):
        for line in (f"x = 1  # {NS}: #42", f"x = 1  # {NS}: rule-x", f"x = 1  # {NS}: rule-x issue 42"):
            with self.subTest(line=line):
                (parsed,) = parse_line(line)
                self.assertFalse(parsed[2])
                self.assertFalse(Suppression("p", 1, line, *parsed).valid)

    def test_non_ascii_letters_are_boundaries_as_in_opengrep(self):
        for line in (f"x = 1  # \u00e9{NS}", f"x = 1  # {NS}\u00e9"):
            with self.subTest(line=line):
                self.assertEqual([p[2] for p in parse_line(line)], [True])

    def test_unicode_case_folding_as_in_opengrep(self):
        long_s = NS.replace("s", "\u017f")
        for line in (
            f"x = 1  # {long_s}",
            f"x = 1  # {long_s.upper()}",
            f"x = 1  # {NSEM.replace('s', chr(0x17F))}",
            f"\u017f{NS}",
        ):
            with self.subTest(line=line):
                self.assertEqual([p[2] for p in parse_line(line)], [True])
        # A no-break space is not whitespace for Opengrep: the id is not read.
        ((ids, _, bare),) = parse_line(f"# {NS}:\u00a0x.y #1")
        self.assertFalse(bare)
        self.assertFalse(Suppression("p", 1, "", ids, "#1", False).valid)

    def test_long_s_file_is_not_skipped_by_the_quick_filter(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.py").write_text("x = 1  # " + NS.replace("s", "\u017f") + "\n", encoding="utf-8")
            self.assertEqual(len(find_suppressions(root, ["a.py"], 1_000_000)), 1)

    def test_not_a_suppression(self):
        self.assertEqual(parse_line(f"{NS}_count = 3"), [])
        self.assertEqual(parse_line("plain code"), [])


class FindSuppressionsTests(unittest.TestCase):
    def test_line_numbers_follow_newlines_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.py").write_text(f"x = 1\x0c y = 2\nz = 3  # {NS}\n", encoding="utf-8")
            (found,) = find_suppressions(root, ["a.py"], 1_000_000)
            self.assertEqual(found.line, 2)

    def test_lint_covers_given_files_including_prose(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
            (root / "src" / "a.py").write_text(
                f"a = 1  # {NS}: r.one #1 reason\nb = 2  # {NS}\nc = 3  # {NSEM}: r.two\n", encoding="utf-8"
            )
            (root / "src" / "unscanned.py").write_text(f"x = 1  # {NS}\n", encoding="utf-8")
            (root / "README.md").write_text(f"Use `{NS}` anywhere.\n", encoding="utf-8")
            found = find_suppressions(root, ["src/a.py", "README.md"], 1_000_000)
            self.assertEqual(
                [(s.path, s.line, s.valid, s.bare) for s in found],
                [
                    ("README.md", 1, False, True),
                    ("src/a.py", 1, True, False),
                    ("src/a.py", 2, False, True),
                    ("src/a.py", 3, False, False),
                ],
            )
            findings = lint_findings(found, {"src": "app"})
            self.assertEqual(len(findings), 3)
            self.assertTrue(all(f.rule == LINT_RULE and f.severity == "ERROR" for f in findings))
            self.assertIn("bare suppression", findings[0].message)
            self.assertEqual(len({f.fingerprint for f in findings}), 3)


class ExcludeMatcherTests(unittest.TestCase):
    def test_patterns(self):
        m = ExcludeMatcher(["target", "node_modules/", "/build", "**/fixtures/**", "*.min.js", "docs/gen/*.py"])
        self.assertTrue(m.excluded("target/debug/x.rs"))
        self.assertTrue(m.excluded("crate/target/x.rs"))
        self.assertTrue(m.excluded("web/node_modules/x/index.js"))
        self.assertTrue(m.excluded("build/out.js"))
        self.assertFalse(m.excluded("src/build/out.js"))
        self.assertTrue(m.excluded("a/b/fixtures/c.py"))
        self.assertTrue(m.excluded("static/app.min.js"))
        self.assertTrue(m.excluded("docs/gen/api.py"))
        self.assertFalse(m.excluded("docs/gen/sub/api.py"))
        self.assertFalse(m.excluded("src/targets.py"))

    def test_negation_is_rejected(self):
        with self.assertRaises(SetupError):
            ExcludeMatcher(["!keep.py"])


if __name__ == "__main__":
    unittest.main()
