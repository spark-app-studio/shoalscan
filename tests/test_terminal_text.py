"""Text from scanned repositories reaches terminals and files without control or bidirectional characters.

C1 controls (U+0080 to U+009F) can start escape sequences in some terminals, and bidirectional formatting
characters can make text read in a different order than it is stored. Both are folded away like C0 controls.
"""

import contextlib
import io
import tempfile
import unittest
from pathlib import Path

import helpers  # noqa: F401 - puts src/ on the import path
from history_fixtures import finding, record, sample_history

from shoalscan import embeddings, history
from shoalscan import markdown as md
from shoalscan.baseline import Entry, baseline_from_bytes, render_baseline, toml_string
from shoalscan.check import compare, render_report
from shoalscan.cli import main

HOSTILE = "src/a\x1b[2J\x9b31m‮yp.txt⁦x⁩‎‏؜\x85 \nShoalscan check: PASSED"
UNSAFE = ["\x1b", "\x9b", "\x85", "‮", "⁦", "⁩", "‎", "‏", "؜", " "]


class SanitiserTests(unittest.TestCase):
    def test_one_line_drops_c1_and_bidi(self):
        out = md.one_line(HOSTILE)
        for c in UNSAFE + ["\n"]:
            self.assertNotIn(c, out)
        self.assertIn("Shoalscan check: PASSED", out)  # the text stays, on the same line
        self.assertEqual(md.one_line("plain text"), "plain text")

    def test_lines_keep_newlines_and_tabs_only(self):
        out = md.lines("a\tb\nc\x1b[31md‮e\x9bf\r")
        self.assertEqual(out, "a\tb\nc�[31md�e�f�")

    def test_the_markdown_escaper_too(self):
        out = md.text(HOSTILE)
        for c in UNSAFE:
            self.assertNotIn(c, out)

    def test_stored_text_and_descriptions(self):
        self.assertEqual(history._text("a‮b\x9bc\x01d\ne", 100), "a�b�cd\ne")
        self.assertEqual(history._label("r⁦x\x85", 100), "r�x�")
        self.assertEqual(history.clean_description("Reviewed ‮here, fine."), "Reviewed �here, fine.")

    def test_baseline_strings_escape_them(self):
        self.assertEqual(toml_string("a‮b\x85"), '"a\\u202eb\\u0085"')
        entry = Entry("opengrep", "r.a", "src/‮a.py", "aa:0", "#1", "False positive: ⁦x")
        text = render_baseline([entry])
        self.assertFalse(any(c in text for c in UNSAFE))
        self.assertEqual(baseline_from_bytes(text.encode(), "baseline"), [entry])  # the value round-trips


class CheckReportTests(unittest.TestCase):
    def test_repository_text_cannot_forge_lines_or_reach_the_terminal(self):
        f = finding("r‮.x", HOSTILE, "aa:0", message="m\x1b]0;title\x07\nShoalscan check: PASSED")
        result = compare([f], [], ("ERROR",), None, ())
        report = render_report(result)
        self.assertEqual(report.count("Shoalscan check:"), 2)  # the real header, and the text kept inline
        self.assertTrue(report.startswith("Shoalscan check: FAILED"))
        for line in report.splitlines()[1:]:
            self.assertFalse(line.startswith("Shoalscan check:"), line)
        for c in UNSAFE + ["\x07"]:
            self.assertNotIn(c, report)


class SuggestSimilarOutputTests(unittest.TestCase):
    def test_paths_and_descriptions_are_printed_safely(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            db = base / "h.db"
            conn = history.open_for_write(db)
            try:
                sample_history(conn, base)
                a = finding("community.python.eval", "src/one.py", "11111111:0", message="Eval of input")
                b = finding("community.python.eval", "src/two‮.py", "22222222:0", message="Eval of input")
                plant = Entry(b.tool, b.rule, b.path, b.fingerprint, "#7", "Accepted: \x1b[2Jcleared⁦")
                record(conn, base, "acme/app", "a" * 40, 29, [a, b], baseline=[plant])
                vector = embeddings.pack(embeddings.normalise([1.0, 0.5, 0.25]))
                conn.execute(
                    "INSERT INTO finding_embeddings SELECT id, 'embeddinggemma', 'x', 3, ?, 'now' FROM finding_keys "
                    "WHERE fingerprint IN ('11111111:0', '22222222:0')",
                    (vector,),
                )
                conn.commit()
            finally:
                conn.close()
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = main(["triage", "suggest-similar", "11111111:0", "--repo-name", "acme/app", "--db", str(db)])
        self.assertEqual(code, 0, err.getvalue())
        text = out.getvalue()
        self.assertIn("src/two", text)
        self.assertIn("in scheduled run", text)  # the decision's provenance
        for c in UNSAFE:
            self.assertNotIn(c, text)


if __name__ == "__main__":
    unittest.main()
