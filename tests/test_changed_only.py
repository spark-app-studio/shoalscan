"""`scan --changed-only`: a pull request scan of its changed files only.

A scan of the changed files must reach the same verdict on those files as a
full scan of the same tree, and `check` must judge only what it scanned.
Needs git and the installed Opengrep (see test_end_to_end.py).
"""

import contextlib
import io
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from test_end_to_end import TOOLS, tools_ready

import test_policy_ref as policy_ref
from shoalscan import changedscan, opengrep, opengrep_langs
from shoalscan.cli import main
from shoalscan.errors import ScanError
from shoalscan.rulesets import rule_languages, split_rules

git = policy_ref.git
MAIN = "refs/heads/main"

SKIP_RULE = """rules:
- id: no-eval
  pattern: eval(...)
  message: Do not eval.
  languages: [python]
  severity: ERROR
  paths:
    exclude:
      - "src/vendored/"
  metadata:
    category: security
"""


@unittest.skipUnless(shutil.which("git") and tools_ready(), "needs git and the installed Opengrep")
class ChangedOnlyTests(unittest.TestCase):
    # The fixture of the --policy-ref tests: a base commit with a configuration, a repository rule and a
    # baseline that holds every finding of the sample repository, and a `change` branch on top of it.
    setUp = policy_ref.PolicyRefTests.setUp
    tearDown = policy_ref.PolicyRefTests.tearDown
    commit = policy_ref.PolicyRefTests.commit

    def cli(self, *args: str, ref: str | None = None):
        extra = ["--policy-ref", ref] if ref else []
        common = ["--repo", str(self.repo), "--out", str(self.out)]
        if args[0] in ("scan", "baseline"):
            common += ["--tools-dir", str(TOOLS)]
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main([*args, *common, *extra])
        return code, out.getvalue(), err.getvalue()

    def pcli(self, *args: str):
        return self.cli(*args, ref=MAIN)

    def run_check(self, changed_only: bool):
        code, out, err = self.pcli("scan", *(["--changed-only"] if changed_only else []))
        self.assertEqual(code, 0, out + err)
        code, out, err = self.pcli("check")
        line = [x for x in out.splitlines() if x.startswith("SHOALSCAN_SUMMARY ")]
        self.assertEqual(len(line), 1, out + err)
        details = json.loads((self.out / "check.json").read_text(encoding="utf-8"))
        return code, json.loads(line[0].split(" ", 1)[1]), details, out + err

    def assert_same_verdict(self):
        """The full scan and the scan of changed files agree on the result and on every new finding."""
        full_code, full, full_details, full_out = self.run_check(changed_only=False)
        code, summary, details, out = self.run_check(changed_only=True)
        self.assertEqual(summary["scan_mode"], "changed")
        self.assertEqual(full["scan_mode"], "full")
        self.assertEqual((code, summary["result"]), (full_code, full["result"]), full_out + "\n----\n" + out)
        self.assertEqual(sorted(map(json.dumps, details["new"])), sorted(map(json.dumps, full_details["new"])))
        self.assertEqual(summary["new_blocking"], full["new_blocking"])
        self.assertEqual(summary["unscanned"]["changed_and_unscanned"], full["unscanned"]["changed_and_unscanned"])
        return code, summary, out

    # ── the verdict matches a full scan ──

    def test_a_known_finding_in_a_changed_file_is_flagged(self):
        (self.repo / "src" / "more.py").write_text(
            "import pickle\n\ndef more(b):\n    return pickle.loads(b)\n", encoding="utf-8"
        )
        self.commit("a new finding")
        code, summary, out = self.assert_same_verdict()
        self.assertEqual((code, summary["new_blocking"]), (1, 1), out)
        self.assertIn("repo.security-rules.no-pickle-loads", out)

    def test_a_finding_added_to_an_already_baselined_file_is_flagged(self):
        with open(self.repo / "src" / "load.py", "a", encoding="utf-8") as f:
            f.write("\ndef again(b):\n    return pickle.loads(b + b)\n")
        self.commit("a second finding in a baselined file")
        code, summary, out = self.assert_same_verdict()
        self.assertEqual((code, summary["new_blocking"]), (1, 1), out)

    def test_a_docs_only_change_passes_and_judges_no_baseline_entry(self):
        with open(self.repo / "docs" / "notes.md", "a", encoding="utf-8") as f:
            f.write("\nMore notes.\n")
        self.commit("docs")
        code, summary, out = self.assert_same_verdict()
        self.assertEqual(code, 0, out)
        # Every baseline entry is in an unchanged file: carried over, not judged, and never stale.
        self.assertEqual(summary["stale"], 0)
        self.assertEqual(summary["baseline_not_judged"], summary["baseline_size"])
        self.assertIn("Changed files only", out)
        doc = json.loads((self.out / "findings.json").read_text(encoding="utf-8"))
        self.assertEqual((doc["changed"]["targets"], doc["changed_unread"]), (["docs/notes.md"], ["docs/notes.md"]))

    def test_an_empty_change_scans_nothing_and_passes(self):
        code, out, err = self.pcli("scan", "--changed-only")
        self.assertEqual(code, 0, err)
        self.assertIn("no scannable changed files", out)
        code, out, err = self.pcli("check")
        self.assertEqual(code, 0, out + err)

    def test_a_deleted_baselined_file_leaves_a_stale_entry(self):
        (self.repo / "src" / "load.py").unlink()
        self.commit("delete")
        code, summary, out = self.assert_same_verdict()
        self.assertEqual(summary["stale"], 1, out)

    def test_a_rename_is_a_deletion_and_an_addition(self):
        git(self.repo, "mv", "src/load.py", "src/loader.py")
        self.commit("rename without the baseline")
        code, summary, out = self.assert_same_verdict()
        self.assertEqual(code, 1, out)
        self.assertEqual((summary["new_blocking"], summary["stale"]), (1, 1), out)

    def test_an_excluded_changed_file_is_not_scanned_as_in_a_full_scan(self):
        (self.repo / "generated").mkdir()
        (self.repo / "generated" / "out.py").write_text("import pickle\npickle.loads(b'')\n", encoding="utf-8")
        self.commit("excluded")
        code, summary, out = self.assert_same_verdict()
        self.assertEqual(code, 0, out)
        record = json.loads((self.out / "findings.json").read_text(encoding="utf-8"))["changed"]
        self.assertEqual(record["excluded"], ["generated/out.py"])

    def test_a_changed_file_over_the_size_limit_is_changed_and_unscanned(self):
        # The explicit-target form would scan it anyway (Opengrep ignores --max-target-bytes for a named file).
        (self.repo / "src" / "big.py").write_text("import pickle\npickle.loads(b'')\n" + "x = 1\n" * 600)
        self.commit("big")
        code, summary, out = self.assert_same_verdict()
        self.assertEqual(summary["unscanned"]["changed_and_unscanned"], 1, out)
        self.assertEqual(code, 1, out)

    def test_a_changed_symbolic_link_is_not_followed(self):
        os.symlink("load.py", self.repo / "src" / "link.py")
        self.commit("link")
        code, summary, out = self.assert_same_verdict()
        self.assertEqual(code, 0, out)
        record = json.loads((self.out / "findings.json").read_text(encoding="utf-8"))["changed"]
        self.assertEqual((record["links"], record["targets"]), (["src/link.py"], []))

    def test_a_rule_path_exclude_still_applies(self):
        (self.repo / "security-rules" / "eval.yaml").write_text(SKIP_RULE, encoding="utf-8")
        self.commit("the base gains a rule")
        git(self.repo, "checkout", "-q", "main")
        git(self.repo, "merge", "-q", "--ff-only", "change")
        git(self.repo, "checkout", "-q", "change")
        (self.repo / "src" / "vendored").mkdir()
        (self.repo / "src" / "vendored" / "lib.py").write_text("eval('1')\n", encoding="utf-8")
        (self.repo / "src" / "own.py").write_text("eval('1')\n", encoding="utf-8")
        self.commit("eval in a vendored and an own file")
        code, summary, out = self.assert_same_verdict()
        self.assertEqual(summary["new_blocking"], 1, out)
        self.assertIn("src/own.py", out)
        self.assertNotIn("src/vendored/lib.py:", out)

    def test_a_nosemgrep_comment_in_a_changed_file_suppresses_as_in_a_full_scan(self):
        (self.repo / "src" / "quiet.py").write_text(
            "import pickle\n\ndef quiet(b):\n"
            "    # nosemgrep: repo.security-rules.no-pickle-loads #7 trusted local cache\n"
            "    return pickle.loads(b)\n",
            encoding="utf-8",
        )
        self.commit("suppressed")
        code, summary, out = self.assert_same_verdict()
        self.assertEqual(code, 0, out)

    # ── a changed file Opengrep leaves out without saying so ──

    def scan_dropping(self, dropped: str):
        """Scan changed files with Opengrep's report edited to leave `dropped` out, as a silent drop would."""
        real = opengrep.execute

        def execute(*args, **kwargs):
            doc = real(*args, **kwargs)
            doc["paths"]["scanned"] = [p for p in doc["paths"]["scanned"] if not p.endswith("/" + dropped)]
            doc["results"] = [r for r in doc["results"] if not r.get("path", "").endswith("/" + dropped)]
            return doc

        with mock.patch.object(opengrep, "execute", execute):
            return self.pcli("scan", "--changed-only")

    def test_a_python_file_left_out_with_python_rules_loaded_stops_the_scan(self):
        (self.repo / "src" / "more.py").write_text("import pickle\npickle.loads(b'')\n", encoding="utf-8")
        self.commit("more")
        code, out, err = self.scan_dropping("src/more.py")
        self.assertEqual(code, 2, out + err)
        self.assertIn("a changed file the loaded rules read", err)

    def test_a_python_script_left_out_by_its_shebang_stops_the_scan(self):
        script = self.repo / "tool"
        script.write_text("#!/usr/bin/env python3\nimport pickle\npickle.loads(b'')\n", encoding="utf-8")
        script.chmod(0o755)
        self.commit("tool")
        # Opengrep itself reads it as Python: an executable file with no extension and a python3 shebang.
        code, summary, out = self.assert_same_verdict()
        self.assertEqual((code, summary["new_blocking"]), (1, 1), out)
        code, out, err = self.scan_dropping("tool")
        self.assertEqual(code, 2, out + err)

    def test_a_file_a_generic_rules_include_reads_left_out_stops_the_scan(self):
        # The base policy gains a generic rule that reads only *.html files.
        policy_ref.git(self.repo, "checkout", "-q", "main")
        (self.repo / "security-rules" / "html.yaml").write_text(
            "rules:\n- id: inline-script\n  languages: [generic]\n  severity: ERROR\n  message: inline script\n"
            "  pattern: <script>eval(...)</script>\n  paths:\n    include:\n    - '*.html'\n",
            encoding="utf-8",
        )
        self.commit("html rule")
        policy_ref.git(self.repo, "checkout", "-q", "change")
        policy_ref.git(self.repo, "merge", "-q", "--ff-only", "main")
        (self.repo / "web").mkdir()
        (self.repo / "web" / "page.html").write_text("<p>hi</p>\n", encoding="utf-8")
        (self.repo / "notes.md").write_text("notes\n", encoding="utf-8")
        self.commit("page")
        # Opengrep reads the page and not the notes, so a full scan and a changed-only scan agree and pass.
        code, summary, out = self.assert_same_verdict()
        self.assertEqual(code, 0, out)
        findings = json.loads((self.out / "findings.json").read_text(encoding="utf-8"))
        self.assertEqual(findings["changed_unread"], ["notes.md"])
        code, out, err = self.scan_dropping("web/page.html")
        self.assertEqual(code, 2, out + err)
        self.assertIn("web/page.html", err)

    # ── what is refused ──

    def test_changed_only_needs_a_policy_ref(self):
        code, _, err = self.cli("scan", "--changed-only", ref=None)
        self.assertEqual(code, 2)
        self.assertIn("--changed-only needs --policy-ref", err)

    def test_a_base_that_is_not_an_ancestor_is_refused(self):
        git(self.repo, "checkout", "-q", "-b", "side", "main")
        (self.repo / "side.txt").write_text("side\n", encoding="utf-8")
        self.commit("side")
        git(self.repo, "checkout", "-q", "change")
        code, _, err = self.cli("scan", "--changed-only", ref="refs/heads/side")
        self.assertEqual(code, 2)
        self.assertIn("is not an ancestor of HEAD", err)

    def test_check_refuses_when_the_changed_files_moved_after_the_scan(self):
        (self.repo / "src" / "a.py").write_text("x = 1\n", encoding="utf-8")
        self.commit("a")
        code, _, err = self.pcli("scan", "--changed-only")
        self.assertEqual(code, 0, err)
        # A new file after the scan: the list of changed files no longer matches the scanned one.
        (self.repo / "src" / "b.py").write_text("import pickle\npickle.loads(b'')\n", encoding="utf-8")
        code, out, err = self.pcli("check")
        self.assertEqual(code, 2, out + err)
        self.assertIn("run the scan again", err)

    def test_check_refuses_a_tampered_target_list(self):
        (self.repo / "src" / "a.py").write_text("x = 1\n", encoding="utf-8")
        (self.repo / "src" / "b.py").write_text("import pickle\npickle.loads(b'')\n", encoding="utf-8")
        self.commit("a and b")
        code, _, err = self.pcli("scan", "--changed-only")
        self.assertEqual(code, 0, err)
        path = self.out / "findings.json"
        doc = json.loads(path.read_text(encoding="utf-8"))
        doc["changed"]["targets"] = ["src/a.py"]
        path.write_text(json.dumps(doc), encoding="utf-8")
        code, out, err = self.pcli("check")
        self.assertEqual(code, 2, out + err)

    def test_check_refuses_changed_findings_without_the_policy_ref(self):
        code, _, err = self.pcli("scan", "--changed-only")
        self.assertEqual(code, 0, err)
        code, out, err = self.cli("check", ref=None)
        self.assertEqual(code, 2, out + err)
        self.assertIn("same --policy-ref", err)

    def test_other_scanners_refuse_changed_only(self):
        text = (self.repo / ".shoalscan.toml").read_text(encoding="utf-8")
        (self.repo / ".shoalscan.toml").write_text('scanners = ["opengrep", "gitleaks"]\n' + text, encoding="utf-8")
        self.commit("the base runs gitleaks too")
        git(self.repo, "checkout", "-q", "main")
        git(self.repo, "merge", "-q", "--ff-only", "change")
        git(self.repo, "checkout", "-q", "change")
        code, _, err = self.pcli("scan", "--changed-only")
        self.assertEqual(code, 2)
        self.assertIn("--changed-only limits only Opengrep", err)


class SilentDropTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def file(self, name: str, text: str = "x\n", mode: int = 0o644) -> str:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        path.chmod(mode)
        return name

    def refuses(self, name: str, languages, globs: tuple[str, ...] = ()) -> bool:
        loaded = None if languages is None else changedscan.LoadedRules(frozenset(languages), globs)
        try:
            changedscan.refuse_silent_drops([name], self.root, loaded)
        except ScanError:
            return True
        return False

    def test_by_extension(self):
        py = frozenset({"python"})
        self.assertTrue(self.refuses(self.file("a.py"), py))
        self.assertTrue(self.refuses(self.file("b.pyi"), py))
        self.assertFalse(self.refuses(self.file("c.md"), py))
        self.assertFalse(self.refuses(self.file("d.js"), py))
        self.assertTrue(self.refuses(self.file("d2.js"), frozenset({"javascript"})))
        # Opengrep's excluded extensions are not read.
        self.assertFalse(self.refuses(self.file("e.min.js"), frozenset({"js"})))
        self.assertFalse(self.refuses(self.file("f.d.ts"), frozenset({"ts"})))
        self.assertTrue(self.refuses(self.file("Dockerfile"), frozenset({"dockerfile"})))
        self.assertTrue(self.refuses(self.file("app.Dockerfile"), frozenset({"docker"})))

    def test_by_shebang(self):
        py = frozenset({"python"})
        self.assertTrue(self.refuses(self.file("run", "#!/usr/bin/env python3\n", 0o755), py))
        self.assertTrue(self.refuses(self.file("run2", "#!/usr/bin/env -S python3 -u\n", 0o755), py))
        self.assertTrue(self.refuses(self.file("run3", "#! /usr/bin/python\n", 0o700), py))
        # Opengrep reads a shebang only on an executable file with no extension.
        self.assertFalse(self.refuses(self.file("plain", "#!/usr/bin/env python3\n", 0o644), py))
        self.assertFalse(self.refuses(self.file("run.txt", "#!/usr/bin/env python3\n", 0o755), py))
        self.assertFalse(self.refuses(self.file("shell", "#!/bin/sh\n", 0o755), py))
        self.assertTrue(self.refuses(self.file("shell2", "#!/bin/sh\n", 0o755), frozenset({"bash"})))

    def test_unknown_or_unreadable_languages_fail_closed(self):
        self.assertTrue(self.refuses(self.file("notes.md"), None))
        self.assertTrue(self.refuses(self.file("notes2.md"), frozenset({"cobol"})))
        self.assertFalse(self.refuses(self.file("notes3.md"), frozenset()))

    def test_loaded_languages(self):
        stage = self.root / "stage"
        self.file(
            "stage/a/one.yaml",
            "rules:\n- id: a\n  languages: [python, js]\n  pattern: x\n- id: b\n  languages:\n  - rust\n  pattern: y\n",
        )
        self.file(
            "stage/b/two.yml",
            "rules:\n- id: c\n  languages: [generic]\n  paths:\n    include:\n    - '*.html'\n  pattern: z\n"
            "- id: c2\n  languages: [regex]\n  paths:\n    include: [sites-enabled/*, '*.html']\n  pattern: z\n",
        )
        self.file("stage/b/two.test.yaml", "rules:\n- id: d\n  languages: python\n  pattern: z\n")
        self.assertEqual(
            changedscan.loaded_languages(stage),
            changedscan.LoadedRules(frozenset({"python", "js", "rust"}), ("*.html", "sites-enabled/*")),
        )
        self.file("stage/c/three.yaml", "rules:\n- id: e\n  languages: python\n  pattern: z\n")
        self.assertIsNone(changedscan.loaded_languages(stage))

    def test_a_generic_rule_with_no_readable_include_counts_as_reading_everything(self):
        stage = self.root / "stage"
        self.file("stage/a/one.yaml", "rules:\n- id: a\n  languages: [python]\n  pattern: x\n")
        self.assertIsNotNone(changedscan.loaded_languages(stage))
        for n, paths in enumerate(("", "  paths:\n    exclude: ['*.md']\n", "  paths:\n    include: '*.html'\n")):
            self.file("stage/b/g.yaml", f"rules:\n- id: g\n  languages: [generic]\n{paths}  pattern: z\n")
            self.assertIsNone(changedscan.loaded_languages(stage), n)

    def test_a_linked_directory_in_the_stage_counts_as_reading_everything(self):
        stage = self.root / "stage"
        self.file("stage/a/one.yaml", "rules:\n- id: a\n  languages: [python]\n  pattern: x\n")
        self.file("elsewhere/two.yaml", "rules:\n- id: b\n  languages: [rust]\n  pattern: y\n")
        self.assertIsNotNone(changedscan.loaded_languages(stage))
        (stage / "linked").symlink_to(self.root / "elsewhere", target_is_directory=True)
        self.assertIsNone(changedscan.loaded_languages(stage))

    def test_by_a_generic_rules_include(self):
        globs = ("*.html", "sites-enabled/*", "*/openssl/*.h", "/docs/", "*Dockerfile*")
        self.assertTrue(self.refuses(self.file("web/page.html"), (), globs))
        self.assertTrue(self.refuses(self.file("web/PAGE.HTML"), (), globs))
        self.assertTrue(self.refuses(self.file("etc/nginx/sites-enabled/site"), (), globs))
        self.assertTrue(self.refuses(self.file("vendor/openssl/ssl.h"), (), globs))
        self.assertTrue(self.refuses(self.file("docs/guide.md"), (), globs))
        self.assertTrue(self.refuses(self.file("deploy/api.dockerfile.tmpl"), (), globs))
        self.assertFalse(self.refuses(self.file("README.md"), (), globs))
        self.assertFalse(self.refuses(self.file("web/page.htm"), (), globs))

    def test_a_linked_rule_file_in_the_stage_counts_as_reading_everything(self):
        stage = self.root / "stage"
        self.file("stage/a/one.yaml", "rules:\n- id: a\n  languages: [python]\n  pattern: x\n")
        self.file("elsewhere.yaml", "rules:\n- id: b\n  languages: [rust]\n  pattern: y\n")
        self.assertEqual(changedscan.loaded_languages(stage), changedscan.LoadedRules(frozenset({"python"}), ()))
        (stage / "a" / "linked.yaml").symlink_to(self.root / "elsewhere.yaml")
        self.assertIsNone(changedscan.loaded_languages(stage))

    def test_rule_languages_forms(self):
        text = (
            "rules:\n"
            '- id: flow\n  languages: [Python, "js"]\n  pattern: x\n'
            "- id: block\n  pattern: y\n  languages:\n    - go  # a comment\n    - rust\n"
            "- id: compact\n  languages:\n  - ts\n  pattern: y\n"
            "- languages: [generic]\n  id: first\n"
            "- id: nested\n  metadata:\n    languages: [python]\n  languages: python\n"
            "- id: twice\n  languages: [go]\n  languages: [js]\n"
            "- id: missing\n  pattern: z\n"
        )
        got = {r.rule_id: rule_languages(r) for r in split_rules(text, "t")}
        self.assertEqual(
            got,
            {
                "flow": {"python", "js"},
                "block": {"go", "rust"},
                "compact": {"ts"},
                "first": {"generic"},
                "nested": None,
                "twice": None,
                "missing": None,
            },
        )

    def test_the_table_knows_every_language_key(self):
        for key in (
            "python",
            "py",
            "python3",
            "js",
            "javascript",
            "ts",
            "typescript",
            "rust",
            "go",
            "golang",
            "bash",
            "sh",
            "dockerfile",
            "docker",
            "yaml",
            "json",
            "terraform",
            "hcl",
            "c#",
            "csharp",
        ):
            self.assertIn(key, opengrep_langs.LANGUAGES, key)


class ChangedFilesUnitTests(unittest.TestCase):
    def test_include_patterns_are_anchored_and_cover_excluded_files(self):
        changed = changedscan.ChangedFiles("b" * 40, ("src/a.py",), ("gone.py",), ("generated/x.py",), (), ())
        self.assertEqual(changedscan.include_patterns(changed), ["/generated/x.py", "/src/a.py"])
        self.assertEqual(changed.paths, {"src/a.py", "gone.py", "generated/x.py"})

    def test_a_target_no_rule_read_is_returned_not_hidden(self):
        root = Path("/repo")
        changed = changedscan.ChangedFiles("b" * 40, ("src/a.py", "docs/b.md", "src/c.py"), (), (), (), ())
        doc = {
            "paths": {"scanned": ["/repo/src/a.py"], "skipped": [{"path": "/repo/src/c.py", "reason": "too_big"}]},
            "errors": [],
        }
        self.assertEqual(changedscan.account_for_targets(doc, root, changed), ["docs/b.md"])

    def test_a_scanned_file_outside_the_targets_stops_the_scan(self):
        root = Path("/repo")
        changed = changedscan.ChangedFiles("b" * 40, ("src/a.py",), (), (), (), ())
        doc = {"paths": {"scanned": ["/repo/src/a.py", "/repo/src/other.py"], "skipped": []}, "errors": []}
        with self.assertRaisesRegex(Exception, "not changed targets"):
            changedscan.account_for_targets(doc, root, changed)

    def test_a_target_left_out_by_the_include_filter_stops_the_scan(self):
        root = Path("/repo")
        changed = changedscan.ChangedFiles("b" * 40, ("src/a.py",), (), (), (), ())
        doc = {
            "paths": {
                "scanned": [],
                "skipped": [{"path": "/repo/src/a.py", "reason": "cli_include_flags_do_not_match"}],
            },
            "errors": [],
        }
        with self.assertRaisesRegex(Exception, "left out a changed file"):
            changedscan.account_for_targets(doc, root, changed)

    def test_an_excluded_file_that_was_scanned_stops_the_scan(self):
        root = Path("/repo")
        changed = changedscan.ChangedFiles("b" * 40, (), (), ("generated/x.py",), (), ())
        doc = {"paths": {"scanned": ["/repo/generated/x.py"], "skipped": []}, "errors": []}
        with self.assertRaisesRegex(Exception, "matchers disagree"):
            changedscan.account_for_targets(doc, root, changed)


if __name__ == "__main__":
    unittest.main()
