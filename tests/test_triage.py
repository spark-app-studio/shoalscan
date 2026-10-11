"""`shoalscan triage`: the prioritised work list, the rule metadata it reads, and safe Markdown."""

import contextlib
import hashlib
import io
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import helpers

from history_fixtures import MALICIOUS
from shoalscan import markdown as md
from shoalscan import opengrep, triage
from shoalscan.baseline import Entry, render_baseline
from shoalscan.check import compare
from shoalscan.cli import main
from shoalscan.findings import Finding, findings_to_json
from shoalscan.gitref import baseline_binding_path, worktree_state
from test_end_to_end import SAMPLE, TOOLS, tools_ready

HAS_GIT = shutil.which("git") is not None
COMMIT = "a" * 40
MARKERS = ("no" + "sem", "no" + "opengrep")


def finding(rule, path, fp, severity="ERROR", component="api", message="a problem", line=3):
    return Finding(tool="opengrep", rule=rule, severity=severity, path=path, line=line, fingerprint=fp, component=component, message=message)


def entry(f: Finding, issue="#1", reason="known") -> Entry:
    return Entry(f.tool, f.rule, f.path, f.fingerprint, issue, reason)


RULES = {
    "shoalscan.python-tls": {"file": "shoalscan/tls.yaml", "cwe": ["CWE-295: Improper Certificate Validation"], "owasp": [],
                             "fix": "Trust a CA bundle.", "references": [], "confidence": "HIGH"},
    "community.python.requests.no-verify": {"file": "community/python/requests/no-verify.yaml", "cwe": ["CWE-295: Improper Certificate Validation"],
                                            "owasp": ["A07:2021"], "fix": None, "references": ["https://example.com/a"], "confidence": "LOW"},
    "shoalscan.secret-in-log": {"file": "shoalscan/log.yaml", "cwe": ["CWE-532: Sensitive Information in Log"], "owasp": [],
                                "fix": None, "references": [], "confidence": "MEDIUM"},
    "repo.rules.custom": {"file": "repo/rules/custom.yaml", "cwe": [], "owasp": [], "fix": None, "references": [], "confidence": None},
}
META = {
    "shoalscan_version": "0.1.1",
    "scanners": {"opengrep": {"community_rules_commit": COMMIT}},
    "rules": RULES,
    "worktree": {"commit": "b" * 40, "dirty": False},
}


class MarkdownTests(unittest.TestCase):
    def test_text_leaves_no_markup(self):
        out = md.text(MALICIOUS + " [x](javascript:alert(1)) ![i](https://e/x.png) **b** a|b ~~s~~ &amp;")
        # The input has no backslashes, so every special character must now follow one.
        self.assertNotRegex(out, r"(?<!\\)[\[\]<>|*_~&`]")
        self.assertIn("\\<img", out)

    def test_text_never_starts_a_block(self):
        # A list item's content is parsed as blocks, so a leading marker would make a heading, a list or a rule.
        cases = {"# h": "\\# h", "- x": "\\- x", "+ x": "\\+ x", "---": "\\---", "===": "\\===", "1. x": "1\\. x", "12) x": "12\\) x"}
        for raw, expected in cases.items():
            self.assertEqual(md.text(raw), expected, raw)
        self.assertEqual(md.text("a # b - c 1. d"), "a # b - c 1. d")
        self.assertEqual(md.text("@team $x$"), "\\@team \\$x\\$")

    def test_text_is_one_line_and_bounded(self):
        out = md.text("a\nb\r\n# heading c\x00d", limit=2000)
        self.assertEqual(out, "a b # heading c d")
        self.assertEqual(len(md.text("x" * 5000, limit=100)), 100)

    def test_code_fence_outlasts_backticks(self):
        self.assertEqual(md.code("a``b"), "```a``b```")
        self.assertEqual(md.code("`x"), "`` `x ``")
        self.assertEqual(md.code("p\nq"), "`p q`")

    def test_link_keeps_only_plain_web_urls(self):
        self.assertEqual(md.link("rule", "https://example.com/a?b=1#c"), "[rule](<https://example.com/a?b=1#c>)")
        for bad in ("javascript:alert(1)", "data:text/html,x", "https://a/b c", "https://a/b)c", "https://a/<b>", None, 3):
            self.assertEqual(md.link("rule", bad), "rule", bad)
        self.assertEqual(md.link("<b>", "javascript:x"), "\\<b\\>")

    def test_issue_keeps_issue_references_linkable(self):
        self.assertEqual(md.issue("#12"), "#12")
        self.assertEqual(md.issue("https://example.com/i/1"), "[https://example.com/i/1](<https://example.com/i/1>)")
        self.assertEqual(md.issue("# 12 <b>"), "\\# 12 \\<b\\>")


class RuleMetadataTests(unittest.TestCase):
    def doc(self, *results):
        return {"results": list(results)}

    def result(self, rule, metadata, ignored=False):
        return {"check_id": rule, "extra": {"metadata": metadata, "is_ignored": ignored}}

    def test_metadata_is_normalised_and_bounded(self):
        doc = self.doc(
            self.result("a", {
                "cwe": "CWE-295: Improper\nCertificate Validation",
                "owasp": ["A1", "A1", 3, "A2"],
                "references": ["https://ok.example/x", "javascript:alert(1)", "https://bad example", "ftp://x", "http://plain.example"],
                "fix": "x" * 2000,
                "confidence": "high",
                "impact": {"no": "dict"},
            }),
            self.result("b", "not a dict"),
            self.result("c", {"cwe": ["CWE-1"]}, ignored=True),
        )  # fmt: skip
        out = opengrep.rule_metadata(doc, {"a": "shoalscan/a.yaml"})
        self.assertEqual(set(out), {"a", "b"})
        a = out["a"]
        self.assertEqual(a["file"], "shoalscan/a.yaml")
        self.assertEqual(a["cwe"], ["CWE-295: Improper Certificate Validation"])
        self.assertEqual(a["owasp"], ["A1", "A2"])
        self.assertEqual(a["references"], ["https://ok.example/x", "http://plain.example"])
        self.assertEqual(len(a["fix"]), opengrep.MAX_META_TEXT)
        self.assertEqual((a["confidence"], a["impact"], a["likelihood"]), ("HIGH", None, None))
        self.assertEqual(out["b"], {"file": None, "cwe": [], "owasp": [], "fix": None, "references": [], "confidence": None, "likelihood": None, "impact": None})

    def test_lists_are_capped(self):
        out = opengrep.rule_metadata(self.doc(self.result("a", {"cwe": [f"CWE-{n}" for n in range(20)]})), {})
        self.assertEqual(len(out["a"]["cwe"]), opengrep.MAX_META_ITEMS)

    def test_staging_records_each_rule_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            stats = opengrep.stage_rules(Path(tmp), [opengrep.RuleSource("shoalscan", helpers.ROOT / "rules")])
        self.assertEqual(stats.rule_files["shoalscan.python-tls-verification-disabled"], "shoalscan/tls-verification-disabled-python.yaml")
        self.assertEqual(set(stats.rule_files), stats.rule_ids)


class FamilyAndExplanationTests(unittest.TestCase):
    def test_family_is_the_first_cwe(self):
        self.assertEqual(triage.family("r", {"cwe": ["CWE-0079: XSS", "CWE-80"]}), ("CWE-79", "CWE-0079: XSS"))
        self.assertEqual(triage.family("r", {"cwe": ["not a cwe"]}), ("r", "r"))
        self.assertEqual(triage.family("r", {}), ("r", "r"))

    def test_explanation_links(self):
        e = triage.explanation
        self.assertEqual(e({"file": "community/python/x.yaml"}, META)["url"],
                         f"https://github.com/opengrep/opengrep-rules/blob/{COMMIT}/python/x.yaml")  # fmt: skip
        self.assertEqual(e({"file": "shoalscan/tls.yaml"}, META)["url"], "https://github.com/spark-app-studio/shoalscan/blob/v0.1.1/rules/tls.yaml")
        self.assertEqual(e({"file": "repo/rules/custom.yaml"}, META), {"url": None, "path": "rules/custom.yaml"})

    def test_explanation_refuses_odd_values(self):
        e = triage.explanation
        none = {"url": None, "path": None}
        self.assertEqual(e({"file": "community/../x.yaml"}, META), none)
        self.assertEqual(e({"file": "community/x y.yaml"}, META), none)
        self.assertEqual(e({"file": "community/x.yaml"}, {**META, "scanners": {"opengrep": {"community_rules_commit": "main"}}}), none)
        self.assertEqual(e({"file": "shoalscan/x.yaml"}, {**META, "shoalscan_version": "1.0/../../evil"}), none)
        self.assertEqual(e({}, META), none)


class BuildTests(unittest.TestCase):
    def setUp(self):
        self.tls_old = finding("shoalscan.python-tls", "src/a.py", "f1", component="api")
        self.tls_community = finding("community.python.requests.no-verify", "src/b.py", "f2", severity="WARNING", component="api")
        self.log_new = finding("shoalscan.secret-in-log", "web/c.py", "f3", component="web")
        self.custom_info = finding("repo.rules.custom", "src/d.py", "f4", severity="INFO", component="api")
        self.docs_new = finding("shoalscan.secret-in-log", "docs/e.py", "f5", component="docs")
        self.findings = [self.tls_old, self.tls_community, self.log_new, self.custom_info, self.docs_new]
        self.stale = Entry("opengrep", "shoalscan.python-tls", "src/gone.py", "f9", "#2", "fixed already")
        baseline = [entry(self.tls_old), entry(self.tls_community, reason="False positive: test helper"), self.stale]
        self.result = compare(self.findings, baseline, ("ERROR", "WARNING"), non_blocking_paths=("docs",))

    def build(self, **kw):
        return triage.build(self.findings, META, self.result, **kw)

    def test_groups_by_family_with_new_blocking_first(self):
        doc = self.build()
        self.assertEqual([g["family"] for g in doc["groups"]], ["CWE-532", "CWE-295", "repo.rules.custom"])
        self.assertEqual([g["rank"] for g in doc["groups"]], [1, 2, 3])
        log, tls, custom = doc["groups"]
        self.assertEqual(log["counts"]["new_blocking"], 1)
        self.assertEqual(log["counts"]["new"], 1)  # the docs/ finding is new but in a non-blocking path
        self.assertEqual(tls["title"], "CWE-295: Improper Certificate Validation")
        self.assertEqual([r["rule"] for r in tls["rules"]], ["shoalscan.python-tls", "community.python.requests.no-verify"])
        self.assertEqual(tls["counts"]["by_severity"], {"ERROR": 1, "WARNING": 1, "INFO": 0})
        self.assertEqual(tls["heat"], 13)
        self.assertEqual(custom["rules"][0]["explanation"], {"url": None, "path": "rules/custom.yaml"})

    def test_finding_statuses_and_baseline_reasons(self):
        doc = self.build()
        by_path = {f["path"]: f for g in doc["groups"] for c in g["components"] for f in c["findings"]}
        self.assertEqual(by_path["web/c.py"]["status"], "new_blocking")
        self.assertEqual(by_path["docs/e.py"]["status"], "new")
        self.assertFalse(by_path["docs/e.py"]["blocking_class"])
        self.assertEqual(by_path["src/a.py"]["status"], "baselined")
        self.assertEqual(by_path["src/b.py"]["baseline"], {"issue": "#1", "reason": "False positive: test helper"})
        self.assertEqual(by_path["src/a.py"]["key"], ["opengrep", "shoalscan.python-tls", "src/a.py", "f1"])

    def test_new_blocking_findings_lead_their_group(self):
        log = self.build()["groups"][0]
        self.assertEqual([c["component"] for c in log["components"]], ["web", "docs"])

    def test_totals_and_stale_entries(self):
        doc = self.build()
        self.assertEqual(doc["totals"], {"findings": 5, "new_blocking": 1, "new": 2, "baselined": 2, "blocking_class": 3,
                                         "groups": 3, "stale": 1, "baseline_size": 3})  # fmt: skip
        self.assertEqual(doc["stale"][0]["path"], "src/gone.py")

    def test_blocking_only_drops_info_and_non_blocking_paths(self):
        doc = self.build(blocking_only=True)
        self.assertEqual(doc["totals"]["findings"], 3)
        self.assertEqual([g["family"] for g in doc["groups"]], ["CWE-532", "CWE-295"])

    def test_findings_without_rule_metadata_group_by_rule(self):
        doc = triage.build(self.findings, {}, self.result)
        self.assertEqual({g["family"] for g in doc["groups"]}, {f.rule for f in self.findings})
        for g in doc["groups"]:
            for r in g["rules"]:
                self.assertEqual(r["explanation"], {"url": None, "path": None})

    def test_empty_scan(self):
        result = compare([], [], ("ERROR",))
        doc = triage.build([], META, result)
        self.assertEqual(doc["groups"], [])
        self.assertIn("Nothing to do", triage.render_markdown(doc))


class RenderTests(unittest.TestCase):
    def test_markdown_lists_groups_in_order_with_links(self):
        b = BuildTests("test_empty_scan")
        b.setUp()
        out = triage.render_markdown(b.build())
        self.assertLess(out.index("Remove 1 stale baseline entry"), out.index("CWE-532"))
        self.assertLess(out.index("CWE-532"), out.index("CWE-295"))
        self.assertIn(f"[rule](<https://github.com/opengrep/opengrep-rules/blob/{COMMIT}/python/requests/no-verify.yaml>)", out)
        self.assertIn("rule file `rules/custom.yaml`", out)
        self.assertIn("- ERROR `web/c.py:3` `shoalscan.secret-in-log`: **new, blocks**", out)
        self.assertIn("baselined (#1: False positive: test helper)", out)
        self.assertIn("  - Fix: Trust a CA bundle.", out)
        for marker in MARKERS:
            self.assertNotIn(marker, out.lower())

    def test_hostile_values_stay_text(self):
        bad = finding("shoalscan.x", "src/a.py", "f1", message=MALICIOUS + "\n## injected heading", component=MALICIOUS)
        evil_path = finding("shoalscan.x", "src/`` <img src=x>|.py", "f2", message=MALICIOUS + "\n## injected heading")
        result = compare([bad, evil_path], [entry(bad, reason=MALICIOUS + "\n# h")], ("ERROR", "WARNING"))
        meta = {"rules": {"shoalscan.x": {"file": "shoalscan/x.yaml", "cwe": [MALICIOUS], "owasp": [], "fix": MALICIOUS,
                                          "references": ["javascript:alert(1)"], "confidence": None}}}  # fmt: skip
        out = triage.render_markdown(triage.build([bad, evil_path], meta, result))
        # The hostile path is the one place a raw < may appear: inside a code span, in a list item.
        span = "```src/`` <img src=x>|.py:3```"
        self.assertIn(f"- ERROR {span} ", out)
        self.assertNotRegex(out.replace(span, ""), r"(?<!\\)(?<!\]\()<")  # our own links are ](<https://...>)
        self.assertIn("\\<script\\>alert(2)", out)
        self.assertNotIn("javascript:", out)
        self.assertNotIn("\n## injected", out)
        self.assertNotIn("\n# h", out)

    def test_rule_text_cannot_start_a_block_in_a_list_item(self):
        f = finding("repo.rules.x", "src/a.py", "f1", message="# Security review passed")
        meta = {"rules": {"repo.rules.x": {"file": "repo/rules/x.yaml", "cwe": ["1. not a cwe"], "owasp": ["---"], "fix": "+ none",
                                           "references": [], "confidence": None}}}  # fmt: skip
        out = triage.render_markdown(triage.build([f], meta, compare([f], [], ("ERROR",))))
        self.assertIn("  - \\# Security review passed", out)
        self.assertIn("  - 1\\. not a cwe; \\---", out)
        self.assertIn("  - Fix: \\+ none", out)

    def test_long_groups_are_cut_in_markdown_only(self):
        many = [finding("shoalscan.python-tls", f"src/f{n:02}.py", f"f{n}") for n in range(30)]
        result = compare(many, [], ("ERROR",))
        doc = triage.build(many, META, result)
        out = triage.render_markdown(doc, per_group=10)
        self.assertEqual(out.count("**new, blocks**"), 10)
        self.assertIn("… and 20 more in this group", out)
        self.assertEqual(len(doc["groups"][0]["components"][0]["findings"]), 30)


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-c", "user.name=test", "-c", "user.email=test@example.invalid", "-c", "commit.gpgsign=false", *args],
        cwd=repo, check=True, capture_output=True, text=True, timeout=60,
    ).stdout  # fmt: skip


@unittest.skipUnless(HAS_GIT, "needs git")
class CommandTests(unittest.TestCase):
    """The command, on a findings file made by hand: no scanner needed."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.repo = base / "repo"
        self.out = base / "out"
        self.out.mkdir()
        (self.repo / "src").mkdir(parents=True)
        (self.repo / "src" / "a.py").write_text("print('hi')\n")
        self.config = 'blocking = ["ERROR", "WARNING"]\nbaseline = "baseline.toml"\n[components]\n"src/" = "api"\n'
        (self.repo / ".shoalscan.toml").write_text(self.config)
        self.old = finding("shoalscan.python-tls", "src/a.py", "f1")
        self.new = finding("shoalscan.secret-in-log", "src/a.py", "f2", line=9)
        (self.repo / "baseline.toml").write_text(render_baseline([entry(self.old)]))
        git(self.repo, "init", "-q", "-b", "main")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "base")
        self.write_findings()

    def tearDown(self):
        self.tmp.cleanup()

    def write_findings(self, policy_ref=None):
        meta = {
            **{k: v for k, v in META.items() if k != "worktree"},
            "worktree": worktree_state(self.repo.resolve(), baseline_binding_path(self.repo, self.repo / "baseline.toml")),
            "policy": {"ref": policy_ref, "commit": None, "config_sha256": hashlib.sha256(self.config.encode()).hexdigest(), "adoption": False},
        }
        (self.out / "findings.json").write_text(findings_to_json([self.old, self.new], meta))

    def cli(self, *extra):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["triage", "--repo", str(self.repo), "--out", str(self.out), *extra])
        return code, out.getvalue(), err.getvalue()

    def test_markdown_to_standard_output(self):
        code, out, err = self.cli()
        self.assertEqual(code, 0, err)
        self.assertEqual(err, "")
        self.assertTrue(out.startswith("# Shoalscan triage work list\n"))
        self.assertIn("1 new and blocking", out)
        self.assertLess(out.index("CWE-532"), out.index("CWE-295"))

    def test_json_to_a_file(self):
        target = Path(self.tmp.name) / "work.json"
        code, out, err = self.cli("--format", "json", "--output", str(target))
        self.assertEqual(code, 0, err)
        self.assertEqual(out, "")
        self.assertIn("wrote 2 findings in 2 groups", err)
        doc = json.loads(target.read_text())
        self.assertEqual(doc["format"], triage.FORMAT)
        self.assertEqual(doc["totals"]["new_blocking"], 1)
        self.assertEqual(doc["warnings"], [])

    def test_editing_only_the_baseline_does_not_warn(self):
        (self.repo / "baseline.toml").write_text(render_baseline([]))
        code, out, err = self.cli()
        self.assertEqual(code, 0, err)
        self.assertEqual(err, "")
        self.assertIn("2 new and blocking", out)

    def test_warns_when_the_tree_changed(self):
        (self.repo / "src" / "a.py").write_text("print('changed')\n")
        code, out, err = self.cli()
        self.assertEqual(code, 0)
        self.assertIn("the working tree changed after the scan", err)
        self.assertIn("> **Warning:** the working tree changed after the scan", out)

    def test_warns_when_head_moved(self):
        git(self.repo, "commit", "-q", "--allow-empty", "-m", "later")
        _, _, err = self.cli()
        self.assertIn("another commit than HEAD", err)

    def test_warns_about_a_policy_ref_scan_and_a_missing_baseline(self):
        self.write_findings(policy_ref="refs/heads/main")
        _, _, err = self.cli("--baseline", str(self.repo / "missing.toml"))
        self.assertIn("read its policy from refs/heads/main", err)
        self.assertIn("so every finding counts as new", err)

    def test_refusals(self):
        code, _, err = main_quiet(["triage", "--repo", str(self.repo), "--out", str(self.repo / "src")])
        self.assertEqual(code, 2)
        self.assertIn("inside the repository", err)
        (self.out / "findings.json").unlink()
        code, _, err = self.cli()
        self.assertEqual(code, 2)
        self.assertIn("run `shoalscan scan` first", err)
        code, _, err = self.cli("--max-per-group", "0")
        self.assertEqual(code, 2)

    def test_export_still_works_beside_the_work_list(self):
        code, _, err = main_quiet(["triage", "export", "--repo", "owner/project", "--issue", "#1", "--db", str(Path(self.tmp.name) / "none.db")])
        self.assertEqual(code, 2)  # no database, but the export command parsed and ran
        self.assertNotIn("unrecognized", err)


def main_quiet(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


@unittest.skipUnless(HAS_GIT and tools_ready(), f"needs git and Opengrep installed in {TOOLS}")
class EndToEndTests(unittest.TestCase):
    def test_scan_records_rule_metadata_for_triage(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            out = Path(tmp) / "out"
            shutil.copytree(SAMPLE, repo)
            git(repo, "init", "-q", "-b", "main")
            git(repo, "add", "-A")
            git(repo, "commit", "-q", "-m", "base")
            code, _, err = main_quiet(["scan", "--repo", str(repo), "--out", str(out), "--tools-dir", str(TOOLS)])
            self.assertEqual(code, 0, err)
            meta = json.loads((out / "findings.json").read_text())
            info = meta["rules"]["shoalscan.python-tls-verification-disabled"]
            self.assertEqual(info["file"], "shoalscan/tls-verification-disabled-python.yaml")
            self.assertEqual(info["cwe"], ["CWE-295: Improper Certificate Validation"])
            self.assertTrue(info["fix"])
            code, text, err = main_quiet(["triage", "--repo", str(repo), "--out", str(out), "--format", "json"])
            self.assertEqual(code, 0, err)
            doc = json.loads(text)
            self.assertIn("CWE-295", [g["family"] for g in doc["groups"]])
            self.assertIn("there is no baseline file", " ".join(doc["warnings"]))


if __name__ == "__main__":
    unittest.main()
