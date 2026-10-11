import hashlib
import tempfile
import tomllib
import unittest
from pathlib import Path

import helpers

from shoalscan import opengrep
from shoalscan.config import parse_config
from shoalscan.errors import SetupError
from shoalscan.rulesets import UNCATEGORISED, RuleIdFilter, select, split_rules

MIXED = """# leading comment
rules:
- id: eval-use
  patterns:
    - pattern: eval(...)
  message: eval
  languages: [python]
  severity: WARNING
  metadata:
    category: security
    cwe: "CWE-95"
- id: missing-timeout
  message: no timeout
  languages: [python]
  severity: WARNING
  pattern: requests.get(...)
  metadata:
    category: 'best-practice'
    references:
      - category: security
- message: id is not first
  id: no-metadata
  languages: [python]
  severity: INFO
  pattern: print(...)
"""

INDENTED = """rules:
  - id: one
    metadata:
      category: SECURITY
    pattern: a(...)
  - id: two
    metadata:
      likelihood: LOW
      category: correctness
    pattern: b(...)
"""


def digest_tree(root: Path) -> str:
    h = hashlib.sha256()
    for p in sorted(root.rglob("*")):
        if p.is_file():
            h.update(p.relative_to(root).as_posix().encode())
            h.update(p.read_bytes())
    return h.hexdigest()


class SplitTests(unittest.TestCase):
    def test_ids_and_categories(self):
        rules = split_rules(MIXED, "mixed.yaml")
        self.assertEqual(
            [(r.rule_id, r.category) for r in rules],
            [("eval-use", "security"), ("missing-timeout", "best-practice"), ("no-metadata", UNCATEGORISED)],
        )
        rules = split_rules(INDENTED, "indented.yaml")
        self.assertEqual([(r.rule_id, r.category) for r in rules], [("one", "security"), ("two", "correctness")])

    def test_unexpected_shapes_fail(self):
        for text in (
            "other: 1\nrules:\n- id: x\n",
            "rules: []\n",
            "rules:\n  id: x\n",
            "no rules here\n",
            "rules:\n- id: a\nextra: 1\n",
        ):
            with self.subTest(text=text), self.assertRaises(SetupError):
                split_rules(text, "bad.yaml")

    def test_unsafe_yaml_is_refused(self):
        for text in (
            "rules:\n- id: &anchor one\n  pattern: x\n",
            "rules:\n- id: *anchor\n  pattern: x\n",
            "rules:\n- id: !tag one\n  pattern: x\n",
            "rules:\n- id: |\n    one\n  pattern: x\n",
            "rules:\n- id: one\n  metadata: {category: security}\n",
            "rules:\n- id: one\n  metadata:\n    category: &c security\n",
            "rules:\n- id: one\n  metadata:\n    category: >\n      security\n",
            "rules:\n- id: one\n  <<: *base\n",
            "rules:\n- id: one\n  id: two\n",
        ):
            with self.subTest(text=text), self.assertRaises(SetupError):
                split_rules(text, "unsafe.yaml")

    def test_category_misreads_are_refused(self):
        for text in (
            "rules:\n- id: one\n  metadata:\n    category: security\n    category: performance\n",
            'rules:\n- id: one\n  metadata:\n    category: "security\n      more"\n',
            "rules:\n- id: one\n  metadata:\n    category: 'security\n",
            "rules:\n- id: one\n  metadata:\n    category: best\n      practice\n",
            "rules:\n- id: one\n    two\n  pattern: x\n",
            'rules:\n- id: "one\n  pattern: x\n',
            'rules:\n- id: "o\\u006ee"\n  pattern: x\n',
            'rules:\n- id: one\n  metadata:\n    category: "sec\\x75rity"\n',
        ):
            with self.subTest(text=text), self.assertRaises(SetupError):
                split_rules(text, "misread.yaml")
        ok = split_rules("rules:\n- id: \"a # b\"\n  metadata:\n    category: 'security'  # note\n", "ok.yaml")
        self.assertEqual([(r.rule_id, r.category) for r in ok], [("a # b", "security")])

    def test_select(self):
        none = RuleIdFilter([])
        text, kept, dropped = select(MIXED, "m", "community.python", frozenset({"security"}), none)
        self.assertEqual((kept, dropped), (1, 2))
        self.assertTrue(text.startswith("rules:\n- id: eval-use"))
        self.assertNotIn("missing-timeout", text)
        # The filtered text still splits into exactly the kept rule.
        self.assertEqual([r.rule_id for r in split_rules(text, "out")], ["eval-use"])

        text, kept, dropped = select(MIXED, "m", "community.python", None, none)
        self.assertEqual((text, kept, dropped), (MIXED, 3, 0))

        text, kept, dropped = select(
            MIXED,
            "m",
            "community.python",
            frozenset({"security", UNCATEGORISED}),
            RuleIdFilter(["community.python.eval-use"]),
        )
        self.assertEqual([r.rule_id for r in split_rules(text, "out")], ["no-metadata"])

        self.assertEqual(select(MIXED, "m", "community.python", frozenset({"performance"}), none)[0], None)

    def test_rule_id_filter(self):
        f = RuleIdFilter(["community.python.eval-use", "community.typescript.react.*"])
        self.assertTrue(f.matches("community.python.eval-use"))
        self.assertFalse(f.matches("community.python.eval-use-2"))
        self.assertTrue(f.matches("community.typescript.react.portability.x"))
        self.assertFalse(f.matches("community.typescript.reactive.x"))
        self.assertFalse(RuleIdFilter([]).matches("anything"))


class StageTests(unittest.TestCase):
    def test_stage_filters_without_touching_the_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            src = base / "snapshot"
            (src / "python" / "lang").mkdir(parents=True)
            (src / "python" / "lang" / "mixed.yaml").write_text(MIXED, encoding="utf-8")
            (src / "python" / "lang" / "perf.yaml").write_text(
                "rules:\n- id: slow\n  metadata:\n    category: performance\n  pattern: x\n", encoding="utf-8"
            )
            (src / "python" / "lang" / "mixed.test.yaml").write_text("not a rule\n", encoding="utf-8")
            before = digest_tree(src)
            stage = base / "stage"
            stats = opengrep.stage_rules(
                stage,
                [opengrep.RuleSource("community", src, frozenset({"security"}))],
                RuleIdFilter([]),
            )
            self.assertEqual(digest_tree(src), before)
            staged = sorted(p.relative_to(stage).as_posix() for p in stage.rglob("*") if p.is_file())
            self.assertEqual(staged, ["community/python/lang/mixed.yaml"])
            self.assertEqual((stats.files, stats.rules_kept, stats.rules_dropped), (1, 1, 3))

            with self.assertRaises(SetupError):
                opengrep.stage_rules(
                    base / "stage2",
                    [opengrep.RuleSource("community", src, frozenset({"security"}))],
                    RuleIdFilter(["community.python.lang.*"]),
                )


class ConfigKeyTests(unittest.TestCase):
    def parse(self, text):
        return parse_config(tomllib.loads(text))

    def test_defaults_and_values(self):
        cfg = self.parse("")
        self.assertEqual(cfg.opengrep.categories, ("security",))
        self.assertEqual(cfg.opengrep.exclude_rules, ())
        self.assertEqual(cfg.non_blocking_paths, ())
        cfg = self.parse(
            'non_blocking_paths = ["demo/", "examples"]\n[opengrep]\ncategories = ["security", "correctness", '
            '"uncategorised"]\n'
            'exclude_rules = ["community.typescript.react.*", "community.python.lang.x"]\n'
        )
        self.assertEqual(cfg.non_blocking_paths, ("demo", "examples"))
        self.assertEqual(cfg.opengrep.categories, ("security", "correctness", "uncategorised"))

    def test_invalid_values(self):
        for text in (
            "[opengrep]\ncategories = []",
            '[opengrep]\ncategories = ["Security Stuff"]',
            '[opengrep]\nexclude_rules = ["*"]',
            '[opengrep]\nexclude_rules = ["community.*.x"]',
            '[opengrep]\nexclude_rules = ["a b"]',
            '[opengrep]\nexclude = ["a"]',
            'non_blocking_paths = ["/abs"]',
            'non_blocking_paths = ["../up"]',
            'non_blocking_path = ["demo"]',
        ):
            with self.subTest(text=text), self.assertRaises(SetupError):
                self.parse(text)
        # With community rules off, an empty category list is allowed.
        self.parse("[opengrep]\ncommunity_rules = false\ncategories = []")


if __name__ == "__main__":
    unittest.main()


class PyYamlAgreementTests(unittest.TestCase):
    """Compare the text-level reader with a real YAML parser on the installed snapshot.

    Runs only where PyYAML and the community rules are installed; run it when
    the rules pin changes.
    """

    def test_snapshot_matches_pyyaml(self):
        try:
            import yaml
        except ImportError:
            self.skipTest("PyYAML is not installed")
        root = helpers.tools_dir() / "rules" / "opengrep-rules"
        if not root.is_dir():
            self.skipTest(f"community rules are not installed in {root}")
        checked = 0
        for path in sorted(root.rglob("*.y*ml")):
            text = path.read_text(encoding="utf-8")
            expected = [
                (str(r["id"]), str((r.get("metadata") or {}).get("category", UNCATEGORISED)).lower())
                for r in yaml.safe_load(text)["rules"]
            ]
            got = [(r.rule_id, r.category) for r in split_rules(text, str(path))]
            self.assertEqual(got, expected, str(path))
            checked += 1
        self.assertGreater(checked, 500)


class CheckedInCategoryListTests(unittest.TestCase):
    """tests/data/community_rule_categories.json was generated with PyYAML for the pinned snapshot.

    Regenerate it with scripts/gen_rule_categories.py whenever the pin changes.
    """

    def setUp(self):
        import json

        self.data = json.loads((helpers.DATA / "community_rule_categories.json").read_text(encoding="utf-8"))

    def test_list_matches_the_pinned_commit(self):
        lock = tomllib.loads((helpers.ROOT / "tools.lock").read_text(encoding="utf-8"))
        self.assertEqual(self.data["commit"], lock["rules"]["commit"], "regenerate the list for the new pin")

    def test_splitter_matches_the_list(self):
        root = helpers.tools_dir() / "rules" / "opengrep-rules"
        if not root.is_dir():
            self.skipTest(f"community rules are not installed in {root}")
        files = sorted(p for p in root.rglob("*") if p.suffix in (".yaml", ".yml") and p.is_file())
        self.assertEqual(sorted(p.relative_to(root).as_posix() for p in files), sorted(self.data["rules"]))
        for path in files:
            rel = path.relative_to(root).as_posix()
            got = [[r.rule_id, r.category] for r in split_rules(path.read_text(encoding="utf-8"), rel)]
            self.assertEqual(got, self.data["rules"][rel], rel)
