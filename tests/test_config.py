import tempfile
import tomllib
import unittest
from pathlib import Path

import helpers  # noqa: F401

from shoalscan.config import Config, component_for, load_config, parse_config
from shoalscan.errors import SetupError


def parse(text: str) -> Config:
    return parse_config(tomllib.loads(text))


class ConfigTests(unittest.TestCase):
    def test_defaults(self):
        cfg = parse("")
        self.assertEqual(cfg.blocking, ("ERROR", "WARNING"))
        self.assertEqual(cfg.scanners, ("opengrep",))
        self.assertTrue(cfg.opengrep.community_rules)
        self.assertEqual(cfg.limits.jobs, 4)

    def test_missing_file_means_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(load_config(Path(tmp) / "absent.toml"), Config())

    def test_full_config(self):
        cfg = parse(
            """
            scanners = ["opengrep"]
            excludes = ["target", "**/fixtures/**"]
            blocking = ["ERROR"]
            baseline = "security/baseline.toml"
            [opengrep]
            community_rules = false
            rule_dirs = ["security/rules"]
            [limits]
            scan_timeout_seconds = 600
            rule_timeout_seconds = 10
            max_target_bytes = 2000000
            jobs = 2
            [components]
            "services/api/" = "api"
            """
        )
        self.assertEqual(cfg.excludes, ("target", "**/fixtures/**"))
        self.assertEqual(cfg.opengrep.rule_dirs, ("security/rules",))
        self.assertEqual(cfg.components, {"services/api": "api"})
        self.assertEqual(cfg.limits.jobs, 2)

    def test_unknown_keys_are_rejected(self):
        for text in (
            'blockng = ["ERROR"]',
            "[opengrep]\ncommunity = false",
            "[limits]\njob = 2",
        ):
            with self.subTest(text=text), self.assertRaises(SetupError):
                parse(text)

    def test_bad_values_are_rejected(self):
        for text in (
            'blocking = ["CRITICAL"]',
            'blocking = ["ERROR", "INFO"]',
            'blocking = ["WARNING"]',
            "blocking = []",
            'scanners = ["semgrep-registry"]',
            'baseline = "/etc/baseline.toml"',
            'baseline = "../baseline.toml"',
            '[opengrep]\nrule_dirs = ["../other-repo/rules"]',
            '[opengrep]\ncommunity_rules = "no"',
            "[opengrep]\ncommunity_rules = false\nshoalscan_rules = false",
            "[limits]\njobs = 0",
            "[limits]\njobs = true",
            "[limits]\nscan_timeout_seconds = 1",
            'excludes = [""]',
            '[components]\n"api/" = ""',
        ):
            with self.subTest(text=text), self.assertRaises(SetupError):
                parse(text)

    def test_invalid_toml(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".shoalscan.toml"
            path.write_text("blocking = [", encoding="utf-8")
            with self.assertRaises(SetupError):
                load_config(path)

    def test_deep_nesting_is_invalid_toml_not_a_crash(self):
        # tomllib recurses into nested arrays and tables; the repository controls these files.
        from shoalscan.baseline import baseline_from_bytes, load_baseline
        from shoalscan.config import config_from_bytes

        for text in ("a = " + "[" * 5000, "a = " + "{x = " * 5000):
            with self.subTest(text=text[:10]), tempfile.TemporaryDirectory() as tmp:
                for parse_bytes in (config_from_bytes, baseline_from_bytes):
                    with self.assertRaisesRegex(SetupError, "not valid TOML"):
                        parse_bytes(text.encode(), "x")
                path = Path(tmp) / "f.toml"
                path.write_text(text, encoding="utf-8")
                for load in (load_config, load_baseline):
                    with self.assertRaises(SetupError):
                        load(path)

    def test_component_longest_prefix(self):
        comps = {"services": "services", "services/api": "api", "web/": "web"}
        self.assertEqual(component_for("services/api/main.py", comps), "api")
        self.assertEqual(component_for("services/db/x.py", comps), "services")
        self.assertEqual(component_for("web/app.js", comps), "web")
        self.assertEqual(component_for("webapp/app.js", comps), "other")
        self.assertEqual(component_for("README", comps), "other")


class ParseWarnOnlyTests(unittest.TestCase):
    def test_a_list_that_would_cover_everything_is_refused(self):
        vowels = ["*a*", "*e*", "*i*", "*o*", "*u*", "*y*"]
        for pattern in vowels:
            with self.subTest(pattern=pattern), self.assertRaises(SetupError):
                parse_config({"parse_warn_only": [pattern]})
        for pattern in (
            "Dockerfile",
            "Dockerfile.*",
            "*.sh",
            "*.min.js",
            "deploy/**/templates/*.yaml",
            "scripts/*/run.sh",
        ):
            with self.subTest(pattern=pattern):
                parse_config({"parse_warn_only": [pattern]})

    def test_valid_globs(self):
        config = parse_config({"parse_warn_only": ["**/Dockerfile", "deploy/charts/**/*.yaml", "scripts/*.sh"]})
        self.assertEqual(config.parse_warn_only, ("**/Dockerfile", "deploy/charts/**/*.yaml", "scripts/*.sh"))
        self.assertEqual(parse_config({}).parse_warn_only, ())

    def test_invalid_globs_are_refused(self):
        for bad in (
            "**",
            "**/*",
            "*",
            "/etc/Dockerfile",
            "../x/Dockerfile",
            "a//b",
            "!Dockerfile",
            "[ab].sh",
            "C:\\x",
            "a b",
            "a\nb",
            "",
            7,
            "*e*",
            "**a**",
            "*a",
            "src/*",
            "src/**",
            "a*b/c.sh",
            "*.*",
            "?.sh",
            ".*",
        ):
            with self.subTest(bad=bad), self.assertRaises(SetupError):
                parse_config({"parse_warn_only": [bad]})
        with self.assertRaises(SetupError):
            parse_config({"parse_warn_only": "**/Dockerfile"})


class ExcludeTests(unittest.TestCase):
    def test_catch_all_excludes_are_refused(self):
        for bad in (
            "**",
            "*",
            "**/*",
            "/**",
            "*/",
            "*e*",
            "?",
            "**/*/**",
            "*.*",
            "/*",
            "**/**",
            "*ab*",
            "[a-z]*",
            "[!0]*",
            "**/[!0]*",
            "*[!0]",
            "{a,b}*",
            "src/{x,y}",
            "../vendor",
            "a/../b",
            "[abcd]efgh",
        ):
            with self.subTest(bad=bad), self.assertRaises(SetupError):
                parse_config({"excludes": [bad]})

    def test_real_excludes_are_kept(self):
        good = [
            "target",
            "node_modules",
            "**/fixtures/**",
            "*.min.js",
            "**/*redteam*",
            "*.h",
            "build*",
            "/dist/",
            "vendor/",
        ]
        self.assertEqual(parse_config({"excludes": good}).excludes, tuple(good))


if __name__ == "__main__":
    unittest.main()
