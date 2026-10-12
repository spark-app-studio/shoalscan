"""Rust test scope: the scope rules, the policy, check, the baseline, the history and the dashboard.

The tests that run Opengrep need the installed tools (see test_end_to_end.py)
and are skipped without them; the rest run anywhere.
"""

import contextlib
import io
import json
import shutil
import sqlite3
import subprocess
import tempfile
import unittest
import unittest.mock
from pathlib import Path

import helpers
from test_end_to_end import TOOLS, tools_ready

from shoalscan import history, testscope
from shoalscan.check import compare, details
from shoalscan.cli import main
from shoalscan.config import config_from_bytes
from shoalscan.dashboard.data import Data
from shoalscan.errors import ScanError, SetupError
from shoalscan.findings import Finding, findings_to_json, load_findings
from shoalscan.testscope import AUTO_REVIEWER, TestScope

FIXTURE = helpers.DATA / "rust_test_scope"
RULE = "repo.rules.temp-dir"
CALL = "let _ = std::env::temp_dir();"


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-c", "user.name=test", "-c", "user.email=test@example.invalid", "-c", "commit.gpgsign=false", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def cli(*args: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(args))
    return code, out.getvalue(), err.getvalue()


def write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def finding(path: str, line: int = 1, rule: str = RULE, tool: str = "opengrep", **kw) -> Finding:
    return Finding(tool, rule, "WARNING", path, line, f"{path}:{line}", "other", "m", **kw)


# ---------------------------------------------------------------- policy


class PolicyTests(unittest.TestCase):
    def parse(self, text: str):
        return config_from_bytes(text.encode(), "test.toml")

    def test_off_by_default(self):
        self.assertEqual(self.parse("").test_scope.non_blocking, ())

    def test_lists_opengrep_rules_like_exclude_rules(self):
        config = self.parse(
            '[test_scope]\nnon_blocking = ["community.rust.lang.security.temp-dir", '
            '"shoalscan.rust-plain-http-url", "community.rust.lang.security.*"]\n'
        )
        self.assertEqual(
            config.test_scope.non_blocking,
            (
                "community.rust.lang.security.*",
                "community.rust.lang.security.temp-dir",
                "shoalscan.rust-plain-http-url",
            ),
        )

    def test_secret_rules_are_refused(self):
        for rule in (
            "community.generic.secrets.security.detected-aws-access-key",
            "community.generic.secrets.gitleaks.generic-api-key",
            "community.rust.lang.security.hardcoded-SECRET",
            "community.generic.secrets.security.detected-github-token",
            "community.generic.secrets.security.detected-private-key",
            "community.generic.secrets.security.detected-jwt-token",
            "repo.rules.detected-slack-token",
            "repo.rules.stripe-api-key",
            "repo.rules.private-key",
            "repo.rules.jwt",
            "community.generic.secrets.*",
        ):
            with self.assertRaisesRegex(SetupError, "it finds secrets", msg=rule):
                self.parse(f'[test_scope]\nnon_blocking = ["{rule}"]\n')

    def test_broad_wildcards_are_refused(self):
        for rule in ("community.*", "shoalscan.*", "repo.*", "repo.rules.*", "community.rust.*"):
            with self.assertRaisesRegex(SetupError, "too broad", msg=rule):
                self.parse(f'[test_scope]\nnon_blocking = ["{rule}"]\n')

    def test_gitleaks_rules_are_refused(self):
        for rule in ("gitleaks.generic-api-key", "gitleaks.*"):
            with self.assertRaisesRegex(SetupError, "a real secret in test code is still a leaked secret"):
                self.parse(f'[test_scope]\nnon_blocking = ["{rule}"]\n')

    def test_other_scanners_are_refused(self):
        for rule in ("hadolint.DL3008", "trivy.AVD-AWS-0089", "zizmor.artipacked", "temp-dir", "community"):
            with self.assertRaisesRegex(SetupError, "not an Opengrep rule"):
                self.parse(f'[test_scope]\nnon_blocking = ["{rule}"]\n')

    def test_the_suppression_lint_is_refused(self):
        with self.assertRaisesRegex(SetupError, "inline suppression"):
            self.parse('[test_scope]\nnon_blocking = ["shoalscan.suppression-without-rule-and-issue"]\n')

    def test_malformed_entries_and_keys_are_refused(self):
        for text in (
            '[test_scope]\nnon_blocking = ["community.*.temp-dir"]\n',
            '[test_scope]\nnon_blocking = "community.x"\n',
            '[test_scope]\nnonblocking = ["community.x"]\n',
            'test_scope = ["community.x"]\n',
        ):
            with self.assertRaises(SetupError, msg=text):
                self.parse(text)


# ---------------------------------------------------------------- check


class CheckTests(unittest.TestCase):
    SCOPE = TestScope("cfg_test_module", "src/lib.rs", 7)

    def test_a_listed_scoped_finding_never_blocks(self):
        scoped = finding("src/lib.rs", 10, test_scope=self.SCOPE)
        plain = finding("src/lib.rs", 4)
        result = compare([scoped, plain], [], ("ERROR", "WARNING"), test_scope=(RULE,))
        self.assertEqual(result.new_blocking, [plain])
        self.assertEqual(result.test_scoped, [scoped])
        d = details(result, "x")
        self.assertEqual(d["summary"]["test_scoped"], 1)
        self.assertEqual(d["summary"]["new_test_scoped"], 1)
        self.assertEqual(d["test_scoped"][0]["kind"], "cfg_test_module")
        self.assertNotIn(list(scoped.key()), d["blocking_class"])

    def test_marks_the_policy_does_not_allow_are_ignored(self):
        cases = [
            finding("src/lib.rs", 10, test_scope=self.SCOPE),  # rule not listed (policy below lists another)
            finding("src/lib.py", 10, test_scope=self.SCOPE),  # not Rust
            finding("src/lib.rs", 10, tool="gitleaks", rule="gitleaks.x", test_scope=self.SCOPE),
            finding("examples/a.rs", 10, test_scope=self.SCOPE),
            finding("src/bin/tool.rs", 10, test_scope=self.SCOPE),
            finding("src/lib.rs", 10, rule="repo.rules.family.hardcoded-secret", test_scope=self.SCOPE),
        ]
        for f in cases:
            listed = ("repo.rules.other",) if f.rule == RULE else (RULE, "repo.rules.family.*")
            result = compare([f], [], ("ERROR", "WARNING"), test_scope=listed)
            self.assertEqual(result.new_blocking, [f], f)

    def test_a_baselined_scoped_finding_is_guidance_not_a_failure(self):
        from shoalscan.baseline import Entry

        scoped = finding("src/lib.rs", 10, test_scope=self.SCOPE)
        entry = Entry("opengrep", RULE, "src/lib.rs", scoped.fingerprint, "#1", "accepted")
        result = compare([scoped], [entry], ("ERROR", "WARNING"), test_scope=(RULE,))
        self.assertTrue(result.passed)
        self.assertEqual(result.stale, [])
        self.assertEqual(details(result, "x")["summary"]["baseline_test_scoped"], 1)

    def test_findings_json_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "findings.json"
            scoped = finding("src/lib.rs", 10, test_scope=self.SCOPE)
            path.write_text(findings_to_json([scoped, finding("src/a.rs")], {}), encoding="utf-8")
            doc = json.loads(path.read_text(encoding="utf-8"))
            self.assertNotIn("test_scope", [f for f in doc["findings"] if f["path"] == "src/a.rs"][0])
            found, _ = load_findings(path)
            self.assertIn(scoped, found)
            doc["findings"][0]["test_scope"] = {"kind": "made_up", "path": "x", "line": 1}
            path.write_text(json.dumps(doc), encoding="utf-8")
            with self.assertRaisesRegex(ScanError, "malformed test_scope"):
                load_findings(path)


# ---------------------------------------------------------------- the repository (no Opengrep needed)


class RepositoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        write(self.root, "Cargo.toml", '[package]\nname = "demo"\n')
        write(self.root, "src/lib.rs", "#[cfg(test)]\nmod tests {}\n")

    def tearDown(self):
        self.tmp.cleanup()

    def repo(self) -> testscope.Repository:
        return testscope.read_repository(self.root)

    def test_a_clean_repository(self):
        repo = self.repo()
        self.assertIsNone(repo.off)
        self.assertEqual(repo.module_names, ["tests"])

    def test_a_build_script_that_may_set_cfg_test_turns_scope_off(self):
        for text in (
            'fn main() { println!("cargo:rustc-cfg=test"); }',
            'fn main() { println!("cargo::rustc-cfg=test_utils"); }',
            'fn main() { let n = "test"; println!("cargo:rustc-cfg={n}"); }',
            'fn main() { println!("cargo:rustc-cfg={}", name()); }',
            'fn main() { println!(concat!("cargo:rustc-cfg=", "te", "st")); }',
            "fn main() { autocfg::new().emit_rustc_cfg(NAME); }",
            "fn main() { cfg_aliases::cfg_aliases! { x: { unix } } }",
        ):
            write(self.root, "build.rs", text)
            self.assertIn("rustc-cfg", self.repo().off or "", text)
        for text in ('fn main() { println!("cargo:rustc-cfg=has_foo"); }', 'fn main() { ac.emit_cfg("has_x"); }'):
            write(self.root, "build.rs", text)
            self.assertIsNone(self.repo().off, text)
        # Any Rust file can be a build script's helper, under any name.
        (self.root / "build.rs").unlink()
        write(self.root, "build/helper.rs", 'pub fn emit() { println!("cargo:rustc-cfg=test"); }')
        self.assertIsNotNone(self.repo().off)

    def test_cargo_configuration_that_passes_cfg_test_turns_scope_off(self):
        cases = {
            ".cargo/config.toml": '[build]\nrustflags = ["--cfg", "test"]\n',
            "crates/a/.cargo/config": '[target.x86_64-unknown-linux-gnu]\nrustflags = "--cfg test"\n',
            "Cargo.toml": '[package]\nname = "demo"\n[profile.release]\nrustflags = ["--cfg=test"]\n',
            "a/target/evil/Cargo.toml": '[package]\nname = "x"\n[profile.dev]\nrustflags = ["--cfg", "test"]\n',
        }
        for path, text in cases.items():
            write(self.root, path, text)
            self.assertIn("--cfg test", self.repo().off or "", path)
            if path == "Cargo.toml":
                write(self.root, path, '[package]\nname = "demo"\n')
            else:
                (self.root / path).unlink()
        write(self.root, ".cargo/config.toml", '[build]\nrustflags = ["--cfg", "tokio_unstable"]\n')
        self.assertIsNone(self.repo().off)

    def test_shadowed_test_attributes(self):
        shadowing = [
            "use test_log::test;",
            "use x::passthrough as test;",
            "use x::{passthrough as rstest};",
            "use other::{test, b};",
            "mod tokio { }",
            "extern crate fake as tokio;",
            "macro_rules! test { () => {} }",
            "fn rstest() {}",
        ]
        for line in shadowing:
            self.assertTrue(testscope.shadows_test_attributes(testscope.strip_code(line)), line)
        for line in (
            "use tokio::sync::Mutex;",
            "use tokio::test;",
            "use rstest::rstest;",
            "use rstest::{fixture, rstest};",
            "use super::*;",
            "fn test_helper() {}",
            "// use test_log::test;",
            'const S: &str = "use x as test;";',
        ):
            self.assertFalse(testscope.shadows_test_attributes(testscope.strip_code(line)), line)
        write(self.root, "src/a.rs", "use test_log::test;\n")
        self.assertEqual(self.repo().shadowed, {"src/a.rs"})

    def test_a_renamed_tokio_or_macro_use_turns_test_fn_off(self):
        write(self.root, "Cargo.toml", '[package]\nname = "demo"\n[dev-dependencies]\ntokio = { path = "fake" }\n')
        self.assertIn("tokio", self.repo().shadowed_everywhere or "")
        write(self.root, "Cargo.toml", '[package]\nname = "demo"\n[dev-dependencies]\ntokio = "1"\n')
        self.assertIsNone(self.repo().shadowed_everywhere)
        write(self.root, "src/lib.rs", "#[macro_use]\nextern crate test_log;\n")
        self.assertIn("macro_use", self.repo().shadowed_everywhere or "")

    def test_module_names_come_only_after_cfg_test(self):
        write(
            self.root,
            "src/lib.rs",
            "// #[cfg(test)]\nmod commented {}\n"
            '#[cfg(not(test))]\nmod not_test {}\nconst S: &str = "#[cfg(test)] mod in_a_string {}";\n'
            "#[cfg(test)]\n/// doc\n#[allow(dead_code)]\npub(crate) mod real {}\n"
            "#[cfg(test)] /* a comment */ mod after_comment {}\n#[cfg(test)]\nmod r#type {}\n",
        )
        self.assertEqual(self.repo().module_names, ["after_comment", "real"])

    def test_the_module_name_cap(self):
        with unittest.mock.patch.object(testscope, "MAX_MODULE_NAMES", 1):
            write(self.root, "src/more.rs", "#[cfg(test)]\nmod a {}\n#[cfg(test)]\nmod b {}\n")
            repo = self.repo()
        self.assertEqual((len(repo.module_names), repo.names_dropped), (1, 2))

    def test_strip_code(self):
        code = testscope.strip_code("a /* x /* nested */ y */ b // c\n\"s\\\"t\" r#\"raw \" x\"# 'q' '\\'' &'a str\n")
        self.assertEqual(code.split(), ["a", "b", "&'a", "str"])
        self.assertEqual(code.count("\n"), 2)

    def test_matches_in_a_file_opengrep_could_not_parse_are_not_used(self):
        match = {
            "check_id": testscope.ITEM_RULE,
            "path": str(self.root / "src/lib.rs"),
            "start": {"line": 1, "col": 1, "offset": 0},
            "end": {"line": 2, "col": 15, "offset": 27},
        }
        repo = self.repo()
        self.assertEqual(testscope.build(self.root, [match], repo).scope_for("src/lib.rs", 2).kind, "cfg_test_item")
        unparsed = frozenset({"src/lib.rs"})
        self.assertIsNone(testscope.build(self.root, [match], repo, unparsed).scope_for("src/lib.rs", 2))

    def test_never_test_scope(self):
        for path in ("examples/x.rs", "build.rs", "crate/build.rs", "src/bin/tool.rs", "crate/src/bin/a/main.rs"):
            self.assertTrue(testscope.never_test_scope(path), path)
        self.assertFalse(testscope.never_test_scope("src/binary.rs"))


# ---------------------------------------------------------------- the scope rules, with Opengrep


ADVERSARIAL = f"""\
#[cfg(any(test, feature = "x"))]
mod any_test {{
    fn a() {{ {CALL} }}
}}

#[cfg(all(test, unix))]
mod all_test {{
    fn b() {{ {CALL} }}
}}

mod outer {{
    #[cfg(test)]
    mod inner {{
        fn c() {{ {CALL} }}
    }}
    #[test]
    fn test_in_a_plain_module() {{ {CALL} }}
}}

#[test]
fn top_level_test() {{ {CALL} }}

#[cfg(test)]
impl Fixture {{
    fn d() {{ {CALL} }}
}}

#[cfg(
    test
)]
mod split {{
    fn e() {{ {CALL} }}
}}

#[cfg(test)]
/// A doc comment between the attribute and the module.
mod documented {{
    fn f() {{ {CALL} }}
}}

const NOTE: &str = "#[cfg(test)] mod fake {{ }}";
// #[cfg(test)]
fn after_a_comment() {{ {CALL} }}

#[cfg(not(test))]
fn not_test() {{ {CALL} }}

#[cfg_attr(test, allow(dead_code))]
fn cfg_attr_test() {{ {CALL} }}

#[cfg(feature = "test")]
fn feature_test() {{ {CALL} }}

#[cfg(test)]
mod tests {{
    mod nested {{
        fn g() {{ {CALL} }}
    }}
}}

#[test_case(1; "one")]
fn test_case_keeps_its_function(x: u8) {{ {CALL} }}

#[cfg(test)]
use std::env;
fn after_a_cfg_test_use() {{ {CALL} }}

#[cfg(test)]
pub mod test_support {{
    pub fn h() {{ {CALL} }}
}}

#[cfg(test)]
mod main;

#[cfg(test)]
#[path = "support/fixture_impl.rs"]
mod fixture;

#[tokio::test(flavor = "multi_thread")]
async fn async_test() {{ {CALL} }}
"""

# The function name on each call's line, and the scope kind it must get (None: not test scope).
EXPECTED = {
    "a": None,
    "b": None,
    "c": None,
    "test_in_a_plain_module": None,
    "top_level_test": "test_fn",
    "d": "cfg_test_item",
    "e": "cfg_test_module",
    "f": "cfg_test_module",
    "after_a_comment": None,
    "not_test": None,
    "cfg_attr_test": None,
    "feature_test": None,
    "g": "cfg_test_module",
    "test_case_keeps_its_function": None,
    "after_a_cfg_test_use": None,
    "h": "cfg_test_module",
    "async_test": "test_fn",
}


def make_crate(root: Path, lib: str, policy: bool = True) -> None:
    shutil.copytree(FIXTURE, root)
    if not policy:
        text = (root / ".shoalscan.toml").read_text(encoding="utf-8")
        (root / ".shoalscan.toml").write_text(text.split("[test_scope]")[0] + "[limits]\njobs = 2\n", encoding="utf-8")
    if lib is not None:
        write(root, "src/lib.rs", lib)


@unittest.skipUnless(tools_ready(), f"Opengrep is not installed in {TOOLS}; run `shoalscan install`")
class ScopeRuleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.repo = self.base / "repo"
        self.out = self.base / "out"

    def tearDown(self):
        self.tmp.cleanup()

    def scan(self, *extra: str) -> dict:
        code, _, err = cli("scan", "--repo", str(self.repo), "--tools-dir", str(TOOLS), "--out", str(self.out), *extra)
        self.assertEqual(code, 0, err)
        return json.loads((self.out / "findings.json").read_text(encoding="utf-8"))

    def test_the_shipped_rule_tests_pass(self):
        run = subprocess.run(
            [str(TOOLS / "opengrep"), "scan", "--test", "--disable-version-check", str(helpers.ROOT / "scope")],
            capture_output=True,
            text=True,
            timeout=300,
        )
        self.assertEqual(run.returncode, 0, run.stdout[-2000:] + run.stderr[-2000:])

    def test_adversarial_constructs(self):
        make_crate(self.repo, ADVERSARIAL)
        # A crate root that a #[cfg(test)] declaration also names, and a #[path] file: whole files are never scoped.
        write(self.repo, "src/main.rs", f"fn main() {{ {CALL} }}\n")
        write(self.repo, "src/support/fixture_impl.rs", f"fn fix() {{ {CALL} }}\n")
        doc = self.scan()
        lines = (self.repo / "src/lib.rs").read_text(encoding="utf-8").split("\n")
        seen = {}
        for f in doc["findings"]:
            if f["path"] == "src/lib.rs" and f["rule"] == RULE:
                name = lines[f["line"] - 1].split("fn ", 1)[1].split("(", 1)[0]
                seen[name] = (f.get("test_scope") or {}).get("kind")
        self.assertEqual(seen, EXPECTED)
        by_path = {f["path"]: f.get("test_scope") for f in doc["findings"] if f["rule"] == RULE}
        self.assertIsNone(by_path["src/main.rs"])
        self.assertIsNone(by_path["src/support/fixture_impl.rs"])
        # The scope rules' matches are never findings, in findings.json or the SARIF file.
        self.assertFalse([f for f in doc["findings"] if f["rule"].startswith("test-scope.")])
        sarif = (self.out / "findings.sarif").read_text(encoding="utf-8")
        self.assertNotIn("test-scope.", sarif)
        self.assertIn("shoalscan/test_scope", sarif)
        self.assertNotIn("test-scope.rust-cfg-test-item", doc["rule_ids"])

    def test_a_build_time_cfg_test_turns_scope_off(self):
        make_crate(self.repo, None)
        write(self.repo, "build.rs", 'fn main() {\n    println!("cargo:rustc-cfg=test");\n}\n')
        code, _, err = cli("scan", "--repo", str(self.repo), "--tools-dir", str(TOOLS), "--out", str(self.out))
        self.assertEqual(code, 0, err)
        self.assertIn("TEST SCOPE IS OFF", err)
        doc = json.loads((self.out / "findings.json").read_text(encoding="utf-8"))
        self.assertIn("build.rs", doc["test_scope"]["off"])
        self.assertFalse([f for f in doc["findings"] if "test_scope" in f])
        (self.repo / "build.rs").unlink()
        write(self.repo, ".cargo/config.toml", '[build]\nrustflags = ["--cfg", "test"]\n')
        doc = self.scan()
        self.assertIn(".cargo/config.toml", doc["test_scope"]["off"])
        self.assertFalse([f for f in doc["findings"] if "test_scope" in f])

    def test_a_shadowed_test_attribute_is_not_scope(self):
        lib = (FIXTURE / "src/lib.rs").read_text(encoding="utf-8")
        make_crate(self.repo, "use test_log::test;\n" + lib)
        doc = self.scan()
        kinds = {f["test_scope"]["kind"] for f in doc["findings"] if f["path"] == "src/lib.rs" and "test_scope" in f}
        self.assertEqual(kinds, {"cfg_test_module", "cfg_test_item"})
        self.assertEqual(doc["test_scope"]["test_fn_dropped"], 1)

    def test_the_module_name_cap_warns(self):
        make_crate(self.repo, None)
        with unittest.mock.patch.object(testscope, "MAX_MODULE_NAMES", 0):
            code, _, err = cli("scan", "--repo", str(self.repo), "--tools-dir", str(TOOLS), "--out", str(self.out))
        self.assertEqual(code, 0, err)
        self.assertIn("module names were left out", err)
        doc = json.loads((self.out / "findings.json").read_text(encoding="utf-8"))
        self.assertEqual(doc["test_scope"]["module_names_dropped"], 3)
        self.assertNotIn("cfg_test_module", {f["test_scope"]["kind"] for f in doc["findings"] if "test_scope" in f})

    def test_policy_off_runs_no_scope_rules(self):
        make_crate(self.repo, None, policy=False)
        doc = self.scan()
        self.assertNotIn("test_scope", doc)
        self.assertFalse([f for f in doc["findings"] if "test_scope" in f])
        self.assertNotIn("shoalscan/test_scope", (self.out / "findings.sarif").read_text(encoding="utf-8"))


# ---------------------------------------------------------------- end to end


@unittest.skipUnless(shutil.which("git") and tools_ready(), "needs git and the installed Opengrep")
class EndToEndTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.repo = self.base / "repo"
        self.out = self.base / "out"
        self.db = self.base / "history.sqlite3"
        make_crate(self.repo, None)
        git(self.repo, "init", "-q", "-b", "main")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "base")

    def tearDown(self):
        self.tmp.cleanup()

    def scan(self, *extra: str) -> dict:
        code, _, err = cli("scan", "--repo", str(self.repo), "--tools-dir", str(TOOLS), "--out", str(self.out), *extra)
        self.assertEqual(code, 0, err)
        return json.loads((self.out / "findings.json").read_text(encoding="utf-8"))

    def check(self, *extra: str) -> tuple[int, dict, str]:
        code, out, err = cli("check", "--repo", str(self.repo), "--out", str(self.out), *extra)
        line = [x for x in out.splitlines() if x.startswith("SHOALSCAN_SUMMARY ")]
        self.assertEqual(len(line), 1, out + err)
        (self.base / "check.txt").write_text(out, encoding="utf-8")
        return code, json.loads(line[0][len("SHOALSCAN_SUMMARY ") :]), out

    def record(self, code: int, when: str) -> None:
        commit = git(self.repo, "rev-parse", "HEAD").strip()
        rc, _, err = cli(
            "record",
            "--out",
            str(self.out),
            "--repo",
            str(self.repo),
            "--check-output",
            str(self.base / "check.txt"),
            "--check-exit",
            str(code),
            "--repo-name",
            "acme/demo",
            "--ref",
            "main",
            "--commit",
            commit,
            "--kind",
            "scheduled",
            "--scanned-at",
            when,
            "--db",
            str(self.db),
        )
        self.assertEqual(rc, 0, err)

    def test_policy_on_blocks_only_shipped_code(self):
        doc = self.scan()
        scoped = {(f["path"], f["test_scope"]["kind"]) for f in doc["findings"] if "test_scope" in f}
        self.assertEqual(
            scoped,
            {
                ("src/lib.rs", "cfg_test_module"),
                ("src/lib.rs", "test_fn"),
                ("src/lib.rs", "cfg_test_item"),
                ("tests/integration.rs", "test_fn"),
            },
        )
        code, summary, out = self.check()
        self.assertEqual(code, 1)
        self.assertEqual(summary["test_scoped"], 4)
        self.assertEqual(summary["new_blocking"], len(doc["findings"]) - 4)
        self.assertIn("Accepted as test-only code (never blocking): 4", out)
        blocked = json.loads((self.out / "check.json").read_text(encoding="utf-8"))["new_blocking"]
        # The rule [test_scope] does not list blocks even inside the test module.
        self.assertIn("repo.rules.other", {k[1] for k in blocked})
        # Whole files are never test scope: not a crate's tests/ (outside a test function), not the file a
        # #[cfg(test)] mod NAME; declaration loads.
        self.assertTrue(
            {"build.rs", "examples/demo.rs", "src/lib.rs", "src/helpers.rs", "tests/common/mod.rs"}
            <= {k[2] for k in blocked}
        )

    def test_policy_off(self):
        text = (self.repo / ".shoalscan.toml").read_text(encoding="utf-8")
        (self.repo / ".shoalscan.toml").write_text(text.split("[test_scope]")[0], encoding="utf-8")
        doc = self.scan()
        self.assertFalse([f for f in doc["findings"] if "test_scope" in f])
        code, summary, _ = self.check()
        self.assertEqual((code, summary["test_scoped"], summary["new_blocking"]), (1, 0, len(doc["findings"])))

    def test_a_gitleaks_rule_in_the_policy_is_refused(self):
        path = self.repo / ".shoalscan.toml"
        path.write_text(
            path.read_text(encoding="utf-8").replace('["repo.rules.temp-dir"]', '["gitleaks.generic-api-key"]'),
            encoding="utf-8",
        )
        code, _, err = cli("scan", "--repo", str(self.repo), "--tools-dir", str(TOOLS), "--out", str(self.out))
        self.assertEqual(code, 2)
        self.assertIn("a real secret in test code is still a leaked secret", err)

    def test_the_policy_comes_from_the_base(self):
        write(self.repo, "baseline.toml", "version = 1\n")
        git(self.repo, "add", "baseline.toml")
        git(self.repo, "commit", "-q", "-m", "baseline")
        base = git(self.repo, "rev-parse", "HEAD").strip()
        path = self.repo / ".shoalscan.toml"
        without = path.read_text(encoding="utf-8").split("[test_scope]")[0]
        # The change drops [test_scope] from its own copy: the base's policy still applies.
        git(self.repo, "checkout", "-q", "-b", "change")
        path.write_text(without, encoding="utf-8")
        git(self.repo, "commit", "-q", "-am", "drop the policy")
        doc = self.scan("--policy-ref", base)
        self.assertEqual(sum(1 for f in doc["findings"] if "test_scope" in f), 4)
        _, summary, out = self.check("--policy-ref", base)
        self.assertEqual(summary["test_scoped"], 4)
        self.assertIn("POLICY CHANGES", out)
        # The other way round: a change cannot turn the policy on for itself.
        git(self.repo, "checkout", "-q", "-b", "base-without", base)
        path.write_text(without, encoding="utf-8")
        git(self.repo, "commit", "-q", "-am", "a base without the policy")
        base2 = git(self.repo, "rev-parse", "HEAD").strip()
        git(self.repo, "checkout", "-q", "-b", "turn-on")
        git(self.repo, "checkout", "-q", base, "--", ".shoalscan.toml")
        git(self.repo, "commit", "-q", "-m", "turn it on")
        doc = self.scan("--policy-ref", base2)
        self.assertFalse([f for f in doc["findings"] if "test_scope" in f])
        _, summary, _ = self.check("--policy-ref", base2)
        self.assertEqual(summary["test_scoped"], 0)

    def test_moving_out_of_test_scope_blocks_again_and_supersedes_the_review(self):
        self.scan()
        code, _, _ = self.check()
        self.record(code, "2026-10-01T02:00:00Z")
        conn = history.open_read_only(self.db)
        try:
            rows = conn.execute(
                "SELECT path, status, updated_by, description, resolved_at FROM finding_reviews ORDER BY path"
            ).fetchall()
        finally:
            conn.close()
        self.assertEqual(len(rows), 4)
        for _path, status, who, description, resolved in rows:
            self.assertEqual((status, who), ("accepted_risk", AUTO_REVIEWER))
            self.assertTrue(description.startswith("test-only code: "), description)
            self.assertIsNotNone(resolved)
        module = [r for r in rows if r[0] == "src/lib.rs" and "cfg_test_module" in r[3]]
        self.assertEqual(module[0][3], "test-only code: cfg_test_module at src/lib.rs:7")

        # A person's review of the test-only impl is never replaced.
        data = self.dashboard()
        page = data.findings(self.repo_id, self.run_id, review="test_scope")["findings"]
        item = [f for f in page if f["test_scope"]["kind"] == "cfg_test_item"][0]
        self.conn.close()
        history.set_reviews(
            self.db, "acme/demo", [item["key"]], "wont_fix", "A person decided this one.", "a@b.example"
        )

        # The #[cfg(test)] goes: the same finding is in shipped code now.
        lib = self.repo / "src/lib.rs"
        text = lib.read_text(encoding="utf-8")
        lib.write_text(text.replace("#[cfg(test)]\nmod tests {", "mod tests {", 1), encoding="utf-8")
        git(self.repo, "commit", "-q", "-am", "ship the module")
        self.scan()
        code, summary, _ = self.check()
        self.assertEqual(code, 1)
        self.assertEqual(summary["test_scoped"], 3)
        blocked = json.loads((self.out / "check.json").read_text(encoding="utf-8"))["new_blocking"]
        self.assertIn(("src/lib.rs", RULE), {(k[2], k[1]) for k in blocked})
        self.record(code, "2026-10-02T02:00:00Z")
        conn = history.open_read_only(self.db)
        try:
            moved = conn.execute(
                "SELECT status, updated_by, description, resolved_at FROM finding_reviews WHERE path = 'src/lib.rs' "
                "AND description LIKE 'No longer in test-only code%'"
            ).fetchall()
            human = conn.execute("SELECT status, updated_by FROM finding_reviews WHERE status = 'wont_fix'").fetchall()
            events = conn.execute(
                "SELECT from_status, to_status, who FROM finding_review_events WHERE to_status = 'open'"
            ).fetchall()
        finally:
            conn.close()
        self.assertEqual(len(moved), 1)
        self.assertEqual((moved[0][0], moved[0][1], moved[0][3]), ("open", AUTO_REVIEWER, None))
        self.assertEqual(human, [("wont_fix", "a@b.example")])
        self.assertEqual(events, [("accepted_risk", "open", AUTO_REVIEWER)])

    def test_a_run_without_check_details_supersedes_automatic_reviews(self):
        self.scan()
        code, _, _ = self.check()
        self.record(code, "2026-10-01T02:00:00Z")
        write(self.repo, "NOTES.md", "a change\n")
        git(self.repo, "add", "NOTES.md")
        git(self.repo, "commit", "-q", "-m", "notes")
        self.scan()
        code, _, _ = self.check()
        (self.out / "check.json").unlink()  # a record with the check output only proves nothing
        self.record(code, "2026-10-02T02:00:00Z")
        conn = history.open_read_only(self.db)
        try:
            statuses = conn.execute("SELECT DISTINCT status, updated_by FROM finding_reviews").fetchall()
        finally:
            conn.close()
        self.assertEqual(statuses, [("open", AUTO_REVIEWER)])

    def dashboard(self) -> Data:
        self.conn = history.open_read_only(self.db)
        data = Data(self.conn)
        self.repo_id = data.repo_id("acme/demo")
        self.run_id = data.resolve_run(self.repo_id, None)
        return data

    def test_the_dashboard_shows_the_scope(self):
        self.scan()
        code, _, _ = self.check()
        self.record(code, "2026-10-01T02:00:00Z")
        data = self.dashboard()
        try:
            page = data.findings(self.repo_id, self.run_id, review="test_scope")
            self.assertEqual(page["total"], 4)
            helper = [f for f in page["findings"] if f["test_scope"]["kind"] == "cfg_test_module"][0]
            self.assertEqual(
                helper["test_scope"],
                {
                    "kind": "cfg_test_module",
                    "path": "src/lib.rs",
                    "line": 7,
                    "description": "test-only code: cfg_test_module at src/lib.rs:7",
                },
            )
            self.assertEqual(helper["review"]["updated_by"], AUTO_REVIEWER)
            self.assertEqual(helper["review"]["status"], "accepted_risk")
            self.assertEqual(data.review_counts(self.repo_id, self.run_id)["test_scoped"], 4)
            self.assertEqual(data.overview(self.repo_id)["latest_trend_run"]["test_scoped"], 4)
            shipped = data.findings(self.repo_id, self.run_id, path="build.rs")["findings"][0]
            self.assertIsNone(shipped["test_scope"])
        finally:
            self.conn.close()

    def test_baseline_guidance_and_prune(self):
        init = ("baseline", "init", "--repo", str(self.repo), "--tools-dir", str(TOOLS), "--out", str(self.out))
        code, _, err = cli(*init, "--issue", "#1", "--reason", "adopted")
        self.assertEqual(code, 0, err)
        size = (self.repo / "baseline.toml").read_text(encoding="utf-8").count("[[finding]]")
        code, summary, out = self.check()
        self.assertEqual((code, summary["stale"], summary["baseline_test_scoped"]), (0, 0, 4))
        self.assertIn("shoalscan baseline prune --test-scope", out)
        code, out, err = cli("baseline", "prune", "--test-scope", "--repo", str(self.repo), "--out", str(self.out))
        self.assertEqual(code, 0, err)
        self.assertIn("removed 4 entries", out)
        self.assertEqual((self.repo / "baseline.toml").read_text(encoding="utf-8").count("[[finding]]"), size - 4)
        code, summary, _ = self.check()
        self.assertEqual((code, summary["new"], summary["new_blocking"], summary["test_scoped"]), (0, 4, 0, 4))
        code, out, _ = cli("baseline", "prune", "--test-scope", "--repo", str(self.repo), "--out", str(self.out))
        self.assertIn("no entries", out)
        # Prune refuses findings made under another configuration.
        path = self.repo / ".shoalscan.toml"
        path.write_text(path.read_text(encoding="utf-8") + "\n", encoding="utf-8")
        code, _, err = cli("baseline", "prune", "--test-scope", "--repo", str(self.repo), "--out", str(self.out))
        self.assertEqual(code, 2)
        self.assertIn("another configuration", err)


# ---------------------------------------------------------------- migrations


class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.db = self.base / "history.sqlite3"
        conn = sqlite3.connect(self.db)
        for version, script in enumerate(history.MIGRATIONS[:13]):
            conn.executescript(f"{script}\nPRAGMA user_version = {version + 1};")
        conn.close()

    def tearDown(self):
        self.tmp.cleanup()

    def version(self, path: Path) -> int:
        conn = sqlite3.connect(path)
        try:
            return conn.execute("PRAGMA user_version").fetchone()[0]
        finally:
            conn.close()

    def check_backup(self, err: str) -> None:
        backup = self.base / "history.sqlite3.bak-schema13"
        self.assertTrue(backup.is_file())
        self.assertEqual(backup.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.version(backup), 13)
        self.assertEqual(self.version(self.db), history.SCHEMA_VERSION)
        self.assertIn(str(backup), err)

    def test_every_migration_backs_up_first(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            history.open_for_write(self.db).close()
        self.check_backup(err.getvalue())

    def test_serve_migrates_at_start(self):
        from shoalscan.dashboard import server

        auth = self.base / "auth"
        auth.mkdir(mode=0o700)
        config = server.ServeConfig(
            db=self.db,
            cert=self.base / "c",
            key=self.base / "k",
            auth_dir=auth,
            bind="127.0.0.1",
            port=0,
            hosts=("127.0.0.1",),
        )
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            server.App(config)
        self.check_backup(err.getvalue())


if __name__ == "__main__":
    unittest.main()
