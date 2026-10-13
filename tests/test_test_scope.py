"""Rust test scope: the scope rules, the policy, check, the baseline, the history and the dashboard.

The tests that run Opengrep need the installed tools (see test_end_to_end.py)
and are skipped without them; the rest run anywhere.
"""

import contextlib
import io
import json
import os
import shutil
import sqlite3
import subprocess
import tempfile
import unittest
import unittest.mock
from pathlib import Path

import helpers
from test_end_to_end import TOOLS, tools_ready

from shoalscan import gitref, history, testscope
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

    def test_trusted_build_scripts_are_refused(self):
        with self.assertRaisesRegex(SetupError, "no hash of it can vouch for it"):
            self.parse(f'[test_scope]\ntrusted_build_scripts = {{ "build.rs" = "{"a" * 64}" }}\n')

    def test_adoption_names_the_test_scope_keys_from_the_change(self):
        from shoalscan.cli import Policy, _print_adoption

        config = self.parse('[test_scope]\nnon_blocking = ["repo.rules.x.y"]\nallowed_rustc_wrappers = ["sccache"]\n')
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            _print_adoption(Policy(config, "refs/heads/main", "0" * 40, "x", adoption=True))
        self.assertIn(
            "ADOPTION: [test_scope] from this change: non_blocking = ['repo.rules.x.y']; "
            "allowed_rustc_wrappers = ['sccache']",
            out.getvalue(),
        )

    def test_allowed_rustc_wrappers(self):
        config = self.parse('[test_scope]\nallowed_rustc_wrappers = ["sccache"]\n')
        self.assertEqual(config.test_scope.allowed_rustc_wrappers, ("sccache",))
        for value in ('["sccache --x"]', '["/usr/bin/sccache"]', '["$WRAP"]', '"sccache"'):
            with self.assertRaises(SetupError, msg=value):
                self.parse(f"[test_scope]\nallowed_rustc_wrappers = {value}\n")

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

    def test_any_build_script_turns_scope_off(self):
        # A build script can read, include or run anything, so none is trusted, whatever its content.
        for name in ("build.rs", "BUILD.RS", "Build.rs", "crates/x/build.rs"):
            write(self.root, name, "fn main() {}\n")
            self.assertIn(name, self.repo().off or "", name)
            (self.root / name).unlink()
        self.assertIsNone(self.repo().off)
        for build in ('"tools/gen.rs"', "true"):
            write(self.root, "Cargo.toml", f'[package]\nname = "demo"\nbuild = {build}\n')
            self.assertIn("build script", self.repo().off or "", build)
        write(self.root, "Cargo.toml", '[package]\nname = "demo"\nbuild = false\n')
        self.assertIsNone(self.repo().off)

    def test_special_names_that_fold_to_cargo_names_turn_scope_off(self):
        # Reviewer repro: APFS folds the long s, so cargo runs `build.rſ` and rustup reads `ruſt-toolchain.toml`.
        for path in ("build.rſ", "crates/x/ruſt-toolchain.toml", "crates/y/\uff23argo.toml"):
            write(self.root, path, "fn main() {}\n")
            self.assertIn("case-insensitive", self.repo().off or "", path)
            (self.root / path).unlink()
        self.assertEqual(testscope.special_name("ＢＵＩＬＤ.ｒｓ"), "build.rs")  # full-width letters fold by NFKC
        self.assertIsNone(self.repo().off)

    def test_target_and_node_modules_are_walked(self):
        for path in ("target/member/Cargo.toml", "node_modules/pkg/Cargo.toml", "a/target/evil/Cargo.toml"):
            write(self.root, path, '[package]\nname = "x"\n[replace]\n"a:1.0.0" = { path = "a" }\n')
            self.assertIn(path, self.repo().off or "", path)
            (self.root / path).unlink()
        write(self.root, "target/member/build.rs", "fn main() {}\n")
        self.assertIn("target/member/build.rs", self.repo().off or "")

    def test_special_names_in_another_letter_case_turn_scope_off(self):
        for path in (
            "crates/y/cargo.toml",
            "crates/x/CARGO.TOML",
            ".Cargo/config.toml",
            ".cargo/Config.Toml",
            ".cargo/CONFIG",
            "Rust-Toolchain.toml",
            "RUST-TOOLCHAIN",
        ):
            write(self.root, path, "\n")
            self.assertIn("case-insensitive", self.repo().off or "", path)
            (self.root / path).unlink()
            if path.startswith(".Cargo/"):
                (self.root / ".Cargo").rmdir()
        self.assertIsNone(self.repo().off)

    def test_rust_toolchain(self):
        for text in (
            "stable\n",
            '[toolchain]\nchannel = "1.98.1"\ncomponents = ["clippy"]\n'
            'targets = ["wasm32-unknown-unknown"]\nprofile = "minimal"\n',
        ):
            write(self.root, "rust-toolchain.toml", text)
            self.assertIsNone(self.repo().off, text)
        for text in ('[toolchain]\npath = "/opt/evil"\n', '[toolchain]\nchannel = "x y"\n', "[other]\n", "not toml ["):
            write(self.root, "rust-toolchain", text)
            self.assertIsNotNone(self.repo().off, text)

    def test_allowed_rustc_wrappers(self):
        write(self.root, ".cargo/config.toml", '[build]\nrustc-wrapper = "sccache"\n')
        self.assertIsNone(testscope.read_repository(self.root, ("sccache",)).off)
        self.assertIsNotNone(testscope.read_repository(self.root).off)
        write(self.root, ".cargo/config.toml", '[build]\nrustc-wrapper = "./sccache"\n')
        self.assertIsNotNone(testscope.read_repository(self.root, ("sccache",)).off)

    def test_linkers_are_refused(self):
        for text in (
            '[target.x86_64-unknown-linux-gnu]\nlinker = "./ld.sh"\n',
            '[build]\nrustflags = ["-C", "linker=./ld.sh"]\n',
            '[build]\nrustflags = "-Clinker=./ld.sh"\n',
            '[target.x]\nrustflags = ["-C", "linker-flavor=ld"]\n',
        ):
            write(self.root, ".cargo/config.toml", text)
            self.assertIn("link", self.repo().off or "", text)

    def test_a_directory_that_cannot_be_listed_turns_scope_off(self):
        locked = self.root / "locked"
        locked.mkdir()
        locked.chmod(0)
        try:
            self.assertIn("could not be listed", self.repo().off or "")
        finally:
            locked.chmod(0o700)

    def test_cargo_files_must_be_fully_understood(self):
        off = {
            ".cargo/config.toml": [
                '[build]\nrustflags = ["--cfg", "test"]\n',
                '[build]\nrustflags = ["--cfg", "\\u0074est"]\n',
                '[build]\nrustflags = "-Z unstable-options"\n',
                '[build]\nrustflags = ["@argfile"]\n',
                '[build]\nrustflags = ["--crate-attr=cfg(test)"]\n',
                '[build]\nrustc-wrapper = "./wrap.sh"\n',
                '[build]\nrustc = "./rustc"\n',
                '[build]\nrustc-workspace-wrapper = "./wrap.sh"\n',
                'paths = ["vendor/tokio"]\n',
                '[source.crates-io]\nreplace-with = "vendored"\n',
                '[patch.crates-io]\ntokio = { path = "vendor/tokio" }\n',
                '[env]\nRUSTFLAGS = "--cfg test"\n',
                '[target.x86_64-unknown-linux-gnu]\nrustflags = ["-C", "link-arg=-s", "--cfg=test"]\n',
                "not toml [",
            ],
            "Cargo.toml": [
                '[package]\nname = "demo"\n[patch.crates-io]\ntokio = { git = "https://example.invalid/tokio" }\n',
                '[package]\nname = "demo"\n[patch.crates-io]\ntokio = { path = "../outside/tokio" }\n',
                '[package]\nname = "demo"\n[replace]\n"tokio:1.0.0" = { path = "vendor/tokio" }\n',
                'cargo-features = ["profile-rustflags"]\n[package]\nname = "demo"\n',
                '[package]\nname = "demo"\n[profile.release]\nrustflags = ["--cfg", "test"]\n',
                '[package]\nname = "demo"\nunknown-key = 1\n',
                '[package]\nname = "demo"\n[target.x]\nrustflags = []\n',
                "[package\n",
            ],
            "nested/target/evil/Cargo.toml": ['[package]\nname = "x"\n[replace]\n"a:1.0.0" = { path = "a" }\n'],
        }
        for path, texts in off.items():
            for text in texts:
                write(self.root, path, text)
                self.assertIsNotNone(self.repo().off, f"{path}: {text}")
            if path == "Cargo.toml":
                write(self.root, path, '[package]\nname = "demo"\n')
            else:
                (self.root / path).unlink()
        self.assertIsNone(self.repo().off)
        # What the reviewed repository uses stays on.
        write(
            self.root,
            "a/.cargo/config.toml",
            '[build]\ntarget = "bpfel-unknown-none"\n[unstable]\nbuild-std = ["core"]\n',
        )
        write(
            self.root,
            "b/.cargo/config.toml",
            '[target.x86_64-unknown-linux-gnu]\nrustflags = ["-C", "link-arg=-Wl,-z,relro", "-Ctarget-cpu=native"]\n',
        )
        write(
            self.root,
            "Cargo.toml",
            '[package]\nname = "demo"\nedition = "2021"\n[dependencies]\ntokio = { version = "1", features = ["rt"] }\n'
            "[profile.release]\nlto = true\n[profile.release.package.x]\nopt-level = 3\n"
            '[target.\'cfg(unix)\'.dependencies]\nlibc = "0.2"\n[workspace]\nmembers = ["a"]\n'
            '[patch.crates-io]\npingora-rustls = { path = "vendor/pingora-rustls" }\n',
        )
        self.assertIsNone(self.repo().off)

    def test_rustflags_forms(self):
        from shoalscan.cargotrust import rustflags_problem

        for good in (["-C", "opt-level=3"], "-Copt-level=3 -L native=/x -lfoo -A warnings -Dunsafe_code", []):
            self.assertIsNone(rustflags_problem(good), good)
        for bad in (["--cfg", "test"], ["-C"], "-Zfoo", ["--cfg=test"], ["@file"], [1], {"a": 1}, "-Clinker=x"):
            self.assertIsNotNone(rustflags_problem(bad), bad)

    def test_a_linked_directory_turns_scope_off(self):
        os.symlink(self.root / "src", self.root / "linked")
        self.assertIn("symbolic link", self.repo().off or "")

    def test_spelling_is_checked_again(self):
        self.assertTrue(testscope.spelled_as_recognised("#[cfg( test )]\n/// doc\nfn a() {}"))
        self.assertTrue(testscope.spelled_as_recognised("#[allow(x)]\n#[cfg(all(unix, test))]\nmod m {}"))
        for text in (
            "#[cfg(r#test)]\nfn a() {}",
            "#[cfg(all(not(test), unix))]\nfn a() {}",
            "#[cfg(any(test, unix))]\nfn a() {}",
            '#[cfg_attr(feature = "x", cfg(test))]\nfn a() {}',
            "// #[cfg(test)]\nfn a() {}",
        ):
            self.assertFalse(testscope.spelled_as_recognised(text), text)
        self.assertFalse(testscope.spelled_as_recognised("#[test]\nfn a() {}"))

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
        write(self.root, "src/lib.rs", "#[cfg(test)]\nfn helper() {}\n")
        match = {
            "check_id": testscope.ITEM_RULE,
            "path": str(self.root / "src/lib.rs"),
            "start": {"line": 1, "col": 1, "offset": 0},
            "end": {"line": 2, "col": 15, "offset": 27},
        }
        self.assertEqual(testscope.build(self.root, [match]).scope_for("src/lib.rs", 13, 27).kind, "cfg_test_item")
        unparsed = frozenset({"src/lib.rs"})
        self.assertIsNone(testscope.build(self.root, [match], unparsed).scope_for("src/lib.rs", 13, 27))

    def test_a_finding_must_lie_wholly_inside_the_item(self):
        scopes = testscope.ScopeMap({"a.rs": [(10, 20, TestScope("cfg_test_item", "a.rs", 1))]})
        self.assertIsNotNone(scopes.scope_for("a.rs", 10, 20))
        for start, end in ((5, 12), (15, 25), (0, 9), (21, 30), (None, 12)):
            self.assertIsNone(scopes.scope_for("a.rs", start, end), (start, end))

    def test_never_test_scope(self):
        for path in ("examples/x.rs", "build.rs", "crate/build.rs", "src/bin/tool.rs", "crate/src/bin/a/main.rs"):
            self.assertTrue(testscope.never_test_scope(path), path)
        self.assertFalse(testscope.never_test_scope("src/binary.rs"))


# ---------------------------------------------------------------- what a change touches (git, no Opengrep)

# Review 4's repros, each a file a pull request adds. Every one is outside Rust source, so the change loses
# test scope however the file's content is spelled.
CHANGE_REPROS = {
    "shell quoting": ("ci/build.sh", 'RUSTFLAGS="--cfg te"st cargo build --release\n'),
    "split flag": ("ci/build2.sh", 'RUSTFLAGS="--c""fg test" \\\n  cargo build\n'),
    "comment in a string": (
        "ci/gen.py",
        'open(".cargo/config.toml", "w").write("""\n# x\n[build]\nrustflags=1\n""")\n',
    ),
    "Makefile continuation": ("Makefile", 'all:\n\tRUSTFLAGS="--cfg \\\n test" cargo build\n'),
    "TOML escape": ("ci/cfg.sh", 'cargo build --config \'build.rustflags=["\\u002D-cfg","test"]\'\n'),
    "YAML escape": (".github/workflows/r.yml", 'env:\n  RUSTFLAGS: "\\x2D\\x2Dcfg test"\n'),
    "quoted variable name": ("ci/enc.sh", "export 'CARGO_ENCODED_RUSTFLAGS'=--cfg\x1ftest\n"),
    "argfile in prose": ("docs/flags.md", "--cfg\ntest\n"),
    "config in prose": ("docs/cfg.md", '[build]\nrustflags = ["--cfg", "test"]\n'),
    "NUL byte script": ("ci/nul.sh", "\0RUSTFLAGS='--cfg test' cargo build\n"),
    "CARGO_HOME config": ("ci/home/config.toml", '[build]\nrustflags = ["--cfg", "test"]\n'),
    "long-s build script": ("build.rſ", 'fn main() { println!("cargo:rustc-cfg=test"); }\n'),
    "long-s toolchain": ("ruſt-toolchain.toml", '[toolchain]\npath = "/tmp/evil"\n'),
    "member under target": ("target/m/src/lib.rs", "pub fn f() {}\n"),
    "member under node_modules": ("node_modules/m/src/lib.rs", "pub fn f() {}\n"),
    "build script text": ("src/build.rs", 'fn main() { println!("cargo:rustc-cfg=test"); }\n'),
    "linker setting": (".cargo/config.toml", '[target.x86_64-unknown-linux-gnu]\nlinker = "./ld.sh"\n'),
}


@unittest.skipUnless(shutil.which("git"), "needs git")
class ChangeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        write(self.root, "Cargo.toml", '[package]\nname = "demo"\n')
        write(self.root, "src/lib.rs", "#[cfg(test)]\nmod tests {}\n")
        write(self.root, ".gitignore", "/ignored-output/\n")
        git(self.root, "init", "-q", "-b", "main")
        git(self.root, "add", "-A")
        git(self.root, "commit", "-q", "-m", "base")
        self.base = git(self.root, "rev-parse", "HEAD").strip()
        git(self.root, "checkout", "-q", "-b", "change")

    def tearDown(self):
        self.tmp.cleanup()

    def problem(self) -> str | None:
        return testscope.change_problem(gitref.changed_entries(self.root, self.base)[1])

    def test_a_rust_only_change_keeps_scope(self):
        write(self.root, "src/lib.rs", "#[cfg(test)]\nmod tests { fn t() {} }\n")
        write(self.root, "src/new.rs", "pub fn f() {}\n")
        git(self.root, "add", "src/new.rs")
        git(self.root, "commit", "-q", "-am", "rust")
        write(self.root, "src/untracked.rs", "pub fn g() {}\n")
        write(self.root, "ignored-output/x.txt", "build output\n")  # ignored: produced by the trusted CI
        self.assertIsNone(self.problem())

    def test_every_repro_loses_scope(self):
        for name, (path, text) in CHANGE_REPROS.items():
            with self.subTest(name):
                (self.root / path).parent.mkdir(parents=True, exist_ok=True)
                (self.root / path).write_text(text, encoding="utf-8")
                problem = self.problem()
                self.assertIn(path, problem or "", name)
                (self.root / path).unlink()

    def test_committed_staged_and_untracked_changes_all_count(self):
        write(self.root, "ci.yml", "a: b\n")
        self.assertIn("ci.yml", self.problem() or "")  # untracked
        git(self.root, "add", "ci.yml")
        self.assertIn("ci.yml", self.problem() or "")  # staged
        git(self.root, "commit", "-q", "-m", "yaml")
        self.assertIn("ci.yml", self.problem() or "")  # committed

    def test_deletions_renames_links_and_modes_lose_scope(self):
        git(self.root, "mv", "src/lib.rs", "src/moved.rs")
        git(self.root, "commit", "-q", "-m", "rename")
        self.assertIn("deletes src/lib.rs", self.problem() or "")  # both sides of a rename count
        git(self.root, "reset", "-q", "--hard", self.base)
        os.chmod(self.root / "src/lib.rs", 0o755)
        self.assertIn("mode", self.problem() or "")
        os.chmod(self.root / "src/lib.rs", 0o644)
        os.symlink("lib.rs", self.root / "src/link.rs")
        self.assertIn("src/link.rs", self.problem() or "")

    def test_an_unresolvable_base_loses_scope(self):
        git(self.root, "checkout", "-q", "--orphan", "unrelated")
        git(self.root, "commit", "-q", "-m", "unrelated history")
        with self.assertRaises(SetupError):
            gitref.changed_entries(self.root, self.base)


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

#[rstest]
fn rstest_case() {{ {CALL} }}

#[cfg(all(test, unix))]
fn all_test() {{ {CALL} }}

#[cfg(all(unix, not(test)))]
fn all_not_test() {{ {CALL} }}

#[cfg(r#test)]
fn raw_test() {{ {CALL} }}

#[cfg_attr(feature = "x", cfg(test))]
fn cfg_attr_cfg_test() {{ {CALL} }}

#[cfg(test)]
struct Carried;
fn after_a_cfg_test_struct() {{ {CALL} }}

#[cfg(all(test, unix))]
mod all_module {{
    fn i() {{ {CALL} }}
}}
"""

# The function name on each call's line, and the scope kind it must get (None: not test scope).
EXPECTED = {
    "a": None,
    "b": "cfg_test_module",
    "c": None,
    "test_in_a_plain_module": None,
    "top_level_test": None,
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
    "async_test": None,
    "rstest_case": None,
    "all_test": "cfg_test_item",
    "all_not_test": None,
    "raw_test": None,
    "cfg_attr_cfg_test": None,
    "after_a_cfg_test_struct": None,
    "i": "cfg_test_module",
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

    def test_build_scripts_and_linkers_turn_scope_off(self):
        make_crate(self.repo, None)
        write(self.repo, "BUILD.RS", 'fn main() {\n    println!("cargo:rustc\\x2dcfg=test");\n}\n')
        code, _, err = cli("scan", "--repo", str(self.repo), "--tools-dir", str(TOOLS), "--out", str(self.out))
        self.assertEqual(code, 0, err)
        self.assertIn("TEST SCOPE IS OFF", err)
        doc = json.loads((self.out / "findings.json").read_text(encoding="utf-8"))
        self.assertIn("BUILD.RS", doc["test_scope"]["off"])
        self.assertFalse([f for f in doc["findings"] if "test_scope" in f])
        (self.repo / "BUILD.RS").unlink()
        write(self.repo, ".cargo/config.toml", '[target.x86_64-unknown-linux-gnu]\nlinker = "./ld.sh"\n')
        doc = self.scan()
        self.assertIn(".cargo/config.toml", doc["test_scope"]["off"])
        self.assertFalse([f for f in doc["findings"] if "test_scope" in f])

    def test_test_functions_are_not_scope(self):
        # Reviewer repros: `#[test]` can mean another macro (an include!d `use pm::test`, a nightly
        # `macro_rules! test` attribute), and so can #[tokio::test] and #[rstest]: none is test scope in 0.3.0.
        lib = (
            "pub mod prelude {\n    pub mod tokio { pub use pm2::test; }\n    pub use pm2::rstest;\n}\n"
            f"#[test]\nfn builtin() {{ {CALL} }}\n"
        )
        make_crate(self.repo, lib)
        glob = f"use crate::prelude::*;\n#[tokio::test]\npub fn f() {{ {CALL} }}\n#[rstest]\npub fn g() {{ {CALL} }}\n"
        write(self.repo, "src/a.rs", glob)
        doc = self.scan()
        scoped = [f for f in doc["findings"] if "test_scope" in f]
        self.assertFalse([f for f in scoped if f["path"] in ("src/a.rs",) or f["line"] == 6])
        self.assertNotIn("test_fn", {f["test_scope"]["kind"] for f in scoped})

    def test_shipped_code_on_the_same_line_as_a_test_item_is_not_scope(self):
        shipped = "pub fn shipped() -> std::path::PathBuf { std::env::temp_dir() }"
        lib = (
            f"{shipped} #[cfg(test)] fn before() {{}}\n"
            f"#[cfg(test)] fn after() {{}} {shipped}\n"
            f"#[cfg(test)]\nmod tests {{\n    fn x() {{}}\n}} {shipped}\n"
            f"#[cfg(test)] const X: u8 = 1; {shipped}\n"
            f"#[cfg(test)] fn inside() {{ {CALL} }}\n"
        )
        make_crate(self.repo, lib)
        doc = self.scan()
        found = {f["line"]: f.get("test_scope") for f in doc["findings"] if f["path"] == "src/lib.rs"}
        self.assertEqual(sorted(found), [1, 2, 6, 7, 8])
        self.assertEqual(
            {line: bool(scope) for line, scope in found.items()}, {1: False, 2: False, 6: False, 7: False, 8: True}
        )

    def test_a_file_that_does_not_parse_gets_no_scope(self):
        make_crate(self.repo, None)
        write(self.repo, "src/broken.rs", f"#[cfg(test)]\nmod tests {{\n    fn x() {{ {CALL} }}\n}}\nfn ( {{\n")
        doc = self.scan()
        self.assertFalse([f for f in doc["findings"] if f["path"] == "src/broken.rs" and "test_scope" in f])
        self.assertIn("src/broken.rs", {e["path"] for e in doc["unscanned"]["errors"]})

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
                ("src/lib.rs", "cfg_test_item"),
            },
        )
        code, summary, out = self.check()
        self.assertEqual(code, 1)
        self.assertEqual(summary["test_scoped"], 2)
        self.assertEqual(summary["new_blocking"], len(doc["findings"]) - 2)
        self.assertIn("Accepted as test-only code (never blocking): 2", out)
        blocked = json.loads((self.out / "check.json").read_text(encoding="utf-8"))["new_blocking"]
        # The rule [test_scope] does not list blocks even inside the test module.
        self.assertIn("repo.rules.other", {k[1] for k in blocked})
        # Whole files are never test scope: not a crate's tests/ (outside a test function), not the file a
        # #[cfg(test)] mod NAME; declaration loads.
        self.assertTrue(
            {"examples/demo.rs", "src/lib.rs", "src/helpers.rs", "tests/common/mod.rs", "tests/integration.rs"}
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

    def base_with_baseline(self) -> str:
        write(self.repo, "baseline.toml", "version = 1\n")
        git(self.repo, "add", "baseline.toml")
        git(self.repo, "commit", "-q", "-m", "baseline")
        return git(self.repo, "rev-parse", "HEAD").strip()

    def scoped(self, doc: dict) -> int:
        return sum(1 for f in doc["findings"] if "test_scope" in f)

    def test_a_rust_only_pull_request_keeps_scope(self):
        base = self.base_with_baseline()
        git(self.repo, "checkout", "-q", "-b", "change")
        lib = self.repo / "src/lib.rs"
        lib.write_text(lib.read_text(encoding="utf-8") + "\npub fn more() {}\n", encoding="utf-8")
        git(self.repo, "commit", "-q", "-am", "rust only")
        doc = self.scan("--policy-ref", base)
        self.assertIsNone(doc["test_scope"]["off"])
        self.assertEqual(doc["test_scope"]["change"]["changed_paths"], 1)
        self.assertEqual(self.scoped(doc), 2)
        _, summary, _ = self.check("--policy-ref", base)
        self.assertEqual(summary["test_scoped"], 2)

    def test_a_pull_request_that_touches_anything_else_loses_scope(self):
        base = self.base_with_baseline()
        git(self.repo, "checkout", "-q", "-b", "change")
        write(self.repo, ".github/workflows/ci.yml", "env:\n  RUSTFLAGS: --cfg test\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "a workflow")
        code, _, err = cli(
            "scan", "--repo", str(self.repo), "--tools-dir", str(TOOLS), "--out", str(self.out), "--policy-ref", base
        )
        self.assertEqual(code, 0, err)
        self.assertIn("TEST SCOPE IS OFF for this scan: the change touches .github/workflows/ci.yml", err)
        doc = json.loads((self.out / "findings.json").read_text(encoding="utf-8"))
        self.assertEqual(self.scoped(doc), 0)
        # A change to the policy itself is such a change too: the base's [test_scope] cannot be dropped
        # or turned on by the pull request, and it does not apply to one that touches the policy file.
        git(self.repo, "checkout", "-q", "-b", "drop-policy", base)
        path = self.repo / ".shoalscan.toml"
        path.write_text(path.read_text(encoding="utf-8").split("[test_scope]")[0], encoding="utf-8")
        git(self.repo, "commit", "-q", "-am", "drop the policy")
        doc = self.scan("--policy-ref", base)
        self.assertIn(".shoalscan.toml", doc["test_scope"]["off"])
        self.assertEqual(self.scoped(doc), 0)

    def test_an_unresolvable_base_loses_scope(self):
        # A base with no history in common with the scanned tree (as in a shallow clone without the merge base).
        self.base_with_baseline()
        git(self.repo, "checkout", "-q", "--orphan", "other-base")
        git(self.repo, "commit", "-q", "-m", "unrelated base")
        base = git(self.repo, "rev-parse", "HEAD").strip()
        git(self.repo, "checkout", "-q", "main")
        code, _, err = cli(
            "scan", "--repo", str(self.repo), "--tools-dir", str(TOOLS), "--out", str(self.out), "--policy-ref", base
        )
        self.assertEqual(code, 0, err)
        self.assertIn("could not be compared", err)
        self.assertIn("fetch-depth", err)
        doc = json.loads((self.out / "findings.json").read_text(encoding="utf-8"))
        self.assertEqual(self.scoped(doc), 0)

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
        self.assertEqual(len(rows), 2)
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
        self.assertEqual(summary["test_scoped"], 1)
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
            self.assertEqual(page["total"], 2)
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
            self.assertEqual(data.review_counts(self.repo_id, self.run_id)["test_scoped"], 2)
            self.assertEqual(data.overview(self.repo_id)["latest_trend_run"]["test_scoped"], 2)
            shipped = data.findings(self.repo_id, self.run_id, path="examples/demo.rs")["findings"][0]
            self.assertIsNone(shipped["test_scope"])
        finally:
            self.conn.close()

    def test_baseline_guidance_and_prune(self):
        init = ("baseline", "init", "--repo", str(self.repo), "--tools-dir", str(TOOLS), "--out", str(self.out))
        code, _, err = cli(*init, "--issue", "#1", "--reason", "adopted")
        self.assertEqual(code, 0, err)
        size = (self.repo / "baseline.toml").read_text(encoding="utf-8").count("[[finding]]")
        code, summary, out = self.check()
        self.assertEqual((code, summary["stale"], summary["baseline_test_scoped"]), (0, 0, 2))
        self.assertIn("shoalscan baseline prune --test-scope", out)
        code, out, err = cli("baseline", "prune", "--test-scope", "--repo", str(self.repo), "--out", str(self.out))
        self.assertEqual(code, 0, err)
        self.assertIn("removed 2 entries", out)
        self.assertEqual((self.repo / "baseline.toml").read_text(encoding="utf-8").count("[[finding]]"), size - 2)
        code, summary, _ = self.check()
        self.assertEqual((code, summary["new"], summary["new_blocking"], summary["test_scoped"]), (0, 2, 0, 2))
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
