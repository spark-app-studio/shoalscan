"""Gitleaks: its pin and install, a hardened command line, a fail-closed run, and findings that hold no secret."""

import contextlib
import copy
import io
import json
import shutil
import stat
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path

import helpers

from shoalscan import gitleaks
from shoalscan import install as inst
from shoalscan.cli import main
from shoalscan.config import Limits, parse_config
from shoalscan.errors import ScanError, SetupError, VerificationError
from shoalscan.lockfile import load_lock, parse_lock, sha256_file
from test_lock_and_install import GITLEAKS_BINARY, PLAT, Assets, sha, tool_tarball

LOCK_PATH = helpers.ROOT / "tools.lock"
TOOLS = helpers.tools_dir()
# Built in pieces, so this file holds no real-looking secret that a scanner would report.
SECRET = "ghp_" + "R2xq7Wd9TbKz4LmN8pQs3VhY6cJf1aEu5oGi"
AWS = "AKIA" + "Z4XQ7RJHJ2KQK6WN"


def gitleaks_ready() -> bool:
    lock = load_lock(LOCK_PATH)
    tool = lock.tools["gitleaks"]
    binary, config = inst.tool_path(TOOLS, "gitleaks"), inst.tool_file_path(TOOLS, "gitleaks", "config")
    try:
        return sha256_file(binary) == tool.platforms[inst.current_platform()].binary_sha256 and sha256_file(config) == tool.files["config"].sha256
    except (OSError, KeyError):
        return False


class LockTests(unittest.TestCase):
    def test_shipped_lock_pins_gitleaks_everywhere(self):
        tool = load_lock(LOCK_PATH).tools["gitleaks"]
        self.assertEqual((tool.version, tool.license, tool.member), ("8.30.1", "MIT", "gitleaks"))
        self.assertEqual(set(tool.platforms), {"darwin-x86_64", "darwin-arm64", "linux-x86_64", "linux-arm64"})
        self.assertIn("83d9cd684c87d95d656c1458ef04895a7f1cbd8e", tool.files["config"].url)

    def test_a_lock_without_gitleaks_is_still_valid(self):
        data = tomllib.loads(LOCK_PATH.read_text(encoding="utf-8"))
        del data["gitleaks"]
        self.assertNotIn("gitleaks", parse_lock(data).tools)

    def test_bad_entries_are_refused(self):
        base = tomllib.loads(LOCK_PATH.read_text(encoding="utf-8"))
        mutations = [
            lambda g: g.__setitem__("member", "../gitleaks"),
            lambda g: g.__setitem__("member", "/gitleaks"),
            lambda g: g.pop("config"),
            lambda g: g.__setitem__("extra", 1),
            lambda g: g["platforms"][PLAT].pop("binary_sha256"),
            lambda g: g["platforms"][PLAT].__setitem__("url", "http://example.com/x.tar.gz"),
            # A bare binary (no member) must have one hash for the download and the binary.
            lambda g: g.pop("member"),
        ]
        for mutate in mutations:
            data = copy.deepcopy(base)
            mutate(data["gitleaks"])
            with self.subTest(mutate=mutate), self.assertRaises(SetupError):
                parse_lock(data)


class InstallTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.tools = self.dir / "tools"
        self.tools.mkdir()
        self.work = self.dir / "work"
        self.work.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def lock_with(self, archive: bytes, binary: bytes = GITLEAKS_BINARY):
        assets = Assets()
        data = tomllib.loads(LOCK_PATH.read_text(encoding="utf-8"))
        gl = data["gitleaks"]
        assets.files[gl["platforms"][PLAT]["url"]] = archive
        gl["platforms"][PLAT]["sha256"], gl["platforms"][PLAT]["binary_sha256"] = sha(archive), sha(binary)
        assets.files[gl["config"]["url"]] = b"config"
        gl["config"]["sha256"] = sha(b"config")
        return parse_lock(data).tools["gitleaks"], assets

    def install(self, tool, assets):
        with contextlib.redirect_stderr(io.StringIO()):
            inst.install_pinned_tool(self.tools, tool, PLAT, assets.fetch, self.work)

    def test_installs_the_member_and_config_then_verifies_in_place(self):
        tool, assets = self.lock_with(tool_tarball({"README.md": b"x", "gitleaks": GITLEAKS_BINARY}))
        self.install(tool, assets)
        binary = inst.tool_path(self.tools, "gitleaks")
        self.assertEqual(binary.read_bytes(), GITLEAKS_BINARY)
        self.assertTrue(binary.stat().st_mode & stat.S_IXUSR)
        self.assertEqual(inst.tool_file_path(self.tools, "gitleaks", "config").read_bytes(), b"config")
        self.assertFalse((self.tools / "README.md").exists())
        assets.requests.clear()
        self.install(tool, assets)
        self.assertEqual(assets.requests, [])

    def test_a_binary_that_does_not_match_its_pin_is_refused(self):
        tool, assets = self.lock_with(tool_tarball({"gitleaks": b"something else"}))
        with self.assertRaises(VerificationError):
            self.install(tool, assets)
        self.assertFalse(inst.tool_path(self.tools, "gitleaks").exists())

    def test_odd_archives_are_refused(self):
        for archive in (
            tool_tarball({"README.md": b"x"}),
            tool_tarball({}, links={"gitleaks": "/bin/sh"}),
            tool_tarball({"gitleaks": GITLEAKS_BINARY, "./gitleaks": GITLEAKS_BINARY}),
        ):
            tool, assets = self.lock_with(archive)
            with self.subTest(archive=len(archive)), self.assertRaises(VerificationError):
                self.install(tool, assets)

    def test_a_tampered_download_is_refused(self):
        tool, assets = self.lock_with(tool_tarball({"gitleaks": GITLEAKS_BINARY}))
        assets.files[tool.platforms[PLAT].download.url] = tool_tarball({"gitleaks": b"evil"})
        with self.assertRaises(VerificationError):
            self.install(tool, assets)


class CommandTests(unittest.TestCase):
    def test_repository_controlled_silencing_is_turned_off(self):
        cmd = gitleaks.build_command(Path("/t/gitleaks"), Path("/repo"), Path("/t/cfg"), Path("/s/ign"), Path("/s/r.json"), Limits(max_target_bytes=2_500_000))
        joined = " ".join(cmd)
        self.assertIn("--config /t/cfg", joined)
        self.assertIn("--gitleaks-ignore-path /s/ign", joined)
        self.assertIn("--ignore-gitleaks-allow", cmd)
        self.assertIn(f"--exit-code {gitleaks.LEAKS_EXIT}", joined)
        self.assertIn("--max-target-megabytes 3", joined)
        self.assertNotIn("--redact", joined)  # the secret is needed, briefly, to mask it out of the fingerprint
        self.assertNotIn("--follow-symlinks", cmd)

    def test_rule_ids_come_from_the_pinned_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "c.toml"
            cfg.write_text('[[rules]]\nid = "b-rule"\n[[rules]]\nid = "a-rule"\n')
            self.assertEqual(gitleaks.rule_ids(cfg), ["gitleaks.a-rule", "gitleaks.b-rule"])
            for bad in ("title = 'x'\n", '[[rules]]\nid = "a b"\n', "not toml ["):
                cfg.write_text(bad)
                with self.subTest(bad=bad), self.assertRaises(SetupError):
                    gitleaks.rule_ids(cfg)


class ExecuteTests(unittest.TestCase):
    """A stand-in script plays Gitleaks: it writes a report to the path after --report-path."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.report = self.dir / "report.json"

    def tearDown(self):
        self.tmp.cleanup()

    def run_standin(self, report: str | None, code: int):
        script = self.dir / "gitleaks"
        write = f"printf '%s' '{report}' > '{self.report}'\n" if report is not None else ""
        script.write_text(f"#!/bin/sh\n{write}exit {code}\n")
        script.chmod(0o755)
        return gitleaks.execute([str(script)], self.dir, self.report, 30)

    def test_clean_and_leaky_runs_are_accepted(self):
        self.assertEqual(self.run_standin("[]", 0), [])
        self.assertEqual(len(self.run_standin('[{"RuleID": "x"}]', gitleaks.LEAKS_EXIT)), 1)

    def test_anything_else_fails_the_scan(self):
        cases = [("[]", 1), ("[]", 2), (None, 0), ("{}", 0), ("not json", 0), ("[]", gitleaks.LEAKS_EXIT), ('[{"RuleID": "x"}]', 0)]
        for report, code in cases:
            self.report.unlink(missing_ok=True)
            with self.subTest(report=report, code=code), self.assertRaises(ScanError):
                self.run_standin(report, code)


class NormaliseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        (self.root / "src").mkdir()
        (self.root / "vendor").mkdir()
        (self.root / ".git").mkdir()
        (self.root / "src" / "app.py").write_text(f'class Client:\n    def connect(self):\n        token = "{SECRET}"\n        other = "{SECRET}"\n')
        (self.root / "vendor" / "lib.py").write_text(f'key = "{AWS}"\n')

    def tearDown(self):
        self.tmp.cleanup()

    def entry(self, path, line, secret=SECRET, rule="github-pat", col=17):
        return {"RuleID": rule, "File": str(self.root / path), "StartLine": line, "EndLine": line, "StartColumn": col,
                "EndColumn": col + len(secret), "Secret": secret, "Match": f'token = "{secret}"', "Description": "Found a GitHub token."}  # fmt: skip

    def normalise(self, report, excludes=("vendor",)):
        return gitleaks.normalise(report, self.root, {"src/": "app"}, excludes)

    def test_findings_hold_no_secret_and_skip_excluded_paths(self):
        report = [self.entry("src/app.py", 3), self.entry("src/app.py", 4), self.entry("vendor/lib.py", 1, AWS, "aws-access-token"),
                  self.entry(".git/config", 1)]  # fmt: skip
        found = self.normalise(report)
        self.assertEqual([(f.rule, f.path, f.line, f.component, f.severity) for f in found],
                         [("gitleaks.github-pat", "src/app.py", 3, "app", "ERROR"), ("gitleaks.github-pat", "src/app.py", 4, "app", "ERROR")])  # fmt: skip
        dumped = json.dumps([f.__dict__ for f in found])
        self.assertNotIn(SECRET, dumped)
        self.assertNotIn(SECRET[4:20], dumped)
        self.assertEqual(found[0].message, "Found a GitHub token.")

    def test_fingerprints_follow_the_line_not_the_secret(self):
        first = self.normalise([self.entry("src/app.py", 3)])[0]
        # A rotated secret on the same line is the same leak; a moved line keeps its fingerprint.
        rotated = SECRET[:-4] + "ZZZZ"
        (self.root / "src" / "app.py").write_text(f'class Client:\n\n    def connect(self):\n        token = "{rotated}"\n')
        moved = self.normalise([self.entry("src/app.py", 4, rotated)])[0]
        self.assertEqual(first.fingerprint, moved.fingerprint)
        other_rule = self.normalise([self.entry("src/app.py", 4, rotated, "generic-api-key")])[0]
        self.assertNotEqual(first.fingerprint, other_rule.fingerprint)

    def test_a_secret_found_decoded_falls_back_to_rule_and_context(self):
        self.assertEqual(gitleaks.masked_code(["x = 'Z2hw...'"], 1, 1, SECRET), "")
        self.assertEqual(gitleaks.masked_code([f"a {SECRET} b {SECRET}"], 1, 1, SECRET), "a \0secret\0 b \0secret\0")
        self.assertEqual(gitleaks.masked_code(["x"], 3, 3, SECRET), "")

    def test_malformed_reports_fail(self):
        bad = [
            ["not an object"],
            [{**self.entry("src/app.py", 3), "RuleID": "a b"}],
            [{**self.entry("src/app.py", 3), "StartLine": "3"}],
            [{**self.entry("src/app.py", 3), "File": "src/app.py"}],
            [{**self.entry("src/app.py", 3), "File": "/etc/passwd"}],
        ]
        for report in bad:
            with self.subTest(report=report), self.assertRaises(ScanError):
                self.normalise(report)


class ConfigTests(unittest.TestCase):
    def test_gitleaks_is_a_known_scanner(self):
        self.assertEqual(parse_config({"scanners": ["opengrep", "gitleaks"]}).scanners, ("opengrep", "gitleaks"))
        with self.assertRaises(SetupError):
            parse_config({"scanners": ["trufflehog"]})


def git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false", *args],
                   cwd=repo, check=True, capture_output=True, timeout=60)  # fmt: skip


@unittest.skipUnless(shutil.which("git") and gitleaks_ready(), f"gitleaks is not installed in {TOOLS}; run `shoalscan install`")
class EndToEndTests(unittest.TestCase):
    def test_a_hostile_repository_cannot_hide_its_secrets(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, out = Path(tmp) / "repo", Path(tmp) / "out"
            (repo / "src").mkdir(parents=True)
            (repo / "src" / "app.py").write_text(f'aws_key = "{AWS}"  # gitleaks:allow\ntoken = "{SECRET}"\n')
            (repo / ".gitleaks.toml").write_text('[allowlist]\npaths = ["src/.*"]\n')
            (repo / ".gitleaksignore").write_text("src/app.py:github-pat:2\n")
            (repo / ".shoalscan.toml").write_text('scanners = ["gitleaks"]\n[opengrep]\ncommunity_rules = false\n')
            git(repo, "init", "-q", "-b", "main")
            git(repo, "add", "-A")
            git(repo, "commit", "-q", "-m", "x")
            err = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
                code = main(["scan", "--repo", str(repo), "--out", str(out), "--tools-dir", str(TOOLS)])
            self.assertEqual(code, 0, err.getvalue())
            doc = json.loads((out / "findings.json").read_text())
            self.assertEqual(sorted(f["rule"] for f in doc["findings"]), ["gitleaks.aws-access-token", "gitleaks.github-pat"])
            self.assertEqual(doc["scanners"]["gitleaks"]["version"], "8.30.1")
            self.assertIn("gitleaks.github-pat", doc["rule_ids"])
            for name in ("findings.json", "findings.sarif"):
                text = (out / name).read_text()
                self.assertNotIn(SECRET, text, name)
                self.assertNotIn(AWS, text, name)


if __name__ == "__main__":
    unittest.main()
