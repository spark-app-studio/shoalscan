"""Hadolint: its pin, finding the Dockerfiles, a hardened command line, a fail-closed run, and findings."""

import contextlib
import io
import json
import os
import shutil
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path

import helpers
from history_fixtures import record
from test_lock_and_install import PLAT, Assets, sha

from shoalscan import hadolint, history
from shoalscan import install as inst
from shoalscan.cli import main
from shoalscan.config import parse_config
from shoalscan.errors import ScanError, SetupError
from shoalscan.findings import Finding
from shoalscan.lockfile import load_lock, parse_lock, sha256_file

LOCK_PATH = helpers.ROOT / "tools.lock"
TOOLS = helpers.tools_dir()

DOCKERFILE = """FROM python:3.12 AS build
RUN pip install flask
FROM ubuntu:latest
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y curl
USER root
"""


def hadolint_ready() -> bool:
    try:
        pin = load_lock(LOCK_PATH).tools["hadolint"].platforms[inst.current_platform()]
        return sha256_file(inst.tool_path(TOOLS, "hadolint")) == pin.binary_sha256
    except (OSError, KeyError):
        return False


class PinTests(unittest.TestCase):
    def test_shipped_lock_pins_bare_binaries(self):
        tool = load_lock(LOCK_PATH).tools["hadolint"]
        self.assertEqual((tool.version, tool.license, tool.member, tool.files), ("2.15.1", "GPL-3.0", None, {}))
        self.assertEqual(len(tool.platforms), 4)
        for pin in tool.platforms.values():
            self.assertEqual(pin.download.sha256, pin.binary_sha256)

    def test_installs_a_bare_binary(self):
        data = tomllib.loads(LOCK_PATH.read_text(encoding="utf-8"))
        entry = data["hadolint"]["platforms"][PLAT]
        entry["sha256"] = entry["binary_sha256"] = sha(b"hadolint-binary")
        tool = parse_lock(data).tools["hadolint"]
        assets = Assets()
        assets.files[entry["url"]] = b"hadolint-binary"
        with tempfile.TemporaryDirectory() as tmp:
            tools, work = Path(tmp) / "tools", Path(tmp) / "work"
            tools.mkdir()
            work.mkdir()
            with contextlib.redirect_stderr(io.StringIO()):
                inst.install_pinned_tool(tools, tool, PLAT, assets.fetch, work)
            self.assertEqual(inst.tool_path(tools, "hadolint").read_bytes(), b"hadolint-binary")


class ConfigTests(unittest.TestCase):
    def test_ignore_takes_rule_codes_only(self):
        self.assertEqual(
            parse_config({"hadolint": {"ignore": ["SC2086", "DL3008"]}}).hadolint.ignore, ("DL3008", "SC2086")
        )
        for bad in (["dl3008"], ["DL30"], ["*"], "DL3008", [""]):
            with self.subTest(bad=bad), self.assertRaises(SetupError):
                parse_config({"hadolint": {"ignore": bad}})
        with self.assertRaises(SetupError):
            parse_config({"hadolint": {"rules": []}})


class DiscoverTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        for rel in (
            "Dockerfile",
            "app/Dockerfile.prod",
            "app/api.dockerfile",
            "svc/Containerfile",
            "vendor/Dockerfile",
            ".git/Dockerfile",
            "docs/dockerfile.md",
            "app/notes.txt",
            "app/Dockerfile.dockerignore",
            "app/Dockerfile.j2",
        ):
            (self.root / rel).parent.mkdir(parents=True, exist_ok=True)
            (self.root / rel).write_text("FROM alpine:3.20\n")
        (self.root / "big").mkdir()
        (self.root / "big" / "Dockerfile").write_text("FROM alpine:3.20\n" + "# x\n" * 1000)
        os.symlink(self.root / "Dockerfile", self.root / "svc" / "Dockerfile")

    def tearDown(self):
        self.tmp.cleanup()

    def test_finds_dockerfiles_outside_excludes_git_and_links(self):
        found, skipped = hadolint.discover(self.root, ("vendor",), 1000)
        self.assertEqual(found, ["Dockerfile", "app/Dockerfile.prod", "app/api.dockerfile", "svc/Containerfile"])
        self.assertEqual(skipped, [{"path": "big/Dockerfile", "reason": "exceeded_size_limit"}])


class CommandTests(unittest.TestCase):
    def test_repository_controlled_silencing_is_turned_off(self):
        cmd = hadolint.build_command(Path("/t/hadolint"), Path("/s/config.yaml"), ("DL3008",), [Path("/r/Dockerfile")])
        joined = " ".join(cmd)
        self.assertIn("--config /s/config.yaml", joined)
        self.assertIn("--disable-ignore-pragma", cmd)
        self.assertIn("--ignore DL3008", joined)
        self.assertEqual(cmd[-1], "/r/Dockerfile")


class ExecuteTests(unittest.TestCase):
    def run_standin(self, body: str):
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "hadolint"
            script.write_text("#!/bin/sh\n" + body + "\n")
            script.chmod(0o755)
            return hadolint.execute([str(script)], Path(tmp), 30)

    def test_only_a_clean_exit_with_a_json_list_is_accepted(self):
        self.assertEqual(self.run_standin("echo '[]'; exit 0"), [])
        for body in ("echo '[]'; exit 1", "echo 'not json'; exit 0", "echo '{}'; exit 0", "exit 0"):
            with self.subTest(body=body), self.assertRaises(ScanError):
                self.run_standin(body)


class NormaliseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        (self.root / "app").mkdir()
        (self.root / "app" / "Dockerfile").write_text(DOCKERFILE)

    def tearDown(self):
        self.tmp.cleanup()

    def result(self, code, level, line, path="app/Dockerfile"):
        return {
            "code": code,
            "level": level,
            "line": line,
            "column": 1,
            "file": str(self.root / path),
            "message": f"{code} message",
        }

    def normalise(self, results, scanned=("app/Dockerfile", "broken/Dockerfile")):
        return hadolint.normalise(results, self.root, set(scanned), {"app/": "app"})

    def test_levels_rules_and_components(self):
        found, errors = self.normalise(
            [
                self.result("DL3007", "warning", 3),
                self.result("DL3008", "warning", 5),
                self.result("DL3002", "error", 6),
                self.result("SC2086", "style", 2),
            ]
        )
        self.assertEqual(errors, [])
        self.assertEqual(
            [(f.rule, f.severity, f.component) for f in found],
            [
                ("hadolint.DL3007", "WARNING", "app"),
                ("hadolint.DL3008", "WARNING", "app"),
                ("hadolint.DL3002", "ERROR", "app"),
                ("hadolint.SC2086", "INFO", "app"),
            ],
        )

    def test_a_file_that_does_not_parse_is_unscanned_not_a_finding(self):
        found, errors = self.normalise(
            [
                self.result("DL1000", "error", 3, "broken/Dockerfile"),
                self.result("DL3007", "warning", 1, "broken/Dockerfile"),
            ]
        )
        self.assertEqual(found, [])
        self.assertEqual(
            errors, [{"path": "broken/Dockerfile", "type": "hadolint DL1000", "message": "DL1000 message"}]
        )

    def test_a_parse_error_keeps_no_quoted_line(self):
        bad = self.result("DL1000", "error", 3, "broken/Dockerfile")
        bad["message"] = "unexpected 'password=hunter2'\nexpecting '#', ADD or end of input"
        _, errors = self.normalise([bad])
        self.assertNotIn("hunter2", errors[0]["message"])
        self.assertIn("unexpected", errors[0]["message"])

    def test_fingerprints_survive_line_shifts_and_name_the_stage(self):
        first = self.normalise([self.result("DL3008", "warning", 5)])[0][0]
        (self.root / "app" / "Dockerfile").write_text("# A comment on top\n\n" + DOCKERFILE)
        moved = self.normalise([self.result("DL3008", "warning", 7)])[0][0]
        self.assertEqual(first.fingerprint, moved.fingerprint)
        lines = DOCKERFILE.splitlines()
        self.assertEqual(hadolint.stage_context(lines, 2), "stage:build")
        self.assertEqual(hadolint.stage_context(lines, 5), "stage:ubuntu:latest")
        self.assertEqual(hadolint.stage_context(["# no FROM"], 1), "")

    def test_malformed_output_fails(self):
        bad = [
            ["x"],
            [{**self.result("DL3008", "warning", 5), "code": "DL30"}],
            [{**self.result("DL3008", "warning", 5), "level": "fatal"}],
            [{**self.result("DL3008", "warning", 5), "file": "app/Dockerfile"}],
            [self.result("DL3008", "warning", 5, "../outside")],
            [self.result("DL3008", "warning", 5, "other/Dockerfile")],
        ]
        for results in bad:
            with self.subTest(results=results), self.assertRaises(ScanError):
                self.normalise(results)


class HistoryTests(unittest.TestCase):
    """A Hadolint finding's absence proves a fix only when Hadolint ran and the policy did not ignore its rule."""

    def test_verification_needs_hadolint_and_its_rule(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            db = tmp / "h.db"
            conn = history.open_for_write(db)
            try:
                lint = Finding(
                    "hadolint", "hadolint.DL3008", "WARNING", "Dockerfile", 3, "dd:0", "other", "Pin versions."
                )
                record(conn, tmp, "acme/app", "1" * 40, 1, [lint])
                history.set_reviews(
                    db,
                    "acme/app",
                    [[lint.tool, lint.rule, lint.path, lint.fingerprint]],
                    "fixed",
                    "Pinned the versions.",
                    "me",
                )
                clean = {"skipped": [], "errors": []}
                review = lambda: conn.execute("SELECT status FROM finding_reviews").fetchone()[0]  # noqa: E731
                record(
                    conn,
                    tmp,
                    "acme/app",
                    "2" * 40,
                    2,
                    [],
                    extra_meta={"unscanned": clean, "scanners": {"opengrep": {}}},
                )
                self.assertEqual(review(), "fixed")
                record(
                    conn,
                    tmp,
                    "acme/app",
                    "3" * 40,
                    3,
                    [],
                    extra_meta={"unscanned": clean, "scanners": {"hadolint": {"ignore": ["DL3008"]}}},
                )
                self.assertEqual(review(), "fixed")
                record(
                    conn,
                    tmp,
                    "acme/app",
                    "4" * 40,
                    4,
                    [],
                    extra_meta={"unscanned": clean, "scanners": {"hadolint": {"ignore": []}}},
                )
                self.assertEqual(review(), "verified_fixed")
            finally:
                conn.close()


def git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        timeout=60,
    )


@unittest.skipUnless(
    shutil.which("git") and hadolint_ready(), f"hadolint is not installed in {TOOLS}; run `shoalscan install`"
)
class EndToEndTests(unittest.TestCase):
    def test_a_hostile_repository_cannot_hide_its_lints(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, out = Path(tmp) / "repo", Path(tmp) / "out"
            (repo / "app").mkdir(parents=True)
            (repo / "app" / "Dockerfile").write_text(DOCKERFILE)
            (repo / "broken.Dockerfile").write_text("FROM alpine\nCOPY --frm=x a b\n")
            (repo / ".hadolint.yaml").write_text("ignored:\n  - DL3007\n  - DL3008\nfailure-threshold: none\n")
            (repo / ".shoalscan.toml").write_text(
                'scanners = ["hadolint"]\n[opengrep]\ncommunity_rules = false\n[hadolint]\nignore = ["DL3015"]\n'
            )
            git(repo, "init", "-q", "-b", "main")
            git(repo, "add", "-A")
            git(repo, "commit", "-q", "-m", "x")
            out_text, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out_text), contextlib.redirect_stderr(err):
                code = main(["scan", "--repo", str(repo), "--out", str(out), "--tools-dir", str(TOOLS)])
            self.assertEqual(code, 0, err.getvalue())
            self.assertNotIn("Opengrep", err.getvalue())  # no signature warning for a scanner that did not run
            doc = json.loads((out / "findings.json").read_text())
            rules = {f["rule"] for f in doc["findings"]}
            self.assertTrue({"hadolint.DL3007", "hadolint.DL3008", "hadolint.DL3002"} <= rules, rules)
            self.assertNotIn("hadolint.DL3015", rules)
            self.assertEqual(doc["unscanned"]["errors"][0]["path"], "broken.Dockerfile")
            self.assertEqual(doc["scanners"]["hadolint"]["files_scanned"], 2)


if __name__ == "__main__":
    unittest.main()
