"""zizmor: its pin, finding the GitHub Actions files, a hardened command line, a fail-closed run, and findings."""

import contextlib
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import helpers
from history_fixtures import record

from shoalscan import history, zizmor
from shoalscan import install as inst
from shoalscan.cli import main
from shoalscan.config import Limits, parse_config
from shoalscan.errors import ScanError, SetupError
from shoalscan.findings import Finding
from shoalscan.lockfile import load_lock, sha256_file

LOCK_PATH = helpers.ROOT / "tools.lock"
TOOLS = helpers.tools_dir()

WORKFLOW = """name: ci
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4  # zizmor: ignore[unpinned-uses]
      - run: echo "${{ github.event.pull_request.title }}"
"""


def zizmor_ready() -> bool:
    try:
        pin = load_lock(LOCK_PATH).tools["zizmor"].platforms[inst.current_platform()]
        return sha256_file(inst.tool_path(TOOLS, "zizmor")) == pin.binary_sha256
    except (OSError, KeyError):
        return False


def result(
    root: Path,
    ident: str,
    severity: str,
    row: int,
    path: str = ".github/workflows/ci.yml",
    route=None,
    feature="run: x",
):
    return {
        "ident": ident,
        "desc": f"{ident} description",
        "url": f"https://docs.zizmor.sh/audits/#{ident}",
        "determinations": {"confidence": "High", "severity": severity, "persona": "Regular"},
        "locations": [
            {
                "symbolic": {
                    "key": {"Local": {"verbatim_path": str(root / path)}},
                    "annotation": "here",
                    "route": {
                        "route": route
                        or [{"Key": "jobs"}, {"Key": "build"}, {"Key": "steps"}, {"Index": 1}, {"Key": "run"}]
                    },
                    "kind": "Primary",
                },
                "concrete": {"location": {"start_point": {"row": row, "column": 4}}, "feature": feature},
            }
        ],
        "ignored": False,
    }


class PinAndConfigTests(unittest.TestCase):
    def test_shipped_lock_pins_zizmor(self):
        tool = load_lock(LOCK_PATH).tools["zizmor"]
        self.assertEqual((tool.version, tool.license, tool.member), ("1.30.1", "MIT", "zizmor"))
        self.assertEqual(len(tool.platforms), 4)

    def test_ignore_takes_audit_names(self):
        self.assertEqual(
            parse_config({"zizmor": {"ignore": ["unpinned-uses", "artipacked"]}}).zizmor.ignore,
            ("artipacked", "unpinned-uses"),
        )
        for bad in (["Artipacked"], ["*"], ["a b"], "artipacked"):
            with self.subTest(bad=bad), self.assertRaises(SetupError):
                parse_config({"zizmor": {"ignore": bad}})


class DiscoverTests(unittest.TestCase):
    def test_finds_workflows_actions_and_dependabot(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for rel in (
                ".github/workflows/ci.yml",
                ".github/workflows/release.yaml",
                ".github/workflows/sub/x.yml",
                ".github/workflows/notes.md",
                ".github/dependabot.yml",
                ".github/zizmor.yml",
                "actions/setup/action.yml",
                "action.yaml",
                "vendor/action.yml",
                ".git/action.yml",
                "ci.yml",
            ):
                (root / rel).parent.mkdir(parents=True, exist_ok=True)
                (root / rel).write_text("name: x\n")
            (root / "big").mkdir()
            (root / "big" / "action.yml").write_text("x" * 2000)
            os.symlink(root / "action.yaml", root / "actions" / "action.yaml")
            found, skipped = zizmor.discover(root, ("vendor",), 1000)
        self.assertEqual(
            sorted(found),
            [
                ".github/dependabot.yml",
                ".github/workflows/ci.yml",
                ".github/workflows/release.yaml",
                "action.yaml",
                "actions/setup/action.yml",
            ],
        )
        self.assertEqual(skipped, [{"path": "big/action.yml", "reason": "exceeded_size_limit"}])


class CommandTests(unittest.TestCase):
    def test_offline_and_unsilenceable(self):
        cmd = zizmor.build_command(Path("/t/zizmor"), [Path("/r/.github/workflows/ci.yml")])
        for flag in ("--offline", "--no-config", "--no-ignores", "--strict-collection", "--no-exit-codes"):
            self.assertIn(flag, cmd)
        self.assertNotIn("--gh-token", cmd)
        self.assertEqual(cmd[-1], "/r/.github/workflows/ci.yml")


class RunTests(unittest.TestCase):
    """A stand-in script plays zizmor: it fails for any argument naming broken.yml."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve() / "repo"
        (self.root / ".github" / "workflows").mkdir(parents=True)
        for name in ("ci.yml", "broken.yml"):
            (self.root / ".github" / "workflows" / name).write_text(WORKFLOW)
        self.stage = Path(self.tmp.name) / "stage"
        self.stage.mkdir()
        self.binary = Path(self.tmp.name) / "zizmor"
        out = json.dumps([result(self.root, "template-injection", "High", 7)])
        self.binary.write_text(
            '#!/bin/sh\nfor a in "$@"; do case "$a" in *broken.yml) echo "failed to load $a" >&2; exit 1;; esac; done\n'
            f"case \"$*\" in *ci.yml*) echo '{out}';; *) echo '[]';; esac\n"
        )
        self.binary.chmod(0o755)

    def tearDown(self):
        self.tmp.cleanup()

    def run_zizmor(self, binary=None):
        b = binary or self.binary
        return zizmor.run(b, sha256_file(b), self.root, self.stage, Limits(), {}, (), ())

    def test_a_file_zizmor_cannot_read_is_unscanned_and_the_rest_still_count(self):
        findings, unscanned, audited, rules = self.run_zizmor()
        self.assertEqual([(f.rule, f.line) for f in findings], [("zizmor.template-injection", 8)])
        self.assertEqual(audited, 1)
        self.assertEqual([e["path"] for e in unscanned["errors"]], [".github/workflows/broken.yml"])
        self.assertNotIn(str(self.root), unscanned["errors"][0]["message"])
        self.assertEqual(
            rules["zizmor.template-injection"]["references"], ["https://docs.zizmor.sh/audits/#template-injection"]
        )

    def test_a_failure_no_single_file_explains_fails_the_scan(self):
        flaky = Path(self.tmp.name) / "flaky"
        flaky.write_text(
            '#!/bin/sh\nn=0\nfor a in "$@"; do case "$a" in *.yml) n=$((n+1));; esac; done\n[ $n -gt 1 ] && exit '
            "1\necho '[]'\n"
        )
        flaky.chmod(0o755)
        (self.root / ".github" / "workflows" / "broken.yml").unlink()
        (self.root / ".github" / "workflows" / "other.yml").write_text(WORKFLOW)
        with self.assertRaises(ScanError):
            self.run_zizmor(flaky)

    def test_bad_output_fails(self):
        for body in ("echo 'not json'", "echo '{}'"):
            bad = Path(self.tmp.name) / "bad"
            bad.write_text(f"#!/bin/sh\n{body}\n")
            bad.chmod(0o755)
            (self.root / ".github" / "workflows" / "broken.yml").unlink(missing_ok=True)
            shutil.rmtree(self.stage / "zizmor", ignore_errors=True)
            with self.subTest(body=body), self.assertRaises(ScanError):
                self.run_zizmor(bad)


class NormaliseTests(unittest.TestCase):
    root = Path("/repo")
    scanned = {".github/workflows/ci.yml"}

    def normalise(self, results, ignore=()):
        return zizmor.normalise(results, self.root, self.scanned, {".github/": "ci"}, ignore)

    def test_severities_lines_and_ignores(self):
        found = self.normalise(
            [
                result(self.root, "template-injection", "High", 7),
                result(self.root, "artipacked", "Medium", 6),
                result(self.root, "unpinned-images", "Low", 3),
                result(self.root, "excessive-permissions", "Informational", 1),
            ],
            ignore=("artipacked",),
        )
        self.assertEqual(
            [(f.rule, f.severity, f.line, f.component) for f in found],
            [
                ("zizmor.template-injection", "ERROR", 8, "ci"),
                ("zizmor.unpinned-images", "INFO", 4, "ci"),
                ("zizmor.excessive-permissions", "INFO", 2, "ci"),
            ],
        )
        self.assertEqual(found[0].message, "template-injection description: here")

    def test_fingerprints_ignore_step_indexes_and_line_shifts(self):
        a = self.normalise([result(self.root, "template-injection", "High", 7)])[0]
        shifted = [{"Key": "jobs"}, {"Key": "build"}, {"Key": "steps"}, {"Index": 4}, {"Key": "run"}]
        b = self.normalise([result(self.root, "template-injection", "High", 19, route=shifted)])[0]
        self.assertEqual(a.fingerprint, b.fingerprint)
        c = self.normalise([result(self.root, "template-injection", "High", 7, feature="run: y")])[0]
        self.assertNotEqual(a.fingerprint, c.fingerprint)

    def test_malformed_output_fails(self):
        good = result(self.root, "artipacked", "Medium", 1)
        bad = [
            ["x"],
            [{**good, "ident": "Bad Ident"}],
            [{**good, "determinations": {"severity": "Critical"}}],
            [{**good, "locations": []}],
            [result(self.root, "artipacked", "Medium", 1, path="../elsewhere.yml")],
            [result(self.root, "artipacked", "Medium", 1, path="other.yml")],
        ]
        for results in bad:
            with self.subTest(results=str(results)[:80]), self.assertRaises(ScanError):
                self.normalise(results)


class HistoryTests(unittest.TestCase):
    def test_verification_needs_zizmor_and_its_audit(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            db = tmp / "h.db"
            conn = history.open_for_write(db)
            try:
                audit = Finding(
                    "zizmor",
                    "zizmor.artipacked",
                    "WARNING",
                    ".github/workflows/ci.yml",
                    7,
                    "zz:0",
                    "ci",
                    "Credentials persist.",
                )
                record(conn, tmp, "acme/app", "1" * 40, 1, [audit])
                history.set_reviews(
                    db,
                    "acme/app",
                    [[audit.tool, audit.rule, audit.path, audit.fingerprint]],
                    "fixed",
                    "Set persist-credentials.",
                    "me",
                )
                clean = {"skipped": [], "errors": []}
                status = lambda: conn.execute("SELECT status FROM finding_reviews").fetchone()[0]  # noqa: E731
                record(
                    conn,
                    tmp,
                    "acme/app",
                    "2" * 40,
                    2,
                    [],
                    extra_meta={"unscanned": clean, "scanners": {"zizmor": {"ignore": ["artipacked"]}}},
                )
                self.assertEqual(status(), "fixed")
                record(
                    conn,
                    tmp,
                    "acme/app",
                    "3" * 40,
                    3,
                    [],
                    extra_meta={"unscanned": clean, "scanners": {"zizmor": {"ignore": []}}},
                )
                self.assertEqual(status(), "verified_fixed")
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
    shutil.which("git") and zizmor_ready(), f"zizmor is not installed in {TOOLS}; run `shoalscan install`"
)
class EndToEndTests(unittest.TestCase):
    def test_a_hostile_repository_cannot_hide_its_workflow_flaws(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, out = Path(tmp) / "repo", Path(tmp) / "out"
            (repo / ".github" / "workflows").mkdir(parents=True)
            (repo / ".github" / "workflows" / "ci.yml").write_text(WORKFLOW)
            (repo / ".github" / "workflows" / "broken.yml").write_text("on: [push\njobs: {\n")
            (repo / ".github" / "zizmor.yml").write_text("rules:\n  template-injection:\n    disable: true\n")
            (repo / ".shoalscan.toml").write_text(
                'scanners = ["zizmor"]\n[opengrep]\ncommunity_rules = false\n[zizmor]\nignore = ["artipacked"]\n'
            )
            git(repo, "init", "-q", "-b", "main")
            git(repo, "add", "-A")
            git(repo, "commit", "-q", "-m", "x")
            err = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
                code = main(["scan", "--repo", str(repo), "--out", str(out), "--tools-dir", str(TOOLS)])
            self.assertEqual(code, 0, err.getvalue())
            doc = json.loads((out / "findings.json").read_text())
            rules = {f["rule"] for f in doc["findings"]}
            self.assertTrue(
                {"zizmor.template-injection", "zizmor.unpinned-uses", "zizmor.dangerous-triggers"} <= rules, rules
            )
            self.assertNotIn("zizmor.artipacked", rules)
            self.assertEqual([e["path"] for e in doc["unscanned"]["errors"]], [".github/workflows/broken.yml"])


if __name__ == "__main__":
    unittest.main()
