"""Trivy: its signed pin, a hardened command line, a fail-closed run, and findings.

Its inline markers are held to Shoalscan's suppression rule.
"""

import contextlib
import copy
import io
import json
import shutil
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path

import helpers
from history_fixtures import record
from test_lock_and_install import PLAT, Assets, sha, tool_tarball

from shoalscan import history, trivy
from shoalscan import install as inst
from shoalscan.cli import main
from shoalscan.config import parse_config
from shoalscan.errors import ScanError, SetupError, VerificationError
from shoalscan.findings import Finding
from shoalscan.lockfile import load_lock, parse_lock, sha256_file
from shoalscan.suppressions import TRIVY_MARKER, lint_findings, parse_trivy_line

LOCK_PATH = helpers.ROOT / "tools.lock"
TOOLS = helpers.tools_dir()
MARK = "#" + TRIVY_MARKER

TERRAFORM = f"""resource "aws_s3_bucket" "logs" {{
  bucket = "my-logs"
}}

{MARK}AVD-AWS-0086 #42 accepted for the demo
resource "aws_s3_bucket_public_access_block" "logs" {{
  bucket = aws_s3_bucket.logs.id
}}

resource "aws_security_group_rule" "ssh" {{
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"] {MARK}AVD-AWS-0107
  security_group_id = "sg-123"
}}
"""
POD = """apiVersion: v1
kind: Pod
metadata:
  name: web
spec:
  containers:
    - name: web
      image: nginx:latest
      securityContext:
        privileged: true
"""


def trivy_ready() -> bool:
    try:
        pin = load_lock(LOCK_PATH).tools["trivy"].platforms[inst.current_platform()]
        return sha256_file(inst.tool_path(TOOLS, "trivy")) == pin.binary_sha256
    except (OSError, KeyError):
        return False


def misconfig(check, severity, start=1, resource="aws_s3_bucket.logs", content="bucket = 1", status="FAIL"):
    return {
        "ID": check,
        "Title": f"{check} title",
        "Message": f"{check} message",
        "Resolution": "Fix it.",
        "Severity": severity,
        "Status": status,
        "PrimaryURL": f"https://avd.aquasec.com/misconfig/{check.lower()}",
        "References": ["javascript:alert(1)"],
        "CauseMetadata": {
            "Resource": resource,
            "StartLine": start,
            "EndLine": start,
            "Code": {
                "Lines": [
                    {"Number": start, "Content": content, "IsCause": True},
                    {"Content": "other", "IsCause": False},
                ]
            },
        },
    }


class PinTests(unittest.TestCase):
    def test_shipped_lock_pins_a_signed_trivy(self):
        tool = load_lock(LOCK_PATH).tools["trivy"]
        self.assertEqual((tool.version, tool.license, tool.member), ("0.74.0", "Apache-2.0", "trivy"))
        self.assertEqual(
            tool.signature.certificate_identity,
            "https://github.com/aquasecurity/trivy/.github/workflows/reusable-release.yaml@refs/tags/v0.74.0",
        )
        self.assertEqual(tool.signature.github_workflow_sha, "e1fd17a0ea4a8cf24bc4b4dd7e2cfbf4bb31b994")
        for pin in tool.platforms.values():
            self.assertTrue(pin.bundle.url.endswith(".tar.gz.sigstore.json"))

    def test_a_signed_tool_needs_a_bundle_per_platform(self):
        base = tomllib.loads(LOCK_PATH.read_text(encoding="utf-8"))
        for mutate in (
            lambda t: t["platforms"][PLAT].pop("bundle_url"),
            lambda t: t["signature"].pop("github_workflow_sha"),
            lambda t: t["signature"].__setitem__("github_workflow_sha", "main"),
        ):
            data = copy.deepcopy(base)
            mutate(data["trivy"])
            with self.subTest(mutate=mutate), self.assertRaises(SetupError):
                parse_lock(data)
        # An unsigned tool may not carry bundle keys.
        data = copy.deepcopy(base)
        data["gitleaks"]["platforms"][PLAT]["bundle_url"] = "https://example.com/b"
        with self.assertRaises(SetupError):
            parse_lock(data)


class InstallTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tools = Path(self.tmp.name) / "tools"
        self.work = Path(self.tmp.name) / "work"
        self.tools.mkdir()
        self.work.mkdir()
        data = tomllib.loads(LOCK_PATH.read_text(encoding="utf-8"))
        entry = data["trivy"]["platforms"][PLAT]
        self.archive = tool_tarball({"trivy": b"trivy-binary", "README.md": b"x"})
        entry["sha256"], entry["binary_sha256"], entry["bundle_sha256"] = (
            sha(self.archive),
            sha(b"trivy-binary"),
            sha(b"bundle"),
        )
        self.tool = parse_lock(data).tools["trivy"]
        self.assets = Assets()
        self.assets.files.update({entry["url"]: self.archive, entry["bundle_url"]: b"bundle"})
        self.checked = []

    def tearDown(self):
        self.tmp.cleanup()

    def install(self, cosign=Path("/t/cosign"), verify=None):
        def accept(cosign, blob, bundle, identity):
            self.checked.append((blob.read_bytes(), bundle.read_bytes(), identity.github_workflow_sha))

        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            inst.install_pinned_tool(
                self.tools, self.tool, PLAT, self.assets.fetch, self.work, cosign, verify or accept
            )
        return err.getvalue()

    def test_the_signature_is_checked_before_anything_is_extracted(self):
        log = self.install()
        self.assertEqual(self.checked, [(self.archive, b"bundle", "e1fd17a0ea4a8cf24bc4b4dd7e2cfbf4bb31b994")])
        self.assertIn("cosign signature verified", log)
        self.assertEqual(inst.tool_path(self.tools, "trivy").read_bytes(), b"trivy-binary")

    def test_a_bad_signature_installs_nothing(self):
        def reject(*args):
            raise VerificationError("cosign signature verification failed")

        with self.assertRaises(VerificationError):
            self.install(verify=reject)
        self.assertFalse(inst.tool_path(self.tools, "trivy").exists())

    def test_without_cosign_it_says_so_loudly(self):
        log = self.install(cosign=None)
        self.assertEqual(self.checked, [])
        self.assertIn("the trivy signature is NOT verified", log)


class ConfigTests(unittest.TestCase):
    def test_ignore_takes_check_ids(self):
        self.assertEqual(
            parse_config({"trivy": {"ignore": ["KSV-0011", "AWS-0089"]}}).trivy.ignore, ("AWS-0089", "KSV-0011")
        )
        for bad in (["ksv-0011"], ["*"], ["AWS"], "AWS-0089"):
            with self.subTest(bad=bad), self.assertRaises(SetupError):
                parse_config({"trivy": {"ignore": bad}})


class CommandTests(unittest.TestCase):
    def test_nothing_from_the_repository_or_the_machine_is_read(self):
        cmd = trivy.build_command(Path("/t/trivy"), Path("/repo"), Path("/s/trivy"))
        joined = " ".join(cmd)
        for part in (
            "--cache-dir /s/trivy/cache",
            "--skip-check-update",
            "--skip-version-check",
            "--disable-telemetry",
            "--config /s/trivy/trivy.yaml",
            "--ignorefile /s/trivy/trivyignore",
            "--module-dir /s/trivy/modules",
            "--exit-code 0",
        ):
            self.assertIn(part, joined)
        self.assertEqual(cmd[-1], "/repo")


class ExecuteTests(unittest.TestCase):
    def run_standin(self, body):
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "trivy"
            script.write_text("#!/bin/sh\n" + body + "\n")
            script.chmod(0o755)
            return trivy.execute([str(script)], Path(tmp), 30)

    def test_only_a_clean_exit_with_a_report_is_accepted(self):
        doc, log = self.run_standin("echo 'note' >&2; echo '{\"Results\": []}'")
        self.assertEqual((doc, log), ({"Results": []}, "note"))
        for body in ("echo '{}'; exit 1", "echo 'nope'", "echo '[]'", "echo '{\"Results\": {}}'"):
            with self.subTest(body=body), self.assertRaises(ScanError):
                self.run_standin(body)


class NormaliseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "infra").mkdir()
        (self.root / "vendor").mkdir()
        (self.root / "infra" / "main.tf").write_text(TERRAFORM)
        (self.root / "vendor" / "x.tf").write_text(TERRAFORM)

    def tearDown(self):
        self.tmp.cleanup()

    def normalise(self, results, ignore=()):
        return trivy.normalise({"Results": results}, self.root, {"infra/": "infra"}, ("vendor",), ignore)

    def test_severities_ignores_and_excludes(self):
        found, meta = self.normalise(
            [
                {"Target": "infra", "Misconfigurations": []},
                {
                    "Target": "infra/main.tf",
                    "Misconfigurations": [
                        misconfig("AWS-0087", "HIGH", 6),
                        misconfig("AWS-0090", "MEDIUM"),
                        misconfig("AWS-0089", "LOW"),
                        misconfig("AWS-0001", "CRITICAL"),
                        misconfig("AWS-0002", "UNKNOWN"),
                        misconfig("AWS-0003", "HIGH", status="PASS"),
                    ],
                },
                {"Target": "vendor/x.tf", "Misconfigurations": [misconfig("AWS-0087", "HIGH")]},
            ],
            ignore=("AWS-0090",),
        )
        self.assertEqual(
            [(f.rule, f.severity, f.line, f.component) for f in found],
            [
                ("trivy.AWS-0087", "ERROR", 6, "infra"),
                ("trivy.AWS-0089", "INFO", 1, "infra"),
                ("trivy.AWS-0001", "ERROR", 1, "infra"),
                ("trivy.AWS-0002", "INFO", 1, "infra"),
            ],
        )
        self.assertEqual(found[0].message, "AWS-0087 title: AWS-0087 message")
        self.assertEqual(meta["trivy.AWS-0087"]["references"], ["https://avd.aquasec.com/misconfig/aws-0087"])
        self.assertEqual(meta["trivy.AWS-0087"]["fix"], "Fix it.")

    def test_fingerprints_follow_the_resource_and_its_code(self):
        a = self.normalise([{"Target": "infra/main.tf", "Misconfigurations": [misconfig("AWS-0087", "HIGH", 6)]}])[0][0]
        b = self.normalise([{"Target": "infra/main.tf", "Misconfigurations": [misconfig("AWS-0087", "HIGH", 30)]}])[0][
            0
        ]
        c = self.normalise(
            [
                {
                    "Target": "infra/main.tf",
                    "Misconfigurations": [misconfig("AWS-0087", "HIGH", 6, resource="aws_s3_bucket.other")],
                }
            ]
        )[0][0]
        self.assertEqual(a.fingerprint, b.fingerprint)
        self.assertNotEqual(a.fingerprint, c.fingerprint)

    def test_findings_outside_the_repository_files_fail(self):
        for target in ("/etc/passwd", "../x.tf", "git::https://example.com/mod", "infra", "infra/missing.tf"):
            with self.subTest(target=target), self.assertRaises(ScanError):
                self.normalise([{"Target": target, "Misconfigurations": [misconfig("AWS-0087", "HIGH")]}])
        for bad in (misconfig("aws-0087", "HIGH"), misconfig("AWS-0087", "SEVERE")):
            with self.subTest(bad=bad["ID"]), self.assertRaises(ScanError):
                self.normalise([{"Target": "infra/main.tf", "Misconfigurations": [bad]}])

    def test_parse_errors_come_from_the_log(self):
        (self.root / "infra" / "broken.tf").write_text("resource {")
        log = (
            '2026-10-11T14:32:12-05:00\tERROR\t[terraform parser] Error parsing file\tmodule="root" '
            'file_path="infra/broken.tf" err="x"\n'
            '2026-10-11T14:32:12-05:00\tERROR\t[terraform parser] Error parsing file\tfile_path="vendor/x.tf"\n'
            '2026-10-11T14:32:12-05:00\tERROR\t[terraform parser] Error parsing file\tfile_path="../../etc/passwd"\n'
            '2026-10-11T14:32:12-05:00\tERROR\t[misconfig] Falling back to embedded checks\terr="no '
            'cache"\n'
        )
        self.assertEqual(
            trivy.parse_errors(log, self.root, ("vendor",)), [{"path": "infra/broken.tf", "type": "trivy parse error"}]
        )


class MarkerTests(unittest.TestCase):
    def test_markers_need_one_check_and_an_issue(self):
        self.assertEqual(parse_trivy_line(f"{MARK}AVD-AWS-0086 #42 accepted"), [(("AVD-AWS-0086",), "#42", False)])
        self.assertEqual(
            parse_trivy_line(f"x = 1 // {TRIVY_MARKER}aws-s3-x:exp:2026-01-01 https://example.com/i/3"),
            [(("aws-s3-x",), "https://example.com/i/3", False)],
        )
        self.assertEqual(parse_trivy_line(f"{MARK}* #3"), [((), None, True)])
        self.assertEqual(parse_trivy_line("nothing here"), [])

    def test_bad_markers_become_blocking_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "main.tf").write_text(TERRAFORM + f"{MARK}* #9\n")
            from shoalscan.suppressions import find_trivy_suppressions

            found = find_trivy_suppressions(root, ["main.tf"], 100_000)
        self.assertEqual([(s.line, s.valid) for s in found], [(5, True), (15, False), (18, False)])
        lint = lint_findings(found, {})
        self.assertEqual([(f.line, f.severity) for f in lint], [(15, "ERROR"), (18, "ERROR")])
        self.assertIn("without an issue reference", lint[0].message)
        self.assertIn("every check (*)", lint[1].message)
        self.assertIn(TRIVY_MARKER + "<check-id> #<issue>", lint[0].message)

    def test_only_configuration_files_are_linted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for rel in ("main.tf", "k8s/pod.yaml", "Dockerfile", "docs/notes.md", "vendor/x.tf", ".git/x.tf"):
                (root / rel).parent.mkdir(parents=True, exist_ok=True)
                (root / rel).write_text("x")
            self.assertEqual(trivy.config_files(root, ("vendor",), 1000), ["Dockerfile", "k8s/pod.yaml", "main.tf"])


class HistoryTests(unittest.TestCase):
    def test_verification_needs_trivy_and_its_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            db = tmp / "h.db"
            conn = history.open_for_write(db)
            try:
                found = Finding("trivy", "trivy.KSV-0017", "ERROR", "k8s/pod.yaml", 7, "tt:0", "k8s", "Privileged.")
                record(conn, tmp, "acme/app", "1" * 40, 1, [found])
                history.set_reviews(
                    db,
                    "acme/app",
                    [[found.tool, found.rule, found.path, found.fingerprint]],
                    "fixed",
                    "Dropped privileged.",
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
                    extra_meta={"unscanned": clean, "scanners": {"trivy": {"ignore": ["KSV-0017"]}}},
                )
                self.assertEqual(status(), "fixed")
                record(
                    conn,
                    tmp,
                    "acme/app",
                    "3" * 40,
                    3,
                    [],
                    extra_meta={"unscanned": clean, "scanners": {"trivy": {"ignore": []}}},
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
    shutil.which("git") and trivy_ready(), f"trivy is not installed in {TOOLS}; run `shoalscan install`"
)
class EndToEndTests(unittest.TestCase):
    def test_a_hostile_repository_cannot_hide_its_misconfigurations(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, out = Path(tmp) / "repo", Path(tmp) / "out"
            (repo / "infra").mkdir(parents=True)
            (repo / "k8s").mkdir()
            (repo / "infra" / "main.tf").write_text(TERRAFORM)
            (repo / "infra" / "broken.tf").write_text('resource "aws_s3_bucket" "x" {\n  bucket = \n')
            (repo / "k8s" / "pod.yaml").write_text(POD)
            (repo / ".trivyignore").write_text("KSV-0017\nAVD-KSV-0017\n")
            (repo / "trivy.yaml").write_text("misconfiguration:\n  scanners: [dockerfile]\n")
            (repo / ".shoalscan.toml").write_text(
                'scanners = ["trivy"]\n[opengrep]\ncommunity_rules = false\n[trivy]\nignore = ["KSV-0011"]\n'
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
                {"trivy.KSV-0017", "trivy.AWS-0087", "shoalscan.suppression-without-rule-and-issue"} <= rules, rules
            )
            self.assertNotIn("trivy.KSV-0011", rules)
            self.assertEqual(doc["unscanned"]["errors"], [{"path": "infra/broken.tf", "type": "trivy parse error"}])
            self.assertEqual(doc["suppressions"], {"total": 2, "invalid": 1, "suppressed_findings": 2})
            self.assertEqual(doc["scanners"]["trivy"]["verification"], "sha256 and cosign")


if __name__ == "__main__":
    unittest.main()
