"""Trivy: its signed pin, a hardened command line, a fail-closed run, and findings.

Its inline markers are held to Shoalscan's suppression rule.
"""

import contextlib
import copy
import io
import json
import os
import shutil
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest import mock

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
            "--misconfig-scanners azure-arm,cloudformation,dockerfile,kubernetes,terraform,",
            "--exit-code 0",
        ):
            self.assertIn(part, joined)
        self.assertEqual(cmd[-1], "/repo")
        self.assertNotIn("helm", cmd[cmd.index("--misconfig-scanners") + 1])


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

    def test_a_target_the_file_system_refuses_fails_the_scan_cleanly(self):
        # Found by the trivy_report fuzz target: a name too long for the file system made is_file() raise OSError.
        for target in ("Docke" + "\udcff" * 200 + "rfile", "a" * 5000, "infra/" + "b" * 300 + ".tf"):
            with self.subTest(length=len(target)), self.assertRaises(ScanError):
                self.normalise([{"Target": target, "Misconfigurations": [misconfig("AWS-0087", "HIGH")]}])
        log = '2026-01-01T00:00:00Z\tERROR\tError parsing file file_path="' + "c" * 5000 + '"\n'
        self.assertEqual(trivy.parse_errors(log, self.root, ()), [])

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

    def test_every_syntax_trivy_accepts_is_a_marker(self):
        legacy = "tf" + "sec:"
        cases = {
            # The legacy prefix, with and without a wildcard.
            f"#{legacy}ignore:*": [((), None, True)],
            f"# {legacy}ignore:AWS-0089 #7": [(("AWS-0089",), "#7", False)],
            # Other keys before the ignore key, parameters after the id, any case.
            "# trivy:exp:2030-01-01:ignore:AVD-AWS-0089 #8": [(("AVD-AWS-0089",), "#8", False)],
            "// trivy:ignore:aws-s3-enable-logging[bucket=x] #9": [(("aws-s3-enable-logging",), "#9", False)],
            "/* TRIVY:ignore:AWS-0089 */": [(("AWS-0089",), None, False)],
            # Wildcards anywhere, and more than one id, are refused.
            "#trivy:ignore:AWS-*": [((), None, True)],
            "#trivy:ignore:*-0089 #1": [((), None, True)],
            "#trivy:ignore:AWS-0001:ignore:AWS-0002 #1": [(("",), "#1", False)],
            "#trivy:ignore: #1": [(("",), "#1", False)],
            # Trivy splits on spaces only: a tab or vertical tab stays inside the word.
            "# trivy:k:v\tw:ignore:*": [((), None, True)],
            "# trivy:k:v\x0bw:ignore:DS002": [(("DS002",), None, False)],
            # Not markers: no ignore key.
            "image: aquasec/trivy:0.74.0": [],
            f"see {legacy}docs": [],
        }
        for line, expected in cases.items():
            with self.subTest(line=line):
                self.assertEqual(parse_trivy_line(line), expected)

    def test_markers_in_packaged_charts_are_found(self):
        from shoalscan.suppressions import find_trivy_suppressions

        chart = tool_tarball(
            {"web/Chart.yaml": b"name: web\n", "web/templates/pod.yaml": b"kind: Pod\n# trivy:ignore:*\nspec: {}\n"}
        )
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "web-1.0.tgz").write_bytes(chart)
            (Path(tmp) / "broken.tgz").write_bytes(b"not an archive")
            files = trivy.config_files(Path(tmp), (), 100_000)
            found = find_trivy_suppressions(Path(tmp), files, 100_000)
        self.assertEqual(files, ["broken.tgz", "web-1.0.tgz"])
        self.assertEqual([(s.path, s.line, s.valid) for s in found], [("web-1.0.tgz", 2, False)])
        self.assertTrue(found[0].text.startswith("web/templates/pod.yaml: "))


class OversizeMarkerTests(unittest.TestCase):
    def test_a_file_over_the_size_limit_is_still_linted(self):
        from shoalscan.suppressions import find_trivy_suppressions

        with tempfile.TemporaryDirectory() as tmp:
            big = "RUN true\n" * 200_000
            (Path(tmp) / "Dockerfile").write_text("FROM alpine\n" + big + "# trivy:ignore:*\n")
            (Path(tmp) / "plain.json").write_text("[" + "1," * 600_000 + "1]")
            found = find_trivy_suppressions(Path(tmp), ["Dockerfile", "plain.json"], 1_000_000)
        self.assertEqual([(s.path, s.line, s.valid) for s in found], [("Dockerfile", 200_002, False)])


class SilencedTests(unittest.TestCase):
    LOG = (
        '2026-10-12T11:58:41-05:00\tINFO\t[terraform executor] Ignore finding\trule="a" range="infra/main.tf:6-8"\n'
        '2026-10-12T11:58:41-05:00\tINFO\t[cloudformation scanner] Ignore finding\trule="b" range="cf.yaml:15"\n'
    )

    def marker(self, path, valid=True):
        from shoalscan.suppressions import Suppression

        return Suppression(path, 1, "x", ("AWS-0001",), "#1" if valid else None, False, kind="trivy")

    def test_each_silenced_finding_needs_a_valid_marker_in_its_file(self):
        both = [self.marker("infra/main.tf"), self.marker("cf.yaml")]
        self.assertEqual(trivy.silenced_findings(self.LOG, both, ()), 2)
        for markers in ([self.marker("infra/main.tf")], [self.marker("infra/main.tf"), self.marker("cf.yaml", False)]):
            with self.subTest(markers=markers), self.assertRaises(ScanError) as ctx:
                trivy.silenced_findings(self.LOG, markers, ())
            self.assertIn("cf.yaml", str(ctx.exception))
        # A valid marker below the silenced finding does not explain it.
        from shoalscan.suppressions import Suppression

        below = [Suppression("infra/main.tf", 9, "x", ("AWS-0001",), "#1", False, kind="trivy"), self.marker("cf.yaml")]
        with self.assertRaises(ScanError):
            trivy.silenced_findings(self.LOG, below, ())
        # Findings in excluded files are dropped anyway.
        self.assertEqual(trivy.silenced_findings(self.LOG, [self.marker("cf.yaml")], ("infra",)), 1)
        odd = 'x\tINFO\t[terraform executor] Ignore finding\trule="a"\n'
        with self.assertRaises(ScanError):
            trivy.silenced_findings(odd, both, ())

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
            # What really happened at install: a cosign check, or none.
            signed = inst.tool_signature_verified(TOOLS, load_lock(LOCK_PATH).tools["trivy"], inst.current_platform())
            self.assertEqual(
                doc["scanners"]["trivy"]["verification"],
                "sha256 and cosign" if signed else "sha256 (signature not verified)",
            )
            self.assertEqual(doc["scanners"]["trivy"]["signature_verified"], bool(signed))

    def test_legacy_and_wildcard_markers_cannot_pass_a_check(self):
        legacy = "#" + "tf" + "sec:ignore:*"
        with tempfile.TemporaryDirectory() as tmp:
            repo, out = Path(tmp) / "repo", Path(tmp) / "out"
            repo.mkdir()
            (repo / "main.tf").write_text(f'{legacy}\nresource "aws_s3_bucket" "a" {{\n  bucket = "a"\n}}\n')
            (repo / ".shoalscan.toml").write_text('scanners = ["trivy"]\n')
            err = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
                code = main(["scan", "--repo", str(repo), "--out", str(out), "--tools-dir", str(TOOLS)])
            # The marker is linted, and the findings it silenced have no valid marker: the scan fails.
            self.assertEqual(code, 2, err.getvalue())
            self.assertIn("not a valid, linted marker (main.tf)", err.getvalue())
            self.assertFalse((out / "findings.json").exists())

    def test_a_remote_module_is_never_fetched(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            marker, repo, out, bin_dir = base / "marker", base / "repo", base / "out", base / "bin"
            for d in (marker, repo, bin_dir):
                d.mkdir()
            (marker / "main.tf").write_text('resource "aws_s3_bucket" "m" {\n  bucket = "marker"\n}\n')
            git(marker, "init", "-q", "-b", "main")
            git(marker, "add", "-A")
            git(marker, "commit", "-q", "-m", "m")
            (repo / "main.tf").write_text(f'module "m" {{\n  source = "git::file://{marker}"\n}}\n')
            (repo / ".shoalscan.toml").write_text('scanners = ["trivy"]\n')
            # Every git Trivy runs goes through this, which records how it ended and what it saw.
            calls = base / "git-calls.txt"
            (bin_dir / "git").write_text(
                f'#!/bin/sh\n{shutil.which("git")} "$@"; rc=$?\n'
                f'echo "$rc|$HOME|$GIT_ALLOW_PROTOCOL|$*" >> {calls}\nexit $rc\n'
            )
            (bin_dir / "git").chmod(0o755)
            env = {"PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}"}
            err = io.StringIO()
            with (
                mock.patch.dict(os.environ, env),
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(err),
            ):
                code = main(["scan", "--repo", str(repo), "--out", str(out), "--tools-dir", str(TOOLS)])
            self.assertEqual(code, 0, err.getvalue())
            lines = calls.read_text().splitlines() if calls.exists() else []
            clones = [line.split("|") for line in lines if "clone" in line]
            # Trivy tried, and git refused: no transport is allowed, and the home is not the real one.
            self.assertTrue(clones, lines)
            for rc, home, allowed, _ in clones:
                self.assertNotEqual(rc, "0")
                self.assertNotEqual(home, os.path.expanduser("~"))
                self.assertEqual(allowed, "")
            doc = json.loads((out / "findings.json").read_text())
            self.assertFalse(any("marker" in f["message"] for f in doc["findings"]))


if __name__ == "__main__":
    unittest.main()
