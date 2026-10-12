"""Scanner isolation: a private home per run, git and proxies that go nowhere, a network sandbox,
streamed output caps, error text without the scanned code, exact archive members and signature records."""

import contextlib
import io
import json
import os
import socket
import stat
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest import mock

import helpers
from test_lock_and_install import PLAT, Assets, sha, tool_tarball

from shoalscan import install as inst
from shoalscan import process
from shoalscan.errors import ScanError, VerificationError
from shoalscan.lockfile import parse_lock
from shoalscan.scan import PinnedBinary

LOCK_PATH = helpers.ROOT / "tools.lock"


def script(directory: Path, body: str) -> Path:
    path = directory / "scanner"
    path.write_text(f"#!{sys.executable}\n" + body, encoding="utf-8")
    path.chmod(0o755)
    return path


class EnvironmentTests(unittest.TestCase):
    def test_the_home_git_proxies_and_cloud_credentials_are_neutralised(self):
        outside = {
            "PATH": "/usr/bin:/bin",
            "HOME": "/Users/someone",
            "TMPDIR": "/var/shared",
            "LANG": "C.UTF-8",
            "SSH_AUTH_SOCK": "/tmp/agent.sock",
            "GIT_CONFIG_GLOBAL": "/Users/someone/.gitconfig",
            "GIT_ASKPASS": "/usr/bin/askpass",
            "HTTPS_PROXY": "http://corp-proxy:3128",
            "NO_PROXY": "*",
            "AWS_ACCESS_KEY_ID": "AKIA...",
            "AWS_PROFILE": "prod",
            "GOOGLE_APPLICATION_CREDENTIALS": "/Users/someone/key.json",
            "AZURE_CLIENT_SECRET": "s",
            "TF_TOKEN_app_terraform_io": "t",
            "GITHUB_TOKEN": "g",
        }
        with mock.patch.dict(os.environ, outside, clear=True):
            env = process.scanner_env(Path("/run/home"))
        self.assertEqual(env["HOME"], "/run/home")
        self.assertEqual({env[k] for k in ("TMPDIR", "TMP", "TEMP")}, {"/run/home/tmp"})
        self.assertEqual(
            {
                k: env[k]
                for k in ("GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_GLOBAL", "GIT_ALLOW_PROTOCOL", "GIT_TERMINAL_PROMPT")
            },
            {
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_ALLOW_PROTOCOL": "",
                "GIT_TERMINAL_PROMPT": "0",
            },
        )
        for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
            self.assertEqual(env[name], process.CLOSED_PROXY, name)
        self.assertEqual((env["NO_PROXY"], env["no_proxy"]), ("", ""))
        self.assertEqual(env["AWS_EC2_METADATA_DISABLED"], "true")
        leaked = [k for k in env if k.startswith(("AWS_", "GOOGLE_", "AZURE_", "TF_TOKEN", "GITHUB", "SSH_"))]
        self.assertEqual(leaked, ["AWS_EC2_METADATA_DISABLED"])
        self.assertNotIn("GIT_ASKPASS", env)

    def test_each_run_has_an_empty_private_home_that_is_removed(self):
        with tempfile.TemporaryDirectory() as tmp:
            body = (
                "import json, os, stat, sys\n"
                "home = os.environ['HOME']\n"
                "print(json.dumps({'home': home, 'mode': stat.S_IMODE(os.stat(home).st_mode),\n"
                "  'entries': sorted(os.listdir(home)), 'tmp': os.environ['TMPDIR']}))\n"
            )
            code, out, _ = process.run_scanner("t", [str(script(Path(tmp), body))], Path(tmp), 30)
        seen = json.loads(out)
        self.assertEqual(code, 0)
        self.assertNotEqual(seen["home"], os.path.expanduser("~"))
        self.assertEqual(seen["mode"], 0o700)
        self.assertEqual(seen["entries"], ["tmp"])
        self.assertEqual(seen["tmp"], os.path.join(seen["home"], "tmp"))
        self.assertFalse(os.path.exists(seen["home"]))


class StreamTests(unittest.TestCase):
    def run_body(self, body, **caps):
        with tempfile.TemporaryDirectory() as tmp:
            return process.run_scanner("t", [str(script(Path(tmp), body))], Path(tmp), 30, **caps)

    def test_output_past_its_cap_stops_the_scanner_and_fails(self):
        endless = "import sys\nwhile True:\n    sys.stdout.write('x' * 65536)\n"
        with self.assertRaises(ScanError) as ctx:
            self.run_body(endless, max_stdout=1024 * 1024)
        self.assertIn("more than 1048576 bytes of output", str(ctx.exception))
        noisy = "import sys\nwhile True:\n    sys.stderr.write('y' * 65536)\n"
        with self.assertRaises(ScanError) as ctx:
            self.run_body(noisy, max_stderr=1024 * 1024)
        self.assertIn("error stream", str(ctx.exception))

    def test_output_within_its_cap_is_returned_whole(self):
        code, out, err = self.run_body(
            "import sys\nsys.stdout.write('a' * 300000)\nsys.stderr.write('warn')\n", max_stdout=300000
        )
        self.assertEqual((code, len(out), err), (0, 300000, "warn"))


class ErrorSummaryTests(unittest.TestCase):
    def test_quoted_source_and_code_frames_are_dropped(self):
        dl1000 = "unexpected 'S'\nexpecting '#', ADD, ARG, or end of input"
        self.assertEqual(process.error_summary(dl1000), "unexpected '...'\nexpecting '...', ADD, ARG, or end of input")
        frame = (
            "error[syntax]: could not parse w.yml\n"
            "  --> .github/workflows/w.yml:5:3\n"
            "   |\n"
            ' 5 |     run: echo "ghp_secret_token_value"\n'
            "   |     ^^^ here\n"
            'invalid value "password=hunter2" at line 5\n'
            "unterminated 'ghp_rest of the line\n"
        )
        summary = process.error_summary(frame)
        for leaked in ("ghp_", "hunter2", "echo"):
            self.assertNotIn(leaked, summary)
        self.assertIn("--> .github/workflows/w.yml:5:3", summary)
        self.assertIn("error[syntax]: could not parse w.yml", summary)
        self.assertEqual(len(process.error_summary("z" * 5000, 400)), 400)
        self.assertEqual(process.error_summary("can't parse 'x' here"), "can't parse '...' here")


@unittest.skipUnless(process.network_sandbox()[1] != "environment only", "no network sandbox on this machine")
class SandboxTests(unittest.TestCase):
    def test_a_scanner_cannot_open_a_connection(self):
        with socket.socket() as server, tempfile.TemporaryDirectory() as tmp:
            server.bind(("127.0.0.1", 0))
            server.listen(1)
            port = server.getsockname()[1]
            body = (
                "import socket, sys\n"
                "try:\n"
                f"    socket.create_connection(('127.0.0.1', {port}), timeout=5).close()\n"
                "    print('connected')\n"
                "except OSError as exc:\n"
                "    print('refused', exc)\n"
            )
            _, out, _ = process.run_scanner("t", [str(script(Path(tmp), body))], Path(tmp), 30)
        self.assertTrue(out.startswith(b"refused"), out)


class MemberTests(unittest.TestCase):
    def test_only_the_exact_member_matches(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name in ("../gitleaks", ".gitleaks", "/gitleaks", "x/../gitleaks", "gitleaks/"):
                archive = Path(tmp) / "a.tar.gz"
                archive.write_bytes(tool_tarball({name: b"bad"}))
                with self.subTest(name=name), self.assertRaises(VerificationError):
                    inst.extract_member(archive, "gitleaks", Path(tmp) / "out")
            archive.write_bytes(tool_tarball({"./gitleaks": b"good"}))
            inst.extract_member(archive, "gitleaks", Path(tmp) / "out")
            self.assertEqual((Path(tmp) / "out").read_bytes(), b"good")


class SignatureRecordTests(unittest.TestCase):
    """`scan` records whether a signed scanner's signature was really checked."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tools, self.work = Path(self.tmp.name) / "tools", Path(self.tmp.name) / "work"
        self.tools.mkdir()
        self.work.mkdir()
        data = tomllib.loads(LOCK_PATH.read_text(encoding="utf-8"))
        entry = data["trivy"]["platforms"][PLAT]
        archive = tool_tarball({"trivy": b"trivy-binary"})
        entry["sha256"], entry["binary_sha256"], entry["bundle_sha256"] = sha(archive), sha(b"trivy-binary"), sha(b"b")
        self.tool = parse_lock(data).tools["trivy"]
        self.assets = Assets()
        self.assets.files.update({entry["url"]: archive, entry["bundle_url"]: b"b"})
        self.checks = 0

    def tearDown(self):
        self.tmp.cleanup()

    def install(self, cosign):
        def accept(*args):
            self.checks += 1

        with contextlib.redirect_stderr(io.StringIO()):
            inst.install_pinned_tool(self.tools, self.tool, PLAT, self.assets.fetch, self.work, cosign, accept)
        return inst.tool_signature_verified(self.tools, self.tool, PLAT)

    def test_skipping_the_check_is_recorded_and_a_later_install_verifies(self):
        self.assertIs(self.install(None), False)
        self.assertEqual(self.checks, 0)
        pin = PinnedBinary("0.74.0", Path("/t"), "0" * 64, signature_verified=False)
        self.assertEqual(pin.verification(), "sha256 (signature not verified)")
        # The binary is in place but was never verified: with cosign, it is checked now.
        self.assertIs(self.install(Path("/t/cosign")), True)
        self.assertEqual(self.checks, 1)
        self.assertEqual(stat.S_IMODE(inst.tool_record_path(self.tools, "trivy").stat().st_mode) & 0o022, 0)
        self.assertIs(self.install(Path("/t/cosign")), True)
        self.assertEqual(self.checks, 1)
        pin = PinnedBinary("0.74.0", Path("/t"), "0" * 64, signature_verified=True)
        self.assertEqual(pin.verification(), "sha256 and cosign")

    def test_a_record_for_another_binary_does_not_count(self):
        self.install(Path("/t/cosign"))
        inst.tool_path(self.tools, "trivy").write_bytes(b"swapped")
        self.assertIs(inst.tool_signature_verified(self.tools, self.tool, PLAT), False)
        unsigned = parse_lock(tomllib.loads(LOCK_PATH.read_text(encoding="utf-8"))).tools["gitleaks"]
        self.assertIsNone(inst.tool_signature_verified(self.tools, unsigned, PLAT))
        self.assertEqual(PinnedBinary("8.30.1", Path("/t"), "0" * 64).verification(), "sha256")


class RunScannersTests(unittest.TestCase):
    def test_a_run_lists_the_scanners_it_used(self):
        from shoalscan.dashboard.data import _scanners_ran

        stored = json.dumps({"opengrep": {"version": "1.30.2"}, "gitleaks": {"version": "8.30.1"}, "odd": 3})
        self.assertEqual(
            _scanners_ran(stored),
            [
                {"name": "gitleaks", "version": "8.30.1"},
                {"name": "odd", "version": None},
                {"name": "opengrep", "version": "1.30.2"},
            ],
        )
        self.assertEqual((_scanners_ran("not json"), _scanners_ran(None), _scanners_ran("[]")), ([], [], []))


if __name__ == "__main__":
    unittest.main()
