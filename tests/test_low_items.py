import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import helpers  # noqa: F401

from shoalscan import cli, download, opengrep
from shoalscan.errors import SetupError


class EnvironmentTests(unittest.TestCase):
    def test_only_allowlisted_variables_reach_the_scanner(self):
        env = {
            "PATH": "/usr/bin",
            "HOME": "/home/u",
            "LC_CTYPE": "C.UTF-8",
            "HTTPS_PROXY": "http://proxy",
            "SEMGREP_RULES": "x",
            "AWS_SECRET_ACCESS_KEY": "s",
        }
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertEqual(opengrep._scanner_env(), {"PATH": "/usr/bin", "HOME": "/home/u", "LC_CTYPE": "C.UTF-8"})


class _Sock:
    def __init__(self):
        self.timeouts = []

    def settimeout(self, value):
        self.timeouts.append(value)


class _SlowResponse:
    """Hands out a chunk per read while the clock moves on by 100 seconds."""

    def __init__(self, clock):
        self.clock = clock
        self.fp = type("FP", (), {"raw": type("Raw", (), {"_sock": _Sock()})()})()

    def read(self, n):
        self.clock[0] += 100
        return b"x" * 10

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class DeadlineTests(unittest.TestCase):
    def test_each_read_is_bounded_by_the_overall_deadline(self):
        clock = [0.0]
        response = _SlowResponse(clock)
        opener = mock.Mock()
        opener.open.return_value = response
        with (
            tempfile.TemporaryDirectory() as tmp,
            mock.patch.object(download.urllib.request, "build_opener", return_value=opener),
            mock.patch.object(download.time, "monotonic", lambda: clock[0]),
        ):
            with self.assertRaises(SetupError) as ctx:
                download.fetch("https://example.invalid/file", Path(tmp) / "f")
        self.assertIn("longer than", str(ctx.exception))
        timeouts = response.fp.raw._sock.timeouts
        self.assertTrue(timeouts)
        # Every read waited no longer than what was left of the deadline.
        for n, value in enumerate(timeouts):
            self.assertLessEqual(value, download.TOTAL_TIMEOUT_SECONDS - 100 * n)


class ExitCodeTests(unittest.TestCase):
    def test_unexpected_error_exits_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, out = Path(tmp) / "repo", Path(tmp) / "out"
            repo.mkdir()
            out.mkdir()
            err = io.StringIO()
            with (
                mock.patch.object(cli, "load_findings", side_effect=RuntimeError("boom")),
                contextlib.redirect_stderr(err),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(cli.main(["check", "--repo", str(repo), "--out", str(out)]), 2)
            self.assertIn("internal error", err.getvalue())


if __name__ == "__main__":
    unittest.main()
