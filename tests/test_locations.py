import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import helpers  # noqa: F401

from shoalscan.cli import main
from shoalscan.errors import SetupError
from shoalscan.locations import default_out_dir, default_tools_dir, refuse_inside_repo


class LocationTests(unittest.TestCase):
    def test_default_tools_dir_follows_xdg(self):
        with mock.patch.dict(os.environ, {"XDG_CACHE_HOME": "/var/cache/me"}):
            self.assertEqual(default_tools_dir(), Path("/var/cache/me/shoalscan/tools"))
        with mock.patch.dict(os.environ, {"XDG_CACHE_HOME": "relative/dir"}):
            self.assertEqual(default_tools_dir(), Path.home() / ".cache" / "shoalscan" / "tools")

    def test_default_out_dir_is_private_and_outside_the_repo(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = default_out_dir(Path(tmp))
            self.assertEqual(os.stat(out).st_mode & 0o777, 0o700)
            refuse_inside_repo(out, Path(tmp), "output directory", "--out")
            os.chmod(out, 0o755)
            with self.assertRaises(SetupError):
                default_out_dir(Path(tmp))
            os.chmod(out, 0o700)

    def test_inside_repo_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            for path in (repo, repo / ".shoalscan" / "tools", repo / "out"):
                with self.subTest(path=path), self.assertRaises(SetupError):
                    refuse_inside_repo(path, repo, "tools directory", "--tools-dir")

    def test_cli_refuses_tools_and_out_inside_repo(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            for args in (
                ["scan", "--repo", str(repo), "--tools-dir", str(repo / "tools"), "--out", str(Path(tmp) / "out")],
                ["scan", "--repo", str(repo), "--tools-dir", str(Path(tmp) / "tools"), "--out", str(repo / "out")],
                ["check", "--repo", str(repo), "--out", str(repo / ".shoalscan-out")],
            ):
                err = io.StringIO()
                with self.subTest(args=args), contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(main(args), 2)
                self.assertIn("inside the repository", err.getvalue())


if __name__ == "__main__":
    unittest.main()
