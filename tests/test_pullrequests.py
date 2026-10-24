"""Listing a public repository's open pull requests without credentials: parsing, selection and failing closed."""

import os
import sys
import unittest
from unittest import mock

import helpers  # noqa: F401 - puts src/ on the import path

from shoalscan import pullrequests
from shoalscan.pullrequests import DiscoveryError, Listing, PullRequest

A = "a" * 40
B = "b" * 40
C = "c" * 40
D = "d" * 40
M = "e" * 40


def listing_text(*lines: str) -> str:
    return "".join(line + "\n" for line in lines)


class ParseTests(unittest.TestCase):
    def test_heads_merges_and_the_branch(self):
        text = listing_text(
            f"{A}\trefs/heads/main",
            f"{B}\trefs/pull/7/head",
            f"{M}\trefs/pull/7/merge",
            f"{C}\trefs/pull/3/head",
            f"{M}\trefs/pull/9/merge",  # a merge ref without a head ref names nothing to scan
        )
        listing = pullrequests.parse_listing(text, "main")
        self.assertEqual(listing.branch_head, A)
        self.assertEqual(listing.pulls, {7: PullRequest(7, B, True), 3: PullRequest(3, C, False)})
        self.assertEqual(listing.pulls[7].ref, "refs/pull/7/head")
        self.assertEqual(listing.pulls[7].fetch_ref, "refs/shoalscan/pull/7")

    def test_sha256_repositories(self):
        listing = pullrequests.parse_listing(listing_text(f"{'1' * 64}\trefs/heads/main"), "main")
        self.assertEqual(listing.branch_head, "1" * 64)

    def test_refs_that_only_end_like_a_pattern_are_ignored(self):
        # ls-remote matches patterns against the end of a ref name.
        text = listing_text(
            f"{A}\trefs/heads/main",
            f"{B}\trefs/remotes/x/refs/pull/1/head",
            f"{C}\trefs/heads/other/refs/heads/main",
            f"{D}\trefs/pull/01/head",
            f"{D}\trefs/pull/2/head/extra",
        )
        listing = pullrequests.parse_listing(text, "main")
        self.assertEqual((listing.branch_head, listing.pulls), (A, {}))

    def test_no_open_pull_requests_is_an_empty_listing(self):
        listing = pullrequests.parse_listing(listing_text(f"{A}\trefs/heads/main"), "main")
        self.assertEqual(listing.pulls, {})

    def test_malformed_listings_fail_closed(self):
        cases = {
            "empty": "",
            "no branch": listing_text(f"{B}\trefs/pull/7/head", f"{M}\trefs/pull/7/merge"),
            "another branch only": listing_text(f"{A}\trefs/heads/develop"),
            "no tab": listing_text(f"{A}\trefs/heads/main", f"{B} refs/pull/7/head"),
            "short sha": listing_text(f"{A}\trefs/heads/main", f"{B[:12]}\trefs/pull/7/head"),
            "upper-case sha": listing_text(f"{A}\trefs/heads/main", f"{B.upper()}\trefs/pull/7/head"),
            "blank line": f"{A}\trefs/heads/main\n\n{B}\trefs/pull/7/head\n",
            "carriage return": listing_text(f"{A}\trefs/heads/main\r"),
            "control character": listing_text(f"{A}\trefs/heads/main", f"{B}\trefs/pull/7/he\x1bad"),
            "warning text": listing_text("warning: redirecting to https://example.com/", f"{A}\trefs/heads/main"),
            "branch twice": listing_text(f"{A}\trefs/heads/main", f"{B}\trefs/heads/main"),
            "head twice": listing_text(f"{A}\trefs/heads/main", f"{B}\trefs/pull/7/head", f"{C}\trefs/pull/7/head"),
            "merge twice": listing_text(f"{A}\trefs/heads/main", f"{M}\trefs/pull/7/merge", f"{M}\trefs/pull/7/merge"),
            "huge number": listing_text(f"{A}\trefs/heads/main", f"{B}\trefs/pull/99999999999/head"),
        }
        for name, text in cases.items():
            with self.subTest(name), self.assertRaises(DiscoveryError):
                pullrequests.parse_listing(text, "main")

    def test_the_source_can_never_be_an_option(self):
        args = pullrequests.ls_remote_args("https://github.com/acme/app.git", "main")
        self.assertEqual(
            args,
            [
                "ls-remote",
                "--",
                "https://github.com/acme/app.git",
                "refs/heads/main",
                "refs/pull/*/head",
                "refs/pull/*/merge",
            ],
        )


class SelectTests(unittest.TestCase):
    def listing(self, *pulls: PullRequest) -> Listing:
        return Listing(A, {p.number: p for p in pulls})

    def test_only_pull_requests_with_a_merge_ref_are_open(self):
        chosen = pullrequests.select(self.listing(PullRequest(1, B, False), PullRequest(2, C, True)), [], 10)
        self.assertEqual([p.number for p in chosen.to_scan], [2])
        self.assertEqual(chosen.not_open, 1)

    def test_a_head_with_a_recorded_run_is_skipped_whatever_its_ref(self):
        recorded = [("refs/pull/2/head", C), ("refs/pull/9/merge", D)]
        chosen = pullrequests.select(self.listing(PullRequest(2, C, True), PullRequest(4, D, True)), recorded, 10)
        self.assertEqual(chosen.to_scan, [])
        self.assertEqual([p.number for p in chosen.already_scanned], [4, 2])

    def test_a_new_head_of_a_scanned_pull_request_without_a_merge_ref_is_scanned(self):
        # An open pull request with conflicts may lose its merge ref; its earlier run says it is worth a look.
        recorded = [("refs/pull/5/head", B)]
        chosen = pullrequests.select(self.listing(PullRequest(5, C, False), PullRequest(6, D, False)), recorded, 10)
        self.assertEqual([p.number for p in chosen.to_scan], [5])
        self.assertEqual(chosen.not_open, 1)
        # A scheduled-looking ref or a merge ref is not "seen before".
        chosen = pullrequests.select(self.listing(PullRequest(5, C, False)), [("refs/pull/5/merge", B)], 10)
        self.assertEqual(chosen.to_scan, [])

    def test_newest_first_and_capped(self):
        pulls = [PullRequest(n, f"{n:040x}", True) for n in (3, 11, 7, 20)]
        chosen = pullrequests.select(self.listing(*pulls), [], 2)
        self.assertEqual([p.number for p in chosen.to_scan], [20, 11])
        self.assertEqual([p.number for p in chosen.deferred], [7, 3])

    def test_head_ref_number(self):
        self.assertEqual(pullrequests.head_ref_number("refs/pull/12/head"), 12)
        for ref in ("refs/pull/12/merge", "main", "refs/pull/012/head", "refs/pull/x/head"):
            self.assertIsNone(pullrequests.head_ref_number(ref))


class ListRemoteTests(unittest.TestCase):
    """The runner around `git ls-remote`, driven with small stand-in commands."""

    def run_py(self, code: str, timeout: float = 30) -> str:
        return pullrequests.list_remote([sys.executable, "-c", code], dict(os.environ), timeout)

    def test_output_is_returned(self):
        self.assertEqual(self.run_py("print('x')"), "x\n")

    def test_a_failure_is_an_error_with_the_last_line(self):
        with self.assertRaisesRegex(DiscoveryError, r"exit 128\): fatal: repository not found"):
            self.run_py("import sys; sys.stderr.write('hint\\nfatal: repository not found\\n'); sys.exit(128)")

    def test_the_deadline_kills_it(self):
        with self.assertRaisesRegex(DiscoveryError, "did not finish"):
            self.run_py("import time; time.sleep(30)", timeout=1)

    def test_too_much_output_is_refused(self):
        with mock.patch.object(pullrequests, "MAX_LISTING_BYTES", 1000):
            with self.assertRaisesRegex(DiscoveryError, "printed more than"):
                self.run_py("import sys\nwhile True: sys.stdout.write('x' * 4096)")
            with self.assertRaisesRegex(DiscoveryError, "printed more than"):
                self.run_py("print('x' * 5000)")

    def test_output_that_is_not_utf8_is_refused(self):
        with self.assertRaisesRegex(DiscoveryError, "not UTF-8"):
            self.run_py("import sys; sys.stdout.buffer.write(b'\\xff\\xfe')")

    def test_a_missing_git_is_an_error(self):
        with self.assertRaisesRegex(DiscoveryError, "could not run"):
            pullrequests.list_remote(["/nonexistent/git"], {}, 5)


if __name__ == "__main__":
    unittest.main()
