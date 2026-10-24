"""Listing a public repository's open pull requests without credentials: parsing, selection and failing closed."""

import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

import helpers  # noqa: F401 - puts src/ on the import path

from shoalscan import pullrequests
from shoalscan.pullrequests import DiscoveryError, Listing, PullRequest, Recorded

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


NOW = datetime(2026, 10, 24, 12, 0, tzinfo=timezone.utc)


def ran(ref: str, commit: str, hours_ago: float, outcome: str = "passed") -> Recorded:
    return Recorded(ref, commit, outcome, (NOW - timedelta(hours=hours_ago)).strftime("%Y-%m-%dT%H:%M:%SZ"))


class SelectTests(unittest.TestCase):
    def listing(self, *pulls: PullRequest) -> Listing:
        return Listing(A, {p.number: p for p in pulls})

    def select(self, pulls, recorded, cap=10):
        return pullrequests.select(self.listing(*pulls), recorded, cap, NOW)

    def test_only_pull_requests_with_a_merge_ref_are_open(self):
        chosen = self.select([PullRequest(1, B, False), PullRequest(2, C, True)], [])
        self.assertEqual([p.number for p in chosen.to_scan], [2])
        self.assertEqual(chosen.not_open, 1)

    def test_a_head_with_a_recorded_run_is_skipped_whatever_its_ref(self):
        recorded = [ran("refs/pull/2/head", C, 5), ran("refs/pull/9/merge", D, 5, "blocked")]
        chosen = self.select([PullRequest(2, C, True), PullRequest(4, D, True)], recorded)
        self.assertEqual(chosen.to_scan, [])
        self.assertEqual([p.number for p in chosen.already_scanned], [2, 4])

    def test_a_new_head_of_a_scanned_pull_request_without_a_merge_ref_is_scanned(self):
        # An open pull request with conflicts may lose its merge ref; its earlier run says it is worth a look.
        chosen = self.select([PullRequest(5, C, False), PullRequest(6, D, False)], [ran("refs/pull/5/head", B, 5)])
        self.assertEqual([p.number for p in chosen.to_scan], [5])
        self.assertEqual(chosen.not_open, 1)
        # A merge ref's run is not "seen before".
        chosen = self.select([PullRequest(5, C, False)], [ran("refs/pull/5/merge", B, 5)])
        self.assertEqual(chosen.to_scan, [])

    def test_a_scan_error_is_retried_after_a_day_and_after_everything_else(self):
        recorded = [ran("refs/pull/3/head", B, 2, "scan_error"), ran("refs/pull/4/head", C, 30, "scan_error")]
        pulls = [PullRequest(3, B, True), PullRequest(4, C, True), PullRequest(9, D, True)]
        chosen = self.select(pulls, recorded)
        self.assertEqual([p.number for p in chosen.failed], [3])
        self.assertEqual([p.number for p in chosen.to_scan], [9, 4])
        # A scan error never hides a run with results for the same head.
        chosen = self.select([PullRequest(3, B, True)], [*recorded, ran("refs/pull/3/head", B, 1)])
        self.assertEqual([p.number for p in chosen.already_scanned], [3])

    def test_one_busy_pull_request_cannot_monopolise_the_scans(self):
        # #5 is force-pushed again and again; it is scanned at most once an hour, and the pull requests scanned
        # longest ago (or never) go first.
        recorded = [ran("refs/pull/5/head", B, 0.2), ran("refs/pull/6/head", C, 3), ran("refs/pull/7/head", D, 9)]
        pulls = [PullRequest(5, M, True), PullRequest(6, "1" * 40, True), PullRequest(7, "2" * 40, True)]
        pulls.append(PullRequest(8, "3" * 40, True))
        chosen = self.select(pulls, recorded)
        self.assertEqual([p.number for p in chosen.throttled], [5])
        self.assertEqual([p.number for p in chosen.to_scan], [8, 7, 6])

    def test_a_head_is_scanned_again_when_its_scan_key_changes(self):
        recorded = [ran("refs/pull/3/head", B, 5), ran("refs/pull/4/head", C, 5, "blocked")]
        pulls = [PullRequest(3, B, True), PullRequest(4, C, True), PullRequest(9, D, True)]
        chosen = pullrequests.select(self.listing(*pulls), recorded, 10, NOW, key="k2", scanned={B: "k2", C: "k1"})
        self.assertEqual([p.number for p in chosen.already_scanned], [3])
        # #4's results predate the key: it goes again, after the never-scanned #9.
        self.assertEqual([p.number for p in chosen.to_scan], [9, 4])
        # Results recorded without a key (by an older version or a CI job) go again too.
        chosen = pullrequests.select(self.listing(*pulls[:1]), recorded, 10, NOW, key="k2", scanned={})
        self.assertEqual([p.number for p in chosen.to_scan], [3])

    def test_an_attempt_that_recorded_nothing_still_counts_against_the_hourly_limit(self):
        pulls = [PullRequest(5, B, True), PullRequest(6, C, True)]
        attempts = {5: (NOW - timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ")}
        chosen = pullrequests.select(self.listing(*pulls), [], 10, NOW, attempts=attempts)
        self.assertEqual([p.number for p in chosen.throttled], [5])
        self.assertEqual([p.number for p in chosen.to_scan], [6])

    def test_capped_in_order(self):
        pulls = [PullRequest(n, f"{n:040x}", True) for n in (3, 11, 7, 20)]
        chosen = self.select(pulls, [], 2)
        self.assertEqual([p.number for p in chosen.to_scan], [3, 7])
        self.assertEqual([p.number for p in chosen.deferred], [11, 20])

    def test_head_ref_number(self):
        self.assertEqual(pullrequests.head_ref_number("refs/pull/12/head"), 12)
        for ref in ("refs/pull/12/merge", "main", "refs/pull/012/head", "refs/pull/x/head"):
            self.assertIsNone(pullrequests.head_ref_number(ref))


class PollStateTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "state.json"

    def tearDown(self):
        self._tmp.cleanup()

    def listing(self, **heads) -> Listing:
        return Listing(A, {int(n[1:]): PullRequest(int(n[1:]), sha, False) for n, sha in heads.items()})

    def test_the_first_poll_sets_the_mark_and_scans_nothing_without_a_merge_ref(self):
        self.assertIsNone(pullrequests.load_state(self.path))
        first = self.listing(n3=B, n5=C)
        self.assertEqual(pullrequests.eligible(first, None), set())
        state = pullrequests.next_state(first, None, set())
        self.path.write_text(pullrequests.state_json(state))
        state = pullrequests.load_state(self.path)
        self.assertEqual((state.mark, state.heads, state.tracked), (5, {3: B, 5: C}, set()))

    def test_new_numbers_and_moved_heads_become_eligible_and_stay_so(self):
        state = pullrequests.PollState(5, {3: B, 5: C, 4: D}, set())
        later = self.listing(n3=B, n4=M, n5=C, n6=D)  # #4 moved, #6 is new, #3 and #5 are unchanged
        extra = pullrequests.eligible(later, state)
        self.assertEqual(extra, {4, 6})
        # A poll that could not scan them (caps) keeps them eligible though nothing moves again.
        state = pullrequests.next_state(later, state, extra)
        self.assertEqual(state.mark, 5)
        self.assertEqual(pullrequests.eligible(later, state), {4, 6})
        chosen = pullrequests.select(later, [], 10, NOW, without_merge_ref=extra)
        self.assertEqual([p.number for p in chosen.to_scan], [4, 6])
        self.assertEqual(chosen.not_open, 2)

    def test_a_state_that_cannot_be_read_fails_closed(self):
        for text in (
            "{",
            "[]",
            '{"mark": "x", "heads": {}, "tracked": []}',
            '{"mark": 1, "heads": {"1": "zz"}, "tracked": []}',
        ):
            with self.subTest(text=text):
                self.path.write_text(text)
                with self.assertRaises(DiscoveryError):
                    pullrequests.load_state(self.path)


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
