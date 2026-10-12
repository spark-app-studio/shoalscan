"""Similar findings: the local Ollama client, the vector maths, storage, and the commands.

A small HTTP server on the loopback interface plays Ollama, so the real
request path (urllib, no proxy, JSON) is exercised without a model.
"""

import contextlib
import hashlib
import io
import json
import math
import re
import tempfile
import threading
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest import mock

import helpers  # noqa: F401 - puts src/ on the import path
from history_fixtures import finding, record, sample_history

from shoalscan import embeddings, history
from shoalscan.cli import main
from shoalscan.errors import SetupError

DIMS = 64


def fake_vector(text: str) -> list[float]:
    """A word-hash vector: texts that share words point the same way."""
    v = [0.0] * DIMS
    for word in re.findall(r"[a-z0-9]+", text.lower()):
        v[int(hashlib.sha256(word.encode()).hexdigest(), 16) % DIMS] += 1.0
    v[0] += 0.1
    return v


class FakeOllama:
    """Answers POST /api/embed like Ollama. `mode` makes it misbehave."""

    def __init__(self):
        self.requests: list[dict] = []
        self.mode = "ok"
        self.redirect_to = ""
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):  # noqa: N802 - the name http.server looks up
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                owner.requests.append({"path": self.path, **body})
                if owner.mode == "missing-model":
                    return self.reply(404, {"error": f'model "{body["model"]}" not found, try pulling it first'})
                if owner.mode == "redirect":
                    self.send_response(307)
                    self.send_header("Location", owner.redirect_to + "/api/embed")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return None
                if owner.mode == "garbage":
                    return self.reply(200, "not json", raw=True)
                vectors = [fake_vector(t) for t in body["input"]]
                if owner.mode == "short":
                    vectors = vectors[:-1]
                if owner.mode == "nan":
                    return self.reply(200, '{"embeddings": [[NaN, 1.0]]}', raw=True)
                if owner.mode == "ragged":
                    vectors = [v[: DIMS - i] for i, v in enumerate(vectors)]
                return self.reply(200, {"model": body["model"], "embeddings": vectors})

            def reply(self, status, payload, raw=False):
                data = (payload if raw else json.dumps(payload)).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.httpd = HTTPServer(("127.0.0.1", 0), Handler)
        self.host = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def closed_port() -> str:
    """The URL of a loopback port nothing listens on."""
    probe = HTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
    port = probe.server_address[1]
    probe.server_close()
    return f"http://127.0.0.1:{port}"


def quiet(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


class SettingsTests(unittest.TestCase):
    def test_only_ollama_on_loopback(self):
        self.assertEqual(embeddings.validate_host("http://localhost:11434"), "http://localhost:11434")
        self.assertEqual(embeddings.validate_host("http://127.0.0.1"), "http://127.0.0.1:11434")
        self.assertEqual(embeddings.validate_host("http://[::1]:9999/"), "http://[::1]:9999")
        for bad in (
            "https://127.0.0.1:11434",
            "http://example.com:11434",
            "http://127.0.0.1.example.com",
            "http://0.0.0.0:11434",
            "http://u:p@127.0.0.1:1",
            "http://127.0.0.1:11434/api",
            "http://127.0.0.1:99999",
            "ftp://127.0.0.1",
        ):
            with self.subTest(bad=bad), self.assertRaises(SetupError):
                embeddings.validate_host(bad)

    def test_model_names(self):
        self.assertEqual(embeddings.validate_model("embeddinggemma:300m"), "embeddinggemma:300m")
        for bad in ("", "a b", "x\n", "y" * 300):
            with self.subTest(bad=bad), self.assertRaises(SetupError):
                embeddings.validate_model(bad)

    def test_the_text_never_holds_code(self):
        text = embeddings.finding_text("opengrep", "r.eval", "src/a.py", "api", "Avoid  eval\nhere")
        self.assertEqual(
            text, "task: sentence similarity | query: opengrep r.eval in api file src/a.py: Avoid eval here"
        )
        self.assertEqual(len(embeddings.finding_text("t", "r", "p", "c", "x" * 5000)), embeddings.MAX_TEXT_CHARS)


class GroupingTests(unittest.TestCase):
    def test_each_group_is_held_together_by_its_leader(self):
        unit = embeddings.normalise
        a, b, c = unit([1.0, 0.0, 0.0]), unit([1.0, 0.6, 0.0]), unit([1.0, 1.4, 0.0])
        far = unit([0.0, 0.0, 1.0])
        # a~b and b~c are alike, but a and c are not: no chain makes them one group.
        self.assertEqual(embeddings.group([(1, a), (2, b), (3, c), (4, far)], 0.85), [[1, 2], [3], [4]])
        self.assertEqual(embeddings.group([(2, b), (1, a), (3, c)], 0.85), [[2, 1, 3]])  # order decides the leaders
        self.assertEqual(embeddings.group([(1, a), (2, [1.0, 0.0])], 0.5), [[1], [2]])  # other lengths never match
        self.assertEqual(embeddings.group([], 0.85), [])


class MathsTests(unittest.TestCase):
    def test_cosine_similarity(self):
        self.assertAlmostEqual(embeddings.cosine([1, 0], [1, 0]), 1.0)
        self.assertAlmostEqual(embeddings.cosine([1, 0], [0, 1]), 0.0)
        self.assertAlmostEqual(embeddings.cosine([1, 0], [-1, 0]), -1.0)
        self.assertAlmostEqual(embeddings.cosine([3, 4], [6, 8]), 1.0)
        self.assertAlmostEqual(embeddings.cosine([1, 1], [1, 0]), 1 / math.sqrt(2))
        self.assertEqual(embeddings.cosine([0, 0], [1, 0]), 0.0)
        with self.assertRaises(ValueError):
            embeddings.cosine([1], [1, 2])

    def test_vectors_are_stored_as_float32(self):
        v = embeddings.normalise([3.0, 4.0])
        self.assertEqual(v, [0.6, 0.8])
        blob = embeddings.pack(v)
        self.assertEqual(len(blob), 8)
        back = embeddings.unpack(blob, 2)
        self.assertAlmostEqual(back[0], 0.6, places=6)
        with self.assertRaises(ValueError):
            embeddings.unpack(blob, 3)
        with self.assertRaises(embeddings.OllamaError):
            embeddings.normalise([0.0, 0.0])


class OllamaClientTests(unittest.TestCase):
    def setUp(self):
        self.ollama = FakeOllama()

    def tearDown(self):
        self.ollama.close()

    def test_batches_and_unit_vectors(self):
        with mock.patch.object(embeddings, "BATCH", 2):
            vectors = embeddings.embed(["a b", "c d", "e f"], "embeddinggemma", self.ollama.host)
        self.assertEqual(len(vectors), 3)
        for v in vectors:
            self.assertAlmostEqual(embeddings.norm(v), 1.0)
        self.assertEqual([r["path"] for r in self.ollama.requests], ["/api/embed", "/api/embed"])
        self.assertEqual(
            self.ollama.requests[0],
            {"path": "/api/embed", "model": "embeddinggemma", "input": ["a b", "c d"], "truncate": True},
        )

    def test_failures_are_ollama_errors(self):
        cases = {
            "missing-model": "ollama pull",
            "garbage": "no embeddings",
            "short": "vectors for",
            "ragged": "different lengths",
        }
        for mode, words in cases.items():
            self.ollama.mode = mode
            with self.subTest(mode=mode), self.assertRaisesRegex(embeddings.OllamaError, words):
                embeddings.embed(["a", "b", "c"], "embeddinggemma", self.ollama.host)
        self.ollama.mode = "nan"
        with self.assertRaisesRegex(embeddings.OllamaError, "finite"):
            embeddings.embed(["a"], "embeddinggemma", self.ollama.host)

    def test_nothing_listening(self):
        with self.assertRaisesRegex(embeddings.OllamaError, "not reachable"):
            embeddings.embed(["a"], "embeddinggemma", closed_port(), timeout=5)

    def test_redirects_are_never_followed(self):
        other = FakeOllama()
        self.addCleanup(other.close)
        self.ollama.mode, self.ollama.redirect_to = "redirect", other.host
        with self.assertRaisesRegex(embeddings.OllamaError, "redirect"):
            embeddings.embed(["a"], "embeddinggemma", self.ollama.host, timeout=5)
        self.assertEqual(other.requests, [], "the finding text must not reach the redirect's target")
        handlers = [type(h) for h in embeddings._opener().handlers]
        self.assertIn(embeddings._RefuseRedirects, handlers)
        self.assertNotIn(urllib.request.HTTPRedirectHandler, handlers)

    def test_the_answer_is_bounded_by_what_a_batch_can_need(self):
        # A batch of the longest vectors, with every number at its longest, fits; the cap stays near 32 MiB.
        self.assertLessEqual(embeddings.MAX_RESPONSE_BYTES, 32 * 1024 * 1024)
        longest = json.dumps({"embeddings": [[-1.2345678901234567e-05] * embeddings.MAX_DIMS] * embeddings.BATCH})
        self.assertLess(len(longest), embeddings.MAX_RESPONSE_BYTES)

    def test_proxies_are_never_used(self):
        with mock.patch.dict(
            "os.environ", {"http_proxy": "http://203.0.113.1:9", "HTTP_PROXY": "http://203.0.113.1:9", "no_proxy": ""}
        ):
            self.assertEqual(len(embeddings.embed(["a"], "embeddinggemma", self.ollama.host, timeout=5)), 1)


class HistoryCase(unittest.TestCase):
    """The sample history in a fresh database, with a fake Ollama."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.db = self.dir / "h.db"
        self.conn = history.open_for_write(self.db)
        sample_history(self.conn, self.dir)
        self.ollama = FakeOllama()

    def tearDown(self):
        self.ollama.close()
        self.conn.close()
        self.tmp.cleanup()

    def embed(self, repo="acme/app"):
        return embeddings.embed_repository(
            self.conn, repo, "embeddinggemma", self.ollama.host, now="2026-10-01T00:00:00Z"
        )

    def key_id(self, path):
        return self.conn.execute("SELECT id FROM finding_keys WHERE path = ?", (path,)).fetchone()[0]


class StorageTests(HistoryCase):
    def test_the_schema_has_the_table(self):
        self.assertEqual(self.conn.execute("PRAGMA user_version").fetchone()[0], history.SCHEMA_VERSION)
        cols = [r[1] for r in self.conn.execute("PRAGMA table_info(finding_embeddings)")]
        self.assertEqual(cols, ["key_id", "model", "text_sha256", "dims", "vector", "created_at"])

    def test_embeds_once_and_again_only_when_the_text_changes(self):
        keys = self.conn.execute(
            "SELECT COUNT(*) FROM finding_keys WHERE repo_id = (SELECT id FROM repos WHERE name = 'acme/app')"
        ).fetchone()[0]
        first = self.embed()
        self.assertEqual((first.embedded, first.up_to_date), (keys, 0))
        again = self.embed()
        self.assertEqual((again.embedded, again.up_to_date), (0, keys))
        changed = finding(
            "shoalscan.plain-http-url", "web/b.js", "bbbb:0", "WARNING", "web", message="a different message"
        )
        record(self.conn, self.dir, "acme/app", "9" * 40, 28, [changed])
        self.assertEqual(self.embed().embedded, 1)
        with self.assertRaises(SetupError):
            self.embed("acme/missing")

    def test_embeddings_go_with_their_finding(self):
        self.embed()
        before = self.conn.execute("SELECT COUNT(*) FROM finding_embeddings").fetchone()[0]
        for run in history.list_runs(self.conn, "acme/app"):
            history.delete_run(self.conn, "acme/app", run["id"])
        self.assertLess(self.conn.execute("SELECT COUNT(*) FROM finding_embeddings").fetchone()[0], before)

    def test_similar_findings_carry_their_decisions(self):
        a = finding("community.python.eval", "src/x.py", "x0:0", message="Eval of user input allows code injection")
        b = finding(
            "community.python.eval", "src/y.py", "y0:0", message="Eval of user input allows code injection here"
        )
        c = finding(
            "shoalscan.tls-off", "src/z.py", "z0:0", message="Certificate checks are turned off for this client"
        )
        from shoalscan.baseline import Entry

        base = [Entry(c.tool, c.rule, c.path, c.fingerprint, "#7", "Accepted: test client only")]
        record(self.conn, self.dir, "acme/app", "a" * 40, 29, [a, b, c], baseline=base)
        self.embed()
        history.set_reviews(
            self.db,
            "acme/app",
            [[b.tool, b.rule, b.path, b.fingerprint]],
            "false_positive",
            "Input is a constant.",
            "me",
        )
        found = embeddings.similar(self.conn, self.key_id("src/x.py"), "embeddinggemma", threshold=0.5, limit=3)
        self.assertEqual(found[0]["key"][2], "src/y.py")
        self.assertGreater(found[0]["score"], 0.9)
        self.assertEqual(found[0]["decision"]["status"], "false_positive")
        self.assertEqual(found[0]["decision"]["source"], "review")
        self.assertTrue(all(f["score"] >= 0.5 for f in found))
        self.assertEqual(found, sorted(found, key=lambda f: -f["score"]))
        tls = embeddings.similar(self.conn, self.key_id("src/z.py"), "embeddinggemma", threshold=-1, limit=50)
        self.assertNotIn("src/z.py", [f["key"][2] for f in tls])
        self.assertEqual(
            len(embeddings.similar(self.conn, self.key_id("src/x.py"), "embeddinggemma", threshold=-1, limit=2)), 2
        )
        z_like = embeddings.similar(self.conn, self.key_id("src/y.py"), "embeddinggemma", threshold=-1, limit=50)
        decided = {f["key"][2]: f["decision"] for f in z_like}
        self.assertEqual(
            decided["src/z.py"],
            {
                "source": "baseline",
                "status": "baselined",
                "issue": "#7",
                "description": "Accepted: test client only",
                "run": self.conn.execute("SELECT MAX(id) FROM runs").fetchone()[0],
                "commit": "a" * 40,
                "at": "2026-09-29T02:00:00Z",
            },
        )
        self.assertEqual(found[0]["decision"]["by"], "me")
        self.assertRegex(found[0]["decision"]["at"], r"^\d{4}-\d\d-\d\dT")
        self.assertIsNone(embeddings.similar(self.conn, self.key_id("src/x.py"), "other-model"))

    def test_other_repositories_only_when_asked(self):
        self.embed()
        self.embed("acme/other")
        target = self.key_id("src/a.py")
        mine = embeddings.similar(self.conn, target, "embeddinggemma", threshold=-1, limit=50)
        everyone = embeddings.similar(self.conn, target, "embeddinggemma", threshold=-1, limit=50, all_repos=True)
        self.assertEqual({f["repo"] for f in mine}, {"acme/app"})
        self.assertEqual({f["repo"] for f in everyone}, {"acme/app", "acme/other"})


class SuggestionTests(HistoryCase):
    """Untriaged findings get the decision of their most similar decided finding, as a hint."""

    def setUp(self):
        super().setUp()
        from shoalscan.baseline import Entry

        self.a = finding(
            "community.python.eval", "src/x.py", "x0:0", message="Eval of user input allows code injection"
        )
        self.b = finding(
            "community.python.eval", "src/y.py", "y0:0", message="Eval of user input allows code injection here"
        )
        self.c = finding(
            "shoalscan.tls-off", "src/z.py", "z0:0", message="Certificate checks are turned off for this client"
        )
        self.d = finding(
            "shoalscan.tls-off", "src/w.py", "w0:0", message="Certificate checks are turned off for that client"
        )
        self.e = finding(
            "shoalscan.tls-off", "src/v.py", "v0:0", message="Certificate checks are turned off for the client"
        )
        base = [
            Entry(self.d.tool, self.d.rule, self.d.path, self.d.fingerprint, "#7", "False positive: test client only")
        ]
        record(self.conn, self.dir, "acme/app", "a" * 40, 29, [self.a, self.b, self.c, self.d, self.e], baseline=base)
        self.review(self.a, "false_positive", "Input is a constant.")
        self.embed()

    def review(self, f, status, description):
        history.set_reviews(self.db, "acme/app", [[f.tool, f.rule, f.path, f.fingerprint]], status, description, "me")

    def suggest(self, threshold=0.6):
        return embeddings.suggest_repository(self.conn, "acme/app", "embeddinggemma", threshold, "2026-10-01T00:00:00Z")

    def rows(self, **kw):
        from shoalscan.dashboard.data import Data

        data = Data(history.open_read_only(self.db))
        try:
            repo_id = data.repo_id("acme/app")
            run = self.conn.execute("SELECT MAX(id) FROM runs").fetchone()[0]
            return {f["path"]: f for f in data.findings(repo_id, run, limit=500, **kw)["findings"]}
        finally:
            data.conn.close()

    def test_untriaged_findings_get_the_closest_decision(self):
        self.assertGreaterEqual(self.suggest(), 3)
        rows = self.rows()
        self.assertEqual(rows["src/y.py"]["suggestion"]["status"], "false_positive")
        self.assertEqual(rows["src/y.py"]["suggestion"]["like"][2], "src/x.py")
        self.assertEqual(rows["src/y.py"]["suggestion"]["source"], "review")
        self.assertEqual(rows["src/y.py"]["suggestion"]["description"], "Input is a constant.")
        self.assertEqual(rows["src/z.py"]["suggestion"]["like"][2], "src/w.py")
        self.assertEqual(rows["src/z.py"]["suggestion"]["source"], "baseline")
        self.assertEqual(rows["src/z.py"]["suggestion"]["issue"], "#7")
        for decided in ("src/x.py", "src/w.py"):
            self.assertIsNone(rows[decided]["suggestion"])
        self.assertEqual(set(self.rows(review="suggested")), {"src/y.py", "src/z.py", "src/v.py"})

    def test_a_high_threshold_suggests_less(self):
        self.assertEqual(self.suggest(threshold=1.0), 0)
        self.assertEqual(self.rows(review="suggested"), {})

    def test_suggestions_follow_decisions_as_they_change(self):
        self.suggest()
        self.review(self.a, "open", "Reopened after a second look.")
        self.assertIsNone(self.rows()["src/y.py"]["suggestion"])
        self.assertNotIn("src/y.py", self.rows(review="suggested"))
        self.review(self.a, "fixed", "Removed the eval call entirely.")
        self.assertIsNone(self.rows()["src/y.py"]["suggestion"])  # a fix is about one place, never a pattern
        self.review(self.a, "wont_fix", "Legacy module, retired next quarter.")
        self.assertEqual(self.rows()["src/y.py"]["suggestion"]["status"], "wont_fix")
        self.review(self.b, "accepted_risk", "Accepted for the demo build.")
        self.assertIsNone(self.rows()["src/y.py"]["suggestion"])  # decided now, so no hint

    def data(self):
        from shoalscan.dashboard.data import Data

        data = Data(history.open_read_only(self.db))
        self.addCleanup(data.conn.close)
        return data, data.repo_id("acme/app"), self.conn.execute("SELECT MAX(id) FROM runs").fetchone()[0]

    def test_untriaged_findings_fall_into_groups(self):
        self.suggest()
        data, repo_id, run = self.data()
        res = data.groups(repo_id, run, 0.6)
        # a is reviewed and d is in the baseline; b stands alone, c and e are alike.
        self.assertEqual((res["untriaged"], res["embedded"], res["considered"]), (3, 3, 3))
        self.assertEqual(len(res["groups"]), 1)
        group = res["groups"][0]
        self.assertEqual(group["size"], 2)
        self.assertEqual({m["path"] for m in group["members"]}, {"src/z.py", "src/v.py"})
        self.assertEqual(group["rules"], [{"rule": "shoalscan.tls-off", "count": 2}])
        self.assertEqual(group["suggested"], [{"status": "false_positive", "count": 2}])
        self.assertEqual(res["grouped"], 2)
        keys = data.group_keys(repo_id, run, group["key"], 0.6)
        found = data.findings(repo_id, run, keys=keys)
        self.assertEqual({f["path"] for f in found["findings"]}, {"src/z.py", "src/v.py"})
        self.assertEqual(data.groups(repo_id, run, 1.0)["groups"], [])

    def test_a_group_shrinks_as_its_findings_are_reviewed(self):
        data, repo_id, run = self.data()
        leader = data.groups(repo_id, run, 0.6)["groups"][0]["key"]
        other = self.e if leader[2] == self.c.path else self.c
        self.review(other, "false_positive", "Test client only, as for src/w.py.")
        data, repo_id, run = self.data()
        self.assertEqual(data.groups(repo_id, run, 0.6)["groups"], [])
        self.assertEqual(data.group_keys(repo_id, run, leader, 0.6), [])
        self.assertEqual(data.findings(repo_id, run, keys=[])["total"], 0)

    def test_the_embedding_status_counts_what_is_missing_or_changed(self):
        self.suggest()
        data, repo_id, run = self.data()
        status = data.embedding_status(repo_id, run)
        self.assertEqual(
            {k: status[k] for k in ("findings", "embedded", "missing", "stale", "untriaged", "suggested")},
            {"findings": 5, "embedded": 5, "missing": 0, "stale": 0, "untriaged": 3, "suggested": 3},
        )
        self.assertEqual((status["embedded_at"], status["suggestions_at"]), ("2026-10-01T00:00:00Z",) * 2)
        changed = finding(self.c.rule, self.c.path, self.c.fingerprint, message="Certificate checks are skipped")
        new = finding("shoalscan.secret-in-log", "src/n.py", "n0:0", message="A token is written to the log")
        record(self.conn, self.dir, "acme/app", "b" * 40, 30, [self.a, self.b, changed, self.d, self.e, new])
        data, repo_id, run = self.data()
        status = data.embedding_status(repo_id, run)
        self.assertEqual((status["findings"], status["embedded"], status["missing"], status["stale"]), (6, 5, 1, 1))
        self.embed()
        data, repo_id, run = self.data()
        status = data.embedding_status(repo_id, run)
        self.assertEqual((status["missing"], status["stale"]), (0, 0))

    def test_the_command_reports_suggestions(self):
        code, _, err = quiet(
            [
                "triage",
                "embed",
                "--repo-name",
                "acme/app",
                "--ollama-host",
                self.ollama.host,
                "--threshold",
                "0.6",
                "--db",
                str(self.db),
            ]
        )
        self.assertEqual(code, 0, err)
        self.assertRegex(err, r"\d+ untriaged findings have a suggestion")
        self.assertEqual(
            quiet(["triage", "embed", "--repo-name", "acme/app", "--threshold", "2", "--db", str(self.db)])[0], 2
        )


class CommandTests(HistoryCase):
    def setUp(self):
        super().setUp()
        self.conn.close()
        self.conn = history.open_for_write(self.db)

    def cli(self, *args):
        return quiet([*args, "--db", str(self.db)])

    def test_embed_then_suggest(self):
        code, _, err = self.cli("triage", "embed", "--repo-name", "acme/app", "--ollama-host", self.ollama.host)
        self.assertEqual(code, 0, err)
        self.assertRegex(err, r"embedded \d+ findings of acme/app with embeddinggemma")
        fp = self.conn.execute("SELECT fingerprint FROM finding_keys WHERE path = 'src/a.py'").fetchone()[0]
        code, out, err = self.cli("triage", "suggest-similar", "aaaa", "--repo-name", "acme/app", "--threshold", "0.1")
        self.assertEqual(code, 2)  # not a whole fingerprint, and too short to be a prefix
        self.assertIn("at least its first 8 characters", err)
        code, out, err = self.cli("triage", "suggest-similar", fp, "--repo-name", "acme/app", "--threshold", "0.1")
        self.assertEqual(code, 0, err)
        self.assertTrue(out.startswith("Findings like community.python.eval in src/a.py"))
        code, out, _ = self.cli(
            "triage", "suggest-similar", fp, "--repo-name", "acme/app", "--threshold", "0.1", "--format", "json"
        )
        doc = json.loads(out)
        self.assertEqual(doc["finding"][2], "src/a.py")
        self.assertLessEqual(len(doc["similar"]), 3)

    def test_without_embeddings_or_ollama(self):
        fp = self.conn.execute("SELECT fingerprint FROM finding_keys WHERE path = 'src/a.py'").fetchone()[0]
        code, _, err = self.cli("triage", "suggest-similar", fp, "--repo-name", "acme/app")
        self.assertEqual(code, 2)
        self.assertIn("triage embed --repo-name acme/app", err)
        code, _, err = self.cli("triage", "embed", "--repo-name", "acme/app", "--ollama-host", closed_port())
        self.assertEqual(code, 2)
        self.assertIn("warning: no embeddings were made", err)
        self.assertNotIn("Traceback", err)
        code, _, err = self.cli(
            "triage", "embed", "--repo-name", "acme/app", "--ollama-host", "http://example.com:11434"
        )
        self.assertEqual(code, 2)
        self.assertIn("loopback", err.replace("127.0.0.1, ::1, localhost", "loopback"))

    def test_ambiguous_prefixes_list_the_candidates(self):
        a = finding("r.one", "src/p.py", "deadbeef00:0")
        b = finding("r.two", "src/q.py", "deadbeef11:0")
        record(self.conn, self.dir, "acme/app", "b" * 40, 29, [a, b])
        code, _, err = self.cli("triage", "suggest-similar", "deadbeef", "--repo-name", "acme/app")
        self.assertEqual(code, 2)
        self.assertIn("2 findings match deadbeef", err)
        self.assertIn("src/q.py", err)


class RecordEmbedTests(unittest.TestCase):
    """`record --embed` never fails a record over Ollama, and refuses a bad host before recording."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.db = self.dir / "h.db"
        from history_fixtures import check_output, summary, write_findings

        self.findings = [finding("r.a", "src/a.py", "aa:0")]
        self.path = write_findings(self.dir, self.findings, {"worktree": {"commit": "c" * 40}})
        self.output = self.dir / "check.txt"
        self.output.write_text(check_output(summary(self.findings)))

    def tearDown(self):
        self.tmp.cleanup()

    def record(self, host):
        return quiet(
            [
                "record",
                "--findings",
                str(self.path),
                "--check-output",
                str(self.output),
                "--repo-name",
                "acme/app",
                "--ref",
                "main",
                "--commit",
                "c" * 40,
                "--kind",
                "scheduled",
                "--db",
                str(self.db),
                "--embed",
                "--ollama-host",
                host,
            ]
        )

    def test_ollama_down_is_a_warning(self):
        code, out, err = self.record(closed_port())
        self.assertEqual(code, 0, err)
        self.assertIn("recorded scheduled run", out)
        self.assertIn("warning: no embeddings were made", err)

    def test_a_bad_host_records_nothing(self):
        code, _, err = self.record("http://198.51.100.7:11434")
        self.assertEqual(code, 2)
        self.assertFalse(self.db.exists())

    def test_with_ollama(self):
        ollama = FakeOllama()
        try:
            code, _, err = self.record(ollama.host)
        finally:
            ollama.close()
        self.assertEqual(code, 0, err)
        self.assertIn("embedded 1 findings of acme/app", err)


if __name__ == "__main__":
    unittest.main()


class ProvenanceTests(HistoryCase):
    """Suggestions come only from dashboard reviews and the baseline of scheduled runs, never from a pull
    request's baseline, and say where they come from."""

    def setUp(self):
        super().setUp()
        self.a = finding("community.python.eval", "src/x.py", "x0:0", message="Eval of user input allows injection")
        self.b = finding("community.python.eval", "src/y.py", "y0:0", message="Eval of user input allows injection!")
        self.c = finding("community.python.eval", "src/n.py", "n0:0", message="Eval of user input allows injection?")
        record(self.conn, self.dir, "acme/app", "a" * 40, 27, [self.a, self.b])

    def planted(self):
        """A pull-request run whose own baseline calls `a` a false positive, with a new finding `c`."""
        from shoalscan.baseline import Entry

        plant = Entry(self.a.tool, self.a.rule, self.a.path, self.a.fingerprint, "#66", "False positive: trust me")
        record(self.conn, self.dir, "acme/app", "f" * 40, 28, [self.a, self.b, self.c], kind="pr", baseline=[plant])

    def suggest(self):
        self.embed()
        return embeddings.suggest_repository(self.conn, "acme/app", "embeddinggemma", 0.6, "2026-10-01T00:00:00Z")

    def stored(self):
        return dict(
            self.conn.execute(
                "SELECT fk.path, nk.path FROM finding_suggestions s JOIN finding_keys fk ON fk.id = s.key_id "
                "JOIN finding_keys nk ON nk.id = s.neighbour_id"
            ).fetchall()
        )

    def dashboard(self, **kw):
        from shoalscan.dashboard.data import Data

        data = Data(history.open_read_only(self.db))
        self.addCleanup(data.conn.close)
        repo_id = data.repo_id("acme/app")
        run = data.resolve_run(repo_id, None)
        return {f["path"]: f for f in data.findings(repo_id, run, limit=500, **kw)["findings"]}

    def test_a_pull_request_baseline_never_suggests(self):
        self.planted()
        self.assertEqual(self.suggest(), 0)
        self.assertEqual(self.stored(), {})
        self.assertIsNone(self.dashboard()["src/y.py"]["suggestion"])
        self.assertEqual(self.dashboard(review="suggested"), {})
        like_b = embeddings.similar(self.conn, self.key_id("src/y.py"), "embeddinggemma", threshold=0.5, limit=5)
        self.assertIsNone({f["key"][2]: f for f in like_b}["src/x.py"]["decision"])
        # Even a suggestion stored before (by an older version) shows nothing for the planted reason.
        self.conn.execute(
            "INSERT INTO finding_suggestions VALUES (?, 'embeddinggemma', ?, 0.99, 'then')",
            (self.key_id("src/y.py"), self.key_id("src/x.py")),
        )
        self.conn.commit()
        self.assertIsNone(self.dashboard()["src/y.py"]["suggestion"])
        self.assertEqual(self.dashboard(review="suggested"), {})

    def test_the_scheduled_baseline_suggests_with_its_provenance(self):
        from shoalscan.baseline import Entry

        self.planted()
        accepted = Entry(self.a.tool, self.a.rule, self.a.path, self.a.fingerprint, "#7", "False positive: test data")
        record(self.conn, self.dir, "acme/app", "b" * 40, 29, [self.a, self.b], baseline=[accepted])
        run = self.conn.execute("SELECT id FROM runs WHERE commit_sha = ?", ("b" * 40,)).fetchone()[0]
        self.assertEqual(self.suggest(), 1)
        got = self.dashboard()["src/y.py"]["suggestion"]
        self.assertEqual(
            {k: got[k] for k in ("status", "source", "description", "issue", "run", "commit", "at", "by")},
            {
                "status": "false_positive",
                "source": "baseline",
                "description": "False positive: test data",
                "issue": "#7",
                "run": run,
                "commit": "b" * 40,
                "at": "2026-09-29T02:00:00Z",
                "by": None,
            },
        )

    def test_a_review_suggests_with_who_and_when(self):
        self.planted()
        history.set_reviews(
            self.db, "acme/app", [list(self.a.key())], "wont_fix", "Legacy module, retired soon.", "alice@example.com"
        )
        self.suggest()
        got = self.dashboard()["src/y.py"]["suggestion"]
        self.assertEqual((got["source"], got["status"], got["by"]), ("review", "wont_fix", "alice@example.com"))
        self.assertRegex(got["at"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertIsNone(got["run"])

    def test_suggestions_are_for_the_latest_trend_run(self):
        self.planted()  # the newest run is a pull request's, and only it has `c`
        history.set_reviews(
            self.db, "acme/app", [list(self.a.key())], "false_positive", "Input is a constant.", "alice@example.com"
        )
        self.suggest()
        self.assertEqual(self.stored(), {"src/y.py": "src/x.py"})  # b is in the scheduled run; c is not

    def test_the_decided_and_untriaged_sets_are_bounded(self):
        history.set_reviews(
            self.db, "acme/app", [list(self.a.key())], "false_positive", "Input is a constant.", "alice@example.com"
        )
        history.set_reviews(
            self.db, "acme/app", [list(self.b.key())], "accepted_risk", "Behind the admin login.", "bob@example.com"
        )
        self.conn.execute("UPDATE finding_reviews SET updated_at = '2026-01-01T00:00:00Z' WHERE path = 'src/x.py'")
        self.conn.commit()
        record(self.conn, self.dir, "acme/app", "c" * 40, 29, [self.a, self.b, self.c])
        with mock.patch.object(embeddings, "MAX_DECIDED", 1):
            self.suggest()
        self.assertEqual(self.stored(), {"src/n.py": "src/y.py"})  # only the most recently decided is compared
        with mock.patch.object(embeddings, "MAX_SUGGESTED", 0):
            self.assertEqual(self.suggest(), 0)

    def test_groups_version_follows_embeddings_and_reviews(self):
        from shoalscan.dashboard.data import Data

        def version():
            data = Data(history.open_read_only(self.db))
            try:
                repo_id = data.repo_id("acme/app")
                return data.groups_version(repo_id, data.resolve_run(repo_id, None))
            finally:
                data.conn.close()

        before = version()
        self.embed()
        embedded = version()
        self.assertNotEqual(before, embedded)
        self.assertEqual(version(), embedded)
        history.set_reviews(self.db, "acme/app", [list(self.a.key())], "open", "Looked at it, still open.", "me")
        self.assertNotEqual(version(), embedded)
