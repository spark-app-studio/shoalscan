"""The dashboard's routes, filters and view models (static/model.js), run under node."""

import json
import shutil
import subprocess
import unittest
from urllib.parse import parse_qs, urlsplit

import helpers  # noqa: F401

from shoalscan.dashboard import server

NODE = shutil.which("node")
MODEL = server.STATIC_DIR / "model.js"
HOSTILE = '"><img src=x onerror=alert(1)>&<script>'


def call(expression: str, **inputs) -> object:
    """Evaluate `expression` with the model as `M` and the JSON `inputs` as variables."""
    script = (
        f"const M = require({json.dumps(str(MODEL))});\n"
        + "".join(f"const {name} = {json.dumps(value)};\n" for name, value in inputs.items())
        + f"process.stdout.write(JSON.stringify((() => {{ {expression} }})()));\n"
    )
    proc = subprocess.run([NODE, "-e", script], capture_output=True, text=True, timeout=30)
    if proc.returncode != 0:
        raise AssertionError(proc.stderr[-2000:])
    return json.loads(proc.stdout)


def query(href: str) -> dict:
    parts = urlsplit(href[1:])  # drop the leading "#"
    return {k: v[0] for k, v in parse_qs(parts.query).items()}


def run(id_=7, **overrides) -> dict:
    base = {
        "id": id_, "kind": "scheduled", "ref": "main", "commit": "a" * 40, "scanned_at": "2026-10-10T02:00:00Z",
        "outcome": "blocked", "findings": 5, "by_severity": {"ERROR": 2, "WARNING": 0, "INFO": 3},
        "new": 3, "new_blocking": 2, "stale": 1, "baseline_size": 4, "baseline_additions": 0,
        "suppressions": {"total": 1, "invalid": 0, "suppressed_findings": 1},
        "unscanned": {"skipped": 2, "errored": 1, "changed_and_unscanned": 0, "changed_partially_parsed_warn_only": 1},
        "lists": {"new": True, "stale": True, "files": True, "suppressions": True},
        "status": {"outcome": "blocked", "label": "Blocked: 2 new blocking findings", "details": ["1 stale baseline entry"],
                   "explanation": "The check blocks ..."},
    }
    base.update(overrides)
    return base


@unittest.skipIf(NODE is None, "node is not installed, so the dashboard's JavaScript model cannot be run")
class RouteTests(unittest.TestCase):
    def test_parse_route_keeps_only_valid_whitelisted_parameters(self):
        cases = {
            "#/findings?severity=ERROR&run=12&new_blocking=1&age=2&x=1": ("findings", {"severity": "ERROR", "run": "12", "new_blocking": "1", "age": "2"}),
            "#/findings?severity=CRITICAL&run=-1&new=yes&age=9&offset=abc": ("findings", {}),
            "#/findings?component=" + "%22%3E%3Cscript%3E": ("findings", {"component": '"><script>'}),
            "#/findings?component=a%0Ab": ("findings", {}),
            "#/runs?run=3&repo=acme%2Fapp": ("runs", {"run": "3", "repo": "acme/app"}),
            "#/runs?repo=..%2F%3Cx%3E": ("runs", {}),
            "#/files?run=3&kind=partial_warn_only": ("files", {"run": "3", "kind": "partial_warn_only"}),
            "#/files?run=3&kind=../../etc": ("files", {"run": "3"}),
            "#/changes?week=2026-09-14&change=fixed": ("changes", {"week": "2026-09-14", "change": "fixed"}),
            "#/changes?week=2026-09-14&change=new&offset=200": ("changes", {"week": "2026-09-14", "change": "new", "offset": "200"}),
            "#/changes?week=2026-09-14": ("overview", {}),
            "#/rule?run=3": ("findings", {}),
            "#/javascript:alert(1)": ("overview", {}),
            "": ("overview", {}),
            "#/about": ("about", {}),
            "#/config?edit=x": ("config", {}),
        }
        results = call("return HASHES.map(h => M.parseRoute(h));", HASHES=list(cases))
        for (hash_, (view, params)), got in zip(cases.items(), results):
            with self.subTest(hash=hash_):
                self.assertEqual(got, {"view": view, "params": params})

    def test_href_builds_only_fixed_routes_and_round_trips(self):
        links = call(
            "M.setRepo('acme/app'); return LINKS.map(([v, p]) => M.href(v, p));",
            LINKS=[["findings", {"run": 5, "severity": "WARNING", "component": HOSTILE}], ["stale", {"run": 5}],
                   ["changes", {"week": "2026-09-14", "change": "new"}], ["overview", {}]],
        )
        for href in links:
            self.assertTrue(href.startswith("#/"))
            self.assertNotIn("<", href)
            self.assertNotIn('"', href)
        self.assertEqual(query(links[0]), {"repo": "acme/app", "run": "5", "severity": "WARNING", "component": HOSTILE})
        back = call("return LINKS.map(h => M.parseRoute(h));", LINKS=links)
        self.assertEqual(back[0]["params"]["component"], HOSTILE)
        self.assertEqual(back[2], {"view": "changes", "params": {"repo": "acme/app", "week": "2026-09-14", "change": "new"}})
        refused = call(
            "return BAD.map(([v, p]) => { try { M.href(v, p); return 'built'; } catch (e) { return 'refused'; } });",
            BAD=[["javascript:alert(1)", {}], ["findings", {"severity": "BAD"}], ["findings", {"onclick": "x"}],
                 ["findings", {"run": "1 OR 1"}], ["files", {"kind": "../x"}], ["findings", {"component": "a\nb"}]],
        )
        self.assertEqual(refused, ["refused"] * 6)


@unittest.skipIf(NODE is None, "node is not installed, so the dashboard's JavaScript model cannot be run")
class ViewModelTests(unittest.TestCase):
    def test_tiles_link_where_their_numbers_come_from(self):
        overview = {"latest_run": run(9), "latest_trend_run": run(7), "time_to_fix": {"fixed": 2, "mean_days": 3.5, "median_days": 3.5}}
        tiles = {t["label"]: t for t in call("M.setRepo('acme/app'); return M.overviewTiles(O);", O=overview)}
        expect = {
            "Open ERROR": ("findings", {"run": "7", "severity": "ERROR"}),
            "Open INFO": ("findings", {"run": "7", "severity": "INFO"}),
            "New": ("findings", {"run": "9", "new": "1"}),
            "New blocking": ("findings", {"run": "9", "new_blocking": "1"}),
            "Stale baseline entries": ("stale", {"run": "9"}),
            "Suppressions": ("suppressions", {"run": "9"}),
            "Not fully scanned": ("files", {"run": "9"}),
            "Partially parsed": ("files", {"run": "9", "kind": "partial_warn_only"}),
        }
        for label, (view, params) in expect.items():
            with self.subTest(tile=label):
                href = tiles[label]["href"]
                self.assertTrue(href.startswith(f"#/{view}?"), href)
                self.assertEqual(query(href), {"repo": "acme/app", **params})
                self.assertTrue(tiles[label]["aria"])
        # No sensible target: no link. A zero count: no link.
        self.assertIsNone(tiles["Baseline"]["href"])
        self.assertIsNone(tiles["Mean time to fix"]["href"])
        self.assertIsNone(tiles["Open WARNING"]["href"])

    def test_tiles_without_recorded_lists_are_not_links(self):
        bare = run(9, lists={"new": False, "stale": False, "files": False, "suppressions": False})
        tiles = {t["label"]: t for t in call("return M.overviewTiles(O);", O={"latest_run": bare, "latest_trend_run": bare, "time_to_fix": {}})}
        for label in ("New", "New blocking", "Stale baseline entries", "Suppressions", "Not fully scanned"):
            self.assertIsNone(tiles[label]["href"], label)
        # After a scan error, per-run tiles use the latest run that has results.
        error = run(10, outcome="scan_error", status={"outcome": "scan_error", "label": "Scan error", "details": [], "explanation": None})
        tiles = {t["label"]: t for t in call("return M.overviewTiles(O);", O={"latest_run": error, "latest_trend_run": run(7), "time_to_fix": {}})}
        self.assertEqual(query(tiles["New"]["href"])["run"], "7")

    def test_status_links_blocked_runs_to_their_new_blocking_findings(self):
        blocked = call("M.setRepo(null); return M.statusView(R);", R=run(9))
        self.assertEqual(blocked["label"], "Blocked: 2 new blocking findings")
        self.assertEqual(blocked["link"]["href"], "#/findings?run=9&new_blocking=1")
        passed = call("return M.statusView(R);", R=run(9, new_blocking=0, status={"outcome": "passed", "label": "Passed", "details": [], "explanation": None}))
        self.assertIsNone(passed["link"])

    def test_chart_points_and_bars_link_to_their_filters(self):
        point = {"run": 12, "scanned_at": "2026-10-10T02:00:00Z", "open": {"ERROR": 114, "WARNING": 0, "INFO": 3},
                 "suppressions": 2, "unscanned_skipped": 0, "unscanned_errored": 0, "lists": {"files": True, "suppressions": True}}
        got = call(
            "M.setRepo(null); return [M.severityPoint(P, 'ERROR'), M.severityLegend('INFO', 12), M.weekBar(W, 'new'), M.weekBar(W, 'fixed'),"
            " M.ageBar({label: '8-30 days', count: 4}, 1, 12), M.ageBar({label: 'x', count: 0}, 2, 12),"
            " M.listPoint(P, 'suppressions', 2, 'Inline suppressions'), M.listPoint(P, 'files', 0, 'Files')];",
            P=point, W={"week": "2026-09-14", "new": 3, "fixed": 0},
        )
        self.assertEqual(got[0], {"href": "#/findings?run=12&severity=ERROR", "aria": "ERROR findings in run of 2026-10-10: 114"})
        self.assertEqual(got[1]["href"], "#/findings?run=12&severity=INFO")
        self.assertEqual(got[2]["href"], "#/changes?week=2026-09-14&change=new")
        self.assertIsNone(got[3])
        self.assertEqual(got[4]["href"], "#/findings?run=12&age=1")
        self.assertIsNone(got[5])
        self.assertEqual(got[6]["href"], "#/suppressions?run=12")
        self.assertIsNone(got[7])

    def test_heatmap_cells_link_to_component_and_severity(self):
        rows = [
            {"component": HOSTILE, "cells": [3, 0, 7], "levels": [2, 0, 5], "new": 1, "new_blocking": 1, "score": 37},
            *({"component": f"c{n:02d}", "cells": [0, 1, 0], "levels": [0, 1, 0], "new": 0, "new_blocking": 0, "score": 3} for n in range(20)),
        ]
        by_component = {"run": 7, "severities": ["ERROR", "WARNING", "INFO"], "max_cell": 7, "rows": rows}
        model = call("M.setRepo('acme/app'); return M.heatmap(B, false);", B=by_component)
        self.assertEqual(len(model["rows"]), 15)
        self.assertEqual(model["hidden"], 6)
        self.assertEqual(len(call("return M.heatmap(B, true).rows;", B=by_component)), 21)
        first = model["rows"][0]
        self.assertEqual(first["component"], HOSTILE)  # shown as text, never parsed
        self.assertEqual(query(first["href"]), {"repo": "acme/app", "run": "7", "component": HOSTILE})
        for row in model["rows"]:
            for severity, cell in zip(by_component["severities"], row["cells"]):
                with self.subTest(component=row["component"], severity=severity):
                    if cell["value"] == 0:
                        self.assertIsNone(cell["href"])
                        self.assertIsNone(cell["aria"])
                    else:
                        self.assertEqual(query(cell["href"]), {"repo": "acme/app", "run": "7", "component": row["component"], "severity": severity})
                        self.assertIn(str(cell["value"]), cell["title"])
                    self.assertNotIn("<", cell["href"] or "")
        self.assertEqual(first["cells"][2]["title"], HOSTILE + ": 7 INFO findings")
        self.assertEqual(first["bar"], 100)


@unittest.skipIf(NODE is None, "node is not installed, so the dashboard's JavaScript model cannot be run")
class BlockingViewTests(unittest.TestCase):
    def test_blocking_filter_routes(self):
        got = call("return H.map(h => M.parseRoute(h).params);", H=[
            "#/findings?run=4&blocking=1&sort=priority",
            "#/findings?blocking=yes&sort=path&baselined=1",
        ])
        self.assertEqual(got[0], {"run": "4", "blocking": "1", "sort": "priority"})
        self.assertEqual(got[1], {"baselined": "1"})

    def test_panel_links_split_new_and_baselined(self):
        overview = {"blocking": {"run": 7, "known": True, "total": 5, "new": 2, "baselined": 3, "top": [
            {"severity": "ERROR", "rule": "community.python.lang.security.eval-detected", "path": "src/a.py", "line": 4,
             "component": "api", "new_blocking": True},
            {"severity": "WARNING", "rule": "shoalscan.plain-http-url\tx", "path": "web/b.js", "line": 9, "component": "web", "new_blocking": False},
        ]}}
        panel = call("M.setRepo('acme/app'); return M.blockingPanel(O);", O={**overview, "blocking": {**overview["blocking"], "top": overview["blocking"]["top"][:1]}})
        self.assertEqual(query(panel["total"]["href"]), {"repo": "acme/app", "run": "7", "blocking": "1"})
        self.assertEqual(query(panel["new"]["href"]), {"repo": "acme/app", "run": "7", "blocking": "1", "new_blocking": "1"})
        self.assertEqual(query(panel["baselined"]["href"]), {"repo": "acme/app", "run": "7", "blocking": "1", "baselined": "1"})
        self.assertEqual(query(panel["seeAll"]["href"]), {"repo": "acme/app", "run": "7", "blocking": "1", "sort": "priority"})
        self.assertEqual(panel["seeAll"]["text"], "See all 5 blocking findings")
        row = panel["top"][0]
        self.assertEqual((row["ruleShort"], row["location"], row["isNew"]), ("eval-detected", "src/a.py:4", True))
        self.assertEqual(query(row["href"]), {"repo": "acme/app", "run": "7", "rule": "community.python.lang.security.eval-detected"})
        self.assertTrue(row["aria"].startswith("New ERROR eval-detected"))
        # A zero part is not a link; an unknown class is not a panel.
        zero = call("return M.blockingPanel(O);", O={"blocking": {"run": 7, "known": True, "total": 2, "new": 0, "baselined": 2, "top": []}})
        self.assertIsNone(zero["new"]["href"])
        self.assertEqual(call("return M.blockingPanel(O);", O={"blocking": {"run": 7, "known": False}}), {"known": False})

    def test_sparkline_points_link_to_the_runs_blocking_findings(self):
        got = call("M.setRepo(null); return [M.blockingPoint(P), M.blockingPoint(Q)];",
                   P={"run": 3, "scanned_at": "2026-10-01T02:00:00Z", "blocking": 41}, Q={"run": 2, "scanned_at": "2026-09-01T02:00:00Z", "blocking": None})
        self.assertEqual(got[0], {"href": "#/findings?run=3&blocking=1", "aria": "Blocking findings in run of 2026-10-01: 41"})
        self.assertIsNone(got[1])


@unittest.skipIf(NODE is None, "node is not installed, so the dashboard's JavaScript model cannot be run")
class ReviewViewTests(unittest.TestCase):
    def test_review_routes(self):
        got = call("return H.map(h => M.parseRoute(h));", H=[
            "#/findings?review=untriaged&blocking=1",
            "#/findings?review=verified",
            "#/finding?run=4&tool=opengrep&rule=r.a&path=src%2Fa.py&fingerprint=aa%3A0",
        ])
        self.assertEqual(got[0]["params"], {"review": "untriaged", "blocking": "1"})
        self.assertEqual(got[1]["params"], {})
        self.assertEqual(got[2], {"view": "finding", "params": {"run": "4", "tool": "opengrep", "rule": "r.a", "path": "src/a.py", "fingerprint": "aa:0"}})

    def test_badges(self):
        got = call("return R.map(r => M.reviewBadge(r));", R=[
            {"status": "open", "source": "none"}, {"status": "open", "source": "review"},
            {"status": "false_positive", "source": "baseline"}, {"status": "regression", "source": "review"},
            {"status": "baselined", "source": "baseline"},
        ])
        self.assertEqual([b["label"] for b in got], ["Untriaged", "Open", "False positive (from baseline)", "Regression", "Baselined (from baseline)"])
        self.assertEqual(got[0]["cls"], "review-untriaged")

    def test_review_tiles_and_finding_links(self):
        tiles = {t["label"]: t for t in call("M.setRepo('acme/app'); return M.overviewTiles(O);",
                 O={"time_to_fix": {}, "reviews": {"run": 7, "untriaged_blocking": 3, "regressions": 2}})}
        self.assertEqual(query(tiles["Untriaged blocking"]["href"]),
                         {"repo": "acme/app", "run": "7", "blocking": "1", "review": "untriaged", "sort": "priority"})
        self.assertEqual(query(tiles["Regressions"]["href"]), {"repo": "acme/app", "run": "7", "review": "regression"})
        none = {t["label"] for t in call("return M.overviewTiles(O);", O={"time_to_fix": {}, "reviews": {"run": 7, "untriaged_blocking": 0, "regressions": 0}})}
        self.assertNotIn("Regressions", none)
        link = call("M.setRepo(null); return M.findingHref(7, K);", K=["opengrep", "r.a", HOSTILE + ".py", "aa:0"])
        self.assertTrue(link.startswith("#/finding?"))
        self.assertEqual(query(link)["path"], HOSTILE + ".py")
        self.assertNotIn("<", link)
        self.assertIsNone(call("return M.findingHref(7, K);", K=["opengrep", "r\na", "a.py", "aa:0"]))


@unittest.skipIf(NODE is None, "node is not installed, so the dashboard's JavaScript model cannot be run")
class BadValueTests(unittest.TestCase):
    def test_a_control_character_gives_text_not_an_error(self):
        by_component = {"run": 7, "severities": ["ERROR", "WARNING", "INFO"], "max_cell": 2, "rows": [
            {"component": "bad\tname", "cells": [2, 0, 0], "levels": [5, 0, 0], "new": 0, "new_blocking": 0, "score": 20},
            {"component": "good", "cells": [1, 0, 0], "levels": [3, 0, 0], "new": 0, "new_blocking": 0, "score": 10},
        ]}
        heat = call("return M.heatmap(B, false);", B=by_component)
        self.assertIsNone(heat["rows"][0]["href"])
        self.assertIsNone(heat["rows"][0]["cells"][0]["href"])
        self.assertEqual(heat["rows"][0]["cells"][0]["value"], 2)
        self.assertTrue(heat["rows"][1]["href"])
        panel = call("return M.blockingPanel(O);", O={"blocking": {"run": 7, "known": True, "total": 1, "new": 1, "baselined": 0, "top": [
            {"severity": "ERROR", "rule": "r\nx", "path": "a.py", "line": 1, "component": "api", "new_blocking": True}]}})
        self.assertIsNone(panel["top"][0]["href"])


class StaticPageTests(unittest.TestCase):
    def test_model_is_served_and_loaded_before_the_app(self):
        self.assertIn("/static/model.js", server.ROUTES)
        page = (server.STATIC_DIR / "index.html").read_text(encoding="utf-8")
        self.assertLess(page.index("/static/model.js"), page.index("/static/app.js"))

    def test_links_only_come_from_the_model(self):
        text = (server.STATIC_DIR / "app.js").read_text(encoding="utf-8")
        code = "\n".join(line for line in text.splitlines() if not line.strip().startswith("//"))
        # Every href the app sets goes through M.href (or is an external https
        # link): no route is ever written as a string literal in the app.
        self.assertNotRegex(code, r"[\"']#/")
        self.assertIn("M.href(", code)


if __name__ == "__main__":
    unittest.main()
