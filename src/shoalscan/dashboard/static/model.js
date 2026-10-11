"use strict";
// Shoalscan dashboard: routes, filters and view models. No DOM here, so the
// rules can be tested on their own (tests/test_dashboard_model.py runs this
// file under node).
//
// Every link the dashboard draws is built by href() below: a fixed "#/view"
// route plus query parameters that are whitelisted per view and validated.
// Anything else is refused, so no data from the server can become a URL of
// its own.

(function (root) {
  var SEVERITIES = ["ERROR", "WARNING", "INFO"];
  var FILE_KINDS = ["skipped", "error", "changed_unscanned", "partial_warning", "partial_warn_only", "excluded_changed"];
  var AGE_BUCKETS = 5;
  var REVIEW_FILTERS = ["untriaged", "suggested", "open", "false_positive", "accepted_risk", "wont_fix", "fixed", "verified_fixed", "regression", "baselined"];
  var USER_STATUSES = ["open", "false_positive", "accepted_risk", "wont_fix", "fixed"];
  var REVIEW_LABELS = {
    untriaged: "Untriaged", open: "Open", false_positive: "False positive", accepted_risk: "Accepted risk", wont_fix: "Won't fix",
    fixed: "Fixed (awaiting verification)", verified_fixed: "Verified fixed", regression: "Regression", baselined: "Baselined",
    suggested: "Untriaged, with a suggestion"
  };
  var HEAT_ROWS_SHOWN = 15;

  function oneOf(list) { return function (v) { return list.indexOf(v) >= 0; }; }
  function id(v) { return /^[0-9]{1,15}$/.test(v); }
  function flag(v) { return v === "1"; }
  function text(max) {
    return function (v) { return v.length > 0 && v.length <= max && !/[\u0000-\u001f\u007f]/.test(v); };
  }
  function age(v) { return /^[0-9]$/.test(v) && Number(v) < AGE_BUCKETS; }
  function week(v) { return /^[0-9]{4}-[0-9]{2}-[0-9]{2}$/.test(v); }
  // A similarity from 0.5 to 1, as the server takes it.
  function threshold(v) { return /^(0\.[0-9]{1,4}|1(\.0{1,4})?)$/.test(v) && Number(v) >= 0.5; }
  // A finding key, ["tool","rule","path","fingerprint"], as JSON.
  function findingKey(v) {
    if (v.length > 5000) return false;
    var k;
    try { k = JSON.parse(v); } catch (e) { return false; }
    return Array.isArray(k) && k.length === 4 && k.every(function (p) { return typeof p === "string" && p.length > 0 && p.length <= 1024; });
  }

  // view -> {parameter: validator}, in the order links write them.
  var VIEWS = {
    overview: {},
    findings: {
      run: id, severity: oneOf(SEVERITIES), rule: text(1024), component: text(200), path: text(200),
      "new": flag, new_blocking: flag, age: age, blocking: flag, baselined: flag, sort: oneOf(["priority"]),
      review: oneOf(REVIEW_FILTERS), group: findingKey, threshold: threshold, offset: id
    },
    groups: { run: id, threshold: threshold },
    finding: { run: id, tool: text(64), rule: text(1024), path: text(1024), fingerprint: text(128) },
    rule: { run: id, rule: text(1024) },
    runs: { run: id, offset: id },
    stale: { run: id },
    files: { run: id, kind: oneOf(FILE_KINDS) },
    suppressions: { run: id },
    config: {},
    users: {},
    changes: { week: week, change: oneOf(["new", "fixed"]), offset: id },
    about: {}
  };

  function has(obj, key) { return Object.prototype.hasOwnProperty.call(obj, key); }

  // Every view also takes the repository, so a link names the run it means.
  var REPO = /^[A-Za-z0-9][A-Za-z0-9._\/@:+-]{0,199}$/;
  Object.keys(VIEWS).forEach(function (view) {
    var spec = { repo: function (v) { return REPO.test(v); } };
    Object.keys(VIEWS[view]).forEach(function (key) { spec[key] = VIEWS[view][key]; });
    VIEWS[view] = spec;
  });
  var context = { repo: null };

  // The repository links are built for, unless a link names its own.
  function setRepo(name) { context.repo = name && REPO.test(name) ? name : null; }

  // "#/findings?severity=ERROR&x=1" -> {view: "findings", params: {severity: "ERROR"}}.
  // Unknown views fall back to the overview; unknown or invalid parameters are dropped.
  function parseRoute(hash) {
    var h = typeof hash === "string" ? hash : "";
    if (h.charAt(0) === "#") h = h.slice(1);
    if (h.charAt(0) === "/") h = h.slice(1);
    var q = h.indexOf("?");
    var view = q < 0 ? h : h.slice(0, q);
    if (!has(VIEWS, view)) view = "overview";
    var search = new URLSearchParams(q < 0 ? "" : h.slice(q + 1));
    var params = {};
    Object.keys(VIEWS[view]).forEach(function (key) {
      var value = search.get(key);
      if (value !== null && VIEWS[view][key](value)) params[key] = value;
    });
    if (view === "rule" && !params.rule) return { view: "findings", params: {} };
    if (view === "changes" && (!params.week || !params.change)) return { view: "overview", params: {} };
    return { view: view, params: params };
  }

  // The one way to build a link. Throws on an unknown view or an invalid value.
  function href(view, params) {
    if (!has(VIEWS, view)) throw new Error("unknown view: " + view);
    var spec = VIEWS[view];
    var search = new URLSearchParams();
    params = Object.assign({ repo: context.repo }, params || {});
    Object.keys(params).forEach(function (key) {
      if (!has(spec, key)) throw new Error("unknown parameter for " + view + ": " + key);
    });
    Object.keys(spec).forEach(function (key) {
      if (!params || params[key] === undefined || params[key] === null || params[key] === "") return;
      var value = String(params[key]);
      if (!spec[key](value)) throw new Error("invalid " + key + " for " + view);
      search.set(key, value);
    });
    var qs = search.toString();
    return "#/" + view + (qs ? "?" + qs : "");
  }

  // For links built from recorded data: a value href() refuses (say, a
  // control character in an old record) gives no link instead of an error.
  function safeHref(view, params) {
    try { return href(view, params); } catch (e) { return null; }
  }

  function plural(n, one, many) { return n + " " + (n === 1 ? one : many); }
  function day(ts) { return ts ? ts.slice(0, 10) : "-"; }

  // ------------------------------------------------------------ status

  function statusView(run) {
    if (!run) return null;
    var s = run.status || { outcome: "passed", label: "Passed", details: [], explanation: null };
    var view = {
      outcome: s.outcome,
      label: s.label,
      icon: s.outcome === "passed" ? "✓" : (s.outcome === "scan_error" ? "!" : "✕"),
      details: s.details || [],
      explanation: s.explanation,
      link: null
    };
    if (s.outcome === "blocked" && run.new_blocking > 0 && run.lists && run.lists["new"]) {
      view.link = { href: href("findings", { run: run.id, new_blocking: "1" }), text: "Show the new blocking findings" };
    }
    return view;
  }

  // ------------------------------------------------------------ overview tiles

  function tile(label, value, sub, link, aria) {
    return { label: label, value: String(value), sub: sub || "", href: link || null, aria: link ? aria : null };
  }

  function overviewTiles(o) {
    var tiles = [];
    var trend = o.latest_trend_run;
    var latest = o.latest_run;
    // Per-run counts come from the latest run that has results.
    var run = latest && latest.outcome !== "scan_error" ? latest : trend;
    if (trend) {
      SEVERITIES.forEach(function (sev) {
        var n = trend.by_severity[sev];
        tiles.push(tile("Open " + sev, n, "latest trend run, " + day(trend.scanned_at),
          n > 0 ? href("findings", { run: trend.id, severity: sev }) : null,
          "Show the " + n + " open " + sev + " findings of the run of " + day(trend.scanned_at)));
      });
    }
    if (run) {
      var lists = run.lists || {};
      tiles.push(tile("New", run["new"], "not in the baseline",
        run["new"] > 0 && lists["new"] ? href("findings", { run: run.id, "new": "1" }) : null,
        "Show the " + run["new"] + " new findings of run " + run.id));
      tiles.push(tile("New blocking", run.new_blocking, "fail the check",
        run.new_blocking > 0 && lists["new"] ? href("findings", { run: run.id, new_blocking: "1" }) : null,
        "Show the " + run.new_blocking + " new blocking findings of run " + run.id));
      tiles.push(tile("Stale baseline entries", run.stale, "no longer reproduce",
        run.stale > 0 && lists.stale ? href("stale", { run: run.id }) : null,
        "Show the " + run.stale + " stale baseline entries of run " + run.id));
      tiles.push(tile("Baseline", run.baseline_size, "accepted findings", null, null));
      tiles.push(tile("Suppressions", run.suppressions.total,
        run.suppressions.invalid ? run.suppressions.invalid + " without a rule and an issue" : "inline, with a rule and an issue",
        run.suppressions.total > 0 && lists.suppressions ? href("suppressions", { run: run.id }) : null,
        "Show the " + run.suppressions.total + " inline suppressions of run " + run.id));
      var unscanned = run.unscanned.skipped + run.unscanned.errored;
      tiles.push(tile("Not fully scanned", unscanned, run.unscanned.skipped + " skipped, " + run.unscanned.errored + " with errors",
        unscanned > 0 && lists.files ? href("files", { run: run.id }) : null,
        "Show the " + unscanned + " files not fully scanned in run " + run.id));
      var warnOnly = run.unscanned.changed_partially_parsed_warn_only || 0;
      if (warnOnly > 0) {
        tiles.push(tile("Partially parsed", warnOnly, "changed files, warn-only by policy",
          lists.files ? href("files", { run: run.id, kind: "partial_warn_only" }) : null,
          "Show the " + warnOnly + " partially parsed changed files of run " + run.id));
      }
    }
    tiles = tiles.concat(reviewTiles(o));
    var ttf = o.time_to_fix || {};
    tiles.push(tile("Mean time to fix", ttf.mean_days === null || ttf.mean_days === undefined ? "-" : ttf.mean_days + " days",
      ttf.fixed ? "median " + ttf.median_days + " days over " + plural(ttf.fixed, "fixed finding", "fixed findings") : "nothing fixed yet",
      null, null));
    return tiles;
  }

  // ------------------------------------------------------------ reviews

  function reviewBadge(review) {
    var r = review || { status: "open", source: "none" };
    var untriaged = r.status === "open" && r.source === "none";
    return {
      cls: "review-" + (untriaged ? "untriaged" : r.status),
      label: (untriaged ? "Untriaged" : REVIEW_LABELS[r.status] || r.status) + (r.source === "baseline" ? " (from baseline)" : "")
    };
  }

  function findingHref(run, key) {
    return safeHref("finding", { run: run, tool: key[0], rule: key[1], path: key[2], fingerprint: key[3] });
  }

  function reviewTiles(o) {
    var r = o.reviews || {};
    var tiles = [];
    if (!r.run) return tiles;
    tiles.push(tile("Untriaged blocking", r.untriaged_blocking, "no review and no baseline reason",
      r.untriaged_blocking > 0 ? href("findings", { run: r.run, blocking: "1", review: "untriaged", sort: "priority" }) : null,
      "Show the " + r.untriaged_blocking + " untriaged blocking findings"));
    if (r.regressions > 0) {
      tiles.push(tile("Regressions", r.regressions, "fixed, then found again",
        href("findings", { run: r.run, review: "regression" }), "Show the " + r.regressions + " regressions"));
    }
    return tiles;
  }

  // ------------------------------------------------------------ chart links

  function severityPoint(point, sev) {
    var n = point.open[sev];
    return {
      href: href("findings", { run: point.run, severity: sev }),
      aria: sev + " findings in run of " + day(point.scanned_at) + ": " + n
    };
  }

  function severityLegend(sev, trendRunId) {
    return {
      href: href("findings", { run: trendRunId, severity: sev }),
      aria: "Show the open " + sev + " findings"
    };
  }

  function weekBar(w, change) {
    var n = w[change];
    if (!n) return null;
    return {
      href: href("changes", { week: w.week, change: change }),
      aria: (change === "new" ? "New" : "Fixed") + " findings in the week of " + w.week + ": " + n
    };
  }

  function ageBar(bucket, index, trendRunId) {
    if (!bucket.count || !trendRunId) return null;
    return { href: href("findings", { run: trendRunId, age: String(index) }), aria: "Open findings aged " + bucket.label + ": " + bucket.count };
  }

  function listPoint(point, view, value, what) {
    var known = point.lists && point.lists[view === "files" ? "files" : "suppressions"];
    if (!value || !known) return null;
    return { href: href(view, { run: point.run }), aria: what + " in run of " + day(point.scanned_at) + ": " + value };
  }

  // ------------------------------------------------------------ blocking findings

  function shortRule(rule) {
    var parts = String(rule).split(".");
    return parts[parts.length - 1] || rule;
  }

  // The "Blocking findings" panel: the count split into new (fails pull
  // requests) and baselined (the backlog), and the top findings to fix first.
  function blockingPanel(o) {
    var b = o.blocking || {};
    if (!b.known || !b.run) return { known: false };
    var run = b.run;
    function part(value, extra, aria) {
      return { value: value, href: value > 0 ? href("findings", Object.assign({ run: run, blocking: "1" }, extra)) : null, aria: aria };
    }
    return {
      known: true,
      run: run,
      total: part(b.total, {}, "Show all " + b.total + " blocking findings, in fix order"),
      "new": part(b["new"], { new_blocking: "1" }, "Show the " + b["new"] + " new blocking findings, which fail pull requests"),
      baselined: part(b.baselined, { baselined: "1" }, "Show the " + b.baselined + " baselined blocking findings, the backlog to burn down"),
      seeAll: b.total > 0 ? { href: href("findings", { run: run, blocking: "1", sort: "priority" }), text: "See all " + b.total + " blocking findings" } : null,
      top: (b.top || []).map(function (f) {
        return {
          severity: f.severity,
          rule: f.rule,
          ruleShort: shortRule(f.rule),
          location: f.path + ":" + f.line,
          component: f.component,
          isNew: !!f.new_blocking,
          href: safeHref("rule", { run: run, rule: f.rule }),
          aria: (f.new_blocking ? "New " : "") + f.severity + " " + shortRule(f.rule) + " in " + f.path + " line " + f.line + ": show the rule and where it was found"
        };
      })
    };
  }

  function blockingPoint(point) {
    if (point.blocking === null || point.blocking === undefined) return null;
    return { href: href("findings", { run: point.run, blocking: "1" }), aria: "Blocking findings in run of " + day(point.scanned_at) + ": " + point.blocking };
  }

  // ------------------------------------------------------------ heatmap

  function heatmap(byComponent, showAll) {
    var rows = byComponent.rows || [];
    var shown = showAll ? rows : rows.slice(0, HEAT_ROWS_SHOWN);
    var maxScore = rows.reduce(function (m, r) { return Math.max(m, r.score); }, 0);
    var run = byComponent.run;
    return {
      severities: byComponent.severities,
      hidden: rows.length - shown.length,
      rows: shown.map(function (r) {
        return {
          component: r.component,
          href: run ? safeHref("findings", { run: run, component: r.component }) : null,
          aria: "Show all open findings in " + r.component,
          score: r.score,
          bar: maxScore ? Math.max(2, Math.round((100 * r.score) / maxScore)) : 0,
          newBlocking: r.new_blocking,
          cells: r.cells.map(function (value, i) {
            var sev = byComponent.severities[i];
            var title = r.component + ": " + plural(value, sev + " finding", sev + " findings");
            var link = value > 0 && run ? safeHref("findings", { run: run, component: r.component, severity: sev }) : null;
            return { value: value, level: r.levels[i], title: title, href: link, aria: link ? "Show " + title : null };
          })
        };
      })
    };
  }

  // ------------------------------------------------------------ similar findings

  var THRESHOLDS = ["0.8", "0.85", "0.9", "0.95"];

  // The Findings view of one group: its leader's key, at the similarity it was grouped at.
  function groupHref(run, key, similarity) {
    return safeHref("findings", { run: run, group: JSON.stringify(key), threshold: similarity, review: "untriaged" });
  }

  // The Overview's Similarity panel: what the stored embeddings cover, and what to run next.
  function similarityView(e, repo) {
    // One command embeds what is new or changed, then works out the suggestions again.
    var embed = "shoalscan triage embed --repo-name " + (repo || "<owner/project>") + " --db <the history database>";
    if (!e || e.embedded === 0) {
      return {
        state: "none",
        headline: "Not set up",
        lines: ["No finding of the latest trend run has an embedding yet, so there are no suggestions or groups.",
                "With Ollama and the " + (e ? e.model : "embeddinggemma") + " model on this machine, run:"],
        commands: [embed],
        links: []
      };
    }
    var lines = [plural(e.embedded, "finding", "findings") + " of " + e.findings + " in run " + e.run +
                 " have an embedding (" + e.model + ", last made " + day(e.embedded_at) + ")."];
    var todo = e.missing + e.stale;
    if (todo > 0) {
      lines.push(plural(todo, "finding needs", "findings need") + " a new embedding (" + e.missing + " without one, " +
                 e.stale + " whose text changed). Suggestions and groups leave them out until then.");
    }
    lines.push(plural(e.suggested, "untriaged finding has", "untriaged findings have") + " a suggestion, of " + e.untriaged +
               " untriaged" + (e.suggestions_at ? " (worked out " + day(e.suggestions_at) + ")." : "."));
    var links = [];
    if (e.suggested > 0) {
      links.push({ href: href("findings", { run: e.run, review: "suggested" }), text: "Show the findings with a suggestion" });
    }
    if (e.untriaged > 1) links.push({ href: href("groups", { run: e.run }), text: "Group the untriaged findings by similarity" });
    return {
      state: todo > 0 ? "partial" : "ok",
      headline: todo > 0 ? "Partly up to date" : "Up to date",
      lines: lines,
      commands: todo > 0 ? [embed] : [],
      links: links
    };
  }

  // One group on the Groups view.
  function groupView(g, run, similarity) {
    var top = g.rules[0];
    return {
      title: plural(g.size, "similar finding", "similar findings"),
      rules: g.rules.map(function (r) { return shortRule(r.rule) + (g.rules.length > 1 ? " (" + r.count + ")" : ""); }),
      severities: SEVERITIES.filter(function (s) { return g.severities[s]; }).map(function (s) { return g.severities[s] + " " + s; }),
      suggested: g.suggested.map(function (s) { return plural(s.count, "suggests", "suggest") + " " + REVIEW_LABELS[s.status]; }),
      more: g.size - g.members.length,
      href: groupHref(run, g.key, similarity),
      aria: "Review the " + g.size + " findings like " + (top ? top.rule : "") + " in " + g.key[2] + " together"
    };
  }

  var Model = {
    SEVERITIES: SEVERITIES,
    FILE_KINDS: FILE_KINDS,
    HEAT_ROWS_SHOWN: HEAT_ROWS_SHOWN,
    VIEWS: Object.keys(VIEWS),
    parseRoute: parseRoute,
    href: href,
    safeHref: safeHref,
    setRepo: setRepo,
    statusView: statusView,
    overviewTiles: overviewTiles,
    severityPoint: severityPoint,
    severityLegend: severityLegend,
    weekBar: weekBar,
    ageBar: ageBar,
    listPoint: listPoint,
    blockingPanel: blockingPanel,
    reviewBadge: reviewBadge,
    findingHref: findingHref,
    REVIEW_FILTERS: REVIEW_FILTERS,
    REVIEW_LABELS: REVIEW_LABELS,
    USER_STATUSES: USER_STATUSES,
    blockingPoint: blockingPoint,
    shortRule: shortRule,
    heatmap: heatmap,
    THRESHOLDS: THRESHOLDS,
    groupHref: groupHref,
    similarityView: similarityView,
    groupView: groupView
  };
  if (typeof module !== "undefined" && module.exports) module.exports = Model;
  else root.ShoalscanModel = Model;
})(this);
