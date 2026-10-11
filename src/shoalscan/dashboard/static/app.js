"use strict";
// Shoalscan dashboard. Plain JavaScript, no libraries.
//
// Safety rules for this file:
// - Data from the server (finding messages, paths, rule ids, component
//   names, refs) is untrusted. It reaches the page only through textContent,
//   createTextNode or setAttribute on non-script attributes. Nothing here
//   uses innerHTML, outerHTML, insertAdjacentHTML or eval.
// - Every in-page link comes from ShoalscanModel.href (model.js): a fixed
//   "#/view" route with whitelisted, validated parameters. internalLink()
//   refuses anything else.

(function () {
  var M = window.ShoalscanModel;
  var SVG = "http://www.w3.org/2000/svg";
  var SEVERITIES = M.SEVERITIES;
  var VIEWS = ["overview", "findings", "finding", "rule", "runs", "stale", "files", "suppressions", "changes", "config", "users", "about"];
  var FILE_KIND_LABELS = {
    skipped: "Skipped", error: "Scanner error", changed_unscanned: "Changed, not fully scanned",
    partial_warning: "Changed, small parse gap", partial_warn_only: "Changed, partially parsed (warn-only)",
    excluded_changed: "Changed, excluded"
  };
  var state = { repo: null, repos: [], csrf: null, heatAll: false, overview: null,
                scan: { status: null, fetchedAt: 0, timer: null, ticker: null, wasRunning: false } };

  // ------------------------------------------------------------ DOM helpers

  function el(tag, attrs) {
    var node = document.createElement(tag);
    setAttrs(node, attrs);
    for (var i = 2; i < arguments.length; i++) append(node, arguments[i]);
    return node;
  }

  function svg(tag, attrs) {
    var node = document.createElementNS(SVG, tag);
    setAttrs(node, attrs);
    for (var i = 2; i < arguments.length; i++) append(node, arguments[i]);
    return node;
  }

  function setAttrs(node, attrs) {
    if (!attrs) return;
    Object.keys(attrs).forEach(function (k) {
      if (attrs[k] === null || attrs[k] === undefined) return;
      if (/^on/i.test(k) || k === "style") throw new Error("refusing attribute " + k);
      if (k === "href" && !/^(#\/|https:\/\/)/.test(String(attrs[k]))) throw new Error("refusing link " + attrs[k]);
      node.setAttribute(k, String(attrs[k]));
    });
  }

  function append(node, child) {
    if (child === null || child === undefined || child === false) return;
    if (Array.isArray(child)) { child.forEach(function (c) { append(node, c); }); return; }
    node.appendChild(typeof child === "object" ? child : document.createTextNode(String(child)));
  }

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
    return node;
  }

  function $(id) { return document.getElementById(id); }
  function status(text) { $("status").textContent = text || ""; }
  function fmtDate(ts) { return ts ? ts.slice(0, 10) : "-"; }
  function fmtTime(ts) { return ts ? ts.slice(0, 16).replace("T", " ") + " UTC" : "-"; }
  // A timestamp in the viewer's local time, with the exact UTC time on hover.
  function localTime(ts) {
    if (!ts) return el("span", null, "-");
    var d = new Date(ts);
    return el("time", { datetime: ts, title: ts + " (UTC)" }, isNaN(d.getTime()) ? ts : d.toLocaleString());
  }
  function badge(review) {
    var b = M.reviewBadge(review);
    return el("span", { "class": "review-badge " + b.cls }, b.label);
  }
  function plural(n, one, many) { return n + " " + (n === 1 ? one : many); }

  // An in-page link; `href` must come from M.href.
  function internalLink(href, text, aria, cls) {
    if (!/^#\//.test(href)) throw new Error("refusing link " + href);
    return el("a", { href: href, "aria-label": aria || null, "class": cls || null }, text);
  }

  function externalLink(href, text) {
    return href && /^https:\/\//.test(href) ? el("a", { href: href, rel: "noopener noreferrer" }, text) : text;
  }

  // ------------------------------------------------------------ server calls

  function api(path, params) {
    var query = Object.assign({}, params || {});
    Object.keys(query).forEach(function (k) { if (query[k] === undefined || query[k] === null || query[k] === "") delete query[k]; });
    var qs = new URLSearchParams(query).toString();
    return fetch(path + (qs ? "?" + qs : ""), { credentials: "same-origin", headers: { "Accept": "application/json" } }).then(function (res) {
      if (res.status === 401) { window.location.assign("/login"); throw new Error("not logged in"); }
      return res.json().then(function (body) {
        if (!res.ok) {
          var err = new Error(body && body.error ? body.error : "request failed (" + res.status + ")");
          err.status = res.status;
          throw err;
        }
        return body;
      });
    });
  }

  function logout() {
    fetch("/logout", { method: "POST", credentials: "same-origin", headers: { "X-CSRF-Token": state.csrf || "" } })
      .finally(function () { window.location.assign("/login"); });
  }

  // ------------------------------------------------------------ charts

  function emptyChart(container, text) {
    clear(container).appendChild(el("p", { "class": "empty" }, text));
  }

  // items: [{name, cls, link: {href, aria} | null}]
  function legend(items) {
    return el("ul", { "class": "legend" }, items.map(function (it) {
      var body = [el("span", { "class": "swatch " + it.cls, "aria-hidden": "true" }), it.name];
      return el("li", null, it.link ? internalLink(it.link.href, body, it.link.aria, "legend-link") : body);
    }));
  }

  function niceMax(v) {
    if (v <= 4) return Math.max(v, 1);
    var p = Math.pow(10, Math.floor(Math.log10(v)));
    var steps = [1, 1.2, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10];
    for (var i = 0; i < steps.length; i++) if (steps[i] * p >= v) return steps[i] * p;
    return 10 * p;
  }

  function yTicks(max) {
    var n = max <= 4 ? max : [4, 5, 3, 6, 2].filter(function (k) { return max % k === 0; })[0] || 4;
    var out = [];
    for (var i = 0; i <= n; i++) out.push(Math.round((max * i) / n));
    return out;
  }

  function svgLink(link, children) {
    if (!/^#\//.test(link.href)) throw new Error("refusing link " + link.href);
    return svg("a", { href: link.href, "aria-label": link.aria, "class": "chart-link" }, children);
  }

  function tooltipFor(container) {
    var tip = el("div", { "class": "tooltip", hidden: "" });
    container.appendChild(tip);
    return {
      show: function (title, rows, x, y) {
        clear(tip);
        tip.appendChild(el("div", { "class": "t-title" }, title));
        rows.forEach(function (r) {
          tip.appendChild(el("div", null, r.cls ? el("span", { "class": "swatch " + r.cls, "aria-hidden": "true" }) : null, " " + r.text));
        });
        tip.hidden = false;
        var box = container.getBoundingClientRect();
        tip.style.left = Math.min(Math.max(0, x + 12), Math.max(0, box.width - tip.offsetWidth)) + "px"; // CSSOM, allowed by the CSP
        tip.style.top = Math.max(0, y - tip.offsetHeight - 8) + "px";
      },
      hide: function () { tip.hidden = true; }
    };
  }

  // A line chart over time. series: [{name, cls, values, link}] aligned with
  // times. opts.point(i, series) may return {href, aria}: each point then
  // becomes a link with a large hit area, instead of the hover crosshair.
  function lineChart(container, times, series, label, opts) {
    opts = opts || {};
    clear(container);
    if (!times.length) return emptyChart(container, "No runs recorded yet.");
    if (series.length > 1 || series.some(function (s) { return s.link; })) container.appendChild(legend(series));
    var W = 640, H = 220, L = 44, R = 104, T = 12, B = 26;
    var xs = times.map(function (t) { return Date.parse(t); });
    var x0 = xs[0], x1 = xs[xs.length - 1];
    if (x1 === x0) { x0 -= 86400000; x1 += 86400000; }
    var max = 0;
    series.forEach(function (s) { s.values.forEach(function (v) { if (v > max) max = v; }); });
    max = niceMax(max);
    function X(t) { return L + ((t - x0) / (x1 - x0)) * (W - L - R); }
    function Y(v) { return T + (1 - v / max) * (H - T - B); }
    var root = svg("svg", { viewBox: "0 0 " + W + " " + H, role: "group", "aria-label": label });
    var axis = svg("g", { "class": "axis", "aria-hidden": "true" });
    yTicks(max).forEach(function (v) {
      root.appendChild(svg("line", { "class": "gridline", x1: L, x2: W - R, y1: Y(v), y2: Y(v) }));
      axis.appendChild(svg("text", { x: L - 6, y: Y(v) + 4, "text-anchor": "end" }, String(v)));
    });
    var tickIdx = xs.length === 1 ? [0] : [0, Math.floor((xs.length - 1) / 2), xs.length - 1];
    tickIdx.filter(function (v, i, a) { return a.indexOf(v) === i; }).forEach(function (i, n, all) {
      var anchor = all.length === 1 ? "middle" : (n === 0 ? "start" : (n === all.length - 1 ? "end" : "middle"));
      axis.appendChild(svg("text", { x: X(xs[i]), y: H - 6, "text-anchor": anchor }, fmtDate(times[i])));
    });
    root.appendChild(axis);
    var linked = typeof opts.point === "function";
    var hitR = Math.max(6, Math.min(14, (W - L - R) / Math.max(1, xs.length) / 2));
    series.forEach(function (s) {
      var d = s.values.map(function (v, i) { return (i ? "L" : "M") + X(xs[i]).toFixed(1) + " " + Y(v).toFixed(1); }).join(" ");
      var path = svg("path", { "class": "line " + s.cls, d: d, "aria-hidden": "true" });
      root.appendChild(s.link ? svgLink(s.link, [path]) : path);
      s.values.forEach(function (v, i) {
        var link = linked ? opts.point(i, s) : null;
        if (link) {
          root.appendChild(svgLink(link, [
            svg("circle", { "class": "hit-area", cx: X(xs[i]), cy: Y(v), r: hitR }),
            svg("circle", { "class": "dot " + s.cls, cx: X(xs[i]), cy: Y(v), r: 4 }),
            svg("title", null, link.aria)
          ]));
        } else if (xs.length <= 40) {
          root.appendChild(svg("circle", { "class": "dot " + s.cls, cx: X(xs[i]), cy: Y(v), r: 3.5, "aria-hidden": "true" }));
        }
      });
      var last = s.values[s.values.length - 1];
      root.appendChild(svg("text", { "class": "label-end", x: X(xs[xs.length - 1]) + 10, y: Y(last) + 4, "aria-hidden": "true" }, s.name + " " + last));
    });
    container.appendChild(root);
    if (linked) return;
    var cross = svg("line", { "class": "crosshair", y1: T, y2: H - B, x1: -10, x2: -10 });
    root.appendChild(cross);
    var hit = svg("rect", { "class": "hit", x: L, y: T, width: W - L - R, height: H - T - B });
    root.appendChild(hit);
    var tip = tooltipFor(container);
    hit.addEventListener("mousemove", function (ev) {
      var box = root.getBoundingClientRect();
      var px = ((ev.clientX - box.left) / box.width) * W;
      var best = 0;
      for (var i = 1; i < xs.length; i++) if (Math.abs(X(xs[i]) - px) < Math.abs(X(xs[best]) - px)) best = i;
      cross.setAttribute("x1", X(xs[best]));
      cross.setAttribute("x2", X(xs[best]));
      var cbox = container.getBoundingClientRect();
      tip.show(fmtTime(times[best]), series.map(function (s) { return { cls: s.cls, text: s.name + ": " + s.values[best] }; }),
        (X(xs[best]) / W) * box.width + (box.left - cbox.left), ev.clientY - cbox.top);
    });
    hit.addEventListener("mouseleave", function () { cross.setAttribute("x1", -10); cross.setAttribute("x2", -10); tip.hide(); });
  }

  // Grouped vertical bars. groups: [{label, title, values}], series: [{name, cls}].
  // barLink(group, j) may return {href, aria}; the whole column slot is the hit area.
  function barChart(container, groups, series, label, barLink) {
    clear(container);
    if (!groups.length) return emptyChart(container, "No data yet.");
    container.appendChild(legend(series));
    var W = 640, H = 220, L = 44, R = 10, T = 10, B = 26;
    var max = 0;
    groups.forEach(function (g) { g.values.forEach(function (v) { if (v > max) max = v; }); });
    max = niceMax(max);
    function Y(v) { return T + (1 - v / max) * (H - T - B); }
    var band = (W - L - R) / groups.length;
    var gap = Math.min(6, band * 0.2);
    var barW = Math.max(1, (band - gap) / series.length - 2);
    var root = svg("svg", { viewBox: "0 0 " + W + " " + H, role: "group", "aria-label": label });
    var axis = svg("g", { "class": "axis", "aria-hidden": "true" });
    yTicks(max).forEach(function (v) {
      root.appendChild(svg("line", { "class": "gridline", x1: L, x2: W - R, y1: Y(v), y2: Y(v) }));
      axis.appendChild(svg("text", { x: L - 6, y: Y(v) + 4, "text-anchor": "end" }, String(v)));
    });
    var every = Math.max(1, Math.ceil(groups.length / 6));
    groups.forEach(function (g, i) {
      if (i % every === 0) axis.appendChild(svg("text", { x: L + band * i + band / 2, y: H - 6, "text-anchor": "middle" }, g.label));
    });
    root.appendChild(axis);
    container.appendChild(root);
    groups.forEach(function (g, i) {
      g.values.forEach(function (v, j) {
        var x = L + band * i + gap / 2 + j * (barW + 2);
        var h = Math.max(v > 0 ? 1 : 0, (H - T - B) - (Y(v) - T));
        var title = (g.title || g.label) + ": " + series[j].name + " " + v;
        var bar = svg("rect", { "class": "bar " + series[j].cls, x: x, y: Y(0) - h, width: barW, height: h, rx: Math.min(3, barW / 2) });
        var link = barLink ? barLink(g, j) : null;
        if (link) {
          root.appendChild(svgLink(link, [svg("rect", { "class": "hit-area", x: x - 1, y: T, width: barW + 2, height: H - T - B }), bar, svg("title", null, link.aria)]));
        } else {
          bar.appendChild(svg("title", null, title));
          root.appendChild(bar);
        }
      });
    });
  }

  // Horizontal bars, one series, with direct value labels. barLink(item, i) may return {href, aria}.
  function hbarChart(container, items, label, barLink) {
    clear(container);
    var total = items.reduce(function (a, b) { return a + b.count; }, 0);
    if (!total) return emptyChart(container, "No open findings.");
    var W = 640, rowH = 30, L = 110, R = 50;
    var H = rowH * items.length + 6;
    var max = niceMax(Math.max.apply(null, items.map(function (i) { return i.count; })));
    var root = svg("svg", { viewBox: "0 0 " + W + " " + H, role: "group", "aria-label": label });
    items.forEach(function (it, i) {
      var y = 4 + i * rowH;
      var w = ((W - L - R) * it.count) / max;
      var parts = [
        svg("text", { "class": "tick", x: L - 8, y: y + rowH / 2 + 3, "text-anchor": "end" }, it.label),
        svg("rect", { "class": "bar s-1", x: L, y: y + 4, width: Math.max(it.count ? 2 : 0, w), height: rowH - 10, rx: 3 }),
        svg("text", { "class": "label-end", x: L + w + 6, y: y + rowH / 2 + 3 }, String(it.count))
      ];
      var link = barLink ? barLink(it, i) : null;
      if (link) {
        root.appendChild(svgLink(link, [svg("rect", { "class": "hit-area", x: 0, y: y, width: W, height: rowH })].concat(parts, [svg("title", null, link.aria)])));
      } else {
        parts[1].appendChild(svg("title", null, it.label + ": " + it.count));
        parts.forEach(function (p) { root.appendChild(p); });
      }
    });
    container.appendChild(root);
  }

  // The component heatmap: a CSS grid of text nodes and real links.
  function heatmap(container, byComponent) {
    clear(container);
    var model = M.heatmap(byComponent, state.heatAll);
    var toggle = $("heat-toggle");
    if (!model.rows.length) {
      toggle.hidden = true;
      return emptyChart(container, "No open findings.");
    }
    var grid = el("div", { "class": "heat-grid", role: "table", "aria-label": "Open findings by component and severity" });
    grid.appendChild(el("div", { "class": "heat-row heat-head", role: "row" },
      el("span", { role: "columnheader" }, "Component"),
      model.severities.map(function (s) { return el("span", { role: "columnheader", "class": "heat-col" }, el("span", { "class": "sev " + s }, s)); }),
      el("span", { role: "columnheader" }, "Heat score")));
    model.rows.forEach(function (r) {
      var name = r.href ? internalLink(r.href, r.component, r.aria, "heat-name") : el("span", { "class": "heat-name" }, r.component);
      var fill = el("span", { "class": "heat-fill" });
      fill.style.width = r.bar + "%"; // CSSOM, allowed by the CSP
      grid.appendChild(el("div", { "class": "heat-row", role: "row" },
        el("span", { role: "rowheader", "class": "heat-label" }, name,
          r.newBlocking ? el("span", { "class": "badge", title: plural(r.newBlocking, "new blocking finding", "new blocking findings") }, r.newBlocking + " new blocking") : null),
        r.cells.map(function (c) {
          var cls = "heat-cell h" + c.level;
          var node = c.href ? internalLink(c.href, String(c.value), c.aria, cls) : el("span", { "class": cls }, String(c.value));
          node.setAttribute("title", c.title);
          return el("span", { role: "cell" }, node);
        }),
        el("span", { role: "cell", "class": "heat-score" }, el("span", { "class": "heat-bar", "aria-hidden": "true" }, fill), String(r.score))));
    });
    container.appendChild(grid);
    var total = (byComponent.rows || []).length;
    toggle.hidden = total <= M.HEAT_ROWS_SHOWN;
    toggle.textContent = state.heatAll ? "Show the top " + M.HEAT_ROWS_SHOWN : "Show all " + total + " components";
    toggle.setAttribute("aria-expanded", state.heatAll ? "true" : "false");
  }

  // A small line of the blocking-class count over the trend runs; each known point links to that run's blocking findings.
  function sparkline(container, series) {
    clear(container);
    var points = series.filter(function (p) { return p.blocking !== null && p.blocking !== undefined; });
    if (!points.length) return emptyChart(container, "Not recorded for these runs yet.");
    var W = 320, H = 70, P = 8;
    var max = Math.max(1, Math.max.apply(null, points.map(function (p) { return p.blocking; })));
    var xs = points.map(function (p) { return Date.parse(p.scanned_at); });
    var x0 = xs[0], x1 = xs[xs.length - 1];
    if (x1 === x0) { x0 -= 86400000; x1 += 86400000; }
    function X(t) { return P + ((t - x0) / (x1 - x0)) * (W - 2 * P - 40); }
    function Y(v) { return P + (1 - v / max) * (H - 2 * P); }
    var root = svg("svg", { viewBox: "0 0 " + W + " " + H, role: "group", "aria-label": "Blocking findings over the scheduled runs" });
    root.appendChild(svg("path", { "class": "line s-ERROR", "aria-hidden": "true",
      d: points.map(function (p, i) { return (i ? "L" : "M") + X(xs[i]).toFixed(1) + " " + Y(p.blocking).toFixed(1); }).join(" ") }));
    points.forEach(function (p, i) {
      var link = M.blockingPoint(p);
      root.appendChild(svgLink(link, [svg("circle", { "class": "hit-area", cx: X(xs[i]), cy: Y(p.blocking), r: 9 }),
        svg("circle", { "class": "dot s-ERROR", cx: X(xs[i]), cy: Y(p.blocking), r: 3 }), svg("title", null, link.aria)]));
    });
    var last = points[points.length - 1];
    root.appendChild(svg("text", { "class": "label-end", x: X(xs[xs.length - 1]) + 8, y: Y(last.blocking) + 4, "aria-hidden": "true" }, String(last.blocking)));
    container.appendChild(root);
  }

  function blockingPanel(o) {
    var panel = M.blockingPanel(o);
    var counts = clear($("blocking-counts"));
    var top = clear($("blocking-top"));
    var all = clear($("blocking-all"));
    sparkline($("blocking-spark"), o.series);
    if (!panel.known) {
      counts.appendChild(el("p", { "class": "muted" }, "The latest trend run was recorded without the blocking class. Record a run with this Shoalscan's check.json to see it."));
      return;
    }
    function number(part, label, cls) {
      var body = [el("span", { "class": "value" }, String(part.value)), el("span", { "class": "label" }, label)];
      return part.href ? internalLink(part.href, body, part.aria, "blocking-count tile-link " + cls) : el("div", { "class": "blocking-count " + cls }, body);
    }
    counts.appendChild(number(panel.total, "blocking", "total"));
    counts.appendChild(number(panel["new"], "new: fail pull requests", "new"));
    counts.appendChild(number(panel.baselined, "baselined: the backlog", "baselined"));
    panel.top.forEach(function (f) {
      top.appendChild(el("li", null, safeRow(function () {
        if (!f.href) throw new Error("no link");
        return internalLink(f.href, [
          el("span", { "class": "sev " + f.severity }, f.severity),
          f.isNew ? el("span", { "class": "badge" }, "new") : null,
          el("span", { "class": "mono rule", title: f.rule }, f.ruleShort),
          el("span", { "class": "mono path" }, f.location),
          el("span", { "class": "muted" }, f.component)
        ], f.aria, "blocking-row");
      }, f.ruleShort + " " + f.location)));
    });
    if (!panel.top.length) top.appendChild(el("li", { "class": "muted" }, "No blocking findings in this run."));
    if (panel.seeAll) all.appendChild(internalLink(panel.seeAll.href, panel.seeAll.text + " \u2192", panel.seeAll.text + ", in fix order"));
  }

  // One bad value must not take the page down: if a row cannot be built
  // (for example a link the model refuses), show it as plain text.
  function safeRow(build, fallback) {
    try {
      return build();
    } catch (e) {
      return el("span", { "class": "muted" }, fallback);
    }
  }

  function tileNode(t) {
    var body = [el("span", { "class": "label" }, t.label), el("span", { "class": "value" }, t.value), t.sub ? el("span", { "class": "sub" }, t.sub) : null];
    return t.href ? internalLink(t.href, body, t.aria, "tile tile-link") : el("div", { "class": "tile" }, body);
  }

  function statusNode(run, heading) {
    var v = M.statusView(run);
    var cls = v.outcome === "passed" ? "status-pass" : (v.outcome === "scan_error" ? "status-error" : "status-fail");
    return el("div", { "class": "status-card " + cls },
      el("div", { "class": "status-head" },
        el("span", { "class": "status-label" }, el("span", { "aria-hidden": "true" }, v.icon + " "), v.label),
        heading ? internalLink(M.href("runs", { run: run.id }), heading, "Show the detail of run " + run.id, "status-run") : null),
      v.details.length ? el("ul", { "class": "status-details" }, v.details.map(function (d) { return el("li", null, d); })) : null,
      v.explanation ? el("p", { "class": "status-explain" }, v.explanation + " ", v.link ? internalLink(v.link.href, v.link.text) : null) : null);
  }

  // ------------------------------------------------------------ views

  function showView(name) {
    VIEWS.forEach(function (v) { $("view-" + v).hidden = v !== name; });
    var parent = { rule: "findings", finding: "findings", stale: "runs", files: "runs", suppressions: "runs", changes: "overview" }[name] || name;
    document.querySelectorAll("nav a[data-view]").forEach(function (a) {
      if (a.getAttribute("data-view") === parent) a.setAttribute("aria-current", "page");
      else a.removeAttribute("aria-current");
    });
  }

  function renderOverview() {
    status("Loading...");
    return api("/api/overview", { repo: state.repo }).then(function (o) {
      status("");
      state.overview = o;
      $("trend-note").textContent = o.trend_kind === "scheduled"
        ? "Trends come from the scheduled scans of the default branch. Select a tile, a point or a bar to see the findings behind it."
        : "This repository has no scheduled runs yet, so the trends use every recorded run.";
      var panel = clear($("latest-status"));
      if (o.latest_run) {
        var r = o.latest_run;
        panel.appendChild(statusNode(r, "Latest run: " + r.kind + " " + r.ref + " at " + r.commit.slice(0, 10) + ", " + fmtTime(r.scanned_at)));
        withScanStatus().then(function () { panel.appendChild(rescanControls(r, false)); });
      }
      blockingPanel(o);
      var tiles = clear($("tiles"));
      M.overviewTiles(o).forEach(function (t) { tiles.appendChild(tileNode(t)); });
      var trendRun = o.latest_trend_run ? o.latest_trend_run.id : null;
      var times = o.series.map(function (p) { return p.scanned_at; });
      lineChart($("chart-open"), times, SEVERITIES.map(function (s) {
        return { name: s, cls: "s-" + s, values: o.series.map(function (p) { return p.open[s]; }), sev: s,
                 link: trendRun ? M.severityLegend(s, trendRun) : null };
      }), "Open findings by severity over time", { point: function (i, s) { return M.severityPoint(o.series[i], s.sev); } });
      lineChart($("chart-baseline"), times, [{ name: "entries", cls: "s-1", values: o.series.map(function (p) { return p.baseline_size; }) }],
        "Baseline entries over time");
      barChart($("chart-weekly"), o.weekly.map(function (w) {
        return { label: w.week.slice(5), title: "Week of " + w.week, values: [w["new"], w.fixed], week: w };
      }), [{ name: "New", cls: "s-2" }, { name: "Fixed", cls: "s-1" }], "New and fixed findings per week",
      function (g, j) { return M.weekBar(g.week, j === 0 ? "new" : "fixed"); });
      hbarChart($("chart-age"), o.age_buckets, "Open findings by age", function (b, i) { return M.ageBar(b, i, trendRun); });
      heatmap($("chart-components"), o.by_component);
      lineChart($("chart-suppressions"), times, [
        { name: "suppressions", cls: "s-1", values: o.series.map(function (p) { return p.suppressions; }), kind: "suppressions" },
        { name: "silenced", cls: "s-2", values: o.series.map(function (p) { return p.suppressed_findings; }), kind: "suppressions" }
      ], "Inline suppressions and the findings they silence",
      { point: function (i, s) { return M.listPoint(o.series[i], "suppressions", o.series[i].suppressions, "Inline suppressions"); } });
      lineChart($("chart-unscanned"), times, [
        { name: "skipped", cls: "s-1", values: o.series.map(function (p) { return p.unscanned_skipped; }) },
        { name: "errors", cls: "s-2", values: o.series.map(function (p) { return p.unscanned_errored; }) }
      ], "Files skipped or with scanner errors",
      { point: function (i) { var p = o.series[i]; return M.listPoint(p, "files", p.unscanned_skipped + p.unscanned_errored, "Files not fully scanned"); } });
    });
  }

  function fillSelect(select, options, current, allLabel) {
    clear(select);
    select.appendChild(el("option", { value: "" }, allLabel));
    options.forEach(function (o) {
      var opt = el("option", { value: o.value }, o.label);
      if (o.value === current) opt.selected = true;
      select.appendChild(opt);
    });
  }

  function chip(text, params, view, drop) {
    var rest = Object.assign({}, params);
    delete rest[drop];
    delete rest.offset;
    return el("li", null, internalLink(M.href(view, rest), [text, el("span", { "aria-hidden": "true" }, " ✕")], "Remove the filter: " + text, "chip"));
  }

  function renderFindings(params) {
    var form = $("filters");
    var ageLabels = ["0-7 days", "8-30 days", "31-90 days", "91-365 days", "over a year"];
    status("Loading...");
    return api("/api/findings", Object.assign({ repo: state.repo, limit: "200" }, params)).then(function (res) {
      status("");
      fillSelect(form.elements.severity, res.facets.severities.map(function (s) { return { value: s, label: s }; }), params.severity, "All");
      fillSelect(form.elements.rule, res.facets.rules.map(function (r) { return { value: r.rule, label: r.rule + " (" + r.count + ")" }; }), params.rule, "All rules");
      fillSelect(form.elements.component, res.facets.components.map(function (c) { return { value: c, label: c }; }), params.component, "All");
      form.elements.path.value = params.path || "";
      form.elements.age.value = params.age || "";
      form.elements["new"].checked = params["new"] === "1";
      form.elements.new_blocking.checked = params.new_blocking === "1";
      form.elements.blocking.checked = params.blocking === "1";
      form.elements.sort.value = res.sort || "";
      form.setAttribute("data-baselined", params.baselined || "");
      fillSelect(form.elements.review, M.REVIEW_FILTERS.map(function (r) { return { value: r, label: M.REVIEW_LABELS[r] }; }), params.review, "Any");
      state.findingsRun = res.run;
      state.selected = {};
      state.findingRows = {};
      renderBulk();
      form.setAttribute("data-run", params.run || "");
      $("findings-note").textContent = plural(res.total, "finding", "findings") + " in run " + res.run + " match.";
      var chips = clear($("findings-chips"));
      if (params.run) chips.appendChild(chip("Run " + params.run, params, "findings", "run"));
      if (params["new"]) chips.appendChild(chip("New", params, "findings", "new"));
      if (params.new_blocking) chips.appendChild(chip("New and blocking", params, "findings", "new_blocking"));
      if (params.age) chips.appendChild(chip("Age " + ageLabels[Number(params.age)], params, "findings", "age"));
      if (params.blocking) chips.appendChild(chip("Blocking", params, "findings", "blocking"));
      if (params.baselined) chips.appendChild(chip("Baselined", params, "findings", "baselined"));
      if (res.sort === "priority") chips.appendChild(el("li", { "class": "muted small" }, "Sorted by fix priority: new blocking first, ERROR before WARNING, hottest component, oldest first."));
      var body = clear($("findings-table").tBodies[0]);
      res.findings.forEach(function (f) {
        var link = safeRow(function () { return el("a", { href: M.href("rule", { rule: f.rule, run: res.run }), title: f.message }, f.rule); }, f.rule);
        var box = el("input", { type: "checkbox", "aria-label": "Select " + f.rule + " in " + f.path + " line " + f.line });
        box.addEventListener("change", function () {
          if (box.checked) state.selected[JSON.stringify(f.key)] = f.key; else delete state.selected[JSON.stringify(f.key)];
          renderBulk();
        });
        state.findingRows[JSON.stringify(f.key)] = f;
        var reviewHref = M.findingHref(res.run, f.key);
        body.appendChild(el("tr", null,
          el("td", null, box),
          el("td", null, el("span", { "class": "sev " + f.severity }, f.severity)),
          el("td", { "class": "mono" }, link),
          el("td", null, f.component),
          el("td", { "class": "path mono" }, f.path + ":" + f.line),
          el("td", null, fmtDate(f.first_seen)),
          el("td", null, f.new_blocking ? "new, blocking" : (f["new"] ? "new" : "")),
          el("td", null, badge(f.review)),
          el("td", null, suggestionCell(f.suggestion)),
          el("td", null, localTime(f.review && f.review.source === "review" ? f.review.resolved_at : null)),
          el("td", null, reviewHref ? internalLink(reviewHref, "Review", "Review " + f.rule + " in " + f.path + " line " + f.line) : "-")));
      });
      if (!res.findings.length) body.appendChild(el("tr", null, el("td", { colspan: "11", "class": "empty" }, "No findings match.")));
      pager($("findings-pager"), res, "findings", params);
    });
  }

  // A suggestion is a hint from a similar finding's decision; a person still decides.
  function suggestionCell(s) {
    if (!s) return "";
    var label = (M.REVIEW_LABELS[s.status] || s.status) + "? " + s.score.toFixed(2);
    var why = "Like " + s.like[2] + " (" + s.like[1] + "), " + (s.source === "review" ? "reviewed" : "baselined") + " as " +
      (M.REVIEW_LABELS[s.status] || s.status) + ": " + (s.description || "");
    var href = M.findingHref(null, s.like);
    return href ? internalLink(href, label, why, "suggestion") : el("span", { "class": "suggestion", title: why }, label);
  }

  function useSuggestion() {
    var picked = Object.keys(state.selected || {}).map(function (k) { return (state.findingRows || {})[k]; });
    var form = $("bulk-review").elements;
    var withOne = picked.filter(function (f) { return f && f.suggestion; });
    if (!picked.length || withOne.length !== picked.length) {
      $("bulk-message").textContent = "Select only findings that have a suggestion.";
      return;
    }
    var status = withOne[0].suggestion.status;
    if (withOne.some(function (f) { return f.suggestion.status !== status; })) {
      $("bulk-message").textContent = "The selected findings have different suggestions; select ones that agree.";
      return;
    }
    var scores = withOne.map(function (f) { return f.suggestion.score; });
    var first = withOne[0].suggestion;
    var label = M.REVIEW_LABELS[status];
    form.status.value = status;
    form.description.value = "Like findings already marked " + label + " (similarity " + Math.min.apply(null, scores).toFixed(2) +
      (withOne.length > 1 ? " to " + Math.max.apply(null, scores).toFixed(2) : "") + "), for example " + first.like[2] + ": " +
      (first.description || "").slice(0, 1500);
    $("bulk-message").textContent = "Check the status and the description, edit them if needed, then Apply. Nothing is saved until you do.";
    form.description.focus();
  }

  function renderBulk() {
    var keys = Object.keys(state.selected || {});
    var form = $("bulk-review");
    form.hidden = keys.length === 0;
    $("bulk-count").textContent = keys.length + " selected";
  }

  function submitBulk(ev) {
    ev.preventDefault();
    var keys = Object.keys(state.selected || {}).map(function (k) { return state.selected[k]; });
    var e = ev.target.elements;
    postJson("/api/review", { repo: state.repo, finding_keys: keys, status: e.status.value, description: e.description.value, run_id: state.findingsRun })
      .then(function (r) {
        if (r.status === 200) {
          e.description.value = "";
          $("bulk-message").textContent = "Marked " + r.body.reviewed + " as " + M.REVIEW_LABELS[r.body.status] + ".";
          route();
        } else {
          $("bulk-message").textContent = "Not saved: " + (r.body.error || "error " + r.status);
        }
      });
  }

  function renderFinding(params) {
    if (!params.tool || !params.rule || !params.path || !params.fingerprint) return Promise.reject(new Error("no finding named"));
    var key = [params.tool, params.rule, params.path, params.fingerprint];
    status("Loading...");
    return api("/api/finding", { repo: state.repo, run: params.run, finding_key: JSON.stringify(key) }).then(function (res) {
      status("");
      var f = res.finding;
      $("finding-back").setAttribute("href", M.href("findings", { run: res.run }));
      $("finding-title").textContent = f.rule;
      var facts = clear($("finding-facts"));
      [["Severity", f.severity], ["Location", f.path + ":" + f.line], ["Component", f.component], ["Fingerprint", f.fingerprint],
       ["First seen", fmtDate(f.first_seen)]].forEach(function (p) { facts.appendChild(el("dt", null, p[0])); facts.appendChild(el("dd", null, p[1])); });
      $("finding-message").textContent = f.message;
      var r = f.review;
      var current = clear($("review-current"));
      current.appendChild(badge(r));
      if (r.source === "review") {
        current.appendChild(document.createTextNode(" by " + r.updated_by + ", "));
        current.appendChild(localTime(r.updated_at));
        if (r.resolved_at) { current.appendChild(document.createTextNode("; resolved ")); current.appendChild(localTime(r.resolved_at)); }
        current.appendChild(el("span", { "class": "review-description" }, r.description));
      }
      $("review-baseline").textContent = r.baseline_reason
        ? "From baseline (read-only): " + r.baseline_reason + " (" + r.baseline_issue + ")" : "";
      var form = $("review-form");
      fillSelect(form.elements.status, M.USER_STATUSES.map(function (s) { return { value: s, label: M.REVIEW_LABELS[s] }; }),
        r.source === "review" && M.USER_STATUSES.indexOf(r.status) >= 0 ? r.status : "", "Choose a status");
      form.setAttribute("data-run", String(res.run));
      state.reviewKey = f.key;
      $("review-error").textContent = "";
      var list = clear($("review-history"));
      res.history.forEach(function (h) {
        list.appendChild(el("li", null, localTime(h.at), " ", el("strong", null, h.who), ": " + M.REVIEW_LABELS[h.from_status] + " \u2192 " + M.REVIEW_LABELS[h.to_status],
          el("span", { "class": "review-description" }, h.description)));
      });
      if (!res.history.length) list.appendChild(el("li", { "class": "muted" }, "No review yet."));
      renderSimilar(f.key);
    });
  }

  function renderSimilar(key) {
    var list = clear($("finding-similar"));
    api("/api/similar", { finding_key: JSON.stringify(key) }).then(function (res) {
      if (!res.embedded) {
        list.appendChild(el("li", { "class": "muted" }, "No embeddings yet. Run shoalscan triage embed --repo-name " + state.repo + " on this server, with Ollama running."));
        return;
      }
      if (!res.similar.length) {
        list.appendChild(el("li", { "class": "muted" }, "None at similarity " + res.threshold + " or above."));
        return;
      }
      res.similar.forEach(function (s) {
        var where = s.key[2] + (s.line ? ":" + s.line : "");
        var label = s.repo === state.repo ? internalLink(M.findingHref(null, s.key), where, "Open the similar finding in " + where) : where + " (" + s.repo + ")";
        var d = s.decision;
        var decided = !d ? "no decision yet"
          : d.source === "review" ? (M.REVIEW_LABELS[d.status] || d.status) + " by " + d.by + ": " + d.description
          : "baselined (" + d.issue + "): " + d.description;
        list.appendChild(el("li", null, el("strong", null, s.score.toFixed(3)), " ", label, " ", el("span", { "class": "mono" }, s.key[1]),
          el("span", { "class": "review-description" }, decided)));
      });
    }, function () { list.appendChild(el("li", { "class": "muted" }, "Similar findings could not be loaded.")); });
  }

  function submitReview(ev) {
    ev.preventDefault();
    var e = ev.target.elements;
    if (!e.status.value) { $("review-error").textContent = "Choose a status."; return; }
    postJson("/api/review", { repo: state.repo, finding_key: state.reviewKey, status: e.status.value, description: e.description.value,
      run_id: Number(ev.target.getAttribute("data-run")) }).then(function (r) {
      if (r.status === 200) { e.description.value = ""; route(); }
      else $("review-error").textContent = r.body.error || "error " + r.status;
    });
  }

  function pager(container, res, view, params) {
    clear(container);
    if (res.total <= res.limit) return;
    var prevOffset = Math.max(0, res.offset - res.limit);
    var nextOffset = res.offset + res.limit;
    if (res.offset > 0) container.appendChild(internalLink(M.href(view, Object.assign({}, params, { offset: prevOffset || null })), "Previous", "Previous page", "button-link"));
    container.appendChild(el("span", null, (res.offset + 1) + "-" + Math.min(res.total, res.offset + res.limit) + " of " + res.total));
    if (nextOffset < res.total) container.appendChild(internalLink(M.href(view, Object.assign({}, params, { offset: nextOffset })), "Next", "Next page", "button-link"));
  }

  function renderRule(params) {
    status("Loading...");
    return api("/api/rule", { repo: state.repo, rule: params.rule, run: params.run }).then(function (res) {
      status("");
      $("rule-title").textContent = res.rule;
      var box = clear($("rule-messages"));
      if (!res.messages.length) box.appendChild(el("p", { "class": "muted" }, "This rule has no findings in this run."));
      res.messages.forEach(function (m) { box.appendChild(el("p", { "class": "message" }, m)); });
      var body = clear($("rule-table").tBodies[0]);
      res.locations.forEach(function (l) {
        body.appendChild(el("tr", null, el("td", null, el("span", { "class": "sev " + l.severity }, l.severity)),
          el("td", null, l.component), el("td", { "class": "path mono" }, l.path + ":" + l.line)));
      });
    });
  }

  function runDetail(run) {
    var box = clear($("run-detail"));
    box.hidden = false;
    box.appendChild(el("h2", null, "Run " + run.id + ": " + run.kind + " " + run.ref + " at " + run.commit.slice(0, 12),
      run.rescanned ? el("span", { "class": "badge neutral" }, "Rescanned") : null));
    box.appendChild(statusNode(run, null));
    withScanStatus().then(function () { box.insertBefore(rescanControls(run, true), box.childNodes[2] || null); });
    var links = [];
    function add(cond, text, href) { if (cond) links.push(el("li", null, internalLink(href, text))); }
    add(run.findings > 0, plural(run.findings, "finding", "findings"), M.href("findings", { run: run.id }));
    add(run["new"] > 0 && run.lists["new"], plural(run["new"], "new finding", "new findings"), M.href("findings", { run: run.id, "new": "1" }));
    add(run.new_blocking > 0 && run.lists["new"], plural(run.new_blocking, "new blocking finding", "new blocking findings"), M.href("findings", { run: run.id, new_blocking: "1" }));
    add(run.stale > 0 && run.lists.stale, plural(run.stale, "stale baseline entry", "stale baseline entries"), M.href("stale", { run: run.id }));
    add(run.suppressions.total > 0 && run.lists.suppressions, plural(run.suppressions.total, "inline suppression", "inline suppressions"), M.href("suppressions", { run: run.id }));
    var files = run.unscanned.skipped + run.unscanned.errored + run.unscanned.changed_and_unscanned;
    add(files > 0 && run.lists.files, plural(files, "file not fully scanned", "files not fully scanned"), M.href("files", { run: run.id }));
    if (links.length) box.appendChild(el("ul", { "class": "detail-links" }, links));
    if (!run.lists["new"] && run.outcome !== "scan_error") {
      box.appendChild(el("p", { "class": "muted small" }, "This run was recorded without check.json, so its new and stale entries cannot be listed."));
    }
    box.appendChild(el("dl", { "class": "facts" },
      el("dt", null, "Scanned"), el("dd", null, fmtTime(run.scanned_at)),
      el("dt", null, "Commit"), el("dd", { "class": "mono" }, run.commit),
      el("dt", null, "Check exit"), el("dd", null, run.check_exit === null ? "not recorded" : String(run.check_exit)),
      el("dt", null, "Policy ref"), el("dd", { "class": "mono" }, run.policy_ref || "the working tree"),
      el("dt", null, "Shoalscan"), el("dd", null, run.shoalscan_version || "-")));
  }

  // ------------------------------------------------------------ on-demand scans

  function postJson(path, payload) {
    return fetch(path, {
      method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json", "Accept": "application/json", "X-CSRF-Token": state.csrf || "" },
      body: JSON.stringify(payload)
    }).then(function (res) {
      return res.json().catch(function () { return {}; }).then(function (body) { return { status: res.status, body: body }; });
    });
  }

  function minutesAndSeconds(seconds) {
    var m = Math.floor(seconds / 60), s = seconds % 60;
    return (m ? m + " min " : "") + s + " s";
  }

  function scanWait(s, name) {
    var elapsed = Math.floor((Date.now() - state.scan.fetchedAt) / 1000);
    var t = (s.targets || []).filter(function (x) { return x.name === name; })[0];
    var own = t ? Math.max(0, t.cooldown_remaining - elapsed) : 0;
    return Math.max(own, Math.max(0, (s.global_remaining || 0) - elapsed));
  }

  function paintScanButton() {
    var s = state.scan.status;
    if (!s) return;
    var button = $("scan-start");
    var name = $("scan-target").value;
    var target = (s.targets || []).filter(function (x) { return x.name === name; })[0];
    var wait = scanWait(s, name);
    button.disabled = !target || !target.enabled || s.running || wait > 0 || s.git_ok === false;
    button.textContent = s.git_ok === false ? "Scans are unavailable" : s.running ? "A scan is running" : (target && !target.enabled ? "This target is disabled"
      : (wait > 0 ? "Available in " + minutesAndSeconds(wait) : "Run a fresh scan"));
  }

  function renderScan(s) {
    state.scan.status = s;
    state.scan.fetchedAt = Date.now();
    $("scan-panel").hidden = false;
    var select = $("scan-target");
    var chosen = select.value || state.repo;
    clear(select);
    s.targets.forEach(function (t) {
      var opt = el("option", { value: t.name }, t.name + " (" + t.branch + ")" + (t.enabled ? "" : ", disabled"));
      if (t.name === chosen) opt.selected = true;
      select.appendChild(opt);
    });
    var c = s.current;
    $("scan-state").textContent = s.git_ok === false ? "Scans are unavailable on this server: " + s.git_error + "." : s.running
      ? "Scanning " + (c && c.target ? c.target : "") + " since " + fmtTime(c && c.started) + ". This page follows it."
      : (c && c.finished ? "Last scan: " + c.target + ", " + c.outcome + ", finished " + fmtTime(c.finished) + "." : "No scan has run from here yet.");
    var result = clear($("scan-result"));
    if (!s.running && c && c.run_id) result.appendChild(internalLink(M.href("runs", { repo: c.target, run: c.run_id }), "Open run " + c.run_id, "Open the run this scan recorded"));
    var log = $("scan-log");
    log.hidden = !(s.log && s.log.length);
    log.textContent = (s.log || []).join("\n");
    var body = clear($("scan-triggers").tBodies[0]);
    (s.triggers || []).forEach(function (t) {
      body.appendChild(el("tr", null, el("td", null, fmtTime(t.started_at)), el("td", null, t.target), el("td", null, t.who + " (" + t.trigger + ")"),
        el("td", null, t.outcome + (t.detail ? ": " + t.detail : "")),
        el("td", null, t.run_id ? safeRow(function () { return internalLink(M.href("runs", { repo: t.target, run: t.run_id }), String(t.run_id), "Open run " + t.run_id); }, String(t.run_id)) : "-")));
    });
    paintScanButton();
    window.clearTimeout(state.scan.timer);
    if (s.running) state.scan.timer = window.setTimeout(refreshScan, 3000);
    else if (state.scan.wasRunning && M.parseRoute(window.location.hash).view === "runs") route(); // show the new run
    state.scan.wasRunning = s.running;
  }

  function refreshScan() {
    return api("/api/scan/status").then(renderScan, function (err) {
      $("scan-panel").hidden = true;
      if (err.status !== 404) status("Could not read the scan status: " + err.message);
    });
  }

  function startScan(ev) {
    ev.preventDefault();
    var name = $("scan-target").value;
    $("scan-start").disabled = true;
    postJson("/api/scan", { target: name }).then(function (r) {
      if (r.status === 202) {
        $("scan-state").textContent = "Starting the scan of " + name + "...";
        state.scan.wasRunning = true;
      } else {
        $("scan-state").textContent = "The scan did not start: " + (r.body.error || "error " + r.status);
      }
      return refreshScan();
    });
  }

  // Rescan buttons, for a repository with a registered scan target. A rescan
  // of the latest tip and a rescan of one run's commit both go to /api/scan
  // with the repository's name and, for a commit, the run's number only.
  function rescanControls(run, withCommit) {
    var box = el("div", { "class": "rescan" });
    var s = state.scan.status;
    var target = s && (s.targets || []).filter(function (t) { return t.name === state.repo; })[0];
    if (!target) return box;
    var message = el("span", { "class": "muted small", role: "status" });
    function button(label, payload, aria) {
      var b = el("button", { type: "button", "class": "secondary", "aria-label": aria }, label);
      var wait = scanWait(s, target.name);
      b.disabled = s.running || !target.enabled || wait > 0 || s.git_ok === false;
      if (s.git_ok === false) b.setAttribute("title", s.git_error);
      if (wait > 0) b.setAttribute("title", "Available in " + minutesAndSeconds(wait));
      b.addEventListener("click", function () {
        b.disabled = true;
        postJson("/api/scan", payload).then(function (r) {
          if (r.status === 202) {
            state.scan.wasRunning = true;
            window.location.hash = M.href("runs", {});
          } else {
            message.textContent = "The rescan did not start: " + (r.body.error || "error " + r.status);
          }
        });
      });
      return b;
    }
    box.appendChild(button("Rescan", { target: target.name, rescan: true }, "Rescan the tip of " + target.branch));
    if (withCommit && run && run.kind === "scheduled") {
      box.appendChild(button("Rescan this commit", { target: target.name, run_id: run.id }, "Scan commit " + run.commit.slice(0, 12) + " again"));
    }
    box.appendChild(message);
    return box;
  }

  function withScanStatus() {
    return api("/api/scan/status").then(function (s) { state.scan.status = s; state.scan.fetchedAt = Date.now(); },
      function () { state.scan.status = null; });
  }

  function renderRuns(params) {
    refreshScan();
    status("Loading...");
    $("run-detail").hidden = true;
    var detail = params.run ? api("/api/run", { repo: state.repo, run: params.run }).then(function (res) { runDetail(res.run); }) : Promise.resolve();
    var list = api("/api/runs", { repo: state.repo, limit: "100", offset: params.offset }).then(function (res) {
      status("");
      var body = clear($("runs-table").tBodies[0]);
      res.runs.forEach(function (r) {
        var cls = r.outcome === "passed" ? "status-pass" : (r.outcome === "scan_error" ? "status-error" : "status-fail");
        // A scan error has no results: its counts are not zero, they are unknown.
        var num = function (v) { return el("td", { "class": "num" }, r.outcome === "scan_error" ? "-" : String(v)); };
        var row = el("tr", { "class": String(r.id) === params.run ? "selected" : null },
          el("td", null, internalLink(M.href("runs", { run: r.id }), String(r.id), "Show the detail of run " + r.id)),
          el("td", null, fmtTime(r.scanned_at)), el("td", null, r.kind), el("td", { "class": "mono" }, r.ref),
          el("td", { "class": "mono", title: r.commit }, r.commit.slice(0, 10)),
          el("td", { "class": cls }, r.status.label + (r.rescanned ? " (rescanned)" : "")),
          num(r.by_severity.ERROR), num(r.by_severity.WARNING), num(r.by_severity.INFO), num(r["new"]), num(r.new_blocking),
          num(r.stale), num(r.baseline_size), num(r.suppressions.total), num(r.unscanned.skipped + r.unscanned.errored));
        body.appendChild(row);
      });
      pager($("runs-pager"), res, "runs", params);
      var deleted = clear($("runs-deleted"));
      var d = res.deletions || { count: 0, items: [] };
      if (d.count) {
        var last = d.items[0];
        deleted.appendChild(document.createTextNode(plural(d.count, "run deleted", "runs deleted") + " with shoalscan history delete-run" +
          (last ? "; the latest, run " + last.run_id + " (" + last.kind + " at " + String(last.commit_sha).slice(0, 10) + ", " + last.findings +
            " findings), by " + last.deleted_by + " on " + fmtTime(last.deleted_at) : "") + "."));
      }
    });
    return Promise.all([detail, list]);
  }

  function runNote(id, prefix) { return prefix + " in run " + id + ". "; }

  function renderStale(params) {
    status("Loading...");
    return api("/api/stale", { repo: state.repo, run: params.run }).then(function (res) {
      status("");
      $("stale-note").textContent = runNote(res.run, plural(res.total, "stale baseline entry", "stale baseline entries")) +
        "These no longer match a finding: remove them from the baseline.";
      var body = clear($("stale-table").tBodies[0]);
      res.entries.forEach(function (e) {
        body.appendChild(el("tr", null, el("td", { "class": "path mono" }, e.path), el("td", { "class": "mono" }, e.rule),
          el("td", { "class": "mono" }, e.fingerprint), el("td", null, e.issue), el("td", null, e.reason)));
      });
    });
  }

  function renderFiles(params) {
    status("Loading...");
    return api("/api/files", { repo: state.repo, run: params.run, kind: params.kind }).then(function (res) {
      status("");
      $("files-note").textContent = runNote(res.run, plural(res.total, "file", "files")) +
        "Rules did not see all of these files, so findings in them may be missing.";
      var kinds = clear($("files-kinds"));
      kinds.appendChild(el("li", null, internalLink(M.href("files", { run: res.run }), "All", "Show every kind", params.kind ? "chip" : "chip active")));
      M.FILE_KINDS.forEach(function (k) {
        if (!res.counts[k]) return;
        kinds.appendChild(el("li", null, internalLink(M.href("files", { run: res.run, kind: k }), FILE_KIND_LABELS[k] + " (" + res.counts[k] + ")",
          "Show " + FILE_KIND_LABELS[k].toLowerCase() + " files", params.kind === k ? "chip active" : "chip")));
      });
      var body = clear($("files-table").tBodies[0]);
      res.files.forEach(function (f) {
        var d = f.detail || {};
        var parts = [d.reason, d.type, d.why,
          d.unparsed_percent !== undefined ? d.unparsed_percent + "% unparsed" : null,
          d.overlaps_added_lines !== undefined ? "overlaps added lines: " + (d.overlaps_added_lines ? "yes" : "no") : null]
          .filter(function (x) { return typeof x === "string" || typeof x === "number"; });
        body.appendChild(el("tr", null, el("td", null, FILE_KIND_LABELS[f.kind] || f.kind), el("td", { "class": "path mono" }, f.path),
          el("td", null, parts.join("; "))));
      });
    });
  }

  function renderSuppressions(params) {
    status("Loading...");
    return api("/api/suppressions", { repo: state.repo, run: params.run }).then(function (res) {
      status("");
      $("suppressions-note").textContent = runNote(res.run, plural(res.total, "inline suppression", "inline suppressions")) +
        "Each one silences findings on its line; check that the issue it names is still open.";
      var body = clear($("suppressions-table").tBodies[0]);
      res.suppressions.forEach(function (s) {
        body.appendChild(el("tr", null, el("td", { "class": "path mono" }, s.path + ":" + s.line), el("td", { "class": "mono" }, s.rules.join(" ")),
          el("td", null, s.issue || "-"), el("td", { "class": s.valid ? "status-pass" : "status-fail" }, s.valid ? "yes" : "no: " + (s.problem || "invalid"))));
      });
    });
  }

  function renderChanges(params) {
    status("Loading...");
    return api("/api/changes", { repo: state.repo, week: params.week, change: params.change, offset: params.offset, limit: "200" }).then(function (res) {
      status("");
      $("changes-title").textContent = (res.change === "new" ? "New" : "Fixed") + " findings in the week of " + res.week;
      $("changes-note").textContent = plural(res.total, "finding", "findings") + (res.change === "new"
        ? " appeared in this week's trend runs." : " went away in this week's trend runs; each is shown as it was in the last run that had it.");
      var body = clear($("changes-table").tBodies[0]);
      res.findings.forEach(function (f) {
        body.appendChild(el("tr", null,
          el("td", null, internalLink(M.href("runs", { run: f.run }), fmtDate(f.when), "Show the detail of run " + f.run)),
          el("td", null, el("span", { "class": "sev " + f.severity }, f.severity)),
          el("td", { "class": "mono" }, safeRow(function () { return el("a", { href: M.href("rule", { rule: f.rule, run: f.run }), title: f.message }, f.rule); }, f.rule)),
          el("td", null, f.component), el("td", { "class": "path mono" }, f.path + ":" + f.line)));
      });
      pager($("changes-pager"), res, "changes", params);
    });
  }

  function renderAbout() {
    return api("/api/about").then(function (a) {
      var inUse = a.scanners_in_use || {};
      var sBody = clear($("about-scanners").tBodies[0]);
      a.scanners.forEach(function (s) {
        var used = inUse[s.name.toLowerCase()];
        sBody.appendChild(el("tr", null, el("td", null, externalLink(s.source, s.name)), el("td", null, s.role),
          el("td", { "class": "mono" }, s.version || "-"), el("td", null, s.licence || "-"),
          el("td", { "class": "mono" }, used && used.version ? used.version : (s.name === "Opengrep" ? "no runs yet" : (s.name === "cosign" ? "install only" : "not enabled")))));
      });
      var rBody = clear($("about-rules").tBodies[0]);
      a.rule_sources.forEach(function (r) {
        rBody.appendChild(el("tr", null, el("td", null, externalLink(r.source, r.name)), el("td", { "class": "mono" }, r.version || "-"),
          el("td", null, r.licence || "-"), el("td", null, r.note || "")));
      });
      var who = clear($("about-audience"));
      who.appendChild(document.createTextNode(
        "Shoalscan is for teams that want security scanning they can run themselves. That includes teams on any CI system, " +
        "teams in air-gapped or regulated environments, startups preparing for a security audit, and teams adopting scanning " +
        "on an existing codebase. See the "));
      who.appendChild(externalLink(a.shoalscan.project_url, "project README"));
      who.appendChild(document.createTextNode(" for the full list, and for when another tool may suit you better."));
      var p = clear($("about-project"));
      p.appendChild(document.createTextNode("Shoalscan " + a.shoalscan.version + " is open source under the "));
      p.appendChild(externalLink(a.shoalscan.licence_url, "Apache License 2.0"));
      p.appendChild(document.createTextNode(". Source code, issues and documentation: "));
      p.appendChild(externalLink(a.shoalscan.project_url, a.shoalscan.project_url));
      p.appendChild(document.createTextNode("."));
    });
  }

  // ------------------------------------------------------------ users

  function changeUser(email, action) {
    postJson("/api/users/change", { email: email, action: action }).then(function (r) {
      $("users-message").textContent = r.status === 200 ? "" : (r.body.error || "error " + r.status);
      renderUsers();
    });
  }

  function renderUsers() {
    return api("/api/users").then(function (res) {
      var p = res.provider;
      $("users-provider").textContent = "People sign in through " + p.name + " (" + p.issuer + "). Admins are those whose ID token's " +
        p.admin_claim + " claim holds " + p.admin_value + "; that is set at the provider, not here.";
      var body = clear($("users-table").tBodies[0]);
      res.users.forEach(function (u) {
        var actions = el("td", { "class": "actions" });
        if (u.email !== state.user) {
          if (u.allowed) actions.appendChild(configAction("Take back access", "Take back the access of " + u.email, function () { changeUser(u.email, "disallow"); }));
          actions.appendChild(configAction(u.disabled ? "Enable" : "Disable", (u.disabled ? "Enable " : "Disable ") + u.email,
            function () { changeUser(u.email, u.disabled ? "enable" : "disable"); }));
        }
        body.appendChild(el("tr", null, el("td", { "class": "mono" }, u.email), el("td", null, u.status),
          el("td", null, u.last_login_at ? fmtTime(u.last_login_at) : "never"),
          el("td", null, fmtDate(u.added_at) + " by " + u.added_by), actions));
      });
      if (!res.users.length) body.appendChild(el("tr", null, el("td", { colspan: "5", "class": "empty" }, "Nobody yet.")));
      var events = clear($("users-events").tBodies[0]);
      res.events.forEach(function (e) {
        events.appendChild(el("tr", null, el("td", null, fmtTime(e.at)), el("td", null, e.who), el("td", { "class": "mono" }, e.user),
          el("td", null, e.action + (e.detail ? ": " + e.detail : ""))));
      });
    });
  }

  function submitUser(ev) {
    ev.preventDefault();
    var e = ev.target.elements;
    postJson("/api/users/allow", { email: e.email.value.trim() }).then(function (r) {
      if (r.status !== 200) { $("users-message").textContent = r.body.error || "error " + r.status; return; }
      e.email.value = "";
      $("users-message").textContent = r.body.email + " may now sign in, as a member.";
      renderUsers();
    });
  }

  // ------------------------------------------------------------ configuration

  var config = { page: null, editing: null, removing: null };

  function configMessage(text, isError) {
    var p = $("config-message");
    p.textContent = text || "";
    p.className = isError ? "error" : "muted";
  }

  function sourceText(s) {
    if (s.kind === "url") return s.url;
    if (s.kind === "mirror") return "mirror: " + s.mirror;
    return "local clone " + (s.clone || "") + " (set by hand)";
  }

  function showForm(t) {
    var f = $("config-form");
    var e = f.elements;
    config.editing = t ? t.name : null;
    $("config-form-title").textContent = t ? "Edit " + t.name : "Add a repository";
    $("config-error").textContent = "";
    e.name.value = t ? t.name : "";
    e.name.readOnly = !!t;
    var kind = t ? t.source.kind : "url";
    Array.prototype.forEach.call(e.kind, function (r) { r.checked = r.value === kind; });
    $("config-kind-clone").hidden = kind !== "clone";
    e.url.value = t && t.source.kind === "url" ? t.source.url : "";
    clear(e.mirror);
    config.page.mirrors.forEach(function (m) {
      var opt = el("option", { value: m }, m);
      if (t && t.source.mirror === m) opt.selected = true;
      e.mirror.appendChild(opt);
    });
    $("config-hosts").textContent = "Allowed hosts: " + config.page.allowed_hosts.join(", ") +
      ". Only public repositories can be cloned from a URL; for a private one, ask the server's owner to register a local mirror." +
      (config.page.mirrors.length ? "" : " No mirrors are registered.");
    e.branch.value = t ? t.branch : "main";
    e.enabled.checked = t ? t.enabled : true;
    e.nightly.checked = t ? t.nightly : true;
    e.policy.value = t && t.policy ? t.policy : "";
    e.policy.disabled = !!(t && !t.policy_editable);
    $("config-policy-note").textContent = t && !t.policy_editable
      ? "This repository's configuration file is set by hand in scan_targets.toml."
      : "Checked with Shoalscan's configuration rules before it is saved. The baseline's location is managed for you, so a baseline key is refused.";
    showScanners(t);
    f.hidden = false;
    e.name.focus();
  }

  var SCANNER_NAMES = { opengrep: "Opengrep", gitleaks: "Gitleaks", hadolint: "Hadolint", zizmor: "zizmor", trivy: "Trivy" };

  function scannerLabel(name) { return SCANNER_NAMES[name] || name; }

  // The Scanners fieldset: "as the policy says" leaves the choice to the policy text (or the
  // repository's own .shoalscan.toml); "choose here" sets it from the checkboxes.
  function showScanners(t) {
    var e = $("config-form").elements;
    var handSet = !!(t && !t.policy_editable);
    var chosen = t && t.scanners;
    var mode = chosen ? "choose" : "policy";
    Array.prototype.forEach.call(e.scanner_mode, function (r) { r.checked = r.value === mode; r.disabled = handSet; });
    var ticked = chosen || (t && t.policy_scanners) || ["opengrep"];
    var list = clear($("config-scanner-list"));
    config.page.scanners.forEach(function (s) {
      var box = el("input", { type: "checkbox", name: "scanner", value: s.name });
      box.checked = ticked.indexOf(s.name) >= 0;
      var note = (s.version ? " " + s.version : "") + (s.installed ? "" : " (not installed on this server; run shoalscan install)");
      list.appendChild(el("label", { "class": "check" }, box, " " + scannerLabel(s.name) + note));
    });
    updateScannersNote();
  }

  function updateScannersNote() {
    var e = $("config-form").elements;
    var t = config.editing ? config.page.targets.filter(function (x) { return x.name === config.editing; })[0] : null;
    var handSet = !!(t && !t.policy_editable);
    var choose = !handSet && Array.prototype.some.call(e.scanner_mode, function (r) { return r.checked && r.value === "choose"; });
    Array.prototype.forEach.call($("config-scanner-list").querySelectorAll("input"), function (b) { b.disabled = !choose; });
    var note;
    if (handSet) {
      note = "This repository's configuration file is set by hand in scan_targets.toml; its scanners are set there.";
    } else if (!choose) {
      note = e.policy.value.trim()
        ? "The policy text decides: its scanners key, or Opengrep alone when it has none."
        : "With no policy text, each scan reads the repository's own .shoalscan.toml, which decides (Opengrep alone by default).";
    } else {
      note = "Each scan runs the scanners ticked here." + (e.policy.value.trim() ? ""
        : " With no policy text, this gives the repository a policy of its own that sets only the scanners: its own .shoalscan.toml no longer applies.");
    }
    $("config-scanners-note").textContent = note;
  }

  function chosenScanners(e) {
    var choose = Array.prototype.some.call(e.scanner_mode, function (r) { return r.checked && r.value === "choose" && !r.disabled; });
    if (!choose) return null;
    return Array.prototype.filter.call($("config-scanner-list").querySelectorAll("input"), function (b) { return b.checked; })
      .map(function (b) { return b.value; });
  }

  function submitConfig(ev) {
    ev.preventDefault();
    var e = ev.target.elements;
    var kind = Array.prototype.filter.call(e.kind, function (r) { return r.checked; }).map(function (r) { return r.value; })[0];
    var source = kind === "url" ? { kind: "url", url: e.url.value } : (kind === "mirror" ? { kind: "mirror", mirror: e.mirror.value } : { kind: "clone" });
    postJson("/api/config/target", {
      original: config.editing, name: e.name.value, source: source, branch: e.branch.value,
      enabled: e.enabled.checked, nightly: e.nightly.checked, policy: e.policy.disabled ? "" : e.policy.value,
      scanners: chosenScanners(e)
    }).then(function (r) {
      if (r.status === 200) {
        $("config-form").hidden = true;
        configMessage("Saved " + r.body.saved + ".");
        renderConfig();
      } else {
        $("config-error").textContent = r.body.error || "error " + r.status;
      }
    });
  }

  function configAction(label, aria, handler) {
    var b = el("button", { type: "button", "class": "secondary small-button", "aria-label": aria }, label);
    b.addEventListener("click", handler);
    return b;
  }

  function showBaseline(name) {
    api("/api/config/baseline", { target: name }).then(function (b) {
      var box = $("config-baseline");
      box.hidden = false;
      $("config-baseline-title").textContent = "Baseline of " + name + " (read-only)";
      $("config-baseline-note").textContent = b.found
        ? plural(b.size, "accepted finding", "accepted findings") + " in " + b.location + (b.size > b.entries.length ? "; the first " + b.entries.length + " are shown." : ".")
        : "No baseline file yet at " + b.location + ": every finding counts as new.";
      $("config-baseline-command").textContent = b.command;
      var body = clear($("config-baseline-table").tBodies[0]);
      b.entries.forEach(function (x) {
        body.appendChild(el("tr", null, el("td", { "class": "path mono" }, x.path), el("td", { "class": "mono" }, x.rule), el("td", null, x.issue), el("td", null, x.reason)));
      });
    }, function (err) { configMessage("Could not read the baseline: " + err.message, true); });
  }

  function renderConfig() {
    status("Loading...");
    return api("/api/config").then(function (page) {
      status("");
      config.page = page;
      var body = clear($("config-table").tBodies[0]);
      page.targets.forEach(function (t) {
        var last = t.last_run;
        var lastCell = last ? safeRow(function () {
          return internalLink(M.href("runs", { repo: t.name, run: last.id }), last.status.label + ", " + fmtDate(last.scanned_at), "Open the latest run of " + t.name);
        }, last.status.label) : "never";
        body.appendChild(el("tr", null,
          el("td", { "class": "mono" }, t.name), el("td", { "class": "path mono" }, sourceText(t.source)), el("td", { "class": "mono" }, t.branch),
          el("td", null, t.enabled ? "yes" : "no"), el("td", null, t.nightly ? "yes" : "no"), el("td", null, lastCell),
          el("td", null, configAction(t.baseline.found ? String(t.baseline.size) : "none", "Show the baseline of " + t.name, function () { showBaseline(t.name); })),
          el("td", { "class": "actions" },
            configAction("Edit", "Edit " + t.name, function () { showForm(t); }),
            configAction(t.enabled ? "Disable" : "Enable", (t.enabled ? "Disable " : "Enable ") + t.name, function () {
              postJson("/api/config/enable", { name: t.name, enabled: !t.enabled }).then(function (r) {
                if (r.status === 200) renderConfig(); else configMessage(r.body.error || "error " + r.status, true);
              });
            }),
            configAction("Remove", "Remove " + t.name, function () {
              config.removing = t.name;
              $("config-remove-title").textContent = "Remove " + t.name + "?";
              $("config-remove-name").value = "";
              $("config-remove").hidden = false;
              $("config-remove-name").focus();
            }),
            t.enabled ? configAction("Run now", "Scan " + t.name + " now", function () {
              postJson("/api/scan", { target: t.name }).then(function (r) {
                configMessage(r.status === 202 ? "Scanning " + t.name + "; follow it on the Runs page." : "The scan did not start: " + (r.body.error || "error " + r.status), r.status !== 202);
              });
            }) : null)));
      });
      if (!page.targets.length) body.appendChild(el("tr", null, el("td", { colspan: "8", "class": "empty" }, "No repositories yet. Add one to start scanning.")));
      var changes = clear($("config-changes").tBodies[0]);
      page.changes.forEach(function (c) {
        var what = Object.keys(c.diff || {}).map(function (k) {
          var pair = c.diff[k];
          if (k === "policy_sha256") return "policy " + (pair[0] ? "changed" : "added");
          return k + ": " + JSON.stringify(pair[0]) + " \u2192 " + JSON.stringify(pair[1]);
        }).join("; ");
        changes.appendChild(el("tr", null, el("td", null, fmtTime(c.changed_at)), el("td", null, c.who), el("td", { "class": "mono" }, c.target),
          el("td", null, c.action), el("td", { "class": "small" }, what,
            c.policy_diff ? el("details", null, el("summary", null, "Policy diff"), el("pre", { "class": "scan-log" }, c.policy_diff)) : null)));
      });
    });
  }

  var RENDER = {
    overview: renderOverview, findings: renderFindings, finding: renderFinding, rule: renderRule, runs: renderRuns, stale: renderStale,
    files: renderFiles, suppressions: renderSuppressions, changes: renderChanges, config: renderConfig, users: renderUsers,
    about: renderAbout
  };

  function selectRepo(name) {
    state.repo = name;
    M.setRepo(name);
    Array.prototype.forEach.call($("repo").options, function (o) { o.selected = o.value === name; });
    try { window.localStorage.setItem("shoalscan.repo", name); } catch (e) { /* storage may be unavailable */ }
  }

  function route() {
    var r = M.parseRoute(window.location.hash);
    var names = state.repos.map(function (x) { return x.name; });
    if (r.params.repo && names.indexOf(r.params.repo) >= 0 && r.params.repo !== state.repo) selectRepo(r.params.repo);
    var params = Object.assign({}, r.params);
    delete params.repo;
    showView(r.view);
    if (r.view !== "about" && r.view !== "config" && !state.repo) {
      status("No runs recorded yet. Record one with `shoalscan record`.");
      return;
    }
    RENDER[r.view](params).catch(function (err) { status("Could not load this page: " + err.message); });
  }

  // ------------------------------------------------------------ start

  function start() {
    $("logout").addEventListener("click", logout);
    $("scan-form").addEventListener("submit", startScan);
    $("bulk-review").addEventListener("submit", submitBulk);
    $("review-form").addEventListener("submit", submitReview);
    fillSelect($("bulk-review").elements.status, M.USER_STATUSES.map(function (s) { return { value: s, label: M.REVIEW_LABELS[s] }; }), "", "Choose a status");
    $("bulk-suggest").addEventListener("click", useSuggestion);
    $("findings-all").addEventListener("change", function (ev) {
      document.querySelectorAll("#findings-table tbody input[type=checkbox]").forEach(function (b) {
        if (b.checked !== ev.target.checked) { b.checked = ev.target.checked; b.dispatchEvent(new Event("change")); }
      });
    });
    $("config-add").addEventListener("click", function () { showForm(null); });
    $("config-cancel").addEventListener("click", function () { $("config-form").hidden = true; });
    $("config-form").addEventListener("submit", submitConfig);
    $("config-form").addEventListener("change", function (ev) { if (ev.target.name === "scanner_mode") updateScannersNote(); });
    $("config-form").elements.policy.addEventListener("input", updateScannersNote);
    $("config-remove-cancel").addEventListener("click", function () { $("config-remove").hidden = true; });
    $("config-remove-confirm").addEventListener("click", function () {
      postJson("/api/config/remove", { name: config.removing, confirm: $("config-remove-name").value }).then(function (r) {
        if (r.status === 200) { $("config-remove").hidden = true; configMessage("Removed " + r.body.removed + ". Its history stays."); renderConfig(); }
        else configMessage(r.body.error || "error " + r.status, true);
      });
    });
    $("scan-target").addEventListener("change", paintScanButton);
    state.scan.ticker = window.setInterval(paintScanButton, 1000);
    $("repo").addEventListener("change", function (ev) {
      selectRepo(ev.target.value);
      var r = M.parseRoute(window.location.hash);
      // Run ids belong to one repository, so a repository switch keeps only the view.
      window.location.hash = M.href(["findings", "runs", "about"].indexOf(r.view) >= 0 ? r.view : "overview", {});
    });
    $("heat-toggle").addEventListener("click", function () {
      state.heatAll = !state.heatAll;
      if (state.overview) heatmap($("chart-components"), state.overview.by_component);
    });
    $("filters").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var f = ev.target.elements;
      var params = { run: ev.target.getAttribute("data-run") || null };
      ["severity", "rule", "component", "path", "age", "review"].forEach(function (k) { if (f[k].value) params[k] = f[k].value; });
      if (f["new"].checked) params["new"] = "1";
      if (f.new_blocking.checked) params.new_blocking = "1";
      if (f.blocking.checked) params.blocking = "1";
      if (f.sort.value) params.sort = f.sort.value;
      if (ev.target.getAttribute("data-baselined")) params.baselined = "1";
      try {
        window.location.hash = M.href("findings", params);
      } catch (e) {
        status("That filter is not valid: " + e.message);
      }
    });
    $("filters").addEventListener("reset", function () {
      window.setTimeout(function () { window.location.hash = M.href("findings", {}); }, 0);
    });
    window.addEventListener("hashchange", route);
    api("/api/config").then(function () { $("nav-config").hidden = false; }, function () { $("nav-config").hidden = true; });
    $("users-form").addEventListener("submit", submitUser);
    Promise.all([api("/api/session"), api("/api/repos")]).then(function (res) {
      state.csrf = res[0].csrf;
      state.user = res[0].user;
      $("nav-users").hidden = res[0].role !== "admin";
      $("whoami").textContent = res[0].user + " (" + res[0].role + ")";
      state.repos = res[1].repos;
      var names = state.repos.map(function (r) { return r.name; });
      var select = clear($("repo"));
      names.forEach(function (n) { select.appendChild(el("option", { value: n }, n)); });
      var saved = null;
      try { saved = window.localStorage.getItem("shoalscan.repo"); } catch (e) { /* ignore */ }
      var fromHash = M.parseRoute(window.location.hash).params.repo;
      var pick = names.indexOf(fromHash) >= 0 ? fromHash : (names.indexOf(saved) >= 0 ? saved : (names[0] || null));
      if (pick) selectRepo(pick);
      route();
    }).catch(function (err) { status("Could not start the dashboard: " + err.message); });
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start);
  else start();
})();
