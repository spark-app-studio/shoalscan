"use strict";
// The sign-in setup wizard. Everything the server says is written as text.
(function () {
  var form = document.getElementById("setup-form");
  var errorBox = document.getElementById("setup-error");
  var checks = document.getElementById("setup-checks");
  var save = document.getElementById("setup-save");
  var redirect = window.location.origin + "/oidc/callback";
  document.getElementById("setup-dex").textContent =
    "staticClients:\n  - id: shoalscan\n    name: Shoalscan\n    secret: <the client secret>\n    redirectURIs:\n      - " + redirect;

  function settings() {
    var out = {};
    ["setup_code", "display_name", "issuer", "client_id", "client_secret", "ca_file", "admin_claim", "admin_value"].forEach(function (name) {
      var value = form.elements[name].value.trim();
      if (value || name !== "ca_file") out[name] = value;
    });
    return out;
  }

  function show(result) {
    checks.textContent = "";
    errorBox.hidden = true;
    (result.checks || []).forEach(function (line) {
      var li = document.createElement("li");
      li.textContent = "✓ " + line;
      checks.appendChild(li);
    });
    if (!result.ok) {
      errorBox.textContent = result.error || "The settings could not be checked.";
      errorBox.hidden = false;
    }
  }

  function post(path) {
    return fetch(path, {
      method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json", "Accept": "application/json" },
      body: JSON.stringify(settings())
    }).then(function (res) {
      return res.json().then(function (body) { return { status: res.status, body: body }; });
    });
  }

  document.getElementById("setup-test").addEventListener("click", function (ev) {
    ev.target.disabled = true;
    save.disabled = true;
    post("/setup/test").then(function (r) {
      var ok = r.status === 200 && r.body.ok;
      show(ok ? r.body : { ok: false, error: r.body.error, checks: r.body.checks });
      save.disabled = !ok;
    }, function () { show({ ok: false, error: "The dashboard could not be reached." }); })
      .then(function () { ev.target.disabled = false; });
  });

  form.addEventListener("input", function () { save.disabled = true; });
  form.addEventListener("submit", function (ev) {
    ev.preventDefault();
    save.disabled = true;
    post("/setup/save").then(function (r) {
      if (r.status === 200 && r.body.ok) { window.location.assign("/login"); return; }
      show({ ok: false, error: r.body.error, checks: r.body.checks });
    }, function () { show({ ok: false, error: "The dashboard could not be reached." }); });
  });
})();
