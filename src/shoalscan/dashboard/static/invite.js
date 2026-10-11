"use strict";
// Uses the invite in this page's fragment (never sent to the server on page
// load, so it stays out of logs and Referer headers) and shows the new token
// once. Text from the server is only ever written as text.
(function () {
  var code = window.location.hash.slice(1);
  var error = document.getElementById("invite-error");
  function fail(text) { error.textContent = text; error.hidden = false; }
  // Take the code out of the address bar and the history at once.
  history.replaceState(null, "", "/invite");
  if (!/^[A-Za-z0-9_-]{20,128}$/.test(code)) {
    document.getElementById("invite-start").hidden = true;
    fail("This link has no invite in it. Ask an admin for a new one.");
    return;
  }
  document.getElementById("invite-accept").addEventListener("click", function (ev) {
    ev.target.disabled = true;
    fetch("/invite", {
      method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json", "Accept": "application/json" },
      body: JSON.stringify({ invite: code })
    }).then(function (res) {
      return res.json().then(function (body) { return { ok: res.ok, body: body }; });
    }).then(function (r) {
      if (!r.ok) { fail(r.body.error || "This invite is not valid."); return; }
      code = "";
      document.getElementById("invite-start").hidden = true;
      document.getElementById("name").value = r.body.name;
      document.getElementById("token").value = r.body.token;
      document.getElementById("invite-done").hidden = false;
    }, function () { fail("The dashboard could not be reached."); ev.target.disabled = false; });
  });
  document.getElementById("invite-show").addEventListener("click", function () {
    var t = document.getElementById("token");
    t.type = t.type === "password" ? "text" : "password";
  });
})();
