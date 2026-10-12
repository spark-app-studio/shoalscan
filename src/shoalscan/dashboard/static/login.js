"use strict";
// Shows why the last sign-in failed. Nothing from the URL is ever written
// into the page: the message comes from a fixed table.
(function () {
  var messages = {
    not_allowed: "You signed in, but you have not been given access to this dashboard. Ask an admin to allow your email address.",
    disabled: "Your access to this dashboard is disabled. Ask an admin.",
    unverified: "Your identity provider did not confirm your email address, so the dashboard cannot let you in.",
    no_email: "Your identity provider did not send an email address. Ask its administrator to include the email scope.",
    other_account: "This email address is tied to a different account at your identity provider.",
    denied: "The sign-in was cancelled at your identity provider.",
    state: "That sign-in had expired or was not started here. Try again.",
    provider: "The identity provider could not be reached, or its answer could not be trusted. Try again, or ask an admin.",
    limit: "Too many failed sign-ins. Wait 15 minutes and try again.",
    starts: "Too many sign-ins were started from your network address. Wait a minute and try again.",
    busy: "The dashboard has had too many sign-ins in the last few minutes. Wait a few minutes and try again."
  };
  var reason = new URLSearchParams(window.location.search).get("error");
  var box = document.getElementById("login-error");
  if (box && Object.prototype.hasOwnProperty.call(messages, reason)) {
    box.textContent = messages[reason];
    box.hidden = false;
  }
})();
