"use strict";
// Shows why the last login attempt failed. Nothing from the URL is ever
// written into the page: the message comes from a fixed table.
(function () {
  var messages = {
    token: "That user name and token do not match an active user.",
    limit: "Too many failed attempts. Wait 15 minutes and try again."
  };
  var reason = new URLSearchParams(window.location.search).get("error");
  var box = document.getElementById("login-error");
  if (box && Object.prototype.hasOwnProperty.call(messages, reason)) {
    box.textContent = messages[reason];
    box.hidden = false;
  }
})();
