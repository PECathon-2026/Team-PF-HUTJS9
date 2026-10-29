// Login page behaviour. No network: submit is handled locally.
"use strict";
(function () {
  const pw = document.getElementById("password");
  const toggle = document.getElementById("toggle-password");
  toggle.addEventListener("click", function () {
    const show = pw.type === "password";
    pw.type = show ? "text" : "password";
    toggle.textContent = show ? "Hide" : "Show";
    toggle.setAttribute("aria-pressed", String(show));
  });
  document.getElementById("send-otp").addEventListener("click", function () {
    document.getElementById("login-result").textContent = "A new OTP has been sent.";
  });
  document.getElementById("login-form").addEventListener("submit", function (e) {
    e.preventDefault();
    const ok = document.getElementById("email").value !== "" && pw.value !== "" &&
      /^[0-9]{6}$/.test(document.getElementById("otp").value);
    document.getElementById("login-result").textContent = ok ? "Signed in." : "Please fill every field.";
    document.body.dataset.result = ok ? "signed-in" : "error";
  });
})();
