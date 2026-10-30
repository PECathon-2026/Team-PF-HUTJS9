// Checkout page behaviour. No network: payment is simulated locally.
"use strict";
(function () {
  const result = document.getElementById("checkout-result");
  document.getElementById("checkout-form").addEventListener("submit", function (e) {
    e.preventDefault();
    const digits = document.getElementById("card-number").value.replace(/\D/g, "");
    const ok = digits.length >= 15 && document.getElementById("card-cvv").value.length >= 3;
    result.textContent = ok ? "Payment authorised. Thank you!" : "Please check your card details.";
    document.body.dataset.result = ok ? "paid" : "error";
  });
  document.getElementById("pay-upi").addEventListener("click", function () {
    result.textContent = "Approve the request in your UPI app.";
  });
})();
