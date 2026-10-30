// Developer settings behaviour. No network; deleting is an irreversible action
// the agent must ask approval for, so the page asks for confirmation text.
"use strict";
(function () {
  const result = document.getElementById("settings-result");
  document.getElementById("integrations-form").addEventListener("submit", function (e) {
    e.preventDefault();
    result.textContent = "Saved.";
    document.body.dataset.result = "saved";
  });
  document.getElementById("copy-primary").addEventListener("click", function () {
    result.textContent = "Copied.";
  });
  document.getElementById("rotate-aws").addEventListener("click", function () {
    result.textContent = "Rotation scheduled.";
  });
  document.getElementById("delete-project").addEventListener("click", function () {
    result.textContent = "Type the project name to confirm deletion.";
    document.body.dataset.result = "delete-requested";
  });
})();
