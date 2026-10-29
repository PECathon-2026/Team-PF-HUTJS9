// Support chat behaviour: sending appends the message locally. No network.
"use strict";
(function () {
  const thread = document.getElementById("chat-thread");
  const box = document.getElementById("composer");
  let n = thread.children.length;
  document.getElementById("composer-form").addEventListener("submit", function (e) {
    e.preventDefault();
    const text = box.value.trim();
    if (!text) return;
    n += 1;
    const li = document.createElement("li");
    li.id = "msg-" + n;
    li.className = "msg me";
    const who = document.createElement("span");
    who.className = "who";
    who.textContent = "You";
    const body = document.createElement("p");
    body.className = "body";
    body.textContent = text;  // plain text only: page text is untrusted
    li.append(who, body);
    thread.append(li);
    box.value = "";
    document.body.dataset.result = "sent";
  });
})();
