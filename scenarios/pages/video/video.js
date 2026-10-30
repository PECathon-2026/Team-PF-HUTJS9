// Video call: draws synthetic cartoon avatars (never photos of real people)
// and a screen-share tile onto one canvas. Positions come from #call-config,
// which the ground truth also records, so face boxes are known exactly.
"use strict";
(function () {
  const cfg = JSON.parse(document.getElementById("call-config").textContent);
  const canvas = document.getElementById("call-canvas");
  const ctx = canvas.getContext("2d");
  const [TW, TH] = cfg.tile;
  const share = new Image();
  let shareReady = false;
  share.onload = function () { shareReady = true; };
  share.src = canvas.dataset.shareSrc;
  let cameraOn = true;
  const t0 = performance.now();

  function drawFace(f, t) {
    const dx = f.amp_x * Math.sin((2 * Math.PI * t) / f.period_ms);
    const cx = f.cx + dx, cy = f.cy;
    // shoulders
    ctx.fillStyle = f.shirt;
    ctx.beginPath();
    ctx.ellipse(cx, cy + f.ry + 70, f.rx * 2.1, 80, 0, Math.PI, 2 * Math.PI);
    ctx.fill();
    // neck
    ctx.fillStyle = f.skin;
    ctx.fillRect(cx - f.rx * 0.35, cy + f.ry * 0.7, f.rx * 0.7, 30);
    // hair back
    ctx.fillStyle = f.hair;
    ctx.beginPath();
    ctx.ellipse(cx, cy - f.ry * 0.12, f.rx * 1.08, f.ry, 0, 0, 2 * Math.PI);
    ctx.fill();
    // head
    ctx.fillStyle = f.skin;
    ctx.beginPath();
    ctx.ellipse(cx, cy, f.rx, f.ry, 0, 0, 2 * Math.PI);
    ctx.fill();
    // fringe
    ctx.fillStyle = f.hair;
    ctx.beginPath();
    ctx.ellipse(cx, cy - f.ry * 0.78, f.rx * 0.95, f.ry * 0.34, 0, Math.PI, 2 * Math.PI);
    ctx.fill();
    // eyes (blink briefly every blink_ms)
    const blink = (t % f.blink_ms) < 120;
    const ey = cy - f.ry * 0.12, ex = f.rx * 0.38;
    for (const s of [-1, 1]) {
      ctx.fillStyle = "#fff";
      ctx.beginPath();
      ctx.ellipse(cx + s * ex, ey, f.rx * 0.2, blink ? 1.5 : f.ry * 0.1, 0, 0, 2 * Math.PI);
      ctx.fill();
      if (!blink) {
        ctx.fillStyle = "#2b1d14";
        ctx.beginPath();
        ctx.arc(cx + s * ex, ey, f.rx * 0.09, 0, 2 * Math.PI);
        ctx.fill();
      }
      // brows
      ctx.strokeStyle = f.hair;
      ctx.lineWidth = 4;
      ctx.beginPath();
      ctx.moveTo(cx + s * ex - f.rx * 0.18, ey - f.ry * 0.2);
      ctx.lineTo(cx + s * ex + f.rx * 0.18, ey - f.ry * 0.22);
      ctx.stroke();
    }
    // nose
    ctx.strokeStyle = "rgba(0,0,0,0.35)";
    ctx.lineWidth = 3;
    ctx.beginPath();
    ctx.moveTo(cx, ey + 6);
    ctx.lineTo(cx - 5, cy + f.ry * 0.22);
    ctx.lineTo(cx + 3, cy + f.ry * 0.24);
    ctx.stroke();
    // mouth
    ctx.strokeStyle = "#7a2e2e";
    ctx.lineWidth = 4;
    ctx.beginPath();
    ctx.arc(cx, cy + f.ry * 0.38, f.rx * 0.32, 0.15 * Math.PI, 0.85 * Math.PI);
    ctx.stroke();
  }

  function frame(now) {
    const t = now - t0;
    ctx.fillStyle = "#111";
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    cfg.faces.forEach(function (f, i) {
      const x0 = (i % 2) * TW, y0 = Math.floor(i / 2) * TH;
      ctx.fillStyle = ["#2b3a4a", "#3a2f45", "#2f4536"][i % 3];
      ctx.fillRect(x0 + 2, y0 + 2, TW - 4, TH - 4);
      if (cameraOn || i !== 0) {
        ctx.save();
        ctx.beginPath();
        ctx.rect(x0 + 2, y0 + 2, TW - 4, TH - 4);
        ctx.clip();
        drawFace(f, t);
        ctx.restore();
      }
    });
    if (shareReady) ctx.drawImage(share, TW, TH, TW, TH);
    requestAnimationFrame(frame);
  }
  requestAnimationFrame(frame);

  document.getElementById("camera").addEventListener("click", function (e) {
    cameraOn = !cameraOn;
    e.target.textContent = cameraOn ? "Stop video" : "Start video";
    e.target.setAttribute("aria-pressed", String(!cameraOn));
  });
  document.getElementById("mute").addEventListener("click", function (e) {
    const muted = e.target.getAttribute("aria-pressed") !== "true";
    e.target.setAttribute("aria-pressed", String(muted));
    e.target.textContent = muted ? "Unmute" : "Mute";
  });
  document.getElementById("leave").addEventListener("click", function () {
    document.body.dataset.result = "left";
  });
})();
