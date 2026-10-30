"""Render generated pages in headless Chromium and add layout boxes to the truth.

    python -m gen.render build/synth [--limit N]

For each page: load it from a local HTTP server bound to 127.0.0.1 (no other
network), take a full-page screenshot (``<out>/shots/<page_id>.png``) and
record each item's box in page coordinates. Values drawn inside images get
the image's box offset by their ``img_box`` (scaled to the displayed size).
Needs the ``browser`` dependency group (Playwright + Chromium).
"""

from __future__ import annotations

import argparse
import functools
import http.server
import json
import threading
from pathlib import Path
from typing import Any

_BOX_JS = """(sels) => sels.map((s) => {
  const els = document.querySelectorAll(s);
  if (els.length !== 1) return {n: els.length};
  const r = els[0].getBoundingClientRect();
  return {n: 1, x: r.x + scrollX, y: r.y + scrollY, w: r.width, h: r.height,
          nw: els[0].naturalWidth || null, nh: els[0].naturalHeight || null};
})"""


class _QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        pass


def render(out: Path, limit: int | None = None) -> dict[str, Any]:
    from playwright.sync_api import sync_playwright

    manifest = json.loads((out / "manifest.json").read_text("utf-8"))
    shots = out / "shots"
    shots.mkdir(exist_ok=True)
    handler = functools.partial(_QuietHandler, directory=str(out / "pages"))
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    problems: list[str] = []
    done = 0
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch()
            ctx = browser.new_context(viewport={"width": 1280, "height": 900}, device_scale_factor=1)
            for entry in manifest["pages"][:limit]:
                pid = entry["page_id"]
                page = ctx.new_page()
                page.on("pageerror", lambda e, pid=pid: problems.append(f"{pid}: {e}"))
                page.on(
                    "request",
                    lambda r, pid=pid: None if r.url.startswith(base) else problems.append(f"{pid}: off-host {r.url}"),
                )
                page.goto(f"{base}/{pid}/", wait_until="load")
                tpath = out / "truth" / f"{pid}.json"
                truth = json.loads(tpath.read_text("utf-8"))
                every = truth["items"] + truth["decoys"]
                boxes = page.evaluate(_BOX_JS, [it["selector"] for it in every])
                for it, b in zip(every, boxes, strict=True):
                    if b["n"] != 1:
                        problems.append(f"{pid}: {it['selector']} matched {b['n']}")
                        continue
                    if it["channel"] == "image" and it.get("img_box") and b["nw"]:
                        sx, sy = b["w"] / b["nw"], b["h"] / b["nh"]
                        x, y, w, h = it["img_box"]
                        it["box"] = [b["x"] + x * sx, b["y"] + y * sy, w * sx, h * sy]
                    else:
                        it["box"] = [b["x"], b["y"], b["w"], b["h"]]
                truth["screenshot"] = f"shots/{pid}.png"
                page.screenshot(path=str(shots / f"{pid}.png"), full_page=True)
                tpath.write_text(json.dumps(truth, indent=1, ensure_ascii=False) + "\n", "utf-8")
                page.close()
                done += 1
            browser.close()
    finally:
        srv.shutdown()
    return {"rendered": done, "problems": problems}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("out", type=Path)
    ap.add_argument("--limit", type=int, default=None)
    a = ap.parse_args()
    res = render(a.out, a.limit)
    print(json.dumps(res, indent=1))
    if res["problems"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
