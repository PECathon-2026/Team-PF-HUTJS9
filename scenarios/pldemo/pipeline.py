"""Data pipeline demo: build -> render -> capture -> detect -> sanitize -> vault -> leak check -> report.

    python -m pldemo.pipeline [--seed N] [--run-seed N] [--out build/demo] [--commit-dir demo-output]

Needs Chromium (Playwright). Owner: WIN.
"""

from __future__ import annotations

import argparse
import functools
import http.server
import io
import json
import random
import secrets
import shutil
import threading
from pathlib import Path
from typing import Any

from PIL import Image, ImageDraw

from plscen.build import DEFAULT_SEED, build
from plscen.pages import PAGES

from . import vault as V
from .capture import capture, find_rects
from .leak import find_leaks, strings_of
from .sanitize import attach_boxes, build_sanitized, detect_capture, issue_placeholders, redactions_json

ROOT = Path(__file__).resolve().parent.parent
DETECTOR = "python-validators"  # the C++ detect library is not used by this demo run
VISIBLE_CHANNELS = {"input_value", "text", "text_split", "image", "canvas"}
IDX_JS = "(s) => Array.from(document.querySelectorAll(s)).map(e => window.__plEls.indexOf(e))"


class _Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        pass


def redact_png(png: bytes, boxes: list[dict[str, Any]]) -> bytes:
    img = Image.open(io.BytesIO(png)).convert("RGB")
    d = ImageDraw.Draw(img)
    for b in boxes:
        x, y, w, h = b["box"]
        d.rectangle((round(x), round(y), round(x + w) - 1, round(y + h) - 1), fill=(0, 0, 0))
    out = io.BytesIO()
    img.save(out, "PNG")  # re-encoded from pixels: no text/EXIF chunks carried over
    return out.getvalue()


def png_chunks(png: bytes) -> list[str]:
    i, names = 8, []
    while i < len(png):
        n = int.from_bytes(png[i : i + 4], "big")
        names.append(png[i + 4 : i + 8].decode("latin1"))
        i += 12 + n
    return names


def black_fraction(png: bytes, rect: list[float]) -> float:
    img = Image.open(io.BytesIO(png)).convert("RGB")
    x, y, w, h = rect
    box = (max(0, int(x)), max(0, int(y)), min(img.width, int(x + w) + 1), min(img.height, int(y + h) + 1))
    if box[2] <= box[0] or box[3] <= box[1]:
        return 1.0
    px = list(img.crop(box).getdata())
    return sum(1 for p in px if max(p) < 12) / len(px)


def process_page(page: Any, base: str, name: str, truth: dict[str, Any], vault: V.Vault, rng: random.Random,
                 out: Path) -> dict[str, Any]:  # fmt: skip
    page.goto(f"{base}/{name}/", wait_until="load")
    page.wait_for_timeout(500)
    cap = capture(page)
    original = page.screenshot(full_page=True)
    dets = detect_capture(cap)
    issued = issue_placeholders(dets, rng)
    boxes = attach_boxes(page, cap, dets)
    redacted = redact_png(original, boxes)
    sanitized = build_sanitized(cap, dets, V.SITE, name, 7)
    sanitized["redactions"] = redactions_json(boxes)

    # Vault: seal every real value, then prove the binding.
    ids = [e["id"] for e in cap["elements"]]
    tests: list[dict[str, bool]] = []
    for d in dets:
        if d.drop or not d.value:
            continue
        sealed = vault.seal(d.value, d.placeholder, d.category, f"n{d.el}")
        other = f"n{ids[(ids.index(d.el) + 1) % len(ids)]}"
        tests.append(vault.binding_test(sealed, d.value, other))
    vault_ok = bool(tests) and all(all(t.values()) for t in tests)

    # Leak check over everything the AI receives (string content of the sanitized page).
    items = [it for it in truth["items"] if it["type"] != "face"]
    leaks = find_leaks(strings_of(sanitized), items)
    control = sum(1 for it in items if it["channel"] not in ("image", "canvas")
                  and find_leaks([*strings_of(cap["elements"]), cap["title"]], [it]))  # fmt: skip
    visible_nonpixel = sum(1 for it in items if it["channel"] not in ("image", "canvas"))
    png_clean = set(png_chunks(redacted)) <= {"IHDR", "IDAT", "IEND", "PLTE"}

    # Independent pixel check: every visible planted value lies under solid black.
    pixel_bad = []
    for it in items:
        if it["channel"] not in VISIBLE_CHANNELS:
            continue
        needle = "" if it["channel"] in ("image", "canvas") else it["shown"]
        fr = [black_fraction(redacted, r) for r in find_rects(page, it["selector"], needle)]
        if any(f < 0.97 for f in fr):
            pixel_bad.append(f"{it['id']}[{it['type']}/{it['channel']}:{min(fr):.2f}]")

    parent = {e["id"]: e["parent"] for e in cap["elements"]}

    def under(el: int, anc: set[int]) -> bool:  # a detection on the element itself or any descendant
        while el != -1:
            if el in anc:
                return True
            el = parent[el]
        return False

    detected_els = {d.el for d in dets}
    detected, fail_closed, misses = 0, 0, []
    for it in items:
        if it["channel"] in ("image", "canvas"):
            fail_closed += 1
        elif any(under(de, set(page.evaluate(IDX_JS, it["selector"]))) for de in detected_els):
            detected += 1
        else:
            misses.append(it["type"])
    text_all = " ".join(strings_of(sanitized))
    decoys_kept = sum(1 for dcy in truth["decoys"] if dcy["value"] in text_all)

    pdir = out / name
    pdir.mkdir(parents=True, exist_ok=True)
    (pdir / "original.png").write_bytes(original)
    (pdir / "redacted.png").write_bytes(redacted)
    (pdir / "sanitized.json").write_text(json.dumps(sanitized, indent=2, ensure_ascii=False) + "\n", "utf-8")
    return {
        "page": name, "planted": len(items), "detected": detected, "fail_closed_regions": fail_closed,
        "detections": len(dets), "placeholders": issued, "leaks": leaks, "pixel_uncovered": pixel_bad,
        "png_clean": png_clean, "vault_entries": len(tests), "vault_ok": vault_ok,
        "vault_detail": {k: sum(t[k] for t in tests) for k in (tests[0] if tests else {})},
        "decoys": f"{decoys_kept}/{len(truth['decoys'])}", "control_found_in_original": f"{control}/{visible_nonpixel}",
        "misses": sorted(set(misses)), "sanitized": sanitized, "truth_items": items, "cap": cap,
        "dets": [{"cat": x.category, "channel": x.channel, "source": x.source, "rule": x.rule,
                  "placeholder": x.placeholder, "value": x.value, "el": x.el, "drop": x.drop} for x in dets],
        "png": {"original": original, "redacted": redacted},
    }  # fmt: skip


def run(seed: int, run_seed: int | None, out: Path, commit_dir: Path | None) -> list[dict[str, Any]]:
    from playwright.sync_api import sync_playwright

    from .report import write_reports

    if out.exists():
        shutil.rmtree(out)
    site_dir = out / "_site"
    build(site_dir, seed)
    handler = functools.partial(_Quiet, directory=str(site_dir / "site"))
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    rng = random.Random(secrets.randbits(64) if run_seed is None else run_seed)
    vault = V.Vault()
    results = []
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch()
            ctx = browser.new_context(viewport={"width": 1366, "height": 900})
            for name in PAGES:
                truth = json.loads((site_dir / "truth" / f"{name}.json").read_text("utf-8"))
                page = ctx.new_page()
                results.append(process_page(page, base, name, truth, vault, rng, out))
                page.close()
            browser.close()
    finally:
        srv.shutdown()
    write_reports(results, out, DETECTOR, vault.session)
    if commit_dir is not None:
        commit(results, out, commit_dir)
    return results


def commit(results: list[dict[str, Any]], out: Path, dest: Path) -> None:
    """Only what is safe to publish: redacted screenshots, what the AI sees, the summary table, and the
    original checkout screenshot (values appear as pixels only; DOM text is never copied)."""
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    for r in results:
        shutil.copy(out / r["page"] / "redacted.png", dest / f"{r['page']}-redacted.png")
        shutil.copy(out / r["page"] / "sanitized.json", dest / f"{r['page']}-sanitized.json")
    shutil.copy(out / "checkout" / "original.png", dest / "checkout-original.png")
    shutil.copy(out / "summary.md", dest / "summary.md")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--seed", type=int, default=DEFAULT_SEED)
    ap.add_argument("--run-seed", type=int, default=None, help="fix the placeholder numbers (default: random per run)")
    ap.add_argument("--out", type=Path, default=ROOT / "build" / "demo")
    ap.add_argument("--commit-dir", type=Path, default=None)
    a = ap.parse_args()
    res = run(a.seed, a.run_seed, a.out, a.commit_dir)
    bad = [r["page"] for r in res if r["leaks"] or r["pixel_uncovered"] or not r["vault_ok"] or not r["png_clean"]]
    for r in res:
        for k in ("leaks", "pixel_uncovered", "misses"):
            if r[k]:
                print(f"  {r['page']} {k}: {r[k]}")
    print(f"demo-pipeline: {len(res)} pages; open {a.out}/index.html; failing pages: {bad or 'none'}")
    raise SystemExit(1 if bad else 0)


if __name__ == "__main__":
    main()
