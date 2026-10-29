"""Every scenario page renders in headless Chromium: no JS errors, no off-host
requests, every annotated element present and laid out, avatars drawn."""

from __future__ import annotations

import functools
import http.server
import json
import os
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from plscen.build import build
from plscen.pages import PAGES

pw = pytest.importorskip("playwright.sync_api", reason="browser test: install the `browser` dependency group")
pytestmark = pytest.mark.browser


@pytest.fixture(scope="module")
def site(tmp_path_factory: pytest.TempPathFactory) -> Iterator[tuple[str, Path]]:
    out = tmp_path_factory.mktemp("render")
    build(out)
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(out / "site"))
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}", out
    srv.shutdown()


@pytest.fixture(scope="module")
def browser() -> Iterator[Any]:
    with pw.sync_playwright() as p:
        b = p.chromium.launch()
        yield b
        b.close()


def _open(browser: Any, base: str, page_name: str) -> tuple[Any, list[str]]:
    problems: list[str] = []
    ctx = browser.new_context(viewport={"width": 1366, "height": 900})
    page = ctx.new_page()
    page.on("console", lambda m: problems.append(f"console {m.type}: {m.text}") if m.type == "error" else None)
    page.on("pageerror", lambda e: problems.append(f"pageerror: {e}"))
    page.on("requestfailed", lambda r: problems.append(f"requestfailed: {r.url}"))
    page.on("request", lambda r: None if r.url.startswith(base) else problems.append(f"off-host: {r.url}"))
    page.goto(f"{base}/{page_name}/", wait_until="load")
    page.wait_for_timeout(400)
    return page, problems


@pytest.mark.parametrize("name", list(PAGES))
def test_page_renders(site: tuple[str, Path], browser: Any, name: str) -> None:
    base, out = site
    page, problems = _open(browser, base, name)
    truth = json.loads((out / "truth" / f"{name}.json").read_text("utf-8"))
    for it in [*truth["items"], *truth["decoys"]]:
        info = page.evaluate(
            """(sel) => { const els = document.querySelectorAll(sel);
                 if (els.length !== 1) return {n: els.length};
                 const r = els[0].getBoundingClientRect();
                 return {n: 1, w: r.width, h: r.height, value: els[0].value ?? null}; }""",
            it["selector"],
        )
        assert info["n"] == 1, (it["id"], info)
        if it["channel"] != "input_hidden":
            assert info["w"] > 0 and info["h"] > 0, (it["id"], info)
        if it["channel"] == "input_value":
            assert it["shown"] in info["value"], it["id"]
    shots = os.environ.get("PL_SHOTS")
    if shots:
        page.screenshot(path=f"{shots}/{name}.png", full_page=True)
    assert not problems, problems
    page.context.close()


def test_video_avatars_and_share_drawn(site: tuple[str, Path], browser: Any) -> None:
    base, out = site
    page, problems = _open(browser, base, "video")
    truth = json.loads((out / "truth" / "video.json").read_text("utf-8"))
    for it in truth["items"]:
        if it["channel"] != "canvas":
            continue
        x, y, w, h = it["box"]
        # Most pixels inside the box must be drawn content, not the empty tile/background.
        drawn = page.evaluate(
            """([x, y, w, h]) => { const c = document.getElementById('call-canvas').getContext('2d');
                 const d = c.getImageData(x, y, w, h).data;
                 const bg = new Set(['17,17,17', '43,58,74', '58,47,69', '47,69,54']);
                 let n = 0;
                 for (let i = 0; i < d.length; i += 4) if (!bg.has(d[i] + ',' + d[i+1] + ',' + d[i+2])) n++;
                 return n / (d.length / 4); }""",
            [x, y, w, h],
        )
        assert drawn > 0.6, (it["id"], drawn)
    assert not problems, problems
    page.context.close()


def test_interactions(site: tuple[str, Path], browser: Any) -> None:
    base, _ = site
    page, problems = _open(browser, base, "login")
    page.click("#toggle-password")
    assert page.get_attribute("#password", "type") == "text"
    page.click("#sign-in")
    assert page.evaluate("document.body.dataset.result") == "signed-in"
    page.context.close()

    page, more = _open(browser, base, "checkout")
    page.click("#pay-now")
    assert page.evaluate("document.body.dataset.result") == "paid"
    page.context.close()

    page, even_more = _open(browser, base, "support")
    page.click("#send")
    assert page.evaluate("document.querySelectorAll('#chat-thread > li').length") == 7
    page.context.close()
    assert not (problems + more + even_more)
