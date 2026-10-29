"""Generated pages render in headless Chromium with a box for every item."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from gen import pages as P

pytest.importorskip("playwright.sync_api", reason="browser test: install the `browser` dependency group")
pytestmark = pytest.mark.browser


def test_render_adds_boxes_and_screenshots(tmp_path: Path) -> None:
    from gen.render import render

    P.generate(tmp_path, seed=3, n=21)
    res = render(tmp_path)
    assert res == {"rendered": 21, "problems": []}
    for f in (tmp_path / "truth").glob("*.json"):
        t = json.loads(f.read_text("utf-8"))
        assert (tmp_path / t["screenshot"]).is_file()
        for it in t["items"] + t["decoys"]:
            x, y, w, h = it["box"]
            assert w > 0 and h > 0 and x >= 0 and y >= 0, it["id"]
