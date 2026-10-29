"""Deterministic PNG rendering of synthetic documents (cards, cheques, ID scans)."""

from __future__ import annotations

import io

from PIL import Image, ImageDraw, ImageFont

_STYLES = {
    # (width, height, background, foreground, font size)
    "card": (428, 270, (32, 58, 112), (240, 240, 240), 26),
    "cheque": (640, 260, (250, 246, 230), (30, 30, 60), 22),
    "document": (480, 300, (255, 255, 255), (20, 20, 20), 22),
}


def render_text_png(lines: list[str], style: str = "card") -> bytes:
    w, h, bg, fg, size = _STYLES[style]
    img = Image.new("RGB", (w, h), bg)
    draw = ImageDraw.Draw(img)
    font = ImageFont.load_default(size=size)
    draw.rounded_rectangle((4, 4, w - 5, h - 5), radius=18, outline=fg, width=2)
    y = 28
    for line in lines:
        draw.text((28, y), line, fill=fg, font=font)
        y += int(size * 1.6)
    buf = io.BytesIO()
    # No text chunks, no timestamps: identical bytes for identical input.
    img.save(buf, format="PNG", optimize=False, compress_level=9)
    return buf.getvalue()
