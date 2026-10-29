"""Page builder: fills ``{{slot}}`` markers in a template and records ground truth.

Each planted value is recorded with its type, canonical value, how it is shown,
the CSS selector of the element holding it, and the channel it sits in.
"""

from __future__ import annotations

import html
import re
import urllib.parse
from dataclasses import asdict, dataclass, field
from typing import Any

from .images import render_text_png

# Channels: where a value sits on the page. Detect/sanitize must cover each.
CHANNELS = frozenset(
    {
        "input_value",  # value attribute of <input>, or <textarea> content
        "input_hidden",  # <input type=hidden> value
        "text",  # visible text node(s)
        "text_split",  # one value split over several sibling elements
        "attribute",  # aria-label, alt, title, placeholder, data-* (see `attribute`)
        "url_query",  # query parameter of an href/src/action URL (see `attribute`)
        "image",  # pixels of an <img>
        "canvas",  # pixels drawn on a <canvas> (video tiles, screen share)
    }
)

_SLOT_RE = re.compile(r"\{\{([a-z0-9_]+)\}\}")


@dataclass
class TruthItem:
    id: str
    type: str
    value: str  # canonical form (e.g. digits only); validates with gen.values
    shown: str  # exactly as rendered (formatting, separators, obfuscation)
    selector: str  # CSS selector, matches exactly one element
    channel: str
    attribute: str | None = None  # for "attribute" and "url_query" channels
    obfuscation: list[str] = field(default_factory=list)
    canary: bool = False
    box: list[int] | None = None  # [x, y, w, h] in element coordinates (canvas only)
    motion: dict[str, float] | None = None  # canvas faces: sinusoidal motion params
    asset: str | None = None  # image file the value is drawn into


class PageBuilder:
    def __init__(self, name: str) -> None:
        self.name = name
        self.slots: dict[str, str] = {}
        self.items: list[TruthItem] = []
        self.decoys: list[TruthItem] = []
        self.assets: dict[str, bytes] = {}

    def _slot(self, key: str, rendered: str) -> None:
        if key in self.slots:
            raise ValueError(f"{self.name}: slot {key!r} filled twice")
        self.slots[key] = rendered

    def _check(self, it: TruthItem) -> TruthItem:
        if it.channel not in CHANNELS:
            raise ValueError(f"{self.name}: unknown channel {it.channel!r}")
        if it.channel in ("attribute", "url_query") and not it.attribute:
            raise ValueError(f"{self.name}: {it.id} needs `attribute`")
        return it

    # ---- planted values
    def put(
        self,
        key: str,
        *,
        type: str,
        value: str,
        selector: str,
        channel: str,
        shown: str | None = None,
        attribute: str | None = None,
        canary: bool = False,
        obfuscation: list[str] | None = None,
    ) -> None:
        """Plant a value as escaped text (text, input, attribute channels)."""
        shown = value if shown is None else shown
        self._slot(key, html.escape(shown, quote=True))
        self.items.append(
            self._check(
                TruthItem(
                    id=f"{self.name}.{key}",
                    type=type,
                    value=value,
                    shown=shown,
                    selector=selector,
                    channel=channel,
                    attribute=attribute,
                    canary=canary,
                    obfuscation=obfuscation or [],
                )
            )
        )

    def put_split(
        self, key: str, *, type: str, value: str, shown: str, selector: str, parts: list[int], canary: bool = False
    ) -> None:
        """Plant a value split over adjacent <span>s with no text between them."""
        digits = shown.replace(" ", "")
        if sum(parts) != len(digits):
            raise ValueError(f"{self.name}: split parts don't cover {key}")
        spans, i = [], 0
        for n in parts:
            spans.append(f'<span class="grp">{html.escape(digits[i : i + n])}</span>')
            i += n
        self._slot(key, "".join(spans))
        self.items.append(
            self._check(TruthItem(f"{self.name}.{key}", type, value, digits, selector, "text_split", canary=canary))
        )

    def put_url_param(
        self, key: str, *, type: str, value: str, selector: str, attribute: str, shown: str | None = None
    ) -> None:
        """Plant a value as a URL-encoded query parameter value."""
        shown = value if shown is None else shown
        self._slot(key, html.escape(urllib.parse.quote(shown, safe=""), quote=True))
        self.items.append(
            self._check(TruthItem(f"{self.name}.{key}", type, value, shown, selector, "url_query", attribute))
        )

    def put_image(
        self,
        key: str,
        *,
        filename: str,
        selector: str,
        lines: list[str],
        planted: list[tuple[str, str, str]],
        style: str = "card",
        channel: str = "image",
        box: list[int] | None = None,
    ) -> None:
        """Draw ``lines`` into a PNG; ``planted`` lists (type, value, shown) drawn in it."""
        self.assets[filename] = render_text_png(lines, style=style)
        self._slot(key, html.escape(filename, quote=True))
        for n, (typ, value, shown) in enumerate(planted):
            self.items.append(
                self._check(
                    TruthItem(f"{self.name}.{key}.{n}", typ, value, shown, selector, channel, box=box, asset=filename)
                )
            )

    def face(self, key: str, *, selector: str, box: list[int], motion: dict[str, float]) -> None:
        """Record a drawn avatar face on a canvas (no slot; drawn by page JS)."""
        self.items.append(
            self._check(TruthItem(f"{self.name}.{key}", "face", "", "", selector, "canvas", box=box, motion=motion))
        )

    # ---- not sensitive
    def decoy(self, key: str, *, type: str, value: str, selector: str) -> None:
        """A look-alike that must NOT be redacted (e.g. a non-Luhn order number)."""
        self._slot(key, html.escape(value, quote=True))
        self.decoys.append(TruthItem(f"{self.name}.{key}", type, value, value, selector, "text"))

    def text(self, key: str, s: str) -> None:
        """Non-sensitive text (labels, city names), HTML-escaped."""
        self._slot(key, html.escape(s, quote=True))

    def raw(self, key: str, rendered_html: str) -> None:
        """Non-sensitive markup (config JSON, labels). Caller guarantees it's safe."""
        self._slot(key, rendered_html)

    # ---- output
    def render(self, template: str) -> str:
        used = set(_SLOT_RE.findall(template))
        missing = used - self.slots.keys()
        unused = self.slots.keys() - used
        if missing or unused:
            raise ValueError(f"{self.name}: missing slots {sorted(missing)}, unused slots {sorted(unused)}")
        for key in used:
            if template.count("{{" + key + "}}") != 1:
                raise ValueError(f"{self.name}: slot {key!r} used more than once")
        return _SLOT_RE.sub(lambda m: self.slots[m.group(1)], template)

    def truth(self, seed: int, url_path: str) -> dict[str, Any]:
        return {
            "schema": "pl.scenario_truth.draft",
            "page": self.name,
            "url_path": url_path,
            "seed": seed,
            "items": [asdict(i) for i in self.items],
            "decoys": [asdict(i) for i in self.decoys],
            "canaries": [i.value for i in self.items if i.canary],
        }
