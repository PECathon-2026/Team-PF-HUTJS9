"""Detect over a captured page, issue placeholders, build the sanitized page the AI would get
(sanitized_page.v1) and the redaction boxes. Owner: WIN. Python twin of daemons/core/{detect,sanitize}.
"""

from __future__ import annotations

import math
import random
import re
from dataclasses import dataclass, field
from typing import Any

from . import detect as D
from .capture import range_rects

ATTR_SCAN = {"aria-label", "aria-description", "title", "placeholder", "alt", "href", "src", "action", "content"}
URL_ATTRS = {"href", "src", "action"}
MARGIN = 4.0
WIDTH_STEP = 32.0
SKIP_TAGS = {"html", "head", "meta", "title", "body", "option"}


@dataclass
class Detection:
    el: int
    channel: str  # text | input_value | attr:<name>
    child: int | None  # childNodes index (text channel)
    begin: int  # offsets in the ORIGINAL channel string
    end: int
    category: str
    rule: str
    source: str  # checksum | pattern | structural | name_dictionary | split_join
    value: str
    drop: bool = False  # extra piece of a split value: text removed, no placeholder of its own
    placeholder: str = ""
    boxes: list[list[float]] = field(default_factory=list)


def _u16(s: str, i: int) -> int:
    return len(s[:i].encode("utf-16-le")) // 2


def _src_of(hit: D.Hit, src: list[int]) -> tuple[int, int]:
    return src[hit.begin], src[hit.end - 1] + 1


def _source(h: D.Hit) -> str:
    if h.category == "NAME":
        return "name_dictionary"
    return "checksum" if h.checksum else "pattern"


def detect_capture(cap: dict[str, Any]) -> list[Detection]:
    els = cap["elements"]
    page_otp = any("one-time-code" in e["attrs"].get("autocomplete", "") for e in els)
    by_id = {e["id"]: e for e in els}
    out: list[Detection] = []
    for e in els:
        if e["tag"] in ("html", "head", "body"):
            continue
        ac = e["attrs"].get("autocomplete", "")
        ctx = D.context_flags(e["label"], ac, page_otp)
        par = by_id.get(e["parent"])
        if (
            page_otp
            and par is not None
            and re.search(r"otp|one-time", " ".join(t["text"] for t in par["text_nodes"]), re.I)
        ):
            ctx.otp = True  # a code shown inside text that talks about an OTP (e.g. an SMS toast)
        for tn in e["text_nodes"]:
            t, src = D.normalize(tn["text"])
            for h in D.scan(t, ctx):
                b, en = _src_of(h, src)
                out.append(Detection(e["id"], "text", tn["i"], b, en, h.category, h.rule, _source(h), tn["text"][b:en]))
        val = e["value"]
        if val:
            st = D.structural(e["type"], ac, e["label"]) if e["tag"] == "input" and e["type"] != "hidden" else None
            if st:
                out.append(Detection(e["id"], "input_value", None, 0, len(val), st[0], st[1], "structural", val))
            else:
                t, src = D.normalize(val)
                for h in D.scan(t, ctx):
                    b, en = _src_of(h, src)
                    out.append(
                        Detection(e["id"], "input_value", None, b, en, h.category, h.rule, _source(h), val[b:en])
                    )
        for name, av in e["attrs"].items():
            if not (name in ATTR_SCAN or name.startswith("data-")) or not av:
                continue
            if name in URL_ATTRS:
                dt, st_, en_ = D.decode_url(av)
                t, src = D.normalize(dt)
                for h in D.scan(t, ctx):
                    b, en = st_[src[h.begin]], en_[src[h.end - 1]]
                    out.append(
                        Detection(e["id"], f"attr:{name}", None, b, en, h.category, h.rule, _source(h), av[b:en])
                    )
            else:
                t, src = D.normalize(av)
                for h in D.scan(t, ctx):
                    b, en = _src_of(h, src)
                    out.append(
                        Detection(e["id"], f"attr:{name}", None, b, en, h.category, h.rule, _source(h), av[b:en])
                    )
    out += _rejoin_split(els, out)
    return out


def _rejoin_split(els: list[dict[str, Any]], existing: list[Detection]) -> list[Detection]:
    """Values split over spans that sit side by side on screen: join them by geometry and rescan."""
    pieces = []
    for e in els:
        if not e["visible"] or e["tag"] in SKIP_TAGS or e["tag"] == "input" or len(e["text_nodes"]) != 1:
            continue
        tn = e["text_nodes"][0]
        if len(tn["text"].strip()) > 40:
            continue
        t, src = D.normalize(tn["text"])
        if t.strip():
            pieces.append((e, tn, t, src))
    pieces.sort(key=lambda p: (round((p[0]["rect"][1] + p[0]["rect"][3] / 2) / 4), p[0]["rect"][0]))
    out: list[Detection] = []
    i = 0
    while i < len(pieces):
        j = i + 1
        while j < len(pieces):
            p, q = pieces[j - 1][0]["rect"], pieces[j][0]["rect"]
            h = max(p[3], q[3])
            same_line = abs((p[1] + p[3] / 2) - (q[1] + q[3] / 2)) <= 0.5 * h
            gap = q[0] - (p[0] + p[2])
            if not same_line or gap > 0.8 * h or gap < -0.5 * h:
                break
            j += 1
        if j - i >= 2:
            joined, where = "", []
            for k in range(i, j):
                text = pieces[k][2]
                if joined and joined[-1].isalpha() != text[0].isalpha() and (joined[-1].isdigit() or text[0].isdigit()):
                    joined += " "  # a word next to digits is not part of the number
                    where.append((k - 1, -1))
                for b, ch in enumerate(text):
                    joined += ch
                    where.append((k, b))
            for h in D.scan(joined, D.Ctx()):
                first, last = where[h.begin][0], where[h.end - 1][0]
                if first == last:
                    continue
                parts = []
                for k in range(first, last + 1):
                    e, tn, t, src = pieces[k]
                    nb = where[h.begin][1] if k == first else 0
                    ne = where[h.end - 1][1] + 1 if k == last else len(t)
                    parts.append((e, tn, src[nb], src[ne - 1] + 1))
                value = "".join(tn["text"][b:en] for _, tn, b, en in parts)
                for n, (e, tn, b, en) in enumerate(parts):
                    out.append(Detection(e["id"], "text", tn["i"], b, en, h.category, h.rule, "split_join",
                                         value if n == 0 else "", drop=n > 0))  # fmt: skip
        i = j
    # A piece already fully handled by a per-node detection of the same category isn't duplicated.
    return [d for d in out if not any(x.el == d.el and x.child == d.child and x.category == d.category and x.begin <= d.begin
                                     and d.end <= x.end for x in existing)]  # fmt: skip


def issue_placeholders(dets: list[Detection], rng: random.Random) -> int:
    """[REDACTED:TYPE#nnnn]: four digits, drawn without repetition for this run. The same value
    keeps the same placeholder so the AI can tell two mentions are one thing."""
    pool = list(range(1000, 10000))
    rng.shuffle(pool)
    known: dict[tuple[str, str], str] = {}
    for d in dets:
        if d.drop:
            continue
        key = (d.category, re.sub(r"[\s.\-]", "", D.normalize(d.value)[0]).lower())
        if key not in known:
            known[key] = f"[REDACTED:{d.category}#{pool.pop()}]"
        d.placeholder = known[key]
    return len(known)


def attach_boxes(page: Any, cap: dict[str, Any], dets: list[Detection]) -> list[dict[str, Any]]:
    """Redaction boxes (page coordinates): field box for inputs, matched-text boxes for text,
    nothing for attributes (not visible). Plus fail-closed boxes over every visible image/canvas."""
    by_id = {e["id"]: e for e in cap["elements"]}
    for d in dets:
        e = by_id[d.el]
        if not e["visible"]:
            continue
        if d.channel == "input_value":
            d.boxes = [e["rect"]]
        elif d.channel == "text" and d.child is not None:
            tn = next(t for t in e["text_nodes"] if t["i"] == d.child)
            d.boxes = range_rects(page, d.el, d.child, _u16(tn["text"], d.begin), _u16(tn["text"], d.end))
    boxes: list[dict[str, Any]] = []
    for d in dets:
        for b in d.boxes:
            boxes.append({"el": d.el, "category": d.category, "placeholder": d.placeholder or None,
                          "box": _pad(b, d.channel == "input_value"), "fail_closed": False})  # fmt: skip
    for e in cap["elements"]:
        if e["tag"] in ("img", "canvas") and e["visible"]:
            boxes.append({"el": e["id"], "category": "SECRET", "placeholder": None, "box": _pad(e["rect"], True),
                          "fail_closed": True})  # fmt: skip
    return boxes


def _pad(b: list[float], field_box: bool) -> list[float]:
    x, y, w, h = b
    w2 = w + 2 * MARGIN
    if not field_box:
        w2 = math.ceil(w2 / WIDTH_STEP) * WIDTH_STEP  # fixed width steps: the box doesn't reveal the length
    return [x - MARGIN, y - MARGIN, w2, h + 2 * MARGIN]


def _replace(s: str, ds: list[Detection]) -> str:
    out, pos = "", 0
    for d in sorted(ds, key=lambda x: x.begin):
        if d.begin < pos:
            continue
        out += s[pos : d.begin] + ("" if d.drop else d.placeholder)
        pos = d.end
    return out + s[pos:]


def build_sanitized(
    cap: dict[str, Any], dets: list[Detection], site: str, page_name: str, snapshot_id: int
) -> dict[str, Any]:
    els = cap["elements"]
    by: dict[tuple[int, str, int | None], list[Detection]] = {}
    for d in dets:
        by.setdefault((d.el, d.channel, d.child), []).append(d)

    def text_of(e: dict[str, Any]) -> str:
        parts = [_replace(tn["text"], by.get((e["id"], "text", tn["i"]), [])).strip() for tn in e["text_nodes"]]
        return " ".join(p for p in parts if p)

    def attr_of(e: dict[str, Any], name: str) -> str:
        return _replace(e["attrs"].get(name, ""), by.get((e["id"], f"attr:{name}", None), []))

    for_label = {e["attrs"]["for"]: text_of(e) for e in els if e["tag"] == "label" and "for" in e["attrs"]}
    options: dict[int, list[str]] = {}
    for e in els:
        if e["tag"] == "option":
            options.setdefault(e["parent"], []).append(text_of(e))
    out_els: list[dict[str, Any]] = []
    for e in els:
        if e["tag"] in SKIP_TAGS or not e["visible"] or e["role"] == "hidden":
            continue
        phs = sorted({d.placeholder for d in dets if d.el == e["id"] and d.placeholder})
        if e["tag"] in ("input", "textarea", "select"):
            name = for_label.get(e["attrs"].get("id", "")) or attr_of(e, "aria-label") or attr_of(e, "placeholder") \
                or attr_of(e, "title")  # fmt: skip
        elif e["tag"] == "img":
            name = attr_of(e, "alt")
        else:
            name = text_of(e) or attr_of(e, "aria-label")
        interactive = e["tag"] in ("input", "textarea", "select", "button", "a", "img", "canvas")
        if not name and not interactive and not phs:
            continue
        item: dict[str, Any] = {"element_id": f"n{e['id']}", "flags": 1, "placeholders": phs, "role": e["role"],
                                "name": name[:2000],
                                "bounds": [round(x, 1) for x in e["rect"]]}  # fmt: skip
        if e["tag"] in ("input", "textarea", "select") and e["role"] != "hidden":
            item["flags"] |= 16
            item["filled"] = bool(e["value"])
            ds = [d for d in dets if d.el == e["id"] and d.channel == "input_value"]
            if ds:
                item["data_type"] = ds[0].category
        if e["tag"] == "select" and e["id"] in options:
            item["options"] = options[e["id"]][:200]
        if e["tag"] == "a" and e["attrs"].get("href"):
            href = attr_of(e, "href")
            item["href"] = re.split(r"[?#]", href)[0][:2048]  # query and fragment never leave
        if e["tag"] in ("img", "canvas"):
            item["pixels_redacted"] = True
        out_els.append(item)
    title_el = next((e for e in els if e["tag"] == "title"), None)
    return {
        "schema": "sanitized_page.v1",
        "snapshot_id": snapshot_id,
        "url": f"http://{site}/{page_name}/",
        "title": text_of(title_el)[:512] if title_el else "",
        "elements": out_els,
    }


def redactions_json(boxes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for b in boxes:
        r: dict[str, Any] = {"element_id": f"n{b['el']}", "category": b["category"],
                             "box": [round(x, 1) for x in b["box"]]}  # fmt: skip
        if b["placeholder"]:
            r["placeholder"] = b["placeholder"]
        if b["fail_closed"]:
            r["fail_closed"] = True
        out.append(r)
    return out
