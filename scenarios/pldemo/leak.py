"""Leak check: scan everything the AI would receive for every planted value and its encodings.
Owner: WIN.

Encodings tried for each value (its canonical form and the form as rendered): as is, case-folded,
normalised (look-alikes and invisible characters removed), separators removed (digits only),
base64 and base64url, hex, URL-encoded, reversed digits. Only string content is scanned (not
numbers such as box coordinates), so short values (CVV, OTP) can't false-match a coordinate.
"""

from __future__ import annotations

import base64
import re
import urllib.parse
from typing import Any

from .detect import normalize


def strings_of(obj: Any) -> list[str]:
    out: list[str] = []
    if isinstance(obj, str):
        out.append(obj)
    elif isinstance(obj, dict):
        for k, v in obj.items():
            out.append(str(k))
            out += strings_of(v)
    elif isinstance(obj, list):
        for v in obj:
            out += strings_of(v)
    return out


def variants(value: str) -> dict[str, str]:
    norm, _ = normalize(value)
    bare = re.sub(r"[\s.\-/]", "", norm)
    raw = value.encode()
    v = {
        "raw": value, "normalized": norm, "separators_removed": bare,
        "base64": base64.b64encode(raw).decode(), "base64url": base64.urlsafe_b64encode(raw).decode().rstrip("="),
        "base64_bare": base64.b64encode(bare.encode()).decode(), "hex": raw.hex(),
        "url_encoded": urllib.parse.quote(value, safe=""),
        "url_encoded_all": "".join(f"%{b:02X}" for b in raw),
    }  # fmt: skip
    if bare.isdigit():
        v["digits_reversed"] = bare[::-1]
    return {k: x for k, x in v.items() if len(x) >= 3}


def find_leaks(haystack_strings: list[str], planted: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Hits as {item, type, encoding}; never the value itself."""
    flat = "\n".join(haystack_strings)
    flat_norm, _ = normalize(flat)
    flat_l = flat.lower()
    flat_bare = re.sub(r"[\s.\-/]", "", flat_norm)  # the output with separators removed too
    hits = []
    for it in planted:
        for form in {it["value"], it["shown"]}:
            if not form:
                continue
            for enc, var in variants(form).items():
                short = len(var) < 6
                hays = [flat, flat_norm, flat_l] + (
                    [flat_bare] if enc in ("separators_removed", "digits_reversed") and not short else []
                )
                for hay in hays:
                    cand = var if hay is not flat_l else var.lower()
                    if short:
                        found = re.search(r"(?<![0-9A-Za-z])" + re.escape(cand) + r"(?![0-9A-Za-z])", hay) is not None
                    else:
                        found = cand in hay
                    if found:
                        hits.append({"item": it["id"], "type": it["type"], "encoding": enc})
                        break
    return hits
