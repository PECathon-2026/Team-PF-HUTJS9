"""Scan model output for anything that looks like personal data (spec §9
anti-reconstruction: "its output is scanned for anything that looks like
personal data"; "no partial hints").

The agent has its own small scanner: it must not depend on ``ml/`` or on
``core``'s detect library. Findings carry only a type and where it was found,
never the matched text (explanation-safety rule, spec §11).

Text is normalised first (NFKC, invisible/bidi characters removed, common
Cyrillic/Greek look-alikes mapped, native digits mapped) so that a model can't
slip a value past by spelling it oddly. Placeholders are removed before
scanning: they are the one legitimate way to mention a sensitive value.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass

from .actions import PLACEHOLDER_RE

# Invisible and bidi-control characters, spelled as code points on purpose.
_INVISIBLE = "".join(
    chr(c)
    for c in [
        0x00AD,
        0x034F,
        0x061C,
        0x180E,
        *range(0x200B, 0x2010),
        *range(0x202A, 0x202F),
        *range(0x2060, 0x2070),
        0xFEFF,
    ]
)
_INVISIBLE_RE = re.compile("[" + re.escape(_INVISIBLE) + "]")
# Cyrillic / Greek letters that look like Latin ones.
_CONFUSABLE = {
    0x0410: "A", 0x0412: "B", 0x0421: "C", 0x0415: "E", 0x041D: "H", 0x041A: "K", 0x041C: "M", 0x041E: "O",
    0x0420: "P", 0x0422: "T", 0x0425: "X", 0x0430: "a", 0x0441: "c", 0x0435: "e", 0x043E: "o", 0x0440: "p",
    0x0445: "x", 0x0443: "y", 0x0456: "i", 0x0458: "j", 0x0455: "s", 0x0391: "A", 0x0392: "B", 0x0395: "E",
    0x0397: "H", 0x0399: "I", 0x039A: "K", 0x039C: "M", 0x039D: "N", 0x039F: "O", 0x03A1: "P", 0x03A4: "T",
    0x03A7: "X", 0x03BF: "o",
}  # fmt: skip


def normalize(text: str) -> str:
    t = unicodedata.normalize("NFKC", text)
    t = _INVISIBLE_RE.sub("", t)
    out = []
    for ch in t:
        cp = ord(ch)
        if cp in _CONFUSABLE:
            out.append(_CONFUSABLE[cp])
        elif ch.isdecimal() and not ch.isascii():
            out.append(str(unicodedata.decimal(ch)))  # Devanagari, Arabic-Indic, ... digits
        else:
            out.append(ch)
    return "".join(out)


def _luhn(d: str) -> bool:
    total = 0
    for i, c in enumerate(reversed(d)):
        n = int(c)
        if i % 2:
            n = n * 2 - 9 if n > 4 else n * 2
        total += n
    return total % 10 == 0


def _d5(j: int, k: int) -> int:
    # Dihedral group D5 product (Verhoeff's numbering): 0-4 rotations, 5-9 reflections.
    if j < 5:
        return (j + k) % 5 if k < 5 else 5 + (j + k) % 5
    return 5 + (j - k) % 5 if k < 5 else (j - k) % 5


_PERM = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]]
_SIGMA = [1, 5, 7, 6, 2, 8, 3, 0, 9, 4]
for _ in range(7):
    _PERM.append([_SIGMA[x] for x in _PERM[-1]])


def _verhoeff(d: str) -> bool:
    c = 0
    for i, ch in enumerate(reversed(d)):
        c = _d5(c, _PERM[i % 8][int(ch)])
    return c == 0


@dataclass(frozen=True)
class Finding:
    kind: str  # card, aadhaar, phone, email, upi, pan, ifsc, api_key, canary, partial_hint, long_number
    where: str  # which part of the output (e.g. "raw", "rationale", "justification[0]")


_DIGITS = re.compile(r"(?<![0-9])[0-9](?:[0-9 ./-]{0,4}[0-9]){5,}(?![0-9])")
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
_UPI = re.compile(r"(?<![A-Za-z0-9._-])[A-Za-z0-9][A-Za-z0-9._-]{1,}@[A-Za-z][A-Za-z0-9]{1,}(?![A-Za-z0-9.@-])")
_PAN = re.compile(r"(?<![A-Z0-9])[A-Z]{3}[PCHFATBLJG][A-Z][0-9]{4}[A-Z](?![A-Z0-9])")
_IFSC = re.compile(r"(?<![A-Z0-9])[A-Z]{4}0[A-Z0-9]{6}(?![A-Z0-9])")
_KEYS = re.compile(
    r"sk-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{20,}|AKIA[A-Z2-7]{12,}|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}"
)
_CANARY = re.compile(r"PLCANARY-[0-9A-Z]{8,}")
_PARTIAL = re.compile(
    r"\b(?:last|final|ending(?:\s+in|\s+with)?|ends?\s+(?:in|with)|first|starts?\s+with|begins?\s+with)"
    r"\s+(?:\w+\s+){0,3}?(?:digits?\s+)?(?:are\s+|is\s+|of\s+|:\s*)?[0-9](?:[\s-]?[0-9]){1,5}\b",
    re.I,
)
_MASKED_TAIL = re.compile(r"(?:[*xX#•]{2,}[\s-]*){1,4}[0-9]{2,6}\b")


_B64_TOKEN = re.compile(r"[A-Za-z0-9+/_-]{12,}={0,2}")
_HEX_TOKEN = re.compile(r"\b(?:[0-9a-fA-F]{2}){8,}\b")


def _decoded(t: str) -> list[str]:
    """Text hidden in base64 or hex tokens (one level deep is enough here: the
    gate decodes recursively, spec §8)."""
    out = []
    for m in _HEX_TOKEN.finditer(t):
        try:
            out.append(bytes.fromhex(m.group(0)).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            pass
    for m in _B64_TOKEN.finditer(t):
        tok = m.group(0)
        try:
            raw = base64.b64decode(tok + "=" * (-len(tok) % 4), altchars=b"-_" if "-" in tok or "_" in tok else None)
            out.append(raw.decode("utf-8"))
        except (binascii.Error, ValueError, UnicodeDecodeError):
            pass
    return [d for d in out if d.isprintable()]


def scan(text: str, where: str = "raw", strict_numbers: bool = False, _depth: int = 0) -> list[Finding]:
    """Findings in ``text``. With ``strict_numbers`` any run of 8+ digits counts
    (used for free-text fields, where there is no legitimate need for one).
    Base64 and hex tokens are decoded and scanned too."""
    t = PLACEHOLDER_RE.sub(" ", normalize(text))
    found_decoded: list[Finding] = []
    if _depth == 0:
        for d in _decoded(t):
            found_decoded += scan(d, where + ":decoded", strict_numbers, _depth=1)
    found: list[Finding] = []
    for m in _DIGITS.finditer(t):
        d = re.sub(r"[^0-9]", "", m.group(0))
        n = len(d)
        if 13 <= n <= 19 and _luhn(d):
            found.append(Finding("card", where))
        elif n == 12 and d[0] in "23456789" and _verhoeff(d):
            found.append(Finding("aadhaar", where))
        elif (
            (n == 10 and d[0] in "6789")
            or (n == 11 and d[0] == "0" and d[1] in "6789")
            or (n == 12 and d[:2] == "91" and d[2] in "6789")
            or (n == 13 and d[:3] == "091" and d[3] in "6789")
        ):
            found.append(Finding("phone", where))
        elif strict_numbers and n >= 8:
            found.append(Finding("long_number", where))
    if _EMAIL.search(t):
        found.append(Finding("email", where))
    elif _UPI.search(t):
        found.append(Finding("upi", where))
    for kind, rx in (("pan", _PAN), ("ifsc", _IFSC), ("api_key", _KEYS), ("canary", _CANARY)):
        if rx.search(t):
            found.append(Finding(kind, where))
    if _PARTIAL.search(t) or _MASKED_TAIL.search(t):
        found.append(Finding("partial_hint", where))
    return found + found_decoded
