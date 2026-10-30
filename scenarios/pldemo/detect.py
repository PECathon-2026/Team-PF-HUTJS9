"""Demo detector (Python validators). Owner: WIN.

Mirrors the C++ detect v1 rules (daemons/core/detect) closely enough for the
data-pipeline demo: normalise look-alikes with a source-offset map, digit-run
scanner with check digits, letter-shaped patterns, structural rules (password
inputs, autocomplete tokens, labels), URL-decoded attribute scanning and
split-value re-joining by on-screen geometry.

NAME detection is a DICTIONARY STAND-IN (the synthetic first names and surnames
the generator draws from). It only works because the data is synthetic; real
names need GLiNER (Sprint 2). The pipeline report says so.
"""

from __future__ import annotations

import re
import unicodedata
import urllib.parse
from dataclasses import dataclass

from gen import values as v

from plscen.redteam import UNHOMOGLYPH

INVISIBLE = {
    0x00AD,
    0x034F,
    0x061C,
    0x180E,
    *range(0x200B, 0x2010),
    *range(0x202A, 0x202F),
    *range(0x2060, 0x2070),
    0xFEFF,
}
NAMES_FIRST = frozenset(v._FIRST_NAMES)
NAMES_LAST = frozenset(v._LAST_NAMES)


def normalize(s: str) -> tuple[str, list[int]]:
    """Normalised text and, for each output char, the index of the source char it came from."""
    out: list[str] = []
    src: list[int] = []
    for i, ch in enumerate(s):
        cp = ord(ch)
        if cp in INVISIBLE:
            continue
        if ch in UNHOMOGLYPH:
            rep = UNHOMOGLYPH[ch]
        elif ch.isdecimal() and not ch.isascii():
            rep = str(unicodedata.decimal(ch))
        else:
            rep = unicodedata.normalize("NFKC", ch)
            if rep.isspace():
                rep = " "
        for r in rep:
            out.append(r)
            src.append(i)
    return "".join(out), src


@dataclass(frozen=True)
class Hit:
    begin: int  # normalised offsets
    end: int
    category: str  # taint category name, e.g. CARD
    rule: str
    checksum: bool = False


@dataclass
class Ctx:
    otp: bool = False
    account: bool = False
    pin: bool = False


_RUN = re.compile(r"\d+(?:[ .\-/]\d+)*")
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
_UPI = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]+@[A-Za-z][A-Za-z0-9]+")
_PAN = re.compile(r"(?<![A-Za-z0-9])[A-Z]{3}[PCHFATBLJG][A-Z][0-9]{4}[A-Z](?![A-Za-z0-9])")
_IFSC = re.compile(r"(?<![A-Za-z0-9])[A-Z]{4}0[A-Z0-9]{6}(?![A-Za-z0-9])")
_KEY = re.compile(r"sk-[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9]{36}|AKIA[A-Z2-7]{16}")
_JWT = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{8,}")
_CANARY = re.compile(r"PLCANARY-[0-9A-HJKMNP-TV-Z]{16}-[0-9]{2}")
_IP = re.compile(r"(?<![0-9.])[0-9]{1,3}(?:\.[0-9]{1,3}){3}(?![0-9.])")
_DOB = re.compile(r"(?<![0-9])(?:[0-9]{1,2}[/.-][0-9]{1,2}[/.-][0-9]{4}|[0-9]{4}-[0-9]{2}-[0-9]{2})(?![0-9])")
_WORD = re.compile(r"[A-Za-z]+")


def _digit_hits(t: str, ctx: Ctx) -> list[Hit]:
    hits: list[Hit] = []
    for m in _RUN.finditer(t):
        if m.start() > 0 and t[m.start() - 1].isalpha():
            continue
        groups = [(g.start() + m.start(), g.end() + m.start()) for g in re.finditer(r"\d+", m.group(0))]
        letter_after = m.end() < len(t) and t[m.end()].isalpha()
        found: list[Hit] = []
        for a in range(len(groups)):
            digits = ""
            for b in range(a, len(groups)):
                digits += t[groups[b][0] : groups[b][1]]
                if len(digits) > 19:
                    break
                if b == len(groups) - 1 and letter_after:
                    continue
                n = len(digits)
                begin, end = groups[a][0], groups[b][1]
                intl = begin > 0 and t[begin - 1] == "+" and n == 12 and digits.startswith("91") and digits[2] >= "6"
                if intl:
                    found.append(Hit(begin - 1, end, "PHONE", "D-07", True))
                elif 13 <= n <= 19 and v.is_card(digits):
                    found.append(Hit(begin, end, "CARD", "D-01", True))
                elif n == 12 and digits[0] >= "2" and v.verhoeff_valid(digits):
                    found.append(Hit(begin, end, "AADHAAR", "D-02", True))
                elif (
                    (n == 10 and digits[0] >= "6")
                    or (n == 11 and digits[0] == "0" and digits[1] >= "6")
                    or (n == 12 and digits.startswith("91") and digits[2] >= "6")
                    or (n == 13 and digits.startswith("091") and digits[3] >= "6")
                ):
                    found.append(Hit(begin - (1 if begin > 0 and t[begin - 1] == "+" else 0), end, "PHONE", "D-07"))
                elif ctx.account and 9 <= n <= 18 and digits[0] != "0":
                    found.append(Hit(begin, end, "BANK_ACCOUNT", "D-15"))
                elif ctx.otp and n in (4, 6, 8):
                    found.append(Hit(begin, end, "OTP", "D-13"))
                elif ctx.pin and n == 6 and digits[0] != "0":
                    found.append(Hit(begin, end, "PIN_CODE", "D-16"))
        found.sort(key=lambda h: (not h.checksum, -(h.end - h.begin)))
        kept: list[Hit] = []
        for h in found:
            if all(h.begin >= k.end or k.begin >= h.end for k in kept):
                kept.append(h)
        hits += kept
    return hits


def scan(t: str, ctx: Ctx | None = None) -> list[Hit]:
    """All validated hits in already-normalised text, non-overlapping (longest wins)."""
    ctx = ctx or Ctx()
    hits = _digit_hits(t, ctx)
    for rx, cat, rule, ok in (
        (_EMAIL, "EMAIL", "D-06", lambda s: True),
        (_PAN, "PAN", "D-03", v.is_pan),
        (_IFSC, "IFSC", "D-04", v.is_ifsc),
        (_KEY, "API_KEY", "D-08", lambda s: True),
        (_JWT, "API_KEY", "D-09", v.is_jwt),
        (_CANARY, "SECRET", "D-10", v.is_canary_token),
        (_IP, "IP_ADDRESS", "D-11", lambda s: all(0 <= int(p) <= 255 for p in s.split("."))),
        (_DOB, "DOB", "D-18", v.is_dob),
    ):
        for m in rx.finditer(t):
            if ok(m.group(0)):
                hits.append(Hit(m.start(), m.end(), cat, rule, cat in ("SECRET",)))
    for m in _UPI.finditer(t):
        nxt = t[m.end()] if m.end() < len(t) else ""
        if nxt not in (".", "-") and not _EMAIL.fullmatch(t[m.start() : m.end()]):
            hits.append(Hit(m.start(), m.end(), "UPI_ID", "D-05"))
    # Names: dictionary stand-in. "First Last" pairs, or a first name alone.
    words = list(_WORD.finditer(t))
    i = 0
    while i < len(words):
        w = words[i].group(0)
        if w in NAMES_FIRST:
            begin, end = words[i].start(), words[i].end()
            if (
                i + 1 < len(words)
                and words[i + 1].group(0) in NAMES_LAST
                and t[end : words[i + 1].start()].strip() == ""
            ):
                end = words[i + 1].end()
                i += 1
            hits.append(Hit(begin, end, "NAME", "D-20"))
        i += 1
    # Overlaps: drop hits inside a larger hit, then keep leftmost non-overlapping, longest first.
    hits.sort(key=lambda h: (h.begin, -(h.end - h.begin)))
    out: list[Hit] = []
    for h in hits:
        if out and h.begin < out[-1].end:
            if (h.end - h.begin) > (out[-1].end - out[-1].begin) and h.checksum:
                out[-1] = h
            continue
        out.append(h)
    return out


# ---- structural rules -----------------------------------------------------------------------------------

_AUTOCOMPLETE = {
    "cc-number": "CARD", "cc-csc": "CARD", "cc-exp": "CARD", "cc-name": "NAME", "one-time-code": "OTP",
    "street-address": "ADDRESS", "address-line1": "ADDRESS", "address-line2": "ADDRESS", "postal-code": "PIN_CODE",
    "tel": "PHONE", "email": "EMAIL", "name": "NAME", "given-name": "NAME", "family-name": "NAME",
    "current-password": "PASSWORD", "new-password": "PASSWORD",
}  # fmt: skip


def structural(input_type: str, autocomplete: str, label: str) -> tuple[str, str] | None:
    """(category, rule) for an input whose whole value is sensitive whatever it looks like."""
    if input_type == "password":
        return "PASSWORD", "D-12"
    for tok in autocomplete.lower().split():
        if tok in _AUTOCOMPLETE:
            return _AUTOCOMPLETE[tok], "D-14"
    lab = label.lower()
    if re.search(r"\b(cvv|cvc)\b|security code", lab):
        return "CARD", "D-17"
    if re.search(r"\botp\b|one-time", lab):
        return "OTP", "D-17"
    if "password" in lab:
        return "PASSWORD", "D-17"
    return None


def context_flags(label: str, autocomplete: str, page_has_otp_signal: bool) -> Ctx:
    lab = label.lower()
    return Ctx(
        otp=(page_has_otp_signal and bool(re.search(r"otp|one-time|code", lab))) or "one-time-code" in autocomplete,
        account=bool(re.search(r"account|a/c|acct", lab)),
        pin=bool(re.search(r"pin code|pincode|postal|zip", lab)) or "postal-code" in autocomplete,
    )


def decode_url(s: str) -> tuple[str, list[int], list[int]]:
    """Percent-decode a URL attribute; returns text plus source start and end index of each decoded char."""
    out: list[str] = []
    starts: list[int] = []
    ends: list[int] = []
    i = 0
    while i < len(s):
        if s[i] == "%" and re.fullmatch(r"[0-9A-Fa-f]{2}", s[i + 1 : i + 3]):
            out.append(urllib.parse.unquote(s[i : i + 3]))
            starts.append(i)
            ends.append(i + 3)
            i += 3
        else:
            out.append(" " if s[i] == "+" else s[i])
            starts.append(i)
            ends.append(i + 1)
            i += 1
    return "".join(out), starts, ends
