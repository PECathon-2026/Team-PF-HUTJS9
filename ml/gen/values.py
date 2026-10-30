"""Synthetic sensitive-value generators and validators (WIN, AD-09).

Every generator draws from one ``random.Random`` seeded by the caller, so the
same seed always gives the same values. Nothing here is real PII: card numbers
are random Luhn-valid numbers in public issuer ranges, Aadhaar numbers are
random Verhoeff-valid numbers, emails use RFC 2606 reserved domains, IPs use
RFC 5737 documentation ranges.

Validators are written from the public format rules. They are the reference
the scenario tests check against; ``daemons/core/detect`` has its own C++
validators, and the gate has independent ones (AD-11).

``near_miss`` produces values that look right but must fail validation (wrong
check digit, wrong range, wrong structure). Tests use them to prove the
validators reject look-alikes.
"""

from __future__ import annotations

import base64
import datetime as _dt
import json
import random
import re
import string
from collections.abc import Callable
from dataclasses import dataclass

# Fixed reference date so date logic (DOB ages, card expiry) is deterministic.
REFERENCE_DATE = _dt.date(2026, 1, 1)

# --------------------------------------------------------------------------
# Check digits
# --------------------------------------------------------------------------


def _digits(s: str) -> list[int]:
    return [ord(c) - 48 for c in s]


def luhn_check_digit(payload: str) -> int:
    """Check digit to append to ``payload`` (digits only) so the result passes Luhn."""
    total = 0
    for i, d in enumerate(reversed(_digits(payload))):
        if i % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return (10 - total % 10) % 10


def luhn_valid(number: str) -> bool:
    if not number.isdigit() or not number.isascii() or len(number) < 2:
        return False
    return luhn_check_digit(number[:-1]) == int(number[-1])


_VERHOEFF_D = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8),
    (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2),
    (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)
_VERHOEFF_P = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0),
    (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
    (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)
_VERHOEFF_INV = (0, 4, 3, 2, 1, 5, 6, 7, 8, 9)


def verhoeff_check_digit(payload: str) -> int:
    c = 0
    for i, d in enumerate(reversed(_digits(payload))):
        c = _VERHOEFF_D[c][_VERHOEFF_P[(i + 1) % 8][d]]
    return _VERHOEFF_INV[c]


def verhoeff_valid(number: str) -> bool:
    if not number.isdigit() or not number.isascii() or len(number) < 2:
        return False
    c = 0
    for i, d in enumerate(reversed(_digits(number))):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][d]]
    return c == 0


# --------------------------------------------------------------------------
# Card issuer ranges (public IIN data)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class IinRange:
    brand: str
    lo: str  # inclusive prefix
    hi: str  # inclusive prefix, same length as lo
    length: int


# Ordered most-specific first: RuPay's 6-digit ranges sit inside Discover's "65".
IIN_RANGES: tuple[IinRange, ...] = (
    IinRange("rupay", "508500", "508999", 16),
    IinRange("rupay", "606985", "607984", 16),
    IinRange("rupay", "608001", "608500", 16),
    IinRange("rupay", "652150", "653149", 16),
    IinRange("visa", "4", "4", 16),
    IinRange("mastercard", "51", "55", 16),
    IinRange("mastercard", "2221", "2720", 16),
    IinRange("amex", "34", "34", 15),
    IinRange("amex", "37", "37", 15),
    IinRange("discover", "6011", "6011", 16),
    IinRange("discover", "644", "649", 16),
    IinRange("discover", "65", "65", 16),
)
CARD_BRANDS = ("visa", "mastercard", "amex", "rupay", "discover")


def _strip_seps(s: str) -> str:
    return s.replace(" ", "").replace("-", "")


def card_brand(number: str) -> str | None:
    """Issuer brand by IIN range and length, or None if no range matches."""
    n = _strip_seps(number)
    if not n.isdigit() or not n.isascii():
        return None
    for r in IIN_RANGES:
        k = len(r.lo)
        if len(n) == r.length and r.lo <= n[:k] <= r.hi:
            return r.brand
    return None


def is_card(number: str) -> bool:
    n = _strip_seps(number)
    return card_brand(n) is not None and luhn_valid(n)


# --------------------------------------------------------------------------
# Indian identifiers and other formats
# --------------------------------------------------------------------------

# 4th PAN character: holder type (P person, C company, H HUF, F firm, A AOP,
# T trust, B BOI, L local authority, J artificial juridical person, G govt).
PAN_HOLDER_TYPES = "PCHFATBLJG"
_PAN_RE = re.compile(rf"[A-Z]{{3}}[{PAN_HOLDER_TYPES}][A-Z](?!0000)[0-9]{{4}}[A-Z]")
_IFSC_RE = re.compile(r"[A-Z]{4}0[A-Z0-9]{6}")
_UPI_RE = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._-]{1,255}@[a-zA-Z][a-zA-Z0-9]{1,63}")
_EMAIL_RE = re.compile(
    r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*"
    r"@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}"
)
_PHONE_IN_RE = re.compile(r"(?:\+91|91|0)?([6-9][0-9]{9})")
_PIN_RE = re.compile(r"[1-9][0-9]{5}")
# Indian passport: letter (not Q/X/Z), then 7 digits, first digit non-zero.
_PASSPORT_RE = re.compile(r"[A-PR-WY][1-9][0-9]{6}")
_OTP_RE = re.compile(r"[0-9]{6}")
_CANARY_RE = re.compile(r"PLCANARY-([0-9A-HJKMNP-TV-Z]{16})-([0-9]{2})")
_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

# Real bank codes (public); branch parts are random so they're synthetic.
IFSC_BANKS = ("SBIN", "HDFC", "ICIC", "UTIB", "PUNB", "BARB", "KKBK", "CNRB", "UBIN", "IDIB")
UPI_PSPS = ("okaxis", "oksbi", "okhdfcbank", "okicici", "ybl", "paytm", "ibl", "axl", "upi")
# RFC 2606 / RFC 6761 reserved domains only: these can never reach a real inbox.
EMAIL_DOMAINS = ("example.com", "example.org", "example.net", "mail.example", "corp.test")
# RFC 5737 documentation ranges.
IPV4_DOC_NETS = ("192.0.2", "198.51.100", "203.0.113")

DOB_FORMATS = ("%d/%m/%Y", "%d-%m-%Y", "%Y-%m-%d", "%d %b %Y", "%d.%m.%Y")


def is_aadhaar(s: str) -> bool:
    n = _strip_seps(s)
    return len(n) == 12 and n.isascii() and n.isdigit() and n[0] in "23456789" and verhoeff_valid(n)


def is_pan(s: str) -> bool:
    return _PAN_RE.fullmatch(s) is not None


def is_ifsc(s: str) -> bool:
    return _IFSC_RE.fullmatch(s) is not None


def is_upi(s: str) -> bool:
    # A UPI handle (VPA) has a dotless provider part; "a@b.com" is an email.
    return _UPI_RE.fullmatch(s) is not None and ".." not in s


def is_email(s: str) -> bool:
    return len(s) <= 254 and _EMAIL_RE.fullmatch(s) is not None


def is_phone_in(s: str) -> bool:
    n = re.sub(r"[\s()-]", "", s)
    return _PHONE_IN_RE.fullmatch(n) is not None


def is_pin_code(s: str) -> bool:
    return _PIN_RE.fullmatch(s.replace(" ", "")) is not None


def is_passport_in(s: str) -> bool:
    return _PASSPORT_RE.fullmatch(s) is not None


def is_otp(s: str) -> bool:
    return _OTP_RE.fullmatch(s) is not None


def is_ipv4_doc(s: str) -> bool:
    parts = s.split(".")
    if len(parts) != 4 or not all(p.isdigit() and p.isascii() and str(int(p)) == p for p in parts):
        return False
    return ".".join(parts[:3]) in IPV4_DOC_NETS and 0 <= int(parts[3]) <= 255


def parse_dob(s: str) -> _dt.date | None:
    for fmt in DOB_FORMATS:
        try:
            d = _dt.datetime.strptime(s, fmt).date()
        except ValueError:
            continue
        # strptime accepts single-digit fields; insist on the canonical rendering.
        if d.strftime(fmt) == s:
            return d
    return None


def is_dob(s: str) -> bool:
    d = parse_dob(s)
    if d is None:
        return False
    age = (REFERENCE_DATE - d).days / 365.2425
    return 0 <= age <= 120


def is_card_expiry(s: str) -> bool:
    m = re.fullmatch(r"(0[1-9]|1[0-2])/([0-9]{2})", s)
    if not m:
        return False
    month, year = int(m.group(1)), 2000 + int(m.group(2))
    return (year, month) >= (REFERENCE_DATE.year, REFERENCE_DATE.month)


def is_cvv(s: str) -> bool:
    return re.fullmatch(r"[0-9]{3,4}", s) is not None


def _canary_check(body: str) -> str:
    n = 0
    for c in body:
        n = n * 32 + _CROCKFORD.index(c)
    return f"{n % 97:02d}"


def is_canary_token(s: str) -> bool:
    m = _CANARY_RE.fullmatch(s)
    return m is not None and _canary_check(m.group(1)) == m.group(2)


def find_canary_tokens(text: str) -> list[str]:
    return [m.group(0) for m in _CANARY_RE.finditer(text) if is_canary_token(m.group(0))]


_B62 = string.ascii_letters + string.digits
_B32_AWS = string.ascii_uppercase + "234567"


def is_api_key(s: str) -> bool:
    """Shape check by known prefix (spec §4). Randomness tests come later in detect."""
    if re.fullmatch(r"sk-(?:proj-)?[A-Za-z0-9_-]{32,}", s):
        return True
    if re.fullmatch(r"ghp_[A-Za-z0-9]{36}", s):
        return True
    if re.fullmatch(r"AKIA[A-Z2-7]{16}", s):
        return True
    return is_jwt(s)


def _b64url_decode(part: str) -> bytes:
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


def is_jwt(s: str) -> bool:
    parts = s.split(".")
    if len(parts) != 3 or not s.startswith("eyJ"):
        return False
    try:
        header = json.loads(_b64url_decode(parts[0]))
        json.loads(_b64url_decode(parts[1]))
        _b64url_decode(parts[2])
    except (ValueError, UnicodeDecodeError):
        return False
    return isinstance(header, dict) and "alg" in header and len(parts[2]) > 0


# --------------------------------------------------------------------------
# Generator
# --------------------------------------------------------------------------

_FIRST_NAMES = (
    "Aarav",
    "Vivaan",
    "Aditya",
    "Ishaan",
    "Kabir",
    "Arjun",
    "Rohan",
    "Siddharth",
    "Ananya",
    "Diya",
    "Isha",
    "Meera",
    "Priya",
    "Saanvi",
    "Kavya",
    "Nisha",
    "Farhan",
    "Zoya",
    "Gurpreet",
    "Harleen",
    "Tenzin",
    "Lalit",
    "Deepa",
    "Rekha",
)
_LAST_NAMES = (
    "Sharma",
    "Verma",
    "Iyer",
    "Nair",
    "Reddy",
    "Patel",
    "Shah",
    "Mehta",
    "Gupta",
    "Singh",
    "Kaur",
    "Das",
    "Bose",
    "Khan",
    "Menon",
    "Pillai",
    "Joshi",
    "Kulkarni",
)
_STREETS = ("MG Road", "Park Street", "Linking Road", "Residency Road", "Anna Salai", "Ring Road")
_CITIES = (("Bengaluru", "56"), ("Mumbai", "40"), ("Chennai", "60"), ("Kolkata", "70"), ("Delhi", "11"), ("Pune", "41"))


class Gen:
    """Deterministic synthetic value generator. Same seed ⇒ same sequence."""

    def __init__(self, seed: int) -> None:
        self.rng = random.Random(seed)

    def _digits(self, n: int) -> str:
        return "".join(self.rng.choice(string.digits) for _ in range(n))

    # ---- cards
    def card(self, brand: str | None = None) -> str:
        """Luhn-valid number inside a real IIN range. Digits only."""
        ranges = [r for r in IIN_RANGES if brand is None or r.brand == brand]
        if not ranges:
            raise ValueError(f"unknown brand {brand!r}")
        r = self.rng.choice(ranges)
        while True:  # retry: Discover "65" contains RuPay's 652150-653149
            prefix = str(self.rng.randint(int(r.lo), int(r.hi))).zfill(len(r.lo))
            payload = prefix + self._digits(r.length - len(prefix) - 1)
            number = payload + str(luhn_check_digit(payload))
            if card_brand(number) == r.brand:
                return number

    @staticmethod
    def format_card(number: str, sep: str = " ") -> str:
        groups = (4, 6, 5) if len(number) == 15 else (4, 4, 4, 4)
        out, i = [], 0
        for g in groups:
            out.append(number[i : i + g])
            i += g
        return sep.join(out)

    def card_expiry(self) -> str:
        months_ahead = self.rng.randint(1, 60)
        y, m = divmod(REFERENCE_DATE.month - 1 + months_ahead, 12)
        return f"{m + 1:02d}/{(REFERENCE_DATE.year + y) % 100:02d}"

    def cvv(self, brand: str = "visa") -> str:
        return self._digits(4 if brand == "amex" else 3)

    # ---- Indian identifiers
    def aadhaar(self) -> str:
        payload = self.rng.choice("23456789") + self._digits(10)
        return payload + str(verhoeff_check_digit(payload))

    @staticmethod
    def format_aadhaar(number: str, sep: str = " ") -> str:
        return sep.join(number[i : i + 4] for i in range(0, 12, 4))

    def pan(self, holder_type: str = "P", surname_initial: str | None = None) -> str:
        letters = string.ascii_uppercase
        first3 = "".join(self.rng.choice(letters) for _ in range(3))
        fifth = surname_initial or self.rng.choice(letters)
        num = f"{self.rng.randint(1, 9999):04d}"
        return f"{first3}{holder_type}{fifth}{num}{self.rng.choice(letters)}"

    def ifsc(self) -> str:
        branch = "".join(self.rng.choice(string.ascii_uppercase + string.digits) for _ in range(6))
        return f"{self.rng.choice(IFSC_BANKS)}0{branch}"

    def bank_account(self) -> str:
        return self.rng.choice("123456789") + self._digits(self.rng.randint(8, 17))

    def upi(self, name: str | None = None) -> str:
        handle = (name or self.rng.choice(_FIRST_NAMES)).lower()
        handle += self.rng.choice(("", ".", "_")) + self._digits(self.rng.randint(2, 4))
        return f"{handle}@{self.rng.choice(UPI_PSPS)}"

    def phone_in(self, style: str | None = None) -> str:
        """Indian mobile. There is no reserved fictional range in India, so these
        are random; they are only ever rendered on local test pages."""
        n = self.rng.choice("6789") + self._digits(9)
        style = style or self.rng.choice(("plain", "intl", "intl_space", "zero", "dash"))
        return {
            "plain": n,
            "intl": f"+91{n}",
            "intl_space": f"+91 {n[:5]} {n[5:]}",
            "zero": f"0{n}",
            "dash": f"{n[:3]}-{n[3:6]}-{n[6:]}",
        }[style]

    def pin_code(self, city_prefix: str | None = None) -> str:
        p = city_prefix or str(self.rng.randint(11, 85))
        return p + self._digits(6 - len(p))

    def passport_in(self) -> str:
        return self.rng.choice("ABCDEFGHJKLMNPRSTUVWY") + self.rng.choice("123456789") + self._digits(6)

    # ---- people
    def name(self) -> str:
        return f"{self.rng.choice(_FIRST_NAMES)} {self.rng.choice(_LAST_NAMES)}"

    def email(self, name: str | None = None) -> str:
        first, _, last = (name or self.name()).lower().partition(" ")
        local = self.rng.choice((f"{first}.{last}", f"{first}{last[:1]}", f"{first}_{last}", first))
        local += self._digits(self.rng.randint(0, 3))
        return f"{local}@{self.rng.choice(EMAIL_DOMAINS)}"

    def address(self) -> tuple[str, str]:
        """(street line, "City PIN")."""
        city, pfx = self.rng.choice(_CITIES)
        line = f"{self.rng.randint(1, 450)}, {self.rng.choice(_STREETS)}"
        return line, f"{city} {self.pin_code(pfx)}"

    def dob(self, fmt: str | None = None) -> str:
        start = _dt.date(1950, 1, 1).toordinal()
        end = _dt.date(2007, 12, 31).toordinal()
        d = _dt.date.fromordinal(self.rng.randint(start, end))
        return d.strftime(fmt or self.rng.choice(DOB_FORMATS))

    def otp(self) -> str:
        return self._digits(6)

    def password(self) -> str:
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*-_"
        while True:
            pw = "".join(self.rng.choice(alphabet) for _ in range(self.rng.randint(12, 20)))
            if any(c.isdigit() for c in pw) and any(c.isupper() for c in pw) and any(not c.isalnum() for c in pw):
                return pw

    def ipv4(self) -> str:
        return f"{self.rng.choice(IPV4_DOC_NETS)}.{self.rng.randint(1, 254)}"

    # ---- keys and tokens (never real: random bodies, never committed rendered)
    def api_key(self, kind: str = "sk") -> str:
        if kind == "sk":
            return "sk-proj-" + "".join(self.rng.choice(_B62) for _ in range(48))
        if kind == "ghp":
            return "ghp_" + "".join(self.rng.choice(_B62) for _ in range(36))
        if kind == "akia":
            return "AKIA" + "".join(self.rng.choice(_B32_AWS) for _ in range(16))
        if kind == "jwt":
            return self.jwt()
        raise ValueError(f"unknown key kind {kind!r}")

    def jwt(self) -> str:
        def enc(obj: object) -> str:
            raw = json.dumps(obj, separators=(",", ":")).encode()
            return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

        header = enc({"alg": "HS256", "typ": "JWT"})
        payload = enc({"sub": f"user-{self._digits(6)}", "iat": 1767225600, "scope": "read:orders"})
        sig = base64.urlsafe_b64encode(self.rng.randbytes(32)).rstrip(b"=").decode()
        return f"{header}.{payload}.{sig}"

    # ---- canaries
    def canary_token(self) -> str:
        """Self-checking canary: ``PLCANARY-<16 Crockford base32>-<mod-97 check>``.

        The gate can recognise these without a list. Format-valued canaries
        (cards, Aadhaar, keys) are ordinary generated values listed in the
        page's ground truth under ``canaries``; see docs/architecture/win.md.
        """
        body = "".join(self.rng.choice(_CROCKFORD) for _ in range(16))
        return f"PLCANARY-{body}-{_canary_check(body)}"


# --------------------------------------------------------------------------
# Near-misses: look right, must fail validation
# --------------------------------------------------------------------------


def _sub_digit(rng: random.Random, s: str, pos: int) -> str:
    d = rng.choice([c for c in string.digits if c != s[pos]])
    return s[:pos] + d + s[pos + 1 :]


def _card_near_miss(rng: random.Random, v: str) -> str:
    kind = rng.choice(("digit", "iin", "length"))
    if kind == "digit":
        return _sub_digit(rng, v, rng.randrange(len(v)))
    if kind == "iin":
        # A first digit no brand uses, with the Luhn digit fixed so only the range is wrong.
        payload = rng.choice("01789") + v[1:-1]
        return payload + str(luhn_check_digit(payload))
    # Wrong length for the brand, Luhn fixed.
    payload = v[:-1] + rng.choice(string.digits)
    return payload + str(luhn_check_digit(payload))


def _aadhaar_near_miss(rng: random.Random, v: str) -> str:
    kind = rng.choice(("digit", "swap", "first"))
    if kind == "digit":
        return _sub_digit(rng, v, rng.randrange(12))
    if kind == "swap":
        candidates = [i for i in range(11) if v[i] != v[i + 1]]
        if candidates:
            i = rng.choice(candidates)
            return v[:i] + v[i + 1] + v[i] + v[i + 2 :]
        return _sub_digit(rng, v, 0)
    payload = rng.choice("01") + v[1:11]
    return payload + str(verhoeff_check_digit(payload))


def _pan_near_miss(rng: random.Random, v: str) -> str:
    kind = rng.choice(("holder", "digit_in_letters", "letter_in_digits", "zeros", "lower"))
    if kind == "holder":
        return v[:3] + rng.choice([c for c in string.ascii_uppercase if c not in PAN_HOLDER_TYPES]) + v[4:]
    if kind == "digit_in_letters":
        i = rng.randrange(5)
        return v[:i] + rng.choice(string.digits) + v[i + 1 :]
    if kind == "letter_in_digits":
        i = rng.randrange(5, 9)
        return v[:i] + rng.choice(string.ascii_uppercase) + v[i + 1 :]
    if kind == "zeros":
        return v[:5] + "0000" + v[9:]
    return v.lower()


def _ifsc_near_miss(rng: random.Random, v: str) -> str:
    kind = rng.choice(("fifth", "short", "digit_bank"))
    if kind == "fifth":
        return v[:4] + rng.choice("123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ") + v[5:]
    if kind == "short":
        return v[:-1]
    return rng.choice(string.digits) + v[1:]


def _upi_near_miss(rng: random.Random, v: str) -> str:
    handle, _, psp = v.partition("@")
    kind = rng.choice(("no_at", "dotted_psp", "empty_handle", "space"))
    if kind == "no_at":
        return handle + psp
    if kind == "dotted_psp":
        return f"{handle}@{psp}.com"
    if kind == "empty_handle":
        return f"@{psp}"
    return f"{handle} @{psp}"


def _email_near_miss(rng: random.Random, v: str) -> str:
    local, _, domain = v.partition("@")
    kind = rng.choice(("no_at", "double_at", "no_tld", "space", "dots"))
    if kind == "no_at":
        return local + domain
    if kind == "double_at":
        return f"{local}@@{domain}"
    if kind == "no_tld":
        return f"{local}@{domain.split('.')[0]}"
    if kind == "space":
        return f"{local} x@{domain}"
    return f"{local}..x@{domain}"


def _phone_near_miss(rng: random.Random, v: str) -> str:
    n = re.sub(r"\D", "", v)[-10:]
    kind = rng.choice(("first", "short", "long"))
    if kind == "first":
        return rng.choice("012345") + n[1:]
    if kind == "short":
        return n[:9]
    return n + rng.choice(string.digits)


def _dob_near_miss(rng: random.Random, v: str) -> str:
    year = rng.randint(1950, 2007)
    return rng.choice(
        (f"31/02/{year}", f"30/02/{year}", f"15/13/{year}", f"00/05/{year}", f"{year}-04-31", "12/05/1850")
    )


def _canary_near_miss(rng: random.Random, v: str) -> str:
    m = _CANARY_RE.fullmatch(v)
    assert m
    good = int(m.group(2))
    bad = rng.choice([f"{i:02d}" for i in range(100) if i != good])
    return f"PLCANARY-{m.group(1)}-{bad}"


NEAR_MISS: dict[str, Callable[[random.Random, str], str]] = {
    "card": _card_near_miss,
    "aadhaar": _aadhaar_near_miss,
    "pan": _pan_near_miss,
    "ifsc": _ifsc_near_miss,
    "upi": _upi_near_miss,
    "email": _email_near_miss,
    "phone_in": _phone_near_miss,
    "dob": _dob_near_miss,
    "canary": _canary_near_miss,
}


def near_miss(kind: str, value: str, rng: random.Random) -> str:
    return NEAR_MISS[kind](rng, value)


# Type name → validator. Ground-truth files use these type names.
VALIDATORS: dict[str, Callable[[str], bool]] = {
    "card": is_card,
    "card_expiry": is_card_expiry,
    "cvv": is_cvv,
    "aadhaar": is_aadhaar,
    "pan": is_pan,
    "ifsc": is_ifsc,
    "bank_account": lambda s: re.fullmatch(r"[1-9][0-9]{8,17}", s) is not None,
    "upi": is_upi,
    "phone_in": is_phone_in,
    "email": is_email,
    "dob": is_dob,
    "pin_code": is_pin_code,
    "passport_in": is_passport_in,
    "otp": is_otp,
    "ipv4": is_ipv4_doc,
    "api_key": is_api_key,
    "canary": is_canary_token,
    # Format-free types: detected structurally, so only sanity-checked here.
    "password": lambda s: len(s) >= 8 and s.isprintable() and " " not in s,
    "name": lambda s: re.fullmatch(r"[A-Z][a-z]+ [A-Z][a-z]+", s) is not None,
    "address": lambda s: len(s) >= 8,
    "face": lambda s: s == "",  # faces carry no text value
}


def validate(kind: str, value: str) -> bool:
    return VALIDATORS[kind](value)
