"""Synthetic page generator v1 (spec §14, §15). Owner: WIN.

    python -m gen.pages --seed S --n N --out build/synth     # HTML + assets + truth + manifest
    python -m gen.render build/synth                          # headless Chromium: screenshots + boxes

Every page belongs to one *layout family*. Families are pinned to a split
(train / calibration / test) so no family is ever in two splits (spec §14,
"split by layout family"). Labels come from templates in English, Hindi and
Hinglish (an LLM writes richer text in Phase 3). Values come from
``gen.values`` and sit in inputs, text, tables and images. Hard negatives
(non-Luhn order IDs, Verhoeff-failing reference numbers, PAN-shaped product
codes, IFSC-shaped SKUs) are recorded as ``decoys``.

Output (all under a gitignored ``build/`` folder):
    <out>/pages/<page_id>/index.html, *.png   what the browser loads
    <out>/truth/<page_id>.json                ground truth (never next to the page)
    <out>/manifest.json                       pages, families, splits
"""

from __future__ import annotations

import argparse
import html
import io
import json
import random
import shutil
import zlib
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from PIL import Image, ImageDraw, ImageFont

from .values import Gen, is_aadhaar, is_card, near_miss

GENERATOR_VERSION = "pages-v1"
LANGS = ("en", "hi", "hinglish")

# Pinned forever: changing this leaks test families into training.
FAMILY_SPLIT: dict[str, str] = {
    "form_stack": "train",
    "form_grid": "train",
    "data_table": "train",
    "profile_card": "train",
    "chat_thread": "calibration",
    "receipt": "test",
    "kyc_upload": "test",
}
FAMILIES = tuple(FAMILY_SPLIT)

# ---------------------------------------------------------------- label templates

LABELS: dict[str, dict[str, tuple[str, ...]]] = {
    "name": {
        "en": ("Full name", "Name", "Account holder", "Customer name"),
        "hi": ("पूरा नाम", "नाम", "खाताधारक का नाम"),
        "hinglish": ("Aapka naam", "Poora naam", "Naam likhein"),
    },
    "email": {
        "en": ("Email", "Email address", "E-mail ID"),
        "hi": ("ईमेल", "ईमेल पता"),
        "hinglish": ("Email ID daalein", "Aapka email"),
    },
    "phone_in": {
        "en": ("Mobile number", "Phone", "Contact no."),
        "hi": ("मोबाइल नंबर", "फ़ोन नंबर"),
        "hinglish": ("Mobile no.", "Phone number daalein"),
    },
    "card": {
        "en": ("Card number", "Credit card no.", "Debit card number"),
        "hi": ("कार्ड नंबर", "कार्ड संख्या"),
        "hinglish": ("Card ka number", "Apna card number"),
    },
    "cvv": {"en": ("CVV", "Security code"), "hi": ("सीवीवी",), "hinglish": ("CVV code",)},
    "card_expiry": {"en": ("Expiry", "Valid thru"), "hi": ("समाप्ति तिथि",), "hinglish": ("Expiry date",)},
    "aadhaar": {
        "en": ("Aadhaar number", "Aadhaar no.", "UID"),
        "hi": ("आधार संख्या", "आधार नंबर"),
        "hinglish": ("Aadhaar number daalein", "Aadhar no."),
    },
    "pan": {
        "en": ("PAN", "PAN number", "Permanent Account Number"),
        "hi": ("पैन नंबर", "पैन"),
        "hinglish": ("PAN card number", "PAN no."),
    },
    "ifsc": {"en": ("IFSC", "IFSC code"), "hi": ("आईएफएससी कोड",), "hinglish": ("Bank ka IFSC",)},
    "bank_account": {
        "en": ("Account number", "A/c no."),
        "hi": ("खाता संख्या",),
        "hinglish": ("Account no.", "Khata number"),
    },
    "upi": {"en": ("UPI ID", "VPA"), "hi": ("यूपीआई आईडी",), "hinglish": ("UPI ID daalein",)},
    "dob": {"en": ("Date of birth", "DOB"), "hi": ("जन्म तिथि",), "hinglish": ("Janam tithi", "DOB")},
    "pin_code": {"en": ("PIN code", "Postal code"), "hi": ("पिन कोड",), "hinglish": ("Pincode",)},
    "address": {"en": ("Address", "Street address"), "hi": ("पता",), "hinglish": ("Ghar ka pata",)},
    "passport_in": {"en": ("Passport no.",), "hi": ("पासपोर्ट संख्या",), "hinglish": ("Passport number",)},
    "password": {"en": ("Password",), "hi": ("पासवर्ड",), "hinglish": ("Password daalein",)},
    # decoys
    "order_id": {"en": ("Order ID", "Order no."), "hi": ("ऑर्डर आईडी",), "hinglish": ("Order ki ID",)},
    "reference": {"en": ("Reference no.", "Txn ref"), "hi": ("संदर्भ संख्या",), "hinglish": ("Ref number",)},
    "product_code": {"en": ("Product code", "Model"), "hi": ("उत्पाद कोड",), "hinglish": ("Product code",)},
    "sku": {"en": ("SKU", "Item code"), "hi": ("आइटम कोड",), "hinglish": ("Item ka code",)},
}

HEADINGS = {
    "en": ("Your details", "Account settings", "Complete your profile", "Payment details", "Customer records"),
    "hi": ("आपका विवरण", "खाता सेटिंग्स", "भुगतान विवरण", "ग्राहक रिकॉर्ड"),
    "hinglish": ("Apni details bharein", "Account settings", "Payment ki details", "Customer ki list"),
}
FILLER = {
    "en": (
        "Please check your details before continuing.",
        "We never share your information without consent.",
        "Fields marked with * are required.",
        "Your changes are saved automatically.",
    ),
    "hi": (
        "आगे बढ़ने से पहले अपना विवरण जाँच लें।",
        "हम आपकी जानकारी बिना अनुमति साझा नहीं करते।",
        "* वाले फ़ील्ड ज़रूरी हैं।",
    ),
    "hinglish": (
        "Aage badhne se pehle details check kar lein.",
        "Hum aapki info kisi ke saath share nahi karte.",
        "Star wale fields zaroori hain.",
    ),
}
CHAT_LINES = {
    "en": ("Sure, here it is: {v}", "My {l} is {v}", "Please use {v}", "{l}: {v}"),
    "hi": ("मेरा {l} {v} है", "यह रहा: {v}", "{l}: {v}"),
    "hinglish": ("Mera {l} {v} hai", "Ye lo: {v}", "{l} hai {v}", "Please {v} use karo"),
}
THEMES = (
    ("#ffffff", "#1d2330", "#2f5bd3", "system-ui, sans-serif"),
    ("#f7f3ea", "#2b2118", "#a3541c", "Georgia, serif"),
    ("#0f1720", "#e6edf3", "#58a6ff", "ui-monospace, monospace"),
    ("#eef6f1", "#13261b", "#1f7a4d", "Verdana, sans-serif"),
    ("#fff8fb", "#2c1424", "#b0306f", "Tahoma, sans-serif"),
)

# ---------------------------------------------------------------- model


@dataclass
class Item:
    id: str
    type: str
    value: str
    shown: str
    selector: str
    channel: str  # input_value | text | table_cell | image
    label: str | None = None
    asset: str | None = None
    img_box: list[int] | None = None  # [x, y, w, h] inside the image (image channel)
    box: list[float] | None = None  # filled by gen.render: page coordinates after layout


@dataclass
class Page:
    page_id: str
    family: str
    language: str
    seed: int
    body: list[str] = field(default_factory=list)
    items: list[Item] = field(default_factory=list)
    decoys: list[Item] = field(default_factory=list)
    assets: dict[str, bytes] = field(default_factory=dict)
    _n: int = 0

    def eid(self) -> str:
        self._n += 1
        return f"e{self._n}"


class Ctx:
    """Per-page state: a value generator plus a page-local RNG for layout choices."""

    def __init__(self, page: Page) -> None:
        self.page = page
        self.g = Gen(page.seed)
        self.rng = random.Random(page.seed ^ 0x5EED)
        self.lang = page.language
        self.person = self.g.name()

    def label(self, kind: str) -> str:
        return self.rng.choice(LABELS[kind][self.lang])

    # ---- values (canonical, shown)
    def value(self, kind: str) -> tuple[str, str]:
        g, rng = self.g, self.rng
        if kind == "name":
            return self.person, self.person
        if kind == "email":
            v = g.email(self.person)
            return v, v
        if kind == "phone_in":
            n = _unambiguous_phone(g)
            return n, rng.choice((n, f"+91 {n[:5]} {n[5:]}", f"+91-{n}", f"0{n}", f"{n[:5]} {n[5:]}"))
        if kind == "card":
            c = g.card(rng.choice(("visa", "mastercard", "rupay", "amex")))
            return c, rng.choice((c, Gen.format_card(c), Gen.format_card(c, "-")))
        if kind == "aadhaar":
            a = g.aadhaar()
            return a, rng.choice((a, Gen.format_aadhaar(a), Gen.format_aadhaar(a, "-")))
        if kind == "address":
            line, city = g.address()
            return line, line
        simple: dict[str, Callable[[], str]] = {
            "cvv": g.cvv,
            "card_expiry": g.card_expiry,
            "pan": g.pan,
            "ifsc": g.ifsc,
            "bank_account": g.bank_account,
            "upi": lambda: g.upi(self.person.split()[0]),
            "dob": g.dob,
            "pin_code": g.pin_code,
            "passport_in": g.passport_in,
            "password": g.password,
        }
        v = simple[kind]()
        return v, v

    def decoy(self, kind: str) -> tuple[str, str]:
        """Look-alikes that must not be redacted. ``type`` says what they imitate."""
        r = random.Random(self.rng.random())
        if kind == "order_id":  # 16 digits, card-like prefix, fails Luhn
            while True:
                v = near_miss("card", self.g.card("visa"), r)
                if len(v) == 16 and v.isdigit() and not is_card(v):
                    return "card", v
        if kind == "reference":  # 12 digits, first 2-9, fails Verhoeff
            while True:
                v = near_miss("aadhaar", self.g.aadhaar(), r)
                if len(v) == 12 and v.isdigit() and v[0] in "23456789" and not is_aadhaar(v):
                    return "aadhaar", v
        if kind == "product_code":  # PAN shape, invalid holder letter
            v = self.g.pan()
            return "pan", v[:3] + r.choice("DEIKMNOQRSUVWXYZ") + v[4:]
        if kind == "sku":  # IFSC shape, 5th char not 0
            v = self.g.ifsc()
            return "ifsc", v[:4] + r.choice("123456789") + v[5:]
        raise ValueError(kind)


def _unambiguous_phone(g: Gen) -> str:
    """Mobile number whose prefixed forms (91…, 0…) aren't also a valid Aadhaar or
    card: keeps labels unambiguous (about 1 in 10 would collide otherwise)."""
    while True:
        n = g.phone_in("plain")
        if not any(is_aadhaar(p + n) or is_card(p + n) for p in ("91", "0", "091")):
            return n


DECOY_KINDS = ("order_id", "reference", "product_code", "sku")
FIELD_KINDS = (
    "name", "email", "phone_in", "card", "cvv", "card_expiry", "aadhaar", "pan", "ifsc",
    "bank_account", "upi", "dob", "pin_code", "address", "passport_in", "password",
)  # fmt: skip
TEXT_KINDS = tuple(k for k in FIELD_KINDS if k not in ("password", "cvv"))

E = html.escape

# ---------------------------------------------------------------- building blocks


def _plant(c: Ctx, kind: str, channel: str, selector: str, label: str | None) -> str:
    v, shown = c.value(kind)
    c.page.items.append(Item(f"{c.page.page_id}.{len(c.page.items)}", kind, v, shown, selector, channel, label))
    return shown


def _decoy(c: Ctx, kind: str, selector: str) -> tuple[str, str]:
    typ, v = c.decoy(kind)
    c.page.decoys.append(Item(f"{c.page.page_id}.d{len(c.page.decoys)}", typ, v, v, selector, "text", kind))
    return c.label(kind), v


def _input(c: Ctx, kind: str) -> str:
    eid = c.page.eid()
    label = c.label(kind)
    shown = _plant(c, kind, "input_value", f"#{eid}", label)
    typ = "password" if kind in ("password", "cvv") and c.rng.random() < 0.7 else "text"
    return (
        f'<div class="field"><label for="{eid}">{E(label)}</label>'
        f'<input id="{eid}" type="{typ}" value="{E(shown)}"></div>'
    )


def _decoy_line(c: Ctx) -> str:
    eid = c.page.eid()
    label, v = _decoy(c, c.rng.choice(DECOY_KINDS), f"#{eid}")
    return f'<p class="meta">{E(label)}: <span id="{eid}">{E(v)}</span></p>'


def _filler(c: Ctx) -> str:
    return f'<p class="muted">{E(c.rng.choice(FILLER[c.lang]))}</p>'


def _image(c: Ctx, kinds: list[str], title: str) -> str:
    """Render a document image (Latin script only: Pillow's default font) with values drawn in it."""
    eid = c.page.eid()
    fname = f"doc{len(c.page.assets)}.png"
    font = ImageFont.load_default(size=c.rng.choice((18, 20, 22)))
    w, h = 520, 70 + 40 * len(kinds)
    bg = c.rng.choice(((255, 255, 255), (250, 246, 230), (235, 242, 255)))
    img = Image.new("RGB", (w, h), bg)
    d = ImageDraw.Draw(img)
    d.rectangle((2, 2, w - 3, h - 3), outline=(60, 60, 80), width=2)
    d.text((20, 18), title, fill=(20, 20, 40), font=font)
    y = 60
    english = {k: LABELS[k]["en"][0] for k in kinds}
    for kind in kinds:
        v, shown = c.value(kind)
        prefix = f"{english[kind]}: "
        x0 = 20 + d.textlength(prefix, font=font)
        d.text((20, y), prefix + shown, fill=(15, 15, 15), font=font)
        left, top, right, bottom = d.textbbox((x0, y), shown, font=font)
        c.page.items.append(
            Item(
                f"{c.page.page_id}.{len(c.page.items)}", kind, v, shown, f"#{eid}", "image",
                english[kind], asset=fname, img_box=[int(left), int(top), int(right - left), int(bottom - top)],
            )
        )  # fmt: skip
        y += 40
    buf = io.BytesIO()
    img.save(buf, "PNG", optimize=False)
    c.page.assets[fname] = buf.getvalue()
    return f'<img id="{eid}" src="{fname}" width="{w}" height="{h}" alt="{E(title)}">'


def _pick(c: Ctx, pool: tuple[str, ...], lo: int, hi: int) -> list[str]:
    return c.rng.sample(pool, c.rng.randint(lo, hi))


# ---------------------------------------------------------------- families


def form_stack(c: Ctx) -> None:
    b = c.page.body
    b.append(f"<h1>{E(c.rng.choice(HEADINGS[c.lang]))}</h1>")
    b.append(_filler(c))
    b.append('<form class="stack">' + "".join(_input(c, k) for k in _pick(c, FIELD_KINDS, 4, 8)) + "</form>")
    b.append(_decoy_line(c))


def form_grid(c: Ctx) -> None:
    b = c.page.body
    b.append(f"<h1>{E(c.rng.choice(HEADINGS[c.lang]))}</h1>")
    kinds = _pick(c, FIELD_KINDS, 6, 10)
    half = len(kinds) // 2
    b.append(
        '<form class="grid"><fieldset>' + "".join(_input(c, k) for k in kinds[:half]) + "</fieldset>"
        "<fieldset>" + "".join(_input(c, k) for k in kinds[half:]) + "</fieldset></form>"
    )
    b.append(_filler(c))
    b.extend(_decoy_line(c) for _ in range(c.rng.randint(1, 2)))


def data_table(c: Ctx) -> None:
    b = c.page.body
    b.append(f"<h1>{E(c.rng.choice(HEADINGS[c.lang]))}</h1>")
    cols = ["name", *_pick(c, ("email", "phone_in", "pan", "upi", "bank_account", "ifsc", "dob", "pin_code"), 2, 4)]
    tid = c.page.eid()
    rows = []
    for _ in range(c.rng.randint(3, 6)):
        c.person = c.g.name()  # each row is a different (synthetic) person
        cells = []
        for k in cols:
            eid = c.page.eid()
            shown = _plant(c, k, "table_cell", f"#{eid}", None)
            cells.append(f'<td id="{eid}">{E(shown)}</td>')
        dk = c.rng.choice(DECOY_KINDS)
        did = c.page.eid()
        _, dv = _decoy(c, dk, f"#{did}")
        cells.append(f'<td id="{did}">{E(dv)}</td>')
        rows.append("<tr>" + "".join(cells) + "</tr>")
    head = "".join(f"<th>{E(c.label(k))}</th>" for k in cols) + f"<th>{E(c.label('order_id'))}</th>"
    b.append(f'<table id="{tid}"><thead><tr>{head}</tr></thead><tbody>{"".join(rows)}</tbody></table>')


def profile_card(c: Ctx) -> None:
    b = c.page.body
    b.append(f"<h1>{E(c.person)}</h1>")
    c.page.items.append(Item(f"{c.page.page_id}.{len(c.page.items)}", "name", c.person, c.person, "h1", "text"))
    dl = []
    for k in _pick(c, TEXT_KINDS[1:], 3, 6):
        eid = c.page.eid()
        label = c.label(k)
        shown = _plant(c, k, "text", f"#{eid}", label)
        dl.append(f'<dt>{E(label)}</dt><dd id="{eid}">{E(shown)}</dd>')
    b.append(f'<dl class="profile">{"".join(dl)}</dl>')
    if c.rng.random() < 0.6:
        b.append(_image(c, _pick(c, ("card", "card_expiry", "name"), 2, 3), "CARD ON FILE"))
    b.append(_decoy_line(c))


def chat_thread(c: Ctx) -> None:
    b = c.page.body
    msgs = []
    count = c.rng.randint(4, 8)
    forced_decoy = c.rng.randrange(count)  # every page has at least one hard negative
    for i in range(count):
        eid = c.page.eid()
        if i == forced_decoy:
            label, v = _decoy(c, c.rng.choice(DECOY_KINDS), f"#{eid} .body")
            text = f"{label}: {v}"
        elif c.rng.random() < 0.6:
            k = c.rng.choice(TEXT_KINDS)
            label = c.label(k)
            shown = _plant(c, k, "text", f"#{eid} .body", label)
            text = c.rng.choice(CHAT_LINES[c.lang]).format(l=label, v=shown)
        elif c.rng.random() < 0.5:
            label, v = _decoy(c, c.rng.choice(DECOY_KINDS), f"#{eid} .body")
            text = f"{label}: {v}"
        else:
            text = c.rng.choice(FILLER[c.lang])
        side = c.rng.choice(("me", "agent"))
        msgs.append(f'<li id="{eid}" class="msg {side}"><p class="body">{E(text)}</p></li>')
    b.append(f'<ol class="chat" role="log">{"".join(msgs)}</ol>')


def receipt(c: Ctx) -> None:
    b = c.page.body
    titles = {
        "en": ("Receipt", "Invoice", "Bill"),
        "hi": ("रसीद", "बिल", "चालान"),
        "hinglish": ("Receipt", "Aapka bill"),
    }
    b.append(f"<h1>{E(c.rng.choice(titles[c.lang]))}</h1>")
    b.extend(_decoy_line(c) for _ in range(c.rng.randint(1, 3)))
    rows = []
    for k in _pick(c, ("name", "email", "phone_in", "upi", "pan", "address", "pin_code"), 3, 5):
        eid = c.page.eid()
        label = c.label(k)
        shown = _plant(c, k, "table_cell", f"#{eid}", label)
        rows.append(f'<tr><th>{E(label)}</th><td id="{eid}">{E(shown)}</td></tr>')
    b.append(f'<table class="kv">{"".join(rows)}</table>')
    b.append(_filler(c))


def kyc_upload(c: Ctx) -> None:
    b = c.page.body
    titles = {"en": ("KYC verification", "Verify your identity"), "hi": ("केवाईसी सत्यापन",), "hinglish": ("KYC karein",)}
    b.append(f"<h1>{E(c.rng.choice(titles[c.lang]))}</h1>")
    b.append(_image(c, _pick(c, ("name", "aadhaar", "dob", "pan", "address"), 2, 4), "IDENTITY DOCUMENT (SAMPLE)"))
    b.append(
        '<form class="stack">'
        + "".join(_input(c, k) for k in _pick(c, ("aadhaar", "pan", "phone_in", "email", "dob"), 2, 3))
        + "</form>"
    )
    b.append(_decoy_line(c))


BUILDERS: dict[str, Callable[[Ctx], None]] = {
    "form_stack": form_stack,
    "form_grid": form_grid,
    "data_table": data_table,
    "profile_card": profile_card,
    "chat_thread": chat_thread,
    "receipt": receipt,
    "kyc_upload": kyc_upload,
}
assert set(BUILDERS) == set(FAMILY_SPLIT)

CSS = """
*{box-sizing:border-box}
body{margin:0;padding:24px;background:var(--bg);color:var(--ink);font-family:var(--font);font-size:var(--size)}
main{max-width:var(--maxw);margin:0 auto}
h1{font-size:1.4em}
label{display:block;margin:10px 0 4px;opacity:.8}
input{width:100%;padding:8px;border:1px solid #8888;border-radius:var(--r);
  background:transparent;color:inherit;font:inherit}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:20px}
fieldset{border:1px solid #8884;border-radius:var(--r)}
table{border-collapse:collapse;width:100%}
td,th{border-bottom:1px solid #8884;padding:6px 8px;text-align:left}
.chat{list-style:none;padding:0;display:flex;flex-direction:column;gap:8px}
.msg{padding:8px 12px;border-radius:12px;max-width:75%}
.msg.me{align-self:flex-end;background:#8882}
.msg.agent{background:#8881}
.msg .body{margin:0}
.profile dt{font-weight:600;margin-top:8px}
.profile dd{margin:2px 0 0}
.muted{opacity:.7}
.meta{font-size:.9em}
a,button{color:var(--accent)}
img{max-width:100%;height:auto;display:block;margin:12px 0}
"""


def _document(p: Page, rng: random.Random) -> str:
    bg, ink, accent, font = rng.choice(THEMES)
    style = (
        f"--bg:{bg};--ink:{ink};--accent:{accent};--font:{font};--size:{rng.choice((13, 14, 15, 16))}px;"
        f"--maxw:{rng.choice((640, 760, 900, 1040))}px;--r:{rng.choice((0, 4, 8))}px"
    )
    lang = "hi" if p.language == "hi" else "en"
    return (
        f'<!doctype html>\n<html lang="{lang}"><head><meta charset="utf-8"><title>{E(p.family)}</title>'
        f'<style>{CSS}</style></head>\n<body style="{style}"><main>\n' + "\n".join(p.body) + "\n</main></body></html>\n"
    )


def page_seed(seed: int, i: int) -> int:
    return zlib.crc32(f"{GENERATOR_VERSION}:{seed}:{i}".encode())


def generate_page(seed: int, i: int) -> tuple[Page, str]:
    ps = page_seed(seed, i)
    rng = random.Random(ps)
    family = FAMILIES[i % len(FAMILIES)]
    p = Page(f"p{i:05d}", family, rng.choice(LANGS), ps)
    BUILDERS[family](Ctx(p))
    return p, _document(p, rng)


def generate(out: Path, seed: int, n: int) -> dict[str, Any]:
    pages_dir, truth_dir = out / "pages", out / "truth"
    for d in (pages_dir, truth_dir):
        if d.exists():
            shutil.rmtree(d)
        d.mkdir(parents=True)
    entries = []
    for i in range(n):
        p, doc = generate_page(seed, i)
        d = pages_dir / p.page_id
        d.mkdir()
        (d / "index.html").write_text(doc, "utf-8")
        for name, data in p.assets.items():
            (d / name).write_bytes(data)
        truth = {
            "schema": "pl.synth_truth.draft",
            "generator": GENERATOR_VERSION,
            "page_id": p.page_id,
            "family": p.family,
            "language": p.language,
            "split": FAMILY_SPLIT[p.family],
            "seed": p.seed,
            "items": [asdict(it) for it in p.items],
            "decoys": [asdict(it) for it in p.decoys],
        }
        (truth_dir / f"{p.page_id}.json").write_text(json.dumps(truth, indent=1, ensure_ascii=False) + "\n", "utf-8")
        entries.append(
            {"page_id": p.page_id, "family": p.family, "language": p.language, "split": FAMILY_SPLIT[p.family],
             "items": len(p.items), "decoys": len(p.decoys)}
        )  # fmt: skip
    splits: dict[str, list[str]] = {}
    for fam, sp in FAMILY_SPLIT.items():
        splits.setdefault(sp, []).append(fam)
    manifest = {
        "generator": GENERATOR_VERSION,
        "seed": seed,
        "n_pages": n,
        "splits": splits,
        "pages": entries,
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=1, ensure_ascii=False) + "\n", "utf-8")
    return manifest


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--seed", type=int, default=20261029)
    ap.add_argument("--n", type=int, default=140)
    ap.add_argument("--out", type=Path, default=Path("build/synth"))
    a = ap.parse_args()
    m = generate(a.out, a.seed, a.n)
    print(json.dumps({"n_pages": m["n_pages"], "splits": m["splits"]}, ensure_ascii=False))


if __name__ == "__main__":
    main()
