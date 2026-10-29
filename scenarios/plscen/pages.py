"""The five required scenario pages (spec §15). Values come from ml/gen/values.py.

Each function fills one template's slots and records ground truth. Selectors
use ids a real site might use; nothing in the markup labels the answers.
"""

from __future__ import annotations

import json
from collections.abc import Callable

from gen.values import Gen, is_aadhaar, is_card, luhn_check_digit

from .builder import PageBuilder

ZWSP = "​"


def _fullwidth(s: str) -> str:
    return "".join(chr(0xFF10 + int(c)) if c.isdigit() else c for c in s)


def _phone(g: Gen) -> str:
    """A 10-digit mobile that can't be misread as another type when shown with a 91/0 prefix.

    About 1 in 10 "+91 <mobile>" strings form a Verhoeff-valid 12-digit run (an
    Aadhaar look-alike). That's a fine hard case for the synthetic generator, but
    the hand-built scenario pages need unambiguous ground truth.
    """
    while True:
        n = g.phone_in("plain")
        if not any(is_aadhaar(pfx + n) or is_card(pfx + n) for pfx in ("91", "0", "091")):
            return n


def _non_luhn_order_number(g: Gen) -> str:
    """16 digits starting like a Visa card but failing Luhn: must not be redacted."""
    payload = "4" + "".join(g.rng.choice("0123456789") for _ in range(14))
    return payload + str((luhn_check_digit(payload) + 1 + g.rng.randrange(9)) % 10)


def login(g: Gen, p: PageBuilder) -> None:
    name = g.name()
    email = g.email(name)
    phone = _phone(g)
    p.text("display_name", name.split()[0])
    p.put("email", type="email", value=email, selector="#email", channel="input_value")
    p.put("password", type="password", value=g.password(), selector="#password", channel="input_value")
    otp = g.otp()
    p.put("otp", type="otp", value=otp, selector="#otp", channel="input_value")
    p.put("sms_otp", type="otp", value=otp, selector="#sms-toast .otp-code", channel="text")
    p.put(
        "otp_phone",
        type="phone_in",
        value=phone,
        shown=f"+91 {phone[:5]} {phone[5:]}",
        selector="#send-otp",
        channel="attribute",
        attribute="aria-label",
    )
    p.put_url_param("reset_email", type="email", value=email, selector="#forgot-link", attribute="href")
    p.put(
        "csrf",
        type="canary",
        value=g.canary_token(),
        selector="input[name=csrf_token]",
        channel="input_hidden",
        canary=True,
    )
    p.put(
        "last_user",
        type="phone_in",
        value=phone,
        selector="#login-form",
        channel="attribute",
        attribute="data-last-user",
    )


def checkout(g: Gen, p: PageBuilder) -> None:
    name = g.name()
    card = g.card("visa")
    p.put(
        "card_number",
        type="card",
        value=card,
        shown=Gen.format_card(card),
        selector="#card-number",
        channel="input_value",
    )
    p.put("card_name", type="name", value=name, selector="#card-name", channel="input_value")
    p.put("card_expiry", type="card_expiry", value=g.card_expiry(), selector="#card-expiry", channel="input_value")
    p.put("card_cvv", type="cvv", value=g.cvv(), selector="#card-cvv", channel="input_value")
    line, city_pin = g.address()
    pin = city_pin.rsplit(" ", 1)[1]
    p.put("addr_line", type="address", value=line, selector="#addr-line", channel="input_value")
    p.text("addr_city", city_pin.rsplit(" ", 1)[0])
    p.put("addr_pin", type="pin_code", value=pin, selector="#addr-pin", channel="input_value")
    phone = _phone(g)
    p.put("phone", type="phone_in", value=phone, shown=f"+91{phone}", selector="#phone", channel="input_value")
    p.put("email", type="email", value=g.email(name), selector="#email", channel="input_value")
    p.put("pan", type="pan", value=g.pan("P", name.split()[1][0]), selector="#gst-pan", channel="input_value")

    saved = g.card("mastercard")
    p.put_split(
        "saved_card",
        type="card",
        value=saved,
        shown=Gen.format_card(saved),
        selector="#saved-card .digits",
        parts=[4, 4, 4, 4],
    )
    p.put(
        "upi", type="upi", value=g.upi(name.split()[0]), selector="#pay-upi", channel="attribute", attribute="data-vpa"
    )
    canary_card = g.card("visa")
    p.put(
        "canary_card",
        type="card",
        value=canary_card,
        shown=Gen.format_card(canary_card),
        selector="#card-on-file",
        channel="attribute",
        attribute="title",
        canary=True,
    )
    photo = g.card("rupay")
    p.put_image(
        "card_img",
        filename="card-photo.png",
        selector="#card-photo",
        lines=["RUPAY  DEBIT", Gen.format_card(photo), f"VALID THRU {g.card_expiry()}", name.upper()],
        planted=[("card", photo, Gen.format_card(photo)), ("name", name, name.upper())],
    )
    p.decoy("order_no", type="card", value=_non_luhn_order_number(g), selector="#order-number")
    p.put_url_param("track_phone", type="phone_in", value=phone, selector="#track-order", attribute="href")


def support(g: Gen, p: PageBuilder) -> None:
    name = g.name()
    first = name.split()[0]
    phone = _phone(g)
    p.text("customer_first", first)
    aadhaar = g.aadhaar()
    p.put(
        "msg_aadhaar",
        type="aadhaar",
        value=aadhaar,
        shown=Gen.format_aadhaar(aadhaar),
        selector="#msg-2 .body",
        channel="text",
    )
    p.put("msg_dob", type="dob", value=(dob := g.dob("%d/%m/%Y")), shown=dob, selector="#msg-2 .body", channel="text")
    p.put(
        "msg_phone",
        type="phone_in",
        value=phone,
        shown=_fullwidth(f"{phone[:5]} {phone[5:]}"),
        selector="#msg-4 .body",
        channel="text",
        obfuscation=["fullwidth_digits"],
    )
    pan = g.pan("P", name.split()[1][0])
    p.put(
        "msg_pan",
        type="pan",
        value=pan,
        shown=pan[:5] + ZWSP + pan[5:],
        selector="#msg-6 .body",
        channel="text",
        obfuscation=["zero_width"],
    )
    email = g.email(name)
    p.put("msg_email", type="email", value=email, selector="#msg-6 .body", channel="text")
    acct = g.bank_account()
    ifsc = g.ifsc()
    p.put_image(
        "cheque_img",
        filename="cheque.png",
        selector="#attach-cheque",
        lines=["SAFFRON BANK", f"IFSC: {ifsc}", f"A/C No: {acct}", f"Pay: {name}"],
        planted=[("ifsc", ifsc, ifsc), ("bank_account", acct, acct), ("name", name, name)],
        style="cheque",
    )
    p.put(
        "cheque_alt_acct",
        type="bank_account",
        value=acct,
        selector="#attach-cheque",
        channel="attribute",
        attribute="alt",
    )
    p.put("draft_upi", type="upi", value=g.upi(first), selector="#composer", channel="input_value")
    p.put_url_param("ticket_email", type="email", value=email, selector="#ticket-link", attribute="href")
    p.put(
        "customer_phone",
        type="phone_in",
        value=phone,
        selector="#chat-thread",
        channel="attribute",
        attribute="data-customer-phone",
    )


# Video call canvas layout: 2x2 tiles of 480x270; tiles 0-2 cameras, tile 3 screen share.
TILE_W, TILE_H = 480, 270
SKIN = ("#8d5524", "#c68642", "#e0ac69", "#f1c27d", "#a8754f", "#6b4226")
HAIR = ("#1b1b1b", "#3b2414", "#5a3a1a", "#2e2e3a")
SHIRT = ("#3a6ea5", "#7a3e9d", "#2f8f6b", "#b5523b", "#44546a")


def video(g: Gen, p: PageBuilder) -> None:
    faces = []
    names = []
    for i in range(3):
        names.append(g.name())
        x0, y0 = (i % 2) * TILE_W, (i // 2) * TILE_H
        rx, ry = g.rng.randint(44, 56), g.rng.randint(58, 70)
        cx, cy = x0 + TILE_W // 2, y0 + 118
        motion = {"amp_x": float(g.rng.randint(8, 24)), "period_ms": float(g.rng.randint(2500, 6000))}
        faces.append(
            {
                "cx": cx,
                "cy": cy,
                "rx": rx,
                "ry": ry,
                **motion,
                "skin": g.rng.choice(SKIN),
                "hair": g.rng.choice(HAIR),
                "shirt": g.rng.choice(SHIRT),
                "blink_ms": g.rng.randint(2500, 5000),
            }
        )
        # Box covers head + hair (video.js: hair ellipse is 1.08 rx wide, 0.12 ry higher), at t=0.
        half_w, top = int(rx * 1.08) + 1, cy - int(ry * 1.12) - 1
        p.face(
            f"face_{i}", selector="#call-canvas", box=[cx - half_w, top, 2 * half_w, cy + ry + 1 - top], motion=motion
        )
    for i, n in enumerate(names):
        p.put(f"p{i}_name", type="name", value=n, selector=f"#participant-{i}", channel="text")
    p.put(
        "p1_email",
        type="email",
        value=g.email(names[1]),
        selector="#tile-label-1",
        channel="attribute",
        attribute="aria-label",
    )

    host = names[0]
    aadhaar = g.aadhaar()
    dob = g.dob("%d/%m/%Y")
    p.put_image(
        "share_img",
        filename="screen-share.png",
        selector="#call-canvas",
        lines=["e-KYC FORM (draft)", f"Name: {host}", f"Aadhaar: {Gen.format_aadhaar(aadhaar)}", f"DOB: {dob}"],
        planted=[("name", host, host), ("aadhaar", aadhaar, Gen.format_aadhaar(aadhaar)), ("dob", dob, dob)],
        style="document",
        channel="canvas",
        box=[TILE_W, TILE_H, TILE_W, TILE_H],
    )
    phone = _phone(g)
    p.put(
        "chat_phone",
        type="phone_in",
        value=phone,
        shown=f"{phone[:5]}-{phone[5:]}",
        selector="#chat-1 .body",
        channel="text",
    )
    p.put("chat_upi", type="upi", value=g.upi(names[2].split()[0]), selector="#chat-2 .body", channel="text")
    p.put_url_param("invite_email", type="email", value=g.email(names[2]), selector="#invite-link", attribute="href")
    config = {"tile": [TILE_W, TILE_H], "faces": faces}
    p.raw("call_config", json.dumps(config, sort_keys=True).replace("<", "\\u003c"))


def devsettings(g: Gen, p: PageBuilder) -> None:
    owner = g.name()
    p.put("owner_email", type="email", value=g.email(owner), selector="#owner-email", channel="text")
    sk = g.api_key("sk")
    p.put("sk_key", type="api_key", value=sk, selector="#key-primary", channel="text")
    p.put("sk_copy", type="api_key", value=sk, selector="#copy-primary", channel="attribute", attribute="aria-label")
    p.put("ghp", type="api_key", value=g.api_key("ghp"), selector="#github-token", channel="input_value")
    p.put(
        "akia",
        type="api_key",
        value=g.api_key("akia"),
        selector="#aws-row",
        channel="attribute",
        attribute="data-access-key-id",
    )
    p.put("jwt", type="api_key", value=g.api_key("jwt"), selector="#curl-example", channel="text")
    p.put(
        "webhook_canary",
        type="canary",
        value=g.canary_token(),
        selector="#webhook-url",
        channel="input_value",
        canary=True,
    )
    p.put_url_param("docs_key", type="api_key", value=g.api_key("sk"), selector="#docs-link", attribute="href")
    p.put("ip_1", type="ipv4", value=g.ipv4(), selector="#ip-1", channel="text")
    p.put("ip_2", type="ipv4", value=g.ipv4(), selector="#ip-2", channel="text")


PAGES: dict[str, Callable[[Gen, PageBuilder], None]] = {
    "login": login,
    "checkout": checkout,
    "support": support,
    "video": video,
    "devsettings": devsettings,
}
