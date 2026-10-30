"""Unit tests for the demo modules that need no browser: vault binding, leak encodings, detection."""

from __future__ import annotations

import base64

from pldemo import detect as D
from pldemo.leak import find_leaks, variants
from pldemo.vault import Binding, Vault


def test_vault_opens_only_for_the_exact_binding() -> None:
    v = Vault()
    s = v.seal("4111111111111111", "[REDACTED:CARD#1234]", "CARD", "n12")
    assert v.open(s, s.binding) == "4111111111111111"
    wrong_bindings = [
        {"element": "n13"},
        {"site": "evil.example"},
        {"field_type": "PAN"},
        {"placeholder": "[REDACTED:CARD#1235]"},
        {"session": "0" * 16},
    ]
    for kw in wrong_bindings:
        b = s.binding
        wrong = Binding(**{**b.__dict__, **kw})
        assert v.open(s, wrong) is None, kw
    assert all(v.binding_test(s, "4111111111111111", "n99").values())


def test_leak_check_finds_encodings_and_ignores_clean_text() -> None:
    item = {"id": "x", "type": "card", "value": "4111111111111111", "shown": "4111 1111 1111 1111"}
    forms = [
        "4111 1111 1111 1111",
        "4111-1111-1111-1111",
        base64.b64encode(b"4111111111111111").decode(),
        b"4111111111111111".hex(),
        "4111%201111%201111%201111",
        "1111111111111114",
    ]
    for text in forms:
        assert find_leaks([text], [item]), text
    assert not find_leaks(["[REDACTED:CARD#4821] and Order 4219910283914533"], [item])
    assert "base64" in variants("abc123")


def test_short_values_do_not_match_inside_numbers() -> None:
    cvv = {"id": "c", "type": "cvv", "value": "123", "shown": "123"}
    assert not find_leaks(["[REDACTED:CARD#1234] 1234567"], [cvv])
    assert find_leaks(["cvv 123 ok"], [cvv])


def test_detect_names_and_phone_with_plus() -> None:
    t, _ = D.normalize("Hi Tenzin Singh, call +91 98765 43210")
    cats = {(h.category, t[h.begin : h.end]) for h in D.scan(t)}
    assert ("NAME", "Tenzin Singh") in cats
    assert ("PHONE", "+91 98765 43210") in cats


def test_normalize_keeps_source_offsets() -> None:
    s = chr(0xFF14) + chr(0xFF11) + chr(0x200B) + "11"
    t, src = D.normalize(s)
    assert t == "4111" and src == [0, 1, 3, 4]
