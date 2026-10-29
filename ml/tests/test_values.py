"""Property and vector tests for ml/gen/values.py."""

from __future__ import annotations

import random
import string
from collections.abc import Callable

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from gen import values as v
from gen.values import Gen

seeds = st.integers(min_value=0, max_value=2**32 - 1)

# ---------------------------------------------------------------- known vectors


def test_luhn_vectors() -> None:
    assert v.luhn_valid("79927398713")
    assert not v.luhn_valid("79927398710")
    assert v.luhn_valid("4111111111111111")  # public test card
    assert v.luhn_check_digit("7992739871") == 3


def test_verhoeff_vectors() -> None:
    # Published example (Verhoeff, Wikipedia): 236 -> 3.
    assert v.verhoeff_check_digit("236") == 3
    assert v.verhoeff_valid("2363")
    assert not v.verhoeff_valid("2364")


def _d5_mul(j: int, k: int) -> int:
    # Dihedral group D5: 0-4 rotations, 5-9 reflections (Verhoeff's numbering).
    if j < 5:
        return (j + k) % 5 if k < 5 else 5 + (j + k) % 5
    return 5 + (j - k) % 5 if k < 5 else (j - k) % 5


_SIGMA = {0: 1, 1: 5, 5: 8, 8: 9, 9: 4, 4: 2, 2: 7, 7: 0, 3: 6, 6: 3}


def _sigma_pow(i: int, x: int) -> int:
    for _ in range(i):
        x = _SIGMA[x]
    return x


def _oracle_check_digit(payload: str) -> int:
    """Verhoeff from first principles (group + permutation), no lookup tables."""
    digits = [int(c) for c in reversed(payload)]
    for check in range(10):
        c = 0
        for i, d in enumerate([check, *digits]):
            c = _d5_mul(c, _sigma_pow(i % 8, d))
        if c == 0:
            return check
    raise AssertionError("no check digit")


@given(payload=st.text(alphabet=string.digits, min_size=1, max_size=20))
def test_verhoeff_matches_group_oracle(payload: str) -> None:
    assert v.verhoeff_check_digit(payload) == _oracle_check_digit(payload)


def test_card_brand_ranges() -> None:
    assert v.card_brand("4" + "0" * 15) == "visa"
    assert v.card_brand("2221" + "0" * 12) == "mastercard"
    assert v.card_brand("2720" + "0" * 12) == "mastercard"
    assert v.card_brand("2721" + "0" * 12) is None
    assert v.card_brand("2220" + "0" * 12) is None
    assert v.card_brand("34" + "0" * 13) == "amex"
    assert v.card_brand("34" + "0" * 14) is None  # amex is 15 long
    assert v.card_brand("652150" + "0" * 10) == "rupay"
    assert v.card_brand("653150" + "0" * 10) == "discover"
    assert v.card_brand("9" * 16) is None


def test_card_accepts_display_separators() -> None:
    g = Gen(1)
    c = g.card("visa")
    assert v.is_card(Gen.format_card(c))
    assert v.is_card(Gen.format_card(c, "-"))


def test_random_order_numbers_mostly_rejected() -> None:
    # The spec's example: a random 16-digit order number fails Luhn ~90% of the time.
    rng = random.Random(7)
    nums = ["4" + "".join(rng.choice(string.digits) for _ in range(15)) for _ in range(5000)]
    rate = sum(v.is_card(n) for n in nums) / len(nums)
    assert 0.07 < rate < 0.13


# ---------------------------------------------------------------- generated values validate

KINDS: dict[str, Callable[[Gen], str]] = {
    "card": lambda g: g.card(),
    "aadhaar": lambda g: g.aadhaar(),
    "pan": lambda g: g.pan(),
    "ifsc": lambda g: g.ifsc(),
    "upi": lambda g: g.upi(),
    "phone_in": lambda g: g.phone_in(),
    "email": lambda g: g.email(),
    "dob": lambda g: g.dob(),
    "canary": lambda g: g.canary_token(),
    "card_expiry": lambda g: g.card_expiry(),
    "cvv": lambda g: g.cvv(),
    "bank_account": lambda g: g.bank_account(),
    "pin_code": lambda g: g.pin_code(),
    "passport_in": lambda g: g.passport_in(),
    "otp": lambda g: g.otp(),
    "ipv4": lambda g: g.ipv4(),
    "password": lambda g: g.password(),
    "name": lambda g: g.name(),
}


@pytest.mark.parametrize("kind", sorted(KINDS))
@given(seed=seeds)
@settings(max_examples=300)
def test_generated_values_validate(kind: str, seed: int) -> None:
    value = KINDS[kind](Gen(seed))
    assert v.validate(kind, value), (kind, value)


@pytest.mark.parametrize("brand", v.CARD_BRANDS)
@given(seed=seeds)
@settings(max_examples=200)
def test_card_brand_roundtrip(brand: str, seed: int) -> None:
    c = Gen(seed).card(brand)
    assert v.card_brand(c) == brand
    assert v.is_card(c)


@pytest.mark.parametrize("kind", ["sk", "ghp", "akia", "jwt"])
@given(seed=seeds)
@settings(max_examples=100)
def test_api_keys_validate(kind: str, seed: int) -> None:
    assert v.is_api_key(Gen(seed).api_key(kind))


@given(seed=seeds)
def test_aadhaar_first_digit(seed: int) -> None:
    a = Gen(seed).aadhaar()
    assert len(a) == 12 and a[0] in "23456789"
    assert v.is_aadhaar(Gen.format_aadhaar(a))


@given(seed=seeds)
def test_upi_is_not_email(seed: int) -> None:
    assert not v.is_email(Gen(seed).upi())


@given(seed=seeds)
def test_email_uses_reserved_domains(seed: int) -> None:
    assert Gen(seed).email().rsplit("@", 1)[1] in v.EMAIL_DOMAINS


@given(seed=seeds)
def test_ipv4_is_documentation_range(seed: int) -> None:
    assert Gen(seed).ipv4().rsplit(".", 1)[0] in v.IPV4_DOC_NETS


# ---------------------------------------------------------------- near-misses fail


@pytest.mark.parametrize("kind", sorted(v.NEAR_MISS))
@given(seed=seeds, mseed=seeds)
@settings(max_examples=400)
def test_near_misses_fail(kind: str, seed: int, mseed: int) -> None:
    good = KINDS[kind](Gen(seed))
    bad = v.near_miss(kind, good, random.Random(mseed))
    assert bad != good
    assert not v.validate(kind, bad), (kind, good, bad)


@given(seed=seeds, pos=st.integers(0, 15), new=st.sampled_from(string.digits))
def test_luhn_catches_every_single_digit_error(seed: int, pos: int, new: str) -> None:
    c = Gen(seed).card("visa")
    if c[pos] == new:
        return
    assert not v.luhn_valid(c[:pos] + new + c[pos + 1 :])


@given(seed=seeds, pos=st.integers(0, 14))
def test_luhn_catches_adjacent_swaps_except_09(seed: int, pos: int) -> None:
    c = Gen(seed).card("visa")
    a, b = c[pos], c[pos + 1]
    if a == b or {a, b} == {"0", "9"}:
        return
    assert not v.luhn_valid(c[:pos] + b + a + c[pos + 2 :])


@given(seed=seeds, pos=st.integers(0, 11), new=st.sampled_from(string.digits))
def test_verhoeff_catches_every_single_digit_error(seed: int, pos: int, new: str) -> None:
    a = Gen(seed).aadhaar()
    if a[pos] == new:
        return
    assert not v.verhoeff_valid(a[:pos] + new + a[pos + 1 :])


@given(seed=seeds, pos=st.integers(0, 10))
def test_verhoeff_catches_every_adjacent_swap(seed: int, pos: int) -> None:
    a = Gen(seed).aadhaar()
    if a[pos] == a[pos + 1]:
        return
    assert not v.verhoeff_valid(a[:pos] + a[pos + 1] + a[pos] + a[pos + 2 :])


@given(s=st.text(alphabet=string.digits, min_size=12, max_size=12))
def test_aadhaar_validator_matches_definition(s: str) -> None:
    assert v.is_aadhaar(s) == (s[0] not in "01" and v.verhoeff_valid(s))


@given(s=st.text(min_size=0, max_size=40))
def test_validators_never_crash(s: str) -> None:
    for fn in v.VALIDATORS.values():
        assert fn(s) in (True, False)


def test_non_ascii_digits_rejected() -> None:
    # Full-width digits must be normalised by detect, not silently accepted here.
    full = "".join(chr(0xFF10 + int(c)) for c in "4111111111111111")  # full-width digits
    assert not v.is_card(full)
    assert not v.luhn_valid(full)


def test_dob_rules() -> None:
    assert v.is_dob("14/03/1989")
    assert v.is_dob("1989-03-14")
    assert v.is_dob("14 Mar 1989")
    assert not v.is_dob("31/02/1990")
    assert not v.is_dob("1/3/1989")  # non-canonical
    assert not v.is_dob("14/03/1850")  # older than 120
    assert not v.is_dob("14/03/2030")  # future


def test_canary_detection_in_text() -> None:
    g = Gen(3)
    c1, c2 = g.canary_token(), g.canary_token()
    text = f"hello {c1} and {c2[:-1]}x and {c2}"
    assert v.find_canary_tokens(text) == [c1, c2]


# ---------------------------------------------------------------- determinism


def _sample(seed: int) -> list[str]:
    g = Gen(seed)
    return [fn(g) for fn in KINDS.values()] + [g.api_key(k) for k in ("sk", "ghp", "akia", "jwt")]


@given(seed=seeds)
@settings(max_examples=50)
def test_same_seed_same_values(seed: int) -> None:
    assert _sample(seed) == _sample(seed)


def test_different_seeds_differ() -> None:
    assert _sample(1) != _sample(2)
