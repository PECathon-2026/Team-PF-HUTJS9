from __future__ import annotations

import json
import random
import re
from pathlib import Path

import pytest
from gen_scrub_corpus import OUT, corpus
from hypothesis import given
from hypothesis import strategies as st

from plpy.scrub import luhn_valid, scrub, verhoeff_valid

VECTORS = Path(__file__).resolve().parents[2] / "plcommon" / "testdata" / "scrubber_vectors.json"


def _vectors() -> list[dict[str, object]]:
    data = json.loads(VECTORS.read_text())
    return list(data["vectors"])


@pytest.mark.parametrize("v", _vectors(), ids=lambda v: str(v["name"]))
def test_shared_vectors(v: dict[str, object]) -> None:
    raw = v["input"]
    text = "".join(raw) if isinstance(raw, list) else str(raw)
    assert scrub(text) == v["expected"]


def test_check_digits() -> None:
    assert luhn_valid("4111111111111111") and luhn_valid("0")
    assert not luhn_valid("4111111111111112") and not luhn_valid("") and not luhn_valid("41a1")
    assert verhoeff_valid("2363") and not verhoeff_valid("2364")
    assert not verhoeff_valid("") and not verhoeff_valid("23x3")


def test_never_leaves_long_digit_runs() -> None:
    rng = random.Random(1234)
    for _ in range(2000):
        s = "x " + "".join(rng.choice("0123456789 -") for _ in range(24))
        assert not re.search(r"[0-9]{6}", scrub(s))


@given(st.text(max_size=200))
def test_total_and_no_long_digit_runs(s: str) -> None:
    out = scrub(s)
    assert not re.search(r"[0-9]{6}", out)
    assert scrub(out) == out  # idempotent: tags never form new matches


def test_random_corpus_is_current() -> None:
    """The committed random corpus (also run by the C++ tests) matches plpy's output today."""
    assert json.loads(OUT.read_text())["cases"] == corpus()
