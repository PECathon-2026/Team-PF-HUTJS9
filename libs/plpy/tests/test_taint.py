from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from plpy.taint import CATEGORIES, TaintLabel, TaintLevel

labels = st.builds(
    lambda cats, lvl: TaintLabel.of(cats[0]).join(TaintLabel(TaintLevel(lvl))) if cats else TaintLabel(TaintLevel(lvl)),
    st.lists(st.sampled_from(sorted(CATEGORIES)), max_size=1),
    st.integers(0, 4),
).flatmap(lambda base: st.lists(st.sampled_from(sorted(CATEGORIES)), max_size=4).map(lambda cs: _join_all(base, cs)))


def _join_all(base: TaintLabel, cats: list[str]) -> TaintLabel:
    for c in cats:
        base = base.join(TaintLabel.of(c))
    return base


def test_bottom_and_egress() -> None:
    assert TaintLabel().allows_egress
    assert not TaintLabel(TaintLevel.INTERNAL).allows_egress
    assert not TaintLabel.of("EMAIL").allows_egress


def test_join_most_secret() -> None:
    j = TaintLabel.of("CARD").join(TaintLabel.of("PASSWORD"))
    assert j.level is TaintLevel.SECRET
    assert j.categories == {"CARD", "PASSWORD"}
    assert TaintLabel.of("CARD").leq(j) and not j.leq(TaintLabel.of("CARD"))


def test_json_round_trip_and_rejects() -> None:
    lab = TaintLabel.of("AADHAAR").join(TaintLabel.of("EMAIL"))
    j = lab.to_json()
    assert j == {"schema": "taint_label.v1", "level": "sensitive", "categories": ["AADHAAR", "EMAIL"]}
    assert TaintLabel.from_json(j) == lab
    with pytest.raises(ValueError):
        TaintLabel.from_json({"schema": "x"})
    with pytest.raises(ValueError):
        TaintLabel.from_json({"schema": "taint_label.v1", "level": "huge", "categories": []})
    with pytest.raises(ValueError):
        TaintLabel.from_json({"schema": "taint_label.v1", "level": "public", "categories": ["NOPE"]})
    with pytest.raises(ValueError):
        TaintLabel.from_json({"schema": "taint_label.v1", "level": "public", "categories": ["CARD"]})


def test_top_and_order_matches_cpp() -> None:
    assert all(TaintLabel.of(c).leq(TaintLabel.top()) for c in CATEGORIES)
    assert list(CATEGORIES)[:3] == ["CARD", "AADHAAR", "PAN"] and len(CATEGORIES) == 20


@given(labels, labels, labels)
def test_lattice_laws(x: TaintLabel, y: TaintLabel, z: TaintLabel) -> None:
    assert x.join(y) == y.join(x)
    assert x.join(y).join(z) == x.join(y.join(z))
    assert x.join(x) == x
    assert x.meet(y) == y.meet(x)
    assert x.meet(y).meet(z) == x.meet(y.meet(z))
    assert x.join(x.meet(y)) == x
    assert x.meet(x.join(y)) == x
    assert x.leq(x.join(y)) and y.leq(x.join(y))
    assert x.meet(y).leq(x) and x.meet(y).leq(y)
    assert x.leq(y) == (x.join(y) == y)
    assert TaintLabel().leq(x)
    assert TaintLabel.from_json(x.to_json()) == x
    assert x.allows_egress == (x == TaintLabel())
