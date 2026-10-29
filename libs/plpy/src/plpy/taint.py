"""Taint lattice, mirroring pl/taint.hpp (spec §6). Wire form: taint_label.v1."""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import Any


class TaintLevel(enum.IntEnum):
    PUBLIC = 0
    INTERNAL = 1
    PERSONAL = 2
    SENSITIVE = 3
    SECRET = 4

    @property
    def wire(self) -> str:
        return self.name.lower()


# Category name (also the placeholder type) -> minimum level. Order matches the C++ enum.
CATEGORIES: dict[str, TaintLevel] = {
    "CARD": TaintLevel.SENSITIVE,
    "AADHAAR": TaintLevel.SENSITIVE,
    "PAN": TaintLevel.SENSITIVE,
    "API_KEY": TaintLevel.SECRET,
    "OTP": TaintLevel.SECRET,
    "PASSWORD": TaintLevel.SECRET,
    "EMAIL": TaintLevel.PERSONAL,
    "PHONE": TaintLevel.PERSONAL,
    "IP_ADDRESS": TaintLevel.PERSONAL,
    "PIN_CODE": TaintLevel.PERSONAL,
    "BANK_ACCOUNT": TaintLevel.SENSITIVE,
    "IFSC": TaintLevel.PERSONAL,
    "UPI_ID": TaintLevel.PERSONAL,
    "PASSPORT": TaintLevel.SENSITIVE,
    "DOB": TaintLevel.PERSONAL,
    "NAME": TaintLevel.PERSONAL,
    "ADDRESS": TaintLevel.PERSONAL,
    "FACE": TaintLevel.PERSONAL,
    "SECRET": TaintLevel.SECRET,
    "QUASI_ID": TaintLevel.PERSONAL,
}
_ORDER = list(CATEGORIES)


def _implied(cats: frozenset[str]) -> TaintLevel:
    return max((CATEGORIES[c] for c in cats), default=TaintLevel.PUBLIC)


@dataclass(frozen=True)
class TaintLabel:
    level: TaintLevel = TaintLevel.PUBLIC
    categories: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        unknown = self.categories - CATEGORIES.keys()
        if unknown:
            raise ValueError(f"unknown taint categories {sorted(unknown)}")
        if self.level < _implied(self.categories):
            raise ValueError("taint level is below what its categories imply")

    @classmethod
    def of(cls, category: str) -> TaintLabel:
        return cls(CATEGORIES[category], frozenset({category}))

    @classmethod
    def top(cls) -> TaintLabel:
        return cls(TaintLevel.SECRET, frozenset(CATEGORIES))

    def join(self, other: TaintLabel) -> TaintLabel:
        return TaintLabel(max(self.level, other.level), self.categories | other.categories)

    def meet(self, other: TaintLabel) -> TaintLabel:
        return TaintLabel(min(self.level, other.level), self.categories & other.categories)

    def leq(self, other: TaintLabel) -> bool:
        return self.level <= other.level and self.categories <= other.categories

    @property
    def allows_egress(self) -> bool:
        return self.level is TaintLevel.PUBLIC and not self.categories

    def to_json(self) -> dict[str, Any]:
        return {
            "schema": "taint_label.v1",
            "level": self.level.wire,
            "categories": [c for c in _ORDER if c in self.categories],
        }

    @classmethod
    def from_json(cls, j: dict[str, Any]) -> TaintLabel:
        if j.get("schema") != "taint_label.v1":
            raise ValueError("not a taint_label.v1")
        try:
            level = TaintLevel[str(j["level"]).upper()]
        except KeyError as e:
            raise ValueError("unknown taint level") from e
        return cls(level, frozenset(j["categories"]))
