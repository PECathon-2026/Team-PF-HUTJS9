"""The only things the model may ask for (spec §9 "Always-valid actions").

``ACTION_SCHEMA`` is the JSON Schema handed to Ollama's ``format`` for
constrained decoding. The model's output is still re-validated here by
``parse_action``, which is stricter than the schema can express.

There is deliberately no action that returns data (no read, get, extract,
copy, screenshot): the model only ever gets the next sanitized page.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

KINDS = ("click", "fill", "select", "navigate", "scroll", "done")
SOURCES = ("system", "user", "webpage")
PLACEHOLDER_RE = re.compile(r"\[REDACTED:([A-Z][A-Z0-9_]{0,23})#([0-9]{1,6})\]")
NODE_ID_RE = re.compile(r"[A-Za-z0-9_:-]{1,64}")
MAX_RATIONALE = 300
MAX_QUOTE = 300
MAX_URL = 2048

_JUSTIFICATION = {
    "type": "array",
    "minItems": 1,
    "maxItems": 4,
    "items": {
        "type": "object",
        "additionalProperties": False,
        "required": ["source", "quote"],
        "properties": {
            "source": {"enum": list(SOURCES)},
            "quote": {"type": "string", "minLength": 1, "maxLength": MAX_QUOTE},
        },
    },
}
_COMMON = {
    "kind": {"enum": list(KINDS)},
    "rationale": {"type": "string", "maxLength": MAX_RATIONALE},
    "justification": _JUSTIFICATION,
}


def _variant(kind: str, required: list[str], extra: dict[str, Any]) -> dict[str, Any]:
    props = {**_COMMON, "kind": {"const": kind}, **extra}
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["kind", "justification", *required],
        "properties": props,
    }


_TARGET = {"type": "string", "pattern": "^" + NODE_ID_RE.pattern + "$"}
ACTION_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "agent_action (draft)",
    "oneOf": [
        _variant("click", ["target"], {"target": _TARGET}),
        _variant(
            "fill",
            ["target", "placeholder"],
            {"target": _TARGET, "placeholder": {"type": "string", "pattern": "^" + PLACEHOLDER_RE.pattern + "$"}},
        ),
        _variant("select", ["target", "option"], {"target": _TARGET, "option": {"type": "string", "maxLength": 200}}),
        _variant("navigate", ["url"], {"url": {"type": "string", "maxLength": MAX_URL}}),
        _variant("scroll", ["direction"], {"direction": {"enum": ["up", "down"]}}),
        _variant("done", [], {}),
    ],
}


@dataclass(frozen=True)
class Justification:
    source: str
    quote: str


@dataclass(frozen=True)
class Action:
    kind: str
    justification: tuple[Justification, ...]
    rationale: str = ""
    target: str | None = None
    placeholder: str | None = None
    option: str | None = None
    url: str | None = None
    direction: str | None = None


class ActionError(ValueError):
    """The model's output isn't a well-formed action. ``rule_id`` names why."""

    def __init__(self, rule_id: str, reason: str) -> None:
        super().__init__(f"{rule_id}: {reason}")
        self.rule_id = rule_id
        self.reason = reason


_FIELDS = {
    "click": {"target"},
    "fill": {"target", "placeholder"},
    "select": {"target", "option"},
    "navigate": {"url"},
    "scroll": {"direction"},
    "done": set(),
}
_COORD_KEYS = {"x", "y", "coords", "coordinates", "point", "position", "offset_x", "offset_y"}


def _str(d: dict[str, Any], key: str, limit: int) -> str:
    v = d[key]
    if not isinstance(v, str) or len(v) > limit:
        raise ActionError("A-01", f"{key} must be a string of at most {limit} chars")
    return v


def parse_action(raw: str | dict[str, Any]) -> Action:
    """Strictly parse one action. Anything unexpected is an error, never ignored."""
    if isinstance(raw, str):
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            raise ActionError("A-01", "output is not JSON") from e
    else:
        data = raw
    if not isinstance(data, dict):
        raise ActionError("A-01", "action must be a JSON object")
    kind = data.get("kind")
    if kind not in KINDS:
        # read/get/extract/copy/eval... are not missing features: they're refused.
        raise ActionError("A-22", f"unknown action kind {kind!r} (there is no read-back action)")
    keys = set(data)
    if keys & _COORD_KEYS:
        raise ActionError("A-06", "coordinate clicks are not allowed")
    allowed = {"kind", "justification", "rationale"} | _FIELDS[kind]
    if keys - allowed:
        raise ActionError("A-01", f"unexpected fields {sorted(keys - allowed)}")
    if missing := (_FIELDS[kind] | {"justification"}) - keys:
        raise ActionError("A-01", f"missing fields {sorted(missing)}")

    just = data["justification"]
    if not isinstance(just, list) or not 1 <= len(just) <= 4:
        raise ActionError("A-01", "justification must list 1-4 items")
    js = []
    for j in just:
        if not isinstance(j, dict) or set(j) != {"source", "quote"} or j["source"] not in SOURCES:
            raise ActionError("A-01", "each justification needs exactly a source and a quote")
        q = _str(j, "quote", MAX_QUOTE)
        if not q.strip():
            raise ActionError("A-01", "empty justification quote")
        js.append(Justification(j["source"], q))

    rationale = _str(data, "rationale", MAX_RATIONALE) if "rationale" in data else ""
    kw: dict[str, str] = {}
    if "target" in _FIELDS[kind]:
        t = _str(data, "target", 64)
        if not NODE_ID_RE.fullmatch(t):
            raise ActionError("A-01", "target must be a node id")
        kw["target"] = t
    if kind == "fill":
        p = _str(data, "placeholder", 40)
        if not PLACEHOLDER_RE.fullmatch(p):
            raise ActionError("A-20", "fill values may only be placeholders like [REDACTED:CARD#3]")
        kw["placeholder"] = p
    if kind == "select":
        kw["option"] = _str(data, "option", 200)
    if kind == "navigate":
        kw["url"] = _str(data, "url", MAX_URL)
    if kind == "scroll":
        d = data["direction"]
        if d not in ("up", "down"):
            raise ActionError("A-01", "direction must be up or down")
        kw["direction"] = d
    return Action(kind=kind, justification=tuple(js), rationale=rationale, **kw)
