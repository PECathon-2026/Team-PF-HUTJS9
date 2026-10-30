"""sanitized_page.v1 (what core sends) -> the agent's SanitizedPage.

The placeholder bindings are derived from the page itself: an element that lists
a placeholder `[REDACTED:TYPE#n]` is the field that placeholder is bound to (the
vault enforces the same binding when it decrypts). Element ids are `n<node_id>`.
"""

from __future__ import annotations

from typing import Any

from .actions import PLACEHOLDER_RE
from .page import Binding, FieldInfo, Node, SanitizedPage

FILLABLE_ROLES = {"textbox", "searchbox", "spinbutton", "combobox", "textarea"}
VISIBLE_FLAG = 1  # NodeFlags::kVisible
EDITABLE_FLAG = 16  # NodeFlags::kEditable


def from_sanitized_page(msg: dict[str, Any]) -> SanitizedPage:
    if msg.get("schema") != "sanitized_page.v1":
        raise ValueError("not a sanitized_page.v1 message")
    nodes: dict[str, Node] = {}
    bindings: dict[str, Binding] = {}
    fallback = msg.get("fallback") is not None  # NullSanitizer: names are absent, everything is redacted
    for e in msg["elements"]:
        eid = e["element_id"]
        role = e.get("role", "text")
        flags = int(e.get("flags", 0))
        phs = e.get("placeholders", [])
        data_type = e.get("data_type")
        for ph in phs:
            m = PLACEHOLDER_RE.fullmatch(ph)
            if m:
                bindings[ph] = Binding(m.group(1), eid)
        field = None
        if role in FILLABLE_ROLES or (flags & EDITABLE_FLAG):
            own = [p for p in phs if p in bindings and bindings[p].node_id == eid]
            field = FieldInfo(
                fillable=True,
                data_type=data_type,
                placeholder=own[0] if own else None,
                filled=e.get("filled"),
            )
        nodes[eid] = Node(
            node_id=eid,
            role=role,
            name="" if fallback else e.get("name", ""),
            visible=bool(flags & VISIBLE_FLAG) if "flags" in e else True,
            enabled=True,
            href=e.get("href"),
            options=tuple(e.get("options", ())),
            field=field,
        )
    return SanitizedPage(
        snapshot_id=str(msg.get("snapshot_id", 0)),
        url=msg.get("url", ""),
        title=msg.get("title", ""),
        nodes=nodes,
        placeholders=bindings,
    )
