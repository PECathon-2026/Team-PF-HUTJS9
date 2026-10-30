"""What the agent can see: a sanitized page and the user's task.

This mirrors the draft ``sanitized_page`` fields in docs/architecture/win.md
§8 until the real schema exists. By construction there is no field that holds
a sensitive value: a sensitive input carries its data type and placeholder,
never its contents. That's half of "no read-back path"; the other half is that
no action kind returns page data to the model (see ``actions.py``).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class FieldInfo:
    """A form field. ``data_type`` is set when detect marked it sensitive."""

    fillable: bool = True
    data_type: str | None = None  # e.g. "CARD"; None = not sensitive
    placeholder: str | None = None  # the placeholder shown instead of the value
    filled: bool | None = None  # adaptive redaction fact ("filled: yes"), policy-controlled


@dataclass(frozen=True)
class Node:
    node_id: str
    role: str  # AX role: button, link, textbox, combobox, heading, text, ...
    name: str  # accessible name, already sanitized (placeholders substituted)
    visible: bool = True
    enabled: bool = True
    href: str | None = None  # links only, already scrubbed
    options: tuple[str, ...] = ()  # combobox / listbox option labels
    field: FieldInfo | None = None


@dataclass(frozen=True)
class Binding:
    """Where the vault will agree to type a placeholder's value (spec §6 binding)."""

    data_type: str
    node_id: str


@dataclass(frozen=True)
class SanitizedPage:
    snapshot_id: str
    url: str
    title: str
    nodes: dict[str, Node]
    placeholders: dict[str, Binding] = field(default_factory=dict)

    def node(self, node_id: str) -> Node | None:
        return self.nodes.get(node_id)

    @staticmethod
    def from_json(data: dict[str, Any]) -> SanitizedPage:
        nodes = {}
        for n in data["nodes"]:
            f = n.get("field")
            nodes[n["node_id"]] = Node(
                node_id=n["node_id"],
                role=n["role"],
                name=n.get("name", ""),
                visible=n.get("visible", True),
                enabled=n.get("enabled", True),
                href=n.get("href"),
                options=tuple(n.get("options", ())),
                field=FieldInfo(**f) if f is not None else None,
            )
        binds = {p: Binding(**b) for p, b in data.get("placeholders", {}).items()}
        return SanitizedPage(data["snapshot_id"], data["url"], data.get("title", ""), nodes, binds)

    @staticmethod
    def load(path: str) -> SanitizedPage:
        with open(path, encoding="utf-8") as f:
            return SanitizedPage.from_json(json.load(f))


@dataclass(frozen=True)
class Task:
    task_id: str
    text: str  # the user's instruction, the only "user" provenance there is
    allowed_domains: tuple[str, ...]
