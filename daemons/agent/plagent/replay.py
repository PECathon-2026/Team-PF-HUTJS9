"""Replay LLM provider and cassette format (AD-06, AD-13).

A cassette is a JSON file:

    {
      "format": "pl.replay.v1",
      "name": "guess-card",
      "description": "...",
      "page": "../../fixtures/checkout_page.json",      # sanitized page fixture, relative to the cassette
      "task": {"task_id": "...", "text": "...", "allowed_domains": ["shop.example"]},
      "steps": [
        {
          "response": "<raw model output, exactly as the model produced it>",
          "request_sha256": "<optional: hash of the canonical prompt it answered>",
          "expect": {"outcome": "blocked", "rule_id": "A-21"}    # optional: what the agent must do
        }
      ]
    }

``request_sha256`` lets recorded (live) cassettes prove the prompt didn't
drift: in strict mode a mismatch is an error. Malicious cassettes are
hand-written, so they usually omit it. ``expect`` is test metadata; the
provider never reads it. Cassettes hold sanitized prompts and model text only;
run the leak scan over them before committing.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

FORMAT = "pl.replay.v1"


class Provider(Protocol):
    def complete(self, messages: list[dict[str, str]]) -> str: ...


def request_hash(messages: list[dict[str, str]]) -> str:
    canon = json.dumps(messages, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canon.encode()).hexdigest()


class ReplayExhausted(RuntimeError):
    pass


class ReplayMismatch(RuntimeError):
    pass


@dataclass
class ReplayProvider:
    steps: list[dict[str, Any]]
    strict: bool = False
    pos: int = 0

    def complete(self, messages: list[dict[str, str]]) -> str:
        if self.pos >= len(self.steps):
            raise ReplayExhausted("cassette has no more responses")  # fail closed: no default reply
        step = self.steps[self.pos]
        self.pos += 1
        want = step.get("request_sha256")
        if self.strict and want is not None and want != request_hash(messages):
            raise ReplayMismatch(f"step {self.pos - 1}: prompt differs from the recording")
        response = step["response"]
        if not isinstance(response, str):
            raise ValueError("response must be a string")
        return response


def load_cassette(path: Path) -> dict[str, Any]:
    data: dict[str, Any] = json.loads(path.read_text("utf-8"))
    if data.get("format") != FORMAT:
        raise ValueError(f"{path}: not a {FORMAT} cassette")
    for k in ("name", "page", "task", "steps"):
        if k not in data:
            raise ValueError(f"{path}: missing {k}")
    if not data["steps"]:
        raise ValueError(f"{path}: no steps")
    return data
