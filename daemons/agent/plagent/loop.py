"""The agent loop: observe -> prompt -> model -> checked decision -> act.

Core is behind ``CoreClient`` (UDS in production, an in-process fake in tests):
    open(url) / observe() -> sanitized_page.v1 dict / act(action dict) -> result dict / end()
The model is behind ``Provider`` (gate AI lane in production, replay in tests).

What leaves the agent: ``agent_action.v1`` dicts for allowed or approved actions.
Blocked actions are never sent; the model is told only the rule ID and a fixed
reason so it can try something else (never a value). Approval is asked of core,
which relays it to the dashboard (timeout means deny).
"""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass, field
from typing import Any, Protocol

from .actions import Action
from .adapter import from_sanitized_page
from .agent import StepResult, decide
from .page import SanitizedPage, Task
from .prompt import build_prompt
from .replay import Provider


class CoreClient(Protocol):
    def open(self, url: str) -> None: ...
    def observe(self) -> dict[str, Any]: ...
    def act(self, action: dict[str, Any]) -> dict[str, Any]: ...
    def request_approval(self, request: dict[str, Any]) -> bool: ...
    def end(self) -> None: ...


@dataclass
class Event:
    step: int
    outcome: str  # execute | approval-granted | approval-denied | blocked | done | error
    rule_id: str = ""
    kind: str = ""
    target: str = ""


@dataclass
class RunResult:
    status: str  # done | max_steps | error
    events: list[Event] = field(default_factory=list)
    prompts: list[list[dict[str, str]]] = field(default_factory=list)  # for leak checks in tests


MAX_BLOCKS_IN_A_ROW = 4


def action_to_message(a: Action, snapshot_id: str, risk: float | None, irreversible: bool) -> dict[str, Any]:
    d: dict[str, Any] = {
        "schema": "agent_action.v1",
        "action_id": "a-" + secrets.token_hex(8),
        "snapshot_id": int(snapshot_id) if snapshot_id.isdigit() else 0,
        "kind": a.kind,
        "justification": [{"source": j.source, "quote": j.quote} for j in a.justification],
    }
    for key in ("target", "placeholder", "text", "option", "url", "direction"):
        v = getattr(a, key)
        if v is not None:
            d[key] = v
    if a.rationale:
        d["rationale"] = a.rationale
    if irreversible:
        d["irreversible"] = True
    if risk is not None:
        d["risk"] = round(risk, 4)
    return d


def action_hash(msg: dict[str, Any]) -> str:
    """Hash the approval binds to: the action without its volatile id."""
    canon = json.dumps({k: v for k, v in msg.items() if k != "action_id"}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canon.encode()).hexdigest()


def run_task(core: CoreClient, provider: Provider, task: Task, start_url: str, max_steps: int = 20,
             attack_alarm: float = 0.0) -> RunResult:  # fmt: skip
    result = RunResult("max_steps")
    core.open(start_url)
    blocked_run = 0
    feedback: str | None = None
    try:
        for step_no in range(1, max_steps + 1):
            page: SanitizedPage = from_sanitized_page(core.observe())
            prompt = build_prompt(task, page)
            msgs = list(prompt.messages)
            if feedback:
                msgs.append({"role": "user", "content": feedback})
            result.prompts.append(msgs)
            raw = provider.complete(msgs)
            res: StepResult = decide(raw, page, task, prompt.system_text, attack_alarm)
            feedback = None
            if res.outcome == "blocked":
                result.events.append(Event(step_no, "blocked", res.rule_id,
                                           res.action.kind if res.action else "", res.action.target or "" if res.action else ""))  # fmt: skip
                blocked_run += 1
                feedback = f"Your last action was refused ({res.rule_id}). Choose a different action."
                if blocked_run >= MAX_BLOCKS_IN_A_ROW:
                    result.status = "error"
                    return result
                continue
            blocked_run = 0
            action = res.action
            assert action is not None
            msg = action_to_message(action, page.snapshot_id, res.risk.risk if res.risk else None,
                                    res.risk.irreversible if res.risk else False)  # fmt: skip
            if res.outcome == "approval":
                req = dict(res.approval_request or {})
                req.update({"action_id": msg["action_id"], "action_hash": action_hash(msg), "kind": action.kind,
                            "rule_ids": [res.rule_id]})  # fmt: skip
                if action.target:
                    req["target"] = action.target
                granted = core.request_approval(req)
                if not granted:
                    result.events.append(Event(step_no, "approval-denied", res.rule_id, action.kind, action.target or ""))
                    feedback = "The user did not approve that action. Do not retry it."
                    continue
                result.events.append(Event(step_no, "approval-granted", res.rule_id, action.kind, action.target or ""))
            else:
                result.events.append(Event(step_no, "execute", "", action.kind, action.target or ""))
            if action.kind == "done":
                core.act(msg)
                result.status = "done"
                return result
            core.act(msg)
        return result
    except Exception:  # fail closed: any error ends the run, nothing half-sent
        result.status = "error"
        result.events.append(Event(len(result.events) + 1, "error"))
        return result
    finally:
        core.end()
