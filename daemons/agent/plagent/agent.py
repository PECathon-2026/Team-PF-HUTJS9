"""One agent step: sanitized page in, a checked decision out (no IPC yet).

Order of checks (every one fail-closed; the first refusal wins):
    1. PII scan of the raw model output                  A-21
    2. strict parse into an Action                        A-01, A-06, A-20, A-22
    3. PII scan of the action's free-text fields          A-21
    4. fills: placeholder binding / text only on non-sensitive fields   A-23, A-24
    5. action validator (target, URL, domain)             A-02..A-09
    6. provenance hard rule                               I-01
    7. noisy-OR risk: allow -> execute, ask -> approval, deny -> blocked (A-30)

Outcomes: "execute" (send to core), "approval" (core must wait for a signed
approval token; timeout means deny), "blocked". Nothing here returns page
data to the model, and a decision never carries a value, only types, rule
IDs, node IDs and placeholders.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import antirecon, risk
from .actions import Action, ActionError, parse_action
from .page import SanitizedPage, Task
from .pii import Finding
from .prompt import build_prompt
from .replay import Provider
from .validator import validate


@dataclass(frozen=True)
class StepResult:
    outcome: str  # execute | approval | blocked
    rule_id: str = ""
    reason: str = ""
    action: Action | None = None
    findings: tuple[str, ...] = ()  # PII finding kinds, never values
    risk: risk.RiskResult | None = None
    approval_request: dict[str, Any] | None = field(default=None)


def _approval_request(action: Action, page: SanitizedPage, r: risk.RiskResult) -> dict[str, Any]:
    node = page.node(action.target) if action.target else None
    summary = f"{action.kind} {node.role} {node.name!r}" if node else action.kind
    if action.placeholder:
        summary += f" with {action.placeholder}"
    if action.url:
        summary += f" -> {action.url}"
    return {
        "snapshot_id": page.snapshot_id,
        "action_summary": summary,
        "risk": round(r.risk, 4),
        "factors": [{"name": k, "level": v} for k, v in r.factors.items() if v > 0],
        "irreversible": r.irreversible,
    }


def decide(raw: str, page: SanitizedPage, task: Task, system_text: str, attack_alarm: float = 0.0) -> StepResult:
    found = antirecon.scan_output(raw, None)
    if found:
        return StepResult("blocked", "A-21", "model output looks like personal data", findings=_kinds(found))
    try:
        action = parse_action(raw)
    except ActionError as e:
        return StepResult("blocked", e.rule_id, e.reason)
    found = antirecon.scan_output("", action)
    if found:
        return StepResult("blocked", "A-21", "action text looks like personal data", action, _kinds(found))
    for v in (
        antirecon.check_fill(action, page),
        validate(action, page, task),
        antirecon.hard_rule(action, task.text, system_text),
    ):
        if not v.ok:
            return StepResult("blocked", v.rule_id, v.reason, action)
    r = risk.score(action, page, task, attack_alarm=attack_alarm)
    if r.decision == "deny":
        return StepResult("blocked", "A-30", "risk too high", action, risk=r)
    if r.decision == "ask":
        return StepResult("approval", "A-31", "needs human approval", action, risk=r,
                          approval_request=_approval_request(action, page, r))  # fmt: skip
    return StepResult("execute", "", "", action, risk=r)


def step(provider: Provider, page: SanitizedPage, task: Task, nonce: str | None = None,
         attack_alarm: float = 0.0) -> StepResult:  # fmt: skip
    prompt = build_prompt(task, page, nonce)
    raw = provider.complete(prompt.messages)
    return decide(raw, page, task, prompt.system_text, attack_alarm)


def _kinds(found: list[Finding]) -> tuple[str, ...]:
    return tuple(sorted({f.kind for f in found}))
