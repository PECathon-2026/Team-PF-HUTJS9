"""Action risk scoring (spec §7): noisy-OR over independent risk factors.

    risk = 1 - prod_i (1 - w_i * f_i),   f_i in [0, 1], w_i in [0, 1]

Each factor is one independent way for harm to happen, so the total never
exceeds 1 and is at least the largest single term. Factors (spec §7):
irreversible, uses a sensitive value, goes to a new website, far from the
user's goal, attack-monitor alarm (injection score / GW alarm, supplied from
outside; 0 until Phase 4).

Decision: risk < allow -> allow; < deny -> ask; otherwise deny. Irreversible
actions (pay, submit, delete...) are never "allow": they always need a signed
human approval, whatever the score (spec §9). Weights and thresholds will
come from the signed policy (Phase 4); these are the defaults.
"""

from __future__ import annotations

import math
import re
import urllib.parse
from dataclasses import dataclass, field

from .actions import PLACEHOLDER_RE, Action
from .page import SanitizedPage, Task
from .pii import normalize

DEFAULT_WEIGHTS = {
    "irreversible": 0.6,
    "sensitive_value": 0.2,
    "new_domain": 0.3,
    "goal_distance": 0.2,
    "attack_alarm": 0.9,
}
ALLOW_BELOW = 0.3
DENY_FROM = 0.7

# Words that mark an irreversible action, in English, Hindi and Hinglish.
IRREVERSIBLE_WORDS = (
    "pay", "buy", "purchase", "place order", "order now", "checkout", "submit", "confirm", "delete", "remove",
    "transfer", "send money", "withdraw", "cancel subscription", "close account", "deactivate", "unsubscribe",
    "authorize", "authorise", "book now",
    "भुगतान", "खरीदें", "जमा करें", "पुष्टि", "हटाएँ", "हटाएं", "मिटाएँ", "भेजें", "ऑर्डर करें",
    "pay karo", "pay karein", "delete karo", "order karo", "bhej do", "confirm karo",
)  # fmt: skip
_WORD_RE = re.compile(r"[a-z0-9ऀ-ॿ]+")
_IRREVERSIBLE_RE = re.compile(r"(?<![a-zऀ-ॿ])(?:" + "|".join(re.escape(w) for w in IRREVERSIBLE_WORDS) + r")(?![a-z])")


def noisy_or(weights: dict[str, float], factors: dict[str, float]) -> float:
    for k, v in {**weights, **factors}.items():
        if not 0.0 <= v <= 1.0 or math.isnan(v):
            raise ValueError(f"{k} must be in [0, 1]")
    p = 1.0
    for k, f in factors.items():
        p *= 1.0 - weights.get(k, 0.0) * f
    return 1.0 - p


def _tokens(s: str) -> set[str]:
    return set(_WORD_RE.findall(normalize(s).casefold()))


def is_irreversible(action: Action, page: SanitizedPage) -> bool:
    if action.kind == "click" and action.target and (node := page.node(action.target)):
        return bool(_IRREVERSIBLE_RE.search(normalize(node.name).casefold()))
    if action.kind == "navigate" and action.url:
        path = urllib.parse.unquote(urllib.parse.urlsplit(action.url).path).casefold()
        return bool(re.search(r"(delete|remove|pay|checkout|confirm|transfer|unsubscribe)", path))
    return False


def goal_distance(action: Action, page: SanitizedPage, task: Task) -> float:
    """1 - share of the target's words that also occur in the task. Crude on
    purpose: it's one weak factor, never a decision on its own."""
    if action.kind in ("scroll", "done"):
        return 0.0
    words: set[str] = set()
    if action.target and (node := page.node(action.target)):
        words |= _tokens(PLACEHOLDER_RE.sub(" ", node.name))
    if action.placeholder and (m := PLACEHOLDER_RE.fullmatch(action.placeholder)):
        words.add(m.group(1).casefold())
    if action.url:
        words |= _tokens(urllib.parse.urlsplit(action.url).path)
    if action.option:
        words |= _tokens(action.option)
    if not words:
        return 1.0
    return 1.0 - len(words & _tokens(task.text)) / len(words)


def _host(url: str, base: str) -> str:
    return (urllib.parse.urlsplit(urllib.parse.urljoin(base, url)).hostname or "").lower()


@dataclass(frozen=True)
class RiskResult:
    risk: float
    decision: str  # allow | ask | deny
    factors: dict[str, float] = field(default_factory=dict)
    irreversible: bool = False


def score(
    action: Action,
    page: SanitizedPage,
    task: Task,
    attack_alarm: float = 0.0,
    weights: dict[str, float] | None = None,
    allow_below: float = ALLOW_BELOW,
    deny_from: float = DENY_FROM,
) -> RiskResult:
    w = DEFAULT_WEIGHTS if weights is None else weights
    irreversible = is_irreversible(action, page)
    sensitive = 0.0
    if action.kind == "fill" and action.placeholder:
        b = page.placeholders.get(action.placeholder)
        sensitive = 1.0 if b is not None else 0.0
    dest = None
    if action.kind == "navigate" and action.url:
        dest = _host(action.url, page.url)
    elif action.kind == "click" and action.target and (n := page.node(action.target)) and n.href:
        dest = _host(n.href, page.url)
    new_domain = 1.0 if dest is not None and dest != _host(page.url, page.url) else 0.0
    factors = {
        "irreversible": 1.0 if irreversible else 0.0,
        "sensitive_value": sensitive,
        "new_domain": new_domain,
        "goal_distance": goal_distance(action, page, task),
        "attack_alarm": attack_alarm,
    }
    risk = noisy_or(w, factors)
    decision = "allow" if risk < allow_below else "ask" if risk < deny_from else "deny"
    if irreversible and decision == "allow":
        decision = "ask"
    return RiskResult(risk, decision, factors, irreversible)
