"""Anti-reconstruction and the provenance hard rule (spec §9, §7).

- ``check_fill``: a fill may only use a placeholder the page issued, of the
  type the field expects, bound to that exact field. A guessed value can't even
  be expressed (``parse_action`` only accepts placeholders), and a real
  placeholder pointed at the wrong field is refused, so the AI can't make the
  vault type a card into a search box.
- ``scan_output``: PII scan of the raw model output and of every free-text
  field of the parsed action.
- ``hard_rule``: an action whose only justification is webpage text is
  blocked. A justification counts as "user" or "system" only if its quote
  really appears in the user's task or the system prompt; the model can't
  launder page text by relabelling it. Stricter than the spec's wording: an
  effectful action needs a verified *user* quote. A system-prompt quote alone
  doesn't count, because generic rules ("complete the task") justify anything.
"""

from __future__ import annotations

import re
import urllib.parse

from .actions import PLACEHOLDER_RE, Action
from .page import SanitizedPage
from .pii import Finding, normalize, scan
from .validator import Verdict

MIN_QUOTE = 4
# Actions with no effect outside the agent's view are exempt from the hard rule.
EFFECT_FREE = ("scroll", "done")


def check_fill(action: Action, page: SanitizedPage) -> Verdict:
    if action.kind != "fill":
        return Verdict(True)
    assert action.placeholder is not None and action.target is not None
    m = PLACEHOLDER_RE.fullmatch(action.placeholder)
    if not m:
        return Verdict(False, "A-20", "fill values may only be placeholders")
    binding = page.placeholders.get(action.placeholder)
    if binding is None:
        return Verdict(False, "A-23", "placeholder was not issued on this page")
    if binding.data_type != m.group(1):
        return Verdict(False, "A-23", "placeholder label doesn't match its binding")
    if binding.node_id != action.target:
        return Verdict(False, "A-23", "placeholder is bound to a different field")
    node = page.node(action.target)
    field = node.field if node else None
    if field is not None and field.data_type is not None and field.data_type != binding.data_type:
        return Verdict(False, "A-23", "field expects a different data type")
    return Verdict(True)


def scan_output(raw: str, action: Action | None) -> list[Finding]:
    found = scan(raw, "raw")
    if action is not None:
        found += scan(action.rationale, "rationale", strict_numbers=True)
        for i, j in enumerate(action.justification):
            found += scan(j.quote, f"justification[{i}]", strict_numbers=True)
        if action.option is not None:
            found += scan(action.option, "option")
        if action.url is not None:
            found += scan(urllib.parse.unquote(urllib.parse.unquote(action.url)), "url")
    return found


def _canon(s: str) -> str:
    return re.sub(r"\s+", " ", normalize(s)).strip().casefold()


def verified_sources(action: Action, task_text: str, system_text: str) -> set[str]:
    """Sources whose quotes check out. Unverifiable user/system quotes are
    downgraded to "webpage": they could only have come from the page."""
    task_c, sys_c = _canon(task_text), _canon(system_text)
    out = set()
    for j in action.justification:
        q = _canon(j.quote)
        if j.source == "user" and len(q) >= MIN_QUOTE and q in task_c:
            out.add("user")
        elif j.source == "system" and len(q) >= MIN_QUOTE and q in sys_c:
            out.add("system")
        else:
            out.add("webpage")
    return out


def hard_rule(action: Action, task_text: str, system_text: str) -> Verdict:
    if action.kind in EFFECT_FREE:
        return Verdict(True)
    if "user" not in verified_sources(action, task_text, system_text):
        return Verdict(False, "I-01", "action is not justified by the user's task (webpage text alone never is)")
    return Verdict(True)
