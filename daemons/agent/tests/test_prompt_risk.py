"""Prompt fences, noisy-OR risk, no read-back structure, source hygiene."""

from __future__ import annotations

import dataclasses
import re
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from plagent import page as page_mod
from plagent.actions import parse_action
from plagent.agent import StepResult, decide
from plagent.page import Node, SanitizedPage, Task
from plagent.prompt import SYSTEM_PROMPT, build_prompt, neutralize
from plagent.risk import ALLOW_BELOW, DEFAULT_WEIGHTS, DENY_FROM, noisy_or, score

ROOT = Path(__file__).resolve().parents[1]
PAGE = SanitizedPage.load(str(ROOT / "fixtures" / "checkout_page.json"))
TASK = Task("t", "Buy the wireless earbuds in my cart: pay with my saved card.", ("shop.example",))
NONCE = "a1b2c3d4e5f60718"

# ---------------------------------------------------------------- prompt fences

hostile = st.lists(
    st.sampled_from(["<", "/", ">", " ", "webpage", "user_task", "system", "WEBPAGE", '"', "nonce=", NONCE,
                     "ignore", chr(0x202E), chr(0x200B), "\n", chr(0x0B)]),
    max_size=40,
).map("".join)  # fmt: skip


@given(hostile, hostile)
@settings(max_examples=600)
def test_page_text_cannot_break_the_fence(name: str, title: str) -> None:
    nodes = {**PAGE.nodes, "nX": Node("nX", "text", name)}
    p = build_prompt(TASK, dataclasses.replace(PAGE, nodes=nodes, title=title), NONCE)
    sys_msg, task_msg, page_msg = (m["content"] for m in p.messages)
    assert [m["role"] for m in p.messages] == ["system", "user", "user"]
    assert sys_msg == SYSTEM_PROMPT
    assert page_msg.count(f'<webpage nonce="{NONCE}"') == 1 and page_msg.count(f'</webpage nonce="{NONCE}">') == 1
    inner = page_msg.split(f'<webpage nonce="{NONCE}" trust="untrusted">', 1)[1].split(f'</webpage nonce="{NONCE}">')[0]
    assert NONCE not in inner
    assert not re.search(r"<\s*/?\s*(webpage|user_task|system)", inner, re.I)
    assert chr(0x202E) not in inner and chr(0x200B) not in inner
    assert "<webpage" not in task_msg


def test_page_text_appears_only_inside_the_webpage_fence() -> None:
    p = build_prompt(TASK, PAGE, NONCE)
    injection = PAGE.nodes["n11"].name[:40]
    assert injection not in p.messages[0]["content"] and injection not in p.messages[1]["content"]
    assert injection in p.messages[2]["content"]
    assert "untrusted" in p.messages[2]["content"]


def test_prompt_lists_placeholders_not_values() -> None:
    body = build_prompt(TASK, PAGE, NONCE).messages[2]["content"]
    assert "placeholder:[REDACTED:CARD#3]" in body and "sensitive:CARD" in body
    assert "Secret admin" not in body  # invisible nodes aren't shown


def test_nonce_is_random_and_hex() -> None:
    assert build_prompt(TASK, PAGE).nonce != build_prompt(TASK, PAGE).nonce
    with pytest.raises(ValueError):
        build_prompt(TASK, PAGE, nonce="not hex!")


def test_neutralize_is_idempotent_on_clean_text() -> None:
    assert neutralize("Pay now", NONCE) == "Pay now"


# ---------------------------------------------------------------- noisy-OR

unit = st.floats(0, 1, allow_nan=False)
factor_names = list(DEFAULT_WEIGHTS)


@given(st.fixed_dictionaries({k: unit for k in factor_names}), st.fixed_dictionaries({k: unit for k in factor_names}))
def test_noisy_or_properties(w: dict[str, float], f: dict[str, float]) -> None:
    r = noisy_or(w, f)
    assert 0.0 <= r <= 1.0
    terms = [w[k] * f[k] for k in factor_names]
    assert r >= max(terms) - 1e-12  # at least the largest single cause
    assert r <= min(1.0, sum(terms)) + 1e-12  # union bound
    assert abs(r - noisy_or(dict(reversed(list(w.items()))), dict(reversed(list(f.items()))))) < 1e-12


@given(st.fixed_dictionaries({k: unit for k in factor_names}), st.sampled_from(factor_names), unit)
def test_noisy_or_is_monotone(f: dict[str, float], k: str, bump: float) -> None:
    g = {**f, k: max(f[k], bump)}
    assert noisy_or(DEFAULT_WEIGHTS, g) >= noisy_or(DEFAULT_WEIGHTS, f) - 1e-12


def test_noisy_or_rejects_out_of_range() -> None:
    with pytest.raises(ValueError):
        noisy_or(DEFAULT_WEIGHTS, {"irreversible": 1.5})
    with pytest.raises(ValueError):
        noisy_or(DEFAULT_WEIGHTS, {"irreversible": float("nan")})


J = [{"source": "user", "quote": "pay with my saved card"}]


@given(unit)
def test_irreversible_actions_never_auto_run(alarm: float) -> None:
    a = parse_action({"kind": "click", "target": "n7", "justification": J})
    r = score(a, PAGE, TASK, attack_alarm=alarm)
    assert r.irreversible and r.decision in ("ask", "deny")
    assert (r.decision == "deny") == (r.risk >= DENY_FROM)


@pytest.mark.parametrize("name", ["Delete account", "Place order", "Submit", "Confirm transfer",
                                  "भुगतान करें", "Pay karo", "Order karo"])  # fmt: skip
def test_irreversible_words_in_three_languages(name: str) -> None:
    page = dataclasses.replace(PAGE, nodes={**PAGE.nodes, "nB": Node("nB", "button", name)})
    a = parse_action({"kind": "click", "target": "nB", "justification": J})
    assert score(a, page, TASK).irreversible


@pytest.mark.parametrize("name", ["Sign in", "Next", "Show password", "Search", "Track order"])
def test_ordinary_buttons_are_not_irreversible(name: str) -> None:
    page = dataclasses.replace(PAGE, nodes={**PAGE.nodes, "nB": Node("nB", "button", name)})
    assert not score(parse_action({"kind": "click", "target": "nB", "justification": J}), page, TASK).irreversible


def test_attack_alarm_turns_ask_into_deny() -> None:
    raw = '{"kind": "click", "target": "n7", "justification": [{"source": "user", "quote": "pay with my saved card"}]}'
    assert decide(raw, PAGE, TASK, SYSTEM_PROMPT).outcome == "approval"
    res = decide(raw, PAGE, TASK, SYSTEM_PROMPT, attack_alarm=0.9)
    assert res.outcome == "blocked" and res.rule_id == "A-30"


def test_new_domain_raises_risk() -> None:
    a = parse_action(
        {"kind": "click", "target": "n14", "justification": [{"source": "user", "quote": "Buy the wireless"}]}
    )
    assert score(a, PAGE, TASK).factors["new_domain"] == 1.0


def test_thresholds_ordered() -> None:
    assert 0 < ALLOW_BELOW < DENY_FROM < 1


def test_approval_request_lists_factors_without_values() -> None:
    raw = '{"kind": "click", "target": "n7", "justification": [{"source": "user", "quote": "pay with my saved card"}]}'
    req = decide(raw, PAGE, TASK, SYSTEM_PROMPT).approval_request
    assert req is not None and req["irreversible"] and {f["name"] for f in req["factors"]} >= {"irreversible"}


# ---------------------------------------------------------------- no read-back, by structure

BANNED = {"value", "raw", "text_raw", "secret", "plaintext", "contents"}


def test_page_model_has_nowhere_to_hold_a_value() -> None:
    for cls in (page_mod.FieldInfo, page_mod.Node, page_mod.Binding, page_mod.SanitizedPage):
        assert not {f.name for f in dataclasses.fields(cls)} & BANNED, cls


def test_step_result_has_nowhere_to_hold_a_value() -> None:
    assert not {f.name for f in dataclasses.fields(StepResult)} & BANNED


# ---------------------------------------------------------------- source hygiene

_RANGES = [(0x200B, 0x200F), (0x202A, 0x202E), (0x2060, 0x2069), (0x00AD, 0x00AD), (0xFEFF, 0xFEFF), (0x0400, 0x04FF)]
_BAD = re.compile("[" + "".join(f"{re.escape(chr(a))}-{re.escape(chr(b))}" for a, b in _RANGES) + "]")


def test_no_hidden_characters_in_agent_source() -> None:
    bad = []
    for f in ROOT.rglob("*"):
        if f.suffix in (".py", ".json", ".toml", ".md") and ".venv" not in f.parts and f.is_file():
            for n, line in enumerate(f.read_text("utf-8").splitlines(), 1):
                if _BAD.search(line):
                    bad.append(f"{f.relative_to(ROOT)}:{n}")
    assert not bad, bad
