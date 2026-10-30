"""Action schema, strict parser and validator: unit + property tests."""

from __future__ import annotations

import json
import string
import urllib.parse
from pathlib import Path
from typing import Any

import jsonschema
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from plagent.actions import ACTION_SCHEMA, KINDS, PLACEHOLDER_RE, ActionError, parse_action
from plagent.page import SanitizedPage, Task
from plagent.validator import check_url, host_allowed, validate

ROOT = Path(__file__).resolve().parents[1]
PAGE = SanitizedPage.load(str(ROOT / "fixtures" / "checkout_page.json"))
TASK = Task("t", "Buy the wireless earbuds with my saved card", ("shop.example",))
J = [{"source": "user", "quote": "Buy the wireless earbuds"}]

# ---------------------------------------------------------------- schema vs parser

JUST_ITEM = st.fixed_dictionaries({"source": st.sampled_from(["user", "webpage", "bot"]), "quote": st.text(max_size=6)})
values = st.one_of(
    st.none(), st.booleans(), st.integers(-5, 5), st.text(max_size=12),
    st.sampled_from(["n2", "n7", "[REDACTED:CARD#3]", "up", "https://shop.example/x", "Standard"]),
    st.lists(JUST_ITEM, max_size=2),
)  # fmt: skip
keys = st.sampled_from(["kind", "target", "placeholder", "option", "url", "direction", "justification", "rationale",
                        "x", "answer"])  # fmt: skip


@st.composite
def action_dicts(draw: st.DrawFn) -> dict[str, Any]:
    d = draw(st.dictionaries(keys, values, max_size=6))
    if draw(st.booleans()):
        d["kind"] = draw(st.sampled_from([*KINDS, "read"]))
    if draw(st.booleans()):
        d["justification"] = J
    return d


@given(action_dicts())
@settings(max_examples=1500)
def test_parser_never_accepts_what_the_schema_rejects(d: dict[str, Any]) -> None:
    """The parser is at least as strict as the JSON Schema given to the model."""
    try:
        parse_action(d)
    except ActionError:
        return
    jsonschema.validate(d, ACTION_SCHEMA)


def test_schema_is_valid_json_schema() -> None:
    jsonschema.Draft202012Validator.check_schema(ACTION_SCHEMA)
    assert {v["properties"]["kind"]["const"] for v in ACTION_SCHEMA["oneOf"]} == set(KINDS)


def test_only_six_kinds_and_no_read_back() -> None:
    assert KINDS == ("click", "fill", "select", "navigate", "scroll", "done")
    for k in ("read", "get", "get_value", "extract", "copy", "screenshot", "eval", "execute_js", "type"):
        with pytest.raises(ActionError) as e:
            parse_action({"kind": k, "target": "n2", "justification": J})
        assert e.value.rule_id == "A-22"


@given(st.text(max_size=40))
def test_fill_accepts_only_exact_placeholders(value: str) -> None:
    d = {"kind": "fill", "target": "n2", "placeholder": value, "justification": J}
    try:
        a = parse_action(d)
        assert PLACEHOLDER_RE.fullmatch(value) and a.placeholder == value
    except ActionError as e:
        assert not PLACEHOLDER_RE.fullmatch(value) or e.rule_id == "A-01"


@pytest.mark.parametrize("extra", [{"x": 1, "y": 2}, {"coordinates": [1, 2]}, {"position": "10,10"}])
def test_coordinate_clicks_rejected(extra: dict[str, Any]) -> None:
    with pytest.raises(ActionError) as e:
        parse_action({"kind": "click", "target": "n7", "justification": J, **extra})
    assert e.value.rule_id == "A-06"


@pytest.mark.parametrize(
    "bad",
    [
        "not json", "[]", "null", '{"kind": "click"}', '{"kind": "click", "target": "n7", "justification": []}',
        '{"kind": "click", "target": "n7 n8", "justification": [{"source": "user", "quote": "x"}]}',
        '{"kind": "scroll", "direction": "left", "justification": [{"source": "user", "quote": "x"}]}',
        '{"kind": "click", "target": "n7", "justification": [{"source": "user", "quote": "   "}]}',
        '{"kind": "click", "target": "n7", "justification": [{"source": "admin", "quote": "x"}]}',
        '{"kind": "click", "target": 7, "justification": [{"source": "user", "quote": "x"}]}',
    ],
)  # fmt: skip
def test_malformed_actions_rejected(bad: str) -> None:
    with pytest.raises(ActionError):
        parse_action(bad)


# ---------------------------------------------------------------- URLs


@st.composite
def disguised_scheme(draw: st.DrawFn) -> str:
    word = draw(st.sampled_from(["javascript", "vbscript", "data", "file", "blob"]))
    out = []
    for ch in word:
        ch = ch.upper() if draw(st.booleans()) else ch
        if draw(st.integers(0, 4)) == 0:
            ch = f"%{ord(ch):02X}"
        out.append(ch)
        if draw(st.integers(0, 5)) == 0:
            out.append(draw(st.sampled_from(["\t", "\n", "\r"])))
    lead = draw(st.text(alphabet=" \t\n" + chr(0) + chr(0x1F), max_size=3))
    return lead + "".join(out) + ":" + draw(st.text(alphabet=string.ascii_letters + "()/.'", max_size=20))


@given(disguised_scheme())
@settings(max_examples=800)
def test_script_urls_always_denied(url: str) -> None:
    v = check_url(url, "https://shop.example/checkout", ("shop.example",))
    assert not v.ok and v.rule_id in ("A-04", "A-05"), (url, v)


@given(st.from_regex(r"[a-z]{1,8}(\.[a-z]{1,8}){0,2}\.(com|net|example|in)", fullmatch=True))
def test_only_allowed_domains(host: str) -> None:
    v = check_url(f"https://{host}/p", "https://shop.example/", ("shop.example",))
    assert v.ok == (host == "shop.example" or host.endswith(".shop.example")), host


@pytest.mark.parametrize(
    ("url", "ok"),
    [
        ("/cart", True), ("cart?x=1", True), ("https://shop.example/a", True), ("https://help.shop.example/faq", True),
        ("http://shop.example/", True), ("https://SHOP.EXAMPLE/", True), ("https://shop.example./", True),
        ("https://shop.example.evil.example/", False), ("https://evilshop.example/", False),
        ("https://shop.example@evil.example/", False), ("https://evil.example\\@shop.example/", False),
        ("https://[::1]/", False), ("https://127.0.0.1/", False), ("ftp://shop.example/", False),
        ("//evil.example", False), ("https:///nohost", False), ("https:evil.example/x", False),
        ("https:/evil.example/x", False), ("https:////shop.example/ok", True), ("HTTPS:shop.example/ok", True),
    ],
)  # fmt: skip
def test_url_cases(url: str, ok: bool) -> None:
    assert check_url(url, "https://shop.example/checkout", ("shop.example",)).ok is ok, url


def test_host_allowed_is_label_aligned() -> None:
    assert host_allowed("a.b.shop.example", ("shop.example",))
    assert not host_allowed("notshop.example", ("shop.example",))


# ---------------------------------------------------------------- targets


def _a(**kw: Any) -> Any:
    return parse_action({**kw, "justification": J})


TARGET_CASES = [
    (dict(kind="click", target="n404"), "A-02"),
    (dict(kind="click", target="n12"), "A-03"),
    (dict(kind="click", target="n13"), "A-03"),
    (dict(kind="fill", target="n7", placeholder="[REDACTED:CARD#3]"), "A-08"),
    (dict(kind="fill", target="n1", placeholder="[REDACTED:CARD#3]"), "A-08"),
    (dict(kind="select", target="n2", option="Standard"), "A-08"),
    (dict(kind="select", target="n6", option="Overnight"), "A-09"),
    (dict(kind="click", target="n10"), "A-04"),
    (dict(kind="click", target="n15"), "A-05"),
]


@pytest.mark.parametrize(("action", "rule"), TARGET_CASES)
def test_target_rules(action: dict[str, Any], rule: str) -> None:
    v = validate(_a(**action), PAGE, TASK)
    assert not v.ok and v.rule_id == rule


@pytest.mark.parametrize(
    "action",
    [dict(kind="click", target="n7"), dict(kind="click", target="n9"), dict(kind="click", target="n14"),
     dict(kind="select", target="n6", option="Express"), dict(kind="scroll", direction="up"), dict(kind="done"),
     dict(kind="fill", target="n2", placeholder="[REDACTED:CARD#3]")],
)  # fmt: skip
def test_valid_targets_pass(action: dict[str, Any]) -> None:
    assert validate(_a(**action), PAGE, TASK).ok


def test_relative_links_resolve_against_page() -> None:
    assert check_url("../x", "https://shop.example/a/b", ("shop.example",)).ok
    assert urllib.parse.urljoin("https://shop.example/a/b", "../x") == "https://shop.example/x"
    assert json.dumps(ACTION_SCHEMA)  # serialisable for Ollama's `format`
