"""Run every cassette through the real agent step: malicious ones never execute."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest

from plagent.agent import step
from plagent.page import SanitizedPage, Task
from plagent.prompt import build_prompt
from plagent.replay import ReplayExhausted, ReplayMismatch, ReplayProvider, load_cassette, request_hash

ROOT = Path(__file__).resolve().parents[1]
CASSETTES = sorted((ROOT / "cassettes").rglob("*.json"))
MALICIOUS = [p for p in CASSETTES if p.parent.name == "malicious"]
NONCE = "0123456789abcdef"


def _setup(path: Path) -> tuple[dict[str, Any], SanitizedPage, Task]:
    c = load_cassette(path)
    page = SanitizedPage.load(str((path.parent / c["page"]).resolve()))
    t = c["task"]
    return c, page, Task(t["task_id"], t["text"], tuple(t["allowed_domains"]))


def _run(path: Path) -> list[tuple[dict[str, Any], Any]]:
    c, page, task = _setup(path)
    provider = ReplayProvider(c["steps"])
    return [(s, step(provider, page, task, nonce=NONCE)) for s in c["steps"]]


@pytest.mark.parametrize("path", CASSETTES, ids=lambda p: f"{p.parent.name}/{p.stem}")
def test_cassette_steps_match_expectations(path: Path) -> None:
    for i, (s, res) in enumerate(_run(path)):
        exp = s["expect"]
        assert res.outcome == exp["outcome"], (i, res)
        if "rule_id" in exp:
            assert res.rule_id == exp["rule_id"], (i, res)
        if "rule_in" in exp:
            assert res.rule_id in exp["rule_in"], (i, res)


@pytest.mark.parametrize("path", MALICIOUS, ids=lambda p: p.stem)
def test_malicious_cassettes_never_execute(path: Path) -> None:
    for i, (_, res) in enumerate(_run(path)):
        assert res.outcome != "execute", (path.stem, i, res)
        if res.outcome == "approval":
            # Only reachable for irreversible actions, which can't run without a signed approval.
            assert res.risk is not None and res.risk.irreversible, (path.stem, i)


def test_malicious_set_covers_the_required_attacks() -> None:
    names = {p.stem for p in MALICIOUS}
    assert {"guess-card", "read-field", "javascript-url", "page-instruction"} <= names
    rules = {res.rule_id for p in MALICIOUS for _, res in _run(p)}
    assert {"A-01", "A-02", "A-03", "A-04", "A-05", "A-06", "A-20", "A-21", "A-22", "A-23", "I-01"} <= rules


def test_blocked_results_carry_no_values() -> None:
    """Decisions name types and rules, never the guessed value."""
    for p in MALICIOUS:
        for s, res in _run(p):
            blob = json.dumps({"rule": res.rule_id, "reason": res.reason, "findings": res.findings})
            for secret in ("4111", "4242", "5555", "NDI0"):
                assert secret not in blob, (p.stem, blob)
            assert s  # keep the step referenced


def test_cassette_files_are_generated() -> None:
    spec = importlib.util.spec_from_file_location("bc", ROOT / "cassettes" / "build_cassettes.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    for rel, data in mod.build().items():
        on_disk = json.loads((ROOT / "cassettes" / f"{rel}.json").read_text("ascii"))
        assert on_disk == data, f"{rel}.json is stale: run cassettes/build_cassettes.py"
    assert json.loads((ROOT / "fixtures" / "checkout_page.json").read_text("ascii")) == mod.PAGE


def test_replay_fails_closed_when_exhausted() -> None:
    p = ReplayProvider([{"response": "{}"}])
    p.complete([])
    with pytest.raises(ReplayExhausted):
        p.complete([])


def test_strict_replay_detects_prompt_drift() -> None:
    _, page, task = _setup(CASSETTES[0])
    msgs = build_prompt(task, page, NONCE).messages
    good = ReplayProvider([{"response": "x", "request_sha256": request_hash(msgs)}], strict=True)
    assert good.complete(msgs) == "x"
    bad = ReplayProvider([{"response": "x", "request_sha256": "0" * 64}], strict=True)
    with pytest.raises(ReplayMismatch):
        bad.complete(msgs)


def test_load_cassette_rejects_bad_files(tmp_path: Path) -> None:
    f = tmp_path / "c.json"
    for bad in ({"format": "other"}, {"format": "pl.replay.v1", "name": "x"},
                {"format": "pl.replay.v1", "name": "x", "page": "p", "task": {}, "steps": []}):  # fmt: skip
        f.write_text(json.dumps(bad))
        with pytest.raises(ValueError):
            load_cassette(f)
