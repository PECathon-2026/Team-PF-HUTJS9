from __future__ import annotations

import copy
import json
import shutil
from pathlib import Path
from typing import Any

import pytest

from pl_contracts import ValidationFailure, load_registry
from pl_contracts.cli import check_fixtures, main
from pl_contracts.lint import lint_contracts, lint_schema

CONTRACTS = Path(__file__).resolve().parents[3]

BASE: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://privacylens.invalid/contracts/event.v1.json",
    "title": "t",
    "description": "d",
    "x-pl-zone": "metadata",
    "type": "object",
    "properties": {"schema": {"const": "event.v1"}, "kind": {"enum": ["a"]}},
    "required": ["schema"],
    "additionalProperties": False,
}
LEVELS = ["public", "internal", "personal", "sensitive", "secret"]


def lint(schema: dict[str, Any], name: str = "event.v1.json") -> list[str]:
    return lint_schema(Path(name), schema, LEVELS, {name.split(".", maxsplit=1)[0]})


def mutate(**props: Any) -> dict[str, Any]:
    s = copy.deepcopy(BASE)
    s["properties"].update(props)
    return s


def test_repo_contracts_are_clean_and_fixtures_agree() -> None:
    assert lint_contracts(CONTRACTS) == []
    assert check_fixtures(CONTRACTS) == []


def test_base_schema_is_clean() -> None:
    assert lint(BASE) == []


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"value": {"type": "integer"}}, "banned field name"),
        ({"note": {"type": "string"}}, "metadata strings need"),
        (
            {"note": {"type": "string", "x-pl-scrubbed": True}},
            "must also set maxLength",
        ),
        (
            {"o": {"type": "object", "properties": {"a": {"const": 1}}}},
            "additionalProperties: false",
        ),
        ({"p": {"type": "string", "pattern": "^a+$"}}, "unbounded quantifier"),
        ({"p": {"type": "string", "maxLength": 9, "pattern": "a"}}, "anchored"),
        (
            {"p": {"type": "string", "maxLength": 9, "pattern": "^(?<=a)b$"}},
            "regex feature",
        ),
        ({"f": {"type": "string", "format": "email"}}, "not portable"),
        ({"r": {"$ref": "other.v1.json#/x"}}, "local"),
        ({"x": {"if": {"const": 1}}}, "portable subset"),
        ({"taint": {"enum": ["low", "high"]}}, "taint_label.v1 level enum"),
        (
            {"z": {"type": "string", "x-pl-opaque": "hex", "maxLength": 4}},
            "x-pl-opaque",
        ),
    ],
)
def test_lint_rules(change: dict[str, Any], message: str) -> None:
    errs = lint(mutate(**change))
    assert any(message in e for e in errs), errs


def test_lint_top_level_rules() -> None:
    for key, bad in (
        ("$schema", "draft-07"),
        ("$id", "x"),
        ("x-pl-zone", "nowhere"),
        ("title", ""),
    ):
        s = copy.deepcopy(BASE)
        s[key] = bad
        assert lint(s), key
    s = copy.deepcopy(BASE)
    s["required"] = []
    assert any("required 'schema'" in e for e in lint(s))
    s = copy.deepcopy(BASE)
    s["required"] = ["schema", "ghost"]
    assert any("missing from properties" in e for e in lint(s))
    assert lint(BASE, "Bad-Name.json")
    assert any("OWNERS.tsv" in e for e in lint_schema(Path("event.v1.json"), BASE, LEVELS, set()))
    vault = copy.deepcopy(BASE)
    vault["x-pl-zone"] = "vault"
    vault["properties"]["plaintext"] = {"type": "string", "maxLength": 9}
    assert lint(vault) == []


def test_lint_contracts_dir_problems(tmp_path: Path) -> None:
    root = tmp_path / "contracts"
    (root / "schemas").mkdir(parents=True)
    shutil.copy(CONTRACTS / "OWNERS.tsv", root / "OWNERS.tsv")
    (root / "schemas" / "event.v1.json").write_text(json.dumps(BASE))
    (root / "schemas" / "broken.v1.json").write_text("{nope")
    (root / "fixtures" / "orphan.v1").mkdir(parents=True)
    errs = lint_contracts(root)
    assert any("not valid JSON" in e for e in errs)
    assert any("needs at least one fixture" in e for e in errs)
    assert any("no matching schema" in e for e in errs)


def test_registry_dispatch_and_errors_hide_values() -> None:
    reg = load_registry(CONTRACTS / "schemas")
    good = json.loads((CONTRACTS / "fixtures/event.v1/valid/detection.json").read_text())
    assert reg.validate(good) == "event.v1"
    bad = dict(good, type="Card 4111 found")
    with pytest.raises(ValidationFailure) as e:
        reg.validate(bad)
    assert "4111" not in str(e.value)
    with pytest.raises(ValidationFailure):
        reg.validate({"no": "schema"})
    assert reg.errors("nope.v1", {}) == ["unknown schema 'nope.v1'"]


def test_load_registry_rejects_bad_names(tmp_path: Path) -> None:
    (tmp_path / "Bad.json").write_text("{}")
    with pytest.raises(ValueError):
        load_registry(tmp_path)


def test_cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["lint", str(CONTRACTS)]) == 0
    assert main(["check", str(CONTRACTS)]) == 0
    schema = CONTRACTS / "schemas" / "event.v1.json"
    assert (
        main(
            [
                "validate",
                str(schema),
                str(CONTRACTS / "fixtures/event.v1/valid/minimal.json"),
            ]
        )
        == 0
    )
    assert (
        main(
            [
                "validate",
                str(schema),
                str(CONTRACTS / "fixtures/event.v1/invalid/carries-value.json"),
            ]
        )
        == 1
    )
    assert "lint clean" in capsys.readouterr().out
