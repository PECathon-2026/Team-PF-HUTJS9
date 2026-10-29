"""Contract linter: the conventions in contracts/README.md, checked mechanically."""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from pl_contracts.registry import DIALECT, ID_PREFIX, PORTABLE_FORMATS, SCHEMA_FILE

BANNED_FIELDS = frozenset({"value", "raw", "text_raw", "secret", "plaintext"})
ZONES = frozenset({"raw", "vault", "sanitized", "metadata"})
ANNOTATIONS = frozenset({"x-pl-zone", "x-pl-scrubbed", "x-pl-note", "x-pl-opaque"})
OPAQUE_ENCODINGS = frozenset({"base64"})
MAX_PATTERN_INPUT = 4096
KEYWORDS = frozenset(
    {
        "$schema", "$id", "$ref", "$defs", "$comment", "title", "description", "type", "properties", "required",
        "additionalProperties", "items", "enum", "const", "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum",
        "minLength", "maxLength", "pattern", "minItems", "maxItems", "uniqueItems", "minProperties", "maxProperties",
        "oneOf", "anyOf", "allOf", "not", "format", "default", "examples",
    }
)  # fmt: skip
SCHEMA_MAP_KEYWORDS = ("properties", "$defs")
SCHEMA_LIST_KEYWORDS = ("oneOf", "anyOf", "allOf")
SCHEMA_SINGLE_KEYWORDS = ("items", "additionalProperties", "not")
STRING_CONSTRAINTS = ("enum", "const", "pattern", "format", "x-pl-opaque")
# A quantifier without an upper bound; std::regex recurses per character on these.
UNBOUNDED_QUANTIFIER = re.compile(r"(?<!\\)[*+]|\{[0-9]+,\}")
# Regex features the C++ engine (std::regex ECMAScript) lacks.
NON_PORTABLE_REGEX = re.compile(r"\(\?<[=!]|\(\?P?<[A-Za-z]|\\[pP]\{|\(\?[imsx]")


def subschemas(
    schema: dict[str, Any], path: str
) -> Iterator[tuple[str, dict[str, Any]]]:
    """Yield (json-path, subschema) for every schema object below and including `schema`."""
    yield path, schema
    for kw in SCHEMA_MAP_KEYWORDS:
        for key, sub in (schema.get(kw) or {}).items():
            if isinstance(sub, dict):
                yield from subschemas(sub, f"{path}/{kw}/{key}")
    for kw in SCHEMA_LIST_KEYWORDS:
        for i, sub in enumerate(schema.get(kw) or []):
            if isinstance(sub, dict):
                yield from subschemas(sub, f"{path}/{kw}/{i}")
    for kw in SCHEMA_SINGLE_KEYWORDS:
        sub = schema.get(kw)
        if isinstance(sub, dict):
            yield from subschemas(sub, f"{path}/{kw}")


def _is_string_schema(s: dict[str, Any]) -> bool:
    t = s.get("type")
    return t == "string" or (isinstance(t, list) and "string" in t)


def _resolve(root: dict[str, Any], s: dict[str, Any]) -> dict[str, Any]:
    ref = s.get("$ref")
    if isinstance(ref, str) and ref.startswith("#/$defs/"):
        target = root.get("$defs", {}).get(ref.removeprefix("#/$defs/"))
        if isinstance(target, dict):
            return target
    return s


def lint_schema(
    path: Path,
    schema: dict[str, Any],
    taint_levels: list[str] | None,
    producers: set[str],
) -> list[str]:
    errs: list[str] = []
    m = SCHEMA_FILE.match(path.name)
    if not m:
        return [f"{path.name}: file name must be <name>.v<N>.json"]
    sid = path.name.removesuffix(".json")
    name = m.group("name")

    def err(where: str, msg: str) -> None:
        errs.append(f"{sid}{where}: {msg}")

    if name not in producers:
        err("", "schema name not listed in contracts/OWNERS.tsv")
    if schema.get("$schema") != DIALECT:
        err("", f"$schema must be {DIALECT}")
    if schema.get("$id") != f"{ID_PREFIX}{sid}.json":
        err("", f"$id must be {ID_PREFIX}{sid}.json")
    for kw in ("title", "description"):
        if not isinstance(schema.get(kw), str) or not schema[kw].strip():
            err("", f"'{kw}' is required")
    zone = schema.get("x-pl-zone")
    if zone not in ZONES:
        err("", f"x-pl-zone must be one of {sorted(ZONES)}")
    if schema.get("type") != "object":
        err("", "top level must be an object")
    top_schema = (schema.get("properties") or {}).get("schema")
    if (
        not isinstance(top_schema, dict)
        or top_schema.get("const") != sid
        or "schema" not in (schema.get("required") or [])
    ):
        err("", f"top level needs a required 'schema' property with const {sid!r}")

    for where, sub in subschemas(schema, ""):
        for key in sub:
            if key not in KEYWORDS and key not in ANNOTATIONS:
                err(where, f"keyword {key!r} is outside the portable subset")
        if where and "x-pl-zone" in sub:
            err(where, "x-pl-zone is only allowed at the top level")
        ref = sub.get("$ref")
        if ref is not None and (
            not isinstance(ref, str) or not ref.startswith("#/$defs/")
        ):
            err(where, "only local '#/$defs/...' references are allowed")
        fmt = sub.get("format")
        if fmt is not None and fmt not in PORTABLE_FORMATS:
            err(
                where,
                f"format {fmt!r} is not portable (allowed: {sorted(PORTABLE_FORMATS)})",
            )
        pat = sub.get("pattern")
        if isinstance(pat, str) and NON_PORTABLE_REGEX.search(pat):
            err(where, "pattern uses a regex feature the C++ engine lacks")
        if isinstance(pat, str) and not (pat.startswith("^") and pat.endswith("$")):
            err(where, "patterns must be anchored with ^...$")
        if isinstance(pat, str) and UNBOUNDED_QUANTIFIER.search(pat):
            ml = sub.get("maxLength")
            if not isinstance(ml, int) or ml > MAX_PATTERN_INPUT:
                err(
                    where,
                    f"pattern with an unbounded quantifier needs maxLength <= {MAX_PATTERN_INPUT} (std::regex recursion)",
                )
        opaque = sub.get("x-pl-opaque")
        if opaque is not None and (
            opaque not in OPAQUE_ENCODINGS
            or "pattern" in sub
            or not isinstance(sub.get("maxLength"), int)
        ):
            err(
                where,
                f"x-pl-opaque must be one of {sorted(OPAQUE_ENCODINGS)}, with maxLength and no pattern",
            )
        props = sub.get("properties")
        if isinstance(props, dict):
            if sub.get("additionalProperties") is not False:
                err(
                    where,
                    "objects with properties must set additionalProperties: false",
                )
            for pname in props:
                if pname in BANNED_FIELDS and zone != "vault":
                    err(
                        f"{where}/properties/{pname}",
                        "banned field name outside the vault zone",
                    )
            missing = [r for r in sub.get("required") or [] if r not in props]
            if missing:
                err(where, f"required names missing from properties: {missing}")
            taint = props.get("taint")
            if (
                isinstance(taint, dict)
                and taint_levels is not None
                and name != "taint_label"
                and _resolve(schema, taint).get("enum") != taint_levels
            ):
                err(
                    f"{where}/properties/taint",
                    "must use exactly the taint_label.v1 level enum",
                )
        if (
            zone == "metadata"
            and _is_string_schema(sub)
            and not any(k in sub for k in STRING_CONSTRAINTS)
            and sub.get("x-pl-scrubbed") is not True
        ):
            err(
                where,
                "metadata strings need enum/const/pattern/format (or x-pl-scrubbed: true)",
            )
        if sub.get("x-pl-scrubbed") is True and not (
            _is_string_schema(sub) and isinstance(sub.get("maxLength"), int)
        ):
            err(where, "x-pl-scrubbed strings must also set maxLength")
    return errs


def lint_fixtures(contracts: Path, sid: str) -> list[str]:
    errs = []
    base = contracts / "fixtures" / sid
    for kind in ("valid", "invalid"):
        files = sorted((base / kind).glob("*.json")) if (base / kind).is_dir() else []
        if not files:
            errs.append(f"{sid}: needs at least one fixture in fixtures/{sid}/{kind}/")
    return errs


def read_producers(contracts: Path) -> set[str]:
    names: set[str] = set()
    owners = contracts / "OWNERS.tsv"
    lines = owners.read_text().splitlines() if owners.exists() else []
    for line in lines:
        if line.strip() and not line.startswith("#"):
            names.add(line.split("\t")[0].strip())
    return names


def _producer_match(name: str, globs: set[str]) -> bool:
    return any(
        re.fullmatch(re.escape(g).replace(r"\*", "[a-z0-9_]*"), name) for g in globs
    )


def lint_contracts(contracts: Path) -> list[str]:
    schema_dir = contracts / "schemas"
    globs = read_producers(contracts)
    loaded: dict[Path, dict[str, Any]] = {}
    errs: list[str] = []
    for path in sorted(schema_dir.glob("*")):
        try:
            loaded[path] = json.loads(path.read_text())
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            errs.append(f"{path.name}: not valid JSON ({e.__class__.__name__})")
    taint_levels = None
    taint = loaded.get(schema_dir / "taint_label.v1.json")
    if taint is not None:
        levels = (taint.get("$defs") or {}).get("level", {}).get("enum")
        taint_levels = levels if isinstance(levels, list) else None
    for path, schema in loaded.items():
        m = SCHEMA_FILE.match(path.name)
        names = (
            {m.group("name")}
            if m and _producer_match(m.group("name"), globs)
            else set()
        )
        errs += lint_schema(path, schema, taint_levels, names)
        if m:
            errs += lint_fixtures(contracts, path.name.removesuffix(".json"))
    fixtures = contracts / "fixtures"
    if fixtures.is_dir():
        for d in sorted(p for p in fixtures.iterdir() if p.is_dir()):
            if not (schema_dir / f"{d.name}.json").exists():
                errs.append(f"fixtures/{d.name}: no matching schema")
    return errs
