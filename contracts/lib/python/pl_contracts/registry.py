"""Schema registry: loads contracts/schemas and validates messages by schema id."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

SCHEMA_FILE = re.compile(
    r"^(?P<name>[a-z][a-z0-9_]*)\.v(?P<version>[1-9][0-9]*)\.json$"
)
DIALECT = "https://json-schema.org/draft/2020-12/schema"
ID_PREFIX = "https://privacylens.invalid/contracts/"
# Formats both validators check identically.
PORTABLE_FORMATS = frozenset({"date-time", "uuid"})


class ValidationFailure(Exception):
    """A message did not match its schema. The message text never includes instance values."""


def _checker() -> FormatChecker:
    checker = FormatChecker(formats=sorted(PORTABLE_FORMATS))
    return checker


@dataclass
class Registry:
    schemas: dict[str, dict[str, Any]] = field(default_factory=dict)
    _validators: dict[str, Draft202012Validator] = field(
        default_factory=dict, repr=False
    )

    def add(self, schema_id: str, schema: dict[str, Any]) -> None:
        Draft202012Validator.check_schema(schema)
        self.schemas[schema_id] = schema
        self._validators[schema_id] = Draft202012Validator(
            schema, format_checker=_checker()
        )

    def errors(self, schema_id: str, instance: Any) -> list[str]:
        """Return error descriptions (JSON paths and keyword only, never the offending value)."""
        if schema_id not in self._validators:
            return [f"unknown schema {schema_id!r}"]
        out = []
        for err in self._validators[schema_id].iter_errors(instance):
            path = "/" + "/".join(str(p) for p in err.absolute_path)
            out.append(f"{path}: fails '{err.validator}'")
        return sorted(out)

    def validate(self, instance: Any, schema_id: str | None = None) -> str:
        """Validate a message. Without `schema_id`, dispatch on its `schema` field. Returns the schema id."""
        sid = schema_id
        if sid is None:
            sid = instance.get("schema") if isinstance(instance, dict) else None
            if not isinstance(sid, str):
                raise ValidationFailure("message has no 'schema' field")
        errs = self.errors(sid, instance)
        if errs:
            raise ValidationFailure(f"{sid}: " + "; ".join(errs))
        return sid


def load_registry(schema_dir: Path) -> Registry:
    reg = Registry()
    for path in sorted(schema_dir.glob("*.json")):
        m = SCHEMA_FILE.match(path.name)
        if not m:
            raise ValueError(f"{path}: schema file name must be <name>.v<N>.json")
        reg.add(path.name.removesuffix(".json"), json.loads(path.read_text()))
    return reg
