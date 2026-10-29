"""Schema validation hook, mirroring pl/validate.hpp. pl_contracts.Registry implements it."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass(frozen=True)
class ValidationResult:
    ok: bool
    errors: list[str] = field(default_factory=list)


class MessageValidator(Protocol):
    def errors(self, schema_id: str, instance: Any) -> list[str]: ...


def validate_dispatch(validator: MessageValidator, message: Any) -> ValidationResult:
    """Validate against the schema named by the message's own `schema` field (fail-closed)."""
    if not isinstance(message, dict):
        return ValidationResult(False, ["/: message must be an object"])
    sid = message.get("schema")
    if not isinstance(sid, str):
        return ValidationResult(False, ["/schema: missing or not a string"])
    errs = validator.errors(sid, message)
    return ValidationResult(not errs, errs)
