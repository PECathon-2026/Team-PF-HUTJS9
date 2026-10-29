from __future__ import annotations

from typing import Any

from plpy.validate import validate_dispatch


class Echo:
    def __init__(self) -> None:
        self.last = ""

    def errors(self, schema_id: str, instance: Any) -> list[str]:
        self.last = schema_id
        return []


def test_dispatch_and_fail_closed() -> None:
    v = Echo()
    assert validate_dispatch(v, {"schema": "event.v1"}).ok
    assert v.last == "event.v1"
    v.last = ""
    assert not validate_dispatch(v, []).ok
    assert not validate_dispatch(v, {"x": 1}).ok
    assert not validate_dispatch(v, {"schema": 5}).ok
    assert v.last == ""
