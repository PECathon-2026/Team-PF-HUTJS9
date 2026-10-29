"""Monotonic IDs, mirroring pl/ids.hpp: next = max(last + 1, CLOCK_REALTIME ns)."""

from __future__ import annotations

import re
import threading
import time

_PREFIX = re.compile(r"^[a-z]{2,8}$")


class MonotonicIds:
    def __init__(self, floor: int = 0) -> None:
        self._last = floor
        self._lock = threading.Lock()

    def next(self) -> int:
        with self._lock:
            self._last = max(self._last + 1, time.time_ns())
            return self._last


def format_id(prefix: str, ident: int) -> str:
    if not _PREFIX.match(prefix):
        raise ValueError("id prefix must be 2-8 lowercase letters")
    if not 0 <= ident < 2**64:
        raise ValueError("id must fit in 64 bits")
    return f"{prefix}-{ident:016x}"
