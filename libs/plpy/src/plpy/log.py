"""Structured, scrubbed logging, mirroring pl/log.hpp (spec §11)."""

from __future__ import annotations

import contextlib
import json
import re
import sys
import threading
import time
from collections.abc import Callable
from enum import IntEnum

from plpy.scrub import scrub

MAX_LOG_STRING = 512
BANNED_FIELDS = frozenset({"value", "raw", "text_raw", "secret", "plaintext"})
_IDENT = re.compile(r"^[a-z][a-z0-9_.]*$")

LogValue = int | float | bool | str
Sink = Callable[[str], None]


class LogLevel(IntEnum):
    DEBUG = 0
    INFO = 1
    WARN = 2
    ERROR = 3


def is_identifier(s: str, max_len: int) -> bool:
    return 0 < len(s) <= max_len and bool(_IDENT.match(s))


def _truncate_utf8(s: str, max_bytes: int) -> str:
    b = s.encode("utf-8", "replace")
    if len(b) <= max_bytes:
        return s
    return b[:max_bytes].decode("utf-8", "ignore")


def _stderr_sink(line: str) -> None:
    with contextlib.suppress(OSError):  # never raise from logging
        sys.stderr.write(line + "\n")


class Logger:
    def __init__(self, component: str, sink: Sink = _stderr_sink, min_level: LogLevel = LogLevel.INFO) -> None:
        if not is_identifier(component, 32):
            raise ValueError("logger component must be an identifier")
        self.component = component
        self._sink = sink
        self._min = min_level
        self._lock = threading.Lock()

    def format(self, level: LogLevel, event: str, fields: dict[str, LogValue], ts_ns: int) -> str:
        out: dict[str, LogValue] = {}
        dropped = 0
        for name, val in fields.items():
            if not is_identifier(name, 32) or "." in name or name in BANNED_FIELDS:
                dropped += 1
                continue
            out[name] = scrub(_truncate_utf8(val, MAX_LOG_STRING)) if isinstance(val, str) else val
        line: dict[str, object] = {
            "ts_ns": ts_ns,
            "level": level.name.lower(),
            "component": self.component,
            "event": event if is_identifier(event, 64) else "invalid_event_name",
            "fields": out,
        }
        if dropped:
            line["dropped_fields"] = dropped
        return json.dumps(line, separators=(",", ":"), ensure_ascii=True)

    def log(self, level: LogLevel, event: str, **fields: LogValue) -> None:
        if level < self._min:
            return
        line = self.format(level, event, fields, time.time_ns())
        with self._lock:
            self._sink(line)

    def debug(self, event: str, **f: LogValue) -> None:
        self.log(LogLevel.DEBUG, event, **f)

    def info(self, event: str, **f: LogValue) -> None:
        self.log(LogLevel.INFO, event, **f)

    def warn(self, event: str, **f: LogValue) -> None:
        self.log(LogLevel.WARN, event, **f)

    def error(self, event: str, **f: LogValue) -> None:
        self.log(LogLevel.ERROR, event, **f)
