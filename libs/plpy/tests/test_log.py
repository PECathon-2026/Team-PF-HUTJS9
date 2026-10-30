from __future__ import annotations

import json

import pytest

from plpy.log import MAX_LOG_SCAN, MAX_LOG_STRING, Logger, LogLevel, LogValue, is_identifier


def capture() -> tuple[list[str], Logger]:
    lines: list[str] = []
    return lines, Logger("vault", lines.append, LogLevel.DEBUG)


def test_structured_scrubbed_line() -> None:
    lines, log = capture()
    log.info("store.ok", field_type="CARD", count=3, ok=True, score=0.5, note="user typed 4111 1111 1111 1111 into mail a@b.co")
    j = json.loads(lines[0])
    assert j["component"] == "vault" and j["event"] == "store.ok" and j["level"] == "info"
    assert j["fields"]["note"] == "user typed [CARD] into mail [EMAIL]"
    assert "dropped_fields" not in j and "4111" not in lines[0]


def test_banned_and_invalid_names_dropped() -> None:
    lines, log = capture()
    fields: dict[str, LogValue] = {"value": "leak", "plaintext": "leak", "Bad Name": 1, "a.b": 1, "kept": 2}
    log.warn("x", **fields)
    j = json.loads(lines[0])
    assert j["dropped_fields"] == 4 and j["fields"] == {"kept": 2}
    assert "leak" not in lines[0]


def test_event_name_levels_truncation() -> None:
    lines, log = capture()
    log.error("card 4111111111111111 failed")
    assert json.loads(lines[0])["event"] == "invalid_event_name"
    quiet: list[str] = []
    q = Logger("core", quiet.append, LogLevel.WARN)
    q.debug("d")
    q.info("i")
    q.warn("w", long="a" * 1000, huge="a" * 5000)
    assert len(quiet) == 1
    fields = json.loads(quiet[0])["fields"]
    assert len(fields["long"]) == MAX_LOG_STRING
    assert fields["huge"] == " [TRUNCATED]"  # one >4 KiB token: dropped whole, never cut
    lines.clear()
    log.debug("utf8", s="a" * (MAX_LOG_STRING - 1) + "étail")
    assert len(json.loads(lines[0])["fields"]["s"]) == MAX_LOG_STRING - 1


def test_bad_component_and_identifiers(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(ValueError):
        Logger("Bad Component")
    assert is_identifier("a.b_c", 8) and not is_identifier("", 8) and not is_identifier("1abc", 8)
    Logger("core").info("stderr.ok")
    assert '"stderr.ok"' in capsys.readouterr().err


def test_scrubs_before_truncating() -> None:
    """Regression (Phase 0 review): values straddling the length limit are scrubbed whole."""
    lines, log = capture()
    for tail in ("john.doe@example.com", "4111111111111111", "sk-ant-abcdefghijklmnop"):
        lines.clear()
        log.info("t", s="a" * (MAX_LOG_STRING - 6) + " " + tail)
        assert tail[:5] not in json.loads(lines[0])["fields"]["s"]
    lines.clear()
    log.info("t", s="b" * (MAX_LOG_SCAN + 10) + " 4111111111111111")
    assert "4111" not in lines[0]


def test_names_with_long_digit_runs_rejected() -> None:
    lines, log = capture()
    log.info("card.4111111111111111", f123456=1)
    j = json.loads(lines[0])
    assert j["event"] == "invalid_event_name" and j["dropped_fields"] == 1
    with pytest.raises(ValueError):
        Logger("core123456")
