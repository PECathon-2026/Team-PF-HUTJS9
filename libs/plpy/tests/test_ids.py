from __future__ import annotations

import threading

import pytest

from plpy.ids import MonotonicIds, format_id


def test_strictly_increasing_and_floor() -> None:
    ids = MonotonicIds()
    last = 0
    for _ in range(10000):
        n = ids.next()
        assert n > last
        last = n
    assert MonotonicIds(2**64 - 11).next() == 2**64 - 10


def test_unique_across_threads() -> None:
    ids = MonotonicIds()
    out: list[int] = []
    lock = threading.Lock()

    def work() -> None:
        got = [ids.next() for _ in range(2000)]
        assert got == sorted(got)
        with lock:
            out.extend(got)

    ts = [threading.Thread(target=work) for _ in range(4)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert len(set(out)) == len(out)


def test_format_matches_cpp() -> None:
    assert format_id("dec", 0x1858F3A2C4B10) == "dec-0001858f3a2c4b10"
    for bad in ("D", "toolongprefix", "a1"):
        with pytest.raises(ValueError):
            format_id(bad, 1)
    with pytest.raises(ValueError):
        format_id("dec", -1)
