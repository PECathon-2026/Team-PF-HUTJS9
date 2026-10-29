from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from plpy.frame import MAX_FRAME_BYTES, FrameDecoder, FrameError, encode_frame


def test_header_is_big_endian() -> None:
    assert encode_frame(b"abc") == b"\x00\x00\x00\x03abc"


def test_rejects_empty_and_oversize() -> None:
    with pytest.raises(ValueError):
        encode_frame(b"")
    with pytest.raises(ValueError):
        encode_frame(b"x" * (MAX_FRAME_BYTES + 1))


def test_zero_length_fails_closed() -> None:
    d = FrameDecoder()
    d.feed(b"\x00\x00\x00\x00x")
    assert d.next() is None
    assert d.error is FrameError.EMPTY_FRAME
    d.feed(encode_frame(b"ok"))
    assert d.next() is None
    assert d.buffered == 0


def test_oversize_header() -> None:
    d = FrameDecoder(1024)
    d.feed(b"\x00\x00\x04\x01")
    assert d.next() is None
    assert d.failed and d.error.value == "too_large"


def test_partial_waits() -> None:
    wire = encode_frame(b"hello")
    d = FrameDecoder()
    d.feed(wire[:6])
    assert d.next() is None and not d.failed
    d.feed(wire[6:])
    assert d.next() == b"hello"


@given(st.lists(st.binary(min_size=1, max_size=300), max_size=20), st.lists(st.integers(1, 17), min_size=1))
def test_round_trip_any_split(msgs: list[bytes], steps: list[int]) -> None:
    wire = b"".join(encode_frame(m) for m in msgs)
    d = FrameDecoder()
    got: list[bytes] = []
    off = k = 0
    while off < len(wire):
        n = steps[k % len(steps)]
        d.feed(wire[off : off + n])
        off += n
        k += 1
        while (p := d.next()) is not None:
            got.append(p)
    assert got == msgs
    assert not d.failed


def test_matches_cpp_wire_format() -> None:
    # Same bytes the C++ encoder produces (plcommon frame_test EncodeHasBigEndianHeader).
    assert encode_frame(b"\x00" * 258)[:4] == b"\x00\x00\x01\x02"
