"""Length-prefixed framing, wire-identical to plcommon (pl/frame.hpp).

A 4-byte big-endian length L (1 <= L <= MAX_FRAME_BYTES), then L bytes. A bad
header fails the decoder permanently (fail-closed).
"""

from __future__ import annotations

import enum

HEADER_BYTES = 4
MAX_FRAME_BYTES = 16 * 1024 * 1024


class FrameError(enum.Enum):
    NONE = "none"
    EMPTY_FRAME = "empty_frame"
    TOO_LARGE = "too_large"


def encode_frame(payload: bytes) -> bytes:
    if not payload:
        raise ValueError("frame payload is empty")
    if len(payload) > MAX_FRAME_BYTES:
        raise ValueError("frame payload exceeds MAX_FRAME_BYTES")
    return len(payload).to_bytes(HEADER_BYTES, "big") + payload


class FrameDecoder:
    def __init__(self, max_frame: int = MAX_FRAME_BYTES) -> None:
        self._buf = bytearray()
        self._max = max_frame
        self.error = FrameError.NONE

    @property
    def failed(self) -> bool:
        return self.error is not FrameError.NONE

    @property
    def buffered(self) -> int:
        return len(self._buf)

    def feed(self, data: bytes) -> None:
        if not self.failed:
            self._buf += data

    def next(self) -> bytes | None:
        if self.failed or len(self._buf) < HEADER_BYTES:
            return None
        n = int.from_bytes(self._buf[:HEADER_BYTES], "big")
        if n == 0:
            self.error = FrameError.EMPTY_FRAME
        elif n > self._max:
            self.error = FrameError.TOO_LARGE
        if self.failed:
            self._buf.clear()
            return None
        if len(self._buf) - HEADER_BYTES < n:
            return None
        payload = bytes(self._buf[HEADER_BYTES : HEADER_BYTES + n])
        del self._buf[: HEADER_BYTES + n]
        return payload
