"""Unix domain sockets with framed JSON messages, mirroring pl/uds.hpp."""

from __future__ import annotations

import json
import os
import select
import socket
import stat
import struct
import time
from dataclasses import dataclass
from typing import Any

from plpy.frame import MAX_FRAME_BYTES, FrameDecoder, encode_frame
from plpy.validate import MessageValidator, validate_dispatch

MAX_JSON_DEPTH = 64


class ProtocolError(Exception):
    """Bad frame, malformed JSON or a schema failure. The connection must be dropped."""


@dataclass(frozen=True)
class PeerCredentials:
    pid: int
    uid: int
    gid: int


SEND_TIMEOUT_S = 5.0


def listen_unix(path: str, backlog: int = 16, mode: int = 0o660) -> socket.socket:
    """Like pl::listen_unix: the socket file gets `mode` via the umask at bind time
    (no chmod-after-bind race). umask is process-wide: call during startup."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        pass
    else:
        if not stat.S_ISSOCK(st.st_mode):
            raise RuntimeError("refusing to replace a non-socket file at the socket path")
        os.unlink(path)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
    old = os.umask(~mode & 0o777)
    try:
        s.bind(path)
    finally:
        os.umask(old)
    s.listen(backlog)
    return s


def connect_unix(path: str) -> socket.socket:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
    s.connect(path)
    return s


def accept_unix(listener: socket.socket, timeout_s: float) -> socket.socket | None:
    r, _, _ = select.select([listener], [], [], timeout_s)
    if not r:
        return None
    conn, _ = listener.accept()
    return conn


def peer_credentials(sock: socket.socket) -> PeerCredentials:
    raw = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    pid, uid, gid = struct.unpack("3i", raw)
    return PeerCredentials(pid, uid, gid)


def _reject_constant(name: str) -> Any:
    raise ValueError(f"{name} is not JSON")


def _check(obj: Any) -> int:
    """Container nesting depth (top-level container = 1, as in plcommon); raises
    UnicodeEncodeError on lone surrogates, which nlohmann rejects at parse time."""
    best = 0
    stack: list[tuple[Any, int]] = [(obj, 1)]
    while stack:
        cur, d = stack.pop()
        if isinstance(cur, str):
            cur.encode("utf-8")
        elif isinstance(cur, dict):
            best = max(best, d)
            for k, v in cur.items():
                k.encode("utf-8")
                stack.append((v, d + 1))
        elif isinstance(cur, list):
            best = max(best, d)
            stack.extend((v, d + 1) for v in cur)
    return best


def parse_json_bounded(payload: bytes) -> Any:
    """Parse like plcommon's parse_json_bounded: strict JSON (no NaN/Infinity, no lone
    surrogates), at most MAX_JSON_DEPTH nested containers."""
    try:
        message = json.loads(payload.decode("utf-8"), parse_constant=_reject_constant)
        depth = _check(message)
    except (UnicodeError, ValueError, RecursionError) as e:
        raise ProtocolError("incoming frame is not valid JSON") from e
    if depth > MAX_JSON_DEPTH:
        raise ProtocolError("incoming JSON nests too deeply")
    return message


class FramedSocket:
    def __init__(self, sock: socket.socket, max_frame: int = MAX_FRAME_BYTES) -> None:
        self.sock = sock
        self._decoder = FrameDecoder(max_frame)
        self.timed_out = False

    def send(self, payload: bytes, timeout_s: float = SEND_TIMEOUT_S) -> None:
        """Raises ProtocolError if the peer doesn't drain the frame within timeout_s."""
        frame = memoryview(encode_frame(payload))
        deadline = time.monotonic() + timeout_s
        while frame:
            left = deadline - time.monotonic()
            if left <= 0 or not select.select([], [self.sock], [], left)[1]:
                raise ProtocolError("send timed out: peer is not reading")
            try:
                n = self.sock.send(frame, socket.MSG_DONTWAIT)
            except BlockingIOError:
                continue
            frame = frame[n:]

    def recv(self, timeout_s: float) -> bytes | None:
        """Next payload; None on clean EOF or timeout (see timed_out). Raises ProtocolError."""
        self.timed_out = False
        deadline = time.monotonic() + timeout_s
        while True:
            payload = self._decoder.next()
            if payload is not None:
                return payload
            if self._decoder.failed:
                raise ProtocolError(f"bad frame: {self._decoder.error.value}")
            left = deadline - time.monotonic()
            if left <= 0 or not select.select([self.sock], [], [], left)[0]:
                self.timed_out = True
                return None
            chunk = self.sock.recv(64 * 1024)
            if not chunk:
                if self._decoder.buffered:
                    raise ProtocolError("peer closed inside a frame")
                return None
            self._decoder.feed(chunk)

    def send_json(self, message: Any, validator: MessageValidator | None, timeout_s: float = SEND_TIMEOUT_S) -> None:
        if validator is not None and not validate_dispatch(validator, message).ok:
            raise ProtocolError("outgoing message fails its schema")
        try:
            data = json.dumps(message, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
        except (ValueError, UnicodeError) as e:
            raise ProtocolError("outgoing message is not strict JSON") from e
        self.send(data, timeout_s)

    def recv_json(self, validator: MessageValidator, timeout_s: float) -> Any | None:
        payload = self.recv(timeout_s)
        if payload is None:
            return None
        message = parse_json_bounded(payload)
        if not validate_dispatch(validator, message).ok:
            raise ProtocolError("incoming message fails its schema")
        return message
