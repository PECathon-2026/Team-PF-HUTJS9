from __future__ import annotations

import os
import socket
import threading
from pathlib import Path
from typing import Any

import pytest

from plpy.uds import (
    MAX_JSON_DEPTH,
    FramedSocket,
    ProtocolError,
    accept_unix,
    connect_unix,
    listen_unix,
    parse_json_bounded,
    peer_credentials,
)


class OkValidator:
    def errors(self, schema_id: str, instance: Any) -> list[str]:
        return [] if schema_id == "ok.v1" else ["/schema: unknown"]


def pair() -> tuple[FramedSocket, FramedSocket]:
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    return FramedSocket(a), FramedSocket(b)


def test_listen_connect_accept(tmp_path: Path) -> None:
    path = str(tmp_path / "s.sock")
    listener = listen_unix(path)
    assert (os.stat(path).st_mode & 0o777) == 0o660

    def client() -> None:
        FramedSocket(connect_unix(path)).send_json({"schema": "ok.v1", "n": 1}, None)

    t = threading.Thread(target=client)
    t.start()
    conn = accept_unix(listener, 2.0)
    assert conn is not None
    assert peer_credentials(conn).uid == os.getuid()
    msg = FramedSocket(conn).recv_json(OkValidator(), 2.0)
    t.join()
    assert msg == {"schema": "ok.v1", "n": 1}
    listener.close()


def test_accept_timeout_and_stale_socket(tmp_path: Path) -> None:
    path = str(tmp_path / "t.sock")
    listen_unix(path).close()
    listener = listen_unix(path)  # stale socket file replaced
    assert accept_unix(listener, 0.01) is None
    listener.close()
    regular = tmp_path / "file"
    regular.write_text("x")
    with pytest.raises(RuntimeError):
        listen_unix(str(regular))


def test_recv_timeout_and_eof() -> None:
    a, b = pair()
    assert b.recv(0.01) is None and b.timed_out
    a.sock.close()
    assert b.recv(1.0) is None and not b.timed_out


def test_eof_inside_frame_and_bad_header() -> None:
    a, b = pair()
    a.sock.sendall(b"\x00\x00\x00\x09ab")
    a.sock.close()
    with pytest.raises(ProtocolError):
        b.recv(1.0)
    c, d = pair()
    c.sock.sendall(b"\x00\x00\x00\x00")
    with pytest.raises(ProtocolError):
        d.recv(1.0)


def test_json_validation_both_ways() -> None:
    a, b = pair()
    with pytest.raises(ProtocolError):
        a.send_json({"schema": "nope.v1"}, OkValidator())
    a.send_json({"schema": "nope.v1"}, None)
    with pytest.raises(ProtocolError):
        b.recv_json(OkValidator(), 1.0)
    a.send(b"{not json")
    with pytest.raises(ProtocolError):
        b.recv_json(OkValidator(), 1.0)
    a.send(b"[1]")
    with pytest.raises(ProtocolError):
        b.recv_json(OkValidator(), 1.0)
    a.sock.close()
    assert b.recv_json(OkValidator(), 1.0) is None


def test_json_depth_limit_matches_cpp() -> None:
    ok = "[" * MAX_JSON_DEPTH + "]" * MAX_JSON_DEPTH
    deep = "[" * (MAX_JSON_DEPTH + 1) + "]" * (MAX_JSON_DEPTH + 1)
    assert parse_json_bounded(ok.encode()) is not None
    with pytest.raises(ProtocolError):
        parse_json_bounded(deep.encode())
    nested_obj = '{"a":' * (MAX_JSON_DEPTH + 1) + "1" + "}" * (MAX_JSON_DEPTH + 1)
    with pytest.raises(ProtocolError):
        parse_json_bounded(nested_obj.encode())
    with pytest.raises(ProtocolError):
        parse_json_bounded(b"\xff\xfe")
