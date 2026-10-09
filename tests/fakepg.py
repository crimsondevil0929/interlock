"""A PostgreSQL that never answers: what a connection pool's queue looks like
from the client (``docs/EPIC7_DESIGN.md`` §3.4).

It completes the startup handshake, so a connection opens, and then takes
every query without answering it, as a transaction-mode pooler holds a client
that no server connection is free for. A cancel request either fails the
waiting query (``answers_cancel``), as a pooler does for a client it holds,
or is dropped, so only shutting the socket ends the wait.
"""

from __future__ import annotations

import contextlib
import socket
import socketserver
import struct
import threading
from collections.abc import Iterator
from contextlib import contextmanager

_SSL = 80877103
_GSSENC = 80877104
_CANCEL = 80877102


def _message(kind: bytes, payload: bytes) -> bytes:
    return kind + struct.pack("!i", len(payload) + 4) + payload


def _cstring(text: str) -> bytes:
    return text.encode() + b"\0"


_PARAMETERS = {
    "server_version": "16.0",
    "server_encoding": "UTF8",
    "client_encoding": "UTF8",
    "DateStyle": "ISO, MDY",
    "IntervalStyle": "postgres",
    "integer_datetimes": "on",
    "standard_conforming_strings": "on",
    "TimeZone": "UTC",
}
_CANCELED = _message(
    b"E",
    b"SERROR\0VERROR\0C57014\0Mcanceling statement due to user request\0\0",
) + _message(b"Z", b"I")


class FakePooler:
    """A server on ``127.0.0.1`` whose sessions wait forever."""

    def __init__(self, *, answers_cancel: bool) -> None:
        self.answers_cancel = answers_cancel
        self.queries: list[bytes] = []
        """What sessions sent after the handshake, as it arrived."""
        self.cancels = 0
        self._sessions: dict[int, socket.socket] = {}
        self._lock = threading.Lock()
        fake = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                fake._serve(self.request)

        self._server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    @property
    def dsn(self) -> str:
        port = self._server.server_address[1]
        return (
            f"host=127.0.0.1 port={port} user=interlock dbname=interlock password=x "
            "sslmode=disable gssencmode=disable"
        )

    def close(self) -> None:
        """Stop listening, and end every session: the client's wait ends with
        the connection, as when a pooler goes away."""
        self._server.shutdown()
        self._server.server_close()
        with self._lock:
            sessions = list(self._sessions.values())
        for session in sessions:
            # Shut the connection down, then close the descriptor. On Linux,
            # close() alone leaves a socket that another thread is blocked
            # reading open, and the client is never told; macOS ends it.
            with contextlib.suppress(OSError):
                session.shutdown(socket.SHUT_RDWR)
            session.close()

    def _serve(self, sock: socket.socket) -> None:
        while True:
            head = _exactly(sock, 8)
            if head is None:
                return
            length, code = struct.unpack("!ii", head)
            if code in (_SSL, _GSSENC):
                sock.sendall(b"N")
                continue
            if code == _CANCEL:
                body = _exactly(sock, 8)
                pid = None if body is None else struct.unpack("!ii", body)[0]
                with self._lock:
                    self.cancels += 1
                    target = None if pid is None else self._sessions.get(pid)
                if self.answers_cancel and target is not None:
                    target.sendall(_CANCELED)
                return
            if _exactly(sock, length - 8) is None:
                return
            break
        with self._lock:
            pid = len(self._sessions) + 1000
            self._sessions[pid] = sock
        greeting = _message(b"R", struct.pack("!i", 0))
        for name, value in _PARAMETERS.items():
            greeting += _message(b"S", _cstring(name) + _cstring(value))
        greeting += _message(b"K", struct.pack("!ii", pid, 4242))
        greeting += _message(b"Z", b"I")
        sock.sendall(greeting)
        while True:
            try:
                data = sock.recv(65536)
            except OSError:
                return
            if not data:
                return
            with self._lock:
                self.queries.append(data)


def _exactly(sock: socket.socket, n: int) -> bytes | None:
    data = b""
    while len(data) < n:
        try:
            chunk = sock.recv(n - len(data))
        except OSError:
            return None
        if not chunk:
            return None
        data += chunk
    return data


@contextmanager
def fake_pooler(*, answers_cancel: bool) -> Iterator[FakePooler]:
    pooler = FakePooler(answers_cancel=answers_cancel)
    try:
        yield pooler
    finally:
        pooler.close()
