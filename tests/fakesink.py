"""A sink for the relay's tests: a real HTTP server on localhost.

It records every call it receives, acts on it (or, honouring idempotency
keys, recognises a key it has acted on and does not act again), and can be
scripted call by call to fail, to hang, to act and then drop the connection
without answering, or to act and then hold the call open while a test kills
the relay that made it.

"Acting" is what a real sink does that matters: charging a card, sending an
email. :attr:`FakeSink.effects` counts it per idempotency key, so a test can
say exactly how many times a request took effect, and :attr:`FakeSink.calls`
how many times it was asked.
"""

from __future__ import annotations

import json
import socket
import socketserver
import threading
import time
from collections import Counter, deque
from collections.abc import Callable
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

OK = ("ok",)
DROP = ("drop",)
"""Act, then close the connection without answering: the relay cannot tell."""
HOLD = ("hold",)
"""Act, signal :attr:`FakeSink.arrived`, and answer only once
:attr:`FakeSink.release` is set: the window a test kills a relay in."""


class _Server(ThreadingHTTPServer):
    """Without the name lookup ``HTTPServer`` makes as it binds, as
    :class:`interlock.inbox.InboxServer` is: on CI's macOS runners it takes
    35 seconds, once in every process."""

    def server_bind(self) -> None:
        socketserver.TCPServer.server_bind(self)
        self.server_name = str(self.server_address[0])
        self.server_port = int(self.server_address[1])


def status(code: int, retry_after: int | None = None) -> tuple[Any, ...]:
    """Do not act; answer ``code``."""
    return ("status", code, retry_after)


def redirect(location: str) -> tuple[Any, ...]:
    """Do not act; answer 302, pointing at ``location``."""
    return ("redirect", location)


def hang(seconds: float) -> tuple[Any, ...]:
    """Act, then wait ``seconds`` before answering: longer than the relay's
    timeout, and the relay cannot tell."""
    return ("hang", seconds)


_ACTS = frozenset({"ok", "drop", "hang", "hold"})


@dataclass(frozen=True)
class Call:
    """One call the sink received."""

    path: str
    key: str
    message: str
    attempt: int
    body: bytes
    acted: bool
    """Whether this call took effect: not a refusal, and not a key the sink
    had already acted on."""
    at: float
    authorization: str | None = None


class FakeSink:
    """
    :param honour_keys: Act once per idempotency key, answering repeats as
        the first call was answered (Stripe's behaviour). ``False``: act on
        every call (SMTP's).
    """

    def __init__(self, *, honour_keys: bool = True) -> None:
        self.honour_keys = honour_keys
        self.calls: list[Call] = []
        self.effects: Counter[str] = Counter()
        self.arrived = threading.Event()
        self.release = threading.Event()
        self._lock = threading.Lock()
        self._default: deque[tuple[Any, ...]] = deque()
        self._by_key: dict[str, deque[tuple[Any, ...]]] = {}
        self.chaos: Callable[[], tuple[Any, ...]] | None = None
        """Asked for a behaviour when nothing is queued: a soak test's
        random failures. :data:`OK` when unset."""
        sink = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self) -> None:
                sink._handle(self)

            do_PUT = do_POST  # noqa: N815

            def log_message(self, *args: object) -> None:
                return None

        self._server = _Server(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self.url = f"http://127.0.0.1:{self._server.server_address[1]}"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    # -- scripting -----------------------------------------------------------

    def script(self, *behaviours: tuple[Any, ...], key: str | None = None) -> None:
        """Queue behaviours for the next calls (for ``key``'s calls only, when
        given). A call with nothing queued is answered :data:`OK`."""
        with self._lock:
            queue = self._default if key is None else self._by_key.setdefault(key, deque())
            queue.extend(behaviours)

    def calls_for(self, key: str) -> list[Call]:
        with self._lock:
            return [c for c in self.calls if c.key == key]

    def close(self) -> None:
        self.release.set()
        self._server.shutdown()
        self._server.server_close()

    # -- serving -------------------------------------------------------------

    def _handle(self, handler: BaseHTTPRequestHandler) -> None:
        length = int(handler.headers.get("Content-Length") or 0)
        body = handler.rfile.read(length)
        key = handler.headers.get("Idempotency-Key") or ""
        with self._lock:
            queue = self._by_key.get(key) or self._default
            if queue:
                behaviour = queue.popleft()
            else:
                behaviour = self.chaos() if self.chaos is not None else OK
            kind = behaviour[0]
            acted = kind in _ACTS and not (self.honour_keys and self.effects[key] > 0)
            if acted:
                self.effects[key] += 1
            self.calls.append(
                Call(
                    path=handler.path,
                    key=key,
                    message=handler.headers.get("X-Interlock-Message-Id") or "",
                    attempt=int(handler.headers.get("X-Interlock-Attempt") or 0),
                    body=body,
                    acted=acted,
                    at=time.monotonic(),
                    authorization=handler.headers.get("Authorization"),
                )
            )
        if kind == "status":
            headers = {} if behaviour[2] is None else {"Retry-After": str(behaviour[2])}
            self._answer(handler, behaviour[1], {"error": "scripted"}, headers)
            return
        if kind == "redirect":
            self._answer(handler, 302, {"moved": True}, {"Location": behaviour[1]})
            return
        if kind == "drop":
            handler.close_connection = True
            try:
                handler.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            return
        if kind == "hang":
            time.sleep(behaviour[1])
        if kind == "hold":
            self.arrived.set()
            self.release.wait(timeout=60)
        self._answer(handler, 201, {"id": key[:12], "duplicate": not acted}, {})

    @staticmethod
    def _answer(
        handler: BaseHTTPRequestHandler, code: int, body: dict[str, Any], headers: dict[str, str]
    ) -> None:
        data = json.dumps(body).encode()
        try:
            handler.send_response(code)
            handler.send_header("Content-Type", "application/json")
            handler.send_header("Content-Length", str(len(data)))
            for name, value in headers.items():
                handler.send_header(name, value)
            handler.end_headers()
            handler.wfile.write(data)
        except OSError:
            pass  # the relay hung up, or was killed: its loss
