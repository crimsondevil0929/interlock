"""A key service on ``127.0.0.1`` speaking :class:`interlock.signers.HttpRemoteSigner`'s
protocol (``docs/EPIC8_DESIGN.md`` §1.2): named Ed25519 keys with versions, held
in memory, as a KMS holds them; and the ways a service fails, on demand.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import json
import secrets
import socketserver
import threading
import time
import urllib.parse
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from agentgov.receipts.signing import Ed25519Signer

GARBAGE = "garbage"
"""Answer every signing request with 64 bytes that are no signature."""
OTHER_KEY = "other-key"
"""Sign with a key the service never published."""
WRONG_VERSION = "wrong-version"
"""Sign, and say it was another version."""
NOT_JSON = "not-json"
OTHER_ALG = "other-alg"
"""Publish the key as another algorithm's."""
WRONG_PIN = "wrong-pin"
"""Publish a version other than the one asked for."""


class _Server(ThreadingHTTPServer):
    """Binds without ``socket.getfqdn``, whose reverse lookup takes seconds on
    some machines (``tests/fakesink.py``)."""

    daemon_threads = True

    def server_bind(self) -> None:
        socketserver.TCPServer.server_bind(self)
        self.server_name = str(self.server_address[0])
        self.server_port = int(self.server_address[1])


class FakeKms:
    """A signing service: :meth:`create` a key, :meth:`rotate` it, and every
    signature it makes is counted by key and version.

    :param token: The bearer token every request must carry, if any.
    """

    def __init__(self, *, token: str | None = None) -> None:
        self.token = token
        self.keys: dict[str, list[Ed25519Signer]] = {}
        self.signed: Counter[tuple[str, int]] = Counter()
        """Signatures made, by key name and version."""
        self.requests: Counter[str] = Counter()
        self.delay = 0.0
        """Seconds every answer waits."""
        self.status: int | None = None
        """Answer every request with this status, when set."""
        self.misbehave: str | None = None
        """One of the module's misbehaviours, when set."""
        self.redirect: str | None = None
        """Answer every request with a 307 to this service, when set."""
        self._lock = threading.Lock()
        kms = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                kms._handle(self, "GET")

            def do_POST(self) -> None:
                kms._handle(self, "POST")

            def log_message(self, format: str, *args: Any) -> None:
                pass

        self._server = _Server(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self._server.server_address[1]}"

    def create(self, name: str, seed: bytes | None = None) -> Ed25519Signer:
        """A key named ``name``, at version 1."""
        key = Ed25519Signer(seed if seed is not None else secrets.token_bytes(32))
        with self._lock:
            self.keys[name] = [key]
        return key

    def rotate(self, name: str) -> Ed25519Signer:
        """A new version of ``name``, which signers built from now on pin."""
        key = Ed25519Signer.generate()
        with self._lock:
            self.keys[name].append(key)
        return key

    def key(self, name: str, version: int | None = None) -> Ed25519Signer:
        with self._lock:
            versions = self.keys[name]
            return versions[-1 if version is None else version - 1]

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()

    def __enter__(self) -> FakeKms:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- the protocol -------------------------------------------------------------

    def _handle(self, handler: BaseHTTPRequestHandler, method: str) -> None:
        if self.delay:
            time.sleep(self.delay)
        url = urllib.parse.urlsplit(handler.path)
        parts = url.path.strip("/").split("/")
        with self._lock:
            self.requests[method] += 1
        if self.token is not None and handler.headers.get("Authorization") != (
            f"Bearer {self.token}"
        ):
            self._answer(handler, 401, {"errors": ["permission denied"]})
            return
        if self.status is not None:
            self._answer(handler, self.status, {"errors": ["scripted"]})
            return
        if self.redirect is not None:
            with contextlib.suppress(OSError):
                handler.send_response(307)
                handler.send_header("Location", self.redirect + handler.path)
                handler.send_header("Content-Length", "0")
                handler.end_headers()
            return
        if len(parts) < 3 or parts[:2] != ["v1", "keys"] or parts[2] not in self.keys:
            self._answer(handler, 404, {"errors": ["no such key"]})
            return
        name = parts[2]
        versions = self.keys[name]
        if method == "GET" and len(parts) == 3:
            query = urllib.parse.parse_qs(url.query)
            version = int(query["version"][0]) if "version" in query else len(versions)
            if not 1 <= version <= len(versions):
                self._answer(handler, 404, {"errors": ["no such version"]})
                return
            public = versions[version - 1].public_key().raw.hex()
            alg = "rsa" if self.misbehave == OTHER_ALG else "ed25519"
            answered = version + 1 if self.misbehave == WRONG_PIN else version
            self._answer(handler, 200, {"alg": alg, "version": answered, "public_key": public})
            return
        if method == "POST" and parts[3:] == ["sign"]:
            length = int(handler.headers.get("Content-Length") or 0)
            try:
                body = json.loads(handler.rfile.read(length))
                version = int(body["version"])
                message = base64.b64decode(body["message"], validate=True)
            except (ValueError, KeyError, TypeError, binascii.Error):
                self._answer(handler, 400, {"errors": ["malformed"]})
                return
            if not 1 <= version <= len(versions):
                self._answer(handler, 400, {"errors": ["no such version"]})
                return
            key = versions[version - 1]
            signature = key.sign(message)
            answered_version = version
            if self.misbehave == GARBAGE:
                signature = secrets.token_bytes(64)
            elif self.misbehave == OTHER_KEY:
                signature = Ed25519Signer.generate().sign(message)
            elif self.misbehave == WRONG_VERSION:
                answered_version = version + 1
            elif self.misbehave == NOT_JSON:
                self._raw(handler, 200, b"<html>signed</html>")
                return
            with self._lock:
                self.signed[(name, version)] += 1
            self._answer(handler, 200, {"version": answered_version, "signature": signature.hex()})
            return
        self._answer(handler, 404, {"errors": ["no such route"]})

    def _answer(self, handler: BaseHTTPRequestHandler, status: int, body: Any) -> None:
        self._raw(handler, status, json.dumps(body).encode())

    @staticmethod
    def _raw(handler: BaseHTTPRequestHandler, status: int, body: bytes) -> None:
        try:
            handler.send_response(status)
            handler.send_header("Content-Type", "application/json")
            handler.send_header("Content-Length", str(len(body)))
            handler.end_headers()
            handler.wfile.write(body)
        except OSError:  # the client stopped waiting
            pass
