"""A SendGrid for the tests: ``POST /v3/mail/send`` on localhost.

It keeps what makes SendGrid unsafe to redeliver to: there are no
idempotency keys, and every call it accepts sends an email. :attr:`effects`
counts the emails sent per Interlock idempotency key (read from the
``custom_args`` the adapter adds), so a test can say whether one went twice.

It checks the parts of the v3 body the adapter builds (a bearer key,
``personalizations`` with recipients, ``from``, ``subject``, ``content`` with
``text/plain`` first) and answers 202 with an ``X-Message-Id``. In sandbox
mode it answers 200 and sends nothing. Calls can be scripted, as
:class:`tests.fakesink.FakeSink`'s are.
"""

from __future__ import annotations

import json
import socket
import time
import uuid
from http.server import BaseHTTPRequestHandler
from typing import Any

from tests.fakesink import OK, Call, FakeSink

KEY = "SG.interlock-test"


def rate_limited(reset_in: int) -> tuple[Any, ...]:
    """Do not send; answer 429 with ``X-RateLimit-Reset`` ``reset_in`` seconds out."""
    return ("rate-limited", reset_in)


def send_then(code: int) -> tuple[Any, ...]:
    """Send, then answer ``code``: a 5xx after the email went."""
    return ("send-then", code)


class FakeSendGrid(FakeSink):
    def __init__(self, *, key: str = KEY) -> None:
        super().__init__(honour_keys=False)
        self.key = key
        self.sent: list[dict[str, Any]] = []
        self.sandboxed: list[dict[str, Any]] = []

    def _handle(self, handler: BaseHTTPRequestHandler) -> None:
        length = int(handler.headers.get("Content-Length") or 0)
        body = handler.rfile.read(length)
        if handler.headers.get("Authorization") != f"Bearer {self.key}":
            self._record(handler, "", body, acted=False)
            self._answer(handler, 401, {"errors": [{"message": "unauthorized"}]}, {})
            return
        try:
            mail = json.loads(body)
            problem = _problem(mail)
        except ValueError:
            mail, problem = {}, "not JSON"
        key = _key(mail)
        if problem is not None:
            self._record(handler, key, body, acted=False)
            self._answer(handler, 400, {"errors": [{"message": problem}]}, {})
            return
        sandbox = bool(mail.get("mail_settings", {}).get("sandbox_mode", {}).get("enable"))
        with self._lock:
            queue = self._by_key.get(key) or self._default
            if queue:
                behaviour = queue.popleft()
            else:
                behaviour = self.chaos() if self.chaos is not None else OK
            kind = behaviour[0]
            sends = kind in ("ok", "drop", "hang", "hold", "send-then") and not sandbox
            if sends:
                self.effects[key] += 1
                self.sent.append(mail)
            elif sandbox and kind == "ok":
                self.sandboxed.append(mail)
            self._record(handler, key, body, acted=sends)
        if kind == "status":
            self._answer(handler, behaviour[1], {"errors": [{"message": "scripted"}]}, {})
            return
        if kind == "rate-limited":
            reset = str(int(time.time()) + behaviour[1])
            self._answer(
                handler,
                429,
                {"errors": [{"message": "too many requests"}]},
                {"X-RateLimit-Reset": reset},
            )
            return
        if kind == "send-then":
            self._answer(handler, behaviour[1], {"errors": [{"message": "after sending"}]}, {})
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
        self._empty(handler, 200 if sandbox else 202, {"X-Message-Id": uuid.uuid4().hex[:22]})

    def _record(
        self, handler: BaseHTTPRequestHandler, key: str, body: bytes, *, acted: bool
    ) -> None:
        self.calls.append(
            Call(
                path=handler.path,
                key=key,
                message="",
                attempt=0,
                body=body,
                acted=acted,
                at=time.monotonic(),
                authorization=handler.headers.get("Authorization"),
            )
        )

    @staticmethod
    def _empty(handler: BaseHTTPRequestHandler, code: int, headers: dict[str, str]) -> None:
        try:
            handler.send_response(code)
            handler.send_header("Content-Length", "0")
            for name, value in headers.items():
                handler.send_header(name, value)
            handler.end_headers()
        except OSError:
            pass


def _key(mail: Any) -> str:
    try:
        return str(mail["personalizations"][0]["custom_args"]["interlock_idempotency_key"])
    except (KeyError, IndexError, TypeError):
        return ""


def _problem(mail: Any) -> str | None:
    if not isinstance(mail, dict):
        return "the body is an object"
    people = mail.get("personalizations")
    if not isinstance(people, list) or not people or not people[0].get("to"):
        return "personalizations[0].to is required"
    if not isinstance(mail.get("from"), dict) or "email" not in mail["from"]:
        return "from.email is required"
    if not mail.get("subject"):
        return "subject is required"
    content = mail.get("content")
    if not isinstance(content, list) or not content:
        return "content is required"
    kinds = [c.get("type") for c in content]
    if "text/plain" in kinds and kinds[0] != "text/plain":
        return "text/plain must come first"
    return None
