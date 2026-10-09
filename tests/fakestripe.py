"""A Stripe for the tests: the protocol the adapter relies on, on localhost.

It keeps what makes Stripe safe to redeliver to, and nothing else:

- **Idempotency.** The first call with a key executes and its result is
  stored; a later call with the key and the same parameters is answered from
  the store, with ``Idempotent-Replayed: true``, and executes nothing. The
  key with other parameters is an ``idempotency_error``; while the first call
  is still executing, a 409.
- **Objects.** A payment intent or charge is created once per key, and a
  refund names one that exists, refunding at most what is left of it.
- **Its wire format.** Form-encoded bodies in bracket notation, a bearer
  key, a ``Stripe-Version``.

Every call can be scripted, as :class:`tests.fakesink.FakeSink`'s are: to
fail without executing, to execute and then hang or drop the connection, or to
execute and hold the reply while a test kills the relay that made the call.
:attr:`effects` counts executions per key: a charge made twice is two.
"""

from __future__ import annotations

import socket
import time
import urllib.parse
from collections import Counter
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler
from typing import Any

from tests.fakesink import OK, Call, FakeSink

KEY = "sk_test_interlock"


def stripe_error(
    code: int, kind: str = "api_error", *, should_retry: bool | None = None
) -> tuple[Any, ...]:
    """Do not execute; answer ``code`` with a Stripe error of ``kind``."""
    return ("stripe-error", code, kind, should_retry)


def act_then(code: int) -> tuple[Any, ...]:
    """Execute, store the result, then answer ``code`` instead of it: a 5xx
    after the work was done."""
    return ("act-then", code)


def parse_form(body: bytes) -> dict[str, Any]:
    """Stripe's bracket notation back into nested objects and arrays."""
    root: dict[str, Any] = {}
    for name, value in urllib.parse.parse_qsl(body.decode("ascii"), keep_blank_values=True):
        head, _, rest = name.partition("[")
        keys = [head] + ([part.rstrip("]") for part in ("[" + rest).split("[")[1:]] if rest else [])
        node: Any = root
        for index, key in enumerate(keys):
            last = index == len(keys) - 1
            nxt: Any = value if last else ([] if keys[index + 1].isdigit() else {})
            if isinstance(node, list):
                position = int(key)
                while len(node) <= position:
                    node.append(None)
                if node[position] is None or last:
                    node[position] = nxt
                node = node[position]
            else:
                if key not in node or last:
                    node[key] = nxt
                node = node[key]
    return root


@dataclass
class Stored:
    params: dict[str, Any]
    path: str
    status: int
    body: dict[str, Any]


class FakeStripe(FakeSink):
    """:param key: The secret key a call must carry."""

    def __init__(self, *, key: str = KEY) -> None:
        super().__init__(honour_keys=True)
        self.key = key
        self.objects: dict[str, dict[str, Any]] = {}
        self.stored: dict[str, Stored] = {}
        self.versions: Counter[str] = Counter()
        self._running: set[str] = set()
        self._numbers = Counter[str]()

    # -- the API -------------------------------------------------------------

    def _handle(self, handler: BaseHTTPRequestHandler) -> None:
        length = int(handler.headers.get("Content-Length") or 0)
        body = handler.rfile.read(length)
        key = handler.headers.get("Idempotency-Key") or ""
        version = handler.headers.get("Stripe-Version") or ""
        if handler.headers.get("Authorization") != f"Bearer {self.key}":
            self._record(handler, key, body, acted=False)
            self._answer(handler, 401, _error("invalid_request_error", "api_key_invalid"), {})
            return
        if handler.headers.get("Content-Type") != "application/x-www-form-urlencoded":
            self._record(handler, key, body, acted=False)
            self._answer(handler, 400, _error("invalid_request_error", "content_type"), {})
            return
        params = parse_form(body)
        with self._lock:
            self.versions[version] += 1
            queue = self._by_key.get(key) or self._default
            if queue:
                behaviour = queue.popleft()
            else:
                behaviour = self.chaos() if self.chaos is not None else OK
            kind = behaviour[0]
            reply: tuple[int, dict[str, Any], dict[str, str]] | None = None
            if kind in ("status", "stripe-error"):
                self._record(handler, key, body, acted=False)
            elif key in self._running:
                self._record(handler, key, body, acted=False)
                reply = (409, _error("invalid_request_error", "idempotency_key_in_use"), {})
                kind = "answer"
            elif key in self.stored:
                stored = self.stored[key]
                self._record(handler, key, body, acted=False)
                if stored.params != params or stored.path != handler.path:
                    reply = (400, _error("idempotency_error", "idempotency_key_reused"), {})
                else:
                    reply = (stored.status, stored.body, {"Idempotent-Replayed": "true"})
                kind = "answer"
            else:
                self._running.add(key)
        if kind == "status":
            headers = {} if behaviour[2] is None else {"Retry-After": str(behaviour[2])}
            self._answer(handler, behaviour[1], _error("api_error", "scripted"), headers)
            return
        if kind == "stripe-error":
            headers = {}
            if behaviour[3] is not None:
                headers["Stripe-Should-Retry"] = "true" if behaviour[3] else "false"
            self._answer(handler, behaviour[1], _error(behaviour[2], "scripted"), headers)
            return
        if kind == "answer":
            assert reply is not None
            self._answer(handler, reply[0], reply[1], reply[2])
            return
        # Execute: once per key, whatever happens to the reply.
        status, result = self._execute(handler.path, params)
        with self._lock:
            acted = 200 <= status < 300
            if acted:
                self.effects[key] += 1
            self.stored[key] = Stored(params, handler.path, status, result)
            self._running.discard(key)
            self._record(handler, key, body, acted=acted)
        if kind == "act-then":
            self._answer(handler, behaviour[1], _error("api_error", "after_executing"), {})
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
        self._answer(handler, status, result, {"Request-Id": f"req_{len(self.calls)}"})

    def _execute(self, path: str, params: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        with self._lock:
            if path == "/v1/payment_intents":
                return 200, self._create("pi", "payment_intent", params, refunded=0)
            if path == "/v1/charges":
                return 200, self._create("ch", "charge", params, refunded=0)
            if path == "/v1/refunds":
                target = params.get("payment_intent") or params.get("charge")
                charged = self.objects.get(str(target))
                if charged is None or charged["object"] == "refund":
                    return 404, _error("invalid_request_error", "resource_missing")
                left = int(charged["amount"]) - int(charged["refunded"])
                amount = int(params.get("amount") or left)
                if left <= 0:
                    return 400, _error("invalid_request_error", "charge_already_refunded")
                if amount > left:
                    return 400, _error("invalid_request_error", "amount_too_large")
                charged["refunded"] = int(charged["refunded"]) + amount
                return 200, self._create(
                    "re", "refund", {**params, "amount": amount, "currency": charged["currency"]}
                )
            return 404, _error("invalid_request_error", "unrecognized_url")

    def _create(
        self, prefix: str, kind: str, params: dict[str, Any], **extra: Any
    ) -> dict[str, Any]:
        self._numbers[prefix] += 1
        made = {
            "id": f"{prefix}_{self._numbers[prefix]:06d}",
            "object": kind,
            **{k: v for k, v in params.items()},
            **extra,
        }
        if "amount" in made:
            made["amount"] = int(made["amount"])
        self.objects[made["id"]] = made
        return dict(made)

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
                traceparent=handler.headers.get("traceparent"),
            )
        )

    # -- reading ---------------------------------------------------------------

    def of(self, kind: str) -> list[dict[str, Any]]:
        with self._lock:
            return [o for o in self.objects.values() if o["object"] == kind]


def _error(kind: str, code: str) -> dict[str, Any]:
    return {"error": {"type": kind, "code": code, "message": f"{kind}: {code}"}}
