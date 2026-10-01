"""Sink adapters for the relay (``docs/OUTBOX_DESIGN.md`` §7.2).

An adapter makes one kind of call. It holds the sink's endpoint and
credentials, which live in the relay's configuration and environment and
nowhere else, and it never sees the database. :class:`HttpAdapter` is the
generic JSON-over-HTTP(S) one.

The classification is the part that matters, because it decides whether a call
is made again:

======================================  ==================  =============================
What happened                           Outcome             Next
======================================  ==================  =============================
2xx                                     ``delivered``       done
408, 409, 425, 429, 500, 502-504        ``retryable``       backoff; ``Retry-After`` kept
any other status                        ``permanent``       dead letter
refused connection, unresolvable host,  ``retryable``       nothing was sent
connect timeout
timeout or connection lost after the    ``unknown``         the sink may have acted:
request was sent                                            redeliver with the same key,
                                                            or dead-letter (per sink)
======================================  ==================  =============================

Redirects are never followed: an endpoint is configured, not discovered, and
a sink that redirects is answered as ``permanent``, never with a call to an
address the agent might have steered it to.
"""

from __future__ import annotations

import hashlib
import http.client
import socket
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Final

from interlock.relay import DELIVERED, PERMANENT, RETRYABLE, UNKNOWN, Delivery, DeliveryResult

__all__ = ["HttpAdapter"]

RETRYABLE_STATUSES: Final = frozenset({408, 409, 425, 429, 500, 502, 503, 504})
"""Statuses that say the sink did not act and may if asked again. 409 is
here because a sink that honours idempotency keys answers it while an earlier
call with the same key is still in progress."""

_MAX_BODY: Final = 1 << 20


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: object, **kwargs: object) -> None:
        return None


class HttpAdapter:
    """Delivers a request as a JSON body to a configured endpoint.

    :param base_url: The sink's endpoint, ``https://api.example.com``.
    :param routes: Each operation the relay may call, as ``"POST /v3/send"``.
    :param headers: Sent with every call: credentials, from the relay's
        environment, never from the payload. A callable is asked on every
        call, for tokens that rotate.
    :param idempotency_header: Carries the request's idempotency key.
    :raises ValueError: On a route that is not ``"METHOD /path"``.
    """

    __slots__ = ("_base", "_headers", "_idempotency_header", "_opener", "_retryable", "_routes")

    def __init__(
        self,
        base_url: str,
        *,
        routes: Mapping[str, str],
        headers: Mapping[str, str] | Callable[[], Mapping[str, str]] | None = None,
        idempotency_header: str = "Idempotency-Key",
        retryable_statuses: frozenset[int] = RETRYABLE_STATUSES,
    ) -> None:
        if not base_url.startswith(("http://", "https://")):
            raise ValueError(f"an endpoint is an http(s) URL, not {base_url!r}")
        self._base = base_url.rstrip("/")
        parsed: dict[str, tuple[str, str]] = {}
        for operation, route in routes.items():
            method, _, path = route.partition(" ")
            if not method.isalpha() or not path.startswith("/"):
                raise ValueError(f"route for {operation!r} is not 'METHOD /path': {route!r}")
            parsed[operation] = (method.upper(), path)
        self._routes = parsed
        self._headers = headers or {}
        self._idempotency_header = idempotency_header
        self._retryable = retryable_statuses
        self._opener = urllib.request.build_opener(_NoRedirects())

    def send(self, delivery: Delivery) -> DeliveryResult:
        route = self._routes.get(delivery.operation)
        if route is None:
            return DeliveryResult(
                PERMANENT, detail=f"the relay has no route for operation {delivery.operation!r}"
            )
        method, path = route
        headers = dict(self._headers() if callable(self._headers) else self._headers)
        headers.update(
            {
                "Content-Type": "application/json",
                self._idempotency_header: delivery.idempotency_key,
                "X-Interlock-Message-Id": str(delivery.message_id),
                "X-Interlock-Attempt": str(delivery.attempt),
                "X-Interlock-Payload-SHA256": delivery.payload_hash,
            }
        )
        # The scheme is http or https, checked at construction; the path is
        # configuration. Nothing in the URL comes from the request.
        request = urllib.request.Request(  # noqa: S310
            self._base + path, data=delivery.payload, headers=headers, method=method
        )
        try:
            with self._opener.open(request, timeout=delivery.timeout) as response:
                body = response.read(_MAX_BODY)
                return _classify(
                    int(response.status), body, response.headers.get("Retry-After"), self._retryable
                )
        except urllib.error.HTTPError as exc:
            try:
                body = exc.read(_MAX_BODY)
            except (OSError, http.client.HTTPException):
                body = b""
            return _classify(
                int(exc.code),
                body,
                exc.headers.get("Retry-After") if exc.headers else None,
                self._retryable,
            )
        except urllib.error.URLError as exc:
            # Raised while connecting: the request never left this process.
            reason = exc.reason
            if isinstance(reason, ConnectionRefusedError | socket.gaierror | TimeoutError):
                return DeliveryResult(RETRYABLE, detail=f"not sent: {reason}")
            return DeliveryResult(UNKNOWN, detail=f"connection failed: {reason}")
        except (TimeoutError, http.client.HTTPException, ConnectionError, OSError) as exc:
            # After the request was sent: whether the sink acted is unknown.
            return DeliveryResult(UNKNOWN, detail=f"{type(exc).__name__} after sending: {exc}")


def _classify(
    status: int, body: bytes, retry_after: str | None, retryable: frozenset[int]
) -> DeliveryResult:
    digest = hashlib.sha256(body).hexdigest()
    if 200 <= status < 300:
        return DeliveryResult(DELIVERED, status_code=status, response_digest=digest)
    if status in retryable:
        return DeliveryResult(
            RETRYABLE,
            status_code=status,
            response_digest=digest,
            detail=f"HTTP {status}",
            retry_after=_seconds(retry_after),
        )
    detail = f"HTTP {status}" + (" (redirects are not followed)" if 300 <= status < 400 else "")
    return DeliveryResult(PERMANENT, status_code=status, response_digest=digest, detail=detail)


def _seconds(retry_after: str | None) -> float | None:
    """``Retry-After`` as seconds from now: a number, or an HTTP date."""
    if not retry_after:
        return None
    value = retry_after.strip()
    if value.isdigit():
        return float(value)
    try:
        when = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    return max(0.0, (when - datetime.now(UTC)).total_seconds())
