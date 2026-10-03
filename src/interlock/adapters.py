"""Sink adapters for the relay (``docs/OUTBOX_DESIGN.md`` §7.2).

An adapter makes one kind of call. It holds the sink's endpoint and
credentials, which live in the relay's configuration and environment and
nowhere else, and it never sees the database. :class:`HttpAdapter` is the
generic JSON-over-HTTP(S) one; :class:`interlock.stripe.StripeAdapter` and
:class:`interlock.sendgrid.SendGridAdapter` speak their vendors' APIs over the
same transport (:func:`exchange`), and classify their vendors' replies.

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
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Final

from interlock.relay import DELIVERED, PERMANENT, RETRYABLE, UNKNOWN, Delivery, DeliveryResult

__all__ = ["HttpAdapter", "Reply", "exchange", "retry_after_seconds"]

RETRYABLE_STATUSES: Final = frozenset({408, 409, 425, 429, 500, 502, 503, 504})
"""Statuses that say the sink did not act and may if asked again. 409 is
here because a sink that honours idempotency keys answers it while an earlier
call with the same key is still in progress."""

_MAX_BODY: Final = 1 << 20


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: object, **kwargs: object) -> None:
        return None


_OPENER: Final = urllib.request.build_opener(_NoRedirects())


@dataclass(frozen=True, slots=True)
class Reply:
    """What a sink answered: its status, its body (up to a megabyte) and its
    headers, for the adapter that asked to classify."""

    status: int
    body: bytes
    headers: Mapping[str, str]

    @property
    def digest(self) -> str:
        """SHA-256 of the body: recorded, never the body itself."""
        return hashlib.sha256(self.body).hexdigest()

    def header(self, name: str) -> str | None:
        wanted = name.lower()
        return next((v for k, v in self.headers.items() if k.lower() == wanted), None)


def exchange(
    url: str, body: bytes, headers: Mapping[str, str], method: str, timeout: float
) -> Reply | DeliveryResult:
    """Make one call. The sink's reply, whatever its status; or, when there
    was none, what that means: ``retryable`` when the request never left this
    process (a refused connection, an unresolvable host, a connect timeout),
    ``unknown`` when it was sent and the reply was lost. Redirects are never
    followed."""
    # The scheme is http or https, checked by every adapter at construction;
    # the path is configuration or the adapter's own. Nothing in the URL comes
    # from the request.
    request = urllib.request.Request(  # noqa: S310
        url, data=body, headers=dict(headers), method=method
    )
    try:
        with _OPENER.open(request, timeout=timeout) as response:
            return Reply(int(response.status), response.read(_MAX_BODY), dict(response.headers))
    except urllib.error.HTTPError as exc:
        try:
            content = exc.read(_MAX_BODY)
        except (OSError, http.client.HTTPException):
            content = b""
        return Reply(int(exc.code), content, dict(exc.headers or {}))
    except urllib.error.URLError as exc:
        # Raised while connecting: the request never left this process.
        reason = exc.reason
        if isinstance(reason, ConnectionRefusedError | socket.gaierror | TimeoutError):
            return DeliveryResult(RETRYABLE, detail=f"not sent: {reason}")
        return DeliveryResult(UNKNOWN, detail=f"connection failed: {reason}")
    except (TimeoutError, http.client.HTTPException, ConnectionError, OSError) as exc:
        # After the request was sent: whether the sink acted is unknown.
        return DeliveryResult(UNKNOWN, detail=f"{type(exc).__name__} after sending: {exc}")


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

    __slots__ = ("_base", "_headers", "_idempotency_header", "_retryable", "_routes")

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
        reply = exchange(self._base + path, delivery.payload, headers, method, delivery.timeout)
        if isinstance(reply, DeliveryResult):
            return reply
        return _classify(reply.status, reply.body, reply.header("Retry-After"), self._retryable)


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
            retry_after=retry_after_seconds(retry_after),
        )
    detail = f"HTTP {status}" + (" (redirects are not followed)" if 300 <= status < 400 else "")
    return DeliveryResult(PERMANENT, status_code=status, response_digest=digest, detail=detail)


def retry_after_seconds(retry_after: str | None) -> float | None:
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
