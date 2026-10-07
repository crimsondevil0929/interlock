"""The zero-trust inbox: vendors' webhooks, verified, bound, attested (``docs/EPIC5_DESIGN.md`` §2).

Vendors answer later: Stripe sends ``charge.refund.updated`` days after a
refund. An inbox process, which alone holds the webhook secrets, takes each
webhook through four steps, and a vendor's retry through them again changes
nothing:

1. **The vendor's signature**, over the raw body, within a tolerance of its
   timestamp: Stripe's ``Stripe-Signature``; the Standard Webhooks scheme
   (``webhook-id``, ``webhook-timestamp``, ``webhook-signature``) for a generic
   source; SendGrid's ECDSA-signed Event Webhook. Anything that does not verify
   is answered and recorded nowhere.
2. **The event**, appended to its source's hash-linked log, attested with the
   inbox's own Ed25519 key: what was received, when, its body's hash, and its
   *projection*, the named fields of a closed set of types an agent may see.
   No free text ever projects.
3. **The match**: the delivered request whose relay-attested ``remote_ref``
   the event names. The relay's attestation is verified, and so is the plan
   its idempotency key derives from, before the event is bound.
4. **The fact**: the binding, attested too. It names the delivery-log row the
   delivery receipt names, so one chain of signatures runs from the vendor to
   the plan.

An engine consumes a fact in a plan exactly once (:meth:`~interlock.engine.EscrowEngine.facts`,
:meth:`~interlock.builder.PlanBuilder.consume`), and only after both
attestations verify under ``[inbox.keys]`` (:func:`verify_fact`).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import logging
import re
import threading
import uuid
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Final, Protocol

from agentgov.receipts.canonical import canonical_bytes
from agentgov.receipts.signing import Signer

from interlock.compaction import instant_text
from interlock.deliveries import _digest
from interlock.records import Keyring
from interlock.types import InboundFact, _frozen, exact_number, field_path, outbound_key, value_at

__all__ = [
    "INBOUND_DOMAIN",
    "KINDS",
    "FieldSpec",
    "InboundEvent",
    "InboundSource",
    "Inbox",
    "InboxReport",
    "InboxServer",
    "Rejected",
    "Response",
    "event_hash",
    "inbox_genesis",
    "project",
    "serve",
    "verify_fact",
    "verify_inbox",
]

logger = logging.getLogger("interlock.inbox")

INBOUND_DOMAIN: Final = b"ILOK1/inbound/v1\n"
"""Prefix on every signing input the inbox makes: its signatures can stand in
for no ILOK1 record's, ARC1 document's or relay attestation's."""
EVENT_VERSION: Final = "ILOK1-inbound-event"
FACT_VERSION: Final = "ILOK1-inbound-fact"
KINDS: Final = ("http", "stripe", "sendgrid")
DEFAULT_TOLERANCE: Final = timedelta(minutes=5)
MAX_BODY: Final = 256 * 1024

_NAME: Final = re.compile(r"[a-z][a-z0-9_-]{0,62}")
_ID: Final = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.:-]{0,254}")
_CODE: Final = re.compile(r"[a-z][a-z0-9_.]{0,63}")
_CURRENCY: Final = re.compile(r"[a-z]{3}")
_EVENT_TYPE: Final = re.compile(r"[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)*")
_MAX_INTEGER: Final = 2**53 - 1


# --------------------------------------------------------------------------
# the projection: what an agent may see of an event, typed
# --------------------------------------------------------------------------

TYPES: Final = ("id", "code", "integer", "decimal", "currency", "boolean", "instant")
"""Every type a projected field may have. None admits free text."""


def typed(kind: str, value: object) -> object | None:
    """``value`` as a projected field of type ``kind``, or ``None`` when it does
    not fit: withheld, never coerced."""
    if kind == "id":
        return value if isinstance(value, str) and _ID.fullmatch(value) else None
    if kind == "code":
        return value if isinstance(value, str) and _CODE.fullmatch(value) else None
    if kind == "currency":
        return value if isinstance(value, str) and _CURRENCY.fullmatch(value) else None
    if kind == "boolean":
        return value if isinstance(value, bool) else None
    if kind in ("integer", "instant"):
        if isinstance(value, bool) or not isinstance(value, int):
            return None
        if not -_MAX_INTEGER <= value <= _MAX_INTEGER or (kind == "instant" and value < 0):
            return None
        return value
    if kind == "decimal":
        if isinstance(value, bool) or not isinstance(value, int | str):
            return None
        return str(value) if exact_number(value) is not None else None
    raise ValueError(f"no field type {kind!r}: one of {', '.join(TYPES)}")


@dataclass(frozen=True, slots=True)
class FieldSpec:
    """One projected field: its name, where the event holds it (a dotted
    path), and its type."""

    name: str
    path: str
    type: str

    def __post_init__(self) -> None:
        if not _CODE.fullmatch(self.name):
            raise ValueError(f"a field's name is a lowercase identifier, not {self.name!r}")
        if self.type not in TYPES:
            raise ValueError(f"field {self.name}: type is one of {', '.join(TYPES)}")
        if not self.path.strip():
            raise ValueError(f"field {self.name} names no path")


def project(
    document: object, specs: Iterable[FieldSpec]
) -> tuple[dict[str, object], tuple[str, ...]]:
    """The fields ``specs`` name, typed, and the names of those present whose
    value did not fit its type. A field the event does not hold is left out."""
    fields: dict[str, object] = {}
    withheld: list[str] = []
    for spec in specs:
        found, value = value_at(document, field_path(spec.path))
        if not found or value is None:
            continue
        fitted = typed(spec.type, value)
        if fitted is None:
            withheld.append(spec.name)
        else:
            fields[spec.name] = fitted
    return fields, tuple(sorted(withheld))


STRIPE_FIELDS: Final = (
    FieldSpec("object", "data.object.object", "code"),
    FieldSpec("id", "data.object.id", "id"),
    FieldSpec("status", "data.object.status", "code"),
    FieldSpec("amount", "data.object.amount", "integer"),
    FieldSpec("amount_refunded", "data.object.amount_refunded", "integer"),
    FieldSpec("currency", "data.object.currency", "currency"),
    FieldSpec("payment_intent", "data.object.payment_intent", "id"),
    FieldSpec("charge", "data.object.charge", "id"),
    FieldSpec("reason", "data.object.reason", "code"),
    FieldSpec("failure_code", "data.object.failure_code", "code"),
    FieldSpec("failure_reason", "data.object.failure_reason", "code"),
    FieldSpec("created", "data.object.created", "instant"),
    FieldSpec("livemode", "livemode", "boolean"),
)
"""What an agent may see of a Stripe event: identifiers, codes, amounts and
flags. Never a description, metadata, a name or an email address."""
_STRIPE_REFERENCES: Final = ("data.object.id", "data.object.payment_intent", "data.object.charge")

SENDGRID_FIELDS: Final = (
    FieldSpec("event", "event", "code"),
    FieldSpec("type", "type", "code"),
    FieldSpec("status", "status", "id"),
    FieldSpec("timestamp", "timestamp", "instant"),
)
"""What an agent may see of a SendGrid event. Never the recipient, the reason
text, the response, a URL or a user agent."""


# --------------------------------------------------------------------------
# sources
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class InboundSource:
    """A vendor that sends webhooks to ``/inbox/<name>`` (``[[inbox.sources]]``).

    :ivar kind: ``"stripe"``, ``"sendgrid"``, or ``"http"`` for a generic
        source signing as Standard Webhooks do.
    :ivar secret_env: The environment variable holding the signing secret
        (``stripe``, ``http``): the inbox process's alone.
    :ivar verification_key: SendGrid's public verification key, base64 DER: a
        public key, so configuration may hold it.
    :ivar tolerance: How far a signed timestamp may be from the inbox's clock.
    :ivar type_field: Where an ``http`` source's event names its type.
    :ivar references: Where an ``http`` source's event names what it is about.
    :ivar fields: An ``http`` source's projection.
    """

    name: str
    kind: str
    secret_env: str = ""
    verification_key: str = ""
    tolerance: timedelta = DEFAULT_TOLERANCE
    type_field: str = "type"
    references: tuple[str, ...] = ()
    fields: tuple[FieldSpec, ...] = ()

    def __post_init__(self) -> None:
        if not _NAME.fullmatch(self.name):
            raise ValueError(f"an inbound source's name is a lowercase identifier: {self.name!r}")
        if self.kind not in KINDS:
            raise ValueError(f"source {self.name}: kind is one of {', '.join(KINDS)}")
        if self.kind == "sendgrid":
            if not self.verification_key:
                raise ValueError(f"source {self.name}: SendGrid's verification_key is needed")
            try:
                _p256(self.name, self.verification_key)
            except ImportError:  # pragma: no cover - the inbox has it, to sign; it checks again
                pass
        elif not self.secret_env:
            raise ValueError(f"source {self.name}: secret_env names its signing secret")
        if not timedelta(seconds=1) <= self.tolerance <= timedelta(hours=1):
            raise ValueError(f"source {self.name}: tolerance is between a second and an hour")
        if self.kind == "http" and not self.references:
            raise ValueError(f"source {self.name}: references name where an event's object is")
        if self.kind != "http" and (self.references or self.fields):
            raise ValueError(
                f"source {self.name}: a {self.kind} source's references and fields are "
                f"{self.kind}'s own"
            )
        names = [f.name for f in self.fields]
        if len(set(names)) != len(names):
            raise ValueError(f"source {self.name}: a field is projected twice")

    def projection(self) -> tuple[FieldSpec, ...]:
        """What an agent may see of this source's events."""
        if self.kind == "stripe":
            return STRIPE_FIELDS
        if self.kind == "sendgrid":
            return SENDGRID_FIELDS
        return self.fields

    def config_hash(self) -> str:
        """A digest of everything the source admits, for the database's mirror."""
        from interlock.types import canonical_hash

        return canonical_hash(
            [
                "inbound-source",
                self.name,
                self.kind,
                self.verification_key,
                int(self.tolerance.total_seconds()),
                self.type_field,
                list(self.references),
                [[f.name, f.path, f.type] for f in self.projection()],
            ]
        )


# --------------------------------------------------------------------------
# the vendors' signatures
# --------------------------------------------------------------------------


class Rejected(Exception):  # noqa: N818 - an answer, not a fault
    """A webhook answered and recorded nowhere: why, and the HTTP status."""

    def __init__(self, status: int, reason: str) -> None:
        super().__init__(reason)
        self.status = status
        self.reason = reason


def _header(headers: Mapping[str, str], name: str) -> str | None:
    wanted = name.lower()
    for key, value in headers.items():
        if key.lower() == wanted:
            return value
    return None


def _within(signed: datetime, now: datetime, tolerance: timedelta) -> None:
    if abs(now - signed) > tolerance:
        raise Rejected(401, "the signed timestamp is outside the tolerance: a replay, or a clock")


def _timestamp(text: str | None) -> datetime:
    if text is None or not text.isascii() or not text.isdigit() or len(text) > 12:
        raise Rejected(400, "no signed timestamp")
    return datetime.fromtimestamp(int(text), UTC)


def verify_stripe(
    secret: str, headers: Mapping[str, str], body: bytes, now: datetime, tolerance: timedelta
) -> datetime:
    """Stripe's ``Stripe-Signature``: ``t=<unix>,v1=<hex>[,v1=<hex>...]``, one
    ``v1`` an HMAC-SHA256 of ``"<t>." + body`` under the endpoint's secret.

    :returns: The signed timestamp.
    :raises Rejected: On a missing or malformed header (400), no signature
        that verifies, or a timestamp outside the tolerance (401).
    """
    header = _header(headers, "Stripe-Signature")
    if not header:
        raise Rejected(400, "no Stripe-Signature")
    stamp: str | None = None
    signatures: list[str] = []
    for item in header.split(","):
        key, sep, value = item.strip().partition("=")
        if not sep:
            continue
        if key == "t":
            stamp = value
        elif key == "v1":
            signatures.append(value)
    signed = _timestamp(stamp)
    if not signatures:
        raise Rejected(400, "no v1 signature")
    expected = hmac.new(secret.encode("utf-8"), f"{stamp}.".encode() + body, "sha256").hexdigest()
    if not any(hmac.compare_digest(expected, candidate) for candidate in signatures):
        raise Rejected(401, "no signature verifies")
    _within(signed, now, tolerance)
    return signed


def verify_standard(
    secret: str, headers: Mapping[str, str], body: bytes, now: datetime, tolerance: timedelta
) -> tuple[str, datetime]:
    """Standard Webhooks: ``webhook-signature: v1,<base64> [v1,<base64>...]``,
    one an HMAC-SHA256 of ``"<webhook-id>.<webhook-timestamp>." + body`` under
    the key ``whsec_<base64>`` encodes.

    :returns: The webhook's id and its signed timestamp.
    :raises Rejected: As :func:`verify_stripe`.
    """
    message_id = _header(headers, "webhook-id")
    stamp = _header(headers, "webhook-timestamp")
    header = _header(headers, "webhook-signature")
    if not message_id or not header or not _ID.fullmatch(message_id):
        raise Rejected(400, "no webhook-id or webhook-signature")
    signed = _timestamp(stamp)
    try:
        key = base64.b64decode(secret.removeprefix("whsec_"), validate=True)
    except binascii.Error as exc:  # pragma: no cover - configuration, checked at start
        raise Rejected(500, "the source's secret is not base64") from exc
    expected = base64.b64encode(
        hmac.new(key, f"{message_id}.{stamp}.".encode() + body, "sha256").digest()
    )
    offered = [
        part.partition(",")[2].encode("ascii", "replace")
        for part in header.split()
        if part.startswith("v1,")
    ]
    if not offered:
        raise Rejected(400, "no v1 signature")
    if not any(hmac.compare_digest(expected, candidate) for candidate in offered):
        raise Rejected(401, "no signature verifies")
    _within(signed, now, tolerance)
    return message_id, signed


def _p256(source: str, public_key: str) -> Any:
    """SendGrid's verification key, base64 DER SubjectPublicKeyInfo, as a P-256
    public key; or why it is not one."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    try:
        key = serialization.load_der_public_key(base64.b64decode(public_key, validate=True))
    except (binascii.Error, ValueError) as exc:
        raise ValueError(
            f"source {source}: verification_key is not a base64 DER public key"
        ) from exc
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise ValueError(f"source {source}: verification_key is not an ECDSA P-256 key")
    return key


def verify_sendgrid(
    public_key: str, headers: Mapping[str, str], body: bytes, now: datetime, tolerance: timedelta
) -> datetime:
    """SendGrid's Signed Event Webhook: an ECDSA P-256 / SHA-256 signature (base64
    DER) over ``timestamp + body``, under the account's verification key.

    :returns: The signed timestamp.
    :raises Rejected: As :func:`verify_stripe`.
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    signature = _header(headers, "X-Twilio-Email-Event-Webhook-Signature")
    stamp = _header(headers, "X-Twilio-Email-Event-Webhook-Timestamp")
    if not signature:
        raise Rejected(400, "no X-Twilio-Email-Event-Webhook-Signature")
    signed = _timestamp(stamp)
    key = _p256("sendgrid", public_key)  # checked when the source was configured
    try:
        raw = base64.b64decode(signature, validate=True)
        key.verify(raw, f"{stamp}".encode() + body, ec.ECDSA(hashes.SHA256()))
    except (binascii.Error, InvalidSignature, ValueError) as exc:
        raise Rejected(401, "the signature does not verify") from exc
    _within(signed, now, tolerance)
    return signed


# --------------------------------------------------------------------------
# events, as parsed, and as recorded
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Parsed:
    """One event of a verified webhook, before it is recorded."""

    event_id: str
    kind: str
    part: int
    refs: tuple[str, ...]
    fields: Mapping[str, object]
    withheld: tuple[str, ...]


def parse_events(source: InboundSource, document: object, *, header_id: str | None) -> list[Parsed]:
    """The events a verified body holds.

    :raises Rejected: (400) On a body that is not the vendor's shape.
    """
    if source.kind == "sendgrid":
        if not isinstance(document, list) or not document:
            raise Rejected(400, "a SendGrid batch is a non-empty array of events")
        events: list[Parsed] = []
        for part, item in enumerate(document):
            if not isinstance(item, Mapping):
                raise Rejected(400, "a SendGrid event is an object")
            event_id, kind = item.get("sg_event_id"), item.get("event")
            if not isinstance(event_id, str) or not _ID.fullmatch(event_id):
                raise Rejected(400, "a SendGrid event without an sg_event_id")
            if not isinstance(kind, str) or not _EVENT_TYPE.fullmatch(kind):
                raise Rejected(400, "a SendGrid event without an event type")
            message = item.get("sg_message_id")
            named: tuple[str, ...] = (
                (message.split(".", 1)[0],)
                if isinstance(message, str) and _ID.fullmatch(message.split(".", 1)[0])
                else ()
            )
            fields, withheld = project(item, SENDGRID_FIELDS)
            events.append(Parsed(event_id, kind, part, named, fields, withheld))
        return events
    if not isinstance(document, Mapping):
        raise Rejected(400, "an event is a JSON object")
    paths: tuple[str, ...]
    if source.kind == "stripe":
        event_id, kind = document.get("id"), document.get("type")
        paths = _STRIPE_REFERENCES
    else:
        event_id = header_id
        found, kind = value_at(document, field_path(source.type_field))
        kind = kind if found else None
        paths = source.references
    if not isinstance(event_id, str) or not _ID.fullmatch(event_id):
        raise Rejected(400, "an event without an id")
    if not isinstance(kind, str) or not _EVENT_TYPE.fullmatch(kind):
        raise Rejected(400, "an event without a type")
    refs: list[str] = []
    for path in paths:
        found, value = value_at(document, field_path(path))
        if found and isinstance(value, str) and _ID.fullmatch(value) and value not in refs:
            refs.append(value)
    fields, withheld = project(document, source.projection())
    return [Parsed(event_id, kind, 0, tuple(refs), fields, withheld)]


@dataclass(frozen=True, slots=True)
class InboundEvent:
    """An event as its source's log records it."""

    source: str
    seq: int
    event_id: str
    kind: str
    vendor_at: datetime | None
    received_at: datetime
    body_hash: str
    part: int
    refs: tuple[str, ...]
    fields: Mapping[str, Any]
    withheld: tuple[str, ...]
    attestation: str
    prev_hash: str
    event_hash: str

    def recomputed(self) -> str:
        return event_hash(
            self.prev_hash,
            self.source,
            self.seq,
            self.event_id,
            self.kind,
            self.vendor_at,
            self.received_at,
            self.body_hash,
            self.part,
            self.refs,
            self.fields,
            self.withheld,
            self.attestation,
        )


def inbox_genesis(source: str) -> str:
    """Where a source's log starts."""
    return _digest("interlock-inbox-genesis-v1", source)


def _json(value: object) -> str:
    return canonical_bytes(value).decode("utf-8")


def event_hash(
    prev: str,
    source: str,
    seq: int,
    event_id: str,
    kind: str,
    vendor_at: datetime | None,
    received_at: datetime,
    body_hash: str,
    part: int,
    refs: Sequence[str],
    fields: Mapping[str, Any],
    withheld: Sequence[str],
    attestation: str,
) -> str:
    """An event row's hash, as ``interlock.inbox_event_hash`` and SQLite's
    ``interlock_inbox_hash`` compute it."""
    return _digest(
        "interlock-inbox-event-v1",
        prev,
        source,
        str(seq),
        event_id,
        kind,
        None if vendor_at is None else instant_text(vendor_at),
        instant_text(received_at),
        body_hash,
        str(part),
        _json(list(refs)),
        _json(dict(fields)),
        _json(list(withheld)),
        attestation,
    )


# --------------------------------------------------------------------------
# the inbox's attestations
# --------------------------------------------------------------------------


def _event_statement(
    source: str,
    event_id: str,
    kind: str,
    vendor_at: datetime | None,
    received_at: datetime,
    body_hash: str,
    part: int,
    refs: Sequence[str],
    fields: Mapping[str, Any],
    withheld: Sequence[str],
    alg: str,
    key_id: str,
) -> dict[str, Any]:
    return {
        "v": EVENT_VERSION,
        "source": source,
        "event_id": event_id,
        "type": kind,
        "vendor_at": None if vendor_at is None else instant_text(vendor_at),
        "received_at": instant_text(received_at),
        "body_hash": body_hash,
        "part": part,
        "refs": list(refs),
        "fields": dict(fields),
        "withheld": list(withheld),
        "sig": {"alg": alg, "key_id": key_id},
    }


def _fact_statement(fact: InboundFact, alg: str, key_id: str) -> dict[str, Any]:
    # The event's own attestation is signed in, and with it everything the
    # event says: a fact cannot carry another event's attested content.
    return {
        "v": FACT_VERSION,
        "fact_id": str(fact.fact_id),
        "event": {
            "source": fact.source,
            "seq": fact.event_seq,
            "hash": fact.event_hash,
            "attestation": fact.event_attestation,
        },
        "subject": {
            "message_id": str(fact.message_id),
            "delivery_seq": fact.delivery_seq,
            "delivery_hash": fact.delivery_hash,
            "remote_ref": fact.remote_ref,
        },
        "scope": fact.scope_id,
        "plan": fact.plan_id,
        "tenant": fact.tenant_id,
        "sig": {"alg": alg, "key_id": key_id},
    }


def _sign(signer: Signer, statement: Mapping[str, Any]) -> str:
    signature = signer.sign(INBOUND_DOMAIN + canonical_bytes(dict(statement)))
    return _json({"alg": signer.alg, "key_id": signer.key_id, "signature": signature.hex()})


def _signature(attestation: str) -> tuple[str, str, bytes] | None:
    try:
        raw = json.loads(attestation)
        if set(raw) != {"alg", "key_id", "signature"}:
            return None
        return str(raw["alg"]), str(raw["key_id"]), bytes.fromhex(str(raw["signature"]))
    except (ValueError, TypeError):
        return None


def _verifies(
    keys: Keyring, attestation: str, statement: Callable[[str, str], dict[str, Any]]
) -> str | None:
    """Why ``attestation`` is not a registered inbox's signature of the
    statement it builds, or ``None``."""
    parsed = _signature(attestation)
    if parsed is None:
        return "its attestation is not a signature"
    alg, key_id, signature = parsed
    key = keys.verifier(key_id)
    if key is None:
        return f"it is attested by key {key_id}, no registered inbox's"
    message = INBOUND_DOMAIN + canonical_bytes(statement(alg, key_id))
    if alg != key.alg or not key.verify(message, signature):
        return f"it says what inbox {keys.name(key_id)} never attested"
    return None


def verify_event(event: InboundEvent, keys: Keyring) -> str | None:
    """Why an event's attestation does not hold under ``keys``, or ``None``."""
    return _verifies(
        keys,
        event.attestation,
        lambda alg, key_id: _event_statement(
            event.source,
            event.event_id,
            event.kind,
            event.vendor_at,
            event.received_at,
            event.body_hash,
            event.part,
            event.refs,
            event.fields,
            event.withheld,
            alg,
            key_id,
        ),
    )


def verify_fact(fact: InboundFact, keys: Keyring) -> str | None:
    """Why a fact does not hold under ``[inbox.keys]``, or ``None``: both the
    event's attestation, over what the agent sees of it, and the binding's."""
    found = _verifies(
        keys,
        fact.event_attestation,
        lambda alg, key_id: _event_statement(
            fact.source,
            fact.event_id,
            fact.kind,
            fact.vendor_at,
            fact.received_at,
            fact.body_hash,
            fact.part,
            fact.refs,
            fact.fields,
            fact.withheld,
            alg,
            key_id,
        ),
    )
    if found is not None:
        return f"its event: {found}"
    found = _verifies(
        keys, fact.attestation, lambda alg, key_id: _fact_statement(fact, alg, key_id)
    )
    return None if found is None else f"its binding: {found}"


# --------------------------------------------------------------------------
# the store an inbox records into
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DeliveredRef:
    """A delivered row whose call created what a reference names."""

    message_id: uuid.UUID
    seq: int
    event_hash: str
    scope_id: str
    plan_id: str
    tenant_id: str | None


class InboxStore(Protocol):
    """What the inbox process reads and writes (:mod:`interlock.inbox_store`)."""

    def record_event(
        self,
        *,
        source: str,
        event_id: str,
        kind: str,
        vendor_at: datetime | None,
        received_at: datetime,
        body: str,
        body_hash: str,
        signature: str,
        part: int,
        refs: Sequence[str],
        fields: Mapping[str, Any],
        withheld: Sequence[str],
        attestation: str,
    ) -> tuple[int, bool]:
        """Append an event to its source's log, once. ``(seq, fresh)``."""
        ...

    def event(self, source: str, seq: int) -> InboundEvent: ...

    def record_fact(self, fact: InboundFact) -> bool:
        """Record a binding, once per event. ``False`` when one was already."""
        ...

    def delivered_with(self, ref: str) -> list[DeliveredRef]: ...

    def snapshot(self, message_ids: Sequence[uuid.UUID] | None) -> tuple[list[Any], list[Any]]: ...

    def unmatched(self, since: datetime) -> list[InboundEvent]:
        """Events received since ``since`` that no fact binds."""
        ...


# --------------------------------------------------------------------------
# the receiver
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Response:
    """What the inbox answers a webhook: an HTTP status and a small JSON body.
    A vendor retries anything but a 2xx."""

    status: int
    body: Mapping[str, Any] = field(default_factory=dict)


def _no_checkpoint(point: str) -> None:
    return None


class Inbox:
    """Receives vendors' webhooks: verify, record, match, attest (module docstring).

    :param store: Where events and facts are recorded: an inbox role's
        connection (:class:`~interlock.inbox_store.PostgresInboxStore`), or a
        SQLite store opened with :data:`~interlock.sqlite_outbox.INBOX`.
    :param sources: The configured sources (``[[inbox.sources]]``).
    :param signer: The inbox's own Ed25519 key, which attests every event and
        fact (``interlock keygen --role inbox``).
    :param relays: Every relay's public key: an event is bound only to a
        delivery a registered relay attested.
    :param secrets: Each source's signing secret, by the environment variable
        its configuration names.
    :param match_window: How long an event that matched nothing is matched
        again: a webhook can arrive before its relay records the delivery.
    :param checkpoint: Called at ``verified``, ``recorded`` and ``matched``:
        the crash tests stop the process there.
    :raises ValueError: On a signer that is not Ed25519.
    """

    def __init__(
        self,
        store: InboxStore,
        sources: Iterable[InboundSource],
        *,
        signer: Signer,
        relays: Keyring,
        secrets: Callable[[str], str | None],
        max_body: int = MAX_BODY,
        match_window: timedelta = timedelta(hours=1),
        clock: Callable[[], datetime] | None = None,
        checkpoint: Callable[[str], None] | None = None,
    ) -> None:
        if signer.alg != "ed25519":
            raise ValueError(
                "an inbox attests with an Ed25519 key, which anyone can verify and only it can sign"
            )
        self._store = store
        self._sources = {source.name: source for source in sources}
        self._signer = signer
        self._relays = relays
        self._secrets = secrets
        self._max_body = max_body
        self._window = match_window
        self._clock = clock or (lambda: datetime.now(UTC))
        self._checkpoint = checkpoint or _no_checkpoint
        self._lock = threading.Lock()

    def receive(self, name: str, headers: Mapping[str, str], body: bytes) -> Response:
        """Take one webhook through verification, recording and matching."""
        source = self._sources.get(name)
        if source is None:
            return Response(404, {"error": "no such source"})
        if len(body) > self._max_body:
            return Response(413, {"error": "the body is too large"})
        content = (_header(headers, "Content-Type") or "").split(";")[0].strip().lower()
        if content != "application/json":
            return Response(415, {"error": "only application/json"})
        now = self._clock()
        try:
            header_id, vendor_at = self._verify(source, headers, body, now)
            self._checkpoint("verified")
            try:
                text = body.decode("utf-8")
                document = json.loads(text)
            except (UnicodeDecodeError, ValueError) as exc:
                raise Rejected(400, "the body is not JSON") from exc
            parsed = parse_events(source, document, header_id=header_id)
        except Rejected as rejected:
            logger.warning("inbox %s refused a webhook: %s", name, rejected.reason)
            return Response(rejected.status, {"error": rejected.reason})
        body_hash = hashlib.sha256(body).hexdigest()
        signature = self._signature_headers(source, headers)
        recorded = matched = 0
        try:
            with self._lock:
                for event in parsed:
                    attestation = _sign(
                        self._signer,
                        _event_statement(
                            source.name,
                            event.event_id,
                            event.kind,
                            vendor_at,
                            now,
                            body_hash,
                            event.part,
                            event.refs,
                            event.fields,
                            event.withheld,
                            self._signer.alg,
                            self._signer.key_id,
                        ),
                    )
                    seq, fresh = self._store.record_event(
                        source=source.name,
                        event_id=event.event_id,
                        kind=event.kind,
                        vendor_at=vendor_at,
                        received_at=now,
                        body=text,
                        body_hash=body_hash,
                        signature=signature,
                        part=event.part,
                        refs=event.refs,
                        fields=event.fields,
                        withheld=event.withheld,
                        attestation=attestation,
                    )
                    recorded += int(fresh)
                    self._checkpoint("recorded")
                    if self._match(self._store.event(source.name, seq)):
                        matched += 1
                    self._checkpoint("matched")
        except Exception:
            # The vendor retries what was not answered 2xx; nothing recorded
            # twice when it does.
            logger.exception("inbox %s could not record a verified webhook", name)
            return Response(503, {"error": "not recorded; send it again"})
        return Response(200, {"recorded": recorded, "matched": matched})

    def match_pending(self) -> int:
        """Bind the events that matched nothing yet, received within the match
        window, to deliveries recorded since. Returns how many it bound."""
        with self._lock:
            since = self._clock() - self._window
            return sum(1 for event in self._store.unmatched(since) if self._match(event))

    def _verify(
        self, source: InboundSource, headers: Mapping[str, str], body: bytes, now: datetime
    ) -> tuple[str | None, datetime]:
        if source.kind == "sendgrid":
            return None, verify_sendgrid(
                source.verification_key, headers, body, now, source.tolerance
            )
        secret = self._secrets(source.secret_env)
        if not secret:
            raise Rejected(503, "the source's secret is not in the inbox's environment")
        if source.kind == "stripe":
            return None, verify_stripe(secret, headers, body, now, source.tolerance)
        return verify_standard(secret, headers, body, now, source.tolerance)

    @staticmethod
    def _signature_headers(source: InboundSource, headers: Mapping[str, str]) -> str:
        """The vendor's signature as received, for whoever holds the secret to
        check it again."""
        names = {
            "stripe": ("Stripe-Signature",),
            "http": ("webhook-id", "webhook-timestamp", "webhook-signature"),
            "sendgrid": (
                "X-Twilio-Email-Event-Webhook-Signature",
                "X-Twilio-Email-Event-Webhook-Timestamp",
            ),
        }[source.kind]
        return _json({name: _header(headers, name) for name in names})

    def _match(self, event: InboundEvent) -> bool:
        """Bind ``event`` to the delivery it names, when exactly one message's
        relay-attested delivery created it. Returns whether a fact now binds it."""
        from interlock.attestations import attestation_of

        for ref in event.refs:
            delivered = self._store.delivered_with(ref)
            if not delivered:
                continue
            if len({d.message_id for d in delivered}) > 1:
                logger.warning(
                    "inbox %s: event %s names %s, which more than one message's delivery "
                    "created; bound to none",
                    event.source,
                    event.event_id,
                    ref,
                )
                return False
            message_id = delivered[0].message_id
            messages, rows = self._store.snapshot([message_id])
            (message,) = messages
            if message.idempotency_key != outbound_key(message.plan_id, message.effect_id):
                logger.warning("inbox: message %s's row names a plan its key does not", message_id)
                return False
            for row in sorted(
                (r for r in rows if r.event == "delivered" and r.remote_ref == ref),
                key=lambda r: r.seq,
            ):
                try:
                    statement = attestation_of(message, row)
                    assert statement.signature is not None
                    key = self._relays.verifier(statement.signature.key_id)
                    if key is None:
                        raise ValueError("no registered relay's key")
                    statement.verify(key)
                except Exception as exc:  # an attestation that does not hold binds nothing
                    logger.warning(
                        "inbox: message %s's delivery row %d is not a registered relay's (%s); "
                        "the event is not bound to it",
                        message_id,
                        row.seq,
                        exc,
                    )
                    continue
                target = next(d for d in delivered if d.seq == row.seq)
                fact = InboundFact(
                    fact_id=uuid.uuid4(),
                    source=event.source,
                    event_seq=event.seq,
                    event_hash=event.event_hash,
                    message_id=message_id,
                    delivery_seq=row.seq,
                    delivery_hash=row.event_hash,
                    remote_ref=ref,
                    scope_id=target.scope_id,
                    plan_id=target.plan_id,
                    tenant_id=target.tenant_id,
                    attestation="",
                    event_id=event.event_id,
                    kind=event.kind,
                    vendor_at=event.vendor_at,
                    received_at=event.received_at,
                    body_hash=event.body_hash,
                    part=event.part,
                    refs=event.refs,
                    fields=event.fields,
                    withheld=event.withheld,
                    event_attestation=event.attestation,
                )
                attested = _replace_attestation(
                    fact,
                    _sign(
                        self._signer, _fact_statement(fact, self._signer.alg, self._signer.key_id)
                    ),
                )
                self._store.record_fact(attested)
                return True
        return False


def _replace_attestation(fact: InboundFact, attestation: str) -> InboundFact:
    import dataclasses

    return dataclasses.replace(fact, attestation=attestation)


# --------------------------------------------------------------------------
# verification
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class InboxReport:
    """What :func:`verify_inbox` found."""

    problems: tuple[str, ...]
    events: int
    facts: int
    consumed: int


def verify_inbox(source: object, keys: Keyring, *, relays: Keyring | None = None) -> InboxReport:
    """Hold every inbound log to its chain and its attestations, and every fact
    to its event, its delivery and its attestation.

    Finds an event that does not link or hash to what it records, a log whose
    head is not its last event, an event or a fact the inbox never attested
    (forged, or copied from another), a fact naming an event or a delivery the
    database does not hold as named, and a delivery its relay never attested
    (with ``relays``). A pruned message's fact is held to its tombstone.
    """
    from interlock.attestations import attestation_of
    from interlock.inbox_store import inbox_reader

    reader = inbox_reader(source)
    problems: list[str] = []
    events = reader.inbound_events()
    by_source: dict[str, list[InboundEvent]] = {}
    for event in events:
        by_source.setdefault(event.source, []).append(event)
    heads = reader.inbound_heads()
    starts = reader.inbound_starts()
    for name, (log_seq, log_head) in sorted(heads.items()):
        start_seq, expected = starts.get(name, (0, inbox_genesis(name)))
        log = sorted(by_source.pop(name, []), key=lambda e: e.seq)
        for index, event in enumerate(log, start=start_seq + 1):
            where = f"inbound source {name}: event {event.seq}"
            if event.seq != index or event.prev_hash != expected:
                problems.append(f"{where} does not link to the event before it")
                break
            if event.recomputed() != event.event_hash:
                problems.append(f"{where} does not hash to what it records")
                break
            found = verify_event(event, keys)
            if found is not None:
                problems.append(f"{where}: {found}")
            expected = event.event_hash
        else:
            if (log_seq, log_head) != (start_seq + len(log), expected):
                problems.append(
                    f"inbound source {name}: its head is event {log_seq}, but its log ends at "
                    f"event {start_seq + len(log)}, or with another hash"
                )
    for name in by_source:
        problems.append(f"inbound source {name} is not installed, and holds events")
    recorded = {(e.source, e.seq): e for e in events}
    facts = reader.inbound_facts()
    messages, rows = reader.snapshot(None)
    by_id = {m.message_id: m for m in messages}
    by_row = {(r.message_id, r.seq): r for r in rows}
    pruned = reader.compacted()
    for fact in facts:
        where = f"fact {fact.fact_id}"
        found = verify_fact(fact, keys)
        if found is not None:
            problems.append(f"{where}: {found}")
        event = recorded.get((fact.source, fact.event_seq))
        if event is None and fact.event_seq <= starts.get(fact.source, (0, ""))[0]:
            # A checkpoint pruned the event with its facts: this one stayed.
            problems.append(f"{where} names an event a checkpoint pruned, and outlived it")
        elif event is None or event.event_hash != fact.event_hash:
            problems.append(f"{where} names an event its source's log does not hold as named")
        row = by_row.get((fact.message_id, fact.delivery_seq))
        if row is None:
            tombstone = pruned.get(fact.message_id)
            if tombstone is None or tombstone.log_seq < fact.delivery_seq:
                problems.append(f"{where} names a delivery the outbox does not hold")
            continue
        if (
            row.event != "delivered"
            or row.event_hash != fact.delivery_hash
            or row.remote_ref != fact.remote_ref
        ):
            problems.append(f"{where} names a delivery the outbox holds otherwise")
            continue
        message = by_id[fact.message_id]
        if (message.scope_id, message.plan_id) != (fact.scope_id, fact.plan_id):
            problems.append(f"{where}'s scope or plan is not its message's")
        if relays is not None:
            try:
                statement = attestation_of(message, row)
                assert statement.signature is not None
                key = relays.verifier(statement.signature.key_id)
                if key is None:
                    raise ValueError("no registered relay's key")
                statement.verify(key)
            except Exception as exc:
                problems.append(f"{where} names a delivery no registered relay attested ({exc})")
    consumed = reader.inbound_consumed()
    known = {f.fact_id for f in facts}
    for fact_id in consumed:
        if fact_id not in known:
            problems.append(f"fact {fact_id} was consumed, and the inbox holds no such fact")
    return InboxReport(tuple(problems), len(events), len(facts), len(consumed))


# --------------------------------------------------------------------------
# the server
# --------------------------------------------------------------------------


class InboxServer:
    """The inbox's HTTP endpoint: ``POST /inbox/<source>`` for vendors, and
    ``GET /healthz`` when given a ``health`` to report. Plain HTTP: put TLS in
    front of it.

    A request is answered on a thread of its own. :meth:`stop` stops
    accepting and waits for the requests in flight to be answered: each read
    is bounded by ``timeout`` seconds, so a slow client cannot hold a stop.

    :param health: Called for ``GET /healthz``; answers with the status and
        a JSON body. Without it the route does not exist.
    """

    def __init__(
        self,
        inbox: Inbox,
        host: str,
        port: int,
        *,
        health: Callable[[], tuple[int, Mapping[str, Any]]] | None = None,
        timeout: float = 10.0,
    ) -> None:
        receiver = inbox
        bound = timeout

        class Handler(BaseHTTPRequestHandler):
            server_version = "interlock-inbox"
            timeout = bound

            def do_POST(self) -> None:
                parts = self.path.split("?", 1)[0].strip("/").split("/")
                if len(parts) != 2 or parts[0] != "inbox":
                    self._answer(Response(404, {"error": "no such route"}))
                    return
                try:
                    length = int(self.headers.get("Content-Length", ""))
                except ValueError:
                    self._answer(Response(411, {"error": "a Content-Length is needed"}))
                    return
                if length < 0 or length > receiver._max_body:
                    self._answer(Response(413, {"error": "the body is too large"}))
                    return
                body = self.rfile.read(length)
                self._answer(receiver.receive(parts[1], dict(self.headers.items()), body))

            def do_GET(self) -> None:
                if health is None or self.path.split("?", 1)[0].rstrip("/") != "/healthz":
                    self._answer(Response(404, {"error": "no such route"}))
                    return
                status, report = health()
                self._answer(Response(status, report))

            def _answer(self, response: Response) -> None:
                payload = json.dumps(dict(response.body), default=str).encode("utf-8")
                self.send_response(response.status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, format: str, *args: Any) -> None:
                logger.info("%s %s", self.address_string(), format % args)

        self._server = ThreadingHTTPServer((host, port), Handler)
        # Answered before a stop returns: threads joined on close, each
        # bounded by the handler's timeout.
        self._server.daemon_threads = False
        self._server.block_on_close = True
        self._thread: threading.Thread | None = None

    @property
    def port(self) -> int:
        """The port bound: the one asked for, or the one chosen for port 0."""
        return int(self._server.server_address[1])

    def start(self) -> int:
        """Accept requests on a thread of its own. Returns :attr:`port`."""
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            kwargs={"poll_interval": 0.1},
            name=f"interlock-inbox-{self.port}",
            daemon=True,
        )
        self._thread.start()
        return self.port

    def stop(self) -> None:
        """Stop accepting, and answer what is in flight. Idempotent."""
        if self._thread is not None:
            self._server.shutdown()
            self._thread.join()
            self._thread = None
        self._server.server_close()


def serve(
    inbox: Inbox,
    host: str,
    port: int,
    *,
    stop: threading.Event,
    ready: Callable[[int], None] | None = None,
    match_every: timedelta = timedelta(seconds=5),
) -> None:
    """Serve ``POST /inbox/<source>`` until ``stop`` is set, matching what is
    pending every ``match_every``. Plain HTTP: put TLS in front of it.

    :param ready: Called with the port bound (useful with port 0).
    """
    server = InboxServer(inbox, host, port)
    bound = server.start()
    if ready is not None:
        ready(bound)
    try:
        while not stop.wait(match_every.total_seconds()):
            try:
                inbox.match_pending()
            except Exception:  # pragma: no cover - logged, retried next round
                logger.exception("inbox: matching what is pending failed")
    finally:
        server.stop()


def frozen_fields(raw: str) -> Mapping[str, Any]:
    """A projection as stored (canonical JSON), read back read-only."""
    value = json.loads(raw)
    return _frozen(value if isinstance(value, dict) else {})  # type: ignore[no-any-return]
