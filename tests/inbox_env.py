"""What the inbox's tests share: the outbox with the inbox installed on either
store, three sources (Stripe, Standard Webhooks, SendGrid), the inbox's own
key, signed webhooks as each vendor sends them, and deliveries whose relay
recorded the reference a webhook names.

- ``stripe`` signs with an endpoint secret (``Stripe-Signature``);
- ``hooks`` signs as Standard Webhooks do (``webhook-id``,
  ``webhook-timestamp``, ``webhook-signature``), and projects ``status``
  and ``amount``;
- ``sendgrid`` signs with an ECDSA P-256 key whose public half is the
  source's verification key.

The secrets are :data:`SECRETS`, as the inbox's environment holds them.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import uuid
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import psycopg
from agentgov.exceptions import DuplicateScopeError
from agentgov.receipts.signing import Ed25519Signer
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from psycopg.conninfo import make_conninfo

from interlock.inbox import FieldSpec, InboundSource, Inbox, Response
from interlock.inbox_store import PostgresInboxStore
from interlock.postgres import install
from interlock.records import Keyring
from interlock.relay import DELIVERED, Delivery, DeliveryResult, Relay
from interlock.sqlite_outbox import INBOX, SqliteOutboxStore, install_sqlite_outbox
from interlock.types import OutboundRequest
from tests.conftest import OBSERVED, PASSWORD, create_role, drop_role
from tests.outbox_env import (
    RELAY_SINKS,
    RELAYS,
    Outbox,
    PostgresOutbox,
    SqliteOutbox,
    relay_signer,
)
from tests.schemas import specs

STRIPE_SECRET = "whsec_" + "5" * 32
HOOKS_KEY = bytes(range(32))
HOOKS_SECRET = "whsec_" + base64.b64encode(HOOKS_KEY).decode("ascii")
SENDGRID_KEY = ec.derive_private_key(0x5E5D_6121D, ec.SECP256R1())
"""The tests' SendGrid account's signing key: SendGrid holds the private half."""
OTHER_SENDGRID_KEY = ec.derive_private_key(0xBAD5EED, ec.SECP256R1())
"""Another SendGrid account's key: what a forger signs with."""
SENDGRID_PUBLIC = base64.b64encode(
    SENDGRID_KEY.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
).decode("ascii")

SECRETS: Mapping[str, str] = {
    "STRIPE_WEBHOOK_SECRET": STRIPE_SECRET,
    "HOOKS_SECRET": HOOKS_SECRET,
}
"""The inbox's environment: each source's signing secret, by name."""

SOURCES: tuple[InboundSource, ...] = (
    InboundSource("stripe", "stripe", secret_env="STRIPE_WEBHOOK_SECRET"),
    InboundSource(
        "hooks",
        "http",
        secret_env="HOOKS_SECRET",
        references=("data.id", "data.parent"),
        fields=(
            FieldSpec("status", "data.status", "code"),
            FieldSpec("amount", "data.amount", "decimal"),
            FieldSpec("note", "data.note", "code"),
        ),
    ),
    InboundSource("sendgrid", "sendgrid", verification_key=SENDGRID_PUBLIC),
)

INBOX_SEED = bytes.fromhex("1b" * 32)


def inbox_signer() -> Ed25519Signer:
    """The tests' inbox's key."""
    return Ed25519Signer(INBOX_SEED)


INBOX_KEYS = Keyring({"inbox": inbox_signer().public_key()})
"""``[inbox.keys]``, as the tests register their inbox."""


def unix(at: datetime | None = None) -> str:
    return str(int((at or datetime.now(UTC)).timestamp()))


def stripe_webhook(
    event: Mapping[str, Any],
    *,
    secret: str = STRIPE_SECRET,
    at: datetime | None = None,
    body: bytes | None = None,
) -> tuple[dict[str, str], bytes]:
    """A Stripe webhook: the body, and ``Stripe-Signature`` over it at ``at``."""
    raw = body if body is not None else json.dumps(event).encode()
    stamp = unix(at)
    signature = hmac.new(secret.encode(), f"{stamp}.".encode() + raw, "sha256").hexdigest()
    return {
        "Content-Type": "application/json; charset=utf-8",
        "Stripe-Signature": f"t={stamp},v1={signature}",
    }, raw


def standard_webhook(
    event: Mapping[str, Any],
    *,
    webhook_id: str = "msg_1",
    key: bytes = HOOKS_KEY,
    at: datetime | None = None,
    body: bytes | None = None,
) -> tuple[dict[str, str], bytes]:
    """A Standard Webhooks request: the body, and its three headers."""
    raw = body if body is not None else json.dumps(event).encode()
    stamp = unix(at)
    signature = base64.b64encode(
        hmac.new(key, f"{webhook_id}.{stamp}.".encode() + raw, "sha256").digest()
    ).decode()
    return {
        "Content-Type": "application/json",
        "webhook-id": webhook_id,
        "webhook-timestamp": stamp,
        "webhook-signature": f"v1,{signature}",
    }, raw


def sendgrid_webhook(
    events: Sequence[Mapping[str, Any]],
    *,
    key: ec.EllipticCurvePrivateKey = SENDGRID_KEY,
    at: datetime | None = None,
    body: bytes | None = None,
) -> tuple[dict[str, str], bytes]:
    """A SendGrid Signed Event Webhook batch: the body and its signature."""
    raw = body if body is not None else json.dumps(list(events)).encode()
    stamp = unix(at)
    signature = key.sign(stamp.encode() + raw, ec.ECDSA(hashes.SHA256()))
    return {
        "Content-Type": "application/json",
        "X-Twilio-Email-Event-Webhook-Signature": base64.b64encode(signature).decode(),
        "X-Twilio-Email-Event-Webhook-Timestamp": stamp,
    }, raw


def refund_event(
    ref: str,
    *,
    event_id: str = "evt_1",
    kind: str = "charge.refund.updated",
    status: str = "succeeded",
    amount: int = 2500,
    **extra: Any,
) -> dict[str, Any]:
    """A Stripe event about the refund ``ref``: what a relay's call created."""
    return {
        "id": event_id,
        "object": "event",
        "type": kind,
        "livemode": False,
        "data": {
            "object": {
                "id": ref,
                "object": "refund",
                "status": status,
                "amount": amount,
                "currency": "usd",
                "charge": "ch_1",
                "payment_intent": "pi_1",
                **extra,
            }
        },
    }


class Referencing:
    """A sink adapter that delivers, recording the reference the payload
    names (``ref``), as a vendor's response names what the call created."""

    def send(self, delivery: Delivery) -> DeliveryResult:
        payload = json.loads(delivery.payload)
        return DeliveryResult(DELIVERED, status_code=200, remote_ref=str(payload["ref"]))


def refund(ref: str, amount: str = "25.00") -> OutboundRequest:
    """A refund request whose delivery creates ``ref``."""
    return OutboundRequest("payments", "refund", {"ref": ref, "amount": amount})


@dataclass
class InboxSite:
    """The inbox installed beside an outbox: its stores, and its deliveries."""

    outbox: Outbox
    target: dict[str, str]
    """Where an inbox in another process records: the store's kind, and the
    inbox role's connection string or the file."""
    opener: Callable[[], tuple[Any, Callable[[], None]]]
    clock: Callable[[], datetime] = field(default=lambda: datetime.now(UTC))
    closers: list[Callable[[], None]] = field(default_factory=list)

    def store(self) -> Any:
        """An inbox's store, as its own role."""
        opened, close = self.opener()
        self.closers.append(close)
        return opened

    def inbox(self, **kwargs: Any) -> Inbox:
        kwargs.setdefault("signer", inbox_signer())
        kwargs.setdefault("relays", RELAYS)
        kwargs.setdefault("secrets", SECRETS.get)
        kwargs.setdefault("clock", lambda: self.clock())
        return Inbox(kwargs.pop("store", None) or self.store(), SOURCES, **kwargs)

    def deliver(
        self, *refs: str, scope: str = "agent", traceparent: str | None = None
    ) -> list[uuid.UUID]:
        """Commit and deliver one refund per reference, each recorded by a
        registered relay with the reference its call created, in
        ``traceparent``'s trace when given. Their messages."""
        try:
            self.outbox.governor.open_root(scope, "100")
        except DuplicateScopeError:
            pass
        _, messages = self.outbox.commit(
            *(refund(ref) for ref in refs), scope=scope, traceparent=traceparent
        )
        relay = Relay(
            self.outbox.store(),
            adapters={"payments": Referencing()},
            breaker=self.outbox.breaker(),
            signer=relay_signer(),
            lease=timedelta(seconds=10),
            timeout=timedelta(seconds=2),
        )
        try:
            self.outbox.drain(relay)
        finally:
            relay.close()
        assert [self.outbox.state(m) for m in messages] == ["delivered"] * len(messages)
        return messages

    def receive(self, inbox: Inbox, source: str, webhook: tuple[dict[str, str], bytes]) -> Response:
        headers, body = webhook
        return inbox.receive(source, headers, body)

    def events(self) -> int:
        table = (
            "interlock.inbox_events"
            if self.outbox.backend == "postgres"
            else ("_interlock_inbox_events")
        )
        return int(self.outbox.fetch(f"SELECT count(*) FROM {table}")[0][0])

    def facts(self) -> int:
        table = (
            "interlock.inbox_facts"
            if self.outbox.backend == "postgres"
            else ("_interlock_inbox_facts")
        )
        return int(self.outbox.fetch(f"SELECT count(*) FROM {table}")[0][0])

    def settle(self, role: str | None = None) -> None:
        """Wait until whatever a killed process had open is gone: on
        PostgreSQL, every session of ``role`` (the inbox's by default)."""
        if not isinstance(self.outbox, PostgresOutbox):
            self.outbox.settle()
            return
        import time

        name = role or self.target["role"]
        deadline = time.monotonic() + 30
        while self.outbox.fetch(
            "SELECT count(*) FROM pg_stat_activity WHERE usename = %s", name
        ) != [(0,)]:
            if time.monotonic() > deadline:
                raise AssertionError(f"the sessions of {name} did not end")
            time.sleep(0.02)

    def reader(self) -> Any:
        """The inbox as an auditor reads it."""
        if isinstance(self.outbox, PostgresOutbox):
            return PostgresInboxStore(self.outbox.operator())
        return self.outbox.operator()

    def close(self) -> None:
        for close in self.closers:
            close()
        self.closers.clear()


@contextmanager
def inbox_site(outbox: Outbox) -> Iterator[InboxSite]:
    """The inbox installed beside ``outbox``: its sources mirrored, and on
    PostgreSQL an inbox role granted what an inbox needs."""
    if isinstance(outbox, PostgresOutbox):
        role = f"il_inbox_{uuid.uuid4().hex[:8]}"
        create_role(outbox.pg.cluster, role)
        try:
            install(
                outbox.operator(),
                specs(*OBSERVED),
                stage_roles=[outbox.pg.role],
                sinks=RELAY_SINKS,
                relay_roles=[outbox.relay_role],
                settler_roles=[outbox.settler_role] if outbox.settler_role else [],
                sources=SOURCES,
                inbox_roles=[role],
            )
            dsn = make_conninfo(outbox.pg.admin, user=role, password=PASSWORD)

            def postgres() -> tuple[Any, Callable[[], None]]:
                conn = psycopg.connect(dsn, autocommit=True)
                return PostgresInboxStore(conn), conn.close

            site = InboxSite(outbox, {"store": "postgres", "dsn": dsn, "role": role}, postgres)
            try:
                yield site
            finally:
                site.close()
        finally:
            drop_role(outbox.pg.cluster, outbox.pg.admin, role)
        return
    assert isinstance(outbox, SqliteOutbox)
    install_sqlite_outbox(outbox.path, RELAY_SINKS, SOURCES)
    path = outbox.path

    def sqlite() -> tuple[Any, Callable[[], None]]:
        store = SqliteOutboxStore(path, writes=INBOX)
        return store, store.close

    site = InboxSite(outbox, {"store": "sqlite", "dsn": path}, sqlite)
    try:
        yield site
    finally:
        site.close()


def digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


# -- the database's owner, around Interlock -----------------------------------


def _owner_sqlite(site: InboxSite) -> Any:
    assert isinstance(site.outbox, SqliteOutbox)
    return site.outbox.raw()


def rewrite_event(site: InboxSite, source: str, seq: int, **columns: object) -> None:
    """Rewrite a recorded event's columns in place, as the database's owner
    could: the append-only guard lifted, the hash left as it was."""
    if isinstance(site.outbox, PostgresOutbox):
        conn = site.outbox.operator()
        conn.execute("ALTER TABLE interlock.inbox_events DISABLE TRIGGER inbox_events_append_only")
        conn.execute(
            f"UPDATE interlock.inbox_events SET "
            f"{', '.join(f'{name} = %({name})s' for name in columns)} "
            f"WHERE source = %(source)s AND seq = %(seq)s",
            {**columns, "source": source, "seq": seq},
        )
        conn.execute(
            "ALTER TABLE interlock.inbox_events ENABLE ALWAYS TRIGGER inbox_events_append_only"
        )
        return
    conn = _owner_sqlite(site)
    try:
        conn.execute("DROP TRIGGER IF EXISTS _interlock_inbox_events_no_update")
        conn.execute(
            f"UPDATE _interlock_inbox_events SET "
            f"{', '.join(f'{name} = :{name}' for name in columns)} "
            f"WHERE source = :source AND seq = :seq",
            {**columns, "source": source, "seq": seq},
        )
    finally:
        conn.close()


def delete_event(site: InboxSite, source: str, seq: int) -> None:
    """Delete a recorded event, as the database's owner could."""
    if isinstance(site.outbox, PostgresOutbox):
        conn = site.outbox.operator()
        conn.execute("ALTER TABLE interlock.inbox_events DISABLE TRIGGER inbox_events_append_only")
        # Its foreign keys too: a fact still names the event.
        conn.execute("SET session_replication_role = replica")
        conn.execute(
            "DELETE FROM interlock.inbox_events WHERE source = %s AND seq = %s", (source, seq)
        )
        conn.execute("SET session_replication_role = DEFAULT")
        conn.execute(
            "ALTER TABLE interlock.inbox_events ENABLE ALWAYS TRIGGER inbox_events_append_only"
        )
        return
    conn = _owner_sqlite(site)
    try:
        conn.execute("DROP TRIGGER IF EXISTS _interlock_inbox_events_no_delete")
        conn.execute(
            "DELETE FROM _interlock_inbox_events WHERE source = ? AND seq = ?", (source, seq)
        )
    finally:
        conn.close()


def append_event(
    site: InboxSite,
    source: str,
    *,
    signer: Any,
    event_id: str,
    kind: str = "charge.refunded",
    refs: Sequence[str] = (),
    fields: Mapping[str, Any] | None = None,
) -> int:
    """Append an event around Interlock, linked and hashed exactly as the
    trigger would, the head advanced, attested by ``signer``: a ghost row the
    chain alone cannot tell from a real one. Its seq."""
    from interlock.inbox import _event_statement, _sign, event_hash

    heads = site.reader().inbound_heads()
    seq, prev = int(heads[source][0]) + 1, str(heads[source][1])
    now = datetime.now(UTC).replace(microsecond=0)
    body = json.dumps({"ghost": event_id})
    body_hash = digest(body.encode())
    projected = dict(fields or {})
    attestation = _sign(
        signer,
        _event_statement(
            source,
            event_id,
            kind,
            None,
            now,
            body_hash,
            0,
            refs,
            projected,
            (),
            signer.alg,
            signer.key_id,
        ),
    )
    hashed = event_hash(
        prev, source, seq, event_id, kind, None, now, body_hash, 0, refs, projected, (), attestation
    )
    row = {
        "source": source,
        "seq": seq,
        "event_id": event_id,
        "event_type": kind,
        "received_at": now,
        "body": body,
        "body_hash": body_hash,
        "signature": "{}",
        "part": 0,
        "refs": json.dumps(list(refs), separators=(",", ":")),
        "fields": json.dumps(projected, separators=(",", ":"), sort_keys=True),
        "withheld": "[]",
        "attestation": attestation,
        "prev_hash": prev,
        "event_hash": hashed,
    }
    if isinstance(site.outbox, PostgresOutbox):
        conn = site.outbox.operator()
        conn.execute("ALTER TABLE interlock.inbox_events DISABLE TRIGGER inbox_log_link")
        conn.execute(
            f"INSERT INTO interlock.inbox_events ({', '.join(row)}) "
            f"VALUES ({', '.join(f'%({name})s' for name in row)})",
            row,
        )
        conn.execute(
            "UPDATE interlock.inbox_sources SET log_seq = %s, log_head = %s WHERE name = %s",
            (seq, hashed, source),
        )
        conn.execute("ALTER TABLE interlock.inbox_events ENABLE ALWAYS TRIGGER inbox_log_link")
        return seq
    from interlock.compaction import instant_text

    row["received_at"] = instant_text(now)
    conn = _owner_sqlite(site)
    try:
        conn.execute("DROP TRIGGER IF EXISTS _interlock_inbox_link")
        conn.execute("DROP TRIGGER IF EXISTS _interlock_inbox_head")
        conn.execute(
            f"INSERT INTO _interlock_inbox_events ({', '.join(row)}) "
            f"VALUES ({', '.join(f':{name}' for name in row)})",
            row,
        )
        conn.execute(
            "UPDATE _interlock_inbox_sources SET log_seq = ?, log_head = ? WHERE name = ?",
            (seq, hashed, source),
        )
    finally:
        conn.close()
    return seq


def insert_fact(site: InboxSite, fact: Any) -> None:
    """Write a fact around the inbox, as the database's owner could."""
    values = (
        str(fact.fact_id),
        fact.source,
        fact.event_seq,
        fact.event_hash,
        str(fact.message_id),
        fact.delivery_seq,
        fact.delivery_hash,
        fact.remote_ref,
        fact.scope_id,
        fact.plan_id,
        fact.tenant_id,
        fact.attestation,
    )
    if isinstance(site.outbox, PostgresOutbox):
        site.outbox.operator().execute(
            "INSERT INTO interlock.inbox_facts (fact_id, source, event_seq, event_hash, "
            "message_id, delivery_seq, delivery_hash, remote_ref, scope_id, plan_id, tenant_id, "
            "attestation) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            values,
        )
        return
    conn = _owner_sqlite(site)
    try:
        conn.execute(
            "INSERT INTO _interlock_inbox_facts (fact_id, source, event_seq, event_hash, "
            "message_id, delivery_seq, delivery_hash, remote_ref, scope_id, plan_id, tenant_id, "
            "attestation, recorded_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)",
            values,
        )
    finally:
        conn.close()
