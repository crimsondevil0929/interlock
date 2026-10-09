"""Keys: which a part may sign with, and which were revoked (``docs/EPIC8_DESIGN.md`` §2).

A key's role is ``relay``, ``inbox`` or ``operator``. The configuration's
keyrings are the roots of each role (``[relays.keys]``, ``[inbox.keys]``,
``[operators.keys]``). The operator log extends them: a ``key.registered``
record, signed by an operator trusted at its position, adds a key to a role;
an ``operator.intent`` whose action is ``revoke-key`` revokes one.

A relay's or an inbox's key is revoked in the database too, in the
transaction of the intent's action: the database records the revocation and
*seals* the key's rows, the reference and hash of every row it had attested
that the database still holds, and from then on refuses every new row the key
attests. The seal's count and digest are signed into the operator log's
``operator.applied`` record, and anchored. An attestation by a revoked key
holds exactly when its row is in the seal, at the same hash.

An operator's key is revoked in the log alone, which orders itself: a record
the key signs after the intent that revoked it does not hold.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Final

from agentgov.exceptions import MalformedReceiptError
from agentgov.receipts.signing import Verifier, parse_key

from interlock.deliveries import frame
from interlock.exceptions import RecordIntegrityError
from interlock.records import GENESIS, Keyring, RecordKind, SignedRecord

__all__ = [
    "KINDS",
    "REVOKE",
    "ROLES",
    "SEALED_ROLES",
    "KeyRegistry",
    "KeyReport",
    "Revocation",
    "attestation_key",
    "event_ref",
    "fact_ref",
    "fact_row_hash",
    "outcome_ref",
    "revocations_of",
    "seal_digest",
    "verify_keys",
]

ROLES: Final = ("relay", "inbox", "operator")
SEALED_ROLES: Final = ("relay", "inbox")
"""The roles whose rows the database holds, and a revocation seals."""
KINDS: Final = ("outcome", "event", "fact")
"""What a seal holds: a relay's outcome rows; an inbox's events and facts."""
REVOKE: Final = "revoke-key"
"""The operator action that revokes a key."""


def outcome_ref(message_id: object, seq: int) -> str:
    """How a seal names a delivery-log row."""
    return f"{message_id}:{seq}"


def event_ref(source: str, seq: int) -> str:
    """How a seal names an inbound event."""
    return f"{source}:{seq}"


def fact_ref(source: str, event_seq: int) -> str:
    """How a seal names a fact: by its event, which has one fact at most, so
    a fact pruned with its event is known as pruned."""
    return f"{source}:{event_seq}"


def fact_row_hash(attestation: str) -> str:
    """What a seal holds of a fact: the hash of its attestation, which signs
    everything the fact says."""
    return hashlib.sha256(attestation.encode("utf-8")).hexdigest()


def seal_digest(members: Iterable[tuple[str, str, str]]) -> str:
    """The digest of a seal: SHA-256 over the length-prefixed framing
    (:func:`interlock.deliveries.frame`) of each member's kind, reference and
    row hash, the members in byte order. ``interlock.key_revoke`` computes the
    same in the database."""
    fields = [value for member in sorted(members) for value in member]
    return hashlib.sha256(frame(*fields).encode("utf-8")).hexdigest()


def revocations_of(source: object) -> dict[str, Revocation]:
    """The revocations a store, a reader or a PostgreSQL connection holds;
    none before version 7, or for a reader that keeps none."""
    read = getattr(source, "revocations", None)
    if read is None and hasattr(source, "execute") and not hasattr(source, "snapshot"):
        from interlock.deliveries import PostgresReader

        read = PostgresReader(source).revocations  # type: ignore[arg-type]
    return dict(read()) if read is not None else {}


def attestation_key(attestation: str | None) -> str | None:
    """The key id an attestation names, if it names one."""
    if not attestation:
        return None
    try:
        value = json.loads(attestation)
    except ValueError:
        return None
    key_id = value.get("key_id") if isinstance(value, dict) else None
    return key_id if isinstance(key_id, str) else None


@dataclass(frozen=True, slots=True)
class Revocation:
    """A revoked relay or inbox key, as the database recorded it.

    :ivar authority: The hash of the operator's signed ``revoke-key`` intent.
    :ivar count: How many rows the seal holds, as recorded.
    :ivar digest: The seal's digest, as recorded.
    :ivar members: The seal: ``(kind, reference, row hash)`` of every row the
        key had attested when it was revoked.
    """

    key_id: str
    role: str
    revoked_at: datetime
    authority: str
    count: int
    digest: str
    members: frozenset[tuple[str, str, str]] = field(default_factory=frozenset)

    def holds(self, kind: str, ref: str, row_hash: str) -> bool:
        """Whether the seal holds this row, at this hash."""
        return (kind, ref, row_hash) in self.members

    def recomputed(self) -> str:
        """The digest of the members as they are now."""
        return seal_digest(self.members)


@dataclass(frozen=True, slots=True)
class Registration:
    """A key the operator log added to a role."""

    role: str
    name: str
    key: Verifier
    record: SignedRecord


@dataclass(frozen=True, slots=True)
class LoggedRevocation:
    """A ``revoke-key`` intent in the operator log, and its outcome.

    :ivar applied: The ``operator.applied`` record, when the action applied:
        for a relay's or an inbox's key it carries the seal's count and digest.
    """

    role: str
    key_id: str
    reason: str | None
    intent: SignedRecord
    applied: SignedRecord | None

    @property
    def seal(self) -> tuple[int, str] | None:
        """The seal's count and digest, as the applied record signs them."""
        if self.applied is None:
            return None
        sealed = self.applied.body.get("seal")
        if not isinstance(sealed, dict):
            return None
        count, digest = sealed.get("count"), sealed.get("digest")
        if not isinstance(count, int) or not isinstance(digest, str):
            return None
        return count, digest


@dataclass(frozen=True, slots=True)
class KeyRegistry:
    """What the configuration's roots and the operator log say about keys.

    Built by walking the log in order, as :func:`interlock.records.verify_records`
    holds it, up to its first record that does not hold: a ``key.registered``
    record or a ``revoke-key`` intent counts only when an operator trusted at
    its position signed it.
    """

    roots: Mapping[str, Mapping[str, str]]
    registrations: tuple[Registration, ...] = ()
    revocations: tuple[LoggedRevocation, ...] = ()
    ignored: tuple[str, ...] = ()
    """Key records signed by no operator trusted where they stand."""

    @classmethod
    def build(
        cls, roots: Mapping[str, Mapping[str, str]], records: Sequence[SignedRecord]
    ) -> KeyRegistry:
        """The registry ``records`` (the operator log, in order) makes of
        ``roots`` (each role's configured keys, by name)."""
        operators = Keyring(roots.get("operator", {}))
        registrations: list[Registration] = []
        intents: dict[str, SignedRecord] = {}
        accepted: list[SignedRecord] = []
        ignored: list[str] = []
        previous = GENESIS
        for index, record in enumerate(records, start=1):
            # Only what holds is evidence: the log up to its first record that
            # does not link, or that no operator trusted where it stands signed.
            key = operators.verifier(record.key_id)
            holds = (
                record.seq == index
                and record.prev == previous
                and key is not None
                and operators.trusts(record.key_id)
            )
            if holds:
                assert key is not None
                try:
                    record.verify(key)
                except RecordIntegrityError:
                    holds = False
            if not holds:
                ignored.append(f"operator record {index} and every one after it")
                break
            accepted.append(record)
            previous = record.record_hash
            if record.kind == RecordKind.KEY_REGISTERED.value:
                registration = _registration(record)
                if registration is None:
                    ignored.append(f"operator record {record.seq} ({record.kind})")
                else:
                    registrations.append(registration)
            elif _revokes(record):
                intents.setdefault(str(record.body.get("key_id")), record)
            operators = operators.after(record)
        outcomes = {
            str(r.body.get("intent", {}).get("hash", "")): r
            for r in accepted
            if r.kind == RecordKind.OPERATOR_APPLIED.value
        }
        revocations = {
            key_id: LoggedRevocation(
                role=str(intent.body.get("role")),
                key_id=key_id,
                reason=intent.body.get("reason"),
                intent=intent,
                applied=outcomes.get(intent.record_hash),
            )
            for key_id, intent in intents.items()
        }
        return cls(roots, tuple(registrations), tuple(revocations.values()), tuple(ignored))

    def keys(self, role: str) -> dict[str, str]:
        """Every key the role ever trusted, by name: the roots and the
        registered, the revoked included, whose history still verifies."""
        keys = dict(self.roots.get(role, {}))
        held = {parse_key(spec).key_id for spec in keys.values()}
        for registration in self.registrations:
            if registration.role != role or registration.key.key_id in held:
                continue
            name = registration.name
            if name in keys:  # refused at registration; tolerated, never merged
                name = f"{name}#{registration.record.seq}"
            keys[name] = _spec(registration.key)
            held.add(registration.key.key_id)
        return keys

    def keyring(self, role: str) -> Keyring:
        return Keyring(self.keys(role))

    def revocation(self, key_id: str) -> LoggedRevocation | None:
        return next((r for r in self.revocations if r.key_id == key_id), None)

    def role_of(self, key_id: str) -> str | None:
        """The role a key is trusted for, or ``None``."""
        for role in ROLES:
            if key_id in self.keyring(role):
                return role
        return None


def _registration(record: SignedRecord) -> Registration | None:
    body = record.body
    role, name, spec = body.get("role"), body.get("name"), body.get("key")
    if role not in ROLES or not isinstance(name, str) or not isinstance(spec, str):
        return None
    try:
        key = parse_key(spec)
    except MalformedReceiptError:
        return None
    if key.alg != "ed25519" or body.get("key_id") != key.key_id:
        return None
    return Registration(str(role), name, key, record)


def _revokes(record: SignedRecord) -> bool:
    return (
        record.kind == RecordKind.OPERATOR_INTENT.value
        and record.body.get("action") == REVOKE
        and record.body.get("role") in ROLES
        and isinstance(record.body.get("key_id"), str)
    )


def _spec(key: Verifier) -> str:
    spec = getattr(key, "spec", None)
    if spec is None:  # pragma: no cover - every registered key is Ed25519
        raise ValueError(f"key {key.key_id} has no spec")
    return str(spec())


def registered_body(role: str, name: str, key: Verifier) -> dict[str, Any]:
    """The body of a ``key.registered`` record."""
    return {"role": role, "name": name, "key": _spec(key), "key_id": key.key_id}


@dataclass(frozen=True, slots=True)
class KeyReport:
    """What :func:`verify_keys` found."""

    problems: tuple[str, ...]
    revoked: int
    """Revocations the database holds, each held to the seal its operator signed."""
    registered: int
    """Keys the operator log registered."""


def verify_keys(
    source: object, records: Sequence[SignedRecord], roots: Mapping[str, Mapping[str, str]]
) -> KeyReport:
    """Hold the database's revocations and seals to the operator log
    (``docs/EPIC8_DESIGN.md`` §2.8).

    Finds a key record signed by no operator trusted where it stands; a
    revocation no signed ``revoke-key`` intent authorized, or recorded with a
    seal other than the one the operator signed; a seal that no longer hashes
    to its digest; a sealed row the database holds at another hash, or no
    longer holds although no checkpoint pruned it; and an applied revocation
    the database does not hold. A row a revoked key attested outside its seal
    is :func:`~interlock.attestations.verify_attestations`' and
    :func:`~interlock.inbox.verify_inbox`'s to name.

    :param source: The outbox: a PostgreSQL connection or a store.
    :param records: The operator log's records, as read from its file.
    :param roots: Each role's configured keys
        (:meth:`interlock.config.InterlockConfig.key_roots`).
    """
    from interlock.deliveries import consistent, reader
    from interlock.inbox_store import inbox_reader

    outbox = reader(source)
    with consistent(outbox):
        revoked = revocations_of(outbox)
        _, events = outbox.snapshot(None)
        tombstones = outbox.compacted()
        inbox = inbox_reader(outbox)
        inbound = inbox.inbound_events()
        facts = inbox.inbound_facts()
        starts = inbox.inbound_starts()
    present: dict[tuple[str, str], str] = {}
    for event in events:
        present[("outcome", outcome_ref(event.message_id, event.seq))] = event.event_hash
    for inbound_event in inbound:
        ref = event_ref(inbound_event.source, inbound_event.seq)
        present[("event", ref)] = inbound_event.event_hash
    for fact in facts:
        present[("fact", fact_ref(fact.source, fact.event_seq))] = fact_row_hash(fact.attestation)

    def pruned(kind: str, ref: str) -> bool:
        head, _, tail = ref.rpartition(":")
        if not tail.isdigit():
            return False
        if kind == "outcome":
            tombstone = tombstones.get(_uuid(head))
            return tombstone is not None and tombstone.log_seq >= int(tail)
        return int(tail) <= int(starts.get(head, (0, ""))[0])

    registry = KeyRegistry.build(roots, records)
    problems = [
        f"operator log: {what} is signed by no operator trusted where it stands"
        for what in registry.ignored
    ]
    logged = {r.key_id: r for r in registry.revocations}
    for key_id, revocation in sorted(revoked.items()):
        where = f"key {key_id} ({revocation.role})"
        entry = logged.get(key_id)
        if entry is None or entry.intent.record_hash != revocation.authority:
            problems.append(
                f"{where} is revoked in the database under an authority no signed revoke-key "
                f"intent holds: revoked around Interlock"
            )
        elif entry.role != revocation.role:
            problems.append(f"{where}: the operator revoked it as a {entry.role} key")
        elif entry.seal is None:
            problems.append(
                f"{where}: the operator log records no seal for its revocation (operator "
                f"record {entry.intent.seq}'s outcome)"
            )
        elif entry.seal != (revocation.count, revocation.digest):
            count, digest = entry.seal
            problems.append(
                f"{where}: the database records a seal of {revocation.count} rows "
                f"({revocation.digest[:16]}), the operator signed {count} ({digest[:16]}): it "
                f"was edited"
            )
        if len(revocation.members) != revocation.count or (
            revocation.recomputed() != revocation.digest
        ):
            problems.append(f"{where}: its seal no longer hashes to its digest: it was edited")
        for kind, ref, row_hash in sorted(revocation.members):
            found = present.get((kind, ref))
            if found is None:
                if not pruned(kind, ref):
                    problems.append(
                        f"{where}: its seal holds {kind} {ref}, which the database no longer "
                        f"holds and no checkpoint pruned"
                    )
            elif found != row_hash:
                problems.append(
                    f"{where}: its seal holds {kind} {ref} at another hash: rewritten since"
                )
    for entry in registry.revocations:
        if entry.role in SEALED_ROLES and entry.seal is not None and entry.key_id not in revoked:
            assert entry.applied is not None
            problems.append(
                f"operator record {entry.applied.seq} applied the revocation of key "
                f"{entry.key_id}, and the database holds none: deleted around Interlock"
            )
    return KeyReport(tuple(problems), len(revoked), len(registry.registrations))


def _uuid(text: str) -> Any:
    import uuid

    try:
        return uuid.UUID(text)
    except ValueError:
        return text
