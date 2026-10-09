"""Operators, and the signed log of everything they do (``docs/EPIC3_DESIGN.md`` §6).

An operator's action on the outbox (releasing a held request, cancelling one,
requeueing a dead one, enqueueing a compensation) is a person's decision about
money and messages that leave the system. Each is made in two phases, as a
commit is:

1. An ``operator.intent`` record is signed with the operator's own Ed25519 key
   and written to the operator log, an ILOK1 log of its own, before the
   database is touched: the action, its targets, and each target's
   delivery-log head as the operator saw it.
2. The database action runs under the intent's hash, its *authority*. Every
   delivery-log row it writes carries the authority, and it runs only while
   each target's log is still at the head the operator signed for: an
   authorization is never replayed on a later state. The database refuses an
   operator's row without an authority.
3. An ``operator.applied`` record names the rows the action wrote, or an
   ``operator.refused`` one says why there were none.

A process killed between the phases leaves an intent with no outcome. The next
operator to act resolves it from the database (:meth:`Operator.resolve`):
``applied`` when rows carry its authority, ``operator.abandoned`` when none
does. Nothing is ever applied without an intent signed first.

Records are anchored into an AgentGov ledger when one is given, as every ILOK1
record is: a log truncated or rewritten later disagrees with the ledger.

:func:`verify_operators` holds the delivery logs to the operator log, from
public keys alone, and names every edit made around it: the "ghost edits" of
an owner with direct access to the database.
"""

from __future__ import annotations

import logging
import os
import secrets
import uuid
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from agentgov.core import EntryType, LedgerEntry
from agentgov.exceptions import MalformedReceiptError
from agentgov.receipts.signing import Ed25519Signer, Signer, Verifier, parse_key

from interlock.deliveries import (
    ACTION_EVENTS,
    OPERATOR_EVENTS,
    AuthorizedRow,
    Compensable,
    LegacySet,
    LegacyVouch,
    OutboxOperations,
    consistent,
    reader,
    registry_digest,
)
from interlock.exceptions import InterlockError, OutboundRequestError, RecordIntegrityError
from interlock.keys import REVOKE, ROLES, SEALED_ROLES, KeyRegistry, registered_body
from interlock.outbound import SinkRegistry, bind, placeholders
from interlock.records import (
    GENESIS,
    Keyring,
    RecordKind,
    RecordLog,
    SignedRecord,
    UntrustedSignerError,
    anchor_memo,
    check_anchors,
)
from interlock.types import EffectId, OutboundRequest, outbound_key

if TYPE_CHECKING:
    from agentgov import BudgetManager

__all__ = [
    "OPERATOR_LOG",
    "Operator",
    "OperatorLog",
    "OperatorRefusedError",
    "OperatorReport",
    "Outcome",
    "generate_key",
    "legacy_vouch",
    "load_key",
    "verify_operators",
]

logger = logging.getLogger("interlock.operators")

OPERATOR_LOG: Final = "interlock-operators"
"""The operator log's id, in its records and its ledger anchors."""

INTENT, APPLIED, REFUSED, ABANDONED, INSTALLED, KEY_REGISTERED = (
    RecordKind.OPERATOR_INTENT,
    RecordKind.OPERATOR_APPLIED,
    RecordKind.OPERATOR_REFUSED,
    RecordKind.OPERATOR_ABANDONED,
    RecordKind.OPERATOR_INSTALLED,
    RecordKind.KEY_REGISTERED,
)
_OUTCOMES: Final = frozenset({APPLIED.value, REFUSED.value, ABANDONED.value})


class OperatorRefusedError(InterlockError):
    """An operator action refused before anything was signed: it does not
    apply to what the outbox holds."""


# --------------------------------------------------------------------------
# keys
# --------------------------------------------------------------------------


def generate_key(path: str | Path) -> Ed25519Signer:
    """A fresh Ed25519 key, its seed written to ``path`` (as hex, readable
    by its owner only). Register its public half, ``signer.public_key().spec()``,
    under the operator's name in ``[operators.keys]``.

    :raises FileExistsError: If ``path`` exists: a key is never overwritten.
    """
    seed = secrets.token_bytes(32)
    signer = Ed25519Signer(seed)
    descriptor = os.open(Path(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="ascii") as handle:
        handle.write(seed.hex() + "\n")
    return signer


def load_key(path: str | Path) -> Ed25519Signer:
    """An operator's private key from the file :func:`generate_key` wrote.

    :raises ValueError: If the file does not hold a 32-byte seed in hex.
    """
    text = Path(path).read_text(encoding="ascii").strip()
    try:
        seed = bytes.fromhex(text)
    except ValueError as exc:
        raise ValueError(f"{path} does not hold an Ed25519 seed in hex") from exc
    return Ed25519Signer(seed)


# --------------------------------------------------------------------------
# the log
# --------------------------------------------------------------------------


def _ref(record: SignedRecord) -> dict[str, Any]:
    return {"seq": record.seq, "hash": record.record_hash}


def _row(row: AuthorizedRow) -> dict[str, Any]:
    return {
        "message": str(row.message_id),
        "seq": row.seq,
        "event": row.event,
        "hash": row.event_hash,
    }


class OperatorLog:
    """The operator log: one ILOK1 log that every operator signs into with
    their own key, verified under all of theirs.

    :param path: The log's file. One process writes it at a time.
    :param signer: This operator's private key.
    :param keyring: Every operator's public key, by name, as configured.
        ``signer`` must be one of them, or registered by a record of the log
        since, and not revoked: its name is who this operator is.
    :param ledger: An AgentGov ledger to anchor every record into, or none.
        When the ledger cannot be written (another process holds it), the
        record stands and is anchored the next time the log is opened.
    :param scope: The ledger scope the anchors are written to.
    :raises ValueError: If ``signer`` is not a registered key, or was revoked.
    :raises RecordIntegrityError: If the file does not verify.
    """

    __slots__ = ("_ledger", "_log", "_scope", "operator")

    def __init__(
        self,
        path: str | Path,
        signer: Signer,
        keyring: Keyring,
        *,
        ledger: BudgetManager | None = None,
        scope: str = "interlock-operators",
        log_id: str = OPERATOR_LOG,
    ) -> None:
        try:
            self._log = RecordLog(signer, log_id=log_id, path=path, keyring=keyring)
        except UntrustedSignerError as exc:
            if exc.revoked_by is not None:
                raise
            raise UntrustedSignerError(
                f"key {signer.key_id} is no registered operator's: add its public half to "
                f"[operators.keys], or have an operator register it"
            ) from exc
        trusted = self._log.trusted
        assert trusted is not None
        self.operator = trusted.name(signer.key_id) or signer.key_id
        self._ledger = ledger
        self._scope = scope
        self.anchor_pending()

    def records(self) -> tuple[SignedRecord, ...]:
        return self._log.records()

    @property
    def signer(self) -> Signer:
        return self._log.signer

    @property
    def trusted(self) -> Keyring | None:
        """The operators' keyring as the log stands: the configured keys,
        with every key its records registered or revoked."""
        return self._log.trusted

    def append(self, kind: RecordKind, body: Mapping[str, Any]) -> SignedRecord:
        """Sign and write a record, as this operator, and anchor it."""
        record = self._log.append(kind, scope=self._scope, body={**body, "operator": self.operator})
        self._anchor(record)
        return record

    def _anchor(self, record: SignedRecord) -> bool:
        if self._ledger is None:
            return False
        try:
            self._ledger.anchor(self._scope, anchor_memo(record))
        except Exception as exc:  # the record stands; anchored on the next open
            logger.warning(
                "operator record %d could not be anchored (%s: %s); it will be on the next open",
                record.seq,
                type(exc).__name__,
                exc,
            )
            return False
        return True

    def anchor_pending(self) -> int:
        """Anchor every record the ledger does not hold yet. Returns how many."""
        if self._ledger is None:
            return 0
        # As of now: a view of a shared ledger lacks what other governors
        # anchored since its last read, and would anchor those records again.
        try:
            self._ledger.refresh()
        except Exception as exc:  # anchored the next time the ledger can be read
            logger.warning(
                "the ledger could not be read (%s: %s); records wait to be anchored",
                type(exc).__name__,
                exc,
            )
            return 0
        anchored = {
            entry.memo
            for entry in self._ledger.audit_trail()
            if entry.entry_type is EntryType.ANCHOR
        }
        return sum(
            1
            for record in self._log.records()
            if anchor_memo(record) not in anchored and self._anchor(record)
        )

    def unresolved(self) -> list[SignedRecord]:
        """Intents no outcome record answers, oldest first."""
        answered = {
            record.body["intent"]["hash"]
            for record in self._log.records()
            if record.kind in _OUTCOMES
        }
        return [
            record
            for record in self._log.records()
            if record.kind == INTENT.value and record.record_hash not in answered
        ]

    def close(self) -> None:
        self._log.close()

    def __enter__(self) -> OperatorLog:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


# --------------------------------------------------------------------------
# acting
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Outcome:
    """What one operator action did."""

    intent: SignedRecord
    record: SignedRecord
    """The ``operator.applied`` or ``operator.refused`` record."""
    rows: tuple[AuthorizedRow, ...]
    """The delivery-log rows the action wrote, every one under its authority."""
    skipped: tuple[tuple[uuid.UUID, str], ...]
    """The targets the database would not act on, and why."""

    @property
    def applied(self) -> bool:
        return bool(self.rows)

    def count(self, event: str) -> int:
        return sum(1 for row in self.rows if row.event == event)


@dataclass(frozen=True, slots=True)
class _Compensation:
    original: Compensable
    message_id: uuid.UUID
    request: OutboundRequest
    idempotency_key: str


class Operator:
    """An operator acting on an outbox, every action signed (module docstring).

    :param log: The operator log, opened with this operator's key.
    :param outbox: The outbox: a PostgreSQL connection as the installer
        wrapped by :func:`interlock.deliveries.operations`, or a SQLite store
        opened with ``writes=OPERATOR``.
    :param checkpoint: Called at ``intent``, ``acted`` and ``recorded``: the
        crash tests stop the process there. Does nothing in production.
    """

    __slots__ = ("_checkpoint", "_log", "_outbox")

    def __init__(
        self,
        log: OperatorLog,
        outbox: OutboxOperations,
        *,
        checkpoint: Callable[[str], None] | None = None,
    ) -> None:
        self._log = log
        self._outbox = outbox
        self._checkpoint = checkpoint or (lambda point: None)

    @property
    def name(self) -> str:
        return self._log.operator

    @property
    def actor(self) -> str:
        """How the delivery log names this operator."""
        return f"operator:{self.name}"

    def resolve(self) -> list[SignedRecord]:
        """Resolve every intent that a process killed between the phases left
        without an outcome, from what the database holds."""
        resolved = []
        for intent in self._log.unresolved():
            if intent.body.get("action") == "compact":
                resolved.append(self._resolve_compaction(intent))
                continue
            if intent.body.get("action") == REVOKE:
                resolved.append(self._resolve_revocation(intent))
                continue
            rows = self._outbox.authorized(intent.record_hash)
            if rows:
                record = self._log.append(
                    APPLIED,
                    {
                        "intent": _ref(intent),
                        "rows": [_row(r) for r in rows],
                        "skipped": [],
                        "resolved": "the process that signed it stopped before recording this",
                    },
                )
            else:
                record = self._log.append(
                    ABANDONED,
                    {
                        "intent": _ref(intent),
                        "why": "no delivery-log row carries its authority: the process that "
                        "signed it stopped before acting",
                    },
                )
            resolved.append(record)
        return resolved

    def _resolve_revocation(self, intent: SignedRecord) -> SignedRecord:
        """A revocation killed between its phases: applied when the database
        holds a revocation under its authority, with that seal; abandoned
        when not, and the key is not revoked. An operator key's revocation
        took effect at its intent: it touches no database."""
        if intent.body.get("role") not in SEALED_ROLES:
            return self._log.append(
                APPLIED,
                {
                    "intent": _ref(intent),
                    "rows": [],
                    "skipped": [],
                    "resolved": "an operator key is revoked in the log, by its intent",
                },
            )
        found = next(
            (r for r in self._outbox.revocations().values() if r.authority == intent.record_hash),
            None,
        )
        if found is not None:
            return self._log.append(
                APPLIED,
                {
                    "intent": _ref(intent),
                    "rows": [],
                    "skipped": [],
                    "seal": {"count": found.count, "digest": found.digest},
                    "resolved": "the process that signed it stopped before recording this",
                },
            )
        return self._log.append(
            ABANDONED,
            {
                "intent": _ref(intent),
                "why": "the database holds no revocation under its authority: the process that "
                "signed it stopped before its transaction committed, and the key is not revoked",
            },
        )

    # -- keys (docs/EPIC8_DESIGN.md §2) ------------------------------------------

    def register_key(
        self,
        role: str,
        name: str,
        key: Verifier | str,
        *,
        roots: Mapping[str, Mapping[str, str]],
    ) -> SignedRecord:
        """Register ``key`` for ``role`` under ``name``: trusted from the next
        record of the log on, beside the configuration's keys.

        :param roots: Each role's configured keys, by name: the configuration's
            keyrings (:meth:`interlock.config.InterlockConfig.key_roots`).
        :raises OperatorRefusedError: On a role that is none, a key that is
            not an Ed25519 public key, one any role trusts already, or a name
            the role uses. Nothing is signed.
        """
        if role not in ROLES:
            raise OperatorRefusedError(f"a key's role is one of {', '.join(ROLES)}, not {role!r}")
        try:
            verifier = parse_key(key) if isinstance(key, str) else key
        except MalformedReceiptError as exc:
            raise OperatorRefusedError(f"the key does not parse: {exc}; nothing signed") from exc
        if verifier.alg != "ed25519":
            raise OperatorRefusedError("a registered key is an Ed25519 public key; nothing signed")
        registry = KeyRegistry.build(roots, self._log.records())
        trusted_as = registry.role_of(verifier.key_id)
        if trusted_as is not None:
            raise OperatorRefusedError(
                f"key {verifier.key_id} is a {trusted_as} key already; nothing signed"
            )
        if name in registry.keys(role):
            raise OperatorRefusedError(f"a {role} key is named {name!r} already; nothing signed")
        self.resolve()
        return self._log.append(KEY_REGISTERED, registered_body(role, name, verifier))

    def revoke_key(
        self,
        role: str,
        key_id: str,
        *,
        reason: str | None = None,
        roots: Mapping[str, Mapping[str, str]],
    ) -> Outcome:
        """Revoke a key (``docs/EPIC8_DESIGN.md`` §2.2): it attests nothing new.
        A relay's or an inbox's key is revoked in the database too, which
        seals every row it attested, under the signed intent; the applied
        record signs the seal's count and digest. An operator key is revoked
        by its intent, and only by another operator.

        :raises OperatorRefusedError: If the key is no trusted key of the role,
            is revoked already, is this operator's own, or is the last operator
            key. Nothing is signed.
        """
        if role not in ROLES:
            raise OperatorRefusedError(f"a key's role is one of {', '.join(ROLES)}, not {role!r}")
        self.resolve()
        registry = KeyRegistry.build(roots, self._log.records())
        if key_id not in registry.keyring(role):
            raise OperatorRefusedError(f"key {key_id} is no {role} key; nothing signed")
        logged = registry.revocation(key_id)
        if logged is not None and logged.applied is not None:
            raise OperatorRefusedError(f"key {key_id} is revoked already; nothing signed")
        if role in SEALED_ROLES and key_id in self._outbox.revocations():
            raise OperatorRefusedError(f"key {key_id} is revoked already; nothing signed")
        if role == "operator":
            trusted = self._log.trusted
            assert trusted is not None
            if key_id == self._log.signer.key_id:
                raise OperatorRefusedError(
                    "an operator does not revoke their own key: another operator does, so the "
                    "revocation is recorded by a key that still signs; nothing signed"
                )
            others = [k for k in registry.keyring("operator").ids() if k != key_id]
            if not any(trusted.trusts(k) for k in others):
                raise OperatorRefusedError(
                    "that is the last operator key: no one could sign again; nothing signed"
                )
        intent = self._log.append(
            INTENT,
            {"action": REVOKE, "role": role, "key_id": key_id, "reason": reason, "targets": []},
        )
        self._checkpoint("intent")
        body: dict[str, Any] = {"intent": _ref(intent), "rows": [], "skipped": []}
        if role in SEALED_ROLES:
            count, digest = self._outbox.revoke_key(role, key_id, authority=intent.record_hash)
            body["seal"] = {"count": count, "digest": digest}
        self._checkpoint("acted")
        record = self._log.append(APPLIED, body)
        self._checkpoint("recorded")
        return Outcome(intent, record, (), ())

    def _resolve_compaction(self, intent: SignedRecord) -> SignedRecord:
        """A vacuum killed between its phases: its checkpoint is in the
        database when its transaction committed, and nowhere when not."""
        found = [c for c in self._outbox.checkpoints() if c.authority == intent.record_hash]
        if found:
            return self._log.append(
                APPLIED,
                {
                    "intent": _ref(intent),
                    "rows": [],
                    "skipped": [],
                    "checkpoint": {"seq": found[0].seq, "digest": found[0].digest},
                    "resolved": "the process that signed it stopped before recording this",
                },
            )
        return self._log.append(
            ABANDONED,
            {
                "intent": _ref(intent),
                "why": "no checkpoint carries its authority: the process that signed it "
                "stopped before its transaction committed, and nothing was pruned",
            },
        )

    def installed(self, legacy: LegacySet | None = None) -> SignedRecord:
        """Vouch for the sink registry as the database mirrors it now, and for
        the legacy set version 4 recorded: signed after ``interlock install``.

        A registry that differs from the last one vouched for was changed
        around Interlock (:func:`verify_operators`). The legacy set is vouched
        for once and for good: the first record that carries it pins it, and
        a later install signs it again only unchanged.

        :param legacy: The legacy set as the install's own transaction read
            it. The set the database holds now must be the same: one edited in
            between is not signed for.
        :raises OperatorRefusedError: If the outbox records no legacy set
            (older than version 4), or one other than ``legacy``, or than the
            one this log already vouched for. Nothing is signed.
        """
        rows = self._outbox.registry()
        recorded = self._outbox.legacy()
        if recorded is None:
            raise OperatorRefusedError(
                "the outbox is older than version 4 and records no legacy set: run "
                "`interlock install` to upgrade it first; nothing signed"
            )
        if legacy is not None and legacy.digest != recorded.digest:
            raise OperatorRefusedError(
                "the legacy set changed between the install that recorded it and this "
                "signature: it was edited around Interlock; nothing signed"
            )
        pinned = _pinned(self._log.records())
        if pinned is not None and pinned.problem(recorded) is not None:
            raise OperatorRefusedError(f"{pinned.problem(recorded)}; nothing signed")
        return self._log.append(
            INSTALLED,
            {
                "registry": registry_digest(rows),
                "sinks": {str(row["name"]): registry_digest([row]) for row in rows},
                "legacy": {"rows": len(recorded), "digest": recorded.digest},
            },
        )

    def release(self, message_ids: Sequence[uuid.UUID], *, reason: str | None = None) -> Outcome:
        """Release held messages for delivery."""
        return self._act(
            "release",
            message_ids,
            reason,
            lambda target, authority: self._outbox.release(
                target.message_id,
                actor=self.actor,
                authority=authority,
                expected_head=target.head,
            ),
        )

    def release_scope(self, scope_id: str, *, reason: str | None = None) -> Outcome:
        """Release every message of a scope that is held now, under one intent."""
        held = self._outbox.held(scope_id)
        if not held:
            raise OperatorRefusedError(f"no message of scope {scope_id!r} is held")
        return self.release(held, reason=reason or f"scope {scope_id}")

    def cancel(self, message_id: uuid.UUID, *, reason: str) -> Outcome:
        """Cancel a pending, held or dead message; what waits for it dies too."""
        return self._act(
            "cancel",
            [message_id],
            reason,
            lambda target, authority: self._outbox.cancel(
                target.message_id,
                actor=self.actor,
                reason=reason or "cancelled by an operator",
                authority=authority,
                expected_head=target.head,
            ),
        )

    def requeue(self, message_id: uuid.UUID, *, reason: str | None = None) -> Outcome:
        """Send a dead message back with a fresh budget of attempts, and what
        died waiting for it."""
        return self._act(
            "requeue",
            [message_id],
            reason,
            lambda target, authority: (
                self._outbox.requeue(
                    target.message_id,
                    actor=self.actor,
                    authority=authority,
                    expected_head=target.head,
                )
                > 0
            ),
        )

    def compensate(
        self,
        message_ids: Sequence[uuid.UUID] = (),
        *,
        plan_id: str | None = None,
        late: bool = False,
        reason: str | None = None,
        registry: SinkRegistry | None = None,
        now: datetime | None = None,
    ) -> Outcome:
        """Enqueue the compensations delivered requests carried (E4-3): each
        a new message, its placeholder bound to what its original's delivery
        created, after the compensations of everything that waited for its
        original (E4-4). Every delivered request of a plan that carries one,
        with ``plan_id``.

        :param late: Compensate past an original's deadline: a stale undo is a
            decision, not a default (E4-5).
        :param registry: Check each compensation against the sinks as the
            engine admits requests (the database checks it again).
        :raises OperatorRefusedError: If a target cannot be compensated, before
            anything is signed.
        :raises OutboundRequestError: If a compensation is not admissible.
        """
        plan = self._compensation_plan(message_ids, plan_id, late, now or datetime.now(UTC))
        if registry is not None:
            for item in plan:
                registry.check(item.request)
        details = {
            item.original.message_id: {
                "compensation": {
                    "message": str(item.message_id),
                    "sink": item.request.sink,
                    "operation": item.request.operation,
                    "payload_hash": item.request.payload_hash,
                    "idempotency_key": item.idempotency_key,
                }
            }
            for item in plan
        }
        by_original = {item.original.message_id: item for item in plan}

        def run(target: _Target, authority: str) -> bool:
            item = by_original[target.message_id]
            return self._outbox.compensate(
                target.message_id,
                actor=self.actor,
                authority=authority,
                expected_head=target.head,
                message_id=item.message_id,
                payload=item.request.canonical_payload,
                idempotency_key=item.idempotency_key,
            )

        return self._act(
            "compensate",
            [item.original.message_id for item in plan],
            reason,
            run,
            details=details,
        )

    # -- the two phases ------------------------------------------------------

    def _act(
        self,
        action: str,
        message_ids: Sequence[uuid.UUID],
        reason: str | None,
        run: Callable[[_Target, str], bool],
        *,
        details: Mapping[uuid.UUID, Mapping[str, Any]] | None = None,
    ) -> Outcome:
        if not message_ids:
            raise OperatorRefusedError(f"nothing to {action}")
        self.resolve()
        heads = self._outbox.heads(message_ids)
        missing = [str(m) for m in message_ids if m not in heads]
        if missing:
            raise OperatorRefusedError(f"the outbox holds no message {', '.join(missing)}")
        targets = [_Target(m, heads[m]) for m in message_ids]
        extra = details or {}
        intent = self._log.append(
            INTENT,
            {
                "action": action,
                "targets": [
                    {"message": str(t.message_id), "head": t.head, **extra.get(t.message_id, {})}
                    for t in targets
                ],
                "reason": reason,
            },
        )
        self._checkpoint("intent")
        skipped: list[tuple[uuid.UUID, str]] = []
        for target in targets:
            try:
                done = run(target, intent.record_hash)
            except OutboundRequestError as exc:
                skipped.append((target.message_id, str(exc)))
                continue
            if not done:
                skipped.append((target.message_id, self._why_not(action, target)))
        self._checkpoint("acted")
        rows = tuple(self._outbox.authorized(intent.record_hash))
        body = {
            "intent": _ref(intent),
            "rows": [_row(r) for r in rows],
            "skipped": [{"message": str(m), "why": why} for m, why in skipped],
        }
        record = self._log.append(APPLIED if rows else REFUSED, body)
        self._checkpoint("recorded")
        return Outcome(intent, record, rows, tuple(skipped))

    def _why_not(self, action: str, target: _Target) -> str:
        (message,), _ = self._outbox.snapshot([target.message_id])
        if message.log_head != target.head:
            return "its delivery log moved after the operator read it"
        return f"it is {message.state}: {action} does not apply"

    # -- compensation ----------------------------------------------------------

    def _compensation_plan(
        self, message_ids: Sequence[uuid.UUID], plan_id: str | None, late: bool, now: datetime
    ) -> list[_Compensation]:
        if plan_id is None:
            plans = {self._outbox.plan_of(m) for m in message_ids}
            if None in plans:
                raise OperatorRefusedError("the outbox holds no such message")
            if len(plans) != 1:
                raise OperatorRefusedError("compensate one plan at a time")
            (plan_id,) = plans
        assert plan_id is not None
        messages = self._outbox.compensables(plan_id)
        if not messages:
            raise OperatorRefusedError(f"the outbox holds no request of plan {plan_id}")
        by_id = {m.message_id: m for m in messages}
        if message_ids:
            chosen = [by_id[m] for m in message_ids]
        else:
            chosen = [
                m
                for m in messages
                if m.compensation is not None
                and m.compensates is None
                and m.compensated_by is None
                and m.state == "delivered"
            ]
            if not chosen:
                raise OperatorRefusedError(
                    f"plan {plan_id} has no delivered request left to compensate"
                )
        ids = {m.message_id for m in chosen}
        for original in chosen:
            problem = _uncompensable(original, messages, ids, late, now)
            if problem is not None:
                raise OperatorRefusedError(f"message {original.message_id}: {problem}")
        plan = []
        for original in _reverse_order(chosen):
            document = original.compensation
            assert document is not None
            not_after = document.get("not_after_seconds")
            request = OutboundRequest(
                str(document["sink"]),
                str(document["operation"]),
                bind(document["payload"], original.remote_ref or ""),
                not_after=None if not_after is None else timedelta(seconds=int(not_after)),
            )
            plan.append(
                _Compensation(
                    original=original,
                    message_id=uuid.uuid4(),
                    request=request,
                    idempotency_key=outbound_key(
                        original.plan_id, EffectId(f"compensate:{original.effect_id}")
                    ),
                )
            )
        return plan


@dataclass(frozen=True, slots=True)
class _Target:
    message_id: uuid.UUID
    head: str


def _uncompensable(
    original: Compensable,
    messages: Sequence[Compensable],
    chosen: set[uuid.UUID],
    late: bool,
    now: datetime,
) -> str | None:
    """Why ``original`` cannot be compensated now, or ``None``."""
    if original.compensates is not None:
        return "it is itself a compensation"
    if original.compensation is None:
        return "it carries no compensation: its operation cannot be undone"
    if original.compensated_by is not None:
        return f"it was compensated already, by {original.compensated_by}"
    if original.state != "delivered":
        return f"only a delivered request is compensated, and it is {original.state}"
    if placeholders(original.compensation.get("payload")) and original.remote_ref is None:
        return "its delivery recorded no reference for the placeholder to bind to"
    if original.not_after < now and not late:
        return (
            f"its deadline passed at {original.not_after.isoformat()}: a late undo is a "
            f"decision (--late), not a default"
        )
    for later in messages:
        if original.effect_id not in later.depends_on or later.compensates is not None:
            continue
        if later.state in ("pending", "leased", "held"):
            return f"message {later.message_id} waits for it and may still be sent: cancel it first"
        if (
            later.state == "delivered"
            and later.compensation is not None
            and later.compensated_by is None
            and later.message_id not in chosen
        ):
            return (
                f"message {later.message_id} waited for it and is delivered, uncompensated: "
                f"compensate it first, or the whole plan"
            )
    return None


def _reverse_order(chosen: Sequence[Compensable]) -> list[Compensable]:
    """Every request after each request that waited for it: compensations are
    enqueued, and run, in reverse topological order of the originals (E4-4)."""
    by_effect = {m.effect_id: m for m in chosen}
    waiting = {
        m.effect_id: {d.effect_id for d in chosen if m.effect_id in d.depends_on} for m in chosen
    }
    ordered: list[Compensable] = []
    done: set[str] = set()
    while len(ordered) < len(chosen):
        ready = sorted(e for e, later in waiting.items() if e not in done and later <= done)
        if not ready:  # pragma: no cover - a plan's dependencies are acyclic
            raise OperatorRefusedError("the plan's requests wait for each other in a cycle")
        for effect in ready:
            ordered.append(by_effect[effect])
            done.add(effect)
    return ordered


# --------------------------------------------------------------------------
# verification
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class OperatorReport:
    """What :func:`verify_operators` found."""

    problems: tuple[str, ...]
    records: int
    """Operator records that verified."""
    actions: int
    """Delivery-log rows written under an operator's authority."""
    legacy: int
    """Operator rows from before schema version 3, which carry no authority:
    rows of the legacy set a signed install vouched for."""


def verify_operators(
    source: object,
    records: Sequence[SignedRecord],
    keyring: Keyring,
    *,
    ledger: Iterable[LedgerEntry] | None = None,
) -> OperatorReport:
    """Hold the delivery logs to the operator log, and the operator log to
    its keys and its ledger anchors.

    Finds:

    - a sink registry other than the one the last signed install vouched for;
    - a record whose signature does not verify under a registered key, or
      that breaks the log's sequence or links: the log was edited;
    - a record the ledger anchored differently, or that it anchored and the
      log no longer holds: the log was rewritten or truncated;
    - an intent with no outcome, or an outcome naming no intent;
    - an operator's row in a delivery log with no authority (written after
      version 3), or an authority no signed intent holds, or one whose
      intent is another action, does not name the message, or named another
      head, or was recorded refused or abandoned;
    - an applied record naming a row the delivery log does not hold, unless a
      checkpoint pruned it (its message's tombstone reaches that row);
    - a checkpoint no signed ``compact`` intent carries, or not the one it
      carries, or recorded otherwise than applied; an applied ``compact``
      intent whose checkpoint the database no longer holds; a chain of
      checkpoints with a gap or a fork; one left open; tombstones that no
      longer fold to their checkpoint's root; a pruned message live again
      (``docs/EPIC5_DESIGN.md`` §1.6).

    :param source: The outbox: a PostgreSQL connection or a store.
    :param records: The operator log's records, as read from its file.
    :param ledger: The ledger's entries, when the log is anchored into one.
    """
    with consistent(source):
        return _verify_operators(source, records, keyring, ledger)


def _verify_operators(
    source: object,
    records: Sequence[SignedRecord],
    keyring: Keyring,
    ledger: Iterable[LedgerEntry] | None,
) -> OperatorReport:
    problems: list[str] = []
    trusted = _verified_prefix(records, keyring, problems)
    if ledger is not None and trusted:
        try:
            check_anchors(trusted, ledger)
        except RecordIntegrityError as exc:
            problems.append(f"operator log: {exc}")

    intents = {r.record_hash: r for r in trusted if r.kind == INTENT.value}
    outcomes: dict[str, SignedRecord] = {}
    for record in trusted:
        if record.kind not in _OUTCOMES:
            continue
        named = str(record.body.get("intent", {}).get("hash", ""))
        if named not in intents:
            problems.append(
                f"operator record {record.seq} ({record.kind}) answers an intent the log does "
                f"not hold"
            )
        elif named in outcomes:
            problems.append(
                f"operator record {record.seq}: intent {intents[named].seq} was answered twice"
            )
        else:
            outcomes[named] = record
    for digest, intent in intents.items():
        if digest not in outcomes:
            body = intent.body
            problems.append(
                f"operator record {intent.seq}: {body.get('operator')}'s {body.get('action')} "
                f"intent has no outcome (any operator action resolves it)"
            )

    source_reader = reader(source)
    installs = [r for r in trusted if r.kind == INSTALLED.value]
    pinned = _pinned(installs)
    for record in installs:
        legacy_body = record.body.get("legacy")
        if (
            pinned is not None
            and isinstance(legacy_body, Mapping)
            and str(legacy_body.get("digest")) != pinned.digest
        ):
            problems.append(
                f"operator record {record.seq} vouches for another legacy set than record "
                f"{pinned.record} did: the set changed after it was first vouched for"
            )
    if installs:
        vouched = installs[-1].body
        rows = source_reader.registry()
        if registry_digest(rows) != vouched.get("registry"):
            now = {str(row["name"]): registry_digest([row]) for row in rows}
            then = dict(vouched.get("sinks", {}))
            changed = sorted(n for n in set(now) | set(then) if now.get(n) != then.get(n))
            problems.append(
                f"the sink registry is not the one operator record {installs[-1].seq} vouched "
                f"for: sink {', '.join(changed)} changed around Interlock"
            )
    messages, events = source_reader.snapshot(None)
    recorded = source_reader.legacy()
    epoch = source_reader.epoch() if recorded is None else None
    mismatch = pinned.problem(recorded) if pinned is not None and recorded is not None else None
    if mismatch is not None:
        problems.append(mismatch)
    pinned_holds = pinned is not None and mismatch is None
    stage_of = {m.message_id: m.stage_id for m in messages}
    by_row = {(e.message_id, e.seq): e for e in events}
    actions = legacy = unvouched = 0
    for event in events:
        where = f"message {event.message_id}: row {event.seq} ({event.event})"
        if event.event not in OPERATOR_EVENTS:
            if event.authority is not None:
                problems.append(f"{where} carries an authority, and is no operator's")
            continue
        if event.authority is None:
            if recorded is None:
                # Before version 4 there is no legacy set: version 2's rows
                # are told by when version 3 was installed.
                if epoch is not None and event.at < epoch:
                    legacy += 1
                else:
                    problems.append(
                        f"{where} carries no authority: it was written around Interlock"
                    )
            elif not recorded.holds(event):
                problems.append(
                    f"{where} carries no authority, and is not in the legacy set version 4 "
                    f"recorded: it was written around Interlock"
                )
            elif pinned_holds:
                legacy += 1
            else:
                unvouched += 1
            continue
        actions += 1
        signed = intents.get(event.authority)
        if signed is None:
            problems.append(
                f"{where} names authority {event.authority[:16]}, which no signed intent holds"
            )
            continue
        body = signed.body
        if ACTION_EVENTS.get(str(body.get("action"))) != event.event:
            problems.append(f"{where} is under the authority of a {body.get('action')} intent")
        targets = {str(t.get("message")): t for t in body.get("targets", [])}
        target = targets.get(str(event.message_id))
        if target is None:
            cascaded = body.get("action") == "requeue" and any(
                stage_of.get(uuid.UUID(m)) == stage_of.get(event.message_id) for m in targets
            )
            if not cascaded:
                problems.append(f"{where} carries the authority of an intent that does not name it")
        elif target.get("head") != event.prev_hash:
            problems.append(
                f"{where} was not written at the head its intent was signed for: the log had moved"
            )
        outcome = outcomes.get(event.authority)
        if outcome is not None and outcome.kind != APPLIED.value:
            problems.append(f"{where} carries the authority of an intent recorded {outcome.kind}")
        elif outcome is not None:
            listed = {
                (str(r.get("message")), r.get("seq"), r.get("hash"))
                for r in outcome.body.get("rows", [])
            }
            if (str(event.message_id), event.seq, event.event_hash) not in listed:
                problems.append(f"{where} is not among the rows its applied record names")
    compacted = source_reader.compacted()
    for digest, outcome in outcomes.items():
        if outcome.kind != APPLIED.value:
            continue
        for row in outcome.body.get("rows", []):
            listed_message = uuid.UUID(str(row.get("message")))
            found = by_row.get((listed_message, row.get("seq")))
            tombstone = compacted.get(listed_message)
            if (
                found is None
                and tombstone is not None
                and int(row.get("seq") or 0) <= tombstone.log_seq
            ):
                continue  # pruned under a checkpoint, which commits to it
            if found is None or found.event_hash != row.get("hash") or found.authority != digest:
                problems.append(
                    f"operator record {outcome.seq} names row {row.get('seq')} of message "
                    f"{row.get('message')}, which the delivery log does not hold as recorded"
                )
    if unvouched:
        problems.append(
            f"{unvouched} operator row(s) from before version 3 carry no authority, and no "
            f"signed install vouches for the legacy set they are in: they rest on the "
            f"database's word. Vouch for it with `interlock install`"
        )
    if recorded is not None:
        problems += recorded.vanished(events)
    problems += _checkpoint_problems(
        source_reader.checkpoints(), compacted, messages, intents, outcomes
    )
    return OperatorReport(tuple(problems), len(trusted), actions, legacy)


def _checkpoint_problems(
    rows: Sequence[Any],
    compacted: Mapping[uuid.UUID, Any],
    messages: Sequence[Any],
    intents: Mapping[str, SignedRecord],
    outcomes: Mapping[str, SignedRecord],
) -> list[str]:
    """Every checkpoint held to the signed intent that carries it, the chain
    of checkpoints to itself, and the tombstones to their checkpoints."""
    import hashlib

    from agentgov.exceptions import MalformedReceiptError
    from agentgov.receipts.canonical import canonical_bytes

    from interlock.compaction import GENESIS, tombstone_root

    problems: list[str] = []
    previous = GENESIS
    by_checkpoint: dict[int, list[Any]] = {}
    for tombstone in compacted.values():
        by_checkpoint.setdefault(tombstone.checkpoint, []).append(tombstone)
    held = {row.authority for row in rows}
    for index, row in enumerate(sorted(rows, key=lambda r: r.seq), start=1):
        where = f"checkpoint {row.seq}"
        if row.seq != index or row.prev != previous:
            problems.append(f"{where} does not follow checkpoint {index - 1}: the chain was cut")
        if hashlib.sha256(row.body.encode("utf-8")).hexdigest() != row.digest:
            problems.append(f"{where}'s digest is not its body's: it was rewritten")
        previous = row.digest
        if row.open:
            problems.append(f"{where} was left open: written around Interlock")
        intent = intents.get(row.authority)
        if intent is None or intent.body.get("action") != "compact":
            problems.append(
                f"{where} names authority {row.authority[:16]}, which no signed compact intent "
                f"holds: written around Interlock"
            )
        else:
            try:
                signed = canonical_bytes(intent.body.get("checkpoint")).decode("utf-8")
            except MalformedReceiptError:  # a body that is no checkpoint at all
                signed = None
            if signed != row.body:
                problems.append(
                    f"{where} is not the checkpoint operator record {intent.seq} signed"
                )
            outcome = outcomes.get(row.authority)
            if outcome is not None and outcome.kind != APPLIED.value:
                problems.append(f"{where}'s intent was recorded {outcome.kind}")
        try:
            body = row.checkpoint()
        except (ValueError, KeyError, TypeError):
            problems.append(f"{where} is not a checkpoint")
            continue
        tombstones = by_checkpoint.get(row.seq, [])
        if (tombstone_root(tombstones), len(tombstones)) != (body.root, body.messages):
            problems.append(
                f"{where}'s tombstones no longer fold to its signed root: they were edited "
                f"around Interlock"
            )
    for digest, outcome in outcomes.items():
        intent = intents.get(digest)
        if (
            outcome.kind == APPLIED.value
            and intent is not None
            and intent.body.get("action") == "compact"
            and digest not in held
        ):
            problems.append(
                f"operator record {outcome.seq} applied a checkpoint the database no longer "
                f"holds: it was deleted around Interlock"
            )
    for message in messages:
        if message.message_id in compacted:
            problems.append(
                f"message {message.message_id} was pruned by checkpoint "
                f"{compacted[message.message_id].checkpoint}, and the outbox holds it again"
            )
    return problems


def legacy_vouch(records: Sequence[SignedRecord], keyring: Keyring) -> LegacyVouch | None:
    """The legacy set a signed install vouched for: the first
    ``operator.installed`` record carrying one, among the records that verify
    under ``keyring``. ``None`` when no install vouched for one."""
    return _pinned(_verified_prefix(records, keyring, []))


def _pinned(records: Iterable[SignedRecord]) -> LegacyVouch | None:
    for record in records:
        legacy = record.body.get("legacy") if record.kind == INSTALLED.value else None
        if isinstance(legacy, Mapping):
            return LegacyVouch(record.seq, int(legacy.get("rows", -1)), str(legacy.get("digest")))
    return None


def _verified_prefix(
    records: Sequence[SignedRecord], keyring: Keyring, problems: list[str]
) -> list[SignedRecord]:
    """The records up to the first that does not hold: nothing after it is
    evidence."""
    trusted: list[SignedRecord] = []
    previous = GENESIS
    for index, record in enumerate(records, start=1):
        try:
            if record.seq != index:
                raise RecordIntegrityError(f"record {index} carries sequence {record.seq}")
            if record.prev != previous:
                raise RecordIntegrityError(f"record {index} does not link to the one before it")
            key = keyring.verifier(record.key_id)
            if key is None:
                raise RecordIntegrityError(
                    f"record {index} was signed by key {record.key_id}, no registered operator's"
                )
            retired = keyring.retired(record.key_id)
            if retired is not None:
                raise RecordIntegrityError(
                    f"record {index} was signed by key {record.key_id} after record {retired} "
                    f"revoked it"
                )
            record.verify(key)
        except RecordIntegrityError as exc:
            problems.append(f"operator log: {exc}")
            break
        trusted.append(record)
        keyring = keyring.after(record)
        previous = record.record_hash
    return trusted
