"""Settlement: delivery receipts, and the credits compensations earn (``docs/EPIC4_DESIGN.md`` §4).

A delivered request is settled once, by the process that holds the receipt log
(the engine's, beside the AgentGov ledger), in three steps:

1. **The delivery receipt.** An ARC1 ``DeliveryReceipt``, signed by the
   receipt log, carrying the relay's attestation of the call and bound to the
   action receipt of the plan that committed the request by that receipt's
   leaf hash (:class:`agentgov.receipts.ActionBinding`). Only a delivery a
   registered relay attested is receipted. A compensation is receipted against
   its original's plan, which committed it: the compensation was adjudicated
   with the plan, and an operator's signed intent only set it off.
2. **The credit**, for a compensation: AgentGov ``refund()`` crediting the
   original request's scope with the ``cost_per_call`` the ledger charged for
   it, never the money the request moved. Posted only when the compensation's
   delivery is attested by a registered relay; the original's ``compensated``
   row carries the authority of a signed operator intent that names this very
   compensation, recorded applied; and the ledger holds the plan's charge, with
   room left in it for the credit.
3. **The settlement row**, in the outbox: the receipt and the credit, or why
   there is none.

Each step first finds what a crash may have left of it: a delivery receipt the
log already holds for the message, a credit the ledger already holds for the
compensation. Killed between any two, the next run settles the message once:
one receipt, at most one credit, one row. One process settles at a time: the
receipt log admits one writer.

A delivery the relays did not attest is not settled at all: it is a ghost
(:mod:`interlock.attestations`), and is reported.
"""

from __future__ import annotations

import logging
import re
import uuid
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from agentgov.core import EntryType, LedgerEntry
from agentgov.exceptions import MalformedReceiptError, ReceiptSignatureError
from agentgov.receipts import (
    ActionReceipt,
    Delivery,
    DeliveryReceipt,
    OutcomeStatus,
    ReceiptLog,
)

from interlock.attestations import attestation_of
from interlock.chain import EscrowChain, EscrowRecord, RecordType
from interlock.deliveries import LogEvent, LoggedMessage, settlements, verify_delivery_log
from interlock.records import Keyring, SignedRecord, read_records

if TYPE_CHECKING:
    from agentgov import BudgetManager

    from interlock.receipts import ReceiptIssuer

__all__ = ["CREDIT_MEMO", "SettlementReport", "Settler", "verify_settlements"]

logger = logging.getLogger("interlock.settlement")

CREDIT_MEMO: Final = "interlock-credit:"
"""Prefix of a credit's memo in the ledger, followed by the compensation's
message id: how a run finds the credit a crashed one posted."""

_RECEIPT: Final = re.compile(r"; receipt ([0-9a-f-]{36})")
_COMMITTED: Final = frozenset({OutcomeStatus.COMMITTED, OutcomeStatus.RECOVERED_COMMITTED})


@dataclass(frozen=True, slots=True)
class SettlementReport:
    """What one :meth:`Settler.settle` did."""

    settled: tuple[uuid.UUID, ...]
    """The messages settled now."""
    receipts: int
    """Delivery receipts issued now (one a crashed run left counts once, then)."""
    credits: int
    """Credits posted now."""
    problems: tuple[str, ...]
    """Deliveries refused settlement: no attestation a registered relay made, or
    a log that does not verify. They stay unsettled, and are reported again."""


class Settler:
    """Settles delivered requests: receipts them, credits compensations.

    :param outbox: The outbox, as the settler reads and writes it: a
        PostgreSQL connection as a settler role (``install(settler_roles=...)``),
        or a SQLite store opened with ``writes=SETTLER``.
    :param receipts: The engine's receipt issuer. Its log holds the plans'
        action receipts; delivery receipts are issued into it.
    :param chain: The engine's escrow chain, or its file: which receipt each
        committed plan was issued, and which records its charge names.
    :param relays: The relays' public keys (``[relays.keys]``).
    :param ledger: The AgentGov ledger the engine charges plans to. Without
        it, nothing is credited.
    :param operator_log: The signed operator log, and ``operators``, every
        operator's public key: what a compensation's authority is held to.
        Without them, nothing is credited.
    :param checkpoint: Called with ``"receipt"``, ``"credit"`` and
        ``"settled"`` and the message, once each step of its settlement is
        durable: the crash tests stop the process there.
    """

    __slots__ = (
        "_chain",
        "_checkpoint",
        "_ledger",
        "_operator_log",
        "_operators",
        "_outbox",
        "_receipts",
        "_relays",
    )

    def __init__(
        self,
        outbox: object,
        *,
        receipts: ReceiptIssuer,
        chain: EscrowChain | str | Path,
        relays: Keyring,
        ledger: BudgetManager | None = None,
        operator_log: str | Path | None = None,
        operators: Keyring | None = None,
        checkpoint: Callable[[str, uuid.UUID], None] | None = None,
    ) -> None:
        self._outbox = settlements(outbox)
        self._receipts = receipts
        self._chain = chain
        self._relays = relays
        self._ledger = ledger
        self._operator_log = operator_log
        self._operators = operators
        self._checkpoint = checkpoint or (lambda point, message: None)

    def settle(self) -> SettlementReport:
        """Settle every delivered request not settled yet."""
        settled_before = self._outbox.settlements()
        messages, events = self._outbox.snapshot(None)
        due = [m for m in messages if m.state == "delivered" and m.message_id not in settled_before]
        if not due:
            return SettlementReport((), 0, 0, ())
        context = _Context.build(
            messages,
            events,
            chain=self._chain_records(),
            log=self._receipts.log,
            ledger=self._ledger,
            operators=self._operator_records(),
            legacy=self._outbox.legacy(),
        )
        problems = verify_delivery_log(self._outbox, message_ids=[m.message_id for m in due])
        broken = {p.split(":", 1)[0].removeprefix("message ") for p in problems}
        settled: list[uuid.UUID] = []
        found: list[str] = list(problems)
        issued = credited = 0
        for message in due:
            if str(message.message_id) in broken:
                continue
            try:
                outcome = self._settle_one(message, context)
            except _UnsettledError as exc:
                found.append(f"message {message.message_id}: {exc}")
                continue
            issued += outcome.issued
            credited += outcome.credited
            if outcome.settled:
                settled.append(message.message_id)
        return SettlementReport(tuple(settled), issued, credited, tuple(found))

    # -- one message ----------------------------------------------------------

    def _settle_one(self, message: LoggedMessage, context: _Context) -> _Outcome:
        (delivered,) = [e for e in context.logs[message.message_id] if e.event == "delivered"][-1:]
        notes: list[str] = []
        if delivered.attestation is None:
            if context.legacy is None or not context.legacy.holds(delivered):
                raise _UnsettledError(
                    "delivered with no relay attestation, and not in the legacy set: an "
                    "outcome no relay reported, not settled"
                )
            notes.append("delivered before version 4, with no relay attestation to receipt")
            settled = self._record(message, None, None, notes)
            return _Outcome(settled, 0, 0)
        statement = attestation_of(message, delivered)
        assert statement.signature is not None
        key = self._relays.verifier(statement.signature.key_id)
        try:
            if key is None:
                raise ReceiptSignatureError("no registered relay's key")
            statement.verify(key)
        except (ReceiptSignatureError, MalformedReceiptError) as exc:
            raise _UnsettledError(
                f"its delivery is not attested by a registered relay ({exc}): not settled"
            ) from exc

        # Whether a compensation earns its credit is decided before anything is
        # issued: one not decided yet leaves the message alone, unreceipted.
        credit: LedgerEntry | None = None
        why: str | None = None
        if message.compensates is not None:
            credit = context.credits.get(message.message_id)
            if credit is None:
                why = self._why_no_credit(message, context)

        # 1. The delivery receipt, or the one a crashed run issued.
        issued = 0
        receipt = context.receipts.get(str(message.message_id))
        if receipt is None:
            action = context.action_receipt(message.plan_id)
            if action is None:
                notes.append(
                    f"no action receipt for plan {message.plan_id} to bind a delivery receipt "
                    f"to (receipts were off, or its commit was recovered after a crash)"
                )
            else:
                receipt = self._receipts.issue_delivery(
                    action=action,
                    request=statement.request,
                    delivery=Delivery(
                        attempt=delivered.attempt or 1,
                        status_code=delivered.status_code,
                        response_digest=delivered.response_digest,
                        remote_ref=delivered.remote_ref,
                        delivered_at=delivered.at,
                        log_seq=delivered.seq,
                        log_hash=delivered.event_hash,
                    ),
                    attestation=statement.signature,
                )
                context.receipts[str(message.message_id)] = receipt
                issued = 1
                self._checkpoint("receipt", message.message_id)

        # 2. The credit, for a compensation, or the one a crashed run posted.
        credited = 0
        if why is not None:
            notes.append(f"no credit: {why}")
        elif message.compensates is not None and credit is None:
            credit = self._credit(message, context)
            credited = 1
            self._checkpoint("credit", message.message_id)

        # 3. The settlement row.
        settled = self._record(
            message,
            receipt.receipt_id if receipt is not None else None,
            credit.entry_hash if credit is not None else None,
            notes,
        )
        return _Outcome(settled, issued, credited)

    def _record(
        self,
        message: LoggedMessage,
        receipt_id: str | None,
        credit: str | None,
        notes: Sequence[str],
    ) -> bool:
        done = self._outbox.settle(
            message.message_id, receipt_id=receipt_id, credit=credit, note="; ".join(notes)
        )
        if done:
            self._checkpoint("settled", message.message_id)
        return done

    # -- credits ------------------------------------------------------------------

    def _why_no_credit(self, message: LoggedMessage, context: _Context) -> str | None:
        """Why this compensation earns no credit, for good, or ``None`` when it
        does.

        :raises _UnsettledError: When the answer is not final yet: the operator log
            is not configured, or the intent behind the compensation awaits
            resolution. The message stays unsettled until it is.
        """
        assert message.compensates is not None
        original = context.messages.get(message.compensates)
        if original is None:  # pragma: no cover - the outbox's foreign key
            return "its original is not in the outbox"
        if self._ledger is None:
            return "no ledger to credit"
        if context.operators is None:
            raise _UnsettledError(
                "a compensation's credit is held to the signed operator log, and none is "
                "configured: not settled"
            )
        authority, pending = context.operators.authorizes(original, message, context.logs)
        if pending:
            raise _UnsettledError(f"{authority}: not settled until it is resolved")
        if authority is not None:
            return f"its authority does not hold: {authority}"
        if original.cost <= 0:
            return "its original cost nothing"
        charge = context.charge(original)
        if charge is None:
            return f"the ledger holds no charge for plan {original.plan_id}"
        room = charge.amount - context.credited(original.plan_id)
        if original.cost > room:
            return (
                f"plan {original.plan_id}'s charge of {charge.amount} has {room} left, less "
                f"than the {original.cost} the original cost"
            )
        return None

    def _credit(self, message: LoggedMessage, context: _Context) -> LedgerEntry:
        assert self._ledger is not None and message.compensates is not None
        original = context.messages[message.compensates]
        charge = context.charge(original)
        assert charge is not None
        entry = self._ledger.refund(
            original.scope_id,
            original.cost,
            memo=(
                f"{CREDIT_MEMO}{message.message_id} compensates {original.message_id} under "
                f"{charge.entry_hash[:16]}"
            ),
        )
        context.credits[message.message_id] = entry
        context.plan_credits[original.plan_id] = (
            context.plan_credits.get(original.plan_id, Decimal(0)) + entry.amount
        )
        return entry

    # -- reading what the engine wrote --------------------------------------------

    def _chain_records(self) -> tuple[EscrowRecord, ...]:
        if isinstance(self._chain, EscrowChain):
            return self._chain.records()
        return EscrowChain.load(self._chain).records()

    def _operator_records(self) -> _Operators | None:
        if self._operator_log is None or self._operators is None:
            return None
        path = Path(self._operator_log)
        records = read_records(path) if path.exists() else ()
        return _Operators.of(records, self._operators)


@dataclass(frozen=True, slots=True)
class _Outcome:
    settled: bool
    issued: int
    credited: int


class _UnsettledError(Exception):
    """A delivery settlement will not settle now: a ghost, or one whose credit
    is not decided yet."""


@dataclass
class _Context:
    """What one run reads once: the outbox, the chain, the logs, the ledger."""

    messages: dict[uuid.UUID, LoggedMessage]
    logs: dict[uuid.UUID, list[LogEvent]]
    receipts: dict[str, DeliveryReceipt]
    """The delivery receipts the log holds, by message."""
    credits: dict[uuid.UUID, LedgerEntry]
    """The credits the ledger holds, by compensation."""
    plan_credits: dict[str, Decimal]
    plan_receipts: dict[str, str]
    """Each committed plan's action receipt id, from the chain."""
    plan_records: dict[str, list[str]]
    """The hashes of each plan's commit records, which its charge's memo names."""
    log: ReceiptLog
    ledger: BudgetManager | None
    operators: _Operators | None
    legacy: Any

    @classmethod
    def build(
        cls,
        messages: Sequence[LoggedMessage],
        events: Sequence[LogEvent],
        *,
        chain: Sequence[EscrowRecord],
        log: ReceiptLog,
        ledger: BudgetManager | None,
        operators: _Operators | None,
        legacy: Any,
    ) -> _Context:
        logs: dict[uuid.UUID, list[LogEvent]] = {}
        for event in events:
            logs.setdefault(event.message_id, []).append(event)
        by_id = {m.message_id: m for m in messages}
        plan_receipts: dict[str, str] = {}
        plan_records: dict[str, list[str]] = {}
        for record in chain:
            if record.record_type in (RecordType.COMMIT_INTENT, RecordType.COMMITTED):
                plan_records.setdefault(str(record.plan_id), []).append(record.record_hash)
            if record.record_type is RecordType.COMMITTED:
                found = _RECEIPT.search(record.note)
                if found is not None:
                    plan_receipts[str(record.plan_id)] = found.group(1)
        credits: dict[uuid.UUID, LedgerEntry] = {}
        plan_credits: dict[str, Decimal] = {}
        if ledger is not None:
            for entry in ledger.audit_trail():
                compensation = _credited(entry)
                if compensation is None:
                    continue
                credits[compensation] = entry
                credited = by_id.get(compensation)
                original = (
                    by_id.get(credited.compensates)
                    if credited is not None and credited.compensates is not None
                    else None
                )
                if original is not None:
                    plan_credits[original.plan_id] = (
                        plan_credits.get(original.plan_id, Decimal(0)) + entry.amount
                    )
        return cls(
            messages=by_id,
            logs=logs,
            receipts={d.request.message_id: d for d in log.deliveries()},
            credits=credits,
            plan_credits=plan_credits,
            plan_receipts=plan_receipts,
            plan_records=plan_records,
            log=log,
            ledger=ledger,
            operators=operators,
            legacy=legacy,
        )

    def action_receipt(self, plan_id: str) -> ActionReceipt | None:
        """The action receipt the plan that committed was issued, if the log holds it."""
        receipt_id = self.plan_receipts.get(plan_id)
        index = None if receipt_id is None else self.log.index_of(receipt_id)
        if index is None:
            return None
        document = self.log.receipt(index)
        if not isinstance(document, ActionReceipt) or document.outcome.status not in _COMMITTED:
            return None
        return document

    def charge(self, original: LoggedMessage) -> LedgerEntry | None:
        """The ledger's charge for the plan that committed ``original``: the
        spend whose memo names one of its commit records."""
        if self.ledger is None:
            return None
        memos = {f"interlock:{h[:16]}" for h in self.plan_records.get(original.plan_id, ())}
        return next(
            (
                entry
                for entry in self.ledger.audit_trail(original.scope_id)
                if entry.entry_type is EntryType.SPEND and entry.memo in memos
            ),
            None,
        )

    def credited(self, plan_id: str) -> Decimal:
        return self.plan_credits.get(plan_id, Decimal(0))


@dataclass(frozen=True, slots=True)
class _Operators:
    """The operator log, as far as it verifies: intents, and their outcomes."""

    intents: Mapping[str, SignedRecord]
    applied: Mapping[str, SignedRecord]
    refused: frozenset[str]
    """Intents recorded refused or abandoned."""

    @classmethod
    def of(cls, records: Sequence[SignedRecord], keyring: Keyring) -> _Operators:
        from interlock.operators import ABANDONED, APPLIED, INTENT, REFUSED, _verified_prefix

        trusted = _verified_prefix(records, keyring, [])

        def answered(kinds: set[str]) -> dict[str, SignedRecord]:
            return {
                str(r.body.get("intent", {}).get("hash", "")): r for r in trusted if r.kind in kinds
            }

        return cls(
            intents={r.record_hash: r for r in trusted if r.kind == INTENT.value},
            applied=answered({APPLIED.value}),
            refused=frozenset(answered({REFUSED.value, ABANDONED.value})),
        )

    def authorizes(
        self,
        original: LoggedMessage,
        compensation: LoggedMessage,
        logs: Mapping[uuid.UUID, Sequence[LogEvent]],
    ) -> tuple[str | None, bool]:
        """Why the original's ``compensated`` row does not carry the authority
        of a signed intent naming exactly this compensation, applied, or
        ``None`` when it does; and whether that may yet change: an intent with
        no outcome recorded is resolved by the next operator command."""
        rows = [
            e
            for e in logs.get(original.message_id, ())
            if e.event == "compensated" and e.detail == f"compensated by {compensation.message_id}"
        ]
        if len(rows) != 1:
            return "the original's log does not record this compensation once", False
        (row,) = rows
        intent = self.intents.get(row.authority or "")
        if intent is None:
            return "no signed intent holds the authority its compensated row carries", False
        body = intent.body
        if body.get("action") != "compensate":
            return f"its authority is a {body.get('action')} intent", False
        target = next(
            (t for t in body.get("targets", []) if t.get("message") == str(original.message_id)),
            None,
        )
        named = dict(target.get("compensation", {})) if target is not None else {}
        expected = {
            "message": str(compensation.message_id),
            "sink": compensation.sink,
            "operation": compensation.operation,
            "payload_hash": compensation.payload_hash,
            "idempotency_key": compensation.idempotency_key,
        }
        if named != expected:
            return "the signed intent does not name this compensation", False
        if intent.record_hash in self.refused:
            return "the intent was recorded refused or abandoned", False
        applied = self.applied.get(intent.record_hash)
        if applied is None:
            return f"operator intent {intent.seq} has no outcome recorded yet", True
        listed = {
            (str(r.get("message")), r.get("seq"), r.get("hash"))
            for r in applied.body.get("rows", [])
        }
        if (str(original.message_id), row.seq, row.event_hash) not in listed:
            return "the intent's applied record does not name the compensated row", False
        return None, False


def _credited(entry: LedgerEntry) -> uuid.UUID | None:
    """The compensation a ledger entry credits for, if it is a settlement credit."""
    if entry.entry_type is not EntryType.REVERSAL or not entry.memo.startswith(CREDIT_MEMO):
        return None
    try:
        return uuid.UUID(entry.memo.removeprefix(CREDIT_MEMO).split(" ", 1)[0])
    except ValueError:
        return None


def verify_settlements(
    outbox: object,
    *,
    log: ReceiptLog,
    relays: Keyring,
    ledger: Iterable[LedgerEntry] | None = None,
) -> tuple[str, ...]:
    """Hold the settlements to the receipt log and the ledger, and both back.

    Finds a settlement naming a delivery receipt the log does not hold, or one
    for another message, or one whose attestation does not verify under a
    registered relay key, or whose binding names no action receipt in the
    log; a delivery receipt no settlement names; a credit no settlement names,
    or one naming a compensation credited twice, or for another amount than
    its original cost; and a settlement naming a credit the ledger does not
    hold.
    """
    source = settlements(outbox)
    rows = source.settlements()
    messages, _ = source.snapshot(None)
    by_id = {m.message_id: m for m in messages}
    problems: list[str] = []
    deliveries = {d.receipt_id: d for d in log.deliveries()}
    named: set[str] = set()
    for message_id, row in sorted(rows.items()):
        if row.receipt_id is None:
            continue
        named.add(row.receipt_id)
        receipt = deliveries.get(row.receipt_id)
        if receipt is None:
            problems.append(
                f"message {message_id}: its settlement names delivery receipt "
                f"{row.receipt_id}, which the receipt log does not hold"
            )
            continue
        if receipt.request.message_id != str(message_id):
            problems.append(
                f"message {message_id}: its settlement names delivery receipt "
                f"{row.receipt_id}, which receipts message {receipt.request.message_id}"
            )
        key = relays.verifier(receipt.attestation.key_id)
        try:
            if key is None:
                raise ReceiptSignatureError("no registered relay's key")
            receipt.attested().verify(key)
        except ReceiptSignatureError as exc:
            problems.append(f"delivery receipt {row.receipt_id}: its attestation: {exc}")
        index = log.index_of(receipt.action.receipt_id)
        action = None if index is None else log.receipt(index)
        if not isinstance(action, ActionReceipt) or receipt.action.problem(action) is not None:
            problems.append(
                f"delivery receipt {row.receipt_id} binds an action receipt the log does not "
                f"hold as bound"
            )
    for receipt_id, receipt in deliveries.items():
        if receipt_id not in named:
            problems.append(
                f"delivery receipt {receipt_id} (message {receipt.request.message_id}) is named "
                f"by no settlement"
            )
    if ledger is not None:
        credits: dict[uuid.UUID, list[LedgerEntry]] = {}
        for entry in ledger:
            compensation = _credited(entry)
            if compensation is not None:
                credits.setdefault(compensation, []).append(entry)
        for compensation, entries in sorted(credits.items()):
            settled = rows.get(compensation)
            message = by_id.get(compensation)
            if len(entries) > 1:
                problems.append(f"compensation {compensation} was credited {len(entries)} times")
            if settled is None or settled.credit not in {e.entry_hash for e in entries}:
                problems.append(
                    f"a credit for compensation {compensation} is named by no settlement"
                )
            original = (
                by_id.get(message.compensates)
                if message is not None and message.compensates
                else None
            )
            if original is None or any(e.amount != original.cost for e in entries):
                problems.append(
                    f"the credit for compensation {compensation} is not its original's cost"
                )
        held = {e.entry_hash for entries in credits.values() for e in entries}
        for message_id, row in sorted(rows.items()):
            if row.credit is not None and row.credit not in held:
                problems.append(
                    f"message {message_id}: its settlement names credit {row.credit[:16]}, "
                    f"which the ledger does not hold"
                )
    return tuple(problems)
