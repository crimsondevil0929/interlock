"""Settlement: delivery receipts, and the credits compensations earn (``docs/EPIC4_DESIGN.md`` §4).

A delivered request is settled once, by the process that holds the receipt log
(the engine's, beside the AgentGov ledger), in three steps:

1. **The delivery receipt.** An ARC1 ``DeliveryReceipt``, signed by the
   receipt log, carrying the relay's attestation of the call and bound to the
   action receipt of the plan that committed the request by that receipt's
   leaf hash (:class:`agentgov.receipts.ActionBinding`). Only a delivery a
   registered relay attested is receipted, and only against the plan its
   attested idempotency key was derived from (:func:`~interlock.types.outbound_key`):
   the plan the outbox row names is the database's word, the key the relay's.
   A compensation is receipted against its original's plan, which committed
   it: the compensation was adjudicated with the plan, and an operator's
   signed intent only set it off.
2. **The credit**, for a compensation: AgentGov ``refund()`` crediting the
   scope the ledger charged for the plan with the ``cost_per_call`` the
   engine's sink registry prices the request at, which is what the plan was
   charged for it; never the money the request moved. Posted only when the
   compensation's delivery is attested by a registered relay; the original's
   ``compensated`` row carries the authority of a signed operator intent that
   names this very compensation, recorded applied; the compensation's
   attested key was derived from the original's plan and effect; the registry
   undoes the original's operation with the compensation's; the outbox
   records the original at the registry's price; and the ledger holds the
   plan's charge, with room left in it for the credit. No column the
   database's owner can rewrite sets the amount, or the scope credited.
3. **The settlement row**, in the outbox: the receipt and the credit, or why
   there is none.

Each step first finds what a crash may have left of it: a delivery receipt the
log already holds for the message, a credit the ledger already holds for the
compensation. Killed between any two, the next run settles the message once:
one receipt, at most one credit, one row. One process settles at a time: the
receipt log admits one writer.

In a cluster (``docs/EPIC9_DESIGN.md`` §3.2) every node's engines write a
receipt log and chains of their own, and a settler settles only the deliveries
of plans its chains record (``partition``): the node that committed a plan
settles it, into the log that holds its action receipt. The nodes' shares are
disjoint, so no two settlers touch one message.

A delivery the relays did not attest is not settled at all: it is a ghost
(:mod:`interlock.attestations`), and is reported.
"""

from __future__ import annotations

import logging
import re
import uuid
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
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
from agentgov.storage import JoinableStore

from interlock.attestations import attestation_of
from interlock.chain import EscrowChain, EscrowRecord, RecordType
from interlock.deliveries import (
    LogEvent,
    LoggedMessage,
    Settled,
    consistent,
    settlements,
    verify_delivery_log,
)
from interlock.keys import Seals, outcome_ref, revocations_of
from interlock.records import Keyring, SignedRecord, read_records
from interlock.types import EffectId, outbound_key

if TYPE_CHECKING:
    from agentgov import BudgetManager

    from interlock.outbound import SinkRegistry, SinkSpec
    from interlock.receipts import ReceiptIssuer

__all__ = ["CREDIT_MEMO", "SettlementReport", "Settler", "verify_settlements"]

logger = logging.getLogger("interlock.settlement")

CREDIT_MEMO: Final = "interlock-credit:"
"""Prefix of a credit's memo in the ledger, followed by the compensation's
message id: how a run finds the credit a crashed one posted."""

_RECEIPT: Final = re.compile(r"; receipt ([0-9a-f-]{36})")
_PRUNED_AT: Final = datetime(1970, 1, 1, tzinfo=UTC)
"""A pruned settlement's time, which its tombstone does not keep."""
_COMMITTED: Final = frozenset({OutcomeStatus.COMMITTED, OutcomeStatus.RECOVERED_COMMITTED})
_OUTCOMES: Final = frozenset(
    {RecordType.COMMITTED, RecordType.ABORTED, RecordType.ORPHANED, RecordType.COMPENSATED}
)
"""The records that end a stage's commit intent."""


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
    lags: tuple[float, ...] = ()
    """For each delivery receipt issued now, the seconds since its delivery."""


class Settler:
    """Settles delivered requests: receipts them, credits compensations.

    :param outbox: The outbox, as the settler reads and writes it: a
        PostgreSQL connection as a settler role (``install(settler_roles=...)``),
        or a SQLite store opened with ``writes=SETTLER``.
    :param receipts: The engine's receipt issuer. Its log holds the plans'
        action receipts; delivery receipts are issued into it.
    :param chain: The engine's escrow chain, or its file: which receipt each
        committed plan was issued, and which records its charge names. Several
        engines' (the daemon's workers, each writing a chain of its own), as a
        sequence of chains or files.
    :param relays: The relays' public keys (``[relays.keys]``).
    :param ledger: The AgentGov ledger the engine charges plans to. Without
        it, nothing is credited.
    :param operator_log: The signed operator log, and ``operators``, every
        operator's public key: what a compensation's authority is held to.
        Without them, a compensation is not settled.
    :param sinks: The engine's sink registry, which priced every request its
        plans committed: a credit is the ``cost_per_call`` it names for the
        compensation's sink, never the price the outbox row records. Without
        it, a compensation is not settled.
    :param checkpoint: Called with ``"receipt"``, ``"credit"`` and
        ``"settled"`` and the message, once each step of its settlement is
        durable: the crash tests stop the process there.
    :param partition: Settle only the deliveries of plans ``chain`` records,
        and leave the rest to the settler whose engines committed them: a node
        of a cluster's. Without it, a delivery of a plan no chain here records
        is settled without a receipt, as one committed before receipts were on.
    """

    __slots__ = (
        "_chain",
        "_checkpoint",
        "_ledger",
        "_operator_log",
        "_operators",
        "_outbox",
        "_partition",
        "_pass_relays",
        "_receipts",
        "_relays",
        "_seals",
        "_sinks",
    )

    def __init__(
        self,
        outbox: object,
        *,
        receipts: ReceiptIssuer,
        chain: EscrowChain | str | Path | Sequence[EscrowChain | str | Path],
        relays: Keyring,
        ledger: BudgetManager | None = None,
        operator_log: str | Path | None = None,
        operators: Keyring | None = None,
        sinks: SinkRegistry | None = None,
        checkpoint: Callable[[str, uuid.UUID], None] | None = None,
        partition: bool = False,
    ) -> None:
        self._outbox = settlements(outbox)
        self._partition = partition
        self._receipts = receipts
        self._chain = chain
        self._relays = relays
        self._pass_relays = relays
        self._seals = Seals()
        self._ledger = ledger
        self._operator_log = operator_log
        self._operators = operators
        self._sinks = sinks
        self._checkpoint = checkpoint or (lambda point, message: None)

    def settle(self) -> SettlementReport:
        """Settle every delivered request not settled yet."""
        settled_before = self._outbox.settlements()
        messages, events = self._outbox.snapshot(None)
        due = [m for m in messages if m.state == "delivered" and m.message_id not in settled_before]
        if not due:
            return SettlementReport((), 0, 0, ())
        chain = self._chain_records()
        if self._partition:
            # Another node's plan is another node's to settle: its receipt
            # goes into the log that holds its action receipt.
            ours = {str(record.plan_id) for record in chain}
            due = [m for m in due if m.plan_id in ours]
            if not due:
                return SettlementReport((), 0, 0, ())
        # A revoked relay's deliveries settle only as its revocation sealed
        # them (docs/EPIC8_DESIGN.md §2.3): the revoked keys read once a pass,
        # each seal once.
        self._pass_relays = self._relays.with_revocations(self._seals.read(self._outbox))
        if self._ledger is not None:
            # A governor's view of a shared ledger is as of its last read or
            # write: the charges other governors booked since are not in it.
            self._ledger.refresh()
        context = _Context.build(
            messages,
            events,
            chain=chain,
            log=self._receipts.log,
            owes=self._receipts.owes,
            ledger=self._ledger,
            operators=self._operator_records(),
            legacy=self._outbox.legacy(),
        )
        problems = verify_delivery_log(self._outbox, message_ids=[m.message_id for m in due])
        broken = {p.split(":", 1)[0].removeprefix("message ") for p in problems}
        settled: list[uuid.UUID] = []
        found: list[str] = list(problems)
        lags: list[float] = []
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
            if outcome.lag is not None:
                lags.append(outcome.lag)
            if outcome.settled:
                settled.append(message.message_id)
        return SettlementReport(tuple(settled), issued, credited, tuple(found), tuple(lags))

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
        relays = self._pass_relays
        key_id = statement.signature.key_id
        key = relays.verifier(key_id)
        try:
            if key is None:
                raise ReceiptSignatureError("no registered relay's key")
            statement.verify(key)
        except (ReceiptSignatureError, MalformedReceiptError) as exc:
            raise _UnsettledError(
                f"its delivery is not attested by a registered relay ({exc}): not settled"
            ) from exc
        refused = relays.refusal(
            key_id, "outcome", outcome_ref(message.message_id, delivered.seq), delivered.event_hash
        )
        if refused is not None:
            raise _UnsettledError(f"its delivery: {refused}: not settled")
        # The plan a delivery receipt binds to: the one the attested key was
        # derived from, which the row's plan must be.
        if message.idempotency_key != outbound_key(message.plan_id, EffectId(message.effect_id)):
            raise _UnsettledError(
                f"its row names plan {message.plan_id}, which its attested idempotency key "
                f"was not derived from: not settled"
            )

        # A stage commits before the chain records it, and its plan's action
        # receipt is issued after that: in one process a relay can deliver,
        # and this run, in either window. A commit not recorded yet, or a
        # receipt the commit names that its engine still owes, is coming; until
        # it is here, nothing is settled.
        if message.stage_id in context.open_stages and str(message.message_id) not in (
            context.receipts
        ):
            raise _UnsettledError(
                "its stage's commit is not recorded on the chain yet (its intent is open): "
                "not settled until it is"
            )
        pending = context.receipt_pending(message.plan_id)
        if pending is not None and str(message.message_id) not in context.receipts:
            raise _UnsettledError(
                f"its plan's action receipt {pending}, which the plan's commit names, is not "
                f"in the receipt log yet: not settled until it is"
            )

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
        lag: float | None = None
        receipt = context.receipts.get(str(message.message_id))
        if receipt is None:
            action = context.action_receipt(message.plan_id)
            named = context.plan_receipts.get(message.plan_id)
            if action is None and named is not None and context.log.index_of(named) is None:
                notes.append(
                    f"no action receipt for plan {message.plan_id} to bind a delivery receipt "
                    f"to: its commit names receipt {named}, which was never issued (the "
                    f"process that committed it stopped first)"
                )
            elif action is None:
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
                lag = max(0.0, (datetime.now(UTC) - delivered.at).total_seconds())
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
        return _Outcome(settled, issued, credited, lag)

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
            or the sink registry is not configured, or the intent behind the
            compensation awaits resolution. The message stays unsettled until
            it is.
        """
        assert message.compensates is not None
        original = context.messages.get(message.compensates)
        if original is None:  # pragma: no cover - the outbox's foreign key
            return "its original is not in the outbox"
        if self._ledger is None:
            return "no ledger to credit"
        if context.operators is None or self._sinks is None:
            missing = "signed operator log" if context.operators is None else "sink registry"
            raise _UnsettledError(
                f"a compensation's credit is held to the {missing}, and none is configured: "
                f"not settled"
            )
        authority, pending = context.operators.authorizes(original, message, context.logs)
        if pending:
            raise _UnsettledError(f"{authority}: not settled until it is resolved")
        if authority is not None:
            return f"its authority does not hold: {authority}"
        # Its key, attested and named in the signed intent, was derived from
        # its original's plan and effect: those the original's row names must
        # be they, or the row was moved to another plan.
        if (message.plan_id, message.effect_id) != (
            original.plan_id,
            f"compensate:{original.effect_id}",
        ):
            return (
                f"its original's row names plan {original.plan_id}, effect "
                f"{original.effect_id!r}; its key was derived from plan {message.plan_id}, "
                f"effect {message.effect_id!r}"
            )
        sink = self._sinks.get(message.sink)
        undoes = None if sink is None else sink.operation(original.operation)
        if (
            sink is None
            or original.sink != message.sink
            or undoes is None
            or undoes.compensation != message.operation
        ):
            return (
                f"the sink registry does not undo {original.sink}.{original.operation} with "
                f"{message.sink}.{message.operation}"
            )
        if sink.cost_per_call <= 0:
            return "its original cost nothing"
        if original.cost != sink.cost_per_call:
            return (
                f"the outbox records its original at {original.cost}, and the sink registry "
                f"prices a {sink.name} request at {sink.cost_per_call}"
            )
        charge = context.charge(original)
        if charge is None:
            if context.charge_claimed(original):
                raise _UnsettledError(
                    f"plan {original.plan_id}'s charge is claimed and not booked yet: not "
                    f"settled until it is"
                )
            return f"the ledger holds no charge for plan {original.plan_id}"
        room = charge.amount - context.credited(original.plan_id)
        if sink.cost_per_call > room:
            return (
                f"plan {original.plan_id}'s charge of {charge.amount} has {room} left, less "
                f"than the {sink.cost_per_call} the original cost"
            )
        return None

    def _credit(self, message: LoggedMessage, context: _Context) -> LedgerEntry:
        assert self._ledger is not None and message.compensates is not None
        original = context.messages[message.compensates]
        charge = context.charge(original)
        sink: SinkSpec | None = None if self._sinks is None else self._sinks.get(message.sink)
        assert charge is not None and sink is not None
        # The scope the ledger charged, at the registry's price: what
        # _why_no_credit held the outbox's columns to, not the columns.
        entry = self._ledger.refund(
            charge.scope_id,
            sink.cost_per_call,
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
        chains = [self._chain] if isinstance(self._chain, EscrowChain | str | Path) else self._chain
        records: list[EscrowRecord] = []
        for chain in chains:
            if isinstance(chain, EscrowChain):
                records += chain.records()
            else:
                records += EscrowChain.load(chain).records()
        return tuple(records)

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
    lag: float | None = None


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
    open_stages: frozenset[uuid.UUID]
    """The stages whose commit intent the chain holds with no outcome after it:
    committing now, or left open by a process that stopped."""
    owes: Callable[[str], bool]
    """Whether an engine of this process may still issue a receipt."""
    plan_records: dict[str, list[str]]
    """The hashes of each plan's commit records, which its charge's memo names."""
    spends: dict[str, LedgerEntry]
    """The ledger's first spend under each memo, in whatever scope it was
    charged to."""
    claims: frozenset[str]
    """The memos of the settlement claims the ledger holds and has not booked
    yet: charges committed with their plans, and not redeemed into the chain."""
    log: ReceiptLog
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
        owes: Callable[[str], bool],
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
        intents: set[uuid.UUID] = set()
        ended: set[uuid.UUID] = set()
        for record in chain:
            if record.record_type in (RecordType.COMMIT_INTENT, RecordType.COMMITTED):
                plan_records.setdefault(str(record.plan_id), []).append(record.record_hash)
            if record.record_type is RecordType.COMMITTED:
                found = _RECEIPT.search(record.note)
                if found is not None:
                    plan_receipts[str(record.plan_id)] = found.group(1)
            if record.stage_id is not None:
                if record.record_type is RecordType.COMMIT_INTENT:
                    intents.add(record.stage_id)
                elif record.record_type in _OUTCOMES:
                    ended.add(record.stage_id)
        credits: dict[uuid.UUID, LedgerEntry] = {}
        plan_credits: dict[str, Decimal] = {}
        spends: dict[str, LedgerEntry] = {}
        claims: frozenset[str] = frozenset()
        if ledger is not None:
            if isinstance(ledger.store, JoinableStore):  # only a shared ledger holds claims
                claims = frozenset(claim.memo for claim in ledger.pending_claims())
            for entry in ledger.audit_trail():
                if entry.entry_type is EntryType.SPEND:
                    spends.setdefault(entry.memo, entry)
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
            open_stages=frozenset(intents - ended),
            owes=owes,
            plan_records=plan_records,
            spends=spends,
            claims=claims,
            log=log,
            operators=operators,
            legacy=legacy,
        )

    def receipt_pending(self, plan_id: str) -> str | None:
        """The action receipt the plan's commit record names, while the log
        does not hold it yet and an engine of this process still owes it. One
        nothing owes was never issued, and never will be: the log is asked
        again after, since the engine logs a receipt before it stops owing it."""
        receipt_id = self.plan_receipts.get(plan_id)
        if receipt_id is None or self.log.index_of(receipt_id) is not None:
            return None
        return receipt_id if self.owes(receipt_id) else None

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
        """The ledger's charge for the plan that committed ``original``: its
        first spend whose memo names one of the plan's commit records. Found by
        the memo alone; the scope the outbox row names is not consulted."""
        found = [
            self.spends[memo]
            for memo in (f"interlock:{h[:16]}" for h in self.plan_records.get(original.plan_id, ()))
            if memo in self.spends
        ]
        return min(found, key=lambda entry: entry.sequence, default=None)

    def charge_claimed(self, original: LoggedMessage) -> bool:
        """Whether the plan's charge is a claim the ledger has not booked yet:
        committed with the plan, redeemed by its engine or by recovery soon."""
        return any(
            f"interlock:{h[:16]}" in self.claims
            for h in self.plan_records.get(original.plan_id, ())
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
    log: ReceiptLog | Sequence[ReceiptLog],
    relays: Keyring,
    ledger: Iterable[LedgerEntry] | None = None,
) -> tuple[str, ...]:
    """Hold the settlements to the receipt log and the ledger, and both back.
    In a cluster, ``log`` is every node's receipt log
    (``docs/EPIC9_DESIGN.md`` §3.2): each settlement's receipt is in one of
    them, bound to an action receipt of the same log.

    Finds a settlement naming a delivery receipt the log does not hold, or one
    for another message, or one whose attestation does not verify under a
    registered relay key, or whose binding names no action receipt in the
    log; a delivery receipt no settlement names; a credit no settlement names,
    or one naming a compensation credited twice, or for another amount than
    its original cost; and a settlement naming a credit the ledger does not
    hold.

    A message a checkpoint pruned (``docs/EPIC5_DESIGN.md`` §1.6) is held by
    its tombstone, which keeps its settlement's receipt and credit, its price
    and what it compensates.
    """
    source = settlements(outbox)
    with consistent(source):  # one state of the database, whatever settles meanwhile
        rows = dict(source.settlements())
        messages, _ = source.snapshot(None)
        pruned = source.compacted()
        relays = relays.with_revocations(revocations_of(source))
    by_id = {m.message_id: m for m in messages}
    for message_id, tombstone in pruned.items():
        if tombstone.state == "delivered" and message_id not in rows:
            rows[message_id] = Settled(
                message_id, tombstone.receipt_id, tombstone.credit, "", _PRUNED_AT
            )

    def compensates(message_id: uuid.UUID) -> uuid.UUID | None:
        live = by_id.get(message_id)
        if live is not None:
            return live.compensates
        tombstone = pruned.get(message_id)
        return None if tombstone is None else tombstone.compensates

    def cost(message_id: uuid.UUID) -> Decimal | None:
        live = by_id.get(message_id)
        if live is not None:
            return live.cost
        tombstone = pruned.get(message_id)
        return None if tombstone is None else Decimal(tombstone.cost)

    problems: list[str] = []
    logs = [log] if isinstance(log, ReceiptLog) else list(log)
    logged = {d.receipt_id: (d, holder) for holder in logs for d in holder.deliveries()}
    deliveries = {receipt_id: receipt for receipt_id, (receipt, _) in logged.items()}
    named: set[str] = set()
    for message_id, row in sorted(rows.items()):
        if row.receipt_id is None:
            continue
        named.add(row.receipt_id)
        found = logged.get(row.receipt_id)
        if found is None:
            problems.append(
                f"message {message_id}: its settlement names delivery receipt "
                f"{row.receipt_id}, which the receipt log does not hold"
            )
            continue
        receipt, holder = found
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
        else:
            # A live row a revoked relay attested is held to the seal; one
            # pruned before the revocation was verified as it was pruned.
            refused = relays.refusal(
                receipt.attestation.key_id,
                "outcome",
                outcome_ref(message_id, receipt.delivery.log_seq),
                receipt.delivery.log_hash,
            )
            if refused is not None and message_id in by_id:
                problems.append(f"delivery receipt {row.receipt_id}: its delivery: {refused}")
        index = holder.index_of(receipt.action.receipt_id)
        action = None if index is None else holder.receipt(index)
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
            if len(entries) > 1:
                problems.append(f"compensation {compensation} was credited {len(entries)} times")
            if settled is None or settled.credit not in {e.entry_hash for e in entries}:
                problems.append(
                    f"a credit for compensation {compensation} is named by no settlement"
                )
            original = compensates(compensation)
            price = None if original is None else cost(original)
            if price is None or any(e.amount != price for e in entries):
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
