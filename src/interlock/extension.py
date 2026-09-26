"""Extension quotes: when a budget runs out, a price for finishing instead of a crash.

AgentGov's backstop is right to be blunt. An authorization that would overdraw
a scope trips its breaker, and a capture that spends a scope to zero trips it
too. For a runaway loop that is exactly the answer. For a task that is only
more expensive than its envelope, it throws away the work done and gives the
operator nothing to decide on.

A :class:`BudgetGuard` asks first. :meth:`BudgetGuard.authorize` checks the
scope's balance before AgentGov has to refuse, and when a call will not fit it
returns an :class:`ExtensionRequest` instead of placing a hold that would trip
the breaker. The request is a signed quote with three parts:

- **Spend to date**, from the ledger: what the task's scopes (the scope, its
  recovery scope, its extensions) have settled, what they hold, and what is left.
- **Proof of work**: the ARC1 receipts of the plans the task committed, with
  the rows they measurably changed, and a signed checkpoint of the receipt log
  they are in, so each one is provable by inclusion; the recovery steps it
  took; and the milestones the harness declares, marked as declared.
- **An estimated completion cost**, by a named method from recorded inputs,
  and the amount requested.

A quote is a request, not a grant. The operator answers it with
:meth:`BudgetGuard.grant` or :meth:`BudgetGuard.decline`, once, before it
expires, and the answer is a signed record naming the quote. AgentGov funds a
root scope directly, and the grant tops it up (resetting its breaker, if the
money running out is what tripped it). A delegated scope cannot be topped up,
so the grant delegates a new scope beside it, ``{scope}/ext-N`` (numbered side
by side: a second grant is ``ext-2``, not ``ext-1/ext-1``), carrying along
whatever the old scope had left, and the task bills that from then on.

A scope halted for any other reason (a cognitive trip, an operator's, an
ancestor's) is not quoted: :meth:`BudgetGuard.authorize` raises AgentGov's
``CircuitOpenError`` as AgentGov would. More money is not the answer to a
safety halt.

Quotes are the operator's evidence. They name amounts and receipts, and none
of it is for the agent. Granting is the operator's act: the guard records
``approved_by`` and cannot authenticate it, so :meth:`BudgetGuard.grant` belongs
behind whatever approval the operator already trusts, and never within an
agent's reach as a tool.
"""

from __future__ import annotations

import logging
import re
import threading
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from decimal import ROUND_CEILING, Decimal
from typing import Any, Final

from agentgov.core import Authorization, BudgetManager, EntryType, LedgerEntry
from agentgov.exceptions import AgentGovError, CircuitOpenError
from agentgov.receipts import OutcomeStatus, ReceiptLog

from interlock.exceptions import ExtensionError
from interlock.records import RecordKind, RecordLog, SignedRecord, anchor_memo, money
from interlock.recovery import breaker_reason, spent_out

__all__ = [
    "BudgetGuard",
    "Estimate",
    "ExtensionGrant",
    "ExtensionRequest",
    "Milestones",
    "Progress",
    "Spend",
]

logger = logging.getLogger("interlock.extension")

_CENT: Final = Decimal("0.01")
_EXTENSION: Final = re.compile(r"/ext-\d+$")
_RECEIPTS_LISTED: Final = 20
"""How many receipt ids a quote names, the newest. The checkpoint covers all."""
_COMMITTED: Final = frozenset({OutcomeStatus.COMMITTED, OutcomeStatus.RECOVERED_COMMITTED})


def _up_to_cent(amount: Decimal) -> Decimal:
    return amount.quantize(_CENT, rounding=ROUND_CEILING)


@dataclass(frozen=True, slots=True)
class Spend:
    """The task's money, from the ledger.

    :ivar spent: Settled, net of vendor refunds, over the task's scopes.
    :ivar held: Open holds over the task's scopes.
    :ivar available: What the quoted scope has left. Negative after an
        overrun AgentGov had to record.
    :ivar scopes: Each of the task's scopes with what it spent.
    """

    spent: Decimal
    held: Decimal
    available: Decimal
    scopes: tuple[tuple[str, Decimal], ...]

    def to_json(self) -> dict[str, Any]:
        return {
            "spent": money(self.spent),
            "held": money(self.held),
            "available": money(self.available),
            "scopes": [{"scope": s, "spent": money(a)} for s, a in self.scopes],
        }


@dataclass(frozen=True, slots=True)
class Milestones:
    """Progress the harness declares: ``done`` of ``total`` units of work.

    Declared, not proven. A quote carries it as the harness's claim and uses it
    only to estimate.
    """

    done: int
    total: int
    unit: str = "steps"

    def __post_init__(self) -> None:
        if not 0 <= self.done <= self.total or self.total < 1:
            raise ValueError(f"milestones are 0 <= done <= total, total >= 1; got {self}")


@dataclass(frozen=True, slots=True)
class Progress:
    """Proof of work: what the task has verifiably done, and what it says it has.

    :ivar committed: Plans the task committed, by their ARC1 receipts.
    :ivar rows: Rows those plans measurably changed.
    :ivar receipts: The newest receipt ids, at most 20; ``checkpoint`` covers
        every one of ``committed``.
    :ivar log: The receipt log's id.
    :ivar checkpoint: ``(tree size, root hash)`` of a checkpoint the log
        signed for this quote. Each receipt is provable against it with
        ``log.bundle(log.index_of(id), checkpoint)``.
    :ivar recovery_steps: Steps the task's recovery took, from the records.
    :ivar milestones: The harness's declaration, if it made one.
    """

    committed: int = 0
    rows: int = 0
    receipts: tuple[str, ...] = ()
    log: str | None = None
    checkpoint: tuple[int, str] | None = None
    recovery_steps: int = 0
    milestones: Milestones | None = None

    def to_json(self) -> dict[str, Any]:
        declared = self.milestones
        return {
            "committed": self.committed,
            "rows": self.rows,
            "receipts": list(self.receipts),
            "log": self.log,
            "checkpoint": (
                {"tree_size": self.checkpoint[0], "root": self.checkpoint[1]}
                if self.checkpoint is not None
                else None
            ),
            "recovery_steps": self.recovery_steps,
            "milestones": (
                {"done": declared.done, "total": declared.total, "unit": declared.unit}
                if declared is not None
                else None
            ),
        }


@dataclass(frozen=True, slots=True)
class Estimate:
    """What finishing would cost, by a stated method from stated inputs.

    ``milestones``: the task spent ``unit_cost`` per declared unit so far, and
    ``remaining`` units are left, so finishing costs ``unit_cost * remaining``,
    and never less than the call that did not fit. ``next_call``: with no
    declared progress to go on, only that call. ``total`` adds ``margin`` and
    rounds up to the cent.
    """

    method: str
    completion: Decimal
    margin: Decimal
    total: Decimal
    unit_cost: Decimal | None = None
    remaining: int | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "unit_cost": money(self.unit_cost) if self.unit_cost is not None else None,
            "remaining": self.remaining,
            "completion": money(self.completion),
            "margin": str(self.margin),
            "total": money(self.total),
        }


@dataclass(frozen=True, slots=True)
class ExtensionRequest:
    """A signed quote for finishing a task whose budget ran out.

    :ivar scope_id: The scope the call did not fit.
    :ivar task: The task's scope; spend is summed over it and ``{task}/...``.
    :ivar needed: The call that did not fit.
    :ivar requested: What the operator is asked for: the estimate, less what
        the scope has left (which a grant carries along), rounded up to the cent.
    :ivar halted_by: The breaker reason, when the money running out had
        already tripped the scope.
    :ivar record: The signed ``extension.quoted`` record.
    """

    quote_id: str
    scope_id: str
    task: str
    needed: Decimal
    spend: Spend
    progress: Progress
    estimate: Estimate
    requested: Decimal
    issued_at: datetime
    expires_at: datetime
    halted_by: str | None
    record: SignedRecord

    def render(self) -> str:
        """The quote in words, for the operator deciding on it."""
        spent = ", ".join(f"{s} {money(a)}" for s, a in self.spend.scopes)
        progress = self.progress
        proof = f"{progress.committed} plan(s) committed ({progress.rows} rows)"
        if progress.checkpoint is not None:
            size, root = progress.checkpoint
            proof += f", provable in receipt log {progress.log} at size {size}, root {root[:16]}"
        if progress.recovery_steps:
            proof += f"; {progress.recovery_steps} recovery step(s)"
        if progress.milestones is not None:
            declared = progress.milestones
            proof += f"; declared {declared.done} of {declared.total} {declared.unit} done"
        estimate = self.estimate
        how = (
            f"{money(estimate.unit_cost)} per unit x {estimate.remaining} remaining"
            if estimate.unit_cost is not None
            else "the next call alone"
        )
        return "\n".join(
            [
                f"Extension requested for {self.scope_id}: {money(self.requested)}.",
                f"Spent {money(self.spend.spent)} ({spent}); held {money(self.spend.held)}; "
                f"{money(self.spend.available)} left; the call needed {money(self.needed)}.",
                f"Proof of work: {proof}.",
                f"Estimate: {how} = {money(estimate.completion)}, plus "
                f"{format((estimate.margin * 100).normalize(), 'f')}% margin "
                f"= {money(estimate.total)} to finish.",
                f"Expires {self.expires_at.isoformat()}.",
            ]
        )


@dataclass(frozen=True, slots=True)
class ExtensionGrant:
    """An operator's grant of a quote.

    :ivar scope_id: Where the task bills from now on: the quoted scope when it
        is a root, else the new ``{scope}/ext-N`` beside it.
    :ivar amount: What was granted: new money, from the treasury for a root or
        from the parent.
    :ivar carried: What the quoted scope had left, moved into the new scope
        with the grant so it is not stranded. Zero for a root.
    :ivar reset: Whether the quoted scope's breaker was reset, which happens
        only for a root whose money running out tripped it.
    """

    grant_id: str
    quote_id: str
    scope_id: str
    amount: Decimal
    carried: Decimal
    approved_by: str
    reset: bool
    record: SignedRecord


@dataclass(slots=True)
class _Pending:
    quote: ExtensionRequest
    decided: str | None = None
    grants: list[str] = field(default_factory=list)


class BudgetGuard:
    """Authorizes spend, and quotes for more instead of letting a budget trip.

    :param governor: A write-capable AgentGov manager.
    :param records: Where quotes and their answers are signed.
    :param receipts: The ARC1 receipt log the task's plans are issued into,
        for proof of work. Without it a quote proves only its records.
    :param margin: Added to an estimate, as a fraction.
    :param ttl: How long a quote may be answered.
    :param clock: The time source; a test supplies its own.
    """

    def __init__(
        self,
        governor: BudgetManager,
        records: RecordLog,
        *,
        receipts: ReceiptLog | None = None,
        margin: Decimal = Decimal("0.25"),
        ttl: timedelta = timedelta(hours=1),
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        if margin < 0:
            raise ValueError("a margin cannot be negative")
        self._governor = governor
        self._records = records
        self._receipts = receipts
        self._margin = Decimal(str(margin))
        self._ttl = ttl
        self._clock = clock
        self._lock = threading.RLock()
        self._pending: dict[str, _Pending] = {}

    @property
    def records(self) -> RecordLog:
        return self._records

    def pending(self) -> tuple[ExtensionRequest, ...]:
        """Quotes not yet granted or declined, oldest first."""
        with self._lock:
            return tuple(p.quote for p in self._pending.values() if p.decided is None)

    # -- asking ---------------------------------------------------------------

    def authorize(
        self,
        scope_id: str,
        amount: Decimal | str,
        *,
        memo: str = "",
        task: str | None = None,
        milestones: Milestones | None = None,
    ) -> Authorization | ExtensionRequest:
        """Hold ``amount`` on ``scope_id``, or quote for more when it will not fit.

        The balance check and the hold happen under the ledger's lock, so no
        concurrent spend can turn a check that passed into an overdraft trip.

        :param task: The task's scope, when ``scope_id`` is one of its
            satellites (``{task}/recovery``, ``{task}/ext-1``); defaults to
            ``scope_id``.
        :returns: The hold, or the quote in its place.
        :raises agentgov.exceptions.CircuitOpenError: If the scope is halted
            for any reason but its money running out.
        """
        needed = Decimal(str(amount))
        if needed <= 0:
            raise ValueError(f"an authorization is positive, got {needed}")
        governor = self._governor
        with governor.ledger.lock:
            halted = governor.halted_by(scope_id)
            reason = breaker_reason(governor, halted) if halted is not None else None
            if halted is not None and (halted != scope_id or not spent_out(reason or "")):
                raise CircuitOpenError(scope_id, halted, reason or "")
            if halted is None and needed <= governor.available(scope_id):
                return governor.authorize(scope_id, needed, memo=memo)
        return self.quote(scope_id, needed, task=task, milestones=milestones)

    def quote(
        self,
        scope_id: str,
        needed: Decimal | str,
        *,
        task: str | None = None,
        milestones: Milestones | None = None,
    ) -> ExtensionRequest:
        """Sign a quote for finishing: spend, proof of work, estimate, request."""
        governor = self._governor
        needed = Decimal(str(needed))
        task = task if task is not None else scope_id
        scopes = [s for s in governor.scopes() if s == task or s.startswith(f"{task}/")]
        trail = governor.audit_trail()
        spent = {s: Decimal(0) for s in scopes}
        for entry in trail:
            if entry.scope_id in spent:
                spent[entry.scope_id] += _signed_spend(entry)
        held = sum(
            (h.amount for h in governor.ledger.open_holds() if h.scope_id in spent), Decimal(0)
        )
        spend = Spend(
            spent=sum(spent.values(), Decimal(0)),
            held=held,
            available=governor.available(scope_id),
            scopes=tuple(spent.items()),
        )
        progress = self._progress(task, milestones)
        estimate = self._estimate(spend.spent, needed, milestones)
        requested = max(Decimal(0), _up_to_cent(estimate.total - spend.available))
        halted = governor.halted_by(scope_id)
        now = self._clock()
        quote_id = str(uuid.uuid4())
        expires = now + self._ttl
        halted_by = breaker_reason(governor, halted) if halted is not None else None
        record = self._records.append(
            RecordKind.EXTENSION_QUOTED,
            scope=task,
            body={
                "quote": quote_id,
                "scope": scope_id,
                "task": task,
                "needed": money(needed),
                "spend": spend.to_json(),
                "progress": progress.to_json(),
                "estimate": estimate.to_json(),
                "requested": money(requested),
                "issued_at": now.isoformat(),
                "expires_at": expires.isoformat(),
                "halted_by": halted_by,
                "ledger": {"sequence": len(governor.ledger), "head": governor.ledger.head_hash},
            },
        )
        self._anchor(scope_id, record)
        quote = ExtensionRequest(
            quote_id=quote_id,
            scope_id=scope_id,
            task=task,
            needed=needed,
            spend=spend,
            progress=progress,
            estimate=estimate,
            requested=requested,
            issued_at=now,
            expires_at=expires,
            halted_by=halted_by,
            record=record,
        )
        with self._lock:
            self._pending[quote_id] = _Pending(quote)
        return quote

    # -- answering --------------------------------------------------------------

    def grant(
        self,
        quote: ExtensionRequest,
        *,
        approved_by: str,
        amount: Decimal | str | None = None,
    ) -> ExtensionGrant:
        """Fund a quote: top up a root, or delegate ``{scope}/ext-N`` beside a child.

        :param amount: What to grant; the quote's request by default.
        :raises ExtensionError: If the quote is unknown here, already answered,
            expired, or the scope that would fund it cannot.
        """
        if not approved_by.strip():
            raise ValueError("a grant names who approved it")
        granted = Decimal(str(amount)) if amount is not None else quote.requested
        if granted <= 0:
            raise ValueError(f"a grant is positive, got {granted}")
        governor = self._governor
        with self._lock:
            pending = self._answerable(quote)
            grant_id = str(uuid.uuid4())
            scope = quote.scope_id
            memo = f"extension {grant_id} for quote {quote.quote_id}, approved by {approved_by}"
            node = governor.node(scope)
            parent = node.parent_id
            reset = False
            carried = Decimal(0)
            try:
                with governor.ledger.lock:
                    if parent is None:
                        halted = governor.halted_by(scope)
                        if halted is not None and not spent_out(breaker_reason(governor, halted)):
                            raise ExtensionError(
                                f"{scope!r} is halted by {halted!r} for a reason other than "
                                f"money; a grant cannot lift it"
                            )
                        entry = governor.fund(scope, granted, memo=memo)
                        if halted is not None:
                            governor.reset(scope)
                            reset = True
                        target, source = scope, "fund"
                    else:
                        # Checked before anything moves, so a grant the parent
                        # cannot make changes nothing.
                        halted = governor.halted_by(parent)
                        funds = governor.available(parent)
                        if halted is not None or funds < granted:
                            why = f"is halted by {halted!r}" if halted else f"has {funds}"
                            raise ExtensionError(
                                f"parent {parent!r} cannot fund {granted} for quote "
                                f"{quote.quote_id}: it {why}"
                            )
                        target = _next_extension(governor, scope)
                        # What the scope has left goes with the task, so no
                        # money is stranded behind it.
                        if governor.available(scope) > 0:
                            carried = governor.release(
                                scope, memo=f"carried into {target} by extension {grant_id}"
                            )
                        governor.delegate(parent, target, granted + carried, memo=memo)
                        entry = governor.audit_trail(target)[0]
                        source = "delegate"
            except AgentGovError as exc:
                raise ExtensionError(
                    f"{_origin_of(parent, scope)} cannot fund {granted} for quote "
                    f"{quote.quote_id}: {exc}"
                ) from exc
            record = self._records.append(
                RecordKind.EXTENSION_GRANTED,
                scope=quote.task,
                body={
                    "grant": grant_id,
                    "quote": {
                        "id": quote.quote_id,
                        "seq": quote.record.seq,
                        "hash": quote.record.record_hash,
                    },
                    "amount": money(granted),
                    "carried": money(carried),
                    "approved_by": approved_by,
                    "scope": target,
                    "source": source,
                    "from": parent if source == "delegate" else None,
                    "reset": reset,
                    "entry": str(entry.entry_id),
                },
            )
            self._anchor(target, record)
            pending.decided = "granted"
            pending.grants.append(grant_id)
            return ExtensionGrant(
                grant_id=grant_id,
                quote_id=quote.quote_id,
                scope_id=target,
                amount=granted,
                carried=carried,
                approved_by=approved_by,
                reset=reset,
                record=record,
            )

    def decline(
        self, quote: ExtensionRequest, *, declined_by: str, reason: str = ""
    ) -> SignedRecord:
        """Record that a quote was declined. The task's halt, if any, stands.

        :raises ExtensionError: If the quote is unknown here or already answered.
        """
        if not declined_by.strip():
            raise ValueError("a decline names who declined")
        with self._lock:
            pending = self._answerable(quote, expired_ok=True)
            record = self._records.append(
                RecordKind.EXTENSION_DECLINED,
                scope=quote.task,
                body={
                    "quote": {
                        "id": quote.quote_id,
                        "seq": quote.record.seq,
                        "hash": quote.record.record_hash,
                    },
                    "declined_by": declined_by,
                    "reason": reason[:512],
                },
            )
            self._anchor(quote.scope_id, record)
            pending.decided = "declined"
            return record

    # -- internals ----------------------------------------------------------------

    def _answerable(self, quote: ExtensionRequest, *, expired_ok: bool = False) -> _Pending:
        pending = self._pending.get(quote.quote_id)
        if pending is None or pending.quote != quote:
            raise ExtensionError(f"quote {quote.quote_id} was not issued by this guard")
        if pending.decided is not None:
            raise ExtensionError(f"quote {quote.quote_id} was already {pending.decided}")
        if not expired_ok and self._clock() > quote.expires_at:
            raise ExtensionError(
                f"quote {quote.quote_id} expired at {quote.expires_at.isoformat()}; the spend "
                f"it priced may have moved, so ask for a new one"
            )
        return pending

    def _progress(self, task: str, milestones: Milestones | None) -> Progress:
        steps = sum(
            1
            for r in self._records.records()
            if r.kind == RecordKind.RECOVERY_STEP and r.scope == task
        )
        log = self._receipts
        if log is None:
            return Progress(recovery_steps=steps, milestones=milestones)
        mine = [
            receipt
            for receipt in log.receipts()
            if receipt.outcome.status in _COMMITTED
            and receipt.authority.scope_path
            and _belongs(receipt.authority.scope_path[-1], task)
        ]
        checkpoint = log.checkpoint() if mine else None
        return Progress(
            committed=len(mine),
            rows=sum(r.effect.row_count for r in mine),
            receipts=tuple(r.receipt_id for r in mine[-_RECEIPTS_LISTED:]),
            log=log.log_id,
            checkpoint=(
                (checkpoint.tree_size, checkpoint.root_hash) if checkpoint is not None else None
            ),
            recovery_steps=steps,
            milestones=milestones,
        )

    def _estimate(self, spent: Decimal, needed: Decimal, milestones: Milestones | None) -> Estimate:
        if milestones is not None and milestones.done > 0:
            unit = spent / milestones.done
            remaining = milestones.total - milestones.done
            completion = max(unit * remaining, needed)
            total = _up_to_cent(completion * (1 + self._margin))
            return Estimate(
                "milestones",
                completion=completion,
                margin=self._margin,
                total=total,
                unit_cost=unit,
                remaining=remaining,
            )
        total = _up_to_cent(needed * (1 + self._margin))
        return Estimate("next_call", completion=needed, margin=self._margin, total=total)

    def _anchor(self, scope_id: str, record: SignedRecord) -> None:
        try:
            self._governor.anchor(scope_id, anchor_memo(record))
        except Exception:  # the record stands; a missing anchor shows as one
            logger.warning(
                "record %s of log %s could not be anchored into the ledger",
                record.seq,
                record.log,
                exc_info=True,
            )


def _origin_of(parent: str | None, scope: str) -> str:
    return f"parent {parent!r}" if parent is not None else f"the treasury for {scope!r}"


def _belongs(scope: str, task: str) -> bool:
    return scope == task or scope.startswith(f"{task}/")


def _signed_spend(entry: LedgerEntry) -> Decimal:
    if entry.entry_type is EntryType.SPEND:
        return entry.amount
    if entry.entry_type is EntryType.REVERSAL:
        return -entry.amount
    return Decimal(0)


def _next_extension(governor: BudgetManager, scope: str) -> str:
    """The next free ``{base}/ext-N``, where ``base`` is ``scope`` less any
    ``/ext-N`` of its own: a task's extensions are numbered side by side,
    never nested."""
    base = _EXTENSION.sub("", scope)
    taken = set(governor.scopes())
    n = 1
    while f"{base}/ext-{n}" in taken:
        n += 1
    return f"{base}/ext-{n}"
