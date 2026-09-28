"""The AgentGov seam.

Interlock imports ``agentgov`` as a read-only audit dependency. The dependency
runs one way only: ``interlock -> agentgov``, never the reverse. Interlock does
not subclass ``Ledger`` or ``BudgetManager``, does not touch a private name, and
does not require any change to AgentGov.

Two modes:

*Audit* opens the ledger with ``read_only=True``. That takes no advisory file
lock, so it can attach while a governor process is actively writing. A write
through this handle raises ``ReadOnlyLedgerError``, which is a bug in Interlock
rather than a condition to handle. The view is refreshed, and what it reads is
verified, before every head read and every pre-commit breaker check: a
read-only view is a snapshot until refreshed, and a stale one would let a plan
commit on a scope the governor halted after Interlock attached.

*Governed* additionally holds a write-capable manager, which lets Interlock
write its own chain head into AgentGov's chain. Each reverse anchor is the
``memo`` of a zero-value ``ANCHOR`` entry, or of the settling spend when the
plan carries a cost. Because ``memo`` is part of AgentGov's own hash payload,
that reverse anchor is tamper-evident inside AgentGov's chain, and the two
chains interlock in both directions. This uses only the public ``anchor()``,
``authorize(memo=)`` and ``capture(memo=)`` surface.

*Same transaction* (``same_transaction=True``) is governed mode over a ledger
shared through PostgreSQL (``BudgetManager.open_postgres``) in the same
database the stages run in. A plan is settled by *claim and settle*:

1. **Reserve.** Before its stage opens, the governor places a hold for the
   plan's cost, in its own transaction (:meth:`LedgerAnchor.reserve`). The
   hold's memo names the plan, so recovery can find it.
2. **Claim.** At commit the governor joins the stage's own transaction
   (:meth:`LedgerAnchor.joined_commit`): the ledger's writer lock is taken
   inside it, the governor catches up and checks the breaker, and a
   settlement claim keyed to the hold is written into the stage. The claim
   commits in the stage's ``COMMIT``, with the effects and the commit marker,
   or not at all, and no trip anywhere can land between the check and it.
3. **Settle.** After the commit the claim is redeemed into the chain: the
   hold's release and the spend, which names the plan's commit intent
   (:meth:`LedgerAnchor.redeem`). A process that dies first leaves the claim
   pending, and recovery redeems it.

The claim reads nothing of the chain, so a stage's ``REPEATABLE READ``
snapshot, taken when it opened, however many ledger commits ago, conflicts
with nothing: however busy the ledger, the plan commits. No crash can leave
effects without their claim, or a claim without its effects; a plan that did
not commit leaves at most its hold, which recovery releases.
"""

from __future__ import annotations

import logging
import sqlite3
from collections.abc import Iterable, Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path

from agentgov.core import (
    Authorization,
    BudgetManager,
    EntryType,
    JoinedTransaction,
    LedgerEntry,
    SettlementClaim,
)
from agentgov.exceptions import (
    AgentGovError,
    BudgetError,
    CircuitBreakerError,
    DoubleSpendError,
    LedgerConflictError,
    LedgerIntegrityError,
    UnknownScopeError,
)
from agentgov.storage import JoinableStore

from interlock.exceptions import (
    AnchorError,
    InterlockError,
    LedgerUnverifiedError,
    ScopeHaltedError,
    StageConflictError,
)
from interlock.types import GENESIS_HASH

__all__ = ["HOLD_MEMO", "AnchorPoint", "JoinedCommit", "LedgerAnchor"]

logger = logging.getLogger("interlock.anchor")

_REVERSE_ANCHOR_TYPES = frozenset({EntryType.ANCHOR, EntryType.SPEND})

HOLD_MEMO = "interlock-hold:"
"""Prefix of a reservation's memo, followed by the plan id. Recovery finds a
plan's hold by it."""


@contextmanager
def _barrier(context: str) -> Iterator[None]:
    """Translate every foreign exception into this package's hierarchy.

    ``agentgov`` is an implementation detail of the anchor. A caller wrapping
    the write path in ``except InterlockError`` must not have to know that
    ``UnknownScopeError`` or ``ConcurrentGovernorError`` exist, let alone
    import ``agentgov.exceptions`` to catch them. Anything this module cannot
    classify more precisely becomes :class:`AnchorError`: the evidence chain
    is unusable, so refuse to operate.

    Nothing else is caught, so an ``InterlockError`` such as a deliberate
    :class:`ScopeHaltedError` is never reclassified as an anchor failure.
    """
    try:
        yield
    except AgentGovError as exc:
        raise AnchorError(f"AgentGov refused {context}: {type(exc).__name__}: {exc}") from exc
    except (sqlite3.Error, OSError) as exc:
        raise AnchorError(f"AgentGov ledger unreachable during {context}: {exc}") from exc


@dataclass(frozen=True, slots=True)
class AnchorPoint:
    """A position in the AgentGov chain, observed at a moment in time."""

    anchored: bool
    head_hash: str
    sequence: int

    @classmethod
    def unanchored(cls) -> AnchorPoint:
        """The position used when no ledger is attached.

        Carries ``anchored=False`` and ``sequence=-1`` so it cannot be read as
        a real anchor at sequence 0.
        """
        return cls(anchored=False, head_hash=GENESIS_HASH, sequence=-1)


class LedgerAnchor:
    """Reads AgentGov, and optionally writes reverse anchors into it.

    :param audit_path: Path to the governor's SQLite ledger. ``None`` runs
        unanchored; records are then written with ``anchored=False`` and
        ``verify_anchors`` has nothing to check.
    :param governed: An already-open, write-capable ``BudgetManager`` for
        co-resident deployments. Supplying it enables reverse anchoring.
    :param same_transaction: Write the breaker check, the reverse anchor and
        the settled cost inside the stage's own transaction. ``governed`` must
        be a governor opened with ``BudgetManager.open_postgres`` on the
        database the stages run in, and the stage's role must be granted
        joined writes (``PostgresStore.grant_join``).
    :raises LedgerUnverifiedError: If ``audit_path`` names nothing, names
        something that is not an AgentGov ledger, or names one whose chain
        does not verify. Every unusable-ledger path raises this and nothing
        else, so a caller can fail closed on one exception type.
    :raises ValueError: If ``same_transaction`` is set without a governor
        that can join a transaction.

    No method on this class raises an ``agentgov`` exception. Every foreign
    error is translated into :class:`~interlock.exceptions.AnchorError` or
    :class:`~interlock.exceptions.ScopeHaltedError`, so the whole write path
    is catchable with ``except InterlockError``.
    """

    __slots__ = ("_audit", "_governed", "_same_transaction")

    def __init__(
        self,
        audit_path: str | Path | None = None,
        *,
        governed: BudgetManager | None = None,
        same_transaction: bool = False,
    ) -> None:
        if same_transaction and (governed is None or not isinstance(governed.store, JoinableStore)):
            raise ValueError(
                "same_transaction needs a governed BudgetManager over a ledger that can "
                "join the stage's transaction: BudgetManager.open_postgres on the database "
                "the stages run in"
            )
        self._governed = governed
        self._same_transaction = same_transaction
        self._audit: BudgetManager | None = None
        if audit_path is None:
            return
        path = Path(audit_path)
        if not path.is_file():
            raise LedgerUnverifiedError(f"no AgentGov ledger at {path}")
        try:
            manager = BudgetManager.open_sqlite(str(path), read_only=True)
        except (AgentGovError, sqlite3.Error, OSError) as exc:
            # sqlite3.Error and OSError are in here because a truncated or
            # otherwise corrupt file raises at the driver, below AgentGov's
            # own exception hierarchy. Letting that through would hand the
            # caller a sqlite3.DatabaseError from a module whose documented
            # contract is LedgerUnverifiedError, so a caller that fails closed
            # on LedgerUnverifiedError would instead crash.
            raise LedgerUnverifiedError(f"cannot open {path} as an AgentGov ledger: {exc}") from exc
        # Admissibility gate. A record anchored to a chain that does not
        # verify still reads as anchored, so refuse at attach time rather than
        # emitting records that look stronger than they are.
        try:
            manager.verify_integrity()
        except LedgerIntegrityError as exc:
            manager.close()
            raise LedgerUnverifiedError(
                f"AgentGov ledger at {path} failed verification, refusing to stage: {exc}"
            ) from exc
        self._audit = manager

    @property
    def attached(self) -> bool:
        return self._audit is not None

    @property
    def can_reverse_anchor(self) -> bool:
        return self._governed is not None

    @property
    def joins_transaction(self) -> bool:
        """Whether commits run through :meth:`joined_commit`."""
        return self._same_transaction

    def observe(self) -> AnchorPoint:
        """Read AgentGov's current head position.

        An audit view is refreshed first, so the position is the governor's
        current head, verified, rather than wherever it stood at attach time.

        :raises LedgerUnverifiedError: If what the governor wrote since the
            last read does not verify.
        """
        source = self._audit or self._governed
        if source is None:
            return AnchorPoint.unanchored()
        self._refresh()
        with _barrier("a chain-head read"):
            ledger = source.ledger
            with ledger.lock:
                return AnchorPoint(anchored=True, head_hash=ledger.head_hash, sequence=len(ledger))

    def _refresh(self) -> None:
        """Catch the attached views up with the ledger, verifying every new entry.

        The audit view follows the governor. A governed manager over a
        single-writer ledger is the writer and always current, so its refresh
        is a no-op; over a ledger shared through PostgreSQL, other governors
        write too, and it follows them.

        :raises LedgerUnverifiedError: If the new entries do not verify, or the
            ledger was rewritten under the view. The view then refuses every
            later read, so the failure repeats rather than clearing itself.
        :raises AnchorError: If the ledger cannot be read at all.
        """
        for source in self._sources():
            self._refresh_one(source)

    def _refresh_one(self, source: BudgetManager) -> None:
        try:
            source.refresh()
        except LedgerIntegrityError as exc:
            raise LedgerUnverifiedError(
                f"the AgentGov ledger no longer verifies against what this anchor read "
                f"before, refusing to operate: {exc}"
            ) from exc
        except AgentGovError as exc:
            raise AnchorError(f"AgentGov refused a refresh: {type(exc).__name__}: {exc}") from exc
        except (sqlite3.Error, OSError) as exc:
            raise AnchorError(f"AgentGov ledger unreachable during a refresh: {exc}") from exc

    def _sources(self) -> tuple[BudgetManager, ...]:
        return tuple(source for source in (self._audit, self._governed) if source is not None)

    def assert_scope_live(self, scope_id: str) -> None:
        """Refuse if AgentGov's breaker has tripped for this scope or an ancestor.

        Called immediately before commit rather than at admission, because the
        staging window is where a trip has to be observed. An audit view is
        refreshed first: a trip the governor wrote after Interlock attached is
        seen here. Every attached view is checked, so with both an audit path
        and a governed manager a halt in either refuses the commit.

        :raises ScopeHaltedError: If the scope or any ancestor is halted.
        :raises LedgerUnverifiedError: If the refresh does not verify. Fails
            closed: a breaker state that cannot be read is not a live scope.
        """
        self._refresh()
        for source in self._sources():
            halted = _halted(source, scope_id)
            if halted is not None:
                raise ScopeHaltedError(
                    f"AgentGov has halted {halted}; refusing to commit staged effects "
                    f"for scope {scope_id!r}"
                )

    @contextmanager
    def guard_commit(self, scope_id: str) -> Iterator[None]:
        """Check the scope is live, and keep it so until the block exits.

        Wrap the substrate commit in this. With a governed manager, the
        governor's own lock is held from the check through the commit, so a
        trip in this process lands strictly before the check (and the commit is
        refused) or strictly after the commit, never between them.

        An audit view is a separate process's database, and no lock spans it
        and the substrate. The check there reads the governor's committed state
        immediately before the commit, verified; a trip the governor commits
        after that read is concurrent with this commit and cannot be excluded.
        :meth:`halted_after_commit` records it when it happens.

        :raises ScopeHaltedError: If the scope or an ancestor is halted.
        """
        if self._governed is None:
            self.assert_scope_live(scope_id)
            yield
            return
        with _barrier("a commit guard"):
            lock = self._governed.ledger.lock
        with lock:
            self.assert_scope_live(scope_id)
            yield

    def reserve(self, plan_id: str, scope_id: str, cost: Decimal) -> Authorization | None:
        """Place the hold a plan's claim will settle against, before its stage
        opens. Same-transaction mode; ``None`` for a free plan.

        In the governor's own transaction, so it is visible to every stage
        opened after it, and checks the breaker and the budget as any
        authorization does: a plan that cannot pay is refused before it
        stages anything.

        :raises ScopeHaltedError: If the scope is halted or cannot pay
            ``cost``. An overdraft trips the breaker, durably.
        :raises AnchorError: If AgentGov refused the hold for another reason.
        """
        governed = self._governed
        if governed is None or not self._same_transaction or cost <= 0:
            return None
        try:
            return governed.authorize(scope_id, cost, memo=f"{HOLD_MEMO}{plan_id}")
        except (CircuitBreakerError, BudgetError) as exc:
            raise ScopeHaltedError(
                f"scope {scope_id!r} cannot reserve this plan's cost of {cost}, so it is not "
                f"staged: {type(exc).__name__}: {exc}"
            ) from exc
        except AgentGovError as exc:
            raise AnchorError(
                f"AgentGov refused the reservation on scope {scope_id!r}: "
                f"{type(exc).__name__}: {exc}"
            ) from exc

    def release(self, reservation: Authorization | None) -> None:
        """Void a reservation whose plan did not commit. Best effort: a hold
        left behind is released by recovery, and never double-spent."""
        if reservation is None or self._governed is None:
            return
        try:
            self._governed.void(reservation, memo="plan did not commit")
        except DoubleSpendError:
            return  # already settled or voided
        except AgentGovError:
            logger.warning(
                "hold %s could not be released now; recovery will",
                reservation.authorization_id,
                exc_info=True,
            )

    @contextmanager
    def joined_commit(self, scope_id: str, connection: object) -> Iterator[JoinedCommit]:
        """Join the stage's transaction for its commit. Same-transaction mode.

        On entry the ledger's writer lock is taken inside the stage's
        transaction, the governor catches up with every other governor's
        commits, and the breaker is checked: the scope is live, and stays so
        until the stage commits or rolls back, fleet-wide. Inside the block,
        :meth:`JoinedCommit.claim` records the plan's settlement claim in the
        stage's transaction. Commit the stage inside the block; redeem the
        claim after it (:meth:`redeem`).

        Nothing here reads the chain through the stage's snapshot, so however
        many ledger commits landed while the plan was staged, nothing
        conflicts.

        :param connection: The stage's connection
            (``PostgresSubstrate.connection``).
        :raises StageConflictError: If the writer lock was not granted within
            the stage's lock bound. Nothing was written; run the plan again.
        :raises ScopeHaltedError: If the scope or an ancestor is halted.
        :raises AnchorError: If the ledger cannot be joined or read.
        """
        governed = self._governed
        if governed is None or not self._same_transaction:
            raise AnchorError("joined_commit needs an anchor built with same_transaction=True")
        with ExitStack() as stack:
            try:
                transaction = stack.enter_context(governed.joined(connection))
            except LedgerConflictError as exc:
                # A halt is final, and a retry would only find it again:
                # refuse the plan rather than invite one.
                self.assert_scope_live(scope_id)
                raise StageConflictError(
                    f"the AgentGov ledger's writer lock was not granted in time: {exc}"
                ) from exc
            except AgentGovError as exc:
                raise AnchorError(
                    f"AgentGov could not join the stage's transaction: {type(exc).__name__}: {exc}"
                ) from exc
            self.assert_scope_live(scope_id)
            yield JoinedCommit(transaction, scope_id)

    def redeem(self, claim: SettlementClaim) -> LedgerEntry | None:
        """Book a committed claim into the chain, right after its commit.

        :returns: The settling entry, or ``None`` when another governor booked
            it first.
        :raises AnchorError: If AgentGov could not book it now. The claim stays
            pending, and recovery books it.
        """
        governed = self._governed
        if governed is None:
            return None
        with _barrier(f"redeeming settlement claim {claim.claim_id}"):
            booked = governed.redeem(claim)
        return booked[0] if booked else None

    def settle_pending(self, releasable: Iterable[str]) -> tuple[LedgerEntry, ...]:
        """After a crash: book every pending claim, and release the holds of
        ``releasable`` plans.

        Any governor may book any pending claim, since a claim exists only for
        a stage that committed. A hold is released only for a plan the caller
        knows can no longer commit (its chain says it ended, or never reached
        its commit intent): never another engine's plan, which may be staging
        right now.

        :param releasable: Ids of plans whose holds may be voided.
        :returns: The entries booked for pending claims.
        :raises AnchorError: If AgentGov cannot be written.
        """
        governed = self._governed
        if governed is None or not self._same_transaction:
            return ()
        plans = frozenset(releasable)
        with _barrier("settling pending claims after recovery"):
            booked = governed.redeem()
            governed.refresh()
            for hold in governed.stale_authorizations(0):
                memo = hold.entry.memo
                if memo.startswith(HOLD_MEMO) and memo.removeprefix(HOLD_MEMO) in plans:
                    self.release(hold)
        for entry in booked:
            logger.warning("recovered a pending settlement claim: %s", entry.memo)
        return booked

    def halted_after_commit(self, scope_id: str) -> str:
        """Describe a halt that raced a commit through an audit view, if any.

        Only an audit-only anchor can race: :meth:`guard_commit` excludes it
        for a governed manager. Never raises, because it runs after the
        substrate has committed.

        :returns: A note for the commit record, or ``""``.
        """
        if self._audit is None or self._governed is not None:
            return ""
        try:
            self._refresh()
            halted = _halted(self._audit, scope_id)
        except InterlockError:
            logger.warning("post-commit breaker read failed for %r", scope_id, exc_info=True)
            return ""
        if halted is None:
            return ""
        return (
            f"a halt on {halted} was found when AgentGov was re-read immediately "
            f"after this commit, and was not visible before it"
        )

    def scope_path(self, scope_id: str) -> tuple[str, ...]:
        """The AgentGov scope path from the root down to ``scope_id``.

        ``(scope_id,)`` when no ledger is attached or AgentGov does not know
        the scope: a receipt names at least the scope the plan claimed.
        """
        source = self._audit or self._governed
        if source is None:
            return (scope_id,)
        try:
            with _barrier("a scope-path read"):
                return tuple(reversed(source.ancestry(scope_id)))
        except AnchorError:
            return (scope_id,)

    def assert_scope_known(self, scope_id: str) -> None:
        """Refuse a plan whose scope AgentGov has never heard of.

        Only meaningful when reverse anchoring is on, because that is the one
        path that *writes* to AgentGov and therefore the one that can fail on
        an unknown scope. Called from admission rather than from the commit
        path deliberately: the reverse anchor is written after the substrate
        has committed, so discovering the scope is bogus there means raising
        on top of durable effects and destroying the caller's ``StageResult``.
        Failing at admission costs nothing and stages nothing.

        :raises AnchorError: If the scope is not present in AgentGov.
        """
        if self._governed is None:
            return
        # A scope another governor of a shared ledger opened is known once
        # this one has followed it.
        self._refresh()
        try:
            self._governed.node(scope_id)
        except UnknownScopeError as exc:
            raise AnchorError(
                f"plan scope {scope_id!r} is not a scope AgentGov knows about, so "
                f"its reverse anchor could never be written. Open or delegate the "
                f"scope before staging, or build the engine without an anchor"
            ) from exc
        except AgentGovError as exc:
            raise AnchorError(
                f"AgentGov refused a scope lookup for {scope_id!r}: {type(exc).__name__}: {exc}"
            ) from exc

    def verify(self) -> None:
        """Re-verify the attached ledger.

        :raises LedgerUnverifiedError: If the chain or conservation fails.
        """
        source = self._audit or self._governed
        if source is None:
            return
        self._refresh()
        try:
            source.verify_integrity()
        except LedgerIntegrityError as exc:
            raise LedgerUnverifiedError(str(exc)) from exc
        except AgentGovError as exc:
            raise AnchorError(
                f"AgentGov refused a verification read: {type(exc).__name__}: {exc}"
            ) from exc

    def reverse_anchor(
        self,
        scope_id: str,
        record_hash: str,
        *,
        cost: Decimal | str = "0",
        reservation: Authorization | None = None,
    ) -> LedgerEntry | None:
        """Write an Interlock chain head into AgentGov's chain.

        The memo is inside AgentGov's hash payload, so once written the reverse
        anchor cannot be edited without breaking AgentGov's own verification.
        That is the upper time bound one-way anchoring does not give.

        :param cost: What the plan cost to produce. Zero (the default) writes
            a zero-value ``ANCHOR`` entry, which moves no money: the anchor is
            free. A positive cost is settled through AgentGov's
            ``authorize``/``capture`` pair and the spend carries the memo.
        :param reservation: The plan's hold, placed before it staged
            (:meth:`reserve`). The cost is then captured against it rather than
            authorized anew.
        :returns: The anchoring entry, or ``None`` when not co-resident.
        :raises AnchorError: If ``cost`` is negative. Raised here rather than
            letting AgentGov's ``ValueError`` surface from inside the commit
            path, where it arrives after the effects are already durable.
        """
        if self._governed is None:
            return None
        amount = Decimal(cost) if not isinstance(cost, Decimal) else cost
        if amount < 0:
            raise AnchorError(
                f"a reverse anchor's settle cost cannot be negative, got {amount}; "
                f"pass the plan's real cost, or zero for a free anchor"
            )
        memo = f"interlock:{record_hash[:16]}"
        with _barrier(f"a reverse anchor on scope {scope_id!r}"):
            if reservation is not None:
                return self._governed.capture(reservation, amount, memo=memo)
            if amount == 0:
                return self._governed.anchor(scope_id, memo)
            authorization = self._governed.authorize(scope_id, amount, memo=memo)
            return self._governed.capture(authorization, amount, memo=memo)

    def find_reverse_anchors(self) -> tuple[LedgerEntry, ...]:
        """Every AgentGov entry carrying an Interlock reverse anchor.

        A free anchor is an ``ANCHOR`` entry; a paid one is the settling
        ``SPEND``. The hold that preceded a paid anchor carries the same memo
        and is not counted.
        """
        source = self._audit or self._governed
        if source is None:
            return ()
        self._refresh()
        with _barrier("an audit-trail read"):
            return tuple(
                entry
                for entry in source.audit_trail()
                if entry.memo.startswith("interlock:") and entry.entry_type in _REVERSE_ANCHOR_TYPES
            )

    def close(self) -> None:
        if self._audit is not None:
            self._audit.close()
            self._audit = None


class JoinedCommit:
    """The ledger's part in one stage's commit. Yielded by
    :meth:`LedgerAnchor.joined_commit`."""

    __slots__ = ("_scope_id", "_transaction")

    def __init__(self, transaction: JoinedTransaction, scope_id: str) -> None:
        self._transaction = transaction
        self._scope_id = scope_id

    def claim(
        self, record_hash: str, *, cost: Decimal, reservation: Authorization | None
    ) -> SettlementClaim:
        """Record the plan's settlement claim in the stage's transaction.

        Durable exactly when the stage's effects are. Redeemed, its spend
        names ``record_hash``, the plan's commit intent, and settles against
        ``reservation``.

        :raises AnchorError: If AgentGov refused the claim.
        """
        memo = f"interlock:{record_hash[:16]}"
        with _barrier(f"a settlement claim on scope {self._scope_id!r}"):
            return self._transaction.claim(self._scope_id, cost, memo=memo, hold=reservation)


def _halted(source: BudgetManager, scope_id: str) -> str | None:
    """Describe the first halt on ``scope_id``'s path to its root, if any.

    A scope AgentGov does not know is not halted by it.

    :returns: ``"'scope' (reported by 'tripped scope': reason)"``, or ``None``.
    """
    try:
        path = (scope_id, *source.ancestry(scope_id))
    except AgentGovError:
        path = (scope_id,)
    for candidate in path:
        try:
            halted_by = source.halted_by(candidate)
        except AgentGovError:
            continue
        if halted_by is not None:
            reason = next(
                (
                    event.reason
                    for event in reversed(source.control_events)
                    if event.scope_id == halted_by and event.event_type == "circuit_tripped"
                ),
                "",
            )
            because = f": {reason}" if reason else ""
            return f"{candidate!r} (reported by {halted_by!r}{because})"
    return None
