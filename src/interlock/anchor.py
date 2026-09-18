"""The AgentGov seam.

Interlock imports ``agentgov`` as a read-only audit dependency. The dependency
runs one way only: ``interlock -> agentgov``, never the reverse. Interlock does
not subclass ``Ledger`` or ``BudgetManager``, does not touch a private name, and
does not require any change to AgentGov.

Two modes:

*Audit* opens the ledger with ``read_only=True``. That takes no advisory file
lock, so it can attach while a governor process is actively writing. A write
through this handle raises ``ReadOnlyLedgerError``, which is a bug in Interlock
rather than a condition to handle.

*Governed* additionally holds a write-capable manager, which lets Interlock
write its own chain head into the ``memo`` of the ledger entries a plan causes.
Because ``memo`` is part of AgentGov's own hash payload, that reverse anchor is
tamper-evident inside AgentGov's chain, and the two chains interlock in both
directions. This uses only the public ``authorize(memo=)`` / ``capture(memo=)``
surface.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path

from agentgov.core import BudgetManager, EntryType, LedgerEntry
from agentgov.exceptions import AgentGovError, LedgerIntegrityError

from interlock.exceptions import LedgerUnverifiedError, ScopeHaltedError
from interlock.types import GENESIS_HASH

__all__ = ["AnchorPoint", "LedgerAnchor"]


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
    :raises LedgerUnverifiedError: If the ledger exists but fails verification.
    """

    __slots__ = ("_audit", "_governed")

    def __init__(
        self,
        audit_path: str | Path | None = None,
        *,
        governed: BudgetManager | None = None,
    ) -> None:
        self._governed = governed
        self._audit: BudgetManager | None = None
        if audit_path is None:
            return
        path = Path(audit_path)
        if not path.is_file():
            raise LedgerUnverifiedError(f"no AgentGov ledger at {path}")
        try:
            manager = BudgetManager.open_sqlite(str(path), read_only=True)
        except AgentGovError as exc:
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

    def observe(self) -> AnchorPoint:
        """Read AgentGov's current head position."""
        source = self._audit or self._governed
        if source is None:
            return AnchorPoint.unanchored()
        entries = source.ledger.entries()
        return AnchorPoint(
            anchored=True,
            head_hash=source.ledger.head_hash,
            sequence=entries[-1].sequence if entries else 0,
        )

    def assert_scope_live(self, scope_id: str) -> None:
        """Refuse if AgentGov's breaker has tripped for this scope or an ancestor.

        Called immediately before commit rather than at admission, because the
        staging window is where a trip has to be observed. AgentGov's breaker
        latches, so the read does not race a reset.

        :raises ScopeHaltedError: If the scope or any ancestor is halted.
        """
        source = self._audit or self._governed
        if source is None:
            return
        try:
            chain = (scope_id, *source.ancestry(scope_id))
        except AgentGovError:
            chain = (scope_id,)
        for candidate in chain:
            try:
                halted_by = source.halted_by(candidate)
            except AgentGovError:
                continue
            if halted_by is not None:
                raise ScopeHaltedError(
                    f"AgentGov has halted {candidate!r} (reported by {halted_by!r}); "
                    f"refusing to commit staged effects for scope {scope_id!r}"
                )

    def verify(self) -> None:
        """Re-verify the attached ledger.

        :raises LedgerUnverifiedError: If the chain or conservation fails.
        """
        source = self._audit or self._governed
        if source is None:
            return
        try:
            source.verify_integrity()
        except LedgerIntegrityError as exc:
            raise LedgerUnverifiedError(str(exc)) from exc

    def reverse_anchor(
        self,
        scope_id: str,
        record_hash: str,
        *,
        cost: Decimal | str = "0",
    ) -> LedgerEntry | None:
        """Write an Interlock chain head into AgentGov's chain.

        The memo is inside AgentGov's hash payload, so once written the reverse
        anchor cannot be edited without breaking AgentGov's own verification.
        That is the upper time bound one-way anchoring does not give.

        :param cost: Amount to settle. A zero-cost plan still anchors, by
            authorizing and capturing zero.
        :returns: The settled entry, or ``None`` when not co-resident.
        """
        if self._governed is None:
            return None
        memo = f"interlock:{record_hash[:16]}"
        amount = Decimal(cost) if not isinstance(cost, Decimal) else cost
        authorization = self._governed.authorize(scope_id, amount, memo=memo)
        return self._governed.capture(authorization, amount, memo=memo)

    def find_reverse_anchors(self) -> tuple[LedgerEntry, ...]:
        """Every AgentGov entry carrying an Interlock reverse anchor."""
        source = self._audit or self._governed
        if source is None:
            return ()
        return tuple(
            entry
            for entry in source.audit_trail()
            if entry.memo.startswith("interlock:") and entry.entry_type is EntryType.SPEND
        )

    def close(self) -> None:
        if self._audit is not None:
            self._audit.close()
            self._audit = None
