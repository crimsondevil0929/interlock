"""The batteries-included entry point.

Wiring Interlock by hand means constructing a substrate, a chain, an anchor
and an engine in a specific order, knowing that the governor's scope has to
exist before the anchor is built and that the anchor has to exist before the
engine is. That order is load-bearing and was, until this module, folklore.

``EscrowRuntime`` owns all four::

    runtime = EscrowRuntime(
        db_path="support.db",
        tables=[TableSpec("orders", columns=["id", "tenant", "total"],
                          tenant_column="tenant")],
        scope_id="support-agent",
        checkers=[TenantIsolation(1), BlastRadius(8)],
    )
    result = runtime.execute_sql(
        "UPDATE orders SET total = :total WHERE id = :id",
        {"total": 100.0, "id": 1},
        table="orders",
        tenant_id="acme",
        stated_rows=1,
    )

Attach a governor with ``governed=manager`` and the same runtime writes
bidirectional anchors. Nothing else changes.
"""

from __future__ import annotations

from collections.abc import Sequence
from decimal import Decimal
from pathlib import Path
from types import TracebackType

from interlock.anchor import LedgerAnchor
from interlock.builder import PlanBuilder
from interlock.cascade import CascadeReport
from interlock.chain import EscrowChain, EscrowRecord
from interlock.engine import EscrowEngine, StageResult
from interlock.invariants import InvariantChecker, default_checkers
from interlock.receipts import ReceiptIssuer
from interlock.repair import Repair
from interlock.substrate import SqliteSubstrate, TableSpec
from interlock.types import EffectKind, EffectPlan

__all__ = ["EscrowRuntime"]


class EscrowRuntime:
    """A configured escrow: substrate, chain, anchor and engine in one object.

    :param db_path: The SQLite database to stage against.
    :param tables: Tables to observe. Writes outside this set are denied by
        the substrate's authorizer unless ``enforce_table_access=False``.
    :param scope_id: Default AgentGov scope for plans this runtime builds.
    :param checkers: Invariants to adjudicate with. Defaults to
        ``default_checkers``, whose thresholds are **uncalibrated
        placeholders** — measure your own diffs and pass your own.
    :param chain_path: Where to persist the escrow chain. ``None`` keeps the
        chain in memory, which is lost when the process exits. An existing
        chain is resumed, verified, and claimed for this runtime until
        :meth:`close`; any commit a crashed predecessor left unresolved is
        then resolved from the substrate's commit marker (see
        :attr:`recovered`).
    :param governed: A live, write-capable ``BudgetManager``. Supplying it
        enables reverse anchoring into AgentGov.
    :param audit_path: Path to a governor ledger to read-only anchor against,
        when this process is not the one governing it.
    :param settle_cost: Cost charged to ``scope_id`` per plan when reverse
        anchoring. The default ``"0"`` writes a free ``ANCHOR`` entry.
        Overridable per call.
    :param max_stage_seconds: Bound on stage lifetime; a stage holds write
        locks for its whole life.
    :param enforce_table_access: Deny row mutations outside ``tables`` inside
        SQLite itself. On by default.
    :param acknowledge_cascades: Unobserved tables a foreign-key action may
        write, unmeasured. See :class:`SqliteSubstrate`.
    :param receipts: Issue a signed ARC1 receipt for every adjudicated plan,
        committed or refused. See :mod:`interlock.receipts`.

    Construction runs the cascade check against the database (see
    :attr:`cascade_report`), so the database must exist: an operation whose
    foreign-key actions reach an unobserved table is logged at startup and
    refused when staged, unless the table is acknowledged.
    """

    __slots__ = (
        "_anchor",
        "_chain",
        "_engine",
        "_recovered",
        "_scope_id",
        "_settle_cost",
        "_substrate",
    )

    def __init__(
        self,
        db_path: str | Path,
        *,
        tables: Sequence[TableSpec],
        scope_id: str,
        checkers: Sequence[InvariantChecker] | None = None,
        chain_path: str | Path | None = None,
        governed: object | None = None,
        audit_path: str | Path | None = None,
        settle_cost: Decimal | str = "0",
        max_stage_seconds: float = 10.0,
        max_diff_rows: int = 50_000,
        enforce_table_access: bool = True,
        acknowledge_cascades: Sequence[str] = (),
        receipts: ReceiptIssuer | None = None,
    ) -> None:
        self._scope_id = scope_id
        self._settle_cost = Decimal(str(settle_cost))
        self._substrate = SqliteSubstrate(
            str(db_path),
            tables=tables,
            max_stage_seconds=max_stage_seconds,
            max_diff_rows=max_diff_rows,
            enforce_table_access=enforce_table_access,
            acknowledge_cascades=acknowledge_cascades,
        )
        # The cascade check at setup: a misconfigured boundary is reported
        # when the runtime starts, not when the first delete is refused.
        self._substrate.check_cascades()
        self._anchor: LedgerAnchor | None = None
        if governed is not None or audit_path is not None:
            self._anchor = LedgerAnchor(audit_path, governed=governed)  # type: ignore[arg-type]
        if checkers is None:
            checkers = default_checkers(
                row_limit=max_diff_rows,
                allowed_tables=[t.name for t in tables],
            )
        try:
            self._chain = EscrowChain(chain_path) if chain_path is not None else EscrowChain()
            try:
                self._engine = EscrowEngine(
                    self._substrate,
                    checkers=checkers,
                    chain=self._chain,
                    anchor=self._anchor,
                    settle_cost=self._settle_cost,
                    receipts=receipts,
                )
                self._recovered = self._engine.recover() if chain_path is not None else ()
            except BaseException:
                self._chain.close()
                raise
        except BaseException:
            if self._anchor is not None:
                self._anchor.close()
            raise

    # -- accessors -------------------------------------------------------

    @property
    def engine(self) -> EscrowEngine:
        """The underlying engine, for callers that need the primitive."""
        return self._engine

    @property
    def chain(self) -> EscrowChain:
        return self._chain

    @property
    def anchor(self) -> LedgerAnchor | None:
        return self._anchor

    @property
    def substrate(self) -> SqliteSubstrate:
        return self._substrate

    @property
    def cascade_report(self) -> CascadeReport | None:
        """The foreign-key reach out of ``tables``: what is gated, what is
        acknowledged. Refreshed whenever a stage sees a schema change."""
        return self._substrate.cascade_report

    @property
    def recovered(self) -> tuple[EscrowRecord, ...]:
        """Records appended at startup resolving a crashed predecessor's commits."""
        return self._recovered

    def plan(self, *, intent: str = "", trajectory_id: str | None = None) -> PlanBuilder:
        """A builder pre-bound to this runtime's scope."""
        return PlanBuilder(self._scope_id, trajectory_id=trajectory_id, intent=intent)

    # -- the write path --------------------------------------------------

    def execute(self, plan: EffectPlan, *, settle_cost: Decimal | str | None = None) -> StageResult:
        """Stage, measure, adjudicate and commit or roll back one plan."""
        return self._engine.execute(plan, settle_cost=settle_cost)

    def repair(self, plan: EffectPlan, *, max_trials: int = 32) -> Repair:
        """The largest part of a refused plan that would be admitted, found by
        staging candidates in savepoints. Advisory: nothing is committed. See
        :meth:`EscrowEngine.repair`."""
        return self._engine.repair(plan, max_trials=max_trials)

    def execute_sql(
        self,
        statement: str,
        parameters: dict[str, object] | None = None,
        *,
        table: str | None = None,
        tenant_id: str | None = None,
        stated_rows: int | None = None,
        kind: EffectKind = EffectKind.UPDATE,
        intent: str = "",
        settle_cost: Decimal | str | None = None,
    ) -> StageResult:
        """Build a one-effect plan from a statement and run it.

        The single-mutation case, which is most of them, in one call.

        :param table: The table the statement writes. Defaults to the single
            observed table when there is exactly one, and is required
            otherwise, because ``Effect.target`` is what admission checks.
        :param stated_rows: What the caller believes this touches. Recorded so
            ``StatedFootprint`` can compare the claim against the measurement;
            omitting it on any effect turns that checker into a no-op.
        :returns: The full :class:`StageResult`, committed or rolled back.
        :raises PlanError: If ``table`` is absent and cannot be inferred, or
            the statement uses a positional placeholder.
        """
        if table is None:
            observed = sorted(self._substrate.observed_tables)
            if len(observed) != 1:
                from interlock.exceptions import PlanError

                raise PlanError(
                    f"table= is required when the substrate observes more than one "
                    f"table (observes: {', '.join(observed) or '<none>'})"
                )
            table = observed[0]
        plan = (
            self.plan(intent=intent or statement[:80])
            .add(
                kind,
                table=table,
                statement=statement,
                parameters=parameters,
                tenant_id=tenant_id,
                stated_rows=stated_rows,
            )
            .build()
        )
        return self.execute(plan, settle_cost=settle_cost)

    # -- verification ----------------------------------------------------

    def verify(self) -> None:
        """Re-derive every record this runtime has written.

        :raises ChainIntegrityError: If Interlock's own chain fails.
        :raises AnchorError: If the anchored AgentGov chain fails.
        """
        self._chain.verify()
        self._chain.verify_anchors()
        if self._anchor is not None:
            self._anchor.verify()

    def close(self) -> None:
        """Release the chain file and the anchor's read-only ledger handle.

        The substrate holds no connection between stages, so there is nothing
        else to release. Idempotent.
        """
        self._chain.close()
        if self._anchor is not None:
            self._anchor.close()

    def __enter__(self) -> EscrowRuntime:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()
