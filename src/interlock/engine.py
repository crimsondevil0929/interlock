"""The escrow state machine.

    PLANNED -> STAGING -> STAGED -> VERIFIED  -> COMMITTED
                                 \\-> REJECTED -> ABORTED

Two properties hold by construction:

1. There is no path from ``STAGED`` to ``COMMITTED`` that skips adjudication.
   The engine exposes no commit that has not been through ``check``.
2. ``REJECTED`` is not overridable in-process. Overriding means submitting a
   new plan that carries an explicit waiver, which is then itself a recorded
   artifact rather than a flag somebody flipped.

What does NOT hold, stated here because the ordering is easy to assume:

3. The chain record is not write-ahead. ``COMMITTED`` is appended after
   ``substrate.commit()`` returns, so a crash in that window leaves a durable
   effect with no ``COMMITTED`` record. Recovering that case needs an intent
   record written before the commit plus a startup scan for intents with no
   outcome, and neither exists. Both chains are append-only, so the missing
   record cannot be backfilled honestly after the fact.

Scope: adjudication reads the measured diff, and the diff covers exactly the
tables the substrate was configured to observe. ``admit`` checks
``Effect.target`` against that set, but ``target`` is a label the agent
supplies and is never compared against the statement, so a statement writing
an unobserved table executes and is measured as nothing. Constrain what the
substrate's connection can reach; do not rely on this layer for containment.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal

from interlock.anchor import AnchorPoint, LedgerAnchor
from interlock.chain import EscrowChain, RecordType
from interlock.exceptions import (
    AdmissionError,
    CyclicPlanError,
    PlanError,
    ScopeHaltedError,
    UncompensatableEffectError,
)
from interlock.invariants import InvariantChecker
from interlock.substrate import ShadowSubstrate
from interlock.types import (
    EffectDiff,
    EffectOutcome,
    EffectPlan,
    InvariantViolation,
    Severity,
    StageHandle,
    StageState,
    Verdict,
)

__all__ = ["EscrowEngine", "StageResult"]

logger = logging.getLogger("interlock.engine")


@dataclass(frozen=True, slots=True)
class StageResult:
    """Everything that happened to one plan.

    Returned whether the plan committed or was refused. A refusal carries the
    full diff and verdict, which is what an operator needs to see what the
    plan would have done.
    """

    plan: EffectPlan
    state: StageState
    diff: EffectDiff | None
    verdict: Verdict | None
    outcomes: tuple[EffectOutcome, ...]
    chain_head: str
    anchored_to: str
    committed: bool

    @property
    def blocked_by(self) -> tuple[str, ...]:
        if self.verdict is None:
            return ()
        return tuple(v.invariant for v in self.verdict.blocking)


class EscrowEngine:
    """Stages a plan, measures it, adjudicates it, then commits or rolls back.

    :param substrate: The backend driver.
    :param checkers: Deterministic predicates. Run in full; the engine does not
        short-circuit on the first blocking result, so a refused plan reports
        every reason at once.
    :param chain: Tamper-evident record chain. Defaults to an in-memory chain,
        which is lost when the process exits; pass ``EscrowChain(path)`` in
        production.
    :param anchor: The AgentGov seam. Optional; records written without one are
        flagged ``anchored=False``.
    :param settle_cost: Amount to settle when writing a reverse anchor into
        AgentGov, representing what the plan cost to produce. Must be
        positive to enable reverse anchoring: AgentGov has no zero-value entry
        that can carry a memo, so there is nothing to write the chain head
        into. The default of ``"0"`` therefore means forward anchoring only,
        and ``StageResult.anchored_to`` is empty. Pass the plan's real cost to
        get the bidirectional anchor.
    """

    __slots__ = ("_anchor", "_chain", "_checkers", "_settle_cost", "_substrate")

    def __init__(
        self,
        substrate: ShadowSubstrate,
        *,
        checkers: Sequence[InvariantChecker],
        chain: EscrowChain | None = None,
        anchor: LedgerAnchor | None = None,
        settle_cost: Decimal | str = "0",
    ) -> None:
        self._substrate = substrate
        self._checkers = tuple(checkers)
        self._chain = chain if chain is not None else EscrowChain()
        self._anchor = anchor
        self._settle_cost = (
            settle_cost if isinstance(settle_cost, Decimal) else Decimal(settle_cost)
        )

    @property
    def chain(self) -> EscrowChain:
        return self._chain

    # -- admission ----------------------------------------------------------

    def admit(self, plan: EffectPlan) -> None:
        """Validate a plan before anything is touched.

        :raises CyclicPlanError: On a dependency cycle or unknown dependency.
        :raises UncompensatableEffectError: If an irreversible effect arrived
            without a serialized undo.
        :raises PlanError: If an effect's declared ``target`` names a substrate
            other than the one this engine holds, or a table that substrate
            does not observe. Both checks read the label, not the statement: a
            statement writing an unobserved table is not caught here and will
            not appear in the diff.
        """
        try:
            plan.topological_order()
        except ValueError as exc:
            raise CyclicPlanError(str(exc)) from exc

        capabilities = self._substrate.capabilities
        for effect in plan.effects:
            if not effect.reversible and effect.compensation is None:
                raise UncompensatableEffectError(
                    f"effect {effect.effect_id!r} is irreversible and carries no "
                    f"compensation; the undo has to be serialized before the "
                    f"effect is staged"
                )
            if capabilities.requires_compensation and effect.compensation is None:
                raise UncompensatableEffectError(
                    f"substrate {self._substrate.substrate_id!r} cannot roll back; "
                    f"effect {effect.effect_id!r} needs a compensation"
                )

        # Effect.target is "<substrate_id>:<table>". Unvalidated, an effect
        # labelled for another substrate is applied to this one, because
        # apply() only ever uses the substrate the engine was built with.
        expected = self._substrate.substrate_id
        foreign = sorted(
            {e.substrate_id for e in plan.effects if e.substrate_id and e.substrate_id != expected}
        )
        if foreign:
            raise PlanError(
                f"plan targets substrate(s) {', '.join(foreign)} but this engine holds "
                f"{expected!r}; one engine stages one substrate, and a cross-substrate "
                f"plan needs 2PC or a saga rather than silent routing"
            )

        observed: frozenset[str] | None = getattr(self._substrate, "observed_tables", None)
        if observed is not None:
            unseen = sorted({e.table for e in plan.effects} - observed)
            if unseen:
                raise PlanError(
                    f"plan targets unobserved table(s): {', '.join(unseen)}; "
                    f"mutations there would not appear in the diff"
                )

    # -- the main path ------------------------------------------------------

    def execute(self, plan: EffectPlan) -> StageResult:
        """Run one plan through the full lifecycle.

        A refusal is a normal return with ``committed=False``, not an
        exception. Use :meth:`execute_or_raise` when a refusal should raise.

        :returns: The outcome, including the diff and verdict, whether or not
            the plan committed.
        """
        self.admit(plan)
        self._record(RecordType.PLAN_ADMITTED, plan, plan.content_hash(), note=plan.intent[:80])

        handle = self._substrate.open(plan)
        outcomes: list[EffectOutcome] = []
        diff: EffectDiff | None = None
        verdict: Verdict | None = None
        state = StageState.STAGING
        committed = False

        try:
            self._record(RecordType.STAGE_OPENED, plan, plan.content_hash(), stage=handle.stage_id)
            for effect in plan.topological_order():
                outcomes.append(self._substrate.apply(handle, effect))
            state = StageState.STAGED

            diff = self._substrate.diff(handle)
            self._record(
                RecordType.DIFF_COMPUTED,
                plan,
                diff.content_hash(),
                stage=handle.stage_id,
                note=f"{diff.blast_radius} rows, {diff.tenant_count} tenant(s)",
            )

            verdict = self._adjudicate(plan, diff, handle)
            blocked = ",".join(v.invariant for v in verdict.blocking)
            self._record(
                RecordType.VERDICT,
                plan,
                verdict.content_hash(),
                stage=handle.stage_id,
                note="admitted" if verdict.admitted else blocked,
            )

            if not verdict.admitted:
                self._substrate.abort(handle)
                self._record(
                    RecordType.ABORTED,
                    plan,
                    verdict.content_hash(),
                    stage=handle.stage_id,
                    note=f"blocked by {blocked}",
                )
                state = StageState.ABORTED
            else:
                state = StageState.VERIFIED
                # Re-read the breaker immediately before commit. The window
                # between staging and commit is exactly where a trip matters,
                # and AgentGov's breaker latches, so this is a stable read.
                if self._anchor is not None:
                    self._anchor.assert_scope_live(plan.scope_id)
                self._substrate.commit(handle)
                committed = True
                state = StageState.COMMITTED
                self._record(
                    RecordType.COMMITTED,
                    plan,
                    diff.content_hash(),
                    stage=handle.stage_id,
                    note=f"{diff.blast_radius} rows committed",
                )
        except ScopeHaltedError as exc:
            self._substrate.abort(handle)
            state = StageState.ABORTED
            self._record(
                RecordType.ABORTED,
                plan,
                diff.content_hash() if diff is not None else plan.content_hash(),
                stage=handle.stage_id,
                note=f"scope halted: {exc}",
            )
        except Exception:
            self._substrate.abort(handle)
            self._record(
                RecordType.ABORTED,
                plan,
                plan.content_hash(),
                stage=handle.stage_id,
                note="stage failed",
            )
            raise
        finally:
            self._substrate.close(handle)

        head = self._chain.head_hash
        return StageResult(
            plan=plan,
            state=state,
            diff=diff,
            verdict=verdict,
            outcomes=tuple(outcomes),
            chain_head=head,
            anchored_to=self._reverse_anchor(plan, head),
            committed=committed,
        )

    def execute_or_raise(self, plan: EffectPlan) -> StageResult:
        """As :meth:`execute`, but raise :class:`AdmissionError` on refusal."""
        result = self.execute(plan)
        if result.verdict is not None and not result.verdict.admitted:
            reasons = "; ".join(v.message for v in result.verdict.blocking)
            raise AdmissionError(f"plan {plan.plan_id} refused: {reasons}", verdict=result.verdict)
        return result

    # -- internals ----------------------------------------------------------

    def _adjudicate(self, plan: EffectPlan, diff: EffectDiff, handle: StageHandle) -> Verdict:
        """Run every checker and union the violations.

        A checker that raises becomes a blocking violation: a predicate that
        did not finish has not approved anything.
        """
        violations: list[InvariantViolation] = []
        names: list[str] = []
        for checker in self._checkers:
            names.append(checker.name)
            try:
                violations.extend(checker.check(plan, diff))
            except Exception as exc:  # a broken checker must never approve
                logger.exception("invariant %s raised", checker.name)
                violations.append(
                    InvariantViolation(
                        invariant=checker.name,
                        severity=Severity.BLOCKING,
                        message=f"checker raised {type(exc).__name__}: {exc}",
                    )
                )
        return Verdict(
            plan_id=plan.plan_id,
            stage_id=handle.stage_id,
            diff_hash=diff.content_hash(),
            decided_at=datetime.now(UTC),
            checkers_run=tuple(names),
            violations=tuple(violations),
        )

    def _record(
        self,
        record_type: RecordType,
        plan: EffectPlan,
        payload_hash: str,
        *,
        stage: uuid.UUID | None = None,
        note: str = "",
    ) -> None:
        point = self._anchor.observe() if self._anchor is not None else AnchorPoint.unanchored()
        self._chain.append(
            record_type,
            plan_id=plan.plan_id,
            payload_hash=payload_hash,
            stage_id=stage,
            anchored=point.anchored,
            agentgov_head_hash=point.head_hash,
            agentgov_sequence=point.sequence,
            note=note,
        )

    def _reverse_anchor(self, plan: EffectPlan, head: str) -> str:
        """Write Interlock's chain head into AgentGov, when co-resident.

        ``memo`` is inside AgentGov's hash payload, so once written the reverse
        anchor cannot be edited without breaking AgentGov's own verification.
        That is what bounds a record's time from above; see
        ``EscrowChain.verify_anchors`` for the lower bound.
        """
        # Runs after commit, so anything raised here arrives when the effects
        # are already durable and would destroy the caller's StageResult. A
        # non-positive settle cost cannot anchor at all (see
        # LedgerAnchor.reverse_anchor), so it is treated as "not configured"
        # rather than attempted and thrown from the commit path.
        if self._anchor is None or not self._anchor.can_reverse_anchor:
            return ""
        if self._settle_cost <= 0:
            return ""
        entry = self._anchor.reverse_anchor(plan.scope_id, head, cost=self._settle_cost)
        return entry.entry_hash if entry is not None else ""
