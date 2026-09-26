"""The escrow state machine.

    PLANNED -> STAGING -> STAGED -> VERIFIED  -> COMMITTED
                                 \\-> REJECTED -> ABORTED

Two properties hold by construction:

1. There is no path from ``STAGED`` to ``COMMITTED`` that skips adjudication.
   The engine exposes no commit that has not been through ``check``.
2. ``REJECTED`` is not overridable in-process. Overriding means submitting a
   new plan that carries an explicit waiver, which is then itself a recorded
   artifact rather than a flag somebody flipped.

3. A committed effect is always discoverable from the chain.
   ``COMMIT_INTENT`` is appended before the substrate is told to commit and
   ``COMMITTED`` after it returns, so a crash in that window leaves an intent
   with no terminal record. :meth:`EscrowChain.unresolved_intents` reads them
   back.

4. A crashed commit is resolved exactly, not guessed. An intent says a commit
   was *attempted*. The substrate writes a commit marker inside the stage's
   own transaction, so the marker exists if and only if the effects do, and
   :meth:`EscrowEngine.recover` reads it for every intent a crashed process
   left open and appends what actually happened. The intent records that the
   marker was armed; an intent without that (written before v0.1.2, or by a
   substrate with no marker) is left open for an operator rather than
   resolved by guesswork. A commit whose answer is lost while the process
   lives (the connection drops with ``COMMIT`` in flight) is put to the same
   marker at once, and left open, not guessed, while the server has not
   decided.

Scope: adjudication reads the measured diff, and the diff covers exactly the
tables the substrate was configured to observe. ``admit`` checks
``Effect.target`` against that set, but ``target`` is a label the agent
supplies and is never compared against the statement, so a statement writing
an unobserved table executes and is measured as nothing. Constrain what the
substrate's connection can reach; do not rely on this layer for containment.
"""

from __future__ import annotations

import logging
import re
import threading
import uuid
from collections.abc import Iterator, Sequence
from contextlib import AbstractContextManager, contextmanager, nullcontext
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from typing import TYPE_CHECKING

from agentgov.core import EntryType, LedgerEntry

from interlock.adjudication import Adjudication, adjudicate
from interlock.anchor import AnchorPoint, LedgerAnchor
from interlock.builder import new_plan_id
from interlock.cascade import CascadeReport
from interlock.chain import EscrowChain, EscrowRecord, RecordType
from interlock.exceptions import (
    AdmissionError,
    AnchorError,
    CommitUnsettledError,
    CyclicPlanError,
    ForbiddenStatementError,
    InterlockError,
    PlanError,
    ScopeHaltedError,
    StageError,
    SubstrateUnavailableError,
    UncompensatableEffectError,
)
from interlock.feedback import AgentFeedback, OperatorEvidence, Refusal, feedback_for_error
from interlock.invariants import InvariantChecker
from interlock.repair import Repair, Trial, dropped_effects, search, subplan
from interlock.substrate import ShadowSubstrate, _verb_reason
from interlock.types import (
    Effect,
    EffectDiff,
    EffectId,
    EffectOutcome,
    EffectPlan,
    PlanId,
    StageHandle,
    StageState,
    Verdict,
)

if TYPE_CHECKING:
    from agentgov.receipts import ActionReceipt

    from interlock.receipts import ReceiptIssuer

__all__ = ["EscrowEngine", "StageResult"]

logger = logging.getLogger("interlock.engine")

_GAPS = "unmeasured cascades acknowledged: "
"""Prefix on a ``STAGE_OPENED`` note naming each foreign-key reach into an
unobserved table the operator accepted. The stage's diff does not cover those
rows, and the chain says so for the stage it applies to."""

_TXID = "; txid "
"""Infix on a ``COMMIT_INTENT`` note carrying the substrate's own transaction
id, when it has one (PostgreSQL's ``pg_current_xact_id()``). Recovery hands it
back to the substrate, which can then tell a transaction still running on the
server from one that rolled back."""

_TXID_PATTERN = re.compile(r"; txid ([0-9]+)(?:;|$)")

_MARKER_ARMED = "; commit marker armed"
"""Suffix on a ``COMMIT_INTENT`` note: the substrate writes a commit marker
inside this stage's transaction, so :meth:`EscrowEngine.recover` may read the
marker's absence as "did not commit". The note is inside the record hash."""

_SAVEPOINT = "ilok_repair"
"""The savepoint a repair search returns to between candidates."""

_REPAIRS_RECEIPT = re.compile(r"; repairs receipt ([0-9a-f-]{36})")
"""Suffix on a ``REPAIR_PROPOSED`` note naming the refused plan's receipt,
which the proposal's own receipt will carry as ``repair_of``."""


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
    feedback: AgentFeedback | None = None
    """What the agent may be told. The diff and verdict above are the
    operator's: they name other tenants and exact totals. See
    :mod:`interlock.feedback`."""
    receipt: ActionReceipt | None = None
    """The signed ARC1 receipt, when the engine issues receipts and the plan
    was adjudicated. ``None`` also when issuing it failed after a commit, which
    is logged: the effects stand, and the terminal record names the receipt id
    that was meant to exist."""

    @property
    def blocked_by(self) -> tuple[str, ...]:
        if self.verdict is None:
            return ()
        return tuple(v.invariant for v in self.verdict.blocking)

    @property
    def refusal(self) -> Refusal | None:
        """The refusal split by audience, or ``None`` when the plan committed."""
        if self.committed or self.feedback is None:
            return None
        return Refusal(
            evidence=OperatorEvidence.of(self.plan, diff=self.diff, verdict=self.verdict),
            feedback=self.feedback,
        )


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
    :param settle_cost: What a plan cost to produce, charged to its scope
        when writing the reverse anchor into a governed AgentGov. The default
        of ``"0"`` writes a zero-value ``ANCHOR`` entry: the reverse anchor is
        free. A positive cost is settled, and the spend carries the anchor.
    :param receipts: Issue a signed ARC1 receipt for every adjudicated plan,
        committed or refused. See :mod:`interlock.receipts`.
    :raises ValueError: If ``settle_cost`` is negative, or ``chain`` is a
        read-only snapshot from :meth:`EscrowChain.load`.
    """

    __slots__ = (
        "_anchor",
        "_chain",
        "_checkers",
        "_claims",
        "_claims_lock",
        "_inflight",
        "_receipts",
        "_settle_cost",
        "_substrate",
    )

    def __init__(
        self,
        substrate: ShadowSubstrate,
        *,
        checkers: Sequence[InvariantChecker],
        chain: EscrowChain | None = None,
        anchor: LedgerAnchor | None = None,
        settle_cost: Decimal | str = "0",
        receipts: ReceiptIssuer | None = None,
    ) -> None:
        self._substrate = substrate
        self._receipts = receipts
        self._checkers = tuple(checkers)
        self._chain = chain if chain is not None else EscrowChain()
        if self._chain.read_only:
            raise ValueError(
                "EscrowChain.load() returns a read-only snapshot; pass EscrowChain(path) "
                "to resume appending to the file"
            )
        self._anchor = anchor
        self._settle_cost = (
            settle_cost if isinstance(settle_cost, Decimal) else Decimal(settle_cost)
        )
        if self._settle_cost < 0:
            raise ValueError(f"settle_cost cannot be negative, got {self._settle_cost}")
        self._inflight: set[uuid.UUID] = set()
        self._claims: set[PlanId] = set()
        self._claims_lock = threading.Lock()

    @property
    def chain(self) -> EscrowChain:
        return self._chain

    @property
    def receipts(self) -> ReceiptIssuer | None:
        return self._receipts

    # -- admission ----------------------------------------------------------

    def admit(self, plan: EffectPlan) -> None:
        """Validate a plan before anything is touched.

        :raises CyclicPlanError: On a dependency cycle or unknown dependency.
        :raises ForbiddenStatementError: If the substrate refuses the statement
            itself. Read from the SQL, not from ``Effect.kind``.
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

        # The substrate vets the statement text. Done at admission so a plan
        # it would refuse never opens a connection or takes a write lock; the
        # substrate re-checks in apply() for callers who skip the engine.
        veto = getattr(self._substrate, "reject_reason", None)
        if callable(veto):
            for effect in plan.effects:
                refusal = veto(effect)
                if refusal is not None:
                    raise ForbiddenStatementError(
                        f"effect {effect.effect_id!r} refused: {refusal}",
                        reason=_verb_reason(effect),
                    )

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

        # The reverse anchor is written after commit, where a failure arrives
        # on top of durable effects. Validate the scope now, while refusing
        # still costs nothing.
        if self._anchor is not None:
            self._anchor.assert_scope_known(plan.scope_id)

    # -- the main path ------------------------------------------------------

    def execute(self, plan: EffectPlan, *, settle_cost: Decimal | str | None = None) -> StageResult:
        """Run one plan through the full lifecycle.

        A refusal is a normal return with ``committed=False``, not an
        exception. Use :meth:`execute_or_raise` when a refusal should raise.
        Either way, what the agent may be told is on the result's, or the
        exception's, ``feedback``.

        :param settle_cost: Overrides the engine's configured settle cost for
            this plan only. What a plan cost to produce is a property of the
            plan, not of the engine that stages it, so an engine-wide constant
            forces either a flat rate for every plan or a new engine per plan.
            ``None`` keeps the configured value.
        :returns: The outcome, including the diff and verdict, whether or not
            the plan committed.
        :raises InterlockError: And only ``InterlockError``, carrying
            ``feedback`` for the agent. Foreign exceptions from the AgentGov
            seam are translated at the anchor.
        :raises CommitUnsettledError: If the connection was lost with
            ``COMMIT`` in flight and the server has not decided yet. Do not
            retry the plan: its intent stays open, and :meth:`recover`
            settles it.
        """
        try:
            with self._repair_claim(plan) as repairs:
                return self._execute(plan, settle_cost=settle_cost, repairs=repairs)
        except InterlockError as exc:
            if exc.feedback is None:
                exc.feedback = feedback_for_error(plan, exc)
            raise

    def _execute(
        self, plan: EffectPlan, *, settle_cost: Decimal | str | None, repairs: str | None
    ) -> StageResult:
        cost = self._settle_cost if settle_cost is None else Decimal(str(settle_cost))
        if cost < 0:
            raise PlanError(f"settle_cost cannot be negative, got {cost}")
        self.admit(plan)
        self._record(
            RecordType.PLAN_ADMITTED,
            plan,
            plan.content_hash(),
            note=(f"repair of {plan.repair_of}: " if plan.repair_of else "") + plan.intent[:80],
        )
        receipt_id = self._receipts.new_id() if self._receipts is not None else None
        stamp = f"; receipt {receipt_id}" if receipt_id else ""
        terminal: EscrowRecord | None = None
        txid: str | None = None

        handle = self._substrate.open(plan)
        outcomes: list[EffectOutcome] = []
        diff: EffectDiff | None = None
        verdict: Verdict | None = None
        judged: Adjudication | None = None
        state = StageState.STAGING
        committed = False
        lost_reply = False

        try:
            self._record(
                RecordType.STAGE_OPENED,
                plan,
                plan.content_hash(),
                stage=handle.stage_id,
                note=_coverage_note(self._substrate),
            )
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

            judged = adjudicate(plan, diff, self._checkers, stage_id=handle.stage_id)
            verdict = judged.verdict
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
                terminal = self._record(
                    RecordType.ABORTED,
                    plan,
                    verdict.content_hash(),
                    stage=handle.stage_id,
                    note=f"blocked by {blocked}{stamp}",
                )
                state = StageState.ABORTED
            else:
                state = StageState.VERIFIED
                # The breaker is re-read immediately before commit, and held
                # there: the window between staging and commit is exactly
                # where a trip matters. See LedgerAnchor.guard_commit.
                guard: AbstractContextManager[None] = (
                    self._anchor.guard_commit(plan.scope_id)
                    if self._anchor is not None
                    else nullcontext()
                )
                with guard:
                    # Write-ahead. The intent lands before the substrate is
                    # told to commit, so a crash in that window leaves
                    # COMMIT_INTENT with no terminal record after it, and
                    # recover() asks the substrate's commit marker what
                    # happened. Without it the window is silent: the effect is
                    # on disk and the chain says the plan never got that far.
                    armed = bool(getattr(self._substrate, "commit_markers", False))
                    txid = _transaction_id(self._substrate, handle)
                    self._inflight.add(handle.stage_id)
                    self._record(
                        RecordType.COMMIT_INTENT,
                        plan,
                        diff.content_hash(),
                        stage=handle.stage_id,
                        note=f"about to commit {diff.blast_radius} rows"
                        + (f"{_TXID}{txid}" if txid else "")
                        + (_MARKER_ARMED if armed else ""),
                    )
                    try:
                        self._substrate.commit(handle)
                    except CommitUnsettledError as lost:
                        # The COMMIT went out and no answer came back. The
                        # marker says what the server did; it returns only
                        # if the stage committed.
                        self._settle_lost_commit(handle.stage_id, txid, armed=armed, lost=lost)
                        lost_reply = True
                    committed = True
                state = StageState.COMMITTED
                note = f"{diff.blast_radius} rows committed"
                if lost_reply:
                    note += "; the commit's reply was lost; its commit marker is present"
                raced = self._anchor.halted_after_commit(plan.scope_id) if self._anchor else ""
                terminal = self._record(
                    RecordType.COMMITTED,
                    plan,
                    diff.content_hash(),
                    stage=handle.stage_id,
                    note=(f"{note}; {raced}" if raced else note) + stamp,
                    best_effort=True,
                )
        except ScopeHaltedError as exc:
            self._substrate.abort(handle)
            state = StageState.ABORTED
            terminal = self._record(
                RecordType.ABORTED,
                plan,
                diff.content_hash() if diff is not None else plan.content_hash(),
                stage=handle.stage_id,
                note=f"scope halted: {exc}{stamp if judged is not None else ''}",
                best_effort=True,
            )
        except Exception as exc:
            if committed or isinstance(exc, CommitUnsettledError):
                # The effects are durable, and only the record of them failed;
                # or the server may still commit them. Never write ABORTED
                # over either. The intent stays open on the chain, and
                # recover() resolves it from the commit marker.
                raise
            self._substrate.abort(handle)
            self._record(
                RecordType.ABORTED,
                plan,
                plan.content_hash(),
                stage=handle.stage_id,
                note="stage failed",
                best_effort=True,
            )
            raise
        finally:
            self._inflight.discard(handle.stage_id)
            self._substrate.close(handle)

        head = self._chain.head_hash
        settlement = self._reverse_anchor(plan, head, cost)
        receipt = None
        if receipt_id is not None and judged is not None and terminal is not None:
            receipt = self._issue_receipt(
                receipt_id,
                judged,
                committed=committed,
                terminal=terminal,
                settlement=settlement,
                txid=txid,
                repair_of=repairs,
            )
        return StageResult(
            plan=plan,
            state=state,
            diff=diff,
            verdict=verdict,
            outcomes=tuple(outcomes),
            chain_head=head,
            anchored_to=settlement.entry_hash if settlement is not None else "",
            committed=committed,
            feedback=judged.feedback(committed=committed) if judged is not None else None,
            receipt=receipt,
        )

    def execute_or_raise(
        self, plan: EffectPlan, *, settle_cost: Decimal | str | None = None
    ) -> StageResult:
        """As :meth:`execute`, but raise :class:`AdmissionError` on refusal."""
        result = self.execute(plan, settle_cost=settle_cost)
        if result.verdict is not None and not result.verdict.admitted:
            # The message is the operator's; the agent gets error.feedback.
            reasons = "; ".join(v.message for v in result.verdict.blocking)
            error = AdmissionError(
                f"plan {plan.plan_id} refused: {reasons}", verdict=result.verdict
            )
            error.feedback = result.feedback
            raise error
        return result

    # -- repair -------------------------------------------------------------

    def repair(self, plan: EffectPlan, *, max_trials: int = 32) -> Repair:
        """Find the largest part of a refused plan that would be admitted.

        Stages ``plan`` once and, inside that one stage, tries candidate
        sub-plans in savepoints: every candidate is run, measured and
        adjudicated by this engine's checkers for real, then rolled back. See
        :mod:`interlock.repair` for the search and why it assumes nothing
        about which steps make a plan worse.

        Advisory. The stage is always rolled back and nothing is committed.
        A proposal is a new plan with ``repair_of`` set; submitting it through
        :meth:`execute` stages and adjudicates it again from scratch, and
        :meth:`execute` admits it only exactly as proposed. With receipts on,
        the whole plan's refusal gets a receipt here, and the proposal's
        receipt will name it as ``repair_of``.

        Effects the substrate would refuse outright (a DDL statement, a table
        it does not observe) are dropped before staging, with everything that
        depends on them.

        :param max_trials: The most candidates staged, the whole plan
            included. Each costs one statement per effect it keeps.
        :returns: The proposal, if any, and why each dropped step was dropped.
        :raises InterlockError: With ``feedback`` for the agent.
        """
        try:
            return self._repair(plan, max_trials=max_trials)
        except InterlockError as exc:
            if exc.feedback is None:
                exc.feedback = feedback_for_error(plan, exc)
            raise

    def _repair(self, plan: EffectPlan, *, max_trials: int) -> Repair:
        if max_trials < 1:
            raise ValueError("a repair needs at least one trial")
        for method in ("savepoint", "rollback_to"):
            if not callable(getattr(self._substrate, method, None)):
                raise StageError(
                    f"substrate {self._substrate.substrate_id!r} cannot set savepoints, "
                    f"which a repair search needs"
                )
        try:
            plan.topological_order()
        except ValueError as exc:
            raise CyclicPlanError(str(exc)) from exc
        if self._anchor is not None:
            self._anchor.assert_scope_known(plan.scope_id)

        inadmissible: dict[EffectId, InterlockError] = {}
        for effect in plan.effects:
            problem = self._effect_problem(effect)
            if problem is not None:
                inadmissible[effect.effect_id] = problem
        candidates = _without(plan, set(inadmissible))
        if not candidates.effects:
            return Repair(
                plan=plan,
                proposal=None,
                already_admissible=False,
                kept=(),
                dropped=dropped_effects(plan, frozenset(), {}, inadmissible),
                trials=0,
                exhaustive=True,
            )

        receipt_id = self._receipts.new_id() if self._receipts is not None else None
        handle = self._substrate.open(candidates)
        whole: Adjudication | None = None
        terminal: EscrowRecord | None = None
        proposal: EffectPlan | None = None
        try:
            self._record(
                RecordType.STAGE_OPENED,
                plan,
                plan.content_hash(),
                stage=handle.stage_id,
                note=("repair search; " + _coverage_note(self._substrate)).rstrip("; "),
            )
            savepoint = getattr(self._substrate, "savepoint")  # noqa: B009
            rollback_to = getattr(self._substrate, "rollback_to")  # noqa: B009
            savepoint(handle, _SAVEPOINT)

            def evaluate(kept: frozenset[EffectId]) -> Trial:
                sub = subplan(candidates, kept)
                rollback_to(handle, _SAVEPOINT)
                try:
                    for effect in sub.topological_order():
                        self._substrate.apply(handle, effect)
                    diff = self._substrate.diff(handle)
                except SubstrateUnavailableError:
                    raise
                except InterlockError as exc:
                    return Trial(kept=kept, admitted=False, error=exc)
                judged = adjudicate(sub, diff, self._checkers, stage_id=handle.stage_id)
                return Trial(kept=kept, admitted=judged.admitted, adjudication=judged)

            result = search(candidates, evaluate, max_trials=max_trials)
            whole = result.whole.adjudication
            complete = len(candidates.effects) == len(plan.effects)
            if whole is not None:
                self._record(
                    RecordType.DIFF_COMPUTED,
                    plan,
                    whole.diff.content_hash(),
                    stage=handle.stage_id,
                    note=f"repair search, whole plan: {whole.diff.blast_radius} rows",
                )
                self._record(
                    RecordType.VERDICT,
                    plan,
                    whole.verdict.content_hash(),
                    stage=handle.stage_id,
                    note="admitted"
                    if whole.admitted
                    else ",".join(v.invariant for v in whole.verdict.blocking),
                )
            refused = complete and whole is not None and not whole.admitted
            if not refused:
                receipt_id = None
            stamp = f"; repairs receipt {receipt_id}" if receipt_id else ""
            already = complete and result.whole.admitted
            kept = result.kept if not already else None
            if kept is not None:
                proposal = EffectPlan(
                    plan_id=new_plan_id("repair"),
                    scope_id=plan.scope_id,
                    trajectory_id=plan.trajectory_id,
                    created_at=datetime.now(UTC),
                    effects=tuple(e for e in plan.effects if e.effect_id in kept),
                    intent=plan.intent,
                    repair_of=plan.plan_id,
                )
                how = "exhaustive" if result.exhaustive else f"stopped: {result.stopped}"
                self._record(
                    RecordType.REPAIR_PROPOSED,
                    plan,
                    proposal.content_hash(),
                    stage=handle.stage_id,
                    note=f"proposal {proposal.plan_id} keeps {len(kept)} of "
                    f"{len(plan.effects)} effects after {result.trials} trials ({how}){stamp}",
                )
            self._substrate.abort(handle)
            outcome = (
                "plan admissible as submitted"
                if already
                else "proposal recorded"
                if proposal is not None
                else "no admissible sub-plan found"
            )
            terminal = self._record(
                RecordType.ABORTED,
                plan,
                whole.verdict.content_hash() if whole is not None else plan.content_hash(),
                stage=handle.stage_id,
                note=f"repair search rolled back: {outcome}"
                + (f"; receipt {receipt_id}" if receipt_id else ""),
            )
        except Exception:
            self._substrate.abort(handle)
            self._record(
                RecordType.ABORTED,
                plan,
                plan.content_hash(),
                stage=handle.stage_id,
                note="repair search failed",
                best_effort=True,
            )
            raise
        finally:
            self._substrate.close(handle)

        receipt = None
        if receipt_id is not None and whole is not None and terminal is not None:
            receipt = self._issue_receipt(
                receipt_id, whole, committed=False, terminal=terminal, settlement=None
            )
        kept_ids = frozenset(e.effect_id for e in proposal.effects) if proposal else frozenset()
        return Repair(
            plan=plan,
            proposal=proposal,
            already_admissible=already,
            kept=tuple(e.effect_id for e in proposal.effects) if proposal else (),
            dropped=() if already else dropped_effects(plan, kept_ids, result.probes, inadmissible),
            trials=result.trials,
            exhaustive=result.exhaustive,
            stopped=result.stopped,
            whole=whole,
            receipt=receipt,
        )

    def _effect_problem(self, effect: Effect) -> InterlockError | None:
        """Why admission would refuse this one effect, or ``None``."""
        veto = getattr(self._substrate, "reject_reason", None)
        if callable(veto):
            refusal = veto(effect)
            if refusal is not None:
                return ForbiddenStatementError(
                    f"effect {effect.effect_id!r} refused: {refusal}",
                    reason=_verb_reason(effect),
                )
        if effect.compensation is None and (
            not effect.reversible or self._substrate.capabilities.requires_compensation
        ):
            return UncompensatableEffectError(
                f"effect {effect.effect_id!r} needs a compensation it does not carry"
            )
        expected = self._substrate.substrate_id
        if effect.substrate_id and effect.substrate_id != expected:
            return PlanError(f"effect {effect.effect_id!r} targets substrate {effect.substrate_id}")
        observed: frozenset[str] | None = getattr(self._substrate, "observed_tables", None)
        if observed is not None and effect.table not in observed:
            return PlanError(
                f"effect {effect.effect_id!r} targets unobserved table {effect.table!r}"
            )
        return None

    @contextmanager
    def _repair_claim(self, plan: EffectPlan) -> Iterator[str | None]:
        """Hold a proposal for the one stage that may commit it.

        A plan naming itself a repair is admitted only exactly as this engine
        proposed it, and only once: one refusal has at most one committed
        repair, so no two receipts can both claim to be its repair. The claim
        is held while the proposal is staged, which refuses a concurrent
        second submission; once the proposal commits, the chain refuses every
        later one.

        :returns: The refused plan's receipt id, when it has one.
        """
        if plan.repair_of is None:
            yield None
            return
        with self._claims_lock:
            if plan.plan_id in self._claims:
                raise PlanError(f"repair {plan.plan_id} is being staged already")
            repairs = self._repair_link(plan)
            self._claims.add(plan.plan_id)
        try:
            yield repairs
        finally:
            with self._claims_lock:
                self._claims.discard(plan.plan_id)

    def _repair_link(self, plan: EffectPlan) -> str | None:
        """Check that a plan claiming to be a repair is one this engine
        proposed, and has not committed yet.

        :returns: The refused plan's receipt id, when it has one.
        :raises PlanError: If no matching proposal is on the chain, or the
            proposal already committed.
        """
        records = self._chain.records()
        mine = [r for r in records if r.plan_id == plan.plan_id]
        intents = {r.stage_id for r in mine if r.record_type is RecordType.COMMIT_INTENT}
        aborted = {r.stage_id for r in mine if r.record_type is RecordType.ABORTED}
        if intents - aborted:
            # An intent with no abort after it committed, or may have: a
            # crashed commit is the substrate's to resolve, not a retry's.
            raise PlanError(
                f"repair {plan.plan_id} of {plan.repair_of} already committed; "
                f"a proposal is admitted once"
            )
        digest = plan.content_hash()
        for record in reversed(records):
            if (
                record.record_type is RecordType.REPAIR_PROPOSED
                and record.plan_id == plan.repair_of
                and record.payload_hash == digest
            ):
                found = _REPAIRS_RECEIPT.search(record.note)
                return found.group(1) if found else None
        raise PlanError(
            f"plan {plan.plan_id} names itself a repair of {plan.repair_of}, but this "
            f"engine's chain holds no such proposal with its content. A repair is "
            f"resubmitted exactly as proposed; anything else is a new plan, and "
            f"must not claim to be one"
        )

    def _issue_receipt(
        self,
        receipt_id: str,
        judged: Adjudication,
        *,
        committed: bool,
        terminal: EscrowRecord,
        settlement: LedgerEntry | None,
        txid: str | None = None,
        repair_of: str | None = None,
    ) -> ActionReceipt | None:
        """Issue the receipt, last, anchored to AgentGov's head as it is now.

        A failure is logged, not raised: after a commit the effects stand,
        and raising would replace a truthful result with bookkeeping.
        """
        assert self._receipts is not None
        plan = judged.plan
        try:
            spent = (
                settlement.amount
                if settlement is not None and settlement.entry_type is EntryType.SPEND
                else Decimal(0)
            )
            return self._receipts.issue(
                receipt_id=receipt_id,
                plan=plan,
                diff=judged.diff,
                verdict=judged.verdict,
                committed=committed,
                substrate=self._substrate,
                checkers=self._checkers,
                escrow=terminal,
                agentgov=self._observe(best_effort=True),
                scope_path=(
                    self._anchor.scope_path(plan.scope_id)
                    if self._anchor is not None
                    else (plan.scope_id,)
                ),
                substrate_txid=txid,
                repair_of=repair_of,
                ledger_txn_ids=(str(settlement.transaction_id),) if settlement is not None else (),
                settled=spent,
            )
        except Exception:
            logger.warning(
                "receipt %s for plan %s could not be issued; the terminal record names it",
                receipt_id,
                plan.plan_id,
                exc_info=True,
            )
            return None

    # -- recovery -----------------------------------------------------------

    def recover(self) -> tuple[EscrowRecord, ...]:
        """Resolve the commit intents a crashed process left open.

        Call at startup, on a chain resumed from its file. Each
        ``COMMIT_INTENT`` with no terminal record after it is put to the
        substrate's commit marker, which was written inside that stage's own
        transaction: present means the effects committed, absent means they
        rolled back. The answer is appended as a ``COMMITTED`` or ``ABORTED``
        record whose note says it was recovered.

        An intent this engine has in flight right now is skipped, and so is
        one the substrate cannot answer for: an intent written before v0.1.2
        (no marker was armed), or by a substrate without markers. Those stay
        open and are logged, for an operator to resolve. So does one the
        substrate cannot answer for *yet*: a client that died with its
        ``COMMIT`` in flight leaves the server still committing, and an absent
        marker then means nothing. It stays open, and a later run resolves it.

        :returns: The records appended, in chain order.
        :raises InterlockError: If the substrate or the chain cannot be read
            or written.
        """
        resolve = getattr(self._substrate, "resolve_intent", None)
        resolved: list[EscrowRecord] = []
        for intent in self._chain.unresolved_intents():
            stage_id = intent.stage_id
            if stage_id is None or stage_id in self._inflight:
                continue
            outcome: bool | None = None
            answerable = False
            if callable(resolve) and intent.note.endswith(_MARKER_ARMED):
                answerable = True
                txid = _recorded_txid(intent.note)
                outcome = resolve(stage_id, txid=txid) if txid else resolve(stage_id)
            if outcome is None and answerable:
                # The marker was armed, and the substrate could not say yet:
                # the server is still running the transaction (a dead
                # client's COMMIT can still land), or the marker was removed.
                # Either way the answer is the substrate's to give, not ours.
                logger.warning(
                    "commit intent for plan %s (stage %s, record %d) is not settled yet; "
                    "recovery will ask again on its next run. The substrate cannot say "
                    "whether the stage committed (see its warning): resolving it by hand "
                    "now could contradict what the server does next",
                    intent.plan_id,
                    stage_id,
                    intent.sequence,
                )
                continue
            if outcome is None:
                logger.warning(
                    "commit intent for plan %s (stage %s, record %d) cannot be resolved: "
                    "no commit marker was armed for it. Check the substrate for its "
                    "effects and resolve it by hand",
                    intent.plan_id,
                    stage_id,
                    intent.sequence,
                )
                continue
            point = self._observe(best_effort=True)
            record = self._chain.append(
                RecordType.COMMITTED if outcome else RecordType.ABORTED,
                plan_id=intent.plan_id,
                payload_hash=intent.payload_hash,
                stage_id=stage_id,
                anchored=point.anchored,
                agentgov_head_hash=point.head_hash,
                agentgov_sequence=point.sequence,
                note=(
                    f"recovered: commit marker present, stage committed (intent {intent.sequence})"
                    if outcome
                    else f"recovered: no commit marker, stage rolled back "
                    f"(intent {intent.sequence})"
                ),
            )
            logger.warning(
                "recovered commit intent for plan %s (stage %s): %s",
                intent.plan_id,
                stage_id,
                "committed" if outcome else "rolled back",
            )
            resolved.append(record)
        return tuple(resolved)

    # -- internals ----------------------------------------------------------

    def _record(
        self,
        record_type: RecordType,
        plan: EffectPlan,
        payload_hash: str,
        *,
        stage: uuid.UUID | None = None,
        note: str = "",
        best_effort: bool = False,
    ) -> EscrowRecord:
        """Append one record, anchored to AgentGov's current head.

        :param best_effort: Record even if AgentGov cannot be read, as an
            unanchored record. For the records that report what already
            happened (a rollback, a durable commit), where refusing to write
            the record would not undo anything and would leave the chain
            silent about it.
        """
        point = self._observe(best_effort=best_effort)
        return self._chain.append(
            record_type,
            plan_id=plan.plan_id,
            payload_hash=payload_hash,
            stage_id=stage,
            anchored=point.anchored,
            agentgov_head_hash=point.head_hash,
            agentgov_sequence=point.sequence,
            note=note,
        )

    def _settle_lost_commit(
        self,
        stage_id: uuid.UUID,
        txid: str | None,
        *,
        armed: bool,
        lost: CommitUnsettledError,
    ) -> None:
        """Ask the commit marker what the server did with a commit whose
        answer never arrived.

        Returns only when the stage committed. Called right away, so a server
        still committing (or not yet done ending the session) is common;
        that answer is "not yet", and :meth:`recover` asks again later.

        :raises StageError: If the marker is absent and the server has ended
            the transaction: it rolled back.
        :raises CommitUnsettledError: ``lost``, when the substrate cannot say
            yet, has no marker, or cannot be reached.
        """
        resolve = getattr(self._substrate, "resolve_intent", None)
        if not armed or not callable(resolve):
            raise lost
        outcome: bool | None = None
        try:
            outcome = resolve(stage_id, txid=txid) if txid else resolve(stage_id)
        except InterlockError:
            logger.warning("stage %s: its commit marker could not be read", stage_id, exc_info=True)
        if outcome is None:
            raise lost
        if not outcome:
            raise StageError(
                f"commit failed: the connection was lost and stage {stage_id} left no "
                f"commit marker; the server rolled it back"
            ) from lost

    def _observe(self, *, best_effort: bool) -> AnchorPoint:
        if self._anchor is None:
            return AnchorPoint.unanchored()
        if not best_effort:
            return self._anchor.observe()
        try:
            return self._anchor.observe()
        except InterlockError:
            logger.warning(
                "AgentGov could not be read; writing this record unanchored", exc_info=True
            )
            return AnchorPoint.unanchored()

    def _reverse_anchor(self, plan: EffectPlan, head: str, cost: Decimal) -> LedgerEntry | None:
        """Write Interlock's chain head into AgentGov, when co-resident.

        ``memo`` is inside AgentGov's hash payload, so once written the reverse
        anchor cannot be edited without breaking AgentGov's own verification.
        That is what bounds a record's time from above; see
        ``EscrowChain.verify_anchors`` for the lower bound.
        """
        # Runs after commit, so anything raised here arrives when the effects
        # are already durable and would destroy the caller's StageResult. A
        # zero cost writes a free ANCHOR entry; a negative one was refused
        # before anything was staged.
        if self._anchor is None or not self._anchor.can_reverse_anchor:
            return None
        try:
            entry = self._anchor.reverse_anchor(plan.scope_id, head, cost=cost)
        except AnchorError:
            # Degrade rather than raise. By here the substrate has already
            # committed, so raising would replace a truthful StageResult about
            # durable effects with an exception about bookkeeping. The forward
            # anchor is already in the chain; only the reverse one is missing,
            # and StageResult.anchored_to == "" says exactly that.
            logger.warning(
                "reverse anchor failed for plan %s on scope %s; effects are "
                "committed and the forward anchor stands, but AgentGov carries "
                "no reverse anchor for this plan",
                plan.plan_id,
                plan.scope_id,
                exc_info=True,
            )
            return None
        return entry


def _coverage_note(substrate: ShadowSubstrate) -> str:
    """Name the acknowledged cascade gaps the stage just opened runs with.

    Empty when the substrate reports none, or runs no cascade check.
    """
    report = getattr(substrate, "cascade_report", None)
    if not isinstance(report, CascadeReport) or not report.gaps:
        return ""
    return _GAPS + report.describe_gaps()


def _transaction_id(substrate: ShadowSubstrate, handle: StageHandle) -> str | None:
    """The substrate's transaction id for an open stage, when it exposes one."""
    reader = getattr(substrate, "transaction_id", None)
    if not callable(reader):
        return None
    value = reader(handle)
    return str(value) if value else None


def _recorded_txid(note: str) -> str | None:
    found = _TXID_PATTERN.search(note)
    return found.group(1) if found else None


def _without(plan: EffectPlan, dropped: set[EffectId]) -> EffectPlan:
    """The plan less ``dropped`` and everything that depends on it."""
    gone = set(dropped)
    for effect in plan.topological_order():
        if gone & set(effect.depends_on):
            gone.add(effect.effect_id)
    return subplan(plan, frozenset(e.effect_id for e in plan.effects if e.effect_id not in gone))
