"""Checked repair: the largest part of a refused plan that would be admitted.

A refused plan is often one bad step away from an acceptable one: nine
corrections to one tenant's orders and a tenth that reaches another tenant.
Refusing all ten is correct; telling the agent which nine would pass is what
turns a halt into completed work. :meth:`EscrowEngine.repair` answers that by
experiment, not by inference.

**What is searched.** A sub-plan must be runnable: when it keeps an effect it
keeps everything that effect depends on. Those are the *down-sets* of the
plan's dependency graph, and they are the only candidates.

**Why by experiment.** Constraints are not monotonic. A debit alone fails a
drawdown guard that the debit and its credit together pass, so dropping a
step can make a plan *less* acceptable, and a "remove whatever violates"
heuristic would drop the debit and keep a lone credit. Nothing here assumes
monotonicity in either direction. Every candidate is staged for real inside a
savepoint of one open stage, measured, adjudicated by the same checkers, and
rolled back to the savepoint before the next.

**Order, deterministic.**

1. The whole plan. If it is admitted there is nothing to repair.
2. Every down-set of size n-1, then n-2, and so on, the largest first, and
   within a size the ones that drop the latest steps first. The first
   admitted candidate is a largest admissible sub-plan, and the result says
   so (``exhaustive``).
3. If the trial budget runs out first: one greedy pass in dependency order,
   keeping each step whose addition is admitted. Its result was staged and
   admitted, so it is sound, but it may not be the largest; ``exhaustive`` is
   then false.
4. For each dropped step whose dependencies were kept, one more trial with
   that step added back, which records the constraints that refuse it. A step
   whose dependency was dropped is reported as dropped for that reason.

Each trial costs one statement per effect it keeps, so a search is roughly
``max_trials * n`` statements, and it runs inside one stage's time bound: a
stage that expires mid-search ends the search with what it has.

**Advisory.** Nothing a repair finds is committed. The proposal is a new plan
with ``repair_of`` naming the refused one; committing it means submitting it
through :meth:`EscrowEngine.execute`, where it is staged and adjudicated again
from scratch, because the database may have moved. See
:class:`~interlock.engine.EscrowEngine` for how the link is checked.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from interlock.adjudication import Adjudication
from interlock.exceptions import InterlockError, StageExpiredError
from interlock.feedback import ConstraintFeedback, agent_feedback, feedback_for_error
from interlock.types import Effect, EffectId, EffectPlan

if TYPE_CHECKING:
    from agentgov.receipts import ActionReceipt

__all__ = [
    "DroppedEffect",
    "Repair",
    "RepairFeedback",
    "SearchResult",
    "Trial",
    "search",
    "subplan",
]

_LEVEL_CAP: Final = 20_000
"""The most candidates one size level may hold before the search stops
enumerating and falls back to the greedy pass. A wide plan's middle levels
are combinatorial; the trial budget would never reach them anyway."""


@dataclass(frozen=True, slots=True)
class Trial:
    """One candidate sub-plan, staged, measured and adjudicated.

    :ivar adjudication: The verdict and its hints, when the candidate ran.
    :ivar error: Why it did not run to a verdict: a statement the substrate
        refused, a statement that failed, a lost write race.
    """

    kept: frozenset[EffectId]
    admitted: bool
    adjudication: Adjudication | None = None
    error: InterlockError | None = None


Evaluate = Callable[[frozenset[EffectId]], Trial]


@dataclass(frozen=True, slots=True)
class SearchResult:
    """What the search found, and how hard it looked.

    :ivar kept: The admissible sub-plan, or ``None`` when no non-empty one was
        found. Every set here was staged and admitted.
    :ivar whole: The trial of the whole plan.
    :ivar exhaustive: Every larger candidate was tried and refused, so
        ``kept`` is a largest admissible sub-plan.
    :ivar probes: For each dropped step whose dependencies were kept, the
        trial that added it back.
    :ivar stopped: Why the search ended before exhausting its candidates:
        ``"budget"`` or ``"expired"``; ``None`` when it did not.
    """

    whole: Trial
    kept: frozenset[EffectId] | None
    trials: int
    exhaustive: bool
    probes: Mapping[EffectId, Trial]
    stopped: str | None = None


def subplan(plan: EffectPlan, kept: frozenset[EffectId]) -> EffectPlan:
    """The plan cut down to ``kept``, which must be a down-set of it."""
    return EffectPlan(
        plan_id=plan.plan_id,
        scope_id=plan.scope_id,
        trajectory_id=plan.trajectory_id,
        created_at=plan.created_at,
        effects=tuple(e for e in plan.effects if e.effect_id in kept),
        intent=plan.intent,
        repair_of=plan.repair_of,
    )


class _BudgetSpentError(Exception):
    """The trial budget is spent."""


class _StageExpiredError(Exception):
    """The stage outlived its bound mid-search."""


class _Trials:
    """Runs trials against a budget, and never runs the same set twice."""

    def __init__(self, evaluate: Evaluate, limit: int) -> None:
        self._evaluate = evaluate
        self._limit = limit
        self._seen: dict[frozenset[EffectId], Trial] = {}
        self.spent = 0

    @property
    def remaining(self) -> int:
        return self._limit - self.spent

    def run(self, kept: frozenset[EffectId]) -> Trial:
        known = self._seen.get(kept)
        if known is not None:
            return known
        if self.spent >= self._limit:
            raise _BudgetSpentError
        self.spent += 1
        trial = self._evaluate(kept)
        self._seen[kept] = trial
        if isinstance(trial.error, StageExpiredError):
            raise _StageExpiredError
        return trial


def search(plan: EffectPlan, evaluate: Evaluate, *, max_trials: int) -> SearchResult:
    """Find the largest admissible down-set of ``plan``, by experiment.

    :param evaluate: Stages one candidate from the stage's starting state and
        adjudicates it. The engine supplies it; see
        :meth:`~interlock.engine.EscrowEngine.repair`.
    :param max_trials: The most candidates staged, the whole plan included.
    :raises ValueError: If ``max_trials`` is below 1.
    """
    if max_trials < 1:
        raise ValueError("a repair needs at least one trial")
    order = plan.topological_order()
    ids = frozenset(e.effect_id for e in order)
    position = {e.effect_id: i for i, e in enumerate(order)}
    dependents: dict[EffectId, set[EffectId]] = {e: set() for e in ids}
    for effect in order:
        for dependency in effect.depends_on:
            dependents[dependency].add(effect.effect_id)

    trials = _Trials(evaluate, max_trials)
    whole = trials.run(ids)
    if whole.admitted:
        return SearchResult(whole=whole, kept=ids, trials=trials.spent, exhaustive=True, probes={})

    best: frozenset[EffectId] | None = None
    exhaustive = False
    stopped: str | None = None
    # The greedy pass needs about one trial per effect; the level search
    # leaves it that much, so a budget that cannot finish the levels still
    # ends with a sound answer.
    reserve = min(len(order), max_trials // 2)
    try:
        for level in _levels(ids, dependents, position):
            for removed in level:
                kept = ids - removed
                if trials.remaining <= reserve:
                    raise _BudgetSpentError
                if trials.run(kept).admitted:
                    best = kept
                    exhaustive = True
                    break
            if best is not None:
                break
        else:
            exhaustive = True  # every candidate refused: nothing is admissible
    except _BudgetSpentError:
        stopped = "budget"
    except _StageExpiredError:
        stopped = "expired"

    if best is None and stopped == "budget":
        best, greedy_stop = _greedy(order, trials)
        stopped = greedy_stop or stopped
    probes = _probe(order, best, trials) if best is not None and stopped != "expired" else {}
    return SearchResult(
        whole=whole,
        kept=best,
        trials=trials.spent,
        exhaustive=exhaustive and stopped is None,
        probes=probes,
        stopped=stopped,
    )


def _levels(
    ids: frozenset[EffectId],
    dependents: Mapping[EffectId, set[EffectId]],
    position: Mapping[EffectId, int],
) -> Iterator[list[frozenset[EffectId]]]:
    """Removal sets by size: every set of k effects closed under dependents.

    Removing such a set leaves a down-set. A set grows by one effect that
    nothing still kept depends on, so every down-set is reached, and each once.
    Sizes run from 1 to n-1, so something is always kept, and every size has
    a set: whatever remains of a DAG has a step nothing else remaining needs.
    Within a size, sets that remove later steps come first.
    """
    current: set[frozenset[EffectId]] = {frozenset()}
    for _ in range(1, len(ids)):
        grown: set[frozenset[EffectId]] = set()
        for removed in current:
            remaining = ids - removed
            for effect in remaining:
                if dependents[effect] & remaining:
                    continue
                grown.add(removed | {effect})
                if len(grown) > _LEVEL_CAP:
                    raise _BudgetSpentError
        yield sorted(
            grown, key=lambda r: sorted((position[e] for e in r), reverse=True), reverse=True
        )
        current = grown


def _greedy(
    order: Sequence[Effect], trials: _Trials
) -> tuple[frozenset[EffectId] | None, str | None]:
    """Keep each step, in dependency order, whose addition is admitted."""
    kept: frozenset[EffectId] = frozenset()
    try:
        for effect in order:
            if not set(effect.depends_on) <= kept:
                continue
            candidate = kept | {effect.effect_id}
            if trials.run(candidate).admitted:
                kept = candidate
    except _BudgetSpentError:
        return (kept or None), "budget"
    except _StageExpiredError:
        return (kept or None), "expired"
    return (kept or None), None


def _probe(
    order: Sequence[Effect], kept: frozenset[EffectId], trials: _Trials
) -> dict[EffectId, Trial]:
    """Add each dropped step whose dependencies were kept back alone."""
    probes: dict[EffectId, Trial] = {}
    for effect in order:
        if effect.effect_id in kept or not set(effect.depends_on) <= kept:
            continue
        try:
            probes[effect.effect_id] = trials.run(kept | {effect.effect_id})
        except (_BudgetSpentError, _StageExpiredError):
            break
    return probes


# --------------------------------------------------------------------------
# What the agent is told
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DroppedEffect:
    """One step the repair leaves out, and why.

    :ivar cause: ``"refused"`` (adding it back was refused: see
        ``constraints``), ``"depends"`` (it depends on ``depends_on``, which
        was dropped), ``"inadmissible"`` (refused before staging), or
        ``"unevaluated"`` (the budget ran out before it was tried alone).
    :ivar constraints: The sanitized constraints that refused it: safe for
        the agent.
    :ivar invariants: The checkers that refused it, by full name: the
        operator's view.
    """

    effect_id: EffectId
    cause: str
    constraints: tuple[ConstraintFeedback, ...] = ()
    invariants: tuple[str, ...] = ()
    depends_on: EffectId | None = None


@dataclass(frozen=True, slots=True)
class RepairFeedback:
    """The repair, as the agent may see it: which of its own steps to keep."""

    found: bool
    already_admissible: bool
    kept: tuple[EffectId, ...]
    dropped: tuple[DroppedEffect, ...]
    exhaustive: bool

    def render(self) -> str:
        if self.already_admissible:
            return "The plan is admissible as it stands; nothing needs repair."
        if not self.found:
            return "No part of the plan would be admitted; it needs rewriting, not trimming."
        how = "the largest part" if self.exhaustive else "a part"
        lines = [
            f"Resubmit {how} of the plan that would be admitted: keep "
            f"{', '.join(self.kept)}; drop {', '.join(d.effect_id for d in self.dropped)}."
        ]
        for dropped in self.dropped:
            if dropped.cause == "depends":
                lines.append(f"- {dropped.effect_id}: depends on dropped {dropped.depends_on}.")
            elif dropped.cause == "refused" and dropped.constraints:
                reasons = " ".join(c.render() for c in dropped.constraints)
                lines.append(f"- {dropped.effect_id}: {reasons}")
            elif dropped.cause == "inadmissible" and dropped.constraints:
                lines.append(f"- {dropped.effect_id}: {dropped.constraints[0].render()}")
            else:
                lines.append(f"- {dropped.effect_id}: not tried alone.")
        return "\n".join(lines)


def dropped_effects(
    plan: EffectPlan,
    kept: frozenset[EffectId],
    probes: Mapping[EffectId, Trial],
    inadmissible: Mapping[EffectId, InterlockError],
) -> tuple[DroppedEffect, ...]:
    """Explain every step the repair leaves out, in the order the plan lists them."""
    gone: list[DroppedEffect] = []
    for effect in plan.effects:
        eid = effect.effect_id
        if eid in kept:
            continue
        if eid in inadmissible:
            fb = feedback_for_error(plan, inadmissible[eid])
            gone.append(DroppedEffect(eid, "inadmissible", constraints=fb.constraints))
            continue
        missing = sorted(d for d in effect.depends_on if d not in kept)
        if missing:
            gone.append(DroppedEffect(eid, "depends", depends_on=missing[0]))
            continue
        probe = probes.get(eid)
        if probe is None:
            gone.append(DroppedEffect(eid, "unevaluated"))
        elif probe.adjudication is not None:
            # Sanitized against the whole plan: the agent named every table
            # and tenant in it, and nothing else.
            judged = probe.adjudication
            invariants = tuple(v.invariant for v in judged.verdict.blocking)
            gone.append(
                DroppedEffect(
                    eid,
                    "refused",
                    constraints=feedback_for_hints(plan, judged),
                    invariants=invariants,
                )
            )
        else:
            error = probe.error
            fb_error = feedback_for_error(plan, error) if error is not None else None
            gone.append(
                DroppedEffect(
                    eid,
                    "refused",
                    constraints=fb_error.constraints if fb_error is not None else (),
                )
            )
    return tuple(gone)


def feedback_for_hints(plan: EffectPlan, judged: Adjudication) -> tuple[ConstraintFeedback, ...]:
    """A trial's blocking constraints, sanitized against the whole ``plan``."""
    return agent_feedback(plan, judged.hints, committed=False).blocking


@dataclass(frozen=True, slots=True)
class Repair:
    """What :meth:`EscrowEngine.repair` found. Advisory: nothing committed.

    :ivar proposal: The admissible sub-plan as a new plan, ``repair_of`` the
        refused one. Submit it with :meth:`EscrowEngine.execute`, unchanged.
    :ivar whole: The whole plan's adjudication in the repair stage, when it
        ran to a verdict: the operator's evidence of why it was refused.
    :ivar receipt: The ARC1 receipt of the whole plan's refusal, when the
        engine issues receipts. The proposal's own receipt will name it as
        ``repair_of``.
    """

    plan: EffectPlan
    proposal: EffectPlan | None
    already_admissible: bool
    kept: tuple[EffectId, ...]
    dropped: tuple[DroppedEffect, ...]
    trials: int
    exhaustive: bool
    stopped: str | None = None
    whole: Adjudication | None = None
    receipt: ActionReceipt | None = None

    @property
    def feedback(self) -> RepairFeedback:
        """What the agent may be told: its own step ids, and why each was
        dropped, sanitized like every other feedback."""
        return RepairFeedback(
            found=self.proposal is not None,
            already_admissible=self.already_admissible,
            kept=self.kept,
            dropped=self.dropped,
            exhaustive=self.exhaustive,
        )
