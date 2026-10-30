"""Meters: what plans consume in a unit, conserved in a ledger of that unit.

A rate window bounds what plans add up to over a span. A meter *conserves*
it, as AgentGov conserves money: a dose in morphine milligram equivalents,
capacity in vCPUs, seats, against an AgentGov ledger of that unit
(``agentgov.Unit``), whose envelopes are delegated down a tree of scopes as
money is. Parallel agents on one envelope then cannot each consume what is
left of it.

Each plan, for each meter the engine is configured with
(``EscrowEngine(meters=...)``):

1. **Holds** the meter's ``per_plan`` on its scope, before it stages, in the
   meter's ledger. A scope whose envelope has less, is halted, or is not in
   that ledger, is refused there, and nothing is staged.
2. **Is measured.** What it consumes is the meter's *measure* of its diff:
   a window's measure (:class:`~interlock.windows.RowSum`,
   :class:`~interlock.windows.RequestSum`, :class:`~interlock.windows.Requests`,
   :class:`~interlock.windows.Plans`), over the whole plan.
3. **Is checked.** :class:`MeterCheck`, which the engine adds, refuses a plan
   that consumes more than ``per_plan``, or whose consumption cannot be
   measured. A pure function of the plan and the diff, like every check.
4. **Settles.** When it commits, what it consumed is captured against the
   hold and the rest released; refused or rolled back, the hold is released.
   The receipt names what it consumed, and the ledger's transaction that
   settled it (ARC1 ``cost.quantities``).

The settlement runs after the commit, in the ledger's own transaction. A
process that dies between the two leaves the hold open; recovery
(:meth:`~interlock.engine.EscrowEngine.recover`) captures a committed plan's
hold whole, which is never less than the plan consumed, and releases the hold
of a plan that did not commit.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import timedelta
from decimal import Decimal
from typing import TYPE_CHECKING, Final

from interlock.exceptions import MeterExhaustedError
from interlock.feedback import FeedbackHint, Guidance
from interlock.types import EffectDiff, EffectPlan, InvariantViolation, Severity
from interlock.windows import Measure, RateWindow

if TYPE_CHECKING:
    from agentgov.core import Authorization, BudgetManager, LedgerEntry

__all__ = ["METER_MEMO", "Meter", "MeterCheck", "Metered"]

logger = logging.getLogger("interlock.meters")

METER_MEMO: Final = "interlock-meter:"
"""Prefix of a meter hold's memo, followed by the plan id: recovery finds a
plan's holds by it."""


@dataclass(frozen=True, slots=True, init=False)
class Meter:
    """What a plan consumes of one unit, held and settled in its ledger.

    :param ledger: A governor of the unit's AgentGov ledger, which may write
        it. Its unit names the meter.
    :param measure: What a plan consumes: a window's measure.
    :param per_plan: The most one plan may consume, and what it holds before
        it stages: a scope's envelope must have this much left for a plan to
        run.
    :raises ValueError: On a ``per_plan`` that is not a positive number, or a
        measure that is not one.
    """

    unit: str
    """The unit's code: the ledger's."""
    measure: Measure
    per_plan: Decimal
    # The ledger is the deployment's, not the policy's: a meter is described,
    # and its check digested, by its unit, measure and per-plan bound alone.
    ledger: BudgetManager = field(repr=False, compare=False)
    _window: RateWindow = field(repr=False, compare=False)

    def __init__(
        self, ledger: BudgetManager, measure: Measure, per_plan: Decimal | int | str
    ) -> None:
        unit = ledger.unit
        # A window over the whole plan measures it as a window would: the
        # same rules for what counts, and for what cannot be measured.
        window = RateWindow(
            f"meter_{unit.code.replace('.', '_').replace('-', '_')}",
            timedelta(seconds=1),
            per_plan,
            measure,
            per="global",
        )
        if window.limit <= 0:
            raise ValueError(f"meter of {unit.code}: per_plan is more than zero")
        object.__setattr__(self, "unit", unit.code)
        object.__setattr__(self, "ledger", ledger)
        object.__setattr__(self, "measure", measure)
        object.__setattr__(self, "per_plan", unit_amount(window.limit, ledger))
        object.__setattr__(self, "_window", window)

    def consumed(self, plan: EffectPlan, diff: EffectDiff) -> tuple[Decimal, tuple[str, ...]]:
        """What the plan consumes, and what of it could not be measured."""
        amounts, problems = self._window.amounts(plan, diff)
        return sum(amounts.values(), Decimal(0)), problems

    def hold(self, plan: EffectPlan) -> Authorization:
        """Hold ``per_plan`` for the plan, before it stages.

        :raises MeterExhaustedError: If its scope cannot hold it: too little
            left, halted, or not in the ledger.
        """
        from agentgov.exceptions import AgentGovError

        # Quietly: the hold is the most a plan may consume, not what it will,
        # so an envelope too small for it is a refusal, not an overdraft to
        # latch the breaker for.
        try:
            held = self.ledger.try_authorize(
                plan.scope_id, self.per_plan, memo=f"{METER_MEMO}{plan.plan_id}"
            )
        except AgentGovError as exc:
            raise MeterExhaustedError(
                f"scope {plan.scope_id!r} cannot hold this plan's {_text(self.per_plan)} "
                f"{self.unit}, so it is not staged: {type(exc).__name__}: {exc}",
                unit=self.unit,
            ) from exc
        if held is None:
            raise MeterExhaustedError(
                f"scope {plan.scope_id!r} has less than this plan's {_text(self.per_plan)} "
                f"{self.unit} left, so it is not staged",
                unit=self.unit,
            )
        return held

    def settle(self, held: Authorization, amount: Decimal, note: str) -> LedgerEntry | None:
        """Capture ``amount`` against ``held``, the rest returned: the plan
        committed. ``None`` when it consumed nothing (the hold is released)."""
        if amount <= 0:
            self.release(held)
            return None
        return self.ledger.capture(
            held, unit_amount(amount, self.ledger), memo=f"{METER_MEMO}{held_plan(held)} {note}"
        )

    def release(self, held: Authorization) -> None:
        """Release the hold of a plan that did not commit. Best effort: one
        left behind is released by recovery."""
        from agentgov.exceptions import AgentGovError, DoubleSpendError

        try:
            self.ledger.void(held, memo=f"{METER_MEMO}{held_plan(held)} did not commit")
        except DoubleSpendError:
            return  # already settled or released
        except AgentGovError:
            logger.warning(
                "%s hold %s could not be released now; recovery will",
                self.unit,
                held.authorization_id,
                exc_info=True,
            )

    def recover(self, committed: Iterable[str], ended: Iterable[str]) -> int:
        """After a crash: capture whole the holds of ``committed`` plans, whose
        settlement never ran, and release those of plans that ``ended``
        otherwise. A plan in neither may still be running: its hold stays.

        :returns: How many holds were settled.
        """
        settled = 0
        done, gone = frozenset(committed), frozenset(ended)
        self.ledger.refresh()
        for held in self.ledger.stale_authorizations(0):
            memo = held.entry.memo
            if not memo.startswith(METER_MEMO):
                continue
            plan = memo.removeprefix(METER_MEMO)
            if plan in done:
                self.ledger.capture(
                    held, held.amount, memo=f"{METER_MEMO}{plan} recovered: settled whole"
                )
            elif plan in gone:
                self.release(held)
            else:
                continue
            settled += 1
        return settled


def held_plan(held: Authorization) -> str:
    """The plan a meter hold is for, from its memo."""
    return held.entry.memo.removeprefix(METER_MEMO)


def unit_amount(amount: Decimal, ledger: BudgetManager) -> Decimal:
    """``amount`` rounded up to the ledger's unit, as a cost is."""
    from agentgov.core import _cost

    return _cost(amount, ledger.unit)


@dataclass(frozen=True, slots=True)
class Metered:
    """What a committed plan consumed of one unit, as its receipt names it."""

    unit: str
    amount: Decimal
    transaction_id: str | None


class MeterCheck:
    """Refuses a plan that consumes more of a meter's unit than one plan may.

    Built in: the engine adds one for each meter. It refuses, failing closed,
    when what the plan consumes cannot be measured.
    """

    __slots__ = ("_meter",)

    def __init__(self, meter: Meter) -> None:
        self._meter = meter

    @property
    def meter(self) -> Meter:
        return self._meter

    @property
    def name(self) -> str:
        return f"meter:{self._meter.unit}"

    def check(self, plan: EffectPlan, diff: EffectDiff) -> tuple[InvariantViolation, ...]:
        meter = self._meter
        consumed, problems = meter.consumed(plan, diff)
        found = [self._violation(f"meter {meter.unit}: {problem}") for problem in problems]
        if consumed > meter.per_plan:
            found.append(
                self._violation(
                    f"the plan consumes {_text(consumed)} {meter.unit}; one plan may consume "
                    f"{_text(meter.per_plan)}"
                )
            )
        return tuple(found)

    def _violation(self, message: str) -> InvariantViolation:
        return InvariantViolation(
            invariant=self.name,
            severity=Severity.BLOCKING,
            message=message,
            evidence={"unit": self._meter.unit},
        )

    def hint(
        self, plan: EffectPlan, diff: EffectDiff, violation: InvariantViolation
    ) -> FeedbackHint:
        # The unit, which is configuration; never what the plan consumed.
        return FeedbackHint(kind=Guidance.METER, window=self._meter.unit)


def _text(amount: Decimal) -> str:
    return format(amount.normalize(), "f")
