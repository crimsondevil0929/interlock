"""Running the checkers: one verdict, and a feedback hint for each violation.

Split out of the engine because two paths adjudicate: :meth:`EscrowEngine.execute`
for a submitted plan, and :meth:`EscrowEngine.repair` for every candidate
sub-plan it tries. Both have to decide the same way.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime

from interlock.feedback import (
    AgentFeedback,
    FeedbackHint,
    Guidance,
    HintedViolation,
    OperatorEvidence,
    Refusal,
    agent_feedback,
)
from interlock.invariants import BUILT_IN_CHECKERS, InvariantChecker
from interlock.types import EffectDiff, EffectPlan, InvariantViolation, Severity, Verdict

__all__ = ["Adjudication", "adjudicate"]

logger = logging.getLogger("interlock.engine")


@dataclass(frozen=True, slots=True)
class Adjudication:
    """A verdict, with what each of its violations may tell the agent."""

    plan: EffectPlan
    diff: EffectDiff
    verdict: Verdict
    hints: tuple[HintedViolation, ...]

    @property
    def admitted(self) -> bool:
        return self.verdict.admitted

    def feedback(self, *, committed: bool) -> AgentFeedback:
        return agent_feedback(self.plan, self.hints, committed=committed)

    def refusal(self) -> Refusal:
        return Refusal(
            evidence=OperatorEvidence.of(self.plan, diff=self.diff, verdict=self.verdict),
            feedback=self.feedback(committed=False),
        )


def adjudicate(
    plan: EffectPlan,
    diff: EffectDiff,
    checkers: Sequence[InvariantChecker],
    *,
    stage_id: uuid.UUID,
) -> Adjudication:
    """Run every checker and union the violations.

    A checker that raises becomes a blocking violation: a predicate that did
    not finish has not approved anything. A hint that raises, or is not a
    :class:`FeedbackHint`, becomes the generic operator-constraint hint: the
    agent loses detail, never the refusal.
    """
    violations: list[InvariantViolation] = []
    hinted: list[HintedViolation] = []
    names: list[str] = []
    for checker in checkers:
        names.append(checker.name)
        try:
            found = tuple(checker.check(plan, diff))
        except Exception as exc:  # a broken checker must never approve
            logger.exception("invariant %s raised", checker.name)
            broken = InvariantViolation(
                invariant=checker.name,
                severity=Severity.BLOCKING,
                message=f"checker raised {type(exc).__name__}: {exc}",
            )
            violations.append(broken)
            hinted.append(HintedViolation(broken, FeedbackHint(kind=Guidance.OPERATOR)))
            continue
        violations.extend(found)
        trusted = type(checker) in BUILT_IN_CHECKERS
        offer = getattr(checker, "hint", None)
        for violation in found:
            hint = FeedbackHint(kind=Guidance.OPERATOR)
            if callable(offer):
                try:
                    candidate = offer(plan, diff, violation)
                except Exception:
                    logger.exception("feedback hint for %s raised", checker.name)
                else:
                    if isinstance(candidate, FeedbackHint):
                        hint = candidate
            hinted.append(HintedViolation(violation, hint, trusted))
    verdict = Verdict(
        plan_id=plan.plan_id,
        stage_id=stage_id,
        diff_hash=diff.content_hash(),
        decided_at=datetime.now(UTC),
        checkers_run=tuple(names),
        violations=tuple(violations),
    )
    return Adjudication(plan=plan, diff=diff, verdict=verdict, hints=tuple(hinted))
