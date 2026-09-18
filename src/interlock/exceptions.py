"""Error hierarchy.

Split by what the caller must do about it, not by where it was raised.

``PlanError``      the plan is malformed or inadmissible; fix the plan.
``StageError``     the substrate could not stage or commit; retry may help.
``AdmissionError`` an invariant refused; nothing was committed, by design.
``AnchorError``    the audit chain is unusable; refuse to operate.
"""

from __future__ import annotations

__all__ = [
    "AdmissionError",
    "AnchorError",
    "ChainIntegrityError",
    "CyclicPlanError",
    "InterlockError",
    "LedgerUnverifiedError",
    "PlanError",
    "ScopeHaltedError",
    "StageConflictError",
    "StageError",
    "StageExpiredError",
    "SubstrateUnavailableError",
    "UncompensatableEffectError",
]


class InterlockError(Exception):
    """Base for every error this package raises."""


# -- the plan is wrong ------------------------------------------------------


class PlanError(InterlockError):
    """The plan cannot be admitted. Nothing was touched."""


class CyclicPlanError(PlanError):
    """The effect DAG contains a cycle, or names an unknown dependency."""


class UncompensatableEffectError(PlanError):
    """An irreversible effect arrived without a serialized undo.

    Raised at admission, not at commit: the undo has to exist before the effect
    is staged.
    """


# -- the substrate is unhappy ----------------------------------------------


class StageError(InterlockError):
    """The staging substrate failed."""


class SubstrateUnavailableError(StageError):
    """The backend could not be reached or a connection could not be bound."""


class StageConflictError(StageError):
    """A conflicting stage already holds the resources this plan needs."""


class StageExpiredError(StageError):
    """The stage outlived ``max_stage_seconds``.

    A stage holds write locks for its whole life, which is what the bound is
    for. Raised from ``apply`` and ``commit``; ``diff`` does not check expiry.
    Nothing transitions the stage to ``ORPHANED`` as of v0.1.0.
    """


# -- an invariant said no ---------------------------------------------------


class AdmissionError(InterlockError):
    """A blocking invariant refused the staged diff.

    The substrate has already been rolled back by the time this is raised.
    Raised only by ``execute_or_raise``; ``execute`` returns a result with
    ``committed=False`` instead.
    """

    def __init__(self, message: str, *, verdict: object | None = None) -> None:
        super().__init__(message)
        self.verdict = verdict


class ScopeHaltedError(AdmissionError):
    """AgentGov's circuit breaker has tripped for this plan's scope.

    Checked immediately before commit rather than at admission: the staging
    window is where a trip has to be observed, since a halt that does not stop
    in-flight side effects does not stop the effects.
    """


# -- the evidence is unusable ----------------------------------------------


class AnchorError(InterlockError):
    """The audit chain cannot be trusted or cannot be reached."""


class LedgerUnverifiedError(AnchorError):
    """The AgentGov ledger failed verification.

    Staging is refused. A record anchored to a chain that does not verify
    carries no evidentiary weight while still reading as anchored.
    """


class ChainIntegrityError(AnchorError):
    """Interlock's own record chain failed verification."""
