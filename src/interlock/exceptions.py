"""Error hierarchy.

Split by what the caller must do about it, not by where it was raised.

``PlanError``      the plan is malformed or inadmissible; fix the plan.
``StageError``     the substrate could not stage or commit; retry may help.
``AdmissionError`` an invariant refused; nothing was committed, by design.
``AnchorError``    the audit chain is unusable; refuse to operate.
``RecoveryError``  the recovery runtime cannot take this step; stop, or ask
                   the operator.
"""

from __future__ import annotations

__all__ = [
    "AdmissionError",
    "AnchorError",
    "ChainInUseError",
    "ChainIntegrityError",
    "CompactionRefusedError",
    "CyclicPlanError",
    "ExtensionError",
    "ForbiddenStatementError",
    "InboundFactError",
    "InterlockError",
    "KeyRevokedError",
    "LedgerUnverifiedError",
    "OutboundRequestError",
    "PlanError",
    "PoolExhaustedError",
    "RecordIntegrityError",
    "RecoveryError",
    "RecoveryExhaustedError",
    "ScopeHaltedError",
    "StageConflictError",
    "StageError",
    "StageExpiredError",
    "SubstrateConfigurationError",
    "SubstrateUnavailableError",
    "SupervisorStoppedError",
    "ToolRevokedError",
    "UncompensatableEffectError",
]


class InterlockError(Exception):
    """Base for every error this package raises.

    :ivar feedback: What the agent may be told about this error. An
        :class:`~interlock.feedback.AgentFeedback`. Send that to the agent,
        never ``str(exc)``, which is written for the operator and can quote
        other tenants' data.

        **This applies to every ``InterlockError``, not only a refused
        plan's checker violations.** ``EscrowEngine.execute()`` and
        ``EscrowEngine.repair()`` populate ``feedback`` (via
        :func:`~interlock.feedback.feedback_for_error`) on *any*
        ``InterlockError`` they catch before re-raising it, including a
        ``StageError`` or ``ForbiddenStatementError`` from a statement that
        failed against the database -- reading the exception's type and
        structured fields only, never its message, so a raw driver error
        (which can quote a column, table or value from the failing
        statement) never reaches ``feedback.render()``. It stays ``None``
        only for an exception raised by calling a substrate directly,
        bypassing the engine entirely (see ``ForbiddenStatementError``
        below): there is nothing to catch it and fill it in. A harness that
        might see ``None`` should treat that case the same as any other
        error outcome, not fall back to ``str(exc)``.
    """

    feedback: object | None = None


# -- the plan is wrong ------------------------------------------------------


class PlanError(InterlockError):
    """The plan cannot be admitted. Nothing was touched."""


class CyclicPlanError(PlanError):
    """The effect DAG contains a cycle, or names an unknown dependency."""


class ForbiddenStatementError(PlanError):
    """The statement is of a kind this substrate refuses to execute.

    Raised on the statement itself rather than on ``Effect.kind``, which the
    agent authors. DDL is the case that matters: it changes the schema, fires
    no row triggers, and so measures as an empty diff that every checker
    reading the diff passes.

    Raised from admission and again from ``apply``. The second is not
    redundant: a caller using a substrate directly never reaches admission --
    and also does not reach ``EscrowEngine``'s catch clause, so ``feedback``
    is ``None`` on that path (see ``InterlockError.feedback``). Raised
    through ``EscrowEngine.execute()``/``repair()``, ``feedback`` is always
    populated, safely.

    :ivar reason: What kind of refusal, for code to branch on:
        ``"statement_kind"``, ``"unobserved_table"``, ``"privilege"``,
        ``"cascade"``, ``"protected"``, ``"transaction_control"``,
        ``"reach"`` or ``"multiple_statements"``.
    :ivar table: The table the refusal is about, when there is one.
    """

    def __init__(self, message: str, *, reason: str = "statement_kind", table: str | None = None):
        super().__init__(message)
        self.reason = reason
        self.table = table


class UncompensatableEffectError(PlanError):
    """An irreversible effect arrived without a serialized undo.

    Raised at admission, not at commit: the undo has to exist before the effect
    is staged.
    """


class OutboundRequestError(PlanError):
    """An outbound request (an ``ENQUEUE`` effect) is not admissible.

    Raised at admission, against the sink registry, and again by the database
    when the stage writes the request to the outbox. ``str(exc)`` is the
    operator's record and can name payload fields; the agent's feedback names
    only the reason.

    :ivar reason: What was wrong, for code to branch on:
        ``"substrate"`` (this substrate has no outbox), ``"no_registry"``,
        ``"unregistered_sink"``, ``"unregistered_operation"``,
        ``"payload_type"``, ``"payload_size"``, ``"credential_field"``,
        ``"payload_schema"``, ``"compensation"``, ``"not_after"``,
        ``"payload_hash"`` or ``"duplicate"``.
    :ivar sink: The sink the request names, when there is one.
    """

    def __init__(self, message: str, *, reason: str, sink: str | None = None):
        super().__init__(message)
        self.reason = reason
        self.sink = sink


# -- the substrate is unhappy ----------------------------------------------


class StageError(InterlockError):
    """The staging substrate failed.

    ``str(exc)`` is the operator's record and can quote the failing
    statement, an offending column or table name, or driver-specific detail.
    Raised through ``EscrowEngine.execute()``/``repair()``, ``feedback`` is a
    fixed, generic "a statement failed in the database" -- see
    ``InterlockError.feedback``. Send ``feedback``, never ``str(exc)``, to
    an agent that will see the result.
    """


class SubstrateUnavailableError(StageError):
    """The backend could not be reached or a connection could not be bound."""


class SubstrateConfigurationError(StageError):
    """The backend is reachable but not set up so a stage can be measured.

    Interlock is not installed in it, the installation does not match the
    configured tables, or the stage's role can write somewhere the capture
    cannot see. Retrying will not help; fix the configuration.
    """


class StageConflictError(StageError):
    """A conflicting stage already holds the resources this plan needs."""


class PoolExhaustedError(StageConflictError):
    """No connection came free in time for a stage's second session, the one
    that reads the rate windows: a connection pool (PgBouncer), or the
    server's own limit, held every one (``docs/EPIC7_DESIGN.md`` §3). The
    stage was aborted, so it holds nothing. Retryable, as a lost race is."""


class StageExpiredError(StageError):
    """The stage outlived ``max_stage_seconds``.

    A stage holds write locks for its whole life, which is what the bound is
    for. Raised from ``apply`` and ``commit``; ``diff`` does not check expiry.
    Nothing transitions the stage to ``ORPHANED`` as of v0.1.0.
    """


class CommitUnsettledError(StageError):
    """The connection was lost with ``COMMIT`` in flight, and the server has
    not decided yet whether the stage committed.

    **Do not retry the plan.** The server may still commit it. The chain holds
    the stage's commit intent and no terminal record, and
    :meth:`~interlock.EscrowEngine.recover` resolves it from the commit
    marker once the server has decided. A commit whose reply alone was lost
    is not this error: its marker already answers, and the plan is reported
    as committed.
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


class ChainInUseError(AnchorError):
    """Another live writer holds the escrow chain file.

    One chain file has one writer. A second would append records carrying the
    same sequence numbers, forking the chain, and its crash recovery would
    resolve the first writer's in-flight commits as though that writer had
    died. Read a live chain with ``EscrowChain.load``, which claims nothing.
    """


class RecordIntegrityError(AnchorError):
    """A signed record log (:mod:`interlock.records`) failed verification.

    A record was edited, re-linked or dropped, is signed by another key, or
    is missing where the AgentGov ledger anchors it.
    """


# -- recovery ----------------------------------------------------------------


class RecoveryError(InterlockError):
    """The recovery runtime cannot take this step.

    Raised for a misuse the caller can fix: a transcript edited between
    steps, a step never answered, a step settled twice, a recovery scope
    that exists without the records that would say what it already did.
    """


class RecoveryExhaustedError(RecoveryError):
    """Nothing is left to try.

    The ladder has no rung left for this halt, the policy's step limit is
    reached, the recovery reserve cannot cover another step, or the recovery
    scope is itself halted. The halt stands; stop the task.

    :ivar quote: When the reserve ran out and the runtime has a budget guard,
        the :class:`~interlock.extension.ExtensionRequest` that asks for more:
        granted, it lets the recovery go on.
    """

    def __init__(self, message: str, *, quote: object | None = None) -> None:
        super().__init__(message)
        self.quote = quote


class ExtensionError(InterlockError):
    """An extension quote cannot be answered as asked.

    It is unknown to this guard, was already granted or declined, has
    expired, or the scope that would fund it cannot.
    """


class ToolRevokedError(RecoveryError):
    """A call to a tool the recovery runtime revoked.

    Revocation is enforced here, where the harness runs tools, whatever the
    model was told: a model that calls a revoked tool anyway gets an error
    result, not the tool.

    :ivar tool: The revoked tool's name.
    """

    def __init__(self, tool: str) -> None:
        self.tool = tool
        super().__init__(f"tool {tool!r} was revoked for the rest of this task")


class CompactionRefusedError(InterlockError):
    """The database refused a vacuum's act (``docs/EPIC5_DESIGN.md`` §1.4):
    a message's delivery log moved after it was verified, a checkpoint does
    not follow the last one, or what the database holds is not what the
    signed checkpoint commits to. Nothing was pruned."""


class InboundFactError(PlanError):
    """A plan consumes an inbound fact it may not (``docs/EPIC5_DESIGN.md``
    §2.6): one unknown, consumed already, of another scope, or whose
    attestation does not verify under ``[inbox.keys]``; or an engine that
    verifies no facts. ``str(exc)`` is the operator's; the agent is told the
    kind of refusal only."""


class SupervisorStoppedError(InterlockError):
    """The supervisor is not accepting plans (``docs/EPIC6_DESIGN.md`` §2.5):
    not started, shutting down, or run without engines. A plan refused with it
    was never staged."""


class KeyRevokedError(InterlockError):
    """The key that would sign was revoked (``docs/EPIC8_DESIGN.md`` §2): it
    attests nothing new. A relay holding it stops before it claims; the
    database refuses what it would write. What it attested before its
    revocation still verifies, under the seal the revocation made."""
