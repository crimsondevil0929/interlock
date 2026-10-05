"""Two audiences for one refusal.

A refused plan produces two records, built from the same adjudication:

- :class:`OperatorEvidence` is everything: the verdict, every violation's
  message and evidence, the measured diff's shape. It is for the operator and
  the receipt, and it routinely names other tenants and exact totals, because
  that is what an operator needs.
- :class:`AgentFeedback` is what the agent may be told. It is built so that it
  cannot carry more than the agent already knew:

  * **tables** only as the plan's own effects name them;
  * **tenants** only as the plan's own effects declare them;
  * **row counts** only as buckets: 0, 1, 2-9, 10-99, 100-999, 1000+;
  * **no aggregate, ever**: no column total, no fraction of one, no count of
    tenants or tables the plan did not name, nothing a rate window holds. The
    one number that is not a bucketed row count is a built-in checker's
    configured limit, as a whole percentage: policy, not data;
  * **windows** only by name, as the operator configured them, and only from
    the built-in rate-window check;
  * **sinks** only as the plan's own requests name them;
  * **payload values and facts never**: no amount, recipient or tenant field a
    request carries, no value an inbound fact holds;
  * **text** chosen by the constraint's :class:`Guidance` kind from a fixed set
    of templates.

A checker contributes a :class:`FeedbackHint` for each violation. Hints are
untrusted input, sanitized field by field, so a custom checker cannot leak
through one: its tables and tenants are filtered against the plan, and its
numbers are dropped, because nothing can tell a row count from a total. A
violation's free-text ``message`` and ``evidence`` never reach the agent.

Send ``StageResult.feedback`` (or ``exc.feedback`` from an exception
:meth:`~interlock.engine.EscrowEngine.execute` raised) to the agent. Never send
``str(exc)``, the verdict, or the diff: those are the operator's.
"""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final

from interlock.exceptions import (
    CyclicPlanError,
    ForbiddenStatementError,
    InboundFactError,
    InterlockError,
    OutboundRequestError,
    PlanError,
    ScopeHaltedError,
    StageConflictError,
    StageError,
    StageExpiredError,
    SubstrateConfigurationError,
    SubstrateUnavailableError,
    UncompensatableEffectError,
)
from interlock.types import EffectDiff, EffectPlan, InvariantViolation, Severity, Verdict

__all__ = [
    "BUCKETS",
    "AgentFeedback",
    "ConstraintFeedback",
    "FeedbackHint",
    "Guidance",
    "OperatorEvidence",
    "Refusal",
    "agent_feedback",
    "bucket",
    "feedback_for_error",
]


# --------------------------------------------------------------------------
# The vocabulary
# --------------------------------------------------------------------------


BUCKETS: Final = ("0", "1", "2-9", "10-99", "100-999", "1000+")
"""Every row count the agent can be shown."""


def bucket(count: int) -> str:
    """A row count as the agent may see it: one of :data:`BUCKETS`."""
    if count <= 0:
        return "0"
    if count == 1:
        return "1"
    if count < 10:
        return "2-9"
    if count < 100:
        return "10-99"
    if count < 1000:
        return "100-999"
    return "1000+"


class Guidance(StrEnum):
    """What kind of constraint refused the plan. Picks the feedback template."""

    # Raised by a checker over the measured diff.
    ROW_LIMIT = "row_limit"
    TENANT_SCOPE = "tenant_scope"
    TABLE_SCOPE = "table_scope"
    NO_DELETE = "no_delete"
    VALUE_DROP = "value_drop"
    TENANT_DRAWDOWN = "tenant_drawdown"
    TRUNCATED = "truncated"
    STATED_FOOTPRINT = "stated_footprint"
    SCHEMA_CHANGE = "schema_change"
    OPERATOR = "operator"
    # Raised before or during staging, by admission or the substrate.
    STATEMENT_KIND = "statement_kind"
    UNOBSERVED_WRITE = "unobserved_write"
    CASCADE = "cascade"
    PROTECTED = "protected"
    TRANSACTION_CONTROL = "transaction_control"
    STATEMENT_FAILED = "statement_failed"
    MALFORMED_PLAN = "malformed_plan"
    CONFLICT = "conflict"
    EXPIRED = "expired"
    SCOPE_HALTED = "scope_halted"
    UNAVAILABLE = "unavailable"
    OUTBOUND_REQUEST = "outbound_request"
    # Raised by a checker over the measured diff and the outbox.
    OUTBOUND_AGREEMENT = "outbound_agreement"
    # Raised by a checker over the measured diff and its windows' history.
    RATE_WINDOW = "rate_window"
    # Raised by a checker over the outbound requests (docs/OUTBOX_DESIGN.md §5.2).
    OUTBOUND_SCOPE = "outbound_scope"
    OUTBOUND_COUNT = "outbound_count"
    OUTBOUND_AMOUNT = "outbound_amount"
    OUTBOUND_RECIPIENT = "outbound_recipient"
    OUTBOUND_TENANT = "outbound_tenant"
    # Raised by admission, or a checker over the facts a plan consumes
    # (docs/EPIC5_DESIGN.md §2).
    INBOUND_FACT = "inbound_fact"
    FACT_AGREEMENT = "fact_agreement"


_LABELS: Final[Mapping[Guidance, str]] = {
    Guidance.ROW_LIMIT: "blast_radius",
    Guidance.TENANT_SCOPE: "tenant_isolation",
    Guidance.TABLE_SCOPE: "table_allowlist",
    Guidance.NO_DELETE: "no_delete",
    Guidance.VALUE_DROP: "column_value_guard",
    Guidance.TENANT_DRAWDOWN: "tenant_drawdown_guard",
    Guidance.TRUNCATED: "truncation_guard",
    Guidance.STATED_FOOTPRINT: "stated_footprint",
    Guidance.SCHEMA_CHANGE: "no_schema_change",
    Guidance.OPERATOR: "operator_constraint",
    Guidance.STATEMENT_KIND: "statement_kind",
    Guidance.UNOBSERVED_WRITE: "unobserved_write",
    Guidance.CASCADE: "cascade",
    Guidance.PROTECTED: "protected_records",
    Guidance.TRANSACTION_CONTROL: "transaction_control",
    Guidance.STATEMENT_FAILED: "statement_failed",
    Guidance.MALFORMED_PLAN: "malformed_plan",
    Guidance.CONFLICT: "write_conflict",
    Guidance.EXPIRED: "stage_expired",
    Guidance.SCOPE_HALTED: "scope_halted",
    Guidance.UNAVAILABLE: "unavailable",
    Guidance.OUTBOUND_REQUEST: "outbound_request",
    Guidance.OUTBOUND_AGREEMENT: "cross_effect_agreement",
    Guidance.RATE_WINDOW: "rate_window",
    Guidance.OUTBOUND_SCOPE: "sink_allowlist",
    Guidance.OUTBOUND_COUNT: "outbound_count",
    Guidance.OUTBOUND_AMOUNT: "payload_amount_cap",
    Guidance.OUTBOUND_RECIPIENT: "recipient_allowlist",
    Guidance.OUTBOUND_TENANT: "outbound_tenant_isolation",
    Guidance.INBOUND_FACT: "inbound_fact",
    Guidance.FACT_AGREEMENT: "fact_agreement",
}
"""The public name of each kind. Derived from the kind, never from a checker's
own ``name``, which can embed configuration (``column_value_guard:orders.total``)
naming a table the plan never did."""

_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,62}")


@dataclass(frozen=True, slots=True)
class FeedbackHint:
    """What a checker offers to tell the agent about one violation. Untrusted.

    Every field is checked against the plan before it is used: see
    :func:`agent_feedback`.

    :ivar tables: Tables involved. Kept only where the plan names them.
    :ivar tenants: Tenants involved. Kept only where the plan declares them.
    :ivar columns: Columns involved, of ``tables``. Kept only from a
        built-in checker, and only when every table the hint names is one the
        plan names.
    :ivar measured: A row count the plan produced. Bucketed; built-in
        checkers only.
    :ivar limit: A row limit the checker was configured with. Bucketed;
        built-in checkers only.
    :ivar percent: A fractional limit the checker was configured with, as a
        whole percentage. Built-in checkers only.
    :ivar window: The name of the rate window that refused the plan. Kept
        only from the built-in rate-window check, and only as an identifier.
    :ivar sinks: Sinks involved. Kept only where the plan's own requests name
        them.
    """

    kind: Guidance
    tables: tuple[str, ...] = ()
    tenants: tuple[str, ...] = ()
    columns: tuple[str, ...] = ()
    measured: int | None = None
    limit: int | None = None
    percent: int | None = None
    window: str = ""
    sinks: tuple[str, ...] = ()


# --------------------------------------------------------------------------
# The agent's record
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ConstraintFeedback:
    """One constraint, as the agent may see it. Already sanitized.

    :ivar withheld_tables: The constraint also involved a table the plan does
        not name. Said, never named or counted.
    :ivar withheld_tenants: The same, for tenants the plan does not declare.
    """

    guidance: Guidance
    blocking: bool
    tables: tuple[str, ...] = ()
    tenants: tuple[str, ...] = ()
    columns: tuple[str, ...] = ()
    measured: str | None = None
    limit: str | None = None
    percent: int | None = None
    withheld_tables: bool = False
    withheld_tenants: bool = False
    window: str = ""
    sinks: tuple[str, ...] = ()

    @property
    def constraint(self) -> str:
        return _LABELS[self.guidance]

    def render(self) -> str:
        """One sentence, from the kind's fixed template."""
        return f"{self.constraint}: {_TEMPLATES[self.guidance](self)}"

    def to_json(self) -> dict[str, Any]:
        named: dict[str, Any] = {"window": self.window} if self.window else {}
        if self.sinks:
            named["sinks"] = list(self.sinks)
        return {
            "constraint": self.constraint,
            "guidance": self.guidance.value,
            "blocking": self.blocking,
            "tables": list(self.tables),
            "tenants": list(self.tenants),
            "columns": list(self.columns),
            "measured": self.measured,
            "limit": self.limit,
            "percent": self.percent,
            "withheld_tables": self.withheld_tables,
            "withheld_tenants": self.withheld_tenants,
            **named,
            "text": self.render(),
        }


@dataclass(frozen=True, slots=True)
class AgentFeedback:
    """Everything the agent may be told about what happened to its plan.

    :ivar outcome: ``"committed"``, ``"refused"``, or ``"error"`` when the
        plan never reached adjudication.
    :ivar retryable: Whether resubmitting the same plan unchanged may
        succeed: a write conflict, an expired stage, an unavailable
        database. A refusal by a constraint is never retryable unchanged.
    """

    outcome: str
    constraints: tuple[ConstraintFeedback, ...] = ()
    retryable: bool = False

    @property
    def blocking(self) -> tuple[ConstraintFeedback, ...]:
        return tuple(c for c in self.constraints if c.blocking)

    def render(self) -> str:
        """The text to hand the agent."""
        head = {
            "committed": "The plan committed.",
            "refused": "The plan was refused and rolled back; nothing changed.",
            "error": "The plan was not staged; nothing changed.",
        }.get(self.outcome, "Nothing changed.")
        lines = [head, *(f"- {c.render()}" for c in self.constraints)]
        if self.retryable:
            lines.append("The same plan may succeed if resubmitted.")
        return "\n".join(lines)

    def to_json(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome,
            "retryable": self.retryable,
            "constraints": [c.to_json() for c in self.constraints],
        }


def _tables(c: ConstraintFeedback, *, fallback: str = "a table the plan does not name") -> str:
    named = ", ".join(c.tables)
    if named and c.withheld_tables:
        return f"{named} and a table the plan does not name"
    return named or fallback


def _tenants(c: ConstraintFeedback) -> str:
    return ", ".join(c.tenants) if c.tenants else "none"


def _column(c: ConstraintFeedback) -> str:
    if len(c.tables) == 1 and len(c.columns) == 1 and not c.withheld_tables:
        return f"{c.tables[0]}.{c.columns[0]}"
    return "a guarded column"


def _sinks(c: ConstraintFeedback) -> str:
    return ", ".join(c.sinks) or "a sink"


def _percent(c: ConstraintFeedback) -> str:
    return f"the {c.percent}% allowed" if c.percent is not None else "what is allowed"


def _drawdown(c: ConstraintFeedback) -> str:
    whom = (
        f"tenant {', '.join(c.tenants)}"
        if c.tenants
        else "a tenant outside the plan's declared tenants"
    )
    return f"the plan lowers {_column(c)} by more than {_percent(c)} for {whom}."


_TEMPLATES: Final[Mapping[Guidance, Any]] = {
    Guidance.ROW_LIMIT: lambda c: (
        f"the plan changed {c.measured or 'too many'} rows; the limit is "
        f"{c.limit or 'lower'}. Narrow the statements' WHERE clauses or split the work."
    ),
    Guidance.TENANT_SCOPE: lambda c: (
        f"the plan changed rows of more tenants than one plan may "
        f"(at most {c.limit or 'a set number'}); its declared tenants are {_tenants(c)}. "
        f"Confine every statement to its declared tenants."
    ),
    Guidance.TABLE_SCOPE: lambda c: (
        f"the plan changed rows in {_tables(c)}, which it may not write."
    ),
    Guidance.NO_DELETE: lambda c: (
        f"the plan deletes rows from {_tables(c)}, where deletes are not allowed."
    ),
    Guidance.VALUE_DROP: lambda c: f"the plan lowers {_column(c)} by more than {_percent(c)}.",
    Guidance.TENANT_DRAWDOWN: _drawdown,
    Guidance.TRUNCATED: lambda c: (
        f"the plan changed more rows than can be measured ({c.measured or 'too many'}). "
        f"Split the work."
    ),
    # For this kind ``limit`` carries the plan's own stated count.
    Guidance.STATED_FOOTPRINT: lambda c: (
        f"the plan stated {c.limit or 'a number of'} rows; the database measured "
        f"{c.measured or 'more'}."
    ),
    Guidance.SCHEMA_CHANGE: lambda c: (
        "an effect is declared as a schema change, which cannot be staged."
    ),
    Guidance.OPERATOR: lambda c: "an operator-defined check refused the plan.",
    Guidance.STATEMENT_KIND: lambda c: (
        "a statement is of a kind that cannot be staged; only row statements "
        "(SELECT, INSERT, UPDATE, DELETE) run in a plan."
    ),
    Guidance.UNOBSERVED_WRITE: lambda c: (
        f"a statement writes {_tables(c)}, which this runtime does not let a plan write."
    ),
    Guidance.CASCADE: lambda c: (
        f"changing {_tables(c)} this way would cascade into data this runtime does "
        f"not measure. Leave its rows and keys in place in a plan."
    ),
    Guidance.PROTECTED: lambda c: "a statement tried to change the runtime's own records.",
    Guidance.TRANSACTION_CONTROL: lambda c: (
        "transaction control (BEGIN, COMMIT, ROLLBACK, SAVEPOINT) is not allowed in a plan."
    ),
    Guidance.STATEMENT_FAILED: lambda c: "a statement failed in the database.",
    Guidance.MALFORMED_PLAN: lambda c: "the plan is malformed and was not staged.",
    Guidance.CONFLICT: lambda c: "another writer holds the rows the plan needs.",
    Guidance.EXPIRED: lambda c: "the plan took longer than a stage allows. Split the work.",
    Guidance.SCOPE_HALTED: lambda c: "the agent's scope is halted; no plan will be staged.",
    Guidance.UNAVAILABLE: lambda c: "the database could not be reached.",
    Guidance.OUTBOUND_REQUEST: lambda c: (
        "an outbound request names a sink or operation that is not registered, or its "
        "payload breaks that operation's rules (schema, size, credentials, compensation)."
    ),
    Guidance.OUTBOUND_AGREEMENT: lambda c: (
        f"an outbound request disagrees with {_column(c)} as this plan wrote it. A request "
        f"must carry what the rows it goes with record: make the two agree, or drop both."
    ),
    Guidance.RATE_WINDOW: lambda c: (
        f"the plan would take {'rate window ' + c.window if c.window else 'a rate window'} "
        f"past its limit"
        + (f" for tenant {', '.join(c.tenants)}" if c.tenants else "")
        + ". The window slides: what earlier plans added stops counting as it ages."
    ),
    Guidance.OUTBOUND_SCOPE: lambda c: (
        f"a request to {_sinks(c)} uses a sink or operation this plan may not call."
    ),
    Guidance.OUTBOUND_COUNT: lambda c: (
        f"the plan enqueues {c.measured or 'too many'} outbound request(s)"
        + (f" to {_sinks(c)}" if c.sinks else "")
        + f"; the limit is {c.limit or 'lower'}. Split the work."
    ),
    Guidance.OUTBOUND_AMOUNT: lambda c: (
        f"a request to {_sinks(c)} carries an amount over its cap, or one that is not a "
        f"plain non-negative number."
    ),
    Guidance.OUTBOUND_RECIPIENT: lambda c: (
        f"a request to {_sinks(c)} addresses a recipient outside the allowed ones, or one "
        f"that is not a single plain address."
    ),
    Guidance.OUTBOUND_TENANT: lambda c: (
        f"the plan's outbound requests reach beyond its tenants "
        f"(at most {c.limit or 'a set number'}); its declared tenants are {_tenants(c)}. A "
        f"request goes only to a tenant the plan's rows involve, and its payload names that "
        f"tenant where it names one."
    ),
    Guidance.INBOUND_FACT: lambda c: (
        "a fact the plan consumes is not pending for its scope, or does not verify. Read the "
        "pending facts again before planning on one."
    ),
    Guidance.FACT_AGREEMENT: lambda c: (
        f"the plan writes {_column(c)} without consuming the inbound fact it must follow, or "
        f"other than that fact says. Consume the fact, and write what it says."
    ),
}


# --------------------------------------------------------------------------
# The operator's record
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class OperatorEvidence:
    """Everything about the refusal. Never for the agent.

    :ivar violations: Every violation, with its full message and evidence.
    """

    plan_id: str
    plan_hash: str
    diff_hash: str | None
    verdict_hash: str | None
    violations: tuple[InvariantViolation, ...] = ()
    tables_touched: tuple[str, ...] = ()
    tenants_touched: tuple[str, ...] = ()
    blast_radius: int = 0
    error: str | None = None

    @classmethod
    def of(
        cls,
        plan: EffectPlan,
        *,
        diff: EffectDiff | None = None,
        verdict: Verdict | None = None,
        error: BaseException | None = None,
    ) -> OperatorEvidence:
        return cls(
            plan_id=str(plan.plan_id),
            plan_hash=plan.content_hash(),
            diff_hash=diff.content_hash() if diff is not None else None,
            verdict_hash=verdict.content_hash() if verdict is not None else None,
            violations=verdict.violations if verdict is not None else (),
            tables_touched=tuple(sorted(diff.tables_touched)) if diff is not None else (),
            tenants_touched=tuple(sorted(diff.tenant_ids)) if diff is not None else (),
            blast_radius=diff.blast_radius if diff is not None else 0,
            error=None if error is None else f"{type(error).__name__}: {error}",
        )


@dataclass(frozen=True, slots=True)
class Refusal:
    """A refused plan, split by audience."""

    evidence: OperatorEvidence
    feedback: AgentFeedback


# --------------------------------------------------------------------------
# Sanitizing
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Scope:
    """What the plan itself names: the only tables and tenants feedback may."""

    tables: Mapping[str, str]
    """Lowercased table name -> the plan's spelling."""
    tenants: frozenset[str]
    sinks: frozenset[str] = frozenset()
    """The sinks the plan's own requests name."""

    @classmethod
    def of(cls, plan: EffectPlan) -> _Scope:
        tables: dict[str, str] = {}
        for effect in plan.effects:
            tables.setdefault(effect.table.lower(), effect.table)
        tenants = frozenset(e.tenant_id for e in plan.effects if e.tenant_id is not None)
        sinks = frozenset(e.request.sink for e in plan.effects if e.request is not None)
        return cls(tables=tables, tenants=tenants, sinks=sinks)


@dataclass(frozen=True, slots=True)
class HintedViolation:
    """A violation, the hint its checker offered, and whether to trust the
    hint's numbers (only a built-in checker's)."""

    violation: InvariantViolation
    hint: FeedbackHint
    trusted: bool = False


def sanitize(
    hint: FeedbackHint, plan: EffectPlan, *, blocking: bool, trusted: bool
) -> ConstraintFeedback:
    """Reduce a hint to what the plan itself entitles the agent to see."""
    scope = _Scope.of(plan)
    kind = hint.kind if isinstance(hint.kind, Guidance) else Guidance.OPERATOR
    tables: list[str] = []
    withheld_tables = False
    for table in hint.tables:
        known = scope.tables.get(str(table).lower())
        if known is None:
            withheld_tables = True
        elif known not in tables:
            tables.append(known)
    tenants: list[str] = []
    withheld_tenants = False
    for tenant in hint.tenants:
        if tenant in scope.tenants:
            if tenant not in tenants:
                tenants.append(tenant)
        else:
            withheld_tenants = True
    columns: tuple[str, ...] = ()
    # Columns only from a built-in checker, where they are its configuration.
    # A custom hint could spell a tenant id as a "column".
    if trusted and tables and not withheld_tables:
        columns = tuple(
            dict.fromkeys(
                c for c in hint.columns if isinstance(c, str) and _IDENTIFIER.fullmatch(c)
            )
        )
    measured = limit = None
    percent: int | None = None
    window = ""
    if trusted:
        measured = bucket(hint.measured) if isinstance(hint.measured, int) else None
        limit = bucket(hint.limit) if isinstance(hint.limit, int) else None
        if isinstance(hint.percent, int) and 0 <= hint.percent <= 100:
            percent = hint.percent
        # A window's name only for a window's guidance, from the built-in
        # check: anything else could spell data as a "name".
        if (
            kind is Guidance.RATE_WINDOW
            and isinstance(hint.window, str)
            and _IDENTIFIER.fullmatch(hint.window)
        ):
            window = hint.window
    # Sinks only as the plan's own requests name them: anything else could
    # spell a payload value as a "sink".
    sinks = tuple(sorted({str(s) for s in hint.sinks if str(s) in scope.sinks}))
    return ConstraintFeedback(
        guidance=kind,
        blocking=blocking,
        tables=tuple(sorted(tables)),
        tenants=tuple(sorted(tenants)),
        columns=columns,
        measured=measured,
        limit=limit,
        percent=percent,
        withheld_tables=withheld_tables,
        withheld_tenants=withheld_tenants,
        window=window,
        sinks=sinks,
    )


def agent_feedback(
    plan: EffectPlan, hinted: Iterable[HintedViolation], *, committed: bool
) -> AgentFeedback:
    """The agent's record of an adjudicated plan.

    Each constraint appears once, in a canonical order: blocking before
    advisory, then by kind, then by text. Never in the order the violations
    came: a checker lists them by tenant, so their order would say how an
    undeclared tenant's id sorts against a declared one.
    """
    unique: dict[str, ConstraintFeedback] = {}
    for item in hinted:
        constraint = sanitize(
            item.hint,
            plan,
            blocking=item.violation.severity is Severity.BLOCKING,
            trusted=item.trusted,
        )
        unique.setdefault(repr(constraint.to_json()), constraint)
    kinds = list(Guidance)
    ordered = sorted(
        unique.values(),
        key=lambda c: (not c.blocking, kinds.index(c.guidance), c.render()),
    )
    return AgentFeedback(
        outcome="committed" if committed else "refused",
        constraints=tuple(ordered),
    )


# --------------------------------------------------------------------------
# Errors
# --------------------------------------------------------------------------


_REASON_GUIDANCE: Final[Mapping[str, Guidance]] = {
    "statement_kind": Guidance.STATEMENT_KIND,
    "unobserved_table": Guidance.UNOBSERVED_WRITE,
    "privilege": Guidance.UNOBSERVED_WRITE,
    "cascade": Guidance.CASCADE,
    "protected": Guidance.PROTECTED,
    "transaction_control": Guidance.TRANSACTION_CONTROL,
    "reach": Guidance.STATEMENT_KIND,
    "multiple_statements": Guidance.STATEMENT_KIND,
}


def feedback_for_error(plan: EffectPlan, error: BaseException) -> AgentFeedback:
    """The agent's record of a plan that never reached a verdict.

    Reads the exception's type and structured fields, never its message:
    a database error's text can quote another row's values.
    """
    blocking = True
    retryable = False
    hint: FeedbackHint
    if isinstance(error, InboundFactError):
        hint = FeedbackHint(kind=Guidance.INBOUND_FACT)
    elif isinstance(error, ForbiddenStatementError):
        kind = _REASON_GUIDANCE.get(error.reason, Guidance.STATEMENT_KIND)
        tables = (error.table,) if error.table else ()
        hint = FeedbackHint(kind=kind, tables=tables)
    elif isinstance(error, OutboundRequestError):
        hint = FeedbackHint(kind=Guidance.OUTBOUND_REQUEST)
    elif isinstance(error, ScopeHaltedError):
        hint = FeedbackHint(kind=Guidance.SCOPE_HALTED)
    elif isinstance(error, CyclicPlanError | UncompensatableEffectError | PlanError):
        hint = FeedbackHint(kind=Guidance.MALFORMED_PLAN)
    elif isinstance(error, StageConflictError):
        hint = FeedbackHint(kind=Guidance.CONFLICT)
        retryable = True
    elif isinstance(error, StageExpiredError):
        hint = FeedbackHint(kind=Guidance.EXPIRED)
    elif isinstance(error, SubstrateUnavailableError | SubstrateConfigurationError):
        hint = FeedbackHint(kind=Guidance.UNAVAILABLE)
        retryable = isinstance(error, SubstrateUnavailableError)
    elif isinstance(error, StageError):
        hint = FeedbackHint(kind=Guidance.STATEMENT_FAILED)
    elif isinstance(error, InterlockError | sqlite3.Error):
        hint = FeedbackHint(kind=Guidance.STATEMENT_FAILED)
    else:
        hint = FeedbackHint(kind=Guidance.UNAVAILABLE)
    return AgentFeedback(
        outcome="error",
        constraints=(sanitize(hint, plan, blocking=blocking, trusted=False),),
        retryable=retryable,
    )
