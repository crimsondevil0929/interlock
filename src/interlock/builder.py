"""A fluent builder for :class:`~interlock.types.EffectPlan`.

``EffectPlan`` is a frozen dataclass with six required fields and ``Effect``
has four more, including two ``NewType`` identifiers and a timezone-aware
timestamp. All of that is ceremony the caller should not be writing: an
identifier nobody reads by hand, a clock reading that is wrong if it is naive,
and a dependency tuple that has to be threaded between effects in the right
order.

``PlanBuilder`` mints the identifiers, stamps UTC, and wires the DAG::

    plan = (
        PlanBuilder(scope_id="support-agent")
        .update(
            table="orders",
            statement="UPDATE orders SET total = :total WHERE id = :id",
            parameters={"total": 100.0, "id": 1},
            tenant_id="acme",
            stated_rows=1,
        )
        .build()
    )

Dependencies default to *sequential*: each effect depends on the one added
before it, which is what a caller writing statements in order almost always
means. Pass ``after=...`` to fan out instead, or ``independent=True`` to
declare an effect free of ordering constraints.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime

from interlock.exceptions import PlanError
from interlock.types import (
    Compensation,
    Effect,
    EffectId,
    EffectKind,
    EffectPlan,
    PlanId,
)

__all__ = ["PlanBuilder"]


def new_plan_id(prefix: str = "plan") -> PlanId:
    """Mint a plan identifier. Exposed so tests can predict the shape."""
    return PlanId(f"{prefix}-{uuid.uuid4().hex[:12]}")


def new_effect_id(prefix: str = "eff") -> EffectId:
    """Mint an effect identifier."""
    return EffectId(f"{prefix}-{uuid.uuid4().hex[:12]}")


class PlanBuilder:
    """Accumulate effects, then freeze them into an :class:`EffectPlan`.

    The builder is mutable and every method returns ``self``, so a plan reads
    as one expression. :meth:`build` produces an immutable plan and may be
    called more than once; each call mints a fresh ``plan_id``.

    :param scope_id: The AgentGov scope accountable for this plan. When the
        engine carries an anchor, this must name a scope AgentGov knows.
    :param trajectory_id: The logical unit of work. Defaults to a fresh id, so
        a one-shot plan needs no ceremony; pass the orchestrator's trajectory
        when retries through fresh sub-agents are still one unit of work.
    :param intent: The agent's own description, recorded for the audit trail.
    :param plan_id: Override the minted identifier. For replaying a recorded
        plan, not for normal use.
    :param created_at: Override the clock. Must be timezone-aware.
    """

    __slots__ = ("_created_at", "_effects", "_intent", "_plan_id", "_scope_id", "_trajectory_id")

    def __init__(
        self,
        scope_id: str,
        *,
        trajectory_id: str | None = None,
        intent: str = "",
        plan_id: PlanId | None = None,
        created_at: datetime | None = None,
    ) -> None:
        if created_at is not None and created_at.tzinfo is None:
            raise PlanError(
                "created_at must be timezone-aware; a naive timestamp records a "
                "moment that cannot be compared against the AgentGov chain"
            )
        self._scope_id = scope_id
        self._trajectory_id = trajectory_id or f"traj-{uuid.uuid4().hex[:12]}"
        self._intent = intent
        self._plan_id = plan_id
        self._created_at = created_at
        self._effects: list[Effect] = []

    # -- adding effects --------------------------------------------------

    def add(
        self,
        kind: EffectKind,
        *,
        table: str,
        statement: str,
        parameters: Mapping[str, object] | None = None,
        tenant_id: str | None = None,
        stated_rows: int | None = None,
        effect_id: EffectId | None = None,
        after: Sequence[EffectId] | None = None,
        independent: bool = False,
        reversible: bool = True,
        compensation: Compensation | None = None,
    ) -> PlanBuilder:
        """Append one effect.

        :param table: The effect's target. A bare table name is fine; a
            ``"<substrate_id>:<table>"`` label is passed through unchanged.
        :param statement: A parameterised statement. **Placeholders must be
            named** (``:name``), because ``parameters`` is a mapping and the
            driver binds by name. A ``?`` placeholder fails at stage time.
        :param after: Effect ids this one depends on. Defaults to the
            previously added effect, making a plan sequential by default.
        :param independent: Declare no ordering constraint at all, overriding
            the sequential default. Mutually exclusive with ``after``.
        :raises PlanError: On an unnamed placeholder, or on ``after`` naming an
            effect this builder has not seen.
        """
        if after is not None and independent:
            raise PlanError("pass either after= or independent=, not both")
        params = dict(parameters or {})
        _assert_named_placeholders(statement, params)

        if independent:
            depends: tuple[EffectId, ...] = ()
        elif after is not None:
            known = {e.effect_id for e in self._effects}
            unknown = [d for d in after if d not in known]
            if unknown:
                raise PlanError(
                    f"after= names effect(s) this builder has not added: "
                    f"{', '.join(map(str, unknown))}"
                )
            depends = tuple(after)
        else:
            depends = (self._effects[-1].effect_id,) if self._effects else ()

        self._effects.append(
            Effect(
                effect_id=effect_id or new_effect_id(),
                kind=kind,
                target=table,
                statement=statement,
                parameters=params,
                depends_on=depends,
                tenant_id=tenant_id,
                reversible=reversible,
                compensation=compensation,
                stated_rows=stated_rows,
            )
        )
        return self

    def insert(self, **kwargs: object) -> PlanBuilder:
        """Append an ``INSERT`` effect. See :meth:`add`."""
        return self.add(EffectKind.INSERT, **kwargs)  # type: ignore[arg-type]

    def update(self, **kwargs: object) -> PlanBuilder:
        """Append an ``UPDATE`` effect. See :meth:`add`."""
        return self.add(EffectKind.UPDATE, **kwargs)  # type: ignore[arg-type]

    def delete(self, **kwargs: object) -> PlanBuilder:
        """Append a ``DELETE`` effect. See :meth:`add`."""
        return self.add(EffectKind.DELETE, **kwargs)  # type: ignore[arg-type]

    # -- inspection ------------------------------------------------------

    @property
    def last_effect_id(self) -> EffectId | None:
        """The id of the most recently added effect, for use with ``after=``."""
        return self._effects[-1].effect_id if self._effects else None

    def __len__(self) -> int:
        return len(self._effects)

    # -- freezing --------------------------------------------------------

    def build(self) -> EffectPlan:
        """Freeze the accumulated effects into a plan.

        :raises PlanError: If no effects were added, or if the resulting DAG
            does not sort. The cycle check runs here rather than at admission
            so a malformed plan fails where it was written.
        """
        if not self._effects:
            raise PlanError(
                "a plan needs at least one effect; an empty plan would stage a "
                "transaction, measure nothing, and commit nothing"
            )
        plan = EffectPlan(
            plan_id=self._plan_id or new_plan_id(),
            scope_id=self._scope_id,
            trajectory_id=self._trajectory_id,
            created_at=self._created_at or datetime.now(UTC),
            effects=tuple(self._effects),
            intent=self._intent,
        )
        try:
            plan.topological_order()
        except ValueError as exc:
            raise PlanError(str(exc)) from exc
        return plan


def _assert_named_placeholders(statement: str, parameters: Mapping[str, object]) -> None:
    """Refuse a positional placeholder before it reaches the driver.

    ``Effect.parameters`` is a mapping, so SQLite binds by name. A ``?`` in the
    statement otherwise surfaces as ``sqlite3.ProgrammingError`` from inside an
    open stage, after locks are taken, with a message about dictionaries that
    does not name the real problem.
    """
    if not parameters:
        return
    without_literals = _strip_literals(statement)
    if "?" in without_literals:
        raise PlanError(
            f"statement uses a positional placeholder '?': {statement!r}. "
            f"Effect.parameters is a Mapping, so placeholders must be named "
            f"(:name). Rewrite as e.g. 'WHERE id = :id'"
        )


def _strip_literals(statement: str) -> str:
    """Blank out single-quoted string literals so a '?' inside one is ignored."""
    out: list[str] = []
    in_literal = False
    for char in statement:
        if char == "'":
            in_literal = not in_literal
            out.append("'")
        elif not in_literal:
            out.append(char)
    return "".join(out)
