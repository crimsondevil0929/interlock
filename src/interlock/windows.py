"""Rate windows: a plan measured with its history (``docs/EPIC4_DESIGN.md`` §3).

A checker sees one plan. An agent that keeps every plan under every per-plan
limit, a refund of 50 a hundred times over, passes every one of them. A rate
window measures a plan with what came before it: "at most 10 emails per tenant
per hour", "at most 10,000 of refunds per agent per day".

A :class:`RateWindow` says what a plan adds (its *measure*: :class:`Requests`,
:class:`RequestSum`, :class:`RowSum`, :class:`Plans`), whose history it adds to
(*per* scope, tenant, or globally), over how long (*span*), and the most the
window may hold (*limit*). Windows compose: one per tenant and one per scope
together leave nothing to gain from spreading requests across tenants, which
a plan declares itself.

An engine configured with windows (``EscrowEngine(windows=...)``) measures what
each plan adds from its diff, then has the substrate read the history of every
window key the plan adds to, with the key locked:

- **PostgreSQL** takes a transaction-scoped advisory lock for each key, in
  sorted order, held until the stage commits or rolls back; then it reads the
  history through ``interlock.window_totals`` on a second connection, in
  ``READ COMMITTED``. The stage's own ``REPEATABLE READ`` snapshot cannot see
  what committed after it began; the second connection sees every commit,
  and no stage can commit to a locked key until this one is done. The count
  is exact. Stages contending for one key serialize from measurement to
  commit; stages that add to different keys, or to none, take no lock in
  common.
- **SQLite** reads it in the stage. The stage holds the database's write lock
  from ``BEGIN IMMEDIATE``, so its snapshot is the latest, and stays so.

The history and what the plan adds go into the diff
(:class:`~interlock.types.WindowMeasure`), so the diff's hash, recorded as
``DIFF_COMPUTED``, covers them, and :class:`RateWindowCheck` (one per window,
added by the engine) decides from the plan and the diff alone, as every
checker does. When the plan commits, what it adds is written in the stage's
own transaction, bound to its commit marker; a plan refused or rolled back adds
nothing. Agent statements can neither write window history nor read it: it
shows other plans', and other tenants', activity.

The agent is told which window refused its plan, and never what the window
holds.
"""

from __future__ import annotations

import hashlib
import math
import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import timedelta
from decimal import Decimal, InvalidOperation
from typing import Final

from interlock.feedback import FeedbackHint, Guidance
from interlock.types import (
    EffectDiff,
    EffectPlan,
    InvariantViolation,
    Severity,
    exact_number,
    field_path,
    value_at,
)

__all__ = [
    "PER",
    "Measure",
    "Plans",
    "RateWindow",
    "RateWindowCheck",
    "RequestSum",
    "Requests",
    "RowSum",
    "WindowCharge",
    "charges",
    "window_lock",
]

PER: Final = ("scope", "tenant", "global")
"""Whose history a window keeps: each scope's (the agent's), each tenant's, or
one for everything."""

_NAME: Final = re.compile(r"[a-z][a-z0-9_]{0,62}")
_ROWS: Final = ("inserted", "net")


@dataclass(frozen=True, slots=True)
class Requests:
    """Counts outbound requests to ``sink``: every operation, or ``operation``.

    Per tenant, a request counts toward the tenant its plan declared for it.
    """

    sink: str
    operation: str | None = None

    def __post_init__(self) -> None:
        _require("sink", self.sink)
        if self.operation is not None:
            _require("operation", self.operation)


@dataclass(frozen=True, slots=True)
class RequestSum:
    """Sums a number in outbound requests' payloads: ``field`` (a dotted path:
    ``"amount"``, ``"refund.amount"``) of each ``sink.operation`` request.

    A request with no number there, or a negative one, refuses the plan: the
    window cannot say what it adds.
    """

    sink: str
    operation: str
    field: str

    def __post_init__(self) -> None:
        _require("sink", self.sink)
        _require("operation", self.operation)
        _require("field", self.field)


@dataclass(frozen=True, slots=True)
class RowSum:
    """Sums ``column`` over the plan's rows of ``table``, measured as
    :class:`~interlock.invariants.CrossEffectAgreement` measures them.

    - ``rows="inserted"`` (the default): the values of the rows the plan
      inserted. A negative one refuses the plan, since it would cancel what
      the others add.
    - ``rows="net"``: after minus before, over every row of the table the plan
      wrote, netted per window key: what it adds is the key's net increase. A
      net decrease adds nothing, and takes nothing back; money moved between
      rows of one key adds nothing.

    A row whose ``column`` holds no number refuses the plan. A float, which is
    how SQLite hands back a ``NUMERIC`` column, is read at the precision SQLite
    printed it with.
    """

    table: str
    column: str
    rows: str = "inserted"

    def __post_init__(self) -> None:
        _require("table", self.table)
        _require("column", self.column)
        if self.rows not in _ROWS:
            raise ValueError(f"rows is one of {', '.join(_ROWS)}, not {self.rows!r}")


@dataclass(frozen=True, slots=True)
class Plans:
    """Counts committed plans. Per tenant, a plan counts once toward every
    tenant whose rows or requests it holds."""


Measure = Requests | RequestSum | RowSum | Plans
"""What a plan adds to a window."""


@dataclass(frozen=True, slots=True, init=False)
class RateWindow:
    """At most ``limit`` of ``measure`` within any ``span``, ``per`` key.

    :param name: Lowercase letters, digits and underscores, starting with a
        letter: it names the window to the agent its limit refuses, and in
        the window's history.
    :param span: How far back the window looks. It slides: what a plan added
        stops counting ``span`` after the plan committed.
    :param limit: The most the window may hold for one key, the plan
        included: a plan that would take it past is refused. An integer, a
        ``Decimal`` or a decimal string; never a float.
    :param measure: What a plan adds.
    :param per: ``"scope"`` (the default): each agent's own history.
        ``"tenant"``: each tenant's, across agents. ``"global"``: one history.
    :raises ValueError: On a name, span, limit, measure or ``per`` that is
        not one.
    """

    name: str
    span: timedelta
    limit: Decimal
    measure: Measure
    per: str

    def __init__(
        self,
        name: str,
        span: timedelta,
        limit: Decimal | int | str,
        measure: Measure,
        per: str = "scope",
    ) -> None:
        if not isinstance(name, str) or not _NAME.fullmatch(name):
            raise ValueError(
                f"a window's name is lowercase letters, digits and underscores, starting "
                f"with a letter: {name!r}"
            )
        if not isinstance(span, timedelta) or span < timedelta(milliseconds=1):
            raise ValueError(f"window {name}: its span is at least a millisecond")
        if not isinstance(measure, Requests | RequestSum | RowSum | Plans):
            raise ValueError(f"window {name}: measure is Requests, RequestSum, RowSum or Plans")
        if per not in PER:
            raise ValueError(f"window {name}: per is one of {', '.join(PER)}")
        for field, value in (
            ("name", name),
            ("span", span),
            ("limit", _limit(name, limit)),
            ("measure", measure),
            ("per", per),
        ):
            object.__setattr__(self, field, value)

    def amounts(
        self, plan: EffectPlan, diff: EffectDiff
    ) -> tuple[dict[str, Decimal], tuple[str, ...]]:
        """What the plan adds to this window, by key (only keys it adds to);
        and what in the plan the window could not measure, each of which
        refuses it."""
        measure = self.measure
        added: dict[str, Decimal] = {}
        problems: list[str] = []

        def add(tenant: str | None, amount: Decimal) -> None:
            key = self.key(plan, tenant)
            added[key] = added.get(key, Decimal(0)) + amount

        if isinstance(measure, Plans):
            if self.per == "tenant":
                tenants = {d.tenant_id or "" for d in diff.deltas}
                tenants |= {o.tenant_id or "" for o in diff.outbound}
                for tenant in tenants or {""}:
                    add(tenant, Decimal(1))
            else:
                add(None, Decimal(1))
        elif isinstance(measure, Requests | RequestSum):
            for request in diff.outbound:
                if request.sink != measure.sink or (
                    measure.operation is not None and request.operation != measure.operation
                ):
                    continue
                if isinstance(measure, Requests):
                    add(request.tenant_id, Decimal(1))
                    continue
                found, value = value_at(request.payload, field_path(measure.field))
                number = exact_number(value) if found else None
                what = f"a {request.sink}.{request.operation} request"
                if number is None:
                    problems.append(f"{what} carries no number at {measure.field}")
                elif number < 0:
                    problems.append(f"{what} carries a negative {measure.field}")
                else:
                    add(request.tenant_id, number)
        else:
            table = measure.table.lower()
            net: dict[str, Decimal] = {}
            for row in diff.deltas:
                if row.table.lower() != table:
                    continue
                if measure.rows == "inserted":
                    if row.operation != "insert" or row.after is None:
                        continue
                    number = _row_number(row.after.get(measure.column))
                    if number is None or number < 0:
                        problems.append(
                            f"a {measure.table} row holds "
                            f"{'no number' if number is None else 'a negative number'} in "
                            f"{measure.column}"
                        )
                    else:
                        add(row.tenant_id, number)
                    continue
                change = Decimal(0)
                for image, sign in ((row.after, 1), (row.before, -1)):
                    if image is None:
                        continue
                    number = _row_number(image.get(measure.column))
                    if number is None:
                        problems.append(
                            f"a {measure.table} row holds no number in {measure.column}"
                        )
                        break
                    change += sign * number
                else:
                    # Netted per key: a transfer between two of one key's
                    # rows adds nothing to it.
                    key = self.key(plan, row.tenant_id)
                    net[key] = net.get(key, Decimal(0)) + change
            for key, total in net.items():
                if total > 0:
                    added[key] = added.get(key, Decimal(0)) + total
        return {k: v for k, v in added.items() if v > 0}, tuple(problems)

    def key(self, plan: EffectPlan, tenant: str | None) -> str:
        """Whose history something the plan adds belongs to."""
        if self.per == "scope":
            return plan.scope_id
        if self.per == "tenant":
            return tenant or ""
        return ""

    def whose(self, key: str) -> str:
        """``key``, said for the operator."""
        if self.per == "scope":
            return f"scope {key}"
        if self.per == "tenant":
            return f"tenant {key}" if key else "what names no tenant"
        return "everything"


@dataclass(frozen=True, slots=True)
class WindowCharge:
    """What a plan adds to one window key. The substrate locks the key, reads
    what the window holds for it over ``span``, and, when the plan commits,
    writes ``amount`` beside its commit marker."""

    window: str
    key: str
    span: timedelta
    amount: Decimal


def charges(
    windows: Sequence[RateWindow], plan: EffectPlan, diff: EffectDiff
) -> tuple[WindowCharge, ...]:
    """Every window key the plan adds to, with what it adds, in a stable order."""
    found: list[WindowCharge] = []
    for window in windows:
        amounts, _ = window.amounts(plan, diff)
        found += [
            WindowCharge(window.name, key, window.span, amount)
            for key, amount in sorted(amounts.items())
        ]
    return tuple(found)


def window_lock(window: str, key: str) -> int:
    """The PostgreSQL advisory lock that serializes one window key: 64 bits of
    a hash of the two, as a signed ``bigint``. Two keys sharing one (2^-64)
    only serialize more than they need to."""
    digest = hashlib.sha256(f"interlock/window\x00{window}\x00{key}".encode()).digest()
    return int.from_bytes(digest[:8], "big", signed=True)


class RateWindowCheck:
    """Refuses a plan that would take its window past the limit.

    Built in: the engine adds one for each window it is configured with. A
    pure function of the plan and the diff, which carries the window's
    history as the stage measured it. It refuses, failing closed, when the
    diff carries no measure of a key the plan adds to, a measure of another
    amount than the plan adds, or anything the window could not measure.
    """

    __slots__ = ("_window",)

    def __init__(self, window: RateWindow) -> None:
        self._window = window

    @property
    def window(self) -> RateWindow:
        return self._window

    @property
    def name(self) -> str:
        return f"rate_window:{self._window.name}"

    def check(self, plan: EffectPlan, diff: EffectDiff) -> tuple[InvariantViolation, ...]:
        window = self._window
        amounts, problems = window.amounts(plan, diff)
        violations = [self._violation(problem, {}) for problem in problems]
        for key in sorted(amounts):
            amount = amounts[key]
            measured = diff.window(window.name, key)
            evidence = {"key": key, "amount": _text(amount)}
            whose = window.whose(key)
            if measured is None:
                violations.append(
                    self._violation(
                        f"window {window.name} was not measured for {whose}: nothing says "
                        f"what it holds",
                        evidence,
                    )
                )
            elif measured.amount != amount:
                violations.append(
                    self._violation(
                        f"window {window.name}: the stage measured {_text(measured.amount)} "
                        f"added for {whose}, and the plan adds {_text(amount)}",
                        {**evidence, "measured": _text(measured.amount)},
                    )
                )
            elif measured.history + amount > window.limit:
                violations.append(
                    self._violation(
                        f"window {window.name} holds {_text(measured.history)} for {whose} "
                        f"within {window.span}; the plan adds {_text(amount)}, past its "
                        f"limit of {_text(window.limit)}",
                        {
                            **evidence,
                            "history": _text(measured.history),
                            "limit": _text(window.limit),
                        },
                    )
                )
        return tuple(violations)

    def _violation(self, message: str, evidence: dict[str, str]) -> InvariantViolation:
        return InvariantViolation(
            invariant=self.name,
            severity=Severity.BLOCKING,
            message=message,
            evidence={"window": self._window.name, "per": self._window.per, **evidence},
        )

    def hint(
        self, plan: EffectPlan, diff: EffectDiff, violation: InvariantViolation
    ) -> FeedbackHint:
        # The window, never what it holds: its history is other plans'.
        key = violation.evidence.get("key", "")
        tenants = (key,) if self._window.per == "tenant" and key else ()
        return FeedbackHint(kind=Guidance.RATE_WINDOW, tenants=tenants, window=self._window.name)


def _row_number(value: object) -> Decimal | None:
    if isinstance(value, float):
        return Decimal(str(value)) if math.isfinite(value) else None
    return exact_number(value)


def _require(label: str, value: object) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"a window's measure needs its {label}")


def _limit(name: str, raw: object) -> Decimal:
    if isinstance(raw, bool) or not isinstance(raw, int | str | Decimal):
        raise ValueError(f"window {name}: its limit is a number, not {raw!r}")
    try:
        limit = Decimal(str(raw)) if not isinstance(raw, Decimal) else raw
    except InvalidOperation as exc:
        raise ValueError(f"window {name}: its limit is a number, not {raw!r}") from exc
    if not limit.is_finite() or limit < 0:
        raise ValueError(f"window {name}: its limit is a finite number, at least 0")
    return limit


def _text(amount: Decimal) -> str:
    return format(amount.normalize(), "f")
