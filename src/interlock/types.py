"""The vocabulary of a staged mutation.

Three kinds of object, kept separate because they have different levels of
trust.

*Plans* come from an untrusted agent. A plan holds no credentials and cannot
execute; it is a statement of intent, and nothing in it is believed.

*Diffs* come from the substrate. They are what the database measured, not what
the plan predicted. A statement reporting three affected rows can cascade
through triggers into six real mutations, and only the substrate sees that.

*Verdicts* come from a deterministic predicate over a diff. They are pure
functions of ``(plan, diff)``, so re-running one on the recorded inputs gives
the same answer.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation
from enum import Enum
from types import MappingProxyType
from typing import Any, Final, NewType

from agentgov.exceptions import MalformedReceiptError
from agentgov.receipts.canonical import canonical_bytes

from interlock.exceptions import PlanError

__all__ = [
    "AUDIT_VERSION",
    "GENESIS_HASH",
    "INBOX_TARGET",
    "MAX_NOT_AFTER",
    "OUTBOX_TARGET",
    "CommitReceipt",
    "Compensation",
    "Effect",
    "EffectDiff",
    "EffectId",
    "EffectKind",
    "EffectOutcome",
    "EffectPlan",
    "InboundFact",
    "InvariantViolation",
    "OutboundDelta",
    "OutboundRequest",
    "PlanId",
    "RowDelta",
    "Severity",
    "StageHandle",
    "StageState",
    "SubstrateCapabilities",
    "Verdict",
    "WindowMeasure",
    "canonical_hash",
    "iso",
    "outbound_key",
]

PlanId = NewType("PlanId", str)
EffectId = NewType("EffectId", str)

AUDIT_VERSION: Final = "ILOK1"
"""Chain version tag. Distinct from AgentGov's ``AGOV1`` so a record from one
chain can never be replayed as a record of the other."""

GENESIS_HASH: Final = "0" * 64


def iso(moment: datetime) -> str:
    """Render a timestamp as UTC ISO-8601 with an explicit offset."""
    return moment.isoformat()


def canonical_hash(fields: Sequence[object]) -> str:
    """Hash a fixed-order field list.

    A JSON list rather than a delimiter-joined string, matching AgentGov. Table
    names, tenant ids and statements are all attacker-influenceable, and a
    delimiter-joined payload can be forged by embedding the delimiter.

    :param fields: Values in a fixed order. Order is part of the contract;
        reordering changes every downstream hash.
    :returns: Lowercase SHA-256 hex digest.
    """
    payload = json.dumps(
        [AUDIT_VERSION, *fields],
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------
# Vocabularies
# --------------------------------------------------------------------------


class EffectKind(Enum):
    """The class of mutation an effect performs."""

    INSERT = "insert"
    UPDATE = "update"
    DELETE = "delete"
    DDL = "ddl"
    ENQUEUE = "enqueue"
    """A post-commit obligation written to a transactional outbox, rather than
    a direct external call. An email has no shadow, so it becomes a row that
    does, and a separate relay delivers it after commit.

    Defined but not implemented as of v0.1.0: nothing reads this kind.
    """


class StageState(Enum):
    """Where a plan is in the escrow lifecycle."""

    PLANNED = "planned"
    STAGING = "staging"
    STAGED = "staged"
    VERIFIED = "verified"
    REJECTED = "rejected"
    COMMITTED = "committed"
    ABORTED = "aborted"
    ORPHANED = "orphaned"


class Severity(Enum):
    ADVISORY = "advisory"
    """Recorded on the verdict; does not block the commit."""

    BLOCKING = "blocking"
    """Forces rejection. There is no in-process override. Overriding means
    submitting a new plan that carries an explicit waiver, which is then itself
    a recorded artifact."""


# --------------------------------------------------------------------------
# Plans: what the agent proposes
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Compensation:
    """A pre-computed undo, serialized before its effect is applied.

    The ordering is a hard requirement: if the undo cannot be written down, the
    effect is not admitted. See ``EscrowEngine.admit``.

    :ivar idempotency_key: Deterministic in ``(plan_id, effect_id)``, so a
        compensation replayed after a crash cannot apply twice.
    """

    statement: str
    parameters: Mapping[str, object] = field(default_factory=dict)
    idempotency_key: str = ""


OUTBOX_TARGET: Final = "interlock.outbox"
"""The target of every ``ENQUEUE`` effect: the table its request is written
to, inside the stage. The request's own destination is its ``sink``."""

INBOX_TARGET: Final = "interlock.inbox"
"""Where a receipt names the inbound facts a plan consumed: each a row its
stage wrote, committed with the rest."""

MAX_NOT_AFTER: Final = timedelta(days=7)
"""The longest a committed request may wait to be delivered. A request older
than that is a stale obligation for an operator, not something to send."""


def _frozen(value: Any) -> Any:
    """A deep, read-only copy of a decoded JSON value."""
    if isinstance(value, Mapping):
        return MappingProxyType({key: _frozen(item) for key, item in value.items()})
    if isinstance(value, list | tuple):
        return tuple(_frozen(item) for item in value)
    return value


def _has_nul(value: Any) -> bool:
    if isinstance(value, str):
        return "\x00" in value
    if isinstance(value, Mapping):
        return any("\x00" in key or _has_nul(item) for key, item in value.items())
    if isinstance(value, tuple | list):
        return any(_has_nul(item) for item in value)
    return False


def outbound_key(plan_id: str, effect_id: str) -> str:
    """The idempotency key of a plan's outbound request.

    Fixed at plan time from ``(plan_id, effect_id)`` (E4-2), so every attempt
    to deliver it, by any relay, after any crash, carries the same key, and a
    sink that honours keys absorbs the duplicates. A plan run again after a
    conflict keeps its key; a repair is a new plan, and gets a new one.
    """
    return canonical_hash(["outbound", plan_id, effect_id])


@dataclass(frozen=True, slots=True)
class OutboundRequest:
    """A call to an external system, proposed by the agent.

    Never made by the agent, which holds no credentials for it. An ``ENQUEUE``
    effect carries one; the stage writes it to the transactional outbox, the
    checkers read it back from there, and a relay delivers it after the stage
    commits.

    :ivar sink: An operator-registered sink name (``"stripe"``), never a URL.
    :ivar operation: One of the sink's registered operations.
    :ivar payload: The request body. The ARC1 canonical JSON domain: strings,
        integers within ±(2**53 - 1), booleans, null, arrays and objects.
        Floats are refused; money travels as decimal strings. Frozen on
        construction, so it cannot change after it is hashed.
    :ivar not_after: How long after staging the request may still be
        delivered. ``None`` takes the sink's default.
    :ivar compensation: The request that undoes this one, when the sink's
        operation has one (E4-3). Serialized with the plan, before the effect
        is staged.
    :raises PlanError: If the payload is outside the canonical domain, holds a
        NUL character (which PostgreSQL's ``jsonb`` refuses), or
        ``not_after`` is not a whole number of seconds, positive and at most
        :data:`MAX_NOT_AFTER`.
    """

    sink: str
    operation: str
    payload: Mapping[str, Any]
    not_after: timedelta | None = None
    compensation: OutboundRequest | None = None
    _canonical: bytes = field(default=b"", init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.payload, Mapping):
            raise PlanError(f"an outbound request's payload is a JSON object, not {self.payload!r}")
        try:
            canonical = canonical_bytes(self.payload)
        except MalformedReceiptError as exc:
            raise PlanError(f"outbound payload for {self.sink}.{self.operation}: {exc}") from exc
        if _has_nul(self.payload):
            raise PlanError(
                f"outbound payload for {self.sink}.{self.operation} holds a NUL character, "
                f"which the outbox cannot store"
            )
        if self.not_after is not None and not timedelta(0) < self.not_after <= MAX_NOT_AFTER:
            raise PlanError(
                f"not_after must be positive and at most {MAX_NOT_AFTER}, got {self.not_after}"
            )
        if self.not_after is not None and self.not_after % timedelta(seconds=1):
            # The outbox stores whole seconds and the plan's hash covers whole
            # seconds: a fraction would be cut off, to nothing below a second.
            raise PlanError(f"not_after is a whole number of seconds, got {self.not_after}")
        # The bytes hashed are the bytes sent: nothing re-encodes the payload
        # between here and the outbox.
        object.__setattr__(self, "_canonical", canonical)
        object.__setattr__(self, "payload", _frozen(self.payload))

    @property
    def canonical_payload(self) -> bytes:
        """The payload's RFC 8785 canonical UTF-8 bytes, as written to the outbox."""
        return self._canonical

    @property
    def payload_hash(self) -> str:
        """SHA-256 of :attr:`canonical_payload`, hex. The database recomputes it."""
        return hashlib.sha256(self._canonical).hexdigest()

    def to_json(self) -> dict[str, Any]:
        """The request as a JSON-able document, for the outbox's compensation column."""
        document: dict[str, Any] = {
            "sink": self.sink,
            "operation": self.operation,
            "payload_hash": self.payload_hash,
            "payload": json.loads(self._canonical),
        }
        if self.not_after is not None:
            document["not_after_seconds"] = int(self.not_after.total_seconds())
        return document

    def content_hash(self) -> str:
        return canonical_hash(
            [
                self.sink,
                self.operation,
                self.payload_hash,
                None if self.not_after is None else int(self.not_after.total_seconds()),
                None if self.compensation is None else self.compensation.content_hash(),
            ]
        )


@dataclass(frozen=True, slots=True)
class Effect:
    """One intended mutation.

    :ivar target: Substrate-qualified resource, ``"<substrate_id>:<table>"``.
    :ivar statement: A parameterised statement. Parameters are bound by the
        driver and are never interpolated into this string. The agent authors
        both fields and is untrusted.
    :ivar depends_on: Effects that must be applied first. Defines the DAG.
    :ivar reversible: Whether the substrate can roll this back natively.
    :ivar stated_rows: What the agent claims this will touch, recorded so the
        claim can be compared against the measurement. Never trusted, and
        optional: an agent that omits it disables ``StatedFootprint``.
    :ivar request: For an ``ENQUEUE`` effect, the outbound request it
        proposes, in place of a statement. ``None`` for every other kind.
    :raises PlanError: If ``statement`` is empty or whitespace-only. Nothing
        downstream (``reject_reason``, the leading-verb check) rejects a
        statement with no verb at all, so an empty one used to stage,
        measure nothing, and commit silently -- most often the sign of a
        template that produced an empty string rather than a genuinely
        empty step. For an ``ENQUEUE`` effect it is the reverse: a request,
        and no statement, parameters or SQL compensation, targeting
        :data:`OUTBOX_TARGET`.
    """

    effect_id: EffectId
    kind: EffectKind
    target: str
    statement: str
    parameters: Mapping[str, object] = field(default_factory=dict)
    depends_on: tuple[EffectId, ...] = ()
    tenant_id: str | None = None
    reversible: bool = True
    compensation: Compensation | None = None
    stated_rows: int | None = None
    request: OutboundRequest | None = None

    def __post_init__(self) -> None:
        if self.kind is EffectKind.ENQUEUE:
            problems = [
                problem
                for problem, present in (
                    ("no outbound request", self.request is None),
                    ("a statement", bool(self.statement.strip())),
                    ("statement parameters", bool(self.parameters)),
                    (
                        "a SQL compensation (an outbound request's undo is its "
                        "request.compensation)",
                        self.compensation is not None,
                    ),
                    (f"a target other than {OUTBOX_TARGET!r}", self.target != OUTBOX_TARGET),
                    ("stated_rows (it writes no observed row)", self.stated_rows is not None),
                )
                if present
            ]
            if problems:
                raise PlanError(
                    f"ENQUEUE effect {self.effect_id!r} has {', '.join(problems)}: an ENQUEUE "
                    f"effect carries an outbound request and nothing else"
                )
            return
        if self.request is not None:
            raise PlanError(
                f"effect {self.effect_id!r} is {self.kind.value}, and only an ENQUEUE effect "
                f"carries an outbound request"
            )
        if not self.statement.strip():
            raise PlanError(
                f"effect {self.effect_id!r} has an empty (or whitespace-only) "
                f"statement. There is no SQL verb here for the substrate to "
                f"reject, so this would stage, measure nothing, and commit as a "
                f"silent no-op -- often the sign of a template that produced an "
                f"empty string rather than a genuinely empty step. Drop the "
                f"effect from the plan if doing nothing is what you mean."
            )

    @property
    def table(self) -> str:
        """The bare table name, with the substrate prefix stripped."""
        _, _, rest = self.target.partition(":")
        return rest or self.target

    @property
    def substrate_id(self) -> str:
        head, sep, _ = self.target.partition(":")
        return head if sep else ""

    def content_hash(self) -> str:
        fields: list[object] = [
            self.effect_id,
            self.kind.value,
            self.target,
            self.statement,
            sorted((k, str(v)) for k, v in self.parameters.items()),
            list(self.depends_on),
            self.tenant_id,
            self.reversible,
        ]
        # Only when set, so every effect hashed before the outbox keeps its hash.
        if self.request is not None:
            fields.append(["request", self.request.content_hash()])
        return canonical_hash(fields)


@dataclass(frozen=True, slots=True)
class EffectPlan:
    """A complete unit of intended change.

    The plan is the atomic unit of staging, verification and commit. Its
    effects either all land or none do.

    :ivar scope_id: The AgentGov scope accountable for this plan. Used for the
        halted-scope check before commit.
    :ivar trajectory_id: The logical unit of work, matching AgentGov's
        trajectory notion, so an orchestrator retrying through fresh
        sub-agents is still one trajectory.
    """

    plan_id: PlanId
    scope_id: str
    trajectory_id: str
    created_at: datetime
    effects: tuple[Effect, ...]
    intent: str = ""
    """The agent's own description. Recorded for the audit trail; no checker
    reads it."""
    repair_of: PlanId | None = None
    """The refused plan this one repairs, when it is a proposal from
    :meth:`~interlock.engine.EscrowEngine.repair`. The engine admits such a
    plan only as proposed: same content, same link."""
    facts: tuple[uuid.UUID, ...] = ()
    """The inbound facts this plan consumes (``docs/EPIC5_DESIGN.md`` §2.6):
    each one its scope's, pending, attested; consumed exactly when the plan
    commits."""

    def topological_order(self) -> tuple[Effect, ...]:
        """Effects in a deterministic execution order.

        Ties break on ``effect_id`` ascending. A plan that stages in a
        different order on replay produces a different diff, which would
        destroy the replay guarantee, so the order is part of the contract.

        :raises ValueError: On a dependency cycle or an unknown dependency.
        """
        by_id = {effect.effect_id: effect for effect in self.effects}
        for effect in self.effects:
            for dependency in effect.depends_on:
                if dependency not in by_id:
                    raise ValueError(
                        f"effect {effect.effect_id!r} depends on unknown {dependency!r}"
                    )

        ordered: list[Effect] = []
        placed: set[EffectId] = set()
        remaining = sorted(self.effects, key=lambda e: e.effect_id)
        while remaining:
            ready = [e for e in remaining if all(d in placed for d in e.depends_on)]
            if not ready:
                stuck = ", ".join(sorted(e.effect_id for e in remaining))
                raise ValueError(f"dependency cycle among effects: {stuck}")
            for effect in ready:
                ordered.append(effect)
                placed.add(effect.effect_id)
            remaining = [e for e in remaining if e.effect_id not in placed]
        return tuple(ordered)

    @property
    def stated_rows(self) -> int | None:
        """The agent's own total claim, when every effect declared one.

        Over the statements only: an outbound request writes no observed row,
        so it has no claim to omit.
        """
        claims = [e.stated_rows for e in self.effects if e.kind is not EffectKind.ENQUEUE]
        if any(c is None for c in claims):
            return None
        return sum(c for c in claims if c is not None)

    def content_hash(self) -> str:
        fields: list[object] = [
            self.plan_id,
            self.scope_id,
            self.trajectory_id,
            iso(self.created_at),
            [e.content_hash() for e in self.topological_order()],
        ]
        # Only when set, so every plan hashed before repairs existed keeps
        # its hash.
        if self.repair_of is not None:
            fields.append(["repair_of", self.repair_of])
        # Likewise the facts it consumes.
        if self.facts:
            fields.append(["facts", sorted(str(f) for f in self.facts)])
        return canonical_hash(fields)


# --------------------------------------------------------------------------
# Diffs: what the substrate measured
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RowDelta:
    """One row's before and after image.

    ``before is None`` is an insert. ``after is None`` is a delete.
    """

    table: str
    primary_key: str
    before: Mapping[str, Any] | None
    after: Mapping[str, Any] | None
    tenant_id: str | None = None

    @property
    def operation(self) -> str:
        if self.before is None:
            return "insert"
        if self.after is None:
            return "delete"
        return "update"

    def changed_columns(self) -> tuple[str, ...]:
        """Columns whose value actually moved. Empty for inserts and deletes."""
        if self.before is None or self.after is None:
            return ()
        return tuple(sorted(k for k in self.after if self.before.get(k) != self.after.get(k)))


@dataclass(frozen=True, slots=True)
class OutboundDelta:
    """One outbound request as the stage wrote it to the outbox.

    Read back from the database, not copied from the plan, like a
    :class:`RowDelta`: what the checkers see is what the relay will send.

    :ivar message_id: The outbox row's id. Minted per stage, so it is left out
        of :meth:`EffectDiff.content_hash`, which must replay.
    :ivar depends_on: The plan's ``ENQUEUE`` effects that must be delivered
        before this one: its dependencies, followed through SQL effects.
    :ivar cost: What the request costs, as the database's sink registry priced
        it when the stage wrote it. Charged with the plan, at commit.
    """

    message_id: uuid.UUID
    effect_id: EffectId
    sink: str
    operation: str
    tenant_id: str | None
    payload: Mapping[str, Any]
    payload_hash: str
    idempotency_key: str
    depends_on: tuple[EffectId, ...] = ()
    cost: Decimal = Decimal(0)


@dataclass(frozen=True, slots=True)
class WindowMeasure:
    """One rate window, as the stage found it: what the window already held
    for one key, and what the plan adds to it (``docs/EPIC4_DESIGN.md`` §3).

    Measured with the window's key locked, so nothing can be added to it
    between the measurement and the stage's commit. See
    :mod:`interlock.windows`.

    :ivar window: The window's name.
    :ivar key: Whose history: the plan's scope, a tenant, or ``""`` for a
        global window (and for what carries no tenant, in a per-tenant one).
    :ivar history: What the window held for ``key`` when measured: the
        contributions of every plan committed within its span.
    :ivar amount: What this plan adds. Written beside its commit marker when
        it commits.
    """

    window: str
    key: str
    history: Decimal
    amount: Decimal


@dataclass(frozen=True, slots=True)
class InboundFact:
    """An inbound event, bound to the delivered request it names: what a plan
    may consume (``docs/EPIC5_DESIGN.md`` §2).

    Everything the inbox process attested, the event's statement and the
    fact's, so either is rebuilt from this alone and checked under
    ``[inbox.keys]`` (:func:`interlock.inbox.verify_fact`).

    :ivar kind: The event's type, as the vendor named it (``charge.refunded``).
    :ivar fields: The event's projection: named values, each of a closed set
        of types, never free text (``docs/EPIC5_DESIGN.md`` §2.5).
    :ivar withheld: The projected fields whose value did not fit its type: by
        name, never their value.
    """

    fact_id: uuid.UUID
    source: str
    event_seq: int
    event_hash: str
    message_id: uuid.UUID
    delivery_seq: int
    delivery_hash: str
    remote_ref: str
    scope_id: str
    plan_id: str
    tenant_id: str | None
    attestation: str
    event_id: str
    kind: str
    vendor_at: datetime | None
    received_at: datetime
    body_hash: str
    part: int
    refs: tuple[str, ...]
    fields: Mapping[str, Any]
    withheld: tuple[str, ...]
    event_attestation: str


@dataclass(frozen=True, slots=True)
class EffectDiff:
    """The delta a stage would commit, as measured by the substrate.

    :ivar truncated: Set when the row cap was reached. The diff is then a
        prefix of the real delta, and any predicate that needs completeness
        must fail closed against it. See ``invariants.TruncationGuard``.
    :ivar outbound: The outbound requests the stage wrote to the outbox, in
        the order it wrote them. Not rows of an observed table, so not in
        ``deltas`` or the blast radius.
    :ivar windows: The rate windows the plan adds to, each measured with its
        history (:class:`WindowMeasure`). Part of the measurement, so the
        diff's hash covers it and a verdict replays from the diff alone.
    :ivar facts: The inbound facts the stage consumed, read back from the
        database (:class:`InboundFact`).
    """

    plan_id: PlanId
    stage_id: uuid.UUID
    substrate_id: str
    computed_at: datetime
    deltas: tuple[RowDelta, ...]
    truncated: bool = False
    outbound: tuple[OutboundDelta, ...] = ()
    windows: tuple[WindowMeasure, ...] = ()
    facts: tuple[InboundFact, ...] = ()

    def window(self, name: str, key: str) -> WindowMeasure | None:
        """The measure of window ``name`` for ``key``, if the stage took one."""
        return next((w for w in self.windows if w.window == name and w.key == key), None)

    @property
    def rows_inserted(self) -> int:
        return sum(1 for d in self.deltas if d.operation == "insert")

    @property
    def rows_updated(self) -> int:
        return sum(1 for d in self.deltas if d.operation == "update")

    @property
    def rows_deleted(self) -> int:
        return sum(1 for d in self.deltas if d.operation == "delete")

    @property
    def blast_radius(self) -> int:
        """Captured mutations. NOT a distinct-row count: a row mutated twice
        inside one plan contributes 2, so this is an upper bound on rows
        touched. Use it as a bound, not as a row tally."""
        return len(self.deltas)

    @property
    def tables_touched(self) -> frozenset[str]:
        return frozenset(d.table for d in self.deltas)

    @property
    def tenant_ids(self) -> frozenset[str]:
        return frozenset(d.tenant_id for d in self.deltas if d.tenant_id is not None)

    @property
    def tenant_count(self) -> int:
        """Distinct tenants touched, as a radius axis independent of row count.

        Reads the tenant label out of the captured row image, so it is 0 for
        any table whose ``TableSpec.tenant_column`` is not also listed in
        ``TableSpec.columns``.
        """
        return len(self.tenant_ids)

    def column_total(self, table: str, column: str) -> tuple[Decimal, Decimal]:
        """Sum a numeric column across this diff, before and after.

        Exact, not approximate. Every value is routed through
        ``Decimal(str(value))`` rather than binary floating point, because this
        total is the input to a financial predicate: a guard that permits a
        30% drawdown must not admit a 30.000000000000004% one because two
        representations of the same cent did not compare equal. The cost is
        that a column of IEEE doubles is summed at the precision it was
        *printed* with, which is the precision it was meant to have.

        Rows absent from one side contribute zero to that side, which is the
        correct treatment for inserts and deletes.

        :returns: ``(before_total, after_total)`` as exact decimals.
        """
        before = after = Decimal(0)
        for delta in self.deltas:
            if delta.table != table:
                continue
            if delta.before is not None:
                before += _as_decimal(delta.before.get(column))
            if delta.after is not None:
                after += _as_decimal(delta.after.get(column))
        return before, after

    def tenant_column_totals(self, table: str, column: str) -> dict[str, tuple[Decimal, Decimal]]:
        """As :meth:`column_total`, but grouped by tenant.

        The whole-table total is the wrong denominator on a multi-tenant
        substrate: draining one tenant completely is a small fraction of a
        platform-wide sum, so a table-scoped guard admits a single-tenant
        wipe. Rows whose tenant could not be read group under ``""``.

        :returns: ``{tenant_id: (before_total, after_total)}``.
        """
        totals: dict[str, tuple[Decimal, Decimal]] = {}
        for delta in self.deltas:
            if delta.table != table:
                continue
            tenant = delta.tenant_id or ""
            before, after = totals.get(tenant, (Decimal(0), Decimal(0)))
            if delta.before is not None:
                before += _as_decimal(delta.before.get(column))
            if delta.after is not None:
                after += _as_decimal(delta.after.get(column))
            totals[tenant] = (before, after)
        return totals

    def content_hash(self) -> str:
        rows = [
            [d.table, d.primary_key, d.operation, d.before, d.after, d.tenant_id]
            for d in sorted(self.deltas, key=lambda d: (d.table, d.primary_key, d.operation))
        ]
        fields: list[object] = [self.plan_id, self.substrate_id, self.truncated, rows]
        # Only when present, so every diff hashed before the outbox keeps its
        # hash. The payload is covered by its hash; the message id is not
        # covered at all, since it is minted per stage and would break replay.
        if self.outbound:
            fields.append(
                [
                    "outbound",
                    [
                        [
                            o.effect_id,
                            o.sink,
                            o.operation,
                            o.tenant_id,
                            o.payload_hash,
                            o.idempotency_key,
                            list(o.depends_on),
                            format(o.cost.normalize(), "f"),
                        ]
                        for o in sorted(self.outbound, key=lambda o: o.effect_id)
                    ],
                ]
            )
        # Likewise only when present: a diff measured with no window keeps
        # the hash it always had.
        if self.windows:
            fields.append(
                [
                    "windows",
                    [
                        [
                            w.window,
                            w.key,
                            format(w.history.normalize(), "f"),
                            format(w.amount.normalize(), "f"),
                        ]
                        for w in sorted(self.windows, key=lambda w: (w.window, w.key))
                    ],
                ]
            )
        # And the facts the plan consumed, as the stage read them back.
        if self.facts:
            fields.append(
                [
                    "facts",
                    [
                        [
                            str(f.fact_id),
                            f.source,
                            f.event_hash,
                            f.kind,
                            str(f.message_id),
                            f.remote_ref,
                            canonical_bytes(dict(f.fields)).decode("utf-8"),
                            list(f.withheld),
                        ]
                        for f in sorted(self.facts, key=lambda f: str(f.fact_id))
                    ],
                ]
            )
        return canonical_hash(fields)


_NUMERAL: Final = re.compile(r"-?(0|[1-9][0-9]*)(\.[0-9]+)?", re.ASCII)
"""A decimal numeral as money travels in a payload: ``"50.00"``, ``"-3"``. No
exponent, no leading zeros, so ``"007"`` stays an identifier. ASCII digits
only: ``re``'s ``[0-9]`` is ASCII already, and the flag says so."""


def field_path(field: str) -> tuple[str, ...]:
    """A payload field's dotted path (``"refund.amount"``, ``"lines.0.amount"``)
    as its parts."""
    return tuple(part for part in field.removeprefix("$.").split(".") if part)


def value_at(payload: object, path: tuple[str, ...]) -> tuple[bool, object]:
    """The value at ``path`` in a payload, and whether there is one."""
    current = payload
    for part in path:
        if isinstance(current, Mapping) and part in current:
            current = current[part]
        elif isinstance(current, tuple | list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            return False, None
    return True, current


def values_at(payload: object, path: tuple[str, ...]) -> list[tuple[str, object]]:
    """Every value at ``path`` in a payload, with where it was found: a ``*``
    part stands for every item of a list, or every value of an object, there.
    Empty when there is none: a path through a missing field finds nothing."""
    found: list[tuple[str, object]] = [("$", payload)]
    for part in path:
        following: list[tuple[str, object]] = []
        for where, current in found:
            if part == "*":
                if isinstance(current, Mapping):
                    following += [(f"{where}.{k}", v) for k, v in current.items()]
                elif isinstance(current, tuple | list):
                    following += [(f"{where}[{i}]", v) for i, v in enumerate(current)]
            elif isinstance(current, Mapping) and part in current:
                following.append((f"{where}.{part}", current[part]))
            elif isinstance(current, tuple | list) and part.isdigit() and int(part) < len(current):
                following.append((f"{where}[{part}]", current[int(part)]))
        found = following
    return found


def exact_number(value: object) -> Decimal | None:
    """A number, exactly: an integer, a ``Decimal``, or a decimal numeral. A
    float, a boolean or anything else is none: so is a string Python's own
    ``Decimal`` would read (``"1_000"``, ``" 5"``, ``"1e3"``, ``"+5"``,
    ``"١٢٣"``) but a sink might read otherwise."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int | Decimal):
        return Decimal(value)
    if isinstance(value, str) and _NUMERAL.fullmatch(value):
        return Decimal(value)
    return None


def _as_decimal(value: object) -> Decimal:
    """Coerce a column value to an exact Decimal, non-numerics to zero.

    ``bool`` is excluded deliberately: it is an ``int`` subclass in Python, and
    summing a status flag into a money column is never what was meant.
    ``Decimal`` is passed through, which is how PostgreSQL's ``NUMERIC`` is
    read. ``str`` is accepted because SQLite is dynamically typed and a NUMERIC
    column can hand back text; an unparseable string contributes zero rather
    than raising, since a checker that dies on one bad row approves nothing.
    """
    if isinstance(value, bool):
        return Decimal(0)
    if isinstance(value, Decimal):
        # PostgreSQL NUMERIC arrives exact; keep it that way.
        return value if value.is_finite() else Decimal(0)
    if isinstance(value, int):
        return Decimal(value)
    if isinstance(value, float | str):
        try:
            return Decimal(str(value))
        except (InvalidOperation, ValueError):
            return Decimal(0)
    return Decimal(0)


# --------------------------------------------------------------------------
# Verdicts: what a deterministic predicate decided
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class InvariantViolation:
    invariant: str
    severity: Severity
    message: str
    evidence: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Verdict:
    """The admission decision for one staged diff."""

    plan_id: PlanId
    stage_id: uuid.UUID
    diff_hash: str
    decided_at: datetime
    checkers_run: tuple[str, ...]
    violations: tuple[InvariantViolation, ...]

    @property
    def blocking(self) -> tuple[InvariantViolation, ...]:
        return tuple(v for v in self.violations if v.severity is Severity.BLOCKING)

    @property
    def admitted(self) -> bool:
        return not self.blocking

    def content_hash(self) -> str:
        return canonical_hash(
            [
                self.plan_id,
                self.diff_hash,
                self.admitted,
                list(self.checkers_run),
                [[v.invariant, v.severity.value, v.message] for v in self.violations],
            ]
        )


# --------------------------------------------------------------------------
# Substrate handles
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SubstrateCapabilities:
    """What a driver supports, declared rather than inferred.

    The engine reads these to decide whether a plan is stageable. A driver that
    overstates them turns an enforced property into an unchecked assumption, so
    a new driver's values are part of its review.
    """

    transactional: bool
    row_level_diff: bool
    snapshot_isolation: bool
    requires_compensation: bool
    max_stage_seconds: float = 10.0
    max_diff_rows: int = 50_000
    outbound: bool = False
    """Stages ``ENQUEUE`` effects into a transactional outbox, committed with
    the rest of the stage."""


@dataclass(frozen=True, slots=True)
class StageHandle:
    """Opaque token identifying one open stage.

    Binds a plan to a single physical connection. Do not serialize it across
    processes. The process that opened the stage owns it; an open transaction
    with no live owner holds write locks until something reaps it.
    """

    stage_id: uuid.UUID
    plan_id: PlanId
    substrate_id: str
    opened_at: datetime
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class EffectOutcome:
    """Result of applying one effect inside a stage."""

    effect_id: EffectId
    rows_affected: int
    applied_at: datetime


@dataclass(frozen=True, slots=True)
class CommitReceipt:
    """Evidence that a stage was made durable."""

    stage_id: uuid.UUID
    plan_id: PlanId
    committed_at: datetime
    diff_hash: str
    verdict_hash: str
    substrate_txn_id: str | None = None
