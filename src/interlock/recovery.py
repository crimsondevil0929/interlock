"""Budgeted recovery: a bounded way for a halted task to finish.

AgentGov halts an agent that thrashes, loops or spends out, and the engine
refuses a plan that breaks an invariant. Both are right, and both used to end
the task. A :class:`RecoveryRuntime` gives a halted task a bounded way to
finish instead: a few more model calls, each under tighter constraints than
the one before, paid for from a reserve set aside for exactly this, and each
recorded and signed before it is made.

**The ladder.** Fixed in order, deterministic, one rung per step:

1. ``revoke_tool``: withdraw the grant of the tool the halt names.
2. ``operator_directive``: append an instruction from the operator's
   allowlist. No other text is ever sent as a directive.
3. ``token_ceiling``: lower ``max_tokens`` for every call from here on.
4. ``guidance``: tell the agent what happened and what to do now, in fixed
   templates; for a refused plan, the sanitized feedback of
   :mod:`interlock.feedback` (or a repair's), and nothing else.

Constraint tightening comes before conversational guidance. A step applies the
first rung that can still do something for this halt: a tool the halt names
and the policy may revoke, a directive answering this kind of halt that has not
been used, a ceiling not yet applied, guidance not yet given. Tightening only
accumulates: a revoked tool stays revoked, and the ceiling stays down. When no
rung applies, or the policy's step limit is reached, recovery is over
(:class:`~interlock.exceptions.RecoveryExhaustedError`) and the halt stands.

**History is never edited.** A step appends to the transcript: the messages it
is given come back first, as the same objects, in the same order. The system
prompt and the tool definitions are never touched. A revoked tool is withdrawn
by an appended ``tool_removal`` block or a user-turn notice (see
:class:`Channel`), and :meth:`RecoveryRuntime.check_tool` refuses it where the
harness runs tools, whatever the model was told. Each step checks that the
transcript it is handed extends the one the previous step returned, and its
record binds the transcript before and after by a running hash
(:func:`transcript_head`), so an edit between steps is refused and an edit
after the fact shows.

**The budget.** Every call made during recovery is billed to
``{scope}/recovery``: each step holds ``step_estimate`` there before the call
it enables, and :meth:`RecoveryRuntime.settle` captures what the call cost.
In AgentGov's tree the recovery scope cannot sit under the scope it recovers:
a trip halts the tripped scope's whole subtree, and recovery exists for a
tripped scope. So the reserve is carved out of the scope's own envelope,
released to the scope's parent and delegated from there, and the recovery
scope sits beside the scope, where the scope's breaker cannot halt it. The
halted scope stays halted; recovery spends its reserve and nothing else. A root
scope has no parent, so its reserve is a new root funded from the treasury;
``RecoveryPolicy.funding`` names a scope to delegate it from instead.

**Records.** Opening, every step, every settlement and the close are signed
:mod:`interlock.records` entries, each anchored into the AgentGov ledger. A
step's record names the halt (and a refused plan's ARC1 receipt), the rung and
exactly what it did, the hold that pays for it, the policy's digest, and the
transcript before and after. It is written before the step is returned, so no
recovery call is made that the log does not already show.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import threading
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Final

from agentgov.core import Authorization, BudgetManager, EntryType, LedgerEntry
from agentgov.exceptions import (
    AgentGovError,
    AgentThrashingError,
    BudgetExceededError,
    CircuitOpenError,
    RunawayLoopDetectedError,
)
from agentgov.receipts import canonical_bytes

from interlock.exceptions import (
    InterlockError,
    RecoveryError,
    RecoveryExhaustedError,
    ScopeHaltedError,
    ToolRevokedError,
)
from interlock.feedback import AgentFeedback
from interlock.records import RecordKind, RecordLog, SignedRecord, anchor_memo, money
from interlock.repair import RepairFeedback

if TYPE_CHECKING:
    from interlock.engine import StageResult
    from interlock.extension import BudgetGuard, ExtensionGrant, ExtensionRequest

__all__ = [
    "LADDER",
    "TOOL_CHANGES_BETA",
    "Channel",
    "Directive",
    "RecoveryPolicy",
    "RecoveryRuntime",
    "RecoveryStep",
    "Rung",
    "Trip",
    "TripKind",
    "breaker_reason",
    "spent_out",
    "transcript_head",
]

logger = logging.getLogger("interlock.recovery")

TOOL_CHANGES_BETA: Final = "mid-conversation-tool-changes-2026-07-01"
"""The beta a ``tool_removal`` block needs, on the Claude models that take it."""

_REASON_LIMIT = 512
_DIRECTIVE_ID = re.compile(r"[a-z0-9][a-z0-9_.-]{0,63}")
_DIRECTIVE_LIMIT = 2000


# --------------------------------------------------------------------------
# Halts
# --------------------------------------------------------------------------


class TripKind(StrEnum):
    """What halted the task."""

    THRASHING = "thrashing"
    """AgentGov's cognitive breaker: calls repeating without progress."""
    RUNAWAY = "runaway"
    """Call velocity over the policy's limit."""
    BUDGET = "budget"
    """A spend was refused or overran: the envelope is spent."""
    HALTED = "halted"
    """The scope, or an ancestor, is halted for another reason."""
    REFUSED = "refused"
    """The engine refused a plan."""


def spent_out(reason: str) -> bool:
    """Whether an AgentGov breaker reason says the money ran out.

    AgentGov writes a trip's reason as text. These are the three it writes for
    money (``agentgov.core``): a capture that left the scope at zero, an
    overdraft refused before any money moved, and a capture that overran its
    hold. Every other halt, a cognitive trip or an operator's, is a safety
    halt and is never read as one of these.
    """
    return (
        reason == "spend envelope exhausted"
        or reason.startswith("overdraft attempt:")
        or (reason.startswith("settled cost ") and "overdrawn by" in reason)
    )


def breaker_reason(governor: BudgetManager, scope_id: str) -> str:
    """Why ``scope_id``'s breaker last tripped, from AgentGov's control events.

    ``""`` if it never did.
    """
    reasons = [
        event.reason
        for event in governor.control_events
        if event.scope_id == scope_id and event.event_type == EntryType.CIRCUIT_TRIPPED.value
    ]
    return reasons[-1] if reasons else ""


@dataclass(frozen=True, slots=True)
class Trip:
    """A halt, as the recovery runtime reads it: from the error, never its text.

    :ivar tool: The tool the halt implicates. AgentGov's errors do not carry
        it; the harness knows which call it was making.
    :ivar reason: The operator's account of the halt. Recorded, never shown
        to the agent.
    :ivar feedback: What the agent may be told about a refused plan, already
        sanitized: the engine's :class:`~interlock.feedback.AgentFeedback`, or
        a repair's :class:`~interlock.repair.RepairFeedback`.
    :ivar receipt_id: The refused plan's ARC1 receipt, when there is one.
    """

    kind: TripKind
    scope_id: str
    tool: str | None = None
    trajectory: str | None = None
    detector: str | None = None
    reason: str = ""
    feedback: AgentFeedback | RepairFeedback | None = None
    receipt_id: str | None = None

    @classmethod
    def of(
        cls,
        error: BaseException,
        *,
        scope_id: str | None = None,
        tool: str | None = None,
        trajectory: str | None = None,
    ) -> Trip:
        """Read a halt from the error that reported it, by type.

        :param scope_id: The plan's scope, for an Interlock error, which does
            not carry one. AgentGov's errors name their own scope.
        :raises TypeError: If ``error`` is not a halt, or ``scope_id`` is
            missing for an Interlock error.
        """
        if isinstance(error, AgentThrashingError):
            return cls(
                TripKind.THRASHING,
                error.scope_id,
                tool=tool,
                trajectory=trajectory or error.trajectory,
                detector=error.detector,
                reason=error.reason,
            )
        if isinstance(error, RunawayLoopDetectedError):
            kind = TripKind.RUNAWAY
            return cls(kind, error.scope_id, tool=tool, trajectory=trajectory, reason=str(error))
        if isinstance(error, BudgetExceededError):
            kind = TripKind.BUDGET
            return cls(kind, error.scope_id, tool=tool, trajectory=trajectory, reason=str(error))
        if isinstance(error, CircuitOpenError):
            return cls(
                TripKind.BUDGET if spent_out(error.reason) else TripKind.HALTED,
                error.scope_id,
                tool=tool,
                trajectory=trajectory,
                reason=f"halted by {error.tripped_scope_id}: {error.reason}",
            )
        if isinstance(error, InterlockError):
            if scope_id is None:
                raise TypeError("an Interlock error does not name its scope; pass scope_id=")
            return cls(
                TripKind.HALTED if isinstance(error, ScopeHaltedError) else TripKind.REFUSED,
                scope_id,
                tool=tool,
                trajectory=trajectory,
                reason=str(error),
                feedback=error.feedback if isinstance(error.feedback, AgentFeedback) else None,
            )
        raise TypeError(f"{type(error).__name__} is not a halt the recovery runtime reads")

    @classmethod
    def refused(
        cls, result: StageResult, *, tool: str | None = None, repair: RepairFeedback | None = None
    ) -> Trip:
        """A plan the engine refused, from its result.

        :param repair: A repair of the plan, whose feedback the guidance rung
            then gives instead of the refusal's.
        :raises ValueError: If the plan committed.
        """
        if result.committed:
            raise ValueError("the plan committed; there is nothing to recover from")
        blocked = ",".join(result.blocked_by)
        return cls(
            TripKind.REFUSED,
            result.plan.scope_id,
            tool=tool,
            trajectory=result.plan.trajectory_id,
            detector=blocked or None,
            reason=f"blocked by {blocked}" if blocked else f"ended {result.state.value}",
            feedback=repair if repair is not None else result.feedback,
            receipt_id=result.receipt.receipt_id if result.receipt is not None else None,
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "scope": self.scope_id,
            "tool": self.tool,
            "trajectory": self.trajectory,
            "detector": self.detector,
            "reason": _clip(self.reason),
            "receipt": self.receipt_id,
        }


# --------------------------------------------------------------------------
# Policy
# --------------------------------------------------------------------------


class Rung(StrEnum):
    """One kind of intervention. :data:`LADDER` fixes their order."""

    REVOKE_TOOL = "revoke_tool"
    OPERATOR_DIRECTIVE = "operator_directive"
    TOKEN_CEILING = "token_ceiling"  # noqa: S105 - a rung name, not a credential
    GUIDANCE = "guidance"


LADDER: Final[tuple[Rung, ...]] = (
    Rung.REVOKE_TOOL,
    Rung.OPERATOR_DIRECTIVE,
    Rung.TOKEN_CEILING,
    Rung.GUIDANCE,
)
"""The order rungs are tried in. Not configurable: a policy can switch rungs
off, never put guidance ahead of a constraint."""


class Channel(StrEnum):
    """How a step's notices reach the model.

    ``system``: a directive, a revocation and a ceiling notice are appended as
    ``{"role": "system"}`` messages, and a revocation as a ``tool_removal``
    block (beta :data:`TOOL_CHANGES_BETA`), the operator channel that text in a
    user turn cannot forge. Claude Opus 5, Opus 5.5, Opus 4.8, Fable 5 and 5.1,
    and Mythos 5 and 5.1 take these; other models return a 400.

    ``user``: every notice is appended as a user turn, and the tool list is
    left as it is: :meth:`RecoveryRuntime.check_tool` refuses a revoked tool.
    For every other model.

    Guidance is always a user turn, since it is conversation, not a constraint.
    """

    SYSTEM = "system"
    USER = "user"


@dataclass(frozen=True, slots=True)
class Directive:
    """An operator instruction, written in advance.

    :ivar directive_id: Names it in the records; ``[a-z0-9][a-z0-9_.-]*``.
    :ivar text: Sent verbatim. At most 2000 characters.
    :ivar answers: The kinds of halt it is for.
    """

    directive_id: str
    text: str
    answers: frozenset[TripKind]

    def __post_init__(self) -> None:
        if not _DIRECTIVE_ID.fullmatch(self.directive_id):
            raise ValueError(
                f"a directive id is [a-z0-9][a-z0-9_.-]{{0,63}}, got {self.directive_id!r}"
            )
        if not self.text.strip() or len(self.text) > _DIRECTIVE_LIMIT:
            raise ValueError(f"directive {self.directive_id!r}: text must be 1-2000 characters")
        object.__setattr__(self, "answers", frozenset(TripKind(k) for k in self.answers))
        if not self.answers:
            raise ValueError(f"directive {self.directive_id!r} answers no kind of halt")

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.text.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class RecoveryPolicy:
    """How a task may recover, and what it may spend doing it.

    :param reserve: What ``{scope}/recovery`` is funded with.
    :param step_estimate: What each step holds for the call it enables. At
        most ``reserve``.
    :param max_steps: The most steps, and so the most rungs, one recovery takes.
    :param directives: The allowlist, in priority order. Only these texts are
        ever sent as directives.
    :param revoke_on: The halts for which the tool they name is revoked. By
        default a thrashing or runaway tool; a refused plan's tool is left to
        guidance, so the agent can correct the plan.
    :param revocable: The tools that may be revoked; ``None`` for any tool
        the runtime was told is granted.
    :param token_ceiling: The ``max_tokens`` the ceiling rung sets; ``None``
        switches the rung off.
    :param ceiling_on: The halts the ceiling rung answers.
    :param guidance: Whether the last rung is on.
    :param channel: See :class:`Channel`.
    :param funding: A scope to delegate the reserve from, instead of carving
        it out of the scope's own envelope (or, for a root, the treasury).
    """

    reserve: Decimal
    step_estimate: Decimal
    max_steps: int = 6
    directives: tuple[Directive, ...] = ()
    revoke_on: frozenset[TripKind] = frozenset({TripKind.THRASHING, TripKind.RUNAWAY})
    revocable: frozenset[str] | None = None
    token_ceiling: int | None = 2048
    ceiling_on: frozenset[TripKind] = frozenset(
        {TripKind.THRASHING, TripKind.RUNAWAY, TripKind.BUDGET}
    )
    guidance: bool = True
    channel: Channel = Channel.SYSTEM
    funding: str | None = None

    def __post_init__(self) -> None:
        reserve = Decimal(str(self.reserve))
        estimate = Decimal(str(self.step_estimate))
        if not Decimal(0) < estimate <= reserve:
            raise ValueError(
                f"a step's estimate must be positive and within the reserve; got {estimate} "
                f"of {reserve}"
            )
        if self.max_steps < 1:
            raise ValueError("a recovery needs at least one step")
        if self.token_ceiling is not None and self.token_ceiling < 1:
            raise ValueError("a token ceiling is at least 1")
        ids = [d.directive_id for d in self.directives]
        if len(ids) != len(set(ids)):
            raise ValueError(f"directive ids must be unique: {ids}")
        object.__setattr__(self, "reserve", reserve)
        object.__setattr__(self, "step_estimate", estimate)
        object.__setattr__(self, "directives", tuple(self.directives))
        object.__setattr__(self, "revoke_on", frozenset(TripKind(k) for k in self.revoke_on))
        object.__setattr__(self, "ceiling_on", frozenset(TripKind(k) for k in self.ceiling_on))
        object.__setattr__(self, "channel", Channel(self.channel))
        if self.revocable is not None:
            object.__setattr__(self, "revocable", frozenset(self.revocable))

    def to_json(self) -> dict[str, Any]:
        return {
            "reserve": money(self.reserve),
            "step_estimate": money(self.step_estimate),
            "max_steps": self.max_steps,
            "directives": [
                {
                    "id": d.directive_id,
                    "sha256": d.digest,
                    "answers": sorted(k.value for k in d.answers),
                }
                for d in self.directives
            ],
            "revoke_on": sorted(k.value for k in self.revoke_on),
            "revocable": sorted(self.revocable) if self.revocable is not None else None,
            "token_ceiling": self.token_ceiling,
            "ceiling_on": sorted(k.value for k in self.ceiling_on),
            "guidance": self.guidance,
            "channel": self.channel.value,
            "funding": self.funding,
        }

    @property
    def digest(self) -> str:
        """SHA-256 of the policy's canonical JSON: which policy a record ran under."""
        return hashlib.sha256(canonical_bytes(self.to_json())).hexdigest()


# --------------------------------------------------------------------------
# The transcript
# --------------------------------------------------------------------------

_TRANSCRIPT_SEED: Final = hashlib.sha256(b"ILOK1/transcript/v1\n").hexdigest()


def transcript_head(messages: Sequence[object], count: int | None = None) -> str:
    """A running hash over the first ``count`` messages (all by default).

    ``h0`` is SHA-256 of ``ILOK1/transcript/v1\\n``, and each message folds in
    as ``h = SHA-256(h ":" SHA-256(json))``, where ``json`` is the message
    serialized with sorted keys, no whitespace, and non-ASCII kept. Two
    transcripts share a head at ``n`` exactly when their first ``n`` messages
    serialize the same, so a record's ``(count, head)`` pins the transcript up
    to that point without holding any of it.

    Messages may be plain JSON-able mappings or SDK objects with ``to_dict()``
    or ``model_dump()``, such as a response's content blocks.
    """
    head = _TRANSCRIPT_SEED
    for message in messages[: len(messages) if count is None else count]:
        digest = hashlib.sha256(_message_bytes(message)).hexdigest()
        head = hashlib.sha256(f"{head}:{digest}".encode("ascii")).hexdigest()
    return head


def _message_bytes(message: object) -> bytes:
    text = json.dumps(
        _plain(message), sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )
    return text.encode("utf-8")


def _plain(value: object) -> object:
    if value is None or isinstance(value, str | bool | int | float):
        return value
    if isinstance(value, Mapping):
        return {str(k): _plain(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_plain(v) for v in value]
    for method in ("to_dict", "model_dump"):
        convert = getattr(value, method, None)
        if callable(convert):
            return _plain(convert())
    raise TypeError(
        f"a {type(value).__name__} in the transcript is not JSON; pass plain mappings "
        f"or SDK objects with to_dict()"
    )


def _role(message: object) -> object:
    plain = _plain(message)
    return plain.get("role") if isinstance(plain, dict) else None


def _pending_tool_uses(message: object) -> list[str]:
    """The ids of the ``tool_use`` blocks an assistant turn left unanswered."""
    plain = _plain(message)
    if not isinstance(plain, dict) or plain.get("role") != "assistant":
        return []
    content = plain.get("content")
    if not isinstance(content, list):
        return []
    return [
        block["id"]
        for block in content
        if isinstance(block, dict)
        and block.get("type") == "tool_use"
        and isinstance(block.get("id"), str)
    ]


# --------------------------------------------------------------------------
# What the agent is told: fixed text, never a halt's own words
# --------------------------------------------------------------------------

_NOT_RUN: Final[Mapping[TripKind, str]] = {
    TripKind.THRASHING: "Not run: this call repeated earlier calls without progress.",
    TripKind.RUNAWAY: "Not run: calls were arriving faster than this task allows.",
    TripKind.BUDGET: "Not run: the budget for this task is spent.",
    TripKind.HALTED: "Not run: this task was halted.",
    TripKind.REFUSED: "Not run.",
}

_GUIDANCE: Final[Mapping[TripKind, str]] = {
    TripKind.THRASHING: (
        "Your recent tool calls repeated earlier ones without new results. Do not repeat a "
        "call that has already returned. Work from the results you have; if they are not "
        "enough, say what is missing."
    ),
    TripKind.RUNAWAY: (
        "Tool calls were arriving faster than this task allows. Make fewer calls, each one "
        "deliberate."
    ),
    TripKind.BUDGET: (
        "The budget for this task is spent. Give the best answer you can from what you have "
        "now, and say plainly what is left undone."
    ),
    TripKind.HALTED: (
        "This task was halted. Do not call any more tools. Summarize what was done and what "
        "remains."
    ),
    TripKind.REFUSED: "A change you proposed was refused and rolled back; nothing changed.",
}

_REFUSED_CLOSE: Final = "Revise the plan to meet these constraints, or say why it cannot be done."


def _guidance(trip: Trip) -> str:
    if trip.feedback is not None:
        return f"{trip.feedback.render()}\n{_REFUSED_CLOSE}"
    return _GUIDANCE[trip.kind]


def _user(text: str) -> dict[str, Any]:
    return {"role": "user", "content": [{"type": "text", "text": text}]}


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _clip(text: str) -> str:
    return text if len(text) <= _REASON_LIMIT else text[: _REASON_LIMIT - 3] + "..."


# --------------------------------------------------------------------------
# The runtime
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RecoveryStep:
    """One step: the rung applied, the request to send, the hold that pays for it.

    Send ``messages`` with ``max_tokens`` (through the beta endpoint with
    ``betas`` when there are any), and with the system prompt and the tool
    definitions exactly as before. Then :meth:`RecoveryRuntime.settle` the
    step with what the call cost.

    :ivar messages: The transcript as given, followed by ``appended``.
    :ivar tools: The tools still granted after this step.
    :ivar record: The signed ``recovery.step`` record, already written.
    """

    number: int
    trip: Trip
    rung: Rung
    messages: tuple[object, ...]
    appended: tuple[dict[str, Any], ...]
    max_tokens: int
    tools: tuple[str, ...]
    betas: tuple[str, ...]
    channel: Channel
    authorization: Authorization
    record: SignedRecord
    tool: str | None = None
    directive: str | None = None


class RecoveryRuntime:
    """Recovers one scope's task from halts, within a policy and a reserve.

    Construction funds ``{scope}/recovery`` (see the module docs), or adopts
    it when ``records`` already holds its opening record, replaying what was
    revoked and which directives were used, so a restart never loosens a
    constraint. A recovery scope that exists without that record is refused.

    Every call made during recovery bills the recovery scope: steps through
    :meth:`recover` and :meth:`settle`, and the task's own calls between steps
    through :meth:`hold` and :meth:`capture`. Before running any tool, the
    harness calls :meth:`check_tool`; before any call, it caps ``max_tokens``
    with :meth:`max_tokens`. Thread-safe.

    With a :class:`~interlock.extension.BudgetGuard`, a reserve that runs out
    is quoted for instead of simply ending the recovery: the
    :class:`~interlock.exceptions.RecoveryExhaustedError` carries the quote,
    :meth:`hold` returns one in place of a hold, and a granted quote is taken
    up with :meth:`extend`, which moves billing to the scope the grant funded.

    :param governor: A write-capable AgentGov manager.
    :param scope_id: The scope whose task this recovers.
    :param records: Where the signed records go. Persist it to keep what was
        tightened across a restart.
    :param tools: The tools the task was granted, which are the ones a step
        may revoke.
    :param trajectory: The task's trajectory, recorded.
    :param guard: Quotes for more when the reserve runs out.
    :raises RecoveryError: If the reserve cannot be funded, or the recovery
        scope exists without its records.
    """

    def __init__(
        self,
        governor: BudgetManager,
        scope_id: str,
        policy: RecoveryPolicy,
        records: RecordLog,
        *,
        tools: Iterable[str] = (),
        trajectory: str | None = None,
        guard: BudgetGuard | None = None,
    ) -> None:
        self._governor = governor
        self._guard = guard
        self._scope = scope_id
        self._policy = policy
        self._records = records
        self._granted: tuple[str, ...] = tuple(dict.fromkeys(tools))
        self._trajectory = trajectory
        self._recovery = f"{scope_id}/recovery"
        self._billing = self._recovery
        self._billed: list[str] = [self._recovery]
        self._lock = threading.RLock()
        self._revoked: list[str] = []
        self._used: set[str] = set()
        self._guided: set[str] = set()
        self._ceiling: int | None = None
        self._taken = 0
        self._steps: list[RecoveryStep] = []
        self._pending: RecoveryStep | None = None
        self._last: tuple[int, str] | None = None
        self._closed = False
        try:
            governor.node(scope_id)
        except AgentGovError as exc:
            raise RecoveryError(f"scope {scope_id!r} is not registered with the governor") from exc
        if self._recovery in governor.scopes():
            self._opened = self._adopt()
        else:
            self._opened = self._fund()

    # -- state ---------------------------------------------------------------

    @property
    def scope_id(self) -> str:
        return self._scope

    @property
    def recovery_scope(self) -> str:
        """The recovery scope, ``{scope}/recovery``."""
        return self._recovery

    @property
    def billing_scope(self) -> str:
        """Where every call made during recovery is billed: the recovery scope,
        or the scope an extension grant funded beside it."""
        with self._lock:
            return self._billing

    @property
    def trajectory(self) -> str:
        """The trajectory to observe recovery calls under: the task's own is
        latched by the halt that started this."""
        return f"{self._trajectory or self._scope}/recovery"

    @property
    def policy(self) -> RecoveryPolicy:
        return self._policy

    @property
    def records(self) -> RecordLog:
        return self._records

    @property
    def opened(self) -> SignedRecord:
        """The ``recovery.opened`` record this runtime wrote."""
        return self._opened

    @property
    def steps(self) -> tuple[RecoveryStep, ...]:
        """The steps this runtime took (not those replayed on adoption)."""
        with self._lock:
            return tuple(self._steps)

    @property
    def taken(self) -> int:
        """Steps taken in this recovery, replayed ones included."""
        with self._lock:
            return self._taken

    @property
    def revoked(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(self._revoked)

    @property
    def granted(self) -> tuple[str, ...]:
        """The tools still granted."""
        with self._lock:
            return tuple(t for t in self._granted if t not in self._revoked)

    def check_tool(self, tool: str) -> None:
        """Refuse a revoked tool, whatever the model was told.

        :raises ToolRevokedError: If ``tool`` was revoked.
        """
        with self._lock:
            if tool in self._revoked:
                raise ToolRevokedError(tool)

    @staticmethod
    def refusal(tool_use_id: str) -> dict[str, Any]:
        """The ``tool_result`` block that answers a call to a revoked tool."""
        return {
            "type": "tool_result",
            "tool_use_id": tool_use_id,
            "content": "Not run: this tool was revoked for the rest of the task.",
            "is_error": True,
        }

    def max_tokens(self, requested: int) -> int:
        """``requested``, capped by the ceiling a step applied."""
        with self._lock:
            return requested if self._ceiling is None else min(requested, self._ceiling)

    # -- the task's own calls ------------------------------------------------

    def hold(self, amount: Decimal | str, *, memo: str = "") -> Authorization | ExtensionRequest:
        """Hold funds for a call the task makes between steps, on the billing scope.

        :returns: The hold; with a guard, a quote in its place when the call
            does not fit.
        :raises agentgov.exceptions.AgentGovError: As ``authorize`` does.
        """
        with self._lock:
            self._check_open()
            billing = self._billing
        memo = memo or "call made during recovery"
        if self._guard is not None:
            return self._guard.authorize(billing, amount, memo=memo, task=self._scope)
        return self._governor.authorize(billing, amount, memo=memo)

    def extend(self, grant: ExtensionGrant) -> None:
        """Bill the scope a granted quote funded from now on.

        :raises RecoveryError: If the grant funded a scope that is not this
            recovery's.
        """
        with self._lock:
            self._check_open()
            scope = grant.scope_id
            if scope not in self._billed and not scope.startswith(f"{self._recovery}/"):
                raise RecoveryError(
                    f"grant {grant.grant_id} funds {scope!r}, not the recovery of {self._scope!r}"
                )
            if scope not in self._billed:
                self._billed.append(scope)
            self._billing = scope

    def capture(self, authorization: Authorization, cost: Decimal | str) -> LedgerEntry:
        """Settle a :meth:`hold` at what the call cost."""
        return self._governor.capture(authorization, cost, memo="call made during recovery")

    # -- steps -----------------------------------------------------------------

    def recover(self, trip: Trip, messages: Sequence[object], *, max_tokens: int) -> RecoveryStep:
        """Take the next step of the ladder for ``trip``.

        :param messages: The transcript as it stands, in Messages API shape.
            The step appends to it and never changes it. If the last message is
            an assistant turn whose tool calls were not run (the halt came
            before them), the step answers each with an error ``tool_result``
            first, as the API requires.
        :param max_tokens: What the next call would otherwise ask for.
        :raises RecoveryExhaustedError: If no rung applies, the step limit is
            reached, the reserve cannot cover the step, or the recovery scope
            is halted. The halt stands.
        :raises RecoveryError: If the previous step is not settled, the
            transcript was edited since it, or it ends in an unanswered system
            message.
        """
        if max_tokens < 1:
            raise ValueError("max_tokens is at least 1")
        with self._lock:
            self._check_open()
            self._check_trip(trip)
            if self._pending is not None:
                raise RecoveryError(
                    f"step {self._pending.number} is not settled; settle it before the next step"
                )
            self._check_transcript(messages)
            if self._taken >= self._policy.max_steps:
                raise RecoveryExhaustedError(
                    f"the policy allows {self._policy.max_steps} recovery steps, and all were taken"
                )
            halted = self._governor.halted_by(self._billing)
            if halted is not None:
                spent = halted == self._billing and spent_out(
                    breaker_reason(self._governor, halted)
                )
                raise RecoveryExhaustedError(
                    f"recovery scope {self._billing!r} is halted by {halted!r}",
                    quote=self._quote() if spent else None,
                )
            choice = self._choose(trip, max_tokens)
            if choice is None:
                raise RecoveryExhaustedError(
                    f"no rung of the ladder is left for this {trip.kind.value} halt"
                )
            rung, detail = choice
            number = self._taken + 1
            authorization = self._authorize(number, rung)
            try:
                step = self._take(number, trip, rung, detail, messages, max_tokens, authorization)
            except BaseException:
                self._governor.void(authorization, memo=f"recovery step {number} not taken")
                raise
            self._anchor(step.record)
            return step

    def settle(self, step: RecoveryStep, cost: Decimal | str) -> SignedRecord:
        """Capture what ``step``'s call cost, and record it.

        A capture that overdraws the recovery scope is recorded (the money was
        spent), and then AgentGov's ``DenialOfWalletError`` propagates: the
        recovery scope is halted, and the next step will say so.

        :raises RecoveryError: If ``step`` is not the step awaiting settlement.
        """
        with self._lock:
            if self._pending is None or self._pending is not step:
                raise RecoveryError(f"step {step.number} is not awaiting settlement")
            overran: BudgetExceededError | None = None
            entry: LedgerEntry | None = None
            try:
                entry = self._governor.capture(
                    step.authorization, cost, memo=f"recovery step {step.number} settled"
                )
            except BudgetExceededError as exc:
                # Recorded by AgentGov before it raised: the money was spent.
                overran = exc
                held = step.authorization.scope_id
                entry = _spend_for(self._governor.audit_trail(held), step.authorization)
            self._pending = None
            spent = entry.amount if entry is not None and entry.entry_type is EntryType.SPEND else 0
            record = self._records.append(
                RecordKind.RECOVERY_SETTLED,
                scope=self._scope,
                body={
                    "recovery_scope": self._recovery,
                    "step": step.number,
                    "step_record": {"seq": step.record.seq, "hash": step.record.record_hash},
                    "cost": money(spent),
                    "entry": str(entry.entry_id) if entry is not None else None,
                    "overdrawn": overran is not None,
                    "available": money(self._governor.available(step.authorization.scope_id)),
                },
            )
            self._anchor(record)
            if overran is not None:
                raise overran
            return record

    def close(self) -> SignedRecord | None:
        """End the recovery: void an unsettled hold, return unused reserve.

        Idempotent; returns the ``recovery.closed`` record the first time.
        """
        with self._lock:
            if self._closed:
                return None
            self._closed = True
            voided = None
            if self._pending is not None:
                self._governor.void(
                    self._pending.authorization, memo="recovery closed before the step settled"
                )
                voided = self._pending.number
                self._pending = None
            returned = Decimal(0)
            spent = Decimal(0)
            for scope in self._billed:
                spent += _spent(self._governor.audit_trail(scope))
                if self._governor.node(scope).parent_id is not None:
                    returned += self._governor.release(
                        scope, memo=f"unused recovery reserve for {self._scope} returned"
                    )
            record = self._records.append(
                RecordKind.RECOVERY_CLOSED,
                scope=self._scope,
                body={
                    "recovery_scope": self._recovery,
                    "scopes": list(self._billed),
                    "steps": self._taken,
                    "revoked": list(self._revoked),
                    "spent": money(spent),
                    "returned": money(returned),
                    "voided_step": voided,
                },
            )
            self._anchor(record)
            return record

    def __enter__(self) -> RecoveryRuntime:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # -- internals -------------------------------------------------------------

    def _check_open(self) -> None:
        if self._closed:
            raise RecoveryError(f"the recovery of {self._scope!r} is closed")

    def _check_trip(self, trip: Trip) -> None:
        mine = (self._scope, self._recovery)
        if trip.scope_id not in mine and not trip.scope_id.startswith(f"{self._scope}/"):
            raise RecoveryError(
                f"the halt is for scope {trip.scope_id!r}; this runtime recovers {self._scope!r}"
            )

    def _check_transcript(self, messages: Sequence[object]) -> None:
        if not messages:
            raise RecoveryError("a recovery step appends to a transcript, and this one is empty")
        if _role(messages[-1]) == "system":
            raise RecoveryError(
                "the transcript ends in a system message no model call has answered; send "
                "the previous step's request and append the response first"
            )
        if self._last is None:
            return
        count, head = self._last
        if len(messages) < count or transcript_head(messages, count) != head:
            raise RecoveryError(
                f"the transcript no longer begins with the {count} messages the previous "
                f"step returned: it was edited. Recovery only ever appends, and so must the "
                f"harness"
            )

    def _choose(self, trip: Trip, max_tokens: int) -> tuple[Rung, object] | None:
        policy = self._policy
        for rung in LADDER:
            if rung is Rung.REVOKE_TOOL:
                tool = trip.tool
                if (
                    trip.kind in policy.revoke_on
                    and tool is not None
                    and tool in self._granted
                    and tool not in self._revoked
                    and (policy.revocable is None or tool in policy.revocable)
                ):
                    return rung, tool
            elif rung is Rung.OPERATOR_DIRECTIVE:
                for directive in policy.directives:
                    if trip.kind in directive.answers and directive.directive_id not in self._used:
                        return rung, directive
            elif rung is Rung.TOKEN_CEILING:
                ceiling = policy.token_ceiling
                if (
                    ceiling is not None
                    and trip.kind in policy.ceiling_on
                    and self._ceiling is None
                    and max_tokens > ceiling
                ):
                    return rung, ceiling
            elif policy.guidance:
                text = _guidance(trip)
                if f"{trip.kind.value}:{_sha256(text)}" not in self._guided:
                    return rung, text
        return None

    def _authorize(self, number: int, rung: Rung) -> Authorization:
        estimate = self._policy.step_estimate
        with self._governor.ledger.lock:
            available = self._governor.available(self._billing)
            if estimate <= available:
                try:
                    return self._governor.authorize(
                        self._billing, estimate, memo=f"recovery step {number}: {rung.value}"
                    )
                except AgentGovError as exc:
                    raise RecoveryExhaustedError(
                        f"recovery scope {self._billing!r} refused the hold: {exc}"
                    ) from exc
        raise RecoveryExhaustedError(
            f"the recovery reserve has {available} left, and a step holds {estimate}",
            quote=self._quote(),
        )

    def _quote(self) -> ExtensionRequest | None:
        """A quote for more reserve, when the runtime has a guard to ask."""
        if self._guard is None:
            return None
        return self._guard.quote(self._billing, self._policy.step_estimate, task=self._scope)

    def _take(
        self,
        number: int,
        trip: Trip,
        rung: Rung,
        detail: object,
        messages: Sequence[object],
        max_tokens: int,
        authorization: Authorization,
    ) -> RecoveryStep:
        appended: list[dict[str, Any]] = []
        pending = _pending_tool_uses(messages[-1])
        if pending:
            appended.append(
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": uid,
                            "content": _NOT_RUN[trip.kind],
                            "is_error": True,
                        }
                        for uid in pending
                    ],
                }
            )
        after_user = bool(appended) or _role(messages[-1]) == "user"
        channel = (
            Channel.SYSTEM
            if self._policy.channel is Channel.SYSTEM and after_user and rung is not Rung.GUIDANCE
            else Channel.USER
        )
        system = channel is Channel.SYSTEM
        betas: list[str] = []
        tool: str | None = None
        directive: Directive | None = None
        ceiling = self._ceiling
        action: dict[str, Any]
        if rung is Rung.REVOKE_TOOL:
            tool = str(detail)
            if system:
                removal = {"type": "tool_removal", "tool": {"type": "tool_reference", "name": tool}}
                appended.append({"role": "system", "content": [removal]})
                betas.append(TOOL_CHANGES_BETA)
            else:
                appended.append(
                    _user(
                        f"The tool {tool} is no longer available for this task; a call to it "
                        f"will not run."
                    )
                )
            action = {"tool": tool}
        elif rung is Rung.OPERATOR_DIRECTIVE:
            assert isinstance(detail, Directive)
            directive = detail
            if system:
                appended.append({"role": "system", "content": directive.text})
            else:
                appended.append(_user(f"<system-reminder>{directive.text}</system-reminder>"))
            action = {"directive": directive.directive_id, "sha256": directive.digest}
        elif rung is Rung.TOKEN_CEILING:
            assert isinstance(detail, int)
            ceiling = detail
            notice = f"Keep your next response under {ceiling} tokens: it is cut off there."
            appended.append({"role": "system", "content": notice} if system else _user(notice))
            action = {"ceiling": ceiling}
        else:
            text = str(detail)
            appended.append(_user(text))
            action = {"sha256": _sha256(text), "feedback": trip.feedback is not None}

        out = (*messages, *appended)
        capped = max_tokens if ceiling is None else min(max_tokens, ceiling)
        revoked = [*self._revoked, *([tool] if tool is not None else [])]
        granted = tuple(t for t in self._granted if t not in revoked)
        record = self._records.append(
            RecordKind.RECOVERY_STEP,
            scope=self._scope,
            body={
                "recovery_scope": self._recovery,
                "step": number,
                "trip": trip.to_json(),
                "rung": rung.value,
                "action": action,
                "channel": channel.value,
                "max_tokens": {"asked": max_tokens, "sent": capped},
                "tools": list(granted),
                "betas": betas,
                "transcript": {
                    "before": {"count": len(messages), "head": transcript_head(messages)},
                    "after": {"count": len(out), "head": transcript_head(out)},
                    "appended_sha256": hashlib.sha256(
                        b"".join(_message_bytes(m) + b"\n" for m in appended)
                    ).hexdigest(),
                },
                "hold": {
                    "scope": authorization.scope_id,
                    "authorization": str(authorization.authorization_id),
                    "amount": money(authorization.amount),
                },
                "policy": self._policy.digest,
            },
        )
        # Only now that the step is on record does it change anything.
        if tool is not None:
            self._revoked.append(tool)
        if directive is not None:
            self._used.add(directive.directive_id)
        if rung is Rung.GUIDANCE:
            self._guided.add(f"{trip.kind.value}:{action['sha256']}")
        self._ceiling = ceiling
        self._taken = number
        self._last = (len(out), transcript_head(out))
        step = RecoveryStep(
            number=number,
            trip=trip,
            rung=rung,
            messages=out,
            appended=tuple(appended),
            max_tokens=capped,
            tools=granted,
            betas=tuple(betas),
            channel=channel,
            authorization=authorization,
            record=record,
            tool=tool,
            directive=directive.directive_id if directive is not None else None,
        )
        self._pending = step
        self._steps.append(step)
        return step

    def _fund(self) -> SignedRecord:
        governor, policy = self._governor, self._policy
        parent = governor.node(self._scope).parent_id
        reserve = policy.reserve
        memo = f"recovery reserve for {self._scope}"
        try:
            with governor.ledger.lock:
                if policy.funding is not None:
                    governor.delegate(policy.funding, self._recovery, reserve, memo=memo)
                    source, origin = "delegated", policy.funding
                elif parent is not None:
                    governor.release(self._scope, reserve, memo=f"{memo}, carved out")
                    governor.delegate(parent, self._recovery, reserve, memo=memo)
                    source, origin = "carved", self._scope
                else:
                    governor.open_root(self._recovery, reserve, memo=f"{memo} (root scope)")
                    source, origin = "treasury", None
        except (AgentGovError, ValueError) as exc:
            raise RecoveryError(
                f"cannot fund {self._recovery!r} with {reserve}: {exc}. The ledger shows how "
                f"far it got"
            ) from exc
        return self._open_record(
            {"source": source, "from": origin, "amount": money(reserve)}, adopted=None
        )

    def _adopt(self) -> SignedRecord:
        mine = [r for r in self._records.records() if r.scope == self._scope]
        if not any(
            r.kind == RecordKind.RECOVERY_OPENED and r.body.get("recovery_scope") == self._recovery
            for r in mine
        ):
            raise RecoveryError(
                f"{self._recovery!r} already exists, but this record log holds no record of "
                f"opening it, so what it already revoked is unknown. Resume with the log "
                f"that opened it"
            )
        if any(r.kind == RecordKind.RECOVERY_CLOSED for r in mine):
            raise RecoveryError(f"the recovery of {self._scope!r} was closed")
        settled = {r.body["step"] for r in mine if r.kind == RecordKind.RECOVERY_SETTLED}
        unsettled = 0
        for record in mine:
            if record.kind == RecordKind.EXTENSION_GRANTED:
                # A grant moved billing to the scope it funded; keep billing there.
                target = record.body["scope"]
                if target == self._recovery or target.startswith(f"{self._recovery}/"):
                    if target not in self._billed:
                        self._billed.append(target)
                    self._billing = target
            if record.kind != RecordKind.RECOVERY_STEP:
                continue
            body = record.body
            action = body["action"]
            if body["rung"] == Rung.REVOKE_TOOL.value:
                self._revoked.append(action["tool"])
            elif body["rung"] == Rung.OPERATOR_DIRECTIVE.value:
                self._used.add(action["directive"])
            elif body["rung"] == Rung.TOKEN_CEILING.value:
                self._ceiling = action["ceiling"]
            else:
                self._guided.add(f"{body['trip']['kind']}:{action['sha256']}")
            self._taken = body["step"]
            after = body["transcript"]["after"]
            self._last = (after["count"], after["head"])
            unsettled += body["step"] not in settled
        voided = [
            held
            for scope in self._billed
            for held in self._governor.void_stale(
                0, scope_id=scope, memo="recovery adopted: an unsettled step's hold voided"
            )
        ]
        return self._open_record(
            None,
            adopted={
                "steps": self._taken,
                "unsettled": unsettled,
                "voided_holds": [str(a.authorization_id) for a in voided],
                "billing": self._billing,
            },
        )

    def _open_record(
        self, funding: dict[str, Any] | None, *, adopted: dict[str, Any] | None
    ) -> SignedRecord:
        record = self._records.append(
            RecordKind.RECOVERY_OPENED,
            scope=self._scope,
            body={
                "recovery_scope": self._recovery,
                "funding": funding,
                "adopted": adopted,
                "policy": self._policy.to_json(),
                "policy_digest": self._policy.digest,
                "tools": list(self._granted),
                "trajectory": self._trajectory,
                "ledger": {
                    "sequence": len(self._governor.ledger),
                    "head": self._governor.ledger.head_hash,
                },
            },
        )
        self._anchor(record)
        return record

    def _anchor(self, record: SignedRecord) -> None:
        """Commit the ledger to ``record``. A failure is logged: the record
        stands, and a missing anchor is visible as one."""
        try:
            self._governor.anchor(self._recovery, anchor_memo(record))
        except Exception:
            logger.warning(
                "record %s of log %s could not be anchored into the ledger",
                record.seq,
                record.log,
                exc_info=True,
            )


def _spend_for(entries: Iterable[LedgerEntry], authorization: Authorization) -> LedgerEntry | None:
    """The spend that settled ``authorization``, which names its hold."""
    hold = authorization.entry.entry_id
    return next(
        (e for e in entries if e.entry_type is EntryType.SPEND and e.ref == hold),
        None,
    )


def _spent(entries: Iterable[LedgerEntry]) -> Decimal:
    """Settled spend, net of vendor refunds."""
    total = Decimal(0)
    for entry in entries:
        if entry.entry_type is EntryType.SPEND:
            total += entry.amount
        elif entry.entry_type is EntryType.REVERSAL:
            total -= entry.amount
    return total
