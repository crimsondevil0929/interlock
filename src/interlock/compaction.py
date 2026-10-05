"""What a checkpoint commits to, and how it is held to it (``docs/EPIC5_DESIGN.md`` §1).

A vacuum prunes history no check will read again: rate-window rows older than
the longest span, and outbox stages final and settled. Before a row goes, a
*checkpoint* commits to it, signed in an operator's intent and anchored into
AgentGov (:mod:`interlock.vacuum`). This module is the arithmetic both stores
and every verifier share:

- a :class:`Tombstone` per pruned message: the tip of its hash-linked delivery
  log, which commits to every row it had and, through its genesis, to the
  request; and its settlement;
- a :class:`WindowRow` per pruned row of window history;
- an :class:`InboxCut` per inbound source whose log lost a prefix: where it
  was cut, and the head there, where the rest of the log continues; and a
  leaf per pruned fact, with the stage that consumed it;
- :func:`fold`: a hash chain over leaves in a fixed order, in the outbox's own
  length-prefixed framing, which PL/pgSQL computes byte for byte
  (``interlock.outbox_compact``);
- the :class:`Checkpoint` body, whose canonical JSON is what the intent
  carries and the database keeps.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any, Final

from agentgov.receipts.canonical import canonical_bytes

from interlock.deliveries import _digest, parse_instant
from interlock.types import InboundFact

__all__ = [
    "CHECKPOINT_VERSION",
    "Checkpoint",
    "CheckpointRow",
    "InboxCut",
    "Tombstone",
    "WindowRow",
    "fold",
    "inbox_fact_leaf",
    "inbox_root",
    "instant_text",
    "tombstone_root",
    "window_root",
]

CHECKPOINT_VERSION: Final = "interlock-checkpoint-v1"
TOMBSTONES_TAG: Final = "interlock-compacted-v1"
TOMBSTONE_TAG: Final = "interlock-tombstone-v1"
WINDOWS_TAG: Final = "interlock-windows-v1"
WINDOW_ROW_TAG: Final = "interlock-window-row-v1"
INBOX_FACTS_TAG: Final = "interlock-inbox-facts-v1"
INBOX_FACT_TAG: Final = "interlock-inbox-fact-v1"
GENESIS: Final = "0" * 64


def instant_text(at: datetime) -> str:
    """An instant as checkpoints write it: UTC, to the microsecond."""
    return at.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def fold(tag: str, leaves: Iterable[str]) -> str:
    """A hash chain over ``leaves``: ``r0 = digest(tag, "0")``,
    ``r_i = digest(tag, r_{i-1}, leaf_i)``. Binding to every leaf and its
    place, and computed the same way in SQL."""
    root = _digest(tag, "0")
    for leaf in leaves:
        root = _digest(tag, root, leaf)
    return root


@dataclass(frozen=True, slots=True)
class Tombstone:
    """A message a checkpoint pruned, as the database records it."""

    message_id: uuid.UUID
    checkpoint: int
    stage_id: uuid.UUID
    plan_id: str
    state: str
    log_seq: int
    log_head: str
    """The tip of its delivery log: every row it had, and its request."""
    receipt_id: str | None
    credit: str | None
    cost: str
    """The price the outbox recorded, as it recorded it."""
    compensates: uuid.UUID | None

    def leaf(self) -> str:
        return _digest(
            TOMBSTONE_TAG,
            str(self.message_id),
            str(self.stage_id),
            self.plan_id,
            self.state,
            str(self.log_seq),
            self.log_head,
            self.receipt_id,
            self.credit,
            self.cost,
            None if self.compensates is None else str(self.compensates),
        )


def tombstone_root(tombstones: Iterable[Tombstone]) -> str:
    """What a checkpoint commits to of the messages it pruned: their
    tombstones' fold, in message order."""
    return fold(TOMBSTONES_TAG, (t.leaf() for t in sorted(tombstones, key=_message_order)))


def _message_order(tombstone: Tombstone) -> str:
    return str(tombstone.message_id)


@dataclass(frozen=True, slots=True)
class WindowRow:
    """One row of rate-window history: what one plan added to one key."""

    stage_id: uuid.UUID
    window: str
    key: str
    amount: Decimal
    at: datetime

    def leaf(self) -> str:
        return _digest(
            WINDOW_ROW_TAG,
            str(self.stage_id),
            self.window,
            self.key,
            format(self.amount.normalize(), "f"),
            instant_text(self.at),
        )

    def order(self) -> tuple[str, str, str, str]:
        return (self.window, self.key, str(self.stage_id), instant_text(self.at))


def window_root(rows: Iterable[WindowRow]) -> str:
    """What a checkpoint commits to of the window history it pruned."""
    return fold(WINDOWS_TAG, (r.leaf() for r in sorted(rows, key=WindowRow.order)))


@dataclass(frozen=True, slots=True)
class InboxCut:
    """A prefix of one inbound source's log, pruned (``docs/EPIC5_DESIGN.md``
    §1.3): events ``from + 1`` to ``through``, their facts, and those facts'
    consumption. The log is a hash chain already: ``head``, the hash of event
    ``through``, commits to the whole prefix, and the rest of the log links to
    it. ``prev`` is the hash the prefix linked to, where an earlier cut, or the
    source's genesis, left it."""

    source: str
    start: int
    prev: str
    through: int
    head: str
    events: int
    facts: int
    consumed: int

    def body(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "from": self.start,
            "prev": self.prev,
            "through": self.through,
            "head": self.head,
            "events": self.events,
            "facts": self.facts,
            "consumed": self.consumed,
        }

    @classmethod
    def parse(cls, raw: Mapping[str, Any]) -> InboxCut:
        return cls(
            source=str(raw["source"]),
            start=int(raw["from"]),
            prev=str(raw["prev"]),
            through=int(raw["through"]),
            head=str(raw["head"]),
            events=int(raw["events"]),
            facts=int(raw["facts"]),
            consumed=int(raw["consumed"]),
        )


def inbox_fact_leaf(fact: InboundFact, consumed_by: uuid.UUID | None) -> str:
    """A pruned fact, as a checkpoint commits to it: the binding the inbox
    attested, and the stage that consumed it."""
    return _digest(
        INBOX_FACT_TAG,
        str(fact.fact_id),
        fact.source,
        str(fact.event_seq),
        fact.event_hash,
        str(fact.message_id),
        str(fact.delivery_seq),
        fact.delivery_hash,
        fact.remote_ref,
        fact.scope_id,
        fact.plan_id,
        fact.tenant_id,
        fact.attestation,
        None if consumed_by is None else str(consumed_by),
    )


def inbox_root(facts: Iterable[tuple[InboundFact, uuid.UUID | None]]) -> str:
    """What a checkpoint commits to of the facts it pruned: their leaves'
    fold, in fact order."""
    ordered = sorted(facts, key=lambda pair: str(pair[0].fact_id))
    return fold(INBOX_FACTS_TAG, (inbox_fact_leaf(f, c) for f, c in ordered))


@dataclass(frozen=True, slots=True)
class Checkpoint:
    """A checkpoint's body: what one compaction pruned, and where it sits.

    :ivar seq: Its position in the database's chain of checkpoints, from 1.
    :ivar prev: The previous checkpoint's :attr:`CheckpointRow.digest`, or 64
        zeros for the first.
    :ivar windows_horizon: Window rows at or before this instant were
        pruned; ``None`` when none were.
    :ivar outbox_horizon: Messages whose last log row is older than this
        were eligible.
    :ivar agentgov: The AgentGov ledger's position as the vacuum read it,
        ``(sequence, head hash)``.
    :ivar archive: The SHA-256 of the archive the pruned rows were written
        to first, or ``None``.
    :ivar inbox: The inbound sources' pruned prefixes: ``{"sources": [each
        :class:`InboxCut`], "facts": n, "root": <fact fold>}``; empty when
        none was pruned.
    """

    seq: int
    prev: str
    windows_horizon: str | None
    outbox_horizon: str | None
    messages: int
    rows: int
    root: str
    window_rows: int
    window_root: str
    agentgov: tuple[int, str]
    archive: str | None = None
    inbox: Mapping[str, Any] = field(default_factory=dict)

    def body(self) -> dict[str, Any]:
        return {
            "v": CHECKPOINT_VERSION,
            "seq": self.seq,
            "prev": self.prev,
            "horizon": {
                "windows": self.windows_horizon,
                "outbox": self.outbox_horizon,
            },
            "outbox": {"messages": self.messages, "rows": self.rows, "root": self.root},
            "windows": {"rows": self.window_rows, "root": self.window_root},
            "inbox": dict(self.inbox),
            "agentgov": {"sequence": self.agentgov[0], "head": self.agentgov[1]},
            "archive": self.archive,
        }

    def canonical(self) -> str:
        """The body's canonical JSON: what the intent signs and the database
        keeps, byte for byte."""
        return canonical_bytes(self.body()).decode("utf-8")

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.canonical().encode("utf-8")).hexdigest()

    @classmethod
    def parse(cls, text: str) -> Checkpoint:
        """A body as the database or an intent carries it.

        :raises ValueError: If it is not a checkpoint of this version.
        """
        raw = json.loads(text)
        if not isinstance(raw, Mapping) or raw.get("v") != CHECKPOINT_VERSION:
            raise ValueError("not a checkpoint")
        horizon, outbox, windows = raw["horizon"], raw["outbox"], raw["windows"]
        anchor = raw["agentgov"]
        return cls(
            seq=int(raw["seq"]),
            prev=str(raw["prev"]),
            windows_horizon=horizon.get("windows"),
            outbox_horizon=horizon.get("outbox"),
            messages=int(outbox["messages"]),
            rows=int(outbox["rows"]),
            root=str(outbox["root"]),
            window_rows=int(windows["rows"]),
            window_root=str(windows["root"]),
            agentgov=(int(anchor["sequence"]), str(anchor["head"])),
            archive=raw.get("archive"),
            inbox=dict(raw.get("inbox") or {}),
        )

    def windows_horizon_at(self) -> datetime | None:
        return None if self.windows_horizon is None else parse_instant(self.windows_horizon)

    def inbox_cuts(self) -> tuple[InboxCut, ...]:
        return tuple(InboxCut.parse(raw) for raw in self.inbox.get("sources", ()))


@dataclass(frozen=True, slots=True)
class CheckpointRow:
    """A checkpoint as the database holds it.

    :ivar open: SQLite only: set while the transaction that wrote it is still
        deleting, and never seen set outside it. A row left open was written
        around Interlock.
    """

    seq: int
    authority: str
    body: str
    digest: str
    prev: str
    windows_horizon: datetime | None
    open: bool = False

    def checkpoint(self) -> Checkpoint:
        return Checkpoint.parse(self.body)


def heads_argument(tombstones: Sequence[Tombstone]) -> list[dict[str, Any]]:
    """The heads a compaction is signed for, as ``outbox_compact`` takes them."""
    return [
        {"message": str(t.message_id), "seq": t.log_seq, "head": t.log_head} for t in tombstones
    ]
