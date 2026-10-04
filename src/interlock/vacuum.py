"""The vacuum: cryptographic compaction of the outbox (``docs/EPIC5_DESIGN.md`` §1).

A vacuum prunes what no check will read again, as an operator's action signed
in two phases like every other (``docs/EPIC3_DESIGN.md`` §6):

1. **Survey.** Verify everything from the database and the keys alone: every
   delivery log, every relay's attestation, every operator row, the operator
   log, every earlier checkpoint. Anything that does not verify is evidence of
   tampering: nothing is pruned while it stands. Then collect what may go:
   stages whose every message is delivered and settled, or cancelled, older
   than the retention, in no row of the legacy set; and rate-window history
   older than the longest window's span plus a margin.
2. **Archive** (optional). Write what will go to a file, whose SHA-256 the
   checkpoint carries: :func:`verify_archive` proves it against the checkpoint.
3. **Intent.** Sign an ``operator.intent``, action ``compact``, carrying the
   :class:`~interlock.compaction.Checkpoint`: the tombstones' fold, the window
   rows' fold, the horizons, the AgentGov ledger's head. The operator log
   anchors it into AgentGov. If the anchor is not there, nothing is pruned:
   the intent is recorded abandoned.
4. **Act.** One database transaction, under the intent's hash: the checkpoint
   row, the tombstones, the folds recomputed from what the database holds and
   held to the signed ones, the deletions. All or nothing.
5. **Outcome.** ``operator.applied`` names the checkpoint; ``operator.refused``
   says why the database refused.

A process killed after the intent leaves no checkpoint under it, and the next
operator command records it abandoned (:meth:`~interlock.operators.Operator.resolve`);
one killed after the commit leaves the checkpoint, and the next records it
applied. Rows never go without a checkpoint signed and anchored before them.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from agentgov.core import EntryType
from agentgov.receipts.canonical import canonical_bytes

from interlock.compaction import (
    GENESIS,
    Checkpoint,
    CheckpointRow,
    Tombstone,
    WindowRow,
    heads_argument,
    instant_text,
    tombstone_root,
    window_root,
)
from interlock.deliveries import (
    LogEvent,
    LoggedMessage,
    OutboxOperations,
    _verify_one,
    parse_instant,
    verify_delivery_log,
)
from interlock.exceptions import CompactionRefusedError
from interlock.records import Keyring, anchor_memo

if TYPE_CHECKING:
    from agentgov import BudgetManager

    from interlock.operators import OperatorLog
    from interlock.windows import RateWindow

__all__ = [
    "ARCHIVE_VERSION",
    "Survey",
    "Vacuum",
    "VacuumReport",
    "survey",
    "verify_archive",
]

ARCHIVE_VERSION: Final = "interlock-archive-v1"
_MESSAGE: Final = re.compile(r"\Amessage ([0-9a-f-]{36})\b")
_FINAL: Final = frozenset({"delivered", "cancelled"})


# --------------------------------------------------------------------------
# survey: what may go, verified first
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Survey:
    """What a vacuum found: what it may prune, and why it prunes nothing else.

    :ivar problems: Findings that are no one message's: the operator log, an
        earlier checkpoint, the legacy set. While any stands, nothing is
        pruned: the evidence a vacuum would rely on does not hold.
    :ivar kept: Each stage with a message that did not verify, and why: it is
        kept, whatever its age.
    """

    now: datetime
    outbox_horizon: datetime
    windows_horizon: datetime | None
    tombstones: tuple[Tombstone, ...]
    log_rows: int
    window_rows: tuple[WindowRow, ...]
    messages: Mapping[uuid.UUID, LoggedMessage]
    events: Mapping[uuid.UUID, tuple[LogEvent, ...]]
    settlements: Mapping[uuid.UUID, Any]
    problems: tuple[str, ...] = ()
    kept: tuple[tuple[uuid.UUID, str], ...] = ()

    @property
    def empty(self) -> bool:
        return not self.tombstones and not self.window_rows


def survey(
    outbox: OutboxOperations,
    *,
    records: Sequence[Any],
    operators: Keyring,
    relays: Keyring,
    windows: Sequence[RateWindow] = (),
    retain: timedelta = timedelta(days=30),
    margin: timedelta = timedelta(hours=1),
) -> Survey:
    """Verify the outbox, then collect what a vacuum may prune.

    :param records: The operator log's records, as read.
    :param operators: Every operator's public key.
    :param relays: Every relay's public key: an outcome is pruned only when
        its attestation verifies.
    :param windows: The rate windows engines measure. Window history goes
        only past the longest one's span plus ``margin``; with none, it stays.
    :param retain: How long after its last log row a final message stays.
    """
    from interlock.attestations import verify_attestations
    from interlock.operators import legacy_vouch, verify_operators

    now = outbox.database_now()
    found: list[str] = list(verify_delivery_log(outbox))
    found += verify_attestations(outbox, relays, legacy=legacy_vouch(records, operators)).problems
    found += verify_operators(outbox, records, operators).problems
    by_message: dict[uuid.UUID, list[str]] = {}
    problems: list[str] = []
    for problem in dict.fromkeys(found):
        matched = _MESSAGE.match(problem)
        if matched is None:
            problems.append(problem)
        else:
            by_message.setdefault(uuid.UUID(matched.group(1)), []).append(problem)
    messages, events = outbox.snapshot(None)
    logs: dict[uuid.UUID, list[LogEvent]] = {}
    for event in events:
        logs.setdefault(event.message_id, []).append(event)
    settled = outbox.settlements()
    legacy = outbox.legacy()
    legacy_messages = {m for m, _ in legacy.rows} if legacy is not None else set()
    outbox_horizon = now - retain
    stages: dict[uuid.UUID, list[LoggedMessage]] = {}
    for message in messages:
        stages.setdefault(message.stage_id, []).append(message)
    tombstones: list[Tombstone] = []
    kept: list[tuple[uuid.UUID, str]] = []
    log_rows = 0
    if not problems:
        for stage, members in sorted(stages.items(), key=lambda item: str(item[0])):
            why = _kept(members, logs, settled, legacy_messages, by_message, outbox_horizon)
            if why is not None:
                if by_message.keys() & {m.message_id for m in members}:
                    kept.append((stage, why))
                continue
            for message in members:
                settlement = settled.get(message.message_id)
                tombstones.append(
                    Tombstone(
                        message_id=message.message_id,
                        checkpoint=0,
                        stage_id=message.stage_id,
                        plan_id=message.plan_id,
                        state=message.state,
                        log_seq=message.log_seq,
                        log_head=message.log_head,
                        receipt_id=None if settlement is None else settlement.receipt_id,
                        credit=None if settlement is None else settlement.credit,
                        cost=_cost_text(message.cost),
                        compensates=message.compensates,
                    )
                )
                log_rows += len(logs.get(message.message_id, ()))
    windows_horizon = None
    pruned: list[WindowRow] = []
    if windows and not problems:
        horizon = now - max(w.span for w in windows) - margin
        pruned = outbox.window_rows(horizon)
        windows_horizon = horizon if pruned else None
    chosen = {t.message_id for t in tombstones}
    return Survey(
        now=now,
        outbox_horizon=outbox_horizon,
        windows_horizon=windows_horizon,
        tombstones=tuple(tombstones),
        log_rows=log_rows,
        window_rows=tuple(pruned),
        messages={m.message_id: m for m in messages if m.message_id in chosen},
        events={m: tuple(logs.get(m, ())) for m in chosen},
        settlements={m: settled[m] for m in chosen if m in settled},
        problems=tuple(problems),
        kept=tuple(kept),
    )


def _kept(
    members: Sequence[LoggedMessage],
    logs: Mapping[uuid.UUID, Sequence[LogEvent]],
    settled: Mapping[uuid.UUID, Any],
    legacy: set[uuid.UUID],
    problems: Mapping[uuid.UUID, Sequence[str]],
    horizon: datetime,
) -> str | None:
    """Why a stage stays, or ``None`` when it may go whole."""
    for message in members:
        where = f"message {message.message_id}"
        if message.message_id in problems:
            return f"{where} does not verify: {problems[message.message_id][0]}"
        if message.state not in _FINAL:
            return f"{where} is {message.state}"
        if message.state == "delivered" and message.message_id not in settled:
            return f"{where} is delivered and not settled yet"
        if message.message_id in legacy:
            return f"{where} is in the legacy set, which is kept"
        log = logs.get(message.message_id, ())
        if not log or log[-1].at >= horizon:
            return f"{where} is within its retention"
    return None


def _cost_text(cost: Decimal) -> str:
    """A price as the outbox stores it: the text it was written as."""
    return str(cost)


# --------------------------------------------------------------------------
# the archive
# --------------------------------------------------------------------------


def _message_line(
    message: LoggedMessage, events: Sequence[LogEvent], settlement: Any
) -> dict[str, Any]:
    return {
        "kind": "message",
        "message": {
            "message_id": str(message.message_id),
            "stage_id": str(message.stage_id),
            "plan_id": message.plan_id,
            "scope_id": message.scope_id,
            "effect_id": message.effect_id,
            "sink": message.sink,
            "operation": message.operation,
            "idempotency_key": message.idempotency_key,
            "payload_hash": message.payload_hash,
            "state": message.state,
            "attempts": message.attempts,
            "log_seq": message.log_seq,
            "log_head": message.log_head,
            "cost": _cost_text(message.cost),
            "compensates": None if message.compensates is None else str(message.compensates),
        },
        "events": [
            {
                "seq": e.seq,
                "attempt": e.attempt,
                "event": e.event,
                "actor": e.actor,
                "at": instant_text(e.at),
                "status_code": e.status_code,
                "response_digest": e.response_digest,
                "detail": e.detail,
                "state_after": e.state_after,
                "prev_hash": e.prev_hash,
                "event_hash": e.event_hash,
                "remote_ref": e.remote_ref,
                "authority": e.authority,
                "attestation": e.attestation,
            }
            for e in events
        ],
        "settlement": None
        if settlement is None
        else {"receipt_id": settlement.receipt_id, "credit": settlement.credit},
    }


def _window_line(row: WindowRow) -> dict[str, Any]:
    return {
        "kind": "window",
        "stage_id": str(row.stage_id),
        "window": row.window,
        "key": row.key,
        "amount": format(row.amount.normalize(), "f"),
        "at": instant_text(row.at),
    }


def write_archive(path: Path, header: Checkpoint, found: Survey) -> str:
    """Write what ``found`` prunes to ``path``, one canonical JSON document a
    line: the checkpoint (its ``archive`` unset), then every message with its
    log and settlement, then every window row. Returns the file's SHA-256,
    which the checkpoint then carries.

    Written whole, then moved into place. A file already there for the same
    checkpoint is one a run that died before its act left: no checkpoint in
    the database names it, so it is replaced.
    """
    lines = [{"v": ARCHIVE_VERSION, "checkpoint": header.body()}]
    for tombstone in sorted(found.tombstones, key=lambda t: str(t.message_id)):
        message = found.messages[tombstone.message_id]
        lines.append(
            _message_line(
                message,
                found.events.get(tombstone.message_id, ()),
                found.settlements.get(tombstone.message_id),
            )
        )
    lines += [_window_line(row) for row in sorted(found.window_rows, key=WindowRow.order)]
    data = b"".join(canonical_bytes(line) + b"\n" for line in lines)
    path.parent.mkdir(parents=True, exist_ok=True)
    partial = path.with_name(path.name + ".partial")
    with partial.open("wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(partial, path)
    return hashlib.sha256(data).hexdigest()


def verify_archive(
    path: Path, checkpoint: Checkpoint, *, relays: Keyring | None = None
) -> list[str]:
    """Prove the history an archive holds against the checkpoint that pruned it.

    Every archived message's log recomputes from its genesis to the head its
    tombstone carries; every outcome's relay attestation verifies (with
    ``relays``); the tombstones fold to the checkpoint's root, the window rows
    to its window root; and the file is the one whose digest the checkpoint
    carries.

    :returns: Every problem found; empty when the archive proves out.
    """
    from agentgov.exceptions import MalformedReceiptError, ReceiptSignatureError

    from interlock.attestations import attestation_of

    data = path.read_bytes()
    problems: list[str] = []
    if checkpoint.archive is None:
        problems.append(f"checkpoint {checkpoint.seq} carries no archive")
    elif hashlib.sha256(data).hexdigest() != checkpoint.archive:
        problems.append(f"{path.name} is not the archive checkpoint {checkpoint.seq} carries")
    lines = [json.loads(line) for line in data.splitlines() if line.strip()]
    if not lines or lines[0].get("v") != ARCHIVE_VERSION:
        return [*problems, f"{path.name} is not an archive"]
    header = Checkpoint.parse(json.dumps(lines[0]["checkpoint"]))
    if header.seq != checkpoint.seq or header.root != checkpoint.root:
        problems.append(f"{path.name} archives checkpoint {header.seq}, not {checkpoint.seq}")
    tombstones: list[Tombstone] = []
    rows: list[WindowRow] = []
    for line in lines[1:]:
        if line.get("kind") == "window":
            rows.append(
                WindowRow(
                    stage_id=uuid.UUID(line["stage_id"]),
                    window=line["window"],
                    key=line["key"],
                    amount=Decimal(line["amount"]),
                    at=parse_instant(line["at"]),
                )
            )
            continue
        raw = line["message"]
        message = LoggedMessage(
            message_id=uuid.UUID(raw["message_id"]),
            stage_id=uuid.UUID(raw["stage_id"]),
            plan_id=raw["plan_id"],
            scope_id=raw["scope_id"],
            effect_id=raw["effect_id"],
            sink=raw["sink"],
            operation=raw["operation"],
            idempotency_key=raw["idempotency_key"],
            payload_hash=raw["payload_hash"],
            state=raw["state"],
            attempts=int(raw["attempts"]),
            log_seq=int(raw["log_seq"]),
            log_head=raw["log_head"],
            cost=Decimal(raw["cost"]),
            compensates=None if raw["compensates"] is None else uuid.UUID(raw["compensates"]),
        )
        events = [
            LogEvent(
                message_id=message.message_id,
                seq=int(e["seq"]),
                attempt=e["attempt"],
                event=e["event"],
                actor=e["actor"],
                at=parse_instant(e["at"]),
                status_code=e["status_code"],
                response_digest=e["response_digest"],
                detail=e["detail"],
                state_after=e["state_after"],
                prev_hash=e["prev_hash"],
                event_hash=e["event_hash"],
                remote_ref=e["remote_ref"],
                authority=e["authority"],
                attestation=e["attestation"],
            )
            for e in line["events"]
        ]
        found = _verify_one(
            events,
            genesis=message.genesis(),
            state=message.state,
            attempts=message.attempts,
            log_seq=message.log_seq,
            log_head=message.log_head,
        )
        problems += [f"message {message.message_id}: {p}" for p in found]
        if relays is not None:
            for event in events:
                if event.attestation is None:
                    continue
                try:
                    statement = attestation_of(message, event)
                    assert statement.signature is not None
                    key = relays.verifier(statement.signature.key_id)
                    if key is None:
                        raise ReceiptSignatureError("no registered relay's key")
                    statement.verify(key)
                except (MalformedReceiptError, ReceiptSignatureError) as exc:
                    problems.append(
                        f"message {message.message_id}: row {event.seq}'s attestation: {exc}"
                    )
        settlement = line.get("settlement") or {}
        tombstones.append(
            Tombstone(
                message_id=message.message_id,
                checkpoint=checkpoint.seq,
                stage_id=message.stage_id,
                plan_id=message.plan_id,
                state=message.state,
                log_seq=message.log_seq,
                log_head=message.log_head,
                receipt_id=settlement.get("receipt_id"),
                credit=settlement.get("credit"),
                cost=raw["cost"],
                compensates=message.compensates,
            )
        )
    if (tombstone_root(tombstones), len(tombstones)) != (checkpoint.root, checkpoint.messages):
        problems.append(f"the archived messages do not fold to checkpoint {checkpoint.seq}'s root")
    if (window_root(rows), len(rows)) != (checkpoint.window_root, checkpoint.window_rows):
        problems.append(
            f"the archived window rows do not fold to checkpoint {checkpoint.seq}'s root"
        )
    return problems


# --------------------------------------------------------------------------
# the vacuum
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class VacuumReport:
    """What one vacuum did.

    :ivar checkpoint: The checkpoint written, or ``None`` when nothing was
        pruned.
    :ivar outcome: ``"applied"``, ``"nothing"`` (nothing was due),
        ``"refused"`` (verification found problems, nothing signed), ``"dry-run"``,
        ``"abandoned"`` (the intent could not be anchored) or ``"rejected"``
        (the database refused the act).
    """

    outcome: str
    checkpoint: Checkpoint | None
    messages: int
    log_rows: int
    window_rows: int
    problems: tuple[str, ...] = ()
    kept: tuple[tuple[uuid.UUID, str], ...] = ()
    archive: Path | None = None


class Vacuum:
    """Compacts an outbox: verify, sign, anchor, prune (module docstring).

    :param log: The operator log, opened with the acting operator's key and
        anchored into ``ledger``.
    :param outbox: The outbox: a PostgreSQL connection as the installer,
        wrapped by :func:`interlock.deliveries.operations`, or a SQLite store
        opened with :data:`~interlock.sqlite_outbox.COMPACTOR`.
    :param operators: Every operator's public key.
    :param relays: Every relay's public key.
    :param ledger: The AgentGov ledger the operator log anchors into: the
        checkpoint is anchored there before anything is pruned.
    :param windows: The rate windows engines measure (``[[windows]]``).
    :param retain: How long a final message stays after its last log row.
    :param margin: How long window history stays past the longest span.
    :param archive: A directory to write each checkpoint's pruned rows to.
    :param checkpoint: Called at ``surveyed``, ``intent``, ``anchored``,
        ``transaction`` (inside the database's transaction, before its commit),
        ``acted`` and ``recorded``: the crash tests stop the process there.
    :raises ValueError: If ``log`` anchors into no ledger.
    """

    __slots__ = (
        "_archive",
        "_checkpoint",
        "_ledger",
        "_log",
        "_margin",
        "_operators",
        "_outbox",
        "_relays",
        "_retain",
        "_windows",
    )

    def __init__(
        self,
        log: OperatorLog,
        outbox: OutboxOperations,
        *,
        operators: Keyring,
        relays: Keyring,
        ledger: BudgetManager,
        windows: Sequence[RateWindow] = (),
        retain: timedelta = timedelta(days=30),
        margin: timedelta = timedelta(hours=1),
        archive: str | Path | None = None,
        checkpoint: Callable[[str], None] | None = None,
    ) -> None:
        if retain < timedelta(0) or margin < timedelta(0):
            raise ValueError("retain and margin are durations, not negative")
        self._log = log
        self._outbox = outbox
        self._operators = operators
        self._relays = relays
        self._ledger = ledger
        self._windows = tuple(windows)
        self._retain = retain
        self._margin = margin
        self._archive = None if archive is None else Path(archive)
        self._checkpoint = checkpoint or (lambda point: None)

    def survey(self) -> Survey:
        """What a run would prune now, and why it prunes nothing else."""
        return survey(
            self._outbox,
            records=self._log.records(),
            operators=self._operators,
            relays=self._relays,
            windows=self._windows,
            retain=self._retain,
            margin=self._margin,
        )

    def run(self, *, reason: str | None = None, dry_run: bool = False) -> VacuumReport:
        """Verify, then prune what may go under one checkpoint."""
        from interlock.operators import ABANDONED, APPLIED, INTENT, REFUSED, Operator, _ref

        Operator(self._log, self._outbox).resolve()
        found = self.survey()
        self._checkpoint("surveyed")
        counts = (len(found.tombstones), found.log_rows, len(found.window_rows))
        if found.problems:
            return VacuumReport("refused", None, 0, 0, 0, found.problems, found.kept)
        if found.empty:
            return VacuumReport("nothing", None, 0, 0, 0, (), found.kept)
        last = _last(self._outbox.checkpoints())
        draft = Checkpoint(
            seq=1 if last is None else last.seq + 1,
            prev=GENESIS if last is None else last.digest,
            windows_horizon=None
            if found.windows_horizon is None
            else instant_text(found.windows_horizon),
            outbox_horizon=instant_text(found.outbox_horizon),
            messages=len(found.tombstones),
            rows=found.log_rows,
            root=tombstone_root(found.tombstones),
            window_rows=len(found.window_rows),
            window_root=window_root(found.window_rows),
            agentgov=self._head(),
        )
        if dry_run:
            return VacuumReport("dry-run", draft, *counts, (), found.kept)
        written = None
        if self._archive is not None:
            written = self._archive / f"checkpoint-{draft.seq}.jsonl"
            digest = write_archive(written, draft, found)
            draft = Checkpoint(**{**_fields(draft), "archive": digest})
        intent = self._log.append(
            INTENT,
            {"action": "compact", "targets": [], "reason": reason, "checkpoint": draft.body()},
        )
        self._checkpoint("intent")
        if not self._anchored(intent):
            self._log.append(
                ABANDONED,
                {
                    "intent": _ref(intent),
                    "why": "the checkpoint could not be anchored into AgentGov: nothing pruned",
                },
            )
            return VacuumReport("abandoned", draft, 0, 0, 0, (), found.kept, written)
        self._checkpoint("anchored")
        try:
            done = self._outbox.compact(
                intent.record_hash,
                draft.canonical(),
                heads_argument(found.tombstones),
                before_commit=lambda: self._checkpoint("transaction"),
            )
        except CompactionRefusedError as exc:
            self._log.append(
                REFUSED, {"intent": _ref(intent), "rows": [], "skipped": [], "why": str(exc)}
            )
            return VacuumReport("rejected", draft, 0, 0, 0, (str(exc),), found.kept, written)
        self._checkpoint("acted")
        self._log.append(
            APPLIED,
            {
                "intent": _ref(intent),
                "rows": [],
                "skipped": [],
                "checkpoint": {"seq": draft.seq, "digest": draft.digest},
                "pruned": done,
            },
        )
        self._checkpoint("recorded")
        return VacuumReport("applied", draft, *counts, (), found.kept, written)

    def _head(self) -> tuple[int, str]:
        ledger = self._ledger.ledger
        with ledger.lock:
            return len(ledger), str(ledger.head_hash)

    def _anchored(self, intent: Any) -> bool:
        memo = anchor_memo(intent)
        return any(
            e.entry_type is EntryType.ANCHOR and e.memo == memo for e in self._ledger.audit_trail()
        )


def _last(rows: Iterable[CheckpointRow]) -> CheckpointRow | None:
    ordered = sorted(rows, key=lambda r: r.seq)
    return ordered[-1] if ordered else None


def _fields(checkpoint: Checkpoint) -> dict[str, Any]:
    return {name: getattr(checkpoint, name) for name in Checkpoint.__dataclass_fields__}
