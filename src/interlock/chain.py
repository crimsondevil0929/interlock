"""Interlock's own append-only, hash-linked record chain.

Separate from AgentGov's ledger. AgentGov records money; Interlock records
adjudication decisions. Keeping them separate keeps the component that holds
production write credentials outside the trust boundary of the record that has
to survive an incident involving that component, and lets the two fail
independently.

The chain stores digests, not row data. Copying before and after images into an
audit log would replicate the production data it is auditing, including
whatever is sensitive in it, into a second store with different access control.

Durability is opt-in. ``EscrowChain()`` with no path keeps records in memory
only, and the process losing them loses the audit trail. Pass a path in
production.
"""

from __future__ import annotations

import json
import threading
import uuid
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path

from interlock.exceptions import ChainIntegrityError
from interlock.types import AUDIT_VERSION, GENESIS_HASH, PlanId, canonical_hash, iso

__all__ = ["EscrowChain", "EscrowRecord", "RecordType"]


class RecordType(Enum):
    """The escrow event a record attests."""

    PLAN_ADMITTED = "plan_admitted"
    STAGE_OPENED = "stage_opened"
    DIFF_COMPUTED = "diff_computed"
    VERDICT = "verdict"
    COMMITTED = "committed"
    ABORTED = "aborted"
    ORPHANED = "orphaned"
    COMPENSATED = "compensated"


@dataclass(frozen=True, slots=True)
class EscrowRecord:
    """One tamper-evident escrow event, anchored to the AgentGov chain.

    :ivar payload_hash: Digest of the artifact this record attests, which is a
        plan, a diff, a verdict or a receipt. The artifact lives elsewhere; the
        chain carries only the digest.
    :ivar anchored: Whether an AgentGov ledger was attached when this was
        written. Recorded explicitly so an unanchored record is not read as an
        anchored one.
    :ivar agentgov_head_hash: ``Ledger.head_hash`` observed at record creation.
    :ivar agentgov_sequence: Sequence of the entry that head belongs to, or
        ``-1`` when unanchored. Enables the monotonicity check.
    """

    sequence: int
    record_id: uuid.UUID
    timestamp: datetime
    record_type: RecordType
    plan_id: PlanId
    stage_id: uuid.UUID | None
    payload_hash: str
    anchored: bool
    agentgov_head_hash: str
    agentgov_sequence: int
    prev_hash: str
    record_hash: str
    note: str = ""

    def recompute_hash(self) -> str:
        """Re-derive this record's hash from its own fields."""
        return canonical_hash(
            [
                self.prev_hash,
                self.sequence,
                str(self.record_id),
                iso(self.timestamp),
                self.record_type.value,
                self.plan_id,
                str(self.stage_id) if self.stage_id else None,
                self.payload_hash,
                self.anchored,
                self.agentgov_head_hash,
                self.agentgov_sequence,
                self.note,
            ]
        )

    def to_json(self) -> dict[str, object]:
        return {
            "v": AUDIT_VERSION,
            "sequence": self.sequence,
            "record_id": str(self.record_id),
            "timestamp": iso(self.timestamp),
            "record_type": self.record_type.value,
            "plan_id": self.plan_id,
            "stage_id": str(self.stage_id) if self.stage_id else None,
            "payload_hash": self.payload_hash,
            "anchored": self.anchored,
            "agentgov_head_hash": self.agentgov_head_hash,
            "agentgov_sequence": self.agentgov_sequence,
            "prev_hash": self.prev_hash,
            "record_hash": self.record_hash,
            "note": self.note,
        }


class EscrowChain:
    """An append-only chain of adjudication records.

    Thread-safe. Appends are serialized by one mutex, which is sufficient
    because a chain append is microseconds of hashing and no I/O beyond an
    optional line write.

    :param path: Optional JSON Lines file. Each append is written and flushed
        immediately, so a crash loses at most the record in flight. With no
        path the chain is in memory only and does not survive the process.

        ``flush()`` pushes to the OS, not to disk. A machine that loses power
        can lose flushed-but-unsynced lines; an ``fsync`` per append is not
        done here and would change the cost of an append.
    """

    __slots__ = ("_head", "_lock", "_path", "_records")

    def __init__(self, path: str | Path | None = None) -> None:
        self._records: list[EscrowRecord] = []
        self._head = GENESIS_HASH
        self._lock = threading.RLock()
        self._path = Path(path) if path is not None else None
        if self._path is not None:
            self._path.parent.mkdir(parents=True, exist_ok=True)

    def __len__(self) -> int:
        with self._lock:
            return len(self._records)

    def __iter__(self) -> Iterator[EscrowRecord]:
        return iter(self.records())

    @property
    def head_hash(self) -> str:
        """Hash of the most recent record, or the genesis value."""
        with self._lock:
            return self._head

    def records(self) -> tuple[EscrowRecord, ...]:
        with self._lock:
            return tuple(self._records)

    def append(
        self,
        record_type: RecordType,
        *,
        plan_id: PlanId,
        payload_hash: str,
        stage_id: uuid.UUID | None = None,
        anchored: bool = False,
        agentgov_head_hash: str = GENESIS_HASH,
        agentgov_sequence: int = -1,
        note: str = "",
    ) -> EscrowRecord:
        """Append one record and return it.

        :returns: The committed record, carrying its own hash.
        """
        with self._lock:
            sequence = len(self._records) + 1
            prev_hash = self._head
            partial = EscrowRecord(
                sequence=sequence,
                record_id=uuid.uuid4(),
                timestamp=datetime.now(UTC),
                record_type=record_type,
                plan_id=plan_id,
                stage_id=stage_id,
                payload_hash=payload_hash,
                anchored=anchored,
                agentgov_head_hash=agentgov_head_hash,
                agentgov_sequence=agentgov_sequence,
                prev_hash=prev_hash,
                record_hash="",
                note=note,
            )
            record = _with_hash(partial)
            self._records.append(record)
            self._head = record.record_hash
            if self._path is not None:
                with self._path.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(record.to_json(), separators=(",", ":")) + "\n")
                    handle.flush()
            return record

    def for_plan(self, plan_id: PlanId) -> tuple[EscrowRecord, ...]:
        return tuple(r for r in self.records() if r.plan_id == plan_id)

    # -- verification -------------------------------------------------------

    def verify(self) -> None:
        """Re-derive every hash and every link.

        :raises ChainIntegrityError: On the first record that does not hold.
        """
        previous = GENESIS_HASH
        for index, record in enumerate(self.records(), start=1):
            if record.sequence != index:
                raise ChainIntegrityError(
                    f"record {index} carries sequence {record.sequence}; the chain has a gap"
                )
            if record.prev_hash != previous:
                raise ChainIntegrityError(
                    f"record {index} links to {record.prev_hash[:16]}, "
                    f"expected {previous[:16]}: the chain was re-linked"
                )
            expected = record.recompute_hash()
            if record.record_hash != expected:
                raise ChainIntegrityError(
                    f"record {index} hashes to {expected[:16]} but claims "
                    f"{record.record_hash[:16]}: its contents were edited"
                )
            previous = record.record_hash

    def verify_anchors(self) -> None:
        """Check that observed AgentGov positions never regress.

        One-way anchoring bounds a record's time from below: a record naming
        head ``H_n`` cannot predate AgentGov entry ``n``. It does not bound it
        from above, because a record can name a stale head and so look older
        than it is. Requiring the observed sequence to be non-decreasing across
        an append-only chain covers that, except at the chain's own genesis,
        which a self-hosted log cannot cover without an external anchor.

        :raises ChainIntegrityError: If an anchor regresses.
        """
        highest = -1
        for record in self.records():
            if not record.anchored:
                continue
            if record.agentgov_sequence < highest:
                raise ChainIntegrityError(
                    f"record {record.sequence} anchors to AgentGov sequence "
                    f"{record.agentgov_sequence}, behind {highest} seen earlier: "
                    f"the anchor regressed"
                )
            highest = max(highest, record.agentgov_sequence)

    @classmethod
    def load(cls, path: str | Path) -> EscrowChain:
        """Read a chain previously written by :meth:`append`.

        Runs :meth:`verify` before returning, so a file whose links or digests
        do not hold raises instead of loading. Does NOT run
        :meth:`verify_anchors`; call that separately if the chain is anchored.
        """
        chain = cls()
        source = Path(path)
        for line in source.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            raw = json.loads(line)
            chain._records.append(_from_json(raw))
        if chain._records:
            chain._head = chain._records[-1].record_hash
        chain._path = source
        chain.verify()
        return chain


def _with_hash(record: EscrowRecord) -> EscrowRecord:
    """Return ``record`` with its ``record_hash`` filled in."""
    digest = record.recompute_hash()
    return EscrowRecord(
        sequence=record.sequence,
        record_id=record.record_id,
        timestamp=record.timestamp,
        record_type=record.record_type,
        plan_id=record.plan_id,
        stage_id=record.stage_id,
        payload_hash=record.payload_hash,
        anchored=record.anchored,
        agentgov_head_hash=record.agentgov_head_hash,
        agentgov_sequence=record.agentgov_sequence,
        prev_hash=record.prev_hash,
        record_hash=digest,
        note=record.note,
    )


def _from_json(raw: dict[str, object]) -> EscrowRecord:
    stage = raw.get("stage_id")
    return EscrowRecord(
        sequence=int(str(raw["sequence"])),
        record_id=uuid.UUID(str(raw["record_id"])),
        timestamp=datetime.fromisoformat(str(raw["timestamp"])),
        record_type=RecordType(str(raw["record_type"])),
        plan_id=PlanId(str(raw["plan_id"])),
        stage_id=uuid.UUID(str(stage)) if stage else None,
        payload_hash=str(raw["payload_hash"]),
        anchored=bool(raw["anchored"]),
        agentgov_head_hash=str(raw["agentgov_head_hash"]),
        agentgov_sequence=int(str(raw["agentgov_sequence"])),
        prev_hash=str(raw["prev_hash"]),
        record_hash=str(raw["record_hash"]),
        note=str(raw.get("note", "")),
    )


def summarize(records: Sequence[EscrowRecord]) -> str:
    """One line per record, for a terminal audit view."""
    lines = []
    for r in records:
        anchor = f"agov={r.agentgov_sequence}" if r.anchored else "unanchored"
        lines.append(
            f"ILOK1|seq={r.sequence:04d}|{r.record_type.value:<14}|plan={r.plan_id}"
            f"|{anchor}|h={r.record_hash[:16]}|{r.note}"
        )
    return "\n".join(lines)
