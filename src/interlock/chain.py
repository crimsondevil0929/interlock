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
production. A chain opened on an existing file resumes it: every record is read
and verified before the first append, so a restarted process continues the
chain instead of forking it at its first record.
"""

from __future__ import annotations

import json
import logging
import os
import socket
import sys
import threading
import uuid
from collections.abc import Iterator, Sequence
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from types import TracebackType

from interlock.exceptions import AnchorError, ChainIntegrityError, ChainInUseError
from interlock.types import AUDIT_VERSION, GENESIS_HASH, PlanId, canonical_hash, iso

__all__ = ["EscrowChain", "EscrowRecord", "RecordType"]

logger = logging.getLogger("interlock.chain")


class RecordType(Enum):
    """The escrow event a record attests."""

    PLAN_ADMITTED = "plan_admitted"
    STAGE_OPENED = "stage_opened"
    DIFF_COMPUTED = "diff_computed"
    VERDICT = "verdict"
    COMMIT_INTENT = "commit_intent"
    """Written immediately before the substrate is told to commit. An intent
    with no terminal record after it marks a plan whose outcome is unknown to
    the chain: see :meth:`EscrowChain.unresolved_intents`."""

    COMMITTED = "committed"
    ABORTED = "aborted"
    ORPHANED = "orphaned"
    COMPENSATED = "compensated"
    REPAIR_PROPOSED = "repair_proposed"
    """A repair search found a smaller plan that would be admitted. The payload
    is the proposal's content hash, the plan id the refused plan's. The engine
    admits a plan naming itself a repair only if this record matches it."""


_TERMINAL = frozenset(
    {RecordType.COMMITTED, RecordType.ABORTED, RecordType.ORPHANED, RecordType.COMPENSATED}
)
"""Records that settle a plan's outcome."""

_SYNCED = frozenset({RecordType.COMMIT_INTENT, *_TERMINAL})
"""Records forced to stable storage before ``append`` returns. An fsync covers
every earlier write to the file too, so the records between two of these are
durable once the second one is."""


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
    because a chain append is microseconds of hashing and one line write.

    :param path: Optional JSON Lines file. An existing file is resumed: its
        records are read and verified before anything is appended, so a
        restarted process continues the chain. A final line left torn by a
        crash mid-append is cut off first; that append never returned, so no
        caller was told the record existed. With no path the chain is in
        memory only and does not survive the process.
    :param fsync: Force records to stable storage. On (the default), every
        ``COMMIT_INTENT`` and every terminal record is fsynced before
        :meth:`append` returns, and with it every record written before it,
        so the write-ahead intent survives a power loss and not just a
        process crash. Off, records are flushed to the OS only.
    :raises ChainInUseError: If another live chain, in this process or
        another, has the file open for appending.
    :raises ChainIntegrityError: If the existing file does not verify.

    One file has one writer. The writer claims ``<path>.lock`` with an
    advisory lock for as long as it is open; :meth:`close` releases it, and so
    does the kernel when the process dies. Read a live chain with
    :meth:`load`, which claims nothing.
    """

    __slots__ = ("_claim", "_closed", "_fsync", "_head", "_lock", "_path", "_read_only", "_records")

    def __init__(self, path: str | Path | None = None, *, fsync: bool = True) -> None:
        self._records: list[EscrowRecord] = []
        self._head = GENESIS_HASH
        self._lock = threading.RLock()
        self._path = Path(path) if path is not None else None
        self._fsync = fsync
        self._read_only = False
        self._closed = False
        self._claim: _FileClaim | None = None
        if self._path is None:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        claim = _FileClaim(self._path)
        claim.acquire()
        try:
            self._resume()
        except BaseException:
            claim.release()
            raise
        self._claim = claim

    def __len__(self) -> int:
        with self._lock:
            return len(self._records)

    def __iter__(self) -> Iterator[EscrowRecord]:
        return iter(self.records())

    def __enter__(self) -> EscrowChain:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    @property
    def head_hash(self) -> str:
        """Hash of the most recent record, or the genesis value."""
        with self._lock:
            return self._head

    @property
    def path(self) -> Path | None:
        """The backing file, or ``None`` for an in-memory chain."""
        return self._path

    @property
    def read_only(self) -> bool:
        """Whether this is a snapshot from :meth:`load`, which cannot append."""
        return self._read_only

    def records(self) -> tuple[EscrowRecord, ...]:
        with self._lock:
            return tuple(self._records)

    def close(self) -> None:
        """Release the claim on the chain file. Idempotent.

        Appending afterwards raises. A no-op for an in-memory chain.
        """
        with self._lock:
            if self._path is None:
                return
            self._closed = True
            claim, self._claim = self._claim, None
        if claim is not None:
            claim.release()

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

        The record is on disk (and, for a synced record type, on stable
        storage) before it is part of the chain in memory, so a failed write
        leaves both exactly as they were.

        :returns: The committed record, carrying its own hash.
        :raises AnchorError: If this chain is a read-only snapshot or closed.
        :raises OSError: If the record cannot be written.
        """
        with self._lock:
            if self._read_only:
                raise AnchorError(
                    f"this chain was read with EscrowChain.load(), which claims nothing and "
                    f"cannot append; open EscrowChain({str(self._path)!r}) to append to it"
                )
            if self._closed:
                raise AnchorError(f"escrow chain {self._path} is closed")
            partial = EscrowRecord(
                sequence=len(self._records) + 1,
                record_id=uuid.uuid4(),
                timestamp=datetime.now(UTC),
                record_type=record_type,
                plan_id=plan_id,
                stage_id=stage_id,
                payload_hash=payload_hash,
                anchored=anchored,
                agentgov_head_hash=agentgov_head_hash,
                agentgov_sequence=agentgov_sequence,
                prev_hash=self._head,
                record_hash="",
                note=note,
            )
            record = _with_hash(partial)
            if self._path is not None:
                self._write(self._path, record)
            self._records.append(record)
            self._head = record.record_hash
            return record

    def _write(self, path: Path, record: EscrowRecord) -> None:
        line = json.dumps(record.to_json(), separators=(",", ":")) + "\n"
        with path.open("ab") as handle:
            start = handle.tell()
            try:
                handle.write(line.encode("utf-8"))
                handle.flush()
                if self._fsync and record.record_type in _SYNCED:
                    os.fsync(handle.fileno())
            except BaseException:
                # Leave no torn line behind for the next append to follow:
                # the file ends where it did, and the record never existed.
                with suppress(OSError):
                    handle.truncate(start)
                raise

    def _resume(self) -> None:
        """Load and verify the existing file; cut off a torn final line."""
        path = self._path
        if path is None:  # pragma: no cover - only called with a path
            return
        if not path.exists():
            path.touch()
            if self._fsync:
                _fsync_directory(path.parent)
            return
        data = path.read_bytes()
        complete, torn = _split_tail(data)
        if torn:
            logger.warning(
                "escrow chain %s ends in a torn record (%d bytes) left by a crash "
                "mid-append; cutting it off. That append never returned, so no "
                "caller was told the record existed",
                path,
                len(torn),
            )
            with path.open("r+b") as handle:
                handle.truncate(len(complete))
                handle.flush()
                os.fsync(handle.fileno())
        self._adopt(_parse(path, complete))

    def _adopt(self, records: list[EscrowRecord]) -> None:
        self._records = records
        self._head = records[-1].record_hash if records else GENESIS_HASH
        self.verify()

    def unresolved_intents(self) -> tuple[EscrowRecord, ...]:
        """Commit intents with no terminal record after them.

        Each one is a plan that was about to commit when the process stopped.
        The effect may or may not be durable; the chain cannot say which, only
        that the question is open for this plan and stage. Resolve it by asking
        the substrate whether the transaction landed.

        :returns: The unresolved ``COMMIT_INTENT`` records, in chain order.
        """
        terminal = _TERMINAL
        resolved: set[uuid.UUID | None] = set()
        intents: dict[uuid.UUID | None, EscrowRecord] = {}
        for record in self.records():
            if record.record_type is RecordType.COMMIT_INTENT:
                intents[record.stage_id] = record
            elif record.record_type in terminal:
                resolved.add(record.stage_id)
        return tuple(
            record
            for stage_id, record in sorted(intents.items(), key=lambda kv: kv[1].sequence)
            if stage_id not in resolved
        )

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
        """Read and verify a chain file, without claiming it.

        Returns a read-only snapshot. It can be verified and queried while a
        live writer keeps appending to the file, and :meth:`append` on it
        raises. A torn final line is a record in flight and is left out, not
        cut off. To resume appending, open ``EscrowChain(path)`` instead.

        Runs :meth:`verify` before returning, so a file whose links or digests
        do not hold raises instead of loading. Does NOT run
        :meth:`verify_anchors`; call that separately if the chain is anchored.

        :raises FileNotFoundError: If there is no file at ``path``.
        :raises ChainIntegrityError: If the file does not verify.
        """
        source = Path(path)
        complete, _ = _split_tail(source.read_bytes())
        chain = cls()
        chain._path = source
        chain._read_only = True
        chain._adopt(_parse(source, complete))
        return chain


def _split_tail(data: bytes) -> tuple[bytes, bytes]:
    """Split a chain file into its complete lines and a torn final line.

    Every append writes a whole line ending in a newline, so bytes after the
    last newline are an append that did not finish.
    """
    cut = data.rfind(b"\n") + 1
    return data[:cut], data[cut:]


def _parse(path: Path, data: bytes) -> list[EscrowRecord]:
    records: list[EscrowRecord] = []
    for number, line in enumerate(data.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            raw = json.loads(line)
            records.append(_from_json(raw))
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            raise ChainIntegrityError(
                f"{path}: line {number} is not an escrow record ({type(exc).__name__}: {exc}); "
                f"the file was edited or corrupted"
            ) from exc
    return records


def _fsync_directory(directory: Path) -> None:
    """Make a newly created file's directory entry durable. Best effort."""
    with suppress(OSError):
        fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


class _FileClaim:
    """An exclusive advisory lock on ``<file>.lock``, held for a writer's life.

    Held by an open file descriptor, so the kernel releases it when the
    holding process exits, ``SIGKILL`` included: a crashed writer leaves a
    stale file, never a stale claim. The holder writes its identity into the
    file so a refused writer can be told who holds it. The escrow chain and
    the signed record log (:mod:`interlock.records`) both claim their files
    this way.
    """

    __slots__ = ("_chain", "_fd", "_hint", "_label", "_path")

    def __init__(
        self,
        chain_path: Path,
        *,
        label: str = "escrow chain",
        hint: str = "Close the other EscrowChain, or read this one with EscrowChain.load()",
    ) -> None:
        self._chain = chain_path
        self._path = chain_path.with_name(chain_path.name + ".lock")
        self._fd: int | None = None
        self._label = label
        self._hint = hint

    def acquire(self) -> None:
        try:
            fd = os.open(self._path, os.O_RDWR | os.O_CREAT, 0o644)
        except OSError as exc:
            raise AnchorError(f"cannot create {self._path}: {exc}") from exc
        try:
            _lock_exclusive_nonblocking(fd)
        except BlockingIOError as exc:
            holder = _read_holder(fd)
            os.close(fd)
            raise ChainInUseError(
                f"{self._label} {self._chain} is already open for appending{holder}. "
                f"One {self._label} file has one writer: a second would fork it. {self._hint}"
            ) from exc
        except OSError as exc:
            os.close(fd)
            raise AnchorError(
                f"cannot lock {self._path}: {exc}. This filesystem may not support "
                f"advisory locking; keep the chain on local storage"
            ) from exc
        self._fd = fd
        identity = json.dumps(
            {
                "pid": os.getpid(),
                "host": socket.gethostname(),
                "since": datetime.now(UTC).isoformat(timespec="seconds"),
            }
        )
        with suppress(OSError):
            os.ftruncate(fd, 0)
            os.pwrite(fd, identity.encode("utf-8"), 0)

    def release(self) -> None:
        fd, self._fd = self._fd, None
        if fd is None:
            return
        with suppress(OSError):
            _unlock(fd)
        with suppress(OSError):
            os.close(fd)

    def __del__(self) -> None:
        self.release()


def _read_holder(fd: int) -> str:
    """`` (held by pid N on host H since T)``, or ``""``. Never raises."""
    try:
        record = json.loads(os.pread(fd, 4096, 0).decode("utf-8"))
        return f" (held by pid {record['pid']} on {record['host']} since {record['since']})"
    except (OSError, ValueError, TypeError, KeyError):
        return ""


if sys.platform == "win32":  # pragma: no cover - not exercised in CI

    def _lock_exclusive_nonblocking(fd: int) -> None:
        import msvcrt

        try:
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        except OSError as exc:
            raise BlockingIOError(str(exc)) from exc

    def _unlock(fd: int) -> None:
        import msvcrt

        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)

else:

    def _lock_exclusive_nonblocking(fd: int) -> None:
        import fcntl

        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def _unlock(fd: int) -> None:
        import fcntl

        fcntl.flock(fd, fcntl.LOCK_UN)


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
