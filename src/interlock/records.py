"""ILOK1: signed, hash-chained records of what the runtime itself did.

An ARC1 receipt (agentgov) records an action against a system of record: a
plan, what it measurably did, and what was decided about it. The runtime's own
acts are a different kind of thing: a recovery step that revoked a tool, what
that step cost, the reserve it ran on. ARC1's log takes only action receipts,
so these go in a log of their own, built from the same parts: agentgov's
canonical JSON (RFC 8785 over a float-free value domain), its signers, and a
signing input that starts with a domain prefix, so a signature over one of
these can never be replayed as an ARC1 signature, or the reverse.

A record, as written (one per line)::

    {"v": "ILOK1", "log": "support", "seq": 3, "kind": "recovery.step",
     "issued_at": "2026-09-26T02:14:00.123456Z", "scope": "support-agent",
     "body": {...}, "prev": "<sha256 of record 2>",
     "sig": {"alg": "hmac-sha256", "key_id": "...", "signature": "<hex>"}}

- The signature covers ``ILOK1/record/v1\\n`` followed by the canonical bytes
  of the record with ``sig`` reduced to its ``alg`` and ``key_id``.
- A record's hash is SHA-256 over the canonical bytes of the whole record,
  signature included. The next record's ``prev`` is that hash; the first
  record's is 64 zeros.
- Money is a decimal string at the ledger's eight places, so every verifier
  reads one number, the one the ledger holds.

A record names what it binds to: ledger entries and holds by id, ARC1
receipts by id, earlier records by sequence and hash. The runtime also anchors
every record into the AgentGov ledger, as a zero-value ``ANCHOR`` entry whose
memo is ``ILOK1 <log> <seq> <hash>``. The ledger is hash-chained and verified
on its own, so a log cut short or rewritten after the fact disagrees with it:
see :func:`check_anchors`.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import logging
import os
import re
import threading
from collections.abc import Iterable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from enum import StrEnum
from pathlib import Path
from types import TracebackType
from typing import Any, Final

from agentgov.core import QUANTUM, EntryType, LedgerEntry
from agentgov.exceptions import MalformedReceiptError
from agentgov.receipts import canonical_bytes, loads_strict
from agentgov.receipts.signing import Signer, Verifier

from interlock.chain import _FileClaim, _fsync_directory, _split_tail
from interlock.exceptions import AnchorError, RecordIntegrityError

__all__ = [
    "ANCHOR_PREFIX",
    "GENESIS",
    "RECORD_DOMAIN",
    "RECORD_VERSION",
    "RecordKind",
    "RecordLog",
    "SignedRecord",
    "anchor_memo",
    "check_anchors",
    "money",
    "verify_records",
]

logger = logging.getLogger("interlock.records")

RECORD_VERSION: Final = "ILOK1"
RECORD_DOMAIN: Final = b"ILOK1/record/v1\n"
"""Prefix on every signing input. ARC1 signs under ``ARC1/...`` prefixes, so
the two formats' signatures cannot stand in for each other."""

GENESIS: Final = "0" * 64
"""The ``prev`` of a log's first record."""

ANCHOR_PREFIX: Final = "ILOK1 "
"""How an AgentGov ``ANCHOR`` memo naming one of these records begins."""

_LOG_ID = re.compile(r"[A-Za-z0-9._:@/-]{1,64}")
_KEY_ID = re.compile(r"[0-9a-f]{16}")
_HASH = re.compile(r"[0-9a-f]{64}")
_FIELDS = frozenset({"v", "log", "seq", "kind", "issued_at", "scope", "body", "prev", "sig"})
_SIGNATURE_BYTES = {"hmac-sha256": 32, "ed25519": 64}


class RecordKind(StrEnum):
    """What a record attests."""

    RECOVERY_OPENED = "recovery.opened"
    """A recovery scope was funded (or an existing one adopted) under a policy."""

    RECOVERY_STEP = "recovery.step"
    """One rung of the ladder applied to one halt, with the hold that pays for
    the model call it enables. Written before the call is made."""

    RECOVERY_SETTLED = "recovery.settled"
    """What that call actually cost."""

    RECOVERY_CLOSED = "recovery.closed"
    """The recovery ended; unused reserve returned."""


def money(amount: Decimal | int | str) -> str:
    """A decimal amount as ILOK1 writes it: a plain decimal string at the
    ledger's precision (AgentGov's ``QUANTUM``, eight places), so a record
    and the ledger entry it names write one number one way."""
    return format(Decimal(str(amount)).quantize(QUANTUM), "f")


@dataclass(frozen=True, slots=True)
class SignedRecord:
    """One signed record. Immutable; the body is kept as its canonical bytes.

    :ivar seq: Position in the log, from 1.
    :ivar kind: A :class:`RecordKind` value.
    :ivar issued_at: When it was signed, as written: ISO 8601, UTC, ``Z``.
    :ivar scope: The AgentGov scope the record is about.
    :ivar prev: The previous record's hash, or :data:`GENESIS`.
    """

    log: str
    seq: int
    kind: str
    issued_at: str
    scope: str
    body_json: bytes
    prev: str
    alg: str
    key_id: str
    signature: bytes

    @property
    def body(self) -> dict[str, Any]:
        """A fresh copy of the body."""
        value = loads_strict(self.body_json)
        if not isinstance(value, dict):  # pragma: no cover - guarded at construction
            raise RecordIntegrityError(f"record {self.seq}: the body is not an object")
        return value

    def _unsigned(self) -> dict[str, Any]:
        return {
            "v": RECORD_VERSION,
            "log": self.log,
            "seq": self.seq,
            "kind": self.kind,
            "issued_at": self.issued_at,
            "scope": self.scope,
            "body": self.body,
            "prev": self.prev,
        }

    def signing_input(self) -> bytes:
        """The exact bytes the signature covers."""
        return RECORD_DOMAIN + canonical_bytes(
            {**self._unsigned(), "sig": {"alg": self.alg, "key_id": self.key_id}}
        )

    def to_json(self) -> dict[str, Any]:
        return {
            **self._unsigned(),
            "sig": {"alg": self.alg, "key_id": self.key_id, "signature": self.signature.hex()},
        }

    @property
    def record_hash(self) -> str:
        """SHA-256 over the canonical bytes of the whole signed record."""
        return hashlib.sha256(canonical_bytes(self.to_json())).hexdigest()

    def verify(self, verifier: Verifier) -> None:
        """Check the signature under ``verifier``.

        :raises RecordIntegrityError: If it was signed with another algorithm
            or key, or does not verify.
        """
        if self.alg != verifier.alg:
            raise RecordIntegrityError(
                f"record {self.seq} claims an {self.alg} signature but the key given is "
                f"{verifier.alg}; a verifier never switches algorithm on the record's say-so"
            )
        if self.key_id != verifier.key_id:
            raise RecordIntegrityError(
                f"record {self.seq} was signed by key {self.key_id}, not by the key given "
                f"({verifier.key_id})"
            )
        if not verifier.verify(self.signing_input(), self.signature):
            raise RecordIntegrityError(
                f"record {self.seq}'s signature does not verify under key {verifier.key_id}: "
                f"it was altered after signing"
            )

    @classmethod
    def from_json(cls, raw: object) -> SignedRecord:
        """Read a record, strictly: every field present, nothing extra.

        :raises RecordIntegrityError: If ``raw`` is not an ILOK1 record.
        """
        if not isinstance(raw, dict) or set(raw) != _FIELDS:
            found = sorted(raw) if isinstance(raw, dict) else type(raw).__name__
            raise RecordIntegrityError(f"not an ILOK1 record: fields {found}")
        sig = raw["sig"]
        if not isinstance(sig, dict) or set(sig) != {"alg", "key_id", "signature"}:
            raise RecordIntegrityError("an ILOK1 record's sig is {alg, key_id, signature}")
        alg, key_id, signature = sig["alg"], sig["key_id"], sig["signature"]
        checks = (
            (raw["v"] == RECORD_VERSION, f"v must be {RECORD_VERSION!r}"),
            (isinstance(raw["log"], str) and _LOG_ID.fullmatch(raw["log"]), "log is malformed"),
            (_positive_int(raw["seq"]), "seq must be a positive integer"),
            (isinstance(raw["kind"], str) and raw["kind"], "kind must be a string"),
            (isinstance(raw["issued_at"], str), "issued_at must be a string"),
            (isinstance(raw["scope"], str) and raw["scope"], "scope must be a string"),
            (isinstance(raw["body"], dict), "body must be an object"),
            (isinstance(raw["prev"], str) and _HASH.fullmatch(raw["prev"]), "prev is malformed"),
            (alg in _SIGNATURE_BYTES, "sig.alg is unknown"),
            (isinstance(key_id, str) and _KEY_ID.fullmatch(key_id), "sig.key_id is malformed"),
            (isinstance(signature, str) and _is_hex(signature), "sig.signature is not hex"),
        )
        for ok, problem in checks:
            if not ok:
                raise RecordIntegrityError(f"not an ILOK1 record: {problem}")
        value = bytes.fromhex(signature)
        if len(value) != _SIGNATURE_BYTES[alg]:
            raise RecordIntegrityError(
                f"record {raw['seq']}: an {alg} signature is {_SIGNATURE_BYTES[alg]} bytes"
            )
        try:
            body_json = canonical_bytes(raw["body"])
        except MalformedReceiptError as exc:
            raise RecordIntegrityError(f"record {raw['seq']}: {exc}") from exc
        return cls(
            log=raw["log"],
            seq=raw["seq"],
            kind=raw["kind"],
            issued_at=raw["issued_at"],
            scope=raw["scope"],
            body_json=body_json,
            prev=raw["prev"],
            alg=alg,
            key_id=key_id,
            signature=value,
        )


def verify_records(records: Sequence[SignedRecord], verifier: Verifier) -> None:
    """Check a log from its first record: sequence, links and signatures.

    A log verified alone can still have lost its tail. Check it against the
    ledger's anchors with :func:`check_anchors` for that.

    :raises RecordIntegrityError: On the first record that does not hold.
    """
    previous = GENESIS
    log: str | None = None
    for index, record in enumerate(records, start=1):
        if record.seq != index:
            raise RecordIntegrityError(
                f"record {index} carries sequence {record.seq}; the log has a gap"
            )
        if log is not None and record.log != log:
            raise RecordIntegrityError(
                f"record {index} belongs to log {record.log!r}, not {log!r}: two logs were spliced"
            )
        log = record.log
        if record.prev != previous:
            raise RecordIntegrityError(
                f"record {index} links to {record.prev[:16]}, expected {previous[:16]}: "
                f"the log was re-linked"
            )
        record.verify(verifier)
        previous = record.record_hash


def anchor_memo(record: SignedRecord) -> str:
    """The AgentGov ``ANCHOR`` memo that commits the ledger to ``record``."""
    return f"{ANCHOR_PREFIX}{record.log} {record.seq} {record.record_hash}"


def check_anchors(records: Sequence[SignedRecord], entries: Iterable[LedgerEntry]) -> int:
    """Check a log against every anchor the ledger holds for it.

    Each ``ANCHOR`` entry whose memo names this log must name a record the log
    holds, with the same hash. A log truncated after its records were anchored,
    or rewritten, fails here even though it verifies on its own.

    :param entries: The ledger's entries, e.g. ``manager.audit_trail()``.
    :returns: How many anchors were checked.
    :raises RecordIntegrityError: If an anchor names a record the log lacks,
        or holds with another hash.
    """
    if not records:
        return 0
    log = records[0].log
    by_seq = {record.seq: record for record in records}
    checked = 0
    for entry in entries:
        if entry.entry_type is not EntryType.ANCHOR:
            continue
        parts = entry.memo.split(" ")
        if len(parts) != 4 or f"{parts[0]} " != ANCHOR_PREFIX or parts[1] != log:
            continue
        seq, digest = parts[2], parts[3]
        record = by_seq.get(int(seq)) if seq.isdigit() else None
        if record is None:
            raise RecordIntegrityError(
                f"the ledger anchors record {seq} of log {log!r} (entry {entry.sequence}), "
                f"which the log does not hold: it was truncated"
            )
        if record.record_hash != digest:
            raise RecordIntegrityError(
                f"the ledger anchors record {seq} of log {log!r} as {digest[:16]}, but the "
                f"log holds {record.record_hash[:16]}: it was rewritten"
            )
        checked += 1
    return checked


class RecordLog:
    """An append-only, signed, hash-chained log of :class:`SignedRecord`.

    Thread-safe. With a path, every record is written and fsynced before
    :meth:`append` returns, and an existing file is resumed: read, and
    verified under the signer, before anything is appended. One file has one
    writer, claimed with ``<path>.lock`` as the escrow chain claims its file.

    :param signer: Signs every record. An HMAC key verifies only for someone
        who holds it; give third parties an Ed25519 key's public half.
    :param log_id: Names this log in every record and every ledger anchor.
        Logs that share a ledger must not share an id.
    :param path: Optional JSON Lines file.
    :raises ChainInUseError: If another live log has the file open.
    :raises RecordIntegrityError: If the existing file does not verify.
    """

    __slots__ = ("_claim", "_closed", "_head", "_lock", "_log_id", "_path", "_records", "_signer")

    def __init__(
        self, signer: Signer, *, log_id: str = "interlock", path: str | Path | None = None
    ) -> None:
        if not _LOG_ID.fullmatch(log_id):
            raise ValueError(f"a log id is 1-64 characters of [A-Za-z0-9._:@/-], got {log_id!r}")
        self._signer = signer
        self._log_id = log_id
        self._records: list[SignedRecord] = []
        self._head = GENESIS
        self._lock = threading.RLock()
        self._closed = False
        self._path = Path(path) if path is not None else None
        self._claim: _FileClaim | None = None
        if self._path is None:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        claim = _FileClaim(
            self._path, label="record log", hint="Close the other RecordLog, or read this one"
        )
        claim.acquire()
        try:
            self._resume(self._path)
        except BaseException:
            claim.release()
            raise
        self._claim = claim

    @property
    def log_id(self) -> str:
        return self._log_id

    @property
    def path(self) -> Path | None:
        return self._path

    @property
    def head(self) -> str:
        """The latest record's hash, or :data:`GENESIS`."""
        with self._lock:
            return self._head

    @property
    def signer(self) -> Signer:
        return self._signer

    def __len__(self) -> int:
        with self._lock:
            return len(self._records)

    def records(self) -> tuple[SignedRecord, ...]:
        with self._lock:
            return tuple(self._records)

    def append(self, kind: RecordKind, *, scope: str, body: Mapping[str, Any]) -> SignedRecord:
        """Sign ``body`` as the next record and write it.

        :raises ValueError: If ``body`` has anything canonical JSON cannot
            carry exactly, such as a float.
        :raises AnchorError: If the log is closed.
        :raises OSError: If the record cannot be written; the log is then
            unchanged.
        """
        try:
            body_json = canonical_bytes(dict(body))
        except MalformedReceiptError as exc:
            raise ValueError(f"a record body must be canonical JSON: {exc}") from exc
        with self._lock:
            if self._closed:
                raise AnchorError(f"record log {self._log_id!r} is closed")
            unsigned = SignedRecord(
                log=self._log_id,
                seq=len(self._records) + 1,
                kind=kind.value,
                issued_at=datetime.now(UTC)
                .isoformat(timespec="microseconds")
                .replace("+00:00", "Z"),
                scope=scope,
                body_json=body_json,
                prev=self._head,
                alg=self._signer.alg,
                key_id=self._signer.key_id,
                signature=b"",
            )
            record = dataclasses.replace(
                unsigned, signature=self._signer.sign(unsigned.signing_input())
            )
            if self._path is not None:
                self._write(self._path, record)
            self._records.append(record)
            self._head = record.record_hash
            return record

    def verify(self, verifier: Verifier | None = None) -> None:
        """Verify the whole log, under the signer unless another key is given.

        :raises RecordIntegrityError: On the first record that does not hold.
        """
        verify_records(self.records(), verifier if verifier is not None else self._signer)

    @staticmethod
    def load(path: str | Path, verifier: Verifier) -> tuple[SignedRecord, ...]:
        """Read and verify a log file without claiming it.

        A torn final line is a record in flight and is left out, not cut off.

        :raises FileNotFoundError: If there is no file at ``path``.
        :raises RecordIntegrityError: If the file does not verify.
        """
        source = Path(path)
        complete, _ = _split_tail(source.read_bytes())
        records = _parse(source, complete)
        verify_records(records, verifier)
        return tuple(records)

    def close(self) -> None:
        """Release the claim on the file. Idempotent; appending afterwards raises."""
        with self._lock:
            self._closed = True
            claim, self._claim = self._claim, None
        if claim is not None:
            claim.release()

    def __enter__(self) -> RecordLog:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def _write(self, path: Path, record: SignedRecord) -> None:
        line = json.dumps(record.to_json(), sort_keys=True, separators=(",", ":")) + "\n"
        with path.open("ab") as handle:
            start = handle.tell()
            try:
                handle.write(line.encode("utf-8"))
                handle.flush()
                os.fsync(handle.fileno())
            except BaseException:
                with suppress(OSError):
                    handle.truncate(start)
                raise

    def _resume(self, path: Path) -> None:
        if not path.exists():
            path.touch()
            _fsync_directory(path.parent)
            return
        complete, torn = _split_tail(path.read_bytes())
        if torn:
            logger.warning(
                "record log %s ends in a torn record (%d bytes) left by a crash mid-append; "
                "cutting it off. That append never returned, so no caller was told the "
                "record existed",
                path,
                len(torn),
            )
            with path.open("r+b") as handle:
                handle.truncate(len(complete))
                handle.flush()
                os.fsync(handle.fileno())
        records = _parse(path, complete)
        verify_records(records, self._signer)
        if records and records[0].log != self._log_id:
            raise RecordIntegrityError(f"{path} holds log {records[0].log!r}, not {self._log_id!r}")
        self._records = records
        self._head = records[-1].record_hash if records else GENESIS


def _parse(path: Path, data: bytes) -> list[SignedRecord]:
    records: list[SignedRecord] = []
    for number, line in enumerate(data.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            records.append(SignedRecord.from_json(loads_strict(line)))
        except (MalformedReceiptError, RecordIntegrityError) as exc:
            raise RecordIntegrityError(f"{path}: line {number}: {exc}") from exc
    return records


def _positive_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 1


def _is_hex(value: str) -> bool:
    return len(value) % 2 == 0 and all(c in "0123456789abcdef" for c in value)
