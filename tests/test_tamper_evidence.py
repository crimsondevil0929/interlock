"""Tamper evidence: alter the audit trail, and it fails exactly where it was altered.

One realistic history is built on the back office: seven adjudicated plans,
refused and committed, a repair among them, each with its signed ARC1 receipt
in a durable receipt log whose checkpoints a witness cosigned, each settled
and reverse-anchored in a governed AgentGov ledger. Every test tampers with a
copy of it the way someone who can write the files would (and, where a test
says so, someone who also holds the issuer's key), then asserts that
verification fails at exactly the check, the receipt, the row or the line
that was touched, with every check before it still passing.

- **Row data.** A disclosed row, in any part (exit 8, naming the row). The
  receipt's row commitment itself, by a forger holding more and more keys:
  the signature fails, then the inclusion proof, then the witness, and the
  witness will not cosign the forgery. A committed row changed in the
  database afterwards (reconcile-effects names the row; the receipt still
  proves what was committed).
- **Checkpoints.** One deleted is re-derived identically, so deleting it hides
  nothing. Deleted to cover a rewrite or a rollback, the log file alone
  cannot tell, and the witness refuses both. A receipt deleted under them
  stops the log at the next line.
- **Signatures.** Forged on a receipt (exit 4), on a checkpoint (exit 5, and
  the log refuses to resume at that line), on a witness cosignature (it
  vouches for nothing, and cannot frame the log either).
- **Links.** An altered inclusion proof (exit 5). A settled cost rewritten
  (exit 7). A rewritten escrow chain, which is keyless and verifies alone,
  against the signed receipts and the ledger anchors that name it.
"""

from __future__ import annotations

import dataclasses
import json
import re
import secrets
import shutil
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from io import StringIO
from pathlib import Path

import pytest
from agentgov import BudgetManager
from agentgov.cli import main as agentgov
from agentgov.core import EntryType
from agentgov.exceptions import ReceiptLogError, WitnessError
from agentgov.receipts import (
    ActionReceipt,
    Checkpoint,
    CheckpointPolicy,
    Cosignature,
    Failure,
    FileWitness,
    HmacKey,
    InclusionProof,
    MerkleTree,
    ReceiptBundle,
    ReceiptLog,
    RowChange,
    RowCommitment,
    RowDisclosure,
    VerificationReport,
    canonical_bytes,
    commit_rows,
    load_cosignatures,
    loads_strict,
    verify_bundle,
)
from agentgov.receipts.schema import DisclosedRow, Signature

from interlock import EscrowChain, LedgerAnchor, PlanBuilder, ReceiptIssuer, StageResult
from interlock.chain import EscrowRecord, RecordType
from interlock.reconcile import install_sqlite_journal, reconcile_postgres, reconcile_sqlite
from interlock.types import EffectDiff, EffectPlan
from tests.conftest import Pg, build_sqlite_back_office
from tests.crash_child import Refund
from tests.plans import pg_engine, sqlite_engine, support_batch, transfer
from tests.schemas import specs

LOG_ID = "audit-receipts"
WITNESS_ID = "audit-witness"
JOURNALED = ("orders", "order_items", "refunds", "shipments", "accounts")
OUTCOMES = ["refused", "refused", "committed", "committed", "committed", "refused", "committed"]
REFUND = 4
"""The refund's receipt: three rows in three tables, the last change to
account 100."""

# --------------------------------------------------------------------------
# the history
# --------------------------------------------------------------------------


def acme_transfer() -> EffectPlan:
    return (
        PlanBuilder("support-agent", intent="move 50 between acme's accounts")
        .update(
            table="accounts",
            statement="UPDATE accounts SET balance = balance - 50 WHERE id = 100",
            tenant_id="acme",
            stated_rows=1,
            independent=True,
        )
        .update(
            table="accounts",
            statement="UPDATE accounts SET balance = balance + 50 WHERE id = 101",
            tenant_id="acme",
            stated_rows=1,
            independent=True,
        )
        .build()
    )


def refund() -> EffectPlan:
    return (
        PlanBuilder("support-agent", intent="refund order item 5000")
        .insert(
            table="refunds",
            statement="INSERT INTO refunds (id, order_item_id, amount) VALUES (:id, 5000, :a)",
            parameters={"id": 9100, "a": "3.00"},
            stated_rows=1,
        )
        .update(
            table="accounts",
            statement="UPDATE accounts SET balance = balance + :a WHERE id = 100",
            parameters={"a": "3.00"},
            tenant_id="acme",
            stated_rows=1,
        )
        .update(
            table="order_items",
            statement="UPDATE order_items SET qty = qty + 1 WHERE id = 5000",
            stated_rows=1,
        )
        .build()
    )


def reprice() -> EffectPlan:
    return (
        PlanBuilder("support-agent", intent="reprice order 501")
        .update(
            table="orders",
            statement="UPDATE orders SET total = 42 WHERE id = 501",
            tenant_id="acme",
            stated_rows=1,
        )
        .build()
    )


@dataclass(frozen=True)
class Entry:
    """One receipt, and the measured diff its rows were committed from."""

    receipt: ActionReceipt
    diff: EffectDiff


@dataclass(frozen=True)
class History:
    root: Path
    issuer_key: bytes
    witness_key: bytes
    row_secret: bytes
    entries: tuple[Entry, ...]

    @property
    def receipts(self) -> Path:
        return self.root / "receipts.jsonl"

    @property
    def checkpoints(self) -> Path:
        return self.root / "receipts.jsonl.checkpoints"

    @property
    def witness_file(self) -> Path:
        return self.root / "witness.jsonl"

    @property
    def chain(self) -> Path:
        return self.root / "escrow.jsonl"

    @property
    def ledger(self) -> Path:
        return self.root / "governor.db"

    @property
    def database(self) -> Path:
        return self.root / "back_office.db"

    @property
    def key(self) -> HmacKey:
        return HmacKey(self.issuer_key)

    @property
    def witness_verifier(self) -> HmacKey:
        return HmacKey(self.witness_key)

    def copy(self, into: Path) -> History:
        shutil.copytree(self.root, into)
        return dataclasses.replace(self, root=into)

    def witness(self) -> FileWitness:
        return FileWitness(
            self.witness_file,
            self.witness_verifier,
            witness_id=WITNESS_ID,
            logs={LOG_ID: self.key},
        )

    def log(self) -> ReceiptLog:
        return ReceiptLog(LOG_ID, self.key, path=self.receipts, witnesses=[self.witness()])

    def bundle(self, index: int) -> ReceiptBundle:
        with self.log() as log:
            return log.bundle(index)

    def verify(
        self,
        bundle: ReceiptBundle | bytes,
        *,
        rows: RowDisclosure | None = None,
        witnessed: bool = True,
    ) -> VerificationReport:
        """Every check the auditor has the means for: the issuer's key, the
        witness's cosignatures and key, the ledger, and the rows if given."""
        ledger = BudgetManager.open_sqlite(str(self.ledger), read_only=True)
        try:
            return verify_bundle(
                bundle,
                issuer_key=self.key,
                cosignatures=load_cosignatures(self.witness_file) if witnessed else None,
                witness_key=self.witness_verifier if witnessed else None,
                ledger=ledger,
                rows=rows,
            )
        finally:
            ledger.close()

    def commitment(self, index: int) -> RowCommitment:
        """The row commitment an auditor rebuilds from the measured rows and
        the issuer's row secret. It must be the one the receipt carries."""
        entry = self.entries[index]
        commitment = commit_rows(
            [
                RowChange.from_values(
                    d.table, d.primary_key, before=d.before, after=d.after, tenant=d.tenant_id
                )
                for d in entry.diff.deltas
            ],
            secret=self.row_secret,
        )
        assert commitment.root == entry.receipt.effect.row_root
        assert commitment.count == entry.receipt.effect.row_count
        return commitment

    def disclosure(self, index: int) -> RowDisclosure:
        commitment = self.commitment(index)
        return commitment.disclose(
            range(commitment.count), receipt_id=self.entries[index].receipt.receipt_id
        )

    def receipt_lines(self) -> list[bytes]:
        return self.receipts.read_bytes().splitlines(keepends=True)


def build_history(root: Path) -> History:
    """Seven plans through a fully wired engine, and every file they leave."""
    root.mkdir(parents=True, exist_ok=True)
    database = build_sqlite_back_office(root / "back_office.db")
    install_sqlite_journal(database, specs(*JOURNALED))
    issuer_key, witness_key, row_secret = (secrets.token_bytes(32) for _ in range(3))
    governor = BudgetManager.open_sqlite(str(root / "governor.db"))
    governor.open_root("support-agent", "100")
    governor.open_root("treasury-agent", "100")
    key = HmacKey(issuer_key)
    witness = FileWitness(
        root / "witness.jsonl", HmacKey(witness_key), witness_id=WITNESS_ID, logs={LOG_ID: key}
    )
    log = ReceiptLog(
        LOG_ID,
        key,
        path=root / "receipts.jsonl",
        witnesses=[witness],
        policy=CheckpointPolicy(every_receipts=2),
    )
    chain = EscrowChain(root / "escrow.jsonl")
    engine = sqlite_engine(
        database,
        chain=chain,
        anchor=LedgerAnchor(governed=governor),
        settle_cost="0.25",
        receipts=ReceiptIssuer(log, row_secret=row_secret),
    )
    entries: list[Entry] = []

    def keep(result: StageResult) -> StageResult:
        assert result.receipt is not None and result.diff is not None
        entries.append(Entry(result.receipt, result.diff))
        return result

    batch = support_batch()
    keep(engine.execute(batch))
    repair = engine.repair(batch)
    assert repair.receipt is not None and repair.whole is not None
    assert repair.proposal is not None
    entries.append(Entry(repair.receipt, repair.whole.diff))
    keep(engine.execute(repair.proposal))
    keep(engine.execute(acme_transfer()))
    keep(engine.execute(refund()))
    keep(engine.execute(transfer()))
    keep(engine.execute(reprice()))
    log.publish()
    log.close()
    chain.close()
    governor.close()
    assert [e.receipt.outcome.status.value for e in entries] == OUTCOMES
    assert entries[2].receipt.decision.repair_of == entries[1].receipt.receipt_id
    return History(root, issuer_key, witness_key, row_secret, tuple(entries))


@pytest.fixture(scope="module")
def pristine(tmp_path_factory: pytest.TempPathFactory) -> History:
    return build_history(tmp_path_factory.mktemp("history") / "files")


@pytest.fixture
def history(pristine: History, tmp_path: Path) -> History:
    """A copy of the history, this test's to tamper with."""
    return pristine.copy(tmp_path / "history")


def failed_at(
    report: VerificationReport,
    check: str,
    failure: Failure,
    detail: str,
    *,
    skipped: tuple[str, ...] = (),
) -> None:
    """The report's first failure is ``check``, for ``failure``, saying
    ``detail``; every check before it passed, but those the auditor had no
    means for (``skipped``)."""
    first = report.first_failure
    assert first is not None, report.to_json()
    assert (first.name, first.failure) == (check, failure), report.to_json()
    assert re.search(detail, first.detail), first.detail
    assert report.exit_code == int(failure)
    names = [c.name for c in report.checks]
    earlier = {c.name: c.status for c in report.checks[: names.index(check)]}
    assert earlier == {name: "skip" if name in skipped else "pass" for name in earlier}, (
        report.to_json()
    )


def test_the_untampered_history_verifies_in_full(history: History) -> None:
    """The baseline every other test departs from: all seven receipts pass
    every check, the refund's disclosed rows included, and the logs, the
    witness, the chain and the ledger all reopen and verify."""
    for index in range(len(history.entries)):
        rows = history.disclosure(index) if index == REFUND else None
        report = history.verify(history.bundle(index), rows=rows)
        assert report.passed, report.to_json()
        assert [c.status for c in report.checks] == ["pass"] * 5 + ["pass" if rows else "skip"]
    with history.log() as log:
        assert [c.tree_size for c in log.checkpoints()] == [2, 4, 6, 7]
    assert [c.tree_size for c in load_cosignatures(history.witness_file)] == [2, 4, 6, 7]
    EscrowChain.load(history.chain).verify()
    reopened = BudgetManager.open_sqlite(str(history.ledger), read_only=True)
    reopened.verify_integrity()
    reopened.close()
    assert reconcile_sqlite(
        str(history.database), specs(*JOURNALED), EscrowChain.load(history.chain).records()
    ).clean


# --------------------------------------------------------------------------
# row data
# --------------------------------------------------------------------------


def _row(disclosure: RowDisclosure, table: str) -> DisclosedRow:
    return next(r for r in disclosure.rows if r.row.table == table)


def _swap_row(disclosure: RowDisclosure, old: DisclosedRow, new: DisclosedRow) -> RowDisclosure:
    rows = tuple(new if r is old else r for r in disclosure.rows)
    return dataclasses.replace(disclosure, rows=rows)


def _edit_row(change: Callable[[RowChange], RowChange]) -> Callable[[RowDisclosure], RowDisclosure]:
    def tamper(disclosure: RowDisclosure) -> RowDisclosure:
        row = _row(disclosure, "accounts")
        return _swap_row(disclosure, row, dataclasses.replace(row, row=change(row.row)))

    return tamper


def _edit_disclosed(
    change: Callable[[DisclosedRow], DisclosedRow],
) -> Callable[[RowDisclosure], RowDisclosure]:
    def tamper(disclosure: RowDisclosure) -> RowDisclosure:
        row = _row(disclosure, "accounts")
        return _swap_row(disclosure, row, change(row))

    return tamper


def _flip(hex_value: str) -> str:
    return ("0" if hex_value[0] != "0" else "1") + hex_value[1:]


def _salt_of_another(disclosure: RowDisclosure) -> RowDisclosure:
    row = _row(disclosure, "accounts")
    other = next(r for r in disclosure.rows if r is not row)
    return _swap_row(disclosure, row, dataclasses.replace(row, salt=other.salt))


def _moved(disclosure: RowDisclosure) -> RowDisclosure:
    row = _row(disclosure, "accounts")
    other = next(r for r in disclosure.rows if r is not row)
    return _swap_row(disclosure, row, dataclasses.replace(row, index=other.index))


def _twice(disclosure: RowDisclosure) -> RowDisclosure:
    row = _row(disclosure, "accounts")
    return dataclasses.replace(disclosure, rows=(*disclosure.rows, row))


ACCOUNT_ROW = r"row (\d) \(accounts 100\) is not the row the receipt committed to"

ROW_TAMPERING: dict[str, tuple[Callable[[RowDisclosure], RowDisclosure], str]] = {
    "a value in the after-image": (
        _edit_row(lambda r: dataclasses.replace(r, after={**(r.after or {}), "balance": "9999"})),
        ACCOUNT_ROW,
    ),
    "a value in the before-image": (
        _edit_row(lambda r: dataclasses.replace(r, before={**(r.before or {}), "balance": "0"})),
        ACCOUNT_ROW,
    ),
    "the tenant": (_edit_row(lambda r: dataclasses.replace(r, tenant="globex")), ACCOUNT_ROW),
    "the operation": (
        _edit_row(lambda r: dataclasses.replace(r, op="insert", before=None)),
        ACCOUNT_ROW,
    ),
    "the primary key": (
        _edit_row(lambda r: dataclasses.replace(r, pk="101")),
        r"row \d \(accounts 101\) is not the row the receipt committed to",
    ),
    "the salt, for another row's": (_salt_of_another, ACCOUNT_ROW),
    "the position": (_moved, r"row \d \(accounts 100\) is not the row"),
    "a node of the audit path": (
        _edit_disclosed(lambda r: dataclasses.replace(r, audit_path=(_flip(r.audit_path[0]),))),
        ACCOUNT_ROW,
    ),
    "the audit path, cut short": (
        _edit_disclosed(lambda r: dataclasses.replace(r, audit_path=r.audit_path[:-1])),
        ACCOUNT_ROW,
    ),
    "one row disclosed twice": (_twice, r"row \d is disclosed twice"),
    "the commitment's size": (
        lambda d: dataclasses.replace(d, row_count=d.row_count - 1),
        r"the disclosure is against a commitment of 2 rows",
    ),
    "the receipt it belongs to": (
        lambda d: dataclasses.replace(d, receipt_id="00000000-0000-4000-8000-000000000000"),
        r"the disclosure is for receipt 00000000-0000-4000-8000-000000000000, not",
    ),
}


@pytest.mark.parametrize("what", list(ROW_TAMPERING))
def test_any_change_to_a_disclosed_row_fails_the_row_check(history: History, what: str) -> None:
    tamper, detail = ROW_TAMPERING[what]
    genuine = history.disclosure(REFUND)
    assert history.verify(history.bundle(REFUND), rows=genuine).passed
    report = history.verify(history.bundle(REFUND), rows=tamper(genuine))
    failed_at(report, "disclosed rows", Failure.ROWS, detail)


def test_the_auditors_command_line_exits_with_the_row_failure(
    history: History, tmp_path: Path
) -> None:
    """``agentgov verify-receipt``, as a CI step would run it: 0 on the
    genuine rows, 8 on an altered one."""
    bundle = tmp_path / "bundle.json"
    bundle.write_bytes(canonical_bytes(history.bundle(REFUND).to_json()))
    genuine = history.disclosure(REFUND)
    altered = ROW_TAMPERING["a value in the after-image"][0](genuine)
    codes = []
    for disclosure in (genuine, altered):
        rows = tmp_path / "rows.json"
        rows.write_bytes(canonical_bytes(disclosure.to_json()))
        out = StringIO()
        argv = ["verify-receipt", str(bundle), "--pubkey", history.key.spec()]
        argv += ["--witness", str(history.witness_file)]
        argv += ["--witness-pubkey", history.witness_verifier.spec()]
        argv += ["--ledger", str(history.ledger), "--rows", str(rows)]
        codes.append(agentgov(argv, out=out))
    assert codes == [0, int(Failure.ROWS)]


def _rewrite_rows(receipt: ActionReceipt) -> ActionReceipt:
    """The receipt claiming other rows: a different row commitment."""
    return dataclasses.replace(
        receipt, effect=dataclasses.replace(receipt.effect, row_root=_flip(receipt.effect.row_root))
    )


def test_rewriting_a_receipts_rows_fails_at_the_first_key_the_forger_lacks(
    history: History,
) -> None:
    """The refund's receipt is made to commit to other rows. Each forger
    holds one more key than the last, and gets exactly one check further."""
    genuine = history.bundle(REFUND)
    forged = _rewrite_rows(genuine.receipt)
    root = genuine.checkpoint.root_hash[:16] if genuine.checkpoint else ""

    # Anyone who can edit the file: the signature no longer covers the body.
    report = history.verify(dataclasses.replace(genuine, receipt=forged))
    failed_at(report, "receipt signature", Failure.SIGNATURE, "does not verify under key")

    # The issuer's key, re-signing: the witnessed checkpoint's tree has the
    # original receipt at that leaf, not this one.
    resigned = forged.sign(history.key)
    report = history.verify(dataclasses.replace(genuine, receipt=resigned))
    failed_at(
        report,
        "log inclusion",
        Failure.INCLUSION,
        f"the audit path does not lead from this receipt at leaf {REFUND} to root {root}",
    )

    # The log's key too, rebuilding the tree and signing a checkpoint over
    # it: the witness cosigned another root at that size.
    with history.log() as log:
        leaves = [r.leaf_hash() for r in log.receipts()]
    leaves[REFUND] = resigned.leaf_hash()
    tree = MerkleTree(leaves)
    checkpoint = Checkpoint(
        log_id=LOG_ID,
        tree_size=len(leaves),
        root_hash=tree.root().hex(),
        issued_at=datetime.now(UTC),
    ).sign(history.key)
    proof = InclusionProof(
        leaf_index=REFUND,
        tree_size=len(leaves),
        audit_path=tuple(p.hex() for p in tree.inclusion_proof(REFUND)),
    )
    report = history.verify(ReceiptBundle(resigned, proof, checkpoint))
    failed_at(report, "witnessed", Failure.WITNESS, f"split view: .* cosigned root {root}")

    # And the witness will not cosign the forged checkpoint: a fork.
    with pytest.raises(WitnessError, match=f"two different roots at size {len(leaves)}"):
        history.witness().cosign(checkpoint, [])


def test_a_committed_row_changed_in_the_database_is_caught_by_reconciliation(
    history: History,
) -> None:
    """The receipt proves what the plan committed; reconcile-effects proves
    someone changed it afterwards, and names the row."""
    disclosure = history.disclosure(REFUND)
    account = _row(disclosure, "accounts").row
    assert account.after is not None
    conn = sqlite3.connect(history.database)
    try:
        current = conn.execute("SELECT balance FROM accounts WHERE id = 100").fetchone()[0]
        assert Decimal(str(current)) == Decimal(str(account.after["balance"]))
        conn.execute("UPDATE accounts SET balance = 0 WHERE id = 100")
        conn.commit()
    finally:
        conn.close()

    found = reconcile_sqlite(
        str(history.database), specs(*JOURNALED), EscrowChain.load(history.chain).records()
    )
    ((write,),) = (found.unmediated,)
    assert (write.table, write.primary_key, write.operation) == ("accounts", "100", "update")
    assert found.stages == ()
    # The committed rows still verify: the receipt is evidence of what the
    # plan did, whatever the table says now.
    assert history.verify(history.bundle(REFUND), rows=disclosure).passed


# --------------------------------------------------------------------------
# checkpoints
# --------------------------------------------------------------------------


def test_a_deleted_checkpoint_is_rederived_identically(history: History) -> None:
    """A checkpoint is derived from the receipts. Deleting one loses no
    evidence: the log re-derives the same root, and the witness, having
    already cosigned that root at that size, adds nothing."""
    lines = history.checkpoints.read_bytes().splitlines(keepends=True)
    deleted = Checkpoint.from_json(loads_strict(lines[-1]))
    history.checkpoints.write_bytes(b"".join(lines[:-1]))
    cosigned = load_cosignatures(history.witness_file)
    with history.log() as log:
        assert [c.tree_size for c in log.checkpoints()] == [2, 4, 6]
        again = log.publish()
    assert (again.tree_size, again.root_hash) == (deleted.tree_size, deleted.root_hash)
    assert load_cosignatures(history.witness_file) == cosigned


def _write_receipt(history: History, index: int, receipt: ActionReceipt) -> None:
    lines = history.receipt_lines()
    lines[index] = receipt.canonical() + b"\n"
    history.receipts.write_bytes(b"".join(lines))


def test_checkpoints_deleted_to_hide_a_rewrite_leave_the_witness_to_catch_it(
    history: History,
) -> None:
    """With every checkpoint gone, a receipt rewritten and re-signed by the
    issuer's own key is vouched for by nothing but that signature, so the
    log file resumes cleanly: alone, it cannot tell. The witness can."""
    history.checkpoints.write_bytes(b"")
    _write_receipt(
        history, REFUND, _rewrite_rows(history.entries[REFUND].receipt).sign(history.key)
    )
    with history.log() as log:
        assert len(log) == len(OUTCOMES) and log.checkpoints() == ()
        with pytest.raises(WitnessError, match=f"two different roots at size {len(OUTCOMES)}"):
            log.publish()
        bundle = log.bundle(REFUND)
    failed_at(history.verify(bundle), "witnessed", Failure.WITNESS, "split view")


def test_checkpoints_deleted_to_hide_a_rollback_leave_the_witness_to_catch_it(
    history: History,
) -> None:
    """The last two receipts deleted, and every checkpoint with them: a
    shorter log that is consistent on its own. The witness saw it longer."""
    kept = len(OUTCOMES) - 2
    held = history.bundle(len(OUTCOMES) - 1)
    history.checkpoints.write_bytes(b"")
    history.receipts.write_bytes(b"".join(history.receipt_lines()[:kept]))
    with history.log() as log:
        assert len(log) == kept
        assert log.index_of(held.receipt.receipt_id) is None
        with pytest.raises(WitnessError, match=f"rolled back from size {len(OUTCOMES)} to {kept}"):
            log.publish()
    # An auditor who kept a bundle for a deleted receipt can still prove it
    # was in the log: its checkpoint is the one the witness cosigned.
    assert history.verify(held).passed


def test_a_receipt_deleted_under_its_checkpoints_stops_the_log_at_the_next_line(
    history: History,
) -> None:
    lines = history.receipt_lines()
    del lines[2]
    history.receipts.write_bytes(b"".join(lines))
    after = history.entries[3].receipt.receipt_id
    with pytest.raises(ReceiptLogError, match=f"receipt {after} claims {LOG_ID}#3; .* at index 2"):
        history.log()


# --------------------------------------------------------------------------
# signatures
# --------------------------------------------------------------------------


def _signature(receipt: ActionReceipt) -> Signature:
    assert receipt.signature is not None
    return receipt.signature


RECEIPT_FORGERIES: dict[str, tuple[Callable[[ActionReceipt, HmacKey], ActionReceipt], str]] = {
    "random bytes": (
        lambda r, k: dataclasses.replace(
            r, signature=dataclasses.replace(_signature(r), value=secrets.token_bytes(32))
        ),
        r"does not verify under key",
    ),
    "another key, under the issuer's key id": (
        lambda r, k: r.sign(HmacKey(secrets.token_bytes(32), key_id=k.key_id)),
        r"does not verify under key",
    ),
    "another key, under its own id": (
        lambda r, k: r.sign(HmacKey.generate()),
        r"was signed by key [0-9a-f]{16}, not by the key given",
    ),
    "another algorithm": (
        lambda r, k: dataclasses.replace(
            r, signature=Signature("ed25519", k.key_id, secrets.token_bytes(64))
        ),
        r"claims an ed25519 signature but the key given is hmac-sha256",
    ),
    "no signature at all": (
        lambda r, k: dataclasses.replace(r, signature=None),
        r"the receipt is not signed",
    ),
}


@pytest.mark.parametrize("forgery", list(RECEIPT_FORGERIES))
def test_a_forged_receipt_signature_fails_the_signature_check(
    history: History, forgery: str
) -> None:
    forge, detail = RECEIPT_FORGERIES[forgery]
    genuine = history.bundle(REFUND)
    forged = dataclasses.replace(genuine, receipt=forge(genuine.receipt, history.key))
    failed_at(history.verify(forged), "receipt signature", Failure.SIGNATURE, detail)


@pytest.mark.parametrize(
    ("forgery", "detail"),
    [
        ("random bytes", r"the checkpoint's hmac-sha256 signature does not verify"),
        ("another key", r"the checkpoint was signed by key [0-9a-f]{16}, not by the key given"),
    ],
)
def test_a_forged_checkpoint_signature_fails_inclusion(
    history: History, forgery: str, detail: str
) -> None:
    genuine = history.bundle(REFUND)
    assert genuine.checkpoint is not None and genuine.checkpoint.signature is not None
    checkpoint = (
        dataclasses.replace(
            genuine.checkpoint,
            signature=dataclasses.replace(
                genuine.checkpoint.signature, value=secrets.token_bytes(32)
            ),
        )
        if forgery == "random bytes"
        else genuine.checkpoint.sign(HmacKey.generate())
    )
    report = history.verify(dataclasses.replace(genuine, checkpoint=checkpoint))
    failed_at(report, "log inclusion", Failure.INCLUSION, detail)


def test_a_forged_checkpoint_in_the_log_stops_it_at_that_line(history: History) -> None:
    lines = history.checkpoints.read_bytes().splitlines(keepends=True)
    forged = json.loads(lines[1])
    forged["sig"]["signature"] = secrets.token_bytes(32).hex()
    lines[1] = canonical_bytes(forged) + b"\n"
    history.checkpoints.write_bytes(b"".join(lines))
    with pytest.raises(
        ReceiptLogError, match=r"\.checkpoints line 2: the checkpoint's hmac-sha256 signature"
    ):
        history.log()


def test_a_forged_cosignature_vouches_for_nothing(history: History) -> None:
    """A cosignature signed by anyone but the witness is ignored: it cannot
    vouch for a forged checkpoint, and it cannot frame the log with a split
    view either. The witness itself refuses to resume from the edited file."""
    genuine = history.bundle(REFUND)
    forger = HmacKey.generate()
    size = len(OUTCOMES)

    # A checkpoint the log's key signed at a size the witness never saw, with
    # a cosignature forged for it.
    with history.log() as log:
        leaves = [r.leaf_hash() for r in log.receipts()]
    tree = MerkleTree([*leaves, leaves[-1]])
    checkpoint = Checkpoint(
        log_id=LOG_ID, tree_size=size + 1, root_hash=tree.root().hex(), issued_at=datetime.now(UTC)
    ).sign(history.key)
    fake = [
        Cosignature(
            witness_id=WITNESS_ID,
            log_id=LOG_ID,
            tree_size=n,
            root_hash=root,
            witnessed_at=datetime.now(UTC),
        ).sign(forger)
        for n, root in ((size + 1, checkpoint.root_hash), (size, _flip(tree.root(size).hex())))
    ]
    with history.witness_file.open("ab") as out:
        out.writelines(canonical_bytes(c.to_json()) + b"\n" for c in fake)

    proof = InclusionProof(
        leaf_index=REFUND,
        tree_size=size + 1,
        audit_path=tuple(p.hex() for p in tree.inclusion_proof(REFUND)),
    )
    report = history.verify(ReceiptBundle(genuine.receipt, proof, checkpoint))
    failed_at(report, "witnessed", Failure.WITNESS, f"at size {size + 1}: .*never witnessed")
    # The forged "other root" at the real size is not a split view.
    assert history.verify(genuine).passed
    with pytest.raises(WitnessError, match="holds a cosignature this witness did not make"):
        history.witness()


# --------------------------------------------------------------------------
# links: the inclusion proof, the ledger, the escrow chain
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("what", "detail"),
    [
        ("a node flipped", f"the audit path does not lead from this receipt at leaf {REFUND}"),
        ("a node dropped", f"the audit path does not lead from this receipt at leaf {REFUND}"),
        (
            "another leaf's proof",
            f"the receipt says it is leaf {REFUND} .* the proof is for leaf 3",
        ),
        ("another tree size", r"the proof is for a tree of 6; the checkpoint is at 7"),
    ],
)
def test_an_altered_inclusion_proof_fails_inclusion(
    history: History, what: str, detail: str
) -> None:
    genuine = history.bundle(REFUND)
    proof = genuine.inclusion
    assert proof is not None
    with history.log() as log:
        other = log.inclusion_proof(3)
        smaller = log.inclusion_proof(REFUND, 6)
    altered = {
        "a node flipped": dataclasses.replace(
            proof, audit_path=(_flip(proof.audit_path[0]), *proof.audit_path[1:])
        ),
        "a node dropped": dataclasses.replace(proof, audit_path=proof.audit_path[1:]),
        "another leaf's proof": other,
        "another tree size": smaller,
    }[what]
    report = history.verify(dataclasses.replace(genuine, inclusion=altered))
    failed_at(report, "log inclusion", Failure.INCLUSION, detail)


def test_a_rewritten_settled_cost_fails_against_the_ledger(history: History) -> None:
    """Re-signed by the issuer's key and handed over bare, without the log's
    proof: the ledger still says what the plan settled."""
    genuine = history.entries[REFUND].receipt
    forged = dataclasses.replace(
        genuine, cost=dataclasses.replace(genuine.cost, settled_usd=Decimal("0"))
    ).sign(history.key)
    report = history.verify(ReceiptBundle(forged), witnessed=False)
    failed_at(
        report,
        "agentgov ledger",
        Failure.LEDGER,
        r"the receipt's transactions settled \$0\.25\d*; it claims \$0",
        skipped=("log inclusion", "witnessed"),
    )


def _rechained(records: list[EscrowRecord], start: int) -> list[EscrowRecord]:
    """Recompute every hash from ``start`` on, as anyone who can write the
    keyless chain can."""
    out = records[:start]
    for record in records[start:]:
        linked = dataclasses.replace(
            record, prev_hash=out[-1].record_hash if out else record.prev_hash
        )
        out.append(dataclasses.replace(linked, record_hash=linked.recompute_hash()))
    return out


def test_a_rewritten_escrow_chain_is_caught_by_the_receipts_that_name_it(
    history: History,
) -> None:
    """The escrow chain has no key: rewrite a verdict and recompute every
    hash after it, and it verifies on its own. The signed receipts name its
    records by hash, and the ledger's reverse anchors name its heads, so each
    one written after the edit, and only those, stops matching."""
    records = list(EscrowChain.load(history.chain).records())
    refused = history.entries[5].receipt
    assert refused.anchors.escrow is not None
    terminal = refused.anchors.escrow.seq - 1
    edited = max(
        i
        for i in range(terminal)
        if records[i].plan_id == records[terminal].plan_id
        and records[i].record_type is RecordType.VERDICT
    )
    assert records[edited].note == "tenant_isolation"
    records[edited] = dataclasses.replace(records[edited], note="admitted")
    rewritten = _rechained(records, edited)
    history.chain.write_bytes(
        b"".join(json.dumps(r.to_json(), separators=(",", ":")).encode() + b"\n" for r in rewritten)
    )
    chain = EscrowChain.load(history.chain).records()  # verifies: nothing in it says otherwise
    assert chain[edited].note == "admitted"

    broken = [
        index
        for index, entry in enumerate(history.entries)
        if (anchor := entry.receipt.anchors.escrow) is not None
        and chain[anchor.seq - 1].record_hash != anchor.head
    ]
    assert broken == [5, 6]
    assert chain[terminal].note.endswith(refused.receipt_id)  # the chain still names it

    heads = {r.record_hash[:16] for r in chain}
    ledger = BudgetManager.open_sqlite(str(history.ledger), read_only=True)
    try:
        anchors = [
            e
            for e in ledger.audit_trail()
            if e.memo.startswith("interlock:")
            and e.entry_type in (EntryType.ANCHOR, EntryType.SPEND)
        ]
    finally:
        ledger.close()
    stale = [a.memo.removeprefix("interlock:") for a in anchors]
    unmatched = [i for i, head in enumerate(stale) if head not in heads]
    assert unmatched == [len(anchors) - 2, len(anchors) - 1]


# --------------------------------------------------------------------------
# the same, over PostgreSQL
# --------------------------------------------------------------------------


def test_receipts_issued_over_postgresql_are_as_tamper_evident(pg: Pg, tmp_path: Path) -> None:
    """A refund committed on PostgreSQL, where money is NUMERIC: its rows
    disclose and verify exactly, an altered one fails the row check, and the
    row changed behind the engine's back is named by reconcile-effects."""
    import psycopg

    key, secret = HmacKey.generate(), secrets.token_bytes(32)
    governor = BudgetManager.open_sqlite(str(tmp_path / "governor.db"))
    governor.open_root("support-agent", "100")
    log = ReceiptLog(LOG_ID, key, path=tmp_path / "receipts.jsonl")
    chain = EscrowChain(tmp_path / "escrow.jsonl")
    try:
        engine = pg_engine(
            pg,
            chain=chain,
            anchor=LedgerAnchor(governed=governor),
            settle_cost="0.25",
            receipts=ReceiptIssuer(log, row_secret=secret),
        )
        result = engine.execute(Refund("refund-pg", 9100, Decimal("3.00")).plan())
        assert result.committed and result.receipt is not None and result.diff is not None
        commitment = commit_rows(
            [
                RowChange.from_values(
                    d.table, d.primary_key, before=d.before, after=d.after, tenant=d.tenant_id
                )
                for d in result.diff.deltas
            ],
            secret=secret,
        )
        assert commitment.root == result.receipt.effect.row_root
        disclosure = commitment.disclose(
            range(commitment.count), receipt_id=result.receipt.receipt_id
        )
        account = _row(disclosure, "accounts").row
        assert account.after is not None and account.after["balance"] == "503.00"
        bundle = log.bundle(0, log.checkpoint())
        assert verify_bundle(bundle, issuer_key=key, ledger=governor, rows=disclosure).passed
        altered = ROW_TAMPERING["a value in the after-image"][0](disclosure)
        report = verify_bundle(bundle, issuer_key=key, ledger=governor, rows=altered)
        assert (report.exit_code, report.first_failure and report.first_failure.name) == (
            int(Failure.ROWS),
            "disclosed rows",
        )

        with psycopg.connect(pg.admin, autocommit=True) as conn:
            conn.execute("UPDATE accounts SET balance = 0 WHERE id = 100")
            found = reconcile_postgres(conn, chain.records())
        ((write,),) = (found.unmediated,)
        assert (write.table, write.primary_key, write.operation) == ("accounts", "100", "update")
        assert found.stages == ()
        assert verify_bundle(bundle, issuer_key=key, ledger=governor, rows=disclosure).passed
    finally:
        log.close()
        chain.close()
        governor.close()
