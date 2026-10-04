"""The vacuum: cryptographic compaction (``docs/EPIC5_DESIGN.md`` §1), on both stores.

- Settled stages go under one checkpoint, signed in an operator's intent and
  anchored into AgentGov before anything is deleted; live ones stay; and every
  verifier passes afterwards, the receipt log and the ledger held to the
  tombstones.
- Nothing that does not verify is pruned: a message whose outcome no relay
  attested keeps its stage, and a finding that is no one message's (a
  checkpoint forged around Interlock) stops the vacuum altogether.
- A stage goes whole, or stays; a cancelled request is final.
- The database refuses, on its own, an act a vacuum did not verify: a log
  that moved, a checkpoint out of order, a message not final and settled,
  half a stage, the legacy set's messages, folds other than the signed ones.
- Rate-window history goes past the longest span; a window reaching back
  further fails closed.
- Rows go only under a checkpoint: every other delete is refused, and every
  forgery around the guards is named.
- An archive proves the pruned history against its checkpoint.
"""

from __future__ import annotations

import json
import time
import uuid
from collections.abc import Iterator
from contextlib import closing
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from agentgov import BudgetManager
from agentgov.core import EntryType

from interlock import PlanBuilder
from interlock.compaction import GENESIS, Checkpoint, tombstone_root, window_root
from interlock.exceptions import CompactionRefusedError, SubstrateConfigurationError
from interlock.operators import verify_operators
from interlock.records import anchor_memo, read_records
from interlock.settlement import verify_settlements
from interlock.vacuum import verify_archive
from interlock.windows import Plans, RateWindow
from tests.outbox_env import (
    BACKENDS,
    RELAYS,
    SCOPE,
    Outbox,
    PostgresOutbox,
    build_either,
    mail,
)
from tests.settling import Bench


@pytest.fixture(params=BACKENDS)
def outbox(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Outbox]:
    yield from build_either(request, tmp_path)


@pytest.fixture
def bench(outbox: Outbox, tmp_path: Path) -> Iterator[Bench]:
    built = Bench(outbox, tmp_path)
    try:
        yield built
    finally:
        built.close()


def office(bench: Bench) -> tuple[uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID]:
    """Two bookings delivered and settled, one compensated (its compensation
    delivered, settled and credited too), and one never delivered."""
    booked, other = bench.book(1), bench.book(2)
    bench.deliver()
    cancel = bench.compensate(booked)
    bench.deliver()
    assert bench.settler().settle().credits == 1
    pending = bench.book(3)
    return booked, other, cancel, pending


def everything_verifies(bench: Bench) -> None:
    outbox = bench.outbox
    outbox.verify()
    entries = list(outbox.governor.audit_trail())
    records = read_records(outbox.operator_log)
    assert (
        verify_operators(outbox.operator(), records, outbox.keyring(), ledger=entries).problems
        == ()
    )
    assert verify_settlements(bench.source(), log=bench.log, relays=RELAYS, ledger=entries) == ()


def owner(outbox: Outbox, *statements: tuple[str, tuple[Any, ...]]) -> None:
    """Statements as the database's owner runs them, around Interlock."""
    if isinstance(outbox, PostgresOutbox):
        with outbox.admin() as conn:
            for sql, params in statements:
                conn.execute(sql, params)
    else:
        with closing(outbox.raw()) as conn:  # type: ignore[attr-defined]
            for sql, params in statements:
                conn.execute(sql.replace("%s", "?").replace("interlock.", "_interlock_"), params)


def table(outbox: Outbox, name: str) -> str:
    return f"interlock.{name}" if isinstance(outbox, PostgresOutbox) else f"_interlock_{name}"


def mark(outbox: Outbox) -> str:
    return "%s" if isinstance(outbox, PostgresOutbox) else "?"


def key(outbox: Outbox, message: uuid.UUID) -> object:
    return message if isinstance(outbox, PostgresOutbox) else str(message)


# --------------------------------------------------------------------------
# what goes, and that everything still verifies
# --------------------------------------------------------------------------


def test_settled_stages_go_under_a_signed_anchored_checkpoint(bench: Bench) -> None:
    outbox = bench.outbox
    booked, other, cancel, pending = office(bench)
    with outbox.vacuum() as vacuum:
        report = vacuum.run(reason="monthly")
    assert report.outcome == "applied" and report.checkpoint is not None
    assert (report.messages, report.window_rows) == (3, 0)
    checkpoint = report.checkpoint
    assert (checkpoint.seq, checkpoint.prev) == (1, GENESIS)
    # Only the undelivered booking is left; the three pruned keep tombstones.
    assert outbox.requests() == 1 and outbox.state(pending) == "pending"
    pruned = outbox.compactor().compacted()
    assert set(pruned) == {booked, other, cancel}
    assert pruned[cancel].credit is not None and pruned[booked].receipt_id is not None
    assert tombstone_root(pruned.values()) == checkpoint.root
    (row,) = outbox.compactor().checkpoints()
    assert row.body == checkpoint.canonical() and row.digest == checkpoint.digest
    # The intent carried the checkpoint, and AgentGov anchored the intent
    # before anything was deleted.
    *_, intent, applied = read_records(outbox.operator_log)
    assert intent.body["action"] == "compact" and intent.body["checkpoint"] == checkpoint.body()
    assert applied.kind == "operator.applied"
    assert applied.body["checkpoint"] == {"seq": 1, "digest": checkpoint.digest}
    memos = {e.memo for e in outbox.governor.audit_trail() if e.entry_type is EntryType.ANCHOR}
    assert anchor_memo(intent) in memos
    assert checkpoint.agentgov[0] > 0
    everything_verifies(bench)


def test_a_second_vacuum_continues_the_chain_and_prunes_nothing_twice(bench: Bench) -> None:
    outbox = bench.outbox
    *_, pending = office(bench)
    with outbox.vacuum() as vacuum:
        first = vacuum.run()
        assert vacuum.run().outcome == "nothing"
    bench.deliver()
    bench.settler().settle()
    with outbox.vacuum() as vacuum:
        second = vacuum.run()
    assert first.checkpoint is not None and second.checkpoint is not None
    assert (second.checkpoint.seq, second.checkpoint.prev) == (2, first.checkpoint.digest)
    assert second.messages == 1 and pending in outbox.compactor().compacted()
    assert outbox.requests() == 0
    everything_verifies(bench)


def test_a_dry_run_signs_and_prunes_nothing(bench: Bench) -> None:
    office(bench)
    before = len(read_records(bench.outbox.operator_log))
    with bench.outbox.vacuum() as vacuum:
        report = vacuum.run(dry_run=True)
    assert report.outcome == "dry-run" and report.messages == 3
    assert len(read_records(bench.outbox.operator_log)) == before
    assert bench.outbox.requests() == 4


def test_retention_keeps_what_is_recent(bench: Bench) -> None:
    office(bench)
    with bench.outbox.vacuum(retain=timedelta(days=1)) as vacuum:
        assert vacuum.run().outcome == "nothing"
    assert bench.outbox.requests() == 4


def test_a_vacuum_whose_checkpoint_is_not_anchored_prunes_nothing(bench: Bench) -> None:
    office(bench)
    with bench.outbox.vacuum(anchored=False) as vacuum:
        report = vacuum.run()
    assert report.outcome == "abandoned"
    *_, intent, abandoned = read_records(bench.outbox.operator_log)
    assert abandoned.kind == "operator.abandoned" and "anchored" in abandoned.body["why"]
    assert intent.body["action"] == "compact"
    assert bench.outbox.requests() == 4 and bench.outbox.compactor().checkpoints() == []
    assert bench.outbox.verify_operators().problems == ()


# --------------------------------------------------------------------------
# nothing unverified is pruned
# --------------------------------------------------------------------------


def test_a_message_that_does_not_verify_keeps_its_stage(bench: Bench) -> None:
    outbox = bench.outbox
    booked, other, cancel, _ = office(bench)
    # Its outcome rewritten around Interlock: the relay never said 418.
    outbox.rewrite_last(other, status_code=418)
    with outbox.vacuum() as vacuum:
        report = vacuum.run()
    assert report.outcome == "applied"
    assert set(outbox.compactor().compacted()) == {booked, cancel}
    (kept,) = report.kept
    assert f"message {other} does not verify" in kept[1]
    assert outbox.state(other) == "delivered"


def test_a_finding_no_one_messages_stops_the_vacuum(bench: Bench) -> None:
    outbox = bench.outbox
    office(bench)
    with outbox.vacuum() as vacuum:
        vacuum.run()
    # A tombstone forged into checkpoint 1: inserting is not refused (nothing
    # can be added to what a checkpoint commits to without its fold changing).
    forged = uuid.uuid4()
    owner(
        outbox,
        (
            f"INSERT INTO {table(outbox, 'outbox_compacted')} (message_id, checkpoint, "
            f"stage_id, plan_id, state, log_seq, log_head, cost) "
            f"VALUES (%s, 1, %s, 'p', 'cancelled', 1, %s, '0')",
            (key(outbox, forged), key(outbox, uuid.uuid4()), "0" * 64),
        ),
    )
    bench.book(9)
    bench.deliver()
    bench.settler().settle()
    with outbox.vacuum() as vacuum:
        report = vacuum.run()
    assert report.outcome == "refused"
    assert any("checkpoint 1's tombstones no longer fold" in p for p in report.problems)
    assert len(outbox.compactor().checkpoints()) == 1


# --------------------------------------------------------------------------
# a stage goes whole
# --------------------------------------------------------------------------


def test_a_stage_goes_whole_or_stays_and_a_cancelled_request_is_final(bench: Bench) -> None:
    outbox = bench.outbox
    kept_first, cancelled = bench.book_together(1, 2)
    with outbox.signed("ops") as operator:
        operator.cancel(cancelled, reason="not wanted")
    bench.deliver()
    bench.settler().settle()
    delivered, unsettled = bench.book_together(3, 4)
    bench.deliver()  # delivered, never settled
    with outbox.vacuum() as vacuum:
        report = vacuum.run()
    pruned = outbox.compactor().compacted()
    assert set(pruned) == {kept_first, cancelled}
    assert pruned[cancelled].state == "cancelled" and pruned[cancelled].receipt_id is None
    assert report.messages == 2
    assert outbox.state(delivered) == outbox.state(unsettled) == "delivered"
    everything_verifies(bench)


# --------------------------------------------------------------------------
# the database refuses on its own
# --------------------------------------------------------------------------


def _body(outbox: Outbox, seq: int = 1, **changes: Any) -> Checkpoint:
    fields: dict[str, Any] = {
        "seq": seq,
        "prev": GENESIS,
        "windows_horizon": None,
        "outbox_horizon": None,
        "messages": 0,
        "rows": 0,
        "root": tombstone_root([]),
        "window_rows": 0,
        "window_root": window_root([]),
        "agentgov": (0, "0" * 64),
    }
    fields.update(changes)
    return Checkpoint(**fields)


def test_the_database_refuses_a_checkpoint_out_of_order(outbox: Outbox) -> None:
    compactor = outbox.compactor()
    with pytest.raises(CompactionRefusedError, match="does not follow"):
        compactor.compact("a" * 64, _body(outbox, seq=2).canonical(), [])
    with pytest.raises(CompactionRefusedError, match="does not follow"):
        compactor.compact("a" * 64, _body(outbox, prev="1" * 64).canonical(), [])
    assert compactor.checkpoints() == []


def test_the_database_refuses_a_log_that_moved(bench: Bench) -> None:
    outbox = bench.outbox
    office(bench)

    def moved(point: str) -> None:
        if point == "anchored":
            # Between the signature and the act, a row lands on a message
            # the checkpoint names.
            (first,) = [t.message_id for t in found.tombstones][:1]
            outbox.forge(first, "requeued", authority="b" * 64, state_after=None)

    with outbox.vacuum(checkpoint=moved) as vacuum:
        found = vacuum.survey()
        report = vacuum.run()
    assert report.outcome == "rejected" and "moved after it was verified" in report.problems[0]
    *_, refused = read_records(outbox.operator_log)
    assert refused.kind == "operator.refused"
    assert outbox.compactor().checkpoints() == [] and outbox.requests() == 4


def test_the_database_refuses_what_is_not_final_settled_and_whole(bench: Bench) -> None:
    outbox = bench.outbox
    pending = bench.book(5)
    first, second = bench.book_together(6, 7)
    bench.deliver()
    compactor = outbox.compactor()
    messages, _ = compactor.snapshot(None)
    heads = {
        m.message_id: {"message": str(m.message_id), "seq": m.log_seq, "head": m.log_head}
        for m in messages
    }
    with pytest.raises(CompactionRefusedError, match="not final and settled"):
        compactor.compact("a" * 64, _body(outbox).canonical(), [heads[first], heads[second]])
    bench.settler().settle()
    messages, _ = compactor.snapshot(None)
    heads = {
        m.message_id: {"message": str(m.message_id), "seq": m.log_seq, "head": m.log_head}
        for m in messages
    }
    with pytest.raises(CompactionRefusedError, match="whole or not at all"):
        compactor.compact("a" * 64, _body(outbox).canonical(), [heads[first]])
    with pytest.raises(CompactionRefusedError, match="not the ones the checkpoint commits to"):
        compactor.compact("a" * 64, _body(outbox).canonical(), [heads[first], heads[second]])
    assert pending in {m.message_id for m in messages}
    assert compactor.checkpoints() == [] and outbox.requests() == 3


def test_the_database_keeps_the_legacy_sets_messages(bench: Bench) -> None:
    outbox = bench.outbox
    booked = bench.book(1)
    bench.deliver()
    bench.settler().settle()
    (event,) = [e for e in outbox.log(booked) if e.event == "delivered"]
    legacy = table(outbox, "outbox_legacy")
    if isinstance(outbox, PostgresOutbox):
        owner(
            outbox,
            (f"ALTER TABLE {legacy} DISABLE TRIGGER legacy_sealed", ()),
            (f"INSERT INTO {legacy} VALUES (%s, %s, %s)", (booked, event.seq, event.event_hash)),
        )
    else:
        owner(
            outbox,
            ("DROP TRIGGER _interlock_legacy_sealed", ()),
            (f"INSERT INTO {legacy} VALUES (?, ?, ?)", (str(booked), event.seq, event.event_hash)),
        )
    compactor = outbox.compactor()
    (message,), _ = compactor.snapshot([booked])
    with pytest.raises(CompactionRefusedError, match="legacy set"):
        compactor.compact(
            "a" * 64,
            _body(outbox).canonical(),
            [{"message": str(booked), "seq": message.log_seq, "head": message.log_head}],
        )


# --------------------------------------------------------------------------
# window history, and its watermark
# --------------------------------------------------------------------------

SHORT = RateWindow("plans_short", timedelta(milliseconds=50), 1000, Plans(), "scope")
LONG = RateWindow("plans_long", timedelta(hours=1), 1000, Plans(), "scope")


def _plan_through(outbox: Outbox, window: RateWindow, n: int) -> bool:
    plan = (
        PlanBuilder(SCOPE)
        .enqueue(sink="mail", operation="send", payload=dict(mail(n).payload))
        .build()
    )
    return outbox.engine(windows=[window]).execute(plan).committed


def test_window_history_goes_past_the_longest_span_and_fails_closed_beyond(
    outbox: Outbox,
) -> None:
    for n in range(3):
        assert _plan_through(outbox, SHORT, n)
    time.sleep(0.2)
    with outbox.vacuum(windows=[SHORT], margin=timedelta(0)) as vacuum:
        report = vacuum.run()
    assert report.outcome == "applied" and report.window_rows == 3 and report.messages == 0
    (row,) = outbox.compactor().checkpoints()
    assert row.windows_horizon is not None
    assert row.checkpoint().window_root != window_root([])
    history = "window_ledger" if isinstance(outbox, PostgresOutbox) else "windows"
    assert outbox.fetch(f"SELECT count(*) FROM {table(outbox, history)}")[0][0] == 0
    # The short window measures as before; a longer one would read pruned
    # history short, and fails closed.
    assert _plan_through(outbox, SHORT, 10)
    with pytest.raises(SubstrateConfigurationError, match="reaches back past the history"):
        _plan_through(outbox, LONG, 11)
    assert outbox.verify_operators().problems == ()


# --------------------------------------------------------------------------
# rows go only under a checkpoint
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "target",
    ["outbox", "outbox_attempts", "outbox_state", "outbox_settlements", "window_ledger"],
)
def test_every_other_delete_is_refused(bench: Bench, target: str) -> None:
    outbox = bench.outbox
    office(bench)
    assert _plan_through(outbox, SHORT, 1)
    name = (
        target
        if isinstance(outbox, PostgresOutbox)
        else ("windows" if target == "window_ledger" else target)
    )
    with pytest.raises(Exception, match=r"append-only|history|goes only with"):
        owner(outbox, (f"DELETE FROM {table(outbox, name)}", ()))


def test_checkpoints_and_tombstones_never_change(bench: Bench) -> None:
    outbox = bench.outbox
    office(bench)
    with outbox.vacuum() as vacuum:
        vacuum.run()
    for name in ("checkpoints", "outbox_compacted"):
        with pytest.raises(Exception, match="append-only"):
            owner(outbox, (f"DELETE FROM {table(outbox, name)}", ()))
    with pytest.raises(Exception, match="append-only"):
        owner(outbox, (f"UPDATE {table(outbox, 'checkpoints')} SET prev = 'x'", ()))


def test_a_checkpoint_written_around_interlock_is_named(bench: Bench) -> None:
    """The database cannot check a signature: an owner who writes a
    checkpoint row, tombstones and all, may delete under it. Verification
    holds its authority to the signed operator log."""
    outbox = bench.outbox
    _, other, _, _ = office(bench)
    compactor = outbox.compactor()
    messages, events = compactor.snapshot([other])
    (message,) = messages
    settled = compactor.settlements()[other]
    from interlock.compaction import Tombstone

    tombstone = Tombstone(
        other,
        1,
        message.stage_id,
        message.plan_id,
        "delivered",
        message.log_seq,
        message.log_head,
        settled.receipt_id,
        settled.credit,
        str(message.cost),
        None,
    )
    body = _body(outbox, messages=1, rows=len(events), root=tombstone_root([tombstone]))
    compactor.compact(
        "c" * 64,
        body.canonical(),
        [{"message": str(other), "seq": message.log_seq, "head": message.log_head}],
    )
    problems = outbox.verify_operators().problems
    assert any("which no signed compact intent holds" in p for p in problems)


def test_forgeries_around_the_guards_are_named(bench: Bench) -> None:
    outbox = bench.outbox
    office(bench)
    with outbox.vacuum() as vacuum:
        vacuum.run()
    assert outbox.verify_operators().problems == ()
    checkpoints = table(outbox, "checkpoints")
    if isinstance(outbox, PostgresOutbox):
        lift = [(f"ALTER TABLE {checkpoints} DISABLE TRIGGER checkpoints_append_only", ())]
    else:
        lift = [("DROP TRIGGER _interlock_checkpoints_no_update", ())]
    owner(outbox, *lift, (f"UPDATE {checkpoints} SET body = body || ' '", ()))
    problems = outbox.verify_operators().problems
    assert any("checkpoint 1's digest is not its body's" in p for p in problems)
    assert any("not the checkpoint operator record" in p for p in problems)


def test_a_deleted_checkpoint_is_named(bench: Bench) -> None:
    outbox = bench.outbox
    office(bench)
    with outbox.vacuum() as vacuum:
        vacuum.run()
    compacted, checkpoints = table(outbox, "outbox_compacted"), table(outbox, "checkpoints")
    if isinstance(outbox, PostgresOutbox):
        lift = [
            (f"ALTER TABLE {compacted} DISABLE TRIGGER compacted_append_only", ()),
            (f"ALTER TABLE {checkpoints} DISABLE TRIGGER checkpoints_append_only", ()),
        ]
    else:
        lift = [
            ("DROP TRIGGER _interlock_compacted_no_delete", ()),
            ("DROP TRIGGER _interlock_checkpoints_no_delete", ()),
        ]
    owner(outbox, *lift, (f"DELETE FROM {compacted}", ()), (f"DELETE FROM {checkpoints}", ()))
    problems = outbox.verify_operators().problems
    assert any("applied a checkpoint the database no longer holds" in p for p in problems)


# --------------------------------------------------------------------------
# the archive
# --------------------------------------------------------------------------


def test_the_archive_proves_the_pruned_history(bench: Bench, tmp_path: Path) -> None:
    outbox = bench.outbox
    office(bench)
    with outbox.vacuum(archive=tmp_path / "archive") as vacuum:
        report = vacuum.run()
    assert report.archive is not None and report.archive.exists()
    checkpoint = report.checkpoint
    assert checkpoint is not None and checkpoint.archive is not None
    assert verify_archive(report.archive, checkpoint, relays=RELAYS) == []
    # The body the database keeps carries the archive's digest.
    (row,) = outbox.compactor().checkpoints()
    assert row.checkpoint().archive == checkpoint.archive
    everything_verifies(bench)
    # One byte of one archived row changed: the file is not the one the
    # checkpoint carries, and its log no longer recomputes.
    lines = report.archive.read_text().splitlines()
    tampered = [json.loads(line) for line in lines]
    for line in tampered[1:]:
        if line.get("kind") == "message":
            line["events"][-1]["detail"] = "rewritten"
            break
    report.archive.write_text("\n".join(json.dumps(line) for line in tampered) + "\n")
    problems = verify_archive(report.archive, checkpoint, relays=RELAYS)
    assert any("is not the archive" in p for p in problems)
    assert any("does not hash to what it records" in p for p in problems)


# --------------------------------------------------------------------------
# the command line
# --------------------------------------------------------------------------


def _cli(*argv: str) -> tuple[int, str]:
    import io

    from interlock.cli import main

    out = io.StringIO()
    return main(list(argv), out=out), out.getvalue()


def _config(outbox: Outbox, tmp_path: Path, *, relays: str, operators: str = "") -> Path:
    """A configuration as ``interlock vacuum`` reads it: the outbox's
    database, ``[operators]`` (anchored into the ledger unless ``operators``
    says otherwise), ``relays`` as given, and ``[vacuum]`` keeping nothing."""
    if isinstance(outbox, PostgresOutbox):
        head = f'substrate = "postgres"\ndatabase = "{outbox.pg.admin}"\n'
    else:
        head = f'substrate = "sqlite"\ndatabase = "{outbox.path}"\n'  # type: ignore[attr-defined]
    keys = "".join(f'{name} = "{key.public_key().spec()}"\n' for name, key in outbox.keys.items())
    operators = operators or (
        f'[operators]\nlog = "{outbox.operator_log}"\nledger = "{outbox.ledger_path}"\n'
        f'scope = "operators"\n[operators.keys]\n{keys}'
    )
    path = tmp_path / "interlock.toml"
    path.write_text(
        head
        + '[[tables]]\nname = "orders"\ncolumns = ["id", "tenant", "status", "total"]\n'
        + operators
        + relays
        + '[vacuum]\nretain_days = 0\nmargin_seconds = 0\narchive = "archive"\n'
    )
    return path


def test_interlock_vacuum_on_the_command_line(bench: Bench, tmp_path: Path) -> None:
    from interlock.operators import generate_key
    from tests.outbox_env import relay_signer

    outbox = bench.outbox
    office(bench)
    bench.close()
    outbox.governor.open_root("operators", "1")
    outbox.governor.close()
    key = tmp_path / "vac.key"
    outbox.keys["vac"] = generate_key(key)
    relays = f'[relays.keys]\nrelay = "{relay_signer().public_key().spec()}"\n'
    config = _config(outbox, tmp_path, relays=relays)

    code, out = _cli("vacuum", "--config", str(config), "--key", str(key), "--dry-run")
    assert code == 0 and "would prune 3 message(s)" in out
    code, out = _cli("vacuum", "--config", str(config), "--key", str(key), "--reason", "monthly")
    assert code == 0 and "checkpoint 1 (" in out and "pruned 3 message(s)" in out
    archive = tmp_path / "archive" / "checkpoint-1.jsonl"
    assert f"archived to {archive}" in out
    code, out = _cli("vacuum", "--config", str(config), "--key", str(key))
    assert (code, out.strip()) == (0, "nothing to prune")
    code, out = _cli("vacuum", "--config", str(config), "--verify-archive", str(archive))
    assert code == 0 and "proves checkpoint 1's pruned history" in out
    code, out = _cli("outbox", "verify", "--config", str(config))
    assert code == 0, out
    assert "1 checkpoint(s) verify against their signed intents; 3 message(s) pruned" in out

    # Refused before anything is signed: no ledger to anchor into, no relay
    # keys to verify with, no operator key.
    unanchored = _config(
        outbox,
        tmp_path,
        relays=relays,
        operators=f'[operators]\nlog = "{outbox.operator_log}"\n[operators.keys]\n'
        f'vac = "{outbox.keys["vac"].public_key().spec()}"\n',
    )
    assert _cli("vacuum", "--config", str(unanchored), "--key", str(key))[0] == 2
    assert (
        _cli("vacuum", "--config", str(_config(outbox, tmp_path, relays="")), "--key", str(key))[0]
        == 2
    )
    assert _cli("vacuum", "--config", str(_config(outbox, tmp_path, relays=relays)))[0] == 2
    outbox.governor = BudgetManager.open_sqlite(outbox.ledger_path)
