"""Rate windows (``docs/EPIC4_DESIGN.md`` §3), on both stores.

- A window admits plans up to its limit and refuses the one past it, which is
  told the window, never what it holds.
- The sub-threshold attacker: every plan under every per-plan limit, refused
  at the window all the same. Spreading requests across tenants buys nothing
  beside a per-scope window.
- It slides: what a plan added stops counting a span after it committed.
- Exact under concurrency: plans racing into one window from many
  connections commit exactly up to its limit. On PostgreSQL, without the
  lock, they would not.
- What a plan adds is written only when it commits, bound to its commit
  marker; agent statements can neither read window history nor write it.
- The diff carries each window's measure, its hash covers them, and the
  verdict replays from the plan and the diff alone.
- A repair keeps what fits the window.
- Each measure, per scope, tenant and globally; what a window cannot
  measure refuses the plan; a window is configured as one or not at all.
"""

from __future__ import annotations

import dataclasses
import threading
import time
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any

import pytest

from interlock import BlastRadius, PlanBuilder, PostgresSubstrate, SqliteSubstrate
from interlock.chain import RecordType
from interlock.engine import EscrowEngine
from interlock.exceptions import ForbiddenStatementError, StageConflictError
from interlock.feedback import AgentFeedback, Guidance, sanitize
from interlock.types import EffectDiff, EffectPlan, OutboundDelta, OutboundRequest, RowDelta
from interlock.windows import (
    Plans,
    RateWindow,
    RateWindowCheck,
    Requests,
    RequestSum,
    RowSum,
    charges,
    window_lock,
)
from tests.conftest import OBSERVED
from tests.outbox_env import BACKENDS, SCOPE, Outbox, PostgresOutbox, build_either, mail
from tests.schemas import specs

POSTGRES_ONLY = pytest.mark.parametrize("outbox", ["postgres"], indirect=True)


@pytest.fixture(params=BACKENDS)
def outbox(request: pytest.FixtureRequest, tmp_path: Any) -> Iterator[Outbox]:
    yield from build_either(request, tmp_path)


def refund(amount: str, n: int = 0) -> OutboundRequest:
    return OutboundRequest("payments", "refund", {"amount": amount, "order": f"o{n}"})


def requests_plan(
    *requests: OutboundRequest, scope: str = SCOPE, tenant: str | None = None
) -> EffectPlan:
    builder = PlanBuilder(scope)
    for request in requests:
        builder.enqueue(
            sink=request.sink,
            operation=request.operation,
            payload=request.payload,
            tenant_id=tenant,
            independent=True,
        )
    return builder.build()


def refused_by(result: Any) -> list[str]:
    return [v.invariant for v in result.verdict.blocking] if result.verdict else []


def history(outbox: Outbox) -> list[tuple[str, str, Decimal]]:
    """Every row of window history, as its owner reads it."""
    table = "interlock.window_ledger" if outbox.backend == "postgres" else "_interlock_windows"
    rows = outbox.fetch(f"SELECT window_name, key, amount FROM {table} ORDER BY at")
    return [(str(w), str(k), Decimal(str(a))) for w, k, a in rows]


# --------------------------------------------------------------------------
# the limit
# --------------------------------------------------------------------------


def test_a_window_admits_up_to_its_limit_and_refuses_past_it(outbox: Outbox) -> None:
    window = RateWindow("mail_per_hour", timedelta(hours=1), 3, Requests("mail"))
    engine = outbox.engine(windows=[window])
    for n in range(3):
        assert engine.execute(requests_plan(mail(n))).committed
    refused = engine.execute(requests_plan(mail(3)))
    assert not refused.committed
    assert refused_by(refused) == ["rate_window:mail_per_hour"]

    # The agent is told the window, nothing it holds.
    assert refused.feedback is not None
    (constraint,) = refused.feedback.blocking
    assert (constraint.guidance, constraint.window) == (Guidance.RATE_WINDOW, "mail_per_hour")
    assert (constraint.measured, constraint.limit, constraint.tenants) == (None, None, ())
    assert "rate window mail_per_hour past its limit" in refused.feedback.render()
    assert "3" not in refused.feedback.render()
    # The operator, everything.
    (violation,) = refused.verdict.blocking if refused.verdict else ()
    assert violation.evidence["history"] == "3" and violation.evidence["limit"] == "3"
    assert "holds 3 for scope agent" in violation.message

    # Only the committed plans added to it: one each.
    assert history(outbox) == [("mail_per_hour", SCOPE, Decimal(1))] * 3
    # Another agent's history is its own.
    assert engine.execute(requests_plan(mail(4), scope="other")).committed


def test_a_plan_that_adds_nothing_to_a_window_is_not_held_by_it(outbox: Outbox) -> None:
    window = RateWindow("pages", timedelta(hours=1), 0, Requests("pager"))
    engine = outbox.engine(windows=[window])
    result = engine.execute(requests_plan(mail(1)))
    assert result.committed and result.diff is not None and result.diff.windows == ()
    assert history(outbox) == []


def test_the_sub_threshold_attacker_is_stopped_at_the_window(outbox: Outbox) -> None:
    """Twenty-two refunds of 50, each under every per-plan limit: a day's
    window of 1000 admits twenty."""
    window = RateWindow(
        "refunds_per_day",
        timedelta(days=1),
        "1000",
        RequestSum("payments", "refund", "amount"),
    )
    engine = outbox.engine(windows=[window], checkers=[BlastRadius(1)])
    outcomes = [engine.execute(requests_plan(refund("50.00", n))).committed for n in range(22)]
    assert outcomes == [True] * 20 + [False] * 2
    assert sum(amount for _, _, amount in history(outbox)) == Decimal("1000")


def test_spreading_requests_across_tenants_buys_nothing(outbox: Outbox) -> None:
    """A request's tenant is the plan's to declare. Each one its own tenant
    never fills the per-tenant window; the per-scope window beside it is full
    all the same."""
    per_tenant = RateWindow("mail_per_tenant", timedelta(hours=1), 2, Requests("mail"), "tenant")
    per_scope = RateWindow("mail_per_agent", timedelta(hours=1), 5, Requests("mail"))
    engine = outbox.engine(windows=[per_tenant, per_scope])
    outcomes = [engine.execute(requests_plan(mail(n), tenant=f"tenant-{n}")) for n in range(6)]
    assert [r.committed for r in outcomes] == [True] * 5 + [False]
    assert refused_by(outcomes[-1]) == ["rate_window:mail_per_agent"]
    # And one tenant's own window fills at two.
    same = [engine.execute(requests_plan(mail(n), tenant="acme", scope="b")) for n in range(3)]
    assert [r.committed for r in same] == [True, True, False]
    assert refused_by(same[-1]) == ["rate_window:mail_per_tenant"]
    assert same[-1].feedback is not None
    (constraint,) = same[-1].feedback.blocking
    assert constraint.tenants == ("acme",) and "for tenant acme" in constraint.render()


def test_the_window_slides(outbox: Outbox) -> None:
    window = RateWindow("burst", timedelta(seconds=1.5), 2, Plans(), per="global")
    engine = outbox.engine(windows=[window])
    assert engine.execute(requests_plan(mail(1))).committed
    assert engine.execute(requests_plan(mail(2))).committed
    assert not engine.execute(requests_plan(mail(3))).committed
    time.sleep(1.6)
    assert engine.execute(requests_plan(mail(4))).committed


# --------------------------------------------------------------------------
# exact under concurrency
# --------------------------------------------------------------------------


def _held_after_reading(monkeypatch: pytest.MonkeyPatch, outbox: Outbox, seconds: float) -> None:
    """Every stage waits ``seconds`` after reading its windows, holding what
    it holds: the window in which racing stages would all read the same
    history, were they not kept apart."""
    kind: type[Any] = PostgresSubstrate if outbox.backend == "postgres" else SqliteSubstrate
    measure = kind.measure_windows

    def slow(self: Any, handle: Any, due: Any) -> Any:
        found = measure(self, handle, due)
        time.sleep(seconds)
        return found

    monkeypatch.setattr(kind, "measure_windows", slow)


def race(outbox: Outbox, window: RateWindow, racers: int) -> list[str]:
    """``racers`` plans from as many engines and connections at once, each
    adding one to ``window``: how each ended."""
    start = threading.Barrier(racers)
    outcomes: list[str] = []
    lock = threading.Lock()

    def run(n: int) -> None:
        try:
            engine = outbox.engine(windows=[window])
            plan = requests_plan(mail(n))
        finally:
            # Every racer reaches the start, or none is left waiting there.
            start.wait(60)
        ended = "conflicted"
        try:
            for _ in range(50):
                try:
                    result = engine.execute(plan)
                except StageConflictError:
                    continue  # another stage held the key past the lock timeout
                ended = "committed" if result.committed else ",".join(refused_by(result))
                break
        except Exception as exc:
            ended = f"raised {type(exc).__name__}: {exc}"
        with lock:
            outcomes.append(ended)

    threads = [threading.Thread(target=run, args=(n,)) for n in range(racers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(120)
    assert not any(thread.is_alive() for thread in threads), "a racer never finished"
    return outcomes


def test_racing_plans_commit_exactly_up_to_the_limit(
    outbox: Outbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    window = RateWindow("racers", timedelta(hours=1), 4, Requests("mail"), per="global")
    _held_after_reading(monkeypatch, outbox, 0.1)
    outcomes = race(outbox, window, 8)
    assert sorted(outcomes) == ["committed"] * 4 + ["rate_window:racers"] * 4
    assert history(outbox) == [("racers", "", Decimal(1))] * 4


@POSTGRES_ONLY
def test_without_the_lock_racing_plans_pass_the_limit(
    outbox: Outbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The mutation the lock is there for: each stage reads the history its
    rivals have not committed to yet, and every one of them commits."""
    window = RateWindow("racers", timedelta(hours=1), 4, Requests("mail"), per="global")
    monkeypatch.setattr(PostgresSubstrate, "_lock_windows", lambda self, conn, due: None)
    _held_after_reading(monkeypatch, outbox, 0.3)
    outcomes = race(outbox, window, 8)
    assert outcomes.count("committed") > 4
    assert len(history(outbox)) > 4


# --------------------------------------------------------------------------
# history: bound to the commit, closed to the agent
# --------------------------------------------------------------------------


def test_a_plan_that_does_not_commit_adds_nothing(outbox: Outbox) -> None:
    window = RateWindow("mail_per_hour", timedelta(hours=1), 10, Requests("mail"))
    refusing = outbox.engine(windows=[window], checkers=[BlastRadius(0)])
    plan = (
        PlanBuilder(SCOPE)
        .update(
            table="orders",
            statement=f"UPDATE orders SET status = 'held' WHERE id = {outbox.named('id')}",
            parameters={"id": 500},
        )
        .enqueue(sink="mail", operation="send", payload=mail(1).payload)
        .build()
    )
    result = refusing.execute(plan)
    assert not result.committed and refused_by(result) == ["blast_radius"]
    assert result.diff is not None and [w.amount for w in result.diff.windows] == [Decimal(1)]
    failing = outbox.engine(windows=[window])
    broken = (
        PlanBuilder(SCOPE)
        .enqueue(sink="mail", operation="send", payload=mail(2).payload)
        .update(table="orders", statement="UPDATE orders SET nope = 1")
        .build()
    )
    with pytest.raises(Exception, match="nope"):
        failing.execute(broken)
    assert history(outbox) == []


def _statement(outbox: Outbox, statement: str) -> EffectPlan:
    return (
        PlanBuilder(SCOPE)
        .enqueue(sink="mail", operation="send", payload=mail(1).payload)
        .update(table="orders", statement=statement)
        .build()
    )


SQLITE_REACHES: tuple[str, ...] = (
    "SELECT count(*) FROM _interlock_windows",
    "UPDATE orders SET status = (SELECT max(key) FROM _interlock_windows)",
    "DELETE FROM _interlock_windows",
    "INSERT INTO _interlock_windows VALUES ('x', 'mail_per_hour', 'agent', '5', 0)",
    "UPDATE _interlock_windows SET amount = '0.5'",
)


def _refused_every(engine: EscrowEngine, outbox: Outbox, expected: dict[str, Guidance]) -> None:
    for statement, guidance in expected.items():
        with pytest.raises(ForbiddenStatementError) as refused:
            engine.execute(_statement(outbox, statement))
        feedback = refused.value.feedback
        assert isinstance(feedback, AgentFeedback)
        (constraint,) = feedback.constraints
        assert constraint.guidance is guidance, statement


def test_agent_statements_cannot_read_or_write_window_history(outbox: Outbox) -> None:
    window = RateWindow("mail_per_hour", timedelta(hours=1), 10, Requests("mail"))
    engine = outbox.engine(windows=[window])
    assert engine.execute(requests_plan(mail(0))).committed
    if outbox.backend == "postgres":
        # The role holds no grant on the ledger, and the functions refuse.
        _refused_every(
            engine,
            outbox,
            {
                "SELECT count(*) FROM interlock.window_ledger": Guidance.UNOBSERVED_WRITE,
                "SELECT * FROM interlock.window_totals("
                "ARRAY['mail_per_hour'], ARRAY['agent'], ARRAY[3600000000::bigint])": (
                    Guidance.PROTECTED
                ),
                "SELECT interlock.window_add('\\x00'::bytea, ARRAY['mail_per_hour'], "
                "ARRAY['agent'], ARRAY[5::numeric])": Guidance.PROTECTED,
                "DELETE FROM interlock.window_ledger": Guidance.UNOBSERVED_WRITE,
            },
        )
    else:
        _refused_every(engine, outbox, dict.fromkeys(SQLITE_REACHES, Guidance.PROTECTED))
    assert history(outbox) == [("mail_per_hour", SCOPE, Decimal(1))]


def test_sqlite_closes_window_history_without_the_table_boundary(tmp_path: Any) -> None:
    """``enforce_table_access=False`` lifts the rule against writing tables the
    substrate does not observe; window history stays closed all the same."""
    from tests.outbox_env import build_sqlite_outbox

    for outbox in build_sqlite_outbox(tmp_path):
        window = RateWindow("mail_per_hour", timedelta(hours=1), 10, Requests("mail"))
        lax = SqliteSubstrate(outbox.path, tables=specs(*OBSERVED), enforce_table_access=False)
        engine = outbox.engine(windows=[window], substrate=lax)
        assert engine.execute(requests_plan(mail(0))).committed
        _refused_every(engine, outbox, dict.fromkeys(SQLITE_REACHES, Guidance.PROTECTED))
        assert history(outbox) == [("mail_per_hour", SCOPE, Decimal(1))]


@POSTGRES_ONLY
def test_postgres_reads_window_history_only_outside_a_stage(outbox: Outbox) -> None:
    """``window_totals`` refuses a stage's transaction, and any but
    ``READ COMMITTED``: the agent's statements run in nothing else."""
    import psycopg

    window = RateWindow("mail_per_hour", timedelta(hours=1), 10, Requests("mail"))
    assert outbox.engine(windows=[window]).execute(requests_plan(mail(0))).committed
    read = (
        "SELECT out_total FROM interlock.window_totals("
        "ARRAY['mail_per_hour'], ARRAY['agent'], ARRAY[3600000000::bigint])"
    )
    assert isinstance(outbox, PostgresOutbox)
    with psycopg.connect(outbox.pg.agent, autocommit=True) as conn:
        assert conn.execute(read).fetchone() == (Decimal(1),)
        with pytest.raises(psycopg.Error, match="outside every stage") as caught:
            with conn.transaction():
                conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
                conn.execute(read)
        assert caught.value.sqlstate == "IL009"


# --------------------------------------------------------------------------
# the measure is the diff's; the verdict replays
# --------------------------------------------------------------------------


def test_the_diff_carries_the_windows_and_the_verdict_replays(outbox: Outbox) -> None:
    window = RateWindow("mail_per_hour", timedelta(hours=1), 1, Requests("mail"))
    engine = outbox.engine(windows=[window])
    assert engine.execute(requests_plan(mail(0))).committed
    plan = requests_plan(mail(1))
    result = engine.execute(plan)
    assert not result.committed and result.diff is not None and result.verdict is not None
    (measure,) = result.diff.windows
    assert (measure.window, measure.key, measure.history, measure.amount) == (
        "mail_per_hour",
        SCOPE,
        Decimal(1),
        Decimal(1),
    )
    # DIFF_COMPUTED records the hash of the diff with its windows.
    (computed,) = [
        r
        for r in engine.chain.records()
        if r.record_type is RecordType.DIFF_COMPUTED and r.plan_id == plan.plan_id
    ]
    assert computed.payload_hash == result.diff.content_hash()
    assert "1 window key(s)" in computed.note
    # The verdict replays from the plan and the diff alone.
    replayed = RateWindowCheck(window).check(plan, result.diff)
    assert replayed == result.verdict.blocking
    # Another history is another diff, and another verdict.
    emptier = _with_history(result.diff, Decimal(0))
    assert emptier.content_hash() != result.diff.content_hash()
    assert RateWindowCheck(window).check(plan, emptier) == ()
    # A diff without windows hashes as it did before them.
    bare = _with_windows(result.diff, ())
    assert bare.content_hash() == _without_windows_field(result.diff)


def _with_history(diff: EffectDiff, held: Decimal) -> EffectDiff:
    return dataclasses.replace(
        diff, windows=tuple(dataclasses.replace(w, history=held) for w in diff.windows)
    )


def _with_windows(diff: EffectDiff, windows: tuple[Any, ...]) -> EffectDiff:
    return dataclasses.replace(diff, windows=windows)


def _without_windows_field(diff: EffectDiff) -> str:
    """The hash version 3 computed, for a diff with no windows."""
    from interlock.types import canonical_hash

    rows = [
        [d.table, d.primary_key, d.operation, d.before, d.after, d.tenant_id]
        for d in sorted(diff.deltas, key=lambda d: (d.table, d.primary_key, d.operation))
    ]
    fields: list[object] = [diff.plan_id, diff.substrate_id, diff.truncated, rows]
    if diff.outbound:
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
                    for o in sorted(diff.outbound, key=lambda o: o.effect_id)
                ],
            ]
        )
    return canonical_hash(fields)


def test_a_repair_keeps_what_fits_the_window(outbox: Outbox) -> None:
    window = RateWindow("mail_per_hour", timedelta(hours=1), 5, Requests("mail"))
    engine = outbox.engine(windows=[window])
    for n in range(3):
        assert engine.execute(requests_plan(mail(n))).committed
    plan = requests_plan(mail(10), mail(11), mail(12), mail(13))
    repair = engine.repair(plan)
    assert repair.proposal is not None
    assert len(repair.proposal.effects) == 2
    assert engine.execute(repair.proposal).committed
    assert sum(a for _, _, a in history(outbox)) == Decimal(5)


# --------------------------------------------------------------------------
# measures, keys, and what a window cannot measure
# --------------------------------------------------------------------------


def test_rows_inserted_and_net_change_count_as_measured(outbox: Outbox) -> None:
    refunds = RateWindow("refund_rows", timedelta(hours=1), "100", RowSum("refunds", "amount"))
    balances = RateWindow(
        "balance_raised", timedelta(hours=1), "1000", RowSum("accounts", "balance", "net"), "tenant"
    )
    engine = outbox.engine(windows=[refunds, balances], checkers=[])
    mark = outbox.named
    plan = (
        PlanBuilder(SCOPE)
        .insert(
            table="refunds",
            statement=f"INSERT INTO refunds (id, order_item_id, amount) "
            f"VALUES ({mark('id')}, 5000, {mark('a')})",
            parameters={"id": 9100, "a": "40.00"},
        )
        .insert(
            table="refunds",
            statement=f"INSERT INTO refunds (id, order_item_id, amount) "
            f"VALUES ({mark('id')}, 5000, {mark('a')})",
            parameters={"id": 9101, "a": "35.50"},
            independent=True,
        )
        .update(
            table="accounts",
            statement=f"UPDATE accounts SET balance = balance + {mark('d')}",
            parameters={"d": "10.00"},
            independent=True,
        )
        .build()
    )
    result = engine.execute(plan)
    assert result.committed, result.verdict
    assert result.diff is not None
    found = {(w.window, w.key): w.amount for w in result.diff.windows}
    assert found.pop(("refund_rows", SCOPE)) == Decimal("75.50")
    raised = {key: amount for (window, key), amount in found.items() if window == "balance_raised"}
    assert raised and set(raised) == {
        d.tenant_id for d in result.diff.deltas if d.table == "accounts"
    }
    assert all(amount % Decimal(10) == 0 for amount in raised.values())


def diff_of(
    *,
    rows: tuple[RowDelta, ...] = (),
    requests: tuple[OutboundDelta, ...] = (),
) -> EffectDiff:
    return EffectDiff(
        plan_id="p",  # type: ignore[arg-type]
        stage_id=uuid.uuid4(),
        substrate_id="sqlite",
        computed_at=datetime.now(UTC),
        deltas=rows,
        outbound=requests,
    )


def request(
    payload: dict[str, Any],
    *,
    sink: str = "payments",
    operation: str = "refund",
    tenant: str | None = None,
) -> OutboundDelta:
    return OutboundDelta(
        message_id=uuid.uuid4(),
        effect_id="e",  # type: ignore[arg-type]
        sink=sink,
        operation=operation,
        tenant_id=tenant,
        payload=payload,
        payload_hash="0" * 64,
        idempotency_key="k",
    )


PLAN = PlanBuilder("agent").enqueue(sink="mail", operation="send", payload={}).build()


@pytest.mark.parametrize(
    ("measure", "per", "diff", "expected", "problem"),
    [
        (
            Requests("payments"),
            "scope",
            diff_of(requests=(request({}), request({}))),
            {"agent": Decimal(2)},
            None,
        ),
        (Requests("payments", "capture"), "scope", diff_of(requests=(request({}),)), {}, None),
        (
            Requests("payments"),
            "tenant",
            diff_of(requests=(request({}, tenant="a"), request({}, tenant="b"), request({}))),
            {"a": Decimal(1), "b": Decimal(1), "": Decimal(1)},
            None,
        ),
        (
            Requests("payments"),
            "global",
            diff_of(requests=(request({}), request({}))),
            {"": Decimal(2)},
            None,
        ),
        (
            RequestSum("payments", "refund", "amount"),
            "scope",
            diff_of(requests=(request({"amount": "12.50"}), request({"amount": 3}))),
            {"agent": Decimal("15.50")},
            None,
        ),
        (
            RequestSum("payments", "refund", "refund.amount"),
            "scope",
            diff_of(requests=(request({"refund": {"amount": "7"}}),)),
            {"agent": Decimal(7)},
            None,
        ),
        (
            RequestSum("payments", "refund", "amount"),
            "scope",
            diff_of(requests=(request({"amount": "ten"}),)),
            {},
            "carries no number at amount",
        ),
        (
            RequestSum("payments", "refund", "amount"),
            "scope",
            diff_of(requests=(request({"amount": "-5"}),)),
            {},
            "carries a negative amount",
        ),
        (
            RowSum("refunds", "amount"),
            "scope",
            diff_of(
                rows=(
                    RowDelta("refunds", "1", None, {"amount": "5.25"}),
                    RowDelta("refunds", "2", None, {"amount": 4.75}),
                    RowDelta("refunds", "3", {"amount": "1"}, {"amount": "9"}),
                )
            ),
            {"agent": Decimal("10.00")},
            None,
        ),
        (
            RowSum("refunds", "amount"),
            "scope",
            diff_of(rows=(RowDelta("refunds", "1", None, {"amount": "-1"}),)),
            {},
            "a negative number",
        ),
        (
            RowSum("refunds", "amount"),
            "scope",
            diff_of(rows=(RowDelta("refunds", "1", None, {"amount": None}),)),
            {},
            "no number",
        ),
        (
            RowSum("accounts", "balance", "net"),
            "tenant",
            diff_of(
                rows=(
                    RowDelta("accounts", "1", {"balance": "10"}, {"balance": "25"}, "a"),
                    RowDelta("accounts", "2", {"balance": "10"}, {"balance": "2"}, "b"),
                    RowDelta("accounts", "3", {"balance": "4"}, None, "a"),
                )
            ),
            {"a": Decimal(11)},
            None,
        ),
        (
            RowSum("accounts", "balance", "net"),
            "scope",
            diff_of(
                rows=(
                    RowDelta("accounts", "1", {"balance": "10"}, {"balance": "25"}, "a"),
                    RowDelta("accounts", "2", {"balance": "20"}, {"balance": "5"}, "b"),
                )
            ),
            {},
            None,
        ),
        (
            RowSum("accounts", "balance", "net"),
            "global",
            diff_of(
                rows=(
                    RowDelta("accounts", "1", {"balance": "10"}, {"balance": "25"}, "a"),
                    RowDelta("accounts", "2", {"balance": "20"}, {"balance": "12"}, "b"),
                )
            ),
            {"": Decimal(7)},
            None,
        ),
        (
            RowSum("accounts", "balance", "net"),
            "scope",
            diff_of(rows=(RowDelta("accounts", "1", {"balance": "x"}, {"balance": "2"}),)),
            {},
            "no number",
        ),
        (Plans(), "scope", diff_of(), {"agent": Decimal(1)}, None),
        (
            Plans(),
            "tenant",
            diff_of(
                rows=(RowDelta("orders", "1", None, {}, "a"),), requests=(request({}, tenant="b"),)
            ),
            {"a": Decimal(1), "b": Decimal(1)},
            None,
        ),
        (Plans(), "tenant", diff_of(), {"": Decimal(1)}, None),
    ],
)
def test_what_a_plan_adds(
    measure: Any, per: str, diff: EffectDiff, expected: dict[str, Decimal], problem: str | None
) -> None:
    window = RateWindow("w", timedelta(hours=1), 100, measure, per)
    added, problems = window.amounts(PLAN, diff)
    assert added == expected
    if problem is None:
        assert problems == ()
    else:
        (found,) = problems
        assert problem in found
        (violation,) = RateWindowCheck(window).check(PLAN, diff)
        assert problem in violation.message


def test_a_window_without_its_measure_refuses_closed() -> None:
    """A diff that does not carry the window's measure for a key the plan
    adds to, or carries another amount, is not judged on faith."""
    window = RateWindow("w", timedelta(hours=1), 100, Requests("payments"))
    diff = diff_of(requests=(request({}),))
    (unmeasured,) = RateWindowCheck(window).check(PLAN, diff)
    assert "was not measured" in unmeasured.message
    from interlock.types import WindowMeasure

    other = dataclasses.replace(
        diff, windows=(WindowMeasure("w", "agent", Decimal(0), Decimal(5)),)
    )
    (mismatch,) = RateWindowCheck(window).check(PLAN, other)
    assert "the stage measured 5 added" in mismatch.message
    assert [c.amount for c in charges([window], PLAN, diff)] == [Decimal(1)]


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"name": "Mail"}, "lowercase"),
        ({"name": "has space"}, "lowercase"),
        ({"span": timedelta(0)}, "at least a millisecond"),
        ({"limit": -1}, "at least 0"),
        ({"limit": 1.5}, "is a number"),
        ({"limit": True}, "is a number"),
        ({"limit": "lots"}, "is a number"),
        ({"limit": "NaN"}, "finite"),
        ({"per": "team"}, "per is one of"),
        ({"measure": "requests"}, "measure is"),
    ],
)
def test_a_window_is_one_or_is_refused(kwargs: dict[str, Any], match: str) -> None:
    fields: dict[str, Any] = {
        "name": "w",
        "span": timedelta(hours=1),
        "limit": 1,
        "measure": Plans(),
        "per": "scope",
        **kwargs,
    }
    with pytest.raises(ValueError, match=match):
        RateWindow(**fields)


@pytest.mark.parametrize(
    ("build", "match"),
    [
        (lambda: Requests(""), "needs its sink"),
        (lambda: Requests("mail", " "), "needs its operation"),
        (lambda: RequestSum("payments", "refund", ""), "needs its field"),
        (lambda: RowSum("refunds", ""), "needs its column"),
        (lambda: RowSum("refunds", "amount", "sum"), "rows is one of"),
    ],
)
def test_a_measure_is_one_or_is_refused(build: Any, match: str) -> None:
    with pytest.raises(ValueError, match=match):
        build()


def test_an_engine_takes_windows_it_can_measure(outbox: Outbox) -> None:
    window = RateWindow("w", timedelta(hours=1), 1, Plans())
    with pytest.raises(ValueError, match="share a name: w"):
        outbox.engine(windows=[window, window])

    class Bare:
        substrate_id = "bare"

    with pytest.raises(ValueError, match="keeps no window history"):
        EscrowEngine(Bare(), checkers=[], windows=[window])  # type: ignore[arg-type]
    engine = outbox.engine(windows=[window])
    assert any(isinstance(c, RateWindowCheck) for c in engine._checkers)


def test_window_locks_are_stable_and_distinct() -> None:
    assert window_lock("w", "a") == window_lock("w", "a")
    assert len({window_lock("w", "a"), window_lock("w", "b"), window_lock("v", "a")}) == 3
    assert -(2**63) <= window_lock("w", "a") < 2**63


def test_only_the_built_in_check_names_a_window_to_the_agent() -> None:
    from interlock.feedback import FeedbackHint

    plan = requests_plan(mail(1), tenant="acme")
    hint = FeedbackHint(kind=Guidance.RATE_WINDOW, tenants=("acme", "globex"), window="w_1")
    trusted = sanitize(hint, plan, blocking=True, trusted=True)
    assert (trusted.window, trusted.tenants, trusted.withheld_tenants) == ("w_1", ("acme",), True)
    assert sanitize(hint, plan, blocking=True, trusted=False).window == ""
    spelled = FeedbackHint(kind=Guidance.RATE_WINDOW, window="acme's balance is 5")
    assert sanitize(spelled, plan, blocking=True, trusted=True).window == ""
    other = FeedbackHint(kind=Guidance.ROW_LIMIT, window="w_1")
    assert sanitize(other, plan, blocking=True, trusted=True).window == ""


# --------------------------------------------------------------------------
# configuration, and grants
# --------------------------------------------------------------------------

WINDOWED = """
substrate = "sqlite"
database = "x.sqlite"

[[tables]]
name = "refunds"
columns = ["id", "order_item_id", "amount"]

[[sinks]]
name = "payments"

[[sinks.operations]]
name = "refund"

[[windows]]
name = "refunds_per_agent_day"
span_seconds = 86400
limit = "10000"
measure = "request_sum"
sink = "payments"
operation = "refund"
field = "amount"

[[windows]]
name = "refund_rows"
span_seconds = 3600
limit = 50
per = "global"
measure = "row_sum"
table = "refunds"
column = "amount"
rows = "net"

[[windows]]
name = "plans_per_tenant"
span_seconds = 60
limit = 5
per = "tenant"
measure = "plans"

[[windows]]
name = "payment_calls"
span_seconds = 0.5
limit = 100
measure = "requests"
sink = "payments"
"""


def test_windows_are_configured_in_the_file(tmp_path: Any) -> None:
    from interlock.config import load_config

    path = tmp_path / "interlock.toml"
    path.write_text(WINDOWED)
    assert load_config(path).windows == (
        RateWindow(
            "refunds_per_agent_day",
            timedelta(days=1),
            "10000",
            RequestSum("payments", "refund", "amount"),
        ),
        RateWindow(
            "refund_rows", timedelta(hours=1), 50, RowSum("refunds", "amount", "net"), "global"
        ),
        RateWindow("plans_per_tenant", timedelta(minutes=1), 5, Plans(), "tenant"),
        RateWindow("payment_calls", timedelta(seconds=0.5), 100, Requests("payments")),
    )


@pytest.mark.parametrize(
    ("change", "match"),
    [
        (lambda t: t.replace('measure = "plans"', 'measure = "bogus"'), "'measure' is one of"),
        (
            lambda t: t.replace('field = "amount"', 'field = "amount"\ntable = "refunds"'),
            "takes no 'table'",
        ),
        (
            lambda t: t.replace('sink = "payments"\noperation', 'sink = "mail"\noperation'),
            "'mail' is not one of",
        ),
        (
            lambda t: t.replace('operation = "refund"\nfield', 'operation = "void"\nfield'),
            "no operation 'void'",
        ),
        (
            lambda t: t.replace('table = "refunds"\ncolumn', 'table = "orders"\ncolumn'),
            "'orders' is not one of",
        ),
        (
            lambda t: t.replace('column = "amount"\nrows', 'column = "total"\nrows'),
            "no column 'total'",
        ),
        (lambda t: t.replace('rows = "net"', 'rows = "sum"'), "rows is one of"),
        (lambda t: t.replace("limit = 50", "limit = 50.5"), "'limit' must be a decimal string"),
        (lambda t: t.replace("limit = 50", 'limit = "-1"'), "at least 0"),
        (
            lambda t: t.replace('name = "refund_rows"', 'name = "plans_per_tenant"'),
            "configured twice",
        ),
        (lambda t: t.replace('name = "refund_rows"', 'name = "Refund Rows"'), "lowercase"),
        (lambda t: t.replace('per = "tenant"', 'per = "team"'), "per is one of"),
        (lambda t: t.replace("span_seconds = 60\n", ""), "'span_seconds' must be a positive"),
        (lambda t: "windows = 5\n" + t.split("[[windows]]")[0], "array of tables"),
        (lambda t: "windows = [5]\n" + t.split("[[windows]]")[0], r"windows\[0\] is not a table"),
    ],
)
def test_a_configured_window_is_one_or_is_refused(tmp_path: Any, change: Any, match: str) -> None:
    from interlock.config import ConfigError, load_config

    path = tmp_path / "interlock.toml"
    path.write_text(change(WINDOWED))
    with pytest.raises(ConfigError, match=match):
        load_config(path)


@POSTGRES_ONLY
def test_postgres_roles_hold_their_part_of_the_windows(outbox: Outbox) -> None:
    """The stage role runs the window functions and touches no window table;
    the relay neither; nobody through PUBLIC."""
    assert isinstance(outbox, PostgresOutbox)
    functions = (
        "interlock.window_lock(bigint[])",
        "interlock.window_totals(text[], text[], bigint[])",
        "interlock.window_add(bytea, text[], text[], numeric[])",
    )

    def may(role: str, privilege: str, target: str) -> bool:
        kind = "function" if "(" in target else "table"
        (row,) = outbox.fetch(f"SELECT has_{kind}_privilege(%s, %s, %s)", role, target, privilege)
        return bool(row[0])

    stage, relay = outbox.pg.role, outbox.relay_role
    assert all(may(stage, "EXECUTE", f) for f in functions)
    assert not any(may(relay, "EXECUTE", f) for f in functions)
    for role in (stage, relay):
        assert not any(
            may(role, p, "interlock.window_ledger")
            for p in ("SELECT", "INSERT", "UPDATE", "DELETE")
        )
    assert not any(may("public", "EXECUTE", f) for f in functions)
