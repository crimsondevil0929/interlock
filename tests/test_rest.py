"""The REST substrate (:mod:`interlock.rest`): predicted, written on the version read, read back
and put back on a JSON API, here a service desk on :mod:`interlock.sim.rest`.

- A patch is predicted from the ticket as read; every checker judges the prediction; the write
  carries ``If-Match`` and the stage's request id, and the read-back holds the API to it.
- An automation the plan never sees (escalating an urgent ticket: reassigned to on-call, an
  incident opened) is caught by the read-back and put back: the stage is ``COMPENSATED``.
- A person's edit between the read and the write refuses the commit (``412``), and so does an
  edit anywhere in the account the stage read.
- A crash part-way leaves an undo that recovery finishes from.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from interlock import BlastRadius, EscrowChain, EscrowEngine, PlanBuilder, TenantIsolation
from interlock.chain import RecordType
from interlock.exceptions import (
    CompensatedError,
    ForbiddenStatementError,
    StageConflictError,
    StageError,
    SubstrateConfigurationError,
    SubstrateUnavailableError,
)
from interlock.predicted import PREDICTED
from interlock.rest import (
    RestResource,
    RestSubstrate,
    fingerprint,
    merge_diff,
    parse_statement,
    rest_tables,
)
from interlock.sim.rest import (
    AUTOMATION_ACTOR,
    Change,
    Collection,
    LoopbackRestServer,
    RuleContext,
    merge_patch,
)
from interlock.types import Compensation, EffectKind, StageState

TOKEN = "agent-token"
ACME, GLOBEX = "acct-acme", "acct-globex"
MANAGED = ("updated_at", "updated_by", "version")

TICKETS = RestResource(
    "tickets",
    "/tickets",
    columns={
        "status": "status",
        "priority": "priority",
        "assignee": "assignee",
        "parent": "parent_id",
    },
    tenant="account_id",
    managed=MANAGED,
    source="last_request",
    void={"status": "deleted"},
)
INCIDENTS = RestResource(
    "incidents",
    "/incidents",
    columns={"status": "status", "severity": "severity", "ticket": "ticket_id"},
    tenant="account_id",
    managed=MANAGED,
    source="last_request",
    void={"status": "cancelled"},
)
TYPES = (TICKETS, INCIDENTS)


def escalate(ctx: RuleContext, change: Change) -> None:
    """The desk's automation: a ticket set to urgent goes to on-call and opens an incident."""
    after, before = change.after or {}, change.before or {}
    if change.collection != "tickets" or after.get("priority") != "urgent":
        return
    if before.get("priority") == "urgent":
        return
    ctx.write("tickets", {**after, "assignee": "oncall"})
    ctx.write(
        "incidents",
        {
            "account_id": after["account_id"],
            "ticket_id": after["id"],
            "severity": "sev2",
            "status": "open",
        },
    )


@pytest.fixture
def server() -> Iterator[LoopbackRestServer]:
    found = LoopbackRestServer(
        (
            Collection("tickets", filters=("account_id", "status"), prefix="tkt", page_size=2),
            Collection("incidents", filters=("account_id",), prefix="inc"),
        ),
        tokens={TOKEN: "support-agent", "person-token": "jo@acme.test"},
        rules=[escalate],
    )
    found.start()
    for n, (account, subject) in enumerate(
        [
            (ACME, "Refund not received"),
            (ACME, "Cannot log in"),
            (ACME, "Invoice address wrong"),
            (GLOBEX, "API rate limit"),
        ],
        1,
    ):
        found.seed(
            "tickets",
            {
                "id": f"tkt-{n}",
                "account_id": account,
                "subject": subject,
                "status": "open",
                "priority": "normal",
                "assignee": "tier1",
            },
        )
    yield found
    found.stop()


class _Rest(RestSubstrate):
    """The substrate, its methods replaceable for a test (no ``__slots__``)."""


def substrate(server: LoopbackRestServer, tmp_path: Path, **kwargs: Any) -> RestSubstrate:
    kwargs.setdefault("resources", TYPES)
    return _Rest(server.url, journal=tmp_path / "journal", token=TOKEN, **kwargs)


def literal(document: Any) -> str:
    return "'" + json.dumps(document).replace("'", "''") + "'"


def patch(ticket: str, change: dict[str, Any], **parameters: Any) -> tuple[Any, ...]:
    listed = "".join(f" :{name}" for name in sorted(parameters))
    return (
        EffectKind.UPDATE,
        f"patch tickets :id {literal(change)}{listed}",
        {"id": ticket, **parameters},
        "tickets",
        "restore tickets",
    )


def create(account: str = ACME, subject: str = "Follow up") -> tuple[Any, ...]:
    template = {"account_id": ":account", "subject": ":subject", "status": "open"}
    template |= {"priority": "normal", "assignee": "tier1"}
    return (
        EffectKind.INSERT,
        f"create tickets {literal(template)} :account :subject",
        {"account": account, "subject": subject},
        "tickets",
        "void tickets",
    )


def plan(*effects: tuple[Any, ...], tenant: str = ACME) -> Any:
    builder = PlanBuilder("support-agent", intent="triage")
    for kind, statement, parameters, table, undo in effects:
        builder.add(
            kind,
            table=f"rest:{table}",
            statement=statement,
            parameters=parameters,
            tenant_id=tenant,
            compensation=Compensation(undo) if undo else None,
        )
    return builder.build()


def engine(sub: RestSubstrate, tmp_path: Path, *checkers: Any, **kwargs: Any) -> EscrowEngine:
    return EscrowEngine(
        sub,
        checkers=list(checkers) or [BlastRadius(10)],
        chain=EscrowChain(tmp_path / "chain.ilok1"),
        **kwargs,
    )


def ticket(server: LoopbackRestServer, n: int) -> dict[str, Any]:
    found = server.get("tickets", f"tkt-{n}")
    assert found is not None
    return found


# -- the language, the images, the configuration --------------------------------------------


def test_statements_parse_each_verb_and_refuse_anything_else() -> None:
    found = parse_statement('patch tickets :id \'{"status": "solved"}\'')
    assert (found.verb, found.table) == ("patch", "tickets")
    assert parse_statement("create tickets '{}' :a :b").binds == ("a", "b")
    assert parse_statement("expect-version tickets :id :v").verb == "expect-version"
    for bad, message in [
        ("delete tickets :id", "verbs"),
        ("patch", "verb, a table"),
        ("patch tickets :id", "takes"),
        ("create tickets '{}' 'x'", "lists the :parameters"),
    ]:
        with pytest.raises(ValueError, match=message):
            parse_statement(bad)


def test_merge_diff_is_the_patch_merge_patch_inverts() -> None:
    before = {"a": 1, "b": {"c": 2, "d": 3}, "e": [1, 2], "gone": True}
    after = {"a": 1, "b": {"c": 5, "d": 3}, "e": [1], "new": "x"}
    patch_ = merge_diff(before, after)
    assert patch_ == {"b": {"c": 5}, "e": [1], "gone": None, "new": "x"}
    assert merge_patch(before, patch_) == after


def test_the_image_and_the_fingerprint() -> None:
    resource = {"id": "tkt-1", "account_id": ACME, "status": "open", "priority": "normal"}
    resource |= {"assignee": "tier1", "updated_at": "now", "last_request": "r1"}
    image = TICKETS.image(resource)
    assert (image["id"], image["tenant"], image["status"], image["parent"]) == (
        "tkt-1",
        ACME,
        "open",
        None,
    )
    moved = {**resource, "updated_at": "later", "last_request": "r2"}
    assert TICKETS.image(moved) == image
    assert fingerprint({**resource, "subject": "x"}, TICKETS.ignored) != image["fingerprint"]
    assert [t.name for t in rest_tables(TYPES)] == ["tickets", "incidents"]
    assert TICKETS.spec().tenant_column == "tenant"


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"table": "Bad"}, "lowercase identifier"),
        ({"path": "tickets"}, "not /a/collection/path"),
        ({"columns": {"tenant": "x"}}, "every type's own"),
        ({"columns": {"a": "x"}, "partitions": {"a": "y"}}, "share a name"),
        ({"columns": {"a": "x..y"}}, "dotted field path"),
        ({"write": "post"}, "'patch' or 'put'"),
    ],
)
def test_a_resource_type_is_checked(kwargs: dict[str, Any], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        RestResource(**{"table": "tickets", "path": "/tickets", **kwargs})


def test_the_substrate_is_configured_sensibly(server: LoopbackRestServer, tmp_path: Path) -> None:
    with pytest.raises(SubstrateConfigurationError, match="over HTTPS"):
        RestSubstrate("http://desk.example.com/api", resources=TYPES, journal=tmp_path)
    with pytest.raises(SubstrateConfigurationError, match="at least one"):
        RestSubstrate(server.url, resources=(), journal=tmp_path)
    with pytest.raises(SubstrateConfigurationError, match="its own table"):
        RestSubstrate(server.url, resources=(TICKETS, TICKETS), journal=tmp_path)
    sub = substrate(server, tmp_path)
    assert sub.capabilities.measurement == PREDICTED and sub.capabilities.requires_compensation
    assert sub.observed_tables == {"tickets", "incidents"} and sub.commit_markers


@pytest.mark.parametrize(
    ("effect", "message"),
    [
        ((EffectKind.UPDATE, "patch tickets :id '{}'", {"id": "tkt-1"}, "tickets", None), "undo"),
        (
            (
                EffectKind.UPDATE,
                "patch tickets :id '{}'",
                {"id": "tkt-1"},
                "tickets",
                "void tickets",
            ),
            "undone by 'restore tickets'",
        ),
        (
            (
                EffectKind.UPDATE,
                'patch tickets :id \'{"updated_at": "x"}\'',
                {"id": "tkt-1"},
                "tickets",
                "restore tickets",
            ),
            "may not set updated_at",
        ),
        (
            (
                EffectKind.UPDATE,
                'patch tickets :id \'{"a": ":b"}\'',
                {"id": "1"},
                "tickets",
                "restore tickets",
            ),
            "does not list",
        ),
        (
            (
                EffectKind.UPDATE,
                "patch nothing :id '{}'",
                {"id": "1"},
                "tickets",
                "restore nothing",
            ),
            "no resource type",
        ),
        (
            (
                EffectKind.UPDATE,
                "patch tickets :id '{}'",
                {"id": "a/b"},
                "tickets",
                "restore tickets",
            ),
            "not a resource id",
        ),
    ],
)
def test_the_substrate_refuses_at_admission(
    server: LoopbackRestServer, tmp_path: Path, effect: tuple[Any, ...], message: str
) -> None:
    sub = substrate(server, tmp_path)
    built = plan(effect)
    found = sub.reject_reason(built.effects[0])
    assert found is not None and message in found


# -- predicted, written, read back ------------------------------------------------------


def test_a_patch_is_predicted_written_on_the_version_read_and_read_back(
    server: LoopbackRestServer, tmp_path: Path
) -> None:
    sub = substrate(server, tmp_path)
    result = engine(sub, tmp_path).execute(plan(patch("tkt-1", {"status": "pending"})))
    assert result.committed, result.verdict
    assert result.diff is not None
    [row] = result.diff.deltas
    assert row.before is not None and row.after is not None
    assert (row.table, row.primary_key, row.tenant_id) == ("tickets", "tkt-1", ACME)
    assert (row.before["status"], row.after["status"]) == ("open", "pending")
    assert ticket(server, 1)["status"] == "pending"
    assert ticket(server, 1)["last_request"] == str(result.diff.stage_id)
    [write] = [e for e in server.audit_events() if e["action"] == "write"]
    assert write["request_id"] == str(result.diff.stage_id) and write["status"] == 200
    assert ("PATCH", "/api/tickets/tkt-1") in server.requests


def test_a_create_is_at_an_id_the_stage_assigns(server: LoopbackRestServer, tmp_path: Path) -> None:
    sub = substrate(server, tmp_path)
    result = engine(sub, tmp_path).execute(plan(create(subject="Callback at 3pm")))
    assert result.committed
    assert result.diff is not None
    [row] = result.diff.deltas
    assert row.before is None and row.after is not None
    created = server.get("tickets", row.primary_key)
    assert created is not None and created["subject"] == "Callback at 3pm"
    assert created["account_id"] == ACME and str(row.primary_key).startswith("tickets-")


def test_an_automation_the_plan_never_saw_is_put_back(
    server: LoopbackRestServer, tmp_path: Path
) -> None:
    sub = substrate(server, tmp_path)
    built = engine(sub, tmp_path)
    before = ticket(server, 2)
    with pytest.raises(CompensatedError, match="not what was predicted") as caught:
        built.execute(plan(patch("tkt-2", {"priority": "urgent"})))
    assert any("assignee 'tier1' -> 'oncall'" in d for d in caught.value.discrepancies)
    assert any("incidents/" in d and "was created" in d for d in caught.value.discrepancies)
    after = ticket(server, 2)
    assert {k: after[k] for k in ("priority", "assignee", "status")} == {
        k: before[k] for k in ("priority", "assignee", "status")
    }
    [incident] = server.find("incidents", account_id=ACME)
    assert incident["status"] == "cancelled"
    assert built.chain.records()[-1].record_type is RecordType.COMPENSATED
    writes = [e for e in server.audit_events() if e["actor"] == AUTOMATION_ACTOR]
    assert writes and all(e["request_id"] == writes[0]["request_id"] for e in writes)


def test_a_change_someone_else_set_off_is_left_for_a_person(
    server: LoopbackRestServer, tmp_path: Path
) -> None:
    def meddle(ctx: RuleContext, change: Change) -> None:
        if change.collection == "tickets" and (change.after or {}).get("status") == "pending":
            server.write("tickets", {**ticket(server, 3), "assignee": "jo"})

    server.add_rule(meddle)
    sub = substrate(server, tmp_path)
    with pytest.raises(CompensatedError, match="left alone, for a person"):
        engine(sub, tmp_path).execute(plan(patch("tkt-1", {"status": "pending"})))
    assert ticket(server, 1)["status"] == "open"
    assert ticket(server, 3)["assignee"] == "jo"


def test_a_persons_edit_after_the_read_refuses_the_commit(
    server: LoopbackRestServer, tmp_path: Path
) -> None:
    sub = substrate(server, tmp_path)
    built = plan(patch("tkt-1", {"status": "pending"}))
    handle = sub.open(built)
    try:
        sub.apply(handle, built.effects[0])
        sub.diff(handle)
        sub.write_undo(handle)
        server.write("tickets", {**ticket(server, 1), "priority": "high"})
        with pytest.raises(StageConflictError, match="tickets/tkt-1"):
            sub.commit(handle)
    finally:
        sub.close(handle)
    assert ticket(server, 1)["status"] == "open" and ticket(server, 1)["priority"] == "high"


def test_an_edit_anywhere_in_the_account_refuses_the_commit(
    server: LoopbackRestServer, tmp_path: Path
) -> None:
    class Racing(_Rest):
        def diff(self, handle: Any) -> Any:
            measured = super().diff(handle)
            server.write("tickets", {**ticket(server, 3), "status": "solved"})
            return measured

    sub = Racing(server.url, resources=TYPES, journal=tmp_path / "journal", token=TOKEN)
    built = engine(sub, tmp_path)
    with pytest.raises(StageConflictError, match="tickets/tkt-3 changed"):
        built.execute(plan(patch("tkt-1", {"status": "pending"})))
    assert ticket(server, 1)["status"] == "open"
    kinds = [r.record_type for r in built.chain.records()]
    assert kinds[-1] is RecordType.ABORTED


def test_the_last_instant_is_the_apis_own_412(server: LoopbackRestServer, tmp_path: Path) -> None:
    sub = substrate(server, tmp_path)
    real = sub._moved

    def then_edit(stage: Any) -> list[str]:
        found = real(stage)
        server.write("tickets", {**ticket(server, 1), "priority": "low"})
        return found

    sub._moved = then_edit  # type: ignore[method-assign]
    with pytest.raises(StageConflictError, match="HTTP 412"):
        engine(sub, tmp_path).execute(plan(patch("tkt-1", {"status": "pending"})))
    assert ticket(server, 1)["status"] == "open"


def test_the_tenant_partitions_and_the_allowlist(
    server: LoopbackRestServer, tmp_path: Path
) -> None:
    sub = substrate(server, tmp_path)
    both = plan(patch("tkt-1", {"status": "pending"}), patch("tkt-4", {"status": "pending"}))
    result = engine(sub, tmp_path, TenantIsolation(1)).execute(both)
    assert not result.committed and "tenant_isolation" in result.blocked_by
    assert ticket(server, 4)["status"] == "open"
    fenced = substrate(server, tmp_path, tenants=(ACME,))
    with pytest.raises(StageError, match="not one a plan may write"):
        engine(fenced, tmp_path).execute(plan(patch("tkt-4", {"status": "x"}), tenant=GLOBEX))


def test_expect_version_pins_what_the_approvers_saw(
    server: LoopbackRestServer, tmp_path: Path
) -> None:
    sub = substrate(server, tmp_path)
    pinned = (
        EffectKind.UPDATE,
        "expect-version tickets :id :version",
        {"id": "tkt-1", "version": '"1"'},
        "tickets",
        "restore tickets",
    )
    assert engine(sub, tmp_path).execute(plan(pinned, patch("tkt-1", {"status": "x"}))).committed
    with pytest.raises(StageConflictError, match="the state it was approved on is gone"):
        engine(sub, tmp_path).execute(plan(pinned))


def test_a_version_field_in_the_body(server: LoopbackRestServer, tmp_path: Path) -> None:
    versioned = RestResource(
        "tickets",
        "/tickets",
        columns={"status": "status"},
        tenant="account_id",
        version="version",
        managed=MANAGED,
        source="last_request",
        write="put",
    )
    sub = substrate(server, tmp_path, resources=(versioned,))
    assert engine(sub, tmp_path).execute(plan(patch("tkt-1", {"status": "pending"}))).committed
    assert ticket(server, 1)["version"] == 2
    built = plan(patch("tkt-1", {"status": "solved"}))
    handle = sub.open(built)
    try:
        sub.apply(handle, built.effects[0])
        sub.diff(handle)
        sub.write_undo(handle)
        sub._moved = lambda stage: []  # type: ignore[method-assign]
        server.write("tickets", {**ticket(server, 1), "priority": "low"})
        with pytest.raises(StageConflictError, match="HTTP 409"):
            sub.commit(handle)
    finally:
        sub.close(handle)


def test_lists_are_followed_page_by_page(server: LoopbackRestServer, tmp_path: Path) -> None:
    sub = substrate(server, tmp_path)
    result = engine(sub, tmp_path).execute(plan(patch("tkt-1", {"status": "pending"})))
    assert result.committed
    pages = [p for m, p in server.requests if m == "GET" and "cursor=" in p]
    assert pages, "the account's three tickets span two pages of two"


def test_a_failed_second_write_puts_back_the_first(
    server: LoopbackRestServer, tmp_path: Path
) -> None:
    sub = substrate(server, tmp_path)
    server.fail_next("tickets", "tkt-2", 503)
    two = plan(patch("tkt-1", {"status": "pending"}), patch("tkt-2", {"status": "pending"}))
    with pytest.raises(CompensatedError, match="HTTP 503"):
        engine(sub, tmp_path).execute(two)
    assert ticket(server, 1)["status"] == "open" and ticket(server, 2)["status"] == "open"


def test_a_crash_part_way_is_put_back_by_recovery(
    server: LoopbackRestServer, tmp_path: Path
) -> None:
    sub = substrate(server, tmp_path)
    two = plan(patch("tkt-1", {"status": "pending"}), patch("tkt-3", {"status": "pending"}))
    handle = sub.open(two)
    for effect in two.effects:
        sub.apply(handle, effect)
    sub.diff(handle)
    undo = sub.write_undo(handle)
    stage_id = handle.stage_id
    # The process writes the first ticket, as the stage would, and dies.
    server.write("tickets", {**ticket(server, 1), "status": "pending"})
    recovered = substrate(server, tmp_path)
    assert recovered.resolve_intent(stage_id) is False
    assert recovered.compensated(stage_id) == undo
    assert ticket(server, 1)["status"] == "open"
    assert recovered.resolve_intent(stage_id) is None  # its undo is spent


def test_a_crash_after_every_write_recovers_as_committed(
    server: LoopbackRestServer, tmp_path: Path
) -> None:
    sub = substrate(server, tmp_path)
    one = plan(patch("tkt-1", {"status": "pending"}))
    handle = sub.open(one)
    sub.apply(handle, one.effects[0])
    sub.diff(handle)
    sub.write_undo(handle)
    server.write("tickets", {**ticket(server, 1), "status": "pending"})
    assert substrate(server, tmp_path).resolve_intent(handle.stage_id) is True


def test_a_resource_neither_as_written_nor_as_read_is_for_an_operator(
    server: LoopbackRestServer, tmp_path: Path
) -> None:
    sub = substrate(server, tmp_path)
    one = plan(patch("tkt-1", {"status": "pending"}))
    handle = sub.open(one)
    sub.apply(handle, one.effects[0])
    sub.diff(handle)
    sub.write_undo(handle)
    server.write("tickets", {**ticket(server, 1), "status": "escalated"})
    assert substrate(server, tmp_path).resolve_intent(handle.stage_id) is None
    assert substrate(server, tmp_path).resolve_intent(uuid.uuid4()) is None


def test_a_refused_write_records_compensated_state(
    server: LoopbackRestServer, tmp_path: Path
) -> None:
    sub = substrate(server, tmp_path)
    built = engine(sub, tmp_path)
    with pytest.raises(CompensatedError):
        built.execute(plan(patch("tkt-2", {"priority": "urgent"})))
    assert StageState.COMPENSATED.value == "compensated"


def test_a_write_through_the_engine_is_forbidden_when_not_a_statement(
    server: LoopbackRestServer, tmp_path: Path
) -> None:
    sub = substrate(server, tmp_path)
    bad = plan((EffectKind.UPDATE, "DELETE FROM tickets", {}, "tickets", "restore tickets"))
    with pytest.raises(ForbiddenStatementError):
        engine(sub, tmp_path).execute(bad)


def test_oversized_response_raises_substrate_unavailable(
    server: LoopbackRestServer, tmp_path: Path
) -> None:
    sub = substrate(server, tmp_path, max_response_bytes=32)
    assert sub.max_response_bytes == 32
    with pytest.raises(SubstrateUnavailableError, match="exceeded 32 bytes"):
        sub._api.call("GET", "/tickets/tkt-1")


def test_repeating_pagination_cursor_raises_stage_error(
    server: LoopbackRestServer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sub = substrate(server, tmp_path)
    # 1. Test page budget limit
    with pytest.raises(StageError, match="repeating pagination cursor or exceeded 1 pages"):
        sub._api.find(TICKETS, "account_id", ACME, limit=10, max_pages=1)

    # 2. Test cyclic cursor detection
    def mock_cyclic_call(self: Any, method: str, path: str, *args: Any, **kwargs: Any) -> Any:
        return type(
            "Reply",
            (),
            {"status": 200, "body": {"data": [{"id": "tkt-1"}], "next": path}, "etag": None},
        )()

    monkeypatch.setattr(sub._api.__class__, "call", mock_cyclic_call)
    with pytest.raises(StageError, match="repeating pagination cursor or exceeded"):
        sub._api.find(TICKETS, "account_id", ACME, limit=10, max_pages=10)

