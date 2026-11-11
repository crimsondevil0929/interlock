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
    CommitUnsettledError,
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
from tests.children import Child

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


# -- bounds on what one answer and one listing may be (1.5.1, settable in 1.5.2) --------------


def test_an_answer_longer_than_the_bound_is_not_read(
    server: LoopbackRestServer, tmp_path: Path
) -> None:
    sub = substrate(server, tmp_path, max_response_bytes=32)
    assert sub.max_response_bytes == 32
    with pytest.raises(SubstrateUnavailableError, match=r"longer than 32 bytes \(max_response_"):
        sub._api.call("GET", "/tickets/tkt-1")
    with pytest.raises(SubstrateUnavailableError, match=r"HTTP 404 answer .* longer than 8 bytes"):
        substrate(server, tmp_path, max_response_bytes=8)._api.call("GET", "/tickets/nothing")


def test_a_listing_stops_at_the_page_bound(server: LoopbackRestServer, tmp_path: Path) -> None:
    """The account's three tickets span two pages of two."""
    sub = substrate(server, tmp_path, max_pages=1)
    assert sub.max_pages == 1
    with pytest.raises(StageError, match=r"runs past 1 page \(max_pages\)"):
        sub._api.find(TICKETS, "account_id", ACME, limit=10)
    assert (
        len(
            substrate(server, tmp_path, max_pages=2)._api.find(
                TICKETS, "account_id", ACME, limit=10
            )
        )
        == 3
    )


class _Looping:
    """The API, every page of a list naming itself as the next one."""

    def __init__(self, inner: Any) -> None:
        self._inner = inner

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    def call(self, method: str, path: str, *args: Any, **kwargs: Any) -> Any:
        reply = self._inner.call(method, path, *args, **kwargs)
        if method == "GET" and isinstance(reply.body, dict) and "data" in reply.body:
            reply.body["next"] = path
        return reply


def test_a_next_link_that_loops_is_refused(server: LoopbackRestServer, tmp_path: Path) -> None:
    sub = substrate(server, tmp_path)
    looping = _Looping(sub._api)
    with pytest.raises(StageError, match="leads back to a page already read"):
        type(sub._api).find(looping, TICKETS, "account_id", ACME, limit=10)  # type: ignore[arg-type]


# -- a commit that cannot finish is settled by reading back, never recorded as aborted (1.5.2) --
#
# Once a write has gone out, a failure says nothing about whether it landed. The commit
# raises CommitUnsettledError, the intent stays open, and resolve_intent settles it: at once
# if the API answers, at the next recovery if not.


class _Flaky:
    """The API, failing as a test says. ``listings``: how many lists fail once a write has
    gone out (a negative number: every one). ``write``: ``"no-answer"`` for a write that
    lands and whose answer is lost, ``"never-sent"`` for one that does not leave."""

    def __init__(
        self,
        inner: Any,
        *,
        listings: int = 0,
        error: Exception | None = None,
        write: str = "ok",
    ) -> None:
        self._inner = inner
        self._listings = listings
        self._error = error or SubstrateUnavailableError("cannot reach the API: timed out")
        self._write = write
        self.wrote = False

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    def call(self, method: str, path: str, *args: Any, **kwargs: Any) -> Any:
        if method == "GET":
            return self._inner.call(method, path, *args, **kwargs)
        if self._write == "never-sent":
            raise SubstrateUnavailableError("cannot reach the API: connection refused")
        reply = self._inner.call(method, path, *args, **kwargs)
        self.wrote = True
        if self._write == "no-answer":
            self._write = "ok"
            raise SubstrateUnavailableError("cannot reach the API: timed out")
        return reply

    def find(self, kind: Any, parameter: str, value: str, *, limit: int) -> Any:
        if self.wrote and self._listings:
            self._listings -= 1
            raise self._error
        return self._inner.find(kind, parameter, value, limit=limit)


def flaky(sub: RestSubstrate, **kwargs: Any) -> RestSubstrate:
    sub._api = _Flaky(sub._api, **kwargs)  # type: ignore[assignment]
    return sub


def kinds(run: EscrowEngine) -> list[RecordType]:
    return [record.record_type for record in run.chain.records()]


def journal(tmp_path: Path) -> list[Path]:
    return sorted((tmp_path / "journal").glob("*"))


def test_a_read_back_that_fails_once_is_settled_at_once(
    server: LoopbackRestServer, tmp_path: Path
) -> None:
    run = engine(flaky(substrate(server, tmp_path), listings=1), tmp_path)
    result = run.execute(plan(patch("tkt-1", {"status": "pending"})))
    assert result.committed and ticket(server, 1)["status"] == "pending"
    last = run.chain.records()[-1]
    assert last.record_type is RecordType.COMMITTED
    assert "the system read back as predicted" in last.note
    assert RecordType.ABORTED not in kinds(run) and not journal(tmp_path)


@pytest.mark.parametrize(
    "error",
    [
        SubstrateUnavailableError("cannot reach the API: timed out"),
        StageError("listing /tickets leads back to a page already read"),
    ],
    ids=["the API is unreachable", "the listing is refused"],
)
def test_a_read_back_that_cannot_be_read_leaves_the_intent_open(
    server: LoopbackRestServer, tmp_path: Path, error: Exception
) -> None:
    """The reproduction of the 1.5.1 bug: the write stayed on the API and the chain said
    ``aborted``. Now the intent stays open, and the next recovery reads the account back."""
    run = engine(flaky(substrate(server, tmp_path), listings=-1, error=error), tmp_path)
    with pytest.raises(CommitUnsettledError, match="A write had been sent"):
        run.execute(plan(patch("tkt-1", {"status": "pending"})))
    assert ticket(server, 1)["status"] == "pending", "the write is on the API"
    assert RecordType.ABORTED not in kinds(run)
    assert kinds(run)[-1] is RecordType.COMMIT_INTENT and len(run.chain.unresolved_intents()) == 1
    assert journal(tmp_path), "the undo stays while the stage is unsettled"
    run.chain.close()
    (record,) = engine(substrate(server, tmp_path), tmp_path).recover()
    assert record.record_type is RecordType.COMMITTED
    assert "read back as predicted" in record.note and not journal(tmp_path)


def test_recovery_reads_the_whole_account_back_and_undoes_a_cascade(
    server: LoopbackRestServer, tmp_path: Path
) -> None:
    """E4-14 at recovery: the ticket was written, the desk's rule reassigned it and opened an
    incident, and the commit never got to read back. Recovery does, and puts all of it back."""
    run = engine(flaky(substrate(server, tmp_path), listings=-1), tmp_path)
    with pytest.raises(CommitUnsettledError):
        run.execute(plan(patch("tkt-1", {"priority": "urgent"})))
    assert ticket(server, 1)["assignee"] == "oncall", "the rule ran"
    assert [i["status"] for i in server.find("incidents", account_id=ACME)] == ["open"]
    run.chain.close()
    (record,) = engine(substrate(server, tmp_path), tmp_path).recover()
    assert record.record_type is RecordType.COMPENSATED
    assert "read-back not as predicted (2 discrepancies" in record.note
    assert "tickets/tkt-1: assignee 'tier1' -> 'oncall', not as predicted" in record.note
    assert "incidents/" in record.note and "was created" in record.note
    assert "2 resources put back" in record.note
    after = ticket(server, 1)
    assert (after["priority"], after["assignee"]) == ("normal", "tier1")
    assert [i["status"] for i in server.find("incidents", account_id=ACME)] == ["cancelled"]
    assert not journal(tmp_path)


def test_a_cascade_found_when_settling_at_once_is_compensated(
    server: LoopbackRestServer, tmp_path: Path
) -> None:
    run = engine(flaky(substrate(server, tmp_path), listings=1), tmp_path)
    with pytest.raises(CompensatedError, match="the system was read back") as caught:
        run.execute(plan(patch("tkt-1", {"priority": "urgent"})))
    assert caught.value.result is not None
    assert caught.value.result.state is StageState.COMPENSATED  # type: ignore[attr-defined]
    assert len(caught.value.discrepancies) == 2 and caught.value.restored == 2
    assert kinds(run)[-1] is RecordType.COMPENSATED
    assert ticket(server, 1)["priority"] == "normal"
    assert [i["status"] for i in server.find("incidents", account_id=ACME)] == ["cancelled"]


def test_a_write_whose_answer_is_lost_is_read_back_and_stands(
    server: LoopbackRestServer, tmp_path: Path
) -> None:
    run = engine(flaky(substrate(server, tmp_path), write="no-answer"), tmp_path)
    result = run.execute(plan(patch("tkt-1", {"status": "pending"})))
    assert result.committed and ticket(server, 1)["status"] == "pending"
    assert kinds(run)[-1] is RecordType.COMMITTED


def test_a_write_that_never_left_is_aborted_and_nothing_changed(
    server: LoopbackRestServer, tmp_path: Path
) -> None:
    run = engine(flaky(substrate(server, tmp_path), write="never-sent"), tmp_path)
    with pytest.raises(StageError, match=r"nothing of stage .* is on it"):
        run.execute(plan(patch("tkt-1", {"status": "pending"})))
    assert ticket(server, 1)["status"] == "open"
    assert kinds(run)[-1] is RecordType.ABORTED and not journal(tmp_path)


def test_a_failure_before_any_write_is_still_a_plain_failure(
    server: LoopbackRestServer, tmp_path: Path
) -> None:
    sub = substrate(server, tmp_path)

    def unreadable(stage: Any) -> list[str]:
        raise SubstrateUnavailableError("cannot reach the API: timed out")

    sub._moved = unreadable  # type: ignore[method-assign]
    run = engine(sub, tmp_path)
    with pytest.raises(SubstrateUnavailableError):
        run.execute(plan(patch("tkt-1", {"status": "pending"})))
    assert ticket(server, 1)["status"] == "open" and kinds(run)[-1] is RecordType.ABORTED


def nudge(ctx: RuleContext, change: Change) -> None:
    """A rule that changes a neighbor: a ticket set to pending raises tkt-2's priority."""
    after, before = change.after or {}, change.before or {}
    if change.collection != "tickets" or after.get("id") != "tkt-1":
        return
    if after.get("status") == "pending" and before.get("status") != "pending":
        other = ctx.get("tickets", "tkt-2")
        assert other is not None
        ctx.write("tickets", {**other, "priority": "high"})


def test_recovery_puts_back_a_neighbor_the_stages_request_changed(
    server: LoopbackRestServer, tmp_path: Path
) -> None:
    server._rules.append(nudge)
    run = engine(flaky(substrate(server, tmp_path), listings=-1), tmp_path)
    with pytest.raises(CommitUnsettledError):
        run.execute(plan(patch("tkt-1", {"status": "pending"})))
    assert ticket(server, 2)["priority"] == "high"
    run.chain.close()
    (record,) = engine(substrate(server, tmp_path), tmp_path).recover()
    assert record.record_type is RecordType.COMPENSATED
    assert (
        "tickets/tkt-2: priority 'normal' -> 'high', which the plan did not change" in record.note
    )
    assert ticket(server, 1)["status"] == "open" and ticket(server, 2)["priority"] == "normal"


def test_an_undo_written_before_1_5_2_leaves_such_a_neighbor_to_a_person(
    server: LoopbackRestServer, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """An older undo holds each neighbor's fingerprint and no image, so recovery cannot put
    one back: it puts back what it can, says so, and the intent stays open."""
    server._rules.append(nudge)
    run = engine(flaky(substrate(server, tmp_path), listings=-1), tmp_path)
    with pytest.raises(CommitUnsettledError):
        run.execute(plan(patch("tkt-1", {"status": "pending"})))
    run.chain.close()
    (undo,) = journal(tmp_path)
    document = json.loads(undo.read_text())
    for listed in document["scope"].values():
        for entry in listed:
            del entry["image"]
    undo.write_text(json.dumps(document))
    again = engine(substrate(server, tmp_path), tmp_path)
    assert again.recover() == ()
    assert "this undo holds no image of it" in caplog.text
    assert ticket(server, 1)["status"] == "open", "what the stage wrote itself is put back"
    assert ticket(server, 2)["priority"] == "high" and journal(tmp_path)
    assert len(again.chain.unresolved_intents()) == 1


def test_someone_elses_change_in_the_gap_is_named_and_never_put_back(
    server: LoopbackRestServer, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    run = engine(flaky(substrate(server, tmp_path), listings=-1), tmp_path)
    with pytest.raises(CommitUnsettledError):
        run.execute(plan(patch("tkt-1", {"status": "pending"})))
    server.write("tickets", {**ticket(server, 2), "priority": "low"})  # a person, meanwhile
    run.chain.close()
    (record,) = engine(substrate(server, tmp_path), tmp_path).recover()
    assert record.record_type is RecordType.COMPENSATED, "a difference is never accepted"
    assert ticket(server, 1)["status"] == "open" and ticket(server, 2)["priority"] == "low"
    assert "tickets/tkt-2 differ from what the stage read and are not its own" in caplog.text


def test_a_change_in_the_gap_with_nothing_written_is_a_plain_rollback(
    server: LoopbackRestServer, tmp_path: Path
) -> None:
    sub = substrate(server, tmp_path)
    one = plan(patch("tkt-1", {"status": "pending"}))
    handle = sub.open(one)
    sub.apply(handle, one.effects[0])
    sub.diff(handle)
    sub.write_undo(handle)
    server.write("tickets", {**ticket(server, 2), "priority": "low"})
    recovered = substrate(server, tmp_path)
    assert recovered.resolve_intent(handle.stage_id) is False
    assert (
        recovered.compensated(handle.stage_id) is None
        and recovered.settlement(handle.stage_id) is None
    )


# -- end to end: a process killed between its write and the read-back (1.5.2) -----------------


def killed_before_the_read_back(
    server: LoopbackRestServer, tmp_path: Path, change: dict[str, Any]
) -> uuid.UUID:
    """Run the commit in a child process and SIGKILL it once every write has landed, before
    the read-back starts. The stage's id."""
    scenario = {"server": server.url, "directory": str(tmp_path), "change": change}
    child = Child(scenario, tmp_path, 1, module="tests.predicted_child")
    stage_id = child.wait_for("written").stage_id
    child.kill()
    return stage_id


def test_a_process_killed_before_the_read_back_is_settled_by_the_next_one(
    server: LoopbackRestServer, tmp_path: Path
) -> None:
    killed_before_the_read_back(server, tmp_path, {"status": "pending"})
    assert ticket(server, 1)["status"] == "pending", "the write landed before the kill"
    run = engine(substrate(server, tmp_path), tmp_path)
    assert kinds(run)[-1] is RecordType.COMMIT_INTENT and journal(tmp_path)
    (record,) = run.recover()
    assert record.record_type is RecordType.COMMITTED
    assert "read back as predicted" in record.note
    assert ticket(server, 1)["status"] == "pending" and not journal(tmp_path)
    assert run.recover() == (), "settled once"


def test_a_process_killed_after_a_write_that_set_off_a_rule_has_it_all_put_back(
    server: LoopbackRestServer, tmp_path: Path
) -> None:
    """The proof of E4-14 at recovery. Before 1.5.2 this recovered as committed: the ticket
    was as predicted but for the rule's reassignment, and nobody listed the account again."""
    stage_id = killed_before_the_read_back(server, tmp_path, {"priority": "urgent"})
    before = ticket(server, 1)
    assert (before["priority"], before["assignee"]) == ("urgent", "oncall")
    (incident,) = server.find("incidents", account_id=ACME)
    assert incident["status"] == "open" and incident["last_request"] == str(stage_id)
    run = engine(substrate(server, tmp_path), tmp_path)
    (record,) = run.recover()
    assert record.record_type is RecordType.COMPENSATED
    assert "read-back not as predicted (2 discrepancies" in record.note
    after = ticket(server, 1)
    assert (after["priority"], after["assignee"]) == ("normal", "tier1")
    (incident,) = server.find("incidents", account_id=ACME)
    assert incident["status"] == "cancelled", "voided, as the type declares, never deleted"
    assert [t["id"] for t in server.find("tickets", account_id=GLOBEX)] == ["tkt-4"]
    assert not journal(tmp_path) and run.chain.unresolved_intents() == ()
