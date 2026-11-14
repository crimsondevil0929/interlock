"""1.9.0: one request delivered now, requests that wait for their turn, and MCP's revisions.

- **Delivered now.** :meth:`Relay.deliver` makes one committed request in the caller's
  process, through the same claim, breaker, call record and signed outcome as any relay,
  and hands back what the sink answered: the body itself, held in memory only.
- **A turn.** A plan with ``turn`` enqueues its requests held for the turn. Nothing sends
  them until an operator's signed intent releases the turn; cancelling the turn means none
  is ever made. A request a warrant holds stays held for the warrant.
- **MCP.** A client probes with ``server/discover`` and falls back to ``initialize``; a
  number argument is recorded as its decimal string and sent as a number.
"""

from __future__ import annotations

import json
import sys
import uuid
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any

import pytest

from interlock import PlanBuilder
from interlock.exceptions import PlanError
from interlock.mcp import (
    LEGACY_VERSIONS,
    MODERN_VERSIONS,
    UNSUPPORTED_VERSION,
    Era,
    McpAdapter,
    McpCallError,
    McpRefusedError,
    StdioServer,
    classify,
    decimals,
    handshake,
    numbers_on_the_wire,
)
from interlock.outbound import DEAD_LETTER, OperationSpec, SinkRegistry, SinkSpec
from interlock.relay import DELIVERED, PERMANENT, Delivery
from interlock.types import TURN_HELD, EffectId
from tests.fakesink import status
from tests.outbox_env import BACKENDS, SCOPE, Outbox, build_either, mail, page, sms


@pytest.fixture(params=BACKENDS)
def outbox(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Outbox]:
    yield from build_either(request, tmp_path)


# --------------------------------------------------------------------------
# delivered now
# --------------------------------------------------------------------------


def test_a_request_is_delivered_now_and_its_answer_comes_back(outbox: Outbox) -> None:
    _, (message,) = outbox.commit(mail(1))
    with outbox.relay() as relay:
        done = relay.deliver(message)
    assert done.delivered and done.state == DELIVERED
    assert done.result is not None and done.result.body is not None
    answer = json.loads(done.result.body)
    assert answer["duplicate"] is False and answer["id"]
    assert outbox.state(message) == "delivered"
    (sent,) = [e for e in outbox.log(message) if e.event == "delivered"]
    assert sent.response_digest == done.result.response_digest
    assert b"duplicate" not in repr(done.result).encode(), "the body is in no repr"
    assert outbox.attestations().problems == ()
    outbox.verify_logs()


def test_a_request_another_relay_delivered_comes_back_without_an_answer(
    outbox: Outbox,
) -> None:
    _, (message,) = outbox.commit(mail(2))
    with outbox.relay() as first:
        first.run_once()
    with outbox.relay() as second:
        done = second.deliver(message)
    assert done.delivered and done.result is None
    assert len(outbox.sink("mail").calls) == 1, "made once, by whichever relay claimed it"


def test_a_refused_call_comes_back_at_once_with_what_the_sink_said(outbox: Outbox) -> None:
    sink = outbox.sink("sms")
    sink.script(status(422))
    _, (message,) = outbox.commit(sms(1))
    with outbox.relay() as relay:
        done = relay.deliver(message)
    assert done.state == "dead" and done.result is not None
    assert done.result.outcome == PERMANENT and done.result.status_code == 422


def test_a_retry_not_due_in_time_is_not_waited_for(outbox: Outbox) -> None:
    sink = outbox.sink("mail")
    sink.script(status(503, retry_after=30))
    _, (message,) = outbox.commit(mail(3))
    with outbox.relay() as relay:
        from datetime import timedelta

        done = relay.deliver(message, wait=timedelta(seconds=2))
    assert done.state == "pending" and done.result is not None
    assert done.result.status_code == 503


def test_delivering_now_refuses_a_sink_it_could_never_claim(outbox: Outbox) -> None:
    from datetime import timedelta

    from interlock.relay import Relay
    from tests.outbox_env import relay_signer

    _, (message,) = outbox.commit(sms(2))
    with Relay(
        outbox.store(),
        adapters={"mail": outbox.adapters()["mail"]},
        breaker=outbox.breaker(),
        signer=relay_signer(),
        lease=timedelta(seconds=10),
        timeout=timedelta(seconds=2),
    ) as relay:
        with pytest.raises(ValueError, match="no adapter"):
            relay.deliver(message)
        assert relay.deliver(uuid.uuid4()).state == "unknown"


# --------------------------------------------------------------------------
# a turn
# --------------------------------------------------------------------------


def test_a_turn_holds_its_requests_until_it_is_released(outbox: Outbox) -> None:
    _, (first,) = outbox.commit(mail(10), turn="turn-1")
    _, (second,) = outbox.commit(mail(11), turn="turn-1")
    _, (other,) = outbox.commit(mail(12), turn="turn-2")
    assert {outbox.state(m) for m in (first, second, other)} == {"held"}
    (event,) = outbox.log(first)
    assert (event.event, event.actor, event.state_after) == ("held", "outbox", "held")
    assert event.detail is not None and "turn-1" in event.detail
    ops = outbox.operations()
    assert ops.held(SCOPE) == [], "waiting for a turn is no hold a person decides"
    assert ops.turn_held("turn-1") == {"turn-1": [first, second]}
    assert set(ops.turn_held()) == {"turn-1", "turn-2"}
    with outbox.relay() as relay:
        outbox.drain(relay)
        assert outbox.sink("mail").calls == [], "nothing is sent while its turn is open"
        assert relay.deliver(first).state == "held"
        with outbox.signed("fiduciary") as operator:
            outcome = operator.release_turn("turn-1")
            assert outcome is not None and outcome.intent.body["reason"] == (
                "turn turn-1 committed"
            )
            assert operator.release_turn("turn-1") is None, "nothing is left to release"
        assert relay.deliver(first).delivered
        outbox.drain(relay)
    assert outbox.state(second) == "delivered" and outbox.state(other) == "held"
    assert len(outbox.sink("mail").calls) == 2
    assert outbox.verify_operators().problems == ()
    outbox.verify_logs()


def test_a_turn_that_did_not_finish_makes_none_of_its_requests(outbox: Outbox) -> None:
    _, (first,) = outbox.commit(mail(20), turn="t_1")
    _, (lookalike,) = outbox.commit(mail(21), turn="tX1")
    with outbox.signed("fiduciary") as operator:
        outcome = operator.cancel_turn("t_1", reason="a later call of the turn was refused")
    assert outcome is not None and [r.message_id for r in outcome.rows] == [first]
    assert outbox.state(first) == "cancelled"
    assert outbox.state(lookalike) == "held", "a turn's id is matched exactly, not as a pattern"
    with outbox.relay() as relay:
        outbox.drain(relay)
    assert outbox.sink("mail").calls == []
    assert outbox.verify_operators().problems == ()
    outbox.verify_logs()


def test_a_request_a_warrant_holds_stays_held_for_the_warrant(outbox: Outbox) -> None:
    from tests.outbox_env import RELAY_SINKS

    held = tuple(
        SinkSpec(
            s.name,
            (OperationSpec("page", hold=True),),
            idempotency="none",
            unknown_outcome=DEAD_LETTER,
            backoff_base=s.backoff_base,
            backoff_cap=s.backoff_cap,
        )
        if s.name == "pager"
        else s
        for s in RELAY_SINKS
    )
    outbox.reinstall(held)
    builder = PlanBuilder(SCOPE, turn="turn-3")
    builder.enqueue(
        sink="pager", operation="page", payload=page(1).payload, effect_id=EffectId("p0")
    )
    plan = builder.build()
    result = outbox.engine(sinks=SinkRegistry(held), checkers=[]).execute(plan)
    assert result.committed, result.feedback
    (message,) = outbox.messages(plan.plan_id)
    assert outbox.state(message) == "held"
    ops = outbox.operations()
    assert ops.turn_held("turn-3") == {}, "a release of the turn does not reach it"
    assert ops.held(SCOPE) == [message]


def test_a_turn_is_in_the_plan_hash_only_when_set() -> None:
    from datetime import UTC, datetime

    def built(turn: str | None) -> Any:
        builder = PlanBuilder(
            SCOPE,
            trajectory_id="t",
            plan_id="plan-000000000001",  # type: ignore[arg-type]
            created_at=datetime(2026, 11, 13, tzinfo=UTC),
            turn=turn,
        )
        builder.enqueue(
            sink="mail", operation="send", payload=mail(1).payload, effect_id=EffectId("r0")
        )
        return builder.build()

    plain, turned = built(None), built("turn-9")
    assert plain.turn is None and turned.turn == "turn-9"
    assert plain.content_hash() != turned.content_hash()
    assert built(None).content_hash() == plain.content_hash()
    with pytest.raises(PlanError, match="turn"):
        PlanBuilder(SCOPE, turn="no spaces")
    assert TURN_HELD == "held for turn "


# --------------------------------------------------------------------------
# MCP's revisions
# --------------------------------------------------------------------------


def _client() -> dict[str, str]:
    return {"name": "test", "version": "0"}


def _server(answers: Mapping[str, Any]) -> tuple[Any, list[tuple[str, dict[str, Any]]]]:
    sent: list[tuple[str, dict[str, Any]]] = []

    def request(method: str, params: Mapping[str, Any], seconds: float) -> Mapping[str, Any]:
        sent.append((method, dict(params)))
        answer = answers.get(method)
        if isinstance(answer, Exception):
            raise answer
        if answer is None:
            raise McpRefusedError("method not found", code=-32601)
        return dict(answer)

    return request, sent


def test_a_modern_server_is_spoken_to_with_its_revision_in_every_request() -> None:
    request, sent = _server({"server/discover": {"supportedVersions": ["2026-07-28"]}})
    era = handshake(request, lambda _: None, _client(), timeout=1.0)
    assert era == Era("2026-07-28", modern=True)
    assert [m for m, _ in sent] == ["server/discover"]
    meta = sent[0][1]["_meta"]
    assert meta["io.modelcontextprotocol/protocolVersion"] == "2026-07-28"
    assert meta["io.modelcontextprotocol/clientCapabilities"] == {}
    params = era.params({"name": "x", "arguments": {}}, _client())
    assert params["_meta"]["io.modelcontextprotocol/protocolVersion"] == "2026-07-28"
    assert Era("2025-11-25", modern=False).params({"name": "x"}, _client()) == {"name": "x"}


def test_an_unsupported_version_error_is_a_modern_server_not_a_fallback() -> None:
    refused = McpRefusedError(
        "Unsupported protocol version",
        code=UNSUPPORTED_VERSION,
        data={"supported": ["2026-07-28", "2025-11-25"], "requested": "x"},
    )
    request, sent = _server({"server/discover": refused})
    assert handshake(request, lambda _: None, _client(), timeout=1.0).modern
    assert [m for m, _ in sent] == ["server/discover"], "never initialize a modern server"
    request, _ = _server(
        {
            "server/discover": McpRefusedError(
                "no", code=UNSUPPORTED_VERSION, data={"supported": ["2099-01-01"]}
            )
        }
    )
    with pytest.raises(McpCallError, match="none is a revision"):
        handshake(request, lambda _: None, _client(), timeout=1.0)


@pytest.mark.parametrize(
    "probe",
    [
        McpRefusedError("method not found", code=-32601),
        McpRefusedError("not initialized", code=-32600),
        McpCallError("silence", sent=True),
    ],
)
def test_any_other_answer_to_the_probe_is_an_older_server(probe: Exception) -> None:
    notified: list[str] = []
    request, sent = _server(
        {"server/discover": probe, "initialize": {"protocolVersion": "2025-06-18"}}
    )
    era = handshake(request, notified.append, _client(), timeout=1.0)
    assert era == Era("2025-06-18", modern=False)
    assert [m for m, _ in sent] == ["server/discover", "initialize"]
    assert sent[1][1]["protocolVersion"] == LEGACY_VERSIONS[0] == "2025-11-25"
    assert notified == ["notifications/initialized"]
    request, _ = _server(
        {"server/discover": probe, "initialize": {"protocolVersion": "2023-01-01"}}
    )
    with pytest.raises(McpCallError, match="does not speak"):
        handshake(request, lambda _: None, _client(), timeout=1.0)
    assert MODERN_VERSIONS == ("2026-07-28",)


_DUAL = """
import json, sys
modern = sys.argv[1] == "modern"
for line in sys.stdin:
    message = json.loads(line)
    if "id" not in message:
        continue
    method, params = message["method"], message.get("params", {})
    if method == "server/discover":
        if not modern:
            print(json.dumps({"jsonrpc": "2.0", "id": message["id"],
                              "error": {"code": -32601, "message": "unknown"}}), flush=True)
            continue
        result = {"resultType": "complete", "supportedVersions": ["2026-07-28"],
                  "capabilities": {"tools": {}}}
    elif method == "initialize":
        result = {"protocolVersion": "2025-11-25", "capabilities": {"tools": {}}}
    else:
        meta = params.get("_meta", {})
        args = params["arguments"]
        result = {"resultType": "complete",
                  "content": [{"type": "text", "text": json.dumps(
                      {"args": args, "version": meta.get(
                          "io.modelcontextprotocol/protocolVersion")})}]}
    print(json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}), flush=True)
"""


@pytest.mark.parametrize(("mode", "version"), [("modern", "2026-07-28"), ("legacy", None)])
def test_a_relay_speaks_to_old_and_new_servers_and_sends_numbers_as_numbers(
    tmp_path: Path, mode: str, version: str | None
) -> None:
    script = tmp_path / "server.py"
    script.write_text(_DUAL)
    server = StdioServer([sys.executable, str(script), mode])
    try:
        adapter = McpAdapter(server, numbers={"set_price": ["price", "lines[].qty"]})
        recorded = decimals(
            {"sku": "A-1", "price": 12.5, "lines": [{"qty": 2}, {"qty": 0.25}]},
            ["price", "lines[].qty"],
        )
        assert recorded == {"sku": "A-1", "price": "12.5", "lines": [{"qty": "2"}, {"qty": "0.25"}]}
        result = adapter.send(_delivery("set_price", recorded))
        assert result.outcome == DELIVERED and result.body is not None
        text = json.loads(json.loads(result.body)["content"][0]["text"])
        assert text["args"] == {"sku": "A-1", "price": 12.5, "lines": [{"qty": 2}, {"qty": 0.25}]}
        assert text["version"] == version
        assert server.era is not None and server.era.modern == (mode == "modern")
    finally:
        server.close()


def test_numbers_are_strings_in_the_record_and_numbers_on_the_wire() -> None:
    recorded = decimals({"a": 1e-7, "b": -0.0, "c": 10, "d": "7", "e": True}, list("abcde"))
    assert recorded == {"a": "0.0000001", "b": "0", "c": "10", "d": "7", "e": True}
    assert numbers_on_the_wire(recorded, list("abcde")) == {
        "a": 1e-7,
        "b": 0,
        "c": 10,
        "d": 7,
        "e": True,
    }
    assert decimals({"x": {"y": 1.5}}, ["x.y", "missing.z"]) == {"x": {"y": "1.5"}}
    assert numbers_on_the_wire({"x": "not a number"}, ["x"]) == {"x": "not a number"}


def test_a_result_that_asks_for_input_is_not_a_delivery() -> None:
    asked = classify({"resultType": "input_required", "inputRequests": {}})
    assert asked.outcome == PERMANENT and "input" in asked.detail
    assert classify({"content": []}).outcome == DELIVERED, "an older server's result is complete"


def _delivery(operation: str, payload: Mapping[str, Any]) -> Delivery:
    from agentgov.receipts.canonical import canonical_bytes

    return Delivery(
        message_id=uuid.uuid4(),
        sink="shop",
        operation=operation,
        idempotency_key="k",
        payload=canonical_bytes(dict(payload)),
        payload_hash="0" * 64,
        attempt=1,
        tenant_id=None,
        timeout=5.0,
    )


def test_a_chain_left_open_at_exit_releases_its_claim_quietly(tmp_path: Path) -> None:
    """A claim released by its finalizer as the interpreter shuts down imports nothing
    then: no "Exception ignored ... sys.meta_path is None" on the way out."""
    import subprocess

    script = (
        "import sys\n"
        "from interlock.chain import EscrowChain\n"
        f"chain = EscrowChain({str(tmp_path / 'escrow.chain')!r})\n"
        "sys.modules.pop('fcntl', None)\n"
        "held = [chain]\n"
    )
    done = subprocess.run(  # noqa: S603 - this interpreter, the script above
        [sys.executable, "-c", script], capture_output=True, text=True, timeout=60, check=False
    )
    assert done.returncode == 0, done.stderr
    assert "Exception ignored" not in done.stderr, done.stderr


def test_an_open_stage_of_a_turn_holds_its_requests(outbox: Outbox) -> None:
    from interlock import BlastRadius

    engine = outbox.engine(checkers=[BlastRadius(0)])
    with engine.stage(SCOPE, turn="turn-open") as stage:
        stage.enqueue(sink="mail", operation="send", payload=mail(30).payload)
        result = stage.settle()
    assert result is not None and result.committed and result.plan.turn == "turn-open"
    (message,) = outbox.messages(result.plan.plan_id)
    assert outbox.state(message) == "held"
    assert outbox.operations().turn_held("turn-open") == {"turn-open": [message]}
