"""Budgeted recovery (M3): a fixed ladder, paid from a reserve, recorded before it acts.

Tested four ways:

- The ladder, against scripted halts: constraints tighten before the agent is
  talked to, one rung per step, the same halts always take the same steps, and
  the recovery is over when nothing is left.
- The transcript: appended to and never edited, with a harness's edits caught
  between steps. A property test checks that no halt's own words, which are the
  operator's, ever reach the agent.
- The budget, in a real AgentGov ledger: the reserve carved out beside the
  scope, holds and settlements, an overdrawn or spent reserve, a halted scope
  that stays halted, and the ledger verified.
- End to end on the back-office schema, in SQLite and PostgreSQL: a scripted
  model whose batch is refused finishes through the repair its guidance offers,
  and one that thrashes on a lookup is walked down the ladder by AgentGov's own
  cognitive breaker.
"""

from __future__ import annotations

import copy
import dataclasses
import json
import logging
import sqlite3
from collections.abc import Callable
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from agentgov import BudgetManager
from agentgov.cognitive import CognitiveBreaker, CognitivePolicy
from agentgov.exceptions import (
    AgentThrashingError,
    CircuitOpenError,
    DenialOfWalletError,
    RunawayLoopDetectedError,
)
from agentgov.receipts import HmacKey, ReceiptLog
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from interlock import EscrowEngine, LedgerAnchor
from interlock.exceptions import (
    AdmissionError,
    AnchorError,
    RecoveryError,
    RecoveryExhaustedError,
    ScopeHaltedError,
    ToolRevokedError,
)
from interlock.feedback import AgentFeedback
from interlock.receipts import ReceiptIssuer
from interlock.records import RecordKind, RecordLog, check_anchors
from interlock.recovery import (
    LADDER,
    TOOL_CHANGES_BETA,
    Channel,
    Directive,
    RecoveryPolicy,
    RecoveryRuntime,
    RecoveryStep,
    Rung,
    Trip,
    TripKind,
    spent_out,
    transcript_head,
)
from tests.conftest import Pg
from tests.plans import pg_engine, pg_placeholder, sqlite_engine, support_batch

TOOLS = ("lookup", "apply_plan")
NO_REPEAT = Directive(
    "no-repeat",
    "Do not repeat a tool call that has already returned; use the results you have.",
    frozenset({TripKind.THRASHING}),
)
WRAP_UP = Directive(
    "wrap-up",
    "Stop calling tools. Answer from what you have and say what is missing.",
    frozenset({TripKind.THRASHING, TripKind.BUDGET}),
)
BASE = RecoveryPolicy(
    reserve=Decimal("1.00"),
    step_estimate=Decimal("0.10"),
    directives=(NO_REPEAT, WRAP_UP),
    token_ceiling=1024,
)
REPLY = {"role": "assistant", "content": [{"type": "text", "text": "Understood."}]}


def policy(**overrides: Any) -> RecoveryPolicy:
    return dataclasses.replace(BASE, **overrides)


def governor(path: Path | None = None) -> BudgetManager:
    gov = BudgetManager.open_sqlite(str(path)) if path is not None else BudgetManager()
    gov.open_root("org", "10")
    gov.delegate("org", "support-agent", "5")
    return gov


def runtime_for(
    gov: BudgetManager, log: RecordLog | None = None, **overrides: Any
) -> RecoveryRuntime:
    return RecoveryRuntime(
        gov,
        "support-agent",
        policy(**overrides),
        log if log is not None else RecordLog(HmacKey.generate(), log_id="support"),
        tools=TOOLS,
        trajectory="ticket-9001",
    )


def history() -> list[object]:
    """A transcript in Messages API shape, halted before its last call ran."""
    return [
        {"role": "user", "content": "Hold order 500 for acme and tell me its total."},
        {
            "role": "assistant",
            "content": [
                {"type": "text", "text": "Looking it up."},
                {"type": "tool_use", "id": "toolu_01", "name": "lookup", "input": {"order": 500}},
            ],
        },
        {
            "role": "user",
            "content": [
                {"type": "tool_result", "tool_use_id": "toolu_01", "content": "open, 45.00"}
            ],
        },
        {
            "role": "assistant",
            "content": [
                {"type": "tool_use", "id": "toolu_02", "name": "lookup", "input": {"order": 500}}
            ],
        },
    ]


def thrash(tool: str = "lookup", scope: str = "support-agent", reason: str = "") -> Trip:
    return Trip(
        TripKind.THRASHING,
        scope,
        tool=tool,
        detector="exact_repeat",
        reason=reason or "2 byte-identical calls to 'lookup' in a row",
    )


def again(step: RecoveryStep, n: int, tool: str = "lookup") -> list[object]:
    """The step's transcript, with the model calling ``tool`` once more."""
    call = {"type": "tool_use", "id": f"toolu_r{n}", "name": tool, "input": {"order": 500}}
    return [*step.messages, {"role": "assistant", "content": [call]}]


def text_of(message: dict[str, Any]) -> str:
    content = message["content"]
    if isinstance(content, str):
        return content
    return "".join(block.get("text", "") for block in content)


# --------------------------------------------------------------------------
# the reserve
# --------------------------------------------------------------------------


def test_the_reserve_is_carved_out_of_the_scope_and_sits_beside_it() -> None:
    gov = governor()
    runtime = runtime_for(gov)
    assert runtime.recovery_scope == "support-agent/recovery"
    assert gov.node("support-agent/recovery").parent_id == "org"
    assert gov.available("support-agent") == Decimal("4.00")
    assert gov.available("support-agent/recovery") == Decimal("1.00")
    assert gov.available("org") == Decimal("5.00")
    body = runtime.opened.body
    assert body["funding"] == {"source": "carved", "from": "support-agent", "amount": "1.00000000"}
    assert body["policy_digest"] == runtime.policy.digest and body["tools"] == list(TOOLS)
    assert runtime.trajectory == "ticket-9001/recovery"
    gov.verify_integrity()


def test_a_root_scope_is_funded_from_the_treasury_or_a_named_scope() -> None:
    gov = BudgetManager()
    gov.open_root("support-agent", "5")
    gov.open_root("ops-reserve", "3")
    key = HmacKey.generate()
    rootless = RecoveryRuntime(gov, "support-agent", BASE, RecordLog(key))
    assert gov.node("support-agent/recovery").parent_id is None
    assert rootless.opened.body["funding"]["source"] == "treasury"
    assert gov.available("support-agent") == Decimal("5")

    gov.open_root("billing-agent", "5")
    named = RecoveryRuntime(gov, "billing-agent", policy(funding="ops-reserve"), RecordLog(key))
    assert gov.node("billing-agent/recovery").parent_id == "ops-reserve"
    assert gov.available("ops-reserve") == Decimal("2.00")
    assert named.opened.body["funding"] == {
        "source": "delegated",
        "from": "ops-reserve",
        "amount": "1.00000000",
    }
    gov.verify_integrity()


def test_a_reserve_that_cannot_be_funded_is_refused() -> None:
    gov = governor()
    with pytest.raises(RecoveryError, match="cannot fund"):
        runtime_for(gov, reserve=Decimal("6"))
    assert gov.available("support-agent") == Decimal("5")  # nothing moved
    with pytest.raises(RecoveryError, match="not registered"):
        RecoveryRuntime(gov, "nobody", BASE, RecordLog(HmacKey.generate()))


# --------------------------------------------------------------------------
# the ladder
# --------------------------------------------------------------------------


def test_the_ladder_tightens_before_it_talks() -> None:
    gov = governor()
    runtime = runtime_for(gov)
    messages = history()
    steps: list[RecoveryStep] = []
    for n in range(1, 6):
        step = runtime.recover(thrash(), messages, max_tokens=4096)
        runtime.settle(step, "0.04")
        steps.append(step)
        messages = again(step, n)
    assert [s.rung for s in steps] == [
        Rung.REVOKE_TOOL,
        Rung.OPERATOR_DIRECTIVE,
        Rung.OPERATOR_DIRECTIVE,
        Rung.TOKEN_CEILING,
        Rung.GUIDANCE,
    ]
    revoke, first, second, ceiling, guidance = steps

    # The halted call is answered first, then the tool is withdrawn in place.
    results, removal = revoke.appended
    assert results["role"] == "user"
    assert results["content"] == [
        {
            "type": "tool_result",
            "tool_use_id": "toolu_02",
            "content": "Not run: this call repeated earlier calls without progress.",
            "is_error": True,
        }
    ]
    assert removal == {
        "role": "system",
        "content": [{"type": "tool_removal", "tool": {"type": "tool_reference", "name": "lookup"}}],
    }
    assert revoke.betas == (TOOL_CHANGES_BETA,) and revoke.tools == ("apply_plan",)
    assert (revoke.tool, revoke.max_tokens) == ("lookup", 4096)

    assert first.appended[-1] == {"role": "system", "content": NO_REPEAT.text}
    assert second.appended[-1] == {"role": "system", "content": WRAP_UP.text}
    assert (first.directive, second.directive, first.betas) == ("no-repeat", "wrap-up", ())

    assert ceiling.max_tokens == 1024 and "1024 tokens" in text_of(ceiling.appended[-1])
    assert guidance.appended[-1]["role"] == "user"
    assert text_of(guidance.appended[-1]).startswith("Your recent tool calls repeated")
    assert guidance.max_tokens == 1024  # the ceiling stays down

    with pytest.raises(ToolRevokedError, match="lookup"):
        runtime.check_tool("lookup")
    runtime.check_tool("apply_plan")
    assert runtime.max_tokens(4096) == 1024 and runtime.max_tokens(500) == 500
    assert runtime.revoked == ("lookup",) and runtime.granted == ("apply_plan",)
    with pytest.raises(RecoveryExhaustedError, match="no rung"):
        runtime.recover(thrash(), messages, max_tokens=4096)
    gov.verify_integrity()


def test_the_same_halts_always_take_the_same_steps() -> None:
    trips = [thrash(), thrash(), Trip(TripKind.BUDGET, "support-agent"), thrash("apply_plan")]
    trips.append(thrash())

    def run() -> list[tuple[Any, ...]]:
        runtime = runtime_for(governor())
        messages = history()
        seen = []
        for n, trip in enumerate(trips):
            step = runtime.recover(trip, messages, max_tokens=4096)
            runtime.settle(step, "0.01")
            body = step.record.body
            seen.append((step.rung, step.appended, step.max_tokens, step.tools, body["transcript"]))
            messages = again(step, n)
        return seen

    first = run()
    assert first == run()
    assert [rung for rung, *_ in first] == [
        Rung.REVOKE_TOOL,
        Rung.OPERATOR_DIRECTIVE,
        Rung.OPERATOR_DIRECTIVE,  # wrap-up answers a spent budget too
        Rung.REVOKE_TOOL,
        Rung.TOKEN_CEILING,
    ]


def test_a_policy_switches_rungs_off_but_never_reorders_them() -> None:
    assert LADDER == (Rung.REVOKE_TOOL, Rung.OPERATOR_DIRECTIVE, Rung.TOKEN_CEILING, Rung.GUIDANCE)
    bare = runtime_for(governor(), revocable=frozenset({"apply_plan"}), directives=())
    step = bare.recover(thrash(), history(), max_tokens=4096)
    assert step.rung is Rung.TOKEN_CEILING  # lookup is not revocable here
    bare.settle(step, "0.01")
    assert bare.recover(thrash(), again(step, 1), max_tokens=4096).rung is Rung.GUIDANCE

    quiet = runtime_for(governor(), directives=(), token_ceiling=None, guidance=False)
    step = quiet.recover(thrash(), history(), max_tokens=4096)
    quiet.settle(step, "0.01")
    with pytest.raises(RecoveryExhaustedError, match="no rung"):
        quiet.recover(thrash(), again(step, 1), max_tokens=4096)


def test_a_refused_plan_is_left_to_guidance_by_default() -> None:
    runtime = runtime_for(governor())
    refused = Trip(TripKind.REFUSED, "support-agent", tool="apply_plan", reason="blocked")
    step = runtime.recover(refused, history(), max_tokens=4096)
    assert step.rung is Rung.GUIDANCE and runtime.revoked == ()
    runtime.settle(step, "0.01")
    with pytest.raises(RecoveryExhaustedError, match="refused halt"):
        runtime.recover(refused, again(step, 1), max_tokens=4096)  # same guidance twice: no


def test_the_step_limit_ends_the_recovery() -> None:
    runtime = runtime_for(governor(), max_steps=1)
    step = runtime.recover(thrash(), history(), max_tokens=4096)
    runtime.settle(step, "0.01")
    with pytest.raises(RecoveryExhaustedError, match="allows 1 recovery steps"):
        runtime.recover(thrash(), again(step, 1), max_tokens=4096)
    assert runtime.taken == 1 and len(runtime.steps) == 1


# --------------------------------------------------------------------------
# the transcript
# --------------------------------------------------------------------------


def test_the_transcript_is_appended_to_and_never_edited() -> None:
    runtime = runtime_for(governor())
    messages = history()
    step = runtime.recover(thrash(), messages, max_tokens=4096)
    assert len(step.messages) == len(messages) + len(step.appended)
    assert all(a is b for a, b in zip(step.messages, messages, strict=False))
    body = step.record.body["transcript"]
    assert body["before"] == {"count": 4, "head": transcript_head(messages)}
    assert body["after"] == {"count": len(step.messages), "head": transcript_head(step.messages)}
    assert transcript_head(step.messages, 4) == transcript_head(messages)
    runtime.settle(step, "0.02")

    with pytest.raises(RecoveryError, match="no model call has answered"):
        runtime.recover(thrash(), step.messages, max_tokens=4096)
    edited = copy.deepcopy([*step.messages, REPLY])
    opening = edited[0]
    assert isinstance(opening, dict)
    opening["content"] = "Hold order 600 instead."
    with pytest.raises(RecoveryError, match="edited"):
        runtime.recover(thrash(), edited, max_tokens=4096)
    with pytest.raises(RecoveryError, match="edited"):
        runtime.recover(thrash(), [*step.messages[1:], REPLY], max_tokens=4096)
    assert runtime.recover(thrash(), [*step.messages, REPLY], max_tokens=4096).rung is (
        Rung.OPERATOR_DIRECTIVE
    )


def test_every_unrun_tool_call_is_answered_in_one_turn() -> None:
    runtime = runtime_for(governor())
    parallel = {
        "role": "assistant",
        "content": [
            {"type": "tool_use", "id": "a", "name": "lookup", "input": {}},
            {"type": "tool_use", "id": "b", "name": "apply_plan", "input": {}},
        ],
    }
    step = runtime.recover(
        Trip(TripKind.RUNAWAY, "support-agent"), [history()[0], parallel], max_tokens=4096
    )
    results = step.appended[0]
    assert [b["tool_use_id"] for b in results["content"]] == ["a", "b"]
    assert {b["content"] for b in results["content"]} == {
        "Not run: calls were arriving faster than this task allows."
    }
    assert step.rung is Rung.TOKEN_CEILING and step.appended[1]["role"] == "system"


def test_after_a_final_answer_a_step_speaks_in_a_user_turn() -> None:
    runtime = runtime_for(governor())
    done = [history()[0], {"role": "assistant", "content": [{"type": "text", "text": "Done."}]}]
    step = runtime.recover(thrash(), done, max_tokens=4096)
    assert step.channel is Channel.USER and step.betas == ()
    assert step.appended == (
        {
            "role": "user",
            "content": [
                {
                    "type": "text",
                    "text": "The tool lookup is no longer available for this task; a call "
                    "to it will not run.",
                }
            ],
        },
    )


def test_the_user_channel_leaves_the_tool_list_alone() -> None:
    runtime = runtime_for(governor(), channel=Channel.USER)
    step = runtime.recover(thrash(), history(), max_tokens=4096)
    assert step.channel is Channel.USER and step.betas == ()
    assert text_of(step.appended[-1]).startswith("The tool lookup is no longer available")
    runtime.settle(step, "0.01")
    step = runtime.recover(thrash(), again(step, 1), max_tokens=4096)
    assert text_of(step.appended[-1]) == f"<system-reminder>{NO_REPEAT.text}</system-reminder>"
    with pytest.raises(ToolRevokedError):
        runtime.check_tool("lookup")
    assert RecoveryRuntime.refusal("toolu_9") == {
        "type": "tool_result",
        "tool_use_id": "toolu_9",
        "content": "Not run: this tool was revoked for the rest of the task.",
        "is_error": True,
    }


class Block:
    """Stands in for an SDK content block: an object with ``to_dict()``."""

    def __init__(self, **fields: object) -> None:
        self.fields = fields

    def to_dict(self) -> dict[str, object]:
        return dict(self.fields)


def test_sdk_objects_in_the_transcript_are_read_as_their_dicts() -> None:
    call = {"type": "tool_use", "id": "t1", "name": "lookup", "input": {"order": 500}}
    as_objects: list[object] = [
        {"role": "user", "content": "hi"},
        {"role": "assistant", "content": [Block(**call)]},
    ]
    as_dicts: list[object] = [
        {"role": "user", "content": "hi"},
        {"role": "assistant", "content": [call]},
    ]
    assert transcript_head(as_objects) == transcript_head(as_dicts)
    step = runtime_for(governor()).recover(thrash(), as_objects, max_tokens=100)
    assert step.appended[0]["content"][0]["tool_use_id"] == "t1"
    assert step.messages[1] is as_objects[1]
    with pytest.raises(TypeError, match="not JSON"):
        transcript_head([{"role": "user", "content": object()}])


@settings(
    max_examples=60,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
@given(
    secret=st.text(alphabet="0123456789abcdef", min_size=16, max_size=32),
    kind=st.sampled_from(list(TripKind)),
    channel=st.sampled_from(list(Channel)),
    tool=st.sampled_from([*TOOLS, None]),
)
def test_a_halts_own_words_never_reach_the_agent(
    secret: str, kind: TripKind, channel: Channel, tool: str | None
) -> None:
    """The reason is the operator's: a thrashing detector's evidence, a
    denial's amounts. It goes into the records and never into a message."""
    marker = f"sk-{secret}"
    runtime = runtime_for(governor(), channel=channel)
    trip = Trip(kind, "support-agent", tool=tool, detector=marker, reason=f"globex {marker} 900")
    messages = history()
    for n in range(len(LADDER) + 2):
        try:
            step = runtime.recover(trip, messages, max_tokens=4096)
        except RecoveryExhaustedError:
            break
        runtime.settle(step, "0.01")
        sent = json.dumps(step.appended)
        assert marker not in sent and "globex" not in sent
        assert marker in step.record.body["trip"]["reason"]
        messages = again(step, n)


# --------------------------------------------------------------------------
# the budget
# --------------------------------------------------------------------------


def test_each_step_holds_then_settles_in_the_recovery_scope() -> None:
    gov = governor()
    runtime = runtime_for(gov)
    step = runtime.recover(thrash(), history(), max_tokens=4096)
    assert gov.available("support-agent/recovery") == Decimal("0.90")
    hold = step.record.body["hold"]
    assert hold == {
        "authorization": str(step.authorization.authorization_id),
        "amount": "0.10000000",
    }
    with pytest.raises(RecoveryError, match="not settled"):
        runtime.recover(thrash(), again(step, 1), max_tokens=4096)
    record = runtime.settle(step, "0.04")
    assert gov.available("support-agent/recovery") == Decimal("0.96")
    assert record.body["cost"] == "0.04000000"
    assert record.body["step_record"] == {"seq": step.record.seq, "hash": step.record.record_hash}
    assert Decimal(record.body["available"]) == Decimal("0.96") and not record.body["overdrawn"]
    with pytest.raises(RecoveryError, match="not awaiting"):
        runtime.settle(step, "0.01")
    gov.verify_integrity()


def test_an_overdrawn_step_is_recorded_before_the_error_and_ends_recovery() -> None:
    gov = governor()
    log = RecordLog(HmacKey.generate())
    runtime = runtime_for(gov, log, reserve=Decimal("0.10"))
    step = runtime.recover(thrash(), history(), max_tokens=4096)
    with pytest.raises(DenialOfWalletError):
        runtime.settle(step, "0.25")
    settled = log.records()[-1]
    assert settled.kind == RecordKind.RECOVERY_SETTLED
    assert settled.body["overdrawn"] is True and settled.body["entry"] is not None
    with pytest.raises(RecoveryExhaustedError, match="halted"):
        runtime.recover(thrash(), again(step, 1), max_tokens=4096)
    gov.verify_integrity()


def test_a_spent_reserve_ends_the_recovery() -> None:
    runtime = runtime_for(governor(), reserve=Decimal("0.20"))
    step = runtime.recover(thrash(), history(), max_tokens=4096)
    runtime.settle(step, "0.05")
    step = runtime.recover(thrash(), again(step, 1), max_tokens=4096)
    runtime.settle(step, "0.08")
    with pytest.raises(RecoveryExhaustedError, match="reserve has"):
        runtime.recover(thrash(), again(step, 2), max_tokens=4096)


def test_the_halted_scope_stays_halted_while_recovery_spends() -> None:
    gov = governor()
    gov.trip("support-agent", "cognitive breaker [exact_repeat]: 2 byte-identical calls")
    runtime = runtime_for(gov)
    step = runtime.recover(thrash(), history(), max_tokens=4096)
    runtime.settle(step, "0.03")
    held = runtime.hold("0.05")
    runtime.capture(held, "0.02")
    assert gov.is_halted("support-agent") and not gov.is_halted("support-agent/recovery")
    with pytest.raises(CircuitOpenError):
        gov.authorize("support-agent", "0.01")
    assert gov.available("support-agent/recovery") == Decimal("0.95")
    gov.verify_integrity()


def test_close_voids_an_unsettled_step_and_returns_the_rest() -> None:
    gov = governor()
    runtime = runtime_for(gov)
    runtime.recover(thrash(), history(), max_tokens=4096)
    record = runtime.close()
    assert record is not None and record.kind == RecordKind.RECOVERY_CLOSED
    assert record.body["voided_step"] == 1 and record.body["revoked"] == ["lookup"]
    assert Decimal(record.body["returned"]) == Decimal("1.00")
    assert Decimal(record.body["spent"]) == 0
    assert gov.available("support-agent/recovery") == 0 and gov.available("org") == Decimal("6")
    assert runtime.close() is None
    with pytest.raises(RecoveryError, match="closed"):
        runtime.recover(thrash(), history(), max_tokens=4096)
    with pytest.raises(RecoveryError, match="closed"):
        runtime.hold("0.01")
    gov.verify_integrity()


def test_what_recovery_spent_is_net_of_vendor_refunds() -> None:
    gov = governor()
    with runtime_for(gov) as runtime:
        assert (runtime.scope_id, runtime.records.log_id) == ("support-agent", "support")
        step = runtime.recover(thrash(), history(), max_tokens=4096)
        runtime.settle(step, "0.04")
        gov.refund(runtime.recovery_scope, "0.01", memo="vendor credit")
    closed = runtime.records.records()[-1]
    assert closed.kind == RecordKind.RECOVERY_CLOSED
    assert Decimal(closed.body["spent"]) == Decimal("0.03")
    assert Decimal(closed.body["returned"]) == Decimal("0.97")


def test_a_hold_the_governor_refuses_ends_the_recovery(monkeypatch: pytest.MonkeyPatch) -> None:
    gov = governor()
    runtime = runtime_for(gov)

    def runaway(scope_id: str, amount: object, *, memo: str = "") -> object:
        raise RunawayLoopDetectedError(scope_id, 50, 1.0)

    monkeypatch.setattr(gov, "authorize", runaway)
    with pytest.raises(RecoveryExhaustedError, match="refused the hold"):
        runtime.recover(thrash(), history(), max_tokens=4096)
    assert runtime.taken == 0


def test_a_step_that_cannot_be_recorded_is_not_taken() -> None:
    gov = governor()
    log = RecordLog(HmacKey.generate())
    runtime = runtime_for(gov, log)
    log.close()
    with pytest.raises(AnchorError, match="closed"):
        runtime.recover(thrash(), history(), max_tokens=4096)
    assert gov.available("support-agent/recovery") == Decimal("1.00")  # the hold was voided
    assert runtime.taken == 0 and runtime.revoked == ()


def test_a_step_the_ledger_cannot_anchor_is_logged_and_stands(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    gov = governor()
    runtime = runtime_for(gov)

    def refuse(scope_id: str, memo: str) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(gov, "anchor", refuse)
    with caplog.at_level(logging.WARNING, logger="interlock.recovery"):
        step = runtime.recover(thrash(), history(), max_tokens=4096)
    assert step.rung is Rung.REVOKE_TOOL and "could not be anchored" in caplog.text


def test_misuse_is_refused_before_anything_is_held() -> None:
    gov = governor()
    runtime = runtime_for(gov)
    with pytest.raises(RecoveryError, match="this runtime recovers"):
        runtime.recover(thrash(scope="billing-agent"), history(), max_tokens=4096)
    with pytest.raises(RecoveryError, match="empty"):
        runtime.recover(thrash(), [], max_tokens=4096)
    with pytest.raises(ValueError, match="max_tokens"):
        runtime.recover(thrash(), history(), max_tokens=0)
    assert gov.available("support-agent/recovery") == Decimal("1.00")
    # a halt reported by the recovery scope itself, or a sub-scope, is fine
    step = runtime.recover(thrash(scope="support-agent/recovery"), history(), max_tokens=4096)
    assert step.rung is Rung.REVOKE_TOOL


# --------------------------------------------------------------------------
# records and restarts
# --------------------------------------------------------------------------


def test_every_record_is_signed_linked_and_anchored_in_the_ledger() -> None:
    gov = governor()
    key = HmacKey.generate()
    log = RecordLog(key, log_id="support")
    runtime = runtime_for(gov, log)
    step = runtime.recover(thrash(), history(), max_tokens=4096)
    runtime.settle(step, "0.03")
    runtime.close()
    assert [r.kind for r in log.records()] == [
        RecordKind.RECOVERY_OPENED,
        RecordKind.RECOVERY_STEP,
        RecordKind.RECOVERY_SETTLED,
        RecordKind.RECOVERY_CLOSED,
    ]
    log.verify(key)
    assert check_anchors(log.records(), gov.audit_trail()) == 4
    body = step.record.body
    assert body["policy"] == runtime.policy.digest and body["rung"] == "revoke_tool"
    assert body["trip"]["tool"] == "lookup" and body["action"] == {"tool": "lookup"}


def test_a_restart_adopts_the_recovery_and_keeps_what_it_tightened(tmp_path: Path) -> None:
    gov = governor(tmp_path / "gov.db")
    key = HmacKey.generate()
    path = tmp_path / "records.jsonl"
    log = RecordLog(key, log_id="support", path=path)
    first = runtime_for(gov, log, directives=(NO_REPEAT,))
    step = first.recover(thrash(), history(), max_tokens=4096)  # revoke lookup
    first.settle(step, "0.03")
    step = first.recover(thrash(), again(step, 1), max_tokens=4096)  # no-repeat
    first.settle(step, "0.03")
    step = first.recover(thrash(), again(step, 2), max_tokens=4096)  # ceiling
    first.settle(step, "0.03")
    unsettled = first.recover(thrash(), again(step, 3), max_tokens=4096)  # guidance
    assert unsettled.rung is Rung.GUIDANCE
    log.close()  # the process dies with a step in flight

    log = RecordLog(key, log_id="support", path=path)
    second = runtime_for(gov, log, directives=(NO_REPEAT,))
    assert second.revoked == ("lookup",) and second.taken == 4
    assert second.max_tokens(4096) == 1024  # the ceiling stays down
    adopted = second.opened.body["adopted"]
    assert adopted == {
        "steps": 4,
        "unsettled": 1,
        "voided_holds": [str(unsettled.authorization.authorization_id)],
    }
    with pytest.raises(ToolRevokedError):
        second.check_tool("lookup")
    with pytest.raises(RecoveryError, match="edited"):
        second.recover(thrash(), [*step.messages, REPLY], max_tokens=4096)
    with pytest.raises(RecoveryExhaustedError, match="no rung"):  # guidance was given
        second.recover(thrash(), again(unsettled, 4), max_tokens=4096)
    resumed = second.recover(
        Trip(TripKind.BUDGET, "support-agent"), again(unsettled, 4), max_tokens=4096
    )
    assert resumed.rung is Rung.GUIDANCE and resumed.max_tokens == 1024
    second.settle(resumed, "0.02")
    second.close()
    log.close()
    with pytest.raises(RecoveryError, match="was closed"):
        runtime_for(gov, RecordLog(key, log_id="support", path=path))
    gov.verify_integrity()
    gov.close()


def test_a_recovery_scope_without_its_records_is_refused() -> None:
    gov = governor()
    gov.delegate("org", "support-agent/recovery", "1")
    with pytest.raises(RecoveryError, match="no record of opening it"):
        runtime_for(gov)


# --------------------------------------------------------------------------
# halts and policies
# --------------------------------------------------------------------------


def test_halts_are_read_by_type_never_by_message() -> None:
    thrashing = AgentThrashingError(
        "support-agent", "t-1", "exact_repeat", "2 byte-identical calls", observations=2
    )
    assert Trip.of(thrashing, tool="lookup") == Trip(
        TripKind.THRASHING,
        "support-agent",
        tool="lookup",
        trajectory="t-1",
        detector="exact_repeat",
        reason="2 byte-identical calls",
    )
    assert Trip.of(RunawayLoopDetectedError("s", 50, 1.0)).kind is TripKind.RUNAWAY
    denial = DenialOfWalletError(Decimal("1"), Decimal("0.5"), "s")
    assert Trip.of(denial).kind is TripKind.BUDGET
    exhausted = CircuitOpenError("s", "s", "spend envelope exhausted")
    assert Trip.of(exhausted).kind is TripKind.BUDGET
    cognitive = CircuitOpenError("s", "org", "cognitive breaker [exact_repeat]: 2 calls")
    assert Trip.of(cognitive).kind is TripKind.HALTED
    assert Trip.of(ScopeHaltedError("halted"), scope_id="s").kind is TripKind.HALTED

    refused = AdmissionError("plan refused: globex holds 900.00")
    refused.feedback = AgentFeedback("refused")
    trip = Trip.of(refused, scope_id="s", tool="apply_plan")
    assert (trip.kind, trip.feedback) == (TripKind.REFUSED, AgentFeedback("refused"))
    with pytest.raises(TypeError, match="scope_id"):
        Trip.of(AdmissionError("x"))
    with pytest.raises(TypeError, match="not a halt"):
        Trip.of(ValueError("x"))


def test_a_committed_plan_is_not_a_halt(back_office: str) -> None:
    from interlock import PlanBuilder

    engine = sqlite_engine(back_office)
    plan = (
        PlanBuilder("support-agent")
        .update(
            table="orders",
            statement="UPDATE orders SET status = 'held' WHERE id = 500",
            tenant_id="acme",
        )
        .build()
    )
    result = engine.execute(plan)
    assert result.committed
    with pytest.raises(ValueError, match="committed"):
        Trip.refused(result)


def test_a_plain_text_assistant_turn_leaves_nothing_to_answer() -> None:
    runtime = runtime_for(governor())
    turn = {"role": "assistant", "content": "I will look it up."}
    step = runtime.recover(thrash(), [history()[0], turn], max_tokens=4096)
    assert [m["role"] for m in step.appended] == ["user"]  # no tool results to write


def test_only_the_breaker_reasons_for_money_read_as_spent() -> None:
    assert spent_out("spend envelope exhausted")
    assert spent_out("overdraft attempt: requested 0.50, available 0.10")
    assert spent_out("settled cost 0.30 overran authorization 0.10; overdrawn by 0.20")
    assert not spent_out("settled cost 0.30")
    assert not spent_out("cognitive breaker [exact_repeat]: spend envelope exhausted")
    assert not spent_out("operator: suspicious")


def test_a_policy_is_checked_when_it_is_made() -> None:
    with pytest.raises(ValueError, match="estimate"):
        RecoveryPolicy(reserve=Decimal("0.10"), step_estimate=Decimal("0.20"))
    with pytest.raises(ValueError, match="at least one step"):
        policy(max_steps=0)
    with pytest.raises(ValueError, match="ceiling"):
        policy(token_ceiling=0)
    with pytest.raises(ValueError, match="unique"):
        policy(directives=(NO_REPEAT, NO_REPEAT))
    with pytest.raises(ValueError, match="directive id"):
        Directive("Bad Id", "text", frozenset({TripKind.BUDGET}))
    with pytest.raises(ValueError, match="1-2000"):
        Directive("blank", "  ", frozenset({TripKind.BUDGET}))
    with pytest.raises(ValueError, match="answers no"):
        Directive("none", "text", frozenset())
    edited = Directive("no-repeat", NO_REPEAT.text + " Please.", NO_REPEAT.answers)
    assert policy(directives=(edited, WRAP_UP)).digest != BASE.digest  # the text is bound
    assert policy().digest == BASE.digest


# --------------------------------------------------------------------------
# end to end, on the back-office schema
# --------------------------------------------------------------------------


def refusal_recovers_through_its_repair(
    engine: EscrowEngine, gov: BudgetManager, placeholder: Callable[[str], str]
) -> None:
    """The batch reaches globex and is refused. Recovery's guidance is the
    repair the engine found; the model takes it, and the repair commits."""
    receipts = engine.receipts
    assert receipts is not None
    log = RecordLog(HmacKey.generate(), log_id="support")
    runtime = runtime_for(gov, log)
    plan = support_batch(placeholder)

    # Turn 1, paid by the task's own scope: the batch is refused.
    turn = gov.authorize("support-agent", "0.10")
    messages: list[object] = [
        {"role": "user", "content": "Apply the corrections from the support ticket."},
        {
            "role": "assistant",
            "content": [
                {
                    "type": "tool_use",
                    "id": "toolu_01",
                    "name": "apply_plan",
                    "input": {"ticket": "T-1"},
                }
            ],
        },
    ]
    gov.capture(turn, "0.06")
    runtime.check_tool("apply_plan")
    refused = engine.execute(plan)
    assert not refused.committed and refused.feedback is not None
    messages.append(
        {
            "role": "user",
            "content": [
                {
                    "type": "tool_result",
                    "tool_use_id": "toolu_01",
                    "content": refused.feedback.render(),
                    "is_error": True,
                }
            ],
        }
    )

    # The refusal is a halt; the guidance rung carries the repair.
    repair = engine.repair(plan)
    assert repair.proposal is not None and repair.receipt is not None
    trip = Trip.refused(refused, tool="apply_plan", repair=repair.feedback)
    step = runtime.recover(trip, messages, max_tokens=4096)
    assert step.rung is Rung.GUIDANCE
    guidance = text_of(step.appended[-1])
    assert "keep hold_500, reprice_501, bump_items_500; drop hold_600" in guidance
    assert refused.receipt is not None
    assert step.record.body["trip"]["receipt"] == refused.receipt.receipt_id

    # The model, sent exactly step.messages, accepts the repair.
    messages = [
        *step.messages,
        {
            "role": "assistant",
            "content": [
                {"type": "tool_use", "id": "toolu_02", "name": "apply_repair", "input": {}}
            ],
        },
    ]
    runtime.settle(step, "0.05")
    committed = engine.execute(repair.proposal)
    assert committed.committed and committed.receipt is not None
    assert committed.receipt.decision.repair_of == repair.receipt.receipt_id

    # The task's last call is billed to the recovery scope too.
    last = runtime.hold("0.10")
    runtime.capture(last, "0.02")
    closed = runtime.close()
    assert closed is not None and Decimal(closed.body["spent"]) == Decimal("0.07")

    sent = json.dumps([*step.messages], default=str)  # all the model was ever sent
    assert "globex" not in sent
    assert "900" not in sent  # globex's account balance
    log.verify()
    assert check_anchors(log.records(), gov.audit_trail()) == len(log)
    assert gov.available("support-agent") == Decimal("3.94")
    gov.verify_integrity()


def thrashing_walks_down_the_ladder(lookup: Callable[[int], str], gov: BudgetManager) -> None:
    """AgentGov's cognitive breaker halts a looping lookup. Recovery revokes
    it; the model tries it again and is refused; the next loop earns the
    operator's directive, and the model answers."""
    log = RecordLog(HmacKey.generate(), log_id="support")
    runtime = runtime_for(gov, log, revocable=frozenset({"lookup"}))
    task = CognitiveBreaker(
        policy=CognitivePolicy(max_identical_repeats=2), observer=None, manager=gov
    )
    watch = CognitiveBreaker(policy=CognitivePolicy(max_identical_repeats=2), observer=None)
    messages: list[object] = [{"role": "user", "content": "What is the total of order 500?"}]

    def call(n: int, breaker: CognitiveBreaker, scope: str, trajectory: str) -> None:
        uid = f"toolu_{n:02}"
        use = {"type": "tool_use", "id": uid, "name": "lookup", "input": {"order": 500}}
        messages.append({"role": "assistant", "content": [use]})
        breaker.observe_call(scope, "lookup", kwargs={"order": 500}, trajectory=trajectory)
        try:
            runtime.check_tool("lookup")
            result = {"type": "tool_result", "tool_use_id": uid, "content": lookup(500)}
        except ToolRevokedError:
            result = RecoveryRuntime.refusal(uid)
        messages.append({"role": "user", "content": [result]})

    call(1, task, "support-agent", "ticket-9001")
    with pytest.raises(AgentThrashingError) as caught:
        call(2, task, "support-agent", "ticket-9001")
    assert gov.is_halted("support-agent")  # the halted call is left unanswered: the step answers it
    first = runtime.recover(Trip.of(caught.value, tool="lookup"), messages, max_tokens=4096)
    assert first.rung is Rung.REVOKE_TOOL and first.tools == ("apply_plan",)
    runtime.settle(first, "0.03")

    messages = list(first.messages)
    trajectory = f"{runtime.trajectory}/{runtime.taken}"
    call(3, watch, runtime.recovery_scope, trajectory)  # revoked: refused
    assert messages[-1] == {"role": "user", "content": [RecoveryRuntime.refusal("toolu_03")]}
    with pytest.raises(AgentThrashingError) as caught:
        call(4, watch, runtime.recovery_scope, trajectory)
    second = runtime.recover(Trip.of(caught.value, tool="lookup"), messages, max_tokens=4096)
    assert (second.rung, second.directive) == (Rung.OPERATOR_DIRECTIVE, "no-repeat")
    runtime.settle(second, "0.02")
    runtime.close()

    assert gov.is_halted("support-agent") and not gov.is_halted("support-agent/recovery")
    log.verify()
    assert check_anchors(log.records(), gov.audit_trail()) == len(log)
    gov.verify_integrity()


def test_sqlite_a_refused_batch_recovers_through_its_repair(back_office: str) -> None:
    gov = governor()
    engine = sqlite_engine(
        back_office,
        anchor=LedgerAnchor(governed=gov),
        receipts=ReceiptIssuer(ReceiptLog("interlock", HmacKey.generate())),
    )
    refusal_recovers_through_its_repair(engine, gov, lambda n: f":{n}")
    conn = sqlite3.connect(back_office)
    try:
        orders = conn.execute("SELECT id, status, total FROM orders ORDER BY id").fetchall()
        assert [(i, s, str(t)) for i, s, t in orders] == [
            (500, "held", "45"),
            (501, "open", "30"),
            (600, "shipped", "10"),
        ]
    finally:
        conn.close()


def test_sqlite_thrashing_walks_down_the_ladder(back_office: str) -> None:
    def lookup(order: int) -> str:
        conn = sqlite3.connect(back_office)
        try:
            status, total = conn.execute(
                "SELECT status, total FROM orders WHERE id = ?", (order,)
            ).fetchone()
        finally:
            conn.close()
        return f"order {order}: {status}, {total}"

    thrashing_walks_down_the_ladder(lookup, governor())


def test_postgres_a_refused_batch_recovers_through_its_repair(pg: Pg) -> None:
    import psycopg

    gov = governor()
    engine = pg_engine(
        pg,
        anchor=LedgerAnchor(governed=gov),
        receipts=ReceiptIssuer(ReceiptLog("interlock", HmacKey.generate())),
    )
    refusal_recovers_through_its_repair(engine, gov, pg_placeholder)
    with psycopg.connect(pg.admin) as conn:
        orders = conn.execute("SELECT id, status, total FROM orders ORDER BY id").fetchall()
    assert [(i, s, str(t)) for i, s, t in orders] == [
        (500, "held", "45.00"),
        (501, "open", "30.00"),
        (600, "shipped", "10.00"),
    ]


def test_postgres_thrashing_walks_down_the_ladder(pg: Pg) -> None:
    import psycopg

    def lookup(order: int) -> str:
        with psycopg.connect(pg.admin) as conn:
            row = conn.execute(
                "SELECT status, total FROM orders WHERE id = %s", (order,)
            ).fetchone()
        assert row is not None
        return f"order {order}: {row[0]}, {row[1]}"

    thrashing_walks_down_the_ladder(lookup, governor())
