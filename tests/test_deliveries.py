"""The delivery log's verifier, without a database.

``test_relay.py`` checks it against the logs PostgreSQL links. Here it is
checked against logs built by hand, one defect at a time, so that each rule it
enforces is seen to fail on its own.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from interlock.deliveries import LogEvent, _verify_one, event_hash, frame, genesis_hash

MESSAGE = uuid.UUID(int=1)
STAGE = uuid.UUID(int=2)
GENESIS = genesis_hash(MESSAGE, STAGE, "plan", "agent", "r0", "mail", "send", "key", "hash")
START = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)


def chain(*steps: tuple[str, int | None, str | None]) -> list[LogEvent]:
    """A delivery log the way the database links one: (event, attempt,
    state_after) per row."""
    events: list[LogEvent] = []
    prev = GENESIS
    for seq, (event, attempt, state_after) in enumerate(steps, start=1):
        at = START + timedelta(milliseconds=seq)
        digest = event_hash(
            prev, MESSAGE, seq, attempt, event, "relay", at, None, None, None, state_after
        )
        events.append(
            LogEvent(
                MESSAGE,
                seq,
                attempt,
                event,
                "relay",
                at,
                None,
                None,
                None,
                state_after,
                prev,
                digest,
            )
        )
        prev = digest
    return events


DELIVERED = (
    ("sending", 1, "leased"),
    ("retryable", 1, "pending"),
    ("sending", 2, "leased"),
    ("delivered", 2, "delivered"),
)


def problems(
    events: list[LogEvent], state: str = "delivered", attempts: int | None = None
) -> list[str]:
    calls = sum(1 for e in events if e.event == "sending") if attempts is None else attempts
    head = events[-1].event_hash if events else GENESIS
    return _verify_one(
        events, genesis=GENESIS, state=state, attempts=calls, log_seq=len(events), log_head=head
    )


def test_frame_is_length_prefixed_utf8() -> None:
    assert frame("a", None, "", "é") == "1:a-0:2:é"
    assert frame("ab", "c") != frame("a", "bc")
    assert frame() == ""


def test_hashes_are_sha256_of_the_frame() -> None:
    assert (
        GENESIS
        == hashlib.sha256(
            frame(
                "interlock-outbox-genesis-v1",
                str(MESSAGE),
                str(STAGE),
                "plan",
                "agent",
                "r0",
                "mail",
                "send",
                "key",
                "hash",
            ).encode()
        ).hexdigest()
    )
    other_zone = START.astimezone(UTC).replace(tzinfo=UTC)
    assert event_hash(
        "p", MESSAGE, 1, None, "held", "x", START, None, None, None, "held"
    ) == event_hash("p", MESSAGE, 1, None, "held", "x", other_zone, None, None, None, "held")


def test_a_well_formed_log_verifies() -> None:
    assert problems(chain(*DELIVERED)) == []
    assert problems([], state="pending") == []
    held = chain(("held", None, "held"), ("released", None, "pending"))
    assert problems(held, state="pending") == []
    assert problems(held, state="leased") == []


def test_a_rewritten_row_is_caught() -> None:
    events = chain(*DELIVERED)
    events[1] = replace(events[1], detail="rewritten")
    assert problems(events) == ["row 2 (retryable) does not hash to what it records"]


def test_a_row_out_of_place_is_caught() -> None:
    events = chain(*DELIVERED)
    events[1], events[2] = events[2], events[1]
    assert problems(events) == ["row 3 is out of place (expected row 2)"]


def test_a_broken_link_is_caught() -> None:
    events = chain(*DELIVERED)
    events[2] = replace(events[2], prev_hash="0" * 64)
    assert problems(events) == ["row 3 does not link to the row before it"]


def test_a_removed_tail_is_caught_by_the_head() -> None:
    events = chain(*DELIVERED)
    found = _verify_one(
        events[:-1],
        genesis=GENESIS,
        state="delivered",
        attempts=2,
        log_seq=4,
        log_head=events[-1].event_hash,
    )
    assert any("a row was removed or rewritten" in p for p in found)
    assert any("records no delivery" in p for p in found)


@pytest.mark.parametrize(
    ("steps", "state", "attempts", "expected"),
    [
        (
            (("sending", 2, "leased"), ("delivered", 2, "delivered")),
            "delivered",
            None,
            "calls are numbered [2]",
        ),
        (
            (("sending", 1, "leased"), ("delivered", 1, "delivered")),
            "delivered",
            3,
            "counts 3 call(s)",
        ),
        ((("delivered", 1, "delivered"),), "delivered", 0, "reports a call never started"),
        (
            (("sending", 1, "leased"), ("retryable", 1, "pending"), ("unknown", 1, "pending")),
            "pending",
            None,
            "call 1 has 2 outcomes",
        ),
        (
            (("sending", 1, "leased"), ("lost", 1, "pending"), ("lost", 1, "pending")),
            "pending",
            None,
            "call 1 has 2 outcomes",
        ),
        (
            (("sending", 1, "leased"), ("delivered", 1, "delivered")),
            "dead",
            None,
            "records delivery",
        ),
        (
            (("sending", 1, "leased"), ("permanent", 1, "dead")),
            "delivered",
            None,
            "records no delivery",
        ),
        ((("held", None, "held"),), "cancelled", None, "leads to held"),
        ((("held", None, "held"),), "pending", None, "leads to held"),
    ],
)
def test_each_rule_fails_on_its_own(
    steps: tuple[tuple[str, int | None, str | None], ...],
    state: str,
    attempts: int | None,
    expected: str,
) -> None:
    found = problems(chain(*steps), state=state, attempts=attempts)
    assert any(expected in p for p in found), found


def test_a_lost_call_and_its_late_outcome_are_both_allowed() -> None:
    """A relay that stalls past its lease reports its call's outcome after the
    next relay recorded the call as lost: one inference, one report."""
    events = chain(
        ("sending", 1, "leased"),
        ("lost", 1, "pending"),
        ("sending", 2, "leased"),
        ("delivered", 2, "delivered"),
        ("delivered", 1, None),
    )
    assert problems(events) == []
