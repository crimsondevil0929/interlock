"""Crash consistency for the relay (Epic 2, phase 4; on SQLite, Epic 3).

A relay is a separate process, and processes die: SIGKILL, power, the OOM
killer. Each test here runs a relay in a child process
(``tests/relay_child.py``), kills it with SIGKILL, so that nothing runs after
the kill, and then lets a surviving relay finish the work. What was left, and
what the survivor did with it, is checked exactly.

**At each point of the delivery path**, for three sinks, one per delivery
guarantee:

- ``mail`` honours idempotency keys and redelivers an unknown outcome;
- ``sms`` does not honour keys, and redelivers;
- ``pager`` does not honour keys, and dead-letters an unknown outcome.

=========================  ========================  ====================================
The relay died...          It left                   Then, for mail / sms / pager
=========================  ========================  ====================================
in the claim's transaction nothing: rolled back      delivered once / once / once
after the claim, before    a lease, no call          the lease runs out; delivered once
recording the call                                   by the survivor, no ``lost``
after recording the call,  a call recorded, never    ``lost``; called again: one call and
before making it           made                      one effect / the same / **dead**, no
                                                     call at all (at most once)
with the call in flight,   a call made, the sink     ``lost``; called again: two calls,
after the sink answered,   acted, no outcome         **one effect** / two calls, **two
in the outcome's                                     effects** / dead, one effect
transaction
after the outcome          delivered                 nothing to do
=========================  ========================  ====================================

So a duplicate effect happens in exactly one place: a sink without
idempotency keys, set to redeliver, whose relay died between the sink acting
and the outcome committing. And it is never silent: the delivery log records
the lost call it came from.

Every test runs against both stores. On SQLite the two relays of a pair
are two processes contending for one file's write lock, and a kill can land
while a relay holds it: the kernel releases it, and what the relay had written
of its transaction never committed.

**At random instants**, relays racing in pairs over a sink that fails, drops
connections and hangs at random, killed over and over. Whatever the
interleaving: every message is delivered; every call the sinks received is in
the log, under a number no other call used; no call started before the one
before it ended or was declared lost; every duplicate effect is accounted for
by a lost or unknown call; and every delivery log verifies.
"""

from __future__ import annotations

import itertools
import json
import os
import random
import select
import signal
import subprocess
import sys
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from interlock.deliveries import OUTCOMES, LogEvent
from interlock.outbound import OperationSpec, SinkSpec
from interlock.types import outbound_key
from tests.fakesink import DROP, HOLD, OK, hang, status
from tests.outbox_env import BACKENDS, RELAY_SINKS, Outbox, build_either, mail, page, sms
from tests.schemas import MAIL_SEND_SCHEMA

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="SIGKILL is POSIX")

ROOT = Path(__file__).resolve().parent.parent
LEASE = 1.5
TIMEOUT = 0.5


@pytest.fixture(params=BACKENDS)
def outbox(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Outbox]:
    """Every crash test runs against both stores."""
    yield from build_either(request, tmp_path)


# --------------------------------------------------------------------------
# the child process
# --------------------------------------------------------------------------


class RelayChild:
    """A relay in a child process. Never asked to stop: killed, or it kills
    itself at its point."""

    def __init__(self, scenario: dict[str, Any], workdir: Path, number: int) -> None:
        path = workdir / f"relay-{number}.json"
        path.write_text(json.dumps(scenario))
        self.stderr_path = workdir / f"relay-{number}.stderr"
        with self.stderr_path.open("wb") as stderr:
            self.process = subprocess.Popen(  # noqa: S603
                [sys.executable, "-m", "tests.relay_child", str(path)],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=stderr,
            )
        assert self.process.stdout is not None
        self._fd = self.process.stdout.fileno()
        self._buffer = b""

    def wait_started(self, timeout: float = 60.0) -> None:
        deadline = time.monotonic() + timeout
        while b'"started"' not in self._buffer:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AssertionError(f"relay did not start\n{self.stderr()}")
            ready, _, _ = select.select([self._fd], [], [], remaining)
            if ready:
                chunk = os.read(self._fd, 65536)
                if not chunk:
                    raise AssertionError(f"relay exited before starting\n{self.stderr()}")
                self._buffer += chunk

    def kill(self) -> None:
        """SIGKILL, from outside: the process ends where it is."""
        os.kill(self.process.pid, signal.SIGKILL)
        self.wait_killed()

    def wait_killed(self, timeout: float = 60.0) -> None:
        """Wait for the child to die by SIGKILL, its own or ours."""
        code = self.process.wait(timeout=timeout)
        if self.process.stdout is not None:
            self.process.stdout.close()
        assert code == -signal.SIGKILL, f"relay ended {code}, not by SIGKILL\n{self.stderr()}"

    def stderr(self) -> str:
        return self.stderr_path.read_text(errors="replace")[-4000:]


def scenario(
    outbox: Outbox,
    *,
    sinks: list[str],
    relay_id: str,
    kill_at: str = "",
    message: uuid.UUID | None = None,
    batch: int = 1,
    idle_rounds: int = 25,
) -> dict[str, Any]:
    return {
        **outbox.relay_target(),
        "ledger": outbox.ledger_path,
        "sinks": {name: outbox.sink(name).url for name in sinks},
        "relay_id": relay_id,
        "lease": LEASE,
        "timeout": TIMEOUT,
        "batch": batch,
        "kill_at": kill_at,
        "message": "" if message is None else str(message),
        "idle_rounds": idle_rounds,
    }


# --------------------------------------------------------------------------
# a kill at each point of the delivery path
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Point:
    at: str
    leased: bool
    """The lease committed before the kill: no relay takes it until it runs out."""
    logged: bool
    """The call was recorded (``sending`` committed) before the kill."""
    called: bool
    """The sink received the call, and acted, before the kill."""
    recorded: bool = False
    """The outcome committed before the kill."""

    @property
    def by_parent(self) -> bool:
        """Killed by the test while the sink holds the call, not by itself."""
        return self.at == "in-flight"


POINTS = (
    Point("claim-uncommitted", leased=False, logged=False, called=False),
    Point("claimed", leased=True, logged=False, called=False),
    Point("checked", leased=True, logged=False, called=False),
    Point("sending-uncommitted", leased=True, logged=False, called=False),
    Point("sending", leased=True, logged=True, called=False),
    Point("in-flight", leased=True, logged=True, called=True),
    Point("called", leased=True, logged=True, called=True),
    Point("outcome-uncommitted", leased=True, logged=True, called=True),
    Point("recorded", leased=True, logged=True, called=True, recorded=True),
)

SINKS = ("mail", "sms", "pager")


Events = list[tuple[str, int | None]]


@dataclass(frozen=True)
class Expected:
    state: str
    events: Events
    calls: int
    effects: int


def expected(point: Point, sink: str) -> Expected:
    """What the outbox and the sink hold once the survivor is done."""
    delivered: Events = [("sending", 1), ("delivered", 1)]
    if point.recorded or not point.logged:
        return Expected("delivered", delivered, 1, 1)
    lost: Events = [("sending", 1), ("lost", 1)]
    made = 1 if point.called else 0
    if sink == "pager":
        # At most once: the call may have happened, so it is never repeated.
        return Expected("dead", lost, made, made)
    calls = made + 1
    return Expected(
        "delivered",
        [*lost, ("sending", 2), ("delivered", 2)],
        calls,
        1 if sink == "mail" else calls,
    )


@pytest.mark.parametrize("point", POINTS, ids=lambda p: p.at)
def test_a_relay_killed_at_each_point_is_recovered_exactly(
    outbox: Outbox, tmp_path: Path, point: Point
) -> None:
    messages: dict[str, uuid.UUID] = {}
    keys: dict[str, str] = {}
    for name, request in (("mail", mail(1)), ("sms", sms(1)), ("pager", page(1))):
        plan, (message,) = outbox.commit(request)
        messages[name] = message
        keys[name] = outbound_key(plan.plan_id, plan.effects[0].effect_id)

    # One dying relay per sink, each claiming only its sink's one message.
    for number, name in enumerate(SINKS):
        sink = outbox.sink(name)
        if point.by_parent:
            sink.script(HOLD, key=keys[name])
        child = RelayChild(
            scenario(
                outbox,
                sinks=[name],
                relay_id=f"dying-{name}",
                kill_at="" if point.by_parent else point.at,
                message=messages[name],
            ),
            tmp_path,
            number,
        )
        if point.by_parent:
            assert sink.arrived.wait(60), child.stderr()
            child.kill()
            sink.release.set()
        else:
            child.wait_killed()
    outbox.settle()

    if point.leased and not point.recorded:
        # A dead relay's lease is not taken early: nobody may assume it died.
        # Checked while every lease has time left: on a loaded machine the
        # first may have run out by the time the third relay is dead.
        left = min(outbox.lease_left(messages[name]) for name in SINKS)
        if left > 0.3:
            with outbox.relay(relay_id="early") as early:
                assert early.run_once(limit=10).claimed == 0
    time.sleep(LEASE + 0.3)
    with outbox.relay(relay_id="survivor") as survivor:
        outbox.drain(survivor)

    for name in SINKS:
        want = expected(point, name)
        message, key, sink = messages[name], keys[name], outbox.sink(name)
        assert outbox.state(message) == want.state, name
        assert outbox.events(message) == want.events, name
        calls = sink.calls_for(key)
        assert len(calls) == want.calls, name
        assert sink.effects[key] == want.effects, name
        # Every call the sink received is in the log, each under its own number.
        assert len({c.attempt for c in calls}) == len(calls)
        started = {a for e, a in outbox.events(message) if e == "sending"}
        assert {c.attempt for c in calls} <= started
        # A duplicate effect is never silent: a lost call accounts for it.
        lost = sum(1 for e, _ in outbox.events(message) if e == "lost")
        assert sink.effects[key] <= 1 + lost
    outbox.verify()


# --------------------------------------------------------------------------
# kills at random instants
# --------------------------------------------------------------------------

_SOAK: dict[str, Any] = {
    "backoff_base": timedelta(milliseconds=10),
    "backoff_cap": timedelta(milliseconds=80),
    "max_attempts": 100,
    "not_after": timedelta(minutes=30),
}

SOAK_SINKS = (
    SinkSpec(
        "mail",
        (OperationSpec("send", schema=MAIL_SEND_SCHEMA),),
        cost_per_call=Decimal("0.002"),
        max_payload_bytes=4096,
        **_SOAK,
    ),
    SinkSpec("sms", (OperationSpec("send"),), idempotency="none", **_SOAK),
    RELAY_SINKS[2],
)


def test_relays_killed_at_random_instants_lose_nothing(outbox: Outbox, tmp_path: Path) -> None:
    rng = random.Random(20261001)  # noqa: S311 - a reproducible schedule, not a secret
    outbox.reinstall(SOAK_SINKS)
    # Eight plans of three requests, each waiting for the one before it.
    plans: list[list[uuid.UUID]] = []
    keys: dict[uuid.UUID, tuple[str, str]] = {}
    for n in range(8):
        requests = [mail(n * 3 + i) if (n + i) % 2 == 0 else sms(n * 3 + i) for i in range(3)]
        plan, messages = outbox.commit(*requests, independent=False)
        plans.append(messages)
        for effect, message in zip(plan.effects, messages, strict=True):
            assert effect.request is not None
            keys[message] = (effect.request.sink, outbound_key(plan.plan_id, effect.effect_id))

    def chaos() -> tuple[Any, ...]:
        return rng.choices([OK, status(503), DROP, hang(0.8)], weights=[55, 15, 15, 15])[0]

    for name in ("mail", "sms"):
        outbox.sink(name).chaos = chaos

    number = 0
    for round_ in range(14):
        pair = []
        for k in range(2):
            number += 1
            pair.append(
                RelayChild(
                    scenario(
                        outbox,
                        sinks=["mail", "sms"],
                        relay_id=f"soak-{round_}-{k}",
                        batch=2,
                        idle_rounds=10_000,
                    ),
                    tmp_path,
                    number,
                )
            )
        for child in pair:
            child.wait_started()
        time.sleep(rng.uniform(0.05, 0.7))
        for child in pair:
            child.kill()
        if not outbox.unsettled():
            break
    outbox.settle()

    for name in ("mail", "sms"):
        outbox.sink(name).chaos = None
    time.sleep(LEASE + 0.3)
    with outbox.relay(relay_id="survivor") as survivor:
        outbox.drain(survivor, rounds=2000)

    assert outbox.states() == {"delivered": 24}
    lost_anywhere = 0
    for message, (name, key) in keys.items():
        log = outbox.log(message)
        calls = outbox.sink(name).calls_for(key)
        numbers = [c.attempt for c in calls]
        # Every call the sink received is in the log, under a number no other
        # call used.
        assert len(set(numbers)) == len(numbers), (message, numbers)
        assert set(numbers) <= {e.attempt for e in log if e.event == "sending"}
        # No call started before the one before it ended or was declared lost:
        # never two calls in flight for one message.
        _one_call_at_a_time(log)
        unknown = sum(1 for e in log if e.event in ("unknown", "lost"))
        lost_anywhere += sum(1 for e in log if e.event == "lost")
        effects = outbox.sink(name).effects[key]
        if name == "mail":
            assert effects == 1, (message, effects)
        else:
            # Each duplicate is a call that acted and whose outcome was lost or unknown.
            assert 1 <= effects <= 1 + unknown, (message, effects, unknown)
    # Within each plan, a request was first called only after the one it
    # waits for was delivered.
    for messages in plans:
        for before, after in itertools.pairwise(messages):
            delivered = next(e.at for e in outbox.log(before) if e.event == "delivered")
            first_call = next(e.at for e in outbox.log(after) if e.event == "sending")
            assert first_call >= delivered
    assert lost_anywhere > 0, "no kill landed mid-call: the soak proved less than it claims"
    outbox.verify()


def _one_call_at_a_time(log: tuple[LogEvent, ...]) -> None:
    ended: set[int | None] = set()
    for event in log:
        if event.event == "sending" and event.attempt is not None and event.attempt > 1:
            assert event.attempt - 1 in ended, (
                f"call {event.attempt} began before {event.attempt - 1} ended"
            )
        if event.event in OUTCOMES or event.event == "lost":
            ended.add(event.attempt)
