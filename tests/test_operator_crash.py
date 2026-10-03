"""An operator command killed at each point of its two phases
(``docs/EPIC3_DESIGN.md`` §6, §7).

The command runs in a child process (``tests/operator_child.py``) and SIGKILLs
itself after signing its intent, after the database action, or after
recording the outcome. Then another operator acts, and resolves whatever the
dead command left: on both stores,

- no database action exists without an intent signed before it;
- every intent resolves exactly: ``abandoned`` when the command died before
  acting, ``applied`` (naming the rows) when it died before recording;
- the delivery logs and the operator log verify afterwards.
"""

from __future__ import annotations

import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from interlock.operators import generate_key
from interlock.records import read_records
from tests.children import Child
from tests.outbox_env import BACKENDS, SCOPE, Outbox, build_either, mail

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="SIGKILL is POSIX")


@pytest.fixture(params=BACKENDS)
def outbox(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Outbox]:
    yield from build_either(request, tmp_path)


@pytest.mark.parametrize(
    ("kill_at", "state", "resolution"),
    [
        ("intent", "held", ["operator.abandoned"]),
        ("acted", "pending", ["operator.applied"]),
        ("recorded", "pending", []),
    ],
)
def test_an_operator_command_killed_at_each_point_is_resolved_exactly(
    outbox: Outbox, tmp_path: Path, kill_at: str, state: str, resolution: list[str]
) -> None:
    _, (message,) = outbox.commit(mail(1))
    outbox.governor.trip(SCOPE, "ops halt")
    with outbox.relay() as relay:
        relay.run_once()
    outbox.governor.reset(SCOPE)
    key = tmp_path / "alice.key"
    outbox.keys["alice"] = generate_key(key)
    outbox.operator_key("bob")
    child = Child(
        {
            **outbox.operator_target(),
            "log": str(outbox.operator_log),
            "key": str(key),
            "keys": {name: k.public_key().spec() for name, k in outbox.keys.items()},
            "message": str(message),
            "kill_at": kill_at,
        },
        tmp_path,
        0,
        module="tests.operator_child",
    )
    child.wait_for("started")
    killed = child.wait_for("killed")
    assert killed.at == kill_at
    code = child.process.wait(timeout=30)
    assert code < 0, f"the command ended {code}, not by its SIGKILL\n{child.stderr()}"
    outbox.settle()

    assert outbox.state(message) == state
    with outbox.signed("bob") as bob:
        assert [r.kind for r in bob.resolve()] == resolution
    records = read_records(outbox.operator_log)
    assert records[0].kind == "operator.intent"
    assert {r.body["operator"] for r in records} <= {"alice", "bob"}
    if kill_at == "acted":
        (applied,) = [r for r in records if r.kind == "operator.applied"]
        assert applied.body["operator"] == "bob"
        assert [row["message"] for row in applied.body["rows"]] == [str(message)]
    outbox.verify()
