"""Undo on a REST API (1.10.0): each changed resource kept whole beside the undo journal,
and patched back, conditional on the version read, only while it is as the plan left it."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

from interlock.exceptions import UndoError
from interlock.sim.rest import LoopbackRestServer
from interlock.undo import UNDO_EXACT, digest_problems
from tests.test_rest import (
    create,
    patch,
    server,  # noqa: F401 - the loopback API, as a fixture
    ticket,
)
from tests.test_rest import engine as rest_engine
from tests.test_rest import plan as rest_plan
from tests.test_rest import substrate as rest_substrate

WEEK = timedelta(days=7)


def test_a_rest_undo_patches_each_resource_back(
    server: LoopbackRestServer,  # noqa: F811 - the fixture imported above
    tmp_path: Path,
) -> None:
    sub = rest_substrate(server, tmp_path, undo=WEEK)
    before = ticket(server, 1)
    done = rest_engine(sub, tmp_path).execute(
        rest_plan(patch("tkt-1", {"status": "solved", "priority": "high"}))
    )
    assert done.committed and len(done.changes) == 1
    assert ticket(server, 1)["status"] == "solved"
    assert (tmp_path / "journal" / "kept" / f"{done.plan.plan_id}.json").is_file()

    undone = rest_engine(sub, tmp_path / "u").undo(done.plan.plan_id, scope_id="support-agent")
    assert undone.committed, undone.blocked_by
    now = ticket(server, 1)
    assert {k: now[k] for k in ("status", "priority", "assignee", "subject")} == {
        k: before[k] for k in ("status", "priority", "assignee", "subject")
    }
    assert digest_problems(undone.undid, undone.changes) == []

    # a person's edit since: the undo is refused, naming the ticket, and writes nothing
    again = rest_engine(sub, tmp_path / "a").execute(
        rest_plan(patch("tkt-2", {"status": "pending"}))
    )
    server.write("tickets", {**ticket(server, 2), "assignee": "tier2"})
    edited = ticket(server, 2)
    refused = rest_engine(sub, tmp_path / "r").undo(again.plan.plan_id, scope_id="support-agent")
    assert not refused.committed and refused.blocked_by == (UNDO_EXACT,)
    assert "tickets tkt-2 was not put back" in refused.verdict.blocking[0].message  # type: ignore[union-attr]
    assert ticket(server, 2) == edited

    # a ticket the plan created is not deleted by an undo: said, before anything is staged
    made = rest_engine(sub, tmp_path / "c").execute(rest_plan(create()))
    assert made.committed
    with pytest.raises(UndoError, match="cannot delete it"):
        rest_engine(sub, tmp_path / "d").undo(made.plan.plan_id, scope_id="support-agent")
