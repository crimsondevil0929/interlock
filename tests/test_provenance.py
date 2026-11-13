"""What a session had read, carried on its plans, and the gate that reads it (1.8.0)."""

from __future__ import annotations

import dataclasses
import sqlite3
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from interlock import EscrowEngine, PlanBuilder, ProvenanceGate, SqliteSubstrate, TableSpec
from interlock.feedback import Guidance
from interlock.types import EffectKind, EffectPlan


def _plan(*labels: str, table: str = "refunds") -> EffectPlan:
    builder = PlanBuilder("support", provenance=labels)
    builder.add(
        EffectKind.INSERT,
        table=table,
        statement=f"INSERT INTO {table} (id, amount) VALUES (:id, :amount)",
        parameters={"id": 7, "amount": 40},
        stated_rows=1,
    )
    return builder.build()


def _diff(kinds: set[str], sinks: set[str] = frozenset()) -> Any:  # type: ignore[assignment]
    return SimpleNamespace(
        kinds_touched=frozenset(kinds),
        outbound=tuple(SimpleNamespace(sink=s) for s in sorted(sinks)),
    )


def test_labels_are_sorted_checked_and_in_the_hash_only_when_present() -> None:
    plain = _plan()
    labeled = dataclasses.replace(plain, provenance=("untrusted", "secret", "untrusted"))
    assert labeled.provenance == ("secret", "untrusted")
    assert labeled.content_hash() != plain.content_hash()
    assert dataclasses.replace(labeled, provenance=()).content_hash() == plain.content_hash()
    with pytest.raises(ValueError, match="provenance label"):
        dataclasses.replace(plain, provenance=("Untrusted!",))


def test_after_untrusted_input_the_listed_kinds_and_sinks_take_a_warrant() -> None:
    gate = ProvenanceGate(untrusted_kinds=["refunds"], untrusted_sinks=["stripe"])
    assert gate.check(_plan(), _diff({"refunds"}, {"stripe"})) == ()
    found = gate.check(_plan("untrusted"), _diff({"refunds", "notes"}, {"stripe", "mail"}))
    (violation,) = found
    assert violation.invariant == "provenance_gate"
    assert violation.evidence["rule"] == "untrusted"
    assert violation.evidence["kinds"] == "refunds" and violation.evidence["sinks"] == "stripe"
    assert "untrusted input" in violation.message
    assert gate.check(_plan("untrusted"), _diff({"notes"}, {"mail"})) == ()
    assert gate.check(_plan("untrusted", "cleared"), _diff({"refunds"})) == ()
    anything = ProvenanceGate(untrusted_kinds=["*"])
    assert anything.check(_plan("untrusted"), _diff({"notes"}))


def test_labeled_data_leaves_only_by_the_sinks_cleared_for_it() -> None:
    gate = ProvenanceGate(egress={"secret": ["vault"], "partition:*": ["mail"]})
    assert gate.check(_plan("secret"), _diff(set(), {"vault"})) == ()
    (violation,) = gate.check(_plan("secret"), _diff(set(), {"vault", "slack"}))
    assert violation.evidence["rule"] == "egress" and violation.evidence["sinks"] == "slack"
    (violation,) = gate.check(_plan("partition:tenant=acme"), _diff(set(), {"stripe"}))
    assert violation.evidence["label"] == "partition:tenant=acme"
    assert gate.check(_plan("partition:tenant=acme"), _diff(set(), {"mail"})) == ()
    assert gate.check(_plan("untrusted"), _diff(set(), {"slack"})) == ()


def test_the_rule_of_two_refuses_the_third() -> None:
    gate = ProvenanceGate(rule_of_two=True)
    assert gate.check(_plan("untrusted"), _diff({"refunds"})) == ()  # input and change
    assert gate.check(_plan("secret"), _diff({"refunds"})) == ()  # sensitive and change
    assert gate.check(_plan("untrusted", "secret"), _diff(set())) == ()  # nothing changed
    (violation,) = gate.check(_plan("untrusted", "secret"), _diff({"refunds"}))
    assert violation.evidence["rule"] == "rule_of_two"
    assert gate.check(_plan("untrusted", "partition:tenant=a"), _diff(set(), {"mail"}))
    assert gate.check(_plan("untrusted", "quarantined:triage"), _diff({"refunds"})) == ()


def test_the_engine_refuses_and_tells_the_agent_in_plain_words(tmp_path: Path) -> None:
    db = tmp_path / "desk.db"
    with closing(sqlite3.connect(db)) as conn:
        conn.execute("CREATE TABLE refunds (id INTEGER PRIMARY KEY, amount INTEGER)")
        conn.commit()
    engine = EscrowEngine(
        SqliteSubstrate(str(db), tables=[TableSpec("refunds", columns=["id", "amount"])]),
        checkers=[ProvenanceGate(untrusted_kinds=["refunds"])],
    )
    refused = engine.execute(_plan("untrusted"))
    assert not refused.committed and refused.blocked_by == ("provenance_gate",)
    assert refused.verdict is not None
    assert refused.verdict.blocking[0].evidence["labels"] == "untrusted"
    assert refused.feedback is not None
    text = refused.feedback.render()
    assert "changing refunds takes the principals' approval" in text
    assert any(c.guidance is Guidance.PROVENANCE for c in refused.feedback.constraints)
    with closing(sqlite3.connect(db)) as conn:
        assert conn.execute("SELECT COUNT(*) FROM refunds").fetchone() == (0,)
    assert engine.execute(_plan("untrusted", "cleared")).committed
    # A stage opened before its plan carries the labels it was opened with.
    with engine.stage("support", provenance=["untrusted"]) as stage:
        stage.add(
            EffectKind.INSERT,
            table="refunds",
            statement="INSERT INTO refunds (id, amount) VALUES (8, 1)",
            stated_rows=1,
        )
        result = stage.settle()
    assert result is not None and not result.committed
    assert result.plan.provenance == ("untrusted",)
