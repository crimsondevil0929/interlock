"""Tests for the AgentGov seam.

`anchor.py` is where Interlock's evidence meets AgentGov's. Everything here is
about refusing to produce evidence that looks stronger than it is, so the tests
are mostly adversarial:

1. A ledger that does not verify must be refused at attach, whatever the reason
   it does not verify, and must be refused with one exception type so a caller
   can fail closed on it.
2. An unanchored deployment must be distinguishable from an anchored one at
   every call, never silently equivalent.
3. A reverse anchor must be inside AgentGov's own hash payload, so editing it
   breaks AgentGov's verification rather than passing unnoticed.
"""

from __future__ import annotations

import sqlite3
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from agentgov import BudgetManager, money
from agentgov.core import EntryType
from agentgov.exceptions import LedgerIntegrityError

from interlock.anchor import AnchorPoint, LedgerAnchor
from interlock.exceptions import AnchorError, LedgerUnverifiedError, ScopeHaltedError
from interlock.types import GENESIS_HASH


def build_ledger(path: Path) -> Path:
    """A small, valid, hash-chained AgentGov ledger on disk."""
    with BudgetManager.open_sqlite(str(path)) as gov:
        gov.open_root("root", money("5.00"))
        gov.delegate("root", "child", money("1.00"))
        authorization = gov.authorize("child", money("0.10"), memo="call")
        gov.capture(authorization, money("0.05"), memo="call")
    return path


def edit(path: Path, sql: str) -> None:
    """Edit the ledger file behind AgentGov's back."""
    conn = sqlite3.connect(path)
    try:
        conn.execute(sql)
        conn.commit()
    finally:
        conn.close()


@pytest.fixture
def ledger(tmp_path: Path) -> Path:
    return build_ledger(tmp_path / "governor.db")


# --------------------------------------------------------------------------
# 1. Admissibility: an unusable ledger is refused, and refused consistently
# --------------------------------------------------------------------------


def test_missing_ledger_file_is_refused(tmp_path: Path) -> None:
    with pytest.raises(LedgerUnverifiedError, match="no AgentGov ledger at"):
        LedgerAnchor(tmp_path / "does-not-exist.db")


def test_directory_in_place_of_a_ledger_is_refused(tmp_path: Path) -> None:
    with pytest.raises(LedgerUnverifiedError, match="no AgentGov ledger at"):
        LedgerAnchor(tmp_path)


def test_tampered_memo_is_refused_at_attach(ledger: Path) -> None:
    """memo is inside the hash payload, so editing it breaks the chain."""
    edit(ledger, "UPDATE entries SET memo='EDITED' WHERE sequence=1")
    with pytest.raises(LedgerUnverifiedError, match="cannot open"):
        LedgerAnchor(ledger)


def test_tampered_amount_is_refused_at_attach(ledger: Path) -> None:
    """The case an attacker actually wants: move money, keep the chain shape."""
    edit(ledger, "UPDATE entries SET amount='99.00000000' WHERE sequence=1")
    with pytest.raises(LedgerUnverifiedError, match="cannot open"):
        LedgerAnchor(ledger)


def test_tampered_balance_is_refused_at_attach(ledger: Path) -> None:
    """balance_after is attested too, so the balance history cannot be rewritten."""
    edit(ledger, "UPDATE entries SET balance_after='999.00000000' WHERE sequence=1")
    with pytest.raises(LedgerUnverifiedError, match="cannot open"):
        LedgerAnchor(ledger)


def test_rewritten_entry_hash_is_refused_at_attach(ledger: Path) -> None:
    """Editing the hash to match a forged payload re-links the chain and fails."""
    edit(ledger, "UPDATE entries SET entry_hash='" + "f" * 64 + "' WHERE sequence=1")
    with pytest.raises(LedgerUnverifiedError, match="cannot open"):
        LedgerAnchor(ledger)


def test_excised_entry_is_refused_at_attach(ledger: Path) -> None:
    """Deleting an entry leaves a gap; the surviving links no longer join up."""
    edit(ledger, "DELETE FROM entries WHERE sequence=2")
    with pytest.raises(LedgerUnverifiedError, match="cannot open"):
        LedgerAnchor(ledger)


def test_tail_truncation_is_not_detected_by_the_chain_alone(ledger: Path) -> None:
    """Deleting the most recent entries leaves a shorter chain that verifies.

    Every surviving link still joins up, so there is nothing internal to the
    file that says entries used to follow. A self-hosted hash chain cannot
    detect its own truncation; only something outside it can, which is what
    the monotonicity rule in EscrowChain.verify_anchors and an external anchor
    are for. Pinned so that if a future change claims to detect rollback, this
    test fails and the claim gets checked.
    """
    edit(ledger, "DELETE FROM entries WHERE sequence >= 4")
    anchor = LedgerAnchor(ledger)
    try:
        assert anchor.attached is True
        assert anchor.observe().sequence == 3
    finally:
        anchor.close()


def test_sqlite_file_without_an_agentgov_schema_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "empty.db"
    sqlite3.connect(path).close()
    with pytest.raises(LedgerUnverifiedError, match="cannot open"):
        LedgerAnchor(path)


def test_corrupt_file_fails_closed_rather_than_leaking_a_driver_error(
    tmp_path: Path,
) -> None:
    """A file that is not a database at all raises at the sqlite3 driver.

    That is below AgentGov's exception hierarchy, so it used to escape as a
    bare sqlite3.DatabaseError from a module documented to raise
    LedgerUnverifiedError, and a caller failing closed on the documented type
    would crash instead.
    """
    path = tmp_path / "corrupt.db"
    path.write_bytes(b"SQLite format 3\x00" + b"\xde\xad\xbe\xef" * 64)
    with pytest.raises(LedgerUnverifiedError, match="cannot open"):
        LedgerAnchor(path)


def test_every_unusable_ledger_raises_the_same_type(tmp_path: Path) -> None:
    """One exception type across every unusable-ledger path."""
    corrupt = tmp_path / "c.db"
    corrupt.write_bytes(b"not a database at all")
    empty = tmp_path / "e.db"
    sqlite3.connect(empty).close()
    tampered = build_ledger(tmp_path / "t.db")
    edit(tampered, "UPDATE entries SET memo='x' WHERE sequence=1")

    for candidate in (tmp_path / "missing.db", corrupt, empty, tampered, tmp_path):
        with pytest.raises(LedgerUnverifiedError):
            LedgerAnchor(candidate)


def test_a_ledger_failing_verification_after_open_is_refused_and_closed(
    ledger: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The defensive branch: open succeeds, verify_integrity then fails.

    open_sqlite verifies on the way in, so this is unreachable through the
    public API today. It is the branch that catches a future open path that
    does not verify, and it must close the manager rather than leak the handle
    and its read claim.
    """
    closed: list[bool] = []
    real_open = BudgetManager.open_sqlite

    def failing_open(path: str, **kwargs: Any) -> BudgetManager:
        manager = real_open(path, **kwargs)
        monkeypatch.setattr(
            manager,
            "verify_integrity",
            lambda: (_ for _ in ()).throw(LedgerIntegrityError("chain broken at 3")),
        )
        monkeypatch.setattr(manager, "close", lambda: closed.append(True))
        return manager

    monkeypatch.setattr("interlock.anchor.BudgetManager.open_sqlite", failing_open)

    with pytest.raises(LedgerUnverifiedError, match="failed verification, refusing to stage"):
        LedgerAnchor(ledger)
    assert closed == [True], "the rejected manager must be closed, not leaked"


def test_a_clean_ledger_attaches(ledger: Path) -> None:
    anchor = LedgerAnchor(ledger)
    try:
        assert anchor.attached is True
        assert anchor.can_reverse_anchor is False
    finally:
        anchor.close()


def test_an_audit_attachment_cannot_write(ledger: Path) -> None:
    """Audit mode opens read-only, so it cannot reverse-anchor."""
    anchor = LedgerAnchor(ledger)
    try:
        assert anchor.can_reverse_anchor is False
        assert anchor.reverse_anchor("root", "a" * 64) is None
    finally:
        anchor.close()


# --------------------------------------------------------------------------
# 2. Missing anchors: unanchored is never silently equivalent to anchored
# --------------------------------------------------------------------------


def test_unanchored_reports_itself_as_unattached() -> None:
    anchor = LedgerAnchor()
    assert anchor.attached is False
    assert anchor.can_reverse_anchor is False


def test_unanchored_observation_is_distinguishable_from_sequence_zero() -> None:
    """sequence -1, not 0: a real ledger with no entries observes at 0."""
    point = LedgerAnchor().observe()
    assert point == AnchorPoint(anchored=False, head_hash=GENESIS_HASH, sequence=-1)
    assert point.anchored is False
    assert point.sequence == -1


def test_an_empty_but_real_ledger_observes_at_sequence_zero() -> None:
    anchor = LedgerAnchor(governed=BudgetManager())
    point = anchor.observe()
    assert point.anchored is True
    assert point.sequence == 0
    assert point.head_hash == GENESIS_HASH


def test_unanchored_calls_are_all_no_ops() -> None:
    anchor = LedgerAnchor()
    assert anchor.observe().anchored is False
    assert anchor.reverse_anchor("scope", "hash") is None
    assert anchor.find_reverse_anchors() == ()
    # These return None; the assertion is that none of them raise or reach a
    # source that is not there.
    anchor.assert_scope_live("anything")
    anchor.verify()
    anchor.close()


# --------------------------------------------------------------------------
# 3. Observation
# --------------------------------------------------------------------------


def test_observation_advances_with_the_ledger() -> None:
    gov = BudgetManager()
    anchor = LedgerAnchor(governed=gov)
    gov.open_root("root", money("5.00"))
    first = anchor.observe()

    gov.delegate("root", "child", money("1.00"))
    second = anchor.observe()

    assert first.anchored is True
    assert second.sequence > first.sequence
    assert second.head_hash != first.head_hash
    assert second.head_hash == gov.ledger.head_hash


def test_observation_prefers_the_audit_handle(ledger: Path) -> None:
    """With both attached, the read-only audit handle is the source."""
    gov = BudgetManager()
    gov.open_root("other", money("1.00"))
    anchor = LedgerAnchor(ledger, governed=gov)
    try:
        assert anchor.observe().head_hash != gov.ledger.head_hash
    finally:
        anchor.close()


# --------------------------------------------------------------------------
# 4. The pre-commit breaker read
# --------------------------------------------------------------------------


def test_a_live_scope_passes() -> None:
    gov = BudgetManager()
    gov.open_root("root", money("5.00"))
    LedgerAnchor(governed=gov).assert_scope_live("root")  # must not raise


def test_a_halted_scope_is_refused() -> None:
    gov = BudgetManager()
    gov.open_root("root", money("5.00"))
    gov.trip("root", "denial of wallet")
    with pytest.raises(ScopeHaltedError, match="refusing to commit staged effects"):
        LedgerAnchor(governed=gov).assert_scope_live("root")


def test_a_halted_ancestor_refuses_the_descendant() -> None:
    """A halt that does not stop a child's in-flight effects does not stop them."""
    gov = BudgetManager()
    gov.open_root("root", money("5.00"))
    gov.delegate("root", "child", money("1.00"))
    gov.delegate("child", "grandchild", money("0.50"))
    gov.trip("root", "denial of wallet")

    with pytest.raises(ScopeHaltedError, match="root"):
        LedgerAnchor(governed=gov).assert_scope_live("grandchild")


def test_a_sibling_halt_does_not_refuse() -> None:
    gov = BudgetManager()
    gov.open_root("root", money("5.00"))
    gov.delegate("root", "left", money("1.00"))
    gov.delegate("root", "right", money("1.00"))
    gov.trip("left", "thrashing")

    LedgerAnchor(governed=gov).assert_scope_live("right")  # must not raise


def test_an_unknown_scope_does_not_crash_the_pre_commit_check() -> None:
    """Both ancestry() and halted_by() raise for an unknown scope.

    The check degrades to "nothing says this is halted" rather than raising a
    stray AgentGovError out of the commit path.
    """
    gov = BudgetManager()
    gov.open_root("root", money("5.00"))
    LedgerAnchor(governed=gov).assert_scope_live("never-registered")  # must not raise


# --------------------------------------------------------------------------
# 5. Re-verification
# --------------------------------------------------------------------------


def test_verify_passes_on_a_clean_ledger(ledger: Path) -> None:
    anchor = LedgerAnchor(ledger)
    try:
        anchor.verify()  # must not raise
    finally:
        anchor.close()


def test_verify_wraps_an_integrity_failure_in_the_interlock_type(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A caller catching LedgerUnverifiedError must not also have to know
    AgentGov's exception hierarchy."""
    gov = BudgetManager()
    gov.open_root("root", money("5.00"))
    monkeypatch.setattr(
        gov,
        "verify_integrity",
        lambda: (_ for _ in ()).throw(LedgerIntegrityError("conservation violated")),
    )
    with pytest.raises(LedgerUnverifiedError, match="conservation violated"):
        LedgerAnchor(governed=gov).verify()


# --------------------------------------------------------------------------
# 6. Reverse anchoring: Interlock's head, inside AgentGov's hash payload
# --------------------------------------------------------------------------


def test_reverse_anchor_writes_a_spend_carrying_the_chain_head() -> None:
    gov = BudgetManager()
    gov.open_root("scope", money("5.00"))
    entry = LedgerAnchor(governed=gov).reverse_anchor("scope", "a" * 64, cost="0.01")

    assert entry is not None
    assert entry.entry_type is EntryType.SPEND
    assert entry.memo == "interlock:" + "a" * 16
    assert entry.amount == Decimal("0.01")


def test_reverse_anchor_truncates_the_head_to_sixteen_hex_characters() -> None:
    gov = BudgetManager()
    gov.open_root("scope", money("5.00"))
    head = "0123456789abcdef" + "f" * 48
    entry = LedgerAnchor(governed=gov).reverse_anchor("scope", head, cost="0.01")

    assert entry is not None
    assert entry.memo == "interlock:0123456789abcdef"


def test_a_zero_settle_cost_is_refused_with_a_typed_error() -> None:
    """AgentGov rejects a non-positive authorization, so zero cannot anchor.

    Caught at this boundary rather than allowed to surface as AgentGov's bare
    ValueError from inside the commit path, where it arrives after the effects
    are durable and destroys the caller's StageResult.
    """
    gov = BudgetManager()
    gov.open_root("scope", money("5.00"))
    with pytest.raises(AnchorError, match="needs a positive settle cost"):
        LedgerAnchor(governed=gov).reverse_anchor("scope", "b" * 64)

    with pytest.raises(AnchorError):
        LedgerAnchor(governed=gov).reverse_anchor("scope", "b" * 64, cost=Decimal("-1"))

    assert gov.available("scope") == Decimal("5.00"), "nothing was written"


def test_reverse_anchor_accepts_decimal_and_string_costs() -> None:
    gov = BudgetManager()
    gov.open_root("scope", money("5.00"))
    anchor = LedgerAnchor(governed=gov)

    from_string = anchor.reverse_anchor("scope", "c" * 64, cost="0.02")
    from_decimal = anchor.reverse_anchor("scope", "d" * 64, cost=Decimal("0.02"))

    assert from_string is not None and from_decimal is not None
    assert from_string.amount == from_decimal.amount == Decimal("0.02")


def test_editing_a_reverse_anchor_breaks_agentgov_verification(tmp_path: Path) -> None:
    """The bidirectional claim, tested rather than asserted.

    The memo is inside AgentGov's hash payload, so an attacker who rewrites an
    Interlock chain head to point at a history they prefer invalidates
    AgentGov's chain in the process. Both must be forged together or neither.
    """
    path = tmp_path / "governor.db"
    gov = BudgetManager.open_sqlite(str(path))
    gov.open_root("scope", money("5.00"))
    LedgerAnchor(governed=gov).reverse_anchor("scope", "e" * 64, cost="0.01")
    gov.verify_integrity()
    gov.close()

    BudgetManager.open_sqlite(str(path), read_only=True).close()  # intact

    edit(path, "UPDATE entries SET memo='interlock:" + "0" * 16 + "' WHERE memo LIKE 'interlock:%'")

    with pytest.raises(LedgerUnverifiedError):
        LedgerAnchor(path)


def test_found_anchors_survive_a_round_trip_through_disk(tmp_path: Path) -> None:
    path = tmp_path / "governor.db"
    gov = BudgetManager.open_sqlite(str(path))
    gov.open_root("scope", money("5.00"))
    heads = ["1" * 64, "2" * 64, "3" * 64]
    for head in heads:
        LedgerAnchor(governed=gov).reverse_anchor("scope", head, cost="0.01")
    gov.close()

    anchor = LedgerAnchor(path)
    try:
        found = anchor.find_reverse_anchors()
        assert [entry.memo for entry in found] == [f"interlock:{h[:16]}" for h in heads]
    finally:
        anchor.close()


# --------------------------------------------------------------------------
# 7. Finding anchors without over-matching
# --------------------------------------------------------------------------


def test_find_reverse_anchors_excludes_the_hold_carrying_the_same_memo() -> None:
    """authorize() and capture() both write the memo; only the settled SPEND
    is an anchor. Counting the HOLD would double every anchor."""
    gov = BudgetManager()
    gov.open_root("scope", money("5.00"))
    LedgerAnchor(governed=gov).reverse_anchor("scope", "f" * 64, cost="0.01")

    with_memo = [e for e in gov.audit_trail() if e.memo.startswith("interlock:")]
    found = LedgerAnchor(governed=gov).find_reverse_anchors()

    assert {e.entry_type for e in with_memo} == {EntryType.HOLD, EntryType.SPEND}
    assert len(found) == 1
    assert found[0].entry_type is EntryType.SPEND


def test_find_reverse_anchors_ignores_unrelated_spend() -> None:
    gov = BudgetManager()
    gov.open_root("scope", money("5.00"))
    unrelated = gov.authorize("scope", money("0.10"), memo="a normal model call")
    gov.capture(unrelated, money("0.05"), memo="a normal model call")
    LedgerAnchor(governed=gov).reverse_anchor("scope", "9" * 64, cost="0.01")

    found = LedgerAnchor(governed=gov).find_reverse_anchors()
    assert len(found) == 1
    assert found[0].memo == "interlock:" + "9" * 16


def test_find_reverse_anchors_does_not_match_a_memo_merely_containing_the_prefix() -> None:
    """startswith, not a substring search: an agent-authored memo that quotes
    the prefix mid-string is not an anchor."""
    gov = BudgetManager()
    gov.open_root("scope", money("5.00"))
    forged = gov.authorize("scope", money("0.10"), memo="see interlock:deadbeefdeadbeef below")
    gov.capture(forged, money("0.05"), memo="see interlock:deadbeefdeadbeef below")

    assert LedgerAnchor(governed=gov).find_reverse_anchors() == ()


# --------------------------------------------------------------------------
# 8. Handle lifecycle
# --------------------------------------------------------------------------


def test_close_is_idempotent(ledger: Path) -> None:
    anchor = LedgerAnchor(ledger)
    anchor.close()
    anchor.close()
    assert anchor.attached is False


def test_close_releases_the_handle_so_a_writer_can_claim_the_file(ledger: Path) -> None:
    """Audit mode takes no write claim, and close() must leave none behind."""
    anchor = LedgerAnchor(ledger)
    assert anchor.attached is True
    anchor.close()

    with BudgetManager.open_sqlite(str(ledger)) as writer:
        writer.open_root("second-root", money("1.00"))
        writer.verify_integrity()


def test_closing_an_audit_handle_leaves_a_governed_handle_usable() -> None:
    gov = BudgetManager()
    gov.open_root("scope", money("5.00"))
    anchor = LedgerAnchor(governed=gov)
    anchor.close()

    assert anchor.can_reverse_anchor is True
    assert anchor.reverse_anchor("scope", "7" * 64, cost="0.01") is not None
