"""The security audit (``docs/EPIC8_DESIGN.md`` §4): ``scripts/security_audit.py``
runs its scenario on each store, and no sensitive value reaches a hash. And the
audit is seen to catch a leak: one planted in a plan's hash, one in a column.
"""

from __future__ import annotations

import importlib.util
import sys
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def audit(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """The script, imported; the secrets it hands the daemon, restored after."""
    spec = importlib.util.spec_from_file_location(
        "security_audit", ROOT / "scripts" / "security_audit.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)
    monkeypatch.setenv(module.API_KEY_ENV, "")
    monkeypatch.setenv(module.WEBHOOK_SECRET_ENV, "")
    return module


def run_on(audit: ModuleType, store: Any) -> Any:
    said: list[str] = []
    try:
        run = audit.audit(store, audit.Canaries.make(), say=said.append)
    finally:
        store.close()
    audit.report(run, said.append)
    return run, "\n".join(said)


def test_nothing_sensitive_reaches_a_hash_on_sqlite(audit: ModuleType, tmp_path: Path) -> None:
    run, said = run_on(audit, audit.SqliteStore(tmp_path / "sqlite"))
    assert run.clean, said
    # Every family of hash was computed, and recorded.
    assert all(run.families.values()), run.families
    # The body is committed to by its SHA-256 alone; the trace, kept beside.
    assert set(run.commitments) == {
        "the body's own SHA-256",
        "the inbound event's hash, over the body's SHA-256",
        "the inbound event's statement, over the body's SHA-256",
    }
    held = {(audit._name(t), c) for t, c in run.held}
    assert held == set(audit.KEPT)
    assert "_interlock_outbox_traces.traceparent: the trace id; read by no hash" in said


def test_nothing_sensitive_reaches_a_hash_on_postgresql(
    audit: ModuleType, tmp_path: Path, pg_admin_dsn: str
) -> None:
    run, said = run_on(audit, audit.PostgresStore(tmp_path / "postgres", pg_admin_dsn))
    assert run.clean, said
    assert all(run.families.values()), run.families
    held = {(audit._name(t), c) for t, c in run.held}
    assert held == set(audit.KEPT)


def test_a_trace_hashed_into_a_plan_is_caught(
    audit: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from interlock.types import EffectPlan, canonical_hash

    honest: Callable[[EffectPlan], str] = EffectPlan.content_hash

    def leaky(plan: EffectPlan) -> str:
        return canonical_hash([honest(plan), plan.traceparent])

    monkeypatch.setattr(EffectPlan, "content_hash", leaky)
    run, said = run_on(audit, audit.SqliteStore(tmp_path / "sqlite"))
    assert not run.clean
    assert any("holds the trace id" in leak and "sha256 input" in leak for leak in run.leaks), said


def test_a_header_kept_where_it_should_not_be_is_caught(
    audit: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from interlock.inbox import Inbox

    def everything(source: Any, headers: Any) -> str:
        import json

        return json.dumps(dict(headers), sort_keys=True)

    monkeypatch.setattr(Inbox, "_signature_headers", staticmethod(everything))
    run, said = run_on(audit, audit.SqliteStore(tmp_path / "sqlite"))
    assert not run.clean
    assert any(
        leak.endswith("_interlock_inbox_events.signature holds the header canary (itself)")
        for leak in run.leaks
    ), said


def test_the_script_exits_zero_when_clean(audit: ModuleType) -> None:
    assert audit.main([]) == 0
