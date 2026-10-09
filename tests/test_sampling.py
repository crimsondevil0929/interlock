"""Sampling the database for the metrics (``docs/EPIC7_DESIGN.md`` §2.4), on
both stores.

- The outbox is read by state, every state named, and by the age of its
  oldest message still due.
- A delivery is in settlement's backlog until it is settled.
- A rate window is read by its fullest key, within its span.
- The inbox is read for facts no plan has consumed and events bound to no
  delivery.
- On PostgreSQL an audit role may take the sample, and a stage role may not.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Iterator
from datetime import timedelta
from decimal import Decimal
from pathlib import Path

import psycopg
import pytest
from psycopg.conninfo import make_conninfo

from interlock.postgres import install
from interlock.sampling import STATES, Sample, sample_postgres, sample_sqlite
from interlock.sqlite_outbox import now_us
from interlock.windows import RateWindow, Requests
from tests.conftest import OBSERVED, PASSWORD, create_role, drop_role
from tests.fakesink import status
from tests.inbox_env import InboxSite, inbox_site, refund_event, stripe_webhook
from tests.outbox_env import (
    BACKENDS,
    RELAY_SINKS,
    Outbox,
    PostgresOutbox,
    SqliteOutbox,
    build_either,
    mail,
    sms,
)
from tests.schemas import specs
from tests.settling import Bench
from tests.test_windows import requests_plan


@pytest.fixture(params=BACKENDS)
def outbox(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Outbox]:
    yield from build_either(request, tmp_path)


def sample(outbox: Outbox, windows: tuple[RateWindow, ...] = (), dsn: str = "") -> Sample:
    if isinstance(outbox, PostgresOutbox):
        return sample_postgres(dsn or outbox.pg.admin, windows, timeout=10)
    assert isinstance(outbox, SqliteOutbox)
    return sample_sqlite(outbox.path, windows, now_us=now_us())


def test_an_empty_outbox_reads_as_zeros(outbox: Outbox) -> None:
    read = sample(outbox)
    assert read.states == dict.fromkeys(STATES, 0)
    assert (read.oldest_due, read.backlog, read.oldest_unsettled) == (None, 0, None)
    assert (read.facts_pending, read.events_unmatched) == (0, 0)


def test_the_outbox_is_read_by_state_and_by_its_oldest_message_due(outbox: Outbox) -> None:
    _, (first, *_) = outbox.commit(mail(1), mail(2), sms(3))
    time.sleep(0.05)
    read = sample(outbox)
    assert read.states == {**dict.fromkeys(STATES, 0), "pending": 3}
    assert read.oldest_due is not None and read.oldest_due >= 0.05
    # One dead, two delivered: none due, and both delivered wait to be settled.
    outbox.sink("mail").script(status(400))
    with outbox.relay() as relay:
        outbox.drain(relay)
    read = sample(outbox)
    assert read.states == {**dict.fromkeys(STATES, 0), "delivered": 2, "dead": 1}
    assert read.oldest_due is None
    assert read.backlog == 2 and read.oldest_unsettled is not None
    assert read.states == {**dict.fromkeys(STATES, 0), **outbox.states()}
    assert first is not None


def test_a_delivery_is_in_the_backlog_until_it_is_settled(outbox: Outbox, tmp_path: Path) -> None:
    bench = Bench(outbox, tmp_path)
    try:
        bench.book_together(1)
        bench.book_together(2)
        bench.deliver()
        assert sample(outbox).backlog == 2
        bench.settler().settle()
        assert sample(outbox).backlog == 0
        bench.book_together(3)
        bench.deliver()
        read = sample(outbox)
        assert read.backlog == 1 and read.oldest_unsettled is not None
    finally:
        bench.close()


def test_a_window_is_read_by_its_fullest_key_within_its_span(outbox: Outbox) -> None:
    window = RateWindow("mail_per_hour", timedelta(hours=1), 10, Requests("mail"))
    short = RateWindow("mail_now", timedelta(milliseconds=200), 10, Requests("mail"))
    engine = outbox.engine(windows=[window, short])
    for n in range(3):
        assert engine.execute(requests_plan(mail(n))).committed
    assert engine.execute(requests_plan(mail(9), scope="other")).committed
    read = sample(outbox, (window, short))
    assert read.windows["mail_per_hour"] == (Decimal(3), 2)
    time.sleep(0.25)
    # Past its span, the short window holds nothing; the hour still holds it all.
    read = sample(outbox, (window, short))
    assert read.windows == {"mail_per_hour": (Decimal(3), 2), "mail_now": (Decimal(0), 0)}


@pytest.fixture
def site(outbox: Outbox) -> Iterator[InboxSite]:
    with inbox_site(outbox) as installed:
        yield installed


def test_the_inbox_is_read_for_pending_facts_and_unmatched_events(site: InboxSite) -> None:
    site.deliver("re_1", "re_2")
    inbox = site.inbox()
    for n, ref in enumerate(("re_1", "re_2", "re_nobody")):
        answer = site.receive(inbox, "stripe", stripe_webhook(refund_event(ref, event_id=f"e{n}")))
        assert answer.status == 200
    read = sample(site.outbox)
    assert (read.facts_pending, read.events_unmatched) == (2, 1)


def test_postgresql_is_sampled_by_an_audit_role_and_not_a_stage_role(outbox: Outbox) -> None:
    if not isinstance(outbox, PostgresOutbox):
        pytest.skip("PostgreSQL's roles")
    audit = f"il_audit_{uuid.uuid4().hex[:8]}"
    create_role(outbox.pg.cluster, audit)
    try:
        install(
            outbox.operator(),
            specs(*OBSERVED),
            stage_roles=[outbox.pg.role],
            sinks=RELAY_SINKS,
            relay_roles=[outbox.relay_role],
            audit_roles=[audit],
        )
        outbox.commit(mail(1))
        window = RateWindow("mail_per_hour", timedelta(hours=1), 10, Requests("mail"))
        read = sample(
            outbox, (window,), make_conninfo(outbox.pg.admin, user=audit, password=PASSWORD)
        )
        assert read.states["pending"] == 1 and read.windows["mail_per_hour"] == (Decimal(0), 0)
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            sample(outbox, (window,), outbox.pg.agent)
    finally:
        drop_role(outbox.pg.cluster, outbox.pg.admin, audit)
