"""The metrics registry and its endpoint (``docs/EPIC7_DESIGN.md`` §2).

- Every metric is declared once, with its labels: anything else is refused.
- Counters add, gauges set, histograms count into cumulative buckets, a peak
  is the largest value of the last minute; collectors run at each scrape.
- The text is Prometheus's format, version 0.0.4, checked line by line against
  its grammar, labels escaped.
- Writes from many threads add up exactly, and cost microseconds.
- ``/metrics`` and ``/healthz`` are served on a listener of their own.
"""

from __future__ import annotations

import json
import re
import threading
import time
import urllib.request
from collections.abc import Iterator

import pytest

from interlock.telemetry import (
    CATALOG,
    CONTENT_TYPE,
    COUNTER,
    HISTOGRAM,
    LATENCY,
    PEAK,
    Metric,
    Metrics,
    MetricsServer,
    NullMetrics,
)

_NAME = re.compile(r"[a-zA-Z_:][a-zA-Z0-9_:]*")
_SAMPLE = re.compile(
    r"(?P<name>[a-zA-Z_:][a-zA-Z0-9_:]*)"
    r"(?:\{(?P<labels>(?:[a-zA-Z_][a-zA-Z0-9_]*=\"(?:[^\"\\\n]|\\[\\\"n])*\",?)*)\})?"
    r" (?P<value>[-+]?(?:[0-9.]+(?:[eE][-+]?[0-9]+)?|Inf|NaN))"
)
_LABEL = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\\n]|\\[\\"n])*)"')


def parse(text: str) -> dict[str, dict[tuple[tuple[str, str], ...], float]]:
    """The samples of a Prometheus text exposition, failing on any line the
    format does not allow. ``{name: {labels: value}}``."""
    assert text.endswith("\n")
    samples: dict[str, dict[tuple[tuple[str, str], ...], float]] = {}
    typed: dict[str, str] = {}
    for line in text.rstrip("\n").split("\n"):
        if line.startswith("# HELP "):
            name = line.split(" ", 3)[2]
            assert _NAME.fullmatch(name), line
            continue
        if line.startswith("# TYPE "):
            _, _, name, kind = line.split(" ")
            assert kind in ("counter", "gauge", "histogram", "summary", "untyped"), line
            assert name not in typed, f"{name} typed twice"
            typed[name] = kind
            continue
        match = _SAMPLE.fullmatch(line)
        assert match is not None, f"not a sample: {line!r}"
        labels = tuple(_LABEL.findall(match.group("labels") or ""))
        value = match.group("value")
        number = float("inf") if value == "+Inf" else float(value)
        series = samples.setdefault(match.group("name"), {})
        assert labels not in series, f"{line!r} twice"
        series[labels] = number
    return samples


@pytest.fixture
def metrics() -> Metrics:
    return Metrics()


# --------------------------------------------------------------------------
# the catalog
# --------------------------------------------------------------------------


def test_every_metric_is_declared_once_and_named_as_prometheus_asks() -> None:
    names = [m.name for m in CATALOG]
    assert len(names) == len(set(names))
    for metric in CATALOG:
        assert metric.name.startswith("interlock_") and _NAME.fullmatch(metric.name)
        assert metric.help and metric.help.endswith(".")
        assert metric.name.endswith("_total") == (metric.kind == COUNTER), metric.name
        assert bool(metric.buckets) == (metric.kind == HISTOGRAM), metric.name
        assert list(metric.buckets) == sorted(metric.buckets)
        for label in metric.labels:
            assert re.fullmatch(r"[a-z][a-z_]*", label) and label != "le"
        # Never a label that grows with the traffic.
        assert not {"tenant", "scope", "plan", "key", "message"} & set(metric.labels)


def test_what_is_not_declared_is_refused(metrics: Metrics) -> None:
    with pytest.raises(KeyError, match="no metric"):
        metrics.inc("interlock_plans")
    with pytest.raises(ValueError, match="takes the labels"):
        metrics.inc("interlock_plans_total", outcom="committed")
    with pytest.raises(ValueError, match="takes the labels"):
        metrics.inc("interlock_plans_total")
    with pytest.raises(TypeError, match="is a counter"):
        metrics.observe("interlock_plans_total", 1.0, outcome="committed")
    with pytest.raises(TypeError, match="is a histogram"):
        metrics.set("interlock_plan_seconds", 1.0, outcome="committed")


# --------------------------------------------------------------------------
# what each kind keeps
# --------------------------------------------------------------------------


def test_counters_add_gauges_set_and_histograms_count(metrics: Metrics) -> None:
    metrics.inc("interlock_plans_total", outcome="committed")
    metrics.inc("interlock_plans_total", 2, outcome="committed")
    metrics.inc("interlock_plans_total", outcome="refused")
    metrics.set("interlock_engine_queue_depth", 7)
    metrics.set("interlock_engine_queue_depth", 3)
    for seconds in (0.0004, 0.003, 0.003, 0.2, 99.0):
        metrics.observe("interlock_plan_seconds", seconds, outcome="committed")
    assert metrics.value("interlock_plans_total", outcome="committed") == 3
    assert metrics.value("interlock_engine_queue_depth") == 3
    assert metrics.value("interlock_plan_seconds", outcome="committed") == 5
    samples = parse(metrics.render())
    assert samples["interlock_plans_total"] == {
        (("outcome", "committed"),): 3,
        (("outcome", "refused"),): 1,
    }
    buckets = {
        dict(labels)["le"]: value
        for labels, value in samples["interlock_plan_seconds_bucket"].items()
    }
    # Cumulative, and +Inf is the count.
    assert buckets["0.001"] == 1 and buckets["0.005"] == 3 and buckets["0.25"] == 4
    assert buckets["10"] == 4 and buckets["+Inf"] == 5
    assert list(buckets.values()) == sorted(buckets.values())
    assert samples["interlock_plan_seconds_count"] == {(("outcome", "committed"),): 5}
    assert samples["interlock_plan_seconds_sum"][(("outcome", "committed"),)] == pytest.approx(
        99.2064
    )


def test_a_peak_is_the_largest_of_the_last_minute(
    metrics: Metrics, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = [1000.0]
    monkeypatch.setattr(time, "monotonic", lambda: clock[0])
    metrics.observe("interlock_wait_max_seconds", 0.2, wait="pool")
    metrics.observe("interlock_wait_max_seconds", 1.5, wait="pool")
    clock[0] += 30
    metrics.observe("interlock_wait_max_seconds", 0.4, wait="pool")
    assert metrics.value("interlock_wait_max_seconds", wait="pool") == 1.5
    clock[0] += 31  # the spike is more than a minute old
    assert metrics.value("interlock_wait_max_seconds", wait="pool") == 0.4
    assert parse(metrics.render())["interlock_wait_max_seconds"] == {(("wait", "pool"),): 0.4}
    clock[0] += 61
    assert parse(metrics.render())["interlock_wait_max_seconds"] == {(("wait", "pool"),): 0}


def test_a_peak_keeps_a_minute_of_seconds_however_many_are_observed(
    metrics: Metrics, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = [1000.0]
    monkeypatch.setattr(time, "monotonic", lambda: clock[0])
    for n in range(12_000):  # a hundred a second, for two minutes
        clock[0] = 1000.0 + n / 100
        metrics.observe("interlock_wait_max_seconds", n % 7 / 10, wait="pool")
    seconds = metrics._families["interlock_wait_max_seconds"].peaks[("pool",)]
    assert len(seconds) <= 61
    assert metrics.value("interlock_wait_max_seconds", wait="pool") == 0.6


def test_collectors_run_at_each_scrape_and_a_family_can_be_cleared(metrics: Metrics) -> None:
    states = {"pending": 4, "dead": 1}

    def count(m: Metrics) -> None:
        for state, n in states.items():
            m.set("interlock_outbox_messages", n, state=state)

    metrics.collect(count)
    assert parse(metrics.render())["interlock_outbox_messages"] == {
        (("state", "dead"),): 1,
        (("state", "pending"),): 4,
    }
    metrics.clear("interlock_outbox_messages")
    states.pop("dead")
    assert parse(metrics.render())["interlock_outbox_messages"] == {(("state", "pending"),): 4}


def test_label_values_are_escaped_and_unlabelled_metrics_start_at_zero(metrics: Metrics) -> None:
    metrics.inc("interlock_webhooks_total", source='odd"\\name\n', status="200")
    samples = parse(metrics.render())
    assert samples["interlock_webhooks_total"] == {
        (("source", 'odd\\"\\\\name\\n'), ("status", "200")): 1
    }
    assert samples["interlock_pool_exhausted_total"] == {(): 0}
    assert "interlock_deliveries_total" not in samples  # labelled: nothing until written


def test_null_metrics_keeps_nothing() -> None:
    null = NullMetrics()
    null.inc("anything")
    null.set("anything", 1)
    null.observe("anything", 1)
    assert null.render() == "\n"


# --------------------------------------------------------------------------
# under load
# --------------------------------------------------------------------------


def test_writes_from_many_threads_add_up(metrics: Metrics) -> None:
    def write() -> None:
        for _ in range(5000):
            metrics.inc("interlock_plans_total", outcome="committed")
            metrics.observe("interlock_plan_seconds", 0.01, outcome="committed")

    threads = [threading.Thread(target=write) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert metrics.value("interlock_plans_total", outcome="committed") == 40_000
    assert metrics.value("interlock_plan_seconds", outcome="committed") == 40_000


def test_a_write_costs_microseconds(metrics: Metrics) -> None:
    n = 50_000
    began = time.perf_counter()
    for _ in range(n):
        metrics.inc("interlock_plans_total", outcome="committed")
        metrics.observe("interlock_plan_seconds", 0.012, outcome="committed")
    per_write = (time.perf_counter() - began) / (2 * n)
    # Measured near 1µs; the bound is generous, for a loaded machine.
    assert per_write < 50e-6, f"{per_write * 1e6:.1f}µs a write"


# --------------------------------------------------------------------------
# the endpoint
# --------------------------------------------------------------------------


@pytest.fixture
def server(metrics: Metrics) -> Iterator[MetricsServer]:
    served = MetricsServer(metrics, "127.0.0.1", 0, health=lambda: (503, {"status": "degraded"}))
    served.start()
    try:
        yield served
    finally:
        served.stop()


def _get(port: int, path: str) -> tuple[int, str, bytes]:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=5) as answer:
            return answer.status, answer.headers["Content-Type"], answer.read()
    except urllib.error.HTTPError as refused:
        return refused.code, refused.headers["Content-Type"], refused.read()


def test_metrics_and_health_are_served_on_a_listener_of_their_own(
    metrics: Metrics, server: MetricsServer
) -> None:
    metrics.inc("interlock_plans_total", outcome="committed")
    status, kind, body = _get(server.port, "/metrics")
    assert (status, kind) == (200, CONTENT_TYPE)
    assert parse(body.decode())["interlock_plans_total"] == {(("outcome", "committed"),): 1}
    assert _get(server.port, "/healthz")[0] == 503
    assert json.loads(_get(server.port, "/healthz")[2]) == {"status": "degraded"}
    assert _get(server.port, "/inbox/stripe")[0] == 404
    server.stop()
    server.stop()  # idempotent


def test_a_catalog_of_ones_own(metrics: Metrics) -> None:
    custom = Metrics([Metric("app_jobs_total", COUNTER, "Jobs."), Metric("app_p", PEAK, "P.")])
    custom.inc("app_jobs_total")
    assert parse(custom.render()) == {"app_jobs_total": {(): 1}}
    assert LATENCY[0] < LATENCY[-1]
