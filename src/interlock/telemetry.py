"""Prometheus metrics (``docs/EPIC7_DESIGN.md`` §2).

Every metric Interlock exports is declared once, in :data:`CATALOG`, with the
labels it takes: a name or a label set it does not declare is refused, so a
typo fails a test rather than a dashboard. The parts measure into a
:class:`Metrics` (the supervisor owns one), or into :class:`NullMetrics`,
which keeps nothing, when they run outside it::

    metrics = Metrics()
    metrics.inc("interlock_plans_total", outcome="committed")
    metrics.observe("interlock_plan_seconds", 0.012, outcome="committed")
    text = metrics.render()   # the Prometheus text format, version 0.0.4

Every label is drawn from configuration or a closed set (services, sinks,
windows, sources, states, outcomes): never a tenant, a scope, a plan or a key,
so the series are fixed by the configuration, not by the traffic.
"""

from __future__ import annotations

import math
import socketserver
import threading
import time
from collections import deque
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Final

__all__ = [
    "CATALOG",
    "CONTENT_TYPE",
    "Metric",
    "Metrics",
    "MetricsServer",
    "NullMetrics",
]

COUNTER: Final = "counter"
GAUGE: Final = "gauge"
HISTOGRAM: Final = "histogram"
PEAK: Final = "peak"
"""A gauge of the largest value observed over the last :data:`PEAK_SECONDS`,
to the second: spikes a histogram's quantiles smooth away."""
PEAK_SECONDS: Final = 60.0

CONTENT_TYPE: Final = "text/plain; version=0.0.4; charset=utf-8"

LATENCY: Final = (0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)
"""Buckets for what takes milliseconds to seconds: a stage, a call, a wait."""
LAG: Final = (0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0, 1800.0)
"""Buckets for what takes seconds to half an hour: a delivery's settlement."""


@dataclass(frozen=True, slots=True)
class Metric:
    """One metric family: its name, kind, meaning, labels and, for a
    histogram, its buckets' upper bounds."""

    name: str
    kind: str
    help: str
    labels: tuple[str, ...] = ()
    buckets: tuple[float, ...] = ()


CATALOG: Final = (
    Metric("interlock_build_info", GAUGE, "Interlock's version, as a label: 1.", ("version",)),
    # -- every part ------------------------------------------------------------
    Metric("interlock_service_up", GAUGE, "1 while a part runs, 0 otherwise.", ("service",)),
    Metric("interlock_service_busy", GAUGE, "1 while a part's step runs.", ("service",)),
    Metric("interlock_service_steps_total", COUNTER, "Steps a part ran to the end.", ("service",)),
    Metric(
        "interlock_service_failures_total",
        COUNTER,
        "Steps, or opens, a part failed and was restarted after.",
        ("service",),
    ),
    Metric(
        "interlock_service_step_seconds",
        HISTOGRAM,
        "How long a part's steps took.",
        ("service",),
        LATENCY,
    ),
    # -- the engines -------------------------------------------------------------
    Metric("interlock_engine_workers", GAUGE, "Engine workers: plans staged at once, at most."),
    Metric("interlock_engine_workers_busy", GAUGE, "Engine workers staging a plan now."),
    Metric("interlock_engine_queue_depth", GAUGE, "Plans waiting for an engine worker."),
    Metric(
        "interlock_engine_queue_wait_seconds",
        HISTOGRAM,
        "How long a plan waited for an engine worker.",
        (),
        LATENCY,
    ),
    Metric(
        "interlock_plans_total",
        COUNTER,
        "Plans staged: committed, refused, failed, unsettled or cancelled.",
        ("outcome",),
    ),
    Metric(
        "interlock_plan_seconds",
        HISTOGRAM,
        "How long a plan took to stage, its retries included.",
        ("outcome",),
        LATENCY,
    ),
    Metric(
        "interlock_plan_conflicts_total",
        COUNTER,
        "Races a plan lost and was staged again after: for a lock, or a pooled connection.",
        ("cause",),
    ),
    Metric(
        "interlock_window_refusals_total",
        COUNTER,
        "Plans a rate window refused.",
        ("window",),
    ),
    # -- waits ---------------------------------------------------------------------
    Metric(
        "interlock_window_lock_wait_seconds",
        HISTOGRAM,
        "PostgreSQL: how long a stage waited for the locks on its rate windows' keys.",
        (),
        LATENCY,
    ),
    Metric(
        "interlock_pool_wait_seconds",
        HISTOGRAM,
        "PostgreSQL: how long a stage waited for its rate windows' connection.",
        (),
        LATENCY,
    ),
    Metric(
        "interlock_pool_exhausted_total",
        COUNTER,
        "PostgreSQL: stages that found no connection for their rate windows in time.",
    ),
    Metric(
        "interlock_wait_max_seconds",
        PEAK,
        "The longest wait of each kind over the last minute: window_lock, pool.",
        ("wait",),
    ),
    # -- the relays ----------------------------------------------------------------
    Metric(
        "interlock_deliveries_total",
        COUNTER,
        "What became of each message a relay leased: delivered, retryable, permanent, "
        "unknown, held, deferred or refused.",
        ("sink", "outcome"),
    ),
    Metric(
        "interlock_delivery_seconds",
        HISTOGRAM,
        "How long a relay's call to a sink took.",
        ("sink",),
        LATENCY,
    ),
    # -- the outbox, sampled ---------------------------------------------------------
    Metric(
        "interlock_outbox_messages",
        GAUGE,
        "Messages in the outbox, by delivery state.",
        ("state",),
    ),
    Metric(
        "interlock_outbox_oldest_due_seconds",
        GAUGE,
        "How long the oldest message still due (pending or leased) has been in the outbox.",
    ),
    # -- the rate windows, sampled ---------------------------------------------------------
    Metric(
        "interlock_window_value",
        GAUGE,
        "What the fullest key of a rate window holds within its span.",
        ("window",),
    ),
    Metric("interlock_window_limit", GAUGE, "A rate window's limit.", ("window",)),
    Metric(
        "interlock_window_saturation",
        GAUGE,
        "The fullest key's total over the window's limit.",
        ("window",),
    ),
    Metric(
        "interlock_window_keys",
        GAUGE,
        "Keys with anything in a rate window's span.",
        ("window",),
    ),
    # -- settlement --------------------------------------------------------------------
    Metric(
        "interlock_settlement_lag_seconds",
        HISTOGRAM,
        "From a request's delivery to its delivery receipt.",
        (),
        LAG,
    ),
    Metric(
        "interlock_settlement_backlog",
        GAUGE,
        "Messages delivered and not settled yet (sampled).",
    ),
    Metric(
        "interlock_settlement_oldest_seconds",
        GAUGE,
        "How long the oldest delivered message has waited to be settled (sampled).",
    ),
    Metric("interlock_receipts_issued_total", COUNTER, "Delivery receipts the settler issued."),
    Metric("interlock_credits_total", COUNTER, "Credits the settler posted for compensations."),
    # -- the inbox ---------------------------------------------------------------------
    Metric(
        "interlock_webhooks_total",
        COUNTER,
        "Webhooks the inbox answered, by source and HTTP status.",
        ("source", "status"),
    ),
    Metric(
        "interlock_webhook_traceparent_total",
        COUNTER,
        "Webhooks taken, by the trace context they carried: valid, invalid or absent.",
        ("source", "result"),
    ),
    Metric(
        "interlock_inbox_facts_pending",
        GAUGE,
        "Facts recorded and not consumed by a plan yet (sampled).",
    ),
    Metric(
        "interlock_inbox_events_unmatched",
        GAUGE,
        "Inbound events bound to no delivery yet (sampled).",
    ),
    # -- the vacuum ---------------------------------------------------------------------
    Metric(
        "interlock_vacuum_runs_total",
        COUNTER,
        "Vacuum runs: applied, nothing, refused, rejected, abandoned or busy.",
        ("outcome",),
    ),
    Metric(
        "interlock_vacuum_pruned_total",
        COUNTER,
        "What vacuums pruned: messages, window_rows, inbox_events.",
        ("kind",),
    ),
    # -- the sampler itself ----------------------------------------------------------------
    Metric(
        "interlock_metrics_sampled_at_seconds",
        GAUGE,
        "When the database was last sampled, in seconds since the epoch: how old the "
        "sampled gauges are.",
    ),
    Metric(
        "interlock_metrics_sample_errors_total",
        COUNTER,
        "Samples of the database that failed.",
    ),
)


@dataclass
class _Family:
    metric: Metric
    lock: threading.Lock = field(default_factory=threading.Lock)
    values: dict[tuple[str, ...], float] = field(default_factory=dict)
    histograms: dict[tuple[str, ...], list[float]] = field(default_factory=dict)
    peaks: dict[tuple[str, ...], deque[tuple[float, float]]] = field(default_factory=dict)


class Metrics:
    """The metrics of one process: every family :data:`CATALOG` declares.

    Thread-safe: one lock per family, held for a dictionary update. Gauges
    that are a reading of something else at the moment of a scrape, a part's
    state say, are set by collectors (:meth:`collect`), which :meth:`render`
    runs first.
    """

    def __init__(self, catalog: Iterable[Metric] = CATALOG) -> None:
        self._families = {metric.name: _Family(metric) for metric in catalog}
        self._collectors: list[Callable[[Metrics], None]] = []
        self._collecting = threading.Lock()

    # -- writing ---------------------------------------------------------------

    def inc(self, name: str, value: float = 1.0, **labels: str) -> None:
        """Add ``value`` to a counter."""
        family, key = self._family(name, labels, COUNTER)
        with family.lock:
            family.values[key] = family.values.get(key, 0.0) + value

    def set(self, name: str, value: float, **labels: str) -> None:
        """Set a gauge, or a counter whose value is read from elsewhere."""
        family, key = self._family(name, labels, GAUGE, COUNTER)
        with family.lock:
            family.values[key] = float(value)

    def observe(self, name: str, value: float, **labels: str) -> None:
        """Count an observation into a histogram's buckets, or a peak's minute."""
        family, key = self._family(name, labels, HISTOGRAM, PEAK)
        if family.metric.kind == PEAK:
            with family.lock:
                # The largest of each second: a minute is at most 61 of them,
                # however many are observed. Read under the lock, so the
                # seconds are appended in order.
                now = time.monotonic()
                second = float(math.floor(now))
                window = family.peaks.setdefault(key, deque())
                if window and window[-1][0] == second:
                    if value > window[-1][1]:
                        window[-1] = (second, float(value))
                else:
                    window.append((second, float(value)))
                _expire(window, now)
            return
        buckets = family.metric.buckets
        with family.lock:
            counts = family.histograms.get(key)
            if counts is None:
                # One count per bucket, then +Inf, the sum and the count.
                counts = family.histograms[key] = [0.0] * (len(buckets) + 3)
            for index, bound in enumerate(buckets):
                if value <= bound:
                    counts[index] += 1
                    break
            else:
                counts[len(buckets)] += 1
            counts[-2] += value
            counts[-1] += 1

    def clear(self, name: str) -> None:
        """Forget every series of a family: a sampled gauge whose label sets
        the next sample decides afresh."""
        family = self._families[name]
        with family.lock:
            family.values.clear()
            family.histograms.clear()
            family.peaks.clear()

    def collect(self, collector: Callable[[Metrics], None]) -> None:
        """Run ``collector`` before every render: for gauges read at the scrape."""
        self._collectors.append(collector)

    # -- reading ---------------------------------------------------------------

    def value(self, name: str, **labels: str) -> float:
        """A counter's or gauge's value, a histogram's count, a peak's
        maximum: 0 for a series never written."""
        family, key = self._family(name, labels, COUNTER, GAUGE, HISTOGRAM, PEAK)
        with family.lock:
            if family.metric.kind == HISTOGRAM:
                counts = family.histograms.get(key)
                return 0.0 if counts is None else counts[-1]
            if family.metric.kind == PEAK:
                window = family.peaks.get(key)
                if not window:
                    return 0.0
                _expire(window, time.monotonic())
                return max((v for _, v in window), default=0.0)
            return family.values.get(key, 0.0)

    def render(self) -> str:
        """Every family, in the Prometheus text format (version 0.0.4)."""
        with self._collecting:
            for collector in self._collectors:
                collector(self)
        lines: list[str] = []
        now = time.monotonic()
        for family in self._families.values():
            metric = family.metric
            kind = GAUGE if metric.kind == PEAK else metric.kind
            lines.append(f"# HELP {metric.name} {_help(metric.help)}")
            lines.append(f"# TYPE {metric.name} {kind}")
            with family.lock:
                if metric.kind == HISTOGRAM:
                    for key, counts in sorted(family.histograms.items()):
                        lines.extend(_histogram(metric, key, counts))
                    continue
                if metric.kind == PEAK:
                    for key, window in sorted(family.peaks.items()):
                        _expire(window, now)
                        peak = max((v for _, v in window), default=0.0)
                        lines.append(f"{metric.name}{_labels(metric.labels, key)} {_number(peak)}")
                    continue
                values = family.values
                if not values and not metric.labels:
                    values = {(): 0.0}
                for key, value in sorted(values.items()):
                    lines.append(f"{metric.name}{_labels(metric.labels, key)} {_number(value)}")
        return "\n".join(lines) + "\n"

    def _family(
        self, name: str, labels: Mapping[str, str], *kinds: str
    ) -> tuple[_Family, tuple[str, ...]]:
        family = self._families.get(name)
        if family is None:
            raise KeyError(f"no metric {name!r} is declared")
        metric = family.metric
        if metric.kind not in kinds:
            raise TypeError(f"{name} is a {metric.kind}")
        if set(labels) != set(metric.labels):
            raise ValueError(
                f"{name} takes the labels {sorted(metric.labels)}, not {sorted(labels)}"
            )
        return family, tuple(str(labels[label]) for label in metric.labels)


class NullMetrics(Metrics):
    """Accepts every write and keeps nothing: what a part measures into when
    it runs outside the supervisor."""

    def __init__(self) -> None:
        super().__init__(())

    def inc(self, name: str, value: float = 1.0, **labels: str) -> None:
        return None

    def set(self, name: str, value: float, **labels: str) -> None:
        return None

    def observe(self, name: str, value: float, **labels: str) -> None:
        return None


def _expire(window: deque[tuple[float, float]], now: float) -> None:
    """Forget each second wholly more than :data:`PEAK_SECONDS` ago."""
    while window and window[0][0] + 1 <= now - PEAK_SECONDS:
        window.popleft()


def _histogram(metric: Metric, key: tuple[str, ...], counts: list[float]) -> list[str]:
    lines: list[str] = []
    cumulative = 0.0
    for index, bound in enumerate(metric.buckets):
        cumulative += counts[index]
        labels = _labels((*metric.labels, "le"), (*key, _number(bound)))
        lines.append(f"{metric.name}_bucket{labels} {_number(cumulative)}")
    labels = _labels((*metric.labels, "le"), (*key, "+Inf"))
    lines.append(f"{metric.name}_bucket{labels} {_number(counts[-1])}")
    lines.append(f"{metric.name}_sum{_labels(metric.labels, key)} {_number(counts[-2])}")
    lines.append(f"{metric.name}_count{_labels(metric.labels, key)} {_number(counts[-1])}")
    return lines


def _labels(names: tuple[str, ...], values: tuple[str, ...]) -> str:
    if not names:
        return ""
    pairs = ",".join(f'{n}="{_escape(v)}"' for n, v in zip(names, values, strict=True))
    return "{" + pairs + "}"


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _help(text: str) -> str:
    return text.replace("\\", "\\\\").replace("\n", "\\n")


def _number(value: float) -> str:
    if math.isnan(value):
        return "NaN"
    if math.isinf(value):
        return "+Inf" if value > 0 else "-Inf"
    if value == int(value) and abs(value) < 2**53:
        return str(int(value))
    return repr(float(value))


# --------------------------------------------------------------------------
# the endpoint
# --------------------------------------------------------------------------


class _Server(ThreadingHTTPServer):
    """``ThreadingHTTPServer`` without the name lookup its bind makes
    (:class:`interlock.inbox.InboxServer` does the same)."""

    def server_bind(self) -> None:
        socketserver.TCPServer.server_bind(self)
        self.server_name = str(self.server_address[0])
        self.server_port = int(self.server_address[1])


class MetricsServer:
    """``GET /metrics`` and, when given a ``health`` to report, ``GET /healthz``,
    on a listener of their own (``docs/EPIC7_DESIGN.md`` §2.2). Plain HTTP and
    unauthenticated: bind it to a private address."""

    def __init__(
        self,
        metrics: Metrics,
        host: str,
        port: int,
        *,
        health: Callable[[], tuple[int, Mapping[str, Any]]] | None = None,
    ) -> None:
        import json

        registry = metrics

        class Handler(BaseHTTPRequestHandler):
            server_version = "interlock-metrics"
            timeout = 10

            def do_GET(self) -> None:
                path = self.path.split("?", 1)[0].rstrip("/")
                if path == "/metrics":
                    self._answer(200, registry.render().encode("utf-8"), CONTENT_TYPE)
                elif path == "/healthz" and health is not None:
                    status, report = health()
                    body = json.dumps(dict(report), default=str).encode("utf-8")
                    self._answer(status, body, "application/json")
                else:
                    self._answer(404, b'{"error": "no such route"}', "application/json")

            def _answer(self, status: int, body: bytes, content_type: str) -> None:
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args: Any) -> None:
                return None

        self._server = _Server((host, port), Handler)
        self._server.daemon_threads = True
        self._thread: threading.Thread | None = None

    @property
    def port(self) -> int:
        """The port bound: the one asked for, or the one chosen for port 0."""
        return int(self._server.server_address[1])

    def start(self) -> int:
        """Answer requests on a thread of its own. Returns :attr:`port`."""
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            kwargs={"poll_interval": 0.1},
            name=f"interlock-metrics-{self.port}",
            daemon=True,
        )
        self._thread.start()
        return self.port

    def stop(self) -> None:
        """Stop answering. Idempotent."""
        if self._thread is not None:
            self._server.shutdown()
            self._thread.join()
            self._thread = None
        self._server.server_close()
