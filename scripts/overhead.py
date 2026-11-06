"""What Interlock adds to one write, measured on each kind of system it stages.

    uv run python scripts/overhead.py                    # SQLite, Git, Kubernetes, FHIR, outbox
    uv run python scripts/overhead.py --postgres "$DSN"  # and PostgreSQL (may create databases)
    uv run python scripts/overhead.py --markdown         # the table the README shows

Each system is timed two ways, in alternating rounds on the same machine so drift
falls on both:

- **direct**: the write an agent's tool makes without Interlock, through the same
  client library and transport;
- **mediated**: the same change as one plan through ``EscrowEngine.execute``: staged,
  measured, judged by checkers, committed, recorded in the escrow chain, and
  receipted (an ARC1 action receipt signed with Ed25519 into a receipt log).

The Kubernetes API server and the FHIR server are Interlock's loopback simulators
(``interlock.sim``), on 127.0.0.1, so the network is a loopback round trip and the
numbers are Interlock's own cost plus the protocol's round trips. Against a real
server across a network, each extra request costs that network's latency: the last
column counts them (and, on PostgreSQL, the connections a plan opens; on Git, the
git processes), so a reader can add their own network's round trip. The outbound row is
a request queued in the transactional outbox and delivered by the relay to a loopback HTTP endpoint,
against a direct POST to that endpoint.

The numbers are wall-clock milliseconds per write: median and 95th percentile.
"""

# ruff: noqa: S105, S106, S310, S603, S607 - throwaway credentials, loopback URLs, git by name

from __future__ import annotations

import argparse
import json
import platform
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import uuid
from collections.abc import Callable, Iterator
from contextlib import closing, contextmanager
from dataclasses import dataclass
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from agentgov.receipts import ReceiptLog
from agentgov.receipts.signing import Ed25519Signer

import interlock
from interlock import (
    BlastRadius,
    EscrowEngine,
    InvariantChecker,
    NoDelete,
    PlanBuilder,
    SqliteSubstrate,
    TableSpec,
    TenantIsolation,
)
from interlock.chain import EscrowChain
from interlock.receipts import ReceiptIssuer
from interlock.types import EffectId, EffectKind


@dataclass
class Row:
    system: str
    measured: str
    direct: list[float]
    mediated: list[float]
    trips: str

    @staticmethod
    def _p(values: list[float], q: float) -> float:
        ordered = sorted(values)
        return ordered[min(len(ordered) - 1, round(q * (len(ordered) - 1)))]

    def cells(self) -> list[str]:
        d50, m50 = statistics.median(self.direct), statistics.median(self.mediated)
        return [
            self.system,
            self.measured,
            f"{d50:.2f}",
            f"{m50:.2f}",
            f"{self._p(self.mediated, 0.95):.2f}",
            f"+{m50 - d50:.2f}",
            f"{m50 / d50:.1f}x",
            self.trips,
        ]


HEAD = [
    "System",
    "Measured as",
    "Direct, median ms",
    "Through Interlock, median ms",
    "Through Interlock, p95 ms",
    "Added, ms",
    "Ratio",
    "Counted per write (direct / through Interlock)",
]


def timed(fn: Callable[[], Any]) -> float:
    started = time.perf_counter()
    fn()
    return (time.perf_counter() - started) * 1000


def alternate(
    n: int, direct: Callable[[int], Any], mediated: Callable[[int], Any]
) -> tuple[list[float], list[float]]:
    a: list[float] = []
    b: list[float] = []
    for i in range(3):  # warm both paths: imports, caches, first connections
        direct(10_000 + i)
        mediated(20_000 + i)
    for i in range(n):
        took: dict[Callable[[int], Any], float] = {}
        for fn in (direct, mediated) if i % 2 else (mediated, direct):
            started = time.perf_counter()
            fn(i)
            took[fn] = (time.perf_counter() - started) * 1000
        a.append(took[direct])
        b.append(took[mediated])
    return a, b


@contextmanager
def counting(module: Any, name: str) -> Iterator[list[int]]:
    """Count the calls to ``module.name`` while the block runs."""
    real = getattr(module, name)
    seen = [0]

    def counted(*args: Any, **kwargs: Any) -> Any:
        seen[0] += 1
        return real(*args, **kwargs)

    setattr(module, name, counted)
    try:
        yield seen
    finally:
        setattr(module, name, real)


def receipted(where: Path, name: str) -> dict[str, Any]:
    """An escrow chain and an Ed25519-signed receipt log for one engine."""
    log = ReceiptLog(name, Ed25519Signer.generate(), path=where / f"{name}-receipts.jsonl")
    return {
        "chain": EscrowChain(where / f"{name}.ilok1"),
        "receipts": ReceiptIssuer(log, row_secret=b"r" * 32),
    }


def CHECKERS() -> list[InvariantChecker]:  # noqa: N802 - read as a constant
    """The checks every mediated write is judged by: three of the defaults."""
    return [BlastRadius(10), TenantIsolation(1), NoDelete()]


ORDERS = TableSpec(
    name="orders", primary_key="id", columns=("id", "status", "tenant"), tenant_column="tenant"
)


def update(n: int, statement: str = "UPDATE orders SET status = :s WHERE id = :id") -> Any:
    return (
        PlanBuilder("bench", intent="mark one order shipped")
        .update(
            table="orders",
            statement=statement,
            parameters={"s": f"shipped-{n}", "id": 1 + n % 50},
            stated_rows=1,
        )
        .build()
    )


# -- SQLite --------------------------------------------------------------------------


def bench_sqlite(where: Path, n: int) -> Row:
    db = where / "sqlite.db"
    with closing(sqlite3.connect(db)) as conn:
        conn.execute("CREATE TABLE orders (id INTEGER PRIMARY KEY, status TEXT, tenant TEXT)")
        conn.executemany(
            "INSERT INTO orders VALUES (?, 'new', 'acme')", [(i,) for i in range(1, 51)]
        )
        conn.commit()
    engine = EscrowEngine(
        SqliteSubstrate(str(db), tables=[ORDERS]), checkers=CHECKERS(), **receipted(where, "sqlite")
    )
    direct_conn = sqlite3.connect(db)

    def direct(i: int) -> None:
        direct_conn.execute(
            "UPDATE orders SET status = ? WHERE id = ?", (f"shipped-{i}", 1 + i % 50)
        )
        direct_conn.commit()

    def mediated(i: int) -> None:
        assert engine.execute(update(i)).committed

    a, b = alternate(n, direct, mediated)
    direct_conn.close()
    return Row("SQLite", "T, in the transaction", a, b, "file")


# -- PostgreSQL ----------------------------------------------------------------------


def bench_postgres(where: Path, n: int, dsn: str) -> Row:
    import psycopg
    from psycopg.conninfo import make_conninfo

    from interlock.postgres import PostgresSubstrate, install

    name = f"ilbench_{uuid.uuid4().hex[:8]}"
    role = f"{name}_stage"
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(f"CREATE DATABASE {name}")
        conn.execute(f"CREATE ROLE {role} LOGIN PASSWORD 'bench'")
    database = make_conninfo(dsn, dbname=name)
    try:
        with psycopg.connect(database, autocommit=True) as conn:
            conn.execute("CREATE TABLE orders (id integer PRIMARY KEY, status text, tenant text)")
            conn.execute("INSERT INTO orders SELECT g, 'new', 'acme' FROM generate_series(1, 50) g")
            install(conn, [ORDERS], stage_roles=[role])
            conn.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON orders TO {role}")
        agent = make_conninfo(database, user=role, password="bench")
        engine = EscrowEngine(
            PostgresSubstrate(agent, tables=[ORDERS]), checkers=CHECKERS(), **receipted(where, "pg")
        )
        direct_conn = psycopg.connect(agent)

        def direct(i: int) -> None:
            direct_conn.execute(
                "UPDATE orders SET status = %s WHERE id = %s", (f"shipped-{i}", 1 + i % 50)
            )
            direct_conn.commit()

        def mediated(i: int) -> None:
            plan = update(i, "UPDATE orders SET status = %(s)s WHERE id = %(id)s")
            assert engine.execute(plan).committed

        a, b = alternate(n, direct, mediated)
        direct_conn.close()
        with (
            counting(psycopg, "connect") as opened,
            counting(psycopg.Connection, "execute") as by_connection,
            counting(psycopg.Cursor, "execute") as by_cursor,
        ):
            mediated(n + 1)
        statements = by_connection[0] + by_cursor[0]
        started = time.perf_counter()
        psycopg.connect(agent).close()
        connect = (time.perf_counter() - started) * 1000
        trips = (
            f"connections: 0 / {opened[0]} ({connect:.1f} ms each here); "
            f"statements: 1 / {statements}"
        )
        return Row("PostgreSQL 16", "T, in the transaction", a, b, trips)
    finally:
        with psycopg.connect(dsn, autocommit=True) as conn:
            conn.execute(f"DROP DATABASE IF EXISTS {name} WITH (FORCE)")
            conn.execute(f"DROP ROLE IF EXISTS {role}")


# -- Git -----------------------------------------------------------------------------


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=cwd, check=True, capture_output=True, text=True
    ).stdout.strip()


def bench_git(where: Path, n: int) -> Row:
    from interlock.git_substrate import GitSubstrate

    origin, work = where / "app.git", where / "work"
    git(where, "init", "-q", "--bare", "-b", "main", str(origin))
    git(where, "clone", "-q", str(origin), str(work))
    for k, v in (("user.name", "bench"), ("user.email", "bench@example.com")):
        git(work, "config", k, v)
    (work / "src").mkdir()
    (work / "src" / "app.py").write_text("VERSION = 0\n")
    git(work, "add", ".")
    git(work, "commit", "-qm", "init")
    git(work, "push", "-q", "origin", "HEAD:main")
    engine = EscrowEngine(GitSubstrate(origin), checkers=CHECKERS(), **receipted(where, "git"))
    other = where / "direct.git"
    git(where, "clone", "-q", "--bare", str(origin), str(other))
    direct_work = where / "direct-work"
    git(where, "clone", "-q", str(other), str(direct_work))
    for k, v in (("user.name", "bench"), ("user.email", "bench@example.com")):
        git(direct_work, "config", k, v)

    def direct(i: int) -> None:
        (direct_work / "src" / "app.py").write_text(f"VERSION = {i}\n")
        git(direct_work, "commit", "-qam", f"bump {i}")
        git(direct_work, "push", "-q", "origin", "HEAD:main")

    def mediated(i: int) -> None:
        plan = (
            PlanBuilder("bench", intent="bump the version")
            .update(
                table="src",
                statement="write 'src/app.py' :text",
                parameters={"text": f"VERSION = {i}\n"},
                stated_rows=1,
            )
            .build()
        )
        assert engine.execute(plan).committed

    a, b = alternate(n, direct, mediated)
    import interlock.git_substrate as git_module

    with counting(git_module.subprocess, "run") as ran:  # type: ignore[attr-defined]
        mediated(n + 1)
    return Row("Git", "P, the branch's own diff", a, b, f"git processes: 3 / {ran[0]}")


# -- Kubernetes, loopback -----------------------------------------------------------


def bench_kubernetes(where: Path, n: int) -> Row:
    from interlock.kubernetes import KubeKind, KubernetesSubstrate
    from interlock.sim.kubernetes import DEPLOYMENTS, LoopbackCluster

    token, ns = "bench-token", "prod"
    cluster = LoopbackCluster((DEPLOYMENTS,), tokens={token: "system:serviceaccount:bench"})
    cluster.start()
    try:
        for name in ("api", "direct"):
            cluster.seed(
                "deployments",
                {
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "metadata": {"name": name, "namespace": ns},
                    "spec": {
                        "replicas": 2,
                        "selector": {"matchLabels": {"app": name}},
                        "template": {
                            "spec": {"containers": [{"name": name, "image": "reg/app:1"}]}
                        },
                    },
                },
            )
        kinds = (
            KubeKind(
                "deployments",
                "deployments",
                "Deployment",
                group="apps",
                columns={"replicas": "spec.replicas"},
            ),
        )
        sub = KubernetesSubstrate(
            cluster.url, kinds=kinds, journal=where / "k8s-journal", token=token
        )
        engine = EscrowEngine(sub, checkers=CHECKERS(), **receipted(where, "k8s"))
        url = f"{cluster.url}/apis/apps/v1/namespaces/{ns}/deployments/direct"

        def direct(i: int) -> None:
            body = json.dumps({"spec": {"replicas": 2 + i % 3}}).encode()
            request = urllib.request.Request(
                url,
                data=body,
                method="PATCH",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/merge-patch+json",
                },
            )
            with urllib.request.urlopen(request) as answer:
                answer.read()

        def mediated(i: int) -> None:
            plan = (
                PlanBuilder("bench", intent="scale")
                .add(
                    EffectKind.APPLY,
                    table="kubernetes:deployments",
                    statement="scale deployments :namespace :name :replicas",
                    parameters={"namespace": ns, "name": "api", "replicas": 2 + (i + 1) % 3},
                    tenant_id=ns,
                )
                .build()
            )
            assert engine.execute(plan).committed

        a, b = alternate(n, direct, mediated)
        before = len(cluster.requests)
        mediated(n + 1)
        trips = f"HTTP requests: 1 / {len(cluster.requests) - before}"
        return Row("Kubernetes (loopback API server)", "P, the server's dry run", a, b, trips)
    finally:
        cluster.stop()


# -- FHIR, loopback -----------------------------------------------------------------


def bench_fhir(where: Path, n: int) -> Row:
    from interlock.fhir import FhirSubstrate, FhirType
    from interlock.sim.fhir import LoopbackFhirServer
    from interlock.types import Compensation

    token = "bench-token"
    server = LoopbackFhirServer(tokens={token: "Device/bench"})
    server.start()
    try:
        server.seed({"resourceType": "Patient", "id": "p1"})
        for oid in ("1", "2"):
            server.seed(
                {
                    "resourceType": "MedicationRequest",
                    "id": oid,
                    "status": "active",
                    "intent": "order",
                    "subject": {"reference": "Patient/p1"},
                    "dosageInstruction": [
                        {"doseAndRate": [{"doseQuantity": {"value": 10, "unit": "mg"}}]}
                    ],
                }
            )
        types = (
            FhirType(
                "medicationrequests",
                "MedicationRequest",
                columns={
                    "status": "status",
                    "dose_mg": "dosageInstruction.0.doseAndRate.0.doseQuantity.value",
                },
            ),
        )
        sub = FhirSubstrate(server.url, types=types, journal=where / "fhir-journal", token=token)
        engine = EscrowEngine(sub, checkers=CHECKERS(), **receipted(where, "fhir"))
        url = f"{server.url}/MedicationRequest/2"
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/fhir+json"}

        def direct(i: int) -> None:
            with urllib.request.urlopen(urllib.request.Request(url, headers=headers)) as answer:
                resource = json.loads(answer.read())
            resource["dosageInstruction"][0]["doseAndRate"][0]["doseQuantity"]["value"] = 10 + i % 5
            version = resource["meta"]["versionId"]
            request = urllib.request.Request(
                url,
                data=json.dumps(resource).encode(),
                method="PUT",
                headers={**headers, "If-Match": f'W/"{version}"'},
            )
            with urllib.request.urlopen(request) as answer:
                answer.read()

        def mediated(i: int) -> None:
            change = json.dumps(
                {
                    "dosageInstruction": [
                        {"doseAndRate": [{"doseQuantity": {"value": ":d", "unit": "mg"}}]}
                    ]
                }
            )
            plan = (
                PlanBuilder("bench", intent="adjust a dose")
                .add(
                    EffectKind.UPDATE,
                    table="fhir:medicationrequests",
                    statement="patch medicationrequests :id '" + change.replace("'", "''") + "' :d",
                    parameters={"id": "1", "d": 10 + (i + 1) % 5},
                    tenant_id="Patient/p1",
                    compensation=Compensation("restore medicationrequests"),
                )
                .build()
            )
            assert engine.execute(plan).committed

        a, b = alternate(n, direct, mediated)
        before = len(server.requests)
        mediated(n + 1)
        trips = f"HTTP requests: 2 / {len(server.requests) - before}"
        return Row("FHIR R4 (loopback server)", "V, predicted, then read back", a, b, trips)
    finally:
        server.stop()


# -- Outbound: the transactional outbox and the relay ---------------------------------


class _Sink(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        body = json.dumps({"id": f"ref_{uuid.uuid4().hex[:12]}"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: Any) -> None:
        pass


@contextmanager
def sink() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Sink)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


def bench_outbox(where: Path, n: int) -> Row:
    from interlock.adapters import HttpAdapter
    from interlock.outbound import OperationSpec, SinkRegistry, SinkSpec
    from interlock.relay import NoBreaker, Relay
    from interlock.sqlite_outbox import SqliteOutboxStore, install_sqlite_outbox

    db = where / "outbox.db"
    with closing(sqlite3.connect(db)) as conn:
        conn.execute("CREATE TABLE orders (id INTEGER PRIMARY KEY, status TEXT, tenant TEXT)")
        conn.commit()
    sinks = (SinkSpec("mail", (OperationSpec("send"),)),)
    install_sqlite_outbox(db, sinks)
    with sink() as url:
        engine = EscrowEngine(
            SqliteSubstrate(str(db), tables=[ORDERS]),
            checkers=[BlastRadius(10)],
            sinks=SinkRegistry(sinks),
            **receipted(where, "outbox"),
        )
        relay = Relay(
            SqliteOutboxStore(str(db)),
            adapters={"mail": HttpAdapter(url, routes={"send": "POST /mail/send"})},
            breaker=NoBreaker(),
            signer=Ed25519Signer.generate(),
            lease=timedelta(seconds=10),
            timeout=timedelta(seconds=5),
        )

        def direct(i: int) -> None:
            body = json.dumps({"to": f"customer{i}@acme.test", "subject": "your order"}).encode()
            request = urllib.request.Request(
                f"{url}/mail/send",
                data=body,
                method="POST",
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(request) as answer:
                answer.read()

        def mediated(i: int) -> None:
            plan = (
                PlanBuilder("bench", intent="notify a customer")
                .enqueue(
                    sink="mail",
                    operation="send",
                    payload={"to": f"customer{i}@acme.test", "subject": "your order"},
                    effect_id=EffectId("r0"),
                    independent=True,
                )
                .build()
            )
            assert engine.execute(plan).committed
            assert relay.run_once().delivered == 1, "the relay delivered the request"

        try:
            a, b = alternate(n, direct, mediated)
        finally:
            relay.close()
    return Row(
        "Outbound request (outbox and relay)",
        "R, the request only",
        a,
        b,
        "HTTP requests: 1 / 1, sent after the commit",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--n", type=int, default=200, help="writes per system and path")
    parser.add_argument(
        "--postgres", metavar="DSN", help="also PostgreSQL: a role that may create databases"
    )
    parser.add_argument("--markdown", action="store_true", help="print the README's table")
    args = parser.parse_args(argv)
    rows: list[Row] = []
    with tempfile.TemporaryDirectory(prefix="interlock-overhead-") as scratch:
        where = Path(scratch)
        benches: list[tuple[str, Callable[[Path], Row]]] = [
            ("sqlite", lambda p: bench_sqlite(p, args.n)),
            ("git", lambda p: bench_git(p, max(20, args.n // 4))),
            ("kubernetes", lambda p: bench_kubernetes(p, args.n)),
            ("fhir", lambda p: bench_fhir(p, args.n)),
            ("outbox", lambda p: bench_outbox(p, args.n)),
        ]
        if args.postgres:
            benches.insert(1, ("postgres", lambda p: bench_postgres(p, args.n, args.postgres)))
        for name, bench in benches:
            directory = where / name
            directory.mkdir()
            rows.append(bench(directory))
            print(f"{name}: done", file=sys.stderr)
    machine = (
        f"{platform.system()} {platform.machine()}, Python {platform.python_version()}, "
        f"interlock {interlock.__version__}"
    )
    if args.markdown:
        print("| " + " | ".join(HEAD) + " |")
        print("|" + "---|" * len(HEAD))
        for row in rows:
            print("| " + " | ".join(row.cells()) + " |")
        print(f"\n{machine}; {args.n} writes per path (Git: {max(20, args.n // 4)}).")
    else:
        widths = [max(len(h), *(len(r.cells()[k]) for r in rows)) for k, h in enumerate(HEAD)]
        print("  ".join(h.ljust(w) for h, w in zip(HEAD, widths, strict=True)))
        for row in rows:
            print("  ".join(c.ljust(w) for c, w in zip(row.cells(), widths, strict=True)))
        print(machine)
    return 0


if __name__ == "__main__":
    sys.exit(main())
