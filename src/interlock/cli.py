"""The ``interlock`` command.

``interlock install``            put Interlock's triggers into the database
``interlock check``              verify the setup, print the cascade check
``interlock reconcile-effects``  fail on any write to an observed table that no
                                 escrow chain records
``interlock relay``              deliver committed outbound requests, until
                                 stopped (``--once``: until none is due)
``interlock outbox ACTION``      ``status``, ``list``, ``show``, ``verify`` the
                                 delivery logs; ``release``, ``cancel``,
                                 ``requeue`` a message (as the installer)

Every command reads a TOML configuration file (see :mod:`interlock.config`).
Exit codes, for scripts and CI:

====  =============================================================
0     done; for ``check``, the setup is sound; for
      ``reconcile-effects``, every write is accounted for
1     ``reconcile-effects`` found an unrecorded write; ``outbox verify``
      found a delivery log that does not verify; an ``outbox`` action
      found nothing to act on
2     usage, or the configuration file is wrong
3     the database is not set up (not installed, grants)
4     the database cannot be reached
5     an escrow chain failed verification, so it proves nothing
====  =============================================================
"""

from __future__ import annotations

import argparse
import getpass
import os
import signal
import sys
import threading
import uuid
from collections.abc import Callable, Mapping, Sequence
from typing import Any, TextIO

from interlock.cascade import CascadeReport, analyze_cascades, read_postgres_foreign_keys
from interlock.chain import EscrowChain, EscrowRecord
from interlock.config import ConfigError, Endpoint, InterlockConfig, RelayConfig, load_config
from interlock.deliveries import (
    cancel,
    message_log,
    messages,
    release,
    release_scope,
    requeue,
    state_counts,
    verify_delivery_log,
)
from interlock.exceptions import (
    ChainIntegrityError,
    InterlockError,
    SubstrateConfigurationError,
    SubstrateUnavailableError,
)
from interlock.postgres import PostgresSubstrate, install
from interlock.reconcile import (
    format_reconciliation,
    install_sqlite_journal,
    reconcile_postgres,
    reconcile_sqlite,
)
from interlock.substrate import SqliteSubstrate

__all__ = ["main", "main_entry"]

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_CONFIGURATION = 3
EXIT_UNAVAILABLE = 4
EXIT_CHAIN = 5


def main(argv: Sequence[str] | None = None, *, out: TextIO | None = None) -> int:
    stream = out if out is not None else sys.stdout
    parser = _parser()
    args = parser.parse_args(argv)
    relaying = args.command == "relay"
    try:
        config = load_config(
            args.config,
            database=None if relaying else args.database,
            require_database=not relaying,
        )
    except ConfigError as exc:
        print(f"interlock: {exc}", file=sys.stderr)
        return EXIT_USAGE
    try:
        if args.command == "install":
            return _install(config, stream)
        if args.command == "reconcile-effects":
            return _reconcile(config, args.chain, args.after, stream)
        if relaying:
            return _relay(config, args, stream)
        if args.command == "outbox":
            return _outbox(config, args, stream)
        return _check(config, stream)
    except ChainIntegrityError as exc:
        print(f"interlock: {exc}", file=sys.stderr)
        return EXIT_CHAIN
    except SubstrateConfigurationError as exc:
        print(f"interlock: {exc}", file=sys.stderr)
        return EXIT_CONFIGURATION
    except (SubstrateUnavailableError, InterlockError) as exc:
        print(f"interlock: {exc}", file=sys.stderr)
        return EXIT_UNAVAILABLE


def _common(command: argparse.ArgumentParser, database: str) -> None:
    command.add_argument("--config", required=True, help="the TOML configuration file")
    command.add_argument("--database", help=database)


_DATABASE_HELP = "overrides the file's database (DSN or SQLite path), as does INTERLOCK_DATABASE"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="interlock", description="Stage, measure, adjudicate, commit."
    )
    commands = parser.add_subparsers(dest="command", required=True)
    relay = commands.add_parser(
        "relay",
        help="deliver committed outbound requests",
        description="Deliver committed outbound requests, at least once, until stopped.",
    )
    _common(relay, "overrides [relay]'s database, as does INTERLOCK_RELAY_DATABASE")
    relay.add_argument("--once", action="store_true", help="stop when nothing is due")
    relay.add_argument("--workers", type=int, help="overrides [relay]'s workers")
    relay.add_argument("--relay-id", help="this relay's name in leases and delivery logs")
    outbox = commands.add_parser(
        "outbox",
        help="inspect and act on the outbox (as the installer)",
        description="Inspect the outbox, verify delivery logs, and act on messages.",
    )
    actions = outbox.add_subparsers(dest="action", required=True)
    for name, text in (
        ("status", "count messages in each state"),
        ("list", "list messages, oldest first"),
        ("show", "show one message and its delivery log"),
        ("verify", "verify every delivery log; exit 1 if one does not"),
        ("release", "release a held message, or every held message of a scope"),
        ("cancel", "cancel a pending, held or dead message"),
        ("requeue", "send a dead message back for delivery"),
    ):
        action = actions.add_parser(name, help=text, description=text)
        _common(action, _DATABASE_HELP)
        if name in ("show", "cancel", "requeue"):
            action.add_argument("message", type=uuid.UUID, help="the message id")
        if name == "release":
            target = action.add_mutually_exclusive_group(required=True)
            target.add_argument("message", nargs="?", type=uuid.UUID, help="the message id")
            target.add_argument("--scope", help="release every held message of this scope")
        if name == "list":
            action.add_argument("--state", help="only messages in this state")
            action.add_argument("--scope", help="only this scope's messages")
            action.add_argument("--limit", type=int, default=100)
        if name == "cancel":
            action.add_argument("--reason", required=True, help="recorded in the delivery log")
        if name in ("release", "cancel", "requeue"):
            action.add_argument(
                "--actor", default=None, help="who is acting; recorded in the delivery log"
            )
    for name, text in (
        ("install", "install Interlock's schema and triggers (run as the tables' owner)"),
        ("check", "verify the setup and print what the cascade check refuses"),
        ("reconcile-effects", "fail on any write to an observed table no escrow chain records"),
    ):
        command = commands.add_parser(name, help=text, description=text)
        _common(command, _DATABASE_HELP)
        if name == "reconcile-effects":
            command.add_argument(
                "--chain",
                action="append",
                required=True,
                help="an escrow chain file that stages against this database; repeat for each",
            )
            command.add_argument(
                "--after",
                type=int,
                default=0,
                help="only logged writes numbered above this: a previous run's last entry",
            )
    return parser


def _install(config: InterlockConfig, out: TextIO) -> int:
    names = ", ".join(t.name for t in config.tables)
    if config.substrate != "postgres":
        from interlock.sqlite_outbox import install_sqlite_outbox

        install_sqlite_journal(config.database, config.tables)
        install_sqlite_outbox(config.database, config.sinks)
        print(f"installed: journal triggers on {len(config.tables)} table(s): {names}", file=out)
        print("installed: the outbox, and WAL mode", file=out)
        for sink in config.sinks:
            operations = ", ".join(op.name for op in sink.operations)
            print(f"registered sink: {sink.name} ({_kind(sink)}{operations})", file=out)
        _print_report(_sqlite(config).check_cascades(), out)
        return EXIT_OK
    import psycopg

    try:
        with psycopg.connect(config.database, autocommit=True) as conn:
            install(
                conn,
                config.tables,
                schema=config.schema,
                stage_roles=config.stage_roles,
                audit_roles=config.audit_roles,
                sinks=config.sinks,
                relay_roles=config.relay_roles,
            )
            report = analyze_cascades(
                read_postgres_foreign_keys(conn, config.schema),
                [t.name for t in config.tables],
                config.acknowledge_cascades,
            )
    except psycopg.Error as exc:
        raise SubstrateUnavailableError(f"install failed: {exc}") from exc
    except ValueError as exc:
        raise SubstrateConfigurationError(str(exc)) from exc
    print(f"installed: {len(config.tables)} table(s) in {config.schema}: {names}", file=out)
    for role in config.stage_roles:
        print(f"granted to stage role: {role}", file=out)
    for role in config.audit_roles:
        print(f"granted to audit role: {role}", file=out)
    for sink in config.sinks:
        operations = ", ".join(op.name for op in sink.operations)
        print(f"registered sink: {sink.name} ({_kind(sink)}{operations})", file=out)
    for role in config.relay_roles:
        print(f"granted to relay role: {role}", file=out)
    _print_report(report, out)
    return EXIT_OK


def _relay(config: InterlockConfig, args: argparse.Namespace, out: TextIO) -> int:
    from interlock.relay import LedgerBreaker, NoBreaker, Relay, RelayReport
    from interlock.sqlite_outbox import SqliteOutboxStore

    settings = config.relay
    if settings is None:
        raise SubstrateConfigurationError("the configuration file has no [relay] section")
    sqlite = config.substrate != "postgres"
    dsn = args.database or settings.database or (config.database if sqlite else "")
    if not dsn:
        raise SubstrateConfigurationError(
            "no database for the relay: set [relay] database, pass --database, or set "
            "INTERLOCK_RELAY_DATABASE"
        )
    workers = args.workers or settings.workers
    relays: list[Relay] = []
    breakers: list[Any] = []
    try:
        for index in range(1 if args.once else workers):
            breaker = (
                LedgerBreaker.open(settings.ledger, schema=settings.ledger_schema)
                if settings.breaker == "agentgov" and settings.ledger is not None
                else NoBreaker()
            )
            breakers.append(breaker)
            relays.append(
                Relay(
                    SqliteOutboxStore(dsn) if sqlite else dsn,
                    adapters=_adapters(settings),
                    breaker=breaker,
                    relay_id=f"{args.relay_id}:{index}" if args.relay_id else None,
                    lease=settings.lease,
                    timeout=settings.timeout,
                    batch=settings.batch,
                )
            )
        if args.once:
            total = RelayReport()
            while True:
                report = relays[0].run_once()
                total = total + report
                if report.claimed == 0:
                    break
            _print_relay(total, out)
            return EXIT_OK
        stop = threading.Event()
        _stop_on_signals(stop)
        reports: list[RelayReport] = []
        threads = [
            threading.Thread(
                target=lambda r=relay: reports.append(r.run(stop, poll=settings.poll_seconds)),
                name=relay.relay_id,
            )
            for relay in relays
        ]
        for thread in threads:
            thread.start()
        print(f"relaying with {len(threads)} worker(s); stop with SIGTERM or Ctrl-C", file=out)
        for thread in threads:
            while thread.is_alive():
                thread.join(timeout=0.5)
        total = RelayReport()
        for report in reports:
            total = total + report
        _print_relay(total, out)
        return EXIT_OK
    finally:
        for relay in relays:
            relay.close()
        for breaker in breakers:
            breaker.close()


def _kind(sink: Any) -> str:
    return "" if sink.kind == "http" else f"{sink.kind}: "


def _adapters(settings: RelayConfig) -> dict[str, Any]:
    missing = sorted(
        [
            f"{variable} (sink {endpoint.sink}, header {header})"
            for endpoint in settings.endpoints
            for header, variable in endpoint.header_env.items()
            if variable not in os.environ
        ]
        + [
            f"{endpoint.secret_env} (sink {endpoint.sink}, its API key)"
            for endpoint in settings.endpoints
            if endpoint.secret_env and endpoint.secret_env not in os.environ
        ]
    )
    if missing:
        raise SubstrateConfigurationError(
            f"the relay's credentials come from its environment, and these are not set: "
            f"{', '.join(missing)}"
        )
    return {endpoint.sink: _adapter(endpoint) for endpoint in settings.endpoints}


def _adapter(endpoint: Endpoint) -> Any:
    """The adapter for one endpoint: the generic one, or its vendor's."""
    if endpoint.kind == "stripe":
        from interlock.stripe import API, STRIPE_VERSION, StripeAdapter

        return StripeAdapter(
            _variable(endpoint.secret_env),
            base_url=endpoint.url or API,
            version=endpoint.stripe_version or STRIPE_VERSION,
        )
    if endpoint.kind == "sendgrid":
        from interlock.sendgrid import API as SENDGRID_API
        from interlock.sendgrid import SendGridAdapter

        return SendGridAdapter(
            _variable(endpoint.secret_env),
            base_url=endpoint.url or SENDGRID_API,
            sandbox=endpoint.sandbox,
        )
    from interlock.adapters import HttpAdapter

    return HttpAdapter(
        endpoint.url, routes=endpoint.routes, headers=_environment(endpoint.header_env)
    )


def _variable(name: str) -> Callable[[], str]:
    """A secret read from the environment on every call, so a rotated key
    takes effect without a restart."""

    def value() -> str:
        return os.environ[name]

    return value


def _environment(names: Mapping[str, str]) -> Callable[[], dict[str, str]]:
    """Header values read from the environment on every call, so a rotated
    credential takes effect without a restart."""
    fixed = dict(names)

    def headers() -> dict[str, str]:
        return {header: os.environ[variable] for header, variable in fixed.items()}

    return headers


def _stop_on_signals(stop: threading.Event) -> None:
    def handle(signum: int, frame: object) -> None:
        stop.set()

    try:
        signal.signal(signal.SIGTERM, handle)
        signal.signal(signal.SIGINT, handle)
    except ValueError:  # pragma: no cover - not the main thread: the caller stops it
        pass


def _print_relay(report: Any, out: TextIO) -> None:
    print(
        f"claimed {report.claimed}: delivered {report.delivered}, retrying "
        f"{report.retrying}, dead {report.dead}, held {report.held}, deferred "
        f"{report.deferred}, refused {report.refused}, skipped {report.skipped}",
        file=out,
    )


def _outbox(config: InterlockConfig, args: argparse.Namespace, out: TextIO) -> int:
    actor = getattr(args, "actor", None) or getpass.getuser()
    if config.substrate != "postgres":
        from interlock.sqlite_outbox import OPERATOR, SqliteOutboxStore

        store = SqliteOutboxStore(config.database, writes=OPERATOR)
        try:
            return _outbox_action(_SqliteActions(store), args, actor, out)
        finally:
            store.close()
    import psycopg

    try:
        with psycopg.connect(config.database, autocommit=True) as conn:
            return _outbox_action(_PostgresActions(conn), args, actor, out)
    except psycopg.Error as exc:
        raise SubstrateUnavailableError(f"outbox {args.action} failed: {exc}") from exc


class _PostgresActions:
    def __init__(self, conn: Any) -> None:
        self.source = conn

    def release(self, message: uuid.UUID, actor: str) -> bool:
        return release(self.source, message, actor=actor)

    def release_scope(self, scope: str, actor: str) -> int:
        return release_scope(self.source, scope, actor=actor)

    def cancel(self, message: uuid.UUID, actor: str, reason: str) -> bool:
        return cancel(self.source, message, actor=actor, reason=reason)

    def requeue(self, message: uuid.UUID, actor: str) -> int:
        return requeue(self.source, message, actor=actor)


class _SqliteActions:
    def __init__(self, store: Any) -> None:
        self.source = store

    def release(self, message: uuid.UUID, actor: str) -> bool:
        return bool(self.source.release(message, actor=f"operator:{actor}"))

    def release_scope(self, scope: str, actor: str) -> int:
        return int(self.source.release_scope(scope, actor=f"operator:{actor}"))

    def cancel(self, message: uuid.UUID, actor: str, reason: str) -> bool:
        return bool(self.source.cancel(message, actor=f"operator:{actor}", reason=reason))

    def requeue(self, message: uuid.UUID, actor: str) -> int:
        return int(self.source.requeue(message, actor=f"operator:{actor}"))


def _outbox_action(actions: Any, args: argparse.Namespace, actor: str, out: TextIO) -> int:
    source = actions.source
    if args.action == "status":
        counts = state_counts(source)
        for state in ("pending", "leased", "held", "delivered", "dead", "cancelled"):
            print(f"{state:<10} {counts.get(state, 0)}", file=out)
        return EXIT_OK
    if args.action == "list":
        for m in messages(source, state=args.state, scope_id=args.scope, limit=args.limit):
            print(
                f"{m.message_id}  {m.state:<9} {m.sink}.{m.operation}  scope "
                f"{m.scope_id}  plan {m.plan_id}  calls {m.attempts}"
                + (f"  ({m.reason})" if m.reason else ""),
                file=out,
            )
        return EXIT_OK
    if args.action == "show":
        log = message_log(source, args.message)
        for event in log:
            print(
                f"{event.seq:>3} {event.at.isoformat()} {event.event:<17} "
                f"call {event.attempt or '-'}  {event.actor}"
                + (f"  HTTP {event.status_code}" if event.status_code else "")
                + (f"  -> {event.state_after}" if event.state_after else "")
                + (f"  {event.detail}" if event.detail else ""),
                file=out,
            )
        return EXIT_OK if log else EXIT_FINDINGS
    if args.action == "verify":
        problems = verify_delivery_log(source)
        for problem in problems:
            print(problem, file=out)
        if problems:
            return EXIT_FINDINGS
        print("every delivery log verifies", file=out)
        return EXIT_OK
    if args.action == "release":
        if args.scope:
            count = actions.release_scope(args.scope, actor)
            print(f"released {count} message(s) of scope {args.scope}", file=out)
            return EXIT_OK if count else EXIT_FINDINGS
        done = actions.release(args.message, actor)
        print("released" if done else "not held; nothing released", file=out)
        return EXIT_OK if done else EXIT_FINDINGS
    if args.action == "cancel":
        done = actions.cancel(args.message, actor, args.reason)
        print("cancelled" if done else "not cancellable; nothing done", file=out)
        return EXIT_OK if done else EXIT_FINDINGS
    count = actions.requeue(args.message, actor)
    print(f"requeued {count} message(s)", file=out)
    return EXIT_OK if count else EXIT_FINDINGS


def _check(config: InterlockConfig, out: TextIO) -> int:
    if config.substrate == "postgres":
        report = PostgresSubstrate(
            config.database,
            tables=config.tables,
            schema=config.schema,
            acknowledge_cascades=config.acknowledge_cascades,
        ).check_cascades()
    else:
        report = _sqlite(config).check_cascades()
    print(f"ok: {config.substrate}, {len(config.tables)} observed table(s)", file=out)
    _print_report(report, out)
    return EXIT_OK


def _reconcile(config: InterlockConfig, chains: Sequence[str], after: int, out: TextIO) -> int:
    records: list[EscrowRecord] = []
    for path in chains:
        try:
            records.extend(EscrowChain.load(path).records())
        except OSError as exc:
            raise ChainIntegrityError(f"cannot read escrow chain {path}: {exc}") from exc
    if config.substrate == "postgres":
        import psycopg

        try:
            with psycopg.connect(config.database, autocommit=True) as conn:
                result = reconcile_postgres(conn, records, after=after)
        except psycopg.Error as exc:
            raise SubstrateUnavailableError(f"cannot connect to PostgreSQL: {exc}") from exc
    else:
        result = reconcile_sqlite(config.database, config.tables, records, after=after)
    for line in format_reconciliation(result):
        print(line, file=out)
    return EXIT_OK if result.clean else EXIT_FINDINGS


def _sqlite(config: InterlockConfig) -> SqliteSubstrate:
    return SqliteSubstrate(
        config.database, tables=config.tables, acknowledge_cascades=config.acknowledge_cascades
    )


def _print_report(report: CascadeReport, out: TextIO) -> None:
    for reach in report.gated:
        print(f"refused:      {reach.describe()}", file=out)
    for reach in report.gaps:
        print(f"acknowledged: {reach.describe()}", file=out)
    for table in sorted(report.unreached_acknowledgments):
        print(f"stale acknowledgment: {table} (no cascade reaches it)", file=out)
    state = "closed" if report.closed else f"open, {len(report.gaps)} acknowledged gap(s)"
    print(f"cascade closure: {state}", file=out)


def main_entry() -> None:  # pragma: no cover - the console-script shim
    sys.exit(main())
