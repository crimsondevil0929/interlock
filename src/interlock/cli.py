"""The ``interlock`` command.

``interlock install``            put Interlock's triggers into the database
``interlock check``              verify the setup, print the cascade check
``interlock reconcile-effects``  fail on any write to an observed table that no
                                 escrow chain records
``interlock relay``              deliver committed outbound requests, until
                                 stopped (``--once``: until none is due)
``interlock outbox ACTION``      ``status``, ``list``, ``show``, ``verify`` the
                                 delivery logs (and the operator log);
                                 ``release``, ``cancel``, ``requeue``,
                                 ``compensate``, ``resolve``: an operator's
                                 actions, each signed with their key
``interlock operator keygen``    a new operator key, and its public half for
                                 ``[operators.keys]``

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
import os
import signal
import sys
import threading
import uuid
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from typing import Any, Final, TextIO

from interlock.cascade import CascadeReport, analyze_cascades, read_postgres_foreign_keys
from interlock.chain import EscrowChain, EscrowRecord
from interlock.config import ConfigError, Endpoint, InterlockConfig, RelayConfig, load_config
from interlock.deliveries import (
    message_log,
    messages,
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
    if args.command == "operator":
        return _keygen(args, stream)
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
            return _install(config, args, stream)
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

OPERATOR_KEY_ENV = "INTERLOCK_OPERATOR_KEY"
"""The path to an operator's key file, when ``--key`` is not given."""
SIGNED: Final = frozenset({"release", "cancel", "requeue", "compensate", "resolve"})
"""The outbox actions an operator signs."""


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
        ("verify", "verify every delivery log, and the operator log; exit 1 on a problem"),
        ("release", "release a held message, or every held message of a scope"),
        ("cancel", "cancel a pending, held or dead message"),
        ("requeue", "send a dead message back for delivery"),
        ("compensate", "enqueue the compensation a delivered request carried"),
        ("resolve", "resolve the intents an operator command killed mid-way left open"),
    ):
        action = actions.add_parser(name, help=text, description=text)
        _common(action, _DATABASE_HELP)
        if name in ("show", "cancel", "requeue"):
            action.add_argument("message", type=uuid.UUID, help="the message id")
        if name == "release":
            target = action.add_mutually_exclusive_group(required=True)
            target.add_argument("message", nargs="?", type=uuid.UUID, help="the message id")
            target.add_argument("--scope", help="release every held message of this scope")
        if name == "compensate":
            target = action.add_mutually_exclusive_group(required=True)
            target.add_argument("message", nargs="?", type=uuid.UUID, help="the message id")
            target.add_argument("--plan", help="every delivered request of this plan")
            action.add_argument(
                "--late", action="store_true", help="compensate past the original's deadline"
            )
        if name == "list":
            action.add_argument("--state", help="only messages in this state")
            action.add_argument("--scope", help="only this scope's messages")
            action.add_argument("--limit", type=int, default=100)
        if name in SIGNED:
            action.add_argument(
                "--key", help=f"your operator key file (default: ${OPERATOR_KEY_ENV})"
            )
            action.add_argument(
                "--reason",
                required=name == "cancel",
                help="recorded in the signed intent and the delivery log",
            )
    operator = commands.add_parser("operator", help="operator keys", description="Operator keys.")
    keys = operator.add_subparsers(dest="action", required=True)
    keygen = keys.add_parser(
        "keygen",
        help="write a new Ed25519 operator key; print its public half",
        description="Write a new Ed25519 operator key (readable by you only), and print the "
        "line that registers its public half in [operators.keys].",
    )
    keygen.add_argument("--out", required=True, help="where to write the key: never overwritten")
    keygen.add_argument("--name", required=True, help="the operator's name")
    for name, text in (
        ("install", "install Interlock's schema and triggers (run as the tables' owner)"),
        ("check", "verify the setup and print what the cascade check refuses"),
        ("reconcile-effects", "fail on any write to an observed table no escrow chain records"),
    ):
        command = commands.add_parser(name, help=text, description=text)
        _common(command, _DATABASE_HELP)
        if name == "install":
            command.add_argument(
                "--key",
                help=f"with [operators]: your operator key, to sign the sink registry "
                f"(default: ${OPERATOR_KEY_ENV})",
            )
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


def _install(config: InterlockConfig, args: argparse.Namespace, out: TextIO) -> int:
    signer = None
    if config.operators is not None:
        # A change to the sink registry is an operator's, and signed: the key
        # is read before anything is installed.
        try:
            signer = _signer(config, args.key)
        except _RefusedError as exc:
            print(f"interlock: install changes the sink registry: {exc}", file=sys.stderr)
            return EXIT_USAGE
    code = _install_schema(config, out)
    if signer is not None:
        _vouch(config, signer, out)
    return code


def _vouch(config: InterlockConfig, signer: Any, out: TextIO) -> None:
    """Sign the registry the database now mirrors."""
    if config.substrate != "postgres":
        from interlock.sqlite_outbox import OPERATOR, SqliteOutboxStore

        store = SqliteOutboxStore(config.database, writes=OPERATOR)
        try:
            with _session(config, store, signer) as operator:
                record = operator.installed()
        finally:
            store.close()
    else:
        import psycopg

        with (
            psycopg.connect(config.database, autocommit=True) as conn,
            _session(config, conn, signer) as operator,
        ):
            record = operator.installed()
    print(
        f"signed by {operator.name}: the sink registry, operator record {record.seq} "
        f"({record.record_hash[:16]})",
        file=out,
    )


def _install_schema(config: InterlockConfig, out: TextIO) -> int:
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


def _keygen(args: argparse.Namespace, out: TextIO) -> int:
    from interlock.operators import generate_key

    try:
        signer = generate_key(args.out)
    except FileExistsError:
        print(f"interlock: {args.out} exists; a key is never overwritten", file=sys.stderr)
        return EXIT_USAGE
    print(f"wrote {args.out} (keep it to yourself). Register its public half:", file=out)
    print("[operators.keys]", file=out)
    print(f'{args.name} = "{signer.public_key().spec()}"', file=out)
    return EXIT_OK


def _outbox(config: InterlockConfig, args: argparse.Namespace, out: TextIO) -> int:
    if config.substrate != "postgres":
        from interlock.sqlite_outbox import OPERATOR, SqliteOutboxStore

        store = SqliteOutboxStore(config.database, writes=OPERATOR)
        try:
            return _outbox_action(config, store, args, out)
        finally:
            store.close()
    import psycopg

    try:
        with psycopg.connect(config.database, autocommit=True) as conn:
            return _outbox_action(config, conn, args, out)
    except psycopg.Error as exc:
        raise SubstrateUnavailableError(f"outbox {args.action} failed: {exc}") from exc


def _outbox_action(
    config: InterlockConfig, source: Any, args: argparse.Namespace, out: TextIO
) -> int:
    if args.action in SIGNED:
        return _signed(config, source, args, out)
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
                + (f"  ref {event.remote_ref}" if event.remote_ref else "")
                + (f"  authority {event.authority[:16]}" if event.authority else "")
                + (f"  {event.detail}" if event.detail else ""),
                file=out,
            )
        return EXIT_OK if log else EXIT_FINDINGS
    return _verify(config, source, out)


def _verify(config: InterlockConfig, source: Any, out: TextIO) -> int:
    problems = list(verify_delivery_log(source))
    settings = config.operators
    legacy = 0
    if settings is not None:
        from interlock.operators import verify_operators
        from interlock.records import read_records

        records = read_records(settings.log) if settings.log.exists() else ()
        entries = None
        if settings.ledger is not None:
            governor = _ledger(settings.ledger, read_only=True)
            try:
                entries = list(governor.audit_trail())
            finally:
                governor.close()
        report = verify_operators(source, records, settings.keyring(), ledger=entries)
        problems += report.problems
        legacy = report.legacy
    for problem in problems:
        print(problem, file=out)
    if problems:
        return EXIT_FINDINGS
    print("every delivery log verifies", file=out)
    if settings is not None:
        print(
            "every operator action is signed, and the operator log verifies"
            + (f" ({legacy} unsigned from before version 3)" if legacy else ""),
            file=out,
        )
    return EXIT_OK


def _ledger(ledger: str, *, read_only: bool = False) -> Any:
    from agentgov import BudgetManager

    if ledger.startswith(("postgres://", "postgresql://")):
        return BudgetManager.open_postgres(ledger, read_only=read_only)
    return BudgetManager.open_sqlite(ledger, read_only=read_only)


class _RefusedError(Exception):
    """An operator command refused before it began: usage, not the outbox."""


def _signer(config: InterlockConfig, key: str | None) -> Any:
    """The operator's key, or why there is none."""
    from interlock.operators import load_key

    if config.operators is None:
        raise _RefusedError(
            "operator actions are signed: configure [operators] with each operator's public "
            "key (docs/EPIC3_DESIGN.md §6)"
        )
    path = key or os.environ.get(OPERATOR_KEY_ENV)
    if not path:
        raise _RefusedError(f"sign with your operator key: --key PATH, or {OPERATOR_KEY_ENV}")
    try:
        return load_key(path)
    except (OSError, ValueError) as exc:
        raise _RefusedError(f"cannot read the operator key: {exc}") from exc


@contextmanager
def _session(config: InterlockConfig, source: Any, signer: Any) -> Iterator[Any]:
    """An operator, signing into the operator log, anchoring into its ledger
    when the ledger can be written now."""
    from interlock.deliveries import operations
    from interlock.operators import Operator, OperatorLog

    settings = config.operators
    assert settings is not None
    governor = None
    if settings.ledger is not None:
        try:
            governor = _ledger(settings.ledger)
        except Exception as exc:  # anchored the next time the ledger can be written
            print(f"interlock: not anchoring now ({exc})", file=sys.stderr)
    try:
        try:
            log = OperatorLog(
                settings.log, signer, settings.keyring(), ledger=governor, scope=settings.scope
            )
        except ValueError as exc:
            raise _RefusedError(str(exc)) from exc
        try:
            yield Operator(log, operations(source))
        finally:
            log.close()
    finally:
        if governor is not None:
            governor.close()


def _signed(config: InterlockConfig, source: Any, args: argparse.Namespace, out: TextIO) -> int:
    from interlock.operators import OperatorRefusedError

    try:
        signer = _signer(config, args.key)
        with _session(config, source, signer) as operator:
            if args.action == "resolve":
                resolved = operator.resolve()
                for record in resolved:
                    print(f"record {record.seq}: {record.kind}", file=out)
                print(f"resolved {len(resolved)} intent(s)", file=out)
                return EXIT_OK
            try:
                outcome = _act(operator, config, args)
            except OperatorRefusedError as exc:
                print(f"refused, nothing signed: {exc}", file=out)
                return EXIT_FINDINGS
    except _RefusedError as exc:
        print(f"interlock: {exc}", file=sys.stderr)
        return EXIT_USAGE
    print(
        f"signed by {operator.name}: intent {outcome.intent.seq} "
        f"({outcome.intent.record_hash[:16]}), {outcome.record.kind}",
        file=out,
    )
    for row in outcome.rows:
        print(f"  {row.event:<12} {row.message_id}  row {row.seq}", file=out)
    for message, why in outcome.skipped:
        print(f"  not done     {message}: {why}", file=out)
    return EXIT_OK if outcome.applied else EXIT_FINDINGS


def _act(operator: Any, config: InterlockConfig, args: argparse.Namespace) -> Any:
    if args.action == "release":
        if args.scope:
            return operator.release_scope(args.scope, reason=args.reason)
        return operator.release([args.message], reason=args.reason)
    if args.action == "cancel":
        return operator.cancel(args.message, reason=args.reason)
    if args.action == "requeue":
        return operator.requeue(args.message, reason=args.reason)
    return operator.compensate(
        [] if args.message is None else [args.message],
        plan_id=args.plan,
        late=args.late,
        reason=args.reason,
        registry=config.sink_registry(),
    )


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
