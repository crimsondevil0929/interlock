"""The ``interlock`` command.

``interlock install``            put Interlock's triggers into the database
``interlock check``              verify the setup, print the cascade check
``interlock reconcile-effects``  fail on any write to an observed table that no
                                 escrow chain records
``interlock relay``              deliver committed outbound requests, until
                                 stopped (``--once``: until none is due),
                                 attesting each outcome with the relay's key
``interlock outbox ACTION``      ``status``, ``list``, ``show``, ``verify`` the
                                 delivery logs, the relays' attestations, and
                                 the operator log;
                                 ``release``, ``cancel``, ``requeue``,
                                 ``compensate``, ``resolve``: an operator's
                                 actions, each signed with their key
``interlock vacuum``             prune what no check will read again, under a
                                 checkpoint the operator signs and AgentGov
                                 anchors first (``--dry-run``: say what;
                                 ``--verify-archive FILE``: prove an archive)
``interlock inbox ACTION``       ``serve``: receive vendors' webhooks, verify
                                 their signatures, bind each to the delivery
                                 it names, attest it; ``match``: bind what
                                 arrived before its delivery was recorded;
                                 ``list`` the events and facts; ``verify``
                                 every inbound log, fact and consumption
``interlock daemon``             every part in one process until stopped: the
                                 relays, the inbox, the settler, the vacuum,
                                 and (``--app module:callable``) the
                                 application's engines and agents
``interlock keygen``             a new relay, operator or inbox key, and its
                                 public half for ``[relays.keys]``,
                                 ``[operators.keys]`` or ``[inbox.keys]``
                                 (``interlock operator keygen``: an operator's)

Every command reads a TOML configuration file (see :mod:`interlock.config`).
Exit codes, for scripts and CI:

====  =============================================================
0     done; for ``check``, the setup is sound; for
      ``reconcile-effects``, every write is accounted for
1     ``reconcile-effects`` found an unrecorded write; ``outbox verify``
      found a delivery log, an attestation or an operator record that
      does not verify; an ``outbox`` action found nothing to act on; a
      ``vacuum`` refused (what it would prune does not verify), or an
      archive does not prove out; ``inbox verify`` found an event, a
      fact or a consumption that does not verify
2     usage, or the configuration file is wrong; a relay or an inbox
      without a key registered in ``[relays.keys]`` or ``[inbox.keys]``
3     the database is not set up (not installed, grants)
4     the database cannot be reached
5     an escrow chain failed verification, so it proves nothing
====  =============================================================
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import threading
import uuid
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Final, TextIO

from interlock.cascade import CascadeReport, analyze_cascades, read_postgres_foreign_keys
from interlock.chain import EscrowChain, EscrowRecord
from interlock.config import (
    INBOX_DATABASE_ENV,
    ConfigError,
    InterlockConfig,
    load_config,
)
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
from interlock.wiring import INBOX_KEY_ENV, RELAY_KEY_ENV, live_keyring, trusted_keyring
from interlock.wiring import RefusedError as _RefusedError
from interlock.wiring import compactor as _compactor
from interlock.wiring import inbox_signer as _inbox_signer
from interlock.wiring import inbox_store as _inbox_store
from interlock.wiring import open_ledger as _ledger
from interlock.wiring import relay_adapters as _adapters
from interlock.wiring import relay_signer as _relay_signer

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
    if args.command in ("operator", "keygen"):
        return _keygen(args, stream)
    # A relay and an inbox connect as their own roles, not the file's; so
    # may every part of the daemon.
    relaying = args.command == "relay" or (
        args.command == "inbox" and args.action in ("serve", "match")
    )
    try:
        config = load_config(
            args.config,
            database=None if relaying else args.database,
            require_database=not relaying and args.command != "daemon",
        )
    except ConfigError as exc:
        print(f"interlock: {exc}", file=sys.stderr)
        return EXIT_USAGE
    try:
        if args.command == "install":
            return _install(config, args, stream)
        if args.command == "reconcile-effects":
            return _reconcile(config, args.chain, args.after, stream)
        if args.command == "inbox":
            return _inbox(config, args, stream)
        if args.command == "daemon":
            return _daemon(config, args, stream)
        if relaying:
            return _relay(config, args, stream)
        if args.command == "outbox":
            return _outbox(config, args, stream)
        if args.command == "keys":
            return _keys(config, args, stream)
        if args.command == "vacuum":
            return _vacuum(config, args, stream)
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
_SIGNER_HELP: Final = "in place of --key: the [signers.<name>] holding your operator key"


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
    relay.add_argument(
        "--key", help=f"overrides [relay]'s key, this relay's own, as does {RELAY_KEY_ENV}"
    )
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
            action.add_argument("--signer", help=_SIGNER_HELP)
            action.add_argument(
                "--reason",
                required=name == "cancel",
                help="recorded in the signed intent and the delivery log",
            )
    vacuum = commands.add_parser(
        "vacuum",
        help="prune settled history under a signed, anchored checkpoint",
        description="Verify the outbox, then prune what no check will read again: stages "
        "delivered and settled, or cancelled, past [vacuum] retain_days; window history past "
        "the longest [[windows]] span. Under one checkpoint, signed with your operator key "
        "and anchored into [operators]' ledger before anything is deleted.",
    )
    _common(vacuum, _DATABASE_HELP)
    vacuum.add_argument("--key", help=f"your operator key file (default: ${OPERATOR_KEY_ENV})")
    vacuum.add_argument("--signer", help=_SIGNER_HELP)
    vacuum.add_argument("--reason", help="recorded in the signed intent")
    vacuum.add_argument("--dry-run", action="store_true", help="say what would go; sign nothing")
    vacuum.add_argument(
        "--verify-archive",
        metavar="FILE",
        help="prove an archive a vacuum wrote against its checkpoint, and do nothing else",
    )
    inbox = commands.add_parser(
        "inbox",
        help="receive vendors' webhooks as facts plans may consume",
        description="Receive vendors' webhooks, verify their signatures, bind each to the "
        "delivered request it names, and attest it as a fact (docs/EPIC5_DESIGN.md §2).",
    )
    steps = inbox.add_subparsers(dest="action", required=True)
    for name, text in (
        ("serve", "serve POST /inbox/<source> until stopped (SIGTERM or Ctrl-C)"),
        ("match", "bind the events that matched nothing yet, once"),
        ("list", "list each source's events, and the facts bound to them"),
        ("verify", "verify every inbound log, fact and consumption; exit 1 on a problem"),
    ):
        step = steps.add_parser(name, help=text, description=text)
        if name in ("serve", "match"):
            _common(step, f"overrides [inbox]'s database, as does {INBOX_DATABASE_ENV}")
            step.add_argument(
                "--key", help=f"overrides [inbox]'s key, the inbox's own, as does {INBOX_KEY_ENV}"
            )
        else:
            _common(step, _DATABASE_HELP)
        if name == "serve":
            step.add_argument("--listen", help="overrides [inbox]'s listen, HOST:PORT")
        if name == "list":
            step.add_argument("--source", help="only this source's events")
            step.add_argument("--limit", type=int, default=100)
    daemon = commands.add_parser(
        "daemon",
        help="run every part of Interlock in one process",
        description="Run the relays, the inbox, the settler and the vacuum, and with --app the "
        "application's engines and agents, in one process until SIGTERM or Ctrl-C "
        "(docs/EPIC6_DESIGN.md). Each part connects as its own role.",
    )
    _common(daemon, _DATABASE_HELP)
    daemon.add_argument(
        "--app",
        metavar="MODULE:CALLABLE",
        help="a callable taking the configuration and returning an interlock.daemon.Application",
    )
    daemon.add_argument("--listen", help="overrides [inbox]'s listen, HOST:PORT")
    daemon.add_argument(
        "--metrics", help="serves /metrics on HOST:PORT, overriding [metrics]'s listen"
    )
    daemon.add_argument(
        "--node",
        help="this daemon's node of the cluster [cluster] configures, overriding its node "
        "and INTERLOCK_NODE (docs/EPIC9_DESIGN.md)",
    )
    daemon.add_argument("--relay-key", help=f"overrides [relay]'s key, as does {RELAY_KEY_ENV}")
    daemon.add_argument("--inbox-key", help=f"overrides [inbox]'s key, as does {INBOX_KEY_ENV}")
    keys_command = commands.add_parser(
        "keys",
        help="list, register and revoke keys (docs/EPIC8_DESIGN.md §2)",
        description="Every role's keys: the configuration's, the ones operators registered, and "
        "the revoked. A registration or a revocation is signed into the operator log; a relay's "
        "or an inbox's key is revoked in the database too, which seals what it signed.",
    )
    key_actions = keys_command.add_subparsers(dest="action", required=True)
    for name, text in (
        ("list", "every role's keys, and what became of each"),
        ("register", "register a key for a role, signed into the operator log"),
        ("revoke", "revoke a key: what it signed still verifies, and nothing new it signs does"),
    ):
        key_action = key_actions.add_parser(name, help=text, description=text)
        _common(key_action, _DATABASE_HELP)
        if name == "list":
            continue
        key_action.add_argument(
            "--key", help=f"your operator key file (default: ${OPERATOR_KEY_ENV})"
        )
        key_action.add_argument("--signer", help=_SIGNER_HELP)
        key_action.add_argument("--role", required=True, choices=("relay", "inbox", "operator"))
        if name == "register":
            key_action.add_argument("--name", required=True, help="whose key it is")
            public = key_action.add_mutually_exclusive_group(required=True)
            public.add_argument("--public", help="the key's public half: ed25519:<hex>")
            public.add_argument(
                "--public-of",
                metavar="SIGNER",
                help="the public half of the key a [signers.<name>] holds, as its service "
                "serves it now",
            )
        else:
            key_action.add_argument("key_id", help="the key's id: 16 hex characters")
            key_action.add_argument("--reason", help="recorded in the signed intent")
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
    keygen.set_defaults(role="operator")
    keygen = commands.add_parser(
        "keygen",
        help="write a new Ed25519 key for a relay, an operator or an inbox; print its public half",
        description="Write a new Ed25519 key (readable by you only), and print the line that "
        "registers its public half: in [relays.keys] for a relay, which signs every outcome "
        "it records; in [operators.keys] for an operator, who signs every action; in "
        "[inbox.keys] for an inbox, which attests every event and fact.",
    )
    keygen.add_argument("--role", required=True, choices=("relay", "operator", "inbox"))
    keygen.add_argument("--out", required=True, help="where to write the key: never overwritten")
    keygen.add_argument("--name", required=True, help="the relay's, operator's or inbox's name")
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
            command.add_argument("--signer", help=_SIGNER_HELP)
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
            signer = _signer(config, args.key, args.signer)
        except _RefusedError as exc:
            print(f"interlock: install changes the sink registry: {exc}", file=sys.stderr)
            return EXIT_USAGE
    code, legacy = _install_schema(config, out)
    if signer is not None:
        from interlock.operators import OperatorRefusedError

        try:
            _vouch(config, signer, legacy, out)
        except OperatorRefusedError as exc:
            print(f"interlock: install is not vouched for: {exc}", file=sys.stderr)
            return EXIT_FINDINGS
    return code


def _vouch(config: InterlockConfig, signer: Any, legacy: Any, out: TextIO) -> None:
    """Sign the registry the database now mirrors, and the legacy set the
    install's own transaction read."""
    if config.substrate != "postgres":
        from interlock.sqlite_outbox import OPERATOR, SqliteOutboxStore

        store = SqliteOutboxStore(config.database, writes=OPERATOR)
        try:
            with _session(config, store, signer) as operator:
                record = operator.installed(legacy)
        finally:
            store.close()
    else:
        import psycopg

        with (
            psycopg.connect(config.database, autocommit=True) as conn,
            _session(config, conn, signer) as operator,
        ):
            record = operator.installed(legacy)
    print(
        f"signed by {operator.name}: the sink registry and the legacy set "
        f"({record.body['legacy']['rows']} row(s) from before version 4), operator record "
        f"{record.seq} ({record.record_hash[:16]})",
        file=out,
    )


def _install_schema(config: InterlockConfig, out: TextIO) -> tuple[int, Any]:
    names = ", ".join(t.name for t in config.tables)
    if config.substrate != "postgres":
        from interlock.sqlite_outbox import install_sqlite_outbox

        install_sqlite_journal(config.database, config.tables)
        legacy = install_sqlite_outbox(config.database, config.sinks, config.inbox.sources)
        print(f"installed: journal triggers on {len(config.tables)} table(s): {names}", file=out)
        print("installed: the outbox, the inbox, and WAL mode", file=out)
        for sink in config.sinks:
            operations = ", ".join(op.name for op in sink.operations)
            print(f"registered sink: {sink.name} ({_kind(sink)}{operations})", file=out)
        for source in config.inbox.sources:
            print(f"registered inbound source: {source.name} ({source.kind})", file=out)
        _print_report(_sqlite(config).check_cascades(), out)
        return EXIT_OK, legacy
    import psycopg

    try:
        with psycopg.connect(config.database, autocommit=True) as conn:
            legacy = install(
                conn,
                config.tables,
                schema=config.schema,
                stage_roles=config.stage_roles,
                audit_roles=config.audit_roles,
                sinks=config.sinks,
                relay_roles=config.relay_roles,
                settler_roles=config.settler_roles,
                sources=config.inbox.sources,
                inbox_roles=config.inbox_roles,
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
    for role in config.settler_roles:
        print(f"granted to settler role: {role}", file=out)
    for source in config.inbox.sources:
        print(f"registered inbound source: {source.name} ({source.kind})", file=out)
    for role in config.inbox_roles:
        print(f"granted to inbox role: {role}", file=out)
    _print_report(report, out)
    return EXIT_OK, legacy


def _relay(config: InterlockConfig, args: argparse.Namespace, out: TextIO) -> int:
    from interlock.exceptions import KeyRevokedError
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
    try:
        signer = _relay_signer(config, args.key or os.environ.get(RELAY_KEY_ENV) or settings.key)
    except _RefusedError as exc:
        print(f"interlock: {exc}", file=sys.stderr)
        return EXIT_USAGE
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
                    signer=signer,
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
        revoked: list[KeyRevokedError] = []

        def work(relay: Relay) -> None:
            try:
                reports.append(relay.run(stop, poll=settings.poll_seconds))
            except KeyRevokedError as exc:  # every worker signs with the one key
                revoked.append(exc)
                stop.set()

        threads = [threading.Thread(target=work, args=(r,), name=r.relay_id) for r in relays]
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
        if revoked:
            print(
                f"interlock: {revoked[0]}: start the relay again with its new key "
                f"(docs/EPIC8_DESIGN.md §2.6)",
                file=sys.stderr,
            )
            return EXIT_CONFIGURATION
        return EXIT_OK
    finally:
        for relay in relays:
            relay.close()
        for breaker in breakers:
            breaker.close()


def _kind(sink: Any) -> str:
    return "" if sink.kind == "http" else f"{sink.kind}: "


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
    print(
        {"relay": "[relays.keys]", "inbox": "[inbox.keys]"}.get(args.role, "[operators.keys]"),
        file=out,
    )
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
        keyring = trusted_keyring(config, "relay")
        for event in log:
            print(
                f"{event.seq:>3} {event.at.isoformat()} {event.event:<17} "
                f"call {event.attempt or '-'}  {event.actor}"
                + (f"  HTTP {event.status_code}" if event.status_code else "")
                + (f"  -> {event.state_after}" if event.state_after else "")
                + (f"  ref {event.remote_ref}" if event.remote_ref else "")
                + (f"  authority {event.authority[:16]}" if event.authority else "")
                + _attester(event.attestation, keyring)
                + (f"  {event.detail}" if event.detail else ""),
                file=out,
            )
        return EXIT_OK if log else EXIT_FINDINGS
    return _verify(config, source, out)


def _attester(attestation: str | None, keyring: Any) -> str:
    """Whose key an outcome's attestation names: the relay registered with
    it, or the key's id. ``outbox verify`` checks the signature."""
    if attestation is None:
        return ""
    try:
        key_id = str(json.loads(attestation)["key_id"])
    except (ValueError, KeyError, TypeError):
        return "  attested (unreadable)"
    name = keyring.name(key_id) if keyring is not None else None
    return f"  attested by {name}" if name else f"  attested by key {key_id}"


def _verify(config: InterlockConfig, source: Any, out: TextIO) -> int:
    from interlock.keys import KeyRegistry, verify_keys
    from interlock.operators import legacy_vouch
    from interlock.records import read_records

    problems = list(verify_delivery_log(source))
    settings = config.operators
    records = read_records(settings.log) if settings is not None and settings.log.exists() else ()
    vouch = legacy_vouch(records, settings.keyring()) if settings is not None else None
    # The relays' keys: the configured, and those operators registered since
    # (docs/EPIC8_DESIGN.md §2.1).
    registry = KeyRegistry.build(config.key_roots(), records)
    keyring = (
        None
        if config.relays is None and not registry.keys("relay")
        else (registry.keyring("relay"))
    )
    attestations = None
    if keyring is not None:
        from interlock.attestations import verify_attestations

        attestations = verify_attestations(source, keyring, legacy=vouch)
        problems += attestations.problems
    legacy = 0
    if settings is not None:
        from interlock.operators import verify_operators

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
        keys = verify_keys(source, records, config.key_roots())
        problems += keys.problems
    # The legacy set is both verifiers' to check: say what is wrong with it once.
    problems = list(dict.fromkeys(problems))
    for problem in problems:
        print(problem, file=out)
    if problems:
        return EXIT_FINDINGS
    print("every delivery log verifies", file=out)
    if attestations is None:
        print("relays' attestations not checked: register their keys in [relays.keys]", file=out)
    else:
        print(
            f"every outcome is attested by a registered relay ({attestations.attested})"
            + (
                f", and {attestations.legacy} from before version 4 are in the legacy set "
                f"operator record {vouch.record} vouched for"
                if attestations.legacy and vouch is not None
                else ""
            ),
            file=out,
        )
    if settings is not None:
        from interlock.deliveries import reader

        checkpoints = reader(source).checkpoints()
        if checkpoints:
            pruned = len(reader(source).compacted())
            print(
                f"{len(checkpoints)} checkpoint(s) verify against their signed intents; "
                f"{pruned} message(s) pruned under them, every tombstone in its fold",
                file=out,
            )
        if keys.registered or keys.revoked:
            print(
                f"{keys.registered} key(s) registered by operators; {keys.revoked} revoked, each "
                f"held to the seal its operator signed",
                file=out,
            )
        print(
            "every operator action is signed, and the operator log verifies"
            + (
                f" ({legacy} from before version 3, in the legacy set operator record "
                f"{vouch.record} vouched for)"
                if legacy and vouch is not None
                else f" ({legacy} unsigned from before version 3)"
                if legacy
                else ""
            ),
            file=out,
        )
    return EXIT_OK


def _signer(config: InterlockConfig, key: str | None, signer: str | None = None) -> Any:
    """The operator's key: the file at ``--key`` or ``INTERLOCK_OPERATOR_KEY``,
    or the ``[signers.<name>]`` that ``--signer`` names; or why there is none."""
    from agentgov.exceptions import SignerUnavailableError

    from interlock.wiring import open_signer

    if config.operators is None:
        raise _RefusedError(
            "operator actions are signed: configure [operators] with each operator's public "
            "key (docs/EPIC3_DESIGN.md §6)"
        )
    if key and signer:
        raise _RefusedError("sign with --key or --signer, not both")
    if signer is not None and signer not in config.signers:
        raise _RefusedError(f"--signer {signer!r} names no [signers.{signer}]")
    path = None if signer else key or os.environ.get(OPERATOR_KEY_ENV)
    if not path and signer is None:
        raise _RefusedError(
            f"sign with your operator key: --key PATH, --signer NAME, or {OPERATOR_KEY_ENV}"
        )
    try:
        return open_signer(config, signer, path)
    except (OSError, ValueError, SignerUnavailableError) as exc:
        raise _RefusedError(f"cannot open the operator key: {exc}") from exc


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
        signer = _signer(config, args.key, args.signer)
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


def _keys(config: InterlockConfig, args: argparse.Namespace, out: TextIO) -> int:
    """``interlock keys``: list, register, revoke (``docs/EPIC8_DESIGN.md`` §2)."""
    if config.operators is None:
        print(
            "interlock: keys are registered and revoked in the operator log: configure "
            "[operators] (docs/EPIC3_DESIGN.md §6)",
            file=sys.stderr,
        )
        return EXIT_USAGE
    if config.substrate != "postgres":
        from interlock.sqlite_outbox import OPERATOR, SqliteOutboxStore

        store = SqliteOutboxStore(config.database, writes=OPERATOR)
        try:
            return _keys_action(config, store, args, out)
        finally:
            store.close()
    import psycopg

    try:
        with psycopg.connect(config.database, autocommit=True) as conn:
            return _keys_action(config, conn, args, out)
    except psycopg.Error as exc:
        raise SubstrateUnavailableError(f"keys {args.action} failed: {exc}") from exc


def _keys_action(
    config: InterlockConfig, source: Any, args: argparse.Namespace, out: TextIO
) -> int:
    from interlock.deliveries import reader
    from interlock.keys import ROLES, revocations_of
    from interlock.operators import OperatorRefusedError
    from interlock.wiring import key_registry

    if args.action == "list":
        registry = key_registry(config)
        revoked = revocations_of(reader(source))
        registered = {r.key.key_id: r.record.seq for r in registry.registrations}
        for role in ROLES:
            keyring = registry.keyring(role)
            for key_id in keyring.ids():
                origin = (
                    f"registered by operator record {registered[key_id]}"
                    if key_id in registered
                    else "configured"
                )
                logged = registry.revocation(key_id)
                if key_id in revoked:
                    sealed = revoked[key_id]
                    status = f"revoked {sealed.revoked_at.isoformat()}, {sealed.count} rows sealed"
                elif logged is not None and logged.applied is not None:
                    status = f"revoked by operator record {logged.intent.seq}"
                else:
                    status = "trusted"
                print(
                    f"{role:<9} {keyring.name(key_id) or '':<20} {key_id}  {origin}; {status}",
                    file=out,
                )
        return EXIT_OK
    try:
        signer = _signer(config, args.key, args.signer)
        with _session(config, source, signer) as operator:
            roots = config.key_roots()
            try:
                if args.action == "register":
                    public = args.public or _public_of(config, args.public_of)
                    record = operator.register_key(args.role, args.name, public, roots=roots)
                    body = record.body
                    print(
                        f"signed by {operator.name}: record {record.seq}, {args.role} key "
                        f"{body['key_id']} registered as {args.name}",
                        file=out,
                    )
                    return EXIT_OK
                outcome = operator.revoke_key(
                    args.role, args.key_id, reason=args.reason, roots=roots
                )
            except OperatorRefusedError as exc:
                print(f"refused, nothing signed: {exc}", file=out)
                return EXIT_FINDINGS
    except _RefusedError as exc:
        print(f"interlock: {exc}", file=sys.stderr)
        return EXIT_USAGE
    seal = outcome.record.body.get("seal")
    print(
        f"signed by {operator.name}: intent {outcome.intent.seq}, {args.role} key "
        f"{args.key_id} revoked"
        + (f"; {seal['count']} rows sealed ({seal['digest'][:16]})" if seal else ""),
        file=out,
    )
    return EXIT_OK


def _public_of(config: InterlockConfig, name: str) -> str:
    """The public half of the key the ``[signers.<name>]`` holds, as its
    service serves it now."""
    from agentgov.exceptions import SignerUnavailableError

    if name not in config.signers:
        raise _RefusedError(f"--public-of {name!r} names no [signers.{name}]")
    try:
        return config.signers[name].open().public_key().spec()
    except SignerUnavailableError as exc:
        raise _RefusedError(f"cannot read the key [signers.{name}] holds: {exc}") from exc


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


def _vacuum(config: InterlockConfig, args: argparse.Namespace, out: TextIO) -> int:
    from interlock.vacuum import Vacuum

    relays = trusted_keyring(config, "relay")
    settings = config.operators
    if args.verify_archive:
        return _verify_archive(config, Path(args.verify_archive), out)
    if settings is None or settings.ledger is None:
        print(
            "interlock: a vacuum's checkpoint is anchored into AgentGov before anything is "
            "pruned: configure [operators] with its ledger",
            file=sys.stderr,
        )
        return EXIT_USAGE
    if relays is None:
        print(
            "interlock: a vacuum prunes only what verifies, relays' attestations included: "
            "register their keys in [relays.keys]",
            file=sys.stderr,
        )
        return EXIT_USAGE
    try:
        signer = _signer(config, args.key, args.signer)
    except _RefusedError as exc:
        print(f"interlock: {exc}", file=sys.stderr)
        return EXIT_USAGE
    from interlock.operators import OperatorLog

    governor = _ledger(settings.ledger)
    source, close = _compactor(config)
    try:
        try:
            log = OperatorLog(
                settings.log, signer, settings.keyring(), ledger=governor, scope=settings.scope
            )
        except ValueError as exc:
            print(f"interlock: {exc}", file=sys.stderr)
            return EXIT_USAGE
        try:
            report = Vacuum(
                log,
                source,
                operators=settings.keyring(),
                relays=relays,
                ledger=governor,
                windows=config.windows,
                retain=config.vacuum.retain,
                margin=config.vacuum.margin,
                archive=config.vacuum.archive,
                inbox=trusted_keyring(config, "inbox"),
            ).run(reason=args.reason, dry_run=args.dry_run)
        finally:
            log.close()
    finally:
        close()
        governor.close()
    for problem in report.problems:
        print(problem, file=out)
    for stage, why in report.kept:
        print(f"kept stage {stage}: {why}", file=out)
    for source, why in report.inbox_kept:
        print(f"kept inbound source {source}: {why}", file=out)
    checkpoint = report.checkpoint
    if report.outcome in ("applied", "dry-run") and checkpoint is not None:
        verb = "pruned" if report.outcome == "applied" else "would prune"
        print(
            f"checkpoint {checkpoint.seq} ({checkpoint.digest[:16]}): {verb} "
            f"{report.messages} message(s), {report.log_rows} log row(s), "
            f"{report.window_rows} window row(s), {report.inbox_events} inbound event(s)"
            + (f"; archived to {report.archive}" if report.archive else ""),
            file=out,
        )
        return EXIT_OK
    if report.outcome == "nothing":
        print("nothing to prune", file=out)
        return EXIT_OK
    print(f"{report.outcome}: nothing pruned", file=out)
    return EXIT_FINDINGS


def _verify_archive(config: InterlockConfig, path: Path, out: TextIO) -> int:
    from interlock.compaction import Checkpoint
    from interlock.vacuum import ARCHIVE_VERSION, verify_archive

    try:
        header = json.loads(path.read_text(encoding="utf-8").split("\n", 1)[0])
        if header.get("v") != ARCHIVE_VERSION:
            raise ValueError("not an archive")
        seq = int(header["checkpoint"]["seq"])
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"interlock: {path} is not a vacuum's archive: {exc}", file=sys.stderr)
        return EXIT_USAGE
    source, close = _compactor(config)
    try:
        rows = [row for row in source.checkpoints() if row.seq == seq]
    finally:
        close()
    if not rows:
        print(f"the database holds no checkpoint {seq}", file=out)
        return EXIT_FINDINGS
    problems = verify_archive(
        path,
        Checkpoint.parse(rows[0].body),
        relays=trusted_keyring(config, "relay"),
        inbox=trusted_keyring(config, "inbox"),
    )
    for problem in problems:
        print(problem, file=out)
    if problems:
        return EXIT_FINDINGS
    print(f"{path.name} proves checkpoint {seq}'s pruned history", file=out)
    return EXIT_OK


def _inbox(config: InterlockConfig, args: argparse.Namespace, out: TextIO) -> int:
    try:
        return _inbox_command(config, args, out)
    except _database_errors() as exc:
        if getattr(exc, "sqlstate", None) == "42501":
            raise SubstrateConfigurationError(
                f"the inbox's role lacks a privilege it needs: {exc}. Install with the role in "
                f"inbox_roles"
            ) from exc
        raise SubstrateUnavailableError(f"inbox {args.action} failed: {exc}") from exc


def _database_errors() -> tuple[type[Exception], ...]:
    import sqlite3

    try:
        import psycopg
    except ImportError:  # pragma: no cover - the postgres extra is not installed
        return (sqlite3.Error,)
    return (sqlite3.Error, psycopg.Error)


def _inbox_command(config: InterlockConfig, args: argparse.Namespace, out: TextIO) -> int:
    settings = config.inbox
    keys = trusted_keyring(config, "inbox")
    if keys is None:
        print(
            "interlock: the inbox attests every event and fact, and verifying needs its "
            "public key: register it in [inbox.keys] (a new one: interlock keygen --role inbox)",
            file=sys.stderr,
        )
        return EXIT_USAGE
    if args.action in ("list", "verify"):
        source, close = _inbox_reader(config)
        try:
            if args.action == "list":
                return _inbox_list(source, args, out)
            return _inbox_verify(config, source, keys, out)
        finally:
            close()
    relays = live_keyring(config, "relay")
    if relays is None:
        print(
            "interlock: an inbox binds an event only to a delivery a registered relay "
            "attested: register the relays' keys in [relays.keys]",
            file=sys.stderr,
        )
        return EXIT_USAGE
    if not settings.sources:
        print("interlock: [[inbox.sources]] configures no source to receive", file=sys.stderr)
        return EXIT_USAGE
    try:
        signer = _inbox_signer(config, args.key or os.environ.get(INBOX_KEY_ENV) or settings.key)
    except _RefusedError as exc:
        print(f"interlock: {exc}", file=sys.stderr)
        return EXIT_USAGE
    from interlock.inbox import Inbox

    store, close = _inbox_store(config, args.database)
    try:
        inbox = Inbox(
            store,
            settings.sources,
            signer=signer,
            relays=relays,
            secrets=os.environ.get,
            max_body=settings.max_body,
            match_window=settings.match_window,
        )
        if args.action == "match":
            print(f"bound {inbox.match_pending()} event(s) to their deliveries", file=out)
            return EXIT_OK
        missing = sorted(
            f"{s.secret_env} (source {s.name})"
            for s in settings.sources
            if s.secret_env and s.secret_env not in os.environ
        )
        if missing:
            raise SubstrateConfigurationError(
                f"a webhook's signing secret comes from the inbox's environment, and these are "
                f"not set: {', '.join(missing)}"
            )
        return _inbox_serve(inbox, args.listen or settings.listen, settings.match_every, out)
    finally:
        close()


def _inbox_serve(inbox: Any, listen: str, every: Any, out: TextIO) -> int:
    from interlock.inbox import serve

    host, _, port = listen.rpartition(":")
    if not host or not port.isdigit():
        print(f"interlock: listen is HOST:PORT, not {listen!r}", file=sys.stderr)
        return EXIT_USAGE
    stop = threading.Event()
    _stop_on_signals(stop)

    def ready(bound: int) -> None:
        print(f"receiving webhooks on {host}:{bound}; stop with SIGTERM or Ctrl-C", file=out)

    from interlock.exceptions import KeyRevokedError

    try:
        serve(inbox, host, int(port), stop=stop, ready=ready, match_every=every)
    except KeyRevokedError as exc:
        print(
            f"interlock: {exc}: start the inbox again with its new key (docs/EPIC8_DESIGN.md §2.6)",
            file=sys.stderr,
        )
        return EXIT_CONFIGURATION
    return EXIT_OK


def _inbox_reader(config: InterlockConfig) -> tuple[Any, Callable[[], None]]:
    """The inbox as the installer or an auditor reads it, and how to close it."""
    if config.substrate != "postgres":
        from interlock.sqlite_outbox import SqliteOutboxStore

        store = SqliteOutboxStore(config.database, writes=frozenset())
        return store, store.close
    import psycopg

    from interlock.inbox_store import PostgresInboxStore

    try:
        conn = psycopg.connect(config.database, autocommit=True)
    except psycopg.Error as exc:
        raise SubstrateUnavailableError(f"cannot connect to PostgreSQL: {exc}") from exc
    return PostgresInboxStore(conn), conn.close


def _inbox_list(source: Any, args: argparse.Namespace, out: TextIO) -> int:
    facts = {(f.source, f.event_seq): f for f in source.inbound_facts()}
    consumed = source.inbound_consumed()
    shown = 0
    for event in source.inbound_events():
        if args.source and event.source != args.source:
            continue
        if shown >= args.limit:
            break
        shown += 1
        fact = facts.get((event.source, event.seq))
        if fact is None:
            bound = "  unmatched"
        else:
            stage = consumed.get(fact.fact_id)
            bound = (
                f"  fact {fact.fact_id} -> message {fact.message_id} (scope {fact.scope_id})"
                + (f", consumed by stage {stage}" if stage else ", pending")
            )
        print(
            f"{event.source} {event.seq:>4} {event.received_at.isoformat()} {event.kind}  "
            f"event {event.event_id}" + (f"#{event.part}" if event.part else "") + bound,
            file=out,
        )
    return EXIT_OK


def _inbox_verify(config: InterlockConfig, source: Any, keys: Any, out: TextIO) -> int:
    from interlock.inbox import verify_inbox

    relays = trusted_keyring(config, "relay")
    report = verify_inbox(source, keys, relays=relays)
    for problem in report.problems:
        print(problem, file=out)
    if report.problems:
        return EXIT_FINDINGS
    print(
        f"every inbound log verifies: {report.events} event(s), each attested by a registered "
        f"inbox; {report.facts} fact(s) bound to the deliveries they name"
        + ("" if relays is None else ", each attested by a registered relay")
        + f"; {report.consumed} consumed",
        file=out,
    )
    if relays is None:
        print("relays' attestations not checked: register their keys in [relays.keys]", file=out)
    return EXIT_OK


def _daemon(config: InterlockConfig, args: argparse.Namespace, out: TextIO) -> int:
    import asyncio

    from interlock.daemon import build_supervisor, load_application

    try:
        config = config.with_node(args.node)
    except ConfigError as exc:
        print(f"interlock: {exc}", file=sys.stderr)
        return EXIT_USAGE
    application = load_application(args.app, config) if args.app else None
    supervisor = build_supervisor(
        config,
        application,
        listen=args.listen,
        relay_key=args.relay_key,
        inbox_key=args.inbox_key,
        metrics_listen=args.metrics,
    )

    def reloaded(outcome: Mapping[str, str | None]) -> None:
        opened = sorted(name for name, error in outcome.items() if error is None)
        print(f"reloaded: {', '.join(opened) or 'nothing'}", file=out)
        for name, error in sorted(outcome.items()):
            if error is not None:
                print(f"reload: {name} could not open again: {error}", file=out)
        out.flush()

    supervisor.on_reload(reloaded)

    async def run() -> None:
        running = asyncio.create_task(supervisor.run(handle_signals=True))
        ready = asyncio.create_task(supervisor.ready())
        await asyncio.wait({running, ready}, return_when=asyncio.FIRST_COMPLETED)
        if ready.done() and not running.done():
            parts = ", ".join(sorted(supervisor.status()))
            node = "" if config.cluster is None else f" as node {config.cluster.node}"
            print(
                f"interlock daemon running{node}: {parts}; reload its keys with SIGHUP; stop "
                f"with SIGTERM or Ctrl-C",
                file=out,
            )
            port = supervisor.inbox_port
            if port is not None:
                print(f"receiving webhooks on port {port}", file=out)
            port = supervisor.metrics_port
            if port is not None:
                print(f"serving metrics on port {port}", file=out)
            out.flush()
        else:
            ready.cancel()
        await running

    asyncio.run(run())
    report = supervisor.status()
    for name, status in sorted(report.items()):
        counters = ", ".join(f"{k} {v}" for k, v in sorted(status.counters.items()) if v)
        print(
            f"{name}: {status.state}, {status.steps} step(s), {status.failures} failure(s)"
            + (f"; {counters}" if counters else ""),
            file=out,
        )
    taken = report.get("cluster")
    if taken is not None and taken.state == "failed":
        # Another process is this node now: this one stopped for it.
        print(f"interlock: {taken.last_error}", file=sys.stderr)
        return EXIT_CONFIGURATION
    return EXIT_OK


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
