"""The ``interlock`` command.

``interlock install``   put Interlock's triggers into the database (PostgreSQL)
``interlock check``     verify the installation and grants, print the cascade check

Every command reads a TOML configuration file (see :mod:`interlock.config`).
Exit codes, for scripts and CI:

====  =============================================================
0     done; for ``check``, the setup is sound
2     usage, or the configuration file is wrong
3     the database is not set up for a stage (not installed, grants)
4     the database cannot be reached
====  =============================================================
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from typing import TextIO

from interlock.cascade import CascadeReport, analyze_cascades, read_postgres_foreign_keys
from interlock.config import ConfigError, InterlockConfig, load_config
from interlock.exceptions import (
    InterlockError,
    SubstrateConfigurationError,
    SubstrateUnavailableError,
)
from interlock.postgres import PostgresSubstrate, install
from interlock.substrate import SqliteSubstrate

__all__ = ["main", "main_entry"]

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_CONFIGURATION = 3
EXIT_UNAVAILABLE = 4


def main(argv: Sequence[str] | None = None, *, out: TextIO | None = None) -> int:
    stream = out if out is not None else sys.stdout
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        config = load_config(args.config, database=args.database)
    except ConfigError as exc:
        print(f"interlock: {exc}", file=sys.stderr)
        return EXIT_USAGE
    try:
        if args.command == "install":
            return _install(config, stream)
        return _check(config, stream)
    except SubstrateConfigurationError as exc:
        print(f"interlock: {exc}", file=sys.stderr)
        return EXIT_CONFIGURATION
    except (SubstrateUnavailableError, InterlockError) as exc:
        print(f"interlock: {exc}", file=sys.stderr)
        return EXIT_UNAVAILABLE


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="interlock", description="Stage, measure, adjudicate, commit."
    )
    commands = parser.add_subparsers(dest="command", required=True)
    for name, text in (
        ("install", "install Interlock's schema and triggers (run as the tables' owner)"),
        ("check", "verify the setup and print what the cascade check refuses"),
    ):
        command = commands.add_parser(name, help=text, description=text)
        command.add_argument("--config", required=True, help="the TOML configuration file")
        command.add_argument(
            "--database",
            help="overrides the file's database (DSN or SQLite path), as does INTERLOCK_DATABASE",
        )
    return parser


def _install(config: InterlockConfig, out: TextIO) -> int:
    if config.substrate != "postgres":
        print(
            "interlock install: SQLite needs nothing installed; its capture triggers "
            "are temporary and created per stage",
            file=out,
        )
        return EXIT_OK
    import psycopg

    try:
        with psycopg.connect(config.database, autocommit=True) as conn:
            install(conn, config.tables, schema=config.schema, stage_roles=config.stage_roles)
            report = analyze_cascades(
                read_postgres_foreign_keys(conn, config.schema),
                [t.name for t in config.tables],
                config.acknowledge_cascades,
            )
    except psycopg.Error as exc:
        raise SubstrateUnavailableError(f"install failed: {exc}") from exc
    except ValueError as exc:
        raise SubstrateConfigurationError(str(exc)) from exc
    names = ", ".join(t.name for t in config.tables)
    print(f"installed: {len(config.tables)} table(s) in {config.schema}: {names}", file=out)
    for role in config.stage_roles:
        print(f"granted to stage role: {role}", file=out)
    _print_report(report, out)
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
        report = SqliteSubstrate(
            config.database,
            tables=config.tables,
            acknowledge_cascades=config.acknowledge_cascades,
        ).check_cascades()
    print(f"ok: {config.substrate}, {len(config.tables)} observed table(s)", file=out)
    _print_report(report, out)
    return EXIT_OK


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
