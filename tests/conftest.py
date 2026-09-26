"""Shared fixtures: the back-office schema on SQLite and on a real PostgreSQL.

PostgreSQL tests run against a live server named by
``INTERLOCK_TEST_POSTGRES_DSN`` (a role that may create databases and roles).
Each test gets a database of its own, created from ``template0`` and dropped
afterwards. Without the variable those tests are skipped, unless
``INTERLOCK_REQUIRE_POSTGRES=1``, which turns the skip into a failure: CI sets
it, so a misconfigured service cannot pass the suite by skipping it.
"""

from __future__ import annotations

import os
import sqlite3
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from tests.schemas import BACK_OFFICE_DDL, BACK_OFFICE_ROWS, insert_sql, specs

POSTGRES_DSN_VAR = "INTERLOCK_TEST_POSTGRES_DSN"
REQUIRE_POSTGRES_VAR = "INTERLOCK_REQUIRE_POSTGRES"


def build_sqlite_back_office(path: Path) -> str:
    conn = sqlite3.connect(path)
    try:
        conn.execute("PRAGMA foreign_keys=ON")
        for ddl in BACK_OFFICE_DDL:
            conn.execute(ddl)
        for table, rows in BACK_OFFICE_ROWS:
            conn.executemany(insert_sql(table, len(rows[0]), "?"), rows)
        conn.commit()
    finally:
        conn.close()
    return str(path)


@pytest.fixture
def back_office(tmp_path: Path) -> str:
    """The back-office schema in a SQLite file, seeded."""
    return build_sqlite_back_office(tmp_path / "back_office.db")


@pytest.fixture(scope="session")
def pg_admin_dsn() -> str:
    dsn = os.environ.get(POSTGRES_DSN_VAR, "")
    if not dsn:
        if os.environ.get(REQUIRE_POSTGRES_VAR) == "1":
            pytest.fail(f"{REQUIRE_POSTGRES_VAR}=1 but {POSTGRES_DSN_VAR} is not set")
        pytest.skip(f"set {POSTGRES_DSN_VAR} to run the PostgreSQL integration tests")
    return dsn


@pytest.fixture
def pg_database(pg_admin_dsn: str) -> Iterator[str]:
    """A fresh, empty PostgreSQL database; yields its DSN."""
    import psycopg
    from psycopg import sql
    from psycopg.conninfo import make_conninfo

    name = f"interlock_t_{uuid.uuid4().hex[:12]}"
    with psycopg.connect(pg_admin_dsn, autocommit=True) as admin:
        admin.execute(sql.SQL("CREATE DATABASE {} TEMPLATE template0").format(sql.Identifier(name)))
    try:
        yield make_conninfo(pg_admin_dsn, dbname=name)
    finally:
        with psycopg.connect(pg_admin_dsn, autocommit=True) as admin:
            admin.execute(
                sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(name))
            )


def build_postgres_back_office(dsn: str) -> None:
    import psycopg

    with psycopg.connect(dsn) as conn:
        for ddl in BACK_OFFICE_DDL:
            conn.execute(ddl)
        for table, rows in BACK_OFFICE_ROWS:
            with conn.cursor() as cur:
                cur.executemany(insert_sql(table, len(rows[0]), "%s"), rows)


@pytest.fixture
def pg_back_office(pg_database: str) -> str:
    """The back-office schema in a fresh PostgreSQL database, seeded."""
    build_postgres_back_office(pg_database)
    return pg_database


PASSWORD = "agent"  # noqa: S105 - a throwaway role in a throwaway database

OBSERVED = ("orders", "order_items", "refunds", "shipments", "stock_reservations", "accounts")


@dataclass(frozen=True)
class Pg:
    admin: str
    """The tables' owner, which installed Interlock. A superuser here."""
    agent: str
    """The stage role: DML on the observed tables, SELECT on the rest."""
    role: str
    cluster: str


def create_role(cluster: str, name: str, *, extra: str = "") -> None:
    import psycopg
    from psycopg import sql

    with psycopg.connect(cluster, autocommit=True) as conn:
        conn.execute(
            sql.SQL("CREATE ROLE {} LOGIN PASSWORD {} " + extra).format(
                sql.Identifier(name), sql.Literal(PASSWORD)
            )
        )


def drop_role(cluster: str, database: str, name: str) -> None:
    import psycopg
    from psycopg import sql

    with psycopg.connect(database, autocommit=True) as conn:
        conn.execute(sql.SQL("DROP OWNED BY {} CASCADE").format(sql.Identifier(name)))
    with psycopg.connect(cluster, autocommit=True) as conn:
        conn.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(name)))


@pytest.fixture
def pg(pg_admin_dsn: str, pg_back_office: str) -> Iterator[Pg]:
    """The back office with Interlock installed as its owner, and a stage role
    granted DML on the observed tables and SELECT on the rest."""
    import psycopg
    from psycopg.conninfo import make_conninfo

    from interlock.postgres import install

    role = f"il_agent_{uuid.uuid4().hex[:10]}"
    create_role(pg_admin_dsn, role)
    try:
        with psycopg.connect(pg_back_office, autocommit=True) as conn:
            install(conn, specs(*OBSERVED), stage_roles=[role])
            conn.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {', '.join(OBSERVED)} TO {role}")
            conn.execute(f"GRANT SELECT ON ALL TABLES IN SCHEMA public TO {role}")
        yield Pg(
            admin=pg_back_office,
            agent=make_conninfo(pg_back_office, user=role, password=PASSWORD),
            role=role,
            cluster=pg_admin_dsn,
        )
    finally:
        drop_role(pg_admin_dsn, pg_back_office, role)
