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
from pathlib import Path

import pytest

from tests.schemas import BACK_OFFICE_DDL, BACK_OFFICE_ROWS, insert_sql

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
