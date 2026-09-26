"""A realistic back-office schema, shared by the SQLite and PostgreSQL tests.

Fifteen tables with foreign keys up to four deep, written once in SQL both
engines accept so the same graph can be read from ``PRAGMA foreign_key_list``
and from ``pg_constraint`` and compared.

::

    tenants ─┬─< customers ─┬─< accounts ──< ledger_entries      (CASCADE, ON UPDATE CASCADE)
             │              └─< orders ─┬─< order_items ──< refunds
             │                          ├─< shipments ──< shipment_events   (SET NULL)
             │                          ├─< stock_reservations              (SET DEFAULT)
             │                          └─< invoices ──< payments           (RESTRICT)
    products ──< order_items.sku                                 (ON UPDATE CASCADE, RESTRICT)
    warehouse_stock ──< stock_reservations (warehouse, sku)      (composite, CASCADE)
    categories ──< categories                                    (self, CASCADE)
    employees ──< employees                                      (self, SET NULL)

Every money column is ``NUMERIC(12,2)``.
"""

from __future__ import annotations

from collections.abc import Sequence

from interlock import TableSpec

BACK_OFFICE_DDL: tuple[str, ...] = (
    "CREATE TABLE tenants (id INTEGER PRIMARY KEY, name TEXT NOT NULL)",
    """CREATE TABLE customers (
        id INTEGER PRIMARY KEY,
        tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
        tenant TEXT NOT NULL,
        email TEXT NOT NULL
    )""",
    # References the parent's primary key implicitly: no column list.
    """CREATE TABLE accounts (
        id INTEGER PRIMARY KEY,
        customer_id INTEGER NOT NULL REFERENCES customers ON DELETE CASCADE,
        tenant TEXT NOT NULL,
        balance NUMERIC(12,2) NOT NULL
    )""",
    """CREATE TABLE ledger_entries (
        id INTEGER PRIMARY KEY,
        account_id INTEGER NOT NULL
            REFERENCES accounts(id) ON DELETE CASCADE ON UPDATE CASCADE,
        amount NUMERIC(12,2) NOT NULL
    )""",
    """CREATE TABLE products (
        id INTEGER PRIMARY KEY,
        sku TEXT NOT NULL UNIQUE,
        price NUMERIC(12,2) NOT NULL
    )""",
    """CREATE TABLE orders (
        id INTEGER PRIMARY KEY,
        customer_id INTEGER NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
        tenant TEXT NOT NULL,
        status TEXT NOT NULL,
        total NUMERIC(12,2) NOT NULL
    )""",
    """CREATE TABLE order_items (
        id INTEGER PRIMARY KEY,
        order_id INTEGER NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
        sku TEXT NOT NULL REFERENCES products(sku) ON UPDATE CASCADE ON DELETE RESTRICT,
        qty INTEGER NOT NULL,
        price NUMERIC(12,2) NOT NULL
    )""",
    """CREATE TABLE refunds (
        id INTEGER PRIMARY KEY,
        order_item_id INTEGER NOT NULL REFERENCES order_items(id) ON DELETE CASCADE,
        amount NUMERIC(12,2) NOT NULL
    )""",
    """CREATE TABLE shipments (
        id INTEGER PRIMARY KEY,
        order_id INTEGER REFERENCES orders(id) ON DELETE SET NULL,
        carrier TEXT NOT NULL
    )""",
    """CREATE TABLE shipment_events (
        id INTEGER PRIMARY KEY,
        shipment_id INTEGER NOT NULL REFERENCES shipments(id) ON DELETE CASCADE,
        status TEXT NOT NULL
    )""",
    """CREATE TABLE invoices (
        id INTEGER PRIMARY KEY,
        order_id INTEGER NOT NULL REFERENCES orders(id) ON DELETE RESTRICT,
        amount NUMERIC(12,2) NOT NULL
    )""",
    """CREATE TABLE payments (
        id INTEGER PRIMARY KEY,
        invoice_id INTEGER NOT NULL REFERENCES invoices(id) ON DELETE CASCADE,
        amount NUMERIC(12,2) NOT NULL
    )""",
    """CREATE TABLE warehouse_stock (
        warehouse TEXT NOT NULL,
        sku TEXT NOT NULL,
        on_hand INTEGER NOT NULL,
        PRIMARY KEY (warehouse, sku)
    )""",
    """CREATE TABLE stock_reservations (
        id INTEGER PRIMARY KEY,
        warehouse TEXT NOT NULL,
        sku TEXT NOT NULL,
        order_id INTEGER DEFAULT NULL REFERENCES orders(id) ON DELETE SET DEFAULT,
        FOREIGN KEY (warehouse, sku) REFERENCES warehouse_stock(warehouse, sku)
            ON DELETE CASCADE ON UPDATE CASCADE
    )""",
    """CREATE TABLE categories (
        id INTEGER PRIMARY KEY,
        parent_id INTEGER REFERENCES categories(id) ON DELETE CASCADE,
        name TEXT NOT NULL
    )""",
    """CREATE TABLE employees (
        id INTEGER PRIMARY KEY,
        manager_id INTEGER REFERENCES employees(id) ON DELETE SET NULL,
        name TEXT NOT NULL
    )""",
)

BACK_OFFICE_ROWS: tuple[tuple[str, tuple[tuple[object, ...], ...]], ...] = (
    ("tenants", ((1, "acme"), (2, "globex"))),
    (
        "customers",
        (
            (10, 1, "acme", "ap@acme.test"),
            (11, 1, "acme", "ops@acme.test"),
            (20, 2, "globex", "ar@globex.test"),
        ),
    ),
    (
        "accounts",
        ((100, 10, "acme", "500.00"), (101, 11, "acme", "250.00"), (200, 20, "globex", "900.00")),
    ),
    ("ledger_entries", ((1000, 100, "500.00"), (1001, 101, "250.00"), (2000, 200, "900.00"))),
    ("products", ((1, "SKU-1", "10.00"), (2, "SKU-2", "25.00"))),
    (
        "orders",
        (
            (500, 10, "acme", "open", "45.00"),
            (501, 11, "acme", "open", "25.00"),
            (600, 20, "globex", "shipped", "10.00"),
        ),
    ),
    (
        "order_items",
        (
            (5000, 500, "SKU-1", 2, "10.00"),
            (5001, 500, "SKU-2", 1, "25.00"),
            (5010, 501, "SKU-2", 1, "25.00"),
            (6000, 600, "SKU-1", 1, "10.00"),
        ),
    ),
    ("refunds", ((9000, 5001, "25.00"),)),
    ("shipments", ((700, 500, "ups"), (701, 600, "dhl"))),
    ("shipment_events", ((7000, 700, "label"), (7001, 700, "picked"), (7010, 701, "delivered"))),
    ("invoices", ((800, 600, "10.00"),)),
    ("payments", ((8000, 800, "10.00"),)),
    ("warehouse_stock", (("east", "SKU-1", 50), ("east", "SKU-2", 10))),
    ("stock_reservations", ((40, "east", "SKU-1", 500), (41, "east", "SKU-2", 501))),
    ("categories", ((1, None, "root"), (2, 1, "shoes"), (3, 2, "boots"))),
    ("employees", ((1, None, "ceo"), (2, 1, "vp"), (3, 2, "engineer"))),
)

SPECS: dict[str, TableSpec] = {
    "tenants": TableSpec("tenants", columns=["id", "name"]),
    "customers": TableSpec(
        "customers", columns=["id", "tenant_id", "tenant", "email"], tenant_column="tenant"
    ),
    "accounts": TableSpec(
        "accounts", columns=["id", "customer_id", "tenant", "balance"], tenant_column="tenant"
    ),
    "ledger_entries": TableSpec("ledger_entries", columns=["id", "account_id", "amount"]),
    "products": TableSpec("products", columns=["id", "sku", "price"]),
    "orders": TableSpec(
        "orders",
        columns=["id", "customer_id", "tenant", "status", "total"],
        tenant_column="tenant",
    ),
    "order_items": TableSpec("order_items", columns=["id", "order_id", "sku", "qty", "price"]),
    "refunds": TableSpec("refunds", columns=["id", "order_item_id", "amount"]),
    "shipments": TableSpec("shipments", columns=["id", "order_id", "carrier"]),
    "shipment_events": TableSpec("shipment_events", columns=["id", "shipment_id", "status"]),
    "invoices": TableSpec("invoices", columns=["id", "order_id", "amount"]),
    "payments": TableSpec("payments", columns=["id", "invoice_id", "amount"]),
    "stock_reservations": TableSpec(
        "stock_reservations", columns=["id", "warehouse", "sku", "order_id"]
    ),
    "categories": TableSpec("categories", columns=["id", "parent_id", "name"]),
    "employees": TableSpec("employees", columns=["id", "manager_id", "name"]),
}
"""A ``TableSpec`` per table with a single-column key. ``warehouse_stock`` has
a composite key, which ``TableSpec`` cannot express, so it is never observed."""


def specs(*names: str) -> list[TableSpec]:
    return [SPECS[name] for name in names]


def insert_sql(table: str, width: int, placeholder: str) -> str:
    marks = ", ".join([placeholder] * width)
    return f"INSERT INTO {table} VALUES ({marks})"


def seed_rows() -> Sequence[tuple[str, tuple[tuple[object, ...], ...]]]:
    return BACK_OFFICE_ROWS
