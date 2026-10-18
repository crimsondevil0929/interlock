"""Every built-in checker, configured with sets of several members, and the
configuration digests ARC1 receipts record for them.

``python -m tests.checker_digests`` prints the digests as one JSON object, so
the test can compare what processes with different ``PYTHONHASHSEED`` values
compute.
"""

from __future__ import annotations

import json
from datetime import timedelta

from interlock.invariants import (
    BUILT_IN_CHECKERS,
    BlastRadius,
    ColumnValueGuard,
    CrossEffectAgreement,
    FactAgreement,
    InvariantChecker,
    NoDelete,
    NoSchemaChange,
    StatedFootprint,
    TableAllowlist,
    TenantDrawdownGuard,
    TenantIsolation,
    TruncationGuard,
)
from interlock.outbound_checks import (
    OutboundCount,
    OutboundTenantIsolation,
    PayloadAmountCap,
    RecipientAllowlist,
    SinkAllowlist,
)
from interlock.receipts import checker_records
from interlock.types import Severity
from interlock.windows import RateWindow, RateWindowCheck, Requests


def checkers() -> tuple[InvariantChecker, ...]:
    """One of each built-in checker; every set it holds has several members."""
    built: tuple[InvariantChecker, ...] = (
        CrossEffectAgreement(
            "stripe", "refunds.create", field="amount", table="refunds", column="amount"
        ),
        FactAgreement(
            ["charge.refunded", "charge.updated", "charge.failed"],
            field="amount",
            table="refunds",
            column="amount",
            exempt=["a", "b", "c", 1, 2],
        ),
        SinkAllowlist(
            {"stripe": ["refunds.create", "charges.create", "payouts.create"], "mail": "*"}
        ),
        OutboundCount(5, per_sink={"stripe": 2, "mail": 3}),
        PayloadAmountCap(
            "stripe",
            "refunds.create",
            field="amount",
            maximum={"usd": "10", "eur": "9"},
            currency_field="currency",
        ),
        RecipientAllowlist(
            "mail",
            "send",
            fields=["to.*.email", "cc.*.email"],
            domains=["acme.com", "beta.org", "gamma.net", "delta.io"],
            addresses=["a@x.com", "b@y.com", "c@z.com"],
            tenant_domains={"t1": ["one.com", "two.com", "three.com"]},
        ),
        OutboundTenantIsolation(fields={"stripe": "metadata.tenant", "mail": "tenant"}),
        RateWindowCheck(RateWindow("w", timedelta(hours=1), 10, Requests("stripe"))),
        BlastRadius(8),
        TenantIsolation(2, declared=True),
        TableAllowlist(["orders", "refunds", "customers", "ledger", "items"]),
        NoDelete(["orders", "refunds", "customers", "ledger"]),
        ColumnValueGuard("orders", "total", max_drop_fraction=0.3),
        TenantDrawdownGuard("orders", "total", max_drop_fraction=0.3),
        TruncationGuard(),
        StatedFootprint(tolerance=2.0, severity=Severity.BLOCKING),
        NoSchemaChange(),
    )
    assert {type(c) for c in built} == set(BUILT_IN_CHECKERS)
    return built


def digests() -> dict[str, str]:
    return {record.name: record.config_hash for record in checker_records(checkers())}


if __name__ == "__main__":
    print(json.dumps(digests(), sort_keys=True))
