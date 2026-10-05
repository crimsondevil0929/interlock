"""The outbound checkers of ``docs/OUTBOX_DESIGN.md`` §5.2 (``docs/EPIC5_DESIGN.md`` §3).

- Numbers in payloads are strict: an integer or a plain decimal numeral. What
  Python's ``Decimal`` would also read (``"1_000"``, ``" 5"``, ``"1e3"``,
  ``"+5"``, Arabic-Indic digits) is not a number to any rule, the schema subset's
  ``minimum`` and ``maximum`` included.
- ``SinkAllowlist``, ``OutboundCount``, ``PayloadAmountCap``,
  ``RecipientAllowlist`` and ``OutboundTenantIsolation``, rule by rule, each
  failing closed on what it cannot read.
- The agent is told the rule and its own sinks and tenants, never a payload
  value, another tenant, or a number but a bucketed count: by example, and as a
  property over generated plans.
- End to end on both stores: a refused plan enqueues nothing.
"""

from __future__ import annotations

import os
import re
import uuid
from collections.abc import Iterator, Mapping, Sequence
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from interlock import (
    OutboundCount,
    OutboundTenantIsolation,
    PayloadAmountCap,
    PlanBuilder,
    RecipientAllowlist,
    SinkAllowlist,
)
from interlock.adjudication import adjudicate
from interlock.feedback import BUCKETS, AgentFeedback, Guidance
from interlock.outbound import schema_problems
from interlock.outbound_checks import email_domain, url_host
from interlock.types import (
    EffectDiff,
    EffectId,
    EffectKind,
    EffectPlan,
    InvariantViolation,
    OutboundDelta,
    RowDelta,
    _frozen,
    exact_number,
    field_path,
    values_at,
)
from tests.outbox_env import BACKENDS, SCOPE, Outbox, build_either

# --------------------------------------------------------------------------
# helpers: a plan, and the diff its stage would measure
# --------------------------------------------------------------------------


def plan_of(*requests: tuple[str, str, Mapping[str, Any], str | None]) -> EffectPlan:
    """A plan enqueueing each ``(sink, operation, payload, tenant)``."""
    builder = PlanBuilder(SCOPE)
    for index, (sink, operation, payload, tenant) in enumerate(requests):
        builder.enqueue(
            sink=sink,
            operation=operation,
            payload=payload,
            tenant_id=tenant,
            effect_id=EffectId(f"r{index}"),
            independent=True,
        )
    return builder.build()


def diff_of(plan: EffectPlan, *rows: RowDelta) -> EffectDiff:
    """What the stage would read back: every request as the plan declared it."""
    outbound = tuple(
        OutboundDelta(
            message_id=uuid.uuid4(),
            effect_id=e.effect_id,
            sink=e.request.sink,
            operation=e.request.operation,
            tenant_id=e.tenant_id,
            payload=_frozen(dict(e.request.payload)),
            payload_hash=e.request.payload_hash,
            idempotency_key=f"key-{e.effect_id}",
        )
        for e in plan.effects
        if e.kind is EffectKind.ENQUEUE and e.request is not None
    )
    return EffectDiff(
        plan_id=plan.plan_id,
        stage_id=uuid.uuid4(),
        substrate_id="sqlite:test",
        computed_at=datetime.now(UTC),
        deltas=rows,
        outbound=outbound,
    )


def row(tenant: str, key: int = 1, table: str = "refunds") -> RowDelta:
    return RowDelta(table, str(key), None, {"id": key, "tenant": tenant}, tenant_id=tenant)


def refund(amount: object, tenant: str | None = "acme", **extra: object) -> Any:
    return ("payments", "refund", {"amount": amount, **extra}, tenant)


def mail(to: object, tenant: str | None = "acme") -> Any:
    return ("mail", "send", {"to": to, "subject": "hello"}, tenant)


def check(checker: Any, plan: EffectPlan, *rows: RowDelta) -> tuple[InvariantViolation, ...]:
    return tuple(checker.check(plan, diff_of(plan, *rows)))


def feedback(checker: Any, plan: EffectPlan, *rows: RowDelta) -> AgentFeedback:
    judged = adjudicate(plan, diff_of(plan, *rows), [checker], stage_id=uuid.UUID(int=0))
    return judged.feedback(committed=judged.admitted)


# --------------------------------------------------------------------------
# strict numbers
# --------------------------------------------------------------------------

LENIENT = (
    "1_000",
    " 5",
    "5 ",
    "1e3",
    "1E+3",
    "+5",
    "\u0661\u0662\u0663",  # Arabic-Indic 123
    "\u0665",
    "NaN",
    "Infinity",
    "0x10",
    "",
)


@pytest.mark.parametrize("text", LENIENT)
def test_what_decimal_would_read_is_no_payload_number(text: str) -> None:
    assert exact_number(text) is None
    assert schema_problems(text, {"type": "string", "maximum": "100"}) == [
        "$ is not a number or a decimal string"
    ]


@pytest.mark.parametrize(
    ("value", "number"),
    [("50.00", Decimal("50.00")), ("-3", Decimal(-3)), ("0", Decimal(0)), (7, Decimal(7))],
)
def test_plain_numerals_and_integers_are_numbers(value: object, number: Decimal) -> None:
    assert exact_number(value) == number
    assert schema_problems(value, {"maximum": "100", "minimum": "-10"}) == []


@pytest.mark.parametrize("value", [True, False, None, 1.5, "007", "1.", ".5", {"a": 1}])
def test_anything_else_is_no_number(value: object) -> None:
    assert exact_number(value) is None


@pytest.mark.parametrize(
    ("value", "schema"),
    [
        (True, {"const": 1}),
        (1, {"const": True}),
        (False, {"enum": [0, 1]}),
        (0, {"enum": [False, True]}),
        (["a"], {"const": ["a", "b"]}),
        ({"a": 1}, {"const": {"a": True}}),
    ],
)
def test_a_constant_is_equal_only_as_json_is(value: object, schema: dict[str, Any]) -> None:
    """``True == 1`` in Python; a boolean is never an integer in a payload."""
    assert schema_problems(_frozen(value), schema) != []


def test_a_constant_and_an_enum_still_match_themselves() -> None:
    assert schema_problems(1, {"const": 1, "enum": [0, 1]}) == []
    assert schema_problems(_frozen(["a", {"b": True}]), {"const": ["a", {"b": True}]}) == []


@pytest.mark.parametrize(
    "key", ["\uff21\uff30\uff29_\uff2b\uff25\uff39", "Api-Key", "\u2170api_key"]
)
def test_a_credential_field_spelled_in_other_letters_is_refused(key: str) -> None:
    from interlock.exceptions import OutboundRequestError
    from interlock.outbound import OperationSpec, SinkRegistry, SinkSpec
    from interlock.types import OutboundRequest

    registry = SinkRegistry([SinkSpec("hooks", (OperationSpec("post"),))])
    with pytest.raises(OutboundRequestError, match="named like a credential"):
        registry.check(OutboundRequest("hooks", "post", {key: "secret"}))


def test_values_at_follows_stars_over_lists_and_objects() -> None:
    payload = _frozen(
        {
            "to": [{"email": "a@x.test"}, {"email": "b@x.test"}, {"name": "c"}],
            "cc": {"one": {"email": "c@x.test"}},
            "reply_to": {"email": "d@x.test"},
        }
    )
    assert values_at(payload, field_path("to.*.email")) == [
        ("$.to[0].email", "a@x.test"),
        ("$.to[1].email", "b@x.test"),
    ]
    assert values_at(payload, field_path("cc.*.email")) == [("$.cc.one.email", "c@x.test")]
    assert values_at(payload, field_path("reply_to.email")) == [("$.reply_to.email", "d@x.test")]
    assert values_at(payload, field_path("to.1.email")) == [("$.to[1].email", "b@x.test")]
    assert values_at(payload, field_path("bcc.*.email")) == []
    assert values_at(payload, field_path("to.9.email")) == []


# --------------------------------------------------------------------------
# SinkAllowlist
# --------------------------------------------------------------------------

REFUNDS_ONLY = SinkAllowlist({"payments": ["refund"], "mail": "*"})


def test_a_sink_allowlist_admits_what_it_lists() -> None:
    assert check(REFUNDS_ONLY, plan_of(refund("5.00"), mail("a@acme.test"))) == ()


def test_a_sink_or_operation_off_the_list_is_refused() -> None:
    (other_sink,) = check(REFUNDS_ONLY, plan_of(("pager", "page", {"note": "x"}, None)))
    assert other_sink.evidence["sink"] == "pager"
    narrow = SinkAllowlist({"payments": "refund.reverse"})
    (other_operation,) = check(narrow, plan_of(refund("5.00")))
    assert other_operation.evidence["operation"] == "refund"
    assert feedback(narrow, plan_of(refund("5.00"))).blocking[0].guidance is (
        Guidance.OUTBOUND_SCOPE
    )


def test_a_sink_allowlist_must_allow_something() -> None:
    with pytest.raises(ValueError, match="at least one sink"):
        SinkAllowlist({})
    with pytest.raises(ValueError, match="no operation"):
        SinkAllowlist({"payments": []})


# --------------------------------------------------------------------------
# OutboundCount
# --------------------------------------------------------------------------


def test_outbound_count_bounds_a_plan_and_each_sink() -> None:
    three = plan_of(refund("1"), refund("2"), mail("a@acme.test"))
    assert check(OutboundCount(3), three) == ()
    (over,) = check(OutboundCount(2), three)
    assert over.evidence == {"measured": "3", "limit": "2"}
    (sink,) = check(OutboundCount(per_sink={"payments": 1, "mail": 1}), three)
    assert sink.evidence["sink"] == "payments"
    (none,) = check(OutboundCount(0), plan_of(mail("a@acme.test")))
    assert none.evidence == {"measured": "1", "limit": "0"}


def test_outbound_count_tells_bucketed_counts_and_the_plans_own_sink() -> None:
    eleven = plan_of(*(refund(str(n)) for n in range(11)))
    (told,) = feedback(OutboundCount(per_sink={"payments": 9}), eleven).blocking
    assert (told.measured, told.limit, told.sinks) == ("10-99", "2-9", ("payments",))
    assert "the plan enqueues 10-99 outbound request(s) to payments; the limit is 2-9" in (
        told.render()
    )


def test_outbound_count_refuses_no_limit_and_a_negative_one() -> None:
    with pytest.raises(ValueError, match="needs max_per_plan"):
        OutboundCount()
    with pytest.raises(ValueError, match="non-negative"):
        OutboundCount(-1)
    with pytest.raises(ValueError, match="non-negative"):
        OutboundCount(per_sink={"mail": True})


# --------------------------------------------------------------------------
# PayloadAmountCap
# --------------------------------------------------------------------------

CAP = PayloadAmountCap("payments", "refund", field="amount", maximum="500.00")


@pytest.mark.parametrize("amount", ["500.00", "500", 500, "0", "499.99"])
def test_an_amount_at_or_under_its_cap_passes(amount: object) -> None:
    assert check(CAP, plan_of(refund(amount))) == ()


@pytest.mark.parametrize("amount", ["500.01", 501, "5000.00"])
def test_an_amount_over_its_cap_is_refused(amount: object) -> None:
    (over,) = check(CAP, plan_of(refund(amount)))
    assert "over the cap" in over.message


@pytest.mark.parametrize("amount", [*LENIENT, "-1", -5, None, True, {"value": "5"}, ["5"]])
def test_an_amount_that_is_no_plain_non_negative_number_is_refused(amount: object) -> None:
    (refused,) = check(CAP, plan_of(refund(amount)))
    assert "no plain non-negative number" in refused.message


def test_a_missing_amount_is_refused() -> None:
    (refused,) = check(CAP, plan_of(("payments", "refund", {"order": 7}, "acme")))
    assert refused.evidence["effect"] == "r0"


def test_a_cap_per_tenant_sums_each_tenants_requests() -> None:
    per_tenant = PayloadAmountCap("payments", "refund", field="amount", maximum="500", per="tenant")
    split = plan_of(refund("300", "acme"), refund("300", "globex"))
    assert check(per_tenant, split) == ()
    (acme,) = check(per_tenant, plan_of(refund("300", "acme"), refund("300", "acme")))
    assert acme.evidence["tenant"] == "acme"


def test_a_cap_per_plan_sums_every_request_and_nets_nothing() -> None:
    whole = PayloadAmountCap("payments", "refund", field="amount", maximum="500", per="plan")
    (over,) = check(whole, plan_of(refund("300", "acme"), refund("300", "globex")))
    assert over.evidence["total"] == "600"
    # A negative entry cannot bring the sum back under the cap.
    refused = check(whole, plan_of(refund("900"), refund("-500")))
    assert {v.message.split(" carries")[0] for v in refused} >= {"request r1"}
    assert any("over the cap" in v.message for v in refused)


def test_a_cap_by_currency_reads_the_currency_case_folded() -> None:
    by_currency = PayloadAmountCap(
        "payments",
        "refund",
        field="amount",
        maximum={"usd": 50_000, "JPY": "5000000"},
        currency_field="currency",
    )
    assert check(by_currency, plan_of(refund(50_000, currency="USD"))) == ()
    assert check(by_currency, plan_of(refund(4_000_000, currency="jpy"))) == ()
    (over,) = check(by_currency, plan_of(refund(50_001, currency="usd")))
    assert "over the cap" in over.message
    for currency in ("eur", None, 840):
        (refused,) = check(by_currency, plan_of(refund(5, currency=currency)))
        assert "names no currency this cap covers" in refused.message


def test_a_cap_is_configured_exactly() -> None:
    for maximum in ("1e3", "-1", 1.5, "abc"):
        with pytest.raises(ValueError, match="a cap is"):
            PayloadAmountCap("p", "o", field="amount", maximum=maximum)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="per is one of"):
        PayloadAmountCap("p", "o", field="amount", maximum=1, per="day")
    with pytest.raises(ValueError, match="needs currency_field"):
        PayloadAmountCap("p", "o", field="amount", maximum={"usd": 1})
    with pytest.raises(ValueError, match="needs a field"):
        PayloadAmountCap("p", "o", field=" ", maximum=1)


def test_the_agent_is_told_the_rule_never_the_amount_or_the_cap() -> None:
    told = feedback(CAP, plan_of(refund("777.13"))).render()
    assert "payload_amount_cap: a request to payments carries an amount over its cap" in told
    assert "777" not in told and "500" not in told


# --------------------------------------------------------------------------
# RecipientAllowlist
# --------------------------------------------------------------------------

ACME = RecipientAllowlist("mail", "send", fields="to", domains=["acme.test"])


@pytest.mark.parametrize("to", ["a@acme.test", "A.B+tag@ACME.TEST", "x@acme.test."])
def test_a_recipient_in_an_allowed_domain_passes(to: str) -> None:
    assert check(ACME, plan_of(mail(to))) == ()


@pytest.mark.parametrize(
    "to",
    [
        "a@evil.test",
        "a@acme.test.evil.test",
        "a@mail.acme.test",  # subdomains are off by default
        "Alice <a@acme.test>",
        "a@acme.test, b@evil.test",
        "a@acme.test b@evil.test",
        '"a@acme.test"@evil.test',
        "a%evil.test@acme.test",
        "evil.test!a@acme.test",
        "a@acme.test@evil.test",
        " a@acme.test",
        "a@acme.test\n",
        "a@\u0430cme.test",  # a Cyrillic a
        "a@bücher.test",
        "a@acme..test",
        "a@-acme.test",
        "a@127.0.0.1",
        "a@[127.0.0.1]",
        "a@",
        "@acme.test",
        "a.@acme.test",
        "",
        7,
        None,
        ["a@acme.test"],
    ],
)
def test_anything_but_one_plain_allowed_address_is_refused(to: object) -> None:
    (refused,) = check(ACME, plan_of(mail(to)))
    assert refused.evidence["where"] == "$.to"
    assert str(to) not in refused.message or to in ("", 7, None)


def test_subdomains_exact_addresses_and_tenant_domains() -> None:
    wide = RecipientAllowlist(
        "mail",
        "send",
        fields="to",
        domains=["acme.test"],
        addresses=["Partner@Partner.test"],
        tenant_domains={"globex": ["globex.test"]},
        subdomains=True,
    )
    assert check(wide, plan_of(mail("a@mail.acme.test"))) == ()
    assert check(wide, plan_of(mail("partner@partner.test"))) == ()
    assert check(wide, plan_of(mail("other@partner.test"))) != ()
    assert check(wide, plan_of(mail("a@globex.test", tenant="globex"))) == ()
    assert check(wide, plan_of(mail("a@globex.test", tenant="acme"))) != ()
    assert check(wide, plan_of(mail("a@globex.test", tenant=None))) != ()
    # A suffix is a subdomain only at a dot.
    assert check(wide, plan_of(mail("a@evilacme.test"))) != ()
    # Without subdomains, only the domain itself.
    narrow = RecipientAllowlist("mail", "send", fields="to", domains=["acme.test"])
    assert check(narrow, plan_of(mail("a@acme.test"))) == ()
    assert check(narrow, plan_of(mail("a@mail.acme.test"))) != ()


def test_an_internationalized_domain_is_allowed_in_its_ascii_form() -> None:
    books = RecipientAllowlist("mail", "send", fields="to", domains=["bücher.test"])
    assert check(books, plan_of(mail("a@xn--bcher-kva.test"))) == ()
    assert check(books, plan_of(mail("a@bücher.test"))) != ()


def test_every_recipient_a_wildcard_path_finds_is_held() -> None:
    sendgrid = RecipientAllowlist(
        "mail", "send", fields=["to.*.email", "cc.*.email", "bcc.*.email"], domains=["acme.test"]
    )
    good = {"to": [{"email": "a@acme.test"}, {"email": "b@acme.test"}], "subject": "x"}
    assert check(sendgrid, plan_of(("mail", "send", good, "acme"))) == ()
    bad = {**good, "bcc": [{"email": "spy@evil.test"}]}
    (refused,) = check(sendgrid, plan_of(("mail", "send", bad, "acme")))
    assert refused.evidence["where"] == "$.bcc[0].email"


@pytest.mark.parametrize(
    ("url", "host"),
    [
        ("https://hooks.acme.test/x", "hooks.acme.test"),
        ("https://HOOKS.ACME.TEST.:8443/x?y=1", "hooks.acme.test"),
        ("http://hooks.acme.test/x", None),
        ("https://user@hooks.acme.test/x", None),
        ("https://hooks.acme.test@evil.test/x", None),
        ("https://evil.test#@hooks.acme.test", "evil.test"),
        ("https://evil.test\\@hooks.acme.test", None),
        ("https://127.0.0.1/x", None),
        ("https://[::1]/x", None),
        ("https://hooks.acme.test:99999/x", None),
        ("https://hööks.acme.test/x", None),
        ("https://hooks.acme.test/x y", None),
        ("javascript:alert(1)", None),
        (17, None),
    ],
)
def test_a_webhook_url_is_parsed_strictly(url: object, host: str | None) -> None:
    assert url_host(url) == host


def test_a_webhook_recipient_is_held_to_its_hosts_domain() -> None:
    hooks = RecipientAllowlist(
        "pager", "page", fields="url", domains=["acme.test"], subdomains=True, kind="url"
    )
    good = ("pager", "page", {"url": "https://hooks.acme.test/in"}, None)
    assert check(hooks, plan_of(good)) == ()
    bad = ("pager", "page", {"url": "https://hooks.acme.test@evil.test/in"}, None)
    assert check(hooks, plan_of(bad)) != ()
    with pytest.raises(ValueError, match="by its domain"):
        RecipientAllowlist("p", "o", fields="u", addresses=["a@b.test"], kind="url")


def test_email_domain_reads_one_plain_address() -> None:
    assert email_domain("Bob.Smith+x@Example.TEST.") == ("Bob.Smith+x", "example.test")
    assert email_domain("a" * 65 + "@x.test") is None
    assert email_domain("a@" + "x" * 64 + ".test") is None


def test_a_recipient_allowlist_is_configured_exactly() -> None:
    with pytest.raises(ValueError, match="allows nothing"):
        RecipientAllowlist("mail", "send", fields="to")
    with pytest.raises(ValueError, match="needs the fields"):
        RecipientAllowlist("mail", "send", fields=[], domains=["acme.test"])
    with pytest.raises(ValueError, match="not a domain name"):
        RecipientAllowlist("mail", "send", fields="to", domains=["acme .test"])
    with pytest.raises(ValueError, match="kind is"):
        RecipientAllowlist("mail", "send", fields="to", domains=["acme.test"], kind="sms")


def test_the_agent_is_never_told_the_recipient() -> None:
    told = feedback(ACME, plan_of(mail("ceo@evil-corp.test"))).render()
    assert "recipient_allowlist: a request to mail addresses a recipient outside" in told
    assert "evil" not in told and "ceo" not in told


# --------------------------------------------------------------------------
# OutboundTenantIsolation
# --------------------------------------------------------------------------


def test_a_request_goes_only_to_a_tenant_the_rows_involve() -> None:
    isolation = OutboundTenantIsolation()
    assert check(isolation, plan_of(refund("5", "acme")), row("acme")) == ()
    refused = check(isolation, plan_of(refund("5", "globex")), row("acme"))
    assert any(v.evidence.get("tenant") == "globex" for v in refused)
    # With no tenant rows, a request is held only to the count.
    assert check(isolation, plan_of(refund("5", "globex"))) == ()


def test_the_payloads_tenant_field_must_be_the_requests_tenant() -> None:
    isolation = OutboundTenantIsolation(fields={"payments.refund": "account.tenant", "mail": "tid"})
    good = refund("5", "acme", account={"tenant": "acme"})
    assert check(isolation, plan_of(good)) == ()
    for account in ({"tenant": "globex"}, {}, {"tenant": None}, {"tenant": True}):
        assert check(isolation, plan_of(refund("5", "acme", account=account))) != ()
    numeric = ("mail", "send", {"to": "a@acme.test", "tid": 42}, "42")
    assert check(isolation, plan_of(numeric)) == ()


def test_a_plan_spans_no_more_tenants_than_allowed() -> None:
    one = OutboundTenantIsolation()
    spanning = plan_of(refund("5", "acme"), refund("5", "globex"))
    (refused,) = check(one, spanning)
    assert refused.evidence["tenants"] == "acme,globex"
    assert check(OutboundTenantIsolation(max_tenants=2), spanning) == ()


def test_a_request_with_no_tenant_is_refused_only_when_one_is_required() -> None:
    untenanted = plan_of(refund("5", None))
    assert check(OutboundTenantIsolation(), untenanted) == ()
    (refused,) = check(OutboundTenantIsolation(require_tenant=True), untenanted)
    assert "names no tenant" in refused.message
    with pytest.raises(ValueError, match="at least 1"):
        OutboundTenantIsolation(max_tenants=0)
    with pytest.raises(ValueError, match="names its sink"):
        OutboundTenantIsolation(fields={"mail": " "})


def test_tenant_isolation_names_only_the_plans_declared_tenants() -> None:
    plan = plan_of(refund("5", "acme"))
    told = feedback(OutboundTenantIsolation(), plan, row("acme"), row("globex", 2))
    (constraint,) = told.blocking
    assert constraint.tenants == ("acme",) and constraint.withheld_tenants
    assert "globex" not in told.render()


# --------------------------------------------------------------------------
# the agent is told nothing a payload carries: a property
# --------------------------------------------------------------------------

SECRET = st.from_regex(r"\Az[qxj]{6}[0-9]{4}\Z")
"""A value only a payload carries: never in a rule, a sink or a tenant name."""
DECLARED = ("acme", "initech")
OTHERS = ("globex", "umbrella", "hooli")


@st.composite
def cases(draw: st.DrawFn) -> tuple[EffectPlan, tuple[RowDelta, ...], list[Any], list[str]]:
    secrets: list[str] = []
    requests = []
    for _ in range(draw(st.integers(1, 4))):
        secret = draw(SECRET)
        secrets.append(secret)
        sink = draw(st.sampled_from(("payments", "mail", "crm")))
        amount = draw(
            st.sampled_from(
                (f"7{draw(st.integers(1000, 9999))}.{draw(st.integers(10, 99))}", secret, "-3")
            )
        )
        if amount not in ("-3",) and amount != secret:
            secrets.append(amount)
        payload = {
            "amount": amount,
            "currency": draw(st.sampled_from(("usd", "eur", secret))),
            "to": draw(st.sampled_from((f"{secret}@acme.test", f"a@{secret}.test", secret))),
            "tenant": draw(st.sampled_from((*DECLARED, secret))),
        }
        operation = draw(st.sampled_from(("refund", "send")))
        requests.append((sink, operation, payload, draw(st.sampled_from((None, *DECLARED)))))
    rows = tuple(
        row(draw(st.sampled_from(DECLARED + OTHERS)), key) for key in range(draw(st.integers(0, 3)))
    )
    checkers: list[Any] = [
        SinkAllowlist({"payments": ["refund"], "mail": "*"}),
        OutboundCount(draw(st.integers(0, 3)), per_sink={"mail": draw(st.integers(0, 2))}),
        PayloadAmountCap(
            draw(st.sampled_from(("payments", "mail"))),
            draw(st.sampled_from(("refund", "send"))),
            field="amount",
            maximum={"usd": 70_000, "eur": "100"},
            currency_field="currency",
            per=draw(st.sampled_from(("request", "tenant", "plan"))),
        ),
        RecipientAllowlist(
            draw(st.sampled_from(("payments", "mail"))),
            draw(st.sampled_from(("refund", "send"))),
            fields="to",
            domains=["acme.test"],
        ),
        OutboundTenantIsolation(fields={"payments": "tenant"}, max_tenants=draw(st.integers(1, 2))),
    ]
    return plan_of(*requests), rows, checkers, secrets


PROPERTY = settings(
    max_examples=int(os.environ.get("INTERLOCK_PROPERTY_EXAMPLES", "300")),
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
_ALLOWED_NUMBERS = {"0", "1", "2", "9", "10", "99", "100", "999", "1000"}


@PROPERTY
@given(cases())
def test_feedback_never_carries_a_payload_value(
    case: tuple[EffectPlan, tuple[RowDelta, ...], list[Any], list[str]],
) -> None:
    plan, rows, checkers, secrets = case
    judged = adjudicate(plan, diff_of(plan, *rows), checkers, stage_id=uuid.UUID(int=0))
    told = judged.feedback(committed=judged.admitted)
    rendered = repr(told.to_json())
    for secret in secrets:
        assert secret not in rendered
    for other in OTHERS:
        assert other not in rendered
    for constraint in told.constraints:
        assert set(constraint.tenants) <= set(DECLARED)
        assert constraint.measured in (None, *BUCKETS)
        assert constraint.limit in (None, *BUCKETS)
        assert set(constraint.sinks) <= {e.request.sink for e in plan.effects if e.request}
    assert set(re.findall(r"\d+(?:\.\d+)?", told.render())) <= _ALLOWED_NUMBERS


# --------------------------------------------------------------------------
# end to end, on both stores: refused, nothing enqueued
# --------------------------------------------------------------------------


@pytest.fixture(params=BACKENDS)
def outbox(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Outbox]:
    yield from build_either(request, tmp_path)


def run(outbox: Outbox, checkers: Sequence[Any], *requests: Any) -> tuple[bool, str]:
    plan = plan_of(*requests)
    result = outbox.engine(checkers=list(checkers)).execute(plan)
    assert result.feedback is not None
    return result.committed, result.feedback.render()


def test_each_rule_refuses_end_to_end_and_nothing_is_enqueued(outbox: Outbox) -> None:
    rules = [
        PayloadAmountCap("payments", "refund", field="amount", maximum="500.00"),
        RecipientAllowlist("mail", "send", fields="to", domains=["acme.test"]),
        SinkAllowlist({"payments": ["refund"], "mail": "*"}),
        OutboundCount(2),
        OutboundTenantIsolation(),
    ]
    committed, told = run(outbox, rules, refund("5000.00"))
    assert not committed and "payload_amount_cap" in told and "5000" not in told
    committed, told = run(outbox, rules, mail("cfo@evil.test"))
    assert not committed and "recipient_allowlist" in told and "evil" not in told
    committed, told = run(outbox, rules, ("pager", "page", {"service": "x"}, None))
    assert not committed and "sink_allowlist" in told
    committed, told = run(outbox, rules, refund("1"), refund("2"), refund("3"))
    assert not committed and "outbound_count" in told
    committed, told = run(outbox, rules, refund("1", "acme"), refund("2", "globex"))
    assert not committed and "outbound_tenant_isolation" in told
    assert outbox.requests() == 0
    committed, _ = run(outbox, rules, refund("500.00"), mail("a@acme.test"))
    assert committed and outbox.requests() == 2
