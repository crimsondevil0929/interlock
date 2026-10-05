"""The outbound checkers of ``docs/OUTBOX_DESIGN.md`` §5.2 (``docs/EPIC5_DESIGN.md`` §3).

Each is a pure function of ``(plan, diff)`` over the requests read back from
the outbox, as the relay will send them, and each fails closed: a value it
cannot read refuses the plan, never passes it. A payload number counts only
as an integer or a plain decimal numeral (:func:`interlock.types.exact_number`).
``"1_000"``, ``" 5"``, ``"1e3"``, ``"+5"`` and non-ASCII digits are not
numbers, because a sink may read them otherwise than the check did.

- :class:`SinkAllowlist`: the sinks and operations a plan may call.
- :class:`OutboundCount`: how many requests a plan may enqueue, in all or per
  sink.
- :class:`PayloadAmountCap`: the most a request, a tenant or a plan may ask
  for, by currency when the cap is.
- :class:`RecipientAllowlist`: where an email or a webhook may go, parsed
  strictly.
- :class:`OutboundTenantIsolation`: a request goes only to a tenant the plan's
  rows involve, and says so where its payload names one.

Every hint names the rule and the plan's own sinks and tenants, never a value
a request carries (:mod:`interlock.feedback`).
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Mapping, Sequence
from decimal import Decimal
from typing import Final
from urllib.parse import urlsplit

from interlock.feedback import FeedbackHint, Guidance
from interlock.types import (
    EffectDiff,
    EffectPlan,
    InvariantViolation,
    OutboundDelta,
    Severity,
    exact_number,
    field_path,
    value_at,
    values_at,
)

__all__ = [
    "OutboundCount",
    "OutboundTenantIsolation",
    "PayloadAmountCap",
    "RecipientAllowlist",
    "SinkAllowlist",
    "email_domain",
    "url_host",
]

ANY: Final = "*"
"""Every operation of a sink, in a :class:`SinkAllowlist`."""

_PER: Final = ("request", "tenant", "plan")

# One address, as plain as mail is: no display name, no comment, no quoted or
# routed local part (``%`` and ``!`` once routed mail onward), no whitespace.
_LOCAL: Final = re.compile(r"[A-Za-z0-9#$&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9#$&'*+/=?^_`{|}~-]+)*")
_LABEL: Final = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)")


def _hostname(text: str) -> str | None:
    """A DNS name as a recipient's domain is compared: ASCII (an internationalized
    name in its ``xn--`` form), case-folded, one trailing dot dropped, every
    label a valid one. ``None`` when it is not one."""
    if not text or not text.isascii():
        return None
    name = text.lower()
    if name.endswith("."):
        name = name[:-1]
    if not name or len(name) > 253:
        return None
    labels = name.split(".")
    if not all(_LABEL.fullmatch(label) for label in labels):
        return None
    # A dotted quad is an address, not a name, whatever DNS would make of it.
    if all(label.isdigit() for label in labels):
        return None
    return name


def email_domain(value: object) -> tuple[str, str] | None:
    """``(local part, domain)`` of an email address written as plainly as one
    can be, or ``None``: ``"a@b.c"``, never ``"A <a@b.c>"``, ``"a@b.c, d@e.f"``,
    ``'"x@b.c"@e.f'``, ``"a%e.f@b.c"`` or a domain in another script."""
    if not isinstance(value, str) or len(value) > 254 or value.count("@") != 1:
        return None
    local, _, domain = value.partition("@")
    if len(local) > 64 or not _LOCAL.fullmatch(local):
        return None
    host = _hostname(domain)
    return None if host is None else (local, host)


def url_host(value: object) -> str | None:
    """The host of an ``https`` URL written plainly, or ``None``: no userinfo,
    no IP literal, no backslash, whitespace, control or non-ASCII character
    anywhere (where browsers and parsers disagree)."""
    if not isinstance(value, str) or not value.isascii() or len(value) > 2048:
        return None
    if any(ch in value for ch in "\\ \t\r\n") or any(ord(ch) < 0x20 for ch in value):
        return None
    try:
        parts = urlsplit(value)
        _ = parts.port  # a malformed port raises
    except ValueError:
        return None
    if parts.scheme != "https" or "@" in parts.netloc or parts.hostname is None:
        return None
    try:
        ipaddress.ip_address(parts.hostname.strip("[]"))
    except ValueError:
        return _hostname(parts.hostname)
    return None


def _domain_rule(domains: Iterable[str]) -> frozenset[str]:
    """Configured domains, as payload domains are compared."""
    rules = set()
    for domain in domains:
        text = domain.strip()
        if not text.isascii():
            text = text.encode("idna").decode("ascii")
        host = _hostname(text)
        if host is None:
            raise ValueError(f"{domain!r} is not a domain name")
        rules.add(host)
    return frozenset(rules)


def _requests(diff: EffectDiff, sink: str, operation: str) -> list[OutboundDelta]:
    return [o for o in diff.outbound if o.sink == sink and o.operation == operation]


def _violation(name: str, message: str, **evidence: str) -> InvariantViolation:
    return InvariantViolation(
        invariant=name, severity=Severity.BLOCKING, message=message, evidence=evidence
    )


# --------------------------------------------------------------------------
# SinkAllowlist
# --------------------------------------------------------------------------


class SinkAllowlist:
    """Refuse a request to a sink, or an operation of one, outside the
    allowlist: ``{"stripe": ["refunds.create"], "mail": "*"}``.

    The sink registry admits requests per engine; this narrows them per plan,
    for an agent that may refund and never charge. Read from the requests as
    the outbox holds them.

    :raises ValueError: On an empty allowlist, or a sink allowed no operation.
    """

    __slots__ = ("_allowed",)

    def __init__(self, allowed: Mapping[str, Sequence[str] | str]) -> None:
        if not allowed:
            raise ValueError("SinkAllowlist needs at least one sink")
        rules: dict[str, frozenset[str] | None] = {}
        for sink, operations in allowed.items():
            if operations == ANY:
                rules[sink] = None
                continue
            listed = [operations] if isinstance(operations, str) else list(operations)
            if not listed:
                raise ValueError(f"sink {sink!r} is allowed no operation; leave it out")
            rules[sink] = frozenset(listed)
        self._allowed = rules

    @property
    def name(self) -> str:
        return "sink_allowlist"

    def check(self, plan: EffectPlan, diff: EffectDiff) -> tuple[InvariantViolation, ...]:
        found = []
        for request in diff.outbound:
            if request.sink not in self._allowed:
                found.append(
                    _violation(
                        self.name,
                        f"request {request.effect_id} goes to sink {request.sink}, which this "
                        f"plan may not call",
                        effect=request.effect_id,
                        sink=request.sink,
                    )
                )
                continue
            operations = self._allowed[request.sink]
            if operations is not None and request.operation not in operations:
                found.append(
                    _violation(
                        self.name,
                        f"request {request.effect_id} calls {request.sink}.{request.operation}, "
                        f"which this plan may not call",
                        effect=request.effect_id,
                        sink=request.sink,
                        operation=request.operation,
                    )
                )
        return tuple(found)

    def hint(
        self, plan: EffectPlan, diff: EffectDiff, violation: InvariantViolation
    ) -> FeedbackHint:
        sink = violation.evidence.get("sink", "")
        return FeedbackHint(kind=Guidance.OUTBOUND_SCOPE, sinks=(sink,) if sink else ())


# --------------------------------------------------------------------------
# OutboundCount
# --------------------------------------------------------------------------


class OutboundCount:
    """Bound the outbound requests one plan may enqueue: the blast radius
    for calls. ``max_per_plan`` over all of them, ``per_sink`` over each
    named sink's.

    :raises ValueError: On a negative limit, or no limit at all.
    """

    __slots__ = ("_max", "_per_sink")

    def __init__(
        self, max_per_plan: int | None = None, *, per_sink: Mapping[str, int] | None = None
    ) -> None:
        per_sink = per_sink or {}
        if max_per_plan is None and not per_sink:
            raise ValueError("OutboundCount needs max_per_plan, per_sink, or both")
        for limit in (max_per_plan, *per_sink.values()):
            if limit is not None and (isinstance(limit, bool) or limit < 0):
                raise ValueError(f"a request limit is a non-negative integer, not {limit!r}")
        self._max = max_per_plan
        self._per_sink = dict(per_sink)

    @property
    def name(self) -> str:
        return "outbound_count"

    def check(self, plan: EffectPlan, diff: EffectDiff) -> tuple[InvariantViolation, ...]:
        found = []
        total = len(diff.outbound)
        if self._max is not None and total > self._max:
            found.append(
                _violation(
                    self.name,
                    f"plan enqueues {total} outbound requests, limit is {self._max}",
                    measured=str(total),
                    limit=str(self._max),
                )
            )
        for sink, limit in sorted(self._per_sink.items()):
            count = sum(1 for o in diff.outbound if o.sink == sink)
            if count > limit:
                found.append(
                    _violation(
                        self.name,
                        f"plan enqueues {count} requests to sink {sink}, limit is {limit}",
                        sink=sink,
                        measured=str(count),
                        limit=str(limit),
                    )
                )
        return tuple(found)

    def hint(
        self, plan: EffectPlan, diff: EffectDiff, violation: InvariantViolation
    ) -> FeedbackHint:
        sink = violation.evidence.get("sink", "")
        return FeedbackHint(
            kind=Guidance.OUTBOUND_COUNT,
            sinks=(sink,) if sink else (),
            measured=int(violation.evidence.get("measured", "0")),
            limit=int(violation.evidence.get("limit", "0")),
        )


# --------------------------------------------------------------------------
# PayloadAmountCap
# --------------------------------------------------------------------------


class PayloadAmountCap:
    """Cap an amount a request carries: a refund's, a charge's.

    :param sink: The requests this rule applies to: this sink's...
    :param operation: ...calls of this operation.
    :param field: The amount, a dotted path into the payload.
    :param maximum: The cap: a number (an integer, a ``Decimal`` or a decimal
        string), or a map from currency code to cap, read at
        ``currency_field``. A request in a currency the map lacks is refused.
    :param per: ``"request"``: each request's amount; ``"tenant"``: the sum
        of the plan's requests for each tenant; ``"plan"``: the sum of them
        all. Sums are per currency.
    :param currency_field: Where a request names its currency; needed with a
        map, and compared case-folded (ISO 4217 codes are case-insensitive).

    A request whose amount is missing, not a plain number, or negative refuses
    the plan: no negative entry can net a sum under the cap. Units are the
    payload's: a Stripe amount is in the currency's minor unit.

    :raises ValueError: On a malformed cap, an unknown ``per``, or a map
        without ``currency_field``.
    """

    __slots__ = ("_caps", "_currency", "_field", "_operation", "_path", "_per", "_sink")

    def __init__(
        self,
        sink: str,
        operation: str,
        *,
        field: str,
        maximum: Decimal | int | str | Mapping[str, Decimal | int | str],
        per: str = "request",
        currency_field: str | None = None,
    ) -> None:
        if per not in _PER:
            raise ValueError(f"per is one of {', '.join(_PER)}, not {per!r}")
        if not field.strip():
            raise ValueError("PayloadAmountCap needs a field")
        caps: dict[str | None, Decimal] = {}
        if isinstance(maximum, Mapping):
            if currency_field is None:
                raise ValueError("a cap by currency needs currency_field")
            for currency, cap in maximum.items():
                caps[currency.lower()] = self._cap(cap)
        else:
            caps[None] = self._cap(maximum)
        self._sink = sink
        self._operation = operation
        self._field = field
        self._path = field_path(field)
        self._caps = caps
        self._per = per
        self._currency = None if currency_field is None else field_path(currency_field)

    @staticmethod
    def _cap(value: object) -> Decimal:
        number = exact_number(value)
        if number is None or number < 0:
            raise ValueError(f"a cap is a non-negative integer or decimal string, not {value!r}")
        return number

    @property
    def name(self) -> str:
        return f"payload_amount_cap:{self._sink}.{self._operation}.{self._field}"

    def _cap_for(self, currency: str | None) -> Decimal:
        return self._caps[None] if None in self._caps else self._caps[currency]

    def check(self, plan: EffectPlan, diff: EffectDiff) -> tuple[InvariantViolation, ...]:
        found: list[InvariantViolation] = []
        totals: dict[tuple[str, str | None], Decimal] = {}
        for request in _requests(diff, self._sink, self._operation):
            where = {"effect": request.effect_id, "sink": self._sink}
            present, value = value_at(request.payload, self._path)
            amount = exact_number(value) if present else None
            if amount is None or amount < 0:
                found.append(
                    _violation(
                        self.name,
                        f"request {request.effect_id} carries no plain non-negative number at "
                        f"{self._field}",
                        **where,
                    )
                )
                continue
            currency: str | None = None
            if self._currency is not None:
                present, named = value_at(request.payload, self._currency)
                currency = named.lower() if present and isinstance(named, str) else None
                if currency is None or currency not in self._caps:
                    found.append(
                        _violation(
                            self.name,
                            f"request {request.effect_id} names no currency this cap covers",
                            **where,
                        )
                    )
                    continue
            if self._per == "request":
                if amount > self._cap_for(currency):
                    found.append(
                        _violation(
                            self.name,
                            f"request {request.effect_id} asks for {amount} at {self._field}, "
                            f"over the cap",
                            **where,
                            amount=str(amount),
                        )
                    )
                continue
            group = (request.tenant_id or "") if self._per == "tenant" else ""
            key = (group, currency)
            totals[key] = totals.get(key, Decimal(0)) + amount
        for (group, currency), total in sorted(
            totals.items(), key=lambda item: (item[0][0], item[0][1] or "")
        ):
            if total > self._cap_for(currency):
                whose = f" for tenant {group}" if self._per == "tenant" else ""
                found.append(
                    _violation(
                        self.name,
                        f"the plan's {self._sink}.{self._operation} requests{whose} ask for "
                        f"{total} at {self._field} in all, over the cap",
                        sink=self._sink,
                        total=str(total),
                        **({"tenant": group} if self._per == "tenant" else {}),
                    )
                )
        return tuple(found)

    def hint(
        self, plan: EffectPlan, diff: EffectDiff, violation: InvariantViolation
    ) -> FeedbackHint:
        # The rule, never the amounts, nor the cap: a cap told is a target.
        tenant = violation.evidence.get("tenant")
        return FeedbackHint(
            kind=Guidance.OUTBOUND_AMOUNT,
            sinks=(self._sink,),
            tenants=(tenant,) if tenant else (),
        )


# --------------------------------------------------------------------------
# RecipientAllowlist
# --------------------------------------------------------------------------


class RecipientAllowlist:
    """Refuse a request addressed outside the allowed domains or addresses.

    :param sink: The requests this rule applies to: this sink's...
    :param operation: ...calls of this operation.
    :param fields: Where recipients are, as dotted paths; ``*`` stands for
        every item of a list there: ``("to.*.email", "cc.*.email",
        "bcc.*.email")``. A path that finds nothing finds no recipient.
    :param domains: Recipients' allowed domains, compared case-folded,
        internationalized names in their ``xn--`` form.
    :param addresses: Allowed addresses, whatever their domain, compared
        case-folded.
    :param tenant_domains: More domains for a request with that tenant: a
        tenant's own.
    :param subdomains: Whether ``mail.acme.com`` is allowed with ``acme.com``.
        Off by default.
    :param kind: ``"email"``, or ``"url"`` for a webhook: an ``https`` URL's
        host is held to the domains.

    Parsed strictly (:func:`email_domain`, :func:`url_host`). A value that is
    not a single plain address, or not text, refuses the plan.

    :raises ValueError: On no fields, nothing allowed, a domain that is no
        domain name, or an unknown ``kind``.
    """

    __slots__ = (
        "_addresses",
        "_domains",
        "_kind",
        "_operation",
        "_paths",
        "_sink",
        "_subdomains",
        "_tenants",
    )

    def __init__(
        self,
        sink: str,
        operation: str,
        *,
        fields: Sequence[str] | str,
        domains: Iterable[str] = (),
        addresses: Iterable[str] = (),
        tenant_domains: Mapping[str, Iterable[str]] | None = None,
        subdomains: bool = False,
        kind: str = "email",
    ) -> None:
        if kind not in ("email", "url"):
            raise ValueError(f"kind is 'email' or 'url', not {kind!r}")
        paths = [fields] if isinstance(fields, str) else list(fields)
        if not paths or not all(p.strip() for p in paths):
            raise ValueError("RecipientAllowlist needs the fields recipients are at")
        self._domains = _domain_rule(domains)
        self._tenants = {tenant: _domain_rule(d) for tenant, d in (tenant_domains or {}).items()}
        self._addresses = frozenset(a.strip().lower() for a in addresses)
        if kind == "url" and self._addresses:
            raise ValueError("a URL recipient is allowed by its domain, not as an address")
        if not self._domains and not self._addresses and not self._tenants:
            raise ValueError("RecipientAllowlist allows nothing: give domains or addresses")
        self._sink = sink
        self._operation = operation
        self._paths = [field_path(p) for p in paths]
        self._subdomains = subdomains
        self._kind = kind

    @property
    def name(self) -> str:
        return f"recipient_allowlist:{self._sink}.{self._operation}"

    def _allowed_domain(self, domain: str, tenant: str | None) -> bool:
        rules = self._domains | (self._tenants.get(tenant, frozenset()) if tenant else frozenset())
        if domain in rules:
            return True
        return self._subdomains and any(domain.endswith("." + rule) for rule in rules)

    def check(self, plan: EffectPlan, diff: EffectDiff) -> tuple[InvariantViolation, ...]:
        found: list[InvariantViolation] = []
        for request in _requests(diff, self._sink, self._operation):
            for path in self._paths:
                for where, value in values_at(request.payload, path):
                    if self._kind == "url":
                        host = url_host(value)
                        ok = host is not None and self._allowed_domain(host, request.tenant_id)
                    else:
                        parsed = email_domain(value)
                        ok = parsed is not None and (
                            f"{parsed[0]}@{parsed[1]}".lower() in self._addresses
                            or self._allowed_domain(parsed[1], request.tenant_id)
                        )
                    if not ok:
                        # Where, never what: a recipient is data.
                        found.append(
                            _violation(
                                self.name,
                                f"request {request.effect_id} addresses a recipient at {where} "
                                f"outside the allowed ones, or not a plain "
                                f"{'URL' if self._kind == 'url' else 'address'}",
                                effect=request.effect_id,
                                sink=self._sink,
                                where=where,
                            )
                        )
        return tuple(found)

    def hint(
        self, plan: EffectPlan, diff: EffectDiff, violation: InvariantViolation
    ) -> FeedbackHint:
        return FeedbackHint(kind=Guidance.OUTBOUND_RECIPIENT, sinks=(self._sink,))


# --------------------------------------------------------------------------
# OutboundTenantIsolation
# --------------------------------------------------------------------------


class OutboundTenantIsolation:
    """Refuse a plan whose requests reach beyond its tenants.

    :param fields: Where a payload names its tenant: ``{"crm.notes.create":
        "account.tenant", "mail": "tenant"}``, by ``sink.operation`` or by
        sink. That field must hold the request's own tenant.
    :param max_tenants: How many tenants the plan's rows and requests may
        span together.
    :param require_tenant: Refuse a request that names no tenant at all.

    A plan whose rows involve tenants may send requests only to those tenants:
    a refund to tenant B beside rows of tenant A is refused. A request with no
    tenant (a page to the operators) is not held to the rows, unless
    ``require_tenant``.

    :raises ValueError: On ``max_tenants`` below 1, or an empty field.
    """

    __slots__ = ("_fields", "_max", "_require")

    def __init__(
        self,
        *,
        fields: Mapping[str, str] | None = None,
        max_tenants: int = 1,
        require_tenant: bool = False,
    ) -> None:
        if isinstance(max_tenants, bool) or max_tenants < 1:
            raise ValueError("max_tenants is at least 1")
        fields = fields or {}
        for target, path in fields.items():
            if not target.strip() or not path.strip():
                raise ValueError("a tenant field names its sink (or sink.operation) and a path")
        self._fields = {target: field_path(path) for target, path in fields.items()}
        self._max = max_tenants
        self._require = require_tenant

    @property
    def name(self) -> str:
        return "outbound_tenant_isolation"

    def _field(self, request: OutboundDelta) -> tuple[str, ...] | None:
        return self._fields.get(f"{request.sink}.{request.operation}") or self._fields.get(
            request.sink
        )

    def check(self, plan: EffectPlan, diff: EffectDiff) -> tuple[InvariantViolation, ...]:
        found: list[InvariantViolation] = []
        rows = diff.tenant_ids
        requested = {o.tenant_id for o in diff.outbound if o.tenant_id is not None}
        for request in diff.outbound:
            where = {"effect": request.effect_id, "sink": request.sink}
            tenant = request.tenant_id
            if tenant is None:
                if self._require:
                    found.append(
                        _violation(
                            self.name, f"request {request.effect_id} names no tenant", **where
                        )
                    )
                continue
            if rows and tenant not in rows:
                found.append(
                    _violation(
                        self.name,
                        f"request {request.effect_id} goes to tenant {tenant}, which none of the "
                        f"plan's rows involve",
                        **where,
                        tenant=tenant,
                    )
                )
            path = self._field(request)
            if path is not None:
                present, value = value_at(request.payload, path)
                if present and isinstance(value, int) and not isinstance(value, bool):
                    value = str(value)
                if not present or value != tenant:
                    found.append(
                        _violation(
                            self.name,
                            f"request {request.effect_id}'s payload names another tenant than "
                            f"its own, or none, where it must name one",
                            **where,
                            tenant=tenant,
                        )
                    )
        spanned = rows | requested
        if len(spanned) > self._max:
            found.append(
                _violation(
                    self.name,
                    f"the plan's rows and requests span {len(spanned)} tenants, limit is "
                    f"{self._max}",
                    tenants=",".join(sorted(spanned)),
                    limit=str(self._max),
                )
            )
        return tuple(found)

    def hint(
        self, plan: EffectPlan, diff: EffectDiff, violation: InvariantViolation
    ) -> FeedbackHint:
        # Every tenant involved goes in for the sanitizer to cut down to the
        # ones the plan declared; how many there were never leaves here.
        involved = sorted(
            diff.tenant_ids | {o.tenant_id for o in diff.outbound if o.tenant_id is not None}
        )
        sink = violation.evidence.get("sink", "")
        return FeedbackHint(
            kind=Guidance.OUTBOUND_TENANT,
            tenants=tuple(involved),
            sinks=(sink,) if sink else (),
            limit=self._max,
        )
