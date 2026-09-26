"""ARC1 receipts for adjudicated plans.

With a :class:`ReceiptIssuer`, the engine issues one signed ARC1
:class:`~agentgov.receipts.ActionReceipt` for every plan it adjudicates,
committed or refused, into an agentgov :class:`~agentgov.receipts.ReceiptLog`.
An outsider holding the issuer's public key can then check, offline, what the
agent was allowed to do, what it said it would do, what it measurably did,
what was decided and what it cost (see agentgov's ``docs/RECEIPTS.md``).

The receipt and the escrow chain name each other. The receipt id is chosen
before the stage's terminal record is written, and the record's note carries
it; the receipt's ``anchors.escrow`` names that record's sequence and hash.
Deleting either leaves the other pointing at nothing.

What each field is built from:

- ``authority``: the AgentGov scope path when an anchor is attached (the
  plan's scope alone otherwise), the plan's trajectory, and a capability of
  the substrate's observed tables with the tightest ``BlastRadius`` limit.
- ``intent``: the plan's content hash and what its effects stated.
- ``effect``: the diff hash the chain's ``DIFF_COMPUTED`` record carries, a
  salted row commitment over every measured row change, and a hash of the
  observed schema (the table specs and the foreign-key graph).
- ``coverage``: the observed tables, whether the cascade check left no
  acknowledged gap, whether writes outside them are refused, and every gap
  the operator acknowledged, in words.
- ``decision``: the verdict hash, each checker with a digest of its
  configuration, the issuer's policy epoch, and ``repair_of``: the refused
  plan's receipt, when this plan is a repair of it.
- ``cost``: the AgentGov transaction that settled the plan, when there is
  one. The receipt is issued after it, anchored to the head it produced.
"""

from __future__ import annotations

import secrets
import uuid
from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

from agentgov.receipts import (
    ActionReceipt,
    Anchors,
    Authority,
    Capability,
    ChainAnchor,
    CheckerRecord,
    Cost,
    Coverage,
    Decision,
    Effect,
    EffectSummary,
    Intent,
    Outcome,
    OutcomeStatus,
    ReceiptLog,
    RowChange,
    StatedFootprint,
    commit_rows,
)

from interlock.anchor import AnchorPoint
from interlock.cascade import CascadeReport
from interlock.chain import EscrowRecord
from interlock.invariants import BlastRadius, InvariantChecker
from interlock.types import EffectDiff, EffectPlan, Verdict, canonical_hash

__all__ = ["ReceiptIssuer", "checker_records", "schema_hash"]

_TEXT_LIMIT = 512


class ReceiptIssuer:
    """Issues an ARC1 receipt for every plan an engine adjudicates.

    :param log: The receipt log to issue into. Its signer signs the receipts.
    :param issuer: Who issues them, recorded in every receipt.
    :param row_secret: The 32-byte secret the row commitments' salts derive
        from. Keep it to disclose rows later; the default is random, which
        makes rows disclosable only while this issuer lives.
    :param policy_epoch: The version of the checker policy, recorded in every
        decision. Bump it when the checkers change.
    """

    __slots__ = ("_epoch", "_issuer", "_log", "_row_secret")

    def __init__(
        self,
        log: ReceiptLog,
        *,
        issuer: str = "interlock",
        row_secret: bytes | None = None,
        policy_epoch: int = 0,
    ) -> None:
        if row_secret is not None and len(row_secret) != 32:
            raise ValueError("a row secret is 32 bytes")
        self._log = log
        self._issuer = issuer
        self._row_secret = row_secret if row_secret is not None else secrets.token_bytes(32)
        self._epoch = policy_epoch

    @property
    def log(self) -> ReceiptLog:
        return self._log

    @staticmethod
    def new_id() -> str:
        """A fresh receipt id, chosen before the record that will name it."""
        return str(uuid.uuid4())

    def issue(
        self,
        *,
        receipt_id: str,
        plan: EffectPlan,
        diff: EffectDiff,
        verdict: Verdict,
        committed: bool,
        substrate: object,
        checkers: Sequence[InvariantChecker],
        escrow: EscrowRecord,
        agentgov: AnchorPoint,
        scope_path: Sequence[str],
        substrate_txid: str | None = None,
        repair_of: str | None = None,
        ledger_txn_ids: Iterable[str] = (),
        settled: Decimal = Decimal(0),
    ) -> ActionReceipt:
        """Build, sign and log the receipt for one adjudicated plan.

        :raises agentgov.exceptions.ReceiptError: If the log refuses it.
        """
        rows = [
            RowChange.from_values(
                d.table, d.primary_key, before=d.before, after=d.after, tenant=d.tenant_id
            )
            for d in diff.deltas
        ]
        commitment = commit_rows(rows, secret=self._row_secret)
        report = getattr(substrate, "cascade_report", None)
        observed = sorted(getattr(substrate, "observed_tables", frozenset()))
        limits = [c.limit for c in checkers if isinstance(c, BlastRadius)]
        draft = ActionReceipt(
            receipt_id=receipt_id,
            issued_at=datetime.now(UTC),
            issuer=self._issuer,
            authority=Authority(
                scope_path=tuple(scope_path) or (plan.scope_id,),
                trajectory_id=plan.trajectory_id,
                capability=Capability(
                    grant=f"interlock:{getattr(substrate, 'substrate_id', 'unknown')}",
                    tables=tuple(observed),
                    row_limit=min(limits) if limits else None,
                ),
            ),
            intent=Intent(
                plan_hash=plan.content_hash(),
                stated=StatedFootprint(
                    rows=plan.stated_rows, tables=tuple({e.table for e in plan.effects})
                ),
            ),
            effect=Effect(
                substrate_id=diff.substrate_id,
                schema_hash=schema_hash(substrate),
                diff_hash=diff.content_hash(),
                row_root=commitment.root,
                row_count=len(rows),
                summary=EffectSummary(
                    inserted=diff.rows_inserted,
                    updated=diff.rows_updated,
                    deleted=diff.rows_deleted,
                    tables=tuple(diff.tables_touched),
                    tenants=tuple(diff.tenant_ids),
                ),
                truncated=diff.truncated,
            ),
            coverage=Coverage(
                observed_tables=tuple(observed),
                cascade_closed=isinstance(report, CascadeReport) and report.closed,
                authorizer_on=bool(getattr(substrate, "enforces_table_access", False)),
                known_gaps=_gaps(substrate, report),
            ),
            decision=Decision(
                verdict_hash=verdict.content_hash(),
                admitted=verdict.admitted,
                checkers=checker_records(checkers),
                policy_epoch=self._epoch,
                repair_of=repair_of,
            ),
            cost=Cost(ledger_txn_ids=tuple(ledger_txn_ids), settled_usd=settled),
            outcome=Outcome(
                status=OutcomeStatus.COMMITTED if committed else OutcomeStatus.REFUSED,
                substrate_txid=substrate_txid if committed else None,
            ),
            anchors=Anchors(
                agentgov=(
                    ChainAnchor(seq=agentgov.sequence, head=agentgov.head_hash)
                    if agentgov.anchored
                    else None
                ),
                escrow=ChainAnchor(seq=escrow.sequence, head=escrow.record_hash),
            ),
        )
        return self._log.issue(draft)


def checker_records(checkers: Sequence[InvariantChecker]) -> tuple[CheckerRecord, ...]:
    """Each checker by name, with a digest of its configuration.

    ARC1 names each checker once, so checkers sharing a name share a record
    whose digest covers all their configurations.
    """
    configs: dict[str, list[Any]] = {}
    for checker in checkers:
        configs.setdefault(checker.name, []).append(_config(checker))
    return tuple(
        CheckerRecord(name=_text(name), config_hash=canonical_hash([name, sorted(map(repr, cs))]))
        for name, cs in sorted(configs.items())
    )


def schema_hash(substrate: object) -> str:
    """A digest of the schema the measurement assumed: the table specs, and
    the foreign-key graph when the cascade check read one."""
    specs = [
        [spec.name, spec.primary_key, list(spec.columns), spec.tenant_column]
        for spec in getattr(substrate, "table_specs", ())
    ]
    report = getattr(substrate, "cascade_report", None)
    keys = []
    if isinstance(report, CascadeReport):
        keys = sorted(
            [
                k.child,
                list(k.child_columns),
                k.parent,
                list(k.parent_columns),
                k.on_delete,
                k.on_update,
            ]
            for k in report.foreign_keys
        )
    return canonical_hash(["schema", sorted(specs), keys])


def _config(checker: object) -> list[tuple[str, str]]:
    slots: Iterable[str] = getattr(type(checker), "__slots__", ())
    state: Mapping[str, Any] = (
        {name: getattr(checker, name, None) for name in slots}
        if slots
        else dict(getattr(checker, "__dict__", {}))
    )
    return [(type(checker).__qualname__, ""), *sorted((k, repr(v)) for k, v in state.items())]


def _gaps(substrate: object, report: object) -> tuple[str, ...]:
    gaps: list[str] = []
    if isinstance(report, CascadeReport):
        gaps += [f"unmeasured cascade: {reach.describe()}" for reach in report.gaps]
    else:
        gaps.append("foreign-key cascades were not checked")
    if not getattr(substrate, "enforces_table_access", False):
        gaps.append("writes to unobserved tables were not refused")
    return tuple(_text(g) for g in gaps)


def _text(value: str) -> str:
    return value if len(value) <= _TEXT_LIMIT else value[: _TEXT_LIMIT - 3] + "..."
