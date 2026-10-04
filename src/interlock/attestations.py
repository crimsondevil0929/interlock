"""Relays' attestations, and the outcomes no relay reported (``docs/EPIC4_DESIGN.md`` §2).

From schema version 4, every outcome a relay records (``delivered``,
``retryable``, ``permanent``, ``unknown``) carries the relay's Ed25519
attestation of what the sink answered: an ARC1 1.1 ``Attestation`` over the
request, as the outbox committed it, and the outcome, as the row records it.
The database refuses an outcome row without one.

Whoever can write the database can still write a row around its triggers,
linked and hashed as Interlock would have: a ``delivered`` that no call
produced. What they cannot write is the relay's signature. So
:func:`verify_attestations` rebuilds each outcome's attestation from the
outbox row and the log row, and verifies it under the registered relay keys
(``[relays.keys]``). An outcome without a valid one, written after version 4
was installed, is named: a *ghost delivery*. A valid attestation copied onto
a second row is not one: :func:`~interlock.deliveries.verify_delivery_log`
names a call with two outcomes.

An outcome recorded before version 4 carries no attestation. Such outcomes
are the legacy set version 4 recorded as it was installed
(:class:`~interlock.deliveries.LegacySet`), and a signed install vouches for
that set: an unattested outcome is legacy only if it is one of those rows,
exactly as recorded, and the set is the one vouched for. Any other is named,
however early it is dated. Without the vouch, the legacy outcomes rest on the
database's word, and verification says so.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from agentgov.exceptions import MalformedReceiptError, ReceiptSignatureError
from agentgov.receipts import Attestation, AttestedOutcome, DeliveredRequest
from agentgov.receipts.canonical import loads_strict
from agentgov.receipts.schema import Signature, _Fields

from interlock.deliveries import OUTCOMES, LegacyVouch, LogEvent, LoggedMessage, reader
from interlock.records import Keyring

__all__ = ["AttestationReport", "attestation_of", "verify_attestations"]


@dataclass(frozen=True, slots=True)
class AttestationReport:
    """What :func:`verify_attestations` found."""

    problems: tuple[str, ...]
    attested: int
    """Outcomes whose attestation verifies under a registered relay key."""
    legacy: int
    """Outcomes recorded before version 4, which carry no attestation: rows of
    the legacy set a signed install vouched for."""


def attestation_of(message: LoggedMessage, event: LogEvent) -> Attestation:
    """The attestation an outcome row carries, rebuilt to verify: the request
    as the outbox committed it, the outcome as the row records it.

    :raises MalformedReceiptError: If the row's attestation is not a signature.
    """
    if event.attestation is None or event.attempt is None:
        raise MalformedReceiptError("the row carries no attestation")
    signature = Signature.from_json(
        _Fields(loads_strict(event.attestation), "attestation", ("alg", "key_id", "signature"))
    )
    return Attestation(
        request=DeliveredRequest(
            message_id=str(message.message_id),
            effect_id=message.effect_id,
            sink=message.sink,
            operation=message.operation,
            payload_hash=message.payload_hash,
            idempotency_key=message.idempotency_key,
        ),
        outcome=AttestedOutcome(
            attempt=event.attempt,
            result=event.event,
            status_code=event.status_code,
            response_digest=event.response_digest,
            remote_ref=event.remote_ref,
        ),
        signature=signature,
    )


def verify_attestations(
    source: object, relays: Keyring, *, legacy: LegacyVouch | None = None
) -> AttestationReport:
    """Hold every outcome in the delivery logs to its relay's signature.

    Finds an outcome with no attestation that is not in the legacy set; one
    attested by a key no relay is registered with; one whose attestation does
    not verify, because the row, or the request it names, says something the
    relay never signed; a legacy set other than the one vouched for, or naming
    a row its log no longer holds; and legacy outcomes that no signed install
    vouches for.

    :param source: The outbox: a PostgreSQL connection or a store.
    :param relays: The relays' public keys (``[relays.keys]``).
    :param legacy: The legacy set a signed install vouched for
        (:func:`interlock.operators.legacy_vouch`).
    """
    source_reader = reader(source)
    recorded = source_reader.legacy()
    if recorded is None:
        return AttestationReport(
            (
                "the outbox is older than version 4, and no outcome in it is attested: run "
                "`interlock install` to upgrade it",
            ),
            0,
            0,
        )
    messages, events = source_reader.snapshot(None)
    by_id: dict[uuid.UUID, LoggedMessage] = {m.message_id: m for m in messages}
    problems: list[str] = []
    mismatch = legacy.problem(recorded) if legacy is not None else None
    if mismatch is not None:
        problems.append(mismatch)
    vouched = legacy is not None and mismatch is None
    attested = counted = unvouched = 0
    for event in events:
        if event.event not in OUTCOMES:
            continue
        where = f"message {event.message_id}: row {event.seq} ({event.event})"
        if event.attestation is None:
            if not recorded.holds(event):
                problems.append(
                    f"{where} carries no relay attestation, and is not in the legacy set "
                    f"version 4 recorded: an outcome no relay reported"
                )
            elif vouched:
                counted += 1
            else:
                unvouched += 1
            continue
        message = by_id.get(event.message_id)
        if message is None:  # pragma: no cover - verify_delivery_log names orphans
            continue
        try:
            statement = attestation_of(message, event)
        except MalformedReceiptError as exc:
            problems.append(f"{where}: its attestation is not a signature: {exc}")
            continue
        assert statement.signature is not None
        key_id = statement.signature.key_id
        key = relays.verifier(key_id)
        if key is None:
            problems.append(f"{where} is attested by key {key_id}, which is no registered relay's")
            continue
        try:
            statement.verify(key)
        except ReceiptSignatureError:
            problems.append(
                f"{where} says what relay {relays.name(key_id)} never attested: the row or "
                f"its request was written around Interlock"
            )
            continue
        attested += 1
    if unvouched and legacy is None:
        problems.append(
            f"{unvouched} outcome(s) from before version 4 carry no relay attestation, and no "
            f"signed install vouches for the legacy set they are in: they rest on the "
            f"database's word. Vouch for it with `interlock install` under [operators]"
        )
    problems += recorded.vanished(events)
    return AttestationReport(tuple(problems), attested, counted)
