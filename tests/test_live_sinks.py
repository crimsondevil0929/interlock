"""The adapters against the real services, when their keys are given.

Skipped unless the environment holds them, and never against anything that
could charge or email anyone:

- ``INTERLOCK_LIVE_STRIPE_KEY``: a Stripe **test mode** secret key
  (``sk_test_...``; a live key is refused). The payment uses Stripe's test
  card, and is refunded.
- ``INTERLOCK_LIVE_SENDGRID_KEY`` and ``INTERLOCK_LIVE_SENDGRID_FROM`` (a
  sender the account has verified): the email is sent in **sandbox mode**,
  which SendGrid validates and does not deliver.

What they prove that the fakes cannot: the wire format is the one the vendor
reads, and the vendor answers as the classification expects.
"""

from __future__ import annotations

import hashlib
import os
import uuid
from typing import Any

import pytest
from agentgov.receipts.canonical import canonical_bytes

from interlock.relay import DELIVERED, PERMANENT, Delivery
from interlock.sendgrid import MAIL_SEND, SendGridAdapter
from interlock.stripe import PAYMENT_INTENTS_CREATE, REFUNDS_CREATE, StripeAdapter

STRIPE_KEY = os.environ.get("INTERLOCK_LIVE_STRIPE_KEY", "")
SENDGRID_KEY = os.environ.get("INTERLOCK_LIVE_SENDGRID_KEY", "")
SENDGRID_FROM = os.environ.get("INTERLOCK_LIVE_SENDGRID_FROM", "")


def delivery(sink: str, operation: str, payload: dict[str, Any], key: str) -> Delivery:
    body = canonical_bytes(payload)
    return Delivery(
        message_id=uuid.uuid4(),
        sink=sink,
        operation=operation,
        idempotency_key=key,
        payload=body,
        payload_hash=hashlib.sha256(body).hexdigest(),
        attempt=1,
        tenant_id=None,
        timeout=20.0,
    )


@pytest.mark.skipif(not STRIPE_KEY, reason="set INTERLOCK_LIVE_STRIPE_KEY (test mode) to run")
def test_stripe_charges_once_replays_and_refunds() -> None:
    if not STRIPE_KEY.startswith("sk_test_"):
        pytest.fail("INTERLOCK_LIVE_STRIPE_KEY must be a test mode key (sk_test_...)")
    adapter = StripeAdapter(STRIPE_KEY)
    key = f"interlock-live-{uuid.uuid4()}"
    charge = {
        "amount": 100,
        "currency": "usd",
        "payment_method": "pm_card_visa",
        "payment_method_types": ["card"],
        "confirm": True,
        "metadata": {"interlock": "live test"},
    }
    made = adapter.send(delivery("stripe", PAYMENT_INTENTS_CREATE, charge, key))
    assert made.outcome == DELIVERED, made.detail
    assert made.remote_ref is not None and made.remote_ref.startswith("pi_")
    replayed = adapter.send(delivery("stripe", PAYMENT_INTENTS_CREATE, charge, key))
    assert (replayed.outcome, replayed.remote_ref) == (DELIVERED, made.remote_ref)
    assert replayed.detail == "an idempotent replay"
    reused = adapter.send(
        delivery("stripe", PAYMENT_INTENTS_CREATE, {**charge, "amount": 200}, key)
    )
    assert reused.outcome == PERMANENT and "other parameters" in reused.detail
    refund = adapter.send(
        delivery("stripe", REFUNDS_CREATE, {"payment_intent": made.remote_ref}, f"{key}-refund")
    )
    assert refund.outcome == DELIVERED and (refund.remote_ref or "").startswith("re_")


@pytest.mark.skipif(
    not (SENDGRID_KEY and SENDGRID_FROM),
    reason="set INTERLOCK_LIVE_SENDGRID_KEY and INTERLOCK_LIVE_SENDGRID_FROM to run",
)
def test_sendgrid_accepts_the_v3_body_in_sandbox_mode() -> None:
    adapter = SendGridAdapter(SENDGRID_KEY, sandbox=True)
    email = {
        "to": [{"email": SENDGRID_FROM}],
        "from": {"email": SENDGRID_FROM},
        "subject": "Interlock live test (sandbox: never delivered)",
        "text": "SendGrid validated this request and sent nothing.",
    }
    result = adapter.send(delivery("sendgrid", MAIL_SEND, email, str(uuid.uuid4())))
    assert result.outcome == DELIVERED, result.detail
