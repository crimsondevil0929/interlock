"""Remote signers (``docs/EPIC8_DESIGN.md`` §1).

- A key at the service signs exactly as the same key would here: one key id,
  one signature.
- A signer pins the version it was built with; a rotated key is a new signer.
- Every way a service can fail (unreachable, refusing, slow, signing with
  another key or version, answering with garbage) is an error, never a
  signature that does not verify; and no error carries the credential.
- A coroutine's loop never waits on the service.
- The operator log and an ARC1 attestation sign through one unchanged.
"""

from __future__ import annotations

import asyncio
import secrets
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from agentgov.receipts import Attestation, AttestedOutcome, DeliveredRequest
from agentgov.receipts.signing import Ed25519Signer

from interlock.records import Keyring, RecordKind, RecordLog
from interlock.signers import HttpRemoteSigner, RemoteSigner, SignerUnavailableError
from tests.fakekms import GARBAGE, NOT_JSON, OTHER_KEY, WRONG_VERSION, FakeKms

TOKEN = "kms-token-" + secrets.token_hex(8)


@pytest.fixture
def kms() -> Iterator[FakeKms]:
    with FakeKms(token=TOKEN) as service:
        yield service


def remote(kms: FakeKms, name: str = "relay", **kwargs: Any) -> HttpRemoteSigner:
    return HttpRemoteSigner(kms.url, name, token=TOKEN, **kwargs)


def test_a_remote_key_signs_as_the_same_key_would_here(kms: FakeKms) -> None:
    seed = secrets.token_bytes(32)
    kms.create("relay", seed)
    local = Ed25519Signer(seed)
    signer = remote(kms)
    assert isinstance(signer, RemoteSigner) and signer.alg == "ed25519"
    assert signer.key_id == local.key_id and signer.version == 1
    assert signer.public_key() == local.public_key()
    message = b"ARC1/attestation/v1\nwhatever is signed"
    # Ed25519 is deterministic: the service's signature is the local one.
    assert signer.sign(message) == local.sign(message)
    assert signer.verify(message, local.sign(message))
    assert not signer.verify(message + b"!", local.sign(message))
    assert kms.signed[("relay", 1)] == 1
    assert repr(signer) == f"HttpRemoteSigner(key_id={local.key_id!r}, version=1)"


def test_a_signer_pins_its_version_and_a_rotated_key_is_a_new_signer(kms: FakeKms) -> None:
    first = kms.create("relay")
    before = remote(kms)
    second = kms.rotate("relay")
    after = remote(kms)
    assert (before.version, after.version) == (1, 2)
    assert before.key_id == first.key_id and after.key_id == second.key_id
    message = b"one message"
    assert before.sign(message) == first.sign(message)
    assert after.sign(message) == second.sign(message)
    assert kms.signed == {("relay", 1): 1, ("relay", 2): 1}
    # A version can be pinned outright, an old one included.
    assert remote(kms, version=1).key_id == first.key_id
    with pytest.raises(SignerUnavailableError, match="404"):
        remote(kms, version=3)


@pytest.mark.parametrize(
    ("misbehave", "status", "match"),
    [
        (GARBAGE, None, "does not verify: nothing is signed"),
        (OTHER_KEY, None, "does not verify: nothing is signed"),
        (WRONG_VERSION, None, "signed with version 2, not the pinned 1"),
        (NOT_JSON, None, "answered with no JSON"),
        (None, 500, "answered 500"),
        (None, 403, "answered 403"),
        (None, 307, "answered 307"),  # a redirect is never followed: the token stays here
    ],
)
def test_a_service_that_fails_to_sign_is_an_error_never_a_signature(
    kms: FakeKms, misbehave: str | None, status: int | None, match: str
) -> None:
    kms.create("relay")
    signer = remote(kms)
    kms.misbehave, kms.status = misbehave, status
    with pytest.raises(SignerUnavailableError, match=match) as raised:
        signer.sign(b"a message")
    assert TOKEN not in str(raised.value)


def test_a_service_that_cannot_be_used_refuses_the_signer(kms: FakeKms) -> None:
    kms.create("relay")
    with pytest.raises(SignerUnavailableError, match="401") as raised:
        HttpRemoteSigner(kms.url, "relay", token="not-the-token")
    assert "not-the-token" not in str(raised.value)
    with pytest.raises(SignerUnavailableError, match="404"):
        remote(kms, "nobody")
    kms.delay = 0.5
    began = time.monotonic()
    with pytest.raises(SignerUnavailableError, match="could not be reached"):
        remote(kms, timeout=0.1)
    assert time.monotonic() - began < 0.45
    kms.delay = 0.0
    kms.close()
    with pytest.raises(SignerUnavailableError, match="could not be reached"):
        remote(kms)


@pytest.mark.parametrize(
    ("url", "key", "kwargs", "match"),
    [
        ("ftp://kms/", "relay", {}, "http"),
        ("http://", "relay", {}, "http"),
        ("http://kms", "../relay", {}, "name"),
        ("http://kms", "relay", {"timeout": 0}, "timeout"),
        ("http://kms", "relay", {"version": 0}, "version"),
    ],
)
def test_what_is_no_service_is_refused_before_a_request(
    url: str, key: str, kwargs: dict[str, Any], match: str
) -> None:
    with pytest.raises(ValueError, match=match):
        HttpRemoteSigner(url, key, **kwargs)


def test_signing_off_the_loop_leaves_it_running(kms: FakeKms) -> None:
    kms.create("relay")
    signer = remote(kms)
    kms.delay = 0.2

    async def main() -> tuple[float, int, list[bytes]]:
        ticks = 0
        done = asyncio.Event()

        async def tick() -> None:
            nonlocal ticks
            while not done.is_set():
                ticks += 1
                await asyncio.sleep(0.01)

        ticker = asyncio.create_task(tick())
        began = time.monotonic()
        signatures = await asyncio.gather(
            *(signer.sign_async(f"message {n}".encode()) for n in range(8))
        )
        took = time.monotonic() - began
        done.set()
        await ticker
        return took, ticks, list(signatures)

    took, ticks, signatures = asyncio.run(main())
    # Eight round trips of 200 ms at once take about one, and the loop ticked
    # all the while.
    assert took < 0.8 and ticks >= 10
    assert all(signer.verify(f"message {n}".encode(), s) for n, s in enumerate(signatures))


def test_the_operator_log_and_an_arc1_attestation_sign_through_it(
    kms: FakeKms, tmp_path: Path
) -> None:
    kms.create("operator")
    signer = remote(kms, "operator")
    keyring = Keyring({"alice": signer.public_key().spec()})
    with RecordLog(signer, log_id="ops", path=tmp_path / "ops.ilok1", keyring=keyring) as log:
        log.append(RecordKind.OPERATOR_INSTALLED, scope="ops", body={"registry": "x"})
    (record,) = RecordLog.load(tmp_path / "ops.ilok1", keyring)
    assert record.key_id == signer.key_id
    statement = Attestation(
        request=DeliveredRequest(
            message_id="m",
            effect_id="e",
            sink="mail",
            operation="send",
            payload_hash="0" * 64,
            idempotency_key="k",
        ),
        outcome=AttestedOutcome(
            attempt=1, result="delivered", status_code=200, response_digest=None, remote_ref=None
        ),
    ).sign(signer)
    statement.verify(signer.public_key())
