"""Signers whose private key lives elsewhere (``docs/EPIC8_DESIGN.md`` §1).

A relay, the inbox, the operator log and the receipt log sign through
agentgov's ``Signer`` protocol: ``alg``, ``key_id``, ``sign(message)`` and
``verify(message, signature)``. :class:`RemoteSigner` implements it for an
Ed25519 key a key service holds (a cloud KMS, an HSM, Vault's transit engine),
so the process never holds the private key: it holds the key's name at the
service, the version it pinned, the public half, and a credential.

Every signature the service hands back is verified under the pinned public key
before it is returned. A service that signs with another key, or another
version, or answers with anything but a signature, fails the call with
``SignerUnavailableError``: what it answered never becomes an attestation that
does not verify.

A signer pins one version of its key when it is built and signs with that
version only. Records and attestations name the key before they are signed, so
the key behind a ``key_id`` cannot change between the two. A rotated key is a
new signer: the daemon builds one when a part opens (§3).

:class:`HttpRemoteSigner` speaks a minimal protocol, shaped like Vault's
transit engine::

    GET  {url}/v1/keys/{name}[?version=N]  -> {"alg": "ed25519", "version": N,
                                               "public_key": "<hex>"}
    POST {url}/v1/keys/{name}/sign          <- {"version": N, "message": "<base64>"}
                                             -> {"version": N, "signature": "<hex>"}

with ``Authorization: Bearer <token>`` when it has a token. An adapter for
another service implements :meth:`RemoteSigner._remote_key` and
:meth:`RemoteSigner._remote_sign`.

These are agentgov's own classes (``agentgov.receipts.signing``), which began
here and moved there in agentgov 1.0, unchanged: an ``isinstance`` check, a
subclass and a ``key_id`` mean the same under either name.
:class:`AwsKmsSigner` (``agentgov.receipts.kms_aws``) is one for a key AWS KMS
holds, with ``boto3`` (the ``kms-aws`` extra). KMS signs at most 4096 bytes, so
it signs at signature version 2, a digest, whatever the document's size: ARC1
documents (a relay's attestations, the receipt log) and ILOK1 records (the
operator log, the vacuum's records in it, a recovery's and a budget guard's).
An inbound statement (the inbox's) is signed whole, so through it each must stay
within those 4096 bytes.
"""

from __future__ import annotations

from agentgov.exceptions import SignerUnavailableError
from agentgov.receipts.kms_aws import AwsKmsSigner
from agentgov.receipts.signing import HttpRemoteSigner, RemoteSigner

__all__ = ["AwsKmsSigner", "HttpRemoteSigner", "RemoteSigner", "SignerUnavailableError"]
