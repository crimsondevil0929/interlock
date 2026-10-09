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
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Final

from agentgov.exceptions import SignerUnavailableError
from agentgov.receipts.signing import ALG_ED25519, Ed25519PublicKey

__all__ = ["HttpRemoteSigner", "RemoteSigner", "SignerUnavailableError"]

_KEY_NAME: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_SIGNATURE_BYTES: Final = 64
_MAX_ANSWER: Final = 65536
"""The most of a key service's answer that is read: a key or a signature is
far shorter."""


class RemoteSigner:
    """An Ed25519 key held elsewhere, signing through agentgov's ``Signer``
    protocol (module docstring).

    A subclass implements :meth:`_remote_key`, the version and public key to
    pin, which the constructor calls once, and :meth:`_remote_sign`.

    :raises SignerUnavailableError: If the service cannot be reached, or
        answers with anything but an Ed25519 public key.
    """

    __slots__ = ("_public", "_version")

    def __init__(self) -> None:
        version, raw = self._remote_key()
        try:
            self._public = Ed25519PublicKey(raw)
        except ValueError as exc:
            raise SignerUnavailableError(
                f"{self.describe()}: its public key is not an Ed25519 key: {exc}"
            ) from exc
        self._version = version

    # -- what a subclass implements ---------------------------------------------

    def _remote_key(self) -> tuple[int, bytes]:
        """The version to pin, and its 32-byte public key."""
        raise NotImplementedError

    def _remote_sign(self, message: bytes) -> bytes:
        """The service's signature of ``message`` with the pinned version."""
        raise NotImplementedError

    def describe(self) -> str:
        """Where the key is, for messages: never a credential."""
        return type(self).__name__

    # -- the Signer protocol ----------------------------------------------------

    @property
    def alg(self) -> str:
        return ALG_ED25519

    @property
    def key_id(self) -> str:
        """Derived from the public key as ARC1 derives it: one key, local or
        remote, has one id."""
        return self._public.key_id

    @property
    def version(self) -> int:
        """The version of the key this signer signs with."""
        return self._version

    def public_key(self) -> Ed25519PublicKey:
        return self._public

    def sign(self, message: bytes) -> bytes:
        """The service's signature of ``message``, verified here first.

        :raises SignerUnavailableError: If the service cannot be reached, or
            answers with a signature the pinned key does not verify.
        """
        message = bytes(message)
        signature = self._remote_sign(message)
        if len(signature) != _SIGNATURE_BYTES or not self._public.verify(message, signature):
            raise SignerUnavailableError(
                f"{self.describe()} answered with a signature its key {self.key_id} "
                f"(version {self._version}) does not verify: nothing is signed"
            )
        return signature

    def verify(self, message: bytes, signature: bytes) -> bool:
        return self._public.verify(message, signature)

    async def sign_async(self, message: bytes) -> bytes:
        """:meth:`sign`, on a worker thread: a coroutine's event loop never
        waits on the service."""
        return await asyncio.to_thread(self.sign, message)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(key_id={self.key_id!r}, version={self._version})"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A key service that redirects is answered as one that refused: a
    redirect could carry the credential to another host."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


class HttpRemoteSigner(RemoteSigner):
    """A key at a signing service over HTTP, in the protocol the module
    docstring describes.

    :param url: The service: ``https://host[:port][/prefix]``.
    :param key: The key's name at the service.
    :param token: Sent as ``Authorization: Bearer``; read it from the
        environment, never from a file anyone else reads.
    :param timeout: The most one request may take, in seconds.
    :param version: The version to pin; the service's latest by default.
    :raises ValueError: On a url, a key name or a timeout that is not one.
    :raises SignerUnavailableError: If the service cannot be reached, or
        does not answer with an Ed25519 key.
    """

    __slots__ = ("_key", "_opener", "_pin", "_timeout", "_token", "_url")

    def __init__(
        self,
        url: str,
        key: str,
        *,
        token: str | None = None,
        timeout: float = 5.0,
        version: int | None = None,
    ) -> None:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError(f"a signing service's url is http(s)://host[:port], not {url!r}")
        if not _KEY_NAME.fullmatch(key):
            raise ValueError(f"a key's name is letters, digits, '.', '_' and '-', not {key!r}")
        if not timeout > 0:
            raise ValueError("a signing service's timeout is positive")
        if version is not None and version < 1:
            raise ValueError("a key's version is a positive integer")
        self._url = url.rstrip("/")
        self._key = key
        self._token = token
        self._timeout = float(timeout)
        self._pin = version
        self._opener = urllib.request.build_opener(_NoRedirect)
        super().__init__()

    def describe(self) -> str:
        return f"the signing service at {self._url} (key {self._key!r})"

    def _remote_key(self) -> tuple[int, bytes]:
        query = "" if self._pin is None else f"?version={self._pin}"
        answer = self._call("GET", f"/v1/keys/{self._key}{query}", None)
        version = answer.get("version")
        public = answer.get("public_key")
        if answer.get("alg") != ALG_ED25519:
            raise SignerUnavailableError(
                f"{self.describe()} holds a {answer.get('alg')!r} key, not an Ed25519 one"
            )
        if not isinstance(version, int) or isinstance(version, bool) or version < 1:
            raise SignerUnavailableError(f"{self.describe()} names no version of its key")
        if self._pin is not None and version != self._pin:
            raise SignerUnavailableError(
                f"{self.describe()} answered for version {version}, not {self._pin}"
            )
        try:
            raw = bytes.fromhex(str(public))
        except ValueError:
            raise SignerUnavailableError(f"{self.describe()}: its public key is not hex") from None
        return version, raw

    def _remote_sign(self, message: bytes) -> bytes:
        answer = self._call(
            "POST",
            f"/v1/keys/{self._key}/sign",
            {"version": self._version, "message": base64.b64encode(message).decode("ascii")},
        )
        if answer.get("version") != self._version:
            raise SignerUnavailableError(
                f"{self.describe()} signed with version {answer.get('version')!r}, not the "
                f"pinned {self._version}: nothing is signed"
            )
        try:
            return bytes.fromhex(str(answer.get("signature")))
        except (ValueError, binascii.Error):
            raise SignerUnavailableError(
                f"{self.describe()} answered with a signature that is not hex"
            ) from None

    def _call(self, method: str, path: str, body: dict[str, Any] | None) -> dict[str, Any]:
        data = None if body is None else json.dumps(body).encode()
        # http or https only: the constructor refuses any other scheme.
        request = urllib.request.Request(self._url + path, data=data, method=method)  # noqa: S310
        request.add_header("Accept", "application/json")
        if data is not None:
            request.add_header("Content-Type", "application/json")
        if self._token:
            request.add_header("Authorization", f"Bearer {self._token}")
        try:
            with self._opener.open(request, timeout=self._timeout) as response:
                raw = response.read(_MAX_ANSWER)
        except urllib.error.HTTPError as exc:
            raise SignerUnavailableError(
                f"{self.describe()} answered {exc.code} {exc.reason}"
            ) from None
        except (urllib.error.URLError, OSError) as exc:
            raise SignerUnavailableError(f"{self.describe()} could not be reached: {exc}") from exc
        try:
            answer = json.loads(raw)
        except ValueError:
            raise SignerUnavailableError(f"{self.describe()} answered with no JSON") from None
        if not isinstance(answer, dict):
            raise SignerUnavailableError(f"{self.describe()} answered with no JSON object")
        return answer
