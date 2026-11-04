"""Where the real systems are, for the tests that run the substrates against
them rather than against the loopback stand-ins (:mod:`interlock.sim`).

Each is named by an environment variable; without it, its tests are skipped,
unless ``INTERLOCK_REQUIRE_REAL=1``, which turns the skip into a failure. CI
sets it in the job that starts the systems, so a system that did not come up
cannot pass by skipping.

- ``INTERLOCK_TEST_TOFU``: the ``tofu`` (or ``terraform``) command.
- ``INTERLOCK_TEST_K8S_SERVER``, ``INTERLOCK_TEST_K8S_TOKEN`` and
  ``INTERLOCK_TEST_K8S_CA``: a Kubernetes API server (a ``kind`` cluster),
  a service account's bearer token with rights over one namespace, and the
  cluster's CA certificate file.
- ``INTERLOCK_TEST_FHIR_URL``: a FHIR R4 server's base URL (HAPI FHIR).
"""

from __future__ import annotations

import os

import pytest

REQUIRE_VAR = "INTERLOCK_REQUIRE_REAL"


def need(*names: str) -> tuple[str, ...]:
    """The values of ``names``, or skip (or fail, when required)."""
    found = tuple(os.environ.get(n, "") for n in names)
    missing = [n for n, v in zip(names, found, strict=True) if not v]
    if missing:
        if os.environ.get(REQUIRE_VAR) == "1":
            pytest.fail(f"{REQUIRE_VAR}=1 but {', '.join(missing)} is not set")
        pytest.skip(f"set {', '.join(missing)} to run against the real system")
    return found
