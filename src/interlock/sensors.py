"""Sensor facts: an analyzer's signed result on the exact diff a stage measured (1.3.0).

A checker is a pure function of the plan and the diff, which is what lets a
verdict be replayed anywhere. An analyzer is not: a policy engine, a schema
validator, IAM Access Analyzer, a scanner or a test suite reads files, calls
services, takes time. So an analyzer never runs inside a checker. It runs
beside the stage, as a *sensor*:

1. The stage measures its diff, as always.
2. The engine hands each sensor the diff, as a canonical JSON document
   (:func:`diff_document`), with the diff's hash (its
   :meth:`~interlock.types.EffectDiff.measured_hash`).
3. The sensor runs its analyzer and returns a :class:`~interlock.types.SensorFact`
   signed with the analyzer's own key: the verdict (``pass`` or ``fail``), how
   many findings, the SHA-256 of the full report, and the diff hash it saw.
4. The engine attaches the facts to the diff, which the verdict then covers.
5. :class:`SensorAttestation`, a pure checker, verifies each fact it requires:
   signed by a key the mandate pins, about this very diff, and ``pass``.

A fact binds the diff by hash, so a clean verdict on one diff can never be
replayed onto another, and a fact signed by a key the mandate does not pin is
no fact. The engine holds no analyzer key: a :class:`CommandSensor` runs the
analyzer as a separate process, which signs with a key only it can read.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from collections.abc import Callable, Iterable, Mapping, Sequence
from datetime import UTC, datetime
from typing import Any, ClassVar, Final, Protocol, runtime_checkable

from agentgov.receipts.canonical import canonical_bytes
from agentgov.receipts.signing import Keyring, Signer, Verifier, parse_key

from interlock.exceptions import StageError
from interlock.text import tally
from interlock.types import (
    EffectDiff,
    EffectPlan,
    InvariantViolation,
    SensorFact,
    Severity,
)

__all__ = [
    "CommandSensor",
    "FunctionSensor",
    "Sensor",
    "SensorAttestation",
    "diff_document",
    "sign_fact",
]

DOCUMENT_FORMAT: Final = "interlock-sensor-input/1"
"""What a diff handed to a sensor names itself."""


def diff_document(plan: EffectPlan, diff: EffectDiff) -> bytes:
    """The diff as a sensor reads it: canonical JSON of every measured row's
    before and after image, every value that could not be measured, and every
    outbound request (by payload hash), with the diff's hash as ``subject``."""
    rows = [
        {
            "table": d.table,
            "key": d.primary_key,
            "operation": d.operation,
            "tenant": d.tenant_id,
            "before": None if d.before is None else _plain(d.before),
            "after": None if d.after is None else _plain(d.after),
        }
        for d in diff.deltas
    ]
    return canonical_bytes(
        {
            "format": DOCUMENT_FORMAT,
            "subject": diff.measured_hash(),
            "plan": str(plan.plan_id),
            "scope": plan.scope_id,
            "intent": plan.intent,
            "substrate": diff.substrate_id,
            "rows": rows,
            "unknowns": [
                {"table": u.table, "key": u.primary_key, "column": u.column} for u in diff.unknowns
            ],
            "outbound": [
                {"sink": o.sink, "operation": o.operation, "payload_hash": o.payload_hash}
                for o in diff.outbound
            ],
        }
    )


def _plain(value: Any) -> Any:
    """A row image's values as canonical JSON takes them: exact numbers as
    text, so a ``Decimal`` keeps its digits."""
    if isinstance(value, Mapping):
        return {str(k): _plain(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_plain(v) for v in value]
    if isinstance(value, bool | str) or value is None:
        return value
    if isinstance(value, int) and abs(value) < 2**53:
        return value
    return str(value)


def sign_fact(
    signer: Signer,
    *,
    sensor: str,
    subject: str,
    verdict: str,
    findings: int,
    report: bytes,
    at: datetime | None = None,
) -> SensorFact:
    """An analyzer's fact on ``subject``, signed with its key."""
    if verdict not in ("pass", "fail"):
        raise ValueError(f"a sensor's verdict is pass or fail, not {verdict!r}")
    draft = SensorFact(
        sensor=sensor,
        subject=subject,
        verdict=verdict,
        findings=findings,
        detail=hashlib.sha256(report).hexdigest(),
        issued_at=(at or datetime.now(UTC)).isoformat(),
        alg=signer.alg,
        key_id=signer.key_id,
        signature="",
    )
    return SensorFact(**{**_fields(draft), "signature": signer.sign(draft.message()).hex()})


def _fields(fact: SensorFact) -> dict[str, Any]:
    return {name: getattr(fact, name) for name in SensorFact.__slots__}


@runtime_checkable
class Sensor(Protocol):
    """An analyzer the engine runs on each measured diff."""

    @property
    def name(self) -> str: ...

    def examine(self, document: bytes, subject: str) -> SensorFact:
        """Analyze ``document`` (:func:`diff_document`), whose hash is
        ``subject``, and return the signed fact.

        :raises StageError: If the analyzer cannot be run or answers nothing a
            fact can be read from. The stage is then not judged: a plan whose
            mandate needs the analyzer cannot commit without it.
        """
        ...


class CommandSensor:
    """An analyzer run as its own process: the diff document on its standard
    input, the signed fact (JSON) on its standard output. The process holds
    the signing key; the engine never sees it.

    :param name: The sensor's registered name.
    :param argv: The command, run with no shell.
    :param timeout: Seconds it may take.
    :param env: Extra environment for it, beside ``PATH`` and the locale.
    """

    __slots__ = ("_argv", "_env", "_name", "_timeout")

    def __init__(
        self,
        name: str,
        argv: Sequence[str],
        *,
        timeout: float = 30.0,
        env: Mapping[str, str] | None = None,
    ) -> None:
        if not argv:
            raise ValueError(f"sensor {name}: argv names the command to run")
        self._name = name
        self._argv = tuple(argv)
        self._timeout = timeout
        self._env = dict(env or {})

    @property
    def name(self) -> str:
        return self._name

    def examine(self, document: bytes, subject: str) -> SensorFact:
        env = {
            "PATH": os.environ.get("PATH", os.defpath),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            **self._env,
        }
        try:
            done = subprocess.run(  # noqa: S603 - operator-configured argv, no shell
                list(self._argv),
                input=document,
                capture_output=True,
                timeout=self._timeout,
                env=env,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise StageError(f"sensor {self._name} ran past its {self._timeout}s") from exc
        except OSError as exc:
            raise StageError(f"sensor {self._name} could not run: {exc}") from exc
        if done.returncode != 0:
            raise StageError(
                f"sensor {self._name} failed ({done.returncode}): "
                + done.stderr.decode("utf-8", "replace").strip()[:500]
            )
        try:
            fact = SensorFact.from_json(json.loads(done.stdout))
        except ValueError as exc:
            raise StageError(f"sensor {self._name} answered no fact: {exc}") from exc
        if fact.sensor != self._name or fact.subject != subject:
            raise StageError(
                f"sensor {self._name} answered a fact about {fact.sensor!r} on another diff"
            )
        return fact


class FunctionSensor:
    """An analyzer in this process: ``analyze(document)`` returns
    ``(verdict, findings, report)``, and ``signer`` signs the fact. For an
    analyzer whose key the operator is content to hold in the engine's process
    (a test, a demo, a check with nothing to hide).

    :param name: The sensor's registered name.
    :param analyze: The analysis.
    :param signer: The analyzer's key.
    """

    __slots__ = ("_analyze", "_name", "_signer")

    def __init__(
        self,
        name: str,
        analyze: Callable[[bytes], tuple[str, int, bytes]],
        signer: Signer,
    ) -> None:
        self._name = name
        self._analyze = analyze
        self._signer = signer

    @property
    def name(self) -> str:
        return self._name

    def examine(self, document: bytes, subject: str) -> SensorFact:
        verdict, findings, report = self._analyze(document)
        return sign_fact(
            self._signer,
            sensor=self._name,
            subject=subject,
            verdict=verdict,
            findings=findings,
            report=report,
        )


def sense(sensors: Iterable[Sensor], plan: EffectPlan, diff: EffectDiff) -> EffectDiff:
    """``diff`` with each sensor's fact on it attached."""
    sensors = tuple(sensors)
    if not sensors:
        return diff
    document = diff_document(plan, diff)
    subject = diff.measured_hash()
    facts = tuple(s.examine(document, subject) for s in sensors)
    from dataclasses import replace

    return replace(diff, sensors=diff.sensors + facts)


class SensorAttestation:
    """Requires ``sensor``'s clean, signed result on this very diff.

    Blocks when the diff carries no fact from the sensor, when no fact it
    carries is signed by one of ``keys`` and bound to the diff's
    :meth:`~interlock.types.EffectDiff.measured_hash`, or when the analyzer
    found problems (``fail``). Pure: it only verifies signatures over bytes the
    diff carries.

    :param sensor: The sensor's registered name.
    :param keys: The analyzer's public keys, as ``ed25519:<hex>`` (or
        ``hmac-sha256:<hex>`` for a shared secret): any of them may sign.
    """

    __slots__ = ("_keys", "_sensor")

    UNSET: ClassVar[Mapping[str, object]] = {}

    def __init__(self, sensor: str, keys: Iterable[str | Verifier]) -> None:
        if not sensor:
            raise ValueError("a sensor attestation names its sensor")
        parsed = tuple(parse_key(k) if isinstance(k, str) else k for k in keys)
        if not parsed:
            raise ValueError(f"sensor {sensor}: at least one key may sign its facts")
        self._sensor = sensor
        self._keys = tuple(sorted(_spec(k) for k in parsed))

    @property
    def name(self) -> str:
        return f"sensor_attestation:{self._sensor}"

    @property
    def sensor(self) -> str:
        return self._sensor

    @property
    def keys(self) -> tuple[str, ...]:
        return self._keys

    def check(self, plan: EffectPlan, diff: EffectDiff) -> tuple[InvariantViolation, ...]:
        subject = diff.measured_hash()
        keyring = Keyring(self._keys)
        facts = [f for f in diff.sensors if f.sensor == self._sensor]
        if not facts:
            return (
                self._violation(
                    f"sensor {self._sensor} attested nothing about this diff: the mandate "
                    f"needs its clean, signed result before the plan may commit",
                    {"sensor": self._sensor},
                ),
            )
        problems: list[str] = []
        for fact in facts:
            problem = _problem(fact, subject, keyring)
            if problem is not None:
                problems.append(problem)
                continue
            if fact.verdict != "pass":
                return (
                    self._violation(
                        f"sensor {self._sensor} found {tally(fact.findings, 'problem')} in this "
                        f"diff (report {fact.detail[:12]})",
                        {
                            "sensor": self._sensor,
                            "fact": fact.digest(),
                            "verdict": fact.verdict,
                            "findings": str(fact.findings),
                        },
                    ),
                )
            return ()
        return (
            self._violation(
                f"sensor {self._sensor}'s result is no fact about this diff: {problems[0]}",
                {"sensor": self._sensor, "fact": facts[0].digest()},
            ),
        )

    def _violation(self, message: str, evidence: Mapping[str, str]) -> InvariantViolation:
        return InvariantViolation(self.name, Severity.BLOCKING, message, dict(evidence))


def _problem(fact: SensorFact, subject: str, keyring: Keyring) -> str | None:
    if fact.subject != subject:
        return "it was signed for another diff"
    key = keyring.get(fact.key_id)
    if key is None:
        return f"key {fact.key_id} is not one the mandate pins for it"
    if key.alg != fact.alg:
        return f"key {fact.key_id} is {key.alg}, and the fact says {fact.alg}"
    try:
        signature = bytes.fromhex(fact.signature)
    except ValueError:
        return "its signature is not hex"
    if not key.verify(fact.message(), signature):
        return "its signature does not verify"
    return None


def _spec(key: Verifier) -> str:
    spec = getattr(key, "spec", None)
    if not callable(spec):  # pragma: no cover - every agentgov verifier has one
        raise ValueError(f"key {key.key_id} cannot be written down")
    return str(spec())
