"""Class V, predicted and verified substrates: what they owe the engine (1.4.0).

Some systems can neither stage a change nor dry-run one: a FHIR server, a SaaS
API (Salesforce, ServiceNow, Jira). What they can do is answer a read with a
version, and refuse a write conditional on a version that has moved. A class V
substrate (:mod:`interlock.fhir`) builds its guarantee from exactly that:

1. **Read the before image**, with its version (a FHIR ``meta.versionId``, a
   ``SystemModstamp``), and the rest of the record it belongs to (a patient's
   chart), which is the scope the write is verified over.
2. **Predict the after image** from the operation's semantics: a merge patch
   applied to what was read, a resource created from its template with its
   conditional references resolved by search. The prediction is an ordinary
   :class:`~interlock.types.EffectDiff`, so every checker, partition and rate
   window judges it before anything is written.
3. **Write the undo down first** (:class:`~interlock.planbound.UndoJournal`):
   each write's before image, and the scope as it was read. The engine names
   its digest in the stage's ``COMMIT_INTENT``. An undo restores the before
   image, or marks a created record void (FHIR's ``entered-in-error``); it
   never deletes one.
4. **Write conditionally**, on the version read (``If-Match``). A system that
   moved after it was measured refuses (``409``, ``412``), and nothing of the
   plan is written: a warrant only executes on the state its approvers saw.
5. **Read back and compare.** The scope is read again and held to the
   prediction. A difference is never accepted: a rule on the server that
   changed more than the plan did, a value the server rewrote. Everything the
   write changed is put back from the undo, the discrepancies are named, and
   the stage is recorded ``COMPENSATED`` (its receipt's outcome is
   ``compensated``, ARC1 1.4).
6. **Never call a sent write aborted** (1.5.2). Once a write has gone out, a
   failure of any kind (a dropped connection, a timeout, a read-back that
   cannot be read) leaves the outcome unknown, not negative. The commit raises
   :class:`~interlock.exceptions.CommitUnsettledError`, the intent stays open,
   and ``resolve_intent`` settles it: at once if the system answers, at the
   next recovery if not. It reads what the commit would have read (every
   written resource and the whole scope) and applies the same rule as step 5.

Every receipt of such a substrate's plans says ``coverage.measurement =
"predicted"``: what was judged is a prediction, made true by a conditional
write and checked by a read-back. It is weaker than plan-bound in one way that
matters, and receipts and the console say so: what a server does on a write it
was never asked to measure is caught after the write, and undone, not refused
before it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

__all__ = ["PREDICTED", "Settlement"]

PREDICTED: Final = "predicted"
"""ARC1 1.3's ``coverage.measurement`` for a predicted and verified substrate."""


@dataclass(frozen=True, slots=True)
class Settlement:
    """What a predicted substrate did when it settled a stage whose commit could not finish
    (1.5.2): a crash, a write whose answer never came, or a read-back that failed. The engine
    asks for it after ``resolve_intent`` answers ``False``, and writes it into the stage's
    ``COMPENSATED`` record.

    :ivar undo: The SHA-256 of the undo, as the commit intent named it.
    :ivar applied: How many of the stage's writes had landed.
    :ivar restored: How many resources were put back: those writes, and whatever the system
        says the stage's request set off.
    :ivar discrepancies: What the read-back found that the prediction does not say, in words.
    :ivar foreign: Resources that differ and are not the stage's to put back: named for a
        person.
    """

    undo: str
    applied: int
    restored: int
    discrepancies: tuple[str, ...] = ()
    foreign: tuple[str, ...] = ()
