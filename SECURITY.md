# Security

Interlock holds write-path credentials to the database an agent's effects land in, and
the credentials of the outside APIs its relay calls. This document states what it keeps,
where that lands, what it signs and what detects a change, and what it does not claim,
so a platform or security team can decide without reading the source.

## Reporting a vulnerability

Please report a suspected vulnerability privately rather than in a public issue: open a
[GitHub security advisory](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
on this repository. Expect an acknowledgement within a week.

Include a reproduction and the Interlock version (`pip show interlock-escrow`). If the issue
involves production rows or payloads, redact them: the report should not be the leak.

Fixes land on `main` and ship in the next 1.x release. There is no backport branch for
earlier releases.

| Version | Supported |
|---|---|
| 1.0.x (latest) | yes |
| < 1.0 | no |

## Data map: what is stored, and where

| Where | What it holds | Row data, payloads or secrets? |
|---|---|---|
| The escrow chain (`chain_path`, a JSONL file) | One record per escrow event: plan id, stage id, record type, the SHA-256 of the artifact it attests, the AgentGov head it observed, a hash link | **No.** Digests, not rows (`interlock/chain.py`) |
| The application database, while a stage is open | Interlock's capture table, the before and after images of the rows a plan changed | **Yes, transiently**, in the database it already lives in; rolled back with the stage or committed with it |
| Commit markers (`_interlock_commits` on SQLite; the stage row on PostgreSQL) | One marker per committed stage, written in its transaction | No |
| The outbox (SQLite file or the `interlock` schema) | Each outside request's payload, until it is delivered and vacuumed, its idempotency key and its delivery log | **Payloads, yes**: the relay needs them to deliver. Sink credentials, no |
| The inbox | A verified webhook's body, signature and body hash; the facts projected from it | **The body, yes**, in the columns made for it only |
| ARC1 receipts (an AgentGov `ReceiptLog`) | A signed receipt per adjudicated plan, naming its terminal chain record | No |
| ILOK1 logs (operators, relays, the recovery runtime) | Signed records of operator acts, relay outcomes, quotes and grants | No payloads; the reasons operators type |
| Configuration (`interlock.toml`) | Sink credentials, webhook secrets, key paths or KMS key ids | **Secrets, yes**: protect the file as you protect the database credential |

`scripts/security_audit.py` checks these claims on both stores: it plants canaries in a
webhook's body and headers, its signing secret, a sink's API key and a plan's trace
context, records the input of every hash and signature Interlock and AgentGov compute,
crawls every column and file, and fails if a canary reaches a hash or a column not made
for it (`docs/EPIC8_DESIGN.md` §4).

## Trust boundaries

- **The agent holds no credentials.** It proposes a plan; Interlock stages it on a
  database role it controls, measures the effect from the database, and commits or rolls
  back that same transaction.
- **The stage role is the boundary that matters.** Grant it exactly the observed tables.
  The SQLite authorizer and the admission checks in [Scope](README.md#scope) are a second
  boundary in front of the database's own grants, not a replacement for them.
- **Every operator act is signed** (ILOK1), by a key the operators' registry names; a
  revoked key is sealed out (`docs/EPIC8_DESIGN.md` §2). Keys may be held by a signing
  service or AWS KMS.
- **What an outside system reports back is its signed word** (the inbox), bound to the
  request, never a measurement.

## What it does not claim

The README's [Scope](README.md#scope) section lists, item by item, what Interlock is not
yet a boundary against, each reproduced against the shipped code. The short version:

- The escrow chain is keyless: whoever can write its file can rewrite it consistently.
  Receipts (signed, under a key the chain file does not hold) and an AgentGov anchor are
  the copies outside it.
- Value guards are one-directional, `StatedFootprint` is cooperative, and every threshold
  in `default_checkers` is a placeholder to calibrate.
- An outside effect's delivery is at least once, recorded and bounded, made exactly once
  by the receiver's idempotency key. What the outside system then does is not measured.
- Interlock does not scan prompts or tool output for injected instructions or leaked
  data. That is a gateway's job; Interlock judges the consequence.
