# The systems Interlock stages on

How Interlock stages, measures and commits on each kind of system, beyond the SQLite of the [README](../../README.md): PostgreSQL, Git, Kubernetes and Terraform, FHIR servers, and outbound requests through the transactional outbox; and the daemon that runs every part in one process. The engine itself is in [GUIDE.md](../GUIDE.md). Every Python block here runs in CI.

## PostgreSQL

`PostgresSubstrate` stages each plan in a `REPEATABLE READ` transaction and measures it with
row triggers installed once, so no stage ever alters a busy table. Install as the tables'
owner, then stage as a separate role granted DML on the observed tables and nothing else:

```bash
uv pip install 'interlock[postgres]'
interlock install --config interlock.toml --database postgresql://owner@db/app
interlock check   --config interlock.toml --database postgresql://interlock_agent@db/app
```

```toml
substrate = "postgres"
schema = "public"
stage_roles = ["interlock_agent"]   # granted the interlock schema's stage functions
acknowledge_cascades = []

[[tables]]
name = "orders"
columns = ["id", "tenant", "total"]
tenant_column = "tenant"
```

<!-- readme-test: skip reason="needs a live PostgreSQL server" -->
```python
from interlock import EscrowEngine, PlanBuilder, PostgresSubstrate, TableSpec, default_checkers

substrate = PostgresSubstrate(
    "postgresql://interlock_agent@db/app",
    tables=[TableSpec("orders", columns=["id", "tenant", "total"], tenant_column="tenant")],
)
engine = EscrowEngine(substrate, checkers=default_checkers(row_limit=8))
plan = (
    PlanBuilder("support-agent")
    .update(
        table="orders",
        statement="UPDATE orders SET total = %(total)s WHERE id = %(id)s",
        parameters={"total": 100, "id": 1},
    )
    .build()
)
result = engine.execute(plan)
```

What `interlock install` puts in the database: an `interlock` schema holding the stage
table and four functions, and on each observed table one `AFTER` row trigger plus one
`TRUNCATE` trigger, both `ENABLE ALWAYS` so `session_replication_role` does not switch them
off. For a transaction that opened no stage, the trigger logs the write to
`interlock.unmediated` (see [Unrecorded writes](GUIDE.md#unrecorded-writes)). For one that did, it
writes before and after images into a temporary table that exists only in that session for
that transaction. Rows are keyed to the stage by `pg_current_xact_id()`, read from a row
that only the stage-opening function can write. They aren't keyed by the
`interlock.stage_id` setting, which any statement could change. The setting is still set,
and the trigger refuses to continue when the two disagree.

Every stage checks, before its first effect and with the observed tables locked
`ROW EXCLUSIVE` so none of it can change underneath:

- each observed table carries Interlock's triggers, enabled always, capturing exactly
  its `TableSpec`'s columns, and has no inheritance children or partitions (a statement
  on the parent writes their rows too, through no trigger, and PostgreSQL checks
  privileges on the parent alone);
- the stage's role isn't a superuser, owns no observed table (an owner can disable a
  trigger), and can't write any other table, whether directly, through a column grant, or
  through a role it belongs to. PostgreSQL has no statement authorizer, so grants are the
  table boundary, and the substrate checks them instead of trusting them.
  `enforce_table_access=False` trusts them;
- the cascade check, read from `pg_constraint`.

What differs from SQLite:

- **Placeholders are psycopg's:** `%(name)s`, and `%%` for a literal percent sign.
- **Only row statements stage:** `SELECT`, `INSERT`, `UPDATE`, `DELETE`, `MERGE`,
  `WITH`, `VALUES`, `TABLE`. Each is sent by the extended query protocol, as one unnamed
  statement, which the server will not split, so `UPDATE ...; COMMIT` fails instead of
  committing before adjudication. Nothing is prepared on the server.
- **A cascade gate fires per row.** A delete of a gated row, or an update that changes a
  gated key, is refused inside the statement and PostgreSQL rolls the statement back,
  cascade included. SQLite refuses when it prepares the statement.
- **`NUMERIC` is read as `Decimal`**, exactly.
- **Bounds are the server's:** `statement_timeout`, `lock_timeout` and
  `idle_in_transaction_session_timeout` are set for the stage and re-set before every
  effect, so a statement cannot lift them, and a stage whose client died cannot hold locks
  past `max_stage_seconds`.
- **Crash recovery reads the transaction.** The stage's row is its commit marker, and
  `pg_current_xact_id()` is written into the commit intent, so recovery can tell a
  transaction the server still has open (a crashed client's, until its session times out,
  or one still committing when its client died) from one that rolled back, and leaves the
  first open. A connection lost with `COMMIT` in flight is answered from the same marker.
  PostgreSQL stops `statement_timeout` before running a commit's deferred triggers, so
  work there is bounded by the stage's `lock_timeout` and not by its statement bound.

**Behind a connection pooler.** A stage holds its connection for its whole life, and reads
the rate windows on a second connection in `READ COMMITTED`, because its own snapshot can't
see what other plans committed after it began. With PgBouncer in transaction mode, give the
stage role's pool at least one connection more than `[engine] workers`. Then a window read
waits only for other window reads, never for a commit. A pool no larger is slow but never
stuck. The second connection has to be obtained within `[engine] pool_timeout_seconds` (the
lock timeout by default). When it can't be, the stage is aborted with `PoolExhaustedError`
(a `StageConflictError`), its locks and connection are released, and the daemon's engine
pool stages the plan again. The read is one transaction that sets nothing beyond itself,
and nothing is prepared, so PgBouncer needs no `max_prepared_statements` and no client
inherits another's session.

Some things grants can't see, so the substrate can't either: a `SECURITY DEFINER` function
the role may call that writes elsewhere, an extension such as `dblink` that opens another
connection, and large objects. Don't grant them to the stage role. PostgreSQL 14 or later
is required, and CI runs 16.

## Git: the same guarantee on a branch

`GitSubstrate` stages a plan on a Git branch with the same guarantee the SQL substrates
give: what commits is exactly what was measured, or nothing commits. It needs only the
`git` command.

- **Stage.** Each plan gets a worktree of its own at the branch's head, its *base*.
- **Apply.** Effects edit files there. The repository's hooks run after each effect, the way
  triggers run after a statement: a code generator, a formatter, a lockfile refresh.
- **Measure.** Git diffs everything in the worktree against the base. A file a hook wrote is
  measured exactly like a file the plan wrote.
- **Commit.** The commit is `git update-ref <branch> <new> <base>`, a compare-and-swap. If
  anything moved the branch while the plan was staged (a push, a merge, another stage), the
  branch stays where it is and nothing commits.

<!-- readme-test: skip reason="needs a bare Git repository; tests/test_git_substrate.py makes the same calls on one" -->
```python
from interlock import BlastRadius, EscrowEngine, NoDelete, PlanBuilder, TableAllowlist
from interlock.git_substrate import GitHook, GitSubstrate

repo = GitSubstrate(
    "/srv/git/billing-service.git",
    branch="main",
    hooks=[
        GitHook(
            "codegen",
            ("python", "tools/codegen.py"),
            when=("src/billing/api/schema.json",),
            sources=("tools/codegen.py",),
        )
    ],
)
engine = EscrowEngine(
    repo,
    checkers=[
        BlastRadius(12),
        TableAllowlist(["src", "tests", "docs"]),
        NoDelete(),
    ],
)
plan = (
    PlanBuilder("repo-agent")
    .update(
        table="src",
        statement="replace :path :old :new",
        stated_rows=1,
        parameters={"path": "src/billing/invoice.py", "old": "x * 1", "new": "round(x, 2)"},
    )
    .build()
)
engine.execute(plan)
```

Or configure it in `interlock.toml`, as SQLite and PostgreSQL are. `database` then names
the control database, a SQLite file for the outbox, the inbox and window history (see
below). `interlock install` sets it up, `interlock check` reads the branch's head through
the substrate, and `EscrowRuntime.from_config`, the daemon and Fiduciary's service all stage
on the repository:

```toml
substrate = "git"
database = "control.db"

[git]
repository = "billing-service.git"   # relative to this file
branch = "main"
workspace = "billing-service"

[[git.hooks]]
name = "codegen"
argv = ["python", "tools/codegen.py"]
when = ["src/billing/api/schema.json"]
sources = ["tools/codegen.py"]
```

The tables are the path classes, so a Git configuration lists no `[[tables]]`. A
`[[windows]]` `row_sum` names a class and a column, such as `src` and `lines_added`. Give
`[[git.classes]]` to replace the default classes. `interlock reconcile-effects --since
<commit>` reconciles the branch.

**What the checkers see.** Each changed path is one measured row:

- the *table* is the path's class: `workflows` (`.github/workflows/**`), `governance`
  (`CODEOWNERS`, `SECURITY.md`, `LICENSE`), `infra`, `deps` (`pyproject.toml`, `uv.lock`,
  `package-lock.json` and their kin), `tests`, `src`, `docs`, and `other` for any path no
  rule names. The globs are configurable (`PathClass`).
- the *primary key* is the path;
- the *partition* is the repository, or the owner a rule names for the path.

Each row records `path`, `blob_sha`, `mode`, `lines_added`, `lines_deleted`, `net_lines`
and `secret_markers`. The last is how many credential-shaped strings the change adds: cloud
and package-registry tokens, private keys, a CI workflow reading a secret, and long
high-entropy strings. Only the count is kept, never the text.

So every built-in checker works unchanged:

- `TableAllowlist` keeps a plan out of workflow files;
- `NoDelete` refuses a deleted test;
- `BlastRadius` and `StatedFootprint` catch the 35 files a code generator rewrote after a
  one-line edit;
- `FactAgreement` holds a dependency change to CI's signed result for exactly the bytes
  being written.

**Statements.** A statement is one operation, with `:parameters` or `'quoted'` literals.
That means a tool binding can pin it the way it pins SQL:

| Statement | Does |
|---|---|
| `write :path :text` | creates or replaces a file |
| `replace :path :old :new` | replaces the one occurrence of `old` (it fails on none, or on more than one) |
| `delete :path` | removes a file |
| `mode :path :mode` | sets `100644` or `100755` |
| `patch :diff` | applies a unified diff (no renames, links or submodules) |
| `expect-head :commit` | refuses unless the branch is at that commit |

`expect-head` pins a plan to the commit its approvers reviewed. A warrant over such a plan
commits onto that exact commit or not at all.

A path is refused if it is absolute, has a `..` component, reaches into `.git`, or passes
through a symbolic link. A plan may not write a file a hook runs (`GitHook.sources`).

**Recovery and reconciliation.**

- Each commit carries the trailer `Interlock-Stage: <stage id>`. `resolve_intent` reads the
  branch's history for it, so a crash between the commit intent and its record is settled
  exactly.
- Savepoints are trees, so `EscrowEngine.repair` searches sub-plans on Git as it does on
  SQL.
- `reconcile_git(substrate, records, since=...)` names every commit on the branch that no
  stage made, and a force-push that rewrote the branch.

**The control database.** Rate windows, the outbox and the inbox need a transactional home
that Git does not have. Pass `control=` a SQLite file that `interlock install` set up. A
stage then writes its requests, the facts it consumes and its window history there, and
the branch moves inside that transaction, just before it commits. A redo record is written
to disk before the branch moves. If the process dies between the two commits, the next
stage or `EscrowEngine.recover()` finishes the database's half, exactly when the branch
holds the commit.

**Limits.**

- A hook is operator code. It runs in the stage's worktree, with a timeout and a scrubbed
  environment (no variable of the process reaches it but `PATH`), and it can reach anything
  the process can.
- Point the substrate at a bare repository, or at a branch no worktree has checked out.
  Moving a checked-out branch would leave that worktree behind, so the substrate refuses.
- A commit that a force-push later removes from the branch reads as not committed to
  recovery, unless a control database recorded it. Reconciliation names the rewrite.

## A directory: the same guarantee on a workspace (1.5.0)

`FilesystemSubstrate` stages an agent's file changes on an ordinary directory: a checkout a
coding agent works in, a service's `config/`, a `deploy/` folder. The guarantee is the SQL
one: what commits is exactly what was measured, or nothing commits.

- **Stage.** `open` copies the workspace into a stage of its own and hashes every file. Those
  hashes are the stage's *base*.
- **Apply.** Effects edit the copy, never the workspace. Hooks you configure (a formatter, a
  code generator) run in the copy after each effect.
- **Measure.** The copy is walked and compared with the base, file by file. Each changed file
  is a row: its path class is the table (`secrets` for `.env`, `.ssh/` and key files, then
  `workflows`, `governance`, `infra`, `deps`, `scripts`, `tests`, `src`, `config`, `docs`,
  `other`), and its columns are `sha256`, `mode`, `bytes`, `lines_added`, `lines_deleted`,
  `net_lines` and `secret_markers`. `TableAllowlist`, `NoDelete` and `BlastRadius` read it
  as they read rows.
- **Commit.** Under the workspace's commit lock, every file the diff touches must still be at
  its base hash. If a person or another agent edited one in the meantime, nothing is written.
  Then, with `mode="in-place"`, each file is written beside its target and renamed over it,
  the set journaled first so a crash part-way is finished by the next stage. With
  `mode="swap"`, the workspace is a link to a version directory: the stage's copy becomes the
  next version and one `rename(2)` of the link switches every reader at once. Old versions
  are kept for rollback (`keep_versions`). `prepare_swap` converts a plain directory.

<!-- readme-test: skip reason="needs a workspace on disk; tests/test_filesystem.py makes the same calls" -->
```python
from interlock import BlastRadius, EscrowEngine, NoDelete, PlanBuilder, TableAllowlist
from interlock.filesystem import FilesystemSubstrate

workspace = FilesystemSubstrate(
    "/srv/billing",
    ignore=["node_modules/**", ".venv/**"],
    control="/var/lib/interlock/control.db",
)
engine = EscrowEngine(
    workspace, checkers=[BlastRadius(10), TableAllowlist(["config", "docs"]), NoDelete()]
)
plan = PlanBuilder("ops-agent", intent="raise the checkout timeout").update(
    table="config",
    statement="replace 'config/service.toml' :old :new",
    parameters={"old": "timeout_ms = 2500", "new": "timeout_ms = 4000"},
    stated_rows=1,
)
result = engine.execute(plan.build())
```

Statements are `write`, `append`, `replace`, `delete`, `move`, `mode` and `expect-hash` (pin a
file to the hash the approvers saw). A path that is absolute, holds `..`, reaches into `.git`,
passes through a symbolic link, is ignored, or is a hook's source is refused before anything
is staged. It's configured in `interlock.toml` as `substrate = "filesystem"` with
`[filesystem]`. In-place mode is atomic per file and crash-consistent as a set; a reader can
see some files new and others old for the moment the commit takes. Use `swap` when readers
must see one tree or the other.

## Kubernetes and Terraform: plan-bound

A cluster and a Terraform configuration cannot be staged in a transaction and rolled back.
They can be measured exactly, though, and the change applied on the condition that nothing
moved. Interlock calls that *plan-bound*: what was measured is the plan that is applied, on
the state it was measured on, and a partial failure is put back from an undo written down
before the first write. Every receipt of such a plan says `coverage.measurement =
"plan-bound"`, never `transactional`.

`KubernetesSubstrate` measures with the API server's own dry run:

- **Stage.** Each effect reads its object live, with its `resourceVersion`, and changes it as
  its statement says: `scale`, `set` (one field), `merge-patch`, `apply` (a whole manifest),
  `delete`, or `expect-version` (pin the version approvers saw).
- **Measure.** The changed object goes to the API server with `?dryRun=All`. Defaults, every
  mutating admission webhook and every validating one run as on a real write, and what comes
  back is the after image. A webhook that turns 6 replicas into 60 is measured as 60. A
  webhook declaring side effects makes the API server refuse the dry run, so a change whose
  admission cannot be measured never stages.
- **Forced replacements.** A change to an immutable field is refused, or, on a kind marked
  `replace_on_immutable` (a GitOps sync with `Replace=true`), measured as the deletion and
  creation the sync would do. `NoDelete` sees the deletion.
- **Commit.** Each object is written on the version measured, with the annotation
  `interlock.io/stage-id`. If anything wrote it since, the API server answers
  `409 Conflict` and nothing is applied. An object that lands other than measured, or a
  write that fails part way, is put back from the undo, and the stage is `COMPENSATED`.

<!-- readme-test: skip reason="needs a cluster; tests/test_kubernetes.py makes the same calls on interlock.sim.kubernetes" -->
```python
from interlock import BlastRadius, EscrowEngine, KubeKind, KubernetesSubstrate, NoDelete

cluster = KubernetesSubstrate(
    "https://10.0.0.1:6443",
    token=open("/var/run/secrets/remediator/token").read().strip(),
    ca_file="/var/run/secrets/remediator/ca.crt",
    namespaces=["prod-east"],
    journal="/var/lib/interlock/undo",
    kinds=[
        KubeKind(
            "deployments",
            "deployments",
            "Deployment",
            group="apps",
            columns={
                "replicas": "spec.replicas",
                "vcpu": "spec.replicas * spec.template.spec.containers.0.resources.requests.cpu",
            },
        ),
        KubeKind(
            "statefulsets",
            "statefulsets",
            "StatefulSet",
            group="apps",
            columns={"storage": "spec.volumeClaimTemplates.0.spec.resources.requests.storage"},
            replace_on_immutable=True,
        ),
    ],
)
engine = EscrowEngine(cluster, checkers=[BlastRadius(20), NoDelete(())])
```

`TerraformSubstrate` (Terraform or OpenTofu) measures with a saved plan. Effects `set` input
variables, and the stage runs `plan -out` and reads `show -json`. Each entry of
`resource_changes` is a row of its resource type's table (`TfResource`). A replacement is a
deletion plus an insertion, and a resource whose type no table names is measured in
`resources`. An observed attribute that the provider only knows after the apply is an
`UnknownValue`, which `TruncationGuard` refuses unless that column is acknowledged
(`TruncationGuard(acknowledged_unknown={"db_instances.endpoint"})`). The commit checks the
state's `serial` and `lineage` and applies exactly the saved plan. The stage's id reaches
the state as the `interlock_stage_id` output, which the configuration has to declare.

Both are configured in `interlock.toml` (`substrate = "kubernetes"` with `[kubernetes]` and
`[[kubernetes.kinds]]`, `substrate = "terraform"` with `[terraform]` and
`[[terraform.resources]]`). `interlock.sim` has a loopback API server, with webhooks called
over HTTP and an audit log, and a stand-in `terraform` command: CI stages class P with no
cloud credentials.

## FHIR servers: predicted and verified

A FHIR server (an EHR's API) can't hold a transaction open or dry-run a write. It does keep
a version on every resource, and it supports conditional writes. Interlock builds a
guarantee from those that it calls *predicted and verified*. The checks judge a
prediction of the change. The write is conditional on the version that was read, and a
read-back afterwards confirms the result matches the prediction. Every receipt for such a
plan says `coverage.measurement = "predicted"`.

`FhirSubstrate`:

- **Stage.** Each effect reads the resources it touches live, with their `meta.versionId`.
  The first time a stage reaches a patient, it reads that patient's whole chart (every
  observed type, `[type]?patient=<id>`). `create` builds a resource from a template whose
  `":name"` values are the effect's parameters. Each conditional reference
  (`Encounter?location=:bed&status=in-progress`) is resolved by a search that must find
  exactly one match. `patch` applies a JSON merge patch, and `expect-version` pins a
  version.
- **Judge.** The predicted change is the diff that every checker, partition and window
  judges. That happens before anything is written, so an order that resolves to the wrong
  patient is refused before the server sees it.
- **Undo first.** Each effect declares its undo (`void <table>` for a create, `restore
  <table>` for a patch). The undo journal gets every before image, and the charts as read,
  before the first write. A created record is undone by marking it `entered-in-error`, never
  by deleting it.
- **Write.** The charts are read again. If anything changed since the stage read it, such
  as a clinician's edit while the plan waited for a warrant, the commit is refused and
  nothing is written. Each update carries `If-Match`, so a change in the last instant gets
  `412 Precondition Failed`. Every write carries the stage's id, in `meta.tag` and in
  `X-Request-Id`, which the server's `AuditEvent` log records.
- **Read back.** The charts are read once more and compared with the prediction. Any
  difference, such as a server rule that stopped the encounter's other orders or a dose it
  rewrote, means everything the write changed is put back and the discrepancies are named.
  The stage is recorded as `COMPENSATED`, with receipt outcome `compensated` (ARC1 1.4), so
  `agentgov reconcile-actions --format fhir-auditevent` ties both the write and its undo to
  that receipt.

<!-- readme-test: skip reason="needs a FHIR server; tests/test_fhir.py makes the same calls on interlock.sim.fhir" -->
```python
from interlock import BlastRadius, EscrowEngine, FhirSubstrate, FhirType, TenantIsolation

ehr = FhirSubstrate(
    "https://ehr.example.org/fhir",
    token=open("/var/run/secrets/med-rec/token").read().strip(),
    journal="/var/lib/interlock/undo",
    control="/var/lib/interlock/control.db",
    types=[
        FhirType(
            "medicationrequests",
            "MedicationRequest",
            columns={
                "status": "status",
                "dose_mg": "dosageInstruction.0.doseAndRate.0.doseQuantity.value",
            },
            partitions={"facility": "dispenseRequest.performer.reference"},
        ),
        FhirType("tasks", "Task", columns={"status": "status"}, tenant="for.reference"),
    ],
)
engine = EscrowEngine(ehr, checkers=[BlastRadius(12), TenantIsolation(declared=True)])
```

It's configured in `interlock.toml` as `substrate = "fhir"` with `[fhir]` and
`[[fhir.types]]`. `interlock.sim.fhir` is a loopback FHIR R4 server (versions, `If-Match`,
search with `_has`, rules that write as the server, and an `AuditEvent` log), so CI stages
class V without an EHR. Class V can't see a server rule before the write. The rule's effect
is caught by the read-back and undone, not refused in advance, and the receipt's class says
so. The server has to allow client-assigned ids, so that a create can be predicted exactly.

Since 1.5.2 a commit that cannot finish is never recorded as aborted once a write has gone
out. The intent stays open and is settled by reading the whole chart back, at once or at the
next `recover()`, as [the REST section](#rest-apis-ticketing-crm-and-hr-systems-predicted-and-verified-150)
describes. The undo journal now holds each chart resource whole, so recovery can put back
an order that a server rule changed and the stage did not write.

## REST APIs: ticketing, CRM and HR systems, predicted and verified (1.5.0)

`RestSubstrate` gives any JSON REST API the FHIR substrate's class V guarantee. It needs two
things most SaaS APIs have: a version on each resource (an `ETag`, or a `version` field) and
writes that can be made conditional on it.

- **Stage.** Each effect reads the resource it touches, with its version. The first time a
  stage reaches a tenant (an account, an organization), it lists every observed resource of
  that tenant (`/tickets?account_id=<id>`, page by page): the scope the write is checked over.
- **Judge.** `create` builds a resource from a template at an id the stage assigns; `patch`
  applies a JSON merge patch. The prediction is the diff every checker judges.
- **Write.** The undo goes to the journal first. The tenant is listed again: if anything in it
  changed, nothing is written. Each write carries the version read (`If-Match`, or the version
  field in the body) and the stage's id (`X-Request-Id`, or a header you name).
- **Read back.** The tenant is listed once more and compared with the prediction. If an
  automation in the system did more than the plan (escalated the ticket, reassigned it,
  opened an incident), everything the write changed is put back and the stage is recorded
  `COMPENSATED`. With `source` naming the field where the API records the request that last
  wrote a resource, a rule your write set off is put back and a person's change is left alone
  and named.
- **When the commit cannot finish (1.5.2).** Once a write has been sent, a failure no longer
  says whether it landed: the connection dropped, the write timed out, or the read-back
  could not be read. The stage is then *unsettled*, never aborted. The commit intent stays
  open on the chain and the undo stays in the journal. The engine settles it at once if the
  API answers, and `recover()` settles it at the next start if not. Either way the
  settlement does the whole read-back: every resource the stage writes, and every tenant
  it listed. As predicted, the stage is recorded `COMMITTED`. Anything else, and what the
  stage wrote is put back (with whatever `source` says its request set off) and it is
  recorded `COMPENSATED`. A resource someone else has written since, or one that cannot be
  put back, leaves the intent open for a person, with a warning that names it.

Two bounds keep one bad answer from taking the process down, both settable under `[rest]`:

| Setting | Default | What it bounds |
|---|---|---|
| `max_response_bytes` | 10485760 (10 MiB) | The longest answer read. A longer one is refused, not read. |
| `max_pages` | 1000 | How many pages one listing follows. A next link that leads back to a page already read is refused whatever this is. |

Recovery after a long outage is deliberately strict. It applies the commit's own rule, so
a neighbor that anyone changed while the process was down counts as a difference, and the
stage's write is put back. The agent can run the plan again against the account as it is now.

<!-- readme-test: skip reason="needs an API; tests/test_rest.py makes the same calls on interlock.sim.rest" -->
```python
from interlock import BlastRadius, EscrowEngine, RestResource, RestSubstrate, TenantIsolation

desk = RestSubstrate(
    "https://desk.example.com/api",
    token=open("/var/run/secrets/support-agent/token").read().strip(),
    journal="/var/lib/interlock/undo",
    resources=[
        RestResource(
            "tickets",
            "/tickets",
            columns={"status": "status", "priority": "priority", "assignee": "assignee"},
            tenant="account_id",
            managed=("updated_at", "version"),
            source="last_request",
            void={"status": "deleted"},
        ),
    ],
)
engine = EscrowEngine(desk, checkers=[BlastRadius(5), TenantIsolation(declared=True)])
```

It's configured in `interlock.toml` as `substrate = "rest"` with `[rest]` and
`[[rest.resources]]`. `interlock.sim.rest` is a loopback API with ETags, conditional `PATCH`
and `PUT`, paged lists, automation rules that write as the system, and an audit log, so CI
stages REST writes without a vendor account. An API must accept client-assigned ids (or an
external-id upsert path) for a create to be predicted exactly.

### Sensor facts: an analyzer's word on the exact diff

A checker is a pure function of the plan and the diff, so it cannot call a policy engine, a
scanner or a test suite. A *sensor* can. The engine shows each measured diff to its sensors
(`EscrowEngine(sensors=...)`), and each signs a `SensorFact` with its own key: its verdict,
its findings, the digest of its report, and the hash of the diff it read. The pure
`SensorAttestation` checker then requires a clean fact from a key the policy pins. A fact
about a different diff, or one signed by a different key, doesn't count.

<!-- readme-test: skip reason="needs an analyzer command; tests/test_sensors.py runs one" -->
```python
from interlock import CommandSensor, EscrowEngine, SensorAttestation

policy = CommandSensor("policy-check", ["policy-check", "--key", "/etc/policy-check/key"])
engine = EscrowEngine(
    cluster,
    checkers=[SensorAttestation("policy-check", ["ed25519:3b6a27bc..."])],
    sensors=[policy],
)
```

### Pinned checker packs

A domain whose invariant can't be built from the built-in checkers ships a pack: a module
that names `PACK_VERSION` and `CHECKERS`. `load_pack(PackPin(module, version, digest))`
loads it only if the installed code is exactly the pinned code (the digest covers every file
in the package). Otherwise it says why: not installed, a different version, or tampered.

### Tested against the real systems

The loopback stand-ins in `interlock.sim` make the unit tests fast and let them inject
faults. CI also runs each substrate against the real system:

- the OpenTofu CLI (1.13.2), with plans of its built-in `terraform_data`, so no provider is
  downloaded;
- a Kubernetes 1.37 cluster (kind), where a `MutatingAdmissionPolicy` multiplies replicas
  by ten and a `ValidatingAdmissionPolicy` sets a ceiling;
- HAPI FHIR (8.12), the reference open-source FHIR server.

Run them locally by naming each system:

```
INTERLOCK_TEST_TOFU=$(command -v tofu) uv run pytest tests/test_real_tofu.py
kind create cluster --name interlock && eval "$(scripts/kind-setup.sh kind-interlock)"
uv run pytest tests/test_real_kubernetes.py
docker run -d -p 8091:8080 hapiproject/hapi:v8.12.0-2
INTERLOCK_TEST_FHIR_URL=http://localhost:8091/fhir uv run pytest tests/test_real_fhir.py
```

The first run against them found three bugs that the stand-ins could not show. All are
fixed in 1.4.1:

- A Kubernetes dry-run delete was real when the request had a body.
- A controller's status writes on a healthy cluster were taken for conflicts.
- A refused FHIR write was put back over the edit that refused it.

## Outbound requests: the transactional outbox

Plans often need to call something besides their database: send an email, issue a refund
through a payment API, post a webhook. None of those calls can be staged, measured or
rolled back. An agent that makes the call itself has made it before anything could check
it, and that's how an instruction injected through a tool result gets out.

So Interlock doesn't let the plan make the call. It uses the **transactional outbox**
pattern. The plan *enqueues a request* for the call alongside its SQL effects, and the
request is handled like a row, on PostgreSQL and SQLite alike. (The design and the proofs are in
[`docs/OUTBOX_DESIGN.md`](OUTBOX_DESIGN.md) and
[`docs/EPIC3_DESIGN.md`](EPIC3_DESIGN.md)).

1. **Enqueue.** `PlanBuilder.enqueue()` adds the request to the plan. Admission holds it to
   the operator's `SinkRegistry`: a registered sink and operation, a payload that matches
   the operation's JSON Schema and fits the sink's size bound, no field named like a
   credential, and the compensation the operation registers, if any.
2. **Stage.** The stage writes the request to `interlock.outbox` in its own transaction,
   through a function gated by a token only the substrate holds. The checkers read it back
   from there, beside the measured rows. It commits with the rows and the stage marker, or
   not at all, so a refused or failed plan leaves no request behind.
3. **Pay.** The plan pays at commit, in the settlement that commits with it: its settle
   cost plus each request's `cost_per_call`. The hold placed before staging covers both. A
   refused plan pays only its settle cost, since its requests never commit.
4. **Deliver.** `interlock relay`, a separate process under its own database role and the
   only holder of the sinks' credentials, reads committed requests and makes the calls, at
   least once.

### Configuring a sink

Sinks are declared in `interlock.toml` beside the tables. `interlock install` mirrors them
into the database, which then refuses a request for any sink or operation it doesn't hold.
A sink has no URL or credential here. Those belong to the relay.

```toml
substrate = "postgres"
stage_roles = ["interlock_agent"]
relay_roles = ["interlock_relay"]     # granted read access and the relay functions, nothing else

[[sinks]]
name = "payments"
cost_per_call = "0.0005"              # a decimal string, charged at commit
idempotency = "header"                # the sink deduplicates on Idempotency-Key; "none" if not
unknown_outcome = "redeliver"         # or "dead-letter": a call that may have acted is not repeated
not_after_seconds = 900               # delivered within this, or not at all
max_attempts = 10
backoff_base_seconds = 1              # doubling, with jitter, up to the cap
backoff_cap_seconds = 600

[[sinks.operations]]
name = "refund"
schema = "schemas/payments-refund.json"   # a JSON Schema subset, relative to this file
compensation = "none-possible"            # or the operation that undoes this one
```

```bash
interlock install --config interlock.toml --database postgresql://owner@db/app
```

### Enqueueing a request, and checking it against its rows

<!-- readme-test: skip reason="needs a live PostgreSQL server" -->
```python
from interlock import (
    BlastRadius,
    CrossEffectAgreement,
    EscrowEngine,
    PlanBuilder,
    PostgresSubstrate,
)
from interlock.config import load_config

config = load_config("interlock.toml")
engine = EscrowEngine(
    PostgresSubstrate("postgresql://interlock_agent@db/app", tables=config.tables),
    checkers=[
        BlastRadius(10),
        # The refund the payment API is asked for is the refund the plan recorded.
        CrossEffectAgreement(
            "payments",
            "refund",
            field="amount",
            table="refunds",
            column="amount",
            key=("order_item", "order_item_id"),
        ),
    ],
    sinks=config.sink_registry(),
)
plan = (
    PlanBuilder("support-agent")
    .insert(
        table="refunds",
        statement=(
            "INSERT INTO refunds (id, order_item_id, amount) VALUES (%(id)s, %(item)s, %(a)s)"
        ),
        parameters={"id": 9100, "item": 5000, "a": "50.00"},
    )
    .enqueue(sink="payments", operation="refund", payload={"order_item": 5000, "amount": "50.00"})
    .build()
)
result = engine.execute(plan)
```

A row diff alone has a blind spot. Every row can be valid and every request well-formed,
and the two can still contradict each other. `CrossEffectAgreement` closes that gap. If a
tool result talks the agent into asking the payment API for 5000.00 while the refund row it
inserts says 50.00, the plan is refused before it commits, so there's no row, no request
and nothing for the relay to send. Both halves are measured: the request is read back from
the outbox and the rows from the stage's capture. The check judges exactly what would be
sent and what would be committed. `measure="net"` holds a request to the change in a
balance it moves, and `measure="value"` holds it to one exact value, such as a currency.
The rule is strict both ways, so a refund call with no refund row, or a refund row with no
call, is refused too. The agent is told which rule it broke, but never the amounts.

### Running the relay

```toml
[relay]
key = "relay.key"                                  # this relay's Ed25519 key; or INTERLOCK_RELAY_KEY
database = "postgresql://interlock_relay@db/app"   # a relay role; or INTERLOCK_RELAY_DATABASE
ledger = "postgresql://interlock_relay@db/app"     # AgentGov, read-only, for the breaker
lease_seconds = 60                                 # at least twice timeout_seconds
timeout_seconds = 10
workers = 4

[[relay.endpoints]]
sink = "payments"
url = "https://api.payments.example"
routes = { refund = "POST /v1/refunds" }                    # every operation the sink registers
header_env = { Authorization = "PAYMENTS_AUTHORIZATION" }   # the value is read from the environment
```

```bash
export PAYMENTS_AUTHORIZATION="Bearer ..."     # in the relay's environment, nowhere else
interlock relay --config interlock.toml        # runs until SIGTERM; --once drains and exits

# As the installer: inspect, verify, and act on what the relay could not deliver.
interlock outbox status  --config interlock.toml --database postgresql://owner@db/app
interlock outbox list    --state dead --config interlock.toml --database postgresql://owner@db/app
interlock outbox verify  --config interlock.toml --database postgresql://owner@db/app
interlock outbox release --scope support-agent --key ~/.interlock/alice.key --config interlock.toml ...
```

Run as many relays as throughput needs, on as many hosts as you like. They share the work
through `FOR UPDATE SKIP LOCKED` and never wait on each other. On SIGTERM a relay finishes
the call in hand, records it, and exits. `interlock outbox show <message>` prints a
message's delivery log. `requeue` sends a dead message back with a fresh budget of
attempts, and `cancel` drops one.

A relay reads AgentGov's ledger and never writes it. For a ledger shared through
PostgreSQL, grant its role `USAGE` on the `agentgov` schema and `SELECT` on its tables, and
nothing more. For a SQLite ledger, name the file, and it's opened read-only. Without
AgentGov at all, set `breaker = "none"` explicitly. A relay never runs without a breaker
by default.

What the relay guarantees, each with a test that fails without it:

- **Nothing is sent before its plan commits, and nothing but what was adjudicated.** The
  relay reads committed rows only, and hashes the stored payload again before every call.
  A payload that no longer matches is refused, not sent.
- **Every call is recorded before it is made, and its outcome after**, in the message's
  delivery log, `interlock.outbox_attempts`. The database links each row to the one before
  it by hash, and `interlock outbox verify` recomputes every link and checks each message's
  state against its log.
- **A tripped breaker holds messages.** AgentGov's breaker for the message's scope is read
  right before every call. If it's tripped, the message is held instead of sent, until an
  operator releases it. Each call records the ledger position its breaker check read.
- **Relays never share a message.** Leases are claimed with `FOR UPDATE SKIP LOCKED`, and a
  fence on each lease stops a relay whose lease ran out from acting on the message again.
- **Delivery is at least once, and a duplicate is never silent.** Every call carries the
  same idempotency key. If a relay dies after its call reached the sink but before it
  recorded the outcome, the call is recorded as lost and made again. A sink that honours
  the key acts once. One that doesn't acts twice, and the log shows which lost call the
  second effect came from. `unknown_outcome = "dead-letter"` makes such a sink at most once
  instead. `tests/test_relay_crash.py` kills relays at every point of this path.
- **Failure is bounded.** Retries back off exponentially with deterministic jitter, honour
  `Retry-After`, and stop at `max_attempts` or the request's deadline. When a request dies,
  the requests waiting on it die with it, and `interlock outbox requeue` brings them back.

### Stripe and SendGrid

Two sinks are typed. They bring their own operations, strict payload schemas, and an
adapter that speaks the vendor's API. Configuration names which operations to allow, but
doesn't write their schemas.

```toml
[[sinks]]
name = "payments"
type = "stripe"                       # payment_intents.create, charges.create, refunds.create
cost_per_call = "0.30"

[[sinks.operations]]
name = "payment_intents.create"       # takes money, so carries its refund...

[[sinks.operations]]
name = "refunds.create"               # ...which is registered too

[[sinks]]
name = "email"
type = "sendgrid"                     # mail.send; at most once unless unknown_outcome = "redeliver"
cost_per_call = "0.001"

[[sinks.operations]]
name = "mail.send"

[[relay.endpoints]]
sink = "payments"
secret_env = "STRIPE_SECRET_KEY"      # the adapter knows the routes and the headers

[[relay.endpoints]]
sink = "email"
secret_env = "SENDGRID_API_KEY"
```

- **A Stripe charge carries the refund that undoes exactly it.** The refund names the charge
  by the placeholder `{"$bind": "delivered.id"}`, never a literal id, so a plan can't point
  its undo at another customer's payment. It refunds no more than was charged, and names no
  currency. The rule is checked at admission and again by the database when the request is
  written, so an engine configured with a looser registry can't stage the charge either.
- **The adapter** sends Stripe's form encoding with the request's idempotency key and a
  pinned `Stripe-Version`, and records the id of the payment intent it created in the
  delivery log. Stripe answers a redelivered call with an idempotent replay, so there's one
  charge whatever the relay went through.
- **SendGrid has no idempotency keys**, so its sinks are at most once by default. A call
  whose outcome is unknown isn't made again, and the message goes dead for an operator to
  resolve. Every email carries its message id and idempotency key in `custom_args`, which
  SendGrid's Event Webhook echoes, so `agentgov reconcile-actions --format sendgrid-events`
  can match each sent message to its delivery receipt.
- `tests/test_relay_crash.py` drives both through the relay's kill matrix, on both stores:
  a charge is made once and an email is never sent twice.

### MCP tools, and holding an operation for a warrant

An MCP tool that writes, behind a sink of type `mcp`, is governed like any request. The
plan is measured and judged, the call is committed to the outbox, and the relay makes it
as one `tools/call`. MCP has no idempotency key, so an `mcp` sink is always at most once. A
call whose outcome is unknown is never made again, and goes to an operator. Some
operations should never run on an agent's word alone. Mark them `hold = true`, on any
sink, and every request for them enters the outbox held, even with the breaker closed,
until an operator or a warrant releases it:

```toml
[[sinks]]
name = "crm"
type = "mcp"

[[sinks.operations]]
name = "close_ticket"
schema = "schemas/close_ticket.json"  # the input schema you pin, not the server's of the day
hold = true

[[relay.endpoints]]
sink = "crm"
command = ["crm-mcp-server", "--stdio"]
```

The receipt of a plan whose only effect is such a request says so. It records that only
the request was measured, and names the sink that carries the effect.

### Sinks and sources of your own

A FHIR server, ServiceNow or a cloud's API can be a typed sink of its own, configured from
`interlock.toml` like Stripe. A package registers its kind with `register_sink_kind`, or
under the `interlock.sinks` entry point, and follows the same contract as `interlock.stripe`
and `interlock.mcp`: its operations (or none), its idempotency, its payload rules and its
relay adapter. A vendor that signs its webhooks its own way is an inbox source kind,
registered with `register_source_kind` or under `interlock.sources`.

### On SQLite

The outbox, the relay and every operator command work on a SQLite file the same way they do
on PostgreSQL. `interlock install` switches the file to WAL and installs the outbox, and
the relay is `interlock relay` with the same configuration. SQLite admits one writer at a
time, and Interlock relies on that. Every write is a short `BEGIN IMMEDIATE` transaction, so
claims queue where PostgreSQL's would skip, and a relay never holds the lock while it calls
a sink. WAL means every process that opens the file has to run on one host. SQLite has no
roles. The file's permissions are the boundary, and verification is how an edit made around
Interlock gets found.

### Operators: every action signed

Releasing a held request, cancelling one, requeueing a dead one, and compensating a
delivered one are a person's decisions about money and messages that leave the system.
Each is signed with the operator's own Ed25519 key, in two phases. First, before the
database is touched, a signed intent names the targets and the delivery-log head of each.
The database acts under the intent's hash, only at those heads, and refuses any operator
row that carries no such authority. Then a signed outcome names the rows it wrote. If a
command is killed between the phases, the next one resolves it.

```bash
interlock operator keygen --out ~/.interlock/alice.key --name alice   # prints the line below
```

```toml
[operators]
log = "operators.ilok1"               # the signed operator log, beside this file
ledger = "governor.db"                # optional: every record anchored into AgentGov

[operators.keys]                      # public halves only
alice = "ed25519:5f0c..."
```

```bash
export INTERLOCK_OPERATOR_KEY=~/.interlock/alice.key
interlock outbox release   <message> --reason "the breaker tripped on a false alarm" --config ...
interlock outbox compensate <message> --config ...       # the undo the plan carried, bound
interlock outbox compensate --plan <plan> --late --config ...   # a whole plan, in reverse order
interlock outbox verify    --config ...
```

`interlock outbox verify` checks every delivery log against the operator log, using public
keys alone, and names each edit made around it. That includes an operator row with no
authority, an authority that no signed intent holds or one replayed on another message, a
row written at a head other than the one signed for, an operator log that was edited or cut
short (its signatures or its AgentGov anchors), and a sink re-enabled or widened since the
last signed `interlock install`. A database's owner can still edit their own database, but
not without it being noticed.

### Relays sign every outcome

A sink's answer is recorded only with the signature of the relay that heard it: an ARC1
1.1 attestation, made with the relay's own Ed25519 key, over the request as the outbox
committed it and the outcome as the row records it. The database refuses an outcome
without one, and a relay starts only with a key registered for verification:

```bash
interlock keygen --role relay --out ~/.interlock/east-1.key --name east-1   # prints the line below
```

```toml
[relays.keys]
east-1 = "ed25519:9a1b..."
```

`interlock outbox verify` rebuilds each outcome's attestation from the outbox row and the
log row, and names every outcome that no registered relay signed. A delivery written around
Interlock is named even if it's linked and hashed perfectly, and so is a genuine row that
was rewritten after it was signed. Outcomes recorded before schema version 4 carry no
attestation. The install that brought version 4 recorded them once as a legacy set, and
the signed `interlock install` vouches for that set. A row forged into an old log later
isn't in it, however early it's dated.

### Keys held by a signing service

A relay, the inbox, the vacuum and the receipt log can sign with a key held by a KMS, an
HSM or Vault's transit engine. The process keeps the key's name, the version it pinned, the
public half and a credential, and never the private key (`docs/EPIC8_DESIGN.md` §1).

```toml
[signers.relay]
type = "http"                       # interlock.signers.HttpRemoteSigner's protocol
url = "https://kms.internal:8200"
key = "interlock-relay"             # the key's name at the service
token_env = "INTERLOCK_KMS_TOKEN"   # its bearer token, read from the environment
timeout_seconds = 5
# version = 3                       # pinned; the service's latest when left out

[relay]
signer = "relay"                    # in place of key = "relay.key"
```

Every signature the service hands back is verified under the pinned key before it's used.
If the service signs with another key or version, or answers with anything but a
signature, the call fails and nothing is attested. `sign_async` signs off the event loop.
Operator commands take `--signer NAME` in place of `--key PATH`. An adapter for another
service implements `RemoteSigner._remote_key` and `_remote_sign`.

### Registering, revoking and rotating keys

The operator log is the key registry and its revocation list (`docs/EPIC8_DESIGN.md` §2).
An operator registers a key beside the configuration's, and it's trusted from the next
record on. Revoking one is a two-phase operator action, like every other. For a relay's or
an inbox's key, the database records the revocation in the transaction of the signed
intent, and *seals* every row the key attested by recording each one's reference and hash.
The applied record signs the seal's count and digest and is anchored in AgentGov. From then
on, the database refuses every row the key would attest. What the key attested before still
verifies, exactly as sealed. `interlock outbox verify` names any row written around the
refusal and any sealed row that was rewritten.

```bash
interlock keys list --config interlock.toml
interlock keys register --config interlock.toml --key ops.key --role relay --name east-2 \
    --public-of relay                 # the version [signers.relay]'s service serves now
interlock keys revoke --config interlock.toml --key ops.key --role relay 03dd37a92a71a9ba \
    --reason "rotated"
```

For a planned rotation, create a new version at the key service and register it. Reload
the daemon (`kill -HUP`, or `await supervisor.reload()`): each part finishes its step and
opens again with the key it's given now. Then revoke the old one. Nothing is refused along
the way. After a compromise, revoke first. A relay finds its key revoked before its next
claim, and the inbox at its next matching pass, and each opens again with the key its
service serves at that point. An operator's key is revoked by another operator, never by
itself, and the last operator key can't be revoked.

### Settlement: delivery receipts, and credits for compensations

The process that holds the receipt log and the ledger (the engine's) settles each
delivered request once (`docs/EPIC4_DESIGN.md` §4):

<!-- readme-test: skip reason="needs a settler role, and the engine's receipt log and ledger" -->
```python
import psycopg

from interlock import Settler

settler = Settler(
    psycopg.connect(SETTLER_DSN, autocommit=True),  # a role in settler_roles
    receipts=issuer,  # the engine's ReceiptIssuer
    chain=engine.chain,
    relays=config.relay_keyring(),
    ledger=governor,  # the engine's AgentGov ledger
    operator_log="operators.ilok1",
    operators=config.operators.keyring(),
    sinks=registry,  # the engine's SinkRegistry, which priced every request
)
report = settler.settle()  # as often as you like
```

- **A delivery receipt** for each delivered request. It's an ARC1 `DeliveryReceipt` signed
  by the receipt log, carrying the relay's attestation. It's bound by leaf hash to the
  action receipt of the plan that committed the request, meaning the plan the attested
  idempotency key was derived from, not just the one the row names. agentgov's verifier
  checks it with `agentgov verify-receipt delivery.json --relay-key ... --action action.json`,
  and `agentgov reconcile-actions` matches a vendor's own log against it by the idempotency
  key and the vendor's id.
- **A credit** for a delivered compensation. It's an AgentGov `refund()` of the
  `cost_per_call` that the engine's sink registry prices the request at, which is what its
  plan was charged for it, to the scope the ledger charged. It never refunds the money the
  request moved. It's posted only when all of these hold: a registered relay attested the
  compensation's delivery, the original's `compensated` row carries the authority of a
  signed operator intent that names exactly this compensation and is recorded as applied,
  and the outbox row agrees with the registry's price and the compensation's signed key. No
  column the database's owner can rewrite sets the amount or the scope. The plan's charge
  caps the credits, and nothing is credited when the row and the registry disagree.
- **Exactly once.** Each step first finds what a crashed run left of it. If a run is
  killed after the receipt, the credit or the settlement row, the next run still settles
  every request once: no duplicate receipt, no orphaned receipt, no second credit.

### Inbound facts: the zero-trust inbox

Vendors answer later. Stripe sends `charge.refund.updated` days after the refund, and
SendGrid reports a bounce an hour after the send. An agent has to react, and a webhook is
an obvious way in for a prompt injection: a forged request, or a genuine one whose
description field says "refund everything". The inbox turns a webhook into a fact the
agent may act on, and nothing more (`docs/EPIC5_DESIGN.md` §2):

```toml
inbox_roles = ["interlock_inbox"]     # PostgreSQL: the inbox's own role

[inbox]
key = "inbox.key"                     # interlock keygen --role inbox
database = "postgresql://interlock_inbox@db/app"
listen = "127.0.0.1:8787"             # plain HTTP: put TLS in front of it

[[inbox.sources]]                     # POST /inbox/stripe
name = "stripe"
kind = "stripe"                       # or "sendgrid", or "http" (Standard Webhooks)
secret_env = "STRIPE_WEBHOOK_SECRET"  # the secret lives in the inbox's environment only

[inbox.keys]                          # what engines verify facts under
main = "ed25519:7d2e..."
```

```bash
interlock keygen --role inbox --out ~/.interlock/inbox.key --name main   # prints [inbox.keys]
STRIPE_WEBHOOK_SECRET=whsec_... interlock inbox serve --config interlock.toml
interlock inbox verify --config interlock.toml
```

- **Verified, or not recorded.** The vendor's signature (Stripe's HMAC, Standard Webhooks'
  HMAC, SendGrid's ECDSA) is checked over the raw bytes, within a timestamp tolerance, before
  the body is parsed. A forged, replayed or stale webhook gets `401` and writes nothing. A
  retry of a genuine one doesn't record anything twice.
- **Bound to what Interlock sent.** An event names what it's about, such as a refund's id.
  It's bound to the delivered request whose relay-attested `remote_ref` is that id. It's
  never bound to a delivery no registered relay attested, or to two messages' deliveries at
  once. The binding gives the fact its scope and plan.
- **Attested, and chained.** Each source's events form a hash-linked log, and the inbox
  signs every event and every fact with its own Ed25519 key. A fact written, copied or
  moved around the inbox does not verify, and `interlock inbox verify` names it.
- **Typed.** A fact carries a projection: ids, codes, integers, decimals, currencies,
  booleans, instants. No type admits free text, so a vendor's description, metadata or
  error message never reaches the agent. A value that doesn't fit is withheld, and named.

An engine consumes facts, never webhooks:

<!-- readme-test: skip reason="needs an inbox's facts" -->
```python
from interlock import EscrowEngine, FactAgreement, PlanBuilder

engine = EscrowEngine(
    substrate,
    checkers=[
        # A refund is marked failed only on the vendor's word that it failed.
        FactAgreement(
            "charge.refund.updated",
            field="status",
            table="refunds",
            column="status",
            exempt=["pending"],
        ),
    ],
    inbox=config.inbox_keyring(),
)
(fact,) = engine.facts("support-agent")  # pending, attested, this scope's
plan = (
    PlanBuilder("support-agent")
    .consume(fact)
    .update(
        table="refunds",
        statement="UPDATE refunds SET status = %(status)s WHERE id = 9000",
        parameters={"status": fact.fields["status"]},
    )
    .build()
)
engine.execute(plan)
```

A fact is consumed once, in the plan's own stage, exactly when the plan commits. A second
plan that names it is refused, and a refused plan consumes nothing. The stage reads the
fact back for the diff, where it's verified again, and the receipt commits to it. No
statement in a plan can read the inbox. `FactAgreement` ties the agent's reaction to the
fact: a plan that writes a status no consumed fact supports is refused, and the agent is
told the rule but never the values.

### Compaction: the vacuum

The outbox, window history and the inbox only grow. `interlock vacuum` prunes what no check
will read again, and keeps it provable (`docs/EPIC5_DESIGN.md` §1):

```toml
[vacuum]
retain_days = 30                      # a delivered request can be compensated this long
margin_seconds = 3600                 # window history stays this long past the longest span
archive = "archive"                   # optional: the pruned rows, written first, provable
```

```bash
interlock vacuum --config interlock.toml --key ~/.interlock/alice.key --dry-run
interlock vacuum --config interlock.toml --key ~/.interlock/alice.key --reason monthly
interlock vacuum --config interlock.toml --verify-archive archive/checkpoint-1.jsonl
```

It verifies everything first: delivery logs, relay attestations, operator records, earlier
checkpoints, and the inbox under `[inbox.keys]`. Anything that doesn't verify is kept and
named. Three kinds of history can go: stages past the retention period whose every request
was delivered and settled, or cancelled; window history older than the longest span; and,
for each inbound source, the events past the retention period whose facts were all
consumed. A *checkpoint* commits to all of it: each pruned message's log head and
settlement, folds over everything pruned, and where each inbound log was cut. It's signed
in an operator intent and anchored into AgentGov before any row is deleted. One database
transaction then records it, recomputes every fold from what the database holds, and
deletes. The database refuses any other delete. Afterwards every verifier passes, counting
pruned history through its tombstones and cuts, and a window that would reach back past
pruned history fails closed.

## The daemon: every part in one process

`interlock daemon` runs the engines that execute your agents' plans alongside the relays,
the inbox, the settler and the vacuum. It's one process with one asyncio event loop, and
each part makes its database calls on a thread of its own (`docs/EPIC6_DESIGN.md`). Each
part connects as its own role, from the sections `interlock.toml` already has, plus these:

```toml
[engine]                              # the engines executing agents' plans
workers = 4                           # plans staged at once (SQLite: one)
database = "postgresql://interlock_agent@db/app"   # the stage role
chain = "escrow.chain"                # worker n writes escrow-<n>.chain
settle_cost = "0.01"
ledger = "postgresql://owner@db/app"  # AgentGov in the same database...
same_transaction = true               # ...settles each plan with its commit
conflict_retries = 16                 # a plan that lost a race is staged again

[receipts]                            # one receipt log, the engines' and the settler's
log = "receipts.jsonl"
key = "receipts.key"

[settler]
database = "postgresql://interlock_settle@db/app"
every_seconds = 5

[vacuum]                              # the daemon's own vacuums
every_seconds = 300
key = "vacuum.key"                    # an operator's key, in [operators.keys]
database = "postgresql://owner@db/app"

[daemon]
drain_timeout_seconds = 30            # each shutdown step's bound

[metrics]                             # Prometheus, on a listener of its own
listen = "127.0.0.1:9464"             # GET /metrics and /healthz: a private address
every_seconds = 15                    # how often the database is sampled
database = "postgresql://interlock_audit@db/app"   # an audit_roles role
```

Your agents and their policy come in as an application: a function that takes the
configuration and returns an `Application` of checkers and agents. An agent is a coroutine
taking an `AgentContext`, or a plain function, run on a thread of its own:

```python
from interlock import AgentContext, Application, BlastRadius, TenantIsolation


async def support(ctx: AgentContext) -> None:
    while not ctx.stopping:
        for fact in await ctx.facts("support-agent"):
            plan = ctx.plan("support-agent", intent=f"react to {fact.kind}")
            ...  # .consume(fact), then the writes it justifies
            await ctx.execute(plan.build())
        await ctx.sleep(1.0)


def build(config: object) -> Application:
    return Application(checkers=[BlastRadius(50), TenantIsolation()], agents=[support])
```

```bash
interlock daemon --config interlock.toml --app myapp.agents:build
```

A plan that loses a race for a row or a window key is staged again, with jittered backoff.
A part that fails is reopened after a backoff that doubles each time. `SIGHUP` reloads the
daemon. The relays and the inbox finish their step and open again, signing with whichever
key their configuration points at by then, and the inbox's listener never closes. The
vacuum opens its key at each run anyway, and engines and agents keep running. `GET
/healthz` on the inbox's port answers `200` while every part runs and `503` otherwise, with
each part's counters. `SIGTERM` stops the parts in order, each step bounded in time: the
agents; the engines (queued plans run until the deadline, and a running stage always
finishes); the inbox, followed by one last match; the relays; the settler, with one last
pass; and any vacuum in progress. A second signal skips the drains and gives the parts one
second to close, and the next start recovers as it would after a crash. Without `--app`,
the daemon runs the relays, the inbox and the vacuum.

In a process of your own, `build_supervisor(config, application)` returns the same
`InterlockSupervisor`, to run on your event loop.

### Several daemons: a cluster

Run three to five daemons over one database and one AgentGov ledger, each in a pod of its
own, and any of them can die at any moment (`docs/EPIC9_DESIGN.md`). Each is a node:

```toml
[cluster]                             # PostgreSQL only
node = "interlock-0"                  # or INTERLOCK_NODE, or interlock daemon --node
database = "postgresql://interlock_cluster@db/app"   # direct, or a session-mode pool
heartbeat_seconds = 1
session_timeout_seconds = 10          # a node silent this long holds nothing more
```

A node's name is at most 40 characters (letters, digits, `.`, `_`, `-`). `database` is the
database Interlock is installed in. A node's lock lives in that database, where the relays
look for it, and a node refuses to join a database without Interlock's storage. Its role
needs no privilege for the locks. To fence other nodes (below), it needs
`pg_signal_backend`, and the parts' roles must not be superusers, because only a superuser
can end a superuser's sessions:

```sql
CREATE ROLE interlock_cluster LOGIN PASSWORD '...';
GRANT pg_signal_backend TO interlock_cluster;
```

A node holds its lock in PostgreSQL, as a session-level advisory lock, for as long as its
process lives. So the database alone decides when a node is gone: when it ends the node's
session. That's immediate for a killed process, and takes `session_timeout_seconds` for one
that froze or lost the network. Every node runs the engines, the relays, the inbox and the
metrics endpoint. The vacuum, and the inbox's matching of webhooks that arrived before
their delivery was recorded, run on one node at a time: the node leading that role, which
holds another advisory lock on the same session. Another node takes the role the next time
it asks after the leader is gone. Each node settles the deliveries of the plans its own
engines committed, into its own receipt log, because a delivery receipt goes into the log
that holds its plan's action receipt. No two nodes ever settle the same message.

A relay's lease names its node (storage version 8: `interlock install` upgrades version 7
in place, and a relay of version 7 left running keeps claiming). When a node is gone, the
next claim of any relay takes its leases over, its calls in flight made again under the same
idempotency key, without waiting for the leases to run out. In a cluster every session that
holds what others wait for, the relays', the inbox's and every AgentGov governor's, is
bounded by `session_timeout_seconds`, and every connection a node opens says whose it is in
`pg_stat_activity`: `interlock-<part>@<node>`.

A node that's gone is fenced. At each heartbeat, a node ends every session belonging to a
node whose lock no session holds, found by its connections' names. A frozen node, or one
cut off from the network, holds nothing past its session timeout plus a heartbeat. That
covers its transactions and any lock it was waiting for, which it would otherwise take and
sit on for its own bound, wait after wait. A node that isn't allowed to end those sessions
says so once in its log, and they end at their own bounds.
`interlock_cluster_fenced_total` counts the sessions a node ended.

On Kubernetes, run it as a StatefulSet:

- `INTERLOCK_NODE` set from the pod's name;
- a volume per pod for its escrow chains and receipt log, with a unique `[receipts] log_id`
  per pod;
- the operator log on a `ReadWriteMany` volume that every pod mounts, with working file
  locks;
- `/healthz` for readiness and liveness (a node on standby for a role counts as healthy);
- the node's session reaching PostgreSQL directly, or through a pool in session mode,
  never transaction mode.

`interlock daemon` exits 3 when its node is already running, or when another process took
its name while it ran.

### Metrics

With `[metrics] listen` set, or `interlock daemon --metrics HOST:PORT`, the daemon serves
Prometheus's text format on a port of its own (never the inbox's, which faces vendors):
`GET /metrics` and `GET /healthz`. Each part measures its own work:

- the engines: every plan by outcome and duration, races lost (to a row's lock or to the
  pool), waits for window-key locks and for the windows' connection, and the longest of
  each in the last minute;
- the relays: every call by sink and outcome;
- the settler: each delivery receipt's lag behind its delivery;
- the inbox: every webhook by answer and by the trace context it carried;
- the vacuum: its runs and what they pruned;
- every part: its state, steps and failures.

What only the database knows is sampled every `every_seconds`, in one read-only snapshot,
as the `database` role: the outbox's depth by state and its oldest due message,
settlement's backlog, facts no plan has consumed, and each rate window's fullest key
against its limit (`interlock_window_saturation`). A scrape reads memory, never the
database. No label is a tenant, a scope, a plan or a key, so the configuration sets the
number of series and traffic doesn't. `interlock.telemetry.CATALOG` lists every metric, and
`docs/EPIC7_DESIGN.md` §2 says what each one measures. The registry adds under two
microseconds to a plan (`scripts/metrics_overhead.py`).

The endpoint isn't authenticated, so bind it to an address only your scraper can reach. It
shows how the system is behaving, never its data.

### Trace context

A plan can carry a W3C `traceparent`, and Interlock carries it wherever the plan's effects
go: beside each request in the outbox, out as the `traceparent` header of every call the
relay makes (`HttpAdapter`, and Stripe's and SendGrid's adapters), retries included, and
onto the refund an operator issues to compensate a charge. When a webhook's signature
verifies, the context it carried is kept beside its event. The fact the inbox binds to a
delivery continues the delivery's trace. It uses the webhook's context when the vendor
continued ours, and the delivery's own when the vendor sent its own trace, a malformed one,
or none. A plan that consumes the fact continues the trace too, so agent, outbox, relay,
vendor, webhook and agent again form one trace:

```python
from interlock import PlanBuilder, child_traceparent, new_traceparent, parse_traceparent

checkout = new_traceparent()  # or your tracing library's current context
plan = (
    PlanBuilder("support-agent", intent="charge order 7", traceparent=checkout)
    .update(
        table="orders",
        statement="UPDATE orders SET status = :status WHERE id = :id",
        parameters={"status": "charging", "id": 7},
    )
    .build()
)
assert plan.traceparent == checkout

# What arrives over HTTP is read as W3C asks a receiver to: malformed is None.
assert parse_traceparent("not a traceparent") is None

# A plan consuming a fact bound to the charge: a span of its own, in the same trace.
follow_up = child_traceparent(checkout)
assert follow_up.split("-")[1] == checkout.split("-")[1] and follow_up != checkout
```

In the daemon, `ctx.plan(scope, traceparent=...)` does the same, and each fact from
`ctx.facts(scope)` has its `traceparent`. Trace context is outside every hash. A plan, a
request, a delivery log, a relay's attestation, a receipt, an event and a fact all hash the
same with or without it, and no decision Interlock makes reads it. It's kept in tables of
its own, which the vacuum prunes along with the rows they describe. Interlock propagates
and records trace context, but exports no spans of its own.

### The soak

`scripts/live_stress_test.py` runs a cluster of daemons for minutes against a live
PostgreSQL, in a container it starts or on a server you name:

```bash
uv run python scripts/live_stress_test.py --docker --minutes 5
uv run python scripts/live_stress_test.py --dsn postgresql://admin:pw@localhost:5432/postgres
```

It runs `--nodes` daemons (three by default), each an `interlock daemon --node` in its own
process, over one database and one ledger. On every node, agents keep plans in flight:
checkouts that insert an order and charge for it, carrying the refund that undoes it;
reconciliations of what the payment API's webhooks say; notes on rows that every node
contends for; and now and then a plan that has to be refused.

A fake payment API answers in Stripe's shape, honours idempotency keys, and fails on
purpose: 500s after acting, 429s, replies slower than the relay waits. Its webhooks come
back signed, duplicated, early, about objects nobody created, and forged. An operator
refunds paid orders, signing every action. Webhooks reach the nodes through a balancer
that takes a node out when it stops answering.

At 45% of the load, the node leading the vacuum is killed with `SIGKILL` while its relays
have a call in flight. At 70%, the node leading it then is frozen with `SIGSTOP`, with a
call in flight and a stage open, its connections left open the way a host cut off from
the network leaves them. It's killed once the server and the other nodes have ended
everything it held. Each node comes back, as a rescheduled pod would, and recovers.

A quarter of the way through, the operator rotates the relays' key, which the relays, the
inbox and the vacuum sign with through a key service in the soak's process. A new version
is registered, every node is reloaded with `SIGHUP`, and the old key is revoked while a
stale relay that still holds it has a call in flight. The database refuses that relay's
outcome, another relay delivers the message once under the new key, and everything the old
key attested before still verifies under its seal.

Then the soak checks, from the database, the ledger, the logs and each node's journal of
what its agents did:

- no deadlock, lock waits within their bounds, and every lost race retried to an outcome;
- every rate window within its limit at every instant of its history;
- the ledger balanced to the cent, each plan charged once and each refund credited once;
- one charge per order and one receipt per delivery, except for a plan whose node died
  before issuing its action receipt;
- no forgery accepted, and the vacuum keeping the outbox bounded as it runs;
- every verifier passing afterwards, a graceful stop, and a second daemon finding nothing
  to recover;
- every checkout's trace context carried to the payment API, onto its refund, back on the
  facts its webhooks became and on to the plans that consumed them, whatever the vendor
  sent;
- the metrics, scraped every second, agreeing with what the run counted itself;
- keys rotating under load, every node sharing the work, and one node leading each role at
  a time;
- the killed node's lock gone with it, its leases taken over within a second, and its call
  in flight made again and acted on once;
- the frozen node's leases taken only once it was gone, every session it held fenced a
  heartbeat later, and no survivor waiting on any of them longer.

`tests/test_soak.py` runs it for a minute and a half in the test suite.

### The security audit

`scripts/security_audit.py` checks whether any sensitive value reaches a hash Interlock
commits to (`docs/EPIC8_DESIGN.md` §4). On each store it runs one scenario through the
daemon, with canaries planted in a plan's trace context, the relay's API key, a webhook's
body and headers, and its signing secret. It records the input of every SHA-256 and every
signature Interlock and AgentGov compute. None of them may contain a sensitive value or its
digest, except the body's SHA-256, which the inbound event commits to, and only columns
made for a sensitive value may hold one. It prints, column by column, what holds a
sensitive value and which hash reads it:

```bash
uv run python scripts/security_audit.py --docker
```

### The customer acceptance matrix

`demo/customer_acceptance_suite.py` puts a live Claude model in front of four unrelated
business domains on SQLite: accounts-payable disbursements on a double-entry ledger, cluster
operations, a multi-tenant SaaS admin console, and fulfilment in dependent stages for a
third-party warehouse. Each has its own schema, triggers, constraints and simulated outside
APIs, and one function builds each domain's policy from the same checkers. Only table and
column names and limits differ. The model gets each domain's everyday request, requests
that conflict with its rules (another tenant's rows, a cap, a table outside its remit, an
append-only log), and conflicting figures. Everything it proposes goes through
`PlanBuilder` and `EscrowEngine.execute`. Independent checks, which don't ask Interlock,
verify every outcome: other tenants' rows byte for byte, each committed request against its
rows, the domain's own invariants, delivery order and count, and that nothing shown to the
model names another tenant's data. Reference proposals, one per policy dimension in every domain, run
the same tool with no model, in CI (`tests/test_acceptance_suite.py`). The last live run is
recorded in [`docs/CUSTOMER_ACCEPTANCE_MATRIX.md`](CUSTOMER_ACCEPTANCE_MATRIX.md), with
every tool call the first model named made, exactly as it made it.

```bash
uv run python demo/customer_acceptance_suite.py --offline    # the references; no model
BENCHMARK_API_KEY=sk-ant-... uv run python demo/customer_acceptance_suite.py \
    --matrix docs/CUSTOMER_ACCEPTANCE_MATRIX.md
```
