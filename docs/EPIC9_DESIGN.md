# Epic 9: high availability, several daemons on one database

**Status: built** on `feat/epic9-ha-clustering`; §9 records how. Builds on
[`EPIC8_DESIGN.md`](EPIC8_DESIGN.md). Every part of Interlock already survives a crash, and the
relays and the inbox already share their work across processes. This epic runs three to five
daemons at once, each in a Kubernetes pod of its own, over one PostgreSQL database and one
AgentGov ledger, and proves that any one of them can die at any moment without a payment made
twice, a webhook recorded twice, or a lock held past a bound. Four parts:

1. **Nodes and leadership** (§1). Each daemon is a *node* of a cluster. It holds its node's
   lock in PostgreSQL for as long as it lives, and the parts that must run on one node at a
   time follow a *leadership*: an advisory lock on the same session. When a node dies, the
   database ends its session, and with it every lock the node held; the nodes that survive
   then end every other session it had (*fencing*).
2. **Leases that follow their node** (§2). A relay's lease names its node. A lease whose node
   is gone is taken over at the next claim, without waiting for the lease to run out.
3. **The singletons** (§3). The vacuum and the inbox's matcher run on one node of the cluster at a time.
   The settler cannot: a delivery receipt goes into the receipt log that holds its plan's
   action receipt, and that log is written by the node whose engine committed the plan. So
   each node settles its own plans, one settler per receipt log, and no two nodes ever
   settle the same message.
4. **The cluster under chaos** (§5). `scripts/live_stress_test.py` runs three daemons as
   processes of their own, over one database, and kills two of them mid-load: one outright
   (`SIGKILL`), and one frozen first (`SIGSTOP`), as a host lost to the network leaves its
   connections open, then killed. Each comes back, as a pod is rescheduled.

Decided before any code:

- **The database is the arbiter of liveness.** A node is alive while PostgreSQL holds its
  session. Nothing compares clocks, nothing gossips: a node that cannot reach the database
  can do nothing that matters, and the database decides, alone, when it is gone.
- **Leadership decides who works. It is not what makes the work correct.** A leader that
  pauses past its session's bound loses its locks while its step still runs; for that one
  step two nodes may work at once. Every singleton's work is already safe under concurrency:
  the vacuum's runs take turns at the operator log's writer lock and chain their checkpoints
  in the database; a receipt log has one writer, and a message one settlement row; an event
  one fact. Leadership removes the contention and the wasted work, never a guarantee.
- **What a node holds, the server bounds.** A node can die without closing its connections:
  a frozen process, a host lost to the network. So every session a daemon opens bounds how
  long it may sit in a transaction, and the node's own session how long it may sit silent.
  A node gone takes nothing with it past those bounds: no row lock, no ledger lock, no
  lease, no leadership. And the nodes that survive end the rest of a gone node's sessions
  (§1.5), so a frozen node's waits for locks it would take and sit on end too.
- **Per-node state stays per node.** Each node's engines write escrow chains of their own and
  issue action receipts into a receipt log of their own, on the node's own volume. Nothing
  about them changes: a node killed and started again recovers them exactly as a crashed
  daemon always has.
- **No new dependency, and no new process.** Advisory locks, `pg_locks` and the server's
  own timeouts are the whole mechanism.

## 1. Nodes and leadership

### 1.1 The node

A daemon in a cluster has a name, unique in the cluster:

```toml
[cluster]
node = "interlock-0"                # or INTERLOCK_NODE, or interlock daemon --node NAME
database = "postgresql://interlock_audit@db/app"   # or INTERLOCK_CLUSTER_DATABASE
heartbeat_seconds = 1               # how often the node shows it is alive
session_timeout_seconds = 10        # how long a silent node keeps what it holds
```

In Kubernetes, a StatefulSet's pod name, through the downward API: 40 characters at most,
so that every connection's name holds it whole (§1.5). `[cluster]` needs PostgreSQL, and its
`database` is the database Interlock is installed in: a node's lock is that database's own,
and the relays look for it in theirs (§2), so a daemon's node refuses to join a database
without Interlock's storage. The node's *session* is one connection of its own, as a role of
its own: an advisory lock needs no privilege, and fencing (§1.5) needs `pg_signal_backend`.
It must reach the server directly or through a pooler in session mode: a transaction-mode
pooler hands a session's locks to whoever runs next on it.

When the daemon starts, before its engines recover anything, the node *joins*: its session
takes the node's lock, `pg_try_advisory_lock(NODE, key(node))`, and keeps it until the
process ends. A node whose lock another session holds waits for it, up to twice the session
timeout: its previous incarnation's session may not have ended yet. Past that, the daemon
refuses to start: another process is that node.

The session is set up so the server ends it when the node goes silent:

- `idle_session_timeout` is the session timeout (PostgreSQL 14 or later). The node
  heartbeats more often than that. A frozen or partitioned node stops heartbeating, and the
  server ends its session, and releases its locks, once the timeout passes.
- TCP keepalives, client and server side, at a fraction of the timeout, for a peer that
  vanished without a word.
- `application_name` is `interlock-cluster@<node>`: who holds what is plain in
  `pg_stat_activity`.

Each heartbeat reads the advisory locks the session holds (`pg_locks`, its own `pid`), then
fences the nodes gone (§1.5). A heartbeat that fails means the session is gone, and every
leadership with it: the node counts itself out of every role at once, reconnects and joins
again. If another process took the node's lock in between, the daemon stops: it is the stale
one.

### 1.2 Leadership

A *role* is held by one node of the cluster at a time: a session-level advisory lock,
`pg_try_advisory_lock(LEADER, key(role))`, on the node's session. Never waiting: a node that
does not get it now tries again at its next step.

| role | held by | why one |
|---|---|---|
| `vacuum` | one node of the cluster | a second vacuum would only wait for the first at the operator log, or survey what it is pruning |
| `inbox-matcher` | one node of the cluster | every node binds the webhooks it receives as it receives them; the matcher binds those that arrived before their delivery was recorded, and N matchers would each sign a fact for the same event |
| `settler:<receipt log id>` | the node whose engines write that log | §3.2 |

A service that follows a role (`Service.leader`) steps only while its node leads the role.
Before each step the supervisor asks: a node that holds the role confirms its session is
alive (one round trip: a session-level lock cannot outlive its session); one that does not
tries to take it. A node that does not lead is on *standby*: the service is open, its step
is skipped, and it asks again after its interval. Standby is healthy, and `/healthz`
answers `200` for it. A leader drains at a shutdown (the settler settles once more, a vacuum
in progress finishes); a standby node does not. Closing a service resigns its role, and
leaving the cluster releases them all.

Keys: `NODE` and `LEADER` are two classes of Interlock's own, `1229737818` and `1229737819`
(the keys lock of Epic 8 is `(1229737817, 8)`); `key(name)` is the first four bytes of
SHA-256 over `interlock.node:<name>` or `interlock.role:<name>`, a signed 32-bit integer,
computed alike in Python and in SQL.

### 1.3 The supervisor

`InterlockSupervisor(cluster=...)` joins before the engines open, heartbeats on a thread of
its own every `heartbeat_seconds`, and leaves last, after every service, engine and shared
resource has closed: a node's next incarnation, which waits for the node's lock, then finds
its chains and its receipt log free. `status()` and `/healthz` report the node as a part
named `cluster`, and each led service as `running` or `standby`.

### 1.4 Metrics

| Metric | Type | Labels | |
|---|---|---|---|
| `interlock_cluster_node` | gauge | `node` | 1 while the process holds its node's lock |
| `interlock_cluster_leader` | gauge | `role` | 1 while the node leads the role |
| `interlock_cluster_leaderships_total` | counter | `role` | times the node took the role |
| `interlock_cluster_fenced_total` | counter | | sessions this node ended of nodes gone (§1.5) |
| `interlock_lease_takeovers_total` | counter | | leases a relay took from a node that was gone |

Labels come from configuration: the node's name and the roles its parts follow.

### 1.5 Fencing

A node the database counts gone may still have sessions on the server: a frozen process,
or a host lost to the network, leaves every connection open. Each holds what it holds until
its own bound ends it, and one waiting for a lock takes the lock when its turn comes and
sits on it for a bound of its own: a frozen node with three sessions queued for the ledger's
writer lock holds it for three bounds, one after another, and the whole cluster's ledger
waits that long.

So the nodes that survive *fence* a node gone. At each heartbeat a node reads
`pg_stat_activity` for the sessions of other nodes, by their names
(`interlock-<part>@<node>`, §3.3), and ends each with `pg_terminate_backend`, in one
statement that first takes the node's lock shared: the try fails while any session holds
the node's lock, so a live node's sessions are never touched, and it holds the lock to the
statement's end, so the node cannot join again in between. A node's cluster session is left
alone, and so is its next incarnation's, waiting there to join; the rest of an incarnation
opens only after it joins. A name PostgreSQL may have cut, 63 bytes or more, is never read
as a node's.

A frozen node then holds nothing past its session timeout and a heartbeat, however many of
its sessions were waiting for what. Ending another role's session takes
`pg_signal_backend`, and a superuser's a superuser: a node that may not says so once in its
log, and the sessions end at their own bounds (§3.3). Fencing is liveness, never safety: a
node fenced while only paused finds its connections gone, as after a restart of the
database, and every part opens again; nothing it did is undone that the database had
committed.

## 2. Leases that follow their node

**Storage version 8** (PostgreSQL; SQLite has no cluster and stays at version 7):

- `interlock.outbox_state.lease_node`: the node whose relay holds the lease, or `NULL`.
- `interlock.relay_claim(relay, lease_seconds, limit, sinks, node)`: records `node` with the
  lease, and claims, beside every message that is due, every message leased to a node that
  is gone: one whose node lock no session holds (`pg_locks`, read once per claim). It
  returns the node taken from, when it took one.
- A lease taken from a node that is gone, after its relay recorded a call and before an
  outcome, is recorded `lost`, exactly as a lease that ran out: the sink may have acted, and
  the call is made again under the same idempotency key. The fence moves with the claim, so
  if the relay was alive after all, nothing it records is accepted.

So a node killed outright loses its leases at the next claim after the database ends its
session, which for a killed process is at once: the kernel closes its sockets. A node that
froze, or lost the network, loses them after its session timeout, or when they run out,
whichever comes first. A lease taken by a relay outside a cluster, or by `interlock relay`,
names no node and runs out as it always has. `interlock install` upgrades version 7 in place;
stop the relays first, as for every version before.

## 3. The singletons, and a node's own

### 3.1 The vacuum and the matcher

The daemon's vacuum follows `vacuum`, and the inbox's matcher `inbox-matcher`; every node
still serves webhooks. A vacuum's reason names the node that ran it, in the operator record
it signs: `scheduled by the daemon on <node>`. The vacuum opens its AgentGov governor at its
first run, so only a leader ever opens one.

### 3.2 The settler, by receipt log

A delivery receipt binds the action receipt its plan was issued, and goes into the log that
holds it (`docs/EPIC4_DESIGN.md` §4). That log has one writer, the process whose engines
issue into it, and the settler needs the chains those engines write to find a plan's receipt
and its charge. A settler on another node, reading neither, would settle a delivery without
its receipt, and a compensation without its credit, for good: that is what a daemon's
settler does today with a plan no chain of its own records.

So in a cluster, a settler settles only the deliveries of plans its own engines' chains
record (`Settler(partition=True)`), and follows `settler:<log id>`: one settler per receipt
log in the cluster, whatever is misconfigured. The partition is disjoint, since a plan is
committed by one engine, so no two settlers ever touch one message, and nothing contends:
each verifies and settles its own deliveries and no one else's. A node that dies leaves its
deliveries unsettled until it comes back; its relays' deliveries do not wait, and neither
does anything else.

`verify_settlements` takes every node's receipt log: each settlement's receipt in one of
them, bound to an action receipt of the same log; every delivery receipt in any of them
named by one settlement.

### 3.3 What every session holds, bounded

In a cluster, every session a node opens bounds how long it may sit inside a transaction by
`session_timeout_seconds`: the relays' (60 seconds before), the inbox's, the settler's, the
vacuum's (none before), and every AgentGov governor's (`idle_timeout`, 60 seconds before).
The stage keeps its own bound, `max_stage_seconds`, as statement and idle timeout. A node
that freezes inside any transaction holds its locks for that long at most, the inbox's lock
on a source's log, the ledger's writer lock, a claim's rows, and then the server rolls it
back. Outside a cluster, the inbox's, the settler's and the vacuum's sessions get the relays'
60 seconds: before this epic two `interlock inbox serve` processes could wait on each other
forever behind one that hung.

Every connection a node opens names it: `interlock-<part>@<node>` (`stage`, `relay`,
`inbox`, `settler`, `vacuum`, `ledger`, `metrics`, `cluster`).

### 3.4 A node's next incarnation

A node started again waits for its node's lock, then recovers its chains, as any daemon
does. Recovery asks the database whether each open commit intent committed; a transaction
still running is not an answer. A transaction of the previous incarnation may outlive its
session: a statement still waiting, then the stage's idle bound. So in a cluster, recovery
asks again until every intent with a marker is answered, for up to twice the stage bound and
its lock timeout; only then are holds released and claims redeemed. Before this epic an
intent unanswered at start stayed open until the next start.

## 4. Kubernetes

A StatefulSet of three to five replicas:

- `INTERLOCK_NODE` from the pod's name; a volume per pod for its escrow chains and receipt
  log (`[engine] chain`, `[receipts] log`, and `log_id` unique per pod).
- The operator log is one file every node reads, and the vacuum and the operators write in
  turn under its lock: a `ReadWriteMany` volume whose locks work (NFSv4).
- Readiness and liveness on `/healthz`. A process that hangs fails its probe, the kubelet
  kills it, and the pod comes back on its volume and recovers.
- Webhooks through a Service in front of every pod's inbox.

## 5. The soak, as a cluster

`scripts/live_stress_test.py` becomes the cluster soak. Its harness runs the payment API,
the vendor's webhooks, the key service, the operator's desk, the auditor and the scrapers as
before, and `--nodes` daemons (three by default), each `interlock daemon` in a process of its
own, with its own volume, over one database and one ledger. Every node runs every agent:
each scope's plans come from every node at once.

- **Agents without shared memory.** An agent finds a fact's order from the fact's plan: a
  checkout's plan id names its order. A few hot rows every node contends for exist before
  the load. Each node writes what its agents did to a journal of its own, one line at a
  time, which survives its death; the claims read the journals, the database, the ledger,
  the chains and the logs.
- **The vendor behind a balancer.** Webhooks go to the nodes in turn, through a balancer that
  checks each node's `/healthz` and takes a node out when it stops answering. A webhook a
  node took and never answered is sent again, to another.
- **The rotation of Epic 8**, cluster-wide: the new key registered, every node reloaded
  (`SIGHUP`), the stale relay refused.
- **A kill.** At about 45% of the load, the node leading `vacuum` is killed with `SIGKILL`,
  at a moment its relays hold a lease with a call in flight. It comes back ten seconds later.
- **A freeze.** At about 70%, the node leading `vacuum` then is stopped with `SIGSTOP`, and
  its connections stay open, as a host lost to the network leaves them. Once the server has
  ended everything it held, it is killed, and comes back.

New claims, beside the twelve of Epics 6 to 8:

| Claim | Measured by |
|---|---|
| **nodes share the work** | every node committed plans, delivered messages, answered webhooks and settled its deliveries |
| **one leader at a time** | `pg_locks`, sampled throughout: no role ever held by two sessions; every vacuum run by the node leading `vacuum` then, as the operator log names it; every receipt log settled by its own node; leadership taken by a survivor after each death |
| **a node killed is survived** | the dead node's leases taken over within a second of its death, its call in flight made again under the same key and answered from the vendor's store; its sessions gone at once; each plan it had in flight committed whole, recovered by its next incarnation, or left nothing; its holds released and its claims redeemed |
| **a node frozen is survived** | its node's lock released at its session timeout, its leases taken over then and not before; every session it had ended by a survivor's fencing a heartbeat later, every lock it held with them, and none past its own bound; no survivor waiting on one of its sessions longer (`pg_blocking_pids`); then as for a kill |

And across both deaths, every claim of Epics 6 to 8 holds: no payment made twice, no event
recorded twice, no fact consumed twice, the ledger balancing to the cent, every log
verifying.

## 6. Proofs

- The node and its leaderships, on PostgreSQL: a second process refused a node that is
  taken, and admitted once its holder's session ends; a role held by one node at a time; a
  standby node taking a role when its leader leaves, is killed, or goes silent past its
  session timeout; a node whose session the server ended counting itself out of every role
  at once, then joining again; a node whose name another process took meanwhile stopping.
- The supervisor: a led service steps only while leading, reports standby, and is healthy;
  drains only as a leader; resigns as it closes; joins before the engines open and leaves
  after everything has closed.
- Leases: a lease of a node that is gone claimed at once, one of a live node not before it
  runs out, the call in flight recorded lost and made again, the old relay's outcome refused;
  version 7 upgraded in place.
- The settler: two nodes settling disjoint halves of one outbox, each into its own log, and
  verifying together; a delivery of another node's plan left alone.
- Bounded sessions: an inbox, a relay, a governor and a vacuum that stop inside a
  transaction release their locks within the bound.
- Recovery that waits out a predecessor's transaction.
- Two daemons as processes on one database: one killed with a lease in hand, the other taking
  its lease at once and its vacuum leadership after; one frozen, the other ending each of its
  sessions once its session times out.
- Fencing: a gone node's sessions ended at a survivor's heartbeat, its lock released with
  them; a live node's, the survivor's own, the next incarnation's and what no node opened
  left alone; a node without the privilege saying so once. A daemon's node refusing a
  database without Interlock's storage.
- The soak (§5); the mutation pass.

## 7. Sequence

1. This design.
2. The lockfile, at the version the bump named.
3. Nodes and leadership: `interlock.cluster`, `[cluster]`, the supervisor, the metrics.
4. Leases that follow their node: storage version 8.
5. The daemon in a cluster: the singletons, the settler's partition, bounded sessions,
   connection names, recovery, `interlock daemon --node`.
6. The soak as a cluster, and its chaos.
7. The documents, the mutation pass and the whole suite.

## 8. Limits

- **A node's deliveries wait for it.** Settlement needs the node's chains and receipt log, on
  its own volume: a node that never comes back leaves its deliveries unsettled until its
  volume is given to another process as that node. Its plans' payments are made, its
  webhooks recorded and its facts consumed by the rest of the cluster meanwhile.
- **Agents die with their node.** Agents run inside the daemon. A plan in flight on a node
  that dies is rolled back, or committed and recovered by the node's next incarnation; the
  agent that submitted it is gone, and the agents of the other nodes carry on.
- **A frozen node is found by the server's timeouts.** Its leases and leaderships pass to
  others after `session_timeout_seconds`, its transactions end within their bounds; until
  then what it holds waits. A shorter timeout finds it sooner, and ends sooner the session
  of a node that only paused.
- **A frozen node keeps its files.** Its chain and receipt log locks are the kernel's, held
  until its process ends: a node's next incarnation starts after its predecessor is gone, as
  a StatefulSet guarantees.
- **The operator log is a shared file.** Every node reads it; the vacuum and the operators
  write it in turn under its lock, which the shared volume must honour.
- **The node's session needs a session.** A transaction-mode pooler cannot carry it; every
  other connection may go through one, as before.
- **Fencing trusts names.** A session called `interlock-<part>@<node>` is taken for that
  node's: a connection of something else that calls itself so is ended when the node is
  gone.
- **A superuser's sessions are fenced only by a superuser.** Run the parts, the ledger
  included, as roles of their own; one opened as a superuser holds what it holds to its own
  bound when its node freezes.
- **A stage's bounds are its transaction's.** They are `SET LOCAL`, as a transaction-mode
  pooler needs. A statement past its bound aborts the transaction, which releases its locks,
  and the session stays, idle in the aborted transaction and holding nothing, until a
  survivor fences it or its process ends.
- **A plan committed by a node that died before its action receipt** has no action receipt,
  and its deliveries are settled without delivery receipts, as a commit recovered after a
  crash always was (§9).
- **SQLite has no cluster.** One file has one host.

## 9. As built

- **Nodes and leadership** (`interlock.cluster`, step 3): as §1. A heartbeat asks only
  whether the session still holds the node's lock: a session that holds it holds every role
  it took, since a session-level lock ends only with an unlock, which resigning records, or
  with the session. One that no longer holds it is what a transaction-mode pooler in front
  of the node's session would leave, and the node counts itself out and joins again.
- **Leases that follow their node** (storage version 8, step 4): as §2. The test of a node
  gone is a shared try of its lock, held to the end of the claim's transaction: it reads no
  `pg_locks`, and keeps the node from joining again mid-claim. A gone node's leases are
  claimed before the messages due: a lease taken over still says it runs to its expiry, and
  ordered by that, a dead node's work in flight waited behind every message due under a
  backlog. The order costs a sort only while some node is gone.
- **The daemon as a node** (step 5): as §3, but for one thing. §3.3 bounds the settler's and
  the vacuum's sessions too; they are not bounded. Each transaction they open is a read-only
  snapshot, which holds no lock a writer waits for and is verified inside for as long as the
  history takes, or a single statement: a settlement, a compaction. A bound would cut a long
  survey short. Fencing ends them with the rest of a gone node's sessions.
- **Fencing** (§1.5) was not in the design. The soak's freeze showed what the bounds alone
  allow: the frozen node had three sessions queued for the ledger's writer lock, each took
  it in turn and held it for its four-second idle bound, and the rest of the cluster waited
  11.8 s for the ledger, three bounds one after another. With the default ten-second bound
  and a busier node, that passes a governor's thirty-second lock timeout. Two rules came
  with it: a node is named in 40 characters, so that its connections' names hold it whole;
  and a daemon's node joins only the database Interlock is installed in, since a relay that
  looked for the nodes' locks in another database would find every node gone, and take every
  live node's leases over.
- **What the soak found**, and what changed for it:
  - A node froze 57 ms after a plan's commit record, before its action receipt: the engine
    was booking the charge, which waits for the ledger's writer lock. The record names the
    receipt, so the node's next incarnation waited for it on every pass, for good: the
    delivery was never settled, its outbox row never pruned, and the run never settled. A
    receipt is now owed while the engine call that chose its id runs
    (`ReceiptIssuer.owe`, `owes`, `forgo`). One the chain names and nothing owes was never
    issued and never will be: its delivery is settled without a delivery receipt, the
    settlement naming the receipt and why, as a commit recovered after a crash always was.
    The same change closes the window before the commit record, in which a settler found no
    receipt for a plan whose stage had committed and settled its delivery without one for
    good: a delivery whose stage has a commit intent with no outcome after it waits. Exactly
    once accepts a delivery settled without a receipt only for a plan in flight on a node
    that died, whose commit names a receipt its log does not hold.
  - A stage frozen between its `BEGIN` and its `SET LOCAL` bounds sat in its transaction
    with no bound at all. They are one message now.
  - A frozen stage whose statement passed its bound aborted, and released its locks; but an
    abort reverts `SET LOCAL`, so the session stayed, idle in the aborted transaction and
    holding nothing. The frozen claim measured sessions ending rather than locks released,
    and failed: it measures both now, and fencing ends the sessions.
  - A vacuum on standby exported none of its families, which the metrics claim reads on
    every node: they are exported at zero from the start.
  - The harness picked a death's moment by reading the database, then signalling: the node
    finished its call in between, and was frozen with none in flight. It now stops the node
    first, looks, and lets it go on if it is not there yet; poised, the node is killed, or
    left frozen.
- **The mutation pass**: 59 mechanisms, each removed in turn, and every one fails a test.
  The first pass left three alive, and each called for a change now in the tree. The roles
  a node held were cleared twice, where its session was lost and again where it joined:
  either alone was enough, so neither was guarded; they are cleared where the session is
  lost, as §1.1 says. The test of a standby vacuum's families asked for a value, which is 0
  for a series never written as much as for one written at zero: it reads the exposition.
  And a daemon whose name another process took while it ran exited 3 only in an in-process
  test: a daemon is now paused while its session ends and its name is taken, and exits 3.
  Written ahead of the pass, for what it would have found unguarded: the wiring of a node's
  parts (their roles, the settler's partition, each session's bound and name, recovery's
  wait), which only the soak exercised, and fencing now hides from it; what fencing leaves
  alone (a next incarnation waiting to join, a name PostgreSQL cut); a session that no
  longer holds its node's lock, as a transaction-mode pooler leaves it; and a daemon's
  node refusing a database without Interlock.
- **The soak** (step 6): as §5, the frozen claim with fencing. Five minutes on
  `postgres:16`, three nodes, each with four agents of three plans in flight, four engines
  and two relays: every claim holds. 8,939 plans submitted and 8,177 charged, each once;
  2,010 payment calls, each acted on once, and 142 replays of a key's result; 2,007 delivery
  receipts across three logs, and three deliveries settled without one, each of a plan its
  dead node never issued a receipt for. The killed node's lock was released 0.02 s after it
  died and its lease taken over 0.08 s after. The frozen node's lock was released 3.79 s
  after it froze (a four-second session timeout), its lease taken over 3.84 s after, and
  every session it had ended 3.90 s after, by node-1's fencing; the longest any survivor
  waited on one of its sessions was 3.45 s. `tests/test_soak.py` runs a minute and a half
  of it.
