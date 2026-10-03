"""FROZEN: the outbox's PostgreSQL objects as version 3 installed them.

``src/interlock/outbox_sql.py`` at interlock main ``76a6f7f`` (Epic 3),
verbatim below this note, with version 3's sink mirror and grants after it,
for ``tests/test_pg_upgrade.py``: version 4 is installed over a database
version 3 installed. Never edit this file.

The original docstring follows.

The transactional outbox's PostgreSQL objects (``docs/OUTBOX_DESIGN.md``).

Installed by :func:`interlock.postgres.install`, after the stage's own objects.
Three kinds of function, by who may call them:

- **The stage** writes a request with :sql:`interlock.enqueue`, gated by the
  stage's token, and reads its own back with :sql:`interlock.stage_outbox`.
- **The relay** (:mod:`interlock.relay`) moves a message through delivery with
  the ``relay_*`` functions: claim a lease, record the call it is about to
  make, record what came back, hold, defer or refuse. It writes nothing else.
- **An operator** releases, cancels and requeues with the ``outbox_*``
  functions, granted to no role: they run as the installer.

Every change to a message's delivery state is a row in
``interlock.outbox_attempts``: the message's delivery log. A trigger links each
row to the one before it by hash, from a genesis hash bound to the request, so
no writer, the installer included, can append a row that does not link. The
log is append-only, like the outbox itself. :mod:`interlock.deliveries`
recomputes every link outside the database.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import timedelta
from typing import Any, Final

__all__ = [
    "OUTBOX_FUNCTIONS",
    "OUTBOX_GUARD",
    "OUTBOX_TABLES",
    "OUTBOX_TRIGGERS",
    "OUTBOX_TRIGGER_NAMES",
    "RELAY_FUNCTIONS",
    "STAGE_OUTBOX_FUNCTIONS",
]

OUTBOX_GUARD: Final = r"""
-- The outbox of a pre-release build (Epic 2, phases 0 and 1) kept a different
-- delivery log. No relay existed to write it, but its tables cannot be
-- reshaped in place: refuse, and say what to do.
DO $guard$
BEGIN
    IF pg_catalog.to_regclass('interlock.outbox_attempts') IS NOT NULL
       AND NOT EXISTS (
           SELECT 1 FROM pg_catalog.pg_attribute AS a
            WHERE a.attrelid = pg_catalog.to_regclass('interlock.outbox_attempts')
              AND a.attname = 'event_hash' AND NOT a.attisdropped) THEN
        RAISE EXCEPTION '%', 'interlock: this database holds an outbox installed by a '
            || 'pre-release build; drop interlock.outbox_attempts, interlock.outbox_state, '
            || 'interlock.outbox and interlock.sinks, then install again'
            USING ERRCODE = 'IL005';
    END IF;
END
$guard$;
"""

OUTBOX_TABLES: Final = r"""
-- The registry, mirrored from configuration. No endpoints, no credentials.
CREATE TABLE IF NOT EXISTS interlock.sinks (
    name              text PRIMARY KEY,
    kind              text NOT NULL DEFAULT 'http'
                      CHECK (kind IN ('http', 'stripe', 'sendgrid')),
    operations        text[] NOT NULL,
    cost_per_call     text NOT NULL,
    idempotency       text NOT NULL CHECK (idempotency IN ('header', 'none')),
    max_payload_bytes integer NOT NULL CHECK (max_payload_bytes > 0),
    not_after_seconds integer NOT NULL CHECK (not_after_seconds > 0),
    max_attempts      integer NOT NULL CHECK (max_attempts > 0),
    backoff_base_ms   integer NOT NULL CHECK (backoff_base_ms > 0),
    backoff_cap_ms    integer NOT NULL CHECK (backoff_cap_ms >= backoff_base_ms),
    unknown_outcome   text NOT NULL CHECK (unknown_outcome IN ('redeliver', 'dead-letter')),
    config_hash       text NOT NULL,
    enabled           boolean NOT NULL DEFAULT true
);
REVOKE ALL ON interlock.sinks FROM PUBLIC;

-- The obligation: the request the checkers adjudicated, priced as the
-- registry priced it when it was staged. Append-only.
CREATE TABLE IF NOT EXISTS interlock.outbox (
    message_id      uuid PRIMARY KEY,
    stage_id        uuid NOT NULL REFERENCES interlock.stages (stage_id),
    plan_id         text NOT NULL,
    scope_id        text NOT NULL,
    effect_id       text NOT NULL,
    seq             integer NOT NULL,
    depends_on      text[] NOT NULL DEFAULT '{}',
    sink            text NOT NULL REFERENCES interlock.sinks (name),
    operation       text NOT NULL,
    tenant_id       text,
    payload         jsonb NOT NULL,
    payload_hash    text NOT NULL,
    idempotency_key text NOT NULL UNIQUE,
    cost            text NOT NULL,
    compensation    jsonb,
    compensates     uuid REFERENCES interlock.outbox (message_id),
    not_after       timestamptz NOT NULL,
    enqueued_at     timestamptz NOT NULL,
    UNIQUE (stage_id, effect_id)
);
CREATE INDEX IF NOT EXISTS outbox_scope ON interlock.outbox (scope_id);
REVOKE ALL ON interlock.outbox FROM PUBLIC;

-- Delivery state, changed only through the relay's and operators' functions.
-- `fence` is the lease's generation: every claim takes the next one, and a
-- relay may change the state only under the fence it was leased with.
-- `log_seq` and `log_head` are the head of the message's delivery log.
CREATE TABLE IF NOT EXISTS interlock.outbox_state (
    message_id      uuid PRIMARY KEY REFERENCES interlock.outbox (message_id),
    state           text NOT NULL DEFAULT 'pending'
                    CHECK (state IN ('pending', 'leased', 'held', 'delivered', 'dead',
                                     'cancelled')),
    attempts        integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    attempt_floor   integer NOT NULL DEFAULT 0 CHECK (attempt_floor >= 0),
    fence           bigint NOT NULL DEFAULT 0,
    lease_owner     text,
    lease_expires   timestamptz,
    next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    reason          text,
    log_seq         integer NOT NULL DEFAULT 0,
    log_head        text NOT NULL,
    updated_at      timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX IF NOT EXISTS outbox_ready ON interlock.outbox_state (next_attempt_at)
    WHERE state IN ('pending', 'leased');
REVOKE ALL ON interlock.outbox_state FROM PUBLIC;

-- The delivery log: every call started, every outcome, every hold, release,
-- cancellation and requeue, hash-linked per message. Append-only. Rows are
-- linked by the outbox_log_link trigger, never by the writer.
CREATE TABLE IF NOT EXISTS interlock.outbox_attempts (
    message_id      uuid NOT NULL REFERENCES interlock.outbox (message_id),
    seq             integer NOT NULL CHECK (seq > 0),
    attempt         integer CHECK (attempt > 0),
    event           text NOT NULL
                    CHECK (event IN ('sending', 'delivered', 'retryable', 'permanent',
                                     'unknown', 'lost', 'held', 'deferred', 'expired',
                                     'refused', 'dependency_failed', 'released', 'requeued',
                                     'cancelled', 'compensated')),
    actor           text NOT NULL,
    at              timestamptz NOT NULL,
    status_code     integer,
    response_digest text,
    detail          text,
    state_after     text CHECK (state_after IN ('pending', 'leased', 'held', 'delivered',
                                                'dead', 'cancelled')),
    remote_ref      text,
    authority       text,
    prev_hash       text NOT NULL,
    event_hash      text NOT NULL,
    PRIMARY KEY (message_id, seq)
);
REVOKE ALL ON interlock.outbox_attempts FROM PUBLIC;

-- When each version was first installed here. An operator's row without an
-- authority is version 2's when it is older than version 3; any later one was
-- written around Interlock (docs/EPIC3_DESIGN.md §6).
CREATE TABLE IF NOT EXISTS interlock.outbox_epochs (
    version text PRIMARY KEY,
    at      timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp()
);
REVOKE ALL ON interlock.outbox_epochs FROM PUBLIC;
INSERT INTO interlock.outbox_epochs (version) VALUES ('3') ON CONFLICT (version) DO NOTHING;

-- Version 3, in place over version 2. Every column it adds is NULL in every
-- row written before, and a row with neither remote_ref nor authority hashes
-- as version 2 hashed it: every delivery log written under 2 still verifies.
ALTER TABLE interlock.sinks
    ADD COLUMN IF NOT EXISTS kind text NOT NULL DEFAULT 'http'
        CHECK (kind IN ('http', 'stripe', 'sendgrid'));
ALTER TABLE interlock.outbox
    ADD COLUMN IF NOT EXISTS compensates uuid REFERENCES interlock.outbox (message_id);
ALTER TABLE interlock.outbox_attempts
    ADD COLUMN IF NOT EXISTS remote_ref text,
    ADD COLUMN IF NOT EXISTS authority text;
DO $upgrade$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint
         WHERE conrelid = 'interlock.outbox_attempts'::regclass
           AND conname = 'outbox_attempts_event_check'
           AND pg_catalog.pg_get_constraintdef(oid) LIKE '%compensated%') THEN
        ALTER TABLE interlock.outbox_attempts
            DROP CONSTRAINT IF EXISTS outbox_attempts_event_check;
        ALTER TABLE interlock.outbox_attempts
            ADD CONSTRAINT outbox_attempts_event_check
            CHECK (event IN ('sending', 'delivered', 'retryable', 'permanent', 'unknown',
                             'lost', 'held', 'deferred', 'expired', 'refused',
                             'dependency_failed', 'released', 'requeued', 'cancelled',
                             'compensated'));
    END IF;
END
$upgrade$;
"""

STAGE_OUTBOX_FUNCTIONS: Final = r"""
-- The phase 0-1 signature, without the scope; a function is identified by its
-- argument types, so it would survive CREATE OR REPLACE as an overload.
DROP FUNCTION IF EXISTS interlock.enqueue(
    bytea, uuid, text, integer, text[], text, text, text, text, text, text, text, integer);

-- Length-prefixed framing: each field as `<UTF-8 byte length>:<text>`, a NULL
-- as `-`. Unambiguous, and reproduced byte for byte by interlock.deliveries.
CREATE OR REPLACE FUNCTION interlock.outbox_frame(VARIADIC p_fields text[])
RETURNS text
LANGUAGE sql IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, pg_temp
AS $fn$
    SELECT coalesce(
        pg_catalog.string_agg(
            CASE WHEN t.f IS NULL THEN '-'
                 ELSE pg_catalog.octet_length(pg_catalog.convert_to(t.f, 'UTF8'))::text
                      || ':' || t.f
            END,
            '' ORDER BY t.i),
        '')
      FROM pg_catalog.unnest(p_fields) WITH ORDINALITY AS t (f, i)
$fn$;

CREATE OR REPLACE FUNCTION interlock.outbox_digest(VARIADIC p_fields text[])
RETURNS text
LANGUAGE sql IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, pg_temp
AS $fn$
    SELECT pg_catalog.encode(
        pg_catalog.sha256(pg_catalog.convert_to(interlock.outbox_frame(VARIADIC p_fields), 'UTF8')),
        'hex')
$fn$;

-- An instant as the log hashes it: UTC, to the microsecond, whatever the
-- session's time zone or DateStyle.
CREATE OR REPLACE FUNCTION interlock.outbox_instant(p_at timestamptz)
RETURNS text
LANGUAGE sql STABLE PARALLEL SAFE
SET search_path = pg_catalog, pg_temp
AS $fn$
    SELECT pg_catalog.to_char(p_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
$fn$;

-- Where a message's delivery log starts: bound to the request it delivers.
CREATE OR REPLACE FUNCTION interlock.outbox_genesis(
    p_message uuid, p_stage uuid, p_plan text, p_scope text, p_effect text, p_sink text,
    p_operation text, p_idempotency_key text, p_payload_hash text)
RETURNS text
LANGUAGE sql IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, pg_temp
AS $fn$
    SELECT interlock.outbox_digest(
        'interlock-outbox-genesis-v1', p_message::text, p_stage::text, p_plan, p_scope,
        p_effect, p_sink, p_operation, p_idempotency_key, p_payload_hash)
$fn$;

-- A row's hash. A row with neither a remote reference nor an operator's
-- authority hashes as version 2 hashed every row (event-v1), so a log written
-- under version 2 verifies unchanged; a row with either frames both (event-v2).
DROP FUNCTION IF EXISTS interlock.outbox_event_hash(
    text, uuid, integer, integer, text, text, timestamptz, integer, text, text, text);
CREATE OR REPLACE FUNCTION interlock.outbox_event_hash(
    p_prev text, p_message uuid, p_seq integer, p_attempt integer, p_event text,
    p_actor text, p_at timestamptz, p_status integer, p_digest text, p_detail text,
    p_state_after text, p_remote_ref text, p_authority text)
RETURNS text
LANGUAGE sql STABLE PARALLEL SAFE
SET search_path = pg_catalog, pg_temp
AS $fn$
    SELECT CASE
        WHEN p_remote_ref IS NULL AND p_authority IS NULL THEN interlock.outbox_digest(
            'interlock-outbox-event-v1', p_prev, p_message::text, p_seq::text,
            p_attempt::text, p_event, p_actor, interlock.outbox_instant(p_at),
            p_status::text, p_digest, p_detail, p_state_after)
        ELSE interlock.outbox_digest(
            'interlock-outbox-event-v2', p_prev, p_message::text, p_seq::text,
            p_attempt::text, p_event, p_actor, interlock.outbox_instant(p_at),
            p_status::text, p_digest, p_detail, p_state_after, p_remote_ref, p_authority)
    END
$fn$;

-- Writes one outbound request, its delivery state and the head of its
-- delivery log into the outbox, in the stage's own transaction: it commits
-- with the stage's effects and its marker, or not at all. Only with the
-- stage's token: every agent statement runs in this transaction as this role,
-- and none of them may enqueue. The request is priced here, from the
-- registry this database holds, and the price is stored with it.
CREATE OR REPLACE FUNCTION interlock.enqueue(
    p_token bytea,
    p_message uuid,
    p_effect text,
    p_seq integer,
    p_depends text[],
    p_sink text,
    p_operation text,
    p_tenant text,
    p_payload text,
    p_payload_hash text,
    p_idempotency_key text,
    p_compensation text,
    p_not_after_seconds integer,
    p_scope text
)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
    stage uuid;
    plan text;
    expected bytea;
    sink_ops text[];
    sink_bytes integer;
    sink_seconds integer;
    sink_cost text;
    sink_kind text;
    problem text;
    bytes bytea := pg_catalog.convert_to(p_payload, 'UTF8');
    -- One instant: not_after is exactly its window past enqueued_at.
    enqueued timestamptz := pg_catalog.clock_timestamp();
BEGIN
    SELECT s.stage_id, s.plan_id, s.enqueue_hash INTO stage, plan, expected
      FROM interlock.stages s
     WHERE s.xid = pg_catalog.pg_current_xact_id();
    IF stage IS NULL OR expected IS NULL
       OR pg_catalog.sha256(p_token) IS DISTINCT FROM expected THEN
        RAISE EXCEPTION 'interlock: this transaction''s stage did not authorize an enqueue'
            USING ERRCODE = 'IL002';
    END IF;
    IF p_scope IS NULL OR p_scope = '' THEN
        RAISE EXCEPTION 'interlock: an outbound request needs the scope that pays for it'
            USING ERRCODE = 'IL002';
    END IF;
    SELECT k.operations, k.max_payload_bytes, k.not_after_seconds, k.cost_per_call, k.kind
      INTO sink_ops, sink_bytes, sink_seconds, sink_cost, sink_kind
      FROM interlock.sinks k
     WHERE k.name = p_sink AND k.enabled;
    IF sink_ops IS NULL THEN
        RAISE EXCEPTION 'interlock: no enabled sink named % is installed', p_sink
            USING ERRCODE = 'IL004',
                  DETAIL = pg_catalog.json_build_object(
                      'reason', 'unregistered_sink', 'sink', p_sink)::text;
    END IF;
    IF NOT (p_operation = ANY (sink_ops)) THEN
        RAISE EXCEPTION 'interlock: sink % installs no operation %', p_sink, p_operation
            USING ERRCODE = 'IL004',
                  DETAIL = pg_catalog.json_build_object(
                      'reason', 'unregistered_operation', 'sink', p_sink)::text;
    END IF;
    IF pg_catalog.octet_length(bytes) > sink_bytes THEN
        RAISE EXCEPTION 'interlock: payload of % bytes exceeds sink %''s bound of %',
            pg_catalog.octet_length(bytes), p_sink, sink_bytes
            USING ERRCODE = 'IL004',
                  DETAIL = pg_catalog.json_build_object(
                      'reason', 'payload_size', 'sink', p_sink)::text;
    END IF;
    -- Recomputed here, over the exact bytes sent: what the checkers
    -- adjudicate and the relay sends is the payload the plan hashed.
    IF pg_catalog.encode(pg_catalog.sha256(bytes), 'hex') <> p_payload_hash THEN
        RAISE EXCEPTION 'interlock: payload does not match its hash'
            USING ERRCODE = 'IL004',
                  DETAIL = pg_catalog.json_build_object(
                      'reason', 'payload_hash', 'sink', p_sink)::text;
    END IF;
    -- A charge carries the refund that undoes exactly it, whatever registry
    -- the engine that staged it was configured with (docs/EPIC3_DESIGN.md §4.1).
    IF sink_kind = 'stripe'
       AND p_operation IN ('payment_intents.create', 'charges.create') THEN
        problem := interlock.stripe_compensation_problem(
            p_operation, p_payload::jsonb, p_compensation::jsonb);
        IF problem IS NOT NULL THEN
            RAISE EXCEPTION 'interlock: sink % refuses the request: %', p_sink, problem
                USING ERRCODE = 'IL004',
                      DETAIL = pg_catalog.json_build_object(
                          'reason', 'compensation', 'sink', p_sink)::text;
        END IF;
    END IF;
    INSERT INTO interlock.outbox (
        message_id, stage_id, plan_id, scope_id, effect_id, seq, depends_on, sink,
        operation, tenant_id, payload, payload_hash, idempotency_key, cost, compensation,
        not_after, enqueued_at
    ) VALUES (
        p_message, stage, plan, p_scope, p_effect, p_seq, coalesce(p_depends, '{}'), p_sink,
        p_operation, p_tenant, p_payload::jsonb, p_payload_hash, p_idempotency_key,
        sink_cost, p_compensation::jsonb,
        enqueued + pg_catalog.make_interval(secs => coalesce(p_not_after_seconds, sink_seconds)),
        enqueued
    );
    INSERT INTO interlock.outbox_state (message_id, log_head)
    VALUES (
        p_message,
        interlock.outbox_genesis(p_message, stage, plan, p_scope, p_effect, p_sink, p_operation,
                                 p_idempotency_key, p_payload_hash)
    );
END
$fn$;

-- interlock.stripe.compensation_problem, word for word: what is wrong with
-- the refund a Stripe charge carries, or NULL when it undoes exactly it.
CREATE OR REPLACE FUNCTION interlock.stripe_compensation_problem(
    p_operation text, p_charge jsonb, p_compensation jsonb)
RETURNS text
LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
    named text := CASE p_operation WHEN 'payment_intents.create' THEN 'payment_intent'
                                   ELSE 'charge' END;
    other text := CASE p_operation WHEN 'payment_intents.create' THEN 'charge'
                                   ELSE 'payment_intent' END;
    refund jsonb := p_compensation -> 'payload';
    amount jsonb;
    charged jsonb := p_charge -> 'amount';
BEGIN
    IF p_compensation IS NULL THEN
        RETURN p_operation || ' takes money, and the request carries no refund to give it back';
    END IF;
    IF p_compensation ->> 'operation' IS DISTINCT FROM 'refunds.create' THEN
        RETURN p_operation || ' is undone by refunds.create, not '
            || coalesce(p_compensation ->> 'operation', 'None');
    END IF;
    IF refund IS NULL OR pg_catalog.jsonb_typeof(refund) <> 'object' THEN
        RETURN 'the refund has no payload';
    END IF;
    IF (refund -> named) IS DISTINCT FROM '{"$bind": "delivered.id"}'::jsonb THEN
        RETURN 'the refund names the ' || named
            || ' it undoes by {"$bind": "delivered.id"}, never by a literal id';
    END IF;
    IF refund ? other THEN
        RETURN 'the refund of a ' || named || ' names no ' || other;
    END IF;
    IF refund ? 'currency' THEN
        RETURN 'the refund names no currency: a refund is in the charge''s';
    END IF;
    amount := refund -> 'amount';
    IF amount IS NOT NULL AND (
        pg_catalog.jsonb_typeof(amount) <> 'number'
        OR charged IS NULL OR pg_catalog.jsonb_typeof(charged) <> 'number'
        OR amount::text !~ '^[0-9]+$' OR charged::text !~ '^[0-9]+$'
        OR amount::text::numeric <= 0 OR amount::text::numeric > charged::text::numeric) THEN
        RETURN 'the refund gives back at most the ' || coalesce(charged::text, 'None')
            || ' charged, not ' || amount::text;
    END IF;
    RETURN NULL;
END
$fn$;

-- This stage's outbound requests, as written, for the diff.
CREATE OR REPLACE FUNCTION interlock.stage_outbox(p_limit bigint)
RETURNS TABLE (
    out_message uuid, out_effect text, out_depends text[], out_sink text,
    out_operation text, out_tenant text, out_payload text, out_payload_hash text,
    out_idempotency_key text, out_cost text
)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
BEGIN
    RETURN QUERY
        SELECT o.message_id, o.effect_id, o.depends_on, o.sink, o.operation, o.tenant_id,
               o.payload::text, o.payload_hash, o.idempotency_key, o.cost
          FROM interlock.outbox AS o
          JOIN interlock.stages AS s ON s.stage_id = o.stage_id
         WHERE s.xid = pg_catalog.pg_current_xact_id()
         ORDER BY o.seq
         LIMIT p_limit;
END
$fn$;

-- The request the checkers adjudicated, and its delivery log, are never
-- edited. Delivery state lives in outbox_state.
CREATE OR REPLACE FUNCTION interlock.outbox_append_only()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $fn$
BEGIN
    RAISE EXCEPTION 'interlock: % is append-only; % refused', TG_TABLE_NAME, TG_OP
        USING ERRCODE = 'IL002';
END
$fn$;

-- Links a delivery-log row to its message's log: assigns its position, the
-- hash of the row before it, its instant and its own hash, and advances the
-- head. Whatever the writer supplied for those is overwritten.
CREATE OR REPLACE FUNCTION interlock.outbox_log_link()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
    head_seq integer;
    head text;
BEGIN
    SELECT s.log_seq, s.log_head INTO head_seq, head
      FROM interlock.outbox_state AS s
     WHERE s.message_id = NEW.message_id
       FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'interlock: message % has no delivery state', NEW.message_id
            USING ERRCODE = 'IL002';
    END IF;
    IF NEW.event IN ('released', 'cancelled', 'requeued', 'compensated')
       AND (NEW.authority IS NULL OR NEW.authority !~ '^[0-9a-f]{64}$') THEN
        RAISE EXCEPTION 'interlock: an operator''s % needs the authority of a signed intent',
            NEW.event USING ERRCODE = 'IL007';
    END IF;
    NEW.seq := head_seq + 1;
    NEW.prev_hash := head;
    NEW.at := pg_catalog.clock_timestamp();
    NEW.event_hash := interlock.outbox_event_hash(
        NEW.prev_hash, NEW.message_id, NEW.seq, NEW.attempt, NEW.event, NEW.actor, NEW.at,
        NEW.status_code, NEW.response_digest, NEW.detail, NEW.state_after, NEW.remote_ref,
        NEW.authority);
    UPDATE interlock.outbox_state
       SET log_seq = NEW.seq, log_head = NEW.event_hash
     WHERE message_id = NEW.message_id;
    RETURN NEW;
END
$fn$;
"""

RELAY_FUNCTIONS: Final = r"""
-- Appends one row to a message's delivery log. Internal: granted to no one.
DROP FUNCTION IF EXISTS interlock.outbox_log(
    uuid, integer, text, text, integer, text, text, text);
CREATE OR REPLACE FUNCTION interlock.outbox_log(
    p_message uuid, p_attempt integer, p_event text, p_actor text, p_status integer,
    p_digest text, p_detail text, p_state_after text, p_remote_ref text DEFAULT NULL,
    p_authority text DEFAULT NULL)
RETURNS void
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $fn$
BEGIN
    INSERT INTO interlock.outbox_attempts (
        message_id, seq, attempt, event, actor, at, status_code, response_digest, detail,
        state_after, remote_ref, authority, prev_hash, event_hash)
    VALUES (
        p_message, 1, p_attempt, p_event, pg_catalog.left(coalesce(p_actor, '?'), 200),
        pg_catalog.clock_timestamp(), p_status, pg_catalog.left(p_digest, 128),
        pg_catalog.left(p_detail, 1000), p_state_after, pg_catalog.left(p_remote_ref, 255),
        p_authority, '', '');
END
$fn$;

-- Moves a message to `p_state` and ends any lease on it. Internal.
CREATE OR REPLACE FUNCTION interlock.outbox_settle(
    p_message uuid, p_state text, p_reason text, p_next timestamptz DEFAULT NULL)
RETURNS void
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $fn$
BEGIN
    UPDATE interlock.outbox_state
       SET state = p_state,
           reason = pg_catalog.left(p_reason, 1000),
           lease_owner = NULL,
           lease_expires = NULL,
           next_attempt_at = coalesce(p_next, pg_catalog.clock_timestamp()),
           updated_at = pg_catalog.clock_timestamp()
     WHERE message_id = p_message;
END
$fn$;

-- A message that will not be delivered takes every request that waits for it
-- with it: dependants still pending or held die, and theirs after them.
-- Internal.
CREATE OR REPLACE FUNCTION interlock.outbox_fail_dependants(p_message uuid, p_actor text)
RETURNS integer
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
    dep record;
    failed integer := 0;
BEGIN
    FOR dep IN
        SELECT d.message_id, o.effect_id
          FROM interlock.outbox AS o
          JOIN interlock.outbox AS d
            ON d.stage_id = o.stage_id AND o.effect_id = ANY (d.depends_on)
          JOIN interlock.outbox_state AS ds ON ds.message_id = d.message_id
         WHERE o.message_id = p_message AND ds.state IN ('pending', 'held')
         ORDER BY d.seq
           FOR UPDATE OF ds
    LOOP
        PERFORM interlock.outbox_log(
            dep.message_id, NULL, 'dependency_failed', p_actor, NULL, NULL,
            'waits for ' || dep.effect_id || ', which will not be delivered', 'dead');
        PERFORM interlock.outbox_settle(
            dep.message_id, 'dead', 'dependency failed: ' || dep.effect_id);
        failed := failed + 1 + interlock.outbox_fail_dependants(dep.message_id, p_actor);
    END LOOP;
    RETURN failed;
END
$fn$;

-- Leases up to p_limit messages that are due, whose dependencies are all
-- delivered, to p_relay, for p_lease_seconds. FOR UPDATE SKIP LOCKED: relays
-- racing for work never wait on each other and never take the same message.
-- A lease that ran out after its relay recorded a call and before it recorded
-- an outcome is recorded as `lost` first: the call's outcome is unknown, and
-- the sink may have acted. A message past its deadline is expired instead of
-- leased.
CREATE OR REPLACE FUNCTION interlock.relay_claim(
    p_relay text, p_lease_seconds double precision, p_limit integer,
    p_sinks text[] DEFAULT NULL)
RETURNS TABLE (
    out_message uuid, out_fence bigint, out_attempts integer, out_attempt_floor integer,
    out_plan text, out_scope text, out_effect text, out_sink text, out_operation text,
    out_tenant text, out_payload text, out_payload_hash text, out_idempotency_key text,
    out_not_after timestamptz, out_idempotency text, out_max_attempts integer,
    out_backoff_base_ms integer, out_backoff_cap_ms integer, out_unknown_outcome text,
    out_lease_expires timestamptz
)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
    m record;
    now_ts timestamptz := pg_catalog.clock_timestamp();
    lease_until timestamptz;
    last_event text;
    last_attempt integer;
    fate text;
BEGIN
    IF coalesce(p_relay, '') = '' OR coalesce(p_lease_seconds, 0) <= 0
       OR coalesce(p_limit, 0) <= 0 THEN
        RAISE EXCEPTION 'interlock: a claim needs a relay id, a positive lease and a positive limit'
            USING ERRCODE = '22023';
    END IF;
    lease_until := now_ts + pg_catalog.make_interval(secs => p_lease_seconds);
    FOR m IN
        SELECT s.message_id, s.state, s.attempts, s.attempt_floor, s.lease_owner,
               o.plan_id, o.scope_id, o.effect_id, o.sink, o.operation, o.tenant_id,
               o.payload::text AS payload, o.payload_hash, o.idempotency_key, o.not_after,
               k.idempotency, k.max_attempts, k.backoff_base_ms, k.backoff_cap_ms,
               k.unknown_outcome
          FROM interlock.outbox_state AS s
          JOIN interlock.outbox AS o ON o.message_id = s.message_id
          JOIN interlock.sinks AS k ON k.name = o.sink
         WHERE s.state IN ('pending', 'leased')
           AND s.next_attempt_at <= now_ts
           AND (p_sinks IS NULL OR o.sink = ANY (p_sinks))
           AND NOT EXISTS (
                 SELECT 1
                   FROM interlock.outbox AS dep
                   JOIN interlock.outbox_state AS ds ON ds.message_id = dep.message_id
                  WHERE dep.stage_id = o.stage_id
                    AND dep.effect_id = ANY (o.depends_on)
                    AND ds.state <> 'delivered')
         ORDER BY s.next_attempt_at, o.enqueued_at, o.seq
         LIMIT p_limit
           FOR UPDATE OF s SKIP LOCKED
    LOOP
        IF m.state = 'leased' THEN
            last_event := NULL;
            SELECT a.event, a.attempt INTO last_event, last_attempt
              FROM interlock.outbox_attempts AS a
             WHERE a.message_id = m.message_id
             ORDER BY a.seq DESC
             LIMIT 1;
            IF last_event = 'sending' THEN
                fate := CASE
                    WHEN m.unknown_outcome = 'dead-letter'
                        THEN 'outcome unknown: the sink may have acted, and this sink''s '
                             || 'unknown outcomes are not redelivered'
                    WHEN m.attempts - m.attempt_floor >= m.max_attempts
                        THEN 'attempts exhausted'
                    ELSE NULL
                END;
                PERFORM interlock.outbox_log(
                    m.message_id, last_attempt, 'lost', p_relay, NULL, NULL,
                    'the lease of ' || coalesce(m.lease_owner, '?')
                        || ' ran out mid-call; the sink may have acted',
                    CASE WHEN fate IS NULL THEN 'pending' ELSE 'dead' END);
                IF fate IS NOT NULL THEN
                    PERFORM interlock.outbox_settle(m.message_id, 'dead', fate);
                    PERFORM interlock.outbox_fail_dependants(m.message_id, p_relay);
                    CONTINUE;
                END IF;
            END IF;
        END IF;
        IF m.not_after < now_ts THEN
            PERFORM interlock.outbox_log(
                m.message_id, NULL, 'expired', p_relay, NULL, NULL,
                'not delivered by its deadline, ' || interlock.outbox_instant(m.not_after),
                'dead');
            PERFORM interlock.outbox_settle(m.message_id, 'dead', 'expired');
            PERFORM interlock.outbox_fail_dependants(m.message_id, p_relay);
            CONTINUE;
        END IF;
        UPDATE interlock.outbox_state
           SET state = 'leased', fence = fence + 1, lease_owner = p_relay,
               lease_expires = lease_until, next_attempt_at = lease_until,
               updated_at = now_ts
         WHERE message_id = m.message_id
        RETURNING fence INTO out_fence;
        out_message := m.message_id;
        out_attempts := m.attempts;
        out_attempt_floor := m.attempt_floor;
        out_plan := m.plan_id;
        out_scope := m.scope_id;
        out_effect := m.effect_id;
        out_sink := m.sink;
        out_operation := m.operation;
        out_tenant := m.tenant_id;
        out_payload := m.payload;
        out_payload_hash := m.payload_hash;
        out_idempotency_key := m.idempotency_key;
        out_not_after := m.not_after;
        out_idempotency := m.idempotency;
        out_max_attempts := m.max_attempts;
        out_backoff_base_ms := m.backoff_base_ms;
        out_backoff_cap_ms := m.backoff_cap_ms;
        out_unknown_outcome := m.unknown_outcome;
        out_lease_expires := lease_until;
        RETURN NEXT;
    END LOOP;
END
$fn$;

-- Records the call p_relay is about to make, immediately before it makes it,
-- and returns the attempt's number. NULL when the call must not be made: the
-- lease is no longer this relay's, or has run out (another relay may take
-- the message at any moment), or the message expired, or its sink was
-- disabled (then it is held).
CREATE OR REPLACE FUNCTION interlock.relay_sending(
    p_message uuid, p_relay text, p_fence bigint, p_detail text)
RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
    s record;
    deadline timestamptz;
    sink_name text;
    sink_enabled boolean;
    now_ts timestamptz := pg_catalog.clock_timestamp();
BEGIN
    SELECT st.state, st.lease_owner, st.fence, st.lease_expires, st.attempts INTO s
      FROM interlock.outbox_state AS st
     WHERE st.message_id = p_message
       FOR UPDATE;
    IF NOT FOUND OR s.state <> 'leased' OR s.lease_owner IS DISTINCT FROM p_relay
       OR s.fence <> p_fence OR s.lease_expires <= now_ts THEN
        RETURN NULL;
    END IF;
    SELECT o.not_after, k.name, k.enabled INTO deadline, sink_name, sink_enabled
      FROM interlock.outbox AS o
      JOIN interlock.sinks AS k ON k.name = o.sink
     WHERE o.message_id = p_message;
    IF deadline < now_ts THEN
        PERFORM interlock.outbox_log(
            p_message, NULL, 'expired', p_relay, NULL, NULL,
            'not delivered by its deadline, ' || interlock.outbox_instant(deadline), 'dead');
        PERFORM interlock.outbox_settle(p_message, 'dead', 'expired');
        PERFORM interlock.outbox_fail_dependants(p_message, p_relay);
        RETURN NULL;
    END IF;
    IF NOT sink_enabled THEN
        PERFORM interlock.outbox_log(
            p_message, NULL, 'held', p_relay, NULL, NULL,
            'sink ' || sink_name || ' is disabled', 'held');
        PERFORM interlock.outbox_settle(p_message, 'held', 'sink disabled');
        RETURN NULL;
    END IF;
    UPDATE interlock.outbox_state
       SET attempts = attempts + 1, updated_at = now_ts
     WHERE message_id = p_message;
    PERFORM interlock.outbox_log(
        p_message, s.attempts + 1, 'sending', p_relay, NULL, NULL, p_detail, 'leased');
    RETURN s.attempts + 1;
END
$fn$;

-- Records what came back from attempt p_attempt, and returns the state the
-- message is now in: NULL when this relay no longer held the lease, in which
-- case the outcome is recorded and the state left to its holder. Except a
-- delivery: the sink acted, whoever held the lease, so the message is
-- delivered. A retry is due p_delay_ms from now, unless the attempts are
-- spent or the deadline would pass first.
DROP FUNCTION IF EXISTS interlock.relay_outcome(
    uuid, text, bigint, integer, text, integer, text, text, bigint);
CREATE OR REPLACE FUNCTION interlock.relay_outcome(
    p_message uuid, p_relay text, p_fence bigint, p_attempt integer, p_outcome text,
    p_status integer, p_digest text, p_detail text, p_delay_ms bigint, p_remote_ref text)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
    s record;
    policy record;
    owned boolean;
    next_state text;
    why text;
    due timestamptz;
BEGIN
    IF p_outcome NOT IN ('delivered', 'retryable', 'permanent', 'unknown') THEN
        RAISE EXCEPTION 'interlock: % is not an outcome', p_outcome USING ERRCODE = '22023';
    END IF;
    SELECT st.state, st.lease_owner, st.fence, st.attempts, st.attempt_floor INTO s
      FROM interlock.outbox_state AS st
     WHERE st.message_id = p_message
       FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'interlock: no message %', p_message USING ERRCODE = 'IL002';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM interlock.outbox_attempts AS a
         WHERE a.message_id = p_message AND a.attempt = p_attempt
           AND a.event = 'sending' AND a.actor = p_relay) THEN
        RAISE EXCEPTION 'interlock: relay % started no attempt % on message %',
            p_relay, p_attempt, p_message USING ERRCODE = 'IL002';
    END IF;
    IF EXISTS (
        SELECT 1 FROM interlock.outbox_attempts AS a
         WHERE a.message_id = p_message AND a.attempt = p_attempt
           AND a.event IN ('delivered', 'retryable', 'permanent', 'unknown')) THEN
        RAISE EXCEPTION 'interlock: attempt % on message % already has an outcome',
            p_attempt, p_message USING ERRCODE = 'IL002';
    END IF;
    SELECT k.max_attempts, k.unknown_outcome, o.not_after INTO policy
      FROM interlock.outbox AS o
      JOIN interlock.sinks AS k ON k.name = o.sink
     WHERE o.message_id = p_message;
    owned := s.state = 'leased' AND s.lease_owner = p_relay AND s.fence = p_fence;
    due := pg_catalog.clock_timestamp() + pg_catalog.make_interval(
        secs => (greatest(coalesce(p_delay_ms, 0), 0) / 1000.0)::double precision);
    IF p_outcome = 'delivered' THEN
        next_state := CASE WHEN s.state = 'delivered' THEN NULL ELSE 'delivered' END;
        why := CASE WHEN s.state IN ('dead', 'cancelled')
                    THEN 'delivered after the message was ' || s.state
                         || '; requests that waited for it stay dead until requeued'
                    ELSE NULL END;
    ELSIF NOT owned THEN
        next_state := NULL;
    ELSIF p_outcome = 'permanent' THEN
        next_state := 'dead';
        why := 'permanent failure';
    ELSIF p_outcome = 'unknown' AND policy.unknown_outcome = 'dead-letter' THEN
        next_state := 'dead';
        why := 'outcome unknown: the sink may have acted, and this sink''s unknown outcomes '
               || 'are not redelivered';
    ELSIF s.attempts - s.attempt_floor >= policy.max_attempts THEN
        next_state := 'dead';
        why := 'attempts exhausted';
    ELSIF due > policy.not_after THEN
        next_state := 'dead';
        why := 'its deadline passes before its next attempt is due';
    ELSE
        next_state := 'pending';
        why := p_outcome || CASE WHEN p_status IS NULL THEN '' ELSE ' ' || p_status::text END;
    END IF;
    PERFORM interlock.outbox_log(
        p_message, p_attempt, p_outcome, p_relay, p_status, p_digest,
        CASE WHEN why IS NOT NULL AND next_state = 'delivered'
             THEN coalesce(p_detail || '; ', '') || why ELSE p_detail END,
        next_state,
        -- What the call created (a Stripe payment intent's id): only a call
        -- that delivered created anything.
        CASE WHEN p_outcome = 'delivered' THEN p_remote_ref END);
    IF next_state = 'pending' THEN
        PERFORM interlock.outbox_settle(p_message, 'pending', why, due);
    ELSIF next_state IS NOT NULL THEN
        PERFORM interlock.outbox_settle(p_message, next_state, coalesce(why, next_state));
        IF next_state = 'dead' THEN
            PERFORM interlock.outbox_fail_dependants(p_message, p_relay);
        END IF;
    END IF;
    RETURN next_state;
END
$fn$;

-- The breaker for the message's scope was tripped when the relay checked it,
-- immediately before the call: the message is held, not delivered, until an
-- operator releases it (interlock.outbox_release) or cancels it.
CREATE OR REPLACE FUNCTION interlock.relay_hold(
    p_message uuid, p_relay text, p_fence bigint, p_reason text)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
BEGIN
    PERFORM 1 FROM interlock.outbox_state AS st
     WHERE st.message_id = p_message AND st.state = 'leased'
       AND st.lease_owner = p_relay AND st.fence = p_fence
       FOR UPDATE;
    IF NOT FOUND THEN
        RETURN false;
    END IF;
    PERFORM interlock.outbox_log(p_message, NULL, 'held', p_relay, NULL, NULL, p_reason, 'held');
    PERFORM interlock.outbox_settle(p_message, 'held', p_reason);
    RETURN true;
END
$fn$;

-- The relay could not decide whether to send (the breaker could not be read,
-- say): nothing is sent, no attempt is spent, and the message is due again
-- p_delay_ms from now.
CREATE OR REPLACE FUNCTION interlock.relay_defer(
    p_message uuid, p_relay text, p_fence bigint, p_reason text, p_delay_ms bigint)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
BEGIN
    PERFORM 1 FROM interlock.outbox_state AS st
     WHERE st.message_id = p_message AND st.state = 'leased'
       AND st.lease_owner = p_relay AND st.fence = p_fence
       FOR UPDATE;
    IF NOT FOUND THEN
        RETURN false;
    END IF;
    PERFORM interlock.outbox_log(
        p_message, NULL, 'deferred', p_relay, NULL, NULL, p_reason, 'pending');
    PERFORM interlock.outbox_settle(
        p_message, 'pending', p_reason,
        pg_catalog.clock_timestamp() + pg_catalog.make_interval(
            secs => (greatest(coalesce(p_delay_ms, 0), 0) / 1000.0)::double precision));
    RETURN true;
END
$fn$;

-- The relay will not send this message at all: the stored payload does not
-- match the hash it was adjudicated under, say. Dead, with the reason.
CREATE OR REPLACE FUNCTION interlock.relay_refuse(
    p_message uuid, p_relay text, p_fence bigint, p_reason text)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
BEGIN
    PERFORM 1 FROM interlock.outbox_state AS st
     WHERE st.message_id = p_message AND st.state = 'leased'
       AND st.lease_owner = p_relay AND st.fence = p_fence
       FOR UPDATE;
    IF NOT FOUND THEN
        RETURN false;
    END IF;
    PERFORM interlock.outbox_log(p_message, NULL, 'refused', p_relay, NULL, NULL, p_reason, 'dead');
    PERFORM interlock.outbox_settle(p_message, 'dead', 'refused: ' || p_reason);
    PERFORM interlock.outbox_fail_dependants(p_message, p_relay);
    RETURN true;
END
$fn$;

-- Operator actions. Granted to no role: they run as the installer.
--
-- Version 3: each takes the authority it acts under (the hash of the
-- operator's signed intent, docs/EPIC3_DESIGN.md §6), which the delivery-log
-- row it writes carries, and the head of the message's log as the operator
-- saw it when they signed. A head that moved is a refusal: an authorization
-- is never replayed on a later state.
DROP FUNCTION IF EXISTS interlock.outbox_release(uuid, text);
DROP FUNCTION IF EXISTS interlock.outbox_release_scope(text, text);
DROP FUNCTION IF EXISTS interlock.outbox_cancel(uuid, text, text);
DROP FUNCTION IF EXISTS interlock.outbox_requeue(uuid, text);

-- Releases a held message for delivery: an operator's decision, after the
-- breaker that held it was reset or judged not to apply.
CREATE OR REPLACE FUNCTION interlock.outbox_release(
    p_message uuid, p_actor text, p_authority text, p_expected_head text)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
BEGIN
    PERFORM 1 FROM interlock.outbox_state AS st
     WHERE st.message_id = p_message AND st.state = 'held'
       AND st.log_head = p_expected_head
       FOR UPDATE;
    IF NOT FOUND THEN
        RETURN false;
    END IF;
    PERFORM interlock.outbox_log(
        p_message, NULL, 'released', p_actor, NULL, NULL, 'released by an operator', 'pending',
        NULL, p_authority);
    PERFORM interlock.outbox_settle(p_message, 'pending', 'released');
    RETURN true;
END
$fn$;

-- Cancels a message that is not being delivered and was not delivered:
-- pending, held or dead. Its dependants die with it.
CREATE OR REPLACE FUNCTION interlock.outbox_cancel(
    p_message uuid, p_actor text, p_reason text, p_authority text, p_expected_head text)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
BEGIN
    PERFORM 1 FROM interlock.outbox_state AS st
     WHERE st.message_id = p_message AND st.state IN ('pending', 'held', 'dead')
       AND st.log_head = p_expected_head
       FOR UPDATE;
    IF NOT FOUND THEN
        RETURN false;
    END IF;
    PERFORM interlock.outbox_log(
        p_message, NULL, 'cancelled', p_actor, NULL, NULL,
        coalesce(p_reason, 'cancelled by an operator'), 'cancelled', NULL, p_authority);
    PERFORM interlock.outbox_settle(
        p_message, 'cancelled', coalesce(p_reason, 'cancelled by an operator'));
    PERFORM interlock.outbox_fail_dependants(p_message, p_actor);
    RETURN true;
END
$fn$;

-- Sends a dead message back for delivery with a fresh budget of attempts,
-- and the requests that died waiting for it with it, under one authority.
-- Not one past its deadline: the deadline is part of what was adjudicated.
CREATE OR REPLACE FUNCTION interlock.outbox_requeue(
    p_message uuid, p_actor text, p_authority text, p_expected_head text)
RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
BEGIN
    PERFORM 1 FROM interlock.outbox_state AS st
     WHERE st.message_id = p_message AND st.log_head = p_expected_head
       FOR UPDATE;
    IF NOT FOUND THEN
        RETURN 0;
    END IF;
    RETURN interlock.outbox_requeue_from(p_message, p_actor, p_authority);
END
$fn$;

-- outbox_requeue without the head: for the dependants it brings back. Internal.
CREATE OR REPLACE FUNCTION interlock.outbox_requeue_from(
    p_message uuid, p_actor text, p_authority text)
RETURNS integer
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
    dep record;
    effect text;
    stage uuid;
    requeued integer := 1;
BEGIN
    PERFORM 1 FROM interlock.outbox_state AS st
      JOIN interlock.outbox AS o ON o.message_id = st.message_id
     WHERE st.message_id = p_message AND st.state = 'dead'
       AND o.not_after > pg_catalog.clock_timestamp()
       FOR UPDATE OF st;
    IF NOT FOUND THEN
        RETURN 0;
    END IF;
    PERFORM interlock.outbox_log(
        p_message, NULL, 'requeued', p_actor, NULL, NULL, 'requeued by an operator', 'pending',
        NULL, p_authority);
    UPDATE interlock.outbox_state
       SET attempt_floor = attempts
     WHERE message_id = p_message;
    PERFORM interlock.outbox_settle(p_message, 'pending', 'requeued');
    SELECT o.effect_id, o.stage_id INTO effect, stage
      FROM interlock.outbox AS o WHERE o.message_id = p_message;
    FOR dep IN
        SELECT d.message_id
          FROM interlock.outbox AS d
          JOIN interlock.outbox_state AS ds ON ds.message_id = d.message_id
         WHERE d.stage_id = stage AND effect = ANY (d.depends_on)
           AND ds.state = 'dead' AND ds.reason = 'dependency failed: ' || effect
         ORDER BY d.seq
    LOOP
        requeued := requeued + interlock.outbox_requeue_from(dep.message_id, p_actor, p_authority);
    END LOOP;
    RETURN requeued;
END
$fn$;

-- A compensation's payload with every {"$bind": "delivered.id"} replaced by
-- what the delivered call created. Internal.
CREATE OR REPLACE FUNCTION interlock.outbox_bind(p_value jsonb, p_ref text)
RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
    bound jsonb;
    item record;
BEGIN
    IF pg_catalog.jsonb_typeof(p_value) = 'object' THEN
        IF p_value = '{"$bind": "delivered.id"}'::jsonb THEN
            RETURN pg_catalog.to_jsonb(p_ref);
        END IF;
        bound := '{}'::jsonb;
        FOR item IN SELECT key, value FROM pg_catalog.jsonb_each(p_value) LOOP
            bound := bound || pg_catalog.jsonb_build_object(
                item.key, interlock.outbox_bind(item.value, p_ref));
        END LOOP;
        RETURN bound;
    END IF;
    IF pg_catalog.jsonb_typeof(p_value) = 'array' THEN
        SELECT coalesce(pg_catalog.jsonb_agg(interlock.outbox_bind(e.value, p_ref)
                                             ORDER BY e.ordinality), '[]'::jsonb)
          INTO bound
          FROM pg_catalog.jsonb_array_elements(p_value) WITH ORDINALITY AS e;
        RETURN bound;
    END IF;
    RETURN p_value;
END
$fn$;

-- Enqueues the compensation a delivered request carried (E4-3), as a new
-- message: its placeholder bound to what the delivered call created, waiting
-- for the compensations of the requests that waited for the original (E4-4),
-- once per original (its effect is the original's, prefixed). The original's
-- log records it. The payload is the caller's canonical bytes, and must be
-- the stored compensation, bound: nothing else can be enqueued this way.
CREATE OR REPLACE FUNCTION interlock.outbox_compensate(
    p_original uuid, p_actor text, p_authority text, p_expected_head text, p_message uuid,
    p_payload text, p_payload_hash text, p_idempotency_key text)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
    o record;
    k record;
    ref text;
    expected jsonb;
    comp jsonb;
    effect text;
    next_seq integer;
    waits text[];
    bytes bytea := pg_catalog.convert_to(p_payload, 'UTF8');
    enqueued timestamptz := pg_catalog.clock_timestamp();
BEGIN
    PERFORM 1 FROM interlock.outbox_state AS st
     WHERE st.message_id = p_original AND st.state = 'delivered'
       AND st.log_head = p_expected_head
       FOR UPDATE;
    IF NOT FOUND THEN
        RETURN false;
    END IF;
    SELECT * INTO o FROM interlock.outbox WHERE message_id = p_original;
    comp := o.compensation;
    IF comp IS NULL THEN
        RETURN false;
    END IF;
    SELECT a.remote_ref INTO ref FROM interlock.outbox_attempts AS a
     WHERE a.message_id = p_original AND a.event = 'delivered'
     ORDER BY a.seq DESC LIMIT 1;
    IF ref IS NULL AND interlock.outbox_bind(comp -> 'payload', '') <> comp -> 'payload' THEN
        RETURN false;  -- a placeholder, and nothing to bind it to
    END IF;
    expected := interlock.outbox_bind(comp -> 'payload', coalesce(ref, ''));
    IF p_payload::jsonb IS DISTINCT FROM expected THEN
        RAISE EXCEPTION '%', 'interlock: the payload is not the compensation message '
            || p_original::text || ' carried, bound to what its delivery created'
            USING ERRCODE = 'IL004',
                  DETAIL = pg_catalog.json_build_object(
                      'reason', 'compensation', 'sink', comp ->> 'sink')::text;
    END IF;
    SELECT kk.operations, kk.max_payload_bytes, kk.not_after_seconds, kk.cost_per_call INTO k
      FROM interlock.sinks AS kk WHERE kk.name = comp ->> 'sink' AND kk.enabled;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'interlock: no enabled sink named % is installed', comp ->> 'sink'
            USING ERRCODE = 'IL004',
                  DETAIL = pg_catalog.json_build_object(
                      'reason', 'unregistered_sink', 'sink', comp ->> 'sink')::text;
    END IF;
    IF NOT ((comp ->> 'operation') = ANY (k.operations)) THEN
        RAISE EXCEPTION 'interlock: sink % installs no operation %',
            comp ->> 'sink', comp ->> 'operation'
            USING ERRCODE = 'IL004',
                  DETAIL = pg_catalog.json_build_object(
                      'reason', 'unregistered_operation', 'sink', comp ->> 'sink')::text;
    END IF;
    IF pg_catalog.octet_length(bytes) > k.max_payload_bytes
       OR pg_catalog.encode(pg_catalog.sha256(bytes), 'hex') <> p_payload_hash THEN
        RAISE EXCEPTION 'interlock: the compensation exceeds its sink''s bound or its hash'
            USING ERRCODE = 'IL004',
                  DETAIL = pg_catalog.json_build_object(
                      'reason', 'payload_hash', 'sink', comp ->> 'sink')::text;
    END IF;
    effect := 'compensate:' || o.effect_id;
    waits := ARRAY(
        SELECT c.effect_id
          FROM interlock.outbox AS d
          JOIN interlock.outbox AS c ON c.compensates = d.message_id
         WHERE d.stage_id = o.stage_id AND o.effect_id = ANY (d.depends_on)
         ORDER BY c.effect_id);
    SELECT coalesce(max(x.seq), 0) + 1 INTO next_seq
      FROM interlock.outbox AS x WHERE x.stage_id = o.stage_id;
    INSERT INTO interlock.outbox (
        message_id, stage_id, plan_id, scope_id, effect_id, seq, depends_on, sink,
        operation, tenant_id, payload, payload_hash, idempotency_key, cost, compensation,
        compensates, not_after, enqueued_at
    ) VALUES (
        p_message, o.stage_id, o.plan_id, o.scope_id, effect, next_seq, waits,
        comp ->> 'sink', comp ->> 'operation', o.tenant_id, p_payload::jsonb, p_payload_hash,
        p_idempotency_key, k.cost_per_call, NULL, p_original,
        enqueued + pg_catalog.make_interval(
            secs => coalesce((comp ->> 'not_after_seconds')::integer, k.not_after_seconds)),
        enqueued
    );
    INSERT INTO interlock.outbox_state (message_id, log_head)
    VALUES (
        p_message,
        interlock.outbox_genesis(p_message, o.stage_id, o.plan_id, o.scope_id, effect,
                                 comp ->> 'sink', comp ->> 'operation', p_idempotency_key,
                                 p_payload_hash)
    );
    PERFORM interlock.outbox_log(
        p_original, NULL, 'compensated', p_actor, NULL, NULL,
        'compensated by ' || p_message::text, NULL, NULL, p_authority);
    RETURN true;
END
$fn$;
"""

OUTBOX_FUNCTIONS: Final = STAGE_OUTBOX_FUNCTIONS + RELAY_FUNCTIONS

OUTBOX_TRIGGERS: Final = r"""
DROP TRIGGER IF EXISTS outbox_append_only ON interlock.outbox;
CREATE TRIGGER outbox_append_only BEFORE UPDATE OR DELETE ON interlock.outbox
    FOR EACH ROW EXECUTE FUNCTION interlock.outbox_append_only();
DROP TRIGGER IF EXISTS outbox_append_only_truncate ON interlock.outbox;
CREATE TRIGGER outbox_append_only_truncate BEFORE TRUNCATE ON interlock.outbox
    FOR EACH STATEMENT EXECUTE FUNCTION interlock.outbox_append_only();
ALTER TABLE interlock.outbox ENABLE ALWAYS TRIGGER outbox_append_only,
    ENABLE ALWAYS TRIGGER outbox_append_only_truncate;
DROP TRIGGER IF EXISTS attempts_append_only ON interlock.outbox_attempts;
CREATE TRIGGER attempts_append_only BEFORE UPDATE OR DELETE ON interlock.outbox_attempts
    FOR EACH ROW EXECUTE FUNCTION interlock.outbox_append_only();
DROP TRIGGER IF EXISTS attempts_append_only_truncate ON interlock.outbox_attempts;
CREATE TRIGGER attempts_append_only_truncate BEFORE TRUNCATE ON interlock.outbox_attempts
    FOR EACH STATEMENT EXECUTE FUNCTION interlock.outbox_append_only();
DROP TRIGGER IF EXISTS outbox_log_link ON interlock.outbox_attempts;
CREATE TRIGGER outbox_log_link BEFORE INSERT ON interlock.outbox_attempts
    FOR EACH ROW EXECUTE FUNCTION interlock.outbox_log_link();
ALTER TABLE interlock.outbox_attempts ENABLE ALWAYS TRIGGER attempts_append_only,
    ENABLE ALWAYS TRIGGER attempts_append_only_truncate,
    ENABLE ALWAYS TRIGGER outbox_log_link;
"""

OUTBOX_TRIGGER_NAMES: Final = (
    ("outbox", "outbox_append_only", "interlock.outbox_append_only"),
    ("outbox", "outbox_append_only_truncate", "interlock.outbox_append_only"),
    ("outbox_attempts", "attempts_append_only", "interlock.outbox_append_only"),
    ("outbox_attempts", "attempts_append_only_truncate", "interlock.outbox_append_only"),
    ("outbox_attempts", "outbox_log_link", "interlock.outbox_log_link"),
)
"""What keeps a committed request, and its delivery log, as written and linked."""


# --------------------------------------------------------------------------
# Version 3's sink mirror and grants (src/interlock/postgres.py at 76a6f7f),
# for interlock.postgres.install to run in place of version 4's.
# --------------------------------------------------------------------------

RELAY_FUNCTIONS_V3: Final = (
    "interlock.relay_claim(text, double precision, integer, text[])",
    "interlock.relay_sending(uuid, text, bigint, text)",
    "interlock.relay_outcome(uuid, text, bigint, integer, text, integer, text, text, bigint, text)",
    "interlock.relay_hold(uuid, text, bigint, text)",
    "interlock.relay_defer(uuid, text, bigint, text, bigint)",
    "interlock.relay_refuse(uuid, text, bigint, text)",
)

OUTBOX_TABLES_V3: Final = (
    "interlock.sinks",
    "interlock.outbox",
    "interlock.outbox_state",
    "interlock.outbox_attempts",
    "interlock.outbox_epochs",
)


def install_sinks_v3(conn: Any, sinks: Sequence[Any]) -> None:
    """Mirror the registry into ``interlock.sinks``, as version 3 did."""
    for sink in sinks:
        conn.execute(
            "INSERT INTO interlock.sinks (name, kind, operations, cost_per_call, idempotency, "
            "max_payload_bytes, not_after_seconds, max_attempts, backoff_base_ms, "
            "backoff_cap_ms, unknown_outcome, config_hash, enabled) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, true) "
            "ON CONFLICT (name) DO UPDATE SET kind = EXCLUDED.kind, "
            "operations = EXCLUDED.operations, cost_per_call = EXCLUDED.cost_per_call, "
            "idempotency = EXCLUDED.idempotency, "
            "max_payload_bytes = EXCLUDED.max_payload_bytes, "
            "not_after_seconds = EXCLUDED.not_after_seconds, "
            "max_attempts = EXCLUDED.max_attempts, "
            "backoff_base_ms = EXCLUDED.backoff_base_ms, "
            "backoff_cap_ms = EXCLUDED.backoff_cap_ms, "
            "unknown_outcome = EXCLUDED.unknown_outcome, "
            "config_hash = EXCLUDED.config_hash, enabled = true",
            (
                sink.name,
                sink.kind,
                [op.name for op in sink.operations],
                str(sink.cost_per_call),
                sink.idempotency,
                sink.max_payload_bytes,
                int(sink.not_after.total_seconds()),
                sink.max_attempts,
                int(sink.backoff_base / timedelta(milliseconds=1)),
                int(sink.backoff_cap / timedelta(milliseconds=1)),
                sink.unknown_outcome,
                sink.config_hash(),
            ),
        )
    conn.execute(
        "UPDATE interlock.sinks SET enabled = false WHERE NOT (name = ANY (%s))",
        ([sink.name for sink in sinks],),
    )
