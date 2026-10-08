"""The inbox's database objects (``docs/EPIC5_DESIGN.md`` §2), on both stores.

Installed with the outbox, as part of schema version 5:

- ``inbox_sources``: each configured inbound source, its kind, and the head of
  its hash-linked log. No secret: a webhook's secret lives in the inbox
  process's environment only.
- ``inbox_events``: every webhook an inbox verified, per source, hash-linked
  by a trigger from the source's genesis, each attested by the inbox process.
  The raw body is kept, so whoever holds the secret can check the vendor's
  signature again; no stage role can read it.
- ``inbox_facts``: what an inbox bound an event to, the delivered request
  whose relay-attested ``remote_ref`` the event names, attested.
- ``inbox_consumed``: which stage consumed each fact, written in the stage's
  own transaction: a fact is consumed exactly when its plan commits.

Who may call what, on PostgreSQL:

- **the inbox process** (``inbox_roles``) records an event with
  :sql:`interlock.inbox_record` and a fact with :sql:`interlock.inbox_match`;
- **the engine** (stage roles) reads a scope's pending facts outside any stage
  with :sql:`interlock.inbox_pending`, consumes them with the stage's token
  with :sql:`interlock.inbox_consume`, and reads them back for the diff with
  :sql:`interlock.stage_facts`;
- **agent statements** can do none of it: they run inside a stage, where
  ``inbox_pending`` refuses, and hold no token and no grant.
"""

from __future__ import annotations

from typing import Final

__all__ = [
    "INBOX_FUNCTIONS",
    "INBOX_TABLES",
    "INBOX_TRIGGERS",
    "SQLITE_CONSUMED",
    "SQLITE_EVENTS",
    "SQLITE_FACTS",
    "SQLITE_INBOX_SCHEMA",
    "SQLITE_INBOX_TABLES",
    "SQLITE_SOURCES",
    "SQLITE_TRACES",
]

_ATTESTATION: Final = r'^\{"alg":"ed25519","key_id":"[0-9a-f]{16}","signature":"[0-9a-f]{128}"\}$'

INBOX_TABLES: Final = r"""
-- Version 5: the inbox (docs/EPIC5_DESIGN.md §2).
CREATE TABLE IF NOT EXISTS interlock.inbox_sources (
    name        text PRIMARY KEY CHECK (name ~ '^[a-z][a-z0-9_-]{0,62}$'),
    kind        text NOT NULL CHECK (kind IN ('http', 'stripe', 'sendgrid')),
    config_hash text NOT NULL,
    enabled     boolean NOT NULL DEFAULT true,
    log_seq     integer NOT NULL DEFAULT 0,
    log_head    text NOT NULL
);
REVOKE ALL ON interlock.inbox_sources FROM PUBLIC;

CREATE TABLE IF NOT EXISTS interlock.inbox_events (
    source      text NOT NULL REFERENCES interlock.inbox_sources (name),
    seq         integer NOT NULL CHECK (seq > 0),
    event_id    text NOT NULL,
    event_type  text NOT NULL,
    vendor_at   timestamptz,
    received_at timestamptz NOT NULL,
    body        text NOT NULL,
    body_hash   text NOT NULL,
    signature   text NOT NULL,
    part        integer NOT NULL DEFAULT 0 CHECK (part >= 0),
    refs        text NOT NULL,
    fields      text NOT NULL,
    withheld    text NOT NULL,
    attestation text NOT NULL,
    prev_hash   text NOT NULL,
    event_hash  text NOT NULL,
    PRIMARY KEY (source, seq),
    UNIQUE (source, event_id)
);
REVOKE ALL ON interlock.inbox_events FROM PUBLIC;

CREATE TABLE IF NOT EXISTS interlock.inbox_facts (
    fact_id       uuid PRIMARY KEY,
    source        text NOT NULL,
    event_seq     integer NOT NULL,
    event_hash    text NOT NULL,
    message_id    uuid NOT NULL,
    delivery_seq  integer NOT NULL,
    delivery_hash text NOT NULL,
    remote_ref    text NOT NULL,
    scope_id      text NOT NULL,
    plan_id       text NOT NULL,
    tenant_id     text,
    attestation   text NOT NULL,
    recorded_at   timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    FOREIGN KEY (source, event_seq) REFERENCES interlock.inbox_events (source, seq),
    UNIQUE (source, event_seq)
);
CREATE INDEX IF NOT EXISTS inbox_facts_by_scope ON interlock.inbox_facts (scope_id);
REVOKE ALL ON interlock.inbox_facts FROM PUBLIC;

CREATE TABLE IF NOT EXISTS interlock.inbox_consumed (
    fact_id  uuid PRIMARY KEY REFERENCES interlock.inbox_facts (fact_id),
    stage_id uuid NOT NULL REFERENCES interlock.stages (stage_id),
    at       timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp()
);
REVOKE ALL ON interlock.inbox_consumed FROM PUBLIC;

-- What an event names is found by what a delivered call created.
CREATE INDEX IF NOT EXISTS outbox_attempts_remote_ref
    ON interlock.outbox_attempts (remote_ref) WHERE remote_ref IS NOT NULL;

-- Version 6 (docs/EPIC7_DESIGN.md §1.4): the trace context a webhook carried,
-- beside its event and in none of its hashes, and deleted with it.
CREATE TABLE IF NOT EXISTS interlock.inbox_traces (
    source      text NOT NULL,
    seq         integer NOT NULL,
    traceparent text NOT NULL
                CHECK (traceparent ~ '^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$'
                       AND pg_catalog.substr(traceparent, 4, 32) <> pg_catalog.repeat('0', 32)
                       AND pg_catalog.substr(traceparent, 37, 16) <> pg_catalog.repeat('0', 16)),
    PRIMARY KEY (source, seq),
    FOREIGN KEY (source, seq) REFERENCES interlock.inbox_events (source, seq) ON DELETE CASCADE
);
REVOKE ALL ON interlock.inbox_traces FROM PUBLIC;
"""

INBOX_FUNCTIONS: Final = (
    r"""
-- The inbox is append-only, but for what a checkpoint written in this very
-- transaction cut: an event at or before its source's cut, that event's
-- facts, and their consumption (docs/EPIC5_DESIGN.md §1.5).
CREATE OR REPLACE FUNCTION interlock.inbox_compactable()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
    src text;
    place integer;
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF TG_TABLE_NAME = 'inbox_events' THEN
            src := OLD.source;
            place := OLD.seq;
        ELSIF TG_TABLE_NAME = 'inbox_facts' THEN
            src := OLD.source;
            place := OLD.event_seq;
        ELSE
            SELECT f.source, f.event_seq INTO src, place
              FROM interlock.inbox_facts AS f WHERE f.fact_id = OLD.fact_id;
        END IF;
        IF EXISTS (
            SELECT 1 FROM interlock.checkpoints AS c,
                   pg_catalog.jsonb_array_elements(
                       coalesce(c.body::jsonb -> 'inbox' -> 'sources', '[]'::jsonb)) AS s
             WHERE c.xid = pg_catalog.pg_current_xact_id()
               AND s ->> 'source' = src AND (s ->> 'through')::integer >= place) THEN
            RETURN OLD;
        END IF;
    END IF;
    RAISE EXCEPTION 'interlock: % is append-only; % refused', TG_TABLE_NAME, TG_OP
        USING ERRCODE = 'IL002';
END
$fn$;

-- An inbound event's hash: the row before it, everything the event row says,
-- and the inbox process's attestation of it.
CREATE OR REPLACE FUNCTION interlock.inbox_event_hash(
    p_prev text, p_source text, p_seq integer, p_event_id text, p_type text,
    p_vendor_at timestamptz, p_received_at timestamptz, p_body_hash text, p_part integer,
    p_refs text, p_fields text, p_withheld text, p_attestation text)
RETURNS text
LANGUAGE sql STABLE PARALLEL SAFE
SET search_path = pg_catalog, pg_temp
AS $fn$
    SELECT interlock.outbox_digest(
        'interlock-inbox-event-v1', p_prev, p_source, p_seq::text, p_event_id, p_type,
        CASE WHEN p_vendor_at IS NULL THEN NULL ELSE interlock.outbox_instant(p_vendor_at) END,
        interlock.outbox_instant(p_received_at), p_body_hash, p_part::text, p_refs, p_fields,
        p_withheld, p_attestation)
$fn$;

-- Links an inbound event to its source's log: its position, the hash of the
-- event before it and its own, and the head advanced. Whatever the writer
-- supplied for those is overwritten. An event carries the inbox's
-- attestation, or is not written.
CREATE OR REPLACE FUNCTION interlock.inbox_log_link()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
    head_seq integer;
    head text;
BEGIN
    SELECT s.log_seq, s.log_head INTO head_seq, head
      FROM interlock.inbox_sources AS s WHERE s.name = NEW.source FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'interlock: no inbound source %', NEW.source USING ERRCODE = 'IL012';
    END IF;
    IF NEW.attestation IS NULL OR NEW.attestation !~ '"""
    + _ATTESTATION
    + r"""' THEN
        RAISE EXCEPTION 'interlock: an inbound event needs the inbox''s attestation'
            USING ERRCODE = 'IL008';
    END IF;
    NEW.seq := head_seq + 1;
    NEW.prev_hash := head;
    NEW.event_hash := interlock.inbox_event_hash(
        NEW.prev_hash, NEW.source, NEW.seq, NEW.event_id, NEW.event_type, NEW.vendor_at,
        NEW.received_at, NEW.body_hash, NEW.part, NEW.refs, NEW.fields, NEW.withheld,
        NEW.attestation);
    UPDATE interlock.inbox_sources SET log_seq = NEW.seq, log_head = NEW.event_hash
     WHERE name = NEW.source;
    RETURN NEW;
END
$fn$;

-- The inbox process records an event it verified, once: a vendor's retry of
-- it is answered with the row already there. The body's hash is recomputed
-- here, over the text as sent. Granted to inbox roles.
CREATE OR REPLACE FUNCTION interlock.inbox_record(
    p_source text, p_event_id text, p_type text, p_vendor_at timestamptz,
    p_received_at timestamptz, p_body text, p_body_hash text, p_signature text,
    p_part integer, p_refs text, p_fields text, p_withheld text, p_attestation text)
RETURNS TABLE (out_seq integer, out_event_hash text, out_fresh boolean)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
    found_seq integer;
    found_hash text;
BEGIN
    -- One writer per source at a time: the head row is held to the commit.
    PERFORM 1 FROM interlock.inbox_sources AS s
     WHERE s.name = p_source AND s.enabled FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'interlock: no enabled inbound source %', p_source
            USING ERRCODE = 'IL012';
    END IF;
    IF pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p_body, 'UTF8')), 'hex')
       IS DISTINCT FROM p_body_hash THEN
        RAISE EXCEPTION 'interlock: the body does not match its hash' USING ERRCODE = 'IL012';
    END IF;
    SELECT e.seq, e.event_hash INTO found_seq, found_hash
      FROM interlock.inbox_events AS e
     WHERE e.source = p_source AND e.event_id = p_event_id;
    IF FOUND THEN
        RETURN QUERY SELECT found_seq, found_hash, false;
        RETURN;
    END IF;
    INSERT INTO interlock.inbox_events (
        source, seq, event_id, event_type, vendor_at, received_at, body, body_hash, signature,
        part, refs, fields, withheld, attestation, prev_hash, event_hash)
    VALUES (
        p_source, 1, p_event_id, p_type, p_vendor_at, p_received_at, p_body, p_body_hash,
        p_signature, p_part, p_refs, p_fields, p_withheld, p_attestation, '', '')
    RETURNING seq, event_hash INTO found_seq, found_hash;
    RETURN QUERY SELECT found_seq, found_hash, true;
END
$fn$;

-- The inbox process binds an event to the delivered request it names, once.
-- The database holds the binding to what it can check: the event at its
-- hash, a delivered row at its position and hash carrying that reference,
-- and the message's scope, plan and tenant. The signatures, verification
-- checks. Granted to inbox roles.
CREATE OR REPLACE FUNCTION interlock.inbox_match(
    p_fact uuid, p_source text, p_event_seq integer, p_event_hash text, p_message uuid,
    p_delivery_seq integer, p_delivery_hash text, p_remote_ref text, p_scope text,
    p_plan text, p_tenant text, p_attestation text)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
BEGIN
    IF p_attestation IS NULL OR p_attestation !~ '"""
    + _ATTESTATION
    + r"""' THEN
        RAISE EXCEPTION 'interlock: a fact needs the inbox''s attestation'
            USING ERRCODE = 'IL008';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM interlock.inbox_events AS e
         WHERE e.source = p_source AND e.seq = p_event_seq AND e.event_hash = p_event_hash) THEN
        RAISE EXCEPTION 'interlock: no event % of source % at that hash', p_event_seq, p_source
            USING ERRCODE = 'IL012';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM interlock.outbox_attempts AS a
          JOIN interlock.outbox AS o ON o.message_id = a.message_id
         WHERE a.message_id = p_message AND a.seq = p_delivery_seq
           AND a.event = 'delivered' AND a.event_hash = p_delivery_hash
           AND a.remote_ref = p_remote_ref AND o.scope_id = p_scope AND o.plan_id = p_plan
           AND o.tenant_id IS NOT DISTINCT FROM p_tenant) THEN
        RAISE EXCEPTION 'interlock: message % delivered nothing named %', p_message, p_remote_ref
            USING ERRCODE = 'IL012';
    END IF;
    INSERT INTO interlock.inbox_facts (
        fact_id, source, event_seq, event_hash, message_id, delivery_seq, delivery_hash,
        remote_ref, scope_id, plan_id, tenant_id, attestation)
    VALUES (
        p_fact, p_source, p_event_seq, p_event_hash, p_message, p_delivery_seq, p_delivery_hash,
        p_remote_ref, p_scope, p_plan, p_tenant, p_attestation)
    ON CONFLICT (source, event_seq) DO NOTHING;
    RETURN FOUND;
END
$fn$;
"""
    + r"""
-- A scope's facts no plan has consumed, with their events: read by the engine
-- outside every stage. An agent statement, which runs only inside a stage,
-- may not read them.
CREATE OR REPLACE FUNCTION interlock.inbox_pending(p_scope text)
RETURNS TABLE (
    out_fact uuid, out_source text, out_event_seq integer, out_event_hash text,
    out_message uuid, out_delivery_seq integer, out_delivery_hash text, out_remote_ref text,
    out_scope text, out_plan text, out_tenant text, out_attestation text,
    out_event_id text, out_type text, out_vendor_at timestamptz, out_received_at timestamptz,
    out_body_hash text, out_part integer, out_refs text, out_fields text, out_withheld text,
    out_event_attestation text
)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
BEGIN
    IF coalesce(pg_catalog.current_setting('interlock.stage_id', true), '') <> ''
       OR EXISTS (SELECT 1 FROM interlock.stages s
                   WHERE s.xid = pg_catalog.pg_current_xact_id_if_assigned()) THEN
        RAISE EXCEPTION 'interlock: the inbox is read outside every stage' USING ERRCODE = 'IL009';
    END IF;
    RETURN QUERY
        SELECT f.fact_id, f.source, f.event_seq, f.event_hash, f.message_id, f.delivery_seq,
               f.delivery_hash, f.remote_ref, f.scope_id, f.plan_id, f.tenant_id,
               f.attestation, e.event_id, e.event_type, e.vendor_at, e.received_at,
               e.body_hash, e.part, e.refs, e.fields, e.withheld, e.attestation
          FROM interlock.inbox_facts AS f
          JOIN interlock.inbox_events AS e ON e.source = f.source AND e.seq = f.event_seq
         WHERE f.scope_id = p_scope
           AND NOT EXISTS (SELECT 1 FROM interlock.inbox_consumed AS c
                            WHERE c.fact_id = f.fact_id)
         ORDER BY e.received_at, f.fact_id;
END
$fn$;

-- The stage consumes facts for its plan, with its token: each one the
-- plan's scope's, and pending. A fact another plan consumed first fails on
-- the key, here or at that plan's commit.
CREATE OR REPLACE FUNCTION interlock.inbox_consume(p_token bytea, p_facts uuid[], p_scope text)
RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
    stage uuid;
    expected bytea;
    fact uuid;
BEGIN
    SELECT s.stage_id, s.enqueue_hash INTO stage, expected
      FROM interlock.stages s
     WHERE s.xid = pg_catalog.pg_current_xact_id();
    IF stage IS NULL OR expected IS NULL
       OR pg_catalog.sha256(p_token) IS DISTINCT FROM expected THEN
        RAISE EXCEPTION 'interlock: this transaction''s stage did not consume a fact'
            USING ERRCODE = 'IL002';
    END IF;
    FOREACH fact IN ARRAY p_facts LOOP
        IF NOT EXISTS (SELECT 1 FROM interlock.inbox_facts AS f
                        WHERE f.fact_id = fact AND f.scope_id = p_scope) THEN
            RAISE EXCEPTION 'interlock: no fact % for scope %', fact, p_scope
                USING ERRCODE = 'IL012';
        END IF;
        INSERT INTO interlock.inbox_consumed (fact_id, stage_id) VALUES (fact, stage);
    END LOOP;
    RETURN pg_catalog.cardinality(p_facts);
END
$fn$;

-- The facts this stage consumed, as the inbox recorded them, for the diff.
CREATE OR REPLACE FUNCTION interlock.stage_facts(p_limit bigint)
RETURNS TABLE (
    out_fact uuid, out_source text, out_event_seq integer, out_event_hash text,
    out_message uuid, out_delivery_seq integer, out_delivery_hash text, out_remote_ref text,
    out_scope text, out_plan text, out_tenant text, out_attestation text,
    out_event_id text, out_type text, out_vendor_at timestamptz, out_received_at timestamptz,
    out_body_hash text, out_part integer, out_refs text, out_fields text, out_withheld text,
    out_event_attestation text
)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
BEGIN
    RETURN QUERY
        SELECT f.fact_id, f.source, f.event_seq, f.event_hash, f.message_id, f.delivery_seq,
               f.delivery_hash, f.remote_ref, f.scope_id, f.plan_id, f.tenant_id,
               f.attestation, e.event_id, e.event_type, e.vendor_at, e.received_at,
               e.body_hash, e.part, e.refs, e.fields, e.withheld, e.attestation
          FROM interlock.inbox_consumed AS c
          JOIN interlock.stages AS s ON s.stage_id = c.stage_id
          JOIN interlock.inbox_facts AS f ON f.fact_id = c.fact_id
          JOIN interlock.inbox_events AS e ON e.source = f.source AND e.seq = f.event_seq
         WHERE s.xid = pg_catalog.pg_current_xact_id()
         ORDER BY f.fact_id
         LIMIT p_limit;
END
$fn$;
"""
    r"""
-- The inbox keeps a webhook's trace context beside its event, once
-- (docs/EPIC7_DESIGN.md §1.4). Granted to inbox roles.
CREATE OR REPLACE FUNCTION interlock.inbox_trace(
    p_source text, p_seq integer, p_traceparent text)
RETURNS void
LANGUAGE sql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
    INSERT INTO interlock.inbox_traces (source, seq, traceparent)
    VALUES (p_source, p_seq, p_traceparent)
    ON CONFLICT (source, seq) DO NOTHING;
$fn$;

-- What decides each pending fact's trace context, for the agent of its scope:
-- its delivery's and its webhook's (interlock.trace.fact_traceparent). Read
-- outside every stage, as interlock.inbox_pending is. Granted to stage roles.
CREATE OR REPLACE FUNCTION interlock.inbox_pending_traces(p_scope text)
RETURNS TABLE (out_fact uuid, out_delivery text, out_webhook text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
BEGIN
    IF coalesce(pg_catalog.current_setting('interlock.stage_id', true), '') <> ''
       OR EXISTS (SELECT 1 FROM interlock.stages s
                   WHERE s.xid = pg_catalog.pg_current_xact_id_if_assigned()) THEN
        RAISE EXCEPTION 'interlock: the inbox is read outside every stage' USING ERRCODE = 'IL009';
    END IF;
    RETURN QUERY
        SELECT f.fact_id, ot.traceparent, it.traceparent
          FROM interlock.inbox_facts AS f
          LEFT JOIN interlock.outbox_traces AS ot ON ot.message_id = f.message_id
          LEFT JOIN interlock.inbox_traces AS it
                 ON it.source = f.source AND it.seq = f.event_seq
         WHERE f.scope_id = p_scope
           AND NOT EXISTS (SELECT 1 FROM interlock.inbox_consumed AS c
                            WHERE c.fact_id = f.fact_id)
           AND (ot.traceparent IS NOT NULL OR it.traceparent IS NOT NULL);
END
$fn$;
"""
)

INBOX_TRIGGERS: Final = r"""
DROP TRIGGER IF EXISTS inbox_log_link ON interlock.inbox_events;
CREATE TRIGGER inbox_log_link BEFORE INSERT ON interlock.inbox_events
    FOR EACH ROW EXECUTE FUNCTION interlock.inbox_log_link();
DROP TRIGGER IF EXISTS inbox_events_append_only ON interlock.inbox_events;
CREATE TRIGGER inbox_events_append_only BEFORE UPDATE OR DELETE ON interlock.inbox_events
    FOR EACH ROW EXECUTE FUNCTION interlock.inbox_compactable();
DROP TRIGGER IF EXISTS inbox_events_truncate ON interlock.inbox_events;
CREATE TRIGGER inbox_events_truncate BEFORE TRUNCATE ON interlock.inbox_events
    FOR EACH STATEMENT EXECUTE FUNCTION interlock.outbox_append_only();
ALTER TABLE interlock.inbox_events ENABLE ALWAYS TRIGGER inbox_log_link,
    ENABLE ALWAYS TRIGGER inbox_events_append_only,
    ENABLE ALWAYS TRIGGER inbox_events_truncate;
DROP TRIGGER IF EXISTS inbox_facts_append_only ON interlock.inbox_facts;
CREATE TRIGGER inbox_facts_append_only BEFORE UPDATE OR DELETE ON interlock.inbox_facts
    FOR EACH ROW EXECUTE FUNCTION interlock.inbox_compactable();
DROP TRIGGER IF EXISTS inbox_facts_truncate ON interlock.inbox_facts;
CREATE TRIGGER inbox_facts_truncate BEFORE TRUNCATE ON interlock.inbox_facts
    FOR EACH STATEMENT EXECUTE FUNCTION interlock.outbox_append_only();
ALTER TABLE interlock.inbox_facts ENABLE ALWAYS TRIGGER inbox_facts_append_only,
    ENABLE ALWAYS TRIGGER inbox_facts_truncate;
DROP TRIGGER IF EXISTS inbox_consumed_append_only ON interlock.inbox_consumed;
CREATE TRIGGER inbox_consumed_append_only BEFORE UPDATE OR DELETE ON interlock.inbox_consumed
    FOR EACH ROW EXECUTE FUNCTION interlock.inbox_compactable();
DROP TRIGGER IF EXISTS inbox_consumed_truncate ON interlock.inbox_consumed;
CREATE TRIGGER inbox_consumed_truncate BEFORE TRUNCATE ON interlock.inbox_consumed
    FOR EACH STATEMENT EXECUTE FUNCTION interlock.outbox_append_only();
ALTER TABLE interlock.inbox_consumed ENABLE ALWAYS TRIGGER inbox_consumed_append_only,
    ENABLE ALWAYS TRIGGER inbox_consumed_truncate;
"""

# --------------------------------------------------------------------------
# SQLite
# --------------------------------------------------------------------------

SQLITE_SOURCES: Final = "_interlock_inbox_sources"
SQLITE_EVENTS: Final = "_interlock_inbox_events"
SQLITE_FACTS: Final = "_interlock_inbox_facts"
SQLITE_CONSUMED: Final = "_interlock_inbox_consumed"
SQLITE_TRACES: Final = "_interlock_inbox_traces"
"""The trace context a webhook carried, beside its event (version 6,
``docs/EPIC7_DESIGN.md`` §1.4): in no hash, and gone with the event."""
SQLITE_INBOX_TABLES: Final = frozenset(
    {SQLITE_SOURCES, SQLITE_EVENTS, SQLITE_FACTS, SQLITE_CONSUMED, SQLITE_TRACES}
)

_SQLITE_CUT: Final = (
    "SELECT 1 FROM _interlock_checkpoints AS c, json_each(c.body, '$.inbox.sources') AS s "
    "WHERE c.open = 1 AND json_extract(s.value, '$.source') = {source} "
    "AND json_extract(s.value, '$.through') >= {seq}"
)
"""Whether a checkpoint still open, one the deleting transaction wrote and
closes before it commits, cut the source's log at or after the row's event.
(``_interlock_checkpoints`` is :data:`interlock.sqlite_outbox.CHECKPOINTS`.)"""

_SQLITE_ATTESTATION_GLOB: Final = (
    '{"alg":"ed25519","key_id":"' + "[0-9a-f]" * 16 + '","signature":"' + "[0-9a-f]" * 128 + '"}'
)

SQLITE_INBOX_SCHEMA: Final = (
    f"""CREATE TABLE IF NOT EXISTS main.{SQLITE_SOURCES} (
        name        TEXT PRIMARY KEY,
        kind        TEXT NOT NULL CHECK (kind IN ('http', 'stripe', 'sendgrid')),
        config_hash TEXT NOT NULL,
        enabled     INTEGER NOT NULL DEFAULT 1,
        log_seq     INTEGER NOT NULL DEFAULT 0,
        log_head    TEXT NOT NULL
    )""",
    f"""CREATE TABLE IF NOT EXISTS main.{SQLITE_EVENTS} (
        source      TEXT NOT NULL REFERENCES {SQLITE_SOURCES} (name),
        seq         INTEGER NOT NULL CHECK (seq > 0),
        event_id    TEXT NOT NULL,
        event_type  TEXT NOT NULL,
        vendor_at   TEXT,
        received_at TEXT NOT NULL,
        body        TEXT NOT NULL,
        body_hash   TEXT NOT NULL,
        signature   TEXT NOT NULL,
        part        INTEGER NOT NULL DEFAULT 0 CHECK (part >= 0),
        refs        TEXT NOT NULL,
        fields      TEXT NOT NULL,
        withheld    TEXT NOT NULL,
        attestation TEXT NOT NULL,
        prev_hash   TEXT NOT NULL,
        event_hash  TEXT NOT NULL,
        PRIMARY KEY (source, seq),
        UNIQUE (source, event_id)
    )""",
    f"""CREATE TABLE IF NOT EXISTS main.{SQLITE_FACTS} (
        fact_id       TEXT PRIMARY KEY,
        source        TEXT NOT NULL,
        event_seq     INTEGER NOT NULL,
        event_hash    TEXT NOT NULL,
        message_id    TEXT NOT NULL,
        delivery_seq  INTEGER NOT NULL,
        delivery_hash TEXT NOT NULL,
        remote_ref    TEXT NOT NULL,
        scope_id      TEXT NOT NULL,
        plan_id       TEXT NOT NULL,
        tenant_id     TEXT,
        attestation   TEXT NOT NULL,
        recorded_at   INTEGER NOT NULL,
        FOREIGN KEY (source, event_seq) REFERENCES {SQLITE_EVENTS} (source, seq),
        UNIQUE (source, event_seq)
    )""",
    f"CREATE INDEX IF NOT EXISTS main.{SQLITE_FACTS}_by_scope ON {SQLITE_FACTS} (scope_id)",
    f"""CREATE TABLE IF NOT EXISTS main.{SQLITE_CONSUMED} (
        fact_id  TEXT PRIMARY KEY REFERENCES {SQLITE_FACTS} (fact_id),
        stage_id TEXT NOT NULL
                 REFERENCES _interlock_commits (stage_id) DEFERRABLE INITIALLY DEFERRED,
        at       INTEGER NOT NULL
    )""",
    "CREATE INDEX IF NOT EXISTS main._interlock_outbox_attempts_remote_ref "
    "ON _interlock_outbox_attempts (remote_ref) WHERE remote_ref IS NOT NULL",
    # Every event sits at its source's head, links to it, and hashes to what
    # it holds, recomputed by interlock_inbox_hash: a function only
    # Interlock's own connections register. And it carries the attestation.
    f"""CREATE TRIGGER IF NOT EXISTS _interlock_inbox_link BEFORE INSERT ON {SQLITE_EVENTS}
    BEGIN
        SELECT RAISE(ABORT, 'interlock: an inbound event must extend its source''s log')
         WHERE NEW.seq IS NOT (SELECT s.log_seq + 1 FROM {SQLITE_SOURCES} AS s
                                WHERE s.name = NEW.source)
            OR NEW.prev_hash IS NOT (SELECT s.log_head FROM {SQLITE_SOURCES} AS s
                                      WHERE s.name = NEW.source)
            OR NEW.attestation NOT GLOB '{_SQLITE_ATTESTATION_GLOB}'
            OR NEW.event_hash IS NOT interlock_inbox_hash(
                   NEW.prev_hash, NEW.source, NEW.seq, NEW.event_id, NEW.event_type,
                   NEW.vendor_at, NEW.received_at, NEW.body_hash, NEW.part, NEW.refs,
                   NEW.fields, NEW.withheld, NEW.attestation);
    END""",
    f"""CREATE TRIGGER IF NOT EXISTS _interlock_inbox_head AFTER INSERT ON {SQLITE_EVENTS}
    BEGIN
        UPDATE {SQLITE_SOURCES} SET log_seq = NEW.seq, log_head = NEW.event_hash
         WHERE name = NEW.source;
    END""",
    f"CREATE TRIGGER IF NOT EXISTS _interlock_inbox_events_no_update BEFORE UPDATE "
    f"ON {SQLITE_EVENTS} BEGIN SELECT RAISE(ABORT, 'interlock: {SQLITE_EVENTS} is append-only'); "
    f"END",
    f"CREATE TRIGGER IF NOT EXISTS _interlock_inbox_events_no_delete BEFORE DELETE "
    f"ON {SQLITE_EVENTS} "
    f"WHEN NOT EXISTS ({_SQLITE_CUT.format(source='OLD.source', seq='OLD.seq')}) "
    f"BEGIN SELECT RAISE(ABORT, 'interlock: {SQLITE_EVENTS} is append-only'); END",
    f"CREATE TRIGGER IF NOT EXISTS _interlock_inbox_facts_no_update BEFORE UPDATE "
    f"ON {SQLITE_FACTS} BEGIN SELECT RAISE(ABORT, 'interlock: {SQLITE_FACTS} is append-only'); "
    f"END",
    f"CREATE TRIGGER IF NOT EXISTS _interlock_inbox_facts_no_delete BEFORE DELETE "
    f"ON {SQLITE_FACTS} "
    f"WHEN NOT EXISTS ({_SQLITE_CUT.format(source='OLD.source', seq='OLD.event_seq')}) "
    f"BEGIN SELECT RAISE(ABORT, 'interlock: {SQLITE_FACTS} is append-only'); END",
    f"""CREATE TRIGGER IF NOT EXISTS _interlock_inbox_facts_attested BEFORE INSERT
    ON {SQLITE_FACTS}
    WHEN NEW.attestation NOT GLOB '{_SQLITE_ATTESTATION_GLOB}'
    BEGIN SELECT RAISE(ABORT, 'interlock: a fact needs the inbox''s attestation'); END""",
    f"CREATE TRIGGER IF NOT EXISTS _interlock_inbox_consumed_no_update BEFORE UPDATE "
    f"ON {SQLITE_CONSUMED} BEGIN SELECT RAISE(ABORT, 'interlock: {SQLITE_CONSUMED} is "
    f"append-only'); END",
    f"CREATE TRIGGER IF NOT EXISTS _interlock_inbox_consumed_no_delete BEFORE DELETE "
    f"ON {SQLITE_CONSUMED} "
    f"WHEN NOT EXISTS (SELECT 1 FROM {SQLITE_FACTS} AS f WHERE f.fact_id = OLD.fact_id AND "
    f"EXISTS ({_SQLITE_CUT.format(source='f.source', seq='f.event_seq')})) "
    f"BEGIN SELECT RAISE(ABORT, 'interlock: {SQLITE_CONSUMED} is append-only'); END",
)
