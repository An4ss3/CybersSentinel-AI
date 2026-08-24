-- CyberSentinel MB4 — Monday Benign canonical event persistence schema
--
-- Dedicated schema for the parallel MB track (MB1 -> MB2 -> MB3 -> MB4).
-- This file NEVER references, alters, or reads m4_canonical, m6_canonical, or
-- the frozen legacy public schema. Every foreign key stays inside
-- mb4_canonical: MB4 references M chain identities by value only, never by
-- constraint, exactly as m6_canonical references m4_canonical event ids.
--
-- Structural mirror of modules/detection/src/persistence/schema_v2.sql: the same
-- four tables, the same column types, the same CHECK constraints, the same
-- UNIQUE constraints, the same partial unique index, and the same indexes. Three
-- families of difference, all deliberate:
--
--   1. schema name mb4_canonical, and the run foreign key column is mb4_run_id;
--   2. provenance columns bind the frozen **MB3** report, not the M3 v2 report;
--   3. an MB-only hardening: output_partition is constrained by CHECK to the
--      single Monday partition in all three partition-bearing tables. No row
--      originating from a Tuesday, Wednesday, Thursday or Friday capture can be
--      stored here even by a buggy writer. This is the storage-layer expression
--      of the MB<->M isolation invariant.
--
-- Inherited MB3 invariants enforced at the storage layer:
--   * exact DECIMAL(38,22) temporal encoding -> NUMERIC(38,22), never float;
--   * event_end_time = event_start_time + event_duration, exactly;
--   * event_end_time <= record_available_time <= ingested_at;
--   * transport closed to tcp/udp;
--   * termination_reason always NULL under the frozen FlowEndV2 contract;
--   * counters non-negative;
--   * one physical conn.log line yields at most one event.

CREATE SCHEMA IF NOT EXISTS mb4_canonical;

-- ---------------------------------------------------------------------------
-- Materialization run identity
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS mb4_canonical.materialization_runs (
    run_id                                UUID PRIMARY KEY,

    -- Frozen MB3 binding (verified before any materialization begins)
    mb3_report_content_sha256             CHAR(64) NOT NULL,
    mb3_report_file_sha256                CHAR(64) NOT NULL,
    mb3_protocol_sha256                   CHAR(64) NOT NULL,
    mb3_event_stream_sha256               CHAR(64) NOT NULL,
    mb3_rejection_audit_stream_sha256     CHAR(64) NOT NULL,

    -- MB track upstream identities, recorded by value for audit
    mb1_manifest_sha256                   CHAR(64) NOT NULL,
    mb2_specification_sha256              CHAR(64) NOT NULL,
    mb2_replay_report_content_sha256      CHAR(64) NOT NULL,
    mb3_event_id_namespace                UUID NOT NULL,

    status                                TEXT NOT NULL
                                          CHECK (status IN ('running', 'verified', 'failed')),

    started_at                            TIMESTAMPTZ NOT NULL,
    completed_at                          TIMESTAMPTZ,

    total_processed_record_count           BIGINT CHECK (total_processed_record_count >= 0),
    total_accepted_record_count            BIGINT CHECK (total_accepted_record_count >= 0),
    total_rejected_record_count            BIGINT CHECK (total_rejected_record_count >= 0),

    -- Independently recomputed during materialization, compared to the frozen values
    materialized_event_stream_sha256       CHAR(64),
    materialized_rejection_stream_sha256   CHAR(64),

    CONSTRAINT ck_mb4_runs_completed_after_started
        CHECK (completed_at IS NULL OR completed_at >= started_at),
    CONSTRAINT ck_mb4_runs_totals_cover
        CHECK (
            total_processed_record_count IS NULL
            OR total_accepted_record_count IS NULL
            OR total_rejected_record_count IS NULL
            OR total_processed_record_count
               = total_accepted_record_count + total_rejected_record_count
        )
);

-- Fail loudly on a duplicate *verified* materialization of the same frozen MB3
-- report. Failed and running rows are retained for audit and do not block retries.
CREATE UNIQUE INDEX IF NOT EXISTS ux_mb4_runs_verified_report
    ON mb4_canonical.materialization_runs (mb3_report_content_sha256)
    WHERE status = 'verified';

-- ---------------------------------------------------------------------------
-- Canonical Monday FlowEndV2 events
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS mb4_canonical.flow_end_events (
    -- provenance.event_id, the deterministic UUIDv5 produced by MB3 under the
    -- MB3 namespace c81ae3e0-7738-5413-80f2-8c2755418232
    event_id                    UUID PRIMARY KEY,

    mb4_run_id                  UUID NOT NULL
                                REFERENCES mb4_canonical.materialization_runs (run_id),

    -- EventProvenance (persisted verbatim)
    sensor_id                   TEXT NOT NULL,
    sensor_run_id               TEXT NOT NULL,
    capture_id                  TEXT NOT NULL,
    dataset_snapshot_id         TEXT,
    model_release_id            TEXT,
    normalizer_version          TEXT NOT NULL,
    pipeline_version            TEXT NOT NULL,

    -- Versioned envelope
    schema_version              TEXT NOT NULL,
    event_version               TEXT NOT NULL,
    feature_version             TEXT NOT NULL,
    sensor_version              TEXT NOT NULL,
    event_type                  TEXT NOT NULL,
    sensor_type                 TEXT NOT NULL,

    -- Exact DECIMAL(38,22) seconds — never float
    event_start_time            NUMERIC(38, 22) NOT NULL,
    event_duration              NUMERIC(38, 22) NOT NULL,
    event_end_time              NUMERIC(38, 22) NOT NULL,
    record_available_time       NUMERIC(38, 22) NOT NULL,
    ingested_at                 NUMERIC(38, 22) NOT NULL,

    conversation_id             TEXT NOT NULL,

    source_ip                   INET NOT NULL,
    source_port                 INTEGER,
    destination_ip              INET NOT NULL,
    destination_port            INTEGER,

    transport                   TEXT NOT NULL CHECK (transport IN ('tcp', 'udp')),
    service                     TEXT,

    source_packets              BIGINT NOT NULL CHECK (source_packets >= 0),
    destination_packets         BIGINT NOT NULL CHECK (destination_packets >= 0),
    source_bytes                BIGINT NOT NULL CHECK (source_bytes >= 0),
    destination_bytes           BIGINT NOT NULL CHECK (destination_bytes >= 0),

    connection_state            TEXT NOT NULL,

    -- Always NULL under the frozen FlowEndV2 contract; retained for completeness
    termination_reason          TEXT CHECK (termination_reason IS NULL),

    -- Deterministic source coordinate back into the MB2 Monday conn.log
    output_partition            TEXT NOT NULL,
    physical_line_number        INTEGER NOT NULL CHECK (physical_line_number > 0),

    -- SHA-256 of the canonical event bytes used for stream hashing
    event_bytes_sha256          CHAR(64) NOT NULL,

    persisted_at                TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT ck_mb4_events_exact_end
        CHECK (event_end_time = event_start_time + event_duration),
    CONSTRAINT ck_mb4_events_causal_order
        CHECK (event_end_time <= record_available_time
               AND record_available_time <= ingested_at),
    CONSTRAINT ck_mb4_events_ports
        CHECK ((source_port IS NULL OR (source_port BETWEEN 0 AND 65535))
               AND (destination_port IS NULL OR (destination_port BETWEEN 0 AND 65535))),

    -- MB-only hardening: this schema stores the Monday partition and nothing else
    CONSTRAINT ck_mb4_events_monday_partition
        CHECK (output_partition = '2017-07-03_Monday-WorkingHours'),

    -- Source-coordinate idempotency: one physical line yields at most one event
    CONSTRAINT ux_mb4_events_source_coordinate
        UNIQUE (output_partition, physical_line_number)
);

CREATE INDEX IF NOT EXISTS ix_mb4_events_run
    ON mb4_canonical.flow_end_events (mb4_run_id);
CREATE INDEX IF NOT EXISTS ix_mb4_events_conversation
    ON mb4_canonical.flow_end_events (conversation_id);
CREATE INDEX IF NOT EXISTS ix_mb4_events_partition_line
    ON mb4_canonical.flow_end_events (output_partition, physical_line_number);

-- ---------------------------------------------------------------------------
-- Rejection audit — aggregate evidence only, never canonical events
--
-- Mirrors ZeekRejectionSpanV2 / ZeekRejectionCountV2 field-for-field. No raw
-- rejected record content exists in any frozen MB artifact, so none is stored.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS mb4_canonical.rejection_spans (
    id                              BIGSERIAL PRIMARY KEY,
    mb4_run_id                      UUID NOT NULL
                                    REFERENCES mb4_canonical.materialization_runs (run_id),
    output_partition                TEXT NOT NULL,
    first_physical_line_number      INTEGER NOT NULL CHECK (first_physical_line_number > 0),
    last_physical_line_number       INTEGER NOT NULL CHECK (last_physical_line_number > 0),
    reason                          TEXT NOT NULL,
    fields                          TEXT[] NOT NULL,

    CONSTRAINT ck_mb4_spans_ordered
        CHECK (last_physical_line_number >= first_physical_line_number),
    CONSTRAINT ck_mb4_spans_monday_partition
        CHECK (output_partition = '2017-07-03_Monday-WorkingHours'),
    CONSTRAINT ux_mb4_spans_run_partition_start
        UNIQUE (mb4_run_id, output_partition, first_physical_line_number)
);

CREATE INDEX IF NOT EXISTS ix_mb4_spans_run
    ON mb4_canonical.rejection_spans (mb4_run_id);
CREATE INDEX IF NOT EXISTS ix_mb4_spans_partition
    ON mb4_canonical.rejection_spans (output_partition);

CREATE TABLE IF NOT EXISTS mb4_canonical.rejection_counts (
    id                  BIGSERIAL PRIMARY KEY,
    mb4_run_id          UUID NOT NULL
                        REFERENCES mb4_canonical.materialization_runs (run_id),
    output_partition    TEXT NOT NULL,
    reason              TEXT NOT NULL,
    count               BIGINT NOT NULL CHECK (count > 0),

    CONSTRAINT ck_mb4_counts_monday_partition
        CHECK (output_partition = '2017-07-03_Monday-WorkingHours'),
    CONSTRAINT ux_mb4_counts_run_partition_reason
        UNIQUE (mb4_run_id, output_partition, reason)
);

CREATE INDEX IF NOT EXISTS ix_mb4_counts_run
    ON mb4_canonical.rejection_counts (mb4_run_id);
