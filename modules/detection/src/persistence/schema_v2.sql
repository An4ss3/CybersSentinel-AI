-- CyberSentinel M4 — canonical event persistence schema
--
-- Dedicated schema for the canonical (M1→M2→M3 v2) evidence track.
-- This file NEVER touches the frozen legacy schema in modules/storage/schema.sql
-- (alerts / threat_intel / genai_audit remain untouched in the public schema).
--
-- Authorized design decisions implemented here:
--   * event_id is the primary key of the canonical event table.
--   * UNIQUE (output_partition, physical_line_number) is an additional
--     source-coordinate idempotency constraint.
--   * A duplicate *verified* materialization of the same frozen M3 report must
--     fail loudly: enforced by a partial unique index on the run table.
--   * Failed materialization runs are retained for audit (never deleted).
--
-- Inherited M3 v2 invariants enforced at the storage layer:
--   * Exact DECIMAL(38,22) temporal encoding -> NUMERIC(38,22), never float.
--   * transport is closed to tcp/udp.
--   * termination_reason is always NULL under the frozen FlowEndV2 contract.
--   * Counters are non-negative.

CREATE SCHEMA IF NOT EXISTS m4_canonical;

-- ---------------------------------------------------------------------------
-- Materialization run identity
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m4_canonical.materialization_runs (
    run_id                                UUID PRIMARY KEY,

    -- Frozen M3 v2 binding (verified before any materialization begins)
    m3_report_content_sha256              CHAR(64) NOT NULL,
    m3_report_file_sha256                 CHAR(64) NOT NULL,
    m3_protocol_sha256                    CHAR(64) NOT NULL,
    m3_event_stream_sha256                CHAR(64) NOT NULL,
    m3_rejection_audit_stream_sha256      CHAR(64) NOT NULL,

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

    CONSTRAINT ck_materialization_runs_completed_after_started
        CHECK (completed_at IS NULL OR completed_at >= started_at),
    CONSTRAINT ck_materialization_runs_totals_cover
        CHECK (
            total_processed_record_count IS NULL
            OR total_accepted_record_count IS NULL
            OR total_rejected_record_count IS NULL
            OR total_processed_record_count
               = total_accepted_record_count + total_rejected_record_count
        )
);

-- Fail loudly on a duplicate *verified* materialization of the same frozen report.
-- Failed and running rows are retained for audit and do not block retries.
CREATE UNIQUE INDEX IF NOT EXISTS ux_materialization_runs_verified_report
    ON m4_canonical.materialization_runs (m3_report_content_sha256)
    WHERE status = 'verified';

-- ---------------------------------------------------------------------------
-- Canonical FlowEndV2 events
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m4_canonical.flow_end_events (
    -- provenance.event_id (deterministic UUIDv5 from the frozen source coordinate)
    event_id                    UUID PRIMARY KEY,

    m4_run_id                   UUID NOT NULL
                                REFERENCES m4_canonical.materialization_runs (run_id),

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

    -- Deterministic source coordinate back into the frozen M2 conn.log
    output_partition            TEXT NOT NULL,
    physical_line_number        INTEGER NOT NULL CHECK (physical_line_number > 0),

    -- SHA-256 of the canonical event bytes used for stream hashing
    event_bytes_sha256          CHAR(64) NOT NULL,

    persisted_at                TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT ck_flow_end_events_exact_end
        CHECK (event_end_time = event_start_time + event_duration),
    CONSTRAINT ck_flow_end_events_causal_order
        CHECK (event_end_time <= record_available_time
               AND record_available_time <= ingested_at),
    CONSTRAINT ck_flow_end_events_ports
        CHECK ((source_port IS NULL OR (source_port BETWEEN 0 AND 65535))
               AND (destination_port IS NULL OR (destination_port BETWEEN 0 AND 65535))),

    -- Source-coordinate idempotency: one physical line yields at most one event
    CONSTRAINT ux_flow_end_events_source_coordinate
        UNIQUE (output_partition, physical_line_number)
);

CREATE INDEX IF NOT EXISTS ix_flow_end_events_run
    ON m4_canonical.flow_end_events (m4_run_id);
CREATE INDEX IF NOT EXISTS ix_flow_end_events_conversation
    ON m4_canonical.flow_end_events (conversation_id);
CREATE INDEX IF NOT EXISTS ix_flow_end_events_partition_line
    ON m4_canonical.flow_end_events (output_partition, physical_line_number);

-- ---------------------------------------------------------------------------
-- Rejection audit — aggregate evidence only, never canonical events
--
-- Mirrors ZeekRejectionSpanV2 / ZeekRejectionCountV2 field-for-field. No raw
-- rejected record content exists in any frozen artifact, so none is stored.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m4_canonical.rejection_spans (
    id                              BIGSERIAL PRIMARY KEY,
    m4_run_id                       UUID NOT NULL
                                    REFERENCES m4_canonical.materialization_runs (run_id),
    output_partition                TEXT NOT NULL,
    first_physical_line_number      INTEGER NOT NULL CHECK (first_physical_line_number > 0),
    last_physical_line_number       INTEGER NOT NULL CHECK (last_physical_line_number > 0),
    reason                          TEXT NOT NULL,
    fields                          TEXT[] NOT NULL,

    CONSTRAINT ck_rejection_spans_ordered
        CHECK (last_physical_line_number >= first_physical_line_number),
    CONSTRAINT ux_rejection_spans_run_partition_start
        UNIQUE (m4_run_id, output_partition, first_physical_line_number)
);

CREATE INDEX IF NOT EXISTS ix_rejection_spans_run
    ON m4_canonical.rejection_spans (m4_run_id);
CREATE INDEX IF NOT EXISTS ix_rejection_spans_partition
    ON m4_canonical.rejection_spans (output_partition);

CREATE TABLE IF NOT EXISTS m4_canonical.rejection_counts (
    id                  BIGSERIAL PRIMARY KEY,
    m4_run_id           UUID NOT NULL
                        REFERENCES m4_canonical.materialization_runs (run_id),
    output_partition    TEXT NOT NULL,
    reason              TEXT NOT NULL,
    count               BIGINT NOT NULL CHECK (count > 0),

    CONSTRAINT ux_rejection_counts_run_partition_reason
        UNIQUE (m4_run_id, output_partition, reason)
);

CREATE INDEX IF NOT EXISTS ix_rejection_counts_run
    ON m4_canonical.rejection_counts (m4_run_id);
