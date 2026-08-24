-- CyberSentinel MB6 — Monday Benign feature-window persistence schema
--
-- Dedicated schema for the parallel MB track (MB1 -> MB2 -> MB3 -> MB4 -> MB6).
-- This file NEVER references, alters, or reads m4_canonical, m6_canonical, or the
-- legacy public schema. Every foreign key stays inside mb6_canonical: MB6
-- references MB4 event identifiers by value only, exactly as m6_canonical
-- references m4_canonical event ids, so MB6 can never constrain or cascade into
-- MB4.
--
-- Structural mirror of modules/detection/src/persistence/schema_m6.sql: the same
-- three tables, the same columns, the same CHECK and UNIQUE constraints, the same
-- partial unique index and the same indexes. Three families of difference, all
-- deliberate:
--
--   1. schema name mb6_canonical, and the run foreign key column is mb6_run_id;
--   2. provenance columns bind the frozen MB3 and MB4 identities, plus the MB4
--      source run id, never the M chain reports;
--   3. MB-only hardening: output_partition is constrained by CHECK to the single
--      Monday partition, and the run identity is deterministic rather than
--      uuid4, so run_id is itself reproducible evidence.
--
-- Inherited M6 invariants enforced at the storage layer:
--   * exact DECIMAL(38,22) temporal encoding -> NUMERIC(38,22), never float;
--   * window_end_time - window_start_time = 60 exactly;
--   * prediction_time = window_end_time;
--   * window_start_time aligned to a multiple of 60 from the Unix epoch;
--   * event_count = source_event_count, and no empty window can exist;
--   * late_event_count and dropped_event_count are always 0 (no watermark policy);
--   * is_final true, is_revision false;
--   * one window per (partition, entity, bucket).

CREATE SCHEMA IF NOT EXISTS mb6_canonical;

-- ---------------------------------------------------------------------------
-- Materialization run identity. Deterministic: uuid5 over the MB6 protocol hash
-- and the MB4 source run id. Never uuid4, never a clock reading.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS mb6_canonical.materialization_runs (
    run_id                          UUID PRIMARY KEY,

    mb6_protocol_sha256             CHAR(64) NOT NULL,
    mb3_report_content_sha256       CHAR(64) NOT NULL,
    mb4_report_content_sha256       CHAR(64) NOT NULL,
    mb4_run_id                      UUID NOT NULL,
    mb6_window_id_namespace         UUID NOT NULL,

    status                          TEXT NOT NULL
                                    CHECK (status IN ('running', 'verified', 'failed')),

    started_at                      TIMESTAMPTZ NOT NULL,
    completed_at                    TIMESTAMPTZ,

    total_source_event_count        BIGINT CHECK (total_source_event_count >= 0),
    total_window_count              BIGINT CHECK (total_window_count >= 0),
    window_stream_sha256            CHAR(64),

    CONSTRAINT ck_mb6_runs_completed_after_started
        CHECK (completed_at IS NULL OR completed_at >= started_at)
);

-- A duplicate *verified* materialization of the same MB6 protocol against the
-- same upstream evidence must fail loudly. Failed/running rows are retained.
CREATE UNIQUE INDEX IF NOT EXISTS ux_mb6_runs_verified_protocol
    ON mb6_canonical.materialization_runs (
        mb6_protocol_sha256, mb3_report_content_sha256, mb4_report_content_sha256
    )
    WHERE status = 'verified';

-- ---------------------------------------------------------------------------
-- Canonical Monday feature windows
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS mb6_canonical.feature_windows (
    window_id                       UUID PRIMARY KEY,
    mb6_run_id                      UUID NOT NULL
                                    REFERENCES mb6_canonical.materialization_runs (run_id),

    output_partition                TEXT NOT NULL,
    entity_type                     TEXT NOT NULL
                                    CHECK (entity_type = 'source_destination_service'),

    -- entity_key, one column per declared ordered component
    entity_source_ip                TEXT NOT NULL,
    entity_destination_ip           TEXT NOT NULL,
    entity_transport                TEXT NOT NULL CHECK (entity_transport IN ('tcp','udp')),
    entity_service                  TEXT NOT NULL,

    -- exact DECIMAL(38,22) seconds, never float
    window_start_time               NUMERIC(38, 22) NOT NULL,
    window_end_time                 NUMERIC(38, 22) NOT NULL,
    prediction_time                 NUMERIC(38, 22) NOT NULL,
    record_available_time           NUMERIC(38, 22) NOT NULL,

    schema_version                  TEXT NOT NULL CHECK (schema_version = '2.0.0'),
    event_version                   TEXT NOT NULL CHECK (event_version = '2.0.0'),
    feature_version                 TEXT NOT NULL CHECK (feature_version = '2.0.0'),
    sensor_version                  TEXT NOT NULL,

    -- provenance, inherited from the source MB4 FlowEndV2 events
    sensor_id                       TEXT NOT NULL,
    sensor_run_id                   TEXT NOT NULL,
    capture_id                      TEXT NOT NULL,
    dataset_snapshot_id             TEXT,
    model_release_id                TEXT CHECK (model_release_id IS NULL),
    normalizer_version              TEXT NOT NULL,
    pipeline_version                TEXT NOT NULL,

    -- the eight authorized features
    event_count                     DOUBLE PRECISION NOT NULL CHECK (event_count >= 1),
    source_packets_total            DOUBLE PRECISION NOT NULL CHECK (source_packets_total >= 0),
    destination_packets_total       DOUBLE PRECISION NOT NULL CHECK (destination_packets_total >= 0),
    source_bytes_total              DOUBLE PRECISION NOT NULL CHECK (source_bytes_total >= 0),
    destination_bytes_total         DOUBLE PRECISION NOT NULL CHECK (destination_bytes_total >= 0),
    distinct_destination_ports      DOUBLE PRECISION NOT NULL CHECK (distinct_destination_ports >= 1),
    distinct_destination_ips        DOUBLE PRECISION NOT NULL CHECK (distinct_destination_ips >= 1),
    distinct_source_ips             DOUBLE PRECISION NOT NULL CHECK (distinct_source_ips >= 1),

    -- data quality; MB6 introduces no watermark or late-arrival policy
    source_event_count              INTEGER NOT NULL CHECK (source_event_count > 0),
    late_event_count                INTEGER NOT NULL CHECK (late_event_count = 0),
    dropped_event_count             INTEGER NOT NULL CHECK (dropped_event_count = 0),
    is_final                        BOOLEAN NOT NULL CHECK (is_final),
    is_revision                     BOOLEAN NOT NULL CHECK (NOT is_revision),

    window_bytes_sha256             CHAR(64) NOT NULL,
    persisted_at                    TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT ck_mb6_window_exact_length
        CHECK (window_end_time - window_start_time = 60),
    CONSTRAINT ck_mb6_window_prediction_equals_end
        CHECK (prediction_time = window_end_time),
    CONSTRAINT ck_mb6_window_causal_order
        CHECK (window_start_time < window_end_time
               AND window_end_time <= prediction_time
               AND prediction_time <= record_available_time),
    CONSTRAINT ck_mb6_window_aligned
        CHECK (mod(window_start_time, 60) = 0),
    CONSTRAINT ck_mb6_window_event_count_matches
        CHECK (event_count = source_event_count),

    -- MB-only hardening: this schema stores the Monday partition and nothing else
    CONSTRAINT ck_mb6_window_monday_partition
        CHECK (output_partition = '2017-07-03_Monday-WorkingHours'),

    -- one window per (partition, entity, bucket): the identity idempotency guard
    CONSTRAINT ux_mb6_window_coordinate
        UNIQUE (output_partition, entity_source_ip, entity_destination_ip,
                entity_transport, entity_service, window_start_time)
);

CREATE INDEX IF NOT EXISTS ix_mb6_windows_run
    ON mb6_canonical.feature_windows (mb6_run_id);
CREATE INDEX IF NOT EXISTS ix_mb6_windows_partition_start
    ON mb6_canonical.feature_windows (output_partition, window_start_time);
CREATE INDEX IF NOT EXISTS ix_mb6_windows_entity
    ON mb6_canonical.feature_windows (entity_source_ip, entity_destination_ip,
                                      entity_transport, entity_service);

-- ---------------------------------------------------------------------------
-- Complete source-event lineage: one row per (window, source event).
-- References MB4 event identifiers by value only; no foreign key leaves
-- mb6_canonical, so MB6 can never constrain or cascade into MB4.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS mb6_canonical.feature_window_sources (
    window_id                       UUID NOT NULL
                                    REFERENCES mb6_canonical.feature_windows (window_id),
    source_event_id                 UUID NOT NULL,

    PRIMARY KEY (window_id, source_event_id)
);

CREATE INDEX IF NOT EXISTS ix_mb6_window_sources_event
    ON mb6_canonical.feature_window_sources (source_event_id);
