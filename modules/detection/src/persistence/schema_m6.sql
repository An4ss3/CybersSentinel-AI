-- CyberSentinel M6 — canonical feature-window persistence schema
--
-- Dedicated storage boundary (D18). This file never references, alters, or
-- drops anything in m4_canonical or in the legacy public schema.
--
-- Frozen M6 decisions enforced at the storage layer:
--   * exact DECIMAL(38,22) temporal representation, never float;
--   * tumbling 60-second windows aligned to exact boundaries;
--   * prediction_time == window_end_time;
--   * window_start < window_end <= prediction <= record_available;
--   * exactly the eight authorized features, as declared columns;
--   * strictly intra-partition windows;
--   * no empty windows (source_event_count > 0);
--   * deterministic window_id (UUID5) as primary key;
--   * complete source-event lineage;
--   * no label / M5 column of any kind.

CREATE SCHEMA IF NOT EXISTS m6_canonical;

-- ---------------------------------------------------------------------------
-- Materialization run identity (run identity lives here, never in the
-- frozen manifest — decision C1-a).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m6_canonical.materialization_runs (
    run_id                          UUID PRIMARY KEY,

    m6_protocol_sha256              CHAR(64) NOT NULL,
    m3_report_content_sha256        CHAR(64) NOT NULL,
    m4_report_content_sha256        CHAR(64) NOT NULL,

    status                          TEXT NOT NULL
                                    CHECK (status IN ('running', 'verified', 'failed')),

    started_at                      TIMESTAMPTZ NOT NULL,
    completed_at                    TIMESTAMPTZ,

    total_source_event_count        BIGINT CHECK (total_source_event_count >= 0),
    total_window_count              BIGINT CHECK (total_window_count >= 0),
    window_stream_sha256            CHAR(64),

    CONSTRAINT ck_m6_runs_completed_after_started
        CHECK (completed_at IS NULL OR completed_at >= started_at)
);

-- A duplicate *verified* materialization of the same M6 protocol against the
-- same upstream evidence must fail loudly. Failed/running rows are retained.
CREATE UNIQUE INDEX IF NOT EXISTS ux_m6_runs_verified_protocol
    ON m6_canonical.materialization_runs (
        m6_protocol_sha256, m3_report_content_sha256, m4_report_content_sha256
    )
    WHERE status = 'verified';

-- ---------------------------------------------------------------------------
-- Canonical feature windows
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m6_canonical.feature_windows (
    window_id                       UUID PRIMARY KEY,
    m6_run_id                       UUID NOT NULL
                                    REFERENCES m6_canonical.materialization_runs (run_id),

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

    -- provenance, inherited from the source FlowEndV2 events
    sensor_id                       TEXT NOT NULL,
    sensor_run_id                   TEXT NOT NULL,
    capture_id                      TEXT NOT NULL,
    dataset_snapshot_id             TEXT,
    model_release_id                TEXT CHECK (model_release_id IS NULL),
    normalizer_version              TEXT NOT NULL,
    pipeline_version                TEXT NOT NULL,

    -- the eight authorized features (FiniteFloat container, per decision D-2)
    event_count                     DOUBLE PRECISION NOT NULL CHECK (event_count >= 1),
    source_packets_total            DOUBLE PRECISION NOT NULL CHECK (source_packets_total >= 0),
    destination_packets_total       DOUBLE PRECISION NOT NULL CHECK (destination_packets_total >= 0),
    source_bytes_total              DOUBLE PRECISION NOT NULL CHECK (source_bytes_total >= 0),
    destination_bytes_total         DOUBLE PRECISION NOT NULL CHECK (destination_bytes_total >= 0),
    distinct_destination_ports      DOUBLE PRECISION NOT NULL CHECK (distinct_destination_ports >= 1),
    distinct_destination_ips        DOUBLE PRECISION NOT NULL CHECK (distinct_destination_ips >= 1),
    distinct_source_ips             DOUBLE PRECISION NOT NULL CHECK (distinct_source_ips >= 1),

    -- data quality; M6 introduces no watermark or late-arrival policy
    source_event_count              INTEGER NOT NULL CHECK (source_event_count > 0),
    late_event_count                INTEGER NOT NULL CHECK (late_event_count = 0),
    dropped_event_count             INTEGER NOT NULL CHECK (dropped_event_count = 0),
    is_final                        BOOLEAN NOT NULL CHECK (is_final),
    is_revision                     BOOLEAN NOT NULL CHECK (NOT is_revision),

    window_bytes_sha256             CHAR(64) NOT NULL,
    persisted_at                    TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT ck_m6_window_exact_length
        CHECK (window_end_time - window_start_time = 60),
    CONSTRAINT ck_m6_window_prediction_equals_end
        CHECK (prediction_time = window_end_time),
    CONSTRAINT ck_m6_window_causal_order
        CHECK (window_start_time < window_end_time
               AND window_end_time <= prediction_time
               AND prediction_time <= record_available_time),
    CONSTRAINT ck_m6_window_aligned
        CHECK (mod(window_start_time, 60) = 0),
    CONSTRAINT ck_m6_window_event_count_matches
        CHECK (event_count = source_event_count),

    -- one window per (partition, entity, bucket): the identity idempotency guard
    CONSTRAINT ux_m6_window_coordinate
        UNIQUE (output_partition, entity_source_ip, entity_destination_ip,
                entity_transport, entity_service, window_start_time)
);

CREATE INDEX IF NOT EXISTS ix_m6_windows_run
    ON m6_canonical.feature_windows (m6_run_id);
CREATE INDEX IF NOT EXISTS ix_m6_windows_partition_start
    ON m6_canonical.feature_windows (output_partition, window_start_time);
CREATE INDEX IF NOT EXISTS ix_m6_windows_entity
    ON m6_canonical.feature_windows (entity_source_ip, entity_destination_ip,
                                     entity_transport, entity_service);

-- ---------------------------------------------------------------------------
-- Complete source-event lineage: one row per (window, source event).
-- References M4 event identifiers by value only; no foreign key into
-- m4_canonical, so M6 can never constrain or cascade into M4.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m6_canonical.feature_window_sources (
    window_id                       UUID NOT NULL
                                    REFERENCES m6_canonical.feature_windows (window_id),
    source_event_id                 UUID NOT NULL,

    PRIMARY KEY (window_id, source_event_id)
);

CREATE INDEX IF NOT EXISTS ix_m6_window_sources_event
    ON m6_canonical.feature_window_sources (source_event_id);
