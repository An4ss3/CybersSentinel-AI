-- CyberSentinel MB7 — Monday Benign sidecar label persistence schema
--
-- Strict sidecar. This file NEVER references, alters, or reads mb4_canonical,
-- mb6_canonical, m4_canonical, m6_canonical, or the legacy public schema. Event
-- and window identities are recorded **by value only**: there is deliberately no
-- foreign key out of mb7_canonical, so labels can never constrain, cascade into,
-- or lock the canonical evidence they describe.
--
-- The frozen M5 contract is preserved column-for-column: rule_version,
-- rule_hash, manifest_hash, authoritative_source and timezone travel with every
-- single label, so any row can be traced back to the exact policy that produced
-- it without consulting another table.
--
-- MB-only hardening, all enforced by the database rather than by convention:
--   * output_partition is constrained to the single Monday partition;
--   * disposition is constrained to the five M5 values;
--   * **attack dispositions are rejected outright** on the Monday benign day, at
--     both event and window level. A writer that produced one could not store it.
--   * a benign_reference row must carry the monday-benign-reference rule id, and
--     an unknown row must carry no matched rule at all;
--   * a window outside the compiled interval can never be benign_reference.
--
-- ``ambiguous`` is a **first-class disposition**, ratified 2026-08-13. Frozen M5
-- classifies an event whose exact interval crosses a rule boundary as ``partial``
-- -> ``ambiguous``, and long-lived Monday flows cross both boundaries of
-- ``[12:00:00Z, 20:01:00Z)``. Measurement found 218 such events producing 127
-- ambiguous windows, 119 inside the interval and 8 outside. Neither ambiguous nor
-- unknown is ever promoted to benign_reference.

CREATE SCHEMA IF NOT EXISTS mb7_canonical;

-- ---------------------------------------------------------------------------
-- Labeling run identity. Deterministic: uuid5 over the MB7 protocol hash and the
-- MB6 run identity. Never uuid4, never a clock reading.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS mb7_canonical.labeling_runs (
    run_id                          UUID PRIMARY KEY,

    mb7_protocol_sha256             CHAR(64) NOT NULL,
    mb3_report_content_sha256       CHAR(64) NOT NULL,
    mb4_report_content_sha256       CHAR(64) NOT NULL,
    mb6_report_content_sha256       CHAR(64) NOT NULL,
    mb6_window_stream_sha256        CHAR(64) NOT NULL,
    mb4_run_id                      UUID NOT NULL,
    mb6_run_id                      UUID NOT NULL,
    mb7_label_namespace             UUID NOT NULL,

    -- frozen M5 policy provenance, recorded once per run
    m5_manifest_hash                CHAR(64) NOT NULL,
    m5_rule_version                 TEXT NOT NULL,
    m5_authoritative_source         TEXT NOT NULL,
    m5_timezone                     TEXT NOT NULL,

    status                          TEXT NOT NULL
                                    CHECK (status IN ('running', 'verified', 'failed')),

    started_at                      TIMESTAMPTZ NOT NULL,
    completed_at                    TIMESTAMPTZ,

    total_event_label_count         BIGINT CHECK (total_event_label_count >= 0),
    total_window_label_count        BIGINT CHECK (total_window_label_count >= 0),
    event_label_stream_sha256       CHAR(64),
    window_label_stream_sha256      CHAR(64),

    CONSTRAINT ck_mb7_runs_completed_after_started
        CHECK (completed_at IS NULL OR completed_at >= started_at)
);

-- A duplicate *verified* labeling of the same protocol against the same MB6 run
-- must fail loudly. Failed/running rows are retained for audit.
CREATE UNIQUE INDEX IF NOT EXISTS ux_mb7_runs_verified_protocol
    ON mb7_canonical.labeling_runs (mb7_protocol_sha256, mb6_run_id)
    WHERE status = 'verified';

-- ---------------------------------------------------------------------------
-- Event-level sidecar labels: one row per MB4 canonical event.
-- source_event_id references mb4_canonical.flow_end_events BY VALUE only.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS mb7_canonical.event_labels (
    label_id                        UUID PRIMARY KEY,
    mb7_run_id                      UUID NOT NULL
                                    REFERENCES mb7_canonical.labeling_runs (run_id),

    source_event_id                 UUID NOT NULL,
    output_partition                TEXT NOT NULL,

    disposition                     TEXT NOT NULL,
    attack_family                   TEXT,
    attack_subtype                  TEXT,
    target_profiles                 TEXT[] NOT NULL,
    matched_rule_ids                TEXT[] NOT NULL,
    matched_direction               TEXT NOT NULL,
    reason                          TEXT NOT NULL,

    -- complete frozen M5 provenance, per label
    rule_version                    TEXT NOT NULL,
    rule_hash                       CHAR(64) NOT NULL,
    manifest_hash                   CHAR(64) NOT NULL,
    authoritative_source            TEXT NOT NULL,
    timezone                        TEXT NOT NULL,

    persisted_at                    TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT ck_mb7_event_disposition
        CHECK (disposition IN ('benign_reference', 'unknown', 'ambiguous',
                               'target_attack', 'known_other_attack')),
    CONSTRAINT ck_mb7_event_no_attack_on_benign_day
        CHECK (disposition NOT IN ('target_attack', 'known_other_attack')),
    CONSTRAINT ck_mb7_event_monday_partition
        CHECK (output_partition = '2017-07-03_Monday-WorkingHours'),
    CONSTRAINT ck_mb7_event_benign_rule
        CHECK (disposition <> 'benign_reference'
               OR matched_rule_ids = ARRAY['monday-benign-reference']::TEXT[]),
    CONSTRAINT ck_mb7_event_unknown_has_no_rule
        CHECK (disposition <> 'unknown' OR matched_rule_ids = ARRAY[]::TEXT[]),
    CONSTRAINT ck_mb7_event_no_attack_metadata
        CHECK (attack_family IS NULL AND attack_subtype IS NULL
               AND target_profiles = ARRAY[]::TEXT[]),
    CONSTRAINT ux_mb7_event_labels_source
        UNIQUE (mb7_run_id, source_event_id)
);

CREATE INDEX IF NOT EXISTS ix_mb7_event_labels_run
    ON mb7_canonical.event_labels (mb7_run_id);
CREATE INDEX IF NOT EXISTS ix_mb7_event_labels_source
    ON mb7_canonical.event_labels (source_event_id);
CREATE INDEX IF NOT EXISTS ix_mb7_event_labels_disposition
    ON mb7_canonical.event_labels (disposition);

-- ---------------------------------------------------------------------------
-- Window-level sidecar labels: one row per MB6 feature window, aggregated under
-- the frozen ANY_ATTACK precedence. source_window_id references
-- mb6_canonical.feature_windows BY VALUE only.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS mb7_canonical.window_labels (
    label_id                        UUID PRIMARY KEY,
    mb7_run_id                      UUID NOT NULL
                                    REFERENCES mb7_canonical.labeling_runs (run_id),

    source_window_id                UUID NOT NULL,
    output_partition                TEXT NOT NULL,

    disposition                     TEXT NOT NULL,
    aggregation_rule                TEXT NOT NULL
                                    CHECK (aggregation_rule = 'any_attack'),
    source_event_count              INTEGER NOT NULL CHECK (source_event_count > 0),
    benign_reference_event_count    INTEGER NOT NULL
                                    CHECK (benign_reference_event_count >= 0),
    unknown_event_count             INTEGER NOT NULL
                                    CHECK (unknown_event_count >= 0),
    ambiguous_event_count           INTEGER NOT NULL
                                    CHECK (ambiguous_event_count >= 0),
    attack_event_count              INTEGER NOT NULL
                                    CHECK (attack_event_count = 0),

    window_start_time               NUMERIC(38, 22) NOT NULL,
    window_end_time                 NUMERIC(38, 22) NOT NULL,
    inside_compiled_interval        BOOLEAN NOT NULL,

    -- complete frozen M5 provenance, per label
    rule_version                    TEXT NOT NULL,
    rule_hash                       CHAR(64) NOT NULL,
    manifest_hash                   CHAR(64) NOT NULL,
    authoritative_source            TEXT NOT NULL,
    timezone                        TEXT NOT NULL,

    persisted_at                    TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT ck_mb7_window_disposition
        CHECK (disposition IN ('benign_reference', 'unknown', 'ambiguous',
                               'target_attack', 'known_other_attack')),
    CONSTRAINT ck_mb7_window_no_attack_on_benign_day
        CHECK (disposition NOT IN ('target_attack', 'known_other_attack')),
    CONSTRAINT ck_mb7_window_monday_partition
        CHECK (output_partition = '2017-07-03_Monday-WorkingHours'),
    CONSTRAINT ck_mb7_window_counts_cover
        CHECK (source_event_count = benign_reference_event_count
               + unknown_event_count + ambiguous_event_count
               + attack_event_count),
    -- ANY_ATTACK, restricted to the dispositions reachable on a benign day:
    -- benign only when every event is benign; otherwise unknown.
    CONSTRAINT ck_mb7_window_any_attack_benign
        CHECK (disposition <> 'benign_reference'
               OR (unknown_event_count = 0
                   AND benign_reference_event_count = source_event_count)),
    CONSTRAINT ck_mb7_window_any_attack_unknown
        CHECK (disposition <> 'unknown' OR unknown_event_count > 0),
    CONSTRAINT ck_mb7_window_any_attack_ambiguous
        CHECK (disposition <> 'ambiguous' OR ambiguous_event_count > 0),
    -- The real R8 invariant. A window outside the compiled interval can never be
    -- promoted to benign_reference. It may legitimately be `unknown` or
    -- `ambiguous`: frozen M5 classifies an event whose exact interval crosses a
    -- rule boundary as `partial` -> `ambiguous`, and long-lived Monday flows do
    -- cross both boundaries. The previous form of this constraint forced
    -- outside => unknown and inside => benign_reference; measurement on
    -- 2026-08-13 falsified it (119 ambiguous inside, 8 outside), so it is
    -- replaced rather than worked around.
    CONSTRAINT ck_mb7_window_outside_never_benign
        CHECK (inside_compiled_interval OR disposition <> 'benign_reference'),
    CONSTRAINT ck_mb7_window_exact_length
        CHECK (window_end_time - window_start_time = 60),
    CONSTRAINT ux_mb7_window_labels_source
        UNIQUE (mb7_run_id, source_window_id)
);

CREATE INDEX IF NOT EXISTS ix_mb7_window_labels_run
    ON mb7_canonical.window_labels (mb7_run_id);
CREATE INDEX IF NOT EXISTS ix_mb7_window_labels_source
    ON mb7_canonical.window_labels (source_window_id);
CREATE INDEX IF NOT EXISTS ix_mb7_window_labels_disposition
    ON mb7_canonical.window_labels (disposition);
