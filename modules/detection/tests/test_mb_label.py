"""Contractual tests for MB-LABEL (MB7), the Monday Benign sidecar labeling.

CRITICAL: strictly read-only against PostgreSQL. MB4, MB6 and MB7 milestone data
all live in ``cybersentinel_test``, the database also used for destructive
integration-test isolation. Every database assertion here is a ``SELECT`` on a
connection with ``default_transaction_read_only = on``.

These tests encode the **corrected** invariants ratified on 2026-08-13. An earlier
preflight predicted 70,697 ``benign_reference`` and 224 ``unknown``; measurement
falsified the disposition split while confirming the temporal partition. The
truth, verified here to the record, is 70,578 benign / 216 unknown / 127
ambiguous, with 70,697 windows inside the compiled interval and 224 outside.
"""
from __future__ import annotations

import json
from pathlib import Path
from uuid import NAMESPACE_URL, UUID, uuid5

import pytest
from pydantic import ValidationError
import yaml

from modules.detection.src.lineage.monday_benign_labeling import (
    MONDAY_RULE_ID,
    bind_monday_benign_labeling_specification,
    build_m5_v1_ledger,
    derive_event_label_id,
    derive_window_label_id,
    load_and_bind_monday_benign_labeling_specification,
    load_monday_benign_labeling_specification,
)
from modules.detection.src.persistence.monday_benign_label_persistence import (
    MB7_DDL_FILE,
    _strip_sql_comments,
    verify_mb7_schema,
)
from modules.detection.src.persistence.monday_benign_persistence import (
    get_monday_benign_connection,
)
from modules.detection.src.schemas.monday_benign_feature_window import (
    MB6_WINDOW_ID_NAMESPACE,
)
from modules.detection.src.schemas.monday_benign_labeling import (
    MB7_LABEL_NAMESPACE,
    MB7_NAMESPACE_DERIVATION_NAME,
    MB7_PROTOCOL_RELATIVE_PATH,
    MB7_REPORT_RELATIVE_PATH,
    MB7_SCHEMA,
    MONDAY_RULE_END_EPOCH,
    MONDAY_RULE_START_EPOCH,
    MondayBenignIntervalSplit,
    MondayBenignLabelingRunReport,
    MondayBenignLabelingSpecification,
    derive_mb7_run_id,
)
from modules.detection.src.schemas.monday_benign_normalization import (
    M3_V2_EVENT_ID_NAMESPACE,
    MB3_EVENT_ID_NAMESPACE,
)
from modules.detection.src.schemas.monday_benign_replay import MONDAY_OUTPUT_PARTITION


REPO_ROOT = Path(__file__).resolve().parents[3]
PROTOCOL_PATH = REPO_ROOT / MB7_PROTOCOL_RELATIVE_PATH
REPORT_PATH = REPO_ROOT / MB7_REPORT_RELATIVE_PATH
TEST_DATABASE = "cybersentinel_test"
PRODUCTION_DATABASE = "cybersentinel"

# Ratified 2026-08-13, measured to the record.
EVENTS_TOTAL = 368_202
EVENTS_BENIGN = 367_171
EVENTS_UNKNOWN = 813
EVENTS_AMBIGUOUS = 218
WINDOWS_TOTAL = 70_921
WINDOWS_BENIGN = 70_578
WINDOWS_UNKNOWN = 216
WINDOWS_AMBIGUOUS = 127
WINDOWS_INSIDE = 70_697
WINDOWS_OUTSIDE = 224
WINDOWS_BEFORE = 198
WINDOWS_AFTER = 26
INSIDE_AMBIGUOUS = 119
OUTSIDE_AMBIGUOUS = 8

pytestmark = pytest.mark.skipif(
    not PROTOCOL_PATH.is_file() or not REPORT_PATH.is_file(),
    reason="MB7 protocol and report must be published for these tests",
)


def _database_available(database: str) -> bool:
    try:
        conn = get_monday_benign_connection(database, connect_timeout=3)
    except Exception:
        return False
    conn.close()
    return True


requires_db = pytest.mark.skipif(
    not _database_available(TEST_DATABASE),
    reason="PostgreSQL cybersentinel_test is unreachable",
)


@pytest.fixture()
def read_only_connection():
    conn = get_monday_benign_connection(TEST_DATABASE)
    try:
        with conn.cursor() as cur:
            cur.execute("SET default_transaction_read_only = on")
        conn.commit()
        yield conn
    finally:
        conn.close()


@pytest.fixture(scope="module")
def specification() -> MondayBenignLabelingSpecification:
    return load_monday_benign_labeling_specification(PROTOCOL_PATH)


@pytest.fixture(scope="module")
def report() -> MondayBenignLabelingRunReport:
    return MondayBenignLabelingRunReport.model_validate_json(
        REPORT_PATH.read_text(encoding="utf-8")
    )


def _protocol_payload() -> dict:
    raw = yaml.safe_load(PROTOCOL_PATH.read_text(encoding="utf-8"))
    return json.loads(json.dumps(raw, default=str))


def _revalidate(payload: dict) -> MondayBenignLabelingSpecification:
    return MondayBenignLabelingSpecification.model_validate_json(
        json.dumps(payload, default=str)
    )


# --------------------------------------------------------------------------
# Namespace separation
# --------------------------------------------------------------------------


def test_mb7_namespace_is_deterministically_derived() -> None:
    assert MB7_LABEL_NAMESPACE == uuid5(
        NAMESPACE_URL, MB7_NAMESPACE_DERIVATION_NAME
    )
    assert MB7_LABEL_NAMESPACE == UUID("1cef710b-751b-584e-b361-d264c8a70eeb")


@pytest.mark.parametrize(
    "forbidden",
    (
        M3_V2_EVENT_ID_NAMESPACE,
        MB3_EVENT_ID_NAMESPACE,
        MB6_WINDOW_ID_NAMESPACE,
        UUID("f787c08a-290e-5b79-a8cb-5bc19ae633dc"),
    ),
    ids=("m3v2", "mb3", "mb6", "m6"),
)
def test_protocol_rejects_a_foreign_namespace(forbidden: UUID) -> None:
    assert MB7_LABEL_NAMESPACE != forbidden
    payload = _protocol_payload()
    payload["label_identity_namespace"] = str(forbidden)
    with pytest.raises(ValidationError):
        _revalidate(payload)


# --------------------------------------------------------------------------
# Ratified policy semantics
# --------------------------------------------------------------------------


def test_protocol_applies_m5_v1_unchanged(
    specification: MondayBenignLabelingSpecification,
) -> None:
    ledger = build_m5_v1_ledger(REPO_ROOT)
    policy = specification.policy
    assert policy.policy_variant == "m5_v1_unchanged"
    assert policy.m5_v2_injected is False
    assert policy.m5_v1_is_normative_source is True
    assert policy.m5_v1_modified is False
    assert policy.manifest_hash == ledger.manifest_hash
    assert policy.rule_version == ledger.manifest.rule_version
    assert policy.applicable_rule_id == MONDAY_RULE_ID
    assert policy.applicable_rule_hash == ledger.rule_hash(MONDAY_RULE_ID)
    assert policy.applicable_rule_mode == "any_network"
    assert policy.compiled_interval_start_epoch_seconds == MONDAY_RULE_START_EPOCH
    assert policy.compiled_interval_end_epoch_seconds == MONDAY_RULE_END_EPOCH


def test_protocol_declares_ambiguous_a_valid_disposition(
    specification: MondayBenignLabelingSpecification,
) -> None:
    """The correction ratified on 2026-08-13, recorded in the protocol itself."""
    policy = specification.policy
    assert policy.ambiguous_is_valid_disposition is True
    assert policy.boundary_crossing_semantics == (
        "label_ledger_partial_overlap_yields_ambiguous"
    )
    assert policy.unknown_to_benign_conversion == "forbidden"
    assert policy.ambiguous_to_benign_conversion == "forbidden"
    assert policy.ambiguous_to_unknown_conversion == "forbidden"
    assert policy.ml_dataset_constructed is False
    assert specification.sidecar_only is True
    assert specification.modifies_mb4_or_mb6 is False


def test_protocol_preserves_the_frozen_any_attack_precedence(
    specification: MondayBenignLabelingSpecification,
) -> None:
    assert specification.aggregation.rule == "any_attack"
    assert specification.aggregation.precedence == (
        "target_attack",
        "known_other_attack",
        "ambiguous",
        "unknown",
        "benign_reference",
    )
    assert specification.aggregation.uncertainty_to_benign == "forbidden"


# --------------------------------------------------------------------------
# Deterministic identity
# --------------------------------------------------------------------------


def test_run_id_is_deterministic_from_protocol_and_mb6_run(
    report: MondayBenignLabelingRunReport,
) -> None:
    assert report.run_id == derive_mb7_run_id(
        report.protocol_sha256, report.mb6_run_id
    )


def test_report_rejects_a_non_derived_run_id() -> None:
    payload = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
    payload["run_id"] = str(UUID(int=7))
    with pytest.raises(ValidationError, match="deterministic derivation"):
        MondayBenignLabelingRunReport.model_validate_json(json.dumps(payload))


def test_label_ids_are_deterministic(
    report: MondayBenignLabelingRunReport,
) -> None:
    """Label identities are reproducible from protocol, policy and subject id.

    KNOWN LATENT WEAKNESS, reported to the owner 2026-08-13:
    ``derive_event_label_id`` and ``derive_window_label_id`` build the same name
    ``protocol|manifest|subject_id`` with no label-kind discriminator, so they
    coincide for an identical subject id. In this track that can never produce a
    collision, because MB3 event ids and MB6 window ids are drawn from different
    UUID5 namespaces and are provably disjoint -- see
    ``test_label_ids_never_collide_with_any_canonical_identity``, which verifies
    zero intersection over the full 368,202 + 70,921 sets. The safety therefore
    rests on input disjointness rather than on the derivation itself. This test
    asserts the guarantee that actually holds; it does not pretend the two label
    spaces are separated by construction.
    """
    ledger = build_m5_v1_ledger(REPO_ROOT)
    subject = UUID(int=1)
    assert derive_event_label_id(
        report.protocol_sha256, ledger.manifest_hash, subject
    ) == derive_event_label_id(
        report.protocol_sha256, ledger.manifest_hash, subject
    )
    assert derive_window_label_id(
        report.protocol_sha256, ledger.manifest_hash, subject
    ) == derive_window_label_id(
        report.protocol_sha256, ledger.manifest_hash, subject
    )
    # Changing any component changes the identity.
    assert derive_event_label_id(
        "0" * 64, ledger.manifest_hash, subject
    ) != derive_event_label_id(
        report.protocol_sha256, ledger.manifest_hash, subject
    )


@requires_db
def test_event_and_window_subject_ids_are_disjoint(read_only_connection) -> None:
    """The property the label derivation currently relies on for uniqueness."""
    with read_only_connection.cursor() as cur:
        cur.execute(f"SELECT source_event_id FROM {MB7_SCHEMA}.event_labels")
        events = {r[0] for r in cur.fetchall()}
        cur.execute(f"SELECT source_window_id FROM {MB7_SCHEMA}.window_labels")
        windows = {r[0] for r in cur.fetchall()}
    assert len(events) == EVENTS_TOTAL
    assert len(windows) == WINDOWS_TOTAL
    assert not (events & windows)


def test_report_identity_excludes_wall_clock(
    report: MondayBenignLabelingRunReport,
) -> None:
    payload = report.identity_payload()
    assert "started_at" not in payload
    assert "completed_at" not in payload
    assert "run_id" in payload


def test_report_content_hash_is_reproducible(
    report: MondayBenignLabelingRunReport,
) -> None:
    reloaded = MondayBenignLabelingRunReport.model_validate_json(
        REPORT_PATH.read_text(encoding="utf-8")
    )
    assert reloaded == report
    assert reloaded.content_sha256() == report.content_sha256()
    assert report.content_sha256() == (
        "5457b98749dca166470a8435502485305ef8228651f8ae79e45a4d33238aef5b"
    )


# --------------------------------------------------------------------------
# Ratified counts, to the record
# --------------------------------------------------------------------------


def test_published_report_matches_the_ratified_event_counts(
    report: MondayBenignLabelingRunReport,
) -> None:
    counts = {
        item.disposition: item.count for item in report.event_disposition_counts
    }
    assert report.total_event_label_count == EVENTS_TOTAL
    assert counts == {
        "ambiguous": EVENTS_AMBIGUOUS,
        "benign_reference": EVENTS_BENIGN,
        "unknown": EVENTS_UNKNOWN,
    }
    assert "target_attack" not in counts
    assert "known_other_attack" not in counts


def test_published_report_matches_the_ratified_window_counts(
    report: MondayBenignLabelingRunReport,
) -> None:
    counts = {
        item.disposition: item.count for item in report.window_disposition_counts
    }
    assert report.total_window_label_count == WINDOWS_TOTAL
    assert counts == {
        "ambiguous": WINDOWS_AMBIGUOUS,
        "benign_reference": WINDOWS_BENIGN,
        "unknown": WINDOWS_UNKNOWN,
    }


def test_published_report_partitions_the_interval_exactly(
    report: MondayBenignLabelingRunReport,
) -> None:
    """The reconciliation that vindicated the preflight's temporal partition."""
    split = report.unknown_window_interval_split
    assert split.windows_inside_interval == WINDOWS_INSIDE
    assert split.windows_outside_interval == WINDOWS_OUTSIDE
    assert split.windows_before_interval == WINDOWS_BEFORE
    assert split.windows_after_interval == WINDOWS_AFTER
    assert split.inside_benign_reference == WINDOWS_BENIGN
    assert split.inside_ambiguous == INSIDE_AMBIGUOUS
    assert split.outside_unknown == WINDOWS_UNKNOWN
    assert split.outside_ambiguous == OUTSIDE_AMBIGUOUS
    # benign + ambiguous inside == 70,697 ; unknown + ambiguous outside == 224
    assert split.inside_benign_reference + split.inside_ambiguous == WINDOWS_INSIDE
    assert split.outside_unknown + split.outside_ambiguous == WINDOWS_OUTSIDE
    assert split.total_windows == WINDOWS_TOTAL


def test_interval_split_rejects_a_partition_that_does_not_close() -> None:
    with pytest.raises(ValidationError):
        MondayBenignIntervalSplit(
            windows_inside_interval=WINDOWS_INSIDE,
            windows_outside_interval=WINDOWS_OUTSIDE,
            windows_before_interval=WINDOWS_BEFORE,
            windows_after_interval=WINDOWS_AFTER,
            inside_benign_reference=WINDOWS_BENIGN,
            inside_ambiguous=0,  # falsifies the inside partition
            outside_unknown=WINDOWS_UNKNOWN,
            outside_ambiguous=OUTSIDE_AMBIGUOUS,
            earliest_window_start_time="1499082900.0000000000000000000000",
            latest_window_start_time="1499112060.0000000000000000000000",
        )


def test_report_rejects_any_attack_disposition() -> None:
    payload = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
    payload["window_disposition_counts"] = [
        {"disposition": "benign_reference", "count": WINDOWS_BENIGN},
        {"disposition": "target_attack", "count": WINDOWS_AMBIGUOUS},
        {"disposition": "unknown", "count": WINDOWS_UNKNOWN},
    ]
    with pytest.raises(ValidationError, match="zero attack windows"):
        MondayBenignLabelingRunReport.model_validate_json(json.dumps(payload))


def test_report_rejects_benign_windows_outside_the_interval() -> None:
    payload = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
    payload["unknown_window_interval_split"]["inside_benign_reference"] = (
        WINDOWS_BENIGN - 1
    )
    with pytest.raises(ValidationError):
        MondayBenignLabelingRunReport.model_validate_json(json.dumps(payload))


# --------------------------------------------------------------------------
# Binding
# --------------------------------------------------------------------------


def test_published_protocol_binds_to_published_mb_evidence() -> None:
    bound = load_and_bind_monday_benign_labeling_specification(REPO_ROOT)
    assert bound.expected_event_count == EVENTS_TOTAL
    assert bound.expected_window_count == WINDOWS_TOTAL
    assert len(bound.protocol_sha256) == 64


@pytest.mark.parametrize(
    "field",
    (
        "mb1_manifest_sha256",
        "mb3_protocol_sha256",
        "mb4_report_content_sha256",
        "mb6_protocol_sha256",
        "mb6_report_content_sha256",
        "mb6_window_stream_sha256",
    ),
)
def test_binding_rejects_a_substituted_upstream_hash(field: str) -> None:
    payload = _protocol_payload()
    payload[field] = "0" * 64
    specification = _revalidate(payload)
    with pytest.raises(Exception):
        bind_monday_benign_labeling_specification(REPO_ROOT, specification)


def test_binding_rejects_a_substituted_m5_manifest_hash() -> None:
    payload = _protocol_payload()
    payload["policy"]["manifest_hash"] = "1" * 64
    specification = _revalidate(payload)
    with pytest.raises(Exception, match="M5"):
        bind_monday_benign_labeling_specification(REPO_ROOT, specification)


# --------------------------------------------------------------------------
# DDL
# --------------------------------------------------------------------------


def test_mb7_ddl_never_references_upstream_schemas_in_statements() -> None:
    executable = _strip_sql_comments(MB7_DDL_FILE.read_text(encoding="utf-8"))
    for forbidden in (
        "m4_canonical",
        "m6_canonical",
        "mb4_canonical",
        "mb6_canonical",
    ):
        assert forbidden not in executable
    assert "mb7_canonical" in executable


def test_mb7_ddl_forbids_attack_and_permits_ambiguous() -> None:
    executable = _strip_sql_comments(MB7_DDL_FILE.read_text(encoding="utf-8"))
    assert "ck_mb7_event_no_attack_on_benign_day" in executable
    assert "ck_mb7_window_no_attack_on_benign_day" in executable
    assert "CHECK (ambiguous_event_count >= 0)" in executable
    assert "CHECK (ambiguous_event_count = 0)" not in executable
    assert "'ambiguous'" in executable


def test_mb7_ddl_enforces_the_corrected_interval_invariant() -> None:
    """Outside the interval, benign is impossible; unknown and ambiguous are not."""
    executable = _strip_sql_comments(MB7_DDL_FILE.read_text(encoding="utf-8"))
    assert "ck_mb7_window_outside_never_benign" in executable
    assert (
        "CHECK (inside_compiled_interval OR disposition <> 'benign_reference')"
        in executable
    )
    assert "ck_mb7_window_interval_consistency" not in executable


# --------------------------------------------------------------------------
# Read-only database assertions
# --------------------------------------------------------------------------


@requires_db
def test_schema_contract_verification_passes_on_the_live_schema(
    read_only_connection,
) -> None:
    verify_mb7_schema(read_only_connection)


@requires_db
def test_persisted_counts_match_the_published_report(read_only_connection) -> None:
    with read_only_connection.cursor() as cur:
        cur.execute(
            f"SELECT (SELECT count(*) FROM {MB7_SCHEMA}.labeling_runs), "
            f"(SELECT count(*) FROM {MB7_SCHEMA}.event_labels), "
            f"(SELECT count(*) FROM {MB7_SCHEMA}.window_labels)"
        )
        runs, events, windows = cur.fetchone()
    assert runs == 1
    assert events == EVENTS_TOTAL
    assert windows == WINDOWS_TOTAL


@requires_db
def test_persisted_event_dispositions_match_the_ratified_counts(
    read_only_connection,
) -> None:
    with read_only_connection.cursor() as cur:
        cur.execute(
            f"SELECT disposition, count(*) FROM {MB7_SCHEMA}.event_labels "
            "GROUP BY 1 ORDER BY 1"
        )
        counts = dict(cur.fetchall())
    assert counts == {
        "ambiguous": EVENTS_AMBIGUOUS,
        "benign_reference": EVENTS_BENIGN,
        "unknown": EVENTS_UNKNOWN,
    }


@requires_db
def test_persisted_window_partition_matches_the_ratified_counts(
    read_only_connection,
) -> None:
    with read_only_connection.cursor() as cur:
        cur.execute(
            f"SELECT inside_compiled_interval, disposition, count(*) "
            f"FROM {MB7_SCHEMA}.window_labels GROUP BY 1, 2"
        )
        rows = {(inside, disp): n for inside, disp, n in cur.fetchall()}
    assert rows[(True, "benign_reference")] == WINDOWS_BENIGN
    assert rows[(True, "ambiguous")] == INSIDE_AMBIGUOUS
    assert rows[(False, "unknown")] == WINDOWS_UNKNOWN
    assert rows[(False, "ambiguous")] == OUTSIDE_AMBIGUOUS
    assert (False, "benign_reference") not in rows


@requires_db
def test_no_attack_label_exists_at_either_level(read_only_connection) -> None:
    with read_only_connection.cursor() as cur:
        cur.execute(
            f"SELECT (SELECT count(*) FROM {MB7_SCHEMA}.event_labels "
            "WHERE disposition IN ('target_attack','known_other_attack')), "
            f"(SELECT count(*) FROM {MB7_SCHEMA}.window_labels "
            "WHERE disposition IN ('target_attack','known_other_attack'))"
        )
        events, windows = cur.fetchone()
    assert events == 0
    assert windows == 0


@requires_db
def test_every_label_carries_complete_m5_provenance(read_only_connection) -> None:
    ledger = build_m5_v1_ledger(REPO_ROOT)
    with read_only_connection.cursor() as cur:
        cur.execute(
            f"SELECT count(*), count(*) FILTER (WHERE rule_version = %s), "
            "count(DISTINCT manifest_hash), count(DISTINCT authoritative_source), "
            "count(DISTINCT timezone), count(*) FILTER (WHERE length(rule_hash) = 64) "
            f"FROM {MB7_SCHEMA}.event_labels",
            (ledger.manifest.rule_version,),
        )
        total, rv, manifests, sources, tzs, hashes = cur.fetchone()
    assert total == rv == hashes == EVENTS_TOTAL
    assert manifests == sources == tzs == 1


@requires_db
def test_labels_are_bijective_with_mb4_and_mb6(read_only_connection) -> None:
    with read_only_connection.cursor() as cur:
        cur.execute(
            f"""
            SELECT (SELECT count(DISTINCT source_event_id)
                      FROM {MB7_SCHEMA}.event_labels),
                   (SELECT count(*) FROM mb4_canonical.flow_end_events),
                   (SELECT count(*) FROM {MB7_SCHEMA}.event_labels e
                      WHERE NOT EXISTS (SELECT 1
                          FROM mb4_canonical.flow_end_events v
                          WHERE v.event_id = e.source_event_id)),
                   (SELECT count(DISTINCT source_window_id)
                      FROM {MB7_SCHEMA}.window_labels),
                   (SELECT count(*) FROM mb6_canonical.feature_windows),
                   (SELECT count(*) FROM {MB7_SCHEMA}.window_labels w
                      WHERE NOT EXISTS (SELECT 1
                          FROM mb6_canonical.feature_windows v
                          WHERE v.window_id = w.source_window_id))
            """
        )
        ev_distinct, mb4, ev_orphans, win_distinct, mb6, win_orphans = cur.fetchone()
    assert ev_distinct == mb4 == EVENTS_TOTAL
    assert win_distinct == mb6 == WINDOWS_TOTAL
    assert ev_orphans == 0
    assert win_orphans == 0


@requires_db
def test_ambiguous_windows_contain_ambiguous_events(read_only_connection) -> None:
    """The 127 ambiguous windows exist only because they hold ambiguous events."""
    with read_only_connection.cursor() as cur:
        cur.execute(
            f"SELECT count(*), min(ambiguous_event_count) "
            f"FROM {MB7_SCHEMA}.window_labels WHERE disposition = 'ambiguous'"
        )
        count, min_ambiguous = cur.fetchone()
    assert count == WINDOWS_AMBIGUOUS
    assert min_ambiguous >= 1


@requires_db
def test_benign_windows_hold_only_benign_events(read_only_connection) -> None:
    with read_only_connection.cursor() as cur:
        cur.execute(
            f"SELECT count(*) FROM {MB7_SCHEMA}.window_labels "
            "WHERE disposition = 'benign_reference' AND "
            "(unknown_event_count > 0 OR ambiguous_event_count > 0 "
            " OR benign_reference_event_count <> source_event_count)"
        )
        assert cur.fetchone()[0] == 0


@requires_db
def test_no_foreign_key_leaves_mb7_canonical(read_only_connection) -> None:
    with read_only_connection.cursor() as cur:
        cur.execute(
            """
            SELECT c.conname, n.nspname
            FROM pg_constraint c
            JOIN pg_class t ON t.oid = c.confrelid
            JOIN pg_namespace n ON n.oid = t.relnamespace
            WHERE c.contype = 'f'
              AND c.conrelid IN (
                  SELECT oid FROM pg_class
                  WHERE relnamespace = %s::regnamespace
              )
            """,
            (MB7_SCHEMA,),
        )
        foreign = cur.fetchall()
    assert foreign
    for name, schema in foreign:
        assert schema == MB7_SCHEMA, f"{name} escapes to {schema}"


@requires_db
def test_label_ids_never_collide_with_any_canonical_identity(
    read_only_connection,
) -> None:
    """Complete set intersections against MB4, MB6 and the M chain."""
    with read_only_connection.cursor() as cur:
        cur.execute(f"SELECT label_id FROM {MB7_SCHEMA}.event_labels")
        event_labels = {r[0] for r in cur.fetchall()}
        cur.execute(f"SELECT label_id FROM {MB7_SCHEMA}.window_labels")
        window_labels = {r[0] for r in cur.fetchall()}
        cur.execute("SELECT event_id FROM mb4_canonical.flow_end_events")
        mb4 = {r[0] for r in cur.fetchall()}
        cur.execute("SELECT window_id FROM mb6_canonical.feature_windows")
        mb6 = {r[0] for r in cur.fetchall()}
    conn = get_monday_benign_connection(PRODUCTION_DATABASE)
    try:
        with conn.cursor() as cur:
            cur.execute("SET default_transaction_read_only = on")
            cur.execute("SELECT event_id FROM m4_canonical.flow_end_events")
            m4 = {r[0] for r in cur.fetchall()}
            cur.execute("SELECT window_id FROM m6_canonical.feature_windows")
            m6 = {r[0] for r in cur.fetchall()}
    finally:
        conn.close()
    assert len(event_labels) == EVENTS_TOTAL
    assert len(window_labels) == WINDOWS_TOTAL
    assert not (event_labels & window_labels)
    for other in (mb4, mb6, m4, m6):
        assert not (event_labels & other)
        assert not (window_labels & other)


@requires_db
def test_a_second_verified_run_is_impossible(read_only_connection) -> None:
    with read_only_connection.cursor() as cur:
        cur.execute(
            "SELECT indexdef FROM pg_indexes "
            "WHERE schemaname = %s AND indexname = 'ux_mb7_runs_verified_protocol'",
            (MB7_SCHEMA,),
        )
        row = cur.fetchone()
    assert row is not None
    assert "UNIQUE" in row[0]
    assert "verified" in row[0]


@requires_db
def test_m_chain_counters_are_untouched() -> None:
    conn = get_monday_benign_connection(PRODUCTION_DATABASE)
    try:
        with conn.cursor() as cur:
            cur.execute("SET default_transaction_read_only = on")
            cur.execute(
                "SELECT (SELECT count(*) FROM m4_canonical.flow_end_events), "
                "(SELECT count(*) FROM m6_canonical.feature_windows), "
                "(SELECT count(*) FROM m6_canonical.feature_window_sources), "
                "(SELECT count(*) FROM information_schema.tables "
                " WHERE table_schema LIKE 'mb%')"
            )
            events, windows, lineage, mb_tables = cur.fetchone()
    finally:
        conn.close()
    assert events == 1_353_467
    assert windows == 172_748
    assert lineage == 1_353_467
    assert mb_tables == 0


@requires_db
def test_mb4_and_mb6_are_untouched(read_only_connection) -> None:
    with read_only_connection.cursor() as cur:
        cur.execute(
            "SELECT (SELECT count(*) FROM mb4_canonical.flow_end_events), "
            "(SELECT count(*) FROM mb6_canonical.feature_windows), "
            "(SELECT count(*) FROM mb6_canonical.feature_window_sources)"
        )
        events, windows, lineage = cur.fetchone()
    assert events == EVENTS_TOTAL
    assert windows == WINDOWS_TOTAL
    assert lineage == EVENTS_TOTAL


# --------------------------------------------------------------------------
# Isolation of the MB7 sources
# --------------------------------------------------------------------------


def test_no_label_column_was_added_to_mb6() -> None:
    """MB7 is a sidecar; the MB6 DDL must remain label-free."""
    mb6_ddl = (
        REPO_ROOT / "modules/detection/src/persistence/schema_mb6.sql"
    ).read_text(encoding="utf-8")
    for forbidden in ("disposition", "label", "benign_reference", "attack_family"):
        assert forbidden not in mb6_ddl


def test_mb_label_did_not_build_a_dataset() -> None:
    """MB-LABEL must not have begun dataset construction, splitting or sampling."""
    for absent in (
        "scripts/build_ml_dataset.py",
        "modules/detection/src/persistence/schema_mb8.sql",
        "datasets/manifests/ml_dataset.yaml",
    ):
        assert not (REPO_ROOT / absent).exists()
