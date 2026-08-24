"""Contractual tests for MB4 Monday Benign canonical persistence.

CRITICAL: these tests are **strictly read-only against PostgreSQL**.

The MB4 milestone data lives in ``cybersentinel_test``, which is also the
database used for destructive integration-test isolation. A ``DELETE`` or
``TRUNCATE`` here would destroy the milestone -- exactly the failure mode that
caused the M4 production data loss, where a test teardown wiped 1,353,467 rows.
No test in this module issues any DML or DDL. Every database assertion is a
``SELECT``.

Contract-level tests need no database at all and always run.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from modules.detection.src.persistence.monday_benign_persistence import (
    MB4_REPORT_RELATIVE_PATH,
    MB4_SCHEMA,
    MondayBenignDatabaseGuardError,
    MondayBenignMaterializationError,
    MondayBenignMaterializationReport,
    _strip_sql_comments,
    assert_expected_database,
    get_monday_benign_connection,
    verify_frozen_mb3_report,
    verify_mb4_schema,
)
from modules.detection.src.schemas.monday_benign_normalization import (
    MB3_EVENT_ID_NAMESPACE,
)
from modules.detection.src.schemas.monday_benign_replay import MONDAY_OUTPUT_PARTITION


REPO_ROOT = Path(__file__).resolve().parents[3]
MB4_DDL = REPO_ROOT / "modules/detection/src/persistence/schema_mb.sql"
M4_DDL = REPO_ROOT / "modules/detection/src/persistence/schema_v2.sql"
MB4_REPORT = REPO_ROOT / MB4_REPORT_RELATIVE_PATH
TEST_DATABASE = "cybersentinel_test"
PRODUCTION_DATABASE = "cybersentinel"


def _database_available(database: str) -> bool:
    try:
        conn = get_monday_benign_connection(database, connect_timeout=3)
    except Exception:
        return False
    conn.close()
    return True


requires_test_db = pytest.mark.skipif(
    not _database_available(TEST_DATABASE),
    reason="PostgreSQL cybersentinel_test is unreachable",
)


@pytest.fixture()
def read_only_test_connection():
    """Yield a connection to the MB4 database in enforced read-only mode.

    ``default_transaction_read_only`` makes an accidental write impossible at
    the server level, not merely by convention.
    """
    conn = get_monday_benign_connection(TEST_DATABASE)
    try:
        with conn.cursor() as cur:
            cur.execute("SET default_transaction_read_only = on")
        conn.commit()
        assert assert_expected_database(conn, TEST_DATABASE) == TEST_DATABASE
        yield conn
    finally:
        conn.close()


@pytest.fixture(scope="module")
def published_report() -> MondayBenignMaterializationReport:
    if not MB4_REPORT.is_file():
        pytest.skip("MB4 report is not published")
    return MondayBenignMaterializationReport.model_validate_json(
        MB4_REPORT.read_text(encoding="utf-8")
    )


# --------------------------------------------------------------------------
# DDL: strict mirror of M4, isolated from the M chain
# --------------------------------------------------------------------------


def test_mb4_ddl_statements_never_reference_an_m_chain_schema() -> None:
    """Comments may name the M schemas to document isolation; statements may not."""
    executable = _strip_sql_comments(MB4_DDL.read_text(encoding="utf-8"))
    assert "m4_canonical" not in executable
    assert "m6_canonical" not in executable
    assert "mb4_canonical" in executable


def test_mb4_ddl_declares_the_four_expected_tables() -> None:
    executable = _strip_sql_comments(MB4_DDL.read_text(encoding="utf-8"))
    for table in (
        "mb4_canonical.materialization_runs",
        "mb4_canonical.flow_end_events",
        "mb4_canonical.rejection_spans",
        "mb4_canonical.rejection_counts",
    ):
        assert f"CREATE TABLE IF NOT EXISTS {table}" in executable


def test_mb4_ddl_preserves_the_m4_invariants() -> None:
    """Every invariant the owner required must be literally present."""
    executable = _strip_sql_comments(MB4_DDL.read_text(encoding="utf-8"))
    assert "event_id                    UUID PRIMARY KEY" in executable
    assert executable.count("NUMERIC(38, 22) NOT NULL") == 5
    assert "CHECK (event_end_time = event_start_time + event_duration)" in executable
    assert "CHECK (event_end_time <= record_available_time" in executable
    assert "record_available_time <= ingested_at)" in executable
    assert "CHECK (transport IN ('tcp', 'udp'))" in executable
    assert "CHECK (termination_reason IS NULL)" in executable
    assert "CHECK (physical_line_number > 0)" in executable
    assert "UNIQUE (output_partition, physical_line_number)" in executable
    assert "WHERE status = 'verified'" in executable
    for counter in (
        "source_packets",
        "destination_packets",
        "source_bytes",
        "destination_bytes",
    ):
        assert f"CHECK ({counter} >= 0)" in executable


def test_mb4_ddl_confines_every_table_to_the_monday_partition() -> None:
    """MB-only hardening absent from M4: the storage layer rejects other days."""
    executable = _strip_sql_comments(MB4_DDL.read_text(encoding="utf-8"))
    occurrences = executable.count(
        f"CHECK (output_partition = '{MONDAY_OUTPUT_PARTITION}')"
    )
    assert occurrences == 3


def test_mb4_ddl_numeric_columns_match_m4_exactly() -> None:
    """The five temporal columns are identical in name and type to M4."""
    mb4 = _strip_sql_comments(MB4_DDL.read_text(encoding="utf-8"))
    m4 = _strip_sql_comments(M4_DDL.read_text(encoding="utf-8"))
    for column in (
        "event_start_time",
        "event_duration",
        "event_end_time",
        "record_available_time",
        "ingested_at",
    ):
        needle = f"{column}"
        assert needle in mb4 and needle in m4
    assert mb4.count("NUMERIC(38, 22) NOT NULL") == m4.count(
        "NUMERIC(38, 22) NOT NULL"
    )


# --------------------------------------------------------------------------
# MB3 gate
# --------------------------------------------------------------------------


def test_frozen_mb3_report_gate_accepts_the_published_report() -> None:
    verified = verify_frozen_mb3_report(REPO_ROOT)
    assert verified.report.track == "monday_benign"
    assert verified.report.event_id_namespace == MB3_EVENT_ID_NAMESPACE
    assert verified.event_stream_sha256 == (
        "ed558ab37f984960816c2370fc3046a0c8d1d2bfbdd4dc353f7a6fbf95c7706a"
    )
    assert len(verified.report_file_sha256) == 64


def test_frozen_mb3_report_gate_rejects_a_missing_report() -> None:
    with pytest.raises(MondayBenignMaterializationError, match="not found"):
        verify_frozen_mb3_report(REPO_ROOT, "artifacts/reports/absent.json")


# --------------------------------------------------------------------------
# Report contract
# --------------------------------------------------------------------------


def _report_payload() -> dict:
    if not MB4_REPORT.is_file():
        pytest.skip("MB4 report is not published")
    return json.loads(MB4_REPORT.read_text(encoding="utf-8"))


def test_published_report_is_verified_and_monday_only(
    published_report: MondayBenignMaterializationReport,
) -> None:
    assert published_report.verification_status == "verified"
    assert published_report.track == "monday_benign"
    assert published_report.output_partition == MONDAY_OUTPUT_PARTITION
    assert published_report.target_schema == MB4_SCHEMA
    assert published_report.mb3_event_id_namespace == MB3_EVENT_ID_NAMESPACE
    assert published_report.total_processed_record_count == 375_432
    assert published_report.total_accepted_record_count == 368_202
    assert published_report.total_rejected_record_count == 7_230
    assert published_report.persisted_event_count == 368_202


def test_published_report_proves_digest_equality_with_mb3(
    published_report: MondayBenignMaterializationReport,
) -> None:
    assert published_report.materialized_event_stream_sha256 == (
        published_report.mb3_event_stream_sha256
    )
    assert published_report.materialized_rejection_stream_sha256 == (
        published_report.mb3_rejection_audit_stream_sha256
    )


def _validate_payload(payload: dict) -> MondayBenignMaterializationReport:
    """Validate a mutated payload in JSON mode.

    ``StrictModel`` rejects plain strings for UUID and datetime fields, so a
    mutated dict must be re-serialized rather than passed to ``model_validate``.
    """
    return MondayBenignMaterializationReport.model_validate_json(json.dumps(payload))


def test_report_rejects_a_digest_that_diverges_from_mb3() -> None:
    payload = _report_payload()
    payload["materialized_event_stream_sha256"] = "0" * 64
    with pytest.raises(ValidationError, match="differs"):
        _validate_payload(payload)


def test_report_rejects_a_foreign_partition() -> None:
    payload = _report_payload()
    payload["output_partition"] = "2017-07-04_Tuesday-WorkingHours"
    with pytest.raises(ValidationError):
        _validate_payload(payload)


def test_report_rejects_a_foreign_namespace() -> None:
    payload = _report_payload()
    payload["mb3_event_id_namespace"] = "f7dad188-04cb-5859-81a0-014329de2899"
    with pytest.raises(ValidationError):
        _validate_payload(payload)


def test_report_rejects_incoherent_totals() -> None:
    payload = _report_payload()
    payload["total_accepted_record_count"] = 1
    with pytest.raises(ValidationError):
        _validate_payload(payload)


def test_report_rejects_a_persisted_count_below_accepted() -> None:
    payload = _report_payload()
    payload["persisted_event_count"] = 10
    with pytest.raises(ValidationError, match="persisted event count"):
        _validate_payload(payload)


def test_report_content_hash_round_trips(
    published_report: MondayBenignMaterializationReport,
) -> None:
    reloaded = MondayBenignMaterializationReport.model_validate_json(
        MB4_REPORT.read_text(encoding="utf-8")
    )
    assert reloaded == published_report
    assert reloaded.content_sha256() == published_report.content_sha256()


# --------------------------------------------------------------------------
# Database guard
# --------------------------------------------------------------------------


def test_connection_requires_an_explicit_database_name() -> None:
    with pytest.raises(MondayBenignDatabaseGuardError):
        get_monday_benign_connection("")


@requires_test_db
def test_database_guard_rejects_a_mismatched_database() -> None:
    conn = get_monday_benign_connection(PRODUCTION_DATABASE)
    try:
        with pytest.raises(MondayBenignDatabaseGuardError, match="refuses to write"):
            assert_expected_database(conn, TEST_DATABASE)
    finally:
        conn.close()


@requires_test_db
def test_database_guard_accepts_the_expected_database(
    read_only_test_connection,
) -> None:
    assert (
        assert_expected_database(read_only_test_connection, TEST_DATABASE)
        == TEST_DATABASE
    )


# --------------------------------------------------------------------------
# Read-only database assertions
# --------------------------------------------------------------------------


@requires_test_db
def test_schema_contract_verification_passes_on_the_live_schema(
    read_only_test_connection,
) -> None:
    verify_mb4_schema(read_only_test_connection)


@requires_test_db
def test_persisted_counts_match_the_published_report(
    read_only_test_connection,
    published_report: MondayBenignMaterializationReport,
) -> None:
    with read_only_test_connection.cursor() as cur:
        cur.execute(
            f"SELECT (SELECT count(*) FROM {MB4_SCHEMA}.materialization_runs), "
            f"(SELECT count(*) FROM {MB4_SCHEMA}.flow_end_events), "
            f"(SELECT count(*) FROM {MB4_SCHEMA}.rejection_spans), "
            f"(SELECT count(*) FROM {MB4_SCHEMA}.rejection_counts)"
        )
        runs, events, spans, counts = cur.fetchone()
    assert runs == 1
    assert events == published_report.persisted_event_count == 368_202
    assert spans == published_report.persisted_rejection_span_count
    assert counts == published_report.persisted_rejection_count_rows == 3


@requires_test_db
def test_every_persisted_row_is_the_monday_partition(
    read_only_test_connection,
) -> None:
    with read_only_test_connection.cursor() as cur:
        cur.execute(
            f"SELECT count(DISTINCT output_partition), min(output_partition) "
            f"FROM {MB4_SCHEMA}.flow_end_events"
        )
        distinct, partition = cur.fetchone()
    assert distinct == 1
    assert partition == MONDAY_OUTPUT_PARTITION


@requires_test_db
def test_event_ids_are_unique_uuid5_and_cover_every_accepted_line(
    read_only_test_connection,
) -> None:
    with read_only_test_connection.cursor() as cur:
        cur.execute(
            f"SELECT count(*), count(DISTINCT event_id), "
            f"count(DISTINCT physical_line_number), "
            f"count(*) FILTER (WHERE substring(event_id::text, 15, 1) = '5') "
            f"FROM {MB4_SCHEMA}.flow_end_events"
        )
        total, distinct_ids, distinct_lines, uuid5_rows = cur.fetchone()
    assert total == distinct_ids == distinct_lines == 368_202
    assert uuid5_rows == 368_202


@requires_test_db
def test_mb3_boundary_event_ids_are_persisted(read_only_test_connection) -> None:
    with read_only_test_connection.cursor() as cur:
        cur.execute(
            f"SELECT count(*) FROM {MB4_SCHEMA}.flow_end_events "
            "WHERE event_id IN (%s, %s)",
            (
                "ccd1c0c7-49aa-579b-9d2e-6c73c47ca522",
                "3963129e-fb7d-5c07-a1ac-2e7b02d73313",
            ),
        )
        assert cur.fetchone()[0] == 2


@requires_test_db
def test_temporal_invariants_hold_for_every_row(read_only_test_connection) -> None:
    with read_only_test_connection.cursor() as cur:
        cur.execute(
            f"""
            SELECT count(*),
                   count(*) FILTER (
                       WHERE event_end_time = event_start_time + event_duration),
                   count(*) FILTER (
                       WHERE event_end_time <= record_available_time
                         AND record_available_time <= ingested_at),
                   count(*) FILTER (
                       WHERE scale(event_start_time) = 22
                         AND scale(event_duration) = 22
                         AND scale(event_end_time) = 22),
                   count(*) FILTER (WHERE termination_reason IS NULL)
            FROM {MB4_SCHEMA}.flow_end_events
            """
        )
        total, exact_end, causal, scale22, termination = cur.fetchone()
    assert total == 368_202
    assert exact_end == causal == scale22 == termination == total


@requires_test_db
def test_temporal_columns_are_numeric_38_22(read_only_test_connection) -> None:
    with read_only_test_connection.cursor() as cur:
        cur.execute(
            "SELECT column_name, numeric_precision, numeric_scale "
            "FROM information_schema.columns "
            "WHERE table_schema = %s AND table_name = 'flow_end_events' "
            "AND data_type = 'numeric' ORDER BY column_name",
            (MB4_SCHEMA,),
        )
        rows = cur.fetchall()
    assert len(rows) == 5
    for _, precision, scale in rows:
        assert (precision, scale) == (38, 22)


@requires_test_db
def test_no_foreign_key_leaves_mb4_canonical(read_only_test_connection) -> None:
    with read_only_test_connection.cursor() as cur:
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
            (MB4_SCHEMA,),
        )
        foreign = cur.fetchall()
    assert foreign, "MB4 must declare run foreign keys"
    for name, schema in foreign:
        assert schema == MB4_SCHEMA, f"{name} escapes {MB4_SCHEMA} to {schema}"


@requires_test_db
def test_rejection_evidence_covers_exactly_the_rejected_records(
    read_only_test_connection,
) -> None:
    with read_only_test_connection.cursor() as cur:
        cur.execute(
            f"SELECT (SELECT sum(count) FROM {MB4_SCHEMA}.rejection_counts), "
            f"(SELECT sum(last_physical_line_number "
            f"- first_physical_line_number + 1) "
            f"FROM {MB4_SCHEMA}.rejection_spans)"
        )
        counts_total, span_coverage = cur.fetchone()
    assert counts_total == span_coverage == 7_230


@requires_test_db
def test_the_run_row_is_verified_and_digest_bound(read_only_test_connection) -> None:
    with read_only_test_connection.cursor() as cur:
        cur.execute(
            f"SELECT status, "
            f"mb3_event_stream_sha256 = materialized_event_stream_sha256, "
            f"mb3_rejection_audit_stream_sha256 "
            f"= materialized_rejection_stream_sha256, "
            f"mb3_event_id_namespace, completed_at >= started_at "
            f"FROM {MB4_SCHEMA}.materialization_runs"
        )
        rows = cur.fetchall()
    assert len(rows) == 1
    status, events_match, rejections_match, namespace, ordered = rows[0]
    assert status == "verified"
    assert events_match is True
    assert rejections_match is True
    assert namespace == MB3_EVENT_ID_NAMESPACE
    assert ordered is True


@requires_test_db
def test_a_second_verified_run_is_impossible(read_only_test_connection) -> None:
    """The partial unique index makes double publication a storage-level error."""
    with read_only_test_connection.cursor() as cur:
        cur.execute(
            "SELECT indexdef FROM pg_indexes "
            "WHERE schemaname = %s AND indexname = 'ux_mb4_runs_verified_report'",
            (MB4_SCHEMA,),
        )
        row = cur.fetchone()
    assert row is not None
    assert "UNIQUE" in row[0]
    assert "mb3_report_content_sha256" in row[0]
    assert "verified" in row[0]


# --------------------------------------------------------------------------
# M chain isolation
# --------------------------------------------------------------------------


@requires_test_db
def test_production_database_holds_no_mb_schema() -> None:
    conn = get_monday_benign_connection(PRODUCTION_DATABASE)
    try:
        with conn.cursor() as cur:
            cur.execute("SET default_transaction_read_only = on")
            cur.execute(
                "SELECT count(*) FROM information_schema.tables "
                "WHERE table_schema LIKE 'mb%'"
            )
            assert cur.fetchone()[0] == 0
    finally:
        conn.close()


@requires_test_db
def test_m_chain_counters_are_untouched() -> None:
    conn = get_monday_benign_connection(PRODUCTION_DATABASE)
    try:
        with conn.cursor() as cur:
            cur.execute("SET default_transaction_read_only = on")
            cur.execute(
                "SELECT (SELECT count(*) FROM m4_canonical.flow_end_events), "
                "(SELECT count(*) FROM m6_canonical.feature_windows), "
                "(SELECT count(*) FROM m6_canonical.feature_window_sources)"
            )
            events, windows, lineage = cur.fetchone()
    finally:
        conn.close()
    assert events == 1_353_467
    assert windows == 172_748
    assert lineage == 1_353_467


def test_mb4_sources_never_reference_an_m_chain_table() -> None:
    """No schema-qualified reference to an M chain table may exist.

    The module docstring names ``m4_canonical`` and ``m6_canonical`` in prose to
    document the isolation boundary, which is why this test looks for the
    *qualified* form ``m4_canonical.`` -- the only shape a real SQL identifier or
    attribute access can take. Prose never carries the trailing dot.
    """
    source = (
        REPO_ROOT / "modules/detection/src/persistence/monday_benign_persistence.py"
    ).read_text(encoding="utf-8")
    assert "m4_canonical." not in source
    assert "m6_canonical." not in source
    # The MB4 schema constant is the only schema this module may qualify.
    assert "mb4_canonical" in source


def test_mb4_remains_independent_of_mb6() -> None:
    """MB4 must not depend on MB6, even though MB6 now exists.

    Before MB6 this test asserted that the MB6 manifest and script were absent.
    MB6 created both on 2026-08-13, so that form became false by design -- the
    same failure mode as the obsolete `test_no_production...` M4 guards. The
    surviving intent is that the dependency runs one way only: MB6 reads MB4,
    never the reverse.
    """
    for source in (
        "modules/detection/src/persistence/monday_benign_persistence.py",
        "scripts/materialize_monday_benign_events.py",
    ):
        text = (REPO_ROOT / source).read_text(encoding="utf-8")
        assert "mb6_canonical" not in text
        assert "monday_benign_window_persistence" not in text
        assert "monday_benign_feature_window" not in text
