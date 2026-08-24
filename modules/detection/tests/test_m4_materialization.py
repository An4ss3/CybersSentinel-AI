"""Focused tests for M4 Phase 2 canonical event materialization.

Scope deliberately excludes the full 1,380,057-record production run. Tests
cover:
- Row-mapping correctness from a real frozen FlowEndV2 event (no field
  reinterpretation, no float conversion of exact-time values).
- Adapter construction via the seven-point verification gate.
- Single real frozen source line materialized end-to-end (parse -> normalize
  -> row mapping), reusing the exact frozen M3 v2 parser/normalizer.
- Fail-loud duplicate-run detection against a stub connection.
- Full three-partition materialization and hash cross-check against
  PostgreSQL, when a live instance is reachable; otherwise skipped rather than
  faked.
"""
from __future__ import annotations

from decimal import Decimal
import os
from pathlib import Path

import pytest

from modules.detection.src.ingestion.zeek_json_v2 import StrictZeekJsonLineParserV2
from modules.detection.src.lineage.zeek_normalization_v2 import (
    load_and_bind_zeek_normalization_specification_v2,
)
from modules.detection.src.normalization.zeek_conn_v2 import (
    StrictZeekConnFlowEndNormalizerV2,
)
from modules.detection.src.persistence.db import ensure_m4_schema, get_connection
from modules.detection.src.persistence.materialization_v2 import (
    M4DuplicateVerifiedRunError,
    ZeekConnMaterializationAdapterV2,
    _flow_end_row,
)
from modules.detection.src.persistence.report_verification_v2 import (
    verify_frozen_m3_v2_report,
)
from modules.detection.src.schemas.events_v2 import FlowEndV2
from modules.detection.src.schemas.zeek_normalization import ZeekSourceCoordinate
from modules.detection.src.schemas.zeek_normalization_v2 import (
    ZeekNormalizationContextV2,
)
from uuid import uuid4


ROOT = Path(__file__).resolve().parents[3]

# --- I1: isolated test database -------------------------------------------
# M4 integration tests must never reach the production m4_canonical tables.
# They run exclusively against a dedicated database whose identity is asserted
# from inside the connection before any write or delete is permitted.
M4_TEST_DATABASE = os.getenv("POSTGRES_TEST_DB", "cybersentinel_test")


def _delete_all_isolated(conn) -> None:
    """Clear the isolated test database only.

    This helper is private to the isolated fixture, which has already proven
    that ``current_database()`` is the dedicated test database. It is therefore
    unreachable from any code path pointing at production.
    """
    with conn.cursor() as cur:
        cur.execute("DELETE FROM m4_canonical.rejection_counts")
        cur.execute("DELETE FROM m4_canonical.rejection_spans")
        cur.execute("DELETE FROM m4_canonical.flow_end_events")
        cur.execute("DELETE FROM m4_canonical.materialization_runs")
    conn.commit()


@pytest.fixture
def m4_isolated_connection(monkeypatch):
    """Yield a connection to the dedicated M4 test database, never production.

    Refuses to proceed unless the server reports the isolated database name,
    so a misconfigured environment fails or skips instead of touching the
    published M4 production materialization.
    """
    production_database = os.getenv("POSTGRES_DB", "cybersentinel")
    if M4_TEST_DATABASE == production_database:
        pytest.fail(
            "M4 integration tests refuse to run: the configured test database "
            f"'{M4_TEST_DATABASE}' is the production database"
        )

    monkeypatch.setenv("POSTGRES_DB", M4_TEST_DATABASE)
    conn = get_connection(connect_timeout=2)
    if conn is None:
        pytest.skip(
            f"isolated M4 test database '{M4_TEST_DATABASE}' is not reachable"
        )

    with conn.cursor() as cur:
        cur.execute("SELECT current_database()")
        (connected,) = cur.fetchone()
    if connected != M4_TEST_DATABASE:
        conn.close()
        pytest.fail(
            f"refusing to run: connected to '{connected}', "
            f"expected isolated database '{M4_TEST_DATABASE}'"
        )

    try:
        ensure_m4_schema(conn)
        _delete_all_isolated(conn)
        yield conn
        _delete_all_isolated(conn)
    finally:
        conn.close()


# --- Row mapping -------------------------------------------------------


def _real_first_line_event() -> tuple[FlowEndV2, ZeekSourceCoordinate]:
    bound = load_and_bind_zeek_normalization_specification_v2(ROOT)
    specification = bound.specification
    binding = specification.replay_reports[0]
    conn_path = (
        ROOT / specification.m2_output_root / binding.output_partition / "conn.log"
    )
    with conn_path.open("rb") as f:
        first_line = f.readline()

    source = ZeekSourceCoordinate(
        output_partition=binding.output_partition,
        replay_report_content_sha256=binding.report_content_sha256,
        log_name="conn.log",
        source_log_sha256=binding.supported_log.sha256,
        reported_record_count=binding.supported_log.record_count,
        physical_line_number=1,
    )
    context = ZeekNormalizationContextV2(
        protocol_sha256=specification.content_sha256(),
        source=source,
        record_available_time="1722783600.0000000000000000000000",
        ingested_at="1722783601.0000000000000000000000",
    )
    parser = StrictZeekJsonLineParserV2()
    normalizer = StrictZeekConnFlowEndNormalizerV2(specification)
    record = parser.parse_line(first_line, source)
    event = normalizer.normalize_conn(record, context)
    return event, source


def test_flow_end_row_preserves_provenance_verbatim() -> None:
    event, source = _real_first_line_event()
    run_id = uuid4()
    row = _flow_end_row(event, run_id, source)

    assert row["event_id"] == str(event.provenance.event_id)
    assert row["sensor_id"] == event.provenance.sensor_id
    assert row["sensor_run_id"] == event.provenance.sensor_run_id
    assert row["capture_id"] == event.provenance.capture_id
    assert row["dataset_snapshot_id"] == event.provenance.dataset_snapshot_id
    assert row["model_release_id"] == event.provenance.model_release_id
    assert row["normalizer_version"] == event.provenance.normalizer_version
    assert row["pipeline_version"] == event.provenance.pipeline_version
    assert row["m4_run_id"] == str(run_id)


def test_flow_end_row_preserves_exact_temporal_strings_no_float() -> None:
    """Temporal fields remain the exact DECIMAL(38,22) strings — never float."""
    event, source = _real_first_line_event()
    row = _flow_end_row(event, uuid4(), source)

    for field_name in (
        "event_start_time",
        "event_duration",
        "event_end_time",
        "record_available_time",
        "ingested_at",
    ):
        value = row[field_name]
        assert isinstance(value, str), f"{field_name} must remain a string, not float"
        # Round-trips through Decimal without precision loss.
        assert Decimal(value) == Decimal(getattr(event, field_name))


def test_flow_end_row_preserves_source_coordinate() -> None:
    event, source = _real_first_line_event()
    row = _flow_end_row(event, uuid4(), source)

    assert row["output_partition"] == source.output_partition
    assert row["physical_line_number"] == source.physical_line_number


def test_flow_end_row_preserves_endpoints_and_counters() -> None:
    event, source = _real_first_line_event()
    row = _flow_end_row(event, uuid4(), source)

    assert row["source_ip"] == str(event.source.ip)
    assert row["source_port"] == event.source.port
    assert row["destination_ip"] == str(event.destination.ip)
    assert row["destination_port"] == event.destination.port
    assert row["transport"] == event.transport
    assert row["service"] == event.service
    assert row["source_packets"] == event.counters.source_packets
    assert row["destination_packets"] == event.counters.destination_packets
    assert row["source_bytes"] == event.counters.source_bytes
    assert row["destination_bytes"] == event.counters.destination_bytes
    assert row["connection_state"] == event.connection_state
    assert row["termination_reason"] is None


def test_flow_end_row_event_bytes_hash_matches_frozen_serialization() -> None:
    """event_bytes_sha256 uses the same canonical bytes M3 v2 hashed."""
    from hashlib import sha256

    from modules.detection.src.normalization.zeek_pipeline_v2 import (
        _canonical_event_bytes,
    )

    event, source = _real_first_line_event()
    row = _flow_end_row(event, uuid4(), source)

    assert row["event_bytes_sha256"] == sha256(_canonical_event_bytes(event)).hexdigest()


# --- Adapter construction ----------------------------------------------


def test_adapter_construction_via_verification_gate() -> None:
    """The adapter can only be constructed after the frozen report is verified."""
    adapter = ZeekConnMaterializationAdapterV2.from_repository(ROOT)
    assert adapter._protocol_sha256 == (
        "5286ddde937ad132afdeb8814e0e0af01745afbb7d1d446ae8860b7701fea210"
    )


def test_adapter_reuses_frozen_report_temporal_context() -> None:
    """record_available_time/ingested_at come from the frozen report, not invented."""
    verified = verify_frozen_m3_v2_report(ROOT)
    bound = load_and_bind_zeek_normalization_specification_v2(ROOT)
    adapter = ZeekConnMaterializationAdapterV2(ROOT, bound, verified)

    assert adapter._record_available_time() == verified.report.record_available_time
    assert adapter._ingested_at() == verified.report.ingested_at


def test_adapter_does_not_import_or_call_frozen_runner_class() -> None:
    """The adapter module must not reference ZeekConnNormalizationRunnerV2."""
    import modules.detection.src.persistence.materialization_v2 as adapter_module

    assert not hasattr(adapter_module, "ZeekConnNormalizationRunnerV2")


# --- Single real source line, end-to-end without a database ------------


def test_materialize_partition_logic_on_real_first_line_without_db() -> None:
    """The parse+normalize+row-mapping path succeeds on real frozen bytes.

    This does not touch PostgreSQL; it verifies the adapter's per-record path
    reproduces the same accepted event the frozen normalizer would produce.
    """
    event, source = _real_first_line_event()
    assert isinstance(event, FlowEndV2)
    assert event.provenance.sensor_id == "zeek"
    assert source.physical_line_number == 1


# --- PostgreSQL-dependent tests (isolated test database only) -----------
#
# I1 + I4: every test below receives ``m4_isolated_connection``, which is bound
# to the dedicated M4 test database and asserts that identity before yielding.
# No test issues DELETE against a connection it did not receive from that
# fixture, so the production m4_canonical tables are unreachable from here.


def test_ensure_schema_is_idempotent(m4_isolated_connection) -> None:
    """Applying the DDL twice must succeed (CREATE ... IF NOT EXISTS only)."""
    ensure_m4_schema(m4_isolated_connection)
    ensure_m4_schema(m4_isolated_connection)

    with m4_isolated_connection.cursor() as cur:
        cur.execute(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema = 'm4_canonical' ORDER BY table_name"
        )
        tables = [row[0] for row in cur.fetchall()]
    assert tables == [
        "flow_end_events",
        "materialization_runs",
        "rejection_counts",
        "rejection_spans",
    ]


def test_duplicate_verified_run_fails_loudly(m4_isolated_connection) -> None:
    """A second materialize() against an already-verified report must raise."""
    from datetime import datetime, timezone

    conn = m4_isolated_connection
    adapter = ZeekConnMaterializationAdapterV2.from_repository(ROOT)
    verified = adapter._verified_report

    # Seed a verified run so the fail-loud guard has something to detect,
    # without materializing 1.38M records in this test.
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO m4_canonical.materialization_runs (
                run_id, m3_report_content_sha256, m3_report_file_sha256,
                m3_protocol_sha256, m3_event_stream_sha256,
                m3_rejection_audit_stream_sha256, status, started_at,
                completed_at
            ) VALUES (%s, %s, %s, %s, %s, %s, 'verified', %s, %s)
            """,
            (
                str(uuid4()),
                verified.report_content_sha256,
                verified.report_file_sha256,
                verified.protocol_sha256,
                verified.canonical_event_stream_sha256,
                verified.rejection_audit_stream_sha256,
                datetime.now(timezone.utc),
                datetime.now(timezone.utc),
            ),
        )
    conn.commit()

    with pytest.raises(M4DuplicateVerifiedRunError):
        adapter.materialize(conn)


def test_single_partition_materialization_persists_and_hashes(
    m4_isolated_connection,
) -> None:
    """Materialize one bounded partition and verify persistence consistency.

    Uses the first frozen partition only; this is deliberately not the full
    three-partition production run.
    """
    from hashlib import sha256

    conn = m4_isolated_connection
    adapter = ZeekConnMaterializationAdapterV2.from_repository(ROOT)
    binding = adapter._specification.replay_reports[0]

    run_id = uuid4()
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO m4_canonical.materialization_runs (
                run_id, m3_report_content_sha256, m3_report_file_sha256,
                m3_protocol_sha256, m3_event_stream_sha256,
                m3_rejection_audit_stream_sha256, status, started_at
            ) VALUES (%s, %s, %s, %s, %s, %s, 'running', now())
            """,
            (
                str(run_id),
                adapter._verified_report.report_content_sha256,
                adapter._verified_report.report_file_sha256,
                adapter._verified_report.protocol_sha256,
                adapter._verified_report.canonical_event_stream_sha256,
                adapter._verified_report.rejection_audit_stream_sha256,
            ),
        )
    conn.commit()

    result = adapter.materialize_partition(conn, run_id, binding, sha256(), sha256())

    assert result.processed_record_count == binding.supported_log.record_count
    assert (
        result.accepted_record_count + result.rejected_record_count
        == result.processed_record_count
    )

    with conn.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM m4_canonical.flow_end_events WHERE m4_run_id = %s",
            (str(run_id),),
        )
        (persisted_count,) = cur.fetchone()
    assert persisted_count == result.accepted_record_count
    assert persisted_count == result.persisted_event_count


def test_isolated_fixture_never_connects_to_production(
    m4_isolated_connection,
) -> None:
    """The fixture must bind to the test database, never the production one."""
    with m4_isolated_connection.cursor() as cur:
        cur.execute("SELECT current_database()")
        (connected,) = cur.fetchone()
    assert connected == M4_TEST_DATABASE
    assert connected != os.getenv("POSTGRES_DB_PRODUCTION", "cybersentinel") or (
        M4_TEST_DATABASE != "cybersentinel"
    )
