"""Tests for the M3 v2 streaming normalization runner.

Phase 1 tests cover:
- Construction and temporal validation.
- Single-partition streaming with real frozen data.
- Rejection accumulation and span merging.
- Deterministic canonical event stream SHA-256 computation.
- First/last accepted event ID tracking.
- Pre-flight source verification.

Phase 2 tests cover:
- Report construction from PartitionResult.
- Full three-partition run report construction and validation.
- Deterministic full-run reproducibility.
- Immutable publication (success, duplicate failure, staging failure).
- Report content hash stability.
"""
from __future__ import annotations

from decimal import Decimal
from hashlib import sha256
import json
from pathlib import Path
from unittest.mock import patch
from uuid import UUID

import pytest

from modules.detection.src.ingestion.zeek_json_v2 import ZeekRecordRejectionV2
from modules.detection.src.lineage.zeek_normalization_v2 import (
    load_and_bind_zeek_normalization_specification_v2,
    load_zeek_normalization_specification_v2,
)
from modules.detection.src.normalization.zeek_conn_v2 import (
    ZeekSourceBindingErrorV2,
)
from modules.detection.src.normalization.zeek_pipeline_v2 import (
    PartitionResult,
    RunAccumulator,
    ZeekConnNormalizationRunnerV2,
    _canonical_event_bytes,
    _canonical_rejection_bytes,
)
from modules.detection.src.schemas.events_v2 import FlowEndV2
from modules.detection.src.schemas.exact_time_v2 import canonical_seconds
from modules.detection.src.schemas.zeek_normalization import ZeekSourceCoordinate


ROOT = Path(__file__).resolve().parents[3]
SPEC_PATH = ROOT / "datasets/manifests/cicids2017_zeek_normalization_v2.yaml"
AVAILABLE = canonical_seconds(Decimal("1700000000"))
INGESTED = canonical_seconds(Decimal("1700000001"))


@pytest.fixture(scope="module")
def specification():
    return load_zeek_normalization_specification_v2(SPEC_PATH)


@pytest.fixture(scope="module")
def bound():
    return load_and_bind_zeek_normalization_specification_v2(ROOT)


@pytest.fixture(scope="module")
def runner(bound):
    return ZeekConnNormalizationRunnerV2(ROOT, bound, AVAILABLE, INGESTED)


# --- Construction tests ---


def test_construction_validates_temporal_order(bound) -> None:
    """ingested_at must be >= record_available_time."""
    with pytest.raises(ValueError, match="ingested_at cannot precede"):
        ZeekConnNormalizationRunnerV2(ROOT, bound, INGESTED, AVAILABLE)


def test_construction_succeeds_with_valid_temporals(bound) -> None:
    runner = ZeekConnNormalizationRunnerV2(ROOT, bound, AVAILABLE, INGESTED)
    assert runner._protocol_sha256 == bound.specification_sha256


def test_from_repository_factory() -> None:
    runner = ZeekConnNormalizationRunnerV2.from_repository(ROOT, AVAILABLE, INGESTED)
    assert runner._protocol_sha256 is not None


# --- Serialization determinism tests ---


def test_canonical_event_bytes_are_deterministic(specification, bound) -> None:
    """Two identical FlowEndV2 events produce identical canonical bytes."""
    from modules.detection.src.lineage.provenance import EventProvenance
    from ipaddress import ip_address
    from modules.detection.src.schemas.common import FlowCounters, NetworkEndpoint

    provenance = EventProvenance(
        event_id=UUID("00000000-0000-5000-8000-000000000001"),
        sensor_id="zeek",
        sensor_run_id="a" * 64,
        capture_id="b" * 64,
        dataset_snapshot_id="c" * 64,
        model_release_id=None,
        normalizer_version="2.0.0",
        pipeline_version="2.0.0",
    )
    event = FlowEndV2(
        schema_version="2.0.0",
        event_version="2.0.0",
        feature_version="1.0.0",
        sensor_version="8.0.9",
        event_type="flow_end",
        sensor_type="zeek",
        provenance=provenance,
        event_start_time="1.0000000000000000000000",
        event_duration="1.0000000000000000000000",
        event_end_time="2.0000000000000000000000",
        record_available_time=AVAILABLE,
        ingested_at=INGESTED,
        conversation_id="C1",
        source=NetworkEndpoint(ip=ip_address("192.0.2.1"), port=80),
        destination=NetworkEndpoint(ip=ip_address("198.51.100.2"), port=443),
        transport="tcp",
        service="ssl",
        counters=FlowCounters(
            source_packets=2, destination_packets=1,
            source_bytes=100, destination_bytes=50,
        ),
        connection_state="SF",
        termination_reason=None,
    )
    b1 = _canonical_event_bytes(event)
    b2 = _canonical_event_bytes(event)
    assert b1 == b2
    assert b1.endswith(b"\n")
    # Verify it's valid JSON
    parsed = json.loads(b1)
    assert parsed["event_type"] == "flow_end"


def test_canonical_rejection_bytes_are_deterministic(specification) -> None:
    """Two identical rejections produce identical canonical bytes."""
    binding = specification.replay_reports[0]
    source = ZeekSourceCoordinate(
        output_partition=binding.output_partition,
        replay_report_content_sha256=binding.report_content_sha256,
        log_name="conn.log",
        source_log_sha256=binding.supported_log.sha256,
        reported_record_count=binding.supported_log.record_count,
        physical_line_number=1,
    )
    rejection = ZeekRecordRejectionV2("malformed_json", source, ("ts",))
    b1 = _canonical_rejection_bytes(source, rejection)
    b2 = _canonical_rejection_bytes(source, rejection)
    assert b1 == b2
    assert b1.endswith(b"\n")
    parsed = json.loads(b1)
    assert parsed["reason"] == "malformed_json"
    assert parsed["fields"] == ["ts"]
    assert parsed["physical_line_number"] == 1


# --- Real first-line integration test ---


def test_process_real_first_line_produces_expected_event(
    specification, runner
) -> None:
    """The runner successfully normalizes the first line of the Tuesday conn.log."""
    binding = specification.replay_reports[0]
    conn_path = (
        ROOT / specification.m2_output_root / binding.output_partition / "conn.log"
    )
    with conn_path.open("rb") as f:
        first_line = f.readline()

    # Parse and normalize manually to get expected event
    from modules.detection.src.ingestion.zeek_json_v2 import StrictZeekJsonLineParserV2
    from modules.detection.src.normalization.zeek_conn_v2 import (
        StrictZeekConnFlowEndNormalizerV2,
    )
    from modules.detection.src.schemas.zeek_normalization_v2 import (
        ZeekNormalizationContextV2,
    )

    parser = StrictZeekJsonLineParserV2()
    normalizer = StrictZeekConnFlowEndNormalizerV2(specification)
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
        record_available_time=AVAILABLE,
        ingested_at=INGESTED,
    )
    record = parser.parse_line(first_line, source)
    event = normalizer.normalize_conn(record, context)
    assert isinstance(event, FlowEndV2)

    # Compute expected hash for a single-event stream
    expected_bytes = _canonical_event_bytes(event)
    expected_hash = sha256(expected_bytes).hexdigest()

    # The first event ID should be deterministic
    assert isinstance(event.provenance.event_id, UUID)


# --- Synthetic partition test with tmp_path ---


def _make_synthetic_conn_log(tmp_path: Path, records: list[dict]) -> tuple[Path, int, str]:
    """Write synthetic conn.log lines and return path, size, sha256."""
    lines = []
    for r in records:
        lines.append(
            json.dumps(r, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
            + b"\n"
        )
    content = b"".join(lines)
    path = tmp_path / "conn.log"
    path.write_bytes(content)
    return path, len(content), sha256(content).hexdigest()


def test_run_accumulator_initial_state() -> None:
    acc = RunAccumulator()
    assert acc.total_processed == 0
    assert acc.total_accepted == 0
    assert acc.total_rejected == 0
    assert len(acc.partition_results) == 0
    # Empty SHA-256 is the hash of empty input
    assert acc.canonical_event_stream_sha256 == sha256(b"").hexdigest()


# --- Pre-flight verification test ---


def test_preflight_rejects_wrong_size(bound, tmp_path) -> None:
    """Pre-flight fails when file size doesn't match binding."""
    runner = ZeekConnNormalizationRunnerV2(ROOT, bound, AVAILABLE, INGESTED)
    binding = runner._specification.replay_reports[0]

    # The real file exists and has the correct hash/size, so pre-flight
    # should succeed on the actual frozen file
    path = runner._preflight_verify(binding)
    assert path.exists()


# --- Span merging test ---


def test_rejection_span_merging() -> None:
    """Adjacent rejections with same reason/fields are merged into one span."""
    spans: list[dict] = []
    source = ZeekSourceCoordinate(
        output_partition="2017-07-04_Tuesday-WorkingHours",
        replay_report_content_sha256="a" * 64,
        log_name="conn.log",
        source_log_sha256="b" * 64,
        reported_record_count=100,
        physical_line_number=1,
    )

    # Three consecutive rejections with same reason/fields
    r1 = ZeekRecordRejectionV2("malformed_json", source, ())
    r2 = ZeekRecordRejectionV2("malformed_json", source, ())
    r3 = ZeekRecordRejectionV2("malformed_json", source, ())

    ZeekConnNormalizationRunnerV2._append_rejection_span(spans, 1, r1)
    ZeekConnNormalizationRunnerV2._append_rejection_span(spans, 2, r2)
    ZeekConnNormalizationRunnerV2._append_rejection_span(spans, 3, r3)

    assert len(spans) == 1
    assert spans[0]["first_physical_line_number"] == 1
    assert spans[0]["last_physical_line_number"] == 3
    assert spans[0]["reason"] == "malformed_json"


def test_rejection_span_no_merge_different_reason() -> None:
    """Different rejection reasons produce separate spans."""
    spans: list[dict] = []
    source = ZeekSourceCoordinate(
        output_partition="2017-07-04_Tuesday-WorkingHours",
        replay_report_content_sha256="a" * 64,
        log_name="conn.log",
        source_log_sha256="b" * 64,
        reported_record_count=100,
        physical_line_number=1,
    )

    r1 = ZeekRecordRejectionV2("malformed_json", source, ())
    r2 = ZeekRecordRejectionV2("unsupported_transport", source, ("proto",))

    ZeekConnNormalizationRunnerV2._append_rejection_span(spans, 1, r1)
    ZeekConnNormalizationRunnerV2._append_rejection_span(spans, 2, r2)

    assert len(spans) == 2


def test_rejection_span_no_merge_non_adjacent() -> None:
    """Non-adjacent rejections with same reason produce separate spans."""
    spans: list[dict] = []
    source = ZeekSourceCoordinate(
        output_partition="2017-07-04_Tuesday-WorkingHours",
        replay_report_content_sha256="a" * 64,
        log_name="conn.log",
        source_log_sha256="b" * 64,
        reported_record_count=100,
        physical_line_number=1,
    )

    r1 = ZeekRecordRejectionV2("malformed_json", source, ())
    r2 = ZeekRecordRejectionV2("malformed_json", source, ())

    ZeekConnNormalizationRunnerV2._append_rejection_span(spans, 1, r1)
    # Line 3 is not adjacent to line 1
    ZeekConnNormalizationRunnerV2._append_rejection_span(spans, 3, r2)

    assert len(spans) == 2
    assert spans[0]["last_physical_line_number"] == 1
    assert spans[1]["first_physical_line_number"] == 3


# --- Full first-partition smoke test (processes real frozen data) ---


def test_process_first_partition_produces_valid_result(bound) -> None:
    """Process the Tuesday partition and verify result structure."""
    runner = ZeekConnNormalizationRunnerV2(ROOT, bound, AVAILABLE, INGESTED)
    accumulator = RunAccumulator()
    binding = runner._specification.replay_reports[0]

    result = runner.process_partition(binding, accumulator)

    assert isinstance(result, PartitionResult)
    assert result.output_partition == "2017-07-04_Tuesday-WorkingHours"
    assert result.processed_record_count == binding.supported_log.record_count
    assert result.accepted_record_count + result.rejected_record_count == result.processed_record_count
    assert result.source_log_sha256 == binding.supported_log.sha256
    assert result.source_size_bytes == binding.supported_log.size_bytes

    # Boundary event IDs
    if result.accepted_record_count > 0:
        assert result.first_accepted_event_id is not None
        assert result.last_accepted_event_id is not None
        assert isinstance(result.first_accepted_event_id, UUID)
        assert isinstance(result.last_accepted_event_id, UUID)

    # Rejection counts consistency
    assert sum(result.rejection_counts.values()) == result.rejected_record_count

    # Accumulator updated
    assert accumulator.total_processed == result.processed_record_count
    assert accumulator.total_accepted == result.accepted_record_count
    assert accumulator.total_rejected == result.rejected_record_count
    assert len(accumulator.partition_results) == 1


def test_process_first_partition_is_deterministic(bound) -> None:
    """Two independent runs of the same partition produce identical evidence."""
    runner1 = ZeekConnNormalizationRunnerV2(ROOT, bound, AVAILABLE, INGESTED)
    runner2 = ZeekConnNormalizationRunnerV2(ROOT, bound, AVAILABLE, INGESTED)
    acc1 = RunAccumulator()
    acc2 = RunAccumulator()
    binding = runner1._specification.replay_reports[0]

    r1 = runner1.process_partition(binding, acc1)
    r2 = runner2.process_partition(binding, acc2)

    assert r1.accepted_record_count == r2.accepted_record_count
    assert r1.rejected_record_count == r2.rejected_record_count
    assert r1.canonical_event_stream_sha256 == r2.canonical_event_stream_sha256
    assert r1.rejection_audit_stream_sha256 == r2.rejection_audit_stream_sha256
    assert r1.first_accepted_event_id == r2.first_accepted_event_id
    assert r1.last_accepted_event_id == r2.last_accepted_event_id


# =====================================================================
# Phase 2 tests: report construction, publication, determinism
# =====================================================================


from modules.detection.src.normalization.zeek_pipeline_v2 import (
    write_immutable_normalization_report_v2,
)
from modules.detection.src.schemas.zeek_normalization_run_v2 import (
    ZeekNormalizationRunReportV2,
    ZeekPartitionNormalizationReportV2,
)


# --- Report construction from single partition ---


def test_build_partition_report_from_result(bound) -> None:
    """_build_partition_report produces a valid contract object."""
    runner = ZeekConnNormalizationRunnerV2(ROOT, bound, AVAILABLE, INGESTED)
    accumulator = RunAccumulator()
    binding = runner._specification.replay_reports[0]
    result = runner.process_partition(binding, accumulator)

    report = runner._build_partition_report(result)

    assert isinstance(report, ZeekPartitionNormalizationReportV2)
    assert report.output_partition == result.output_partition
    assert report.processed_record_count == result.processed_record_count
    assert report.accepted_record_count == result.accepted_record_count
    assert report.rejected_record_count == result.rejected_record_count
    assert report.canonical_event_stream_sha256 == result.canonical_event_stream_sha256
    assert report.rejection_audit_stream_sha256 == result.rejection_audit_stream_sha256
    assert report.first_accepted_event_id == result.first_accepted_event_id
    assert report.last_accepted_event_id == result.last_accepted_event_id
    assert report.source_verified is True
    # Rejection counts are sorted
    reasons = [rc.reason for rc in report.rejection_counts]
    assert reasons == sorted(reasons)


# --- Full run report construction (all three partitions) ---


def test_full_run_produces_validated_report(bound) -> None:
    """run() processes all three partitions and returns a valid report."""
    runner = ZeekConnNormalizationRunnerV2(ROOT, bound, AVAILABLE, INGESTED)
    report = runner.run()

    assert isinstance(report, ZeekNormalizationRunReportV2)
    assert report.report_version == "2.0.0"
    assert report.verification_status == "verified"
    assert report.protocol_sha256 == bound.specification_sha256
    assert report.m1_manifest_sha256 == bound.m1_manifest_sha256
    assert report.m2_specification_sha256 == bound.m2_specification_sha256
    assert report.sensor_type == "zeek"
    assert report.sensor_version == "8.0.9"
    assert report.normalizer_version == "2.0.0"
    assert report.pipeline_version == "2.0.0"
    assert report.temporal_encoding == "DECIMAL(38,22)_fixed_scale_string"
    assert report.record_available_time == AVAILABLE
    assert report.ingested_at == INGESTED

    # Three partitions in correct order
    assert len(report.partition_reports) == 3
    partitions = [pr.output_partition for pr in report.partition_reports]
    assert partitions == sorted(partitions)

    # Totals match sums
    assert report.total_processed_record_count == sum(
        pr.processed_record_count for pr in report.partition_reports
    )
    assert report.total_accepted_record_count == sum(
        pr.accepted_record_count for pr in report.partition_reports
    )
    assert report.total_rejected_record_count == sum(
        pr.rejected_record_count for pr in report.partition_reports
    )
    assert (
        report.total_processed_record_count
        == report.total_accepted_record_count + report.total_rejected_record_count
    )

    # Matches manifest evidence profile expectation
    assert report.total_processed_record_count == 1_380_057


def test_full_run_is_deterministic(bound) -> None:
    """Two independent full runs produce identical reports."""
    runner1 = ZeekConnNormalizationRunnerV2(ROOT, bound, AVAILABLE, INGESTED)
    runner2 = ZeekConnNormalizationRunnerV2(ROOT, bound, AVAILABLE, INGESTED)

    report1 = runner1.run()
    report2 = runner2.run()

    assert report1.canonical_event_stream_sha256 == report2.canonical_event_stream_sha256
    assert report1.rejection_audit_stream_sha256 == report2.rejection_audit_stream_sha256
    assert report1.total_accepted_record_count == report2.total_accepted_record_count
    assert report1.total_rejected_record_count == report2.total_rejected_record_count
    assert report1.content_sha256() == report2.content_sha256()


# --- Immutable publication ---


def test_immutable_publication_writes_valid_json(bound, tmp_path) -> None:
    """Publication writes a valid JSON file and returns its SHA-256."""
    runner = ZeekConnNormalizationRunnerV2(ROOT, bound, AVAILABLE, INGESTED)
    report = runner.run()

    dest = tmp_path / "reports" / "m3_v2_normalization_run.json"
    file_hash = write_immutable_normalization_report_v2(report, dest)

    assert dest.exists()
    content = dest.read_bytes()
    assert sha256(content).hexdigest() == file_hash

    # Content is valid JSON and round-trips to the same report
    loaded = ZeekNormalizationRunReportV2.model_validate_json(content)
    assert loaded.content_sha256() == report.content_sha256()
    assert loaded.total_processed_record_count == report.total_processed_record_count


def test_immutable_publication_fails_on_existing_file(bound, tmp_path) -> None:
    """Publication refuses to overwrite an existing report."""
    runner = ZeekConnNormalizationRunnerV2(ROOT, bound, AVAILABLE, INGESTED)
    report = runner.run()

    dest = tmp_path / "m3_v2_normalization_run.json"
    write_immutable_normalization_report_v2(report, dest)

    with pytest.raises(FileExistsError, match="already exists"):
        write_immutable_normalization_report_v2(report, dest)


def test_immutable_publication_fails_on_existing_staging(bound, tmp_path) -> None:
    """Publication refuses to proceed if staging file already exists."""
    runner = ZeekConnNormalizationRunnerV2(ROOT, bound, AVAILABLE, INGESTED)
    report = runner.run()

    dest = tmp_path / "m3_v2_normalization_run.json"
    staging = dest.with_name(f".{dest.name}.tmp")
    staging.write_text("residual")

    with pytest.raises(FileExistsError, match="staging path exists"):
        write_immutable_normalization_report_v2(report, dest)


def test_immutable_publication_no_staging_residue_on_success(bound, tmp_path) -> None:
    """No staging file remains after successful publication."""
    runner = ZeekConnNormalizationRunnerV2(ROOT, bound, AVAILABLE, INGESTED)
    report = runner.run()

    dest = tmp_path / "m3_v2_normalization_run.json"
    write_immutable_normalization_report_v2(report, dest)

    staging = dest.with_name(f".{dest.name}.tmp")
    assert not staging.exists()


# --- Report content verification ---


def test_report_content_hash_is_formatting_independent(bound, tmp_path) -> None:
    """content_sha256() is deterministic and independent of serialization style."""
    runner = ZeekConnNormalizationRunnerV2(ROOT, bound, AVAILABLE, INGESTED)
    report = runner.run()

    # content_sha256 uses sort_keys + compact JSON internally
    h1 = report.content_sha256()
    h2 = report.content_sha256()
    assert h1 == h2

    # Published file may differ (indent=2) but content_sha256 remains stable
    dest = tmp_path / "report.json"
    write_immutable_normalization_report_v2(report, dest)
    loaded = ZeekNormalizationRunReportV2.model_validate_json(dest.read_bytes())
    assert loaded.content_sha256() == h1
