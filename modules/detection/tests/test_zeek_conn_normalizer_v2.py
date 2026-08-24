"""Tests for the concrete v2 conn.log normalizer (StrictZeekConnFlowEndNormalizerV2)."""
from __future__ import annotations

from decimal import Decimal
from pathlib import Path
from uuid import UUID

import pytest

from modules.detection.src.ingestion.zeek_json_v2 import (
    StrictZeekJsonLineParserV2,
    ZeekRecordRejectionV2,
)
from modules.detection.src.lineage.zeek_normalization_v2 import (
    load_and_bind_zeek_normalization_specification_v2,
    load_zeek_normalization_specification_v2,
)
from modules.detection.src.normalization.zeek_conn_v2 import (
    StrictZeekConnFlowEndNormalizerV2,
    ZeekSourceBindingErrorV2,
)
from modules.detection.src.schemas.events_v2 import FlowEndV2
from modules.detection.src.schemas.exact_time_v2 import canonical_seconds
from modules.detection.src.schemas.zeek_normalization import ZeekSourceCoordinate
from modules.detection.src.schemas.zeek_normalization_v2 import (
    ZeekNormalizationContextV2,
)

ROOT = Path(__file__).resolve().parents[3]
SPEC_PATH = ROOT / "datasets/manifests/cicids2017_zeek_normalization_v2.yaml"
AVAILABLE = canonical_seconds(Decimal("1700000000"))
INGESTED = canonical_seconds(Decimal("1700000001"))


@pytest.fixture(scope="module")
def specification():
    return load_zeek_normalization_specification_v2(SPEC_PATH)


@pytest.fixture(scope="module")
def normalizer(specification):
    return StrictZeekConnFlowEndNormalizerV2(specification)


@pytest.fixture(scope="module")
def bound():
    return load_and_bind_zeek_normalization_specification_v2(ROOT)


def _source(specification, *, line_number: int = 42) -> ZeekSourceCoordinate:
    binding = specification.replay_reports[0]
    return ZeekSourceCoordinate(
        output_partition=binding.output_partition,
        replay_report_content_sha256=binding.report_content_sha256,
        log_name="conn.log",
        source_log_sha256=binding.supported_log.sha256,
        reported_record_count=binding.supported_log.record_count,
        physical_line_number=line_number,
    )


def _context(specification, *, line_number: int = 42, bound=None):
    return ZeekNormalizationContextV2(
        protocol_sha256=(bound or specification).content_sha256()
        if not hasattr(bound, "specification_sha256")
        else bound.specification_sha256
        if bound
        else specification.content_sha256(),
        source=_source(specification, line_number=line_number),
        record_available_time=AVAILABLE,
        ingested_at=INGESTED,
    )


def _valid_record() -> dict:
    return {
        "ts": Decimal("1499169223.751094"),
        "uid": "CJioLj2aEkGc9R3T0b",
        "id.orig_h": "192.0.2.1",
        "id.orig_p": 5353,
        "id.resp_h": "198.51.100.2",
        "id.resp_p": 53,
        "proto": "udp",
        "service": "dns",
        "duration": Decimal("1.000001"),
        "orig_bytes": 74,
        "resp_bytes": 10,
        "conn_state": "SF",
        "orig_pkts": 2,
        "resp_pkts": 1,
    }


def test_normalizer_produces_flow_end_v2_with_exact_time(
    specification, normalizer
) -> None:
    ctx = _context(specification)
    event = normalizer.normalize_conn(_valid_record(), ctx)
    assert isinstance(event, FlowEndV2)
    assert event.event_start_time == "1499169223.7510940000000000000000"
    assert event.event_duration == "1.0000010000000000000000"
    assert event.event_end_time == "1499169224.7510950000000000000000"
    assert event.transport == "udp"
    assert event.service == "dns"
    assert event.connection_state == "SF"
    assert event.provenance.sensor_id == "zeek"
    assert event.provenance.normalizer_version == "2.0.0"
    assert event.provenance.model_release_id is None
    assert event.schema_version == "2.0.0"


def test_normalizer_event_id_is_deterministic(specification, normalizer) -> None:
    ctx = _context(specification)
    e1 = normalizer.normalize_conn(_valid_record(), ctx)
    e2 = normalizer.normalize_conn(_valid_record(), ctx)
    assert e1.provenance.event_id == e2.provenance.event_id
    assert isinstance(e1.provenance.event_id, UUID)


def test_normalizer_rejects_missing_required_field(
    specification, normalizer
) -> None:
    record = _valid_record()
    del record["ts"]
    with pytest.raises(ZeekRecordRejectionV2) as captured:
        normalizer.normalize_conn(record, _context(specification))
    assert captured.value.reason == "missing_required_field"
    assert "ts" in captured.value.fields


def test_normalizer_rejects_null_required_field(
    specification, normalizer
) -> None:
    record = _valid_record()
    record["duration"] = None
    with pytest.raises(ZeekRecordRejectionV2) as captured:
        normalizer.normalize_conn(record, _context(specification))
    assert captured.value.reason == "null_required_field"


def test_normalizer_rejects_unknown_field(specification, normalizer) -> None:
    record = _valid_record()
    record["unknown_field"] = 42
    with pytest.raises(ZeekRecordRejectionV2) as captured:
        normalizer.normalize_conn(record, _context(specification))
    assert captured.value.reason == "unknown_field"
    assert "unknown_field" in captured.value.fields


def test_normalizer_rejects_unsupported_transport(
    specification, normalizer
) -> None:
    record = _valid_record()
    record["proto"] = "icmp"
    with pytest.raises(ZeekRecordRejectionV2) as captured:
        normalizer.normalize_conn(record, _context(specification))
    assert captured.value.reason == "unsupported_transport"


def test_normalizer_rejects_comma_service(specification, normalizer) -> None:
    record = _valid_record()
    record["service"] = "http,ssl"
    with pytest.raises(ZeekRecordRejectionV2) as captured:
        normalizer.normalize_conn(record, _context(specification))
    assert captured.value.reason == "unsupported_service_cardinality"


def test_normalizer_rejects_excess_precision(specification, normalizer) -> None:
    record = _valid_record()
    # 23 fractional digits → exceeds scale 22
    record["duration"] = Decimal("0.00000000000000000000001")
    with pytest.raises(ZeekRecordRejectionV2) as captured:
        normalizer.normalize_conn(record, _context(specification))
    assert captured.value.reason == "decimal38_22_range_or_scale"


def test_normalizer_rejects_negative_duration(specification, normalizer) -> None:
    record = _valid_record()
    record["duration"] = Decimal("-1")
    with pytest.raises(ZeekRecordRejectionV2) as captured:
        normalizer.normalize_conn(record, _context(specification))
    assert captured.value.reason == "decimal38_22_range_or_scale"


def test_normalizer_accepts_ignored_fields(specification, normalizer) -> None:
    record = _valid_record()
    record["history"] = "ShAdDfF"
    record["local_orig"] = True
    record["missed_bytes"] = 0
    event = normalizer.normalize_conn(record, _context(specification))
    assert isinstance(event, FlowEndV2)


def test_normalizer_maps_absent_service_to_null(
    specification, normalizer
) -> None:
    record = _valid_record()
    del record["service"]
    event = normalizer.normalize_conn(record, _context(specification))
    assert event.service is None


def test_normalizer_rejects_source_binding_mismatch(
    specification, normalizer
) -> None:
    source = ZeekSourceCoordinate(
        output_partition="fake_partition",
        replay_report_content_sha256="0" * 64,
        log_name="conn.log",
        source_log_sha256="0" * 64,
        reported_record_count=1,
        physical_line_number=1,
    )
    ctx = ZeekNormalizationContextV2(
        protocol_sha256=specification.content_sha256(),
        source=source,
        record_available_time=AVAILABLE,
        ingested_at=INGESTED,
    )
    with pytest.raises(ZeekSourceBindingErrorV2):
        normalizer.normalize_conn(_valid_record(), ctx)


def test_normalizer_accepts_real_first_line(specification, normalizer) -> None:
    """Parse and normalize the real first line of the frozen Tuesday conn.log."""
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
    ctx = ZeekNormalizationContextV2(
        protocol_sha256=specification.content_sha256(),
        source=source,
        record_available_time=AVAILABLE,
        ingested_at=INGESTED,
    )
    record = StrictZeekJsonLineParserV2().parse_line(first_line, source)
    event = normalizer.normalize_conn(record, ctx)
    assert isinstance(event, FlowEndV2)
    assert event.event_start_time.startswith("1499169")
