"""Regression coverage for the existing additive M3 v2 contracts.

These tests cover protocol/schema/parser/lineage consistency only. They do not
provide or exercise a v2 normalizer, runner, persisted event stream, or Step 3.
"""
from __future__ import annotations

from decimal import Decimal, getcontext, localcontext
import os
from pathlib import Path
import subprocess
import sys
from uuid import UUID

from ipaddress import ip_address
from pydantic import ValidationError
import pytest
import yaml

import modules.detection.src.ingestion as ingestion
import modules.detection.src.lineage as lineage
import modules.detection.src.normalization as normalization
import modules.detection.src.schemas as schemas
from modules.detection.src.ingestion.zeek_json_v2 import (
    StrictZeekJsonLineParserV2,
    ZeekRecordRejectionV2,
)
from modules.detection.src.lineage.provenance import EventProvenance
from modules.detection.src.lineage.zeek_normalization_v2 import (
    load_and_bind_zeek_normalization_specification_v2,
    load_zeek_normalization_specification_v2,
)
from modules.detection.src.schemas.events_v2 import FlowEndV2
from modules.detection.src.schemas.exact_time_v2 import (
    ExactDecimalConversionError,
    canonical_seconds,
    canonical_seconds_from_unscaled,
    decimal_to_unscaled,
    unscaled_from_canonical,
)
from modules.detection.src.schemas.zeek_normalization import ZeekSourceCoordinate
from modules.detection.src.schemas.zeek_normalization_run_v2 import (
    ZeekNormalizationRunReportV2,
    ZeekPartitionNormalizationReportV2,
    ZeekRejectionCountV2,
    ZeekRejectionSpanV2,
)


ROOT = Path(__file__).resolve().parents[3]
SPEC_PATH = ROOT / "datasets/manifests/cicids2017_zeek_normalization_v2.yaml"
PROTOCOL_SHA256 = "5286ddde937ad132afdeb8814e0e0af01745afbb7d1d446ae8860b7701fea210"
PRE_REPAIR_PROTOCOL_SHA256 = (
    "617298f5dfa0940cbf1f0c1d1a5730e8ee83c43160c29b4b2bfb9e6fc56914d4"
)
V1_PROTOCOL_SHA256 = "99ab724a3d245a352e888e2f4771b5a354b5855180af4a72c36980c9296897d4"
M1_SHA256 = "feab8d4fbd8454cd12723368704e1e7311853a4316efec7f94bf11726ebb984e"
M2_SHA256 = "e52c183a315c1ac38cbf1e64155489f5f041e95aa5d2e5cbb82e31f03ac4c455"
ZERO = "0.0000000000000000000000"
ONE = "1.0000000000000000000000"
TWO = "2.0000000000000000000000"
THREE = "3.0000000000000000000000"


@pytest.fixture(scope="module")
def specification():
    return load_zeek_normalization_specification_v2(SPEC_PATH)


def _source(specification, *, line_number: int = 1) -> ZeekSourceCoordinate:
    binding = specification.replay_reports[0]
    return ZeekSourceCoordinate(
        output_partition=binding.output_partition,
        replay_report_content_sha256=binding.report_content_sha256,
        log_name="conn.log",
        source_log_sha256=binding.supported_log.sha256,
        reported_record_count=binding.supported_log.record_count,
        physical_line_number=line_number,
    )


def _flow_payload() -> dict[str, object]:
    return {
        "schema_version": "2.0.0",
        "event_version": "2.0.0",
        "feature_version": "1.0.0",
        "sensor_version": "8.0.9",
        "event_type": "flow_end",
        "sensor_type": "zeek",
        "provenance": EventProvenance(
            event_id=UUID("00000000-0000-5000-8000-000000000001"),
            sensor_id="zeek",
            sensor_run_id="8d7b3e8d3090b93f90df50e77d48f1a33f587dca2982a3d5cdf17623c01c1314",
            capture_id="080c2250154c5a174c03660ed0f75a3858d41a27511ba716e780d7bcb1ec4c57",
            dataset_snapshot_id=M1_SHA256,
            model_release_id=None,
            normalizer_version="2.0.0",
            pipeline_version="2.0.0",
        ),
        "event_start_time": ONE,
        "event_duration": ONE,
        "event_end_time": TWO,
        "record_available_time": TWO,
        "ingested_at": THREE,
        "conversation_id": "CZeekV2",
        "source": {"ip": ip_address("192.0.2.1"), "port": 12345},
        "destination": {"ip": ip_address("198.51.100.2"), "port": 443},
        "transport": "tcp",
        "service": "ssl",
        "counters": {
            "source_packets": 2,
            "destination_packets": 1,
            "source_bytes": 74,
            "destination_bytes": 10,
        },
        "connection_state": "SF",
        "termination_reason": None,
    }


def _partition(name: str) -> ZeekPartitionNormalizationReportV2:
    return ZeekPartitionNormalizationReportV2(
        output_partition=name,
        replay_report_content_sha256="1" * 64,
        input_capture_sha256="2" * 64,
        log_name="conn.log",
        source_log_sha256="3" * 64,
        source_size_bytes=10,
        reported_record_count=1,
        source_verified=True,
        processed_record_count=1,
        accepted_record_count=0,
        rejected_record_count=1,
        rejection_counts=(ZeekRejectionCountV2(reason="malformed_json", count=1),),
        rejection_spans=(
            ZeekRejectionSpanV2(
                first_physical_line_number=1,
                last_physical_line_number=1,
                reason="malformed_json",
                fields=(),
            ),
        ),
        canonical_event_stream_sha256="4" * 64,
        rejection_audit_stream_sha256="5" * 64,
        first_accepted_event_id=None,
        last_accepted_event_id=None,
    )


def _run_payload() -> dict[str, object]:
    partitions = (
        _partition("2017-07-04_Tuesday-WorkingHours"),
        _partition("2017-07-05_Wednesday-workingHours"),
        _partition("2017-07-07_Friday-WorkingHours"),
    )
    return {
        "report_version": "2.0.0",
        "verification_status": "verified",
        "protocol_sha256": PROTOCOL_SHA256,
        "supersedes_protocol_sha256": V1_PROTOCOL_SHA256,
        "m1_manifest_sha256": M1_SHA256,
        "m2_specification_sha256": M2_SHA256,
        "dataset_name": "cicids2017",
        "sensor_type": "zeek",
        "sensor_version": "8.0.9",
        "schema_version": "2.0.0",
        "event_version": "2.0.0",
        "feature_version": "1.0.0",
        "normalizer_version": "2.0.0",
        "pipeline_version": "2.0.0",
        "temporal_encoding": "DECIMAL(38,22)_fixed_scale_string",
        "record_available_time": TWO,
        "ingested_at": THREE,
        "partition_reports": partitions,
        "total_processed_record_count": 3,
        "total_accepted_record_count": 0,
        "total_rejected_record_count": 3,
        "canonical_event_stream_sha256": "6" * 64,
        "rejection_audit_stream_sha256": "7" * 64,
    }


def test_official_v2_protocol_identity_and_lineage_binding(specification) -> None:
    bound = load_and_bind_zeek_normalization_specification_v2(ROOT)
    assert bound.specification == specification
    assert bound.specification_sha256 == PROTOCOL_SHA256
    assert bound.supersedes_protocol_sha256 == V1_PROTOCOL_SHA256
    assert bound.m1_manifest_sha256 == M1_SHA256
    assert bound.m2_specification_sha256 == M2_SHA256
    assert bound.replay_report_count == 3
    assert bound.supported_record_count == 1_380_057
    assert specification.protocol_version == "2.0.0"
    assert specification.boundaries.normalizer_output == (
        "FlowEndV2_or_explicit_rejection"
    )
    assert specification.evidence.expected_accepted_record_count == 1_353_467
    assert specification.evidence.expected_rejected_record_count == 26_590


def test_pre_repair_identity_is_recorded_but_not_current(specification) -> None:
    assert specification.content_sha256() != PRE_REPAIR_PROTOCOL_SHA256
    assert PRE_REPAIR_PROTOCOL_SHA256 == (
        "617298f5dfa0940cbf1f0c1d1a5730e8ee83c43160c29b4b2bfb9e6fc56914d4"
    )


def test_schema_and_lineage_v2_contracts_are_public_but_concrete_runtime_is_private() -> None:
    schema_names = {
        "FlowEndV2",
        "CanonicalNetworkEventV2",
        "ExactDecimalSeconds22",
        "ZeekNormalizationSpecificationV2",
        "ZeekNormalizationRunReportV2",
        "ZeekParserBoundaryPolicyV2",
    }
    lineage_names = {
        "BoundZeekNormalizationSpecificationV2",
        "load_zeek_normalization_specification_v2",
        "load_and_bind_zeek_normalization_specification_v2",
    }
    assert schema_names <= set(schemas.__all__)
    assert lineage_names <= set(lineage.__all__)
    assert all(hasattr(schemas, name) for name in schema_names)
    assert all(hasattr(lineage, name) for name in lineage_names)
    assert not hasattr(ingestion, "StrictZeekJsonLineParserV2")
    assert not hasattr(normalization, "ZeekConnNormalizationRunnerV2")


def test_clean_package_imports_are_order_independent() -> None:
    code = (
        "import modules.detection.src.schemas as s; "
        "import modules.detection.src.schemas.events_v2 as e; "
        "import modules.detection.src.lineage as l; "
        "assert s.FlowEndV2 is e.FlowEndV2; "
        "assert hasattr(l, 'load_and_bind_zeek_normalization_specification_v2')"
    )
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    completed = subprocess.run(
        [sys.executable, "-c", code],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (0, ZERO),
        (1, ONE),
        (Decimal("0.0000000000000000000001"), "0.0000000000000000000001"),
        (Decimal("1499165260.62538"), "1499165260.6253800000000000000000"),
    ],
)
def test_exact_time_canonicalization(value, expected: str) -> None:
    assert canonical_seconds(value) == expected
    assert canonical_seconds_from_unscaled(unscaled_from_canonical(expected)) == expected


@pytest.mark.parametrize(
    "value",
    [
        Decimal("-1"),
        Decimal("0.00000000000000000000001"),
        Decimal("10000000000000000"),
        Decimal("NaN"),
        Decimal("Infinity"),
        1.0,
        True,
    ],
)
def test_exact_time_rejects_noncanonical_values(value) -> None:
    with pytest.raises(ExactDecimalConversionError):
        decimal_to_unscaled(value)


def test_exact_time_is_decimal_context_independent() -> None:
    original = getcontext().prec
    with localcontext() as context:
        context.prec = 2
        assert canonical_seconds(Decimal("1499165260.62538")) == (
            "1499165260.6253800000000000000000"
        )
    assert getcontext().prec == original


def test_v2_parser_preserves_numeric_lexemes(specification) -> None:
    record = StrictZeekJsonLineParserV2().parse_line(
        b'{"ts":1499165260.62538,"duration":1,"uid":"C1"}\r\n',
        _source(specification),
    )
    assert record == {
        "ts": Decimal("1499165260.62538"),
        "duration": 1,
        "uid": "C1",
    }
    assert type(record["duration"]) is int


@pytest.mark.parametrize(
    ("line", "reason", "fields"),
    [
        (b"", "malformed_json", ()),
        (b"{}\n{}\n", "malformed_json", ()),
        (b"[]\n", "non_object_json", ()),
        (b'{"a":1,"a":2}\n', "malformed_json", ("a",)),
        (b'{"a":NaN}\n', "non_finite_number", ()),
    ],
)
def test_v2_parser_rejections_are_explicit_and_coordinate_bound(
    specification, line: bytes, reason: str, fields: tuple[str, ...]
) -> None:
    source = _source(specification)
    with pytest.raises(ZeekRecordRejectionV2) as captured:
        StrictZeekJsonLineParserV2().parse_line(line, source)
    assert captured.value.reason == reason
    assert captured.value.fields == fields
    assert captured.value.source == source


def test_v2_parser_requires_bytes(specification) -> None:
    with pytest.raises(TypeError, match="must be bytes"):
        StrictZeekJsonLineParserV2().parse_line("{}", _source(specification))  # type: ignore[arg-type]


def test_flow_end_v2_enforces_exact_time_versions_and_provenance() -> None:
    event = FlowEndV2(**_flow_payload())
    assert event.event_end_time == TWO
    payload = event.model_dump()
    payload["event_end_time"] = THREE
    with pytest.raises(ValidationError, match="exactly equal"):
        FlowEndV2.model_validate(payload)

    for field, value, message in (
        ("sensor_id", "other", "sensor_id"),
        ("normalizer_version", "1.0.0", "provenance versions"),
        ("pipeline_version", "1.0.0", "provenance versions"),
        ("model_release_id", "model-1", "explicit null"),
    ):
        payload = _flow_payload()
        provenance = payload["provenance"].model_dump()  # type: ignore[union-attr]
        provenance[field] = value
        payload["provenance"] = provenance
        with pytest.raises(ValidationError, match=message):
            FlowEndV2.model_validate(payload)


def test_v2_manifest_rejects_binding_input_tampering(tmp_path: Path) -> None:
    payload = yaml.safe_load(SPEC_PATH.read_text(encoding="utf-8"))
    payload["replay_reports"][0]["input"]["size_bytes"] += 1
    path = tmp_path / "tampered-v2.yaml"
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    with pytest.raises(ValueError, match="input binding mismatch"):
        load_and_bind_zeek_normalization_specification_v2(ROOT, path)


def test_v2_manifest_rejects_duplicate_or_out_of_root_report_paths(
    tmp_path: Path,
) -> None:
    payload = yaml.safe_load(SPEC_PATH.read_text(encoding="utf-8"))
    payload["replay_reports"][1]["report_relative_path"] = payload[
        "replay_reports"
    ][0]["report_relative_path"]
    duplicate = tmp_path / "duplicate-v2.yaml"
    duplicate.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    with pytest.raises(ValidationError, match="paths must be unique"):
        load_zeek_normalization_specification_v2(duplicate)

    payload = yaml.safe_load(SPEC_PATH.read_text(encoding="utf-8"))
    payload["replay_reports"][0]["report_relative_path"] = (
        "artifacts/reports/replay_run.json"
    )
    outside = tmp_path / "outside-v2.yaml"
    outside.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    with pytest.raises(ValidationError, match="below the frozen M2 root"):
        load_zeek_normalization_specification_v2(outside)


def test_v2_run_report_enforces_causal_time_order_and_partition_order() -> None:
    report = ZeekNormalizationRunReportV2(**_run_payload())
    assert report.total_processed_record_count == 3

    payload = report.model_dump()
    payload["record_available_time"] = THREE
    payload["ingested_at"] = TWO
    with pytest.raises(ValidationError, match="precedes record_available_time"):
        ZeekNormalizationRunReportV2.model_validate(payload)

    payload = report.model_dump()
    payload["partition_reports"] = tuple(reversed(payload["partition_reports"]))
    with pytest.raises(ValidationError, match="unique and ordered"):
        ZeekNormalizationRunReportV2.model_validate(payload)


def test_v2_run_report_rejection_spans_cover_counts() -> None:
    payload = _partition("2017-07-04_Tuesday-WorkingHours").model_dump()
    payload["rejection_counts"] = (
        {"reason": "malformed_json", "count": 2},
    )
    with pytest.raises(ValidationError, match="counts do not cover"):
        ZeekPartitionNormalizationReportV2.model_validate(payload)


def test_v2_models_are_strict_and_immutable(specification) -> None:
    payload = specification.model_dump(mode="json")
    payload["unexpected"] = True
    with pytest.raises(ValidationError, match="Extra inputs"):
        schemas.ZeekNormalizationSpecificationV2.model_validate(payload)
    with pytest.raises(ValidationError, match="frozen"):
        specification.protocol_version = "9.9.9"  # type: ignore[misc]
