"""Contract tests for the frozen M3 Step 1 Zeek normalization protocol.

Tests use specification/report metadata and synthetic values only.  They never
open Zeek logs and never create canonical events.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from uuid import UUID, uuid5

from pydantic import ValidationError
import pytest

from modules.detection.src.lineage.zeek_normalization import (
    bind_zeek_normalization_specification,
    load_and_bind_zeek_normalization_specification,
    load_zeek_normalization_specification,
)
from modules.detection.src.lineage.replay import load_zeek_replay_specification
from modules.detection.src.schemas.replay import ZeekReplayRunReport
from modules.detection.src.schemas.zeek_normalization import (
    ZeekNormalizationContext,
    ZeekNormalizationSpecification,
    ZeekSourceCoordinate,
)


ROOT = Path(__file__).resolve().parents[3]
SPEC_PATH = ROOT / "datasets/manifests/cicids2017_zeek_normalization.yaml"
M2_SPEC_PATH = ROOT / "datasets/manifests/cicids2017_zeek_replay.yaml"
PROTOCOL_SHA256 = "99ab724a3d245a352e888e2f4771b5a354b5855180af4a72c36980c9296897d4"
M1_SHA256 = "feab8d4fbd8454cd12723368704e1e7311853a4316efec7f94bf11726ebb984e"
M2_SHA256 = "e52c183a315c1ac38cbf1e64155489f5f041e95aa5d2e5cbb82e31f03ac4c455"
UUID_NAMESPACE = UUID("90b642e0-53d5-5057-80cc-994f89d797b4")

EXPECTED_BINDINGS = (
    (
        "2017-07-04_Tuesday-WorkingHours",
        "Tuesday-WorkingHours.pcap",
        "e8908003c583fd5fb148521266b065289f17ba9003d701ea5323208e6534e00b",
        "8d7b3e8d3090b93f90df50e77d48f1a33f587dca2982a3d5cdf17623c01c1314",
        323342,
        130683765,
        "5a828bcb809ad6ee8e6e83d5334c9082b38b4d20e4df41f1249639416973b860",
    ),
    (
        "2017-07-05_Wednesday-workingHours",
        "Wednesday-workingHours.pcap",
        "56f49ee0c9abda9f9cf05346b8db91f82b7de67c9f65701f35cfb10c34079bb0",
        "8bd688deff24280dca33548295e7261a4aadeedc2b8f658e811eefd37d361a10",
        509362,
        205786448,
        "f4aae4520456deaec725ab110a3760c83e9d52e78d8069a83819e18c7cd5ccd5",
    ),
    (
        "2017-07-07_Friday-WorkingHours",
        "Friday-WorkingHours.pcap",
        "f59ed149e2582fc93a51667b70b4791f5ba0cb2f3e1df4d0bb133b51d7f8f8ae",
        "df81b14b28ba54597097dde1f8414e4868a9dcee28430189393727c2747453aa",
        547353,
        218393867,
        "1b42468fe419047a009925e03b9ff51b04417a4f5bee6e54cec3c1799f7dec47",
    ),
)


@pytest.fixture(scope="module")
def specification() -> ZeekNormalizationSpecification:
    return load_zeek_normalization_specification(SPEC_PATH)


def _reports(
    specification: ZeekNormalizationSpecification,
) -> tuple[ZeekReplayRunReport, ...]:
    return tuple(
        ZeekReplayRunReport.model_validate_json(
            (ROOT / binding.report_relative_path).read_bytes()
        )
        for binding in specification.replay_reports
    )


def _report_file_hashes(
    specification: ZeekNormalizationSpecification,
) -> tuple[str, ...]:
    return tuple(binding.report_file_sha256 for binding in specification.replay_reports)


def _validate_json_payload(payload: dict[str, object]) -> ZeekNormalizationSpecification:
    return ZeekNormalizationSpecification.model_validate_json(json.dumps(payload))


def _source_coordinate(line_number: int = 42, record_count: int = 323342) -> ZeekSourceCoordinate:
    first = EXPECTED_BINDINGS[0]
    return ZeekSourceCoordinate(
        output_partition=first[0],
        replay_report_content_sha256=first[3],
        log_name="conn.log",
        source_log_sha256=first[6],
        reported_record_count=record_count,
        physical_line_number=line_number,
    )


def test_official_specification_has_frozen_identity_and_is_immutable(
    specification: ZeekNormalizationSpecification,
) -> None:
    assert specification.protocol_version == "1.0.0"
    assert specification.content_sha256() == PROTOCOL_SHA256
    assert specification.m1_manifest_sha256 == M1_SHA256
    assert specification.m2_specification_sha256 == M2_SHA256
    assert specification.dataset_name == "cicids2017"
    assert specification.sensor_type == "zeek"
    assert specification.sensor_version == "8.0.9"
    with pytest.raises(ValidationError, match="frozen"):
        specification.protocol_version = "2.0.0"  # type: ignore[misc]


def test_protocol_supports_exactly_conn_log_to_flow_end(
    specification: ZeekNormalizationSpecification,
) -> None:
    assert specification.supported_log_names == ("conn.log",)
    assert len(specification.log_mappings) == 1
    mapping = specification.log_mappings[0]
    assert mapping.log_name == "conn.log"
    assert mapping.classification == "canonical_telemetry"
    assert mapping.target_model == "FlowEnd"
    assert mapping.target_event_type == "flow_end"
    assert specification.unsupported_records.unsupported_log == "reject_source_with_audit"
    assert specification.unsupported_records.operational_log == "reject_source_with_audit"


def test_conn_field_sets_are_closed_sorted_and_disjoint(
    specification: ZeekNormalizationSpecification,
) -> None:
    mapping = specification.log_mappings[0]
    assert mapping.required_fields == (
        "conn_state",
        "duration",
        "id.orig_h",
        "id.orig_p",
        "id.resp_h",
        "id.resp_p",
        "orig_bytes",
        "orig_pkts",
        "proto",
        "resp_bytes",
        "resp_pkts",
        "ts",
        "uid",
    )
    assert mapping.optional_mapped_fields == ("service",)
    assert mapping.optional_ignored_fields == (
        "history",
        "ip_proto",
        "local_orig",
        "local_resp",
        "missed_bytes",
        "orig_ip_bytes",
        "resp_ip_bytes",
        "tunnel_parents",
    )
    sets = (
        set(mapping.required_fields),
        set(mapping.optional_mapped_fields),
        set(mapping.optional_ignored_fields),
    )
    assert not sets[0] & sets[1]
    assert not sets[0] & sets[2]
    assert not sets[1] & sets[2]
    assert mapping.allowed_fields == tuple(sorted(set().union(*sets)))
    assert mapping.unknown_field_policy == "reject_record"


def test_exact_field_mapping_and_payload_byte_semantics(
    specification: ZeekNormalizationSpecification,
) -> None:
    mapping = {
        item.source_field: (item.target_field, item.transform)
        for item in specification.log_mappings[0].field_mappings
    }
    assert mapping == {
        "conn_state": ("connection_state", "strict_identifier"),
        "duration": ("event_end_time", "add_exact_microseconds_to_ts"),
        "id.orig_h": ("source.ip", "ip_address"),
        "id.orig_p": ("source.port", "port"),
        "id.resp_h": ("destination.ip", "ip_address"),
        "id.resp_p": ("destination.port", "port"),
        "orig_bytes": ("counters.source_bytes", "non_negative_integer"),
        "orig_pkts": ("counters.source_packets", "non_negative_integer"),
        "proto": ("transport", "closed_tcp_udp_transport"),
        "resp_bytes": ("counters.destination_bytes", "non_negative_integer"),
        "resp_pkts": ("counters.destination_packets", "non_negative_integer"),
        "service": ("service", "single_strict_identifier_or_null"),
        "ts": ("event_start_time", "unix_epoch_utc_exact_microseconds"),
        "uid": ("conversation_id", "strict_identifier"),
    }
    envelope = specification.event_envelope
    assert envelope.byte_counter_semantics == "zeek_payload_bytes"
    assert "orig_ip_bytes" in specification.log_mappings[0].optional_ignored_fields
    assert "resp_ip_bytes" in specification.log_mappings[0].optional_ignored_fields
    assert envelope.termination_reason_policy == "explicit_null"


def test_required_or_mapping_drift_is_rejected(
    specification: ZeekNormalizationSpecification,
) -> None:
    payload = specification.model_dump(mode="json")
    payload["log_mappings"][0]["required_fields"].remove("duration")
    with pytest.raises(ValidationError, match="required fields"):
        _validate_json_payload(payload)

    payload = specification.model_dump(mode="json")
    payload["log_mappings"][0]["field_mappings"][6]["target_field"] = (
        "counters.destination_bytes"
    )
    with pytest.raises(ValidationError, match="mappings are not canonical"):
        _validate_json_payload(payload)


def test_unknown_keys_and_type_coercion_are_rejected(
    specification: ZeekNormalizationSpecification,
) -> None:
    payload = specification.model_dump(mode="json")
    payload["unexpected"] = "not permitted"
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        _validate_json_payload(payload)

    payload = specification.model_dump(mode="json")
    payload["protocol_version"] = 1
    with pytest.raises(ValidationError):
        _validate_json_payload(payload)

    with pytest.raises(ValidationError):
        ZeekSourceCoordinate(
            output_partition=EXPECTED_BINDINGS[0][0],
            replay_report_content_sha256=EXPECTED_BINDINGS[0][3],
            log_name="conn.log",
            source_log_sha256=EXPECTED_BINDINGS[0][6],
            reported_record_count=True,
            physical_line_number=1,
        )


def test_timestamp_contract_requires_exact_decimal_microseconds_without_defaults(
    specification: ZeekNormalizationSpecification,
) -> None:
    policy = specification.timestamps
    assert policy.json_number_decoder == "decimal_from_json_lexeme"
    assert policy.epoch == "unix"
    assert policy.timezone == "UTC"
    assert policy.precision == "microseconds"
    assert policy.excess_precision_policy == "reject_without_rounding"
    assert policy.timestamp_range == "non_negative_finite"
    assert policy.duration_range == "non_negative_finite"
    assert policy.event_start_time_source == "ts"
    assert policy.event_end_time_rule == "ts_plus_duration"
    assert policy.record_available_time_source == "normalization_context"
    assert policy.ingested_at_source == "normalization_context"
    assert policy.required_temporal_order == (
        "event_start_time_le_event_end_time_le_record_available_time_le_ingested_at"
    )
    rejected = specification.unsupported_records
    assert rejected.non_finite_number == "reject_record_with_audit"
    assert rejected.excess_timestamp_precision == "reject_record_with_audit"
    assert rejected.silent_defaults_forbidden is True
    assert rejected.partial_events_forbidden is True


def test_normalization_context_requires_explicit_ordered_utc_times() -> None:
    available = datetime(2026, 7, 31, 11, 0, tzinfo=timezone.utc)
    context = ZeekNormalizationContext(
        protocol_sha256=PROTOCOL_SHA256,
        source=_source_coordinate(),
        record_available_time=available,
        ingested_at=available + timedelta(microseconds=1),
    )
    assert context.record_available_time == available
    assert context.ingested_at > context.record_available_time

    with pytest.raises(ValidationError, match="cannot precede"):
        context.model_copy(
            update={"ingested_at": available - timedelta(microseconds=1)}
        ).model_validate(context.model_copy(
            update={"ingested_at": available - timedelta(microseconds=1)}
        ))
    with pytest.raises(ValidationError):
        ZeekNormalizationContext(
            protocol_sha256=PROTOCOL_SHA256,
            source=_source_coordinate(),
            record_available_time=datetime(2026, 7, 31, 11, 0),
            ingested_at=available,
        )
    with pytest.raises(ValidationError):
        ZeekNormalizationContext.model_validate(
            {
                "protocol_sha256": PROTOCOL_SHA256,
                "source": _source_coordinate(),
                "record_available_time": available,
            }
        )


def test_transport_and_service_policies_are_closed(
    specification: ZeekNormalizationSpecification,
) -> None:
    envelope = specification.event_envelope
    assert envelope.supported_transports == ("tcp", "udp")
    assert envelope.service_policy == (
        "missing_or_null_to_null_single_identifier_only_reject_comma_list"
    )
    assert specification.unsupported_records.unsupported_transport == (
        "reject_record_with_audit"
    )
    assert specification.unsupported_records.unsupported_service_cardinality == (
        "reject_record_with_audit"
    )
    service = next(
        item
        for item in specification.log_mappings[0].field_mappings
        if item.source_field == "service"
    )
    assert service.presence == "optional"
    assert service.null_policy == "map_missing_to_null"
    assert service.transform == "single_strict_identifier_or_null"

    payload = specification.model_dump(mode="json")
    payload["event_envelope"]["supported_transports"].append("icmp")
    with pytest.raises(ValidationError, match="Input should be 'tcp' or 'udp'"):
        _validate_json_payload(payload)


def test_unsupported_and_operational_log_sources_are_rejected_by_schema() -> None:
    common = {
        "output_partition": EXPECTED_BINDINGS[0][0],
        "replay_report_content_sha256": EXPECTED_BINDINGS[0][3],
        "source_log_sha256": EXPECTED_BINDINGS[0][6],
        "reported_record_count": 10,
        "physical_line_number": 1,
    }
    for log_name in ("dns.log", "stats.log", "telemetry.log"):
        with pytest.raises(ValidationError):
            ZeekSourceCoordinate(log_name=log_name, **common)


def test_source_coordinates_are_one_based_and_report_bounded() -> None:
    coordinate = _source_coordinate(line_number=323342)
    assert coordinate.physical_line_number == coordinate.reported_record_count
    with pytest.raises(ValidationError):
        _source_coordinate(line_number=0)
    with pytest.raises(ValidationError, match="exceeds reported record count"):
        _source_coordinate(line_number=323343)
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        ZeekSourceCoordinate.model_validate(
            {**coordinate.model_dump(), "record_payload": "forbidden"}
        )


def test_uuidv5_recipe_matches_fixed_synthetic_vector_and_excludes_wall_clock(
    specification: ZeekNormalizationSpecification,
) -> None:
    policy = specification.provenance
    assert policy.event_id_algorithm == "uuid5"
    assert policy.event_id_namespace == UUID_NAMESPACE
    assert policy.event_id_components == (
        "protocol_sha256",
        "replay_report_content_sha256",
        "source_log_sha256",
        "output_partition",
        "log_name",
        "physical_line_number",
    )
    assert policy.event_id_name_encoding == (
        "utf8_component_values_joined_by_single_ascii_pipe_line_number_base10"
    )
    values = (
        PROTOCOL_SHA256,
        EXPECTED_BINDINGS[0][3],
        EXPECTED_BINDINGS[0][6],
        EXPECTED_BINDINGS[0][0],
        "conn.log",
        "42",
    )
    assert uuid5(UUID_NAMESPACE, "|".join(values)) == UUID(
        "c258e55a-76b4-53bc-9e44-2e6432ba6c0a"
    )
    assert "record_available_time" not in policy.event_id_components
    assert "ingested_at" not in policy.event_id_components
    assert policy.sensor_id == "zeek"
    assert policy.sensor_run_id_source == "replay_report_content_sha256"
    assert policy.capture_id_source == "input_pcap_sha256"
    assert policy.dataset_snapshot_id_source == "m1_manifest_sha256"
    assert policy.model_release_id_policy == "explicit_null"


def test_ordering_is_report_then_physical_line_and_never_value_sorted(
    specification: ZeekNormalizationSpecification,
) -> None:
    policy = specification.ordering
    assert policy.partition_order == "replay_report_binding_order"
    assert policy.record_order == "physical_jsonl_line_number_ascending"
    assert policy.line_number_base == 1
    assert policy.cross_partition_order == "concatenate_partitions"
    assert policy.sort_by_event_time is False
    assert policy.sort_by_uid is False
    assert policy.deduplicate_records is False
    assert policy.rejected_records_retain_coordinates is True
    assert tuple(item.output_partition for item in specification.replay_reports) == (
        EXPECTED_BINDINGS[0][0],
        EXPECTED_BINDINGS[1][0],
        EXPECTED_BINDINGS[2][0],
    )

    # Synthetic event values would sort differently; coordinates remain authoritative.
    synthetic = (
        (0, 1, {"ts": 200, "uid": "z"}),
        (0, 2, {"ts": 100, "uid": "a"}),
        (1, 1, {"ts": 50, "uid": "a"}),
    )
    assert tuple((partition, line) for partition, line, _ in synthetic) == (
        (0, 1),
        (0, 2),
        (1, 1),
    )
    assert [item[2]["ts"] for item in synthetic] == [200, 100, 50]


def test_exact_three_replay_report_and_conn_artifact_bindings(
    specification: ZeekNormalizationSpecification,
) -> None:
    assert len(specification.replay_reports) == 3
    actual = tuple(
        (
            binding.output_partition,
            binding.input.relative_path,
            binding.report_file_sha256,
            binding.report_content_sha256,
            binding.supported_log.record_count,
            binding.supported_log.size_bytes,
            binding.supported_log.sha256,
        )
        for binding in specification.replay_reports
    )
    assert actual == EXPECTED_BINDINGS
    assert all(
        binding.supported_log.log_name == "conn.log"
        and binding.supported_log.classification == "canonical_telemetry"
        for binding in specification.replay_reports
    )


def test_official_report_only_binding_reads_no_zeek_logs(monkeypatch: pytest.MonkeyPatch) -> None:
    observed_reads: list[Path] = []
    original_read_bytes = Path.read_bytes

    def tracked_read_bytes(path: Path) -> bytes:
        observed_reads.append(path)
        assert path.name == "replay_run.json"
        assert path.suffix != ".log"
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", tracked_read_bytes)
    bound = load_and_bind_zeek_normalization_specification(ROOT)
    assert bound.specification_sha256 == PROTOCOL_SHA256
    assert bound.m1_manifest_sha256 == M1_SHA256
    assert bound.m2_specification_sha256 == M2_SHA256
    assert bound.replay_report_count == 3
    assert bound.supported_record_count == 1_380_057
    assert len(observed_reads) == 3


def test_binder_rejects_forged_report_file_or_content_hash(
    specification: ZeekNormalizationSpecification,
) -> None:
    m2 = load_zeek_replay_specification(M2_SPEC_PATH)
    reports = _reports(specification)
    hashes = _report_file_hashes(specification)
    with pytest.raises(ValueError, match="file hash"):
        bind_zeek_normalization_specification(
            specification,
            m2,
            reports,
            ("0" * 64, *hashes[1:]),
        )

    forged = reports[0].model_copy(
        update={"command": (*reports[0].command, "forged")}
    )
    with pytest.raises(ValueError, match="content hash"):
        bind_zeek_normalization_specification(
            specification,
            m2,
            (forged, *reports[1:]),
            hashes,
        )


def test_binder_rejects_forged_runtime_input_and_conn_artifact(
    specification: ZeekNormalizationSpecification,
) -> None:
    m2 = load_zeek_replay_specification(M2_SPEC_PATH)
    reports = _reports(specification)
    hashes = _report_file_hashes(specification)

    forged_runtime = reports[0].runtime.model_copy(update={"zeek_version": "8.0.8"})
    forged_report = reports[0].model_copy(update={"runtime": forged_runtime})
    binding = specification.replay_reports[0].model_copy(
        update={"report_content_sha256": forged_report.content_sha256()}
    )
    forged_spec = specification.model_copy(
        update={"replay_reports": (binding, *specification.replay_reports[1:])}
    )
    with pytest.raises(ValueError, match="runtime"):
        bind_zeek_normalization_specification(
            forged_spec, m2, (forged_report, *reports[1:]), hashes
        )

    forged_input = reports[0].input.model_copy(
        update={"relative_path": "Forged-Tuesday.pcap"}
    )
    forged_report = reports[0].model_copy(update={"input": forged_input})
    binding = specification.replay_reports[0].model_copy(
        update={
            "report_content_sha256": forged_report.content_sha256(),
            "input": forged_input,
        }
    )
    forged_spec = specification.model_copy(
        update={"replay_reports": (binding, *specification.replay_reports[1:])}
    )
    with pytest.raises(ValueError, match="M2 input order"):
        bind_zeek_normalization_specification(
            forged_spec, m2, (forged_report, *reports[1:]), hashes
        )

    conn_index = next(
        index
        for index, artifact in enumerate(reports[0].logs)
        if artifact.log_name == "conn.log"
    )
    forged_conn = reports[0].logs[conn_index].model_copy(
        update={"record_count": reports[0].logs[conn_index].record_count + 1}
    )
    forged_logs = list(reports[0].logs)
    forged_logs[conn_index] = forged_conn
    forged_report = reports[0].model_copy(update={"logs": tuple(forged_logs)})
    binding = specification.replay_reports[0].model_copy(
        update={"report_content_sha256": forged_report.content_sha256()}
    )
    forged_spec = specification.model_copy(
        update={"replay_reports": (binding, *specification.replay_reports[1:])}
    )
    with pytest.raises(ValueError, match="conn.log artifact"):
        bind_zeek_normalization_specification(
            forged_spec, m2, (forged_report, *reports[1:]), hashes
        )


def test_binder_rejects_forged_m1_m2_and_report_count_bindings(
    specification: ZeekNormalizationSpecification,
) -> None:
    m2 = load_zeek_replay_specification(M2_SPEC_PATH)
    reports = _reports(specification)
    hashes = _report_file_hashes(specification)

    with pytest.raises(ValueError, match="M2 hash"):
        bind_zeek_normalization_specification(
            specification.model_copy(update={"m2_specification_sha256": "0" * 64}),
            m2,
            reports,
            hashes,
        )
    with pytest.raises(ValueError, match="M1 hash"):
        bind_zeek_normalization_specification(
            specification.model_copy(update={"m1_manifest_sha256": "0" * 64}),
            m2,
            reports,
            hashes,
        )
    with pytest.raises(ValueError, match="report count"):
        bind_zeek_normalization_specification(
            specification,
            m2,
            reports[:-1],
            hashes,
        )
    with pytest.raises(ValueError, match="file-hash count"):
        bind_zeek_normalization_specification(
            specification,
            m2,
            reports,
            hashes[:-1],
        )


def test_parser_boundaries_forbid_io_events_persistence_and_features(
    specification: ZeekNormalizationSpecification,
) -> None:
    boundary = specification.boundaries
    assert boundary.parser_input == (
        "one_utf8_json_object_line_plus_source_coordinate"
    )
    assert boundary.parser_output == "raw_sensor_record_or_explicit_rejection"
    assert boundary.normalizer_input == (
        "raw_sensor_record_plus_normalization_context"
    )
    assert boundary.normalizer_output == "FlowEnd_or_explicit_rejection"
    assert boundary.parser_creates_events is False
    assert boundary.parser_persists_output is False
    assert boundary.normalizer_reads_files is False
    assert boundary.normalizer_persists_output is False
    assert boundary.feature_engineering_allowed is False
