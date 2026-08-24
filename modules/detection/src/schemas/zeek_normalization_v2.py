"""Strict additive M3 v2 normalization protocol contracts.

V2 deliberately supersedes the v1 microsecond temporal representation while
leaving every M1, M2, and M3 v1 artifact immutable.
"""
from __future__ import annotations

from hashlib import sha256
import json
from typing import Annotated, Literal
from uuid import UUID

from pydantic import Field, field_validator, model_validator

from modules.detection.src.contracts import (
    NonEmptyText,
    StrictIdentifier,
    StrictModel,
    VersionContract,
)
from modules.detection.src.schemas.datasets import Sha256Digest
from modules.detection.src.schemas.exact_time_v2 import ExactDecimalSeconds22
from modules.detection.src.schemas.replay import RepositoryRelativePath
from modules.detection.src.schemas.zeek_normalization import (
    ZeekOrderingPolicy,
    ZeekParserBoundaryPolicy,
    ZeekReplayReportBinding,
    ZeekSourceCoordinate,
    _repository_relative,
)


_REQUIRED_FIELDS = (
    "conn_state", "duration", "id.orig_h", "id.orig_p", "id.resp_h",
    "id.resp_p", "orig_bytes", "orig_pkts", "proto", "resp_bytes",
    "resp_pkts", "ts", "uid",
)
_OPTIONAL_MAPPED = ("service",)
_OPTIONAL_IGNORED = (
    "history", "ip_proto", "local_orig", "local_resp", "missed_bytes",
    "orig_ip_bytes", "resp_ip_bytes", "tunnel_parents",
)


class ZeekFieldMappingV2(StrictModel):
    source_field: StrictIdentifier
    target_fields: Annotated[tuple[StrictIdentifier, ...], Field(min_length=1)]
    presence: Literal["required", "optional"]
    source_type: Literal["json_number_decimal", "string", "integer"]
    transform: Literal[
        "decimal38_22_exact_timestamp",
        "decimal38_22_exact_duration_and_end",
        "strict_identifier",
        "ip_address",
        "port",
        "non_negative_integer",
        "closed_tcp_udp_transport",
        "single_strict_identifier_or_null",
    ]
    null_policy: Literal["reject", "map_missing_to_null"]


class ZeekConnLogMappingV2(StrictModel):
    log_name: Literal["conn.log"]
    classification: Literal["canonical_telemetry"]
    target_model: Literal["FlowEndV2"]
    target_event_type: Literal["flow_end"]
    required_fields: tuple[StrictIdentifier, ...]
    optional_mapped_fields: tuple[StrictIdentifier, ...]
    optional_ignored_fields: tuple[StrictIdentifier, ...]
    unknown_field_policy: Literal["reject_record"]
    field_mappings: tuple[ZeekFieldMappingV2, ...]

    @model_validator(mode="after")
    def validate_exact_mapping(self) -> "ZeekConnLogMappingV2":
        if self.required_fields != _REQUIRED_FIELDS:
            raise ValueError("v2 conn required fields diverge from frozen mapping")
        if self.optional_mapped_fields != _OPTIONAL_MAPPED:
            raise ValueError("v2 optional mapped fields must contain only service")
        if self.optional_ignored_fields != _OPTIONAL_IGNORED:
            raise ValueError("v2 ignored fields diverge from frozen mapping")
        sources = tuple(item.source_field for item in self.field_mappings)
        if tuple(sorted(sources)) != sources or len(set(sources)) != len(sources):
            raise ValueError("v2 mappings must be unique and source-sorted")
        expected = {
            "conn_state": (("connection_state",), "required", "string", "strict_identifier", "reject"),
            "duration": (("event_duration", "event_end_time"), "required", "json_number_decimal", "decimal38_22_exact_duration_and_end", "reject"),
            "id.orig_h": (("source.ip",), "required", "string", "ip_address", "reject"),
            "id.orig_p": (("source.port",), "required", "integer", "port", "reject"),
            "id.resp_h": (("destination.ip",), "required", "string", "ip_address", "reject"),
            "id.resp_p": (("destination.port",), "required", "integer", "port", "reject"),
            "orig_bytes": (("counters.source_bytes",), "required", "integer", "non_negative_integer", "reject"),
            "orig_pkts": (("counters.source_packets",), "required", "integer", "non_negative_integer", "reject"),
            "proto": (("transport",), "required", "string", "closed_tcp_udp_transport", "reject"),
            "resp_bytes": (("counters.destination_bytes",), "required", "integer", "non_negative_integer", "reject"),
            "resp_pkts": (("counters.destination_packets",), "required", "integer", "non_negative_integer", "reject"),
            "service": (("service",), "optional", "string", "single_strict_identifier_or_null", "map_missing_to_null"),
            "ts": (("event_start_time",), "required", "json_number_decimal", "decimal38_22_exact_timestamp", "reject"),
            "uid": (("conversation_id",), "required", "string", "strict_identifier", "reject"),
        }
        observed = {
            item.source_field: (
                item.target_fields, item.presence, item.source_type,
                item.transform, item.null_policy,
            ) for item in self.field_mappings
        }
        if observed != expected:
            raise ValueError("v2 conn.log to FlowEndV2 mappings are not canonical")
        return self

    @property
    def allowed_fields(self) -> tuple[str, ...]:
        return tuple(sorted(set(self.required_fields) | set(self.optional_mapped_fields) | set(self.optional_ignored_fields)))


class ZeekParserBoundaryPolicyV2(ZeekParserBoundaryPolicy):
    """V2 parser/normalizer separation with an exact FlowEndV2 output name."""

    normalizer_output: Literal["FlowEndV2_or_explicit_rejection"]


class ZeekTemporalPolicyV2(StrictModel):
    source_decoder: Literal["decimal_from_json_lexeme"]
    canonical_type: Literal["DECIMAL(38,22)"]
    json_encoding: Literal["fixed_scale_string_22_fractional_digits"]
    epoch: Literal["unix"]
    time_scale: Literal["posix"]
    display_timezone: Literal["UTC"]
    unit: Literal["seconds"]
    precision: Literal[38]
    scale: Literal[22]
    conversion: Literal["append_zeros_only"]
    arithmetic: Literal["unscaled_integer"]
    float_conversion: Literal["forbidden"]
    rounding: Literal["forbidden"]
    truncation: Literal["forbidden"]
    event_end_rule: Literal["exact_start_plus_duration"]
    exact_temporal_order: Literal[
        "start_le_end_le_record_available_le_ingested"
    ]


class ZeekEventEnvelopePolicyV2(StrictModel):
    event_type: Literal["flow_end"]
    target_model: Literal["FlowEndV2"]
    sensor_type: Literal["zeek"]
    versions: VersionContract
    normalizer_version: Literal["2.0.0"]
    pipeline_version: Literal["2.0.0"]
    termination_reason_policy: Literal["explicit_null"]
    byte_counter_semantics: Literal["zeek_payload_bytes"]
    supported_transports: tuple[Literal["tcp", "udp"], ...]
    service_policy: Literal[
        "missing_or_null_to_null_single_identifier_only_reject_comma_list"
    ]

    @model_validator(mode="after")
    def validate_versions(self) -> "ZeekEventEnvelopePolicyV2":
        if self.versions != VersionContract(
            schema_version="2.0.0", event_version="2.0.0",
            feature_version="1.0.0", sensor_version="8.0.9",
        ):
            raise ValueError("v2 output versions are not frozen correctly")
        if self.supported_transports != ("tcp", "udp"):
            raise ValueError("v2 supports exactly tcp and udp")
        return self


class ZeekProvenancePolicyV2(StrictModel):
    event_id_algorithm: Literal["uuid5"]
    event_id_namespace: UUID
    event_id_components: tuple[NonEmptyText, ...]
    event_id_name_encoding: Literal[
        "utf8_component_values_joined_by_single_ascii_pipe_line_number_base10"
    ]
    sensor_id: Literal["zeek"]
    sensor_run_id_source: Literal["replay_report_content_sha256"]
    capture_id_source: Literal["input_pcap_sha256"]
    dataset_snapshot_id_source: Literal["m1_manifest_sha256"]
    model_release_id_policy: Literal["explicit_null"]

    @model_validator(mode="after")
    def validate_identity(self) -> "ZeekProvenancePolicyV2":
        if self.event_id_namespace != UUID("f7dad188-04cb-5859-81a0-014329de2899"):
            raise ValueError("v2 UUID namespace mismatch")
        if self.event_id_components != (
            "protocol_sha256", "replay_report_content_sha256",
            "source_log_sha256", "output_partition", "log_name",
            "physical_line_number",
        ):
            raise ValueError("v2 event ID components mismatch")
        return self


class ZeekUnsupportedRecordPolicyV2(StrictModel):
    malformed_json: Literal["reject_record_with_audit"]
    non_object_json: Literal["reject_record_with_audit"]
    missing_required_field: Literal["reject_record_with_audit"]
    null_required_field: Literal["reject_record_with_audit"]
    unknown_field: Literal["reject_record_with_audit"]
    invalid_field_type: Literal["reject_record_with_audit"]
    non_finite_number: Literal["reject_record_with_audit"]
    decimal38_22_range_or_scale: Literal["reject_record_with_audit"]
    unsupported_transport: Literal["reject_record_with_audit"]
    unsupported_service_cardinality: Literal["reject_record_with_audit"]
    source_binding_mismatch: Literal["reject_source_with_audit"]
    continue_after_record_rejection: Literal[True]
    silent_defaults_forbidden: Literal[True]
    partial_events_forbidden: Literal[True]


class ZeekTemporalEvidenceProfileV2(StrictModel):
    scanned_record_count: Literal[1380057]
    records_with_duration: Literal[1355131]
    timestamp_max_significant_digits: Literal[17]
    timestamp_max_fractional_digits: Literal[7]
    duration_max_significant_digits: Literal[17]
    duration_max_fractional_digits: Literal[22]
    exact_end_max_significant_digits: Literal[32]
    exact_end_max_fractional_digits: Literal[22]
    expected_accepted_record_count: Literal[1353467]
    expected_rejected_record_count: Literal[26590]
    expected_acceptance_rate: Literal["98.073267988%"]
    analytical_projection: Literal["DECIMAL(38,22)"]


class ZeekNormalizationSpecificationV2(StrictModel):
    protocol_version: Literal["2.0.0"]
    frozen_at: str
    supersedes_protocol_path: RepositoryRelativePath
    supersedes_protocol_sha256: Sha256Digest
    revision_reason: Literal[
        "microsecond_temporal_representation_empirically_incompatible_with_frozen_m2_evidence"
    ]
    dataset_name: StrictIdentifier
    m1_manifest_sha256: Sha256Digest
    m2_specification_path: RepositoryRelativePath
    m2_specification_sha256: Sha256Digest
    m2_output_root: RepositoryRelativePath
    sensor_type: Literal["zeek"]
    sensor_version: Literal["8.0.9"]
    input_format: Literal["json_lines"]
    replay_reports: tuple[ZeekReplayReportBinding, ...]
    log_mappings: tuple[ZeekConnLogMappingV2, ...]
    temporal: ZeekTemporalPolicyV2
    evidence: ZeekTemporalEvidenceProfileV2
    event_envelope: ZeekEventEnvelopePolicyV2
    provenance: ZeekProvenancePolicyV2
    unsupported_records: ZeekUnsupportedRecordPolicyV2
    ordering: ZeekOrderingPolicy
    boundaries: ZeekParserBoundaryPolicyV2
    authoritative_sources: Annotated[tuple[NonEmptyText, ...], Field(min_length=1)]

    @field_validator("frozen_at")
    @classmethod
    def validate_frozen_at(cls, value: str) -> str:
        if value != "2026-07-31T15:46:36.173000Z":
            raise ValueError("v2 frozen_at identity mismatch")
        return value

    @field_validator("supersedes_protocol_path", "m2_specification_path", "m2_output_root")
    @classmethod
    def validate_paths(cls, value: str) -> str:
        return _repository_relative(value)

    @field_validator("authoritative_sources")
    @classmethod
    def validate_sources(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if tuple(sorted(value)) != value or len(set(value)) != len(value):
            raise ValueError("authoritative sources must be unique and sorted")
        if any(not item.startswith("https://") for item in value):
            raise ValueError("authoritative sources must use HTTPS")
        return value

    @model_validator(mode="after")
    def validate_v2_freeze(self) -> "ZeekNormalizationSpecificationV2":
        if self.supersedes_protocol_sha256 != "99ab724a3d245a352e888e2f4771b5a354b5855180af4a72c36980c9296897d4":
            raise ValueError("v2 must supersede the exact frozen v1 protocol")
        if len(self.replay_reports) != 3 or len(self.log_mappings) != 1:
            raise ValueError("v2 requires three reports and one conn mapping")
        if self.log_mappings[0].log_name != "conn.log":
            raise ValueError("v2 supports only conn.log")
        keys = tuple((item.input.capture_date, item.input.relative_path) for item in self.replay_reports)
        if tuple(sorted(keys)) != keys or len(set(keys)) != len(keys):
            raise ValueError("v2 replay reports must retain unique M1 order")
        paths = tuple(item.report_relative_path for item in self.replay_reports)
        if len(set(paths)) != len(paths):
            raise ValueError("v2 replay report paths must be unique")
        prefix = f"{self.m2_output_root}/"
        if any(not path.startswith(prefix) for path in paths):
            raise ValueError("v2 replay reports must remain below the frozen M2 root")
        return self

    def content_sha256(self) -> str:
        payload = json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return sha256(payload).hexdigest()


class ZeekNormalizationContextV2(StrictModel):
    protocol_sha256: Sha256Digest
    source: ZeekSourceCoordinate
    record_available_time: ExactDecimalSeconds22
    ingested_at: ExactDecimalSeconds22

    @model_validator(mode="after")
    def validate_order(self) -> "ZeekNormalizationContextV2":
        from modules.detection.src.schemas.exact_time_v2 import unscaled_from_canonical
        if unscaled_from_canonical(self.ingested_at) < unscaled_from_canonical(self.record_available_time):
            raise ValueError("v2 ingested_at precedes record_available_time")
        return self
