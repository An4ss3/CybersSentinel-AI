"""Strict design-freeze contracts for M3 Zeek-to-NetworkEvent normalization.

Step 1 is declarative only.  These models define the accepted Zeek source,
field semantics, lineage, ordering, and rejection policy without opening sensor
logs, parsing JSON records, or constructing canonical events.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import PurePosixPath
from typing import Annotated, Literal
from uuid import UUID

from pydantic import Field, StringConstraints, field_validator, model_validator

from modules.detection.src.contracts import (
    NonEmptyText,
    PositiveInt,
    StrictIdentifier,
    StrictModel,
    UtcDateTime,
    VersionContract,
    VersionString,
)
from modules.detection.src.schemas.datasets import PcapEvidenceFile, Sha256Digest
from modules.detection.src.schemas.replay import (
    RepositoryRelativePath,
    ZeekLogArtifact,
    ZeekLogName,
)


ZeekFieldName = Annotated[
    str,
    StringConstraints(pattern=r"^[a-z][a-z0-9_.]*$", max_length=128),
]
CanonicalFieldPath = Annotated[
    str,
    StringConstraints(pattern=r"^[a-z][a-z0-9_.]*$", max_length=128),
]


_REQUIRED_CONN_FIELDS = (
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
_OPTIONAL_MAPPED_CONN_FIELDS = ("service",)
_OPTIONAL_IGNORED_CONN_FIELDS = (
    "history",
    "ip_proto",
    "local_orig",
    "local_resp",
    "missed_bytes",
    "orig_ip_bytes",
    "resp_ip_bytes",
    "tunnel_parents",
)

_EXPECTED_CONN_MAPPINGS = {
    "conn_state": (
        "connection_state",
        "required",
        "string",
        "strict_identifier",
        "reject",
    ),
    "duration": (
        "event_end_time",
        "required",
        "json_number_decimal",
        "add_exact_microseconds_to_ts",
        "reject",
    ),
    "id.orig_h": ("source.ip", "required", "string", "ip_address", "reject"),
    "id.orig_p": ("source.port", "required", "integer", "port", "reject"),
    "id.resp_h": (
        "destination.ip",
        "required",
        "string",
        "ip_address",
        "reject",
    ),
    "id.resp_p": (
        "destination.port",
        "required",
        "integer",
        "port",
        "reject",
    ),
    "orig_bytes": (
        "counters.source_bytes",
        "required",
        "integer",
        "non_negative_integer",
        "reject",
    ),
    "orig_pkts": (
        "counters.source_packets",
        "required",
        "integer",
        "non_negative_integer",
        "reject",
    ),
    "proto": (
        "transport",
        "required",
        "string",
        "closed_tcp_udp_transport",
        "reject",
    ),
    "resp_bytes": (
        "counters.destination_bytes",
        "required",
        "integer",
        "non_negative_integer",
        "reject",
    ),
    "resp_pkts": (
        "counters.destination_packets",
        "required",
        "integer",
        "non_negative_integer",
        "reject",
    ),
    "service": (
        "service",
        "optional",
        "string",
        "single_strict_identifier_or_null",
        "map_missing_to_null",
    ),
    "ts": (
        "event_start_time",
        "required",
        "json_number_decimal",
        "unix_epoch_utc_exact_microseconds",
        "reject",
    ),
    "uid": (
        "conversation_id",
        "required",
        "string",
        "strict_identifier",
        "reject",
    ),
}


def _repository_relative(value: str) -> str:
    if "\\" in value:
        raise ValueError("repository path must use POSIX separators")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("repository path must remain inside the repository root")
    if path.as_posix() != value or any(part in ("", ".") for part in path.parts):
        raise ValueError("repository path must already be canonical")
    return value


class ZeekFieldMapping(StrictModel):
    """One exact source-field to FlowEnd-field mapping declaration."""

    source_field: ZeekFieldName
    target_field: CanonicalFieldPath
    presence: Literal["required", "optional"]
    source_type: Literal["json_number_decimal", "string", "integer"]
    transform: Literal[
        "unix_epoch_utc_exact_microseconds",
        "add_exact_microseconds_to_ts",
        "strict_identifier",
        "ip_address",
        "port",
        "non_negative_integer",
        "closed_tcp_udp_transport",
        "single_strict_identifier_or_null",
    ]
    null_policy: Literal["reject", "map_missing_to_null"]

    @model_validator(mode="after")
    def validate_presence_and_null_policy(self) -> "ZeekFieldMapping":
        if self.presence == "required" and self.null_policy != "reject":
            raise ValueError("required fields must reject null and missing values")
        if self.presence == "optional" and self.null_policy != "map_missing_to_null":
            raise ValueError("optional mapped fields must map absence to explicit null")
        return self


class ZeekConnLogMapping(StrictModel):
    """The sole supported Zeek 8.0.9 mapping in M3 Step 1."""

    log_name: Literal["conn.log"]
    classification: Literal["canonical_telemetry"]
    target_model: Literal["FlowEnd"]
    target_event_type: Literal["flow_end"]
    required_fields: Annotated[tuple[ZeekFieldName, ...], Field(min_length=1)]
    optional_mapped_fields: tuple[ZeekFieldName, ...]
    optional_ignored_fields: tuple[ZeekFieldName, ...]
    unknown_field_policy: Literal["reject_record"]
    field_mappings: Annotated[tuple[ZeekFieldMapping, ...], Field(min_length=1)]

    @model_validator(mode="after")
    def validate_exact_conn_contract(self) -> "ZeekConnLogMapping":
        collections = (
            self.required_fields,
            self.optional_mapped_fields,
            self.optional_ignored_fields,
        )
        for values in collections:
            if tuple(sorted(values)) != values or len(set(values)) != len(values):
                raise ValueError("Zeek field collections must be unique and sorted")
        if set(self.required_fields) & set(self.optional_mapped_fields):
            raise ValueError("required and optional mapped fields must be disjoint")
        if (set(self.required_fields) | set(self.optional_mapped_fields)) & set(
            self.optional_ignored_fields
        ):
            raise ValueError("mapped and ignored fields must be disjoint")
        if self.required_fields != _REQUIRED_CONN_FIELDS:
            raise ValueError("conn.log required fields diverge from FlowEnd protocol")
        if self.optional_mapped_fields != _OPTIONAL_MAPPED_CONN_FIELDS:
            raise ValueError("conn.log optional mapped fields must contain only service")
        if self.optional_ignored_fields != _OPTIONAL_IGNORED_CONN_FIELDS:
            raise ValueError("conn.log ignored fields diverge from the frozen protocol")

        sources = tuple(item.source_field for item in self.field_mappings)
        if tuple(sorted(sources)) != sources or len(set(sources)) != len(sources):
            raise ValueError("field mappings must be unique and sorted by source field")
        if set(sources) != set(self.required_fields) | set(
            self.optional_mapped_fields
        ):
            raise ValueError("every mapped field must have exactly one mapping")
        observed = {
            item.source_field: (
                item.target_field,
                item.presence,
                item.source_type,
                item.transform,
                item.null_policy,
            )
            for item in self.field_mappings
        }
        if observed != _EXPECTED_CONN_MAPPINGS:
            raise ValueError("conn.log to FlowEnd mappings are not canonical")
        return self

    @property
    def allowed_fields(self) -> tuple[str, ...]:
        """Return the closed set of source fields accepted by this protocol."""
        return tuple(
            sorted(
                set(self.required_fields)
                | set(self.optional_mapped_fields)
                | set(self.optional_ignored_fields)
            )
        )


class ZeekTimestampPolicy(StrictModel):
    """Exact, non-coercing conversion and availability-time policy."""

    json_number_decoder: Literal["decimal_from_json_lexeme"]
    epoch: Literal["unix"]
    timezone: Literal["UTC"]
    precision: Literal["microseconds"]
    excess_precision_policy: Literal["reject_without_rounding"]
    timestamp_range: Literal["non_negative_finite"]
    duration_range: Literal["non_negative_finite"]
    event_start_time_source: Literal["ts"]
    event_end_time_rule: Literal["ts_plus_duration"]
    record_available_time_source: Literal["normalization_context"]
    ingested_at_source: Literal["normalization_context"]
    required_temporal_order: Literal[
        "event_start_time_le_event_end_time_le_record_available_time_le_ingested_at"
    ]


class ZeekEventEnvelopePolicy(StrictModel):
    """Constants and version identities required for each future FlowEnd."""

    event_type: Literal["flow_end"]
    sensor_type: Literal["zeek"]
    versions: VersionContract
    normalizer_version: VersionString
    pipeline_version: VersionString
    termination_reason_policy: Literal["explicit_null"]
    byte_counter_semantics: Literal["zeek_payload_bytes"]
    supported_transports: tuple[Literal["tcp", "udp"], ...]
    service_policy: Literal[
        "missing_or_null_to_null_single_identifier_only_reject_comma_list"
    ]

    @model_validator(mode="after")
    def validate_frozen_versions(self) -> "ZeekEventEnvelopePolicy":
        expected = VersionContract(
            schema_version="1.0.0",
            event_version="1.0.0",
            feature_version="1.0.0",
            sensor_version="8.0.9",
        )
        if self.versions != expected:
            raise ValueError("canonical output versions must match the M3 freeze")
        if self.normalizer_version != "1.0.0" or self.pipeline_version != "1.0.0":
            raise ValueError("normalizer and pipeline versions must be 1.0.0")
        if self.supported_transports != ("tcp", "udp"):
            raise ValueError("initial conn protocol supports only tcp and udp")
        return self


class ZeekProvenancePolicy(StrictModel):
    """Deterministic source lineage mapped into existing EventProvenance."""

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
    source_coordinate: Literal[
        "output_partition_log_name_physical_line_number_one_based"
    ]

    @model_validator(mode="after")
    def validate_event_identity_recipe(self) -> "ZeekProvenancePolicy":
        expected = (
            "protocol_sha256",
            "replay_report_content_sha256",
            "source_log_sha256",
            "output_partition",
            "log_name",
            "physical_line_number",
        )
        if self.event_id_components != expected:
            raise ValueError("event UUIDv5 components must use frozen source identity")
        if self.event_id_namespace != UUID("90b642e0-53d5-5057-80cc-994f89d797b4"):
            raise ValueError("event UUIDv5 namespace does not match M3 protocol")
        return self


class ZeekUnsupportedRecordPolicy(StrictModel):
    """Closed fail-explicit disposition for unsupported sources and records."""

    unsupported_log: Literal["reject_source_with_audit"]
    operational_log: Literal["reject_source_with_audit"]
    malformed_json: Literal["reject_record_with_audit"]
    non_object_json: Literal["reject_record_with_audit"]
    missing_required_field: Literal["reject_record_with_audit"]
    null_required_field: Literal["reject_record_with_audit"]
    unknown_field: Literal["reject_record_with_audit"]
    invalid_field_type: Literal["reject_record_with_audit"]
    non_finite_number: Literal["reject_record_with_audit"]
    excess_timestamp_precision: Literal["reject_record_with_audit"]
    unsupported_transport: Literal["reject_record_with_audit"]
    unsupported_service_cardinality: Literal["reject_record_with_audit"]
    source_binding_mismatch: Literal["reject_source_with_audit"]
    continue_after_record_rejection: Literal[True]
    silent_defaults_forbidden: Literal[True]
    partial_events_forbidden: Literal[True]


class ZeekOrderingPolicy(StrictModel):
    """Stable ordering independent of event values or parser scheduling."""

    partition_order: Literal["replay_report_binding_order"]
    record_order: Literal["physical_jsonl_line_number_ascending"]
    line_number_base: Literal[1]
    cross_partition_order: Literal["concatenate_partitions"]
    sort_by_event_time: Literal[False]
    sort_by_uid: Literal[False]
    deduplicate_records: Literal[False]
    rejected_records_retain_coordinates: Literal[True]


class ZeekParserBoundaryPolicy(StrictModel):
    """Frozen separation between transport parsing and normalization."""

    parser_input: Literal["one_utf8_json_object_line_plus_source_coordinate"]
    parser_output: Literal["raw_sensor_record_or_explicit_rejection"]
    normalizer_input: Literal["raw_sensor_record_plus_normalization_context"]
    normalizer_output: Literal["FlowEnd_or_explicit_rejection"]
    parser_creates_events: Literal[False]
    parser_persists_output: Literal[False]
    normalizer_reads_files: Literal[False]
    normalizer_persists_output: Literal[False]
    feature_engineering_allowed: Literal[False]


class ZeekReplayReportBinding(StrictModel):
    """Exact M2 report and supported conn.log identity for one partition."""

    report_relative_path: RepositoryRelativePath
    report_file_sha256: Sha256Digest
    report_content_sha256: Sha256Digest
    output_partition: StrictIdentifier
    input: PcapEvidenceFile
    supported_log: ZeekLogArtifact

    @field_validator("report_relative_path")
    @classmethod
    def validate_report_path(cls, value: str) -> str:
        value = _repository_relative(value)
        if not value.endswith("/replay_run.json"):
            raise ValueError("replay report path must end with replay_run.json")
        return value

    @model_validator(mode="after")
    def validate_supported_log(self) -> "ZeekReplayReportBinding":
        if self.supported_log.log_name != "conn.log":
            raise ValueError("M3 Step 1 binds only conn.log")
        if self.supported_log.classification != "canonical_telemetry":
            raise ValueError("supported log must be canonical telemetry")
        if self.supported_log.record_count <= 0 or self.supported_log.size_bytes <= 0:
            raise ValueError("supported conn.log must be non-empty")
        expected_partition = (
            f"{self.input.capture_date.isoformat()}_"
            f"{PurePosixPath(self.input.relative_path).stem}"
        )
        if self.output_partition != expected_partition:
            raise ValueError("partition identity does not match input PCAP")
        return self


class ZeekNormalizationSpecification(StrictModel):
    """Immutable M3 Step 1 protocol bound to frozen M1 and M2 evidence."""

    protocol_version: VersionString
    frozen_at: UtcDateTime
    dataset_name: StrictIdentifier
    m1_manifest_sha256: Sha256Digest
    m2_specification_path: RepositoryRelativePath
    m2_specification_sha256: Sha256Digest
    m2_output_root: RepositoryRelativePath
    sensor_type: Literal["zeek"]
    sensor_version: Literal["8.0.9"]
    input_format: Literal["json_lines"]
    replay_reports: Annotated[
        tuple[ZeekReplayReportBinding, ...],
        Field(min_length=1),
    ]
    log_mappings: Annotated[tuple[ZeekConnLogMapping, ...], Field(min_length=1)]
    timestamps: ZeekTimestampPolicy
    event_envelope: ZeekEventEnvelopePolicy
    provenance: ZeekProvenancePolicy
    unsupported_records: ZeekUnsupportedRecordPolicy
    ordering: ZeekOrderingPolicy
    boundaries: ZeekParserBoundaryPolicy
    authoritative_sources: Annotated[tuple[NonEmptyText, ...], Field(min_length=1)]

    @field_validator("m2_specification_path", "m2_output_root")
    @classmethod
    def validate_repository_path(cls, value: str) -> str:
        return _repository_relative(value)

    @field_validator("authoritative_sources")
    @classmethod
    def validate_sources(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if tuple(sorted(value)) != value or len(set(value)) != len(value):
            raise ValueError("authoritative_sources must be unique and sorted")
        if any(not source.startswith("https://") for source in value):
            raise ValueError("authoritative sources must use HTTPS")
        return value

    @model_validator(mode="after")
    def validate_protocol_bindings(self) -> "ZeekNormalizationSpecification":
        if self.protocol_version != "1.0.0":
            raise ValueError("initial M3 protocol_version must be 1.0.0")
        if not self.m2_specification_path.endswith((".yaml", ".yml")):
            raise ValueError("M2 specification path must use a YAML suffix")
        if not self.m2_output_root.startswith("artifacts/canonical/"):
            raise ValueError("M2 output root must remain in artifacts/canonical")
        if self.event_envelope.versions.sensor_version != self.sensor_version:
            raise ValueError("event sensor version must equal the bound Zeek version")
        if len(self.log_mappings) != 1 or self.log_mappings[0].log_name != "conn.log":
            raise ValueError("M3 Step 1 supports exactly one conn.log mapping")
        if len(self.replay_reports) != 3:
            raise ValueError("initial M3 protocol requires all three M2 partitions")

        keys = tuple(
            (binding.input.capture_date, binding.input.relative_path)
            for binding in self.replay_reports
        )
        if tuple(sorted(keys)) != keys or len(set(keys)) != len(keys):
            raise ValueError("replay report bindings must use unique M1 order")
        paths = tuple(binding.report_relative_path for binding in self.replay_reports)
        if len(set(paths)) != len(paths):
            raise ValueError("replay report paths must be unique")
        prefix = f"{self.m2_output_root}/"
        if any(not path.startswith(prefix) for path in paths):
            raise ValueError("replay reports must remain below the frozen M2 root")
        return self

    @property
    def supported_log_names(self) -> tuple[str, ...]:
        return tuple(mapping.log_name for mapping in self.log_mappings)

    def content_sha256(self) -> str:
        """Return a formatting-independent identity for the M3 protocol."""
        payload = json.dumps(
            self.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        return sha256(payload).hexdigest()


class ZeekSourceCoordinate(StrictModel):
    """Stable location of one future source record without parsing its content."""

    output_partition: StrictIdentifier
    replay_report_content_sha256: Sha256Digest
    log_name: Literal["conn.log"]
    source_log_sha256: Sha256Digest
    reported_record_count: PositiveInt
    physical_line_number: PositiveInt

    @model_validator(mode="after")
    def validate_line_bound(self) -> "ZeekSourceCoordinate":
        if self.physical_line_number > self.reported_record_count:
            raise ValueError("physical line number exceeds reported record count")
        return self


class ZeekNormalizationContext(StrictModel):
    """Externally supplied non-fabricated availability and ingestion context."""

    protocol_sha256: Sha256Digest
    source: ZeekSourceCoordinate
    record_available_time: UtcDateTime
    ingested_at: UtcDateTime

    @model_validator(mode="after")
    def validate_context_time_order(self) -> "ZeekNormalizationContext":
        if self.ingested_at < self.record_available_time:
            raise ValueError("ingested_at cannot precede record_available_time")
        return self
