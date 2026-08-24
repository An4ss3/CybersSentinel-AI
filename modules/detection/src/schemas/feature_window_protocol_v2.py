"""Strict M6 feature-window protocol and run-report contracts.

The specification model validates the frozen M6 manifest before any window is
built. The run-report model records observed materialization evidence and binds
it to every upstream identity. Neither model modifies M1, M2, M3 v2, M4, or M5.
"""
from __future__ import annotations

from hashlib import sha256
import json
from typing import Annotated, Literal
from uuid import UUID

from pydantic import Field, model_validator

from modules.detection.src.contracts import (
    NonNegativeInt,
    PositiveInt,
    NonEmptyText,
    StrictIdentifier,
    StrictModel,
    UtcDateTime,
    VersionString,
)
from modules.detection.src.schemas.datasets import Sha256Digest
from modules.detection.src.schemas.exact_time_v2 import (
    ExactDecimalSeconds22,
    unscaled_from_canonical,
)
from modules.detection.src.schemas.feature_window_v2 import (
    AUTHORIZED_FEATURE_NAMES,
    NULL_SERVICE_SENTINEL,
)


_EXPECTED_FEATURE_NAMES = AUTHORIZED_FEATURE_NAMES
_EXPECTED_IDENTITY_COMPONENTS = (
    "protocol_sha256",
    "output_partition",
    "entity_type",
    "entity_key_components_in_declared_order",
    "window_start_time",
    "window_length_seconds",
)
_EXPECTED_KEY_COMPONENTS = ("source_ip", "destination_ip", "transport", "service")
_EXPECTED_ORDERING_KEYS = (
    "output_partition",
    "entity_type",
    "entity_key",
    "window_start_time",
)


class FeatureWindowTemporalPolicyV2(StrictModel):
    canonical_type: Literal["DECIMAL(38,22)"]
    json_encoding: Literal["fixed_scale_string_22_fractional_digits"]
    arithmetic: Literal["unscaled_integer"]
    float_conversion: Literal["forbidden"]
    rounding: Literal["forbidden"]
    truncation: Literal["forbidden"]
    datetime_conversion: Literal["forbidden"]
    timedelta_bounds: Literal["forbidden"]
    windowing_basis: Literal["event_start_time"]
    forbidden_windowing_fields: tuple[StrictIdentifier, ...]
    prediction_time_rule: Literal["equals_window_end_time"]
    record_available_time_rule: Literal["inherited_from_source_events"]
    required_order: Literal[
        "window_start_lt_window_end_le_prediction_le_record_available"
    ]

    @model_validator(mode="after")
    def validate_forbidden_fields(self) -> "FeatureWindowTemporalPolicyV2":
        if tuple(sorted(self.forbidden_windowing_fields)) != (
            "ingested_at",
            "record_available_time",
        ):
            raise ValueError("M6 must forbid windowing on availability/ingest time")
        return self


class FeatureWindowGeometryV2(StrictModel):
    type: Literal["tumbling"]
    length_seconds: ExactDecimalSeconds22
    slide_seconds: ExactDecimalSeconds22
    boundary_semantics: Literal["half_open_start_inclusive_end_exclusive"]
    alignment: Literal["floor_to_multiple_of_length_from_unix_epoch"]
    partition_policy: Literal["strictly_intra_partition"]
    cross_partition_windows: Literal[False]
    empty_windows: Literal["forbidden"]
    overlapping_windows: Literal[False]

    @model_validator(mode="after")
    def validate_tumbling_60s(self) -> "FeatureWindowGeometryV2":
        length = unscaled_from_canonical(self.length_seconds)
        slide = unscaled_from_canonical(self.slide_seconds)
        if length != 60 * 10**22:
            raise ValueError("M6 window length must be exactly 60 seconds")
        if slide != length:
            raise ValueError("tumbling windows require slide == length")
        return self


class FeatureWindowEntityPolicyV2(StrictModel):
    entity_type: Literal["source_destination_service"]
    key_components: tuple[StrictIdentifier, ...]
    key_encoding: Literal[
        "ordered_tuple_of_strict_identifiers_one_element_per_component"
    ]
    null_service_sentinel: StrictIdentifier
    null_service_sentinel_collision_scope: Literal[
        "verified_only_for_this_dataset_snapshot"
    ]
    forbidden_entity_types: tuple[StrictIdentifier, ...]

    @model_validator(mode="after")
    def validate_entity_policy(self) -> "FeatureWindowEntityPolicyV2":
        if self.key_components != _EXPECTED_KEY_COMPONENTS:
            raise ValueError("M6 entity key components diverge from the freeze")
        if self.null_service_sentinel != NULL_SERVICE_SENTINEL:
            raise ValueError("M6 null-service sentinel diverges from the freeze")
        if tuple(sorted(self.forbidden_entity_types)) != ("custom", "sensor"):
            raise ValueError("M6 must forbid the sensor and custom entity types")
        return self


class FeatureWindowFeaturePolicyV2(StrictModel):
    count: Literal[8]
    container_type: Literal["mapping_of_strict_identifier_to_finite_float"]
    names: tuple[StrictIdentifier, ...]
    definitions: dict[StrictIdentifier, NonEmptyText]
    forbidden: tuple[NonEmptyText, ...]

    @model_validator(mode="after")
    def validate_feature_policy(self) -> "FeatureWindowFeaturePolicyV2":
        if self.names != _EXPECTED_FEATURE_NAMES:
            raise ValueError(
                "M6 feature names must be exactly the eight authorized, sorted"
            )
        if tuple(sorted(self.definitions)) != _EXPECTED_FEATURE_NAMES:
            raise ValueError("every authorized feature requires one definition")
        return self


class FeatureWindowIdentityPolicyV2(StrictModel):
    algorithm: Literal["uuid5"]
    namespace: UUID
    namespace_derivation: NonEmptyText
    components: tuple[NonEmptyText, ...]
    name_encoding: Literal["utf8_component_values_joined_by_single_ascii_pipe"]
    window_id_rule: Literal["text_form_of_the_uuid5"]
    provenance_event_id_rule: Literal["same_uuid5_as_uuid"]
    random_identifiers: Literal["forbidden"]

    @model_validator(mode="after")
    def validate_identity_policy(self) -> "FeatureWindowIdentityPolicyV2":
        if self.components != _EXPECTED_IDENTITY_COMPONENTS:
            raise ValueError("M6 identity components diverge from the freeze")
        return self


class FeatureWindowProvenancePolicyV2(StrictModel):
    sensor_id: Literal["inherited_from_source_events"]
    sensor_run_id: Literal["inherited_from_source_events"]
    capture_id: Literal["inherited_from_source_events"]
    dataset_snapshot_id: Literal["inherited_from_source_events"]
    model_release_id: Literal["inherited_from_source_events"]
    normalizer_version: Literal["inherited_from_source_events"]
    pipeline_version: Literal["inherited_from_source_events"]
    event_id: Literal["derived_uuid5_per_identity_policy"]
    fabricated_placeholder_values: Literal["forbidden"]
    homogeneity_requirement: Literal[
        "all_inherited_fields_must_be_identical_across_window_events"
    ]


class FeatureWindowLabelPolicyV2(StrictModel):
    m5_interaction: Literal["none"]
    label_fields_in_window_contract: Literal["forbidden"]
    forbidden_fields: tuple[StrictIdentifier, ...]
    m5_contract_modification: Literal["forbidden"]

    @model_validator(mode="after")
    def validate_label_policy(self) -> "FeatureWindowLabelPolicyV2":
        required = {
            "attack_family",
            "attack_subtype",
            "disposition",
            "label",
            "labels",
            "target_profiles",
        }
        if not required <= set(self.forbidden_fields):
            raise ValueError("M6 must forbid every M5-derived field name")
        return self


class FeatureWindowDeferredPolicyV2(StrictModel):
    watermark_policy: Literal["deferred_not_introduced_by_m6"]
    late_arrival_policy: Literal["deferred_not_introduced_by_m6"]
    revision_policy: Literal["deferred_not_introduced_by_m6"]


class FeatureWindowOrderingPolicyV2(StrictModel):
    keys: tuple[StrictIdentifier, ...]
    partition_order: Literal["m3_replay_report_binding_order"]
    window_start_comparison: Literal["unscaled_integer"]
    sort_by_feature_value: Literal[False]
    dictionary_or_set_iteration_order: Literal["forbidden"]

    @model_validator(mode="after")
    def validate_ordering(self) -> "FeatureWindowOrderingPolicyV2":
        if self.keys != _EXPECTED_ORDERING_KEYS:
            raise ValueError("M6 canonical ordering keys diverge from the freeze")
        return self


class FeatureWindowPersistencePolicyV2(StrictModel):
    canonical_evidence: Literal["immutable_published_report"]
    operational_projection: Literal["postgresql_schema_m6_canonical"]
    projection_is_reconstructible: Literal[True]
    destructive_modification_of_m4_canonical: Literal["forbidden"]
    test_isolation: Literal["dedicated_test_database_required"]


class FeatureWindowGovernancePolicyV2(StrictModel):
    manifest_frozen_before_materialization: Literal[True]
    run_identity_in_manifest: Literal[False]
    run_identity_location: Literal["materialization_report_only"]
    run_identity_algorithm: Literal["uuid4_at_execution"]
    immutable_publication: Literal["fail_if_exists_fsync_atomic_rename"]
    deterministic_rerun_requirement: Literal["identical_content_sha256"]


class FeatureWindowContractVersionsV2(StrictModel):
    schema_version: Literal["2.0.0"]
    event_version: Literal["2.0.0"]
    feature_version: Literal["2.0.0"]
    sensor_version_source: Literal["inherited_from_source_events"]


class FeatureWindowSpecificationV2(StrictModel):
    """Immutable M6 protocol bound to frozen M1/M2/M3 v2/M4 identities."""

    protocol_version: Literal["2.0.0"]
    milestone: Literal["m6"]
    frozen_at: UtcDateTime
    dataset_name: StrictIdentifier

    m1_manifest_sha256: Sha256Digest
    m2_specification_sha256: Sha256Digest
    m3_protocol_sha256: Sha256Digest
    m3_report_content_sha256: Sha256Digest
    m3_report_file_sha256: Sha256Digest
    m3_event_stream_sha256: Sha256Digest
    m3_rejection_audit_stream_sha256: Sha256Digest
    m4_report_content_sha256: Sha256Digest
    m4_report_file_sha256: Sha256Digest

    source_event_model: Literal["FlowEndV2"]
    source_event_feature_version: Literal["1.0.0"]
    operational_source: Literal["m4_canonical.flow_end_events"]
    evidence_source: Literal["frozen_m2_conn_log_via_m3_v2_protocol"]
    postgresql_is_independent_evidence: Literal[False]

    target_model: Literal["FeatureWindowV2"]
    window_contract_versions: FeatureWindowContractVersionsV2
    feature_window_v1_status: Literal["preserved_unchanged"]

    temporal: FeatureWindowTemporalPolicyV2
    window: FeatureWindowGeometryV2
    entity: FeatureWindowEntityPolicyV2
    features: FeatureWindowFeaturePolicyV2
    identity: FeatureWindowIdentityPolicyV2
    provenance: FeatureWindowProvenancePolicyV2
    labels: FeatureWindowLabelPolicyV2
    deferred: FeatureWindowDeferredPolicyV2
    ordering: FeatureWindowOrderingPolicyV2
    persistence: FeatureWindowPersistencePolicyV2
    governance: FeatureWindowGovernancePolicyV2
    authoritative_sources: Annotated[tuple[NonEmptyText, ...], Field(min_length=1)]

    @model_validator(mode="after")
    def validate_specification(self) -> "FeatureWindowSpecificationV2":
        if tuple(sorted(self.authoritative_sources)) != self.authoritative_sources:
            raise ValueError("authoritative sources must be unique and sorted")
        if any(
            not value.startswith("https://") for value in self.authoritative_sources
        ):
            raise ValueError("authoritative sources must use HTTPS")
        return self

    def content_sha256(self) -> str:
        """Return a formatting-independent identity for the M6 protocol."""
        payload = json.dumps(
            self.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        return sha256(payload).hexdigest()


class FeatureWindowPartitionReportV2(StrictModel):
    """Observed per-partition window materialization counts."""

    output_partition: StrictIdentifier
    source_event_count: NonNegativeInt
    window_count: NonNegativeInt
    entity_count: NonNegativeInt
    first_window_id: StrictIdentifier | None
    last_window_id: StrictIdentifier | None
    window_stream_sha256: Sha256Digest

    @model_validator(mode="after")
    def validate_partition(self) -> "FeatureWindowPartitionReportV2":
        if self.window_count:
            if self.first_window_id is None or self.last_window_id is None:
                raise ValueError("non-empty partition requires boundary window IDs")
        elif self.first_window_id is not None or self.last_window_id is not None:
            raise ValueError("empty partition cannot declare boundary window IDs")
        if self.window_count > self.source_event_count:
            raise ValueError(
                "empty windows are forbidden, so windows cannot exceed events"
            )
        return self


class FeatureWindowRunReportV2(StrictModel):
    """Deterministic evidence for one M6 window materialization run."""

    report_version: Literal["1.0.0"]
    run_id: UUID
    verification_status: Literal["verified"]

    protocol_sha256: Sha256Digest
    m1_manifest_sha256: Sha256Digest
    m2_specification_sha256: Sha256Digest
    m3_protocol_sha256: Sha256Digest
    m3_report_content_sha256: Sha256Digest
    m4_report_content_sha256: Sha256Digest

    dataset_name: StrictIdentifier
    target_model: Literal["FeatureWindowV2"]
    schema_version: Literal["2.0.0"]
    event_version: Literal["2.0.0"]
    feature_version: Literal["2.0.0"]
    sensor_version: VersionString

    entity_type: Literal["source_destination_service"]
    window_length_seconds: ExactDecimalSeconds22
    windowing_basis: Literal["event_start_time"]

    started_at: UtcDateTime
    completed_at: UtcDateTime

    total_source_event_count: NonNegativeInt
    total_window_count: NonNegativeInt
    window_stream_sha256: Sha256Digest

    partition_reports: Annotated[
        tuple[FeatureWindowPartitionReportV2, ...], Field(min_length=1)
    ]

    @model_validator(mode="after")
    def validate_run(self) -> "FeatureWindowRunReportV2":
        if self.completed_at < self.started_at:
            raise ValueError("M6 completed_at precedes started_at")
        if len(self.partition_reports) != 3:
            raise ValueError("M6 run requires exactly three frozen partitions")
        partitions = tuple(item.output_partition for item in self.partition_reports)
        if tuple(sorted(partitions)) != partitions or len(set(partitions)) != len(
            partitions
        ):
            raise ValueError("M6 partitions must be unique and ordered")
        if self.total_source_event_count != sum(
            item.source_event_count for item in self.partition_reports
        ):
            raise ValueError("M6 total source event count mismatch")
        if self.total_window_count != sum(
            item.window_count for item in self.partition_reports
        ):
            raise ValueError("M6 total window count mismatch")
        if unscaled_from_canonical(self.window_length_seconds) != 60 * 10**22:
            raise ValueError("M6 window length must be exactly 60 seconds")
        return self

    def content_sha256(self) -> str:
        """Return the formatting-independent deterministic M6 run identity."""
        payload = json.dumps(
            self.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        return sha256(payload).hexdigest()
