"""Deterministic M3 v2 normalization report contracts."""
from __future__ import annotations

from hashlib import sha256
import json
from typing import Annotated, Literal, TypeAlias
from uuid import UUID

from pydantic import Field, model_validator

from modules.detection.src.contracts import (
    NonNegativeInt, PositiveInt, StrictIdentifier, StrictModel,
)
from modules.detection.src.schemas.datasets import Sha256Digest
from modules.detection.src.schemas.exact_time_v2 import (
    ExactDecimalSeconds22,
    unscaled_from_canonical,
)


ZeekRejectionReasonV2: TypeAlias = Literal[
    "malformed_json", "non_object_json", "missing_required_field",
    "null_required_field", "unknown_field", "invalid_field_type",
    "non_finite_number", "decimal38_22_range_or_scale",
    "unsupported_transport", "unsupported_service_cardinality",
]


class ZeekRejectionCountV2(StrictModel):
    reason: ZeekRejectionReasonV2
    count: PositiveInt


class ZeekRejectionSpanV2(StrictModel):
    first_physical_line_number: PositiveInt
    last_physical_line_number: PositiveInt
    reason: ZeekRejectionReasonV2
    fields: tuple[StrictIdentifier, ...]

    @model_validator(mode="after")
    def validate_span(self) -> "ZeekRejectionSpanV2":
        if self.last_physical_line_number < self.first_physical_line_number:
            raise ValueError("v2 rejection span ends before it starts")
        if tuple(sorted(self.fields)) != self.fields or len(set(self.fields)) != len(self.fields):
            raise ValueError("v2 rejection fields must be unique and sorted")
        return self

    @property
    def record_count(self) -> int:
        return self.last_physical_line_number - self.first_physical_line_number + 1


class ZeekPartitionNormalizationReportV2(StrictModel):
    output_partition: StrictIdentifier
    replay_report_content_sha256: Sha256Digest
    input_capture_sha256: Sha256Digest
    log_name: Literal["conn.log"]
    source_log_sha256: Sha256Digest
    source_size_bytes: NonNegativeInt
    reported_record_count: PositiveInt
    source_verified: Literal[True]
    processed_record_count: NonNegativeInt
    accepted_record_count: NonNegativeInt
    rejected_record_count: NonNegativeInt
    rejection_counts: tuple[ZeekRejectionCountV2, ...]
    rejection_spans: tuple[ZeekRejectionSpanV2, ...]
    canonical_event_stream_sha256: Sha256Digest
    rejection_audit_stream_sha256: Sha256Digest
    first_accepted_event_id: UUID | None
    last_accepted_event_id: UUID | None

    @model_validator(mode="after")
    def validate_report(self) -> "ZeekPartitionNormalizationReportV2":
        if self.processed_record_count != self.reported_record_count:
            raise ValueError("v2 full run must process reported count")
        if self.processed_record_count != self.accepted_record_count + self.rejected_record_count:
            raise ValueError("v2 accepted/rejected counts do not cover source")
        reasons = tuple(item.reason for item in self.rejection_counts)
        if tuple(sorted(reasons)) != reasons or len(set(reasons)) != len(reasons):
            raise ValueError("v2 rejection counts must be unique and sorted")
        if sum(item.count for item in self.rejection_counts) != self.rejected_record_count:
            raise ValueError("v2 rejection counts do not cover rejections")
        if sum(item.record_count for item in self.rejection_spans) != self.rejected_record_count:
            raise ValueError("v2 rejection spans do not cover rejections")
        span_counts: dict[str, int] = {}
        previous: ZeekRejectionSpanV2 | None = None
        for span in self.rejection_spans:
            if span.last_physical_line_number > self.processed_record_count:
                raise ValueError("v2 rejection span exceeds source")
            if previous is not None:
                if span.first_physical_line_number <= previous.last_physical_line_number:
                    raise ValueError("v2 rejection spans overlap or are unordered")
                if (
                    span.first_physical_line_number == previous.last_physical_line_number + 1
                    and span.reason == previous.reason and span.fields == previous.fields
                ):
                    raise ValueError("v2 adjacent equal spans must be merged")
            span_counts[span.reason] = span_counts.get(span.reason, 0) + span.record_count
            previous = span
        if span_counts != {item.reason: item.count for item in self.rejection_counts}:
            raise ValueError("v2 rejection spans/counts disagree")
        if self.accepted_record_count:
            if self.first_accepted_event_id is None or self.last_accepted_event_id is None:
                raise ValueError("v2 accepted stream requires boundary IDs")
        elif self.first_accepted_event_id is not None or self.last_accepted_event_id is not None:
            raise ValueError("v2 empty accepted stream cannot have IDs")
        return self


class ZeekNormalizationRunReportV2(StrictModel):
    report_version: Literal["2.0.0"]
    verification_status: Literal["verified"]
    protocol_sha256: Sha256Digest
    supersedes_protocol_sha256: Sha256Digest
    m1_manifest_sha256: Sha256Digest
    m2_specification_sha256: Sha256Digest
    dataset_name: StrictIdentifier
    sensor_type: Literal["zeek"]
    sensor_version: Literal["8.0.9"]
    schema_version: Literal["2.0.0"]
    event_version: Literal["2.0.0"]
    feature_version: Literal["1.0.0"]
    normalizer_version: Literal["2.0.0"]
    pipeline_version: Literal["2.0.0"]
    temporal_encoding: Literal["DECIMAL(38,22)_fixed_scale_string"]
    record_available_time: ExactDecimalSeconds22
    ingested_at: ExactDecimalSeconds22
    partition_reports: Annotated[
        tuple[ZeekPartitionNormalizationReportV2, ...], Field(min_length=1)
    ]
    total_processed_record_count: NonNegativeInt
    total_accepted_record_count: NonNegativeInt
    total_rejected_record_count: NonNegativeInt
    canonical_event_stream_sha256: Sha256Digest
    rejection_audit_stream_sha256: Sha256Digest

    @model_validator(mode="after")
    def validate_run(self) -> "ZeekNormalizationRunReportV2":
        if unscaled_from_canonical(self.ingested_at) < unscaled_from_canonical(
            self.record_available_time
        ):
            raise ValueError("v2 ingested_at precedes record_available_time")
        if len(self.partition_reports) != 3:
            raise ValueError("v2 run requires exactly three partitions")
        partitions = tuple(item.output_partition for item in self.partition_reports)
        if tuple(sorted(partitions)) != partitions or len(set(partitions)) != len(partitions):
            raise ValueError("v2 partitions must be unique and ordered")
        if self.total_processed_record_count != sum(item.processed_record_count for item in self.partition_reports):
            raise ValueError("v2 total processed mismatch")
        if self.total_accepted_record_count != sum(item.accepted_record_count for item in self.partition_reports):
            raise ValueError("v2 total accepted mismatch")
        if self.total_rejected_record_count != sum(item.rejected_record_count for item in self.partition_reports):
            raise ValueError("v2 total rejected mismatch")
        if self.total_processed_record_count != self.total_accepted_record_count + self.total_rejected_record_count:
            raise ValueError("v2 totals do not cover source")
        return self

    def content_sha256(self) -> str:
        payload = json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return sha256(payload).hexdigest()
