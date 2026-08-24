"""Deterministic report contracts for concrete M3 conn.log normalization.

Reports retain every rejected physical coordinate as lossless contiguous spans
and bind accepted events through a canonical stream digest.  Canonical events
are never persisted by this contract.
"""
from __future__ import annotations

from hashlib import sha256
import json
from typing import Annotated, Literal, TypeAlias
from uuid import UUID

from pydantic import Field, model_validator

from modules.detection.src.contracts import (
    NonNegativeInt,
    PositiveInt,
    StrictIdentifier,
    StrictModel,
    UtcDateTime,
    VersionString,
)
from modules.detection.src.schemas.datasets import Sha256Digest


ZeekRejectionReason: TypeAlias = Literal[
    "malformed_json",
    "non_object_json",
    "missing_required_field",
    "null_required_field",
    "unknown_field",
    "invalid_field_type",
    "non_finite_number",
    "excess_timestamp_precision",
    "unsupported_transport",
    "unsupported_service_cardinality",
]


class ZeekRejectionCount(StrictModel):
    """Count for one deterministic primary rejection reason."""

    reason: ZeekRejectionReason
    count: PositiveInt


class ZeekRejectionSpan(StrictModel):
    """Lossless compact audit of consecutive identically rejected records."""

    first_physical_line_number: PositiveInt
    last_physical_line_number: PositiveInt
    reason: ZeekRejectionReason
    fields: tuple[StrictIdentifier, ...]

    @model_validator(mode="after")
    def validate_span(self) -> "ZeekRejectionSpan":
        if self.last_physical_line_number < self.first_physical_line_number:
            raise ValueError("rejection span cannot end before it starts")
        if tuple(sorted(self.fields)) != self.fields or len(set(self.fields)) != len(
            self.fields
        ):
            raise ValueError("rejection fields must be unique and sorted")
        return self

    @property
    def record_count(self) -> int:
        return self.last_physical_line_number - self.first_physical_line_number + 1


class ZeekPartitionNormalizationReport(StrictModel):
    """Deterministic full-file result for one frozen M2 conn.log partition."""

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
    rejection_counts: tuple[ZeekRejectionCount, ...]
    rejection_spans: tuple[ZeekRejectionSpan, ...]
    canonical_event_stream_sha256: Sha256Digest
    rejection_audit_stream_sha256: Sha256Digest
    first_accepted_event_id: UUID | None
    last_accepted_event_id: UUID | None

    @model_validator(mode="after")
    def validate_partition_report(self) -> "ZeekPartitionNormalizationReport":
        if self.processed_record_count != self.reported_record_count:
            raise ValueError("full normalization must process the reported record count")
        if self.processed_record_count != (
            self.accepted_record_count + self.rejected_record_count
        ):
            raise ValueError("accepted and rejected counts must cover all records")
        reasons = tuple(item.reason for item in self.rejection_counts)
        if tuple(sorted(reasons)) != reasons or len(set(reasons)) != len(reasons):
            raise ValueError("rejection counts must be unique and sorted by reason")
        if sum(item.count for item in self.rejection_counts) != self.rejected_record_count:
            raise ValueError("rejection reason counts must cover all rejected records")
        if sum(item.record_count for item in self.rejection_spans) != (
            self.rejected_record_count
        ):
            raise ValueError("rejection spans must cover all rejected records")

        previous: ZeekRejectionSpan | None = None
        span_counts: dict[str, int] = {}
        for span in self.rejection_spans:
            if span.last_physical_line_number > self.processed_record_count:
                raise ValueError("rejection span exceeds processed record count")
            if previous is not None:
                if span.first_physical_line_number <= previous.last_physical_line_number:
                    raise ValueError("rejection spans must be strictly ordered")
                if (
                    span.first_physical_line_number
                    == previous.last_physical_line_number + 1
                    and span.reason == previous.reason
                    and span.fields == previous.fields
                ):
                    raise ValueError("adjacent equivalent rejection spans must be merged")
            span_counts[span.reason] = span_counts.get(span.reason, 0) + span.record_count
            previous = span
        declared_counts = {item.reason: item.count for item in self.rejection_counts}
        if span_counts != declared_counts:
            raise ValueError("rejection spans and reason counts disagree")
        if self.accepted_record_count == 0:
            if self.first_accepted_event_id is not None or self.last_accepted_event_id is not None:
                raise ValueError("empty accepted stream cannot declare event IDs")
        elif self.first_accepted_event_id is None or self.last_accepted_event_id is None:
            raise ValueError("non-empty accepted stream requires boundary event IDs")
        return self


class ZeekNormalizationRunReport(StrictModel):
    """Deterministic report for all three frozen M2 conn.log files."""

    report_version: VersionString
    verification_status: Literal["verified"]
    protocol_sha256: Sha256Digest
    m1_manifest_sha256: Sha256Digest
    m2_specification_sha256: Sha256Digest
    dataset_name: StrictIdentifier
    sensor_type: Literal["zeek"]
    sensor_version: VersionString
    normalizer_version: VersionString
    pipeline_version: VersionString
    input_format: Literal["json_lines"]
    record_available_time: UtcDateTime
    ingested_at: UtcDateTime
    partition_reports: Annotated[
        tuple[ZeekPartitionNormalizationReport, ...],
        Field(min_length=1),
    ]
    total_processed_record_count: NonNegativeInt
    total_accepted_record_count: NonNegativeInt
    total_rejected_record_count: NonNegativeInt
    canonical_event_stream_sha256: Sha256Digest
    rejection_audit_stream_sha256: Sha256Digest

    @model_validator(mode="after")
    def validate_run_report(self) -> "ZeekNormalizationRunReport":
        if self.report_version != "1.0.0":
            raise ValueError("initial normalization report version must be 1.0.0")
        if self.normalizer_version != "1.0.0" or self.pipeline_version != "1.0.0":
            raise ValueError("normalizer and pipeline versions must be 1.0.0")
        if self.ingested_at < self.record_available_time:
            raise ValueError("ingested_at cannot precede record_available_time")
        partitions = tuple(item.output_partition for item in self.partition_reports)
        if len(set(partitions)) != len(partitions):
            raise ValueError("normalization partitions must be unique")
        if self.total_processed_record_count != sum(
            item.processed_record_count for item in self.partition_reports
        ):
            raise ValueError("total processed count does not match partitions")
        if self.total_accepted_record_count != sum(
            item.accepted_record_count for item in self.partition_reports
        ):
            raise ValueError("total accepted count does not match partitions")
        if self.total_rejected_record_count != sum(
            item.rejected_record_count for item in self.partition_reports
        ):
            raise ValueError("total rejected count does not match partitions")
        if self.total_processed_record_count != (
            self.total_accepted_record_count + self.total_rejected_record_count
        ):
            raise ValueError("run accepted and rejected counts must cover all records")
        return self

    def content_sha256(self) -> str:
        """Return the formatting-independent deterministic run identity."""
        payload = json.dumps(
            self.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        return sha256(payload).hexdigest()
