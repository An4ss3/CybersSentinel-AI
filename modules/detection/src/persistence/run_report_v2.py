"""M4 materialization report contract.

Records what M4 materialized, bound to the frozen M3 v2 evidence it was
verified against. Mirrors the M3 v2 report philosophy: strict contract,
self-validating invariants, and a formatting-independent content identity.

This contract introduces no semantics beyond the authorized M4 decisions and
the frozen M3 v2 evidence it echoes.
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
    StrictIdentifier,
    StrictModel,
    UtcDateTime,
)
from modules.detection.src.schemas.datasets import Sha256Digest


class M4PartitionMaterializationCountsV2(StrictModel):
    """Observed per-partition materialization counts for one frozen partition."""

    output_partition: StrictIdentifier
    source_log_sha256: Sha256Digest
    reported_record_count: PositiveInt
    processed_record_count: NonNegativeInt
    accepted_record_count: NonNegativeInt
    rejected_record_count: NonNegativeInt
    persisted_event_count: NonNegativeInt

    @model_validator(mode="after")
    def validate_counts(self) -> "M4PartitionMaterializationCountsV2":
        if self.processed_record_count != self.reported_record_count:
            raise ValueError(
                "M4 partition must process the frozen reported record count"
            )
        if self.processed_record_count != (
            self.accepted_record_count + self.rejected_record_count
        ):
            raise ValueError("M4 partition accepted/rejected counts do not cover source")
        if self.persisted_event_count != self.accepted_record_count:
            raise ValueError(
                "M4 must persist exactly one canonical event per accepted record"
            )
        return self


class M4MaterializationReportV2(StrictModel):
    """Deterministic evidence for one M4 canonical materialization run."""

    report_version: Literal["1.0.0"]
    run_id: UUID
    verification_status: Literal["verified", "failed"]

    # Frozen M3 v2 binding — echoed from the verified frozen report
    m3_report_content_sha256: Sha256Digest
    m3_report_file_sha256: Sha256Digest
    m3_protocol_sha256: Sha256Digest
    m3_event_stream_sha256: Sha256Digest
    m3_rejection_audit_stream_sha256: Sha256Digest

    # Observed totals
    total_processed_record_count: NonNegativeInt
    total_accepted_record_count: NonNegativeInt
    total_rejected_record_count: NonNegativeInt
    total_persisted_event_count: NonNegativeInt

    # Independently recomputed during materialization
    materialized_event_stream_sha256: Sha256Digest
    materialized_rejection_stream_sha256: Sha256Digest

    started_at: UtcDateTime
    completed_at: UtcDateTime

    partition_counts: Annotated[
        tuple[M4PartitionMaterializationCountsV2, ...], Field(min_length=1)
    ]

    @model_validator(mode="after")
    def validate_run(self) -> "M4MaterializationReportV2":
        if self.completed_at < self.started_at:
            raise ValueError("M4 completed_at precedes started_at")

        if len(self.partition_counts) != 3:
            raise ValueError("M4 run requires exactly three frozen partitions")

        partitions = tuple(item.output_partition for item in self.partition_counts)
        if tuple(sorted(partitions)) != partitions or len(set(partitions)) != len(
            partitions
        ):
            raise ValueError("M4 partitions must be unique and ordered")

        if self.total_processed_record_count != sum(
            item.processed_record_count for item in self.partition_counts
        ):
            raise ValueError("M4 total processed mismatch")
        if self.total_accepted_record_count != sum(
            item.accepted_record_count for item in self.partition_counts
        ):
            raise ValueError("M4 total accepted mismatch")
        if self.total_rejected_record_count != sum(
            item.rejected_record_count for item in self.partition_counts
        ):
            raise ValueError("M4 total rejected mismatch")
        if self.total_persisted_event_count != sum(
            item.persisted_event_count for item in self.partition_counts
        ):
            raise ValueError("M4 total persisted event count mismatch")
        if self.total_processed_record_count != (
            self.total_accepted_record_count + self.total_rejected_record_count
        ):
            raise ValueError("M4 totals do not cover source")

        # A verified run must reproduce the frozen M3 v2 stream identities exactly.
        if self.verification_status == "verified":
            if self.materialized_event_stream_sha256 != self.m3_event_stream_sha256:
                raise ValueError(
                    "verified M4 run must reproduce the frozen event stream digest"
                )
            if (
                self.materialized_rejection_stream_sha256
                != self.m3_rejection_audit_stream_sha256
            ):
                raise ValueError(
                    "verified M4 run must reproduce the frozen rejection digest"
                )
        return self

    def content_sha256(self) -> str:
        """Return the formatting-independent deterministic M4 run identity."""
        payload = json.dumps(
            self.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        return sha256(payload).hexdigest()
