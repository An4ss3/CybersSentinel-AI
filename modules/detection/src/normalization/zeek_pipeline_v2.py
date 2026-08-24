"""Streaming M3 v2 conn.log normalization runner.

Processes the three frozen M2 conn.log partitions in manifest binding order,
streaming each physical line through the strict parser and normalizer.
Accumulates deterministic evidence (counts, rejection spans, SHA-256 digests,
boundary event IDs) without retaining events in memory, then constructs the
verified ZeekNormalizationRunReportV2 and publishes it immutably.

Capabilities:
- Pre-flight source verification (hash + size).
- Deterministic per-partition streaming normalization.
- Canonical event bytes serialization and SHA-256 accumulation.
- Rejection audit bytes serialization and SHA-256 accumulation.
- Per-partition and global digest computation.
- Rejection span merging and reason counting.
- First/last accepted event ID tracking.
- Report construction from accumulated evidence.
- Immutable atomic publication (fail-if-exists, fsync, atomic rename).

Does NOT:
- Persist canonical events (M4 concern).
- Apply feature engineering.
- Modify frozen M1, M2, or v1 artifacts.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from hashlib import sha256
import json
import os
from pathlib import Path
from typing import Any
from uuid import UUID

from modules.detection.src.ingestion.zeek_json_v2 import (
    StrictZeekJsonLineParserV2,
    ZeekRecordRejectionV2,
)
from modules.detection.src.lineage.zeek_normalization_v2 import (
    BoundZeekNormalizationSpecificationV2,
    load_and_bind_zeek_normalization_specification_v2,
)
from modules.detection.src.normalization.zeek_conn_v2 import (
    StrictZeekConnFlowEndNormalizerV2,
    ZeekSourceBindingErrorV2,
)
from modules.detection.src.schemas.events_v2 import FlowEndV2
from modules.detection.src.schemas.exact_time_v2 import ExactDecimalSeconds22
from modules.detection.src.schemas.zeek_normalization import (
    ZeekReplayReportBinding,
    ZeekSourceCoordinate,
)
from modules.detection.src.schemas.zeek_normalization_v2 import (
    ZeekNormalizationContextV2,
    ZeekNormalizationSpecificationV2,
)
from modules.detection.src.schemas.zeek_normalization_run_v2 import (
    ZeekNormalizationRunReportV2,
    ZeekPartitionNormalizationReportV2,
    ZeekRejectionCountV2,
    ZeekRejectionSpanV2,
)


def _canonical_event_bytes(event: FlowEndV2) -> bytes:
    """Stable semantic JSON bytes for stream hashing — not for persistence."""
    return (
        json.dumps(
            event.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        + b"\n"
    )


def _canonical_rejection_bytes(
    source: ZeekSourceCoordinate,
    rejection: ZeekRecordRejectionV2,
) -> bytes:
    """Deterministic rejection audit record for stream hashing."""
    payload = {
        "fields": list(rejection.fields),
        "log_name": source.log_name,
        "output_partition": source.output_partition,
        "physical_line_number": source.physical_line_number,
        "reason": rejection.reason,
        "replay_report_content_sha256": source.replay_report_content_sha256,
        "source_log_sha256": source.source_log_sha256,
    }
    return (
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        + b"\n"
    )


@dataclass(frozen=True, slots=True)
class PartitionResult:
    """Accumulated evidence from processing one conn.log partition."""

    output_partition: str
    replay_report_content_sha256: str
    input_capture_sha256: str
    source_log_sha256: str
    source_size_bytes: int
    reported_record_count: int
    processed_record_count: int
    accepted_record_count: int
    rejected_record_count: int
    rejection_counts: dict[str, int]
    rejection_spans: tuple[dict[str, Any], ...]
    canonical_event_stream_sha256: str
    rejection_audit_stream_sha256: str
    first_accepted_event_id: UUID | None
    last_accepted_event_id: UUID | None


@dataclass(slots=True)
class RunAccumulator:
    """Mutable accumulator for global run-level evidence."""

    global_event_digest: Any = field(default_factory=sha256)
    global_rejection_digest: Any = field(default_factory=sha256)
    partition_results: list[PartitionResult] = field(default_factory=list)
    total_processed: int = 0
    total_accepted: int = 0
    total_rejected: int = 0

    @property
    def canonical_event_stream_sha256(self) -> str:
        return self.global_event_digest.hexdigest()

    @property
    def rejection_audit_stream_sha256(self) -> str:
        return self.global_rejection_digest.hexdigest()


class ZeekConnNormalizationRunnerV2:
    """Stream-process three frozen M2 conn.log files under the v2 protocol."""

    def __init__(
        self,
        repository_root: str | Path,
        bound_specification: BoundZeekNormalizationSpecificationV2,
        record_available_time: ExactDecimalSeconds22,
        ingested_at: ExactDecimalSeconds22,
    ) -> None:
        self._root = Path(repository_root).resolve(strict=True)
        self._bound = bound_specification
        self._specification = bound_specification.specification
        self._protocol_sha256 = bound_specification.specification_sha256
        self._record_available_time = record_available_time
        self._ingested_at = ingested_at

        # Validate temporal ordering at construction
        from modules.detection.src.schemas.exact_time_v2 import unscaled_from_canonical

        if unscaled_from_canonical(ingested_at) < unscaled_from_canonical(
            record_available_time
        ):
            raise ValueError("ingested_at cannot precede record_available_time")

        self._parser = StrictZeekJsonLineParserV2()
        self._normalizer = StrictZeekConnFlowEndNormalizerV2(self._specification)

    @classmethod
    def from_repository(
        cls,
        repository_root: str | Path,
        record_available_time: ExactDecimalSeconds22,
        ingested_at: ExactDecimalSeconds22,
    ) -> "ZeekConnNormalizationRunnerV2":
        """Load, bind, and construct the runner from the repository root."""
        root = Path(repository_root).resolve(strict=True)
        bound = load_and_bind_zeek_normalization_specification_v2(root)
        return cls(root, bound, record_available_time, ingested_at)

    def _source_path(self, binding: ZeekReplayReportBinding) -> Path:
        """Resolve and validate the bound conn.log path."""
        candidate = (
            self._root
            / self._specification.m2_output_root
            / binding.output_partition
            / binding.supported_log.log_name
        ).resolve(strict=True)
        try:
            candidate.relative_to(self._root)
        except ValueError as error:
            raise ZeekSourceBindingErrorV2(
                "bound conn.log resolves outside repository root"
            ) from error
        return candidate

    def _preflight_verify(self, binding: ZeekReplayReportBinding) -> Path:
        """Verify source file hash and size; return resolved path."""
        path = self._source_path(binding)
        artifact = binding.supported_log
        digest = sha256()
        size = 0
        with path.open("rb") as stream:
            while chunk := stream.read(8 * 1024 * 1024):
                digest.update(chunk)
                size += len(chunk)
        if size != artifact.size_bytes:
            raise ZeekSourceBindingErrorV2(
                f"conn.log size mismatch: expected {artifact.size_bytes}, got {size}"
            )
        if digest.hexdigest() != artifact.sha256:
            raise ZeekSourceBindingErrorV2(
                "conn.log hash does not match frozen binding"
            )
        return path

    @staticmethod
    def _append_rejection_span(
        spans: list[dict[str, Any]],
        line_number: int,
        rejection: ZeekRecordRejectionV2,
    ) -> None:
        """Merge adjacent spans with identical (reason, fields) or append new."""
        fields = rejection.fields
        if (
            spans
            and spans[-1]["last_physical_line_number"] + 1 == line_number
            and spans[-1]["reason"] == rejection.reason
            and spans[-1]["fields"] == fields
        ):
            spans[-1]["last_physical_line_number"] = line_number
            return
        spans.append(
            {
                "first_physical_line_number": line_number,
                "last_physical_line_number": line_number,
                "reason": rejection.reason,
                "fields": fields,
            }
        )

    def process_partition(
        self,
        binding: ZeekReplayReportBinding,
        accumulator: RunAccumulator,
    ) -> PartitionResult:
        """Stream one verified partition, accumulate evidence, discard events."""
        path = self._preflight_verify(binding)
        artifact = binding.supported_log

        partition_event_digest = sha256()
        partition_rejection_digest = sha256()
        source_verification_digest = sha256()
        rejection_counts: Counter[str] = Counter()
        rejection_spans: list[dict[str, Any]] = []
        accepted = 0
        rejected = 0
        processed = 0
        first_event_id: UUID | None = None
        last_event_id: UUID | None = None

        with path.open("rb") as stream:
            for physical_line_number, line in enumerate(stream, start=1):
                source_verification_digest.update(line)

                if physical_line_number > artifact.record_count:
                    raise ZeekSourceBindingErrorV2(
                        "conn.log contains more lines than its frozen report"
                    )

                processed = physical_line_number
                source = ZeekSourceCoordinate(
                    output_partition=binding.output_partition,
                    replay_report_content_sha256=binding.report_content_sha256,
                    log_name="conn.log",
                    source_log_sha256=artifact.sha256,
                    reported_record_count=artifact.record_count,
                    physical_line_number=physical_line_number,
                )
                context = ZeekNormalizationContextV2(
                    protocol_sha256=self._protocol_sha256,
                    source=source,
                    record_available_time=self._record_available_time,
                    ingested_at=self._ingested_at,
                )

                try:
                    record = self._parser.parse_line(line, source)
                    event = self._normalizer.normalize_conn(record, context)
                except ZeekRecordRejectionV2 as rejection:
                    rejected += 1
                    rejection_counts[rejection.reason] += 1
                    self._append_rejection_span(
                        rejection_spans, physical_line_number, rejection
                    )
                    payload = _canonical_rejection_bytes(source, rejection)
                    partition_rejection_digest.update(payload)
                    accumulator.global_rejection_digest.update(payload)
                    continue

                # Accepted event — hash and discard
                accepted += 1
                event_id = event.provenance.event_id
                if first_event_id is None:
                    first_event_id = event_id
                last_event_id = event_id

                payload = _canonical_event_bytes(event)
                partition_event_digest.update(payload)
                accumulator.global_event_digest.update(payload)

        # Post-processing verification
        if processed != artifact.record_count:
            raise ZeekSourceBindingErrorV2(
                f"conn.log line count mismatch: expected {artifact.record_count}, "
                f"got {processed}"
            )
        if source_verification_digest.hexdigest() != artifact.sha256:
            raise ZeekSourceBindingErrorV2(
                "conn.log bytes changed between pre-flight and processing"
            )

        result = PartitionResult(
            output_partition=binding.output_partition,
            replay_report_content_sha256=binding.report_content_sha256,
            input_capture_sha256=binding.input.sha256,
            source_log_sha256=artifact.sha256,
            source_size_bytes=artifact.size_bytes,
            reported_record_count=artifact.record_count,
            processed_record_count=processed,
            accepted_record_count=accepted,
            rejected_record_count=rejected,
            rejection_counts=dict(rejection_counts),
            rejection_spans=tuple(rejection_spans),
            canonical_event_stream_sha256=partition_event_digest.hexdigest(),
            rejection_audit_stream_sha256=partition_rejection_digest.hexdigest(),
            first_accepted_event_id=first_event_id,
            last_accepted_event_id=last_event_id,
        )

        accumulator.partition_results.append(result)
        accumulator.total_processed += processed
        accumulator.total_accepted += accepted
        accumulator.total_rejected += rejected

        return result

    def run_all_partitions(self) -> RunAccumulator:
        """Process all three partitions in frozen manifest order.

        Returns the accumulated evidence suitable for report construction.
        Does not construct or publish the final report.
        """
        accumulator = RunAccumulator()
        for binding in self._specification.replay_reports:
            self.process_partition(binding, accumulator)
        return accumulator

    # ------------------------------------------------------------------
    # Phase 2: report construction and publication
    # ------------------------------------------------------------------

    @staticmethod
    def _build_partition_report(
        result: PartitionResult,
    ) -> ZeekPartitionNormalizationReportV2:
        """Convert one PartitionResult into its validated contract form."""
        return ZeekPartitionNormalizationReportV2(
            output_partition=result.output_partition,
            replay_report_content_sha256=result.replay_report_content_sha256,
            input_capture_sha256=result.input_capture_sha256,
            log_name="conn.log",
            source_log_sha256=result.source_log_sha256,
            source_size_bytes=result.source_size_bytes,
            reported_record_count=result.reported_record_count,
            source_verified=True,
            processed_record_count=result.processed_record_count,
            accepted_record_count=result.accepted_record_count,
            rejected_record_count=result.rejected_record_count,
            rejection_counts=tuple(
                ZeekRejectionCountV2(reason=reason, count=count)
                for reason, count in sorted(result.rejection_counts.items())
            ),
            rejection_spans=tuple(
                ZeekRejectionSpanV2.model_validate(span)
                for span in result.rejection_spans
            ),
            canonical_event_stream_sha256=result.canonical_event_stream_sha256,
            rejection_audit_stream_sha256=result.rejection_audit_stream_sha256,
            first_accepted_event_id=result.first_accepted_event_id,
            last_accepted_event_id=result.last_accepted_event_id,
        )

    def _build_run_report(
        self, accumulator: RunAccumulator
    ) -> ZeekNormalizationRunReportV2:
        """Construct the full validated run report from accumulated evidence."""
        partition_reports = tuple(
            self._build_partition_report(result)
            for result in accumulator.partition_results
        )
        return ZeekNormalizationRunReportV2(
            report_version="2.0.0",
            verification_status="verified",
            protocol_sha256=self._protocol_sha256,
            supersedes_protocol_sha256=self._specification.supersedes_protocol_sha256,
            m1_manifest_sha256=self._bound.m1_manifest_sha256,
            m2_specification_sha256=self._bound.m2_specification_sha256,
            dataset_name=self._specification.dataset_name,
            sensor_type="zeek",
            sensor_version="8.0.9",
            schema_version="2.0.0",
            event_version="2.0.0",
            feature_version="1.0.0",
            normalizer_version="2.0.0",
            pipeline_version="2.0.0",
            temporal_encoding="DECIMAL(38,22)_fixed_scale_string",
            record_available_time=self._record_available_time,
            ingested_at=self._ingested_at,
            partition_reports=partition_reports,
            total_processed_record_count=accumulator.total_processed,
            total_accepted_record_count=accumulator.total_accepted,
            total_rejected_record_count=accumulator.total_rejected,
            canonical_event_stream_sha256=accumulator.canonical_event_stream_sha256,
            rejection_audit_stream_sha256=accumulator.rejection_audit_stream_sha256,
        )

    def run(self) -> ZeekNormalizationRunReportV2:
        """Execute the full normalization pipeline and return validated report.

        Orchestration order:
        1. run_all_partitions() — preflight + streaming normalization
        2. Build partition reports from accumulated evidence
        3. Build and validate the run report
        4. Return the validated report (publication is a separate step)
        """
        accumulator = self.run_all_partitions()
        return self._build_run_report(accumulator)


def write_immutable_normalization_report_v2(
    report: ZeekNormalizationRunReportV2,
    path: str | Path,
) -> str:
    """Publish the verified report immutably. Returns SHA-256 of written bytes.

    Guarantees:
    - Fails rather than overwriting an existing file.
    - Uses exclusive-create + fsync + atomic rename for publication.
    - Cleans up staging file in all cases.
    """
    destination = Path(path)
    if destination.exists():
        raise FileExistsError(
            f"normalization report already exists: {destination}"
        )
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = report.model_dump_json(indent=2).encode("utf-8") + b"\n"
    temporary = destination.with_name(f".{destination.name}.tmp")
    if temporary.exists():
        raise FileExistsError(
            f"normalization report staging path exists: {temporary}"
        )
    try:
        with temporary.open("xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    except BaseException:
        if temporary.exists():
            temporary.unlink()
        raise
    return sha256(payload).hexdigest()
