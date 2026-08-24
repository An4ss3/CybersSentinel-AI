"""Streaming M3 Step 2 conn.log normalization runner.

The runner verifies each frozen source, reads one physical line at a time,
constructs and validates accepted FlowEnd objects, and retains only deterministic
hash/statistical evidence.  It never persists canonical events.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime
from hashlib import sha256
import json
import os
from pathlib import Path
from typing import Any
from uuid import UUID

from pydantic import TypeAdapter

from modules.detection.src.contracts import UtcDateTime
from modules.detection.src.ingestion.zeek_json import (
    StrictZeekJsonLineParser,
    ZeekRecordRejection,
)
from modules.detection.src.lineage.zeek_normalization import (
    BoundZeekNormalizationSpecification,
    load_and_bind_zeek_normalization_specification,
)
from modules.detection.src.normalization.zeek_conn import (
    StrictZeekConnFlowEndNormalizer,
    ZeekSourceBindingError,
)
from modules.detection.src.schemas.events import FlowEnd
from modules.detection.src.schemas.zeek_normalization import (
    ZeekNormalizationContext,
    ZeekReplayReportBinding,
    ZeekSourceCoordinate,
)
from modules.detection.src.schemas.zeek_normalization_run import (
    ZeekNormalizationRunReport,
    ZeekPartitionNormalizationReport,
    ZeekRejectionCount,
    ZeekRejectionSpan,
)


_UTC_DATETIME_ADAPTER = TypeAdapter(UtcDateTime)


def canonical_event_bytes(event: FlowEnd) -> bytes:
    """Return stable semantic JSON bytes used only for stream hashing."""
    return json.dumps(
        event.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8") + b"\n"


def _canonical_rejection_bytes(
    source: ZeekSourceCoordinate,
    rejection: ZeekRecordRejection,
) -> bytes:
    payload = {
        "fields": list(rejection.fields),
        "log_name": source.log_name,
        "output_partition": source.output_partition,
        "physical_line_number": source.physical_line_number,
        "reason": rejection.reason,
        "replay_report_content_sha256": source.replay_report_content_sha256,
        "source_log_sha256": source.source_log_sha256,
    }
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8") + b"\n"


def _sha256_stream(stream: Any) -> tuple[str, int]:
    digest = sha256()
    size_bytes = 0
    while chunk := stream.read(8 * 1024 * 1024):
        digest.update(chunk)
        size_bytes += len(chunk)
    return digest.hexdigest(), size_bytes


class ZeekConnNormalizationRunner:
    """Normalize the three bound conn.log files in report/physical-line order."""

    def __init__(
        self,
        repository_root: str | Path,
        bound_specification: BoundZeekNormalizationSpecification,
        record_available_time: datetime,
        ingested_at: datetime,
    ) -> None:
        self._root = Path(repository_root).resolve(strict=True)
        self._bound = bound_specification
        self._specification = bound_specification.specification
        self._record_available_time = _UTC_DATETIME_ADAPTER.validate_python(
            record_available_time,
            strict=True,
        )
        self._ingested_at = _UTC_DATETIME_ADAPTER.validate_python(
            ingested_at,
            strict=True,
        )
        if self._ingested_at < self._record_available_time:
            raise ValueError("ingested_at cannot precede record_available_time")
        self._parser = StrictZeekJsonLineParser()
        self._normalizer = StrictZeekConnFlowEndNormalizer(self._specification)

    @classmethod
    def from_repository(
        cls,
        repository_root: str | Path,
        record_available_time: datetime,
        ingested_at: datetime,
    ) -> "ZeekConnNormalizationRunner":
        root = Path(repository_root).resolve(strict=True)
        return cls(
            root,
            load_and_bind_zeek_normalization_specification(root),
            record_available_time,
            ingested_at,
        )

    def _source_path(self, binding: ZeekReplayReportBinding) -> Path:
        candidate = (
            self._root
            / self._specification.m2_output_root
            / binding.output_partition
            / binding.supported_log.log_name
        ).resolve(strict=True)
        try:
            candidate.relative_to(self._root)
        except ValueError as error:
            raise ZeekSourceBindingError(
                "bound conn.log resolves outside repository root"
            ) from error
        return candidate

    @staticmethod
    def _append_rejection_span(
        spans: list[dict[str, Any]],
        line_number: int,
        rejection: ZeekRecordRejection,
    ) -> None:
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

    def normalize_partition(
        self,
        binding: ZeekReplayReportBinding,
        global_event_digest: Any | None = None,
        global_rejection_digest: Any | None = None,
    ) -> ZeekPartitionNormalizationReport:
        """Verify and stream one complete bound source without event retention."""
        path = self._source_path(binding)
        artifact = binding.supported_log
        event_digest = sha256()
        rejection_digest = sha256()
        processed_source_digest = sha256()
        rejection_counts: Counter[str] = Counter()
        rejection_spans: list[dict[str, Any]] = []
        accepted = 0
        rejected = 0
        processed = 0
        first_event_id: UUID | None = None
        last_event_id: UUID | None = None

        with path.open("rb") as stream:
            preflight_sha256, preflight_size = _sha256_stream(stream)
            if preflight_size != artifact.size_bytes:
                raise ZeekSourceBindingError(
                    "conn.log size does not match frozen binding"
                )
            if preflight_sha256 != artifact.sha256:
                raise ZeekSourceBindingError(
                    "conn.log hash does not match frozen binding"
                )
            stream.seek(0)
            for physical_line_number, line in enumerate(stream, start=1):
                processed_source_digest.update(line)
                if physical_line_number > artifact.record_count:
                    raise ZeekSourceBindingError(
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
                context = ZeekNormalizationContext(
                    protocol_sha256=self._bound.specification_sha256,
                    source=source,
                    record_available_time=self._record_available_time,
                    ingested_at=self._ingested_at,
                )
                try:
                    record = self._parser.parse_line(line, source)
                    event = self._normalizer.normalize_conn(
                        record,
                        context,
                        self._specification,
                    )
                except ZeekRecordRejection as rejection:
                    rejected += 1
                    rejection_counts[rejection.reason] += 1
                    self._append_rejection_span(
                        rejection_spans,
                        physical_line_number,
                        rejection,
                    )
                    payload = _canonical_rejection_bytes(source, rejection)
                    rejection_digest.update(payload)
                    if global_rejection_digest is not None:
                        global_rejection_digest.update(payload)
                    continue

                accepted += 1
                event_id = event.provenance.event_id
                first_event_id = first_event_id or event_id
                last_event_id = event_id
                payload = canonical_event_bytes(event)
                event_digest.update(payload)
                if global_event_digest is not None:
                    global_event_digest.update(payload)

        if processed != artifact.record_count:
            raise ZeekSourceBindingError(
                "conn.log physical line count does not match frozen report"
            )
        if processed_source_digest.hexdigest() != artifact.sha256:
            raise ZeekSourceBindingError(
                "conn.log bytes changed between verification and normalization"
            )
        return ZeekPartitionNormalizationReport(
            output_partition=binding.output_partition,
            replay_report_content_sha256=binding.report_content_sha256,
            input_capture_sha256=binding.input.sha256,
            log_name="conn.log",
            source_log_sha256=artifact.sha256,
            source_size_bytes=artifact.size_bytes,
            reported_record_count=artifact.record_count,
            source_verified=True,
            processed_record_count=processed,
            accepted_record_count=accepted,
            rejected_record_count=rejected,
            rejection_counts=tuple(
                ZeekRejectionCount(reason=reason, count=count)  # type: ignore[arg-type]
                for reason, count in sorted(rejection_counts.items())
            ),
            rejection_spans=tuple(
                ZeekRejectionSpan.model_validate(span) for span in rejection_spans
            ),
            canonical_event_stream_sha256=event_digest.hexdigest(),
            rejection_audit_stream_sha256=rejection_digest.hexdigest(),
            first_accepted_event_id=first_event_id,
            last_accepted_event_id=last_event_id,
        )

    def run(self) -> ZeekNormalizationRunReport:
        """Normalize every partition in frozen report order."""
        global_event_digest = sha256()
        global_rejection_digest = sha256()
        partition_reports = tuple(
            self.normalize_partition(
                binding,
                global_event_digest,
                global_rejection_digest,
            )
            for binding in self._specification.replay_reports
        )
        envelope = self._specification.event_envelope
        return ZeekNormalizationRunReport(
            report_version="1.0.0",
            verification_status="verified",
            protocol_sha256=self._bound.specification_sha256,
            m1_manifest_sha256=self._bound.m1_manifest_sha256,
            m2_specification_sha256=self._bound.m2_specification_sha256,
            dataset_name=self._specification.dataset_name,
            sensor_type="zeek",
            sensor_version=self._specification.sensor_version,
            normalizer_version=envelope.normalizer_version,
            pipeline_version=envelope.pipeline_version,
            input_format=self._specification.input_format,
            record_available_time=self._record_available_time,
            ingested_at=self._ingested_at,
            partition_reports=partition_reports,
            total_processed_record_count=sum(
                item.processed_record_count for item in partition_reports
            ),
            total_accepted_record_count=sum(
                item.accepted_record_count for item in partition_reports
            ),
            total_rejected_record_count=sum(
                item.rejected_record_count for item in partition_reports
            ),
            canonical_event_stream_sha256=global_event_digest.hexdigest(),
            rejection_audit_stream_sha256=global_rejection_digest.hexdigest(),
        )


def write_immutable_normalization_report(
    report: ZeekNormalizationRunReport,
    path: str | Path,
) -> str:
    """Publish only the deterministic report, failing rather than overwriting."""
    destination = Path(path)
    if destination.exists():
        raise FileExistsError(f"normalization report already exists: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = report.model_dump_json(indent=2).encode("utf-8") + b"\n"
    temporary = destination.with_name(f".{destination.name}.tmp")
    if temporary.exists():
        raise FileExistsError(f"normalization report staging path exists: {temporary}")
    try:
        with temporary.open("xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, destination)
    finally:
        if temporary.exists():
            temporary.unlink()
    return sha256(payload).hexdigest()
