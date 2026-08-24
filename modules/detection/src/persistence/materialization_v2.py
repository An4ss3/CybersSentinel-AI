"""M4 canonical event materialization adapter.

Independently streams the three frozen M2 conn.log partitions through the
frozen M3 v2 parser and normalizer (imported, never modified) to materialize
and persist ``FlowEndV2`` events into ``m4_canonical.flow_end_events`` and
rejection evidence into ``m4_canonical.rejection_spans`` /
``m4_canonical.rejection_counts``.

This adapter does not call ``ZeekConnNormalizationRunnerV2`` (which discards
events after hashing) and does not modify it in any way. It constructs its own
parser/normalizer instances using the same bound specification, exactly
mirroring the frozen runner's construction pattern, then retains what the
frozen runner intentionally discards.

Before any row is written, the frozen M3 v2 report is re-verified with the
Phase 1 seven-point gate. After all three partitions are persisted, the
canonical event stream and rejection audit stream hashes are independently
recomputed and compared byte-for-byte to the frozen report's hashes. The run
is marked ``verified`` only on an exact match; any mismatch marks it
``failed`` and the row is retained for audit.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

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
from modules.detection.src.normalization.zeek_pipeline_v2 import (
    _canonical_event_bytes,
    _canonical_rejection_bytes,
)
from modules.detection.src.persistence.report_verification_v2 import (
    VerifiedM3Report,
    verify_frozen_m3_v2_report,
)
from modules.detection.src.schemas.events_v2 import FlowEndV2
from modules.detection.src.schemas.exact_time_v2 import unscaled_from_canonical
from modules.detection.src.schemas.zeek_normalization import (
    ZeekReplayReportBinding,
    ZeekSourceCoordinate,
)
from modules.detection.src.schemas.zeek_normalization_v2 import (
    ZeekNormalizationContextV2,
)


class M4MaterializationError(RuntimeError):
    """Materialization cannot proceed or could not be verified."""


class M4DuplicateVerifiedRunError(M4MaterializationError):
    """A verified materialization of this frozen report already exists."""


_INSERT_RUN_SQL = """
INSERT INTO m4_canonical.materialization_runs (
    run_id, m3_report_content_sha256, m3_report_file_sha256, m3_protocol_sha256,
    m3_event_stream_sha256, m3_rejection_audit_stream_sha256,
    status, started_at
) VALUES (
    %(run_id)s, %(m3_report_content_sha256)s, %(m3_report_file_sha256)s,
    %(m3_protocol_sha256)s, %(m3_event_stream_sha256)s,
    %(m3_rejection_audit_stream_sha256)s, %(status)s, %(started_at)s
)
"""

_UPDATE_RUN_SQL = """
UPDATE m4_canonical.materialization_runs
SET status = %(status)s,
    completed_at = %(completed_at)s,
    total_processed_record_count = %(total_processed_record_count)s,
    total_accepted_record_count = %(total_accepted_record_count)s,
    total_rejected_record_count = %(total_rejected_record_count)s,
    materialized_event_stream_sha256 = %(materialized_event_stream_sha256)s,
    materialized_rejection_stream_sha256 = %(materialized_rejection_stream_sha256)s
WHERE run_id = %(run_id)s
"""

_INSERT_EVENT_SQL = """
INSERT INTO m4_canonical.flow_end_events (
    event_id, m4_run_id, sensor_id, sensor_run_id, capture_id,
    dataset_snapshot_id, model_release_id, normalizer_version, pipeline_version,
    schema_version, event_version, feature_version, sensor_version,
    event_type, sensor_type,
    event_start_time, event_duration, event_end_time,
    record_available_time, ingested_at,
    conversation_id, source_ip, source_port, destination_ip, destination_port,
    transport, service,
    source_packets, destination_packets, source_bytes, destination_bytes,
    connection_state, termination_reason,
    output_partition, physical_line_number, event_bytes_sha256
) VALUES (
    %(event_id)s, %(m4_run_id)s, %(sensor_id)s, %(sensor_run_id)s, %(capture_id)s,
    %(dataset_snapshot_id)s, %(model_release_id)s, %(normalizer_version)s,
    %(pipeline_version)s,
    %(schema_version)s, %(event_version)s, %(feature_version)s, %(sensor_version)s,
    %(event_type)s, %(sensor_type)s,
    %(event_start_time)s, %(event_duration)s, %(event_end_time)s,
    %(record_available_time)s, %(ingested_at)s,
    %(conversation_id)s, %(source_ip)s, %(source_port)s, %(destination_ip)s,
    %(destination_port)s,
    %(transport)s, %(service)s,
    %(source_packets)s, %(destination_packets)s, %(source_bytes)s,
    %(destination_bytes)s,
    %(connection_state)s, %(termination_reason)s,
    %(output_partition)s, %(physical_line_number)s, %(event_bytes_sha256)s
)
"""

_INSERT_REJECTION_SPAN_SQL = """
INSERT INTO m4_canonical.rejection_spans (
    m4_run_id, output_partition, first_physical_line_number,
    last_physical_line_number, reason, fields
) VALUES (
    %(m4_run_id)s, %(output_partition)s, %(first_physical_line_number)s,
    %(last_physical_line_number)s, %(reason)s, %(fields)s
)
"""

_INSERT_REJECTION_COUNT_SQL = """
INSERT INTO m4_canonical.rejection_counts (
    m4_run_id, output_partition, reason, count
) VALUES (
    %(m4_run_id)s, %(output_partition)s, %(reason)s, %(count)s
)
"""

_CHECK_VERIFIED_RUN_SQL = """
SELECT run_id FROM m4_canonical.materialization_runs
WHERE m3_report_content_sha256 = %(m3_report_content_sha256)s
  AND status = 'verified'
"""


def _flow_end_row(
    event: FlowEndV2,
    run_id: UUID,
    source: ZeekSourceCoordinate,
) -> dict[str, Any]:
    """Map one FlowEndV2 to its persistence row, verbatim, no reinterpretation."""
    provenance = event.provenance
    return {
        "event_id": str(provenance.event_id),
        "m4_run_id": str(run_id),
        "sensor_id": provenance.sensor_id,
        "sensor_run_id": provenance.sensor_run_id,
        "capture_id": provenance.capture_id,
        "dataset_snapshot_id": provenance.dataset_snapshot_id,
        "model_release_id": provenance.model_release_id,
        "normalizer_version": provenance.normalizer_version,
        "pipeline_version": provenance.pipeline_version,
        "schema_version": event.schema_version,
        "event_version": event.event_version,
        "feature_version": event.feature_version,
        "sensor_version": event.sensor_version,
        "event_type": event.event_type,
        "sensor_type": event.sensor_type,
        # Exact DECIMAL(38,22) strings -> Decimal via psycopg's own adapter,
        # never through float. psycopg passes str/Decimal to NUMERIC untouched.
        "event_start_time": event.event_start_time,
        "event_duration": event.event_duration,
        "event_end_time": event.event_end_time,
        "record_available_time": event.record_available_time,
        "ingested_at": event.ingested_at,
        "conversation_id": event.conversation_id,
        "source_ip": str(event.source.ip),
        "source_port": event.source.port,
        "destination_ip": str(event.destination.ip),
        "destination_port": event.destination.port,
        "transport": event.transport,
        "service": event.service,
        "source_packets": event.counters.source_packets,
        "destination_packets": event.counters.destination_packets,
        "source_bytes": event.counters.source_bytes,
        "destination_bytes": event.counters.destination_bytes,
        "connection_state": event.connection_state,
        "termination_reason": event.termination_reason,
        "output_partition": source.output_partition,
        "physical_line_number": source.physical_line_number,
        "event_bytes_sha256": sha256(_canonical_event_bytes(event)).hexdigest(),
    }


@dataclass(slots=True)
class _PartitionMaterializationResult:
    output_partition: str
    source_log_sha256: str
    reported_record_count: int
    processed_record_count: int
    accepted_record_count: int
    rejected_record_count: int
    persisted_event_count: int
    event_stream_sha256: str
    rejection_stream_sha256: str


@dataclass(slots=True)
class MaterializationOutcome:
    """Result of one M4 materialization attempt."""

    run_id: UUID
    verification_status: str  # "verified" | "failed"
    started_at: datetime
    completed_at: datetime
    total_processed_record_count: int
    total_accepted_record_count: int
    total_rejected_record_count: int
    total_persisted_event_count: int
    materialized_event_stream_sha256: str
    materialized_rejection_stream_sha256: str
    partition_results: tuple[_PartitionMaterializationResult, ...] = field(
        default_factory=tuple
    )


class ZeekConnMaterializationAdapterV2:
    """Persist FlowEndV2 events and rejection evidence for the frozen M3 v2 run.

    Reuses the frozen M3 v2 parser and normalizer by import only. Does not
    call, modify, or reopen ``ZeekConnNormalizationRunnerV2``.
    """

    def __init__(
        self,
        repository_root: str | Path,
        bound_specification: BoundZeekNormalizationSpecificationV2,
        verified_m3_report: VerifiedM3Report,
    ) -> None:
        self._root = Path(repository_root).resolve(strict=True)
        self._bound = bound_specification
        self._specification = bound_specification.specification
        self._protocol_sha256 = bound_specification.specification_sha256
        self._verified_report = verified_m3_report

        # Independent construction — mirrors, but does not call into,
        # ZeekConnNormalizationRunnerV2.__init__.
        self._parser = StrictZeekJsonLineParserV2()
        self._normalizer = StrictZeekConnFlowEndNormalizerV2(self._specification)

    @classmethod
    def from_repository(
        cls,
        repository_root: str | Path,
    ) -> "ZeekConnMaterializationAdapterV2":
        """Verify the frozen report, then construct the adapter."""
        root = Path(repository_root).resolve(strict=True)
        verified = verify_frozen_m3_v2_report(root)
        bound = load_and_bind_zeek_normalization_specification_v2(root)
        return cls(root, bound, verified)

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
            raise ZeekSourceBindingErrorV2(
                "bound conn.log resolves outside repository root"
            ) from error
        return candidate

    def _preflight_verify(self, binding: ZeekReplayReportBinding) -> Path:
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

    def _record_available_time(self) -> str:
        return self._verified_report.report.record_available_time

    def _ingested_at(self) -> str:
        return self._verified_report.report.ingested_at

    def materialize_partition(
        self,
        conn,
        run_id: UUID,
        binding: ZeekReplayReportBinding,
        global_event_digest: Any,
        global_rejection_digest: Any,
    ) -> _PartitionMaterializationResult:
        """Stream, persist, and hash one partition inside its own transaction."""
        path = self._preflight_verify(binding)
        artifact = binding.supported_log

        partition_event_digest = sha256()
        partition_rejection_digest = sha256()
        rejection_counts: Counter[str] = Counter()
        rejection_spans: list[dict[str, Any]] = []
        accepted = 0
        rejected = 0
        processed = 0
        event_rows: list[dict[str, Any]] = []

        record_available_time = self._record_available_time()
        ingested_at = self._ingested_at()

        with path.open("rb") as stream:
            for physical_line_number, line in enumerate(stream, start=1):
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
                    record_available_time=record_available_time,
                    ingested_at=ingested_at,
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
                    global_rejection_digest.update(payload)
                    continue

                accepted += 1
                payload = _canonical_event_bytes(event)
                partition_event_digest.update(payload)
                global_event_digest.update(payload)
                event_rows.append(_flow_end_row(event, run_id, source))

        if processed != artifact.record_count:
            raise ZeekSourceBindingErrorV2(
                f"conn.log line count mismatch: expected {artifact.record_count}, "
                f"got {processed}"
            )

        # One transaction per partition, as authorized.
        with conn.cursor() as cur:
            if event_rows:
                cur.executemany(_INSERT_EVENT_SQL, event_rows)
            for reason, count in sorted(rejection_counts.items()):
                cur.execute(
                    _INSERT_REJECTION_COUNT_SQL,
                    {
                        "m4_run_id": str(run_id),
                        "output_partition": binding.output_partition,
                        "reason": reason,
                        "count": count,
                    },
                )
            for span in rejection_spans:
                cur.execute(
                    _INSERT_REJECTION_SPAN_SQL,
                    {
                        "m4_run_id": str(run_id),
                        "output_partition": binding.output_partition,
                        "first_physical_line_number": span[
                            "first_physical_line_number"
                        ],
                        "last_physical_line_number": span[
                            "last_physical_line_number"
                        ],
                        "reason": span["reason"],
                        "fields": list(span["fields"]),
                    },
                )
        conn.commit()

        return _PartitionMaterializationResult(
            output_partition=binding.output_partition,
            source_log_sha256=artifact.sha256,
            reported_record_count=artifact.record_count,
            processed_record_count=processed,
            accepted_record_count=accepted,
            rejected_record_count=rejected,
            persisted_event_count=len(event_rows),
            event_stream_sha256=partition_event_digest.hexdigest(),
            rejection_stream_sha256=partition_rejection_digest.hexdigest(),
        )

    @staticmethod
    def _append_rejection_span(
        spans: list[dict[str, Any]],
        line_number: int,
        rejection: ZeekRecordRejectionV2,
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

    def materialize(self, conn) -> MaterializationOutcome:
        """Materialize all three frozen partitions; verify; record the run.

        Raises ``M4DuplicateVerifiedRunError`` if a verified materialization of
        this exact frozen report already exists (fail-loud idempotency).
        """
        report = self._verified_report.report
        m3_report_content_sha256 = self._verified_report.report_content_sha256

        with conn.cursor() as cur:
            cur.execute(
                _CHECK_VERIFIED_RUN_SQL,
                {"m3_report_content_sha256": m3_report_content_sha256},
            )
            existing = cur.fetchone()
        if existing is not None:
            raise M4DuplicateVerifiedRunError(
                "a verified M4 materialization of this frozen M3 v2 report "
                f"already exists: run_id={existing[0]}"
            )

        run_id = uuid4()
        started_at = datetime.now(timezone.utc)

        with conn.cursor() as cur:
            cur.execute(
                _INSERT_RUN_SQL,
                {
                    "run_id": str(run_id),
                    "m3_report_content_sha256": m3_report_content_sha256,
                    "m3_report_file_sha256": self._verified_report.report_file_sha256,
                    "m3_protocol_sha256": report.protocol_sha256,
                    "m3_event_stream_sha256": report.canonical_event_stream_sha256,
                    "m3_rejection_audit_stream_sha256": (
                        report.rejection_audit_stream_sha256
                    ),
                    "status": "running",
                    "started_at": started_at,
                },
            )
        conn.commit()

        global_event_digest = sha256()
        global_rejection_digest = sha256()
        partition_results: list[_PartitionMaterializationResult] = []

        try:
            for binding in self._specification.replay_reports:
                result = self.materialize_partition(
                    conn, run_id, binding, global_event_digest, global_rejection_digest
                )
                partition_results.append(result)
        except Exception:
            self._finalize_run(
                conn,
                run_id,
                status="failed",
                completed_at=datetime.now(timezone.utc),
                totals=(None, None, None),
                materialized_hashes=(None, None),
            )
            raise

        total_processed = sum(item.processed_record_count for item in partition_results)
        total_accepted = sum(item.accepted_record_count for item in partition_results)
        total_rejected = sum(item.rejected_record_count for item in partition_results)
        total_persisted = sum(item.persisted_event_count for item in partition_results)

        materialized_event_sha256 = global_event_digest.hexdigest()
        materialized_rejection_sha256 = global_rejection_digest.hexdigest()

        matches_frozen_evidence = (
            materialized_event_sha256 == report.canonical_event_stream_sha256
            and materialized_rejection_sha256 == report.rejection_audit_stream_sha256
        )
        status = "verified" if matches_frozen_evidence else "failed"
        completed_at = datetime.now(timezone.utc)

        self._finalize_run(
            conn,
            run_id,
            status=status,
            completed_at=completed_at,
            totals=(total_processed, total_accepted, total_rejected),
            materialized_hashes=(materialized_event_sha256, materialized_rejection_sha256),
        )

        if not matches_frozen_evidence:
            raise M4MaterializationError(
                "materialized stream hashes do not match the frozen M3 v2 report; "
                f"run_id={run_id} marked failed and retained for audit"
            )

        return MaterializationOutcome(
            run_id=run_id,
            verification_status=status,
            started_at=started_at,
            completed_at=completed_at,
            total_processed_record_count=total_processed,
            total_accepted_record_count=total_accepted,
            total_rejected_record_count=total_rejected,
            total_persisted_event_count=total_persisted,
            materialized_event_stream_sha256=materialized_event_sha256,
            materialized_rejection_stream_sha256=materialized_rejection_sha256,
            partition_results=tuple(partition_results),
        )

    @staticmethod
    def _finalize_run(
        conn,
        run_id: UUID,
        *,
        status: str,
        completed_at: datetime,
        totals: tuple[int | None, int | None, int | None],
        materialized_hashes: tuple[str | None, str | None],
    ) -> None:
        with conn.cursor() as cur:
            cur.execute(
                _UPDATE_RUN_SQL,
                {
                    "run_id": str(run_id),
                    "status": status,
                    "completed_at": completed_at,
                    "total_processed_record_count": totals[0],
                    "total_accepted_record_count": totals[1],
                    "total_rejected_record_count": totals[2],
                    "materialized_event_stream_sha256": materialized_hashes[0],
                    "materialized_rejection_stream_sha256": materialized_hashes[1],
                },
            )
        conn.commit()
