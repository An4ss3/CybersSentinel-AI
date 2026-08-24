"""Streaming MB3 normalization runner for the Monday Benign track.

Reuse boundary
--------------
``ZeekConnNormalizationRunnerV2`` is **subclassed, never modified**. Everything
that actually touches evidence is inherited verbatim:

* ``_source_path`` -- resolves the conn.log below ``specification.m2_output_root``
  and refuses any path escaping the repository root;
* ``_preflight_verify`` -- re-hashes the conn.log and compares size and SHA-256
  against the frozen binding before a single line is parsed;
* ``process_partition`` -- streams the file line by line, builds the
  ``ZeekSourceCoordinate`` and ``ZeekNormalizationContextV2``, delegates to
  ``StrictZeekJsonLineParserV2`` and ``StrictZeekConnFlowEndNormalizerV2``,
  accumulates rejection spans and counts, hashes each accepted event and each
  rejection, verifies the streamed bytes still hash to the frozen digest, and
  discards every event without persisting it;
* ``_build_partition_report`` and ``_append_rejection_span``.

MB3 overrides only what is M-chain specific:

* ``from_repository`` -- binds through the MB3 lineage module;
* ``_build_run_report`` -- emits a ``MondayBenignNormalizationRunReport`` with MB
  coordinates instead of a three-partition M3 v2 report.

For MB3 ``specification.m2_output_root`` is a read-only alias returning the
**MB2** output root, so the inherited path resolution can never reach the frozen
M2 tree. No event is persisted anywhere: MB4 is a separate, unstarted milestone.
"""
from __future__ import annotations

from hashlib import sha256
import os
from pathlib import Path

from modules.detection.src.lineage.monday_benign_normalization import (
    BoundMondayBenignNormalizationSpecification,
    load_and_bind_monday_benign_normalization_specification,
)
from modules.detection.src.normalization.zeek_pipeline_v2 import (
    RunAccumulator,
    ZeekConnNormalizationRunnerV2,
)
from modules.detection.src.schemas.exact_time_v2 import ExactDecimalSeconds22
from modules.detection.src.schemas.monday_benign_normalization import (
    MB3_PROTOCOL_RELATIVE_PATH,
    MondayBenignNormalizationRunReport,
)


class MondayBenignNormalizationRunner(ZeekConnNormalizationRunnerV2):
    """Stream the single MB2 Monday conn.log under the frozen MB3 protocol."""

    @classmethod
    def from_repository(  # type: ignore[override]
        cls,
        repository_root: str | Path,
        record_available_time: ExactDecimalSeconds22,
        ingested_at: ExactDecimalSeconds22,
        specification_path: str | Path = MB3_PROTOCOL_RELATIVE_PATH,
    ) -> "MondayBenignNormalizationRunner":
        """Load, bind, and construct the MB3 runner from the repository root."""
        root = Path(repository_root).resolve(strict=True)
        bound = load_and_bind_monday_benign_normalization_specification(
            root, specification_path
        )
        return cls(root, bound, record_available_time, ingested_at)

    @property
    def mb3_bound(self) -> BoundMondayBenignNormalizationSpecification:
        """Return the bound MB3 specification with its concrete type."""
        bound = self._bound
        if not isinstance(bound, BoundMondayBenignNormalizationSpecification):
            raise TypeError(
                "MB3 runner requires a BoundMondayBenignNormalizationSpecification; "
                "an M3 v2 binding can never drive the MB track"
            )
        return bound

    def _build_run_report(  # type: ignore[override]
        self,
        accumulator: RunAccumulator,
    ) -> MondayBenignNormalizationRunReport:
        """Construct the validated MB3 run report from accumulated evidence."""
        bound = self.mb3_bound
        specification = bound.specification
        if len(accumulator.partition_results) != 1:
            raise ValueError(
                "MB3 must accumulate exactly one partition result, got "
                f"{len(accumulator.partition_results)}"
            )
        partition_reports = tuple(
            self._build_partition_report(result)
            for result in accumulator.partition_results
        )
        return MondayBenignNormalizationRunReport(
            report_version="2.0.0",
            verification_status="verified",
            track="monday_benign",
            protocol_sha256=bound.specification_sha256,
            m1_manifest_sha256=bound.m1_manifest_sha256,
            mb2_specification_sha256=bound.mb2_specification_sha256,
            mb2_replay_report_content_sha256=(
                bound.mb2_replay_report_content_sha256
            ),
            event_id_namespace=specification.provenance.event_id_namespace,
            dataset_name=specification.dataset_name,
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
            canonical_event_stream_sha256=(
                accumulator.canonical_event_stream_sha256
            ),
            rejection_audit_stream_sha256=(
                accumulator.rejection_audit_stream_sha256
            ),
        )

    def run(self) -> MondayBenignNormalizationRunReport:  # type: ignore[override]
        """Stream the Monday partition and return the validated MB3 report."""
        accumulator = self.run_all_partitions()
        return self._build_run_report(accumulator)


def write_immutable_monday_benign_normalization_report(
    report: MondayBenignNormalizationRunReport,
    path: str | Path,
) -> str:
    """Publish the verified MB3 report immutably; return the written-byte hash.

    Mirrors the frozen M3 v2 publication policy exactly: refuses to overwrite,
    exclusive-create into a staging name, ``flush`` + ``os.fsync``, then atomic
    rename, with staging cleanup on any failure.
    """
    destination = Path(path)
    if destination.exists():
        raise FileExistsError(f"MB3 report already exists: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = report.model_dump_json(indent=2).encode("utf-8") + b"\n"
    temporary = destination.with_name(f".{destination.name}.tmp")
    if temporary.exists():
        raise FileExistsError(f"MB3 report staging path exists: {temporary}")
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
