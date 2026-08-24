"""Materialize M6 canonical feature windows and publish their evidence.

Orchestration order:

    1. bind the frozen M6 manifest to every upstream identity
       (this runs the existing seven-point M3 v2 gate unchanged)
    2. ensure the dedicated m6_canonical schema exists
    3. stream M4 events in canonical order and build exact tumbling windows
    4. persist windows and their complete source lineage
    5. build the M6 run report from observed evidence
    6. publish that report immutably

``--recompute-only`` performs steps 1 and 3 without touching PostgreSQL or the
filesystem, returning the deterministic evidence for independent dual-run
verification.

This command never modifies M1, M2, M3 v2, M4, or M5. It reads
``m4_canonical`` with SELECT only and writes solely into ``m6_canonical``.

Example:
    python -m scripts.materialize_m6_feature_windows
    python -m scripts.materialize_m6_feature_windows --recompute-only
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
from typing import Sequence
from uuid import UUID, uuid4

from modules.detection.src.feature_engineering.window_builder_v2 import (
    FeatureWindowBuilderV2,
    SourceEventRow,
    canonical_window_bytes,
    entity_key_for,
    window_start_unscaled,
)
from modules.detection.src.lineage.feature_window_v2 import (
    load_and_bind_feature_window_specification_v2,
)
from modules.detection.src.persistence.db import get_connection
from modules.detection.src.persistence.feature_window_persistence_v2 import (
    ensure_m6_schema,
    existing_verified_run,
    finalize_run,
    insert_run,
    persist_window_batch,
    stream_partition_events,
    window_row,
)
from modules.detection.src.schemas.feature_window_protocol_v2 import (
    FeatureWindowPartitionReportV2,
    FeatureWindowRunReportV2,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
CANONICAL_M6_REPORT_RELATIVE_PATH = "artifacts/reports/m6_v2_feature_window_run.json"
DEFAULT_REPORT_PATH = REPO_ROOT / CANONICAL_M6_REPORT_RELATIVE_PATH
BATCH_SIZE = 4_000


class M6RunError(RuntimeError):
    """The M6 run could not complete successfully."""


class M6DuplicateVerifiedRunError(M6RunError):
    """A verified M6 materialization of this exact evidence already exists."""


class M6ReportAlreadyPublishedError(M6RunError):
    """A production M6 report already exists and must never be overwritten."""


class M6PublicationFailedError(M6RunError):
    """Windows were materialized but the report could not be published."""

    def __init__(self, message: str, run_id: UUID) -> None:
        super().__init__(message)
        self.run_id = run_id


class M6OrderingViolation(M6RunError):
    """Streamed windows were not emitted in the frozen canonical order."""


@dataclass(slots=True)
class PartitionEvidence:
    output_partition: str
    source_event_count: int = 0
    window_count: int = 0
    entity_count: int = 0
    first_window_id: str | None = None
    last_window_id: str | None = None
    partition_digest: object = field(default_factory=sha256)

    @property
    def digest_hex(self) -> str:
        return self.partition_digest.hexdigest()


@dataclass(slots=True)
class RunEvidence:
    total_source_event_count: int = 0
    total_window_count: int = 0
    partitions: list[PartitionEvidence] = field(default_factory=list)
    global_digest: object = field(default_factory=sha256)

    @property
    def window_stream_sha256(self) -> str:
        return self.global_digest.hexdigest()


def _groups_in_canonical_order(
    builder: FeatureWindowBuilderV2, rows_iter
) -> "object":
    """Yield contiguous (entity_key, bucket) groups from an ordered stream."""
    current_key: tuple | None = None
    batch: list[SourceEventRow] = []
    for row in rows_iter:
        key = (
            entity_key_for(row),
            window_start_unscaled(row.event_start_time, builder.window_length_unscaled),
        )
        if current_key is None:
            current_key = key
        elif key != current_key:
            yield current_key, batch
            current_key, batch = key, []
        batch.append(row)
    if current_key is not None and batch:
        yield current_key, batch


def _process_partition(
    builder: FeatureWindowBuilderV2,
    partition: str,
    rows_iter,
    evidence: RunEvidence,
    conn=None,
    run_id: UUID | None = None,
) -> PartitionEvidence:
    """Build (and optionally persist) one partition's windows in canonical order."""
    partition_evidence = PartitionEvidence(output_partition=partition)
    previous_sort_key: tuple | None = None
    entities: set[tuple] = set()
    window_batch: list[dict[str, object]] = []
    lineage_batch: list[tuple[str, str]] = []

    for (entity_key, start_unscaled), rows in _groups_in_canonical_order(
        builder, rows_iter
    ):
        window = builder.build_window(partition, entity_key, start_unscaled, rows)

        sort_key = (partition, entity_key, start_unscaled)
        if previous_sort_key is not None and not sort_key > previous_sort_key:
            raise M6OrderingViolation(
                "streamed windows left canonical order: "
                f"{previous_sort_key!r} then {sort_key!r}"
            )
        previous_sort_key = sort_key

        payload = canonical_window_bytes(window)
        digest = sha256(payload).hexdigest()
        partition_evidence.partition_digest.update(payload)
        evidence.global_digest.update(payload)

        partition_evidence.window_count += 1
        partition_evidence.source_event_count += len(rows)
        entities.add(entity_key)
        window_id = str(window.provenance.event_id)
        if partition_evidence.first_window_id is None:
            partition_evidence.first_window_id = window_id
        partition_evidence.last_window_id = window_id

        if conn is not None and run_id is not None:
            window_batch.append(window_row(window, run_id, digest))
            lineage_batch.extend(
                (window_id, str(event_id)) for event_id in window.source_event_ids
            )
            if len(window_batch) >= BATCH_SIZE:
                persist_window_batch(conn, window_batch, lineage_batch)
                window_batch, lineage_batch = [], []

    if conn is not None and window_batch:
        persist_window_batch(conn, window_batch, lineage_batch)

    partition_evidence.entity_count = len(entities)
    evidence.total_window_count += partition_evidence.window_count
    evidence.total_source_event_count += partition_evidence.source_event_count
    evidence.partitions.append(partition_evidence)
    return partition_evidence


def recompute_evidence(
    repository_root: str | Path = REPO_ROOT,
    *,
    verbose: bool = True,
) -> tuple[RunEvidence, object]:
    """Rebuild every window from M4 without writing anything anywhere."""
    root = Path(repository_root).resolve(strict=True)
    bound = load_and_bind_feature_window_specification_v2(root)
    builder = FeatureWindowBuilderV2(bound.specification)

    connection = get_connection(connect_timeout=10)
    if connection is None:
        raise M6RunError("PostgreSQL is unreachable; M6 cannot read M4 events")

    evidence = RunEvidence()
    try:
        for partition in bound.partition_order:
            result = _process_partition(
                builder, partition, stream_partition_events(connection, partition),
                evidence,
            )
            if verbose:
                print(
                    f"  {partition:36s} events={result.source_event_count:>7} "
                    f"windows={result.window_count:>6} entities={result.entity_count:>6}"
                )
    finally:
        connection.close()
    return evidence, bound


def materialize(
    repository_root: str | Path = REPO_ROOT,
    report_path: str | Path = DEFAULT_REPORT_PATH,
    *,
    verbose: bool = True,
) -> FeatureWindowRunReportV2:
    """Run the full M6 workflow and return the published run report."""
    root = Path(repository_root).resolve(strict=True)
    destination = Path(report_path)

    if destination.exists():
        raise M6ReportAlreadyPublishedError(
            f"M6 report already exists and will not be overwritten: {destination}"
        )

    bound = load_and_bind_feature_window_specification_v2(root)
    builder = FeatureWindowBuilderV2(bound.specification)
    if verbose:
        print(f"  M6 protocol sha256 : {builder.protocol_sha256}")

    connection = get_connection(connect_timeout=10)
    if connection is None:
        raise M6RunError("PostgreSQL is unreachable; M6 materialization not started")

    identity = {
        "m6_protocol_sha256": builder.protocol_sha256,
        "m3_report_content_sha256": bound.m3_report_content_sha256,
        "m4_report_content_sha256": bound.m4_report_content_sha256,
    }

    run_id = uuid4()
    started_at = datetime.now(timezone.utc)
    evidence = RunEvidence()

    try:
        ensure_m6_schema(connection)
        duplicate = existing_verified_run(connection, identity)
        if duplicate is not None:
            raise M6DuplicateVerifiedRunError(
                "a verified M6 materialization of this evidence already exists: "
                f"run_id={duplicate}"
            )
        insert_run(
            connection,
            {**identity, "run_id": str(run_id), "status": "running",
             "started_at": started_at},
        )

        try:
            for partition in bound.partition_order:
                result = _process_partition(
                    builder, partition,
                    stream_partition_events(connection, partition),
                    evidence, conn=connection, run_id=run_id,
                )
                connection.commit()
                if verbose:
                    print(
                        f"  {partition:36s} events={result.source_event_count:>7} "
                        f"windows={result.window_count:>6} "
                        f"entities={result.entity_count:>6} "
                        f"digest={result.digest_hex[:16]}…"
                    )
        except Exception:
            connection.rollback()
            finalize_run(connection, {
                "run_id": str(run_id), "status": "failed",
                "completed_at": datetime.now(timezone.utc),
                "total_source_event_count": None, "total_window_count": None,
                "window_stream_sha256": None,
            })
            raise

        completed_at = datetime.now(timezone.utc)
        finalize_run(connection, {
            "run_id": str(run_id), "status": "verified",
            "completed_at": completed_at,
            "total_source_event_count": evidence.total_source_event_count,
            "total_window_count": evidence.total_window_count,
            "window_stream_sha256": evidence.window_stream_sha256,
        })
    finally:
        connection.close()

    report = FeatureWindowRunReportV2(
        report_version="1.0.0",
        run_id=run_id,
        verification_status="verified",
        protocol_sha256=builder.protocol_sha256,
        m1_manifest_sha256=bound.specification.m1_manifest_sha256,
        m2_specification_sha256=bound.specification.m2_specification_sha256,
        m3_protocol_sha256=bound.specification.m3_protocol_sha256,
        m3_report_content_sha256=bound.m3_report_content_sha256,
        m4_report_content_sha256=bound.m4_report_content_sha256,
        dataset_name=bound.specification.dataset_name,
        target_model="FeatureWindowV2",
        schema_version="2.0.0",
        event_version="2.0.0",
        feature_version="2.0.0",
        sensor_version=bound.sensor_version,
        entity_type=bound.specification.entity.entity_type,
        window_length_seconds=bound.specification.window.length_seconds,
        windowing_basis="event_start_time",
        started_at=started_at,
        completed_at=completed_at,
        total_source_event_count=evidence.total_source_event_count,
        total_window_count=evidence.total_window_count,
        window_stream_sha256=evidence.window_stream_sha256,
        partition_reports=tuple(
            FeatureWindowPartitionReportV2(
                output_partition=item.output_partition,
                source_event_count=item.source_event_count,
                window_count=item.window_count,
                entity_count=item.entity_count,
                first_window_id=item.first_window_id,
                last_window_id=item.last_window_id,
                window_stream_sha256=item.digest_hex,
            )
            for item in evidence.partitions
        ),
    )

    try:
        file_sha256 = write_immutable_feature_window_report_v2(report, destination)
    except Exception as error:
        raise M6PublicationFailedError(
            "windows are materialized and recorded in PostgreSQL, but the "
            f"immutable M6 report could not be published to {destination}: "
            f"{error}. The run is NOT complete.",
            run_id=run_id,
        ) from error

    if verbose:
        print(f"  published          : {destination}")
        print(f"  report file sha256 : {file_sha256}")
    return report


def write_immutable_feature_window_report_v2(
    report: FeatureWindowRunReportV2,
    path: str | Path,
) -> str:
    """Publish the M6 report immutably; returns SHA-256 of the written bytes."""
    destination = Path(path)
    if destination.exists():
        raise FileExistsError(f"M6 report already exists: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = report.model_dump_json(indent=2).encode("utf-8") + b"\n"
    temporary = destination.with_name(f".{destination.name}.tmp")
    if temporary.exists():
        raise FileExistsError(f"M6 report staging path exists: {temporary}")
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", type=Path, default=REPO_ROOT)
    parser.add_argument("--report-path", type=Path, default=DEFAULT_REPORT_PATH)
    parser.add_argument(
        "--recompute-only",
        action="store_true",
        help="rebuild every window and print the digest without writing anything",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.recompute_only:
            evidence, _ = recompute_evidence(args.repository_root)
            print(json.dumps({
                "mode": "recompute_only",
                "total_source_event_count": evidence.total_source_event_count,
                "total_window_count": evidence.total_window_count,
                "window_stream_sha256": evidence.window_stream_sha256,
                "partitions": [
                    {
                        "output_partition": item.output_partition,
                        "source_event_count": item.source_event_count,
                        "window_count": item.window_count,
                        "entity_count": item.entity_count,
                        "window_stream_sha256": item.digest_hex,
                    }
                    for item in evidence.partitions
                ],
            }, indent=2, sort_keys=True))
            return 0
        report = materialize(args.repository_root, args.report_path)
        print(json.dumps({
            "status": "published",
            "run_id": str(report.run_id),
            "total_window_count": report.total_window_count,
            "total_source_event_count": report.total_source_event_count,
            "window_stream_sha256": report.window_stream_sha256,
            "report_content_sha256": report.content_sha256(),
        }, indent=2, sort_keys=True))
        return 0
    except (M6RunError, OSError, ValueError) as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}, indent=2))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
