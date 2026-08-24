"""M4 materialization report construction and immutable publication.

Converts an observed ``MaterializationOutcome`` into the authorized
``M4MaterializationReportV2`` contract, then publishes it immutably using the
same pattern as the frozen M3 v2 publisher
(``write_immutable_normalization_report_v2``): fail-if-exists, exclusive
create, ``fsync`` of the written file descriptor, and atomic rename.

The frozen M3 v2 publisher is used as a read-only reference only; it is never
imported for mutation, modified, reopened, or refactored.

Reported values are always the *observed* materialization results. Nothing is
projected, defaulted, or invented. ``verification_status`` is derived by
comparing the observed stream digests to the frozen M3 v2 digests, so a run
whose digests do not reproduce the frozen evidence can never be published as
``verified``.
"""
from __future__ import annotations

from hashlib import sha256
import os
from pathlib import Path
from typing import Final

from modules.detection.src.persistence.materialization_v2 import (
    M4MaterializationError,
    MaterializationOutcome,
)
from modules.detection.src.persistence.report_verification_v2 import VerifiedM3Report
from modules.detection.src.persistence.run_report_v2 import (
    M4MaterializationReportV2,
    M4PartitionMaterializationCountsV2,
)


CANONICAL_M4_V2_REPORT_RELATIVE_PATH: Final[str] = (
    "artifacts/reports/m4_v2_materialization_run.json"
)

M4_REPORT_VERSION: Final[str] = "1.0.0"


class M4ReportBuildError(M4MaterializationError):
    """The observed outcome cannot be expressed as a consistent M4 report."""


def derive_verification_status(
    outcome: MaterializationOutcome,
    verified_m3_report: VerifiedM3Report,
) -> str:
    """Return ``"verified"`` only if both observed digests reproduce M3 v2."""
    event_matches = (
        outcome.materialized_event_stream_sha256
        == verified_m3_report.canonical_event_stream_sha256
    )
    rejection_matches = (
        outcome.materialized_rejection_stream_sha256
        == verified_m3_report.rejection_audit_stream_sha256
    )
    return "verified" if (event_matches and rejection_matches) else "failed"


def build_materialization_report_v2(
    outcome: MaterializationOutcome,
    verified_m3_report: VerifiedM3Report,
) -> M4MaterializationReportV2:
    """Build the validated M4 report from observed materialization evidence.

    Raises ``M4ReportBuildError`` if the outcome's own declared status
    disagrees with the status derived from the observed digests, so mislabelled
    evidence fails loudly instead of being published.
    """
    derived_status = derive_verification_status(outcome, verified_m3_report)

    if outcome.verification_status not in ("verified", "failed"):
        raise M4ReportBuildError(
            "unknown materialization verification_status: "
            f"{outcome.verification_status!r}"
        )
    if outcome.verification_status != derived_status:
        raise M4ReportBuildError(
            "materialization outcome status disagrees with observed digests: "
            f"declared={outcome.verification_status!r}, derived={derived_status!r}"
        )

    partition_counts = tuple(
        M4PartitionMaterializationCountsV2(
            output_partition=result.output_partition,
            source_log_sha256=result.source_log_sha256,
            reported_record_count=result.reported_record_count,
            processed_record_count=result.processed_record_count,
            accepted_record_count=result.accepted_record_count,
            rejected_record_count=result.rejected_record_count,
            persisted_event_count=result.persisted_event_count,
        )
        for result in outcome.partition_results
    )

    report = verified_m3_report.report
    return M4MaterializationReportV2(
        report_version=M4_REPORT_VERSION,
        run_id=outcome.run_id,
        verification_status=derived_status,
        m3_report_content_sha256=verified_m3_report.report_content_sha256,
        m3_report_file_sha256=verified_m3_report.report_file_sha256,
        m3_protocol_sha256=report.protocol_sha256,
        m3_event_stream_sha256=report.canonical_event_stream_sha256,
        m3_rejection_audit_stream_sha256=report.rejection_audit_stream_sha256,
        total_processed_record_count=outcome.total_processed_record_count,
        total_accepted_record_count=outcome.total_accepted_record_count,
        total_rejected_record_count=outcome.total_rejected_record_count,
        total_persisted_event_count=outcome.total_persisted_event_count,
        materialized_event_stream_sha256=outcome.materialized_event_stream_sha256,
        materialized_rejection_stream_sha256=(
            outcome.materialized_rejection_stream_sha256
        ),
        started_at=outcome.started_at,
        completed_at=outcome.completed_at,
        partition_counts=partition_counts,
    )


def write_immutable_materialization_report_v2(
    report: M4MaterializationReportV2,
    path: str | Path,
) -> str:
    """Publish the M4 report immutably. Returns SHA-256 of the written bytes.

    Mirrors the frozen M3 v2 publication pattern exactly:
    - Fails rather than overwriting an existing report.
    - Fails rather than reusing a residual staging file.
    - Exclusive create, write, flush, ``fsync`` of the file descriptor.
    - Atomic rename into place.
    - Removes the staging file on any failure.

    Note: the frozen M3 v2 publisher does not fsync the containing directory;
    this publisher deliberately matches that behavior rather than diverging.
    """
    destination = Path(path)
    if destination.exists():
        raise FileExistsError(
            f"M4 materialization report already exists: {destination}"
        )
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = report.model_dump_json(indent=2).encode("utf-8") + b"\n"
    temporary = destination.with_name(f".{destination.name}.tmp")
    if temporary.exists():
        raise FileExistsError(
            f"M4 materialization report staging path exists: {temporary}"
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
