"""Execute the M4 canonical event materialization and publish its evidence.

Orchestrates, in this exact order:

    1. seven-point frozen M3 v2 verification gate
    2. ensure the m4_canonical PostgreSQL schema exists
    3. materialize canonical events + rejection evidence
    4. build the M4MaterializationReportV2 from the observed outcome
    5. publish that report immutably

Every stage reuses the existing M4 implementation; nothing is duplicated and no
value is invented. The report is only ever built from a real
``MaterializationOutcome`` produced by the materialization adapter.

Failure at any stage prevents false success:
  * verification failure  -> no materialization, no report
  * schema failure        -> no materialization, no report
  * materialization error -> no report (the failed run row is retained in
                             PostgreSQL for audit)
  * build failure         -> no publication
  * existing report       -> refused up front, before any materialization
  * publication failure   -> reported explicitly as materialized-but-unpublished

This command never modifies M1, M2, or any frozen M3 v2 artifact.

Example:
    python scripts/materialize_m4_canonical_events.py
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
from pathlib import Path
from typing import Sequence
from uuid import UUID

from modules.detection.src.lineage.zeek_normalization_v2 import (
    load_and_bind_zeek_normalization_specification_v2,
)
from modules.detection.src.persistence.db import ensure_m4_schema, get_connection
from modules.detection.src.persistence.materialization_v2 import (
    M4MaterializationError,
    ZeekConnMaterializationAdapterV2,
)
from modules.detection.src.persistence.report_publication_v2 import (
    CANONICAL_M4_V2_REPORT_RELATIVE_PATH,
    build_materialization_report_v2,
    write_immutable_materialization_report_v2,
)
from modules.detection.src.persistence.report_verification_v2 import (
    verify_frozen_m3_v2_report,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REPORT_PATH = REPO_ROOT / CANONICAL_M4_V2_REPORT_RELATIVE_PATH


class M4ProductionRunError(RuntimeError):
    """The M4 production run could not complete successfully."""


class M4SchemaPreparationError(M4ProductionRunError):
    """The m4_canonical schema could not be prepared; nothing was materialized."""


class M4ConnectionError(M4ProductionRunError):
    """PostgreSQL is unreachable; nothing was materialized."""


class M4ReportAlreadyPublishedError(M4ProductionRunError):
    """A production M4 report already exists and must never be overwritten."""


class M4PublicationFailedError(M4ProductionRunError):
    """Materialization succeeded but the report could not be published.

    This is deliberately distinct from every other failure: PostgreSQL holds a
    verified materialization while no immutable report exists on disk. The run
    must not be reported as complete.
    """

    def __init__(self, message: str, run_id: UUID) -> None:
        super().__init__(message)
        self.run_id = run_id


@dataclass(frozen=True, slots=True)
class ProductionRunResult:
    """Identities of one completed and published M4 production run."""

    status: str
    run_id: UUID
    report_path: Path
    report_file_sha256: str
    report_content_sha256: str
    verification_status: str
    total_processed_record_count: int
    total_accepted_record_count: int
    total_rejected_record_count: int
    total_persisted_event_count: int
    materialized_event_stream_sha256: str
    materialized_rejection_stream_sha256: str

    def as_json_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "run_id": str(self.run_id),
            "report_path": str(self.report_path),
            "report_file_sha256": self.report_file_sha256,
            "report_content_sha256": self.report_content_sha256,
            "verification_status": self.verification_status,
            "total_processed_record_count": self.total_processed_record_count,
            "total_accepted_record_count": self.total_accepted_record_count,
            "total_rejected_record_count": self.total_rejected_record_count,
            "total_persisted_event_count": self.total_persisted_event_count,
            "materialized_event_stream_sha256": (
                self.materialized_event_stream_sha256
            ),
            "materialized_rejection_stream_sha256": (
                self.materialized_rejection_stream_sha256
            ),
        }


def run_m4_production_materialization(
    *,
    repository_root: str | Path = REPO_ROOT,
    report_path: str | Path = DEFAULT_REPORT_PATH,
) -> ProductionRunResult:
    """Run the full M4 production workflow and return its published identities.

    Success is reported only after the immutable report has been written.
    """
    root = Path(repository_root).resolve(strict=True)
    destination = Path(report_path)

    # Stage 0 — refuse to overwrite an existing production report *before* doing
    # any expensive work. Publication is fail-if-exists too, but checking here
    # avoids materializing 1.38M records only to be rejected at the last step.
    if destination.exists():
        raise M4ReportAlreadyPublishedError(
            f"M4 production report already exists and will not be overwritten: "
            f"{destination}"
        )

    # Stage 1 — seven-point frozen M3 v2 verification gate.
    # Raises M3ReportVerificationError; nothing has been materialized yet.
    verified_m3 = verify_frozen_m3_v2_report(root)

    # Stage 2 — connection + schema preparation.
    connection = get_connection()
    if connection is None:
        raise M4ConnectionError(
            "PostgreSQL is unreachable; M4 materialization was not started"
        )

    try:
        try:
            ensure_m4_schema(connection)
        except Exception as error:
            raise M4SchemaPreparationError(
                f"could not prepare the m4_canonical schema: {error}"
            ) from error

        # Stage 3 — materialization using the existing Phase 2 adapter.
        bound = load_and_bind_zeek_normalization_specification_v2(root)
        adapter = ZeekConnMaterializationAdapterV2(root, bound, verified_m3)
        outcome = adapter.materialize(connection)
    finally:
        connection.close()

    # Stage 4 — build the report from the observed outcome (Phase 3).
    report = build_materialization_report_v2(outcome, verified_m3)

    # Stage 5 — immutable publication (Phase 3).
    try:
        report_file_sha256 = write_immutable_materialization_report_v2(
            report, destination
        )
    except Exception as error:
        raise M4PublicationFailedError(
            "materialization completed and is recorded in PostgreSQL, but the "
            f"immutable M4 report could not be published to {destination}: "
            f"{error}. The run is NOT complete.",
            run_id=outcome.run_id,
        ) from error

    return ProductionRunResult(
        status="published",
        run_id=report.run_id,
        report_path=destination,
        report_file_sha256=report_file_sha256,
        report_content_sha256=report.content_sha256(),
        verification_status=report.verification_status,
        total_processed_record_count=report.total_processed_record_count,
        total_accepted_record_count=report.total_accepted_record_count,
        total_rejected_record_count=report.total_rejected_record_count,
        total_persisted_event_count=report.total_persisted_event_count,
        materialized_event_stream_sha256=report.materialized_event_stream_sha256,
        materialized_rejection_stream_sha256=(
            report.materialized_rejection_stream_sha256
        ),
    )


def build_parser() -> argparse.ArgumentParser:
    """Create the command-line parser without performing filesystem I/O."""
    parser = argparse.ArgumentParser(
        description=(
            "Materialize M4 canonical events from frozen M3 v2 evidence and "
            "publish the immutable M4 materialization report."
        )
    )
    parser.add_argument("--repository-root", type=Path, default=REPO_ROOT)
    parser.add_argument("--report-path", type=Path, default=DEFAULT_REPORT_PATH)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the M4 production workflow and print its published identities."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        result = run_m4_production_materialization(
            repository_root=args.repository_root,
            report_path=args.report_path,
        )
    except (M4ProductionRunError, M4MaterializationError, OSError, ValueError) as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}, indent=2))
        return 1
    print(json.dumps(result.as_json_dict(), sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
