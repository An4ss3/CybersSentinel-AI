"""Focused tests for M4 Phase 3 report construction and immutable publication.

No production artifact is ever written: every publication test targets pytest's
``tmp_path``. The full 1,380,057-record materialization is never executed;
outcomes are constructed from the *real* frozen M3 v2 per-partition evidence so
the contract invariants are exercised against authentic counts.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import ValidationError

from modules.detection.src.persistence.materialization_v2 import (
    MaterializationOutcome,
    _PartitionMaterializationResult,
)
from modules.detection.src.persistence.report_publication_v2 import (
    CANONICAL_M4_V2_REPORT_RELATIVE_PATH,
    M4ReportBuildError,
    build_materialization_report_v2,
    derive_verification_status,
    write_immutable_materialization_report_v2,
)
from modules.detection.src.persistence.report_verification_v2 import (
    FROZEN_M3_V2_IDENTITY,
    verify_frozen_m3_v2_report,
)
from modules.detection.src.persistence.run_report_v2 import (
    M4MaterializationReportV2,
)


ROOT = Path(__file__).resolve().parents[3]
STARTED = datetime(2026, 8, 10, 12, 0, 0, tzinfo=timezone.utc)
COMPLETED = STARTED + timedelta(minutes=6)


@pytest.fixture(scope="module")
def verified_m3():
    return verify_frozen_m3_v2_report(ROOT)


def _outcome_from_frozen_evidence(
    verified_m3,
    *,
    event_sha256: str | None = None,
    rejection_sha256: str | None = None,
    declared_status: str | None = None,
) -> MaterializationOutcome:
    """Build an outcome mirroring the real frozen per-partition evidence.

    Defaults reproduce the frozen digests exactly (a successful run). Overrides
    allow simulating a digest mismatch without running materialization.
    """
    report = verified_m3.report
    partition_results = tuple(
        _PartitionMaterializationResult(
            output_partition=pr.output_partition,
            source_log_sha256=pr.source_log_sha256,
            reported_record_count=pr.reported_record_count,
            processed_record_count=pr.processed_record_count,
            accepted_record_count=pr.accepted_record_count,
            rejected_record_count=pr.rejected_record_count,
            persisted_event_count=pr.accepted_record_count,
            event_stream_sha256=pr.canonical_event_stream_sha256,
            rejection_stream_sha256=pr.rejection_audit_stream_sha256,
        )
        for pr in report.partition_reports
    )
    materialized_event = (
        event_sha256
        if event_sha256 is not None
        else report.canonical_event_stream_sha256
    )
    materialized_rejection = (
        rejection_sha256
        if rejection_sha256 is not None
        else report.rejection_audit_stream_sha256
    )
    status = declared_status
    if status is None:
        status = (
            "verified"
            if (
                materialized_event == report.canonical_event_stream_sha256
                and materialized_rejection == report.rejection_audit_stream_sha256
            )
            else "failed"
        )
    return MaterializationOutcome(
        run_id=uuid4(),
        verification_status=status,
        started_at=STARTED,
        completed_at=COMPLETED,
        total_processed_record_count=sum(
            item.processed_record_count for item in partition_results
        ),
        total_accepted_record_count=sum(
            item.accepted_record_count for item in partition_results
        ),
        total_rejected_record_count=sum(
            item.rejected_record_count for item in partition_results
        ),
        total_persisted_event_count=sum(
            item.persisted_event_count for item in partition_results
        ),
        materialized_event_stream_sha256=materialized_event,
        materialized_rejection_stream_sha256=materialized_rejection,
        partition_results=partition_results,
    )


# --- 1. Outcome -> report conversion -----------------------------------


def test_outcome_converts_to_validated_report(verified_m3) -> None:
    outcome = _outcome_from_frozen_evidence(verified_m3)
    report = build_materialization_report_v2(outcome, verified_m3)

    assert isinstance(report, M4MaterializationReportV2)
    assert report.report_version == "1.0.0"
    assert report.run_id == outcome.run_id
    assert report.verification_status == "verified"
    assert report.started_at == STARTED
    assert report.completed_at == COMPLETED


# --- 2. Exact counts preserved ----------------------------------------


def test_exact_counts_are_preserved(verified_m3) -> None:
    outcome = _outcome_from_frozen_evidence(verified_m3)
    report = build_materialization_report_v2(outcome, verified_m3)

    assert report.total_processed_record_count == 1_380_057
    assert report.total_accepted_record_count == 1_353_467
    assert report.total_rejected_record_count == 26_590
    assert report.total_persisted_event_count == 1_353_467

    assert report.total_processed_record_count == (
        FROZEN_M3_V2_IDENTITY.total_processed_record_count
    )
    assert report.total_accepted_record_count == (
        FROZEN_M3_V2_IDENTITY.total_accepted_record_count
    )
    assert report.total_rejected_record_count == (
        FROZEN_M3_V2_IDENTITY.total_rejected_record_count
    )


# --- 3. M3 content-hash binding preserved ------------------------------


def test_m3_report_binding_is_preserved(verified_m3) -> None:
    outcome = _outcome_from_frozen_evidence(verified_m3)
    report = build_materialization_report_v2(outcome, verified_m3)

    assert report.m3_report_content_sha256 == (
        FROZEN_M3_V2_IDENTITY.report_content_sha256
    )
    assert report.m3_report_file_sha256 == FROZEN_M3_V2_IDENTITY.report_file_sha256
    assert report.m3_protocol_sha256 == FROZEN_M3_V2_IDENTITY.protocol_sha256


# --- 4 & 5. Stream hashes preserved -----------------------------------


def test_event_stream_hash_is_preserved(verified_m3) -> None:
    outcome = _outcome_from_frozen_evidence(verified_m3)
    report = build_materialization_report_v2(outcome, verified_m3)

    assert report.m3_event_stream_sha256 == (
        FROZEN_M3_V2_IDENTITY.canonical_event_stream_sha256
    )
    assert report.materialized_event_stream_sha256 == (
        FROZEN_M3_V2_IDENTITY.canonical_event_stream_sha256
    )


def test_rejection_stream_hash_is_preserved(verified_m3) -> None:
    outcome = _outcome_from_frozen_evidence(verified_m3)
    report = build_materialization_report_v2(outcome, verified_m3)

    assert report.m3_rejection_audit_stream_sha256 == (
        FROZEN_M3_V2_IDENTITY.rejection_audit_stream_sha256
    )
    assert report.materialized_rejection_stream_sha256 == (
        FROZEN_M3_V2_IDENTITY.rejection_audit_stream_sha256
    )


# --- 6. Successful validation + deterministic identity -----------------


def test_report_validates_and_content_hash_is_deterministic(verified_m3) -> None:
    outcome = _outcome_from_frozen_evidence(verified_m3)
    first = build_materialization_report_v2(outcome, verified_m3)
    second = build_materialization_report_v2(outcome, verified_m3)

    assert first.content_sha256() == second.content_sha256()
    assert first == second


# --- 11. Per-partition counts -----------------------------------------


def test_per_partition_counts_match_frozen_partition_reports(verified_m3) -> None:
    outcome = _outcome_from_frozen_evidence(verified_m3)
    report = build_materialization_report_v2(outcome, verified_m3)

    assert len(report.partition_counts) == 3
    partitions = [item.output_partition for item in report.partition_counts]
    assert partitions == sorted(partitions)

    for observed, frozen in zip(
        report.partition_counts, verified_m3.report.partition_reports
    ):
        assert observed.output_partition == frozen.output_partition
        assert observed.source_log_sha256 == frozen.source_log_sha256
        assert observed.reported_record_count == frozen.reported_record_count
        assert observed.processed_record_count == frozen.processed_record_count
        assert observed.accepted_record_count == frozen.accepted_record_count
        assert observed.rejected_record_count == frozen.rejected_record_count
        assert observed.persisted_event_count == frozen.accepted_record_count


# --- 12. Failed verification cannot produce a "verified" report --------


def test_digest_mismatch_derives_failed_status(verified_m3) -> None:
    outcome = _outcome_from_frozen_evidence(verified_m3, event_sha256="0" * 64)
    assert derive_verification_status(outcome, verified_m3) == "failed"

    report = build_materialization_report_v2(outcome, verified_m3)
    assert report.verification_status == "failed"
    assert report.materialized_event_stream_sha256 == "0" * 64


def test_mislabelled_verified_outcome_fails_loudly(verified_m3) -> None:
    """An outcome claiming 'verified' with mismatched digests must not build."""
    outcome = _outcome_from_frozen_evidence(
        verified_m3, rejection_sha256="1" * 64, declared_status="verified"
    )
    with pytest.raises(M4ReportBuildError, match="disagrees with observed digests"):
        build_materialization_report_v2(outcome, verified_m3)


def test_unknown_status_fails_loudly(verified_m3) -> None:
    outcome = _outcome_from_frozen_evidence(verified_m3, declared_status="partial")
    with pytest.raises(M4ReportBuildError, match="unknown materialization"):
        build_materialization_report_v2(outcome, verified_m3)


def test_contract_rejects_forged_verified_report_with_mismatched_digest(
    verified_m3,
) -> None:
    """Even bypassing the builder, the contract refuses a forged verified run.

    Uses python-mode ``model_dump()`` (not ``mode="json"``) because
    ``StrictModel`` sets ``strict=True``: a JSON-mode dump would fail field
    validation on UUID/datetime/tuple before the run validator is reached.
    """
    outcome = _outcome_from_frozen_evidence(verified_m3)
    valid = build_materialization_report_v2(outcome, verified_m3)

    payload = valid.model_dump()
    payload["materialized_event_stream_sha256"] = "2" * 64
    with pytest.raises(ValidationError, match="reproduce the frozen event stream"):
        M4MaterializationReportV2.model_validate(payload)

    payload = valid.model_dump()
    payload["materialized_rejection_stream_sha256"] = "3" * 64
    with pytest.raises(ValidationError, match="reproduce the frozen rejection"):
        M4MaterializationReportV2.model_validate(payload)


# --- 7, 8, 9. Publication: success, fail-if-exists, atomicity ----------


def test_publication_writes_exact_validated_report(verified_m3, tmp_path) -> None:
    outcome = _outcome_from_frozen_evidence(verified_m3)
    report = build_materialization_report_v2(outcome, verified_m3)

    destination = tmp_path / "reports" / "m4_v2_materialization_run.json"
    file_sha256 = write_immutable_materialization_report_v2(report, destination)

    assert destination.is_file()
    content = destination.read_bytes()
    assert sha256(content).hexdigest() == file_sha256
    assert content.endswith(b"\n")

    reloaded = M4MaterializationReportV2.model_validate_json(content)
    assert reloaded.content_sha256() == report.content_sha256()
    assert reloaded == report
    # Valid JSON, published with indent=2 like the frozen M3 pattern
    assert json.loads(content)["verification_status"] == "verified"


def test_publication_fails_if_destination_exists(verified_m3, tmp_path) -> None:
    outcome = _outcome_from_frozen_evidence(verified_m3)
    report = build_materialization_report_v2(outcome, verified_m3)

    destination = tmp_path / "m4_v2_materialization_run.json"
    write_immutable_materialization_report_v2(report, destination)

    with pytest.raises(FileExistsError, match="already exists"):
        write_immutable_materialization_report_v2(report, destination)


def test_publication_does_not_overwrite_existing_content(
    verified_m3, tmp_path
) -> None:
    outcome = _outcome_from_frozen_evidence(verified_m3)
    report = build_materialization_report_v2(outcome, verified_m3)

    destination = tmp_path / "m4_v2_materialization_run.json"
    sentinel = b"PRE-EXISTING IMMUTABLE CONTENT"
    destination.write_bytes(sentinel)

    with pytest.raises(FileExistsError):
        write_immutable_materialization_report_v2(report, destination)
    assert destination.read_bytes() == sentinel


def test_publication_fails_on_residual_staging_file(verified_m3, tmp_path) -> None:
    outcome = _outcome_from_frozen_evidence(verified_m3)
    report = build_materialization_report_v2(outcome, verified_m3)

    destination = tmp_path / "m4_v2_materialization_run.json"
    staging = destination.with_name(f".{destination.name}.tmp")
    staging.write_text("residual")

    with pytest.raises(FileExistsError, match="staging path exists"):
        write_immutable_materialization_report_v2(report, destination)
    assert not destination.exists()


def test_publication_leaves_no_staging_residue_on_success(
    verified_m3, tmp_path
) -> None:
    outcome = _outcome_from_frozen_evidence(verified_m3)
    report = build_materialization_report_v2(outcome, verified_m3)

    destination = tmp_path / "m4_v2_materialization_run.json"
    write_immutable_materialization_report_v2(report, destination)

    staging = destination.with_name(f".{destination.name}.tmp")
    assert not staging.exists()


def test_publication_cleans_staging_and_leaves_no_partial_file_on_failure(
    verified_m3, tmp_path, monkeypatch
) -> None:
    """An interrupted rename must leave neither destination nor staging behind."""
    outcome = _outcome_from_frozen_evidence(verified_m3)
    report = build_materialization_report_v2(outcome, verified_m3)

    destination = tmp_path / "m4_v2_materialization_run.json"

    def _boom(src, dst):  # noqa: ANN001
        raise OSError("simulated atomic rename failure")

    monkeypatch.setattr(os, "replace", _boom)

    with pytest.raises(OSError, match="simulated atomic rename failure"):
        write_immutable_materialization_report_v2(report, destination)

    assert not destination.exists()
    assert not destination.with_name(f".{destination.name}.tmp").exists()


# --- 10. fsync / flush behavior matches the frozen M3 pattern ----------


def test_publication_fsyncs_written_file_descriptor(
    verified_m3, tmp_path, monkeypatch
) -> None:
    outcome = _outcome_from_frozen_evidence(verified_m3)
    report = build_materialization_report_v2(outcome, verified_m3)

    fsync_calls: list[int] = []
    real_fsync = os.fsync

    def _recording_fsync(fd: int) -> None:
        fsync_calls.append(fd)
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", _recording_fsync)

    destination = tmp_path / "m4_v2_materialization_run.json"
    write_immutable_materialization_report_v2(report, destination)

    assert len(fsync_calls) == 1, "exactly one fsync of the written file descriptor"
    assert destination.is_file()


def test_publication_uses_atomic_rename(verified_m3, tmp_path, monkeypatch) -> None:
    """Publication routes through os.replace, matching the frozen M3 pattern."""
    outcome = _outcome_from_frozen_evidence(verified_m3)
    report = build_materialization_report_v2(outcome, verified_m3)

    replace_calls: list[tuple[str, str]] = []
    real_replace = os.replace

    def _recording_replace(src, dst):  # noqa: ANN001
        replace_calls.append((str(src), str(dst)))
        real_replace(src, dst)

    monkeypatch.setattr(os, "replace", _recording_replace)

    destination = tmp_path / "m4_v2_materialization_run.json"
    write_immutable_materialization_report_v2(report, destination)

    assert len(replace_calls) == 1
    source_path, target_path = replace_calls[0]
    assert source_path.endswith(".m4_v2_materialization_run.json.tmp")
    assert target_path == str(destination)


# --- No production artifact may exist as a side effect ------------------


def test_no_production_m4_report_is_created_by_these_tests(
    production_m4_report_fingerprint: str | None,
) -> None:
    """Phase 3 must neither fabricate nor mutate the production artifact.

    M4 has since been executed, so the frozen report legitimately exists. The
    invariant is therefore that this session leaves it byte-identical to what it
    found, and that any such file is the authentic materialization.
    """
    production = ROOT / CANONICAL_M4_V2_REPORT_RELATIVE_PATH
    observed = (
        sha256(production.read_bytes()).hexdigest() if production.exists() else None
    )
    assert observed == production_m4_report_fingerprint, (
        "the production M4 report must only be published after a real "
        "1,380,057-record materialization, never as a test side effect"
    )
    if observed is not None:
        report = json.loads(production.read_text(encoding="utf-8"))
        assert report["total_processed_record_count"] == 1_380_057


def test_package_exports_phase_3_symbols() -> None:
    import modules.detection.src.persistence as persistence

    for name in (
        "CANONICAL_M4_V2_REPORT_RELATIVE_PATH",
        "M4ReportBuildError",
        "build_materialization_report_v2",
        "derive_verification_status",
        "write_immutable_materialization_report_v2",
    ):
        assert name in persistence.__all__
        assert hasattr(persistence, name)
