"""Focused tests for the seven-point frozen M3 v2 report verification gate.

Each of the seven checks is exercised on the real frozen artifact for the
success path and with deliberate tampering for the failure path. Tampered
copies are written only into pytest ``tmp_path``; the frozen artifact itself is
never modified.
"""
from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import shutil

import pytest

from modules.detection.src.persistence.report_verification_v2 import (
    CANONICAL_M3_V2_REPORT_RELATIVE_PATH,
    FROZEN_M3_V2_IDENTITY,
    M3ReportVerificationError,
    VerifiedM3Report,
    verify_frozen_m3_v2_report,
)
from modules.detection.src.schemas.zeek_normalization_run_v2 import (
    ZeekNormalizationRunReportV2,
)


ROOT = Path(__file__).resolve().parents[3]
FROZEN_REPORT = ROOT / CANONICAL_M3_V2_REPORT_RELATIVE_PATH


def _isolated_root(tmp_path: Path, payload: bytes) -> Path:
    """Build a throwaway repository root containing only a report artifact."""
    destination = tmp_path / CANONICAL_M3_V2_REPORT_RELATIVE_PATH
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(payload)
    return tmp_path


# --- Success path -----------------------------------------------------------


def test_gate_accepts_the_official_frozen_report() -> None:
    """All seven checks pass against the real published artifact."""
    verified = verify_frozen_m3_v2_report(ROOT)

    assert isinstance(verified, VerifiedM3Report)
    assert isinstance(verified.report, ZeekNormalizationRunReportV2)
    assert verified.report_file_sha256 == FROZEN_M3_V2_IDENTITY.report_file_sha256
    assert verified.report_content_sha256 == (
        FROZEN_M3_V2_IDENTITY.report_content_sha256
    )
    assert verified.protocol_sha256 == FROZEN_M3_V2_IDENTITY.protocol_sha256
    assert verified.canonical_event_stream_sha256 == (
        FROZEN_M3_V2_IDENTITY.canonical_event_stream_sha256
    )
    assert verified.rejection_audit_stream_sha256 == (
        FROZEN_M3_V2_IDENTITY.rejection_audit_stream_sha256
    )


def test_gate_returns_frozen_observed_counts() -> None:
    """The verified report carries the frozen observed counts."""
    verified = verify_frozen_m3_v2_report(ROOT)
    report = verified.report

    assert report.total_processed_record_count == (
        FROZEN_M3_V2_IDENTITY.total_processed_record_count
    )
    assert report.total_accepted_record_count == (
        FROZEN_M3_V2_IDENTITY.total_accepted_record_count
    )
    assert report.total_rejected_record_count == (
        FROZEN_M3_V2_IDENTITY.total_rejected_record_count
    )


def test_frozen_artifact_is_not_modified_by_verification() -> None:
    """Running the gate leaves the frozen artifact byte-identical."""
    before = FROZEN_REPORT.read_bytes()
    verify_frozen_m3_v2_report(ROOT)
    assert FROZEN_REPORT.read_bytes() == before


# --- Check 1: presence / readability ---------------------------------------


def test_gate_stops_when_report_is_missing(tmp_path: Path) -> None:
    with pytest.raises(M3ReportVerificationError, match="is missing"):
        verify_frozen_m3_v2_report(tmp_path)


# --- Check 2: raw file SHA-256 --------------------------------------------


def test_gate_stops_on_file_hash_mismatch(tmp_path: Path) -> None:
    """Byte-level tampering that preserves semantics still fails the file hash."""
    payload = FROZEN_REPORT.read_bytes()
    # Appending whitespace keeps the JSON semantically identical but changes bytes.
    root = _isolated_root(tmp_path, payload + b"\n")

    with pytest.raises(M3ReportVerificationError, match="file SHA-256 mismatch"):
        verify_frozen_m3_v2_report(root)


# --- Check 3: contract validation -----------------------------------------


def test_gate_stops_when_contract_validation_fails(tmp_path: Path) -> None:
    """A structurally invalid report fails ZeekNormalizationRunReportV2."""
    document = json.loads(FROZEN_REPORT.read_bytes())
    document.pop("partition_reports")
    payload = json.dumps(document).encode("utf-8")
    root = _isolated_root(tmp_path, payload)

    expected_file_sha256 = __import__("hashlib").sha256(payload).hexdigest()
    identity = replace(
        FROZEN_M3_V2_IDENTITY, report_file_sha256=expected_file_sha256
    )

    with pytest.raises(M3ReportVerificationError, match="failed .* validation"):
        verify_frozen_m3_v2_report(
            root, CANONICAL_M3_V2_REPORT_RELATIVE_PATH, identity
        )


# --- Check 4: content SHA-256 ---------------------------------------------


def test_gate_stops_on_content_hash_mismatch(tmp_path: Path) -> None:
    """Semantic tampering is caught by the formatting-independent hash."""
    payload = FROZEN_REPORT.read_bytes()
    root = _isolated_root(tmp_path, payload)

    identity = replace(
        FROZEN_M3_V2_IDENTITY,
        report_content_sha256="0" * 64,
    )

    with pytest.raises(M3ReportVerificationError, match="content SHA-256 mismatch"):
        verify_frozen_m3_v2_report(
            root, CANONICAL_M3_V2_REPORT_RELATIVE_PATH, identity
        )


# --- Check 5: protocol identity -------------------------------------------


def test_gate_stops_on_protocol_identity_mismatch(tmp_path: Path) -> None:
    payload = FROZEN_REPORT.read_bytes()
    root = _isolated_root(tmp_path, payload)

    identity = replace(FROZEN_M3_V2_IDENTITY, protocol_sha256="1" * 64)

    with pytest.raises(
        M3ReportVerificationError, match="protocol identity mismatch"
    ):
        verify_frozen_m3_v2_report(
            root, CANONICAL_M3_V2_REPORT_RELATIVE_PATH, identity
        )


# --- Check 6: canonical event stream digest -------------------------------


def test_gate_stops_on_event_stream_digest_mismatch(tmp_path: Path) -> None:
    payload = FROZEN_REPORT.read_bytes()
    root = _isolated_root(tmp_path, payload)

    identity = replace(
        FROZEN_M3_V2_IDENTITY, canonical_event_stream_sha256="2" * 64
    )

    with pytest.raises(
        M3ReportVerificationError, match="canonical event stream SHA-256 mismatch"
    ):
        verify_frozen_m3_v2_report(
            root, CANONICAL_M3_V2_REPORT_RELATIVE_PATH, identity
        )


# --- Check 7: rejection audit stream digest -------------------------------


def test_gate_stops_on_rejection_stream_digest_mismatch(tmp_path: Path) -> None:
    payload = FROZEN_REPORT.read_bytes()
    root = _isolated_root(tmp_path, payload)

    identity = replace(
        FROZEN_M3_V2_IDENTITY, rejection_audit_stream_sha256="3" * 64
    )

    with pytest.raises(
        M3ReportVerificationError, match="rejection audit stream SHA-256 mismatch"
    ):
        verify_frozen_m3_v2_report(
            root, CANONICAL_M3_V2_REPORT_RELATIVE_PATH, identity
        )


# --- Ordering guarantee ---------------------------------------------------


def test_file_hash_is_checked_before_contract_validation(tmp_path: Path) -> None:
    """A byte-tampered *and* structurally broken report fails on the file hash."""
    document = json.loads(FROZEN_REPORT.read_bytes())
    document.pop("partition_reports")
    root = _isolated_root(tmp_path, json.dumps(document).encode("utf-8"))

    with pytest.raises(M3ReportVerificationError, match="file SHA-256 mismatch"):
        verify_frozen_m3_v2_report(root)


# --- Package export surface ----------------------------------------------


def test_persistence_package_exports_the_gate() -> None:
    import modules.detection.src.persistence as persistence

    for name in (
        "FROZEN_M3_V2_IDENTITY",
        "M3ReportVerificationError",
        "M4MaterializationReportV2",
        "M4PartitionMaterializationCountsV2",
        "VerifiedM3Report",
        "verify_frozen_m3_v2_report",
    ):
        assert name in persistence.__all__
        assert hasattr(persistence, name)


def test_schema_ddl_exists_and_declares_authorized_constraints() -> None:
    """The M4 DDL exists and encodes the authorized Phase 1 decisions."""
    ddl = (
        Path(__file__).resolve().parents[1]
        / "src"
        / "persistence"
        / "schema_v2.sql"
    ).read_text(encoding="utf-8")

    assert "CREATE SCHEMA IF NOT EXISTS m4_canonical" in ddl
    assert "event_id                    UUID PRIMARY KEY" in ddl
    assert "UNIQUE (output_partition, physical_line_number)" in ddl
    assert "WHERE status = 'verified'" in ddl
    assert "NUMERIC(38, 22)" in ddl
    assert "termination_reason IS NULL" in ddl
