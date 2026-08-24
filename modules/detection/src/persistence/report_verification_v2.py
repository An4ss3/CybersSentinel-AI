"""Frozen M3 v2 report verification gate for M4 materialization.

M4 must not materialize anything until the frozen M3 v2 run report has been
proven identical to the officially frozen evidence. This module implements the
seven-point gate from the M4 design specification:

1. The report file exists and is readable.
2. Its raw file SHA-256 matches the frozen file identity.
3. It validates against ``ZeekNormalizationRunReportV2`` (which enforces every
   internal count/span/ordering invariant of the frozen contract).
4. Its formatting-independent ``content_sha256()`` matches the frozen identity.
5. Its ``protocol_sha256`` matches the authoritative M3 v2 protocol identity.
6. Its ``canonical_event_stream_sha256`` matches the frozen event stream digest.
7. Its ``rejection_audit_stream_sha256`` matches the frozen rejection digest.

Any failure raises ``M3ReportVerificationError`` and M4 must stop. This module
reads the frozen artifact and frozen contract only; it never modifies, reopens,
regenerates, or refactors any M3 v2 file or artifact.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Final

from pydantic import ValidationError

from modules.detection.src.schemas.zeek_normalization_run_v2 import (
    ZeekNormalizationRunReportV2,
)


CANONICAL_M3_V2_REPORT_RELATIVE_PATH: Final[str] = (
    "artifacts/reports/m3_v2_normalization_run.json"
)


@dataclass(frozen=True, slots=True)
class FrozenM3V2Identity:
    """The officially frozen M3 v2 identities M4 binds itself to."""

    report_content_sha256: str
    report_file_sha256: str
    protocol_sha256: str
    canonical_event_stream_sha256: str
    rejection_audit_stream_sha256: str
    total_processed_record_count: int
    total_accepted_record_count: int
    total_rejected_record_count: int


FROZEN_M3_V2_IDENTITY: Final[FrozenM3V2Identity] = FrozenM3V2Identity(
    report_content_sha256=(
        "6c9ef7aa545769d0e4b913b1227dc27f43ab1734227f9afeb8d1d642264848e0"
    ),
    report_file_sha256=(
        "62426406249a96eb991a0c6bdcde78cd0b730afaa7de057d7740c2d5f62a8032"
    ),
    protocol_sha256=(
        "5286ddde937ad132afdeb8814e0e0af01745afbb7d1d446ae8860b7701fea210"
    ),
    canonical_event_stream_sha256=(
        "ce71a3401f606ecedac11007fdd9d649d32d10b969c53e961db6b96710b1d82f"
    ),
    rejection_audit_stream_sha256=(
        "b443b14c9894ea342b199e9c9880360a9cf3d00cf490164e7d2cf2f2d2f09b5f"
    ),
    total_processed_record_count=1_380_057,
    total_accepted_record_count=1_353_467,
    total_rejected_record_count=26_590,
)


class M3ReportVerificationError(RuntimeError):
    """The frozen M3 v2 report does not match its official identity."""


@dataclass(frozen=True, slots=True)
class VerifiedM3Report:
    """A frozen M3 v2 report proven identical to the official freeze evidence."""

    report: ZeekNormalizationRunReportV2
    report_path: Path
    report_file_sha256: str
    report_content_sha256: str

    @property
    def protocol_sha256(self) -> str:
        return self.report.protocol_sha256

    @property
    def canonical_event_stream_sha256(self) -> str:
        return self.report.canonical_event_stream_sha256

    @property
    def rejection_audit_stream_sha256(self) -> str:
        return self.report.rejection_audit_stream_sha256


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise M3ReportVerificationError(message)


def verify_frozen_m3_v2_report(
    repository_root: str | Path,
    report_relative_path: str = CANONICAL_M3_V2_REPORT_RELATIVE_PATH,
    expected: FrozenM3V2Identity = FROZEN_M3_V2_IDENTITY,
) -> VerifiedM3Report:
    """Run the seven-point gate and return the verified frozen report.

    Raises ``M3ReportVerificationError`` on any mismatch. The caller must treat
    any exception as a terminal stop condition for M4.
    """
    root = Path(repository_root).resolve(strict=True)
    report_path = (root / report_relative_path).resolve()

    # 1. The report file exists and is readable.
    _require(
        report_path.is_file(),
        f"frozen M3 v2 report is missing: {report_path}",
    )
    try:
        payload = report_path.read_bytes()
    except OSError as error:
        raise M3ReportVerificationError(
            f"frozen M3 v2 report is unreadable: {report_path}"
        ) from error

    # 2. Raw file SHA-256 matches the frozen file identity.
    observed_file_sha256 = sha256(payload).hexdigest()
    _require(
        observed_file_sha256 == expected.report_file_sha256,
        "frozen M3 v2 report file SHA-256 mismatch: "
        f"expected {expected.report_file_sha256}, observed {observed_file_sha256}",
    )

    # 3. Validates against the frozen report contract.
    try:
        report = ZeekNormalizationRunReportV2.model_validate_json(payload)
    except ValidationError as error:
        raise M3ReportVerificationError(
            "frozen M3 v2 report failed ZeekNormalizationRunReportV2 validation"
        ) from error

    # 4. Formatting-independent content SHA-256 matches the frozen identity.
    observed_content_sha256 = report.content_sha256()
    _require(
        observed_content_sha256 == expected.report_content_sha256,
        "frozen M3 v2 report content SHA-256 mismatch: "
        f"expected {expected.report_content_sha256}, "
        f"observed {observed_content_sha256}",
    )

    # 5. Protocol identity matches the authoritative M3 v2 protocol.
    _require(
        report.protocol_sha256 == expected.protocol_sha256,
        "frozen M3 v2 protocol identity mismatch: "
        f"expected {expected.protocol_sha256}, observed {report.protocol_sha256}",
    )

    # 6. Canonical event stream digest matches the frozen value.
    _require(
        report.canonical_event_stream_sha256 == expected.canonical_event_stream_sha256,
        "frozen M3 v2 canonical event stream SHA-256 mismatch: "
        f"expected {expected.canonical_event_stream_sha256}, "
        f"observed {report.canonical_event_stream_sha256}",
    )

    # 7. Rejection audit stream digest matches the frozen value.
    _require(
        report.rejection_audit_stream_sha256
        == expected.rejection_audit_stream_sha256,
        "frozen M3 v2 rejection audit stream SHA-256 mismatch: "
        f"expected {expected.rejection_audit_stream_sha256}, "
        f"observed {report.rejection_audit_stream_sha256}",
    )

    return VerifiedM3Report(
        report=report,
        report_path=report_path,
        report_file_sha256=observed_file_sha256,
        report_content_sha256=observed_content_sha256,
    )
