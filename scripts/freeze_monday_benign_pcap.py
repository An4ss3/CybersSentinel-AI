"""Freeze and verify the Monday CICIDS2017 capture for MB1 (Monday Benign).

This is the MB-track counterpart of ``scripts/freeze_cicids2017_pcaps.py``. It
is a **new script**, not a modification: the frozen M1 script excludes Monday by
design through ``APPROVED_CAPTURE_DATES``, and that exclusion is never touched.

Every integrity primitive is reused from ``lineage/dataset_freeze.py`` exactly as
it exists, with no wrapper reimplementation:

* ``build_dataset_freeze_manifest`` -> measures size and SHA-256 via
  ``inventory_pcap_evidence``;
* ``verify_dataset_freeze`` -> containment, symlink, regular-file, size,
  SHA-256, and stability-during-hash checks;
* ``build_dataset_verification_report`` -> binds totals to the inventory;
* ``write_immutable_dataset_manifest`` / ``write_immutable_verification_report``
  -> exclusive create, ``fsync``, idempotent on identical content, refusal on
  divergent content.

The publish-then-reload-then-verify ordering of the M1 script is reproduced
exactly, so the MB1 report is bound to the serialized repository bytes rather
than to the in-memory manifest.

The Monday PCAP is only ever opened in binary read mode by those primitives. No
byte under ``datasets/cicids2017/pcap/`` is written, copied, or moved.

Artifact convention
-------------------
The verification report is **JSON under ``artifacts/canonical/``**, mirroring the
existing ``artifacts/canonical/cicids2017/m1/dataset_freeze_verification.json``.
``write_immutable_verification_report`` emits JSON, so a ``.yaml`` report path
would be a misnamed file; the established convention is followed instead.

Usage
-----
``retrieved_at`` and ``frozen_at`` are mandatory and explicit, exactly as in the
M1 script, so a freeze is never silently stamped with an incidental clock read::

    python -m scripts.freeze_monday_benign_pcap \
        --retrieved-at 2026-07-28T13:08:25.402744Z \
        --frozen-at 2026-08-13T12:00:00Z

The Monday capture was acquired in the same publisher-gate session as the three
M1 captures, so passing the M1 manifest's ``retrieved_at`` is the accurate
provenance statement.
"""
from __future__ import annotations

import argparse
from collections.abc import Sequence
from datetime import date, datetime, timezone
import json
from pathlib import Path

from modules.detection.src.lineage.dataset_freeze import (
    build_dataset_freeze_manifest,
    build_dataset_verification_report,
    load_dataset_freeze_manifest,
    verify_dataset_freeze,
    write_immutable_dataset_manifest,
    write_immutable_verification_report,
)
from modules.detection.src.schemas import DatasetSource
from modules.detection.src.schemas.monday_benign_replay import (
    MB1_MANIFEST_RELATIVE_PATH,
    MONDAY_CAPTURE_DATE,
    MONDAY_PCAP_RELATIVE_PATH,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATASET_ROOT = REPO_ROOT / "datasets" / "cicids2017" / "pcap"
DEFAULT_MANIFEST_PATH = REPO_ROOT / MB1_MANIFEST_RELATIVE_PATH
MB1_VERIFICATION_REPORT_RELATIVE_PATH = (
    "artifacts/canonical/cicids2017/mb1/dataset_freeze_verification.json"
)
DEFAULT_REPORT_PATH = REPO_ROOT / MB1_VERIFICATION_REPORT_RELATIVE_PATH

# Identical official provenance strings as the M1 freeze: same publisher, same
# landing page, same download gate. Referenced by value; no M1 file is read.
OFFICIAL_PUBLISHER = "Canadian Institute for Cybersecurity"
OFFICIAL_LANDING_PAGE = "https://www.unb.ca/cic/datasets/ids-2017.html"
OFFICIAL_DOWNLOAD_GATE = "https://cicresearch.ca/CICDataset/CIC-IDS-2017/"

APPROVED_MB1_CAPTURE_DATES = frozenset((MONDAY_CAPTURE_DATE,))
SELECTION_RATIONALE = (
    "Complete Monday CICIDS2017 capture frozen as the independent benign "
    "reference day of the parallel Monday Benign track; the official schedule "
    "and label distribution identify Monday as normal activity only. This "
    "freeze is additive and leaves the M1 three-day canonical freeze unchanged."
)


class MondayBenignFreezeScopeError(ValueError):
    """Raised when a freeze request is not exactly the Monday capture."""


def parse_utc_datetime(value: str) -> datetime:
    """Parse an explicit UTC timestamp without silently converting timezones."""
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"invalid ISO-8601 timestamp: {value}"
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(None):
        raise argparse.ArgumentTypeError(
            "timestamp must be explicit UTC, for example 2026-08-13T12:00:00Z"
        )
    return parsed


def freeze_monday_benign_pcap(
    *,
    dataset_root: Path,
    manifest_path: Path,
    report_path: Path,
    file_capture_dates: dict[str, date],
    retrieved_at: datetime,
    frozen_at: datetime,
) -> dict[str, object]:
    """Build, verify, and immutably persist the MB1 Monday evidence freeze.

    The scope guard is the mirror image of the M1 script's: M1 requires exactly
    Tuesday, Wednesday and Friday; MB1 requires exactly Monday. Neither can
    silently ingest the other's evidence.
    """
    if set(file_capture_dates.values()) != APPROVED_MB1_CAPTURE_DATES:
        raise MondayBenignFreezeScopeError(
            "MB1 freeze scope must contain exactly the Monday "
            f"{MONDAY_CAPTURE_DATE.isoformat()} capture"
        )
    if len(file_capture_dates) != 1:
        raise MondayBenignFreezeScopeError(
            "MB1 freeze scope must contain exactly one PCAP"
        )
    if tuple(file_capture_dates) != (MONDAY_PCAP_RELATIVE_PATH,):
        raise MondayBenignFreezeScopeError(
            f"MB1 freeze scope must be {MONDAY_PCAP_RELATIVE_PATH}"
        )

    source = DatasetSource(
        publisher=OFFICIAL_PUBLISHER,
        landing_page_url=OFFICIAL_LANDING_PAGE,
        download_url=OFFICIAL_DOWNLOAD_GATE,
        retrieved_at=retrieved_at,
    )
    manifest = build_dataset_freeze_manifest(
        dataset_root=dataset_root,
        file_capture_dates=file_capture_dates,
        source=source,
        frozen_at=frozen_at,
        selection_rationale=SELECTION_RATIONALE,
    )

    # Verify before persistence, then reload and verify the exact serialized
    # manifest so the final report is bound to repository bytes.
    verify_dataset_freeze(manifest, dataset_root)
    manifest_sha256 = write_immutable_dataset_manifest(manifest, manifest_path)
    persisted_manifest = load_dataset_freeze_manifest(manifest_path)
    verification = verify_dataset_freeze(persisted_manifest, dataset_root)
    report = build_dataset_verification_report(persisted_manifest, verification)
    report_sha256 = write_immutable_verification_report(report, report_path)

    return {
        "status": "verified",
        "track": "monday_benign",
        "dataset_root": str(dataset_root),
        "manifest_path": str(manifest_path),
        "manifest_sha256": manifest_sha256,
        "report_path": str(report_path),
        "report_sha256": report_sha256,
        "selected_capture_days": [
            item.isoformat() for item in persisted_manifest.selected_capture_days
        ],
        "verified_file_count": report.verified_file_count,
        "verified_total_size_bytes": report.verified_total_size_bytes,
        "pcap_sha256": persisted_manifest.files[0].sha256,
    }


def build_parser() -> argparse.ArgumentParser:
    """Return the MB1 command-line interface."""
    parser = argparse.ArgumentParser(
        description=(
            "Freeze and verify the Monday CICIDS2017 capture for the MB track."
        )
    )
    parser.add_argument("--dataset-root", type=Path, default=DEFAULT_DATASET_ROOT)
    parser.add_argument("--manifest-path", type=Path, default=DEFAULT_MANIFEST_PATH)
    parser.add_argument("--report-path", type=Path, default=DEFAULT_REPORT_PATH)
    parser.add_argument(
        "--capture",
        default=MONDAY_PCAP_RELATIVE_PATH,
        help="relative path of the Monday PCAP under the dataset root",
    )
    parser.add_argument("--retrieved-at", type=parse_utc_datetime, required=True)
    parser.add_argument("--frozen-at", type=parse_utc_datetime, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the MB1 freeze and print a deterministic JSON summary."""
    args = build_parser().parse_args(argv)
    result = freeze_monday_benign_pcap(
        dataset_root=args.dataset_root,
        manifest_path=args.manifest_path,
        report_path=args.report_path,
        file_capture_dates={args.capture: MONDAY_CAPTURE_DATE},
        retrieved_at=args.retrieved_at,
        frozen_at=args.frozen_at,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
