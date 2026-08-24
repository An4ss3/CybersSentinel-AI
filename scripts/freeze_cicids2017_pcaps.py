"""Freeze and verify the approved CICIDS2017 PCAP subset for M1.

This command integrates PCAPs obtained manually through the official CIC gate.
It never downloads data, invokes Zeek, parses packets, or creates events.

Example:
    python scripts/freeze_cicids2017_pcaps.py \
      --capture 2017-07-04=Tuesday-WorkingHours.pcap \
      --capture 2017-07-05=Wednesday-WorkingHours.pcap \
      --capture 2017-07-07=Friday-WorkingHours.pcap \
      --retrieved-at 2026-07-27T12:00:00Z \
      --frozen-at 2026-07-27T13:00:00Z
"""
from __future__ import annotations

import argparse
from datetime import date, datetime, timedelta
import json
from pathlib import Path
from typing import Sequence

from modules.detection.src.lineage import (
    build_dataset_freeze_manifest,
    build_dataset_verification_report,
    load_dataset_freeze_manifest,
    verify_dataset_freeze,
    write_immutable_dataset_manifest,
    write_immutable_verification_report,
)
from modules.detection.src.schemas import DatasetSource


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATASET_ROOT = REPO_ROOT / "datasets" / "CICIDS2017" / "pcap"
DEFAULT_MANIFEST_PATH = (
    REPO_ROOT / "datasets" / "manifests" / "cicids2017_pcap_freeze.yaml"
)
DEFAULT_REPORT_PATH = (
    REPO_ROOT
    / "artifacts"
    / "canonical"
    / "cicids2017"
    / "m1"
    / "dataset_freeze_verification.json"
)
OFFICIAL_PUBLISHER = "Canadian Institute for Cybersecurity"
OFFICIAL_LANDING_PAGE = "https://www.unb.ca/cic/datasets/ids-2017.html"
OFFICIAL_DOWNLOAD_GATE = "https://cicresearch.ca/CICDataset/CIC-IDS-2017/"
APPROVED_CAPTURE_DATES = frozenset(
    (date(2017, 7, 4), date(2017, 7, 5), date(2017, 7, 7))
)
SELECTION_RATIONALE = (
    "Complete Tuesday, Wednesday, and Friday CICIDS2017 captures selected "
    "before Zeek replay, feature engineering, or canonical model inspection; "
    "Monday and Thursday are excluded from the initial canonical freeze."
)


def parse_utc_datetime(value: str) -> datetime:
    """Parse an explicit UTC timestamp without silently converting timezones."""
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid ISO-8601 timestamp: {value}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise argparse.ArgumentTypeError("timestamp must be timezone-aware UTC")
    return parsed


def parse_capture_specs(values: Sequence[str]) -> dict[str, date]:
    """Parse DATE=RELATIVE_PATH entries and enforce the approved three days."""
    selections: dict[str, date] = {}
    for value in values:
        date_text, separator, relative_path = value.partition("=")
        if not separator or not relative_path:
            raise ValueError("capture must use DATE=RELATIVE_PATH syntax")
        try:
            capture_date = date.fromisoformat(date_text)
        except ValueError as exc:
            raise ValueError(f"invalid capture date: {date_text}") from exc
        if capture_date not in APPROVED_CAPTURE_DATES:
            raise ValueError(
                f"capture date is outside the approved M1 scope: {capture_date}"
            )
        if relative_path in selections:
            raise ValueError(f"duplicate capture path: {relative_path}")
        selections[relative_path] = capture_date

    represented_dates = set(selections.values())
    if represented_dates != APPROVED_CAPTURE_DATES:
        missing = sorted(APPROVED_CAPTURE_DATES - represented_dates)
        extra = sorted(represented_dates - APPROVED_CAPTURE_DATES)
        raise ValueError(
            f"captures must represent exactly Tuesday, Wednesday, and Friday; "
            f"missing={missing}, extra={extra}"
        )
    return selections


def freeze_cicids2017_pcaps(
    *,
    dataset_root: Path,
    manifest_path: Path,
    report_path: Path,
    file_capture_dates: dict[str, date],
    retrieved_at: datetime,
    frozen_at: datetime,
) -> dict[str, object]:
    """Build, verify, and immutably persist the approved M1 evidence freeze."""
    if set(file_capture_dates.values()) != APPROVED_CAPTURE_DATES:
        raise ValueError("freeze scope must contain Tuesday, Wednesday, and Friday")

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
        "dataset_root": str(dataset_root),
        "manifest_path": str(manifest_path),
        "manifest_sha256": manifest_sha256,
        "report_path": str(report_path),
        "report_sha256": report_sha256,
        "verified_file_count": report.verified_file_count,
        "verified_total_size_bytes": report.verified_total_size_bytes,
    }


def build_parser() -> argparse.ArgumentParser:
    """Create the command-line parser without performing filesystem I/O."""
    parser = argparse.ArgumentParser(
        description=(
            "Freeze official CICIDS2017 Tuesday/Wednesday/Friday PCAP evidence."
        )
    )
    parser.add_argument(
        "--capture",
        action="append",
        required=True,
        metavar="DATE=RELATIVE_PATH",
        help="repeat for every selected PCAP; all three approved dates are required",
    )
    parser.add_argument("--retrieved-at", required=True, type=parse_utc_datetime)
    parser.add_argument("--frozen-at", required=True, type=parse_utc_datetime)
    parser.add_argument("--dataset-root", type=Path, default=DEFAULT_DATASET_ROOT)
    parser.add_argument("--manifest-path", type=Path, default=DEFAULT_MANIFEST_PATH)
    parser.add_argument("--report-path", type=Path, default=DEFAULT_REPORT_PATH)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the deterministic M1 freeze command and print its identities."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        selections = parse_capture_specs(args.capture)
        result = freeze_cicids2017_pcaps(
            dataset_root=args.dataset_root,
            manifest_path=args.manifest_path,
            report_path=args.report_path,
            file_capture_dates=selections,
            retrieved_at=args.retrieved_at,
            frozen_at=args.frozen_at,
        )
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
