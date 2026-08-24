"""Tests for the final M1 CICIDS2017 PCAP freeze workflow."""
from __future__ import annotations

from dataclasses import replace
from datetime import date, datetime, timezone
from hashlib import sha256
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from modules.detection.src.lineage import (
    VerifiedDatasetFreeze,
    build_dataset_freeze_manifest,
    build_dataset_verification_report,
    inventory_pcap_evidence,
    load_dataset_freeze_manifest,
    verify_dataset_freeze,
    write_immutable_dataset_manifest,
    write_immutable_verification_report,
)
from modules.detection.src.schemas import (
    DatasetFreezeVerificationReport,
    DatasetSource,
)
from scripts.freeze_cicids2017_pcaps import (
    APPROVED_CAPTURE_DATES,
    OFFICIAL_DOWNLOAD_GATE,
    OFFICIAL_LANDING_PAGE,
    freeze_cicids2017_pcaps,
    parse_capture_specs,
    parse_utc_datetime,
)


TUESDAY = date(2017, 7, 4)
WEDNESDAY = date(2017, 7, 5)
FRIDAY = date(2017, 7, 7)
RETRIEVED_AT = datetime(2026, 7, 27, 10, 0, tzinfo=timezone.utc)
FROZEN_AT = datetime(2026, 7, 27, 10, 30, tzinfo=timezone.utc)
CAPTURE_BYTES = {
    "Tuesday.pcap": b"synthetic Tuesday evidence",
    "Wednesday.pcap": b"synthetic Wednesday evidence",
    "Friday.pcap": b"synthetic Friday evidence",
}
CAPTURE_DATES = {
    "Tuesday.pcap": TUESDAY,
    "Wednesday.pcap": WEDNESDAY,
    "Friday.pcap": FRIDAY,
}


def _write_captures(root: Path) -> None:
    root.mkdir(parents=True)
    for relative_path, content in CAPTURE_BYTES.items():
        (root / relative_path).write_bytes(content)


def _source() -> DatasetSource:
    return DatasetSource(
        publisher="Canadian Institute for Cybersecurity",
        landing_page_url=OFFICIAL_LANDING_PAGE,
        download_url=OFFICIAL_DOWNLOAD_GATE,
        retrieved_at=RETRIEVED_AT,
    )


def _build_manifest(root: Path):
    return build_dataset_freeze_manifest(
        dataset_root=root,
        file_capture_dates=CAPTURE_DATES,
        source=_source(),
        frozen_at=FROZEN_AT,
        selection_rationale="Approved test selection before downstream processing.",
    )


def test_inventory_measures_real_bytes_and_uses_deterministic_order(
    tmp_path: Path,
) -> None:
    root = tmp_path / "pcap"
    _write_captures(root)

    files = inventory_pcap_evidence(root, CAPTURE_DATES)

    assert [(item.capture_date, item.relative_path) for item in files] == [
        (TUESDAY, "Tuesday.pcap"),
        (WEDNESDAY, "Wednesday.pcap"),
        (FRIDAY, "Friday.pcap"),
    ]
    for item in files:
        content = CAPTURE_BYTES[item.relative_path]
        assert item.size_bytes == len(content)
        assert item.sha256 == sha256(content).hexdigest()


def test_inventory_validates_relative_paths_before_filesystem_access(
    tmp_path: Path,
) -> None:
    root = tmp_path / "pcap"
    root.mkdir()

    with pytest.raises(ValidationError, match="inside the dataset root"):
        inventory_pcap_evidence(root, {"../outside.pcap": TUESDAY})


def test_report_is_bound_to_the_verified_manifest(tmp_path: Path) -> None:
    root = tmp_path / "pcap"
    _write_captures(root)
    manifest = _build_manifest(root)
    verification = verify_dataset_freeze(manifest, root)

    report = build_dataset_verification_report(manifest, verification)

    assert report.verification_status == "verified"
    assert report.verification_method == "complete_inventory_size_sha256"
    assert report.manifest_sha256 == manifest.content_sha256()
    assert report.verified_file_count == 3
    assert report.verified_total_size_bytes == sum(
        len(value) for value in CAPTURE_BYTES.values()
    )

    forged = replace(verification, manifest_sha256="0" * 64)
    with pytest.raises(ValueError, match="does not belong"):
        build_dataset_verification_report(manifest, forged)


def test_report_contract_rejects_inconsistent_totals(tmp_path: Path) -> None:
    root = tmp_path / "pcap"
    _write_captures(root)
    manifest = _build_manifest(root)
    report = build_dataset_verification_report(
        manifest,
        verify_dataset_freeze(manifest, root),
    )
    payload = report.model_dump()
    payload["verified_total_size_bytes"] += 1

    with pytest.raises(ValidationError, match="must equal file byte sizes"):
        DatasetFreezeVerificationReport.model_validate(payload)


def test_immutable_writers_are_idempotent_and_reject_replacement(
    tmp_path: Path,
) -> None:
    root = tmp_path / "pcap"
    _write_captures(root)
    manifest = _build_manifest(root)
    verification = verify_dataset_freeze(manifest, root)
    report = build_dataset_verification_report(manifest, verification)
    manifest_path = tmp_path / "manifest.yaml"
    report_path = tmp_path / "report.json"

    first_manifest_hash = write_immutable_dataset_manifest(manifest, manifest_path)
    first_report_hash = write_immutable_verification_report(report, report_path)
    original_manifest_bytes = manifest_path.read_bytes()
    original_report_bytes = report_path.read_bytes()

    assert write_immutable_dataset_manifest(manifest, manifest_path) == first_manifest_hash
    assert write_immutable_verification_report(report, report_path) == first_report_hash
    assert manifest_path.read_bytes() == original_manifest_bytes
    assert report_path.read_bytes() == original_report_bytes

    report_path.write_text("{}\n", encoding="utf-8")
    with pytest.raises(FileExistsError, match="different content"):
        write_immutable_verification_report(report, report_path)


def test_complete_local_workflow_persists_reloadable_verified_artifacts(
    tmp_path: Path,
) -> None:
    root = tmp_path / "datasets" / "CICIDS2017" / "pcap"
    _write_captures(root)
    (root / "Monday-WorkingHours.pcap").write_bytes(b"unselected official evidence")
    manifest_path = tmp_path / "datasets" / "manifests" / "freeze.yaml"
    report_path = tmp_path / "artifacts" / "canonical" / "m1" / "report.json"

    result = freeze_cicids2017_pcaps(
        dataset_root=root,
        manifest_path=manifest_path,
        report_path=report_path,
        file_capture_dates=CAPTURE_DATES,
        retrieved_at=RETRIEVED_AT,
        frozen_at=FROZEN_AT,
    )

    manifest = load_dataset_freeze_manifest(manifest_path)
    report = DatasetFreezeVerificationReport.model_validate_json(
        report_path.read_text(encoding="utf-8")
    )
    second_result = freeze_cicids2017_pcaps(
        dataset_root=root,
        manifest_path=manifest_path,
        report_path=report_path,
        file_capture_dates=CAPTURE_DATES,
        retrieved_at=RETRIEVED_AT,
        frozen_at=FROZEN_AT,
    )

    assert set(manifest.selected_capture_days) == APPROVED_CAPTURE_DATES
    assert manifest.source.landing_page_url == OFFICIAL_LANDING_PAGE
    assert manifest.source.download_url == OFFICIAL_DOWNLOAD_GATE
    assert verify_dataset_freeze(manifest, root).manifest_sha256 == result[
        "manifest_sha256"
    ]
    assert report.manifest_sha256 == result["manifest_sha256"]
    assert report.content_sha256() == result["report_sha256"]
    assert second_result == result


@pytest.mark.parametrize(
    "specs",
    (
        ["2017-07-04=Tuesday.pcap", "2017-07-05=Wednesday.pcap"],
        [
            "2017-07-04=Tuesday.pcap",
            "2017-07-05=Wednesday.pcap",
            "2017-07-06=Thursday.pcap",
            "2017-07-07=Friday.pcap",
        ],
        ["not-a-capture-spec"],
    ),
)
def test_capture_spec_parser_rejects_incomplete_or_out_of_scope_input(
    specs: list[str],
) -> None:
    with pytest.raises(ValueError):
        parse_capture_specs(specs)


def test_capture_spec_parser_accepts_multiple_files_per_approved_day() -> None:
    selections = parse_capture_specs(
        [
            "2017-07-04=Tuesday-part-1.pcap",
            "2017-07-04=Tuesday-part-2.pcap",
            "2017-07-05=Wednesday.pcap",
            "2017-07-07=Friday.pcap",
        ]
    )

    assert set(selections.values()) == APPROVED_CAPTURE_DATES
    assert len(selections) == 4


@pytest.mark.parametrize(
    "value",
    (
        "2026-07-27T10:00:00",
        "2026-07-27T11:00:00+01:00",
        "not-a-timestamp",
    ),
)
def test_timestamp_parser_rejects_non_utc_or_invalid_values(value: str) -> None:
    with pytest.raises(Exception):
        parse_utc_datetime(value)


def test_timestamp_parser_accepts_explicit_zulu_time() -> None:
    parsed = parse_utc_datetime("2026-07-27T10:00:00Z")

    assert parsed == RETRIEVED_AT
    assert parsed.utcoffset() == timezone.utc.utcoffset(parsed)
