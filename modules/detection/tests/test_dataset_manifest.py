"""Tests for the M1 Step 1 primary-evidence freeze contracts."""
from __future__ import annotations

from datetime import date, datetime, timezone
import json

import pytest
from pydantic import ValidationError

from modules.detection.src.schemas import (
    DatasetFreezeManifest,
    DatasetSource,
    PcapEvidenceFile,
)


FIRST_DIGEST = "1" * 64
SECOND_DIGEST = "2" * 64


def _source(**changes: object) -> DatasetSource:
    payload: dict[str, object] = {
        "publisher": "Canadian Institute for Cybersecurity",
        "landing_page_url": "https://www.unb.ca/cic/datasets/ids-2017.html",
        "download_url": "https://example.invalid/cicids2017/pcaps.zip",
        "retrieved_at": datetime(2026, 7, 24, 10, 0, tzinfo=timezone.utc),
    }
    payload.update(changes)
    return DatasetSource.model_validate(payload)


def _file(
    relative_path: str = "Tuesday-WorkingHours.pcap",
    capture_date: date = date(2017, 7, 4),
    size_bytes: int = 123_456,
    digest: str = FIRST_DIGEST,
) -> PcapEvidenceFile:
    return PcapEvidenceFile(
        relative_path=relative_path,
        capture_date=capture_date,
        size_bytes=size_bytes,
        sha256=digest,
    )


def _manifest(**changes: object) -> DatasetFreezeManifest:
    payload: dict[str, object] = {
        "manifest_version": "1.0.0",
        "dataset_name": "cicids2017",
        "dataset_release": "CICIDS2017 PCAP",
        "source": _source(),
        "frozen_at": datetime(2026, 7, 24, 10, 30, tzinfo=timezone.utc),
        "selection_rationale": (
            "Complete capture days selected before replay or model inspection."
        ),
        "selected_capture_days": (date(2017, 7, 4), date(2017, 7, 5)),
        "files": (
            _file(),
            _file(
                relative_path="Wednesday-WorkingHours.pcap",
                capture_date=date(2017, 7, 5),
                size_bytes=654_321,
                digest=SECOND_DIGEST,
            ),
        ),
    }
    payload.update(changes)
    return DatasetFreezeManifest.model_validate(payload)


def test_manifest_round_trips_and_has_stable_content_identity() -> None:
    manifest = _manifest()
    restored = DatasetFreezeManifest.model_validate_json(manifest.model_dump_json())

    assert restored == manifest
    assert restored.content_sha256() == manifest.content_sha256()
    assert len(manifest.content_sha256()) == 64


def test_material_manifest_change_changes_content_identity() -> None:
    original = _manifest()
    changed = _manifest(selection_rationale="A different pre-declared selection.")

    assert changed.content_sha256() != original.content_sha256()


def test_manifest_and_nested_contracts_are_immutable() -> None:
    manifest = _manifest()

    with pytest.raises(ValidationError, match="frozen_instance"):
        manifest.dataset_name = "changed"  # type: ignore[misc]
    with pytest.raises(ValidationError, match="frozen_instance"):
        manifest.files[0].size_bytes = 1  # type: ignore[misc]


def test_unknown_fields_are_rejected_at_every_boundary() -> None:
    payload = json.loads(_manifest().model_dump_json())
    payload["unreviewed"] = True
    with pytest.raises(ValidationError, match="extra_forbidden"):
        DatasetFreezeManifest.model_validate_json(json.dumps(payload))

    file_payload = json.loads(_file().model_dump_json())
    file_payload["trusted_without_checksum"] = True
    with pytest.raises(ValidationError, match="extra_forbidden"):
        PcapEvidenceFile.model_validate_json(json.dumps(file_payload))


@pytest.mark.parametrize(
    "url",
    (
        "http://example.invalid/cicids2017",
        "https://",
        "https://user:secret@example.invalid/cicids2017",
    ),
)
def test_source_requires_absolute_credential_free_https_urls(url: str) -> None:
    with pytest.raises(ValidationError, match="dataset source URLs"):
        _source(download_url=url)


def test_acquisition_and_freeze_timestamps_must_be_utc_and_causal() -> None:
    with pytest.raises(ValidationError, match="timezone-aware UTC"):
        _source(retrieved_at=datetime(2026, 7, 24, 10, 0))

    with pytest.raises(ValidationError, match="cannot precede"):
        _manifest(frozen_at=datetime(2026, 7, 24, 9, 59, tzinfo=timezone.utc))


@pytest.mark.parametrize(
    "path",
    (
        "../Tuesday.pcap",
        "/absolute/Tuesday.pcap",
        "captures\\Tuesday.pcap",
        "captures/./Tuesday.pcap",
        "captures/Tuesday.csv",
    ),
)
def test_evidence_path_must_be_portable_relative_and_pcap(path: str) -> None:
    with pytest.raises(ValidationError, match="relative_path|evidence file"):
        _file(relative_path=path)


def test_checksum_size_and_scalar_types_are_strict() -> None:
    with pytest.raises(ValidationError, match="sha256"):
        _file(digest="A" * 64)
    with pytest.raises(ValidationError, match="size_bytes"):
        _file(size_bytes=0)

    payload = json.loads(_file().model_dump_json())
    payload["size_bytes"] = "123456"
    with pytest.raises(ValidationError, match="size_bytes"):
        PcapEvidenceFile.model_validate_json(json.dumps(payload))


def test_selected_days_must_be_unique_and_chronological() -> None:
    with pytest.raises(ValidationError, match="sorted chronologically"):
        _manifest(
            selected_capture_days=(date(2017, 7, 5), date(2017, 7, 4))
        )
    with pytest.raises(ValidationError, match="must be unique"):
        _manifest(
            selected_capture_days=(date(2017, 7, 4), date(2017, 7, 4))
        )


def test_files_must_be_deterministically_ordered() -> None:
    valid = _manifest()
    with pytest.raises(ValidationError, match="files must be sorted"):
        _manifest(files=tuple(reversed(valid.files)))


def test_selected_days_must_exactly_match_file_capture_dates() -> None:
    with pytest.raises(ValidationError, match="must exactly match"):
        _manifest(
            selected_capture_days=(
                date(2017, 7, 4),
                date(2017, 7, 5),
                date(2017, 7, 7),
            )
        )


def test_duplicate_paths_and_content_are_rejected() -> None:
    first = _file()
    duplicate_path = _file(size_bytes=999, digest=SECOND_DIGEST)
    with pytest.raises(ValidationError, match="relative_path values must be unique"):
        _manifest(
            selected_capture_days=(date(2017, 7, 4),),
            files=(first, duplicate_path),
        )

    duplicate_content = _file(
        relative_path="Tuesday-Z-copy.pcap",
        size_bytes=123_456,
        digest=FIRST_DIGEST,
    )
    with pytest.raises(ValidationError, match="sha256 values must be unique"):
        _manifest(
            selected_capture_days=(date(2017, 7, 4),),
            files=(first, duplicate_content),
        )
