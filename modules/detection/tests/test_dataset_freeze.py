"""Tests for M1 Step 2 dataset-freeze loading and integrity verification."""
from __future__ import annotations

from datetime import date, datetime, timezone
from hashlib import sha256
from pathlib import Path

import pytest
from pydantic import ValidationError
import yaml

import modules.detection.src.lineage.dataset_freeze as dataset_freeze_module
from modules.detection.src.lineage import (
    DatasetFreezeVerificationError,
    load_dataset_freeze_manifest,
    verify_dataset_freeze,
)
from modules.detection.src.schemas import (
    DatasetFreezeManifest,
    DatasetSource,
    PcapEvidenceFile,
)


CAPTURE_DATE = date(2017, 7, 4)
PCAP_BYTES = b"synthetic-test-bytes-not-a-real-pcap"


def _digest(content: bytes) -> str:
    return sha256(content).hexdigest()


def _evidence(
    relative_path: str = "Tuesday-WorkingHours.pcap",
    content: bytes = PCAP_BYTES,
) -> PcapEvidenceFile:
    return PcapEvidenceFile(
        relative_path=relative_path,
        capture_date=CAPTURE_DATE,
        size_bytes=len(content),
        sha256=_digest(content),
    )


def _manifest(
    files: tuple[PcapEvidenceFile, ...] | None = None,
) -> DatasetFreezeManifest:
    evidence = files or (_evidence(),)
    return DatasetFreezeManifest(
        manifest_version="1.0.0",
        dataset_name="cicids2017",
        dataset_release="CICIDS2017 PCAP",
        source=DatasetSource(
            publisher="Canadian Institute for Cybersecurity",
            landing_page_url="https://www.unb.ca/cic/datasets/ids-2017.html",
            download_url="https://example.invalid/cicids2017/pcaps.zip",
            retrieved_at=datetime(2026, 7, 24, 10, 0, tzinfo=timezone.utc),
        ),
        frozen_at=datetime(2026, 7, 24, 10, 30, tzinfo=timezone.utc),
        selection_rationale="Complete days selected before replay or model inspection.",
        selected_capture_days=tuple(sorted({item.capture_date for item in evidence})),
        files=evidence,
    )


def _write_manifest(path: Path, manifest: DatasetFreezeManifest) -> None:
    path.write_text(
        yaml.safe_dump(manifest.model_dump(mode="json"), sort_keys=False),
        encoding="utf-8",
    )


def _issue_kinds(error: DatasetFreezeVerificationError) -> tuple[str, ...]:
    return tuple(issue.kind for issue in error.issues)


def test_yaml_manifest_loads_strictly_and_local_evidence_verifies(
    tmp_path: Path,
) -> None:
    dataset_root = tmp_path / "pcaps"
    dataset_root.mkdir()
    evidence_path = dataset_root / "Tuesday-WorkingHours.pcap"
    evidence_path.write_bytes(PCAP_BYTES)
    manifest_path = tmp_path / "freeze.yaml"
    expected_manifest = _manifest()
    _write_manifest(manifest_path, expected_manifest)

    loaded = load_dataset_freeze_manifest(manifest_path)
    before_stat = evidence_path.stat()
    result = verify_dataset_freeze(loaded, dataset_root)
    after_stat = evidence_path.stat()

    assert loaded == expected_manifest
    assert result.manifest_sha256 == expected_manifest.content_sha256()
    assert result.verified_file_count == 1
    assert result.verified_total_size_bytes == len(PCAP_BYTES)
    assert before_stat.st_size == after_stat.st_size
    assert before_stat.st_mtime_ns == after_stat.st_mtime_ns


def test_loader_rejects_non_mapping_and_unknown_fields(tmp_path: Path) -> None:
    non_mapping = tmp_path / "list.yaml"
    non_mapping.write_text("- not\n- a\n- manifest\n", encoding="utf-8")
    with pytest.raises(ValueError, match="root must be a mapping"):
        load_dataset_freeze_manifest(non_mapping)

    payload = _manifest().model_dump(mode="json")
    payload["silently_trusted"] = True
    unknown = tmp_path / "unknown.yaml"
    unknown.write_text(yaml.safe_dump(payload), encoding="utf-8")
    with pytest.raises(ValidationError, match="extra_forbidden"):
        load_dataset_freeze_manifest(unknown)


def test_loader_preserves_strict_scalar_validation(tmp_path: Path) -> None:
    payload = _manifest().model_dump(mode="json")
    payload["files"][0]["size_bytes"] = str(len(PCAP_BYTES))
    path = tmp_path / "coerced.yaml"
    path.write_text(yaml.safe_dump(payload), encoding="utf-8")

    with pytest.raises(ValidationError, match="size_bytes"):
        load_dataset_freeze_manifest(path)


@pytest.mark.parametrize(
    ("root_factory", "expected_kind"),
    (
        (lambda base: base / "missing", "dataset_root_missing"),
        (lambda base: _create_regular_file(base / "not-a-directory"), "dataset_root_not_directory"),
    ),
)
def test_invalid_dataset_roots_are_rejected(
    tmp_path: Path,
    root_factory,
    expected_kind: str,
) -> None:
    root = root_factory(tmp_path)
    with pytest.raises(DatasetFreezeVerificationError) as caught:
        verify_dataset_freeze(_manifest(), root)

    assert _issue_kinds(caught.value) == (expected_kind,)


def _create_regular_file(path: Path) -> Path:
    path.write_bytes(b"not a directory")
    return path


def test_unselected_pcaps_coexist_but_cannot_replace_selected_evidence(
    tmp_path: Path,
) -> None:
    root = tmp_path / "pcaps"
    root.mkdir()
    (root / "Monday-WorkingHours.pcap").write_bytes(b"unselected official evidence")

    with pytest.raises(DatasetFreezeVerificationError) as caught:
        verify_dataset_freeze(_manifest(), root)
    assert [(issue.relative_path, issue.kind) for issue in caught.value.issues] == [
        ("Tuesday-WorkingHours.pcap", "file_missing"),
    ]

    (root / "Tuesday-WorkingHours.pcap").write_bytes(PCAP_BYTES)
    result = verify_dataset_freeze(_manifest(), root)
    assert result.verified_file_count == 1
    assert result.verified_total_size_bytes == len(PCAP_BYTES)


def test_unrelated_non_pcap_files_do_not_change_the_frozen_evidence_set(
    tmp_path: Path,
) -> None:
    root = tmp_path / "pcaps"
    root.mkdir()
    (root / "Tuesday-WorkingHours.pcap").write_bytes(PCAP_BYTES)
    (root / "README.txt").write_text("local operator note", encoding="utf-8")

    result = verify_dataset_freeze(_manifest(), root)

    assert result.verified_file_count == 1


def test_size_mismatch_is_rejected_without_claiming_hash_verification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "pcaps"
    root.mkdir()
    (root / "Tuesday-WorkingHours.pcap").write_bytes(PCAP_BYTES + b"tampered")

    def should_not_hash(_: Path) -> str:
        raise AssertionError("size-mismatched evidence must not be hashed")

    monkeypatch.setattr(dataset_freeze_module, "_sha256_file", should_not_hash)
    with pytest.raises(DatasetFreezeVerificationError) as caught:
        verify_dataset_freeze(_manifest(), root)

    assert _issue_kinds(caught.value) == ("size_mismatch",)


def test_same_size_content_tampering_is_detected_by_sha256(tmp_path: Path) -> None:
    root = tmp_path / "pcaps"
    root.mkdir()
    tampered = b"X" * len(PCAP_BYTES)
    (root / "Tuesday-WorkingHours.pcap").write_bytes(tampered)

    with pytest.raises(DatasetFreezeVerificationError) as caught:
        verify_dataset_freeze(_manifest(), root)

    assert _issue_kinds(caught.value) == ("sha256_mismatch",)
    assert _digest(tampered) in caught.value.issues[0].detail


def test_manifest_path_must_resolve_to_a_regular_file(tmp_path: Path) -> None:
    root = tmp_path / "pcaps"
    root.mkdir()
    (root / "Tuesday-WorkingHours.pcap").mkdir()

    with pytest.raises(DatasetFreezeVerificationError) as caught:
        verify_dataset_freeze(_manifest(), root)

    assert _issue_kinds(caught.value) == ("file_not_regular",)


def test_manifest_symlink_is_rejected_when_platform_supports_symlinks(
    tmp_path: Path,
) -> None:
    root = tmp_path / "pcaps"
    root.mkdir()
    target = tmp_path / "actual-evidence.bin"
    target.write_bytes(PCAP_BYTES)
    link = root / "Tuesday-WorkingHours.pcap"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symbolic links are unavailable in this Windows environment")

    with pytest.raises(DatasetFreezeVerificationError) as caught:
        verify_dataset_freeze(_manifest(), root)

    assert _issue_kinds(caught.value) == ("symlink_not_allowed",)


def test_file_change_during_hashing_is_detected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "pcaps"
    root.mkdir()
    path = root / "Tuesday-WorkingHours.pcap"
    path.write_bytes(PCAP_BYTES)
    real_hash = dataset_freeze_module._sha256_file

    def mutate_after_hash(file_path: Path) -> str:
        observed = real_hash(file_path)
        file_path.write_bytes(PCAP_BYTES + b"changed-during-read")
        return observed

    monkeypatch.setattr(dataset_freeze_module, "_sha256_file", mutate_after_hash)
    with pytest.raises(DatasetFreezeVerificationError) as caught:
        verify_dataset_freeze(_manifest(), root)

    assert _issue_kinds(caught.value) == ("file_changed_during_verification",)


def test_hash_access_failure_is_reported_without_raw_exception(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "pcaps"
    root.mkdir()
    (root / "Tuesday-WorkingHours.pcap").write_bytes(PCAP_BYTES)

    def deny_access(_: Path) -> str:
        raise PermissionError("test access denied")

    monkeypatch.setattr(dataset_freeze_module, "_sha256_file", deny_access)
    with pytest.raises(DatasetFreezeVerificationError) as caught:
        verify_dataset_freeze(_manifest(), root)

    assert _issue_kinds(caught.value) == ("file_access_error",)
    assert "test access denied" in caught.value.issues[0].detail


def test_nested_manifest_paths_and_multiple_files_verify(tmp_path: Path) -> None:
    root = tmp_path / "pcaps"
    nested = root / "Tuesday"
    nested.mkdir(parents=True)
    first_content = b"first synthetic capture"
    second_content = b"second synthetic capture"
    (nested / "part-01.pcap").write_bytes(first_content)
    (nested / "part-02.pcapng").write_bytes(second_content)
    manifest = _manifest(
        files=(
            _evidence("Tuesday/part-01.pcap", first_content),
            _evidence("Tuesday/part-02.pcapng", second_content),
        )
    )

    result = verify_dataset_freeze(manifest, root)

    assert result.verified_file_count == 2
    assert result.verified_total_size_bytes == len(first_content) + len(second_content)
