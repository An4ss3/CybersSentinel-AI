"""Deterministic loading and integrity verification for M1 PCAP freezes.

This module verifies local primary evidence against a validated
``DatasetFreezeManifest``. It does not download data, create manifests, parse
packets, or mutate evidence. Successful verification proves that every
manifest-selected file matches the declared freeze; unselected publisher files
may coexist under the same primary-evidence root.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from hashlib import sha256
import json
import os
from pathlib import Path, PurePosixPath
from typing import Literal, Mapping, TypeAlias

import yaml

from modules.detection.src.schemas import (
    DatasetFreezeManifest,
    DatasetFreezeVerificationReport,
    DatasetSource,
    PcapEvidenceFile,
)


IntegrityIssueKind: TypeAlias = Literal[
    "dataset_root_missing",
    "dataset_root_not_directory",
    "file_missing",
    "file_not_regular",
    "path_escape",
    "symlink_not_allowed",
    "size_mismatch",
    "sha256_mismatch",
    "file_changed_during_verification",
    "file_access_error",
]
_HASH_CHUNK_SIZE = 1024 * 1024


@dataclass(frozen=True, slots=True)
class DatasetIntegrityIssue:
    """One deterministic reason local evidence does not match its manifest."""

    kind: IntegrityIssueKind
    relative_path: str | None
    detail: str


@dataclass(frozen=True, slots=True)
class DatasetFreezeVerificationError(ValueError):
    """Raised with every integrity issue found during one verification pass."""

    issues: tuple[DatasetIntegrityIssue, ...]

    def __str__(self) -> str:
        rendered = "; ".join(
            f"{issue.kind}:{issue.relative_path or '<dataset-root>'}: {issue.detail}"
            for issue in self.issues
        )
        return f"dataset freeze verification failed: {rendered}"


@dataclass(frozen=True, slots=True)
class VerifiedDatasetFreeze:
    """Deterministic summary returned only after complete verification succeeds."""

    manifest_sha256: str
    verified_file_count: int
    verified_total_size_bytes: int


def _json_default(value: object) -> str:
    """Serialize only YAML date types needed by strict JSON-mode validation."""
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    raise TypeError(f"unsupported YAML value type: {type(value).__name__}")


def load_dataset_freeze_manifest(path: str | Path) -> DatasetFreezeManifest:
    """Load a YAML manifest through strict Pydantic JSON-mode validation."""
    source = Path(path)
    raw = yaml.safe_load(source.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("dataset freeze manifest root must be a mapping")
    normalized = json.dumps(raw, default=_json_default)
    return DatasetFreezeManifest.model_validate_json(normalized)


def _sha256_file(path: Path) -> str:
    """Hash a file incrementally without loading large PCAPs into memory."""
    digest = sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(_HASH_CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _issue_sort_key(issue: DatasetIntegrityIssue) -> tuple[str, str, str]:
    return (issue.relative_path or "", issue.kind, issue.detail)


def _root_error(root: Path) -> DatasetFreezeVerificationError | None:
    if not root.exists():
        return DatasetFreezeVerificationError(
            (
                DatasetIntegrityIssue(
                    kind="dataset_root_missing",
                    relative_path=None,
                    detail=f"dataset root does not exist: {root}",
                ),
            )
        )
    if not root.is_dir():
        return DatasetFreezeVerificationError(
            (
                DatasetIntegrityIssue(
                    kind="dataset_root_not_directory",
                    relative_path=None,
                    detail=f"dataset root is not a directory: {root}",
                ),
            )
        )
    return None


def verify_dataset_freeze(
    manifest: DatasetFreezeManifest,
    dataset_root: str | Path,
) -> VerifiedDatasetFreeze:
    """Verify every manifest-selected PCAP without constraining other evidence.

    The function is read-only. It checks containment, regular-file status,
    symlink use, byte size, SHA-256 content, and file stability during hashing.
    Unselected PCAPs may coexist under the dataset root and are not consumed.
    All issues affecting selected files are returned in deterministic order.
    """
    root = Path(dataset_root)
    root_error = _root_error(root)
    if root_error is not None:
        raise root_error

    resolved_root = root.resolve(strict=True)
    issues: list[DatasetIntegrityIssue] = []

    for evidence in manifest.files:
        relative_path = evidence.relative_path
        path = root.joinpath(*PurePosixPath(relative_path).parts)

        if not path.exists():
            issues.append(
                DatasetIntegrityIssue(
                    kind="file_missing",
                    relative_path=relative_path,
                    detail="manifest-listed PCAP does not exist",
                )
            )
            continue
        if path.is_symlink():
            issues.append(
                DatasetIntegrityIssue(
                    kind="symlink_not_allowed",
                    relative_path=relative_path,
                    detail="manifest-listed evidence must not be a symbolic link",
                )
            )
            continue
        try:
            path.resolve(strict=True).relative_to(resolved_root)
        except ValueError:
            issues.append(
                DatasetIntegrityIssue(
                    kind="path_escape",
                    relative_path=relative_path,
                    detail="resolved evidence path escapes the dataset root",
                )
            )
            continue
        except OSError as exc:
            issues.append(
                DatasetIntegrityIssue(
                    kind="file_access_error",
                    relative_path=relative_path,
                    detail=str(exc),
                )
            )
            continue
        if not path.is_file():
            issues.append(
                DatasetIntegrityIssue(
                    kind="file_not_regular",
                    relative_path=relative_path,
                    detail="manifest-listed evidence is not a regular file",
                )
            )
            continue

        try:
            before = path.stat()
            if before.st_size != evidence.size_bytes:
                issues.append(
                    DatasetIntegrityIssue(
                        kind="size_mismatch",
                        relative_path=relative_path,
                        detail=(
                            f"expected {evidence.size_bytes} bytes, "
                            f"observed {before.st_size}"
                        ),
                    )
                )
                continue

            observed_sha256 = _sha256_file(path)
            after = path.stat()
        except OSError as exc:
            issues.append(
                DatasetIntegrityIssue(
                    kind="file_access_error",
                    relative_path=relative_path,
                    detail=str(exc),
                )
            )
            continue

        if before.st_size != after.st_size or before.st_mtime_ns != after.st_mtime_ns:
            issues.append(
                DatasetIntegrityIssue(
                    kind="file_changed_during_verification",
                    relative_path=relative_path,
                    detail="file size or modification time changed while hashing",
                )
            )
            continue
        if observed_sha256 != evidence.sha256:
            issues.append(
                DatasetIntegrityIssue(
                    kind="sha256_mismatch",
                    relative_path=relative_path,
                    detail=(
                        f"expected {evidence.sha256}, observed {observed_sha256}"
                    ),
                )
            )

    if issues:
        raise DatasetFreezeVerificationError(
            tuple(sorted(issues, key=_issue_sort_key))
        )

    return VerifiedDatasetFreeze(
        manifest_sha256=manifest.content_sha256(),
        verified_file_count=len(manifest.files),
        verified_total_size_bytes=sum(item.size_bytes for item in manifest.files),
    )



def inventory_pcap_evidence(
    dataset_root: str | Path,
    file_capture_dates: Mapping[str, date],
) -> tuple[PcapEvidenceFile, ...]:
    """Measure stable byte sizes and SHA-256 digests for selected local PCAPs.

    Relative paths are validated before any filesystem access. The function is
    read-only and returns entries in deterministic capture-date/path order.
    """
    if not file_capture_dates:
        raise ValueError("at least one PCAP path and capture date is required")

    root = Path(dataset_root)
    root_error = _root_error(root)
    if root_error is not None:
        raise root_error
    resolved_root = root.resolve(strict=True)
    evidence_files: list[PcapEvidenceFile] = []
    issues: list[DatasetIntegrityIssue] = []

    selections = sorted(
        file_capture_dates.items(),
        key=lambda item: (item[1], item[0]),
    )
    for relative_path, capture_date in selections:
        # Construct a temporary valid contract before joining the path. This
        # reuses the Step 1 path policy and prevents traversal before I/O.
        validated_path = PcapEvidenceFile(
            relative_path=relative_path,
            capture_date=capture_date,
            size_bytes=1,
            sha256="0" * 64,
        ).relative_path
        path = root.joinpath(*PurePosixPath(validated_path).parts)

        if not path.exists():
            issues.append(
                DatasetIntegrityIssue(
                    kind="file_missing",
                    relative_path=validated_path,
                    detail="selected PCAP does not exist",
                )
            )
            continue
        if path.is_symlink():
            issues.append(
                DatasetIntegrityIssue(
                    kind="symlink_not_allowed",
                    relative_path=validated_path,
                    detail="selected evidence must not be a symbolic link",
                )
            )
            continue
        try:
            path.resolve(strict=True).relative_to(resolved_root)
        except ValueError:
            issues.append(
                DatasetIntegrityIssue(
                    kind="path_escape",
                    relative_path=validated_path,
                    detail="resolved evidence path escapes the dataset root",
                )
            )
            continue
        except OSError as exc:
            issues.append(
                DatasetIntegrityIssue(
                    kind="file_access_error",
                    relative_path=validated_path,
                    detail=str(exc),
                )
            )
            continue
        if not path.is_file():
            issues.append(
                DatasetIntegrityIssue(
                    kind="file_not_regular",
                    relative_path=validated_path,
                    detail="selected evidence is not a regular file",
                )
            )
            continue

        try:
            before = path.stat()
            observed_sha256 = _sha256_file(path)
            after = path.stat()
        except OSError as exc:
            issues.append(
                DatasetIntegrityIssue(
                    kind="file_access_error",
                    relative_path=validated_path,
                    detail=str(exc),
                )
            )
            continue
        if before.st_size != after.st_size or before.st_mtime_ns != after.st_mtime_ns:
            issues.append(
                DatasetIntegrityIssue(
                    kind="file_changed_during_verification",
                    relative_path=validated_path,
                    detail="file size or modification time changed while hashing",
                )
            )
            continue

        evidence_files.append(
            PcapEvidenceFile(
                relative_path=validated_path,
                capture_date=capture_date,
                size_bytes=after.st_size,
                sha256=observed_sha256,
            )
        )

    if issues:
        raise DatasetFreezeVerificationError(
            tuple(sorted(issues, key=_issue_sort_key))
        )
    return tuple(evidence_files)


def build_dataset_freeze_manifest(
    *,
    dataset_root: str | Path,
    file_capture_dates: Mapping[str, date],
    source: DatasetSource,
    frozen_at: datetime,
    selection_rationale: str,
    manifest_version: str = "1.0.0",
    dataset_name: str = "cicids2017",
    dataset_release: str = "CICIDS2017 PCAP",
) -> DatasetFreezeManifest:
    """Build a strict manifest from measured local evidence without writing it."""
    files = inventory_pcap_evidence(dataset_root, file_capture_dates)
    return DatasetFreezeManifest(
        manifest_version=manifest_version,
        dataset_name=dataset_name,
        dataset_release=dataset_release,
        source=source,
        frozen_at=frozen_at,
        selection_rationale=selection_rationale,
        selected_capture_days=tuple(
            sorted({item.capture_date for item in files})
        ),
        files=files,
    )


def build_dataset_verification_report(
    manifest: DatasetFreezeManifest,
    verification: VerifiedDatasetFreeze,
    *,
    report_version: str = "1.0.0",
) -> DatasetFreezeVerificationReport:
    """Bind a successful verification result to a standalone strict report."""
    if verification.manifest_sha256 != manifest.content_sha256():
        raise ValueError("verification does not belong to the supplied manifest")
    if verification.verified_file_count != len(manifest.files):
        raise ValueError("verification file count does not match the manifest")
    if verification.verified_total_size_bytes != sum(
        item.size_bytes for item in manifest.files
    ):
        raise ValueError("verification byte total does not match the manifest")

    return DatasetFreezeVerificationReport(
        report_version=report_version,
        verification_status="verified",
        verification_method="complete_inventory_size_sha256",
        manifest_sha256=verification.manifest_sha256,
        dataset_name=manifest.dataset_name,
        dataset_release=manifest.dataset_release,
        selected_capture_days=manifest.selected_capture_days,
        verified_file_count=verification.verified_file_count,
        verified_total_size_bytes=verification.verified_total_size_bytes,
        files=manifest.files,
    )


def _write_immutable_bytes(path: Path, payload: bytes) -> None:
    """Create bytes once; accept an identical rerun and reject replacement."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() != payload:
            raise FileExistsError(
                f"immutable artifact already exists with different content: {path}"
            )
        return

    try:
        with path.open("xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def write_immutable_dataset_manifest(
    manifest: DatasetFreezeManifest,
    path: str | Path,
) -> str:
    """Write deterministic YAML once and return the manifest content identity."""
    payload = yaml.safe_dump(
        manifest.model_dump(mode="json"),
        sort_keys=False,
        allow_unicode=False,
    ).encode("utf-8")
    _write_immutable_bytes(Path(path), payload)
    return manifest.content_sha256()


def write_immutable_verification_report(
    report: DatasetFreezeVerificationReport,
    path: str | Path,
) -> str:
    """Write deterministic JSON once and return the report content identity."""
    payload = (
        json.dumps(
            report.model_dump(mode="json"),
            sort_keys=True,
            indent=2,
            ensure_ascii=True,
        )
        + "\n"
    ).encode("utf-8")
    _write_immutable_bytes(Path(path), payload)
    return report.content_sha256()
