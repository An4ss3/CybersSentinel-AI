"""Strict contracts for freezing primary PCAP evidence in M1.

These contracts describe acquired evidence without downloading, parsing, or
modifying it. A populated manifest can exist only after every listed file has
been acquired and its byte size and SHA-256 digest have been measured.
"""
from __future__ import annotations

from datetime import date
from hashlib import sha256
import json
from pathlib import PurePosixPath
from typing import Annotated, Literal
from urllib.parse import urlsplit

from pydantic import Field, StringConstraints, field_validator, model_validator

from modules.detection.src.contracts import (
    NonEmptyText,
    PositiveInt,
    StrictIdentifier,
    StrictModel,
    UtcDateTime,
    VersionString,
)


Sha256Digest = Annotated[
    str,
    StringConstraints(pattern=r"^[0-9a-f]{64}$"),
]
PcapRelativePath = Annotated[
    str,
    StringConstraints(min_length=6, max_length=512, pattern=r".*\S.*"),
]


class DatasetSource(StrictModel):
    """Authoritative location and acquisition time for a dataset release."""

    publisher: NonEmptyText
    landing_page_url: NonEmptyText
    download_url: NonEmptyText
    retrieved_at: UtcDateTime

    @field_validator("landing_page_url", "download_url")
    @classmethod
    def require_https_url(cls, value: str) -> str:
        """Reject unauthenticated source locations in a freeze manifest."""
        parsed = urlsplit(value)
        if parsed.scheme != "https" or parsed.hostname is None:
            raise ValueError("dataset source URLs must be absolute https URLs")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("dataset source URLs cannot contain credentials")
        return value


class PcapEvidenceFile(StrictModel):
    """One locally acquired PCAP identified by immutable content metadata."""

    relative_path: PcapRelativePath
    capture_date: date
    size_bytes: PositiveInt
    sha256: Sha256Digest

    @field_validator("relative_path")
    @classmethod
    def require_canonical_relative_pcap_path(cls, value: str) -> str:
        """Require portable POSIX paths with no traversal or normalization."""
        if "\\" in value:
            raise ValueError("relative_path must use POSIX separators")
        path = PurePosixPath(value)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError("relative_path must remain inside the dataset root")
        if path.as_posix() != value or any(part in ("", ".") for part in path.parts):
            raise ValueError("relative_path must already be in canonical form")
        if path.suffix.lower() not in (".pcap", ".pcapng"):
            raise ValueError("evidence file must have a .pcap or .pcapng suffix")
        return value


class DatasetFreezeManifest(StrictModel):
    """Complete deterministic inventory of the PCAP evidence frozen for M1.

    The manifest is descriptive: it records source provenance, the explicitly
    selected capture days, selection rationale, and locally measured integrity
    metadata. It performs no I/O and makes no claim that a listed path exists.
    Filesystem verification belongs to a later M1 increment.
    """

    manifest_version: VersionString
    dataset_name: StrictIdentifier
    dataset_release: NonEmptyText
    source: DatasetSource
    frozen_at: UtcDateTime
    selection_rationale: NonEmptyText
    selected_capture_days: Annotated[tuple[date, ...], Field(min_length=1)]
    files: Annotated[tuple[PcapEvidenceFile, ...], Field(min_length=1)]

    @model_validator(mode="after")
    def validate_inventory(self) -> "DatasetFreezeManifest":
        """Reject ambiguous, duplicated, incomplete, or non-canonical inventory."""
        if self.frozen_at < self.source.retrieved_at:
            raise ValueError("frozen_at cannot precede source retrieved_at")
        if tuple(sorted(self.selected_capture_days)) != self.selected_capture_days:
            raise ValueError("selected_capture_days must be sorted chronologically")
        if len(set(self.selected_capture_days)) != len(self.selected_capture_days):
            raise ValueError("selected_capture_days must be unique")

        file_keys = tuple((item.capture_date, item.relative_path) for item in self.files)
        if tuple(sorted(file_keys)) != file_keys:
            raise ValueError("files must be sorted by capture_date and relative_path")

        paths = [item.relative_path for item in self.files]
        if len(set(paths)) != len(paths):
            raise ValueError("relative_path values must be unique")

        digests = [item.sha256 for item in self.files]
        if len(set(digests)) != len(digests):
            raise ValueError("sha256 values must be unique")

        selected_days = set(self.selected_capture_days)
        represented_days = {item.capture_date for item in self.files}
        if represented_days != selected_days:
            raise ValueError(
                "selected_capture_days must exactly match capture dates in files"
            )
        return self

    def content_sha256(self) -> str:
        """Return a formatting-independent identity for the manifest content."""
        canonical_json = json.dumps(
            self.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        return sha256(canonical_json).hexdigest()



class DatasetFreezeVerificationReport(StrictModel):
    """Immutable, standalone evidence that one dataset freeze verified fully."""

    report_version: VersionString
    verification_status: Literal["verified"]
    verification_method: Literal["complete_inventory_size_sha256"]
    manifest_sha256: Sha256Digest
    dataset_name: StrictIdentifier
    dataset_release: NonEmptyText
    selected_capture_days: Annotated[tuple[date, ...], Field(min_length=1)]
    verified_file_count: PositiveInt
    verified_total_size_bytes: PositiveInt
    files: Annotated[tuple[PcapEvidenceFile, ...], Field(min_length=1)]

    @model_validator(mode="after")
    def validate_verified_inventory(self) -> "DatasetFreezeVerificationReport":
        """Bind report totals and selected days to its complete file inventory."""
        if self.verified_file_count != len(self.files):
            raise ValueError("verified_file_count must equal the number of files")
        if self.verified_total_size_bytes != sum(
            item.size_bytes for item in self.files
        ):
            raise ValueError("verified_total_size_bytes must equal file byte sizes")
        file_keys = tuple((item.capture_date, item.relative_path) for item in self.files)
        if tuple(sorted(file_keys)) != file_keys:
            raise ValueError("report files must use deterministic manifest order")
        represented_days = tuple(sorted({item.capture_date for item in self.files}))
        if represented_days != self.selected_capture_days:
            raise ValueError(
                "selected_capture_days must exactly match report file dates"
            )
        return self

    def content_sha256(self) -> str:
        """Return a formatting-independent identity for the report content."""
        canonical_json = json.dumps(
            self.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        return sha256(canonical_json).hexdigest()
