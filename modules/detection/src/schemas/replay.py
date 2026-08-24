"""Strict contracts for deterministic offline Zeek replay in M2.

The specification freezes the sensor runtime, M1 evidence binding, command
semantics, and output policy. It describes replay but performs no execution.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import PurePosixPath
from typing import Annotated, Literal

from pydantic import Field, StringConstraints, field_validator, model_validator

from modules.detection.src.contracts import (
    NonEmptyText,
    NonNegativeInt,
    PositiveInt,
    StrictIdentifier,
    StrictModel,
    UtcDateTime,
    VersionString,
)
from modules.detection.src.schemas.datasets import PcapEvidenceFile, Sha256Digest


ContainerDigest = Annotated[
    str,
    StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$"),
]
ZeekLogName = Annotated[
    str,
    StringConstraints(pattern=r"^[a-z0-9_]+\.log$"),
]
RepositoryRelativePath = Annotated[
    str,
    StringConstraints(min_length=1, max_length=512, pattern=r".*\S.*"),
]


def _validate_repository_relative_path(value: str) -> str:
    """Require a portable, already-normalized path inside the repository."""
    if "\\" in value:
        raise ValueError("repository path must use POSIX separators")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("repository path must remain inside the repository root")
    if path.as_posix() != value or any(part in ("", ".") for part in path.parts):
        raise ValueError("repository path must already be in canonical form")
    return value


class ZeekRuntimePin(StrictModel):
    """Exact official Zeek container and Linux platform identity."""

    zeek_version: VersionString
    image_repository: Literal["zeek/zeek"]
    image_tag: VersionString
    image_index_digest: ContainerDigest
    platform: Literal["linux/amd64"]
    platform_manifest_digest: ContainerDigest

    @model_validator(mode="after")
    def validate_runtime_identity(self) -> "ZeekRuntimePin":
        if self.image_tag != self.zeek_version:
            raise ValueError("official image tag must equal zeek_version")
        if self.image_index_digest == self.platform_manifest_digest:
            raise ValueError("index and platform manifest digests must be distinct")
        return self

    @property
    def immutable_image_reference(self) -> str:
        """Return the pull reference that cannot move between executions."""
        return f"{self.image_repository}@{self.image_index_digest}"


class ZeekDeterminismPolicy(StrictModel):
    """Single-process execution settings that control replay byte stability."""

    execution_mode: Literal["offline_single_process"]
    process_count: Literal[1]
    random_seed: PositiveInt
    checksum_policy: Literal["ignore_invalid_checksums"]
    timezone: Literal["UTC"]
    locale: Literal["C"]
    loaded_scripts: Annotated[tuple[StrictIdentifier, ...], Field(min_length=1)]
    external_packages: tuple[StrictIdentifier, ...]
    json_logs: Literal[True]
    log_rotation_interval_seconds: Literal[0]
    command_template: Annotated[tuple[NonEmptyText, ...], Field(min_length=1)]

    @model_validator(mode="after")
    def validate_exact_command_semantics(self) -> "ZeekDeterminismPolicy":
        if len(set(self.loaded_scripts)) != len(self.loaded_scripts):
            raise ValueError("loaded_scripts must be unique")
        if self.external_packages:
            raise ValueError("initial M2 replay cannot load external Zeek packages")
        expected = (
            "zeek",
            "-D",
            "-C",
            "-r",
            "{pcap}",
            *self.loaded_scripts,
            "LogAscii::use_json=T",
            "Log::default_rotation_interval=0secs",
        )
        if self.command_template != expected:
            raise ValueError("command_template does not match deterministic policy")
        return self


class ZeekOutputPolicy(StrictModel):
    """Immutable output layout and evidence classification for each PCAP run."""

    output_root: RepositoryRelativePath
    partitioning: Literal["one_directory_per_pcap"]
    existing_output_policy: Literal["fail_if_exists"]
    log_format: Literal["json_lines"]
    retention: Literal["all_emitted_logs"]
    canonical_log_policy: Literal["all_emitted_except_operational_runtime"]
    excluded_operational_logs: Annotated[
        tuple[ZeekLogName, ...],
        Field(min_length=1),
    ]
    operational_log_directory: Literal["operational"]
    required_logs: Annotated[tuple[ZeekLogName, ...], Field(min_length=1)]
    protocol_logs_of_interest: Annotated[
        tuple[ZeekLogName, ...],
        Field(min_length=1),
    ]
    artifact_hash_algorithm: Literal["sha256"]
    immutable_after_validation: Literal[True]

    @field_validator("output_root")
    @classmethod
    def validate_output_root(cls, value: str) -> str:
        return _validate_repository_relative_path(value)

    @model_validator(mode="after")
    def validate_log_policy(self) -> "ZeekOutputPolicy":
        collections = {
            "required_logs": self.required_logs,
            "protocol_logs_of_interest": self.protocol_logs_of_interest,
            "excluded_operational_logs": self.excluded_operational_logs,
        }
        for field_name, names in collections.items():
            if len(set(names)) != len(names):
                raise ValueError(f"{field_name} must be unique")
            if tuple(sorted(names)) != names:
                raise ValueError(f"{field_name} must be sorted")
        approved_operational_logs = (
            "packet_filter.log",
            "stats.log",
            "telemetry.log",
        )
        if self.excluded_operational_logs != approved_operational_logs:
            raise ValueError(
                "excluded_operational_logs must contain only the approved "
                "runtime measurement logs"
            )
        if not set(self.required_logs).issubset(self.protocol_logs_of_interest):
            raise ValueError("required_logs must be included in logs of interest")
        if set(self.protocol_logs_of_interest) & set(self.excluded_operational_logs):
            raise ValueError(
                "canonical protocol logs cannot be classified as operational"
            )
        return self


class ZeekReplaySpecification(StrictModel):
    """Frozen M2 replay protocol bound exactly to one M1 dataset manifest."""

    specification_version: VersionString
    frozen_at: UtcDateTime
    m1_manifest_path: RepositoryRelativePath
    m1_manifest_sha256: Sha256Digest
    dataset_name: StrictIdentifier
    inputs: Annotated[tuple[PcapEvidenceFile, ...], Field(min_length=1)]
    runtime: ZeekRuntimePin
    determinism: ZeekDeterminismPolicy
    output: ZeekOutputPolicy
    authoritative_sources: Annotated[tuple[NonEmptyText, ...], Field(min_length=1)]

    @field_validator("m1_manifest_path")
    @classmethod
    def validate_manifest_path(cls, value: str) -> str:
        value = _validate_repository_relative_path(value)
        if not value.endswith((".yaml", ".yml")):
            raise ValueError("M1 manifest path must use a YAML suffix")
        return value

    @field_validator("authoritative_sources")
    @classmethod
    def validate_authoritative_sources(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        if len(set(value)) != len(value):
            raise ValueError("authoritative_sources must be unique")
        if tuple(sorted(value)) != value:
            raise ValueError("authoritative_sources must be sorted")
        if any(not item.startswith("https://") for item in value):
            raise ValueError("authoritative sources must use HTTPS")
        return value

    @model_validator(mode="after")
    def validate_input_inventory(self) -> "ZeekReplaySpecification":
        keys = tuple((item.capture_date, item.relative_path) for item in self.inputs)
        if tuple(sorted(keys)) != keys:
            raise ValueError("replay inputs must use M1 manifest order")
        paths = [item.relative_path for item in self.inputs]
        if len(set(paths)) != len(paths):
            raise ValueError("replay input paths must be unique")
        return self

    def content_sha256(self) -> str:
        """Return a formatting-independent identity for the replay protocol."""
        payload = json.dumps(
            self.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        return sha256(payload).hexdigest()



class ZeekLogArtifact(StrictModel):
    """Validated identity, classification, and count for one emitted Zeek log."""

    log_name: ZeekLogName
    classification: Literal["canonical_telemetry", "operational_runtime"]
    size_bytes: NonNegativeInt
    sha256: Sha256Digest
    record_count: NonNegativeInt


class ZeekReplayRunReport(StrictModel):
    """Deterministic provenance for one successfully published PCAP replay."""

    report_version: VersionString
    verification_status: Literal["verified"]
    specification_sha256: Sha256Digest
    m1_manifest_sha256: Sha256Digest
    input: PcapEvidenceFile
    runtime: ZeekRuntimePin
    output_partition: StrictIdentifier
    command: Annotated[tuple[NonEmptyText, ...], Field(min_length=1)]
    required_logs: Annotated[tuple[ZeekLogName, ...], Field(min_length=1)]
    excluded_operational_logs: Annotated[
        tuple[ZeekLogName, ...],
        Field(min_length=1),
    ]
    operational_log_directory: Literal["operational"]
    logs: Annotated[tuple[ZeekLogArtifact, ...], Field(min_length=1)]

    @model_validator(mode="after")
    def validate_run_inventory(self) -> "ZeekReplayRunReport":
        names = tuple(item.log_name for item in self.logs)
        if names != tuple(sorted(names)):
            raise ValueError("replay logs must be sorted by log_name")
        if len(set(names)) != len(names):
            raise ValueError("replay log names must be unique")
        if not set(self.required_logs).issubset(names):
            raise ValueError("all required logs must exist in replay inventory")
        if tuple(sorted(self.required_logs)) != self.required_logs:
            raise ValueError("required_logs must be sorted")
        if tuple(sorted(self.excluded_operational_logs)) != (
            self.excluded_operational_logs
        ):
            raise ValueError("excluded_operational_logs must be sorted")
        if len(set(self.excluded_operational_logs)) != len(
            self.excluded_operational_logs
        ):
            raise ValueError("excluded_operational_logs must be unique")
        approved_operational_logs = (
            "packet_filter.log",
            "stats.log",
            "telemetry.log",
        )
        if self.excluded_operational_logs != approved_operational_logs:
            raise ValueError(
                "excluded_operational_logs must contain only the approved "
                "runtime measurement logs"
            )
        for artifact in self.logs:
            expected = (
                "operational_runtime"
                if artifact.log_name in self.excluded_operational_logs
                else "canonical_telemetry"
            )
            if artifact.classification != expected:
                raise ValueError(
                    f"incorrect replay classification for {artifact.log_name}"
                )
        return self

    @property
    def canonical_logs(self) -> tuple[ZeekLogArtifact, ...]:
        """Return only PCAP-derived canonical replay evidence."""
        return tuple(
            item for item in self.logs if item.classification == "canonical_telemetry"
        )

    @property
    def operational_logs(self) -> tuple[ZeekLogArtifact, ...]:
        """Return retained runtime measurements excluded from canonical evidence."""
        return tuple(
            item for item in self.logs if item.classification == "operational_runtime"
        )

    def content_sha256(self) -> str:
        """Return a formatting-independent identity for run provenance."""
        payload = json.dumps(
            self.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        return sha256(payload).hexdigest()
