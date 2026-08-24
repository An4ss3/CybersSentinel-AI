"""Strict additive MB2 contracts for the Monday Benign Zeek replay track.

Scope and boundary
------------------
These contracts belong to the **MB track** (Monday Benign), a strictly parallel
canonical track. They never modify, supersede, or re-identify any artifact of
the **M chain** (M1 -> M2 -> M3 v2 -> M4 -> M5 -> M6).

Why autonomous contracts instead of reusing ``ZeekReplaySpecification``
----------------------------------------------------------------------
``ZeekReplaySpecification`` is *not* cardinality-constrained: it accepts a
single input and a free ``output_root``. Reusing it directly would therefore
have worked. It is deliberately **not** reused as the MB2 specification type
because it cannot express the MB-specific invariants that must be unrepresentable
rather than merely untested:

* the output root must be exactly the MB2 tree, never the frozen M2 tree;
* there must be exactly one input, and it must be the Monday capture;
* the Zeek runtime must be byte-identical to the M2 pin so MB2 provenance stays
  comparable to M2;
* the bound manifest must be the MB1 manifest, never the frozen M1 manifest.

A subclass was rejected: Pydantic executes parent validators, and inheriting
``ZeekReplaySpecification.validate_input_inventory`` plus its free-form
``output_root`` would reintroduce exactly the looseness these contracts remove.

Safe M2 primitives *are* reused unchanged: ``PcapEvidenceFile``,
``ZeekRuntimePin``, ``ZeekDeterminismPolicy``, ``ZeekOutputPolicy``,
``ZeekLogArtifact``, ``ZeekLogName``, ``Sha256Digest`` and
``RepositoryRelativePath``.

Report identity determinism
---------------------------
``MondayBenignReplayRunReport.content_sha256()`` deliberately excludes
``started_at`` and ``completed_at``. Those are execution metadata, not evidence.
MB3 will consume the report content digest as a component of every MB3
``event_id``; if wall-clock timestamps entered that digest, MB3 event identities
would change on every re-run and determinism would be unprovable. The M2 report
solves the same problem by carrying no timestamps at all. MB2 records them for
operational auditability but keeps them outside the identity payload.
"""
from __future__ import annotations

from datetime import date
from hashlib import sha256
import json
from pathlib import PurePosixPath
from typing import Annotated, Final, Literal

from pydantic import Field, model_validator

from modules.detection.src.contracts import (
    NonEmptyText,
    StrictIdentifier,
    StrictModel,
    UtcDateTime,
    VersionString,
)
from modules.detection.src.schemas.datasets import PcapEvidenceFile, Sha256Digest
from modules.detection.src.schemas.replay import (
    RepositoryRelativePath,
    ZeekDeterminismPolicy,
    ZeekLogArtifact,
    ZeekLogName,
    ZeekOutputPolicy,
    ZeekRuntimePin,
    _validate_repository_relative_path,
)


# --- MB track frozen coordinates -------------------------------------------

MB1_MANIFEST_RELATIVE_PATH: Final[str] = (
    "datasets/manifests/monday_benign_pcap_freeze.yaml"
)
MB2_SPECIFICATION_RELATIVE_PATH: Final[str] = (
    "datasets/manifests/monday_benign_zeek_replay.yaml"
)
MB2_OUTPUT_ROOT: Final[str] = "artifacts/canonical/cicids2017/mb2/zeek-8.0.9"
MB2_COMPOSE_SERVICE: Final[str] = "zeek-replay-mb"
MB2_COMPOSE_PROFILE: Final[str] = "zeek-replay-mb"

MONDAY_PCAP_RELATIVE_PATH: Final[str] = "Monday-WorkingHours.pcap"
MONDAY_CAPTURE_DATE: Final[date] = date(2017, 7, 3)
MONDAY_OUTPUT_PARTITION: Final[str] = "2017-07-03_Monday-WorkingHours"

# --- Frozen M chain coordinates, referenced by value only, never written ----

M2_FROZEN_OUTPUT_ROOT: Final[str] = "artifacts/canonical/cicids2017/m2/zeek-8.0.9"
M2_COMPOSE_SERVICE: Final[str] = "zeek-replay"
M2_ZEEK_IMAGE_INDEX_DIGEST: Final[str] = (
    "sha256:c7dfad9ab8296b2994d113222e77a22ebc9c8963b2b1200b798484ac923bc94f"
)
M2_ZEEK_PLATFORM_MANIFEST_DIGEST: Final[str] = (
    "sha256:65c79e9e641a90488e303a464bf063288b3f656fa73cd7d6aefe6d119c0bf9d5"
)
M2_ZEEK_VERSION: Final[str] = "8.0.9"

_REPORT_IDENTITY_EXCLUDED_FIELDS: Final[frozenset[str]] = frozenset(
    {"started_at", "completed_at"}
)


def _canonical_digest(payload: dict[str, object]) -> str:
    """Hash a payload with the project-wide canonical serialization."""
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return sha256(encoded).hexdigest()


def _reject_m2_containment(value: str, field_name: str) -> str:
    """Forbid any MB path that is inside, or equal to, the frozen M2 tree."""
    if value == M2_FROZEN_OUTPUT_ROOT or value.startswith(
        M2_FROZEN_OUTPUT_ROOT.rstrip("/") + "/"
    ):
        raise ValueError(
            f"{field_name} must never resolve inside the frozen M2 tree "
            f"{M2_FROZEN_OUTPUT_ROOT}"
        )
    return value


def monday_partition_name(evidence: PcapEvidenceFile) -> str:
    """Derive the MB2 partition name with the frozen M2 naming convention."""
    stem = PurePosixPath(evidence.relative_path).stem
    return f"{evidence.capture_date.isoformat()}_{stem}"


class MondayBenignReplaySpecification(StrictModel):
    """Frozen MB2 replay protocol bound to exactly one MB1 Monday freeze."""

    specification_version: VersionString
    frozen_at: UtcDateTime
    m1_manifest_path: RepositoryRelativePath
    m1_manifest_sha256: Sha256Digest
    dataset_name: StrictIdentifier
    inputs: Annotated[
        tuple[PcapEvidenceFile, ...],
        Field(min_length=1, max_length=1),
    ]
    runtime: ZeekRuntimePin
    determinism: ZeekDeterminismPolicy
    output: ZeekOutputPolicy
    authoritative_sources: Annotated[tuple[NonEmptyText, ...], Field(min_length=1)]

    @model_validator(mode="after")
    def validate_monday_benign_freeze(self) -> "MondayBenignReplaySpecification":
        """Make M2 reuse and non-Monday input structurally impossible."""
        manifest_path = _validate_repository_relative_path(self.m1_manifest_path)
        if not manifest_path.endswith((".yaml", ".yml")):
            raise ValueError("MB1 manifest path must use a YAML suffix")
        if manifest_path != MB1_MANIFEST_RELATIVE_PATH:
            raise ValueError(
                "MB2 must bind the MB1 manifest exactly "
                f"({MB1_MANIFEST_RELATIVE_PATH}); the frozen M1 manifest is "
                "never a valid MB2 input"
            )

        output_root = _validate_repository_relative_path(self.output.output_root)
        _reject_m2_containment(output_root, "output.output_root")
        if output_root != MB2_OUTPUT_ROOT:
            raise ValueError(
                f"MB2 output_root must be exactly {MB2_OUTPUT_ROOT}"
            )

        evidence = self.inputs[0]
        if evidence.relative_path != MONDAY_PCAP_RELATIVE_PATH:
            raise ValueError(
                f"MB2 input must be {MONDAY_PCAP_RELATIVE_PATH}"
            )
        if evidence.capture_date != MONDAY_CAPTURE_DATE:
            raise ValueError(
                f"MB2 capture_date must be {MONDAY_CAPTURE_DATE.isoformat()}"
            )
        if monday_partition_name(evidence) != MONDAY_OUTPUT_PARTITION:
            raise ValueError(
                f"MB2 partition must be {MONDAY_OUTPUT_PARTITION}"
            )

        if self.runtime.zeek_version != M2_ZEEK_VERSION:
            raise ValueError("MB2 must pin the same Zeek version as M2")
        if self.runtime.image_index_digest != M2_ZEEK_IMAGE_INDEX_DIGEST:
            raise ValueError("MB2 must pin the same Zeek image digest as M2")
        if self.runtime.platform_manifest_digest != (
            M2_ZEEK_PLATFORM_MANIFEST_DIGEST
        ):
            raise ValueError("MB2 must pin the same Zeek platform digest as M2")

        if tuple(sorted(self.authoritative_sources)) != self.authoritative_sources:
            raise ValueError("authoritative_sources must be sorted")
        if len(set(self.authoritative_sources)) != len(self.authoritative_sources):
            raise ValueError("authoritative_sources must be unique")
        if any(
            not item.startswith("https://") for item in self.authoritative_sources
        ):
            raise ValueError("authoritative sources must use HTTPS")
        return self

    @property
    def input(self) -> PcapEvidenceFile:
        """Return the single Monday capture bound by this specification."""
        return self.inputs[0]

    @property
    def output_partition(self) -> str:
        """Return the deterministic MB2 partition name."""
        return monday_partition_name(self.inputs[0])

    def content_sha256(self) -> str:
        """Return a formatting-independent identity for the MB2 protocol."""
        return _canonical_digest(self.model_dump(mode="json"))


class MondayBenignReplayRunReport(StrictModel):
    """Deterministic provenance for one published MB2 Monday replay.

    Carries everything MB3 needs to bind its normalization protocol: the
    specification identity, the MB1 manifest identity, the runtime pin, the
    partition, the output root, and a per-log SHA-256 inventory with record
    counts. It additionally records the Compose service and profile actually
    used, so a reader can prove the M2 service was not involved.
    """

    report_version: VersionString
    verification_status: Literal["verified"]
    track: Literal["monday_benign"]
    specification_sha256: Sha256Digest
    m1_manifest_sha256: Sha256Digest
    input: PcapEvidenceFile
    runtime: ZeekRuntimePin
    output_root: RepositoryRelativePath
    output_partition: StrictIdentifier
    compose_service: Literal["zeek-replay-mb"]
    compose_profile: Literal["zeek-replay-mb"]
    command: Annotated[tuple[NonEmptyText, ...], Field(min_length=1)]
    required_logs: Annotated[tuple[ZeekLogName, ...], Field(min_length=1)]
    excluded_operational_logs: Annotated[
        tuple[ZeekLogName, ...],
        Field(min_length=1),
    ]
    operational_log_directory: Literal["operational"]
    logs: Annotated[tuple[ZeekLogArtifact, ...], Field(min_length=1)]
    started_at: UtcDateTime
    completed_at: UtcDateTime

    @model_validator(mode="after")
    def validate_run_inventory(self) -> "MondayBenignReplayRunReport":
        """Bind the report to MB coordinates and a coherent log inventory."""
        output_root = _validate_repository_relative_path(self.output_root)
        _reject_m2_containment(output_root, "output_root")
        if output_root != MB2_OUTPUT_ROOT:
            raise ValueError(f"MB2 output_root must be exactly {MB2_OUTPUT_ROOT}")
        if self.output_partition != MONDAY_OUTPUT_PARTITION:
            raise ValueError(f"MB2 partition must be {MONDAY_OUTPUT_PARTITION}")
        if self.input.relative_path != MONDAY_PCAP_RELATIVE_PATH:
            raise ValueError(f"MB2 input must be {MONDAY_PCAP_RELATIVE_PATH}")
        if self.input.capture_date != MONDAY_CAPTURE_DATE:
            raise ValueError(
                f"MB2 capture_date must be {MONDAY_CAPTURE_DATE.isoformat()}"
            )
        if self.runtime.image_index_digest != M2_ZEEK_IMAGE_INDEX_DIGEST:
            raise ValueError("MB2 report must carry the frozen M2 image digest")
        if self.completed_at < self.started_at:
            raise ValueError("completed_at cannot precede started_at")

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

    def identity_payload(self) -> dict[str, object]:
        """Return the deterministic evidence payload used for identity.

        Execution metadata (``started_at`` / ``completed_at``) is excluded so
        that re-running an identical replay yields an identical digest, which
        MB3 requires because it consumes this digest as an event-ID component.
        """
        payload = self.model_dump(mode="json")
        for field_name in _REPORT_IDENTITY_EXCLUDED_FIELDS:
            payload.pop(field_name, None)
        return payload

    def content_sha256(self) -> str:
        """Return the deterministic, timestamp-independent report identity."""
        return _canonical_digest(self.identity_payload())
