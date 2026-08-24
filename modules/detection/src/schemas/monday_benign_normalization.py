"""Strict additive MB3 contracts for Monday Benign exact-time normalization.

Scope
-----
MB3 belongs to the **MB track**. It never modifies, supersedes, or re-identifies
any artifact of the **M chain** (M1 -> M2 -> M3 v2 -> M4 -> M5 -> M6).

Why an autonomous specification
-------------------------------
``ZeekNormalizationSpecificationV2`` cannot be reused or subclassed for MB3. It
hard-locks seven values, every one of them M-chain specific:

1. ``len(replay_reports) != 3`` -> raises;
2. ``frozen_at`` must equal the literal ``2026-07-31T15:46:36.173000Z``;
3. ``event_id_namespace`` must equal ``f7dad188-04cb-5859-81a0-014329de2899``;
4. ``supersedes_protocol_sha256`` must equal the frozen M3 v1 protocol;
5. ``revision_reason`` is a fixed literal about microsecond incompatibility;
6. ``ZeekTemporalEvidenceProfileV2`` declares the M-chain record counts
   (1,380,057 / 1,353,467 / 26,590) as ``Literal`` values;
7. replay report paths must sit below the frozen M2 output root.

Subclassing would re-run every one of those validators, so MB3 declares its own
specification. Each **cardinality-agnostic** policy sub-model is nevertheless
reused verbatim: ``ZeekConnLogMappingV2``, ``ZeekTemporalPolicyV2``,
``ZeekEventEnvelopePolicyV2``, ``ZeekUnsupportedRecordPolicyV2``,
``ZeekOrderingPolicy``, ``ZeekParserBoundaryPolicyV2``,
``ZeekReplayReportBinding``, and the whole partition-report family
(``ZeekPartitionNormalizationReportV2``, ``ZeekRejectionCountV2``,
``ZeekRejectionSpanV2``). MB3 therefore inherits identical conn.log ->
``FlowEndV2`` mapping semantics and identical exact-time guarantees.

Evidence profile: a deliberate departure from M3 v2
---------------------------------------------------
M3 v2 baked *predicted* accept/reject counts into its protocol as ``Literal``
values. Reproducing that would be circular for MB3: the counts are only knowable
by running the normalizer, which needs the protocol hash, which would change if
the counts changed. ``MondayBenignEvidenceProfile`` therefore declares **only
what is measurable by a read-only lexical pre-scan** -- line count, how many
records carry a duration, and the observed decimal widths. Accept and reject
counts live solely in the run report, where they are observed rather than
predicted.
"""
from __future__ import annotations

from hashlib import sha256
import json
from typing import Annotated, Final, Literal
from uuid import NAMESPACE_URL, UUID, uuid5

from pydantic import Field, field_validator, model_validator

from modules.detection.src.contracts import (
    NonEmptyText,
    NonNegativeInt,
    PositiveInt,
    StrictIdentifier,
    StrictModel,
    UtcDateTime,
)
from modules.detection.src.schemas.datasets import Sha256Digest
from modules.detection.src.schemas.exact_time_v2 import (
    ExactDecimalSeconds22,
    unscaled_from_canonical,
)
from modules.detection.src.schemas.monday_benign_replay import (
    M2_FROZEN_OUTPUT_ROOT,
    MB2_OUTPUT_ROOT,
    MB2_SPECIFICATION_RELATIVE_PATH,
    MONDAY_OUTPUT_PARTITION,
)
from modules.detection.src.schemas.replay import RepositoryRelativePath
from modules.detection.src.schemas.zeek_normalization import (
    ZeekOrderingPolicy,
    ZeekReplayReportBinding,
    _repository_relative,
)
from modules.detection.src.schemas.zeek_normalization_run_v2 import (
    ZeekPartitionNormalizationReportV2,
)
from modules.detection.src.schemas.zeek_normalization_v2 import (
    ZeekConnLogMappingV2,
    ZeekEventEnvelopePolicyV2,
    ZeekParserBoundaryPolicyV2,
    ZeekTemporalPolicyV2,
    ZeekUnsupportedRecordPolicyV2,
)


# --- MB3 frozen coordinates -------------------------------------------------

MB3_PROTOCOL_RELATIVE_PATH: Final[str] = (
    "datasets/manifests/monday_benign_zeek_normalization.yaml"
)
MB3_REPORT_RELATIVE_PATH: Final[str] = (
    "artifacts/reports/mb3_monday_benign_normalization_run.json"
)

#: Deterministic MB3 identity namespace. Derived, never invented, and provably
#: distinct from the M3 v2 and M6 namespaces. Reproduce with:
#:     uuid5(NAMESPACE_URL, MB3_NAMESPACE_DERIVATION_NAME)
MB3_NAMESPACE_DERIVATION_NAME: Final[str] = (
    "https://cybersentinel.invalid/mb3/monday-benign/"
    "exact-time-normalization/2.0.0"
)
MB3_EVENT_ID_NAMESPACE: Final[UUID] = uuid5(
    NAMESPACE_URL, MB3_NAMESPACE_DERIVATION_NAME
)

#: Namespaces owned by the M chain. MB3 must never reuse either.
M3_V2_EVENT_ID_NAMESPACE: Final[UUID] = UUID("f7dad188-04cb-5859-81a0-014329de2899")
M6_WINDOW_ID_NAMESPACE: Final[UUID] = UUID("f787c08a-290e-5b79-a8cb-5bc19ae633dc")

MB_DATASET_NAME: Final[str] = "cicids2017"

_EXPECTED_EVENT_ID_COMPONENTS: Final[tuple[str, ...]] = (
    "protocol_sha256",
    "replay_report_content_sha256",
    "source_log_sha256",
    "output_partition",
    "log_name",
    "physical_line_number",
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
    """Forbid any MB path inside, or equal to, the frozen M2 tree."""
    if value == M2_FROZEN_OUTPUT_ROOT or value.startswith(
        M2_FROZEN_OUTPUT_ROOT.rstrip("/") + "/"
    ):
        raise ValueError(
            f"{field_name} must never resolve inside the frozen M2 tree "
            f"{M2_FROZEN_OUTPUT_ROOT}"
        )
    return value


class MondayBenignEvidenceProfile(StrictModel):
    """Read-only lexical measurements of the Monday conn.log.

    Every field is observable without invoking the normalizer, so freezing this
    profile cannot depend on the outcome it would otherwise predict. Accept and
    reject counts are deliberately absent; they belong to the run report.
    """

    measurement_method: Literal["read_only_lexical_prescan"]
    scanned_record_count: PositiveInt
    records_with_duration: NonNegativeInt
    timestamp_max_significant_digits: PositiveInt
    timestamp_max_fractional_digits: NonNegativeInt
    duration_max_significant_digits: NonNegativeInt
    duration_max_fractional_digits: NonNegativeInt
    exact_end_max_significant_digits: NonNegativeInt
    exact_end_max_fractional_digits: NonNegativeInt
    canonical_type: Literal["DECIMAL(38,22)"]

    @model_validator(mode="after")
    def validate_profile(self) -> "MondayBenignEvidenceProfile":
        """Reject a profile that cannot describe DECIMAL(38,22) evidence."""
        if self.records_with_duration > self.scanned_record_count:
            raise ValueError("records_with_duration exceeds scanned_record_count")
        for name, value in (
            ("timestamp_max_significant_digits", self.timestamp_max_significant_digits),
            ("duration_max_significant_digits", self.duration_max_significant_digits),
            ("exact_end_max_significant_digits", self.exact_end_max_significant_digits),
        ):
            if value > 38:
                raise ValueError(f"{name} exceeds DECIMAL(38,22) precision")
        for name, value in (
            ("timestamp_max_fractional_digits", self.timestamp_max_fractional_digits),
            ("duration_max_fractional_digits", self.duration_max_fractional_digits),
            ("exact_end_max_fractional_digits", self.exact_end_max_fractional_digits),
        ):
            if value > 22:
                raise ValueError(f"{name} exceeds DECIMAL(38,22) scale")
        return self


class MondayBenignProvenancePolicy(StrictModel):
    """MB3 identity policy: same algorithm as M3 v2, distinct namespace."""

    event_id_algorithm: Literal["uuid5"]
    event_id_namespace: UUID
    event_id_namespace_derivation: NonEmptyText
    event_id_components: tuple[NonEmptyText, ...]
    event_id_name_encoding: Literal[
        "utf8_component_values_joined_by_single_ascii_pipe_line_number_base10"
    ]
    sensor_id: Literal["zeek"]
    sensor_run_id_source: Literal["replay_report_content_sha256"]
    capture_id_source: Literal["input_pcap_sha256"]
    dataset_snapshot_id_source: Literal["m1_manifest_sha256"]
    model_release_id_policy: Literal["explicit_null"]

    @model_validator(mode="after")
    def validate_identity(self) -> "MondayBenignProvenancePolicy":
        """Pin the MB3 namespace and forbid reusing any M chain namespace."""
        if self.event_id_namespace == M3_V2_EVENT_ID_NAMESPACE:
            raise ValueError(
                "MB3 must never reuse the M3 v2 event ID namespace"
            )
        if self.event_id_namespace == M6_WINDOW_ID_NAMESPACE:
            raise ValueError("MB3 must never reuse the M6 window ID namespace")
        if self.event_id_namespace != MB3_EVENT_ID_NAMESPACE:
            raise ValueError(
                f"MB3 event ID namespace must be {MB3_EVENT_ID_NAMESPACE}"
            )
        if self.event_id_namespace_derivation != MB3_NAMESPACE_DERIVATION_NAME:
            raise ValueError("MB3 namespace derivation string mismatch")
        if uuid5(NAMESPACE_URL, self.event_id_namespace_derivation) != (
            self.event_id_namespace
        ):
            raise ValueError(
                "declared MB3 namespace is not reproducible from its derivation"
            )
        if self.event_id_components != _EXPECTED_EVENT_ID_COMPONENTS:
            raise ValueError("MB3 event ID components diverge from the freeze")
        return self


class MondayBenignNormalizationSpecification(StrictModel):
    """Frozen MB3 protocol bound to exactly one MB2 Monday replay partition."""

    protocol_version: Literal["2.0.0"]
    frozen_at: UtcDateTime
    track: Literal["monday_benign"]
    dataset_name: StrictIdentifier
    m1_manifest_sha256: Sha256Digest
    mb2_specification_path: RepositoryRelativePath
    mb2_specification_sha256: Sha256Digest
    mb2_output_root: RepositoryRelativePath
    sensor_type: Literal["zeek"]
    sensor_version: Literal["8.0.9"]
    input_format: Literal["json_lines"]
    replay_reports: Annotated[
        tuple[ZeekReplayReportBinding, ...],
        Field(min_length=1, max_length=1),
    ]
    log_mappings: Annotated[
        tuple[ZeekConnLogMappingV2, ...],
        Field(min_length=1, max_length=1),
    ]
    temporal: ZeekTemporalPolicyV2
    evidence: MondayBenignEvidenceProfile
    event_envelope: ZeekEventEnvelopePolicyV2
    provenance: MondayBenignProvenancePolicy
    unsupported_records: ZeekUnsupportedRecordPolicyV2
    ordering: ZeekOrderingPolicy
    boundaries: ZeekParserBoundaryPolicyV2
    authoritative_sources: Annotated[tuple[NonEmptyText, ...], Field(min_length=1)]

    @field_validator("mb2_specification_path", "mb2_output_root")
    @classmethod
    def validate_paths(cls, value: str) -> str:
        return _repository_relative(value)

    @model_validator(mode="after")
    def validate_monday_benign_freeze(
        self,
    ) -> "MondayBenignNormalizationSpecification":
        """Make M chain reuse and non-Monday partitions structurally impossible."""
        _reject_m2_containment(self.mb2_output_root, "mb2_output_root")
        if self.mb2_output_root != MB2_OUTPUT_ROOT:
            raise ValueError(f"MB3 mb2_output_root must be exactly {MB2_OUTPUT_ROOT}")
        if self.mb2_specification_path != MB2_SPECIFICATION_RELATIVE_PATH:
            raise ValueError(
                f"MB3 must bind {MB2_SPECIFICATION_RELATIVE_PATH}"
            )
        if self.dataset_name != MB_DATASET_NAME:
            raise ValueError(f"MB track dataset_name must be {MB_DATASET_NAME}")

        binding = self.replay_reports[0]
        if binding.output_partition != MONDAY_OUTPUT_PARTITION:
            raise ValueError(f"MB3 partition must be {MONDAY_OUTPUT_PARTITION}")
        prefix = f"{self.mb2_output_root}/"
        if not binding.report_relative_path.startswith(prefix):
            raise ValueError(
                "MB3 replay report must sit below the MB2 output root"
            )
        _reject_m2_containment(
            binding.report_relative_path, "replay_reports[0].report_relative_path"
        )
        if self.log_mappings[0].log_name != "conn.log":
            raise ValueError("MB3 supports only conn.log")

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
    def m2_output_root(self) -> str:
        """Alias consumed by the reused M3 v2 runner internals.

        The reused streaming runner resolves source logs through
        ``specification.m2_output_root``. For MB3 that root is the **MB2** tree;
        the field is named ``mb2_output_root`` so no manifest can imply the
        frozen M2 tree, and this alias keeps the inherited runner working
        without modifying it.
        """
        return self.mb2_output_root

    @property
    def output_partition(self) -> str:
        """Return the single MB3 partition name."""
        return self.replay_reports[0].output_partition

    def content_sha256(self) -> str:
        """Return a formatting-independent identity for the MB3 protocol."""
        return _canonical_digest(self.model_dump(mode="json"))


class MondayBenignNormalizationRunReport(StrictModel):
    """Deterministic MB3 run evidence for the single Monday partition."""

    report_version: Literal["2.0.0"]
    verification_status: Literal["verified"]
    track: Literal["monday_benign"]
    protocol_sha256: Sha256Digest
    m1_manifest_sha256: Sha256Digest
    mb2_specification_sha256: Sha256Digest
    mb2_replay_report_content_sha256: Sha256Digest
    event_id_namespace: UUID
    dataset_name: StrictIdentifier
    sensor_type: Literal["zeek"]
    sensor_version: Literal["8.0.9"]
    schema_version: Literal["2.0.0"]
    event_version: Literal["2.0.0"]
    feature_version: Literal["1.0.0"]
    normalizer_version: Literal["2.0.0"]
    pipeline_version: Literal["2.0.0"]
    temporal_encoding: Literal["DECIMAL(38,22)_fixed_scale_string"]
    record_available_time: ExactDecimalSeconds22
    ingested_at: ExactDecimalSeconds22
    partition_reports: Annotated[
        tuple[ZeekPartitionNormalizationReportV2, ...],
        Field(min_length=1, max_length=1),
    ]
    total_processed_record_count: NonNegativeInt
    total_accepted_record_count: NonNegativeInt
    total_rejected_record_count: NonNegativeInt
    canonical_event_stream_sha256: Sha256Digest
    rejection_audit_stream_sha256: Sha256Digest

    @model_validator(mode="after")
    def validate_run(self) -> "MondayBenignNormalizationRunReport":
        """Bind totals, partition identity, and namespace to MB coordinates."""
        if unscaled_from_canonical(self.ingested_at) < unscaled_from_canonical(
            self.record_available_time
        ):
            raise ValueError("MB3 ingested_at precedes record_available_time")
        if self.event_id_namespace != MB3_EVENT_ID_NAMESPACE:
            raise ValueError(
                f"MB3 report namespace must be {MB3_EVENT_ID_NAMESPACE}"
            )
        if self.dataset_name != MB_DATASET_NAME:
            raise ValueError(f"MB track dataset_name must be {MB_DATASET_NAME}")

        partition = self.partition_reports[0]
        if partition.output_partition != MONDAY_OUTPUT_PARTITION:
            raise ValueError(f"MB3 partition must be {MONDAY_OUTPUT_PARTITION}")
        if partition.replay_report_content_sha256 != (
            self.mb2_replay_report_content_sha256
        ):
            raise ValueError(
                "MB3 partition report does not reference the bound MB2 replay"
            )
        if self.total_processed_record_count != partition.processed_record_count:
            raise ValueError("MB3 total processed mismatch")
        if self.total_accepted_record_count != partition.accepted_record_count:
            raise ValueError("MB3 total accepted mismatch")
        if self.total_rejected_record_count != partition.rejected_record_count:
            raise ValueError("MB3 total rejected mismatch")
        if self.total_processed_record_count != (
            self.total_accepted_record_count + self.total_rejected_record_count
        ):
            raise ValueError("MB3 totals do not cover the source")
        return self

    def content_sha256(self) -> str:
        """Return a formatting-independent identity for the MB3 run."""
        return _canonical_digest(self.model_dump(mode="json"))
