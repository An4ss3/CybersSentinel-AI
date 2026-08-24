"""Strict additive MB6 contracts for Monday Benign feature windows.

Scope
-----
MB6 belongs to the **MB track**. It never modifies, supersedes, or re-identifies
any artifact of the **M chain**. Its operational source is
``mb4_canonical.flow_end_events``; it never reads ``m4_canonical`` or
``m6_canonical``, never reads the PCAP, and never reads the Zeek logs.

Why an autonomous specification
-------------------------------
``FeatureWindowSpecificationV2`` cannot be reused for MB6. It hard-locks five
M-chain values as ``Literal``:

1. ``milestone`` = ``"m6"``;
2. ``operational_source`` = ``"m4_canonical.flow_end_events"``;
3. ``evidence_source`` = ``"frozen_m2_conn_log_via_m3_v2_protocol"``;
4. ``FeatureWindowPersistencePolicyV2.operational_projection`` =
   ``"postgresql_schema_m6_canonical"``;
5. ``FeatureWindowOrderingPolicyV2.partition_order`` =
   ``"m3_replay_report_binding_order"``.

A correction to an earlier claim in the project index: that index previously said
``FeatureWindowSpecificationV2`` was reusable unchanged. That is true only for its
**namespace**, which is a free ``UUID``. The five literals above make the
specification itself unusable for MB6.

Everything cardinality-agnostic *is* reused verbatim, so MB6 inherits identical
window semantics: ``FeatureWindowTemporalPolicyV2``, ``FeatureWindowGeometryV2``,
``FeatureWindowEntityPolicyV2``, ``FeatureWindowFeaturePolicyV2``,
``FeatureWindowIdentityPolicyV2``, ``FeatureWindowProvenancePolicyV2``,
``FeatureWindowLabelPolicyV2``, ``FeatureWindowDeferredPolicyV2``,
``FeatureWindowContractVersionsV2``, ``FeatureWindowPartitionReportV2``,
``FeatureWindowV2`` and ``FeatureWindowBuilderV2``.

Determinism, stricter than M6
-----------------------------
M6 declared ``run_identity_algorithm = "uuid4_at_execution"``, which is why the
M6 report ``content_sha256`` is knowingly irreproducible. MB6 forbids randomness
outright: ``run_id`` is ``uuid5`` over the MB6 protocol hash and the MB4 run
identity, so the same protocol against the same MB4 run always yields the same
run identity. Wall-clock fields are recorded for audit but excluded from
``content_sha256``, under the identity rule the owner ratified for MB2.
"""
from __future__ import annotations

from hashlib import sha256
import json
from typing import Annotated, Final, Literal
from uuid import NAMESPACE_URL, UUID, uuid5

from pydantic import Field, model_validator

from modules.detection.src.contracts import (
    NonEmptyText,
    NonNegativeInt,
    StrictIdentifier,
    StrictModel,
    UtcDateTime,
    VersionString,
)
from modules.detection.src.schemas.datasets import Sha256Digest
from modules.detection.src.schemas.exact_time_v2 import ExactDecimalSeconds22
from modules.detection.src.schemas.feature_window_protocol_v2 import (
    FeatureWindowContractVersionsV2,
    FeatureWindowDeferredPolicyV2,
    FeatureWindowEntityPolicyV2,
    FeatureWindowFeaturePolicyV2,
    FeatureWindowGeometryV2,
    FeatureWindowIdentityPolicyV2,
    FeatureWindowLabelPolicyV2,
    FeatureWindowPartitionReportV2,
    FeatureWindowProvenancePolicyV2,
    FeatureWindowTemporalPolicyV2,
)
from modules.detection.src.schemas.monday_benign_normalization import (
    M3_V2_EVENT_ID_NAMESPACE,
    MB3_EVENT_ID_NAMESPACE,
    MB_DATASET_NAME,
)
from modules.detection.src.schemas.monday_benign_replay import MONDAY_OUTPUT_PARTITION


MB6_PROTOCOL_RELATIVE_PATH: Final[str] = (
    "datasets/manifests/monday_benign_feature_window.yaml"
)
MB6_REPORT_RELATIVE_PATH: Final[str] = (
    "artifacts/reports/mb6_monday_benign_feature_window_run.json"
)
MB6_SCHEMA: Final[str] = "mb6_canonical"
MB4_OPERATIONAL_SOURCE: Final[str] = "mb4_canonical.flow_end_events"

#: Deterministic MB6 window-identity namespace. Reproduce with
#: ``uuid5(NAMESPACE_URL, MB6_NAMESPACE_DERIVATION_NAME)``.
MB6_NAMESPACE_DERIVATION_NAME: Final[str] = (
    "https://cybersentinel.invalid/mb6/monday-benign/feature-window/2.0.0"
)
MB6_WINDOW_ID_NAMESPACE: Final[UUID] = uuid5(
    NAMESPACE_URL, MB6_NAMESPACE_DERIVATION_NAME
)

#: Namespaces owned by the M chain or by an earlier MB milestone.
M6_WINDOW_ID_NAMESPACE: Final[UUID] = UUID("f787c08a-290e-5b79-a8cb-5bc19ae633dc")
_FORBIDDEN_NAMESPACES: Final[tuple[UUID, ...]] = (
    M6_WINDOW_ID_NAMESPACE,
    M3_V2_EVENT_ID_NAMESPACE,
    MB3_EVENT_ID_NAMESPACE,
)

_RUN_ID_DERIVATION_PREFIX: Final[str] = "mb6-run"


def _canonical_digest(payload: dict[str, object]) -> str:
    """Hash a payload with the project-wide canonical serialization."""
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return sha256(encoded).hexdigest()


def derive_mb6_run_id(protocol_sha256: str, mb4_run_id: UUID | str) -> UUID:
    """Derive the deterministic MB6 run identity.

    One MB6 run exists per (MB6 protocol, MB4 source run). No randomness and no
    clock reading enters the identity, so a re-run over the same evidence is
    recognisable rather than merely similar.
    """
    name = f"{_RUN_ID_DERIVATION_PREFIX}|{protocol_sha256}|{mb4_run_id}"
    return uuid5(MB6_WINDOW_ID_NAMESPACE, name)


class MondayBenignWindowPersistencePolicy(StrictModel):
    """MB6 persistence policy: projects into mb6_canonical, never the M chain."""

    canonical_evidence: Literal["immutable_published_report"]
    operational_projection: Literal["postgresql_schema_mb6_canonical"]
    projection_is_reconstructible: Literal[True]
    destructive_modification_of_mb4_canonical: Literal["forbidden"]
    destructive_modification_of_m_chain: Literal["forbidden"]
    foreign_keys_outside_mb6_canonical: Literal["forbidden"]
    test_isolation: Literal["read_only_tests_against_the_mb_database"]


class MondayBenignWindowOrderingPolicy(StrictModel):
    """MB6 canonical ordering: identical keys, MB-scoped partition order."""

    keys: tuple[StrictIdentifier, ...]
    partition_order: Literal["mb3_replay_report_binding_order"]
    window_start_comparison: Literal["unscaled_integer"]
    sort_by_feature_value: Literal[False]
    dictionary_or_set_iteration_order: Literal["forbidden"]

    @model_validator(mode="after")
    def validate_ordering(self) -> "MondayBenignWindowOrderingPolicy":
        expected = (
            "output_partition",
            "entity_type",
            "entity_key",
            "window_start_time",
        )
        if self.keys != expected:
            raise ValueError("MB6 canonical ordering keys diverge from the freeze")
        return self


class MondayBenignWindowGovernancePolicy(StrictModel):
    """MB6 governance: deterministic run identity, no randomness anywhere."""

    manifest_frozen_before_materialization: Literal[True]
    run_identity_in_manifest: Literal[False]
    run_identity_location: Literal["materialization_report_only"]
    run_identity_algorithm: Literal[
        "deterministic_uuid5_over_protocol_and_mb4_run_id"
    ]
    random_identifiers: Literal["forbidden"]
    wall_clock_in_identity: Literal["forbidden"]
    immutable_publication: Literal["fail_if_exists_fsync_atomic_rename"]
    deterministic_rerun_requirement: Literal["identical_content_sha256"]


class MondayBenignFeatureWindowSpecification(StrictModel):
    """Frozen MB6 protocol bound to MB1/MB2/MB3/MB4 identities."""

    protocol_version: Literal["2.0.0"]
    milestone: Literal["mb6"]
    track: Literal["monday_benign"]
    frozen_at: UtcDateTime
    dataset_name: StrictIdentifier

    mb1_manifest_sha256: Sha256Digest
    mb2_specification_sha256: Sha256Digest
    mb2_replay_report_content_sha256: Sha256Digest
    mb3_protocol_sha256: Sha256Digest
    mb3_report_content_sha256: Sha256Digest
    mb3_report_file_sha256: Sha256Digest
    mb3_event_stream_sha256: Sha256Digest
    mb3_rejection_audit_stream_sha256: Sha256Digest
    mb4_report_content_sha256: Sha256Digest
    mb4_report_file_sha256: Sha256Digest
    mb4_run_id: UUID

    output_partition: StrictIdentifier
    source_event_model: Literal["FlowEndV2"]
    source_event_feature_version: Literal["1.0.0"]
    operational_source: Literal["mb4_canonical.flow_end_events"]
    evidence_source: Literal["mb2_monday_conn_log_via_mb3_protocol"]
    postgresql_is_independent_evidence: Literal[False]

    target_model: Literal["FeatureWindowV2"]
    window_contract_versions: FeatureWindowContractVersionsV2
    m_chain_status: Literal["untouched_and_frozen"]

    temporal: FeatureWindowTemporalPolicyV2
    window: FeatureWindowGeometryV2
    entity: FeatureWindowEntityPolicyV2
    features: FeatureWindowFeaturePolicyV2
    identity: FeatureWindowIdentityPolicyV2
    provenance: FeatureWindowProvenancePolicyV2
    labels: FeatureWindowLabelPolicyV2
    deferred: FeatureWindowDeferredPolicyV2
    ordering: MondayBenignWindowOrderingPolicy
    persistence: MondayBenignWindowPersistencePolicy
    governance: MondayBenignWindowGovernancePolicy
    authoritative_sources: Annotated[tuple[NonEmptyText, ...], Field(min_length=1)]

    @model_validator(mode="after")
    def validate_specification(self) -> "MondayBenignFeatureWindowSpecification":
        """Pin MB coordinates and forbid every M chain namespace."""
        if self.output_partition != MONDAY_OUTPUT_PARTITION:
            raise ValueError(f"MB6 partition must be {MONDAY_OUTPUT_PARTITION}")
        if self.dataset_name != MB_DATASET_NAME:
            raise ValueError(f"MB track dataset_name must be {MB_DATASET_NAME}")

        namespace = self.identity.namespace
        if namespace in _FORBIDDEN_NAMESPACES:
            raise ValueError(
                "MB6 must never reuse an M chain or earlier MB namespace"
            )
        if namespace != MB6_WINDOW_ID_NAMESPACE:
            raise ValueError(
                f"MB6 window namespace must be {MB6_WINDOW_ID_NAMESPACE}"
            )
        if self.identity.namespace_derivation != MB6_NAMESPACE_DERIVATION_NAME:
            raise ValueError("MB6 namespace derivation string mismatch")
        if uuid5(NAMESPACE_URL, self.identity.namespace_derivation) != namespace:
            raise ValueError(
                "declared MB6 namespace is not reproducible from its derivation"
            )

        if tuple(sorted(self.authoritative_sources)) != self.authoritative_sources:
            raise ValueError("authoritative sources must be sorted")
        if len(set(self.authoritative_sources)) != len(self.authoritative_sources):
            raise ValueError("authoritative sources must be unique")
        if any(
            not value.startswith("https://") for value in self.authoritative_sources
        ):
            raise ValueError("authoritative sources must use HTTPS")
        return self

    def content_sha256(self) -> str:
        """Return a formatting-independent identity for the MB6 protocol."""
        return _canonical_digest(self.model_dump(mode="json"))


class MondayBenignFeatureWindowRunReport(StrictModel):
    """Deterministic evidence for one MB6 window materialization run."""

    report_version: Literal["1.0.0"]
    verification_status: Literal["verified"]
    track: Literal["monday_benign"]
    run_id: UUID
    run_id_derivation: Literal[
        "deterministic_uuid5_over_protocol_and_mb4_run_id"
    ]

    protocol_sha256: Sha256Digest
    mb1_manifest_sha256: Sha256Digest
    mb2_specification_sha256: Sha256Digest
    mb3_protocol_sha256: Sha256Digest
    mb3_report_content_sha256: Sha256Digest
    mb4_report_content_sha256: Sha256Digest
    mb4_run_id: UUID
    window_id_namespace: UUID

    target_database: StrictIdentifier
    target_schema: Literal["mb6_canonical"]
    operational_source: Literal["mb4_canonical.flow_end_events"]

    dataset_name: StrictIdentifier
    target_model: Literal["FeatureWindowV2"]
    schema_version: Literal["2.0.0"]
    event_version: Literal["2.0.0"]
    feature_version: Literal["2.0.0"]
    sensor_version: VersionString

    entity_type: Literal["source_destination_service"]
    window_length_seconds: ExactDecimalSeconds22
    windowing_basis: Literal["event_start_time"]

    total_source_event_count: NonNegativeInt
    total_window_count: NonNegativeInt
    total_lineage_row_count: NonNegativeInt
    rejected_event_count: Literal[0]
    window_stream_sha256: Sha256Digest

    partition_reports: Annotated[
        tuple[FeatureWindowPartitionReportV2, ...],
        Field(min_length=1, max_length=1),
    ]

    started_at: UtcDateTime
    completed_at: UtcDateTime

    @model_validator(mode="after")
    def validate_run(self) -> "MondayBenignFeatureWindowRunReport":
        """Bind totals, partition identity, namespace and run derivation."""
        if self.completed_at < self.started_at:
            raise ValueError("MB6 completed_at precedes started_at")
        if self.window_id_namespace != MB6_WINDOW_ID_NAMESPACE:
            raise ValueError(
                f"MB6 report namespace must be {MB6_WINDOW_ID_NAMESPACE}"
            )
        if self.dataset_name != MB_DATASET_NAME:
            raise ValueError(f"MB track dataset_name must be {MB_DATASET_NAME}")
        if self.run_id != derive_mb6_run_id(self.protocol_sha256, self.mb4_run_id):
            raise ValueError(
                "MB6 run_id is not the deterministic derivation of its protocol "
                "and MB4 run identity"
            )

        partition = self.partition_reports[0]
        if partition.output_partition != MONDAY_OUTPUT_PARTITION:
            raise ValueError(f"MB6 partition must be {MONDAY_OUTPUT_PARTITION}")
        if self.total_source_event_count != partition.source_event_count:
            raise ValueError("MB6 total source event count mismatch")
        if self.total_window_count != partition.window_count:
            raise ValueError("MB6 total window count mismatch")
        if self.window_stream_sha256 != partition.window_stream_sha256:
            raise ValueError(
                "MB6 global window-stream digest must equal the single partition"
            )
        if self.total_lineage_row_count != self.total_source_event_count:
            raise ValueError(
                "MB6 lineage must hold exactly one row per source event"
            )
        return self

    def identity_payload(self) -> dict[str, object]:
        """Return the deterministic payload used for the report identity.

        ``started_at`` and ``completed_at`` are excluded, under the identity rule
        ratified for MB2: wall-clock execution metadata must not enter a digest
        that downstream milestones may bind to. ``run_id`` is *included* because
        it is itself deterministic.
        """
        payload = self.model_dump(mode="json")
        payload.pop("started_at", None)
        payload.pop("completed_at", None)
        return payload

    def content_sha256(self) -> str:
        """Return the deterministic, timestamp-independent report identity."""
        return _canonical_digest(self.identity_payload())
