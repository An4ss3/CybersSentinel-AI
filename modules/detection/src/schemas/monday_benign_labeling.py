"""Strict additive MB-LABEL (MB7) contracts for the Monday Benign track.

Scope and non-scope
-------------------
MB7 records **only** what the frozen M5 v1 policy says about MB4 events and MB6
windows. It is a pure sidecar: no field is added to ``mb4_canonical`` or
``mb6_canonical``, no event is modified, no ``event_id`` is regenerated, and no
dataset decision is taken. In particular MB7 **never** converts ``unknown`` into
``benign_reference``.

Ratified policy (2026-08-13)
----------------------------
* **M5 v1 applied unchanged.** The ``monday-benign-reference`` rule uses
  ``any_network``, so the M5 v2 attacker realignment has no effect here and is
  deliberately not injected.
* **Two granularities.** Event labels for all 368,202 MB4 events, and window
  labels for all 70,921 MB6 windows aggregated by the frozen ``ANY_ATTACK``
  precedence ``target_attack > known_other_attack > ambiguous > unknown >
  benign_reference``.
* **Expected outcome, verified to the record**: 70,697 windows
  ``benign_reference``, 224 ``unknown``, 0 attack. The 224 are windows that fall
  outside the compiled interval ``[1499083200, 1499112060)`` -- 198 starting
  before it and 26 at or after its end. They must remain ``unknown``.
* **Deterministic identity.** ``run_id`` is ``uuid5`` over the MB7 protocol hash
  and the MB6 run identity. No ``uuid4`` and no clock reading enters any identity
  or reproducible digest; ``started_at`` / ``completed_at`` are excluded from
  ``content_sha256``.
* **R11 is not addressed here.** Attack-class entity disjunction and an effective
  attack sample size of about nine entities are dataset-level problems. Labeling
  does not and cannot correct them.
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
from modules.detection.src.schemas.labels import (
    AuthoritativeSource,
    LabelAssignmentProvenance,
)
from modules.detection.src.schemas.monday_benign_feature_window import (
    MB6_WINDOW_ID_NAMESPACE,
)
from modules.detection.src.schemas.monday_benign_normalization import (
    M3_V2_EVENT_ID_NAMESPACE,
    MB3_EVENT_ID_NAMESPACE,
    MB_DATASET_NAME,
)
from modules.detection.src.schemas.monday_benign_replay import MONDAY_OUTPUT_PARTITION


MB7_PROTOCOL_RELATIVE_PATH: Final[str] = (
    "datasets/manifests/monday_benign_labeling.yaml"
)
MB7_REPORT_RELATIVE_PATH: Final[str] = (
    "artifacts/reports/mb7_monday_benign_labeling_run.json"
)
MB7_SCHEMA: Final[str] = "mb7_canonical"

MB7_NAMESPACE_DERIVATION_NAME: Final[str] = (
    "https://cybersentinel.invalid/mb7/monday-benign/labeling/1.0.0"
)
MB7_LABEL_NAMESPACE: Final[UUID] = uuid5(
    NAMESPACE_URL, MB7_NAMESPACE_DERIVATION_NAME
)
M6_WINDOW_ID_NAMESPACE: Final[UUID] = UUID("f787c08a-290e-5b79-a8cb-5bc19ae633dc")
_FORBIDDEN_NAMESPACES: Final[tuple[UUID, ...]] = (
    M3_V2_EVENT_ID_NAMESPACE,
    M6_WINDOW_ID_NAMESPACE,
    MB3_EVENT_ID_NAMESPACE,
    MB6_WINDOW_ID_NAMESPACE,
)

#: Compiled UTC bounds of the frozen ``monday-benign-reference`` rule, in whole
#: seconds. Recorded so the report can state, rather than imply, which interval
#: produced the split between ``benign_reference`` and ``unknown``.
MONDAY_RULE_START_EPOCH: Final[int] = 1_499_083_200
MONDAY_RULE_END_EPOCH: Final[int] = 1_499_112_060

_RUN_ID_DERIVATION_PREFIX: Final[str] = "mb7-run"
_DISPOSITIONS: Final[tuple[str, ...]] = (
    "ambiguous",
    "benign_reference",
    "known_other_attack",
    "target_attack",
    "unknown",
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


def derive_mb7_run_id(protocol_sha256: str, mb6_run_id: UUID | str) -> UUID:
    """Derive the deterministic MB7 run identity from protocol and MB6 run."""
    name = f"{_RUN_ID_DERIVATION_PREFIX}|{protocol_sha256}|{mb6_run_id}"
    return uuid5(MB7_LABEL_NAMESPACE, name)


class MondayBenignLabelPolicyBinding(StrictModel):
    """Exact frozen M5 policy this labeling run applied."""

    policy_version: Literal["1.0.0"]
    policy_variant: Literal["m5_v1_unchanged"]
    manifest_relative_path: NonEmptyText
    manifest_hash: Sha256Digest
    rule_version: VersionString
    authoritative_source: AuthoritativeSource
    timezone: StrictIdentifier
    applicable_rule_id: Literal["monday-benign-reference"]
    applicable_rule_hash: Sha256Digest
    applicable_rule_mode: Literal["any_network"]
    applicable_rule_disposition: Literal["benign_reference"]
    compiled_interval_start_epoch_seconds: Literal[1_499_083_200]
    compiled_interval_end_epoch_seconds: Literal[1_499_112_060]
    m5_v2_injected: Literal[False]
    unknown_to_benign_conversion: Literal["forbidden"]
    ambiguous_to_benign_conversion: Literal["forbidden"]
    ambiguous_to_unknown_conversion: Literal["forbidden"]
    m5_v1_is_normative_source: Literal[True]
    m5_v1_modified: Literal[False]
    ambiguous_is_valid_disposition: Literal[True]
    boundary_crossing_semantics: Literal[
        "label_ledger_partial_overlap_yields_ambiguous"
    ]
    ml_dataset_constructed: Literal[False]


class MondayBenignLabelAggregationPolicy(StrictModel):
    """The frozen ANY_ATTACK window aggregation, recorded verbatim."""

    rule: Literal["any_attack"]
    precedence: tuple[StrictIdentifier, ...]
    attack_dispositions: tuple[StrictIdentifier, ...]
    uncertainty_to_benign: Literal["forbidden"]

    @model_validator(mode="after")
    def validate_precedence(self) -> "MondayBenignLabelAggregationPolicy":
        expected = (
            "target_attack",
            "known_other_attack",
            "ambiguous",
            "unknown",
            "benign_reference",
        )
        if self.precedence != expected:
            raise ValueError("MB7 ANY_ATTACK precedence diverges from the freeze")
        if tuple(sorted(self.attack_dispositions)) != (
            "known_other_attack",
            "target_attack",
        ):
            raise ValueError("MB7 attack dispositions diverge from the freeze")
        return self


class MondayBenignLabelingSpecification(StrictModel):
    """Frozen MB7 protocol bound to MB1/MB2/MB3/MB4/MB6 and to M5 v1."""

    protocol_version: Literal["1.0.0"]
    milestone: Literal["mb7"]
    track: Literal["monday_benign"]
    frozen_at: UtcDateTime
    dataset_name: StrictIdentifier
    output_partition: StrictIdentifier

    mb1_manifest_sha256: Sha256Digest
    mb2_specification_sha256: Sha256Digest
    mb3_protocol_sha256: Sha256Digest
    mb3_report_content_sha256: Sha256Digest
    mb4_report_content_sha256: Sha256Digest
    mb4_run_id: UUID
    mb6_protocol_sha256: Sha256Digest
    mb6_report_content_sha256: Sha256Digest
    mb6_run_id: UUID
    mb6_window_stream_sha256: Sha256Digest

    event_source: Literal["mb4_canonical.flow_end_events"]
    window_source: Literal["mb6_canonical.feature_windows"]
    lineage_source: Literal["mb6_canonical.feature_window_sources"]
    label_projection: Literal["postgresql_schema_mb7_canonical"]
    sidecar_only: Literal[True]
    modifies_mb4_or_mb6: Literal[False]
    m_chain_status: Literal["untouched_and_frozen"]

    policy: MondayBenignLabelPolicyBinding
    aggregation: MondayBenignLabelAggregationPolicy

    label_identity_algorithm: Literal["uuid5"]
    label_identity_namespace: UUID
    label_identity_namespace_derivation: NonEmptyText
    event_label_identity_components: tuple[NonEmptyText, ...]
    window_label_identity_components: tuple[NonEmptyText, ...]
    run_identity_algorithm: Literal[
        "deterministic_uuid5_over_protocol_and_mb6_run_id"
    ]
    random_identifiers: Literal["forbidden"]
    wall_clock_in_identity: Literal["forbidden"]

    authoritative_sources: Annotated[tuple[NonEmptyText, ...], Field(min_length=1)]

    @model_validator(mode="after")
    def validate_specification(self) -> "MondayBenignLabelingSpecification":
        """Pin MB coordinates and forbid every foreign namespace."""
        if self.output_partition != MONDAY_OUTPUT_PARTITION:
            raise ValueError(f"MB7 partition must be {MONDAY_OUTPUT_PARTITION}")
        if self.dataset_name != MB_DATASET_NAME:
            raise ValueError(f"MB track dataset_name must be {MB_DATASET_NAME}")
        namespace = self.label_identity_namespace
        if namespace in _FORBIDDEN_NAMESPACES:
            raise ValueError(
                "MB7 must never reuse an M chain or earlier MB namespace"
            )
        if namespace != MB7_LABEL_NAMESPACE:
            raise ValueError(f"MB7 label namespace must be {MB7_LABEL_NAMESPACE}")
        if self.label_identity_namespace_derivation != (
            MB7_NAMESPACE_DERIVATION_NAME
        ):
            raise ValueError("MB7 namespace derivation string mismatch")
        if uuid5(NAMESPACE_URL, self.label_identity_namespace_derivation) != (
            namespace
        ):
            raise ValueError(
                "declared MB7 namespace is not reproducible from its derivation"
            )
        if self.event_label_identity_components != (
            "protocol_sha256",
            "m5_manifest_hash",
            "event_id",
        ):
            raise ValueError("MB7 event label identity components diverge")
        if self.window_label_identity_components != (
            "protocol_sha256",
            "m5_manifest_hash",
            "window_id",
        ):
            raise ValueError("MB7 window label identity components diverge")
        if tuple(sorted(self.authoritative_sources)) != self.authoritative_sources:
            raise ValueError("authoritative sources must be sorted")
        if any(
            not v.startswith("https://") for v in self.authoritative_sources
        ):
            raise ValueError("authoritative sources must use HTTPS")
        return self

    def content_sha256(self) -> str:
        """Return a formatting-independent identity for the MB7 protocol."""
        return _canonical_digest(self.model_dump(mode="json"))


class MondayBenignDispositionCount(StrictModel):
    """One observed disposition count."""

    disposition: StrictIdentifier
    count: NonNegativeInt

    @model_validator(mode="after")
    def validate_disposition(self) -> "MondayBenignDispositionCount":
        if self.disposition not in _DISPOSITIONS:
            raise ValueError(f"unknown disposition {self.disposition!r}")
        return self


class MondayBenignIntervalSplit(StrictModel):
    """Exact partition of MB6 windows against the compiled M5 interval.

    The ratified invariants, verified 2026-08-13 to the record:

    * inside  ``[12:00:00Z, 20:01:00Z)`` : ``benign_reference`` + ``ambiguous``
      = 70,697
    * outside                            : ``unknown`` + ``ambiguous`` = 224,
      itself 198 before the opening and 26 after the close
    * total                              : 70,921

    An earlier form of this model asserted ``unknown == windows outside``. That was
    falsified by measurement: 119 windows inside the interval and 8 outside resolve
    to ``ambiguous`` because frozen M5 maps a boundary-crossing event interval to
    ``partial`` -> ``ambiguous``. The invariant is corrected, never the data.
    """

    windows_inside_interval: NonNegativeInt
    windows_outside_interval: NonNegativeInt
    windows_before_interval: NonNegativeInt
    windows_after_interval: NonNegativeInt
    inside_benign_reference: NonNegativeInt
    inside_ambiguous: NonNegativeInt
    outside_unknown: NonNegativeInt
    outside_ambiguous: NonNegativeInt
    earliest_window_start_time: ExactDecimalSeconds22
    latest_window_start_time: ExactDecimalSeconds22

    @model_validator(mode="after")
    def validate_split(self) -> "MondayBenignIntervalSplit":
        """Require the partition to close exactly, on both axes."""
        if self.windows_before_interval + self.windows_after_interval != (
            self.windows_outside_interval
        ):
            raise ValueError(
                "before + after must equal the windows outside the interval"
            )
        if self.inside_benign_reference + self.inside_ambiguous != (
            self.windows_inside_interval
        ):
            raise ValueError(
                "inside the interval, benign_reference + ambiguous must equal the "
                "window count; no other disposition is reachable there"
            )
        if self.outside_unknown + self.outside_ambiguous != (
            self.windows_outside_interval
        ):
            raise ValueError(
                "outside the interval, unknown + ambiguous must equal the window "
                "count; benign_reference is never reachable there"
            )
        return self

    @property
    def total_windows(self) -> int:
        """Return the total number of partitioned windows."""
        return self.windows_inside_interval + self.windows_outside_interval

    @property
    def total_outside(self) -> int:
        """Return the number of windows outside the compiled interval."""
        return self.windows_outside_interval


class MondayBenignLabelingRunReport(StrictModel):
    """Deterministic evidence for one MB7 labeling run."""

    report_version: Literal["1.0.0"]
    verification_status: Literal["verified"]
    track: Literal["monday_benign"]
    run_id: UUID
    run_id_derivation: Literal[
        "deterministic_uuid5_over_protocol_and_mb6_run_id"
    ]

    protocol_sha256: Sha256Digest
    mb3_report_content_sha256: Sha256Digest
    mb4_report_content_sha256: Sha256Digest
    mb4_run_id: UUID
    mb6_report_content_sha256: Sha256Digest
    mb6_run_id: UUID
    mb6_window_stream_sha256: Sha256Digest
    label_identity_namespace: UUID

    target_database: StrictIdentifier
    target_schema: Literal["mb7_canonical"]
    output_partition: StrictIdentifier
    dataset_name: StrictIdentifier

    policy: MondayBenignLabelPolicyBinding
    label_provenance: LabelAssignmentProvenance

    total_event_label_count: NonNegativeInt
    total_window_label_count: NonNegativeInt
    event_disposition_counts: Annotated[
        tuple[MondayBenignDispositionCount, ...], Field(min_length=1)
    ]
    window_disposition_counts: Annotated[
        tuple[MondayBenignDispositionCount, ...], Field(min_length=1)
    ]
    unknown_window_interval_split: MondayBenignIntervalSplit

    event_label_stream_sha256: Sha256Digest
    window_label_stream_sha256: Sha256Digest

    started_at: UtcDateTime
    completed_at: UtcDateTime

    @model_validator(mode="after")
    def validate_run(self) -> "MondayBenignLabelingRunReport":
        """Enforce MB coordinates, identity derivation and label coherence."""
        if self.completed_at < self.started_at:
            raise ValueError("MB7 completed_at precedes started_at")
        if self.label_identity_namespace != MB7_LABEL_NAMESPACE:
            raise ValueError(f"MB7 namespace must be {MB7_LABEL_NAMESPACE}")
        if self.output_partition != MONDAY_OUTPUT_PARTITION:
            raise ValueError(f"MB7 partition must be {MONDAY_OUTPUT_PARTITION}")
        if self.dataset_name != MB_DATASET_NAME:
            raise ValueError(f"MB track dataset_name must be {MB_DATASET_NAME}")
        if self.run_id != derive_mb7_run_id(self.protocol_sha256, self.mb6_run_id):
            raise ValueError(
                "MB7 run_id is not the deterministic derivation of its protocol "
                "and MB6 run identity"
            )

        for label, counts, total in (
            ("event", self.event_disposition_counts, self.total_event_label_count),
            ("window", self.window_disposition_counts, self.total_window_label_count),
        ):
            names = tuple(item.disposition for item in counts)
            if tuple(sorted(names)) != names or len(set(names)) != len(names):
                raise ValueError(f"MB7 {label} counts must be unique and sorted")
            if sum(item.count for item in counts) != total:
                raise ValueError(f"MB7 {label} counts do not cover the total")

        window_by_disposition = {
            item.disposition: item.count for item in self.window_disposition_counts
        }
        attacks = window_by_disposition.get("target_attack", 0) + (
            window_by_disposition.get("known_other_attack", 0)
        )
        if attacks:
            raise ValueError(
                "MB7 must observe zero attack windows on the Monday benign day; "
                f"found {attacks}"
            )
        split = self.unknown_window_interval_split
        if split.total_windows != self.total_window_label_count:
            raise ValueError(
                "MB7 interval partition must cover every window label"
            )
        if window_by_disposition.get("benign_reference", 0) != (
            split.inside_benign_reference
        ):
            raise ValueError(
                "MB7 benign_reference windows must all lie inside the interval"
            )
        if window_by_disposition.get("unknown", 0) != split.outside_unknown:
            raise ValueError(
                "MB7 unknown windows must all lie outside the interval; unknown "
                "is never reclassified"
            )
        if window_by_disposition.get("ambiguous", 0) != (
            split.inside_ambiguous + split.outside_ambiguous
        ):
            raise ValueError(
                "MB7 ambiguous windows must be accounted for on both sides of the "
                "interval; ambiguous is never requalified"
            )

        event_by_disposition = {
            item.disposition: item.count for item in self.event_disposition_counts
        }
        event_attacks = event_by_disposition.get("target_attack", 0) + (
            event_by_disposition.get("known_other_attack", 0)
        )
        if event_attacks:
            raise ValueError(
                "MB7 must observe zero attack events on the Monday benign day"
            )
        # A window is benign only if every one of its events is benign, so the
        # benign window count can never exceed the benign event count.
        if window_by_disposition.get("benign_reference", 0) > (
            event_by_disposition.get("benign_reference", 0)
        ):
            raise ValueError(
                "MB7 benign window count exceeds the benign event count"
            )
        return self

    def identity_payload(self) -> dict[str, object]:
        """Return the deterministic payload used for the report identity."""
        payload = self.model_dump(mode="json")
        payload.pop("started_at", None)
        payload.pop("completed_at", None)
        return payload

    def content_sha256(self) -> str:
        """Return the deterministic, timestamp-independent report identity."""
        return _canonical_digest(self.identity_payload())
