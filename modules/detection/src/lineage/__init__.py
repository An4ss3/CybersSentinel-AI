"""Lineage contracts for reproducible IDS observations and derived features.

Lineage is kept separate from labels and model features so identifiers required
for audit and grouped evaluation cannot accidentally become predictive inputs.
"""
from .provenance import EventProvenance
from .replay import (
    BoundZeekReplaySpecification,
    bind_zeek_replay_specification,
    load_zeek_replay_specification,
)
from .zeek_normalization import (
    BoundZeekNormalizationSpecification,
    bind_zeek_normalization_specification,
    load_and_bind_zeek_normalization_specification,
    load_zeek_normalization_specification,
)
from .zeek_normalization_v2 import (
    BoundZeekNormalizationSpecificationV2,
    load_and_bind_zeek_normalization_specification_v2,
    load_zeek_normalization_specification_v2,
)
from .dataset_freeze import (
    DatasetFreezeVerificationError,
    DatasetIntegrityIssue,
    VerifiedDatasetFreeze,
    build_dataset_freeze_manifest,
    build_dataset_verification_report,
    inventory_pcap_evidence,
    load_dataset_freeze_manifest,
    verify_dataset_freeze,
    write_immutable_dataset_manifest,
    write_immutable_verification_report,
)
from .label_reports import (
    LabelAmbiguityReport,
    LabelCoverageReport,
    ManifestAmbiguityReport,
    ManifestCoverageReport,
    build_label_reports,
    build_manifest_audit,
    write_reports,
)
from .labeling import (
    LabelLedger,
    LabelManifestOverlapError,
    find_manifest_overlaps,
    hash_manifest,
    hash_rule,
    load_label_manifest,
)

__all__ = [
    "BoundZeekReplaySpecification",
    "BoundZeekNormalizationSpecification",
    "BoundZeekNormalizationSpecificationV2",
    "DatasetFreezeVerificationError",
    "DatasetIntegrityIssue",
    "EventProvenance",
    "LabelAmbiguityReport",
    "LabelCoverageReport",
    "LabelLedger",
    "LabelManifestOverlapError",
    "ManifestAmbiguityReport",
    "ManifestCoverageReport",
    "VerifiedDatasetFreeze",
    "bind_zeek_replay_specification",
    "bind_zeek_normalization_specification",
    "build_dataset_freeze_manifest",
    "build_dataset_verification_report",
    "build_label_reports",
    "build_manifest_audit",
    "find_manifest_overlaps",
    "hash_manifest",
    "hash_rule",
    "inventory_pcap_evidence",
    "load_dataset_freeze_manifest",
    "load_label_manifest",
    "load_zeek_replay_specification",
    "load_zeek_normalization_specification",
    "load_zeek_normalization_specification_v2",
    "load_and_bind_zeek_normalization_specification",
    "load_and_bind_zeek_normalization_specification_v2",
    "verify_dataset_freeze",
    "write_immutable_dataset_manifest",
    "write_immutable_verification_report",
    "write_reports",
]
