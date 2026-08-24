"""Loading and MB-track lineage binding for the frozen MB6 protocol.

Verifies MB6 provenance only: it builds no window, opens no database, and touches
no M chain artifact. The binding proves the MB6 protocol is tied to the exact
MB1 freeze, MB2 specification and replay report, MB3 protocol and report, and MB4
materialization report -- each checked against bytes on disk rather than against
a declared constant.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from hashlib import sha256
import json
from pathlib import Path

import yaml

from modules.detection.src.lineage.monday_benign_normalization import (
    load_and_bind_monday_benign_normalization_specification,
)
from modules.detection.src.persistence.monday_benign_persistence import (
    MB4_REPORT_RELATIVE_PATH,
    MondayBenignMaterializationReport,
)
from modules.detection.src.schemas.monday_benign_feature_window import (
    MB6_PROTOCOL_RELATIVE_PATH,
    MondayBenignFeatureWindowSpecification,
    derive_mb6_run_id,
)
from modules.detection.src.schemas.monday_benign_replay import (
    MONDAY_OUTPUT_PARTITION,
)


@dataclass(frozen=True, slots=True)
class BoundMondayBenignFeatureWindowSpecification:
    """Validated MB6 identity chained through MB1, MB2, MB3 and MB4."""

    specification: MondayBenignFeatureWindowSpecification
    protocol_sha256: str
    mb1_manifest_sha256: str
    mb2_specification_sha256: str
    mb3_protocol_sha256: str
    mb3_report_content_sha256: str
    mb4_report_content_sha256: str
    mb4_run_id: str
    run_id: str
    output_partition: str
    expected_source_event_count: int


def _json_default(value: object) -> str:
    """Serialize only YAML date types needed by strict JSON-mode validation."""
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    raise TypeError(f"unsupported YAML value type: {type(value).__name__}")


def load_monday_benign_feature_window_specification(
    path: str | Path,
) -> MondayBenignFeatureWindowSpecification:
    """Load YAML through strict JSON-mode Pydantic validation."""
    source = Path(path)
    raw = yaml.safe_load(source.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("MB6 protocol root must be a mapping")
    normalized = json.dumps(raw, default=_json_default)
    return MondayBenignFeatureWindowSpecification.model_validate_json(normalized)


def bind_monday_benign_feature_window_specification(
    repository_root: str | Path,
    specification: MondayBenignFeatureWindowSpecification,
) -> BoundMondayBenignFeatureWindowSpecification:
    """Verify the whole MB1 -> MB2 -> MB3 -> MB4 -> MB6 identity chain."""
    root = Path(repository_root).resolve(strict=True)

    mb3 = load_and_bind_monday_benign_normalization_specification(root)
    if specification.mb1_manifest_sha256 != mb3.m1_manifest_sha256:
        raise ValueError("MB6 MB1 manifest hash does not match")
    if specification.mb2_specification_sha256 != mb3.mb2_specification_sha256:
        raise ValueError("MB6 MB2 specification hash does not match")
    if specification.mb2_replay_report_content_sha256 != (
        mb3.mb2_replay_report_content_sha256
    ):
        raise ValueError("MB6 MB2 replay report hash does not match")
    if specification.mb3_protocol_sha256 != mb3.specification_sha256:
        raise ValueError("MB6 MB3 protocol hash does not match")

    mb4_path = root / MB4_REPORT_RELATIVE_PATH
    mb4_bytes = mb4_path.read_bytes()
    if specification.mb4_report_file_sha256 != sha256(mb4_bytes).hexdigest():
        raise ValueError("MB6 MB4 report file hash does not match")
    mb4 = MondayBenignMaterializationReport.model_validate_json(
        mb4_bytes.decode("utf-8")
    )
    if specification.mb4_report_content_sha256 != mb4.content_sha256():
        raise ValueError("MB6 MB4 report content hash does not match")
    if mb4.verification_status != "verified":
        raise ValueError("MB4 report is not verified")
    if mb4.output_partition != MONDAY_OUTPUT_PARTITION:
        raise ValueError("MB4 report is not the Monday partition")
    if specification.mb4_run_id != mb4.run_id:
        raise ValueError("MB6 MB4 run identity does not match the MB4 report")
    if specification.mb3_report_content_sha256 != mb4.mb3_report_content_sha256:
        raise ValueError(
            "MB6 and MB4 disagree on the MB3 report they descend from"
        )
    if mb4.materialized_event_stream_sha256 != specification.mb3_event_stream_sha256:
        raise ValueError(
            "MB4 did not reproduce the MB3 event stream declared by MB6"
        )
    if specification.output_partition != mb4.output_partition:
        raise ValueError("MB6 partition does not match MB4")

    protocol_sha256 = specification.content_sha256()
    return BoundMondayBenignFeatureWindowSpecification(
        specification=specification,
        protocol_sha256=protocol_sha256,
        mb1_manifest_sha256=specification.mb1_manifest_sha256,
        mb2_specification_sha256=specification.mb2_specification_sha256,
        mb3_protocol_sha256=specification.mb3_protocol_sha256,
        mb3_report_content_sha256=specification.mb3_report_content_sha256,
        mb4_report_content_sha256=specification.mb4_report_content_sha256,
        mb4_run_id=str(specification.mb4_run_id),
        run_id=str(
            derive_mb6_run_id(protocol_sha256, specification.mb4_run_id)
        ),
        output_partition=specification.output_partition,
        expected_source_event_count=mb4.persisted_event_count,
    )


def load_and_bind_monday_benign_feature_window_specification(
    repository_root: str | Path,
    specification_path: str | Path = MB6_PROTOCOL_RELATIVE_PATH,
) -> BoundMondayBenignFeatureWindowSpecification:
    """Load the MB6 protocol from the repository and bind it to MB evidence."""
    root = Path(repository_root).resolve(strict=True)
    specification = load_monday_benign_feature_window_specification(
        root / specification_path
    )
    return bind_monday_benign_feature_window_specification(root, specification)
