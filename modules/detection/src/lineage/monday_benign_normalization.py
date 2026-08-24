"""Loading and MB-track lineage binding for the frozen MB3 protocol.

Verifies MB3 provenance only: it parses no Zeek record, creates no event, and
touches no M chain artifact. The binding proves that the MB3 protocol is tied to
the exact MB1 freeze, the exact MB2 specification, and the exact MB2 replay
report that produced the Monday ``conn.log``.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from hashlib import sha256
import json
from pathlib import Path

import yaml

from modules.detection.src.lineage.dataset_freeze import load_dataset_freeze_manifest
from modules.detection.src.lineage.monday_benign_replay import (
    load_monday_benign_replay_specification,
)
from modules.detection.src.schemas.monday_benign_normalization import (
    MB3_PROTOCOL_RELATIVE_PATH,
    MondayBenignNormalizationSpecification,
)
from modules.detection.src.schemas.monday_benign_replay import (
    MB1_MANIFEST_RELATIVE_PATH,
    MB2_SPECIFICATION_RELATIVE_PATH,
    MONDAY_OUTPUT_PARTITION,
    MondayBenignReplayRunReport,
)


@dataclass(frozen=True, slots=True)
class BoundMondayBenignNormalizationSpecification:
    """Validated MB3 identity chained to MB1, the MB2 spec, and the MB2 replay."""

    specification: MondayBenignNormalizationSpecification
    specification_sha256: str
    m1_manifest_sha256: str
    mb2_specification_sha256: str
    mb2_replay_report_content_sha256: str
    output_partition: str
    reported_record_count: int


def _json_default(value: object) -> str:
    """Serialize only YAML date types needed by strict JSON-mode validation."""
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    raise TypeError(f"unsupported YAML value type: {type(value).__name__}")


def load_monday_benign_normalization_specification(
    path: str | Path,
) -> MondayBenignNormalizationSpecification:
    """Load YAML through strict JSON-mode Pydantic validation."""
    source = Path(path)
    raw = yaml.safe_load(source.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("MB3 normalization protocol root must be a mapping")
    normalized = json.dumps(raw, default=_json_default)
    return MondayBenignNormalizationSpecification.model_validate_json(normalized)


def bind_monday_benign_normalization_specification(
    repository_root: str | Path,
    specification: MondayBenignNormalizationSpecification,
) -> BoundMondayBenignNormalizationSpecification:
    """Verify the whole MB1 -> MB2 -> MB3 identity chain from published bytes.

    Nine checks, each against a file on disk rather than a declared constant:
    the MB1 manifest hash, the MB2 specification hash, the MB2 replay report file
    and content hashes, the Monday partition name, the conn.log name, size,
    SHA-256 and record count.
    """
    root = Path(repository_root).resolve(strict=True)

    manifest = load_dataset_freeze_manifest(root / MB1_MANIFEST_RELATIVE_PATH)
    manifest_sha256 = manifest.content_sha256()
    if specification.m1_manifest_sha256 != manifest_sha256:
        raise ValueError("MB3 specification MB1 manifest hash does not match")

    mb2_specification = load_monday_benign_replay_specification(
        root / MB2_SPECIFICATION_RELATIVE_PATH
    )
    mb2_specification_sha256 = mb2_specification.content_sha256()
    if specification.mb2_specification_sha256 != mb2_specification_sha256:
        raise ValueError("MB3 specification MB2 specification hash does not match")
    if mb2_specification.m1_manifest_sha256 != manifest_sha256:
        raise ValueError("MB2 specification is not bound to the same MB1 freeze")

    binding = specification.replay_reports[0]
    report_path = root / binding.report_relative_path
    report_bytes = report_path.read_bytes()
    if sha256(report_bytes).hexdigest() != binding.report_file_sha256:
        raise ValueError("MB2 replay report file hash does not match the binding")
    report = MondayBenignReplayRunReport.model_validate_json(
        report_bytes.decode("utf-8")
    )
    if report.content_sha256() != binding.report_content_sha256:
        raise ValueError("MB2 replay report content hash does not match the binding")
    if report.output_partition != MONDAY_OUTPUT_PARTITION:
        raise ValueError("MB2 replay report is not the Monday partition")
    if report.specification_sha256 != mb2_specification_sha256:
        raise ValueError("MB2 replay report was produced by another specification")
    if report.input != binding.input:
        raise ValueError("MB3 binding input does not match the MB2 replay input")

    conn_logs = tuple(item for item in report.logs if item.log_name == "conn.log")
    if len(conn_logs) != 1:
        raise ValueError("MB2 replay report must declare exactly one conn.log")
    conn_log = conn_logs[0]
    if binding.supported_log != conn_log:
        raise ValueError(
            "MB3 supported conn.log artifact diverges from the MB2 replay report"
        )

    return BoundMondayBenignNormalizationSpecification(
        specification=specification,
        specification_sha256=specification.content_sha256(),
        m1_manifest_sha256=manifest_sha256,
        mb2_specification_sha256=mb2_specification_sha256,
        mb2_replay_report_content_sha256=binding.report_content_sha256,
        output_partition=binding.output_partition,
        reported_record_count=conn_log.record_count,
    )


def load_and_bind_monday_benign_normalization_specification(
    repository_root: str | Path,
    specification_path: str | Path = MB3_PROTOCOL_RELATIVE_PATH,
) -> BoundMondayBenignNormalizationSpecification:
    """Load the MB3 protocol from the repository and bind it to MB evidence."""
    root = Path(repository_root).resolve(strict=True)
    specification = load_monday_benign_normalization_specification(
        root / specification_path
    )
    return bind_monday_benign_normalization_specification(root, specification)
