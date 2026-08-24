"""Loading and immutable lineage binding for the M6 feature-window protocol.

Binds the frozen M6 manifest to the frozen M3 v2 protocol/report and the
published M4 materialization report. Reads upstream artefacts only; never
modifies M1, M2, M3 v2, M4, or M5.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from hashlib import sha256
import json
from pathlib import Path

import yaml

from modules.detection.src.persistence.report_verification_v2 import (
    verify_frozen_m3_v2_report,
)
from modules.detection.src.persistence.run_report_v2 import (
    M4MaterializationReportV2,
)
from modules.detection.src.schemas.feature_window_protocol_v2 import (
    FeatureWindowSpecificationV2,
)


CANONICAL_M6_MANIFEST_RELATIVE_PATH: str = (
    "datasets/manifests/cicids2017_feature_window_v2.yaml"
)
CANONICAL_M4_REPORT_RELATIVE_PATH: str = (
    "artifacts/reports/m4_v2_materialization_run.json"
)


class FeatureWindowBindingError(RuntimeError):
    """The M6 manifest does not bind to the frozen upstream evidence."""


@dataclass(frozen=True, slots=True)
class BoundFeatureWindowSpecificationV2:
    """An M6 protocol proven consistent with every upstream identity."""

    specification: FeatureWindowSpecificationV2
    specification_sha256: str
    m3_report_content_sha256: str
    m4_report_content_sha256: str
    m4_report: M4MaterializationReportV2
    partition_order: tuple[str, ...]
    sensor_version: str


def _json_default(value: object) -> str:
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    raise TypeError(f"unsupported YAML value type: {type(value).__name__}")


def load_feature_window_specification_v2(
    path: str | Path,
) -> FeatureWindowSpecificationV2:
    """Load the M6 manifest through strict JSON-mode validation."""
    source = Path(path)
    raw = yaml.safe_load(source.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("M6 feature-window manifest root must be a mapping")
    return FeatureWindowSpecificationV2.model_validate_json(
        json.dumps(raw, default=_json_default)
    )


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise FeatureWindowBindingError(message)


def load_and_bind_feature_window_specification_v2(
    repository_root: str | Path,
    manifest_path: str | Path = CANONICAL_M6_MANIFEST_RELATIVE_PATH,
) -> BoundFeatureWindowSpecificationV2:
    """Load the M6 manifest and verify every upstream identity it declares."""
    root = Path(repository_root).resolve(strict=True)
    specification = load_feature_window_specification_v2(root / manifest_path)

    # Frozen M3 v2 evidence: reuse the existing seven-point gate unchanged.
    verified_m3 = verify_frozen_m3_v2_report(root)
    _require(
        specification.m3_protocol_sha256 == verified_m3.protocol_sha256,
        "M6 manifest M3 protocol identity mismatch",
    )
    _require(
        specification.m3_report_content_sha256 == verified_m3.report_content_sha256,
        "M6 manifest M3 report content identity mismatch",
    )
    _require(
        specification.m3_report_file_sha256 == verified_m3.report_file_sha256,
        "M6 manifest M3 report file identity mismatch",
    )
    _require(
        specification.m3_event_stream_sha256
        == verified_m3.canonical_event_stream_sha256,
        "M6 manifest M3 event stream identity mismatch",
    )
    _require(
        specification.m3_rejection_audit_stream_sha256
        == verified_m3.rejection_audit_stream_sha256,
        "M6 manifest M3 rejection audit identity mismatch",
    )
    _require(
        specification.m1_manifest_sha256 == verified_m3.report.m1_manifest_sha256,
        "M6 manifest M1 identity mismatch",
    )
    _require(
        specification.m2_specification_sha256
        == verified_m3.report.m2_specification_sha256,
        "M6 manifest M2 identity mismatch",
    )
    _require(
        specification.dataset_name == verified_m3.report.dataset_name,
        "M6 manifest dataset identity mismatch",
    )

    # Published M4 materialization report.
    m4_path = (root / CANONICAL_M4_REPORT_RELATIVE_PATH).resolve()
    _require(m4_path.is_file(), f"published M4 report is missing: {m4_path}")
    m4_payload = m4_path.read_bytes()
    observed_m4_file = sha256(m4_payload).hexdigest()
    _require(
        observed_m4_file == specification.m4_report_file_sha256,
        "M6 manifest M4 report file identity mismatch",
    )
    m4_report = M4MaterializationReportV2.model_validate_json(m4_payload)
    _require(
        m4_report.content_sha256() == specification.m4_report_content_sha256,
        "M6 manifest M4 report content identity mismatch",
    )
    _require(
        m4_report.verification_status == "verified",
        "M6 requires a verified M4 materialization",
    )
    _require(
        m4_report.m3_report_content_sha256 == verified_m3.report_content_sha256,
        "M4 report is not bound to the frozen M3 v2 report",
    )

    # Source event contract version declared by M6 must match the frozen M3 v2
    # report, which is the authoritative carrier of the event feature version.
    _require(
        specification.source_event_feature_version
        == verified_m3.report.feature_version,
        "M6 source event feature version mismatch",
    )

    partition_order = tuple(
        item.output_partition for item in m4_report.partition_counts
    )
    _require(len(partition_order) == 3, "M6 requires exactly three partitions")

    return BoundFeatureWindowSpecificationV2(
        specification=specification,
        specification_sha256=specification.content_sha256(),
        m3_report_content_sha256=verified_m3.report_content_sha256,
        m4_report_content_sha256=m4_report.content_sha256(),
        m4_report=m4_report,
        partition_order=partition_order,
        sensor_version=verified_m3.report.sensor_version,
    )
