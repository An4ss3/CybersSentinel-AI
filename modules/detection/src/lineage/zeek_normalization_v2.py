"""Loading and immutable lineage binding for M3 v2 normalization."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from hashlib import sha256
import json
from pathlib import Path

import yaml

from modules.detection.src.lineage.replay import load_zeek_replay_specification
from modules.detection.src.lineage.zeek_normalization import (
    load_zeek_normalization_specification,
)
from modules.detection.src.schemas.replay import ZeekReplayRunReport
from modules.detection.src.schemas.zeek_normalization_v2 import (
    ZeekNormalizationSpecificationV2,
)


@dataclass(frozen=True, slots=True)
class BoundZeekNormalizationSpecificationV2:
    specification: ZeekNormalizationSpecificationV2
    specification_sha256: str
    supersedes_protocol_sha256: str
    m1_manifest_sha256: str
    m2_specification_sha256: str
    replay_report_count: int
    supported_record_count: int


def _json_default(value: object) -> str:
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    raise TypeError(f"unsupported YAML value type: {type(value).__name__}")


def load_zeek_normalization_specification_v2(
    path: str | Path,
) -> ZeekNormalizationSpecificationV2:
    source = Path(path)
    raw = yaml.safe_load(source.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("M3 v2 normalization specification root must be a mapping")
    return ZeekNormalizationSpecificationV2.model_validate_json(
        json.dumps(raw, default=_json_default)
    )


def load_and_bind_zeek_normalization_specification_v2(
    repository_root: str | Path,
    specification_path: str | Path = (
        "datasets/manifests/cicids2017_zeek_normalization_v2.yaml"
    ),
) -> BoundZeekNormalizationSpecificationV2:
    root = Path(repository_root).resolve(strict=True)
    specification = load_zeek_normalization_specification_v2(
        root / specification_path
    )
    v1 = load_zeek_normalization_specification(
        root / specification.supersedes_protocol_path
    )
    if v1.content_sha256() != specification.supersedes_protocol_sha256:
        raise ValueError("M3 v2 superseded protocol identity mismatch")

    m2 = load_zeek_replay_specification(root / specification.m2_specification_path)
    m2_sha256 = m2.content_sha256()
    if m2_sha256 != specification.m2_specification_sha256:
        raise ValueError("M3 v2 M2 specification identity mismatch")
    if m2.m1_manifest_sha256 != specification.m1_manifest_sha256:
        raise ValueError("M3 v2 M1 identity mismatch")
    if m2.dataset_name != specification.dataset_name:
        raise ValueError("M3 v2 dataset identity mismatch")
    if m2.output.output_root != specification.m2_output_root:
        raise ValueError("M3 v2 output root mismatch")
    if m2.runtime.zeek_version != specification.sensor_version:
        raise ValueError("M3 v2 sensor version mismatch")

    for index, binding in enumerate(specification.replay_reports):
        path = root / binding.report_relative_path
        raw = path.read_bytes()
        if sha256(raw).hexdigest() != binding.report_file_sha256:
            raise ValueError("M3 v2 replay report file identity mismatch")
        report = ZeekReplayRunReport.model_validate_json(raw)
        if report.content_sha256() != binding.report_content_sha256:
            raise ValueError("M3 v2 replay report content identity mismatch")
        if report.specification_sha256 != m2_sha256:
            raise ValueError("M3 v2 replay report M2 identity mismatch")
        if report.m1_manifest_sha256 != specification.m1_manifest_sha256:
            raise ValueError("M3 v2 replay report M1 identity mismatch")
        if report.runtime != m2.runtime:
            raise ValueError("M3 v2 replay report runtime mismatch")
        if report.input != binding.input:
            raise ValueError("M3 v2 replay report input binding mismatch")
        if report.input != m2.inputs[index]:
            raise ValueError("M3 v2 report order/input mismatch")
        if report.output_partition != binding.output_partition:
            raise ValueError("M3 v2 report partition mismatch")
        matches = tuple(
            artifact for artifact in report.logs
            if artifact.log_name == "conn.log"
        )
        if matches != (binding.supported_log,):
            raise ValueError("M3 v2 conn.log artifact binding mismatch")

    return BoundZeekNormalizationSpecificationV2(
        specification=specification,
        specification_sha256=specification.content_sha256(),
        supersedes_protocol_sha256=specification.supersedes_protocol_sha256,
        m1_manifest_sha256=specification.m1_manifest_sha256,
        m2_specification_sha256=m2_sha256,
        replay_report_count=len(specification.replay_reports),
        supported_record_count=sum(
            item.supported_log.record_count for item in specification.replay_reports
        ),
    )
