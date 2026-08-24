"""Loading and frozen M2 report binding for the M3 Zeek protocol.

This module may read YAML and the three small replay reports.  It never opens,
iterates, or parses a Zeek sensor log and cannot create canonical events.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from hashlib import sha256
import json
from pathlib import Path

import yaml

from modules.detection.src.schemas.replay import (
    ZeekReplayRunReport,
    ZeekReplaySpecification,
)
from modules.detection.src.schemas.zeek_normalization import (
    ZeekNormalizationSpecification,
)


@dataclass(frozen=True, slots=True)
class BoundZeekNormalizationSpecification:
    """Validated identity joining M3 to all frozen M2 replay reports."""

    specification: ZeekNormalizationSpecification
    specification_sha256: str
    m1_manifest_sha256: str
    m2_specification_sha256: str
    replay_report_count: int
    supported_record_count: int


def _json_default(value: object) -> str:
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    raise TypeError(f"unsupported YAML value type: {type(value).__name__}")


def load_zeek_normalization_specification(
    path: str | Path,
) -> ZeekNormalizationSpecification:
    """Load YAML through strict JSON-mode Pydantic validation."""
    source = Path(path)
    raw = yaml.safe_load(source.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("Zeek normalization specification root must be a mapping")
    normalized = json.dumps(raw, default=_json_default)
    return ZeekNormalizationSpecification.model_validate_json(normalized)


def bind_zeek_normalization_specification(
    specification: ZeekNormalizationSpecification,
    m2_specification: ZeekReplaySpecification,
    replay_reports: tuple[ZeekReplayRunReport, ...],
    replay_report_file_sha256s: tuple[str, ...],
) -> BoundZeekNormalizationSpecification:
    """Require exact M2 identity, report order, and conn.log artifacts."""
    m2_sha256 = m2_specification.content_sha256()
    if specification.m2_specification_sha256 != m2_sha256:
        raise ValueError("normalization specification M2 hash does not match")
    if specification.m1_manifest_sha256 != m2_specification.m1_manifest_sha256:
        raise ValueError("normalization specification M1 hash does not match M2")
    if specification.dataset_name != m2_specification.dataset_name:
        raise ValueError("normalization dataset_name does not match M2")
    if specification.m2_output_root != m2_specification.output.output_root:
        raise ValueError("normalization M2 output root does not match replay")
    if specification.sensor_version != m2_specification.runtime.zeek_version:
        raise ValueError("normalization sensor version does not match replay")
    if len(replay_reports) != len(specification.replay_reports):
        raise ValueError("replay report count does not match normalization bindings")
    if len(replay_report_file_sha256s) != len(specification.replay_reports):
        raise ValueError("replay report file-hash count does not match bindings")

    for index, binding in enumerate(specification.replay_reports):
        report = replay_reports[index]
        file_sha256 = replay_report_file_sha256s[index]
        if file_sha256 != binding.report_file_sha256:
            raise ValueError("replay report file hash does not match binding")
        if report.content_sha256() != binding.report_content_sha256:
            raise ValueError("replay report content hash does not match binding")
        if report.specification_sha256 != m2_sha256:
            raise ValueError("replay report does not reference the bound M2 protocol")
        if report.m1_manifest_sha256 != specification.m1_manifest_sha256:
            raise ValueError("replay report does not reference the bound M1 manifest")
        if report.runtime != m2_specification.runtime:
            raise ValueError("replay report runtime does not match M2")
        if report.output_partition != binding.output_partition:
            raise ValueError("replay report partition does not match binding")
        if report.input != binding.input:
            raise ValueError("replay report input does not match binding")
        if report.input != m2_specification.inputs[index]:
            raise ValueError("replay report order does not match M2 input order")
        matches = tuple(
            artifact
            for artifact in report.logs
            if artifact.log_name == binding.supported_log.log_name
        )
        if matches != (binding.supported_log,):
            raise ValueError("replay report conn.log artifact does not match binding")

    return BoundZeekNormalizationSpecification(
        specification=specification,
        specification_sha256=specification.content_sha256(),
        m1_manifest_sha256=specification.m1_manifest_sha256,
        m2_specification_sha256=m2_sha256,
        replay_report_count=len(replay_reports),
        supported_record_count=sum(
            binding.supported_log.record_count
            for binding in specification.replay_reports
        ),
    )


def load_and_bind_zeek_normalization_specification(
    repository_root: str | Path,
    specification_path: str | Path = (
        "datasets/manifests/cicids2017_zeek_normalization.yaml"
    ),
) -> BoundZeekNormalizationSpecification:
    """Load M3, M2, and report metadata only; never read Zeek log content."""
    root = Path(repository_root).resolve(strict=True)
    specification = load_zeek_normalization_specification(root / specification_path)

    from modules.detection.src.lineage.replay import (
        load_zeek_replay_specification,
    )

    m2_specification = load_zeek_replay_specification(
        root / specification.m2_specification_path
    )
    reports: list[ZeekReplayRunReport] = []
    file_hashes: list[str] = []
    for binding in specification.replay_reports:
        raw = (root / binding.report_relative_path).read_bytes()
        file_hashes.append(sha256(raw).hexdigest())
        reports.append(ZeekReplayRunReport.model_validate_json(raw))

    return bind_zeek_normalization_specification(
        specification,
        m2_specification,
        tuple(reports),
        tuple(file_hashes),
    )
