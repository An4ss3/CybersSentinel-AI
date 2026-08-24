"""Loading and M1 lineage binding for frozen Zeek replay specifications.

This module validates replay provenance only. It does not invoke Zeek, create
output directories, or inspect sensor logs.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
import json
from pathlib import Path

import yaml

from modules.detection.src.schemas import DatasetFreezeManifest
from modules.detection.src.schemas.replay import ZeekReplaySpecification


@dataclass(frozen=True, slots=True)
class BoundZeekReplaySpecification:
    """Validated identity connecting one replay protocol to one M1 freeze."""

    specification: ZeekReplaySpecification
    specification_sha256: str
    m1_manifest_sha256: str
    input_file_count: int
    input_total_size_bytes: int


def _json_default(value: object) -> str:
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    raise TypeError(f"unsupported YAML value type: {type(value).__name__}")


def load_zeek_replay_specification(
    path: str | Path,
) -> ZeekReplaySpecification:
    """Load YAML through strict JSON-mode Pydantic validation."""
    source = Path(path)
    raw = yaml.safe_load(source.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("Zeek replay specification root must be a mapping")
    normalized = json.dumps(raw, default=_json_default)
    return ZeekReplaySpecification.model_validate_json(normalized)


def bind_zeek_replay_specification(
    specification: ZeekReplaySpecification,
    m1_manifest: DatasetFreezeManifest,
) -> BoundZeekReplaySpecification:
    """Require exact dataset identity and selected-file equality with M1."""
    manifest_sha256 = m1_manifest.content_sha256()
    if specification.m1_manifest_sha256 != manifest_sha256:
        raise ValueError("replay specification M1 manifest hash does not match")
    if specification.dataset_name != m1_manifest.dataset_name:
        raise ValueError("replay specification dataset_name does not match M1")
    if specification.inputs != m1_manifest.files:
        raise ValueError("replay inputs do not exactly match M1 selected files")

    return BoundZeekReplaySpecification(
        specification=specification,
        specification_sha256=specification.content_sha256(),
        m1_manifest_sha256=manifest_sha256,
        input_file_count=len(specification.inputs),
        input_total_size_bytes=sum(
            item.size_bytes for item in specification.inputs
        ),
    )
