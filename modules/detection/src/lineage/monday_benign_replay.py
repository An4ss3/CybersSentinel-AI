"""Loading and MB1 lineage binding for the frozen MB2 replay specification.

This module validates MB2 provenance only. It does not invoke Zeek, create
output directories, or inspect sensor logs. It never reads, writes, or
re-identifies any M chain artifact.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
import json
from pathlib import Path

import yaml

from modules.detection.src.schemas.datasets import DatasetFreezeManifest
from modules.detection.src.schemas.monday_benign_replay import (
    MONDAY_CAPTURE_DATE,
    MONDAY_PCAP_RELATIVE_PATH,
    MondayBenignReplaySpecification,
)


@dataclass(frozen=True, slots=True)
class BoundMondayBenignReplaySpecification:
    """Validated identity connecting the MB2 protocol to one MB1 freeze."""

    specification: MondayBenignReplaySpecification
    specification_sha256: str
    m1_manifest_sha256: str
    input_file_count: int
    input_total_size_bytes: int


def _json_default(value: object) -> str:
    """Serialize only YAML date types needed by strict JSON-mode validation."""
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    raise TypeError(f"unsupported YAML value type: {type(value).__name__}")


def load_monday_benign_replay_specification(
    path: str | Path,
) -> MondayBenignReplaySpecification:
    """Load YAML through strict JSON-mode Pydantic validation."""
    source = Path(path)
    raw = yaml.safe_load(source.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("MB2 replay specification root must be a mapping")
    normalized = json.dumps(raw, default=_json_default)
    return MondayBenignReplaySpecification.model_validate_json(normalized)


def bind_monday_benign_replay_specification(
    specification: MondayBenignReplaySpecification,
    mb1_manifest: DatasetFreezeManifest,
) -> BoundMondayBenignReplaySpecification:
    """Require exact dataset identity and file equality with the MB1 freeze.

    The manifest must be a Monday-only freeze. A three-partition M1 manifest can
    never satisfy this binding, which keeps MB2 structurally unable to consume
    frozen M chain evidence.
    """
    manifest_sha256 = mb1_manifest.content_sha256()
    if specification.m1_manifest_sha256 != manifest_sha256:
        raise ValueError("MB2 specification MB1 manifest hash does not match")
    if specification.dataset_name != mb1_manifest.dataset_name:
        raise ValueError("MB2 specification dataset_name does not match MB1")
    if specification.inputs != mb1_manifest.files:
        raise ValueError("MB2 inputs do not exactly match MB1 selected files")

    if mb1_manifest.selected_capture_days != (MONDAY_CAPTURE_DATE,):
        raise ValueError(
            "MB1 manifest must select exactly the Monday 2017-07-03 capture day"
        )
    if len(mb1_manifest.files) != 1:
        raise ValueError("MB1 manifest must contain exactly one PCAP")
    if mb1_manifest.files[0].relative_path != MONDAY_PCAP_RELATIVE_PATH:
        raise ValueError(f"MB1 manifest PCAP must be {MONDAY_PCAP_RELATIVE_PATH}")

    return BoundMondayBenignReplaySpecification(
        specification=specification,
        specification_sha256=specification.content_sha256(),
        m1_manifest_sha256=manifest_sha256,
        input_file_count=len(specification.inputs),
        input_total_size_bytes=sum(
            item.size_bytes for item in specification.inputs
        ),
    )
