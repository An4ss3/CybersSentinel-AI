"""MB-LABEL lineage: bind the frozen M5 v1 policy to MB4 events and MB6 windows.

Nothing here parses evidence, writes a row, or invents a value. Events are
reconstructed as genuine ``FlowEndV2`` instances from the columns MB4 already
persisted, so the labels are produced by the **unmodified** frozen machinery:
``LabelLedger`` compiles the M5 v1 manifest, and ``ExactTimeLabelAdapterV2``
performs the exact-integer temporal comparison that ``LabelLedger.assign`` cannot
do on ``FlowEndV2``.

The reconstruction is lossless with respect to everything labeling reads. The
adapter uses ``event_start_time``, ``event_end_time``, ``source``, ``destination``,
``transport`` and ``provenance.event_id``; all six come straight from
``mb4_canonical.flow_end_events``. Reconstructing the full contract rather than a
loose projection means ``FlowEndV2``'s own validators re-run on every row, so a
corrupted MB4 row would be refused rather than silently labelled.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from hashlib import sha256
import json
from pathlib import Path
from typing import Final, Iterator
from uuid import UUID, uuid5

import yaml

from modules.detection.src.lineage.exact_time_labeling_v2 import (
    ExactTimeLabelAdapterV2,
)
from modules.detection.src.lineage.labeling import LabelLedger
from modules.detection.src.lineage.monday_benign_feature_window import (
    load_and_bind_monday_benign_feature_window_specification,
)
from modules.detection.src.lineage.provenance import EventProvenance
from modules.detection.src.persistence.monday_benign_persistence import (
    MB4_REPORT_RELATIVE_PATH,
    MondayBenignMaterializationReport,
)
from modules.detection.src.schemas.common import FlowCounters, NetworkEndpoint
from modules.detection.src.schemas.events_v2 import FlowEndV2
from modules.detection.src.schemas.labels import EventLabel
from modules.detection.src.schemas.monday_benign_feature_window import (
    MB6_REPORT_RELATIVE_PATH,
    MondayBenignFeatureWindowRunReport,
)
from modules.detection.src.schemas.monday_benign_labeling import (
    MB7_LABEL_NAMESPACE,
    MB7_PROTOCOL_RELATIVE_PATH,
    MONDAY_RULE_END_EPOCH,
    MONDAY_RULE_START_EPOCH,
    MondayBenignLabelingSpecification,
    derive_mb7_run_id,
)
from modules.detection.src.schemas.monday_benign_replay import MONDAY_OUTPUT_PARTITION


M5_V1_MANIFEST_RELATIVE_PATH: Final[str] = "datasets/manifests/cicids2017_labels.yaml"
MONDAY_RULE_ID: Final[str] = "monday-benign-reference"


class MondayBenignLabelingError(RuntimeError):
    """MB7 labeling cannot proceed or could not be verified."""


@dataclass(frozen=True, slots=True)
class BoundMondayBenignLabelingSpecification:
    """Validated MB7 identity chained through MB1..MB6 and bound to M5 v1."""

    specification: MondayBenignLabelingSpecification
    protocol_sha256: str
    run_id: str
    mb4_run_id: str
    mb6_run_id: str
    mb3_report_content_sha256: str
    mb4_report_content_sha256: str
    mb6_report_content_sha256: str
    mb6_window_stream_sha256: str
    ledger: LabelLedger
    adapter: ExactTimeLabelAdapterV2
    expected_event_count: int
    expected_window_count: int


def _json_default(value: object) -> str:
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    raise TypeError(f"unsupported YAML value type: {type(value).__name__}")


def load_monday_benign_labeling_specification(
    path: str | Path,
) -> MondayBenignLabelingSpecification:
    """Load YAML through strict JSON-mode Pydantic validation."""
    source = Path(path)
    raw = yaml.safe_load(source.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("MB7 protocol root must be a mapping")
    return MondayBenignLabelingSpecification.model_validate_json(
        json.dumps(raw, default=_json_default)
    )


def build_m5_v1_ledger(repository_root: str | Path) -> LabelLedger:
    """Load the frozen M5 v1 manifest exactly as published. No variant."""
    root = Path(repository_root).resolve(strict=True)
    return LabelLedger.from_yaml(root / M5_V1_MANIFEST_RELATIVE_PATH)


def bind_monday_benign_labeling_specification(
    repository_root: str | Path,
    specification: MondayBenignLabelingSpecification,
) -> BoundMondayBenignLabelingSpecification:
    """Verify the whole MB1..MB6 chain and the frozen M5 v1 policy binding."""
    root = Path(repository_root).resolve(strict=True)

    mb6 = load_and_bind_monday_benign_feature_window_specification(root)
    if specification.mb6_protocol_sha256 != mb6.protocol_sha256:
        raise MondayBenignLabelingError("MB7 MB6 protocol hash does not match")
    if specification.mb1_manifest_sha256 != mb6.mb1_manifest_sha256:
        raise MondayBenignLabelingError("MB7 MB1 manifest hash does not match")
    if specification.mb2_specification_sha256 != mb6.mb2_specification_sha256:
        raise MondayBenignLabelingError("MB7 MB2 specification hash does not match")
    if specification.mb3_protocol_sha256 != mb6.mb3_protocol_sha256:
        raise MondayBenignLabelingError("MB7 MB3 protocol hash does not match")
    if specification.mb4_report_content_sha256 != mb6.mb4_report_content_sha256:
        raise MondayBenignLabelingError("MB7 MB4 report hash does not match")
    if str(specification.mb4_run_id) != mb6.mb4_run_id:
        raise MondayBenignLabelingError("MB7 MB4 run identity does not match")

    mb6_report = MondayBenignFeatureWindowRunReport.model_validate_json(
        (root / MB6_REPORT_RELATIVE_PATH).read_text(encoding="utf-8")
    )
    if mb6_report.verification_status != "verified":
        raise MondayBenignLabelingError("MB6 report is not verified")
    if specification.mb6_report_content_sha256 != mb6_report.content_sha256():
        raise MondayBenignLabelingError("MB7 MB6 report content hash mismatch")
    if str(specification.mb6_run_id) != str(mb6_report.run_id):
        raise MondayBenignLabelingError("MB7 MB6 run identity does not match")
    if specification.mb6_window_stream_sha256 != mb6_report.window_stream_sha256:
        raise MondayBenignLabelingError("MB7 MB6 window stream digest mismatch")
    if mb6_report.partition_reports[0].output_partition != MONDAY_OUTPUT_PARTITION:
        raise MondayBenignLabelingError("MB6 report is not the Monday partition")

    mb4_report = MondayBenignMaterializationReport.model_validate_json(
        (root / MB4_REPORT_RELATIVE_PATH).read_text(encoding="utf-8")
    )
    if specification.mb3_report_content_sha256 != (
        mb4_report.mb3_report_content_sha256
    ):
        raise MondayBenignLabelingError("MB7 and MB4 disagree on the MB3 report")

    ledger = build_m5_v1_ledger(root)
    policy = specification.policy
    if policy.manifest_hash != ledger.manifest_hash:
        raise MondayBenignLabelingError(
            "MB7 declares an M5 manifest hash that is not the published M5 v1"
        )
    if policy.rule_version != ledger.manifest.rule_version:
        raise MondayBenignLabelingError("MB7 M5 rule_version mismatch")
    if policy.authoritative_source != ledger.manifest.authoritative_source:
        raise MondayBenignLabelingError("MB7 M5 authoritative_source mismatch")
    if policy.timezone != ledger.manifest.timezone:
        raise MondayBenignLabelingError("MB7 M5 timezone mismatch")
    if policy.applicable_rule_hash != ledger.rule_hash(MONDAY_RULE_ID):
        raise MondayBenignLabelingError("MB7 Monday rule hash mismatch")

    monday = tuple(
        interval
        for interval in ledger.compiled_intervals
        if interval.rule.rule_id == MONDAY_RULE_ID
    )
    if len(monday) != 1:
        raise MondayBenignLabelingError(
            f"expected exactly one compiled Monday interval, found {len(monday)}"
        )
    interval = monday[0]
    if interval.rule.selector.mode != "any_network":
        raise MondayBenignLabelingError("Monday rule selector mode changed")
    if interval.rule.disposition != "benign_reference":
        raise MondayBenignLabelingError("Monday rule disposition changed")
    start = int(interval.start_utc.timestamp())
    end = int(interval.end_utc.timestamp())
    if (start, end) != (MONDAY_RULE_START_EPOCH, MONDAY_RULE_END_EPOCH):
        raise MondayBenignLabelingError(
            f"compiled Monday interval moved: [{start}, {end}) != "
            f"[{MONDAY_RULE_START_EPOCH}, {MONDAY_RULE_END_EPOCH})"
        )

    protocol_sha256 = specification.content_sha256()
    return BoundMondayBenignLabelingSpecification(
        specification=specification,
        protocol_sha256=protocol_sha256,
        run_id=str(derive_mb7_run_id(protocol_sha256, specification.mb6_run_id)),
        mb4_run_id=str(specification.mb4_run_id),
        mb6_run_id=str(specification.mb6_run_id),
        mb3_report_content_sha256=specification.mb3_report_content_sha256,
        mb4_report_content_sha256=specification.mb4_report_content_sha256,
        mb6_report_content_sha256=specification.mb6_report_content_sha256,
        mb6_window_stream_sha256=specification.mb6_window_stream_sha256,
        ledger=ledger,
        adapter=ExactTimeLabelAdapterV2(ledger),
        expected_event_count=mb4_report.persisted_event_count,
        expected_window_count=mb6_report.total_window_count,
    )


def load_and_bind_monday_benign_labeling_specification(
    repository_root: str | Path,
    specification_path: str | Path = MB7_PROTOCOL_RELATIVE_PATH,
) -> BoundMondayBenignLabelingSpecification:
    """Load the MB7 protocol from the repository and bind it to MB evidence."""
    root = Path(repository_root).resolve(strict=True)
    return bind_monday_benign_labeling_specification(
        root, load_monday_benign_labeling_specification(root / specification_path)
    )


# --------------------------------------------------------------------------
# Faithful FlowEndV2 reconstruction from MB4
# --------------------------------------------------------------------------

MB4_EVENT_COLUMNS: Final[str] = """
    event_id, output_partition,
    event_start_time::text, event_duration::text, event_end_time::text,
    record_available_time::text, ingested_at::text,
    conversation_id, host(source_ip), source_port,
    host(destination_ip), destination_port, transport, service,
    source_packets, destination_packets, source_bytes, destination_bytes,
    connection_state,
    sensor_id, sensor_run_id, capture_id, dataset_snapshot_id,
    model_release_id, normalizer_version, pipeline_version,
    schema_version, event_version, feature_version, sensor_version,
    event_type, sensor_type
"""


def flow_end_from_mb4_row(row: tuple) -> FlowEndV2:
    """Rebuild one genuine FlowEndV2 from an MB4 row. Nothing is invented."""
    return FlowEndV2(
        schema_version=row[26],
        event_version=row[27],
        feature_version=row[28],
        sensor_version=row[29],
        event_type=row[30],
        sensor_type=row[31],
        provenance=EventProvenance(
            event_id=row[0],
            sensor_id=row[19],
            sensor_run_id=row[20],
            capture_id=row[21],
            dataset_snapshot_id=row[22],
            model_release_id=row[23],
            normalizer_version=row[24],
            pipeline_version=row[25],
        ),
        event_start_time=row[2],
        event_duration=row[3],
        event_end_time=row[4],
        record_available_time=row[5],
        ingested_at=row[6],
        conversation_id=row[7],
        source=NetworkEndpoint(ip=row[8], port=row[9]),
        destination=NetworkEndpoint(ip=row[10], port=row[11]),
        transport=row[12],
        service=row[13],
        counters=FlowCounters(
            source_packets=row[14],
            destination_packets=row[15],
            source_bytes=row[16],
            destination_bytes=row[17],
        ),
        connection_state=row[18],
        termination_reason=None,
    )


def derive_event_label_id(
    protocol_sha256: str, manifest_hash: str, event_id: UUID | str
) -> UUID:
    """Derive the deterministic MB7 event-label identity."""
    return uuid5(
        MB7_LABEL_NAMESPACE, f"{protocol_sha256}|{manifest_hash}|{event_id}"
    )


def derive_window_label_id(
    protocol_sha256: str, manifest_hash: str, window_id: UUID | str
) -> UUID:
    """Derive the deterministic MB7 window-label identity."""
    return uuid5(
        MB7_LABEL_NAMESPACE, f"{protocol_sha256}|{manifest_hash}|{window_id}"
    )


def canonical_event_label_bytes(label: EventLabel) -> bytes:
    """Stable semantic JSON bytes for event-label stream hashing."""
    return (
        json.dumps(
            label.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        + b"\n"
    )
