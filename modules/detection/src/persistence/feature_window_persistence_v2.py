"""M6 feature-window persistence: schema, streaming M4 reader, batched writes.

Reads ``m4_canonical.flow_end_events`` with ``SELECT`` only and writes solely
into the dedicated ``m6_canonical`` schema. Nothing here modifies, updates, or
deletes any upstream artefact.

The M4 reader emits events already ordered by the frozen M6 canonical key
(``output_partition``, ``entity_key``, window bucket) using ``COLLATE "C"`` so
PostgreSQL text ordering matches Python code-point ordering exactly. Windows can
therefore be emitted in canonical order while holding only one group in memory.
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterator
from uuid import UUID

from modules.detection.src.feature_engineering.window_builder_v2 import (
    SourceEventRow,
)
from modules.detection.src.schemas.feature_window_v2 import (
    NULL_SERVICE_SENTINEL,
    FeatureWindowV2,
)


M6_SCHEMA_FILE = Path(__file__).resolve().parent / "schema_m6.sql"

#: Streaming projection of M4 events in exact M6 canonical order.
#: ``COLLATE "C"`` guarantees code-point ordering identical to Python's.
STREAM_PARTITION_EVENTS_SQL = """
SELECT
    event_id,
    output_partition,
    event_start_time::text,
    record_available_time::text,
    host(source_ip),
    source_port,
    host(destination_ip),
    destination_port,
    transport,
    service,
    source_packets,
    destination_packets,
    source_bytes,
    destination_bytes,
    sensor_id,
    sensor_run_id,
    capture_id,
    dataset_snapshot_id,
    model_release_id,
    normalizer_version,
    pipeline_version,
    sensor_version
FROM m4_canonical.flow_end_events
WHERE output_partition = %(partition)s
ORDER BY
    host(source_ip) COLLATE "C",
    host(destination_ip) COLLATE "C",
    transport COLLATE "C",
    coalesce(service, %(sentinel)s) COLLATE "C",
    floor(event_start_time / 60)
"""

_INSERT_RUN_SQL = """
INSERT INTO m6_canonical.materialization_runs (
    run_id, m6_protocol_sha256, m3_report_content_sha256,
    m4_report_content_sha256, status, started_at
) VALUES (
    %(run_id)s, %(m6_protocol_sha256)s, %(m3_report_content_sha256)s,
    %(m4_report_content_sha256)s, %(status)s, %(started_at)s
)
"""

_UPDATE_RUN_SQL = """
UPDATE m6_canonical.materialization_runs
SET status = %(status)s,
    completed_at = %(completed_at)s,
    total_source_event_count = %(total_source_event_count)s,
    total_window_count = %(total_window_count)s,
    window_stream_sha256 = %(window_stream_sha256)s
WHERE run_id = %(run_id)s
"""

_CHECK_VERIFIED_RUN_SQL = """
SELECT run_id FROM m6_canonical.materialization_runs
WHERE m6_protocol_sha256 = %(m6_protocol_sha256)s
  AND m3_report_content_sha256 = %(m3_report_content_sha256)s
  AND m4_report_content_sha256 = %(m4_report_content_sha256)s
  AND status = 'verified'
"""

_INSERT_WINDOW_SQL = """
INSERT INTO m6_canonical.feature_windows (
    window_id, m6_run_id, output_partition, entity_type,
    entity_source_ip, entity_destination_ip, entity_transport, entity_service,
    window_start_time, window_end_time, prediction_time, record_available_time,
    schema_version, event_version, feature_version, sensor_version,
    sensor_id, sensor_run_id, capture_id, dataset_snapshot_id,
    model_release_id, normalizer_version, pipeline_version,
    event_count, source_packets_total, destination_packets_total,
    source_bytes_total, destination_bytes_total,
    distinct_destination_ports, distinct_destination_ips, distinct_source_ips,
    source_event_count, late_event_count, dropped_event_count,
    is_final, is_revision, window_bytes_sha256
) VALUES (
    %(window_id)s, %(m6_run_id)s, %(output_partition)s, %(entity_type)s,
    %(entity_source_ip)s, %(entity_destination_ip)s, %(entity_transport)s,
    %(entity_service)s,
    %(window_start_time)s, %(window_end_time)s, %(prediction_time)s,
    %(record_available_time)s,
    %(schema_version)s, %(event_version)s, %(feature_version)s,
    %(sensor_version)s,
    %(sensor_id)s, %(sensor_run_id)s, %(capture_id)s, %(dataset_snapshot_id)s,
    %(model_release_id)s, %(normalizer_version)s, %(pipeline_version)s,
    %(event_count)s, %(source_packets_total)s, %(destination_packets_total)s,
    %(source_bytes_total)s, %(destination_bytes_total)s,
    %(distinct_destination_ports)s, %(distinct_destination_ips)s,
    %(distinct_source_ips)s,
    %(source_event_count)s, %(late_event_count)s, %(dropped_event_count)s,
    %(is_final)s, %(is_revision)s, %(window_bytes_sha256)s
)
"""

_INSERT_SOURCE_SQL = """
INSERT INTO m6_canonical.feature_window_sources (window_id, source_event_id)
VALUES (%s, %s)
"""


def ensure_m6_schema(conn) -> None:
    """Apply schema_m6.sql (idempotent CREATE ... IF NOT EXISTS only)."""
    with conn.cursor() as cur:
        cur.execute(M6_SCHEMA_FILE.read_text(encoding="utf-8"))
    conn.commit()


def stream_partition_events(conn, partition: str) -> Iterator[SourceEventRow]:
    """Yield one partition's M4 events in exact M6 canonical order."""
    with conn.cursor(name=f"m6_stream_{abs(hash(partition))}") as cur:
        cur.itersize = 20_000
        cur.execute(
            STREAM_PARTITION_EVENTS_SQL,
            {"partition": partition, "sentinel": NULL_SERVICE_SENTINEL},
        )
        for record in cur:
            yield SourceEventRow(
                event_id=record[0],
                output_partition=record[1],
                event_start_time=record[2],
                record_available_time=record[3],
                source_ip=record[4],
                source_port=record[5],
                destination_ip=record[6],
                destination_port=record[7],
                transport=record[8],
                service=record[9],
                source_packets=record[10],
                destination_packets=record[11],
                source_bytes=record[12],
                destination_bytes=record[13],
                sensor_id=record[14],
                sensor_run_id=record[15],
                capture_id=record[16],
                dataset_snapshot_id=record[17],
                model_release_id=record[18],
                normalizer_version=record[19],
                pipeline_version=record[20],
                sensor_version=record[21],
            )


def window_row(window: FeatureWindowV2, run_id: UUID, digest: str) -> dict[str, object]:
    """Map one FeatureWindowV2 to its persistence row, verbatim."""
    p = window.provenance
    f = window.features
    q = window.data_quality
    return {
        "window_id": str(window.provenance.event_id),
        "m6_run_id": str(run_id),
        "output_partition": window.output_partition,
        "entity_type": window.entity_type,
        "entity_source_ip": window.entity_key[0],
        "entity_destination_ip": window.entity_key[1],
        "entity_transport": window.entity_key[2],
        "entity_service": window.entity_key[3],
        "window_start_time": window.window_start_time,
        "window_end_time": window.window_end_time,
        "prediction_time": window.prediction_time,
        "record_available_time": window.record_available_time,
        "schema_version": window.schema_version,
        "event_version": window.event_version,
        "feature_version": window.feature_version,
        "sensor_version": window.sensor_version,
        "sensor_id": p.sensor_id,
        "sensor_run_id": p.sensor_run_id,
        "capture_id": p.capture_id,
        "dataset_snapshot_id": p.dataset_snapshot_id,
        "model_release_id": p.model_release_id,
        "normalizer_version": p.normalizer_version,
        "pipeline_version": p.pipeline_version,
        "event_count": f["event_count"],
        "source_packets_total": f["source_packets_total"],
        "destination_packets_total": f["destination_packets_total"],
        "source_bytes_total": f["source_bytes_total"],
        "destination_bytes_total": f["destination_bytes_total"],
        "distinct_destination_ports": f["distinct_destination_ports"],
        "distinct_destination_ips": f["distinct_destination_ips"],
        "distinct_source_ips": f["distinct_source_ips"],
        "source_event_count": q.source_event_count,
        "late_event_count": q.late_event_count,
        "dropped_event_count": q.dropped_event_count,
        "is_final": q.is_final,
        "is_revision": q.is_revision,
        "window_bytes_sha256": digest,
    }


def persist_window_batch(
    conn,
    window_rows: list[dict[str, object]],
    lineage_rows: list[tuple[str, str]],
) -> None:
    """Insert one batch of windows and their complete source lineage."""
    if not window_rows:
        return
    with conn.cursor() as cur:
        cur.executemany(_INSERT_WINDOW_SQL, window_rows)
        cur.executemany(_INSERT_SOURCE_SQL, lineage_rows)


def insert_run(conn, payload: dict[str, object]) -> None:
    with conn.cursor() as cur:
        cur.execute(_INSERT_RUN_SQL, payload)
    conn.commit()


def finalize_run(conn, payload: dict[str, object]) -> None:
    with conn.cursor() as cur:
        cur.execute(_UPDATE_RUN_SQL, payload)
    conn.commit()


def existing_verified_run(conn, payload: dict[str, object]) -> UUID | None:
    with conn.cursor() as cur:
        cur.execute(_CHECK_VERIFIED_RUN_SQL, payload)
        record = cur.fetchone()
    return None if record is None else record[0]
