"""MB6 feature-window persistence for the Monday Benign track.

Reads ``mb4_canonical.flow_end_events`` with ``SELECT`` only and writes solely
into ``mb6_canonical``. It never issues DDL or DML against ``mb4_canonical``,
``m4_canonical``, ``m6_canonical`` or the legacy ``public`` schema, never opens the
PCAP, and never reads a Zeek log: MB4 is the canonical event source, as the MB6
protocol declares.

Ordering
--------
The source projection is ordered by ``(source_ip, destination_ip, transport,
coalesce(service, sentinel), floor(event_start_time / 60))`` with ``COLLATE "C"``
so PostgreSQL text ordering matches Python code-point ordering exactly. The runner
asserts strict monotonicity of the emitted canonical order at run time and raises
rather than publishing a stream whose order it cannot prove.

Determinism
-----------
``run_id`` is ``uuid5`` over the MB6 protocol hash and the MB4 run identity. No
``uuid4`` and no clock reading enters any identity or digest, so a re-run over the
same evidence reproduces the run identity, the window-stream digest and the report
content hash. This is deliberately stricter than M6, whose report digest is
irreproducible by construction.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import os
from pathlib import Path
from typing import Any, Final, Iterator
from uuid import UUID

from modules.detection.src.feature_engineering.window_builder_v2 import (
    FeatureWindowBuilderV2,
    SourceEventRow,
    canonical_window_bytes,
    entity_key_for,
    window_start_unscaled,
)
from modules.detection.src.lineage.monday_benign_feature_window import (
    BoundMondayBenignFeatureWindowSpecification,
)
from modules.detection.src.schemas.feature_window_v2 import (
    NULL_SERVICE_SENTINEL,
    FeatureWindowV2,
)
from modules.detection.src.schemas.monday_benign_feature_window import (
    MB6_REPORT_RELATIVE_PATH,
    MB6_SCHEMA,
    MB6_WINDOW_ID_NAMESPACE,
    MondayBenignFeatureWindowRunReport,
)
from modules.detection.src.schemas.monday_benign_replay import MONDAY_OUTPUT_PARTITION


MB6_DDL_FILE: Final[Path] = Path(__file__).resolve().parent / "schema_mb6.sql"
MB6_REPORT_VERSION: Final[str] = "1.0.0"
_WINDOW_BATCH_SIZE: Final[int] = 2_000

_REQUIRED_TABLES: Final[tuple[str, ...]] = (
    "feature_window_sources",
    "feature_windows",
    "materialization_runs",
)
_REQUIRED_WINDOW_CONSTRAINTS: Final[tuple[str, ...]] = (
    "ck_mb6_window_aligned",
    "ck_mb6_window_causal_order",
    "ck_mb6_window_event_count_matches",
    "ck_mb6_window_exact_length",
    "ck_mb6_window_monday_partition",
    "ck_mb6_window_prediction_equals_end",
    "ux_mb6_window_coordinate",
)
_EXACT_NUMERIC_COLUMNS: Final[tuple[str, ...]] = (
    "prediction_time",
    "record_available_time",
    "window_end_time",
    "window_start_time",
)


class MondayBenignWindowError(RuntimeError):
    """MB6 materialization cannot proceed or could not be verified."""


class MondayBenignWindowOrderingViolation(MondayBenignWindowError):
    """The emitted canonical order was not strictly increasing."""


class MondayBenignDuplicateVerifiedWindowRunError(MondayBenignWindowError):
    """A verified MB6 materialization of this evidence already exists."""


STREAM_MB4_EVENTS_SQL: Final[str] = f"""
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
FROM mb4_canonical.flow_end_events
WHERE output_partition = %(partition)s
ORDER BY
    host(source_ip) COLLATE "C",
    host(destination_ip) COLLATE "C",
    transport COLLATE "C",
    coalesce(service, %(sentinel)s) COLLATE "C",
    floor(event_start_time / 60)
"""

_INSERT_RUN_SQL = f"""
INSERT INTO {MB6_SCHEMA}.materialization_runs (
    run_id, mb6_protocol_sha256, mb3_report_content_sha256,
    mb4_report_content_sha256, mb4_run_id, mb6_window_id_namespace,
    status, started_at
) VALUES (
    %(run_id)s, %(mb6_protocol_sha256)s, %(mb3_report_content_sha256)s,
    %(mb4_report_content_sha256)s, %(mb4_run_id)s, %(mb6_window_id_namespace)s,
    %(status)s, %(started_at)s
)
"""

_UPDATE_RUN_SQL = f"""
UPDATE {MB6_SCHEMA}.materialization_runs
SET status = %(status)s,
    completed_at = %(completed_at)s,
    total_source_event_count = %(total_source_event_count)s,
    total_window_count = %(total_window_count)s,
    window_stream_sha256 = %(window_stream_sha256)s
WHERE run_id = %(run_id)s
"""

_CHECK_VERIFIED_RUN_SQL = f"""
SELECT run_id FROM {MB6_SCHEMA}.materialization_runs
WHERE mb6_protocol_sha256 = %(mb6_protocol_sha256)s
  AND mb3_report_content_sha256 = %(mb3_report_content_sha256)s
  AND mb4_report_content_sha256 = %(mb4_report_content_sha256)s
  AND status = 'verified'
"""

_CHECK_ANY_RUN_SQL = f"""
SELECT run_id, status FROM {MB6_SCHEMA}.materialization_runs
WHERE run_id = %(run_id)s
"""

_INSERT_WINDOW_SQL = f"""
INSERT INTO {MB6_SCHEMA}.feature_windows (
    window_id, mb6_run_id, output_partition, entity_type,
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
    %(window_id)s, %(mb6_run_id)s, %(output_partition)s, %(entity_type)s,
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

_INSERT_SOURCE_SQL = f"""
INSERT INTO {MB6_SCHEMA}.feature_window_sources (window_id, source_event_id)
VALUES (%s, %s)
"""


def _strip_sql_comments(ddl: str) -> str:
    """Return the DDL with ``--`` line comments removed."""
    lines = []
    for line in ddl.splitlines():
        marker = line.find("--")
        lines.append(line if marker == -1 else line[:marker])
    return "\n".join(lines)


def ensure_mb6_schema(conn) -> None:
    """Apply schema_mb6.sql. Every statement is CREATE ... IF NOT EXISTS."""
    ddl = MB6_DDL_FILE.read_text(encoding="utf-8")
    executable = _strip_sql_comments(ddl)
    for forbidden in ("m4_canonical", "m6_canonical"):
        if forbidden in executable:
            raise MondayBenignWindowError(
                f"MB6 DDL must never reference {forbidden} in a statement"
            )
    with conn.cursor() as cur:
        cur.execute(ddl)
    conn.commit()


def verify_mb6_schema(conn) -> None:
    """Prove the target schema matches the MB6 contract before any insert."""
    with conn.cursor() as cur:
        cur.execute(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema = %s ORDER BY table_name",
            (MB6_SCHEMA,),
        )
        tables = tuple(row[0] for row in cur.fetchall())
        if tables != _REQUIRED_TABLES:
            raise MondayBenignWindowError(
                f"MB6 tables mismatch: expected {_REQUIRED_TABLES}, found {tables}"
            )

        cur.execute(
            "SELECT column_name, numeric_precision, numeric_scale "
            "FROM information_schema.columns "
            "WHERE table_schema = %s AND table_name = 'feature_windows' "
            "AND column_name = ANY(%s) ORDER BY column_name",
            (MB6_SCHEMA, list(_EXACT_NUMERIC_COLUMNS)),
        )
        numeric = tuple(cur.fetchall())
        if len(numeric) != len(_EXACT_NUMERIC_COLUMNS):
            raise MondayBenignWindowError("MB6 temporal columns are incomplete")
        for name, precision, scale in numeric:
            if (precision, scale) != (38, 22):
                raise MondayBenignWindowError(
                    f"MB6 column {name} must be NUMERIC(38,22)"
                )

        cur.execute(
            "SELECT conname FROM pg_constraint WHERE conrelid = %s::regclass",
            (f"{MB6_SCHEMA}.feature_windows",),
        )
        constraints = {row[0] for row in cur.fetchall()}
        missing = tuple(
            name for name in _REQUIRED_WINDOW_CONSTRAINTS
            if name not in constraints
        )
        if missing:
            raise MondayBenignWindowError(f"MB6 missing constraints: {missing}")

        cur.execute(
            """
            SELECT c.conname, n.nspname
            FROM pg_constraint c
            JOIN pg_class t ON t.oid = c.confrelid
            JOIN pg_namespace n ON n.oid = t.relnamespace
            WHERE c.contype = 'f'
              AND c.conrelid IN (
                  SELECT oid FROM pg_class
                  WHERE relnamespace = %s::regnamespace
              )
            """,
            (MB6_SCHEMA,),
        )
        offending = tuple(
            (name, schema)
            for name, schema in cur.fetchall()
            if schema != MB6_SCHEMA
        )
        if offending:
            raise MondayBenignWindowError(
                f"MB6 foreign keys must stay inside {MB6_SCHEMA}: {offending}"
            )


def stream_mb4_events(conn, partition: str) -> Iterator[SourceEventRow]:
    """Yield the MB4 Monday events in exact MB6 canonical order, read-only."""
    with conn.cursor(name=f"mb6_stream_{abs(hash(partition))}") as cur:
        cur.itersize = 20_000
        cur.execute(
            STREAM_MB4_EVENTS_SQL,
            {"partition": partition, "sentinel": NULL_SERVICE_SENTINEL},
        )
        for row in cur:
            yield SourceEventRow(
                event_id=row[0],
                output_partition=row[1],
                event_start_time=row[2],
                record_available_time=row[3],
                source_ip=row[4],
                source_port=row[5],
                destination_ip=row[6],
                destination_port=row[7],
                transport=row[8],
                service=row[9],
                source_packets=row[10],
                destination_packets=row[11],
                source_bytes=row[12],
                destination_bytes=row[13],
                sensor_id=row[14],
                sensor_run_id=row[15],
                capture_id=row[16],
                dataset_snapshot_id=row[17],
                model_release_id=row[18],
                normalizer_version=row[19],
                pipeline_version=row[20],
                sensor_version=row[21],
            )


def _window_row(window: FeatureWindowV2, run_id: str, digest: str) -> dict[str, Any]:
    """Map one FeatureWindowV2 to its MB6 row, verbatim."""
    provenance = window.provenance
    source_ip, destination_ip, transport, service = window.entity_key
    features = window.features
    quality = window.data_quality
    return {
        "window_id": window.window_id,
        "mb6_run_id": run_id,
        "output_partition": window.output_partition,
        "entity_type": window.entity_type,
        "entity_source_ip": source_ip,
        "entity_destination_ip": destination_ip,
        "entity_transport": transport,
        "entity_service": service,
        "window_start_time": window.window_start_time,
        "window_end_time": window.window_end_time,
        "prediction_time": window.prediction_time,
        "record_available_time": window.record_available_time,
        "schema_version": window.schema_version,
        "event_version": window.event_version,
        "feature_version": window.feature_version,
        "sensor_version": window.sensor_version,
        "sensor_id": provenance.sensor_id,
        "sensor_run_id": provenance.sensor_run_id,
        "capture_id": provenance.capture_id,
        "dataset_snapshot_id": provenance.dataset_snapshot_id,
        "model_release_id": provenance.model_release_id,
        "normalizer_version": provenance.normalizer_version,
        "pipeline_version": provenance.pipeline_version,
        "event_count": features["event_count"],
        "source_packets_total": features["source_packets_total"],
        "destination_packets_total": features["destination_packets_total"],
        "source_bytes_total": features["source_bytes_total"],
        "destination_bytes_total": features["destination_bytes_total"],
        "distinct_destination_ports": features["distinct_destination_ports"],
        "distinct_destination_ips": features["distinct_destination_ips"],
        "distinct_source_ips": features["distinct_source_ips"],
        "source_event_count": quality.source_event_count,
        "late_event_count": quality.late_event_count,
        "dropped_event_count": quality.dropped_event_count,
        "is_final": quality.is_final,
        "is_revision": quality.is_revision,
        "window_bytes_sha256": digest,
    }


@dataclass(frozen=True, slots=True)
class MondayBenignWindowOutcome:
    """Accumulated MB6 materialization evidence."""

    run_id: str
    source_event_count: int
    window_count: int
    entity_count: int
    lineage_row_count: int
    first_window_id: str | None
    last_window_id: str | None
    window_stream_sha256: str
    sensor_version: str
    started_at: datetime
    completed_at: datetime


class MondayBenignWindowRunner:
    """Build and persist Monday feature windows from MB4 canonical events."""

    def __init__(
        self,
        bound: BoundMondayBenignFeatureWindowSpecification,
        expected_database: str,
    ) -> None:
        self._bound = bound
        self._expected_database = expected_database
        self._builder = FeatureWindowBuilderV2(bound.specification)  # type: ignore[arg-type]
        if self._builder.protocol_sha256 != bound.protocol_sha256:
            raise MondayBenignWindowError(
                "MB6 builder protocol hash diverges from the bound protocol"
            )

    @property
    def builder(self) -> FeatureWindowBuilderV2:
        return self._builder

    def _assert_database(self, conn) -> None:
        with conn.cursor() as cur:
            cur.execute("SELECT current_database()")
            row = cur.fetchone()
        actual = row[0] if row else None
        if actual != self._expected_database:
            raise MondayBenignWindowError(
                f"MB6 refuses to write: connected to {actual!r}, "
                f"expected {self._expected_database!r}"
            )

    def build_windows(self, conn) -> list[FeatureWindowV2]:
        """Build every window in canonical order, asserting strict monotonicity."""
        partition = self._bound.output_partition
        rows = list(stream_mb4_events(conn, partition))
        if not rows:
            raise MondayBenignWindowError(
                f"MB4 holds no events for partition {partition}"
            )
        for row in rows:
            if row.output_partition != MONDAY_OUTPUT_PARTITION:
                raise MondayBenignWindowError(
                    f"MB6 refuses a non-Monday source row: {row.output_partition}"
                )
        length = self._builder.window_length_unscaled
        observed = [
            (
                row.output_partition,
                entity_key_for(row),
                window_start_unscaled(row.event_start_time, length),
            )
            for row in rows
        ]
        if observed != sorted(observed):
            raise MondayBenignWindowOrderingViolation(
                "MB4 projection did not arrive in MB6 canonical order"
            )
        windows = list(self._builder.build_ordered(rows))
        keys = [
            (w.output_partition, w.entity_type, w.entity_key, w.window_start_time)
            for w in windows
        ]
        if keys != sorted(keys):
            raise MondayBenignWindowOrderingViolation(
                "MB6 emitted windows out of canonical order"
            )
        if len(set(keys)) != len(keys):
            raise MondayBenignWindowOrderingViolation(
                "MB6 emitted duplicate window coordinates"
            )
        return windows

    def materialize(self, conn) -> MondayBenignWindowOutcome:
        """Persist the Monday windows and their complete source lineage."""
        self._assert_database(conn)
        verify_mb6_schema(conn)

        bound = self._bound
        with conn.cursor() as cur:
            cur.execute(
                _CHECK_VERIFIED_RUN_SQL,
                {
                    "mb6_protocol_sha256": bound.protocol_sha256,
                    "mb3_report_content_sha256": bound.mb3_report_content_sha256,
                    "mb4_report_content_sha256": bound.mb4_report_content_sha256,
                },
            )
            existing = cur.fetchone()
        if existing is not None:
            raise MondayBenignDuplicateVerifiedWindowRunError(
                "a verified MB6 materialization of this evidence already exists: "
                f"run_id={existing[0]}"
            )
        with conn.cursor() as cur:
            cur.execute(_CHECK_ANY_RUN_SQL, {"run_id": bound.run_id})
            prior = cur.fetchone()
        if prior is not None:
            raise MondayBenignWindowError(
                f"MB6 run_id {bound.run_id} already exists with status "
                f"{prior[1]!r}. The run identity is deterministic, so a prior "
                "attempt must be resolved by the owner rather than overwritten."
            )

        windows = self.build_windows(conn)
        source_event_count = sum(
            window.data_quality.source_event_count for window in windows
        )
        if source_event_count != bound.expected_source_event_count:
            raise MondayBenignWindowError(
                "MB6 consumed "
                f"{source_event_count} events but MB4 published "
                f"{bound.expected_source_event_count}"
            )

        started_at = datetime.now(timezone.utc)
        with conn.cursor() as cur:
            cur.execute(
                _INSERT_RUN_SQL,
                {
                    "run_id": bound.run_id,
                    "mb6_protocol_sha256": bound.protocol_sha256,
                    "mb3_report_content_sha256": bound.mb3_report_content_sha256,
                    "mb4_report_content_sha256": bound.mb4_report_content_sha256,
                    "mb4_run_id": bound.mb4_run_id,
                    "mb6_window_id_namespace": str(MB6_WINDOW_ID_NAMESPACE),
                    "status": "running",
                    "started_at": started_at,
                },
            )
        conn.commit()

        stream_digest = sha256()
        entities: set[tuple[str, ...]] = set()
        lineage_rows = 0
        first_window_id: str | None = None
        last_window_id: str | None = None
        try:
            with conn.cursor() as cur:
                batch: list[dict[str, Any]] = []
                lineage: list[tuple[str, str]] = []
                for window in windows:
                    payload = canonical_window_bytes(window)
                    stream_digest.update(payload)
                    entities.add(tuple(window.entity_key))
                    if first_window_id is None:
                        first_window_id = window.window_id
                    last_window_id = window.window_id
                    batch.append(
                        _window_row(
                            window, bound.run_id, sha256(payload).hexdigest()
                        )
                    )
                    for source_event_id in window.source_event_ids:
                        lineage.append((window.window_id, str(source_event_id)))
                        lineage_rows += 1
                    if len(batch) >= _WINDOW_BATCH_SIZE:
                        cur.executemany(_INSERT_WINDOW_SQL, batch)
                        cur.executemany(_INSERT_SOURCE_SQL, lineage)
                        batch.clear()
                        lineage.clear()
                if batch:
                    cur.executemany(_INSERT_WINDOW_SQL, batch)
                if lineage:
                    cur.executemany(_INSERT_SOURCE_SQL, lineage)
            conn.commit()

            if lineage_rows != source_event_count:
                raise MondayBenignWindowError(
                    "MB6 lineage rows do not equal the consumed event count"
                )
            completed_at = datetime.now(timezone.utc)
            with conn.cursor() as cur:
                cur.execute(
                    _UPDATE_RUN_SQL,
                    {
                        "run_id": bound.run_id,
                        "status": "verified",
                        "completed_at": completed_at,
                        "total_source_event_count": source_event_count,
                        "total_window_count": len(windows),
                        "window_stream_sha256": stream_digest.hexdigest(),
                    },
                )
            conn.commit()
        except BaseException:
            conn.rollback()
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        _UPDATE_RUN_SQL,
                        {
                            "run_id": bound.run_id,
                            "status": "failed",
                            "completed_at": datetime.now(timezone.utc),
                            "total_source_event_count": source_event_count,
                            "total_window_count": len(windows),
                            "window_stream_sha256": None,
                        },
                    )
                conn.commit()
            except Exception:  # pragma: no cover - best-effort audit trail
                conn.rollback()
            raise

        sensor_versions = {window.sensor_version for window in windows}
        if len(sensor_versions) != 1:
            raise MondayBenignWindowError(
                "MB6 windows disagree on inherited sensor_version"
            )
        return MondayBenignWindowOutcome(
            run_id=bound.run_id,
            source_event_count=source_event_count,
            window_count=len(windows),
            entity_count=len(entities),
            lineage_row_count=lineage_rows,
            first_window_id=first_window_id,
            last_window_id=last_window_id,
            window_stream_sha256=stream_digest.hexdigest(),
            sensor_version=sensor_versions.pop(),
            started_at=started_at,
            completed_at=completed_at,
        )

    def recompute_only(self, conn) -> MondayBenignWindowOutcome:
        """Rebuild every window and digest without writing a single row."""
        self._assert_database(conn)
        windows = self.build_windows(conn)
        digest = sha256()
        entities: set[tuple[str, ...]] = set()
        lineage_rows = 0
        for window in windows:
            digest.update(canonical_window_bytes(window))
            entities.add(tuple(window.entity_key))
            lineage_rows += len(window.source_event_ids)
        now = datetime.now(timezone.utc)
        return MondayBenignWindowOutcome(
            run_id=self._bound.run_id,
            source_event_count=sum(
                w.data_quality.source_event_count for w in windows
            ),
            window_count=len(windows),
            entity_count=len(entities),
            lineage_row_count=lineage_rows,
            first_window_id=windows[0].window_id if windows else None,
            last_window_id=windows[-1].window_id if windows else None,
            window_stream_sha256=digest.hexdigest(),
            sensor_version=windows[0].sensor_version,
            started_at=now,
            completed_at=now,
        )

    def build_report(
        self, outcome: MondayBenignWindowOutcome
    ) -> MondayBenignFeatureWindowRunReport:
        """Bind a successful outcome to the immutable MB6 report contract."""
        from modules.detection.src.schemas.feature_window_protocol_v2 import (
            FeatureWindowPartitionReportV2,
        )

        bound = self._bound
        specification = bound.specification
        partition = FeatureWindowPartitionReportV2(
            output_partition=bound.output_partition,
            source_event_count=outcome.source_event_count,
            window_count=outcome.window_count,
            entity_count=outcome.entity_count,
            first_window_id=outcome.first_window_id,
            last_window_id=outcome.last_window_id,
            window_stream_sha256=outcome.window_stream_sha256,
        )
        return MondayBenignFeatureWindowRunReport(
            report_version=MB6_REPORT_VERSION,
            verification_status="verified",
            track="monday_benign",
            run_id=UUID(outcome.run_id),
            run_id_derivation=(
                "deterministic_uuid5_over_protocol_and_mb4_run_id"
            ),
            protocol_sha256=bound.protocol_sha256,
            mb1_manifest_sha256=bound.mb1_manifest_sha256,
            mb2_specification_sha256=bound.mb2_specification_sha256,
            mb3_protocol_sha256=bound.mb3_protocol_sha256,
            mb3_report_content_sha256=bound.mb3_report_content_sha256,
            mb4_report_content_sha256=bound.mb4_report_content_sha256,
            mb4_run_id=UUID(bound.mb4_run_id),
            window_id_namespace=MB6_WINDOW_ID_NAMESPACE,
            target_database=self._expected_database,
            target_schema=MB6_SCHEMA,
            operational_source="mb4_canonical.flow_end_events",
            dataset_name=specification.dataset_name,
            target_model="FeatureWindowV2",
            schema_version="2.0.0",
            event_version="2.0.0",
            feature_version="2.0.0",
            sensor_version=outcome.sensor_version,
            entity_type=specification.entity.entity_type,
            window_length_seconds=specification.window.length_seconds,
            windowing_basis="event_start_time",
            total_source_event_count=outcome.source_event_count,
            total_window_count=outcome.window_count,
            total_lineage_row_count=outcome.lineage_row_count,
            rejected_event_count=0,
            window_stream_sha256=outcome.window_stream_sha256,
            partition_reports=(partition,),
            started_at=outcome.started_at,
            completed_at=outcome.completed_at,
        )


def write_immutable_mb6_report(
    report: MondayBenignFeatureWindowRunReport,
    path: str | Path,
) -> str:
    """Publish the MB6 report immutably; return the written-byte hash."""
    destination = Path(path)
    if destination.exists():
        raise FileExistsError(f"MB6 report already exists: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = report.model_dump_json(indent=2).encode("utf-8") + b"\n"
    temporary = destination.with_name(f".{destination.name}.tmp")
    if temporary.exists():
        raise FileExistsError(f"MB6 report staging path exists: {temporary}")
    try:
        with temporary.open("xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    except BaseException:
        if temporary.exists():
            temporary.unlink()
        raise
    return sha256(payload).hexdigest()
