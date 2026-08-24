"""MB7 sidecar label persistence for the Monday Benign track.

Reads ``mb4_canonical.flow_end_events``, ``mb6_canonical.feature_windows`` and
``mb6_canonical.feature_window_sources`` with ``SELECT`` only, and writes solely
into ``mb7_canonical``. It issues no DDL or DML against MB4, MB6, the M chain or
the legacy ``public`` schema. No ``event_id`` and no ``window_id`` is regenerated:
both are read from the canonical tables and recorded by value.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
import os
from pathlib import Path
from typing import Any, Final
from uuid import UUID

from modules.detection.src.lineage.exact_time_labeling_v2 import (
    aggregate_window_disposition,
)
from modules.detection.src.lineage.monday_benign_labeling import (
    MB4_EVENT_COLUMNS,
    BoundMondayBenignLabelingSpecification,
    MondayBenignLabelingError,
    canonical_event_label_bytes,
    derive_event_label_id,
    derive_window_label_id,
    flow_end_from_mb4_row,
)
from modules.detection.src.schemas.labels import EventLabel
from modules.detection.src.schemas.monday_benign_labeling import (
    MB7_LABEL_NAMESPACE,
    MB7_REPORT_RELATIVE_PATH,
    MB7_SCHEMA,
    MONDAY_RULE_END_EPOCH,
    MONDAY_RULE_START_EPOCH,
    MondayBenignDispositionCount,
    MondayBenignIntervalSplit,
    MondayBenignLabelingRunReport,
)
from modules.detection.src.schemas.monday_benign_replay import MONDAY_OUTPUT_PARTITION


MB7_DDL_FILE: Final[Path] = Path(__file__).resolve().parent / "schema_mb7.sql"
MB7_REPORT_VERSION: Final[str] = "1.0.0"
_BATCH: Final[int] = 5_000

_REQUIRED_TABLES: Final[tuple[str, ...]] = (
    "event_labels",
    "labeling_runs",
    "window_labels",
)
_REQUIRED_EVENT_CONSTRAINTS: Final[tuple[str, ...]] = (
    "ck_mb7_event_benign_rule",
    "ck_mb7_event_disposition",
    "ck_mb7_event_monday_partition",
    "ck_mb7_event_no_attack_metadata",
    "ck_mb7_event_no_attack_on_benign_day",
    "ck_mb7_event_unknown_has_no_rule",
)
_REQUIRED_WINDOW_CONSTRAINTS: Final[tuple[str, ...]] = (
    "ck_mb7_window_any_attack_ambiguous",
    "ck_mb7_window_any_attack_benign",
    "ck_mb7_window_any_attack_unknown",
    "ck_mb7_window_counts_cover",
    "ck_mb7_window_monday_partition",
    "ck_mb7_window_no_attack_on_benign_day",
    "ck_mb7_window_outside_never_benign",
)


class MondayBenignDuplicateVerifiedLabelingError(MondayBenignLabelingError):
    """A verified MB7 labeling of this evidence already exists."""


def _source_text(source: Any) -> str:
    """Serialize the M5 AuthoritativeSource model to canonical JSON text.

    ``AuthoritativeSource`` is a structured model (name, url, retrieved_at), not
    a string. Storing its canonical JSON keeps the full provenance auditable in
    one TEXT column without inventing a flattened representation.
    """
    import json as _json

    return _json.dumps(
        source.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def _strip_sql_comments(ddl: str) -> str:
    """Return the DDL with ``--`` line comments removed."""
    out = []
    for line in ddl.splitlines():
        marker = line.find("--")
        out.append(line if marker == -1 else line[:marker])
    return "\n".join(out)


def ensure_mb7_schema(conn) -> None:
    """Apply schema_mb7.sql. Every statement is CREATE ... IF NOT EXISTS."""
    ddl = MB7_DDL_FILE.read_text(encoding="utf-8")
    executable = _strip_sql_comments(ddl)
    for forbidden in ("m4_canonical", "m6_canonical", "mb4_canonical", "mb6_canonical"):
        if forbidden in executable:
            raise MondayBenignLabelingError(
                f"MB7 DDL must never reference {forbidden} in a statement"
            )
    with conn.cursor() as cur:
        cur.execute(ddl)
    conn.commit()


def verify_mb7_schema(conn) -> None:
    """Prove the target schema matches the MB7 contract before any insert."""
    with conn.cursor() as cur:
        cur.execute(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema = %s ORDER BY table_name",
            (MB7_SCHEMA,),
        )
        tables = tuple(row[0] for row in cur.fetchall())
        if tables != _REQUIRED_TABLES:
            raise MondayBenignLabelingError(
                f"MB7 tables mismatch: expected {_REQUIRED_TABLES}, found {tables}"
            )
        for table, required in (
            ("event_labels", _REQUIRED_EVENT_CONSTRAINTS),
            ("window_labels", _REQUIRED_WINDOW_CONSTRAINTS),
        ):
            cur.execute(
                "SELECT conname FROM pg_constraint WHERE conrelid = %s::regclass",
                (f"{MB7_SCHEMA}.{table}",),
            )
            present = {row[0] for row in cur.fetchall()}
            missing = tuple(n for n in required if n not in present)
            if missing:
                raise MondayBenignLabelingError(
                    f"MB7 {table} is missing constraints: {missing}"
                )
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
            (MB7_SCHEMA,),
        )
        offending = tuple(
            (name, schema)
            for name, schema in cur.fetchall()
            if schema != MB7_SCHEMA
        )
        if offending:
            raise MondayBenignLabelingError(
                f"MB7 foreign keys must stay inside {MB7_SCHEMA}: {offending}"
            )


_INSERT_RUN_SQL = f"""
INSERT INTO {MB7_SCHEMA}.labeling_runs (
    run_id, mb7_protocol_sha256, mb3_report_content_sha256,
    mb4_report_content_sha256, mb6_report_content_sha256,
    mb6_window_stream_sha256, mb4_run_id, mb6_run_id, mb7_label_namespace,
    m5_manifest_hash, m5_rule_version, m5_authoritative_source, m5_timezone,
    status, started_at
) VALUES (
    %(run_id)s, %(mb7_protocol_sha256)s, %(mb3_report_content_sha256)s,
    %(mb4_report_content_sha256)s, %(mb6_report_content_sha256)s,
    %(mb6_window_stream_sha256)s, %(mb4_run_id)s, %(mb6_run_id)s,
    %(mb7_label_namespace)s,
    %(m5_manifest_hash)s, %(m5_rule_version)s, %(m5_authoritative_source)s,
    %(m5_timezone)s, %(status)s, %(started_at)s
)
"""

_UPDATE_RUN_SQL = f"""
UPDATE {MB7_SCHEMA}.labeling_runs
SET status = %(status)s, completed_at = %(completed_at)s,
    total_event_label_count = %(total_event_label_count)s,
    total_window_label_count = %(total_window_label_count)s,
    event_label_stream_sha256 = %(event_label_stream_sha256)s,
    window_label_stream_sha256 = %(window_label_stream_sha256)s
WHERE run_id = %(run_id)s
"""

_CHECK_VERIFIED_SQL = f"""
SELECT run_id FROM {MB7_SCHEMA}.labeling_runs
WHERE mb7_protocol_sha256 = %(protocol)s AND mb6_run_id = %(mb6_run_id)s
  AND status = 'verified'
"""

_CHECK_ANY_SQL = f"""
SELECT run_id, status FROM {MB7_SCHEMA}.labeling_runs WHERE run_id = %(run_id)s
"""

_INSERT_EVENT_LABEL_SQL = f"""
INSERT INTO {MB7_SCHEMA}.event_labels (
    label_id, mb7_run_id, source_event_id, output_partition,
    disposition, attack_family, attack_subtype, target_profiles,
    matched_rule_ids, matched_direction, reason,
    rule_version, rule_hash, manifest_hash, authoritative_source, timezone
) VALUES (
    %(label_id)s, %(mb7_run_id)s, %(source_event_id)s, %(output_partition)s,
    %(disposition)s, %(attack_family)s, %(attack_subtype)s, %(target_profiles)s,
    %(matched_rule_ids)s, %(matched_direction)s, %(reason)s,
    %(rule_version)s, %(rule_hash)s, %(manifest_hash)s,
    %(authoritative_source)s, %(timezone)s
)
"""

_INSERT_WINDOW_LABEL_SQL = f"""
INSERT INTO {MB7_SCHEMA}.window_labels (
    label_id, mb7_run_id, source_window_id, output_partition,
    disposition, aggregation_rule, source_event_count,
    benign_reference_event_count, unknown_event_count,
    ambiguous_event_count, attack_event_count,
    window_start_time, window_end_time, inside_compiled_interval,
    rule_version, rule_hash, manifest_hash, authoritative_source, timezone
) VALUES (
    %(label_id)s, %(mb7_run_id)s, %(source_window_id)s, %(output_partition)s,
    %(disposition)s, %(aggregation_rule)s, %(source_event_count)s,
    %(benign_reference_event_count)s, %(unknown_event_count)s,
    %(ambiguous_event_count)s, %(attack_event_count)s,
    %(window_start_time)s, %(window_end_time)s, %(inside_compiled_interval)s,
    %(rule_version)s, %(rule_hash)s, %(manifest_hash)s,
    %(authoritative_source)s, %(timezone)s
)
"""


@dataclass(slots=True)
class MondayBenignLabelingOutcome:
    """Accumulated MB7 labeling evidence."""

    run_id: str
    event_labels: int = 0
    window_labels: int = 0
    event_dispositions: Counter = field(default_factory=Counter)
    window_dispositions: Counter = field(default_factory=Counter)
    windows_before_interval: int = 0
    windows_after_interval: int = 0
    windows_inside_interval: int = 0
    windows_outside_interval: int = 0
    inside_by_disposition: Counter = field(default_factory=Counter)
    outside_by_disposition: Counter = field(default_factory=Counter)
    earliest_window_start: str = ""
    latest_window_start: str = ""
    event_label_stream_sha256: str = ""
    window_label_stream_sha256: str = ""
    started_at: datetime | None = None
    completed_at: datetime | None = None


class MondayBenignLabelingRunner:
    """Apply the frozen M5 v1 policy to MB4 events and MB6 windows."""

    def __init__(
        self,
        bound: BoundMondayBenignLabelingSpecification,
        expected_database: str,
    ) -> None:
        self._bound = bound
        self._expected_database = expected_database

    def _assert_database(self, conn) -> None:
        with conn.cursor() as cur:
            cur.execute("SELECT current_database()")
            row = cur.fetchone()
        actual = row[0] if row else None
        if actual != self._expected_database:
            raise MondayBenignLabelingError(
                f"MB7 refuses to write: connected to {actual!r}, "
                f"expected {self._expected_database!r}"
            )

    def compute(self, conn) -> tuple[
        dict[str, EventLabel], list[dict[str, Any]], MondayBenignLabelingOutcome
    ]:
        """Label every MB4 event and aggregate every MB6 window. Read-only."""
        bound = self._bound
        adapter = bound.adapter
        outcome = MondayBenignLabelingOutcome(run_id=bound.run_id)

        labels: dict[str, EventLabel] = {}
        event_digest = sha256()
        with conn.cursor(name="mb7_events") as cur:
            cur.itersize = 20_000
            cur.execute(
                f"SELECT {MB4_EVENT_COLUMNS} FROM mb4_canonical.flow_end_events "
                "WHERE output_partition = %(p)s ORDER BY event_id",
                {"p": MONDAY_OUTPUT_PARTITION},
            )
            for row in cur:
                if row[1] != MONDAY_OUTPUT_PARTITION:
                    raise MondayBenignLabelingError(
                        f"MB7 refuses a non-Monday event row: {row[1]}"
                    )
                event = flow_end_from_mb4_row(row)
                label = adapter.assign(event)
                if str(label.event_id) != str(row[0]):
                    raise MondayBenignLabelingError(
                        "MB7 label event_id diverges from the MB4 event_id; "
                        "no identity may be regenerated"
                    )
                if label.disposition in ("target_attack", "known_other_attack"):
                    raise MondayBenignLabelingError(
                        "MB7 observed an attack disposition on the Monday benign "
                        f"day for event {row[0]}: {label.disposition}"
                    )
                labels[str(row[0])] = label
                outcome.event_dispositions[label.disposition] += 1
                event_digest.update(canonical_event_label_bytes(label))
        outcome.event_labels = len(labels)
        outcome.event_label_stream_sha256 = event_digest.hexdigest()
        if outcome.event_labels != bound.expected_event_count:
            raise MondayBenignLabelingError(
                f"MB7 labelled {outcome.event_labels} events but MB4 published "
                f"{bound.expected_event_count}"
            )

        window_rows: list[dict[str, Any]] = []
        window_digest = sha256()
        provenance = bound.ledger  # provenance values come from the ledger
        manifest_hash = provenance.manifest_hash
        rule_version = provenance.manifest.rule_version
        authoritative_source = _source_text(provenance.manifest.authoritative_source)
        tz = provenance.manifest.timezone
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT w.window_id, w.output_partition,
                       w.window_start_time::text, w.window_end_time::text,
                       w.source_event_count,
                       array_agg(s.source_event_id::text ORDER BY s.source_event_id)
                FROM mb6_canonical.feature_windows w
                JOIN mb6_canonical.feature_window_sources s
                  ON s.window_id = w.window_id
                GROUP BY w.window_id, w.output_partition, w.window_start_time,
                         w.window_end_time, w.source_event_count
                ORDER BY w.window_id
                """
            )
            for wid, part, ws, we, nev, sources in cur:
                if part != MONDAY_OUTPUT_PARTITION:
                    raise MondayBenignLabelingError(
                        f"MB7 refuses a non-Monday window row: {part}"
                    )
                if len(sources) != nev:
                    raise MondayBenignLabelingError(
                        f"MB6 window {wid} lineage count disagrees with "
                        "source_event_count"
                    )
                dispositions = []
                for source_id in sources:
                    label = labels.get(source_id)
                    if label is None:
                        raise MondayBenignLabelingError(
                            f"MB6 window {wid} references unlabelled event "
                            f"{source_id}"
                        )
                    dispositions.append(label.disposition)
                disposition = aggregate_window_disposition(dispositions)
                counts = Counter(dispositions)
                attack = counts["target_attack"] + counts["known_other_attack"]
                if attack:
                    raise MondayBenignLabelingError(
                        f"MB7 observed an attack window on the benign day: {wid}"
                    )
                start_epoch = int(float(ws))
                inside = (
                    MONDAY_RULE_START_EPOCH <= start_epoch < MONDAY_RULE_END_EPOCH
                )
                # The only absolute invariants are: no attack on the benign day,
                # and no promotion of uncertainty to benign. `ambiguous` is a
                # legitimate third outcome: an event whose exact interval crosses
                # the rule boundary yields `partial` -> `ambiguous` in frozen M5,
                # and ANY_ATTACK ranks `ambiguous` above both `unknown` and
                # `benign_reference`. A window outside the interval can therefore
                # never be benign, but a window inside it is benign only when
                # every one of its events resolved cleanly.
                if not inside and disposition == "benign_reference":
                    raise MondayBenignLabelingError(
                        f"window {wid} is outside the compiled interval but "
                        "resolved to benign_reference; unknown is never promoted"
                    )
                if counts["unknown"] and disposition == "benign_reference":
                    raise MondayBenignLabelingError(
                        f"window {wid} contains unknown events but resolved to "
                        "benign_reference"
                    )
                if inside:
                    outcome.windows_inside_interval += 1
                    outcome.inside_by_disposition[disposition] += 1
                else:
                    outcome.windows_outside_interval += 1
                    outcome.outside_by_disposition[disposition] += 1
                if start_epoch < MONDAY_RULE_START_EPOCH:
                    outcome.windows_before_interval += 1
                elif start_epoch >= MONDAY_RULE_END_EPOCH:
                    outcome.windows_after_interval += 1
                if not outcome.earliest_window_start or ws < outcome.earliest_window_start:
                    outcome.earliest_window_start = ws
                if ws > outcome.latest_window_start:
                    outcome.latest_window_start = ws
                outcome.window_dispositions[disposition] += 1
                row = {
                    "label_id": str(
                        derive_window_label_id(
                            bound.protocol_sha256, manifest_hash, wid
                        )
                    ),
                    "mb7_run_id": bound.run_id,
                    "source_window_id": str(wid),
                    "output_partition": part,
                    "disposition": disposition,
                    "aggregation_rule": "any_attack",
                    "source_event_count": nev,
                    "benign_reference_event_count": counts["benign_reference"],
                    "unknown_event_count": counts["unknown"],
                    "ambiguous_event_count": counts["ambiguous"],
                    "attack_event_count": 0,
                    "window_start_time": ws,
                    "window_end_time": we,
                    "inside_compiled_interval": inside,
                    "rule_version": rule_version,
                    "rule_hash": (
                        provenance.rule_hash("monday-benign-reference")
                        if disposition == "benign_reference"
                        else labels[sources[0]].provenance.rule_hash
                    ),
                    "manifest_hash": manifest_hash,
                    "authoritative_source": authoritative_source,
                    "timezone": tz,
                }
                window_rows.append(row)
                window_digest.update(
                    (
                        "|".join(
                            (
                                row["label_id"],
                                row["source_window_id"],
                                row["disposition"],
                                str(row["source_event_count"]),
                                row["window_start_time"],
                            )
                        )
                        + "\n"
                    ).encode("utf-8")
                )
        outcome.window_labels = len(window_rows)
        outcome.window_label_stream_sha256 = window_digest.hexdigest()
        if outcome.window_labels != bound.expected_window_count:
            raise MondayBenignLabelingError(
                f"MB7 labelled {outcome.window_labels} windows but MB6 published "
                f"{bound.expected_window_count}"
            )
        return labels, window_rows, outcome

    def materialize(self, conn) -> MondayBenignLabelingOutcome:
        """Persist event and window labels into mb7_canonical."""
        self._assert_database(conn)
        verify_mb7_schema(conn)
        bound = self._bound

        with conn.cursor() as cur:
            cur.execute(
                _CHECK_VERIFIED_SQL,
                {"protocol": bound.protocol_sha256, "mb6_run_id": bound.mb6_run_id},
            )
            existing = cur.fetchone()
        if existing is not None:
            raise MondayBenignDuplicateVerifiedLabelingError(
                "a verified MB7 labeling of this evidence already exists: "
                f"run_id={existing[0]}"
            )
        with conn.cursor() as cur:
            cur.execute(_CHECK_ANY_SQL, {"run_id": bound.run_id})
            prior = cur.fetchone()
        if prior is not None:
            raise MondayBenignLabelingError(
                f"MB7 run_id {bound.run_id} already exists with status "
                f"{prior[1]!r}. The run identity is deterministic, so a prior "
                "attempt must be resolved by the owner rather than overwritten."
            )

        labels, window_rows, outcome = self.compute(conn)
        started_at = datetime.now(timezone.utc)
        outcome.started_at = started_at
        ledger = bound.ledger
        with conn.cursor() as cur:
            cur.execute(
                _INSERT_RUN_SQL,
                {
                    "run_id": bound.run_id,
                    "mb7_protocol_sha256": bound.protocol_sha256,
                    "mb3_report_content_sha256": bound.mb3_report_content_sha256,
                    "mb4_report_content_sha256": bound.mb4_report_content_sha256,
                    "mb6_report_content_sha256": bound.mb6_report_content_sha256,
                    "mb6_window_stream_sha256": bound.mb6_window_stream_sha256,
                    "mb4_run_id": bound.mb4_run_id,
                    "mb6_run_id": bound.mb6_run_id,
                    "mb7_label_namespace": str(MB7_LABEL_NAMESPACE),
                    "m5_manifest_hash": ledger.manifest_hash,
                    "m5_rule_version": ledger.manifest.rule_version,
                    "m5_authoritative_source": _source_text(
                        ledger.manifest.authoritative_source
                    ),
                    "m5_timezone": ledger.manifest.timezone,
                    "status": "running",
                    "started_at": started_at,
                },
            )
        conn.commit()

        try:
            with conn.cursor() as cur:
                batch: list[dict[str, Any]] = []
                for event_id, label in labels.items():
                    batch.append(
                        {
                            "label_id": str(
                                derive_event_label_id(
                                    bound.protocol_sha256,
                                    ledger.manifest_hash,
                                    event_id,
                                )
                            ),
                            "mb7_run_id": bound.run_id,
                            "source_event_id": event_id,
                            "output_partition": MONDAY_OUTPUT_PARTITION,
                            "disposition": label.disposition,
                            "attack_family": label.attack_family,
                            "attack_subtype": label.attack_subtype,
                            "target_profiles": list(label.target_profiles),
                            "matched_rule_ids": list(label.matched_rule_ids),
                            "matched_direction": label.matched_direction,
                            "reason": label.reason,
                            "rule_version": label.provenance.rule_version,
                            "rule_hash": label.provenance.rule_hash,
                            "manifest_hash": label.provenance.manifest_hash,
                            "authoritative_source": _source_text(
                                label.provenance.authoritative_source
                            ),
                            "timezone": label.provenance.timezone,
                        }
                    )
                    if len(batch) >= _BATCH:
                        cur.executemany(_INSERT_EVENT_LABEL_SQL, batch)
                        batch.clear()
                if batch:
                    cur.executemany(_INSERT_EVENT_LABEL_SQL, batch)
                for start in range(0, len(window_rows), _BATCH):
                    cur.executemany(
                        _INSERT_WINDOW_LABEL_SQL,
                        window_rows[start : start + _BATCH],
                    )
            conn.commit()
            completed_at = datetime.now(timezone.utc)
            outcome.completed_at = completed_at
            with conn.cursor() as cur:
                cur.execute(
                    _UPDATE_RUN_SQL,
                    {
                        "run_id": bound.run_id,
                        "status": "verified",
                        "completed_at": completed_at,
                        "total_event_label_count": outcome.event_labels,
                        "total_window_label_count": outcome.window_labels,
                        "event_label_stream_sha256": (
                            outcome.event_label_stream_sha256
                        ),
                        "window_label_stream_sha256": (
                            outcome.window_label_stream_sha256
                        ),
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
                            "total_event_label_count": outcome.event_labels,
                            "total_window_label_count": outcome.window_labels,
                            "event_label_stream_sha256": None,
                            "window_label_stream_sha256": None,
                        },
                    )
                conn.commit()
            except Exception:  # pragma: no cover - best-effort audit trail
                conn.rollback()
            raise
        return outcome

    def build_report(
        self, outcome: MondayBenignLabelingOutcome
    ) -> MondayBenignLabelingRunReport:
        """Bind a successful outcome to the immutable MB7 report contract."""
        bound = self._bound
        specification = bound.specification
        ledger = bound.ledger
        now = datetime.now(timezone.utc)
        return MondayBenignLabelingRunReport(
            report_version=MB7_REPORT_VERSION,
            verification_status="verified",
            track="monday_benign",
            run_id=UUID(outcome.run_id),
            run_id_derivation=(
                "deterministic_uuid5_over_protocol_and_mb6_run_id"
            ),
            protocol_sha256=bound.protocol_sha256,
            mb3_report_content_sha256=bound.mb3_report_content_sha256,
            mb4_report_content_sha256=bound.mb4_report_content_sha256,
            mb4_run_id=UUID(bound.mb4_run_id),
            mb6_report_content_sha256=bound.mb6_report_content_sha256,
            mb6_run_id=UUID(bound.mb6_run_id),
            mb6_window_stream_sha256=bound.mb6_window_stream_sha256,
            label_identity_namespace=MB7_LABEL_NAMESPACE,
            target_database=self._expected_database,
            target_schema=MB7_SCHEMA,
            output_partition=MONDAY_OUTPUT_PARTITION,
            dataset_name=specification.dataset_name,
            policy=specification.policy,
            label_provenance=ledger._provenance(  # noqa: SLF001
                ledger.rule_hash("monday-benign-reference")
            ),
            total_event_label_count=outcome.event_labels,
            total_window_label_count=outcome.window_labels,
            event_disposition_counts=tuple(
                MondayBenignDispositionCount(disposition=name, count=count)
                for name, count in sorted(outcome.event_dispositions.items())
            ),
            window_disposition_counts=tuple(
                MondayBenignDispositionCount(disposition=name, count=count)
                for name, count in sorted(outcome.window_dispositions.items())
            ),
            unknown_window_interval_split=MondayBenignIntervalSplit(
                windows_inside_interval=outcome.windows_inside_interval,
                windows_outside_interval=outcome.windows_outside_interval,
                windows_before_interval=outcome.windows_before_interval,
                windows_after_interval=outcome.windows_after_interval,
                inside_benign_reference=outcome.inside_by_disposition[
                    'benign_reference'
                ],
                inside_ambiguous=outcome.inside_by_disposition['ambiguous'],
                outside_unknown=outcome.outside_by_disposition['unknown'],
                outside_ambiguous=outcome.outside_by_disposition['ambiguous'],
                earliest_window_start_time=outcome.earliest_window_start,
                latest_window_start_time=outcome.latest_window_start,
            ),
            event_label_stream_sha256=outcome.event_label_stream_sha256,
            window_label_stream_sha256=outcome.window_label_stream_sha256,
            started_at=outcome.started_at or now,
            completed_at=outcome.completed_at or now,
        )


def write_immutable_mb7_report(
    report: MondayBenignLabelingRunReport,
    path: str | Path,
) -> str:
    """Publish the MB7 report immutably; return the written-byte hash."""
    destination = Path(path)
    if destination.exists():
        raise FileExistsError(f"MB7 report already exists: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = report.model_dump_json(indent=2).encode("utf-8") + b"\n"
    temporary = destination.with_name(f".{destination.name}.tmp")
    if temporary.exists():
        raise FileExistsError(f"MB7 report staging path exists: {temporary}")
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
