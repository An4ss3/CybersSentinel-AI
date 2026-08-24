"""Materialize the MB3 Monday events into mb4_canonical.

The target database is a **required** argument. There is no default, so no
invocation can silently write to production. ``assert_expected_database`` compares
``current_database()`` against that argument before any write, and
``verify_mb4_schema`` proves the target tables match the MB4 contract before the
first insert.

Modes
-----
``--preflight`` reports state and verifies every gate without writing anything.
``--dry-run`` additionally applies the idempotent DDL and re-verifies the schema,
still without inserting a row.
Default runs the materialization and publishes the immutable MB4 report.
"""
from __future__ import annotations

import argparse
from collections.abc import Sequence
import json
from pathlib import Path

from modules.detection.src.lineage.monday_benign_normalization import (
    load_and_bind_monday_benign_normalization_specification,
)
from modules.detection.src.persistence.monday_benign_persistence import (
    MB4_REPORT_RELATIVE_PATH,
    MB4_SCHEMA,
    MondayBenignMaterializationAdapter,
    assert_expected_database,
    ensure_mb4_schema,
    get_monday_benign_connection,
    verify_frozen_mb3_report,
    verify_mb4_schema,
    write_immutable_mb4_report,
)


REPO_ROOT = Path(__file__).resolve().parents[1]


def _preflight(database: str) -> dict[str, object]:
    """Collect read-only MB4 preflight evidence."""
    bound = load_and_bind_monday_benign_normalization_specification(REPO_ROOT)
    verified = verify_frozen_mb3_report(REPO_ROOT)
    partition = verified.report.partition_reports[0]

    state: dict[str, object] = {
        "target_database": database,
        "mb3_protocol_sha256": bound.specification_sha256,
        "mb3_report_content_sha256": verified.report_content_sha256,
        "mb3_report_file_sha256": verified.report_file_sha256,
        "mb3_event_stream_sha256": verified.event_stream_sha256,
        "mb3_rejection_audit_stream_sha256": (
            verified.rejection_audit_stream_sha256
        ),
        "mb1_manifest_sha256": bound.m1_manifest_sha256,
        "mb2_specification_sha256": bound.mb2_specification_sha256,
        "mb2_replay_report_content_sha256": (
            bound.mb2_replay_report_content_sha256
        ),
        "output_partition": partition.output_partition,
        "expected_processed": partition.processed_record_count,
        "expected_accepted": partition.accepted_record_count,
        "expected_rejected": partition.rejected_record_count,
        "protocol_matches_report": (
            bound.specification_sha256 == verified.protocol_sha256
        ),
    }

    conn = get_monday_benign_connection(database)
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT current_database()")
            state["current_database"] = cur.fetchone()[0]
            cur.execute(
                "SELECT count(*) FROM information_schema.schemata "
                "WHERE schema_name = %s",
                (MB4_SCHEMA,),
            )
            state["mb4_schema_exists"] = cur.fetchone()[0] == 1
            cur.execute(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema = %s ORDER BY table_name",
                (MB4_SCHEMA,),
            )
            state["mb4_tables"] = [row[0] for row in cur.fetchall()]
            if state["mb4_tables"]:
                cur.execute(
                    f"SELECT (SELECT count(*) FROM {MB4_SCHEMA}.materialization_runs), "
                    f"(SELECT count(*) FROM {MB4_SCHEMA}.flow_end_events), "
                    f"(SELECT count(*) FROM {MB4_SCHEMA}.rejection_spans), "
                    f"(SELECT count(*) FROM {MB4_SCHEMA}.rejection_counts)"
                )
                runs, events, spans, counts = cur.fetchone()
                state["mb4_existing_counts"] = {
                    "materialization_runs": runs,
                    "flow_end_events": events,
                    "rejection_spans": spans,
                    "rejection_counts": counts,
                }
    finally:
        conn.close()
    return state


def main(argv: Sequence[str] | None = None) -> int:
    """Run MB4 preflight, dry run, or materialization."""
    parser = argparse.ArgumentParser(
        description="Materialize MB3 Monday events into mb4_canonical."
    )
    parser.add_argument(
        "--database",
        required=True,
        help="explicit target database; no default exists by design",
    )
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    state = _preflight(args.database)
    if args.preflight:
        state["status"] = "preflight_ok"
        print(json.dumps(state, indent=2, sort_keys=True))
        return 0

    conn = get_monday_benign_connection(args.database)
    try:
        assert_expected_database(conn, args.database)
        ensure_mb4_schema(conn)
        verify_mb4_schema(conn)
        if args.dry_run:
            state["status"] = "schema_applied_and_verified_no_rows_written"
            print(json.dumps(state, indent=2, sort_keys=True))
            return 0

        adapter = MondayBenignMaterializationAdapter.from_repository(
            REPO_ROOT, args.database
        )
        outcome = adapter.materialize(conn)
        report = adapter.build_report(outcome)
    finally:
        conn.close()

    report_file_sha256 = write_immutable_mb4_report(
        report, REPO_ROOT / MB4_REPORT_RELATIVE_PATH
    )
    state.update(
        {
            "status": "verified",
            "run_id": str(outcome.run_id),
            "processed": outcome.processed,
            "accepted": outcome.accepted,
            "rejected": outcome.rejected,
            "persisted_events": outcome.persisted_events,
            "persisted_rejection_spans": outcome.persisted_spans,
            "persisted_rejection_counts": outcome.persisted_counts,
            "rejection_counts": [
                {"reason": reason, "count": count}
                for reason, count in outcome.rejection_counts
            ],
            "materialized_event_stream_sha256": (
                outcome.materialized_event_stream_sha256
            ),
            "materialized_rejection_stream_sha256": (
                outcome.materialized_rejection_stream_sha256
            ),
            "digest_matches_mb3": (
                outcome.materialized_event_stream_sha256
                == state["mb3_event_stream_sha256"]
            ),
            "report_path": MB4_REPORT_RELATIVE_PATH,
            "report_content_sha256": report.content_sha256(),
            "report_file_sha256": report_file_sha256,
            "elapsed_seconds": round(
                (outcome.completed_at - outcome.started_at).total_seconds(), 1
            ),
        }
    )
    print(json.dumps(state, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
