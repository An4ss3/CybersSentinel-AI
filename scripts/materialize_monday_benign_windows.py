"""Freeze the MB6 protocol and materialize Monday Benign feature windows.

Source of truth
---------------
Windows are built from ``mb4_canonical.flow_end_events`` only. The PCAP and the
Zeek logs are never opened: MB4 is the canonical event source, as the MB6
protocol declares.

Manifest derivation
-------------------
The MB6 manifest reuses the frozen M6 manifest's **policy blocks** verbatim --
temporal, window geometry, entity, features, provenance, labels, deferred,
contract versions and authoritative sources -- so MB6 window semantics are
provably identical to M6 rather than retyped and possibly divergent. That file is
read **read-only** and never modified. Only the identity surface changes: MB
upstream hashes, the Monday partition, the MB6 namespace, the MB operational
source and projection, the MB partition-order label, and a governance block that
forbids the ``uuid4`` run identity M6 permitted.

Database
--------
MB6 reads MB4 and writes MB6, both inside one database passed explicitly. **MB6
never needs M6 or ``m4_canonical``**, so no cross-database access arises here.
The need to co-locate M and MB is purely a future ML-dataset concern and nothing
is moved or re-materialized by this script.

Modes
-----
``--preflight`` reports state and verifies every gate without writing anything.
``--recompute-only`` rebuilds every window and digest, writing nothing.
Default freezes the manifest, materializes, and publishes the immutable report.
"""
from __future__ import annotations

import argparse
from collections.abc import Sequence
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
from typing import Any, Final

import yaml

from modules.detection.src.lineage.dataset_freeze import _write_immutable_bytes
from modules.detection.src.lineage.monday_benign_feature_window import (
    load_and_bind_monday_benign_feature_window_specification,
)
from modules.detection.src.lineage.monday_benign_normalization import (
    load_and_bind_monday_benign_normalization_specification,
)
from modules.detection.src.persistence.monday_benign_persistence import (
    MB4_REPORT_RELATIVE_PATH,
    MondayBenignMaterializationReport,
    get_monday_benign_connection,
)
from modules.detection.src.persistence.monday_benign_window_persistence import (
    MondayBenignWindowRunner,
    ensure_mb6_schema,
    verify_mb6_schema,
    write_immutable_mb6_report,
)
from modules.detection.src.schemas.monday_benign_feature_window import (
    MB6_NAMESPACE_DERIVATION_NAME,
    MB6_PROTOCOL_RELATIVE_PATH,
    MB6_REPORT_RELATIVE_PATH,
    MB6_SCHEMA,
    MB6_WINDOW_ID_NAMESPACE,
    MondayBenignFeatureWindowSpecification,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
M6_MANIFEST_RELATIVE_PATH: Final[str] = (
    "datasets/manifests/cicids2017_feature_window_v2.yaml"
)
_REUSED_POLICY_BLOCKS: Final[tuple[str, ...]] = (
    "window_contract_versions",
    "temporal",
    "window",
    "entity",
    "features",
    "provenance",
    "labels",
    "deferred",
    "authoritative_sources",
)


def parse_utc_datetime(value: str) -> datetime:
    """Parse an explicit UTC timestamp without silently converting timezones."""
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid timestamp: {value}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(None):
        raise argparse.ArgumentTypeError("timestamp must be explicit UTC")
    return parsed


def build_specification(
    repository_root: Path,
    *,
    frozen_at: datetime,
) -> MondayBenignFeatureWindowSpecification:
    """Build the MB6 protocol from published MB evidence and M6 policy blocks."""
    m6_manifest = yaml.safe_load(
        (repository_root / M6_MANIFEST_RELATIVE_PATH).read_text(encoding="utf-8")
    )
    missing = tuple(
        name for name in _REUSED_POLICY_BLOCKS if name not in m6_manifest
    )
    if missing:
        raise ValueError(f"frozen M6 manifest lacks policy blocks: {missing}")

    mb3 = load_and_bind_monday_benign_normalization_specification(repository_root)
    mb4_bytes = (repository_root / MB4_REPORT_RELATIVE_PATH).read_bytes()
    mb4 = MondayBenignMaterializationReport.model_validate_json(
        mb4_bytes.decode("utf-8")
    )

    identity = dict(m6_manifest["identity"])
    identity["namespace"] = str(MB6_WINDOW_ID_NAMESPACE)
    identity["namespace_derivation"] = MB6_NAMESPACE_DERIVATION_NAME

    payload: dict[str, Any] = {
        "protocol_version": "2.0.0",
        "milestone": "mb6",
        "track": "monday_benign",
        "frozen_at": frozen_at.isoformat().replace("+00:00", "Z"),
        "dataset_name": mb3.specification.dataset_name,
        "mb1_manifest_sha256": mb3.m1_manifest_sha256,
        "mb2_specification_sha256": mb3.mb2_specification_sha256,
        "mb2_replay_report_content_sha256": mb3.mb2_replay_report_content_sha256,
        "mb3_protocol_sha256": mb3.specification_sha256,
        "mb3_report_content_sha256": mb4.mb3_report_content_sha256,
        "mb3_report_file_sha256": mb4.mb3_report_file_sha256,
        "mb3_event_stream_sha256": mb4.mb3_event_stream_sha256,
        "mb3_rejection_audit_stream_sha256": (
            mb4.mb3_rejection_audit_stream_sha256
        ),
        "mb4_report_content_sha256": mb4.content_sha256(),
        "mb4_report_file_sha256": sha256(mb4_bytes).hexdigest(),
        "mb4_run_id": str(mb4.run_id),
        "output_partition": mb4.output_partition,
        "source_event_model": "FlowEndV2",
        "source_event_feature_version": "1.0.0",
        "operational_source": "mb4_canonical.flow_end_events",
        "evidence_source": "mb2_monday_conn_log_via_mb3_protocol",
        "postgresql_is_independent_evidence": False,
        "target_model": "FeatureWindowV2",
        "m_chain_status": "untouched_and_frozen",
        "identity": identity,
        "ordering": {
            "keys": [
                "output_partition",
                "entity_type",
                "entity_key",
                "window_start_time",
            ],
            "partition_order": "mb3_replay_report_binding_order",
            "window_start_comparison": "unscaled_integer",
            "sort_by_feature_value": False,
            "dictionary_or_set_iteration_order": "forbidden",
        },
        "persistence": {
            "canonical_evidence": "immutable_published_report",
            "operational_projection": "postgresql_schema_mb6_canonical",
            "projection_is_reconstructible": True,
            "destructive_modification_of_mb4_canonical": "forbidden",
            "destructive_modification_of_m_chain": "forbidden",
            "foreign_keys_outside_mb6_canonical": "forbidden",
            "test_isolation": "read_only_tests_against_the_mb_database",
        },
        "governance": {
            "manifest_frozen_before_materialization": True,
            "run_identity_in_manifest": False,
            "run_identity_location": "materialization_report_only",
            "run_identity_algorithm": (
                "deterministic_uuid5_over_protocol_and_mb4_run_id"
            ),
            "random_identifiers": "forbidden",
            "wall_clock_in_identity": "forbidden",
            "immutable_publication": "fail_if_exists_fsync_atomic_rename",
            "deterministic_rerun_requirement": "identical_content_sha256",
        },
    }
    for name in _REUSED_POLICY_BLOCKS:
        payload[name] = m6_manifest[name]

    return MondayBenignFeatureWindowSpecification.model_validate_json(
        json.dumps(payload, default=str)
    )


def _preflight(database: str) -> dict[str, Any]:
    """Collect read-only MB6 preflight evidence."""
    state: dict[str, Any] = {"target_database": database}
    protocol_path = REPO_ROOT / MB6_PROTOCOL_RELATIVE_PATH
    state["mb6_protocol_published"] = protocol_path.is_file()
    state["mb6_report_published"] = (
        REPO_ROOT / MB6_REPORT_RELATIVE_PATH
    ).is_file()

    mb4_bytes = (REPO_ROOT / MB4_REPORT_RELATIVE_PATH).read_bytes()
    mb4 = MondayBenignMaterializationReport.model_validate_json(
        mb4_bytes.decode("utf-8")
    )
    state["mb4_run_id"] = str(mb4.run_id)
    state["mb4_report_content_sha256"] = mb4.content_sha256()
    state["mb4_persisted_event_count"] = mb4.persisted_event_count
    state["mb4_target_database"] = mb4.target_database
    state["output_partition"] = mb4.output_partition
    state["mb6_window_id_namespace"] = str(MB6_WINDOW_ID_NAMESPACE)

    conn = get_monday_benign_connection(database)
    try:
        with conn.cursor() as cur:
            cur.execute("SET default_transaction_read_only = on")
            cur.execute("SELECT current_database()")
            state["current_database"] = cur.fetchone()[0]
            cur.execute(
                "SELECT count(*) FROM mb4_canonical.flow_end_events "
                "WHERE output_partition = %s",
                (mb4.output_partition,),
            )
            state["mb4_events_available"] = cur.fetchone()[0]
            cur.execute(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema = %s ORDER BY table_name",
                (MB6_SCHEMA,),
            )
            state["mb6_tables"] = [row[0] for row in cur.fetchall()]
            if state["mb6_tables"]:
                cur.execute(
                    f"SELECT (SELECT count(*) FROM {MB6_SCHEMA}.materialization_runs), "
                    f"(SELECT count(*) FROM {MB6_SCHEMA}.feature_windows), "
                    f"(SELECT count(*) FROM {MB6_SCHEMA}.feature_window_sources)"
                )
                runs, windows, lineage = cur.fetchone()
                state["mb6_existing_counts"] = {
                    "materialization_runs": runs,
                    "feature_windows": windows,
                    "feature_window_sources": lineage,
                }
    finally:
        conn.close()
    return state


def main(argv: Sequence[str] | None = None) -> int:
    """Freeze MB6, materialize windows, publish the immutable report."""
    parser = argparse.ArgumentParser(
        description="Materialize Monday Benign feature windows from MB4."
    )
    parser.add_argument("--database", required=True)
    parser.add_argument("--frozen-at", type=parse_utc_datetime, default=None)
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument("--recompute-only", action="store_true")
    parser.add_argument(
        "--publish-from-verified-run",
        action="store_true",
        help=(
            "recompute every window read-only, cross-check the result against "
            "the stored verified run row, then publish the report. Used when "
            "materialization succeeded but report publication did not."
        ),
    )
    args = parser.parse_args(argv)

    state = _preflight(args.database)
    if args.preflight:
        state["status"] = "preflight_ok"
        print(json.dumps(state, indent=2, sort_keys=True))
        return 0

    protocol_path = REPO_ROOT / MB6_PROTOCOL_RELATIVE_PATH
    if not protocol_path.is_file():
        if args.frozen_at is None:
            raise SystemExit("--frozen-at is required to freeze the MB6 protocol")
        specification = build_specification(REPO_ROOT, frozen_at=args.frozen_at)
        _write_immutable_bytes(
            protocol_path,
            yaml.safe_dump(
                specification.model_dump(mode="json"),
                sort_keys=False,
                allow_unicode=False,
            ).encode("utf-8"),
        )

    bound = load_and_bind_monday_benign_feature_window_specification(REPO_ROOT)
    state.update(
        {
            "protocol_path": MB6_PROTOCOL_RELATIVE_PATH,
            "protocol_sha256": bound.protocol_sha256,
            "run_id": bound.run_id,
            "expected_source_event_count": bound.expected_source_event_count,
        }
    )
    runner = MondayBenignWindowRunner(bound, args.database)

    conn = get_monday_benign_connection(args.database)
    try:
        if args.recompute_only:
            with conn.cursor() as cur:
                cur.execute("SET default_transaction_read_only = on")
            outcome = runner.recompute_only(conn)
            state.update(
                {
                    "status": "recomputed_not_published",
                    "window_count": outcome.window_count,
                    "entity_count": outcome.entity_count,
                    "source_event_count": outcome.source_event_count,
                    "lineage_row_count": outcome.lineage_row_count,
                    "first_window_id": outcome.first_window_id,
                    "last_window_id": outcome.last_window_id,
                    "window_stream_sha256": outcome.window_stream_sha256,
                }
            )
            report = runner.build_report(outcome)
            state["report_content_sha256"] = report.content_sha256()
            print(json.dumps(state, indent=2, sort_keys=True))
            return 0

        ensure_mb6_schema(conn)
        verify_mb6_schema(conn)
        if args.publish_from_verified_run:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT run_id::text, status, total_source_event_count, "
                    "total_window_count, window_stream_sha256 "
                    "FROM mb6_canonical.materialization_runs "
                    "WHERE mb6_protocol_sha256 = %s",
                    (bound.protocol_sha256,),
                )
                stored = cur.fetchall()
            if len(stored) != 1:
                raise SystemExit(
                    f"expected exactly one MB6 run for this protocol, found "
                    f"{len(stored)}"
                )
            run_id, status, stored_events, stored_windows, stored_digest = stored[0]
            if status != "verified":
                raise SystemExit(f"stored MB6 run is {status!r}, not verified")
            if run_id != bound.run_id:
                raise SystemExit(
                    f"stored run_id {run_id} is not the deterministic derivation "
                    f"{bound.run_id}"
                )
            with conn.cursor() as cur:
                cur.execute("SET default_transaction_read_only = on")
            outcome = runner.recompute_only(conn)
            mismatches = {
                name: (recomputed, stored_value)
                for name, recomputed, stored_value in (
                    ("source_event_count", outcome.source_event_count, stored_events),
                    ("window_count", outcome.window_count, stored_windows),
                    (
                        "window_stream_sha256",
                        outcome.window_stream_sha256,
                        stored_digest,
                    ),
                )
                if recomputed != stored_value
            }
            if mismatches:
                raise SystemExit(
                    f"recomputed MB6 evidence disagrees with the stored run: "
                    f"{mismatches}"
                )
            state["cross_checked_against_stored_run"] = True
            report = runner.build_report(outcome)
        else:
            outcome = runner.materialize(conn)
            report = runner.build_report(outcome)
    finally:
        conn.close()

    report_file_sha256 = write_immutable_mb6_report(
        report, REPO_ROOT / MB6_REPORT_RELATIVE_PATH
    )
    state.update(
        {
            "status": "verified",
            "window_count": outcome.window_count,
            "entity_count": outcome.entity_count,
            "source_event_count": outcome.source_event_count,
            "lineage_row_count": outcome.lineage_row_count,
            "first_window_id": outcome.first_window_id,
            "last_window_id": outcome.last_window_id,
            "window_stream_sha256": outcome.window_stream_sha256,
            "report_path": MB6_REPORT_RELATIVE_PATH,
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
