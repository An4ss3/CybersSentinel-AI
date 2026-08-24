"""Freeze the MB7 protocol and label the Monday Benign track.

Applies the frozen M5 v1 policy to the 368,202 MB4 events and aggregates the
70,921 MB6 windows under the ratified ANY_ATTACK precedence. Labels are strictly
sidecar: nothing is written to MB4 or MB6, no identity is regenerated, and
``unknown`` is never converted to ``benign_reference``.

Modes
-----
``--preflight``      report state and verify every gate, writing nothing.
``--recompute-only`` recompute all labels and digests read-only, writing nothing.
default              freeze the protocol, materialize, publish the report.
"""
from __future__ import annotations

import argparse
from collections.abc import Sequence
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Final

import yaml

from modules.detection.src.lineage.dataset_freeze import _write_immutable_bytes
from modules.detection.src.lineage.monday_benign_feature_window import (
    load_and_bind_monday_benign_feature_window_specification,
)
from modules.detection.src.lineage.monday_benign_labeling import (
    M5_V1_MANIFEST_RELATIVE_PATH,
    MONDAY_RULE_ID,
    build_m5_v1_ledger,
    load_and_bind_monday_benign_labeling_specification,
)
from modules.detection.src.persistence.monday_benign_label_persistence import (
    MondayBenignLabelingRunner,
    ensure_mb7_schema,
    verify_mb7_schema,
    write_immutable_mb7_report,
)
from modules.detection.src.persistence.monday_benign_persistence import (
    MB4_REPORT_RELATIVE_PATH,
    MondayBenignMaterializationReport,
    get_monday_benign_connection,
)
from modules.detection.src.schemas.monday_benign_feature_window import (
    MB6_REPORT_RELATIVE_PATH,
    MondayBenignFeatureWindowRunReport,
)
from modules.detection.src.schemas.monday_benign_labeling import (
    MB7_LABEL_NAMESPACE,
    MB7_NAMESPACE_DERIVATION_NAME,
    MB7_PROTOCOL_RELATIVE_PATH,
    MB7_REPORT_RELATIVE_PATH,
    MB7_SCHEMA,
    MONDAY_RULE_END_EPOCH,
    MONDAY_RULE_START_EPOCH,
    MondayBenignLabelingSpecification,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
AUTHORITATIVE_SOURCES: Final[tuple[str, ...]] = (
    "https://www.unb.ca/cic/datasets/ids-2017.html",
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
    repository_root: Path, *, frozen_at: datetime
) -> MondayBenignLabelingSpecification:
    """Build the MB7 protocol from published MB evidence and the M5 v1 policy."""
    mb6 = load_and_bind_monday_benign_feature_window_specification(repository_root)
    mb6_report = MondayBenignFeatureWindowRunReport.model_validate_json(
        (repository_root / MB6_REPORT_RELATIVE_PATH).read_text(encoding="utf-8")
    )
    mb4_report = MondayBenignMaterializationReport.model_validate_json(
        (repository_root / MB4_REPORT_RELATIVE_PATH).read_text(encoding="utf-8")
    )
    ledger = build_m5_v1_ledger(repository_root)

    payload: dict[str, Any] = {
        "protocol_version": "1.0.0",
        "milestone": "mb7",
        "track": "monday_benign",
        "frozen_at": frozen_at.isoformat().replace("+00:00", "Z"),
        "dataset_name": mb6.specification.dataset_name,
        "output_partition": mb6.output_partition,
        "mb1_manifest_sha256": mb6.mb1_manifest_sha256,
        "mb2_specification_sha256": mb6.mb2_specification_sha256,
        "mb3_protocol_sha256": mb6.mb3_protocol_sha256,
        "mb3_report_content_sha256": mb4_report.mb3_report_content_sha256,
        "mb4_report_content_sha256": mb6.mb4_report_content_sha256,
        "mb4_run_id": mb6.mb4_run_id,
        "mb6_protocol_sha256": mb6.protocol_sha256,
        "mb6_report_content_sha256": mb6_report.content_sha256(),
        "mb6_run_id": str(mb6_report.run_id),
        "mb6_window_stream_sha256": mb6_report.window_stream_sha256,
        "event_source": "mb4_canonical.flow_end_events",
        "window_source": "mb6_canonical.feature_windows",
        "lineage_source": "mb6_canonical.feature_window_sources",
        "label_projection": "postgresql_schema_mb7_canonical",
        "sidecar_only": True,
        "modifies_mb4_or_mb6": False,
        "m_chain_status": "untouched_and_frozen",
        "policy": {
            "policy_version": "1.0.0",
            "policy_variant": "m5_v1_unchanged",
            "manifest_relative_path": M5_V1_MANIFEST_RELATIVE_PATH,
            "manifest_hash": ledger.manifest_hash,
            "rule_version": ledger.manifest.rule_version,
            "authoritative_source": (
                ledger.manifest.authoritative_source.model_dump(mode="json")
            ),
            "timezone": ledger.manifest.timezone,
            "applicable_rule_id": MONDAY_RULE_ID,
            "applicable_rule_hash": ledger.rule_hash(MONDAY_RULE_ID),
            "applicable_rule_mode": "any_network",
            "applicable_rule_disposition": "benign_reference",
            "compiled_interval_start_epoch_seconds": MONDAY_RULE_START_EPOCH,
            "compiled_interval_end_epoch_seconds": MONDAY_RULE_END_EPOCH,
            "m5_v2_injected": False,
            "unknown_to_benign_conversion": "forbidden",
            "ambiguous_to_benign_conversion": "forbidden",
            "ambiguous_to_unknown_conversion": "forbidden",
            "m5_v1_is_normative_source": True,
            "m5_v1_modified": False,
            "ambiguous_is_valid_disposition": True,
            "boundary_crossing_semantics": (
                "label_ledger_partial_overlap_yields_ambiguous"
            ),
            "ml_dataset_constructed": False,
        },
        "aggregation": {
            "rule": "any_attack",
            "precedence": [
                "target_attack",
                "known_other_attack",
                "ambiguous",
                "unknown",
                "benign_reference",
            ],
            "attack_dispositions": ["known_other_attack", "target_attack"],
            "uncertainty_to_benign": "forbidden",
        },
        "label_identity_algorithm": "uuid5",
        "label_identity_namespace": str(MB7_LABEL_NAMESPACE),
        "label_identity_namespace_derivation": MB7_NAMESPACE_DERIVATION_NAME,
        "event_label_identity_components": [
            "protocol_sha256",
            "m5_manifest_hash",
            "event_id",
        ],
        "window_label_identity_components": [
            "protocol_sha256",
            "m5_manifest_hash",
            "window_id",
        ],
        "run_identity_algorithm": (
            "deterministic_uuid5_over_protocol_and_mb6_run_id"
        ),
        "random_identifiers": "forbidden",
        "wall_clock_in_identity": "forbidden",
        "authoritative_sources": list(AUTHORITATIVE_SOURCES),
    }
    return MondayBenignLabelingSpecification.model_validate_json(
        json.dumps(payload, default=str)
    )


def _preflight(database: str) -> dict[str, Any]:
    """Collect read-only MB7 preflight evidence."""
    ledger = build_m5_v1_ledger(REPO_ROOT)
    state: dict[str, Any] = {
        "target_database": database,
        "mb7_protocol_published": (REPO_ROOT / MB7_PROTOCOL_RELATIVE_PATH).is_file(),
        "mb7_report_published": (REPO_ROOT / MB7_REPORT_RELATIVE_PATH).is_file(),
        "m5_policy_variant": "m5_v1_unchanged",
        "m5_manifest_hash": ledger.manifest_hash,
        "m5_rule_version": ledger.manifest.rule_version,
        "monday_rule_hash": ledger.rule_hash(MONDAY_RULE_ID),
        "compiled_interval": [MONDAY_RULE_START_EPOCH, MONDAY_RULE_END_EPOCH],
        "mb7_label_namespace": str(MB7_LABEL_NAMESPACE),
    }
    conn = get_monday_benign_connection(database)
    try:
        with conn.cursor() as cur:
            cur.execute("SET default_transaction_read_only = on")
            cur.execute("SELECT current_database()")
            state["current_database"] = cur.fetchone()[0]
            cur.execute(
                "SELECT (SELECT count(*) FROM mb4_canonical.flow_end_events), "
                "(SELECT count(*) FROM mb6_canonical.feature_windows), "
                "(SELECT count(*) FROM mb6_canonical.feature_window_sources)"
            )
            ev, win, lin = cur.fetchone()
            state["mb4_events"] = ev
            state["mb6_windows"] = win
            state["mb6_lineage"] = lin
            cur.execute(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema = %s ORDER BY table_name",
                (MB7_SCHEMA,),
            )
            state["mb7_tables"] = [r[0] for r in cur.fetchall()]
            if state["mb7_tables"]:
                cur.execute(
                    f"SELECT (SELECT count(*) FROM {MB7_SCHEMA}.labeling_runs), "
                    f"(SELECT count(*) FROM {MB7_SCHEMA}.event_labels), "
                    f"(SELECT count(*) FROM {MB7_SCHEMA}.window_labels)"
                )
                r, e, w = cur.fetchone()
                state["mb7_existing_counts"] = {
                    "labeling_runs": r,
                    "event_labels": e,
                    "window_labels": w,
                }
    finally:
        conn.close()
    return state


def main(argv: Sequence[str] | None = None) -> int:
    """Freeze MB7, label, publish the immutable report."""
    parser = argparse.ArgumentParser(
        description="Label the Monday Benign track with the frozen M5 v1 policy."
    )
    parser.add_argument("--database", required=True)
    parser.add_argument("--frozen-at", type=parse_utc_datetime, default=None)
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument("--recompute-only", action="store_true")
    args = parser.parse_args(argv)

    state = _preflight(args.database)
    if args.preflight:
        state["status"] = "preflight_ok"
        print(json.dumps(state, indent=2, sort_keys=True))
        return 0

    protocol_path = REPO_ROOT / MB7_PROTOCOL_RELATIVE_PATH
    if not protocol_path.is_file():
        if args.frozen_at is None:
            raise SystemExit("--frozen-at is required to freeze the MB7 protocol")
        specification = build_specification(REPO_ROOT, frozen_at=args.frozen_at)
        _write_immutable_bytes(
            protocol_path,
            yaml.safe_dump(
                specification.model_dump(mode="json"),
                sort_keys=False,
                allow_unicode=False,
            ).encode("utf-8"),
        )

    bound = load_and_bind_monday_benign_labeling_specification(REPO_ROOT)
    state.update(
        {
            "protocol_path": MB7_PROTOCOL_RELATIVE_PATH,
            "protocol_sha256": bound.protocol_sha256,
            "run_id": bound.run_id,
            "expected_event_count": bound.expected_event_count,
            "expected_window_count": bound.expected_window_count,
        }
    )
    runner = MondayBenignLabelingRunner(bound, args.database)

    conn = get_monday_benign_connection(args.database)
    try:
        if args.recompute_only:
            with conn.cursor() as cur:
                cur.execute("SET default_transaction_read_only = on")
            _, _, outcome = runner.compute(conn)
            state.update(
                {
                    "status": "recomputed_not_published",
                    "event_labels": outcome.event_labels,
                    "window_labels": outcome.window_labels,
                    "event_dispositions": dict(
                        sorted(outcome.event_dispositions.items())
                    ),
                    "window_dispositions": dict(
                        sorted(outcome.window_dispositions.items())
                    ),
                    "windows_before_interval": outcome.windows_before_interval,
                    "windows_after_interval": outcome.windows_after_interval,
                    "event_label_stream_sha256": (
                        outcome.event_label_stream_sha256
                    ),
                    "window_label_stream_sha256": (
                        outcome.window_label_stream_sha256
                    ),
                }
            )
            report = runner.build_report(outcome)
            state["report_content_sha256"] = report.content_sha256()
            print(json.dumps(state, indent=2, sort_keys=True))
            return 0

        ensure_mb7_schema(conn)
        verify_mb7_schema(conn)
        outcome = runner.materialize(conn)
        report = runner.build_report(outcome)
    finally:
        conn.close()

    report_file_sha256 = write_immutable_mb7_report(
        report, REPO_ROOT / MB7_REPORT_RELATIVE_PATH
    )
    state.update(
        {
            "status": "verified",
            "event_labels": outcome.event_labels,
            "window_labels": outcome.window_labels,
            "event_dispositions": dict(sorted(outcome.event_dispositions.items())),
            "window_dispositions": dict(sorted(outcome.window_dispositions.items())),
            "windows_before_interval": outcome.windows_before_interval,
            "windows_after_interval": outcome.windows_after_interval,
            "event_label_stream_sha256": outcome.event_label_stream_sha256,
            "window_label_stream_sha256": outcome.window_label_stream_sha256,
            "report_path": MB7_REPORT_RELATIVE_PATH,
            "report_content_sha256": report.content_sha256(),
            "report_file_sha256": report_file_sha256,
        }
    )
    print(json.dumps(state, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
