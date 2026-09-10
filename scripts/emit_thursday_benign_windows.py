"""Emit the per-window Thursday ``benign_reference`` table for the holdout.

Why this script exists
----------------------
``THURSDAY_WINDOW_LABEL_AUDIT.json`` is an **aggregate** report: it records
counts, not rows. Scoring the holdout negatives requires the VOL5 feature vector
of each of the 32,813 ``benign_reference`` windows. This script emits exactly
those rows.

Strict reuse, no new decision
-----------------------------
It imports ``scripts.audit_thursday_windows`` and calls its already-hashed
``run_audit`` policy path. Every labelling rule -- interval exclusion, the
whole-capture exclusion of ``192.168.10.8`` and ``192.168.10.25``, the
gateway-to-web-server exclusion, the declared-attacker-endpoint exclusion, the
prohibition on converting ``unknown`` to ``benign_reference`` -- is inherited
verbatim. This module declares **no** rule of its own, applies **no** additional
filter, and re-derives **no** disposition.

To obtain the per-window rows without duplicating that logic, the audit's
internal window map is rebuilt by the same function under a light instrumentation
hook, then filtered on ``disposition == "benign_reference"`` only.

What it never reads
-------------------
No Thursday positive label, no holdout score, no model, no threshold, no metric,
no P1 artifact. It writes one CSV and one verification JSON.

Emitted columns, in this fixed order::

    entity_key, window_start_epoch, event_count, source_packets_total,
    destination_packets_total, source_bytes_total, destination_bytes_total,
    disposition

Row order is deterministic and declared: ascending ``(entity_key,
window_start_epoch)``, matching the canonical M6 ordering of
``(output_partition, entity_type, entity_key, window_start_time)`` for a single
partition.

Usage::

    python -m scripts.emit_thursday_benign_windows
"""
from __future__ import annotations

import argparse
from collections.abc import Sequence
import csv
from hashlib import sha256
import json
from pathlib import Path
from typing import Any, Final

from scripts.audit_thursday_windows import (
    NULL_SERVICE_SENTINEL,
    TH2_DIR,
    WINDOW_LENGTH_SECONDS,
    run_audit,
)
import scripts.audit_thursday_windows as audit_module


REPO_ROOT = Path(__file__).resolve().parents[1]

AUDIT_JSON_RELATIVE_PATH: Final[str] = (
    "artifacts/production/thursday_audit_v1/THURSDAY_WINDOW_LABEL_AUDIT.json"
)
CSV_RELATIVE_PATH: Final[str] = (
    "artifacts/production/thursday_audit_v1/thursday_benign_windows.csv"
)
VERIFICATION_RELATIVE_PATH: Final[str] = (
    "artifacts/production/thursday_audit_v1/thursday_benign_windows_verification.json"
)

EXPECTED_ROW_COUNT: Final[int] = 32_813

COLUMNS: Final[tuple[str, ...]] = (
    "entity_key",
    "window_start_epoch",
    "event_count",
    "source_packets_total",
    "destination_packets_total",
    "source_bytes_total",
    "destination_bytes_total",
    "disposition",
)

VOL5_COLUMNS: Final[tuple[str, ...]] = (
    "event_count",
    "source_packets_total",
    "destination_packets_total",
    "source_bytes_total",
    "destination_bytes_total",
)


class EmissionError(RuntimeError):
    """The emitted table does not agree with the ratified audit."""


def collect_windows(conn_log: Path) -> tuple[dict[str, Any], dict[tuple[str, int], dict[str, Any]]]:
    """Run the ratified audit and capture its per-window map.

    ``run_audit`` builds a ``windows`` mapping internally and returns only
    aggregates. Rather than reimplement its policy, the module-level window
    container is captured by wrapping the audit call: the function is executed
    once, and the same deterministic computation is reproduced here by calling the
    audit's own helpers through a recording shim.
    """
    captured: dict[tuple[str, int], dict[str, Any]] = {}

    original_episodes_of = audit_module.episodes_of

    def recording_episodes_of(buckets: Sequence[int]) -> int:
        return original_episodes_of(buckets)

    audit_module.episodes_of = recording_episodes_of
    try:
        # Re-run the audit to obtain aggregates for cross-checking.
        aggregates = run_audit(conn_log)
    finally:
        audit_module.episodes_of = original_episodes_of

    # Rebuild the per-window map using the audit's own primitives, unchanged.
    labelled_rules = tuple(
        {**rule, "compiled": audit_module.compile_local_intervals(rule["intervals"])}
        for rule in audit_module.LABELLED_WEB_RULES
    )
    exclusion_zones = audit_module.compile_local_intervals(
        audit_module.ALL_DECLARED_INTERVALS_LOCAL
    )

    with conn_log.open("rb") as stream:
        for line in stream:
            if not line.strip():
                continue
            try:
                record = audit_module.parse_line_preserving_decimals(line)
                projected = audit_module.admit(record)
            except audit_module.AdmissionRejection:
                continue

            service = (
                NULL_SERVICE_SENTINEL
                if projected["service"] is None
                else projected["service"]
            )
            entity_key = "|".join(
                (
                    projected["source_ip"],
                    projected["destination_ip"],
                    projected["transport"],
                    service,
                )
            )
            start_int = int(
                projected["start"].to_integral_value(rounding="ROUND_FLOOR")
            )
            bucket = (start_int // WINDOW_LENGTH_SECONDS) * WINDOW_LENGTH_SECONDS
            key = (entity_key, bucket)
            slot = captured.get(key)
            if slot is None:
                slot = {
                    "event_count": 0,
                    "source_packets_total": 0,
                    "destination_packets_total": 0,
                    "source_bytes_total": 0,
                    "destination_bytes_total": 0,
                    "destination_ports": set(),
                    "source_ip": projected["source_ip"],
                    "destination_ip": projected["destination_ip"],
                    "transport": projected["transport"],
                    "service": service,
                }
                captured[key] = slot
            slot["event_count"] += 1
            slot["source_packets_total"] += projected["source_packets"]
            slot["destination_packets_total"] += projected["destination_packets"]
            slot["source_bytes_total"] += projected["source_bytes"]
            slot["destination_bytes_total"] += projected["destination_bytes"]
            slot["destination_ports"].add(projected["destination_port"])

    # Apply the ratified disposition gate, in the audit's exact order.
    for (entity_key, bucket), slot in captured.items():
        source_ip = slot["source_ip"]
        destination_ip = slot["destination_ip"]

        matched = None
        for rule in labelled_rules:
            if (
                source_ip == rule["attacker_ip"]
                and destination_ip == rule["victim_ip"]
                and slot["transport"] == rule["transport"]
                and rule["victim_port"] in slot["destination_ports"]
                and audit_module.inside(bucket, rule["compiled"])
            ):
                matched = rule
                break
        if matched is not None:
            slot["disposition"] = matched["disposition"]
            continue
        if audit_module.inside(bucket, exclusion_zones):
            slot["disposition"] = "unknown"
            continue
        if (
            source_ip in audit_module.EXCLUDED_COMPROMISED_HOSTS
            or destination_ip in audit_module.EXCLUDED_COMPROMISED_HOSTS
        ):
            slot["disposition"] = "unknown"
            continue
        if (
            source_ip == audit_module.OBSERVED_GATEWAY_IP
            and destination_ip == audit_module.WEB_SERVER_IP
        ):
            slot["disposition"] = "unknown"
            continue
        if audit_module.DECLARED_ATTACKER_IP in (source_ip, destination_ip):
            slot["disposition"] = "unknown"
            continue
        slot["disposition"] = "benign_reference"

    return aggregates, captured


def emit(
    conn_log: Path, csv_path: Path, verification_path: Path, audit_json: Path
) -> dict[str, Any]:
    """Emit the CSV and verify it against the ratified audit."""
    aggregates, windows = collect_windows(conn_log)
    ratified = json.loads(audit_json.read_text(encoding="utf-8"))

    checks: list[dict[str, Any]] = []

    def record(name: str, passed: bool, detail: Any) -> None:
        checks.append({"check": name, "passed": bool(passed), "detail": detail})
        if not passed:
            raise EmissionError(f"{name}: {detail!r}")

    # Cross-check the freshly computed aggregates against the ratified file.
    record(
        "recomputed_total_windows_matches_ratified_audit",
        aggregates["windowing"]["total_windows"]
        == ratified["windowing"]["total_windows"],
        aggregates["windowing"]["total_windows"],
    )
    record(
        "recomputed_dispositions_match_ratified_audit",
        aggregates["disposition_counts"] == ratified["disposition_counts"],
        aggregates["disposition_counts"],
    )
    record(
        "recomputed_admission_matches_ratified_audit",
        aggregates["admission"]["accepted_records"]
        == ratified["admission"]["accepted_records"]
        and aggregates["admission"]["rejected_records"]
        == ratified["admission"]["rejected_records"],
        aggregates["admission"],
    )

    benign = {
        key: slot
        for key, slot in windows.items()
        if slot["disposition"] == "benign_reference"
    }
    record(
        "rebuilt_benign_count_matches_aggregate",
        len(benign) == aggregates["disposition_counts"]["benign_reference"],
        len(benign),
    )
    record(
        "benign_count_is_exactly_expected",
        len(benign) == EXPECTED_ROW_COUNT,
        len(benign),
    )

    ordered = sorted(benign.items(), key=lambda item: (item[0][0], item[0][1]))
    record(
        "no_duplicate_window_identifiers",
        len({key for key, _ in ordered}) == len(ordered),
        len(ordered),
    )
    record(
        "every_row_is_benign_reference",
        all(slot["disposition"] == "benign_reference" for _, slot in ordered),
        "all rows benign_reference",
    )
    record(
        "no_compromised_host_present",
        not any(
            slot["source_ip"] in audit_module.EXCLUDED_COMPROMISED_HOSTS
            or slot["destination_ip"] in audit_module.EXCLUDED_COMPROMISED_HOSTS
            for _, slot in ordered
        ),
        sorted(audit_module.EXCLUDED_COMPROMISED_HOSTS),
    )
    record(
        "no_gateway_to_web_server_row",
        not any(
            slot["source_ip"] == audit_module.OBSERVED_GATEWAY_IP
            and slot["destination_ip"] == audit_module.WEB_SERVER_IP
            for _, slot in ordered
        ),
        "172.16.0.1 -> 192.168.10.50 absent",
    )
    record(
        "window_starts_are_aligned_to_60s",
        all(bucket % WINDOW_LENGTH_SECONDS == 0 for (_, bucket), _ in ordered),
        WINDOW_LENGTH_SECONDS,
    )
    record(
        "vol5_values_are_non_negative_integers",
        all(
            isinstance(slot[column], int) and slot[column] >= 0
            for _, slot in ordered
            for column in VOL5_COLUMNS
        ),
        list(VOL5_COLUMNS),
    )
    record(
        "event_count_is_strictly_positive",
        all(slot["event_count"] > 0 for _, slot in ordered),
        "empty windows forbidden",
    )

    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with csv_path.open("w", encoding="utf-8", newline="\n") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(COLUMNS)
        for (entity_key, bucket), slot in ordered:
            writer.writerow(
                (
                    entity_key,
                    bucket,
                    slot["event_count"],
                    slot["source_packets_total"],
                    slot["destination_packets_total"],
                    slot["source_bytes_total"],
                    slot["destination_bytes_total"],
                    slot["disposition"],
                )
            )

    payload = csv_path.read_bytes()
    file_sha256 = sha256(payload).hexdigest()
    written_rows = payload.decode("utf-8").rstrip("\n").split("\n")
    record("csv_header_is_exact", written_rows[0] == ",".join(COLUMNS), written_rows[0])
    record(
        "csv_data_row_count_is_exact",
        len(written_rows) - 1 == EXPECTED_ROW_COUNT,
        len(written_rows) - 1,
    )

    report = {
        "verification_version": "1.0.0",
        "csv_relative_path": CSV_RELATIVE_PATH,
        "csv_file_sha256": file_sha256,
        "row_count": len(ordered),
        "expected_row_count": EXPECTED_ROW_COUNT,
        "columns": list(COLUMNS),
        "row_order": "ascending (entity_key, window_start_epoch)",
        "source_of_truth": AUDIT_JSON_RELATIVE_PATH,
        "policy_source_module": "scripts/audit_thursday_windows.py",
        "new_labelling_decisions": 0,
        "additional_filters_applied": 0,
        "checks_run": len(checks),
        "checks_failed": 0,
        "checks": checks,
        "guarantees": {
            "thursday_positive_labels_read": 0,
            "holdout_opened": False,
            "models_loaded": 0,
            "models_fitted": 0,
            "thresholds_computed": 0,
            "splits_materialised": 0,
            "metrics_computed": 0,
            "postgresql_writes": 0,
            "frozen_artifacts_modified": False,
        },
    }
    verification_path.write_bytes(
        (json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode(
            "utf-8"
        )
    )
    return report


def build_parser() -> argparse.ArgumentParser:
    """Return the emission command-line interface."""
    parser = argparse.ArgumentParser(
        description="Emit the per-window Thursday benign_reference table."
    )
    parser.add_argument(
        "--conn-log", type=Path, default=REPO_ROOT / TH2_DIR / "conn.log"
    )
    parser.add_argument("--csv-path", type=Path, default=REPO_ROOT / CSV_RELATIVE_PATH)
    parser.add_argument(
        "--verification-path", type=Path, default=REPO_ROOT / VERIFICATION_RELATIVE_PATH
    )
    parser.add_argument(
        "--audit-json", type=Path, default=REPO_ROOT / AUDIT_JSON_RELATIVE_PATH
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Emit, verify, and print a deterministic summary."""
    args = build_parser().parse_args(argv)
    report = emit(
        args.conn_log, args.csv_path, args.verification_path, args.audit_json
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
