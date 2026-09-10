"""Definitive read-only Thursday window and label audit (TH-AUDIT).

Status of this artifact
-----------------------
This is an **audit**, not a canonical materialization. It is deliberately NOT
TH3/TH4/TH6/TH7. No PostgreSQL schema is created, no table is written, no
canonical event or window is persisted, and no frozen artifact is touched.

Why it is an audit and not the canonical chain
----------------------------------------------
A faithful canonical Thursday chain is blocked by three frozen contracts, each
verified by direct inspection:

1. ``ZeekNormalizationSpecificationV2`` pins the M-chain evidence counts as
   literal types (``scanned_record_count: Literal[1380057]``,
   ``expected_accepted_record_count: Literal[1353467]``), so no Thursday protocol
   can be expressed with it.
2. ``MondayBenignNormalizationSpecification`` is locked to Monday: it imports
   ``MB2_OUTPUT_ROOT`` and ``MONDAY_OUTPUT_PARTITION`` and owns a dedicated MB3
   UUID namespace.
3. ``StrictZeekConnFlowEndNormalizerV2._validate_source`` raises
   ``"source partition is not bound by v2 protocol"`` for any partition absent
   from its specification bindings.

A canonical TH chain therefore requires a dedicated TH3 contract module, binder
and runner, plus TH4/TH6/TH7 persistence, mirroring roughly 175 KB of strictly
contracted MB code. That remains a separate, additive engineering step.

What this audit reproduces exactly
----------------------------------
The **admission and windowing semantics** of the frozen chain are reimplemented
from the published protocol documents, field for field, so the audited
population matches what a canonical run would admit:

* record admission follows ``cicids2017_zeek_normalization_v2.yaml``:
  the thirteen required conn.log fields, ``service`` as the only optional mapped
  field, a closed set of optional ignored fields, ``unknown_field_policy:
  reject_record``, strict per-field types, the closed ``{tcp, udp}`` transport
  set, and rejection of comma-separated ``service`` lists;
* windowing follows ``cicids2017_feature_window_v2.yaml`` as implemented by
  ``feature_engineering/window_builder_v2.py``: tumbling 60-second windows,
  ``windowing_basis: event_start_time``, floor-to-multiple alignment from the
  Unix epoch, half-open bounds, strictly intra-partition, empty windows
  forbidden, and the entity key ``(source ip, destination ip, transport,
  service)`` with the frozen ``none`` sentinel for a null service;
* the five VOL5 features are aggregated exactly as ``_aggregate_features`` does.

Temporal arithmetic uses ``Decimal`` and integers only. No float is used for any
window bound.

Ratified TH7 labelling policy
-----------------------------
Decisions taken by the project owner and applied verbatim:

* the two Infiltration rules are **never labelled**: ``infiltration-mac`` matched
  zero flows, and ``infiltration-vista`` shows traffic sourced by internal hosts,
  which contradicts the declared attacker. Forcing a label is refused;
* the compromised hosts ``192.168.10.8`` and ``192.168.10.25`` are excluded from
  ``benign_reference`` across the **whole** capture, in both directions, even
  outside every declared interval;
* every window falling temporally inside any declared attack interval is
  excluded from ``benign_reference``, even when it belongs to an unrelated
  entity;
* gateway-to-web-server traffic is never a negative;
* ``unknown`` is never converted to ``benign_reference``. In doubt: ``unknown``.

The three Web Attack rules are labelled ``known_other_attack`` using the NAT
realignment empirically confirmed on this capture: 100% of the flows reaching the
declared victim, port and protocol inside those intervals are sourced by
``172.16.0.1``, and no other gateway traffic occurs inside them.

Usage::

    python -m scripts.audit_thursday_windows
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from collections.abc import Sequence
from decimal import Decimal
from hashlib import sha256
import json
from pathlib import Path
from typing import Any, Final


REPO_ROOT = Path(__file__).resolve().parents[1]

TH2_PARTITION: Final[str] = "2017-07-06_Thursday-WorkingHours"
TH2_DIR: Final[str] = f"artifacts/canonical/cicids2017/th2/zeek-8.0.9/{TH2_PARTITION}"
DEFAULT_OUTPUT_DIR: Final[str] = "artifacts/production/thursday_audit_v1"

WINDOW_LENGTH_SECONDS: Final[int] = 60
NULL_SERVICE_SENTINEL: Final[str] = "none"

# --- Admission contract, transcribed from cicids2017_zeek_normalization_v2.yaml
REQUIRED_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "conn_state", "duration", "id.orig_h", "id.orig_p", "id.resp_h",
        "id.resp_p", "orig_bytes", "orig_pkts", "proto", "resp_bytes",
        "resp_pkts", "ts", "uid",
    }
)
OPTIONAL_MAPPED_FIELDS: Final[frozenset[str]] = frozenset({"service"})
OPTIONAL_IGNORED_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "history", "ip_proto", "local_orig", "local_resp", "missed_bytes",
        "orig_ip_bytes", "resp_ip_bytes", "tunnel_parents",
    }
)
ALLOWED_FIELDS: Final[frozenset[str]] = (
    REQUIRED_FIELDS | OPTIONAL_MAPPED_FIELDS | OPTIONAL_IGNORED_FIELDS
)
SUPPORTED_TRANSPORTS: Final[frozenset[str]] = frozenset({"tcp", "udp"})

STRING_FIELDS: Final[tuple[str, ...]] = (
    "conn_state", "id.orig_h", "id.resp_h", "proto", "uid",
)
INTEGER_FIELDS: Final[tuple[str, ...]] = (
    "id.orig_p", "id.resp_p", "orig_bytes", "orig_pkts", "resp_bytes", "resp_pkts",
)

# --- Timezone: America/Moncton is UTC-3 on 2017-07-06 (ADT).
THURSDAY_UTC_MIDNIGHT: Final[int] = 1_499_299_200
MONCTON_UTC_OFFSET_SECONDS: Final[int] = -3 * 3600

OBSERVED_GATEWAY_IP: Final[str] = "172.16.0.1"
DECLARED_ATTACKER_IP: Final[str] = "205.174.165.73"
WEB_SERVER_IP: Final[str] = "192.168.10.50"

#: Ratified exclusion: compromised / attack-involved hosts, whole capture.
EXCLUDED_COMPROMISED_HOSTS: Final[frozenset[str]] = frozenset(
    {"192.168.10.8", "192.168.10.25"}
)

#: Web Attack rules that ARE labelled, with the confirmed NAT realignment.
LABELLED_WEB_RULES: Final[tuple[dict[str, Any], ...]] = (
    {
        "rule_id": "thursday-web-bruteforce",
        "attack_type": "web_attack/web_bruteforce",
        "disposition": "known_other_attack",
        "attacker_ip": OBSERVED_GATEWAY_IP,
        "victim_ip": WEB_SERVER_IP,
        "victim_port": 80,
        "transport": "tcp",
        "intervals": (("09:20:00", "10:00:00"),),
    },
    {
        "rule_id": "thursday-xss",
        "attack_type": "web_attack/xss",
        "disposition": "known_other_attack",
        "attacker_ip": OBSERVED_GATEWAY_IP,
        "victim_ip": WEB_SERVER_IP,
        "victim_port": 80,
        "transport": "tcp",
        "intervals": (("10:15:00", "10:35:00"),),
    },
    {
        "rule_id": "thursday-sql-injection",
        "attack_type": "web_attack/sql_injection",
        "disposition": "known_other_attack",
        "attacker_ip": OBSERVED_GATEWAY_IP,
        "victim_ip": WEB_SERVER_IP,
        "victim_port": 80,
        "transport": "tcp",
        "intervals": (("10:40:00", "10:42:00"),),
    },
)

#: Rules deliberately NOT labelled, with the factual reason recorded.
NOT_LABELLED_RULES: Final[dict[str, str]] = {
    "thursday-infiltration-mac": (
        "0 flows observed towards the declared victim 192.168.10.25 in the whole "
        "declared interval; no exploitable observation, so no label is forced"
    ),
    "thursday-infiltration-vista": (
        "the 1669 flows reaching the declared victim 192.168.10.8 are sourced by "
        "eight internal hosts (192.168.10.25/.12/.51/.16/.19/.17/.9/.50), not by "
        "the declared attacker 205.174.165.73 nor by the gateway 172.16.0.1; the "
        "observed direction contradicts the declaration, so no label is forced"
    ),
}

#: Every declared interval, including the unlabelled Infiltration ones, is an
#: exclusion zone for benign_reference.
ALL_DECLARED_INTERVALS_LOCAL: Final[tuple[tuple[str, str], ...]] = (
    ("09:20:00", "10:00:00"),   # web bruteforce
    ("10:15:00", "10:35:00"),   # xss
    ("10:40:00", "10:42:00"),   # sql injection
    ("14:19:00", "14:19:00"),   # infiltration vista
    ("14:20:00", "14:21:00"),
    ("14:33:00", "14:35:00"),
    ("15:04:00", "15:45:00"),
    ("14:53:00", "15:00:00"),   # infiltration mac
)

P1_PRIORITY_ENTITY_KEYS: Final[frozenset[str]] = frozenset(
    {
        f"{OBSERVED_GATEWAY_IP}|{WEB_SERVER_IP}|tcp|ftp",
        f"{OBSERVED_GATEWAY_IP}|{WEB_SERVER_IP}|tcp|ssh",
        f"{OBSERVED_GATEWAY_IP}|{WEB_SERVER_IP}|tcp|none",
        f"{OBSERVED_GATEWAY_IP}|{WEB_SERVER_IP}|tcp|http",
    }
)

TOP_N: Final[int] = 20


def moncton_to_utc_epoch(clock: str) -> int:
    """Convert an ``HH:MM:SS`` Moncton wall clock on 2017-07-06 to UTC epoch."""
    hours, minutes, seconds = (int(part) for part in clock.split(":"))
    return (
        THURSDAY_UTC_MIDNIGHT
        + hours * 3600 + minutes * 60 + seconds
        - MONCTON_UTC_OFFSET_SECONDS
    )


def compile_local_intervals(
    intervals: Sequence[tuple[str, str]]
) -> tuple[tuple[int, int], ...]:
    """Expand ``end_time_inclusive`` minutes to half-open UTC epoch bounds."""
    return tuple(
        (moncton_to_utc_epoch(start), moncton_to_utc_epoch(end) + 60)
        for start, end in intervals
    )


def inside(epoch: int, intervals: tuple[tuple[int, int], ...]) -> bool:
    """Return whether an instant lies in any half-open interval."""
    return any(start <= epoch < end for start, end in intervals)


class AdmissionRejection(Exception):
    """A conn.log record is refused, mirroring the M3 v2 rejection reasons."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def admit(record: dict[str, Any]) -> dict[str, Any]:
    """Apply the M3 v2 admission contract; return the projected fields."""
    keys = set(record)
    if REQUIRED_FIELDS - keys:
        raise AdmissionRejection("missing_required_field")
    if any(record[field] is None for field in REQUIRED_FIELDS):
        raise AdmissionRejection("null_required_field")
    if keys - ALLOWED_FIELDS:
        raise AdmissionRejection("unknown_field")

    for field in ("ts", "duration"):
        if type(record[field]) not in (int, Decimal):
            raise AdmissionRejection("invalid_field_type")
    for field in STRING_FIELDS:
        if type(record[field]) is not str:
            raise AdmissionRejection("invalid_field_type")
    for field in INTEGER_FIELDS:
        if type(record[field]) is not int:
            raise AdmissionRejection("invalid_field_type")

    service = record.get("service")
    if service is not None:
        if type(service) is not str:
            raise AdmissionRejection("invalid_field_type")
        if "," in service:
            raise AdmissionRejection("unsupported_service_cardinality")

    transport = record["proto"]
    if transport not in SUPPORTED_TRANSPORTS:
        raise AdmissionRejection("unsupported_transport")

    ts = record["ts"]
    duration = record["duration"]
    ts_decimal = Decimal(ts) if type(ts) is int else ts
    dur_decimal = Decimal(duration) if type(duration) is int else duration
    if not ts_decimal.is_finite() or not dur_decimal.is_finite():
        raise AdmissionRejection("non_finite_number")
    if (ts_decimal.is_signed() and ts_decimal != 0) or (
        dur_decimal.is_signed() and dur_decimal != 0
    ):
        raise AdmissionRejection("decimal38_22_range_or_scale")

    for field in ("orig_bytes", "orig_pkts", "resp_bytes", "resp_pkts"):
        if record[field] < 0:
            raise AdmissionRejection("non_negative_integer")

    return {
        "start": ts_decimal,
        "source_ip": record["id.orig_h"],
        "destination_ip": record["id.resp_h"],
        "destination_port": record["id.resp_p"],
        "transport": transport,
        "service": service,
        "source_packets": record["orig_pkts"],
        "destination_packets": record["resp_pkts"],
        "source_bytes": record["orig_bytes"],
        "destination_bytes": record["resp_bytes"],
    }


def parse_line_preserving_decimals(line: bytes) -> dict[str, Any]:
    """Parse one JSON object line, keeping numeric lexemes as ``Decimal``."""
    text = line.decode("utf-8")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise AdmissionRejection("duplicate_field")
            result[key] = value
        return result

    def constant(_: str) -> object:
        raise AdmissionRejection("non_finite_number")

    try:
        value = json.loads(
            text,
            parse_float=Decimal,
            object_pairs_hook=pairs,
            parse_constant=constant,  # type: ignore[arg-type]
        )
    except json.JSONDecodeError as exc:
        raise AdmissionRejection("malformed_json") from exc
    if not isinstance(value, dict):
        raise AdmissionRejection("non_object_json")
    return value


def episodes_of(buckets: Sequence[int]) -> int:
    """Count maximal runs of consecutive 60-second windows."""
    ordered = sorted(buckets)
    if not ordered:
        return 0
    count = 1
    for previous, current in zip(ordered, ordered[1:]):
        if current - previous > WINDOW_LENGTH_SECONDS:
            count += 1
    return count


def run_audit(conn_log: Path) -> dict[str, Any]:
    """Stream the TH2 conn.log once and produce the full labelled audit."""
    labelled_rules = tuple(
        {**rule, "compiled": compile_local_intervals(rule["intervals"])}
        for rule in LABELLED_WEB_RULES
    )
    all_exclusion_zones = compile_local_intervals(ALL_DECLARED_INTERVALS_LOCAL)

    processed = 0
    accepted = 0
    rejected = 0
    rejection_reasons: Counter[str] = Counter()

    # window key -> aggregation
    windows: dict[tuple[str, int], dict[str, Any]] = {}

    with conn_log.open("rb") as stream:
        for line in stream:
            if not line.strip():
                continue
            processed += 1
            try:
                record = parse_line_preserving_decimals(line)
                projected = admit(record)
            except AdmissionRejection as rejection:
                rejected += 1
                rejection_reasons[rejection.reason] += 1
                continue
            accepted += 1

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
            # Exact floor alignment with integer arithmetic only.
            start_int = int(projected["start"].to_integral_value(rounding="ROUND_FLOOR"))
            bucket = (start_int // WINDOW_LENGTH_SECONDS) * WINDOW_LENGTH_SECONDS

            key = (entity_key, bucket)
            slot = windows.get(key)
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
                windows[key] = slot
            slot["event_count"] += 1
            slot["source_packets_total"] += projected["source_packets"]
            slot["destination_packets_total"] += projected["destination_packets"]
            slot["source_bytes_total"] += projected["source_bytes"]
            slot["destination_bytes_total"] += projected["destination_bytes"]
            slot["destination_ports"].add(projected["destination_port"])

    # --- labelling -------------------------------------------------------
    disposition_counts: Counter[str] = Counter()
    attack_windows_by_type: Counter[str] = Counter()
    attack_buckets: dict[str, dict[str, list[int]]] = defaultdict(
        lambda: defaultdict(list)
    )
    attack_entities: dict[str, set[str]] = defaultdict(set)
    benign_entities: set[str] = set()
    benign_source_ips: Counter[str] = Counter()
    benign_services: Counter[str] = Counter()
    unknown_reasons: Counter[str] = Counter()

    for (entity_key, bucket), slot in windows.items():
        source_ip = slot["source_ip"]
        destination_ip = slot["destination_ip"]

        matched_rule = None
        for rule in labelled_rules:
            if (
                source_ip == rule["attacker_ip"]
                and destination_ip == rule["victim_ip"]
                and slot["transport"] == rule["transport"]
                and rule["victim_port"] in slot["destination_ports"]
                and inside(bucket, rule["compiled"])
            ):
                matched_rule = rule
                break

        if matched_rule is not None:
            attack_type = matched_rule["attack_type"]
            disposition_counts[matched_rule["disposition"]] += 1
            attack_windows_by_type[attack_type] += 1
            attack_buckets[attack_type][entity_key].append(bucket)
            attack_entities[attack_type].add(entity_key)
            slot["disposition"] = matched_rule["disposition"]
            slot["attack_type"] = attack_type
            continue

        # Conservative benign_reference gate. Any failure -> unknown.
        if inside(bucket, all_exclusion_zones):
            unknown_reasons["inside_a_declared_attack_interval"] += 1
            slot["disposition"] = "unknown"
            slot["attack_type"] = None
            disposition_counts["unknown"] += 1
            continue
        if (
            source_ip in EXCLUDED_COMPROMISED_HOSTS
            or destination_ip in EXCLUDED_COMPROMISED_HOSTS
        ):
            unknown_reasons["compromised_host_excluded_whole_capture"] += 1
            slot["disposition"] = "unknown"
            slot["attack_type"] = None
            disposition_counts["unknown"] += 1
            continue
        if source_ip == OBSERVED_GATEWAY_IP and destination_ip == WEB_SERVER_IP:
            unknown_reasons["gateway_to_web_server_never_a_negative"] += 1
            slot["disposition"] = "unknown"
            slot["attack_type"] = None
            disposition_counts["unknown"] += 1
            continue
        if DECLARED_ATTACKER_IP in (source_ip, destination_ip):
            unknown_reasons["declared_attacker_endpoint"] += 1
            slot["disposition"] = "unknown"
            slot["attack_type"] = None
            disposition_counts["unknown"] += 1
            continue

        slot["disposition"] = "benign_reference"
        slot["attack_type"] = None
        disposition_counts["benign_reference"] += 1
        benign_entities.add(entity_key)
        benign_source_ips[source_ip] += 1
        benign_services[slot["service"]] += 1

    per_family: dict[str, Any] = {}
    for attack_type, by_entity in attack_buckets.items():
        total_episodes = sum(
            episodes_of(buckets) for buckets in by_entity.values()
        )
        per_family[attack_type] = {
            "disposition": "known_other_attack",
            "windows": attack_windows_by_type[attack_type],
            "episodes": total_episodes,
            "entities": len(attack_entities[attack_type]),
            "entity_keys": sorted(attack_entities[attack_type]),
            "entity_keys_shared_with_p1_priority": sorted(
                attack_entities[attack_type] & P1_PRIORITY_ENTITY_KEYS
            ),
            "partition": TH2_PARTITION,
            "priority_family": False,
        }

    all_entities = {entity for entity, _ in windows}
    return {
        "audit_version": "1.0.0",
        "artifact_status": (
            "AUDIT ONLY - not TH3/TH4/TH6/TH7, no canonical persistence, "
            "0 PostgreSQL writes"
        ),
        "partition": TH2_PARTITION,
        "admission": {
            "contract": "cicids2017_zeek_normalization_v2.yaml, reimplemented field for field",
            "processed_records": processed,
            "accepted_records": accepted,
            "rejected_records": rejected,
            "acceptance_rate_percent": (
                round(100.0 * accepted / processed, 6) if processed else None
            ),
            "rejection_reasons": dict(rejection_reasons.most_common()),
        },
        "windowing": {
            "contract": "cicids2017_feature_window_v2.yaml via window_builder_v2",
            "basis": "event_start_time",
            "length_seconds": WINDOW_LENGTH_SECONDS,
            "alignment": "floor_to_multiple_of_length_from_unix_epoch",
            "entity_key": "source_ip|destination_ip|transport|service",
            "null_service_sentinel": NULL_SERVICE_SENTINEL,
            "total_windows": len(windows),
        },
        "disposition_counts": dict(sorted(disposition_counts.items())),
        "unknown_breakdown": dict(unknown_reasons.most_common()),
        "attack_families": per_family,
        "not_labelled_rules": NOT_LABELLED_RULES,
        "benign_reference": {
            "windows": disposition_counts.get("benign_reference", 0),
            "distinct_entities": len(benign_entities),
            "top_source_ips": dict(benign_source_ips.most_common(TOP_N)),
            "services": dict(benign_services.most_common(TOP_N)),
        },
        "entity_comparison_with_p1": {
            "p1_priority_entity_keys": sorted(P1_PRIORITY_ENTITY_KEYS),
            "thursday_entity_keys_shared_with_p1_priority": sorted(
                all_entities & P1_PRIORITY_ENTITY_KEYS
            ),
            "thursday_total_distinct_entities": len(all_entities),
            "entity_disjoint_from_p1": not bool(
                all_entities & P1_PRIORITY_ENTITY_KEYS
            ),
            "interpretation": (
                "Thursday is NOT an entity-disjoint validation. Its scientific "
                "value is an independent capture/day for conservative benign "
                "false-positive evaluation, and secondarily three known-other "
                "web attack families which must not be used as primary evidence "
                "of generalisation to the priority FTP/SSH/DoS/DDoS families."
            ),
        },
        "ratified_policy": {
            "unknown_to_benign_conversion": "forbidden",
            "ambiguous_to_benign_conversion": "forbidden",
            "excluded_compromised_hosts": sorted(EXCLUDED_COMPROMISED_HOSTS),
            "compromised_host_exclusion_scope": "whole_capture_both_directions",
            "windows_inside_declared_intervals": "excluded_from_benign_reference",
            "gateway_to_web_server": "never_a_negative",
            "infiltration_rules": "never_labelled_with_recorded_reason",
        },
        "guarantees": {
            "postgresql_writes": 0,
            "postgresql_schemas_created": 0,
            "canonical_events_persisted": 0,
            "canonical_windows_persisted": 0,
            "models_loaded": 0,
            "models_fitted": 0,
            "thresholds_chosen": 0,
            "splits_created": 0,
            "performance_measured": False,
            "frozen_artifacts_modified": False,
        },
    }


def build_parser() -> argparse.ArgumentParser:
    """Return the audit command-line interface."""
    parser = argparse.ArgumentParser(
        description="Definitive read-only Thursday window and label audit."
    )
    parser.add_argument(
        "--conn-log", type=Path, default=REPO_ROOT / TH2_DIR / "conn.log"
    )
    parser.add_argument(
        "--output-dir", type=Path, default=REPO_ROOT / DEFAULT_OUTPUT_DIR
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the audit, persist it, and print it."""
    args = build_parser().parse_args(argv)
    result = run_audit(args.conn_log)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    destination = args.output_dir / "THURSDAY_WINDOW_LABEL_AUDIT.json"
    payload = (
        json.dumps(result, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    ).encode("utf-8")
    destination.write_bytes(payload)
    result["audit_file_sha256"] = sha256(payload).hexdigest()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
