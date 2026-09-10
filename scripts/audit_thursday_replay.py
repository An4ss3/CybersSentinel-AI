"""Read-only NAT and population audit of the TH2 Thursday Zeek replay.

This script answers, from the bytes Zeek actually produced, the question left
open by ``label_policy_v3.json``: whether Thursday exhibits the same network
address translation behaviour as the M chain, where the logical CICIDS2017
attacker ``205.174.165.73`` never appears as a source and the gateway
``172.16.0.1`` does.

It reads ``conn.log`` only. It writes a single JSON audit artifact. It creates no
label, no window table, no dataset, and no model. It never converts anything to
``benign_reference``: window *candidates* are counted, not labelled.

Window candidate convention
---------------------------
To stay comparable with M6, a candidate window is identified by the tuple
``(source ip, destination ip, transport, service)`` and the 60-second bucket of
the **flow end** instant ``ts + duration``, mirroring ``FlowEndV2``. This is a
counting convention for the audit only; no window is materialised.

Timezone
--------
The CICIDS2017 label schedule is expressed in ``America/Moncton``. On
2017-07-06 that is ADT, i.e. UTC-3. Declared intervals are converted to UTC
epoch seconds explicitly, with the frozen ``end_time_inclusive`` minute expanded
to a half-open bound exactly as the M5 ledger specifies.

Usage::

    python -m scripts.audit_thursday_replay
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from collections.abc import Sequence
import json
from pathlib import Path
from typing import Any, Final


REPO_ROOT = Path(__file__).resolve().parents[1]

TH2_PARTITION: Final[str] = "2017-07-06_Thursday-WorkingHours"
TH2_CONN_LOG: Final[str] = (
    f"artifacts/canonical/cicids2017/th2/zeek-8.0.9/{TH2_PARTITION}/conn.log"
)
DEFAULT_AUDIT_PATH: Final[str] = (
    "artifacts/canonical/cicids2017/th2/thursday_replay_audit.json"
)

#: 2017-07-06T00:00:00Z
THURSDAY_UTC_MIDNIGHT: Final[int] = 1_499_299_200
#: America/Moncton is UTC-3 on 2017-07-06 (ADT).
MONCTON_UTC_OFFSET_SECONDS: Final[int] = -3 * 3600

WINDOW_LENGTH_SECONDS: Final[int] = 60

#: The logical attacker declared by the frozen M5 v1 ledger for every Thursday
#: rule, and the gateway identity observed on the M chain instead.
DECLARED_ATTACKER_IP: Final[str] = "205.174.165.73"
OBSERVED_GATEWAY_IP: Final[str] = "172.16.0.1"

#: Frozen M5 v1 Thursday rules, transcribed read-only for interval arithmetic.
THURSDAY_RULES: Final[tuple[dict[str, Any], ...]] = (
    {
        "rule_id": "thursday-web-bruteforce",
        "attack_type": "web_attack/web_bruteforce",
        "disposition": "known_other_attack",
        "victim_ips": ("192.168.10.50",),
        "victim_ports": (80,),
        "intervals": (("09:20:00", "10:00:00"),),
    },
    {
        "rule_id": "thursday-xss",
        "attack_type": "web_attack/xss",
        "disposition": "known_other_attack",
        "victim_ips": ("192.168.10.50",),
        "victim_ports": (80,),
        "intervals": (("10:15:00", "10:35:00"),),
    },
    {
        "rule_id": "thursday-sql-injection",
        "attack_type": "web_attack/sql_injection",
        "disposition": "known_other_attack",
        "victim_ips": ("192.168.10.50",),
        "victim_ports": (80,),
        "intervals": (("10:40:00", "10:42:00"),),
    },
    {
        "rule_id": "thursday-infiltration-vista",
        "attack_type": "infiltration/vista_infiltration",
        "disposition": "known_other_attack",
        "victim_ips": ("192.168.10.8",),
        "victim_ports": (),
        "intervals": (
            ("14:19:00", "14:19:00"),
            ("14:20:00", "14:21:00"),
            ("14:33:00", "14:35:00"),
            ("15:04:00", "15:45:00"),
        ),
    },
    {
        "rule_id": "thursday-infiltration-mac",
        "attack_type": "infiltration/mac_infiltration",
        "disposition": "known_other_attack",
        "victim_ips": ("192.168.10.25",),
        "victim_ports": (),
        "intervals": (("14:53:00", "15:00:00"),),
    },
)

#: The four priority entity keys already present in the P1/v2 population.
P1_PRIORITY_ENTITY_KEYS: Final[frozenset[str]] = frozenset(
    {
        "172.16.0.1|192.168.10.50|tcp|ftp",
        "172.16.0.1|192.168.10.50|tcp|ssh",
        "172.16.0.1|192.168.10.50|tcp|none",
        "172.16.0.1|192.168.10.50|tcp|http",
    }
)

TOP_N: Final[int] = 15


def moncton_clock_to_utc_epoch(clock: str) -> int:
    """Convert an ``HH:MM:SS`` Moncton wall clock on 2017-07-06 to UTC epoch."""
    hours, minutes, seconds = (int(part) for part in clock.split(":"))
    local_offset = hours * 3600 + minutes * 60 + seconds
    return THURSDAY_UTC_MIDNIGHT + local_offset - MONCTON_UTC_OFFSET_SECONDS


def compile_intervals(rule: dict[str, Any]) -> tuple[tuple[int, int], ...]:
    """Return half-open UTC epoch intervals for one frozen rule."""
    compiled: list[tuple[int, int]] = []
    for start_clock, end_clock in rule["intervals"]:
        start = moncton_clock_to_utc_epoch(start_clock)
        # end_time_inclusive names a whole minute; expand to a half-open bound.
        end = moncton_clock_to_utc_epoch(end_clock) + 60
        compiled.append((start, end))
    return tuple(compiled)


def in_any_interval(epoch: float, intervals: tuple[tuple[int, int], ...]) -> bool:
    """Return whether an instant falls in any half-open interval."""
    return any(start <= epoch < end for start, end in intervals)


def audit(conn_log: Path) -> dict[str, Any]:
    """Stream conn.log once and return the full read-only audit."""
    compiled = {rule["rule_id"]: compile_intervals(rule) for rule in THURSDAY_RULES}
    rules_by_id = {rule["rule_id"]: rule for rule in THURSDAY_RULES}

    source_counter: Counter[str] = Counter()
    dest_counter: Counter[str] = Counter()
    service_counter: Counter[str] = Counter()
    proto_counter: Counter[str] = Counter()
    declared_attacker_as_source = 0
    declared_attacker_as_dest = 0
    gateway_as_source = 0
    gateway_as_dest = 0

    total = 0
    malformed = 0
    first_ts: float | None = None
    last_end: float | None = None

    # Per rule: flows whose destination matches the declared victim/port, grouped
    # by observed source, plus candidate windows and episodes.
    per_rule_sources: dict[str, Counter[str]] = defaultdict(Counter)
    per_rule_windows: dict[str, set[tuple[str, int]]] = defaultdict(set)
    per_rule_other_traffic: dict[str, Counter[str]] = defaultdict(Counter)

    # Global candidate windows, and those falling inside any declared interval.
    all_windows: set[tuple[str, int]] = set()
    windows_in_any_attack_interval: set[tuple[str, int]] = set()
    gateway_to_web_windows_outside: set[tuple[str, int]] = set()

    any_interval = tuple(
        interval for intervals in compiled.values() for interval in intervals
    )

    with conn_log.open("r", encoding="utf-8") as stream:
        for line in stream:
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                malformed += 1
                continue
            total += 1

            src = record.get("id.orig_h")
            dst = record.get("id.resp_h")
            dport = record.get("id.resp_p")
            proto = record.get("proto") or "unknown"
            service = record.get("service") or "none"
            ts = record.get("ts")
            duration = record.get("duration") or 0.0
            if src is None or dst is None or ts is None:
                malformed += 1
                continue

            end = float(ts) + float(duration)
            if first_ts is None or float(ts) < first_ts:
                first_ts = float(ts)
            if last_end is None or end > last_end:
                last_end = end

            source_counter[src] += 1
            dest_counter[dst] += 1
            service_counter[service] += 1
            proto_counter[proto] += 1
            if src == DECLARED_ATTACKER_IP:
                declared_attacker_as_source += 1
            if dst == DECLARED_ATTACKER_IP:
                declared_attacker_as_dest += 1
            if src == OBSERVED_GATEWAY_IP:
                gateway_as_source += 1
            if dst == OBSERVED_GATEWAY_IP:
                gateway_as_dest += 1

            entity_key = f"{src}|{dst}|{proto}|{service}"
            bucket = int(end // WINDOW_LENGTH_SECONDS) * WINDOW_LENGTH_SECONDS
            window = (entity_key, bucket)
            all_windows.add(window)
            if in_any_interval(end, any_interval):
                windows_in_any_attack_interval.add(window)

            for rule_id, intervals in compiled.items():
                rule = rules_by_id[rule_id]
                if not in_any_interval(end, intervals):
                    continue
                victim_ok = dst in rule["victim_ips"]
                port_ok = (
                    not rule["victim_ports"]
                    or (dport is not None and int(dport) in rule["victim_ports"])
                )
                if victim_ok and port_ok:
                    per_rule_sources[rule_id][src] += 1
                    per_rule_windows[rule_id].add(window)
                elif src == OBSERVED_GATEWAY_IP:
                    # Gateway traffic inside the interval but NOT towards the
                    # declared victim/port: the false-positive risk indicator.
                    per_rule_other_traffic[rule_id][f"{dst}:{dport}"] += 1

            # Gateway -> web server traffic OUTSIDE every declared interval.
            if (
                src == OBSERVED_GATEWAY_IP
                and dst == "192.168.10.50"
                and not in_any_interval(end, any_interval)
            ):
                gateway_to_web_windows_outside.add(window)

    def episodes(windows: set[tuple[str, int]]) -> int:
        """Count maximal runs of consecutive 60s windows per entity."""
        by_entity: dict[str, list[int]] = defaultdict(list)
        for entity_key, bucket in windows:
            by_entity[entity_key].append(bucket)
        count = 0
        for buckets in by_entity.values():
            ordered = sorted(buckets)
            count += 1
            for previous, current in zip(ordered, ordered[1:]):
                if current - previous > WINDOW_LENGTH_SECONDS:
                    count += 1
        return count

    per_rule: dict[str, Any] = {}
    for rule in THURSDAY_RULES:
        rule_id = rule["rule_id"]
        windows = per_rule_windows[rule_id]
        entities = sorted({entity for entity, _ in windows})
        per_rule[rule_id] = {
            "attack_type": rule["attack_type"],
            "disposition": rule["disposition"],
            "declared_victim_ips": list(rule["victim_ips"]),
            "declared_victim_ports": list(rule["victim_ports"]),
            "declared_attacker_ip": DECLARED_ATTACKER_IP,
            "intervals_utc": [list(item) for item in compiled[rule_id]],
            "matching_flows_by_observed_source": dict(
                per_rule_sources[rule_id].most_common()
            ),
            "matching_flow_total": sum(per_rule_sources[rule_id].values()),
            "candidate_windows": len(windows),
            "candidate_episodes": episodes(windows),
            "observed_entity_keys": entities,
            "entity_keys_already_in_p1": sorted(
                set(entities) & P1_PRIORITY_ENTITY_KEYS
            ),
            "gateway_traffic_in_interval_not_towards_declared_victim": dict(
                per_rule_other_traffic[rule_id].most_common(TOP_N)
            ),
        }

    nat_confirmed = declared_attacker_as_source == 0 and gateway_as_source > 0
    return {
        "audit_version": "1.0.0",
        "partition": TH2_PARTITION,
        "conn_log_records": total,
        "malformed_records": malformed,
        "observed_time_span_utc": {
            "first_flow_start_epoch": first_ts,
            "last_flow_end_epoch": last_end,
        },
        "nat_resolution": {
            "declared_attacker_ip": DECLARED_ATTACKER_IP,
            "declared_attacker_as_source_flows": declared_attacker_as_source,
            "declared_attacker_as_destination_flows": declared_attacker_as_dest,
            "observed_gateway_ip": OBSERVED_GATEWAY_IP,
            "gateway_as_source_flows": gateway_as_source,
            "gateway_as_destination_flows": gateway_as_dest,
            "nat_behaviour_matches_m_chain": nat_confirmed,
        },
        "top_source_ips": dict(source_counter.most_common(TOP_N)),
        "top_destination_ips": dict(dest_counter.most_common(TOP_N)),
        "services": dict(service_counter.most_common(TOP_N)),
        "protocols": dict(proto_counter.most_common()),
        "per_rule": per_rule,
        "window_candidates": {
            "convention": (
                "entity=(src|dst|proto|service), 60s bucket of flow end ts+duration"
            ),
            "total_candidate_windows": len(all_windows),
            "candidate_windows_inside_any_declared_interval": len(
                windows_in_any_attack_interval
            ),
            "candidate_windows_outside_every_declared_interval": len(
                all_windows - windows_in_any_attack_interval
            ),
            "gateway_to_web_server_windows_outside_intervals": len(
                gateway_to_web_windows_outside
            ),
        },
        "p1_entity_comparison": {
            "p1_priority_entity_keys": sorted(P1_PRIORITY_ENTITY_KEYS),
            "thursday_candidate_entity_keys_shared_with_p1": sorted(
                {entity for entity, _ in all_windows} & P1_PRIORITY_ENTITY_KEYS
            ),
        },
        "guarantees": {
            "labels_written": 0,
            "windows_materialised": 0,
            "models_loaded": 0,
            "postgresql_writes": 0,
            "unknown_to_benign_conversion": "forbidden",
        },
    }


def build_parser() -> argparse.ArgumentParser:
    """Return the audit command-line interface."""
    parser = argparse.ArgumentParser(
        description="Read-only NAT and population audit of the TH2 replay."
    )
    parser.add_argument("--conn-log", type=Path, default=REPO_ROOT / TH2_CONN_LOG)
    parser.add_argument("--audit-path", type=Path, default=REPO_ROOT / DEFAULT_AUDIT_PATH)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the audit, persist it as JSON, and print it."""
    args = build_parser().parse_args(argv)
    result = audit(args.conn_log)
    args.audit_path.parent.mkdir(parents=True, exist_ok=True)
    payload = (
        json.dumps(result, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    ).encode("utf-8")
    args.audit_path.write_bytes(payload)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
