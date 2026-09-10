"""Label-coverage correction — publish Production Finale v2 and the ground truth.

Commands::

    python -m scripts.run_label_coverage_correction --preflight
    python -m scripts.run_label_coverage_correction --publish
    python -m scripts.run_label_coverage_correction --verify

PostgreSQL is read **only**: the connection is switched to read-only before the
transaction begins and ``transaction_read_only`` is asserted before any statement.
No model is loaded, fitted or evaluated here. Outputs are additive, under
``artifacts/production/ml_dataset_v2/``; Production Finale v1 is never touched.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import csv
from datetime import UTC, datetime
from hashlib import sha256
import json
import os
from pathlib import Path
from typing import Any, Final, Sequence

from modules.detection.src.experiments.p1_dataset import (
    FEATURE_NAMES,
    Row,
    _assign_episodes,
    dataset_digest,
)
from modules.detection.src.lineage.labeling import load_label_manifest
from modules.detection.src.lineage.m5_policy_v2 import load_m5_v2_manifest
from modules.detection.src.lineage.m5_policy_v3 import (
    COVERAGE_CORRECTION_RULE_IDS,
    COVERAGE_EVIDENCE,
    DELIBERATELY_NOT_REALIGNED,
    M5_V3_RULE_VERSION,
    REALIGNED_RULE_IDS_V3,
    load_m5_v3_manifest,
    policy_diff,
    verify_v3_is_additive,
)
from modules.detection.src.persistence.monday_benign_persistence import (
    get_monday_benign_connection,
)
from modules.detection.src.production.ml_dataset import (
    DATASET_COLUMNS,
    EXCLUDED_SENTINEL,
    WINDOW_LABEL_COLUMNS,
    ProductionDatasetError,
    WindowLabel,
    canonical_digest,
    dataset_bytes,
    label_of,
    window_label_bytes,
    window_label_counts,
)
from modules.detection.src.production.ml_dataset_v2 import (
    EXPECTED_ATTACK_ENTITIES,
    EXPECTED_ATTACK_EPISODES,
    EXPECTED_ATTACK_TYPE_EPISODES,
    EXPECTED_ATTACK_TYPE_WINDOWS,
    EXPECTED_ATTACK_WINDOWS,
    EXPECTED_BENIGN_ROWS,
    EXPECTED_M6_WINDOWS,
    EXPECTED_MB6_WINDOWS,
    EXPECTED_MB7_WINDOW_LABELS,
    EXPECTED_TOTAL_ROWS,
    EXPECTED_UNKNOWN_WINDOWS,
    NEWLY_COVERED_FAMILIES,
    PRIORITY_FAMILIES,
    V1_ATTACK_EPISODES,
    V1_ATTACK_WINDOWS,
    V1_DATASET_FILE_SHA256,
    V1_TOTAL_ROWS,
)

REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[1]
V1_DIR: Final[Path] = REPO_ROOT / "artifacts" / "production" / "ml_dataset_v1"
OUT_DIR: Final[Path] = REPO_ROOT / "artifacts" / "production" / "ml_dataset_v2"
DATASET_PATH: Final[Path] = OUT_DIR / "ml_dataset.csv"
WINDOW_LABELS_PATH: Final[Path] = OUT_DIR / "window_labels.csv"
POLICY_PATH: Final[Path] = OUT_DIR / "label_policy_v3.json"
GROUND_TRUTH_PATH: Final[Path] = OUT_DIR / "ground_truth.json"
REPORT_PATH: Final[Path] = OUT_DIR / "LABEL_COVERAGE_REPORT.md"
MANIFEST_PATH: Final[Path] = OUT_DIR / "dataset_manifest.json"

PRODUCTION_DATABASE: Final[str] = "cybersentinel"
MB_DATABASE: Final[str] = "cybersentinel_test"

FROZEN_INPUTS: Final[tuple[str, ...]] = (
    "datasets/manifests/cicids2017_labels.yaml",
    "artifacts/production/ml_dataset_v1/ml_dataset.csv",
    "artifacts/production/ml_dataset_v1/window_labels.csv",
    "artifacts/production/ml_dataset_v1/dataset_manifest.json",
    "artifacts/reports/m6_v2_feature_window_run.json",
    "artifacts/reports/mb7_monday_benign_labeling_run.json",
)

IDENTITY_EXCLUDED_FIELDS: Final[frozenset[str]] = frozenset(
    {"frozen_at", "manifest_content_sha256"}
)


def sha256_file(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def json_bytes(document: Any) -> bytes:
    return json.dumps(document, indent=2, sort_keys=True).encode("utf-8") + b"\n"


def manifest_identity(document: dict[str, Any]) -> str:
    return canonical_digest(
        {k: v for k, v in document.items() if k not in IDENTITY_EXCLUDED_FIELDS}
    )


def publish_immutable(path: Path, payload: bytes) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() != payload:
            raise FileExistsError(
                f"immutable artifact already exists with different content: {path}"
            )
        return sha256(payload).hexdigest()
    temporary = path.with_name(f".{path.name}.tmp")
    try:
        with temporary.open("xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return sha256(payload).hexdigest()


def read_only_query(database: str, sql: str) -> list[tuple]:
    """Run one query inside a genuinely read-only transaction."""
    connection = get_monday_benign_connection(database)
    try:
        connection.read_only = True
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT current_database(), current_setting('transaction_read_only')"
            )
            observed, mode = cursor.fetchone()
            if observed != database:
                raise ProductionDatasetError(f"connected to {observed!r}, expected {database!r}")
            if mode != "on":
                raise ProductionDatasetError(f"{database}: transaction is not read-only")
            cursor.execute(sql)
            return cursor.fetchall()
    finally:
        connection.rollback()
        connection.close()


def compile_rules(manifest) -> list[dict[str, Any]]:
    """Compile a label manifest into the window-classification form used by P1."""
    from decimal import Decimal

    from modules.detection.src.lineage.labeling import LabelLedger

    ledger = LabelLedger(manifest)
    rules: list[dict[str, Any]] = []
    for interval in ledger.compiled_intervals:
        selector = interval.rule.selector
        rules.append(
            {
                "rule_id": interval.rule.rule_id,
                "disposition": interval.rule.disposition,
                "attack_type": (
                    f"{interval.rule.attack_family}/{interval.rule.attack_subtype}"
                    if interval.rule.attack_family
                    else None
                ),
                "mode": selector.mode,
                "attackers": {str(v) for v in selector.attacker_ips},
                "victims": {str(v) for v in selector.victim_ips},
                "protocols": {str(p) for p in selector.protocols},
                "victim_ports": {int(p) for p in (selector.victim_ports or [])},
                "start": Decimal(interval.start_utc.timestamp()),
                "end": Decimal(interval.end_utc.timestamp()),
            }
        )
    return rules


def classify(rules, src, dst, transport, port, start, end) -> tuple[str, str | None]:
    """Window classification under ANY_ATTACK precedence, port-aware."""
    hits = []
    for rule in rules:
        if rule["mode"] == "any_network":
            if start < rule["end"] and end > rule["start"]:
                hits.append(rule)
            continue
        if rule["protocols"] and transport not in rule["protocols"]:
            continue
        forward = src in rule["attackers"] and dst in rule["victims"]
        reverse = src in rule["victims"] and dst in rule["attackers"]
        if not (forward or reverse):
            continue
        if rule["victim_ports"]:
            victim_port = port if forward else None
            if victim_port is None or victim_port not in rule["victim_ports"]:
                continue
        if start < rule["end"] and end > rule["start"]:
            hits.append(rule)
    for wanted in ("target_attack", "known_other_attack", "ambiguous", "benign_reference"):
        for rule in hits:
            if rule["disposition"] == wanted:
                return wanted, rule["attack_type"]
    return "unknown", None


def load_m_chain_windows() -> list[tuple]:
    """Read every M6 window with the fields the classifier needs. Read-only."""
    features = ", ".join(FEATURE_NAMES)
    return read_only_query(
        PRODUCTION_DATABASE,
        "SELECT window_id::text, output_partition, entity_source_ip,"
        " entity_destination_ip, entity_transport, entity_service,"
        f" window_start_time, window_end_time, {features}"
        " FROM m6_canonical.feature_windows",
    )


def window_destination_ports() -> dict[tuple[str, str, int], int]:
    """Majority destination port per M6 window, from the canonical events.

    ``FeatureWindowV2`` does not persist a port, and the frozen DoS rules are
    port-constrained, so the port is recovered from ``m4_canonical`` by the same
    ``(partition, entity_key, minute bucket)`` key M6 used.
    """
    rows = read_only_query(
        PRODUCTION_DATABASE,
        """
        SELECT output_partition,
               host(source_ip) || '|' || host(destination_ip) || '|'
                 || transport || '|' || coalesce(service, 'none') AS entity_key,
               (floor(event_start_time/60)*60)::bigint AS bucket,
               destination_port,
               count(*) AS n
        FROM m4_canonical.flow_end_events
        GROUP BY 1, 2, 3, 4
        """,
    )
    best: dict[tuple[str, str, int], tuple[int, int]] = {}
    for partition, entity_key, bucket, port, count in rows:
        key = (partition, entity_key, int(bucket))
        current = best.get(key)
        if current is None or int(count) > current[1]:
            best[key] = (int(port), int(count))
    return {key: value[0] for key, value in best.items()}


def load_negatives_read_only() -> list[Row]:
    """The MB-LABEL ``benign_reference`` windows, unchanged from v1."""
    features = ", ".join(f"f.{name}" for name in FEATURE_NAMES)
    raw = read_only_query(
        MB_DATABASE,
        "SELECT f.window_id::text, f.output_partition, f.entity_source_ip,"
        " f.entity_destination_ip, f.entity_transport, f.entity_service,"
        f" f.window_start_time, {features}"
        " FROM mb6_canonical.feature_windows f"
        " JOIN mb7_canonical.window_labels w ON w.source_window_id = f.window_id"
        " WHERE w.disposition = 'benign_reference'",
    )
    negatives: list[Row] = []
    for record in raw:
        wid, partition, src, dst, transport, service, start = record[:7]
        negatives.append(
            Row(
                row_id=wid,
                source="mb6",
                label=0,
                disposition="benign_reference",
                attack_type=None,
                entity_key="|".join((src, dst, transport, service)),
                episode_id=None,
                partition=partition,
                window_start_epoch=int(start),
                features=tuple(float(v) for v in record[7:]),
            )
        )
    return negatives


def materialise(rules, windows, ports) -> tuple[list[WindowLabel], list[Row]]:
    """Label every M6 window and collect the supervised positives."""
    labels: list[WindowLabel] = []
    positives: list[Row] = []
    for record in windows:
        wid, partition, src, dst, transport, service, start, end = record[:8]
        entity_key = "|".join((src, dst, transport, service))
        bucket = int(start)
        port = ports.get((partition, entity_key, bucket))
        disposition, attack_type = classify(
            rules, src, dst, transport, port, start, end
        )
        labels.append(
            WindowLabel(
                window_id=wid,
                output_partition=partition,
                entity_key=entity_key,
                window_start_epoch=bucket,
                disposition=disposition,
                attack_type=attack_type,
            )
        )
        if disposition in ("target_attack", "known_other_attack"):
            if attack_type is None:
                raise ProductionDatasetError(f"attack window {wid} has no attack type")
            positives.append(
                Row(
                    row_id=wid,
                    source="m6",
                    label=1,
                    disposition=disposition,
                    attack_type=attack_type,
                    entity_key=entity_key,
                    episode_id=None,
                    partition=partition,
                    window_start_epoch=bucket,
                    features=tuple(float(v) for v in record[8:]),
                )
            )
    return labels, _assign_episodes(positives)


def ground_truth(positives: Sequence[Row], negatives: Sequence[Row]) -> dict[str, Any]:
    """The ground-truth table required before any performance is measured."""
    by_family: dict[str, dict[str, Any]] = {}
    for row in positives:
        family = str(row.attack_type)
        entry = by_family.setdefault(
            family,
            {
                "attack_type": family,
                "disposition": row.disposition,
                "windows": 0,
                "episodes": set(),
                "entities": set(),
                "partitions": set(),
                "first_window_epoch": row.window_start_epoch,
                "last_window_epoch": row.window_start_epoch,
            },
        )
        entry["windows"] += 1
        entry["episodes"].add(row.episode_id)
        entry["entities"].add(row.entity_key)
        entry["partitions"].add(row.partition)
        entry["first_window_epoch"] = min(entry["first_window_epoch"], row.window_start_epoch)
        entry["last_window_epoch"] = max(entry["last_window_epoch"], row.window_start_epoch)
    table = []
    for family in sorted(by_family):
        entry = by_family[family]
        table.append(
            {
                "attack_type": family,
                "disposition": entry["disposition"],
                "priority_family": family in PRIORITY_FAMILIES,
                "newly_covered_by_v3": family in NEWLY_COVERED_FAMILIES,
                "windows": entry["windows"],
                "episodes": len(entry["episodes"]),
                "entities": len(entry["entities"]),
                "entity_keys": sorted(entry["entities"]),
                "partitions": sorted(entry["partitions"]),
                "first_window_epoch": entry["first_window_epoch"],
                "last_window_epoch": entry["last_window_epoch"],
                "episode_ids": sorted(str(e) for e in entry["episodes"]),
            }
        )
    document = {
        "purpose": (
            "ground truth available in Production Finale v2, published before any "
            "model performance is measured"
        ),
        "label_policy": "M5 v3, NAT realignment extended to three DoS rules",
        "families": table,
        "totals": {
            "attack_windows": sum(e["windows"] for e in table),
            "attack_episodes": sum(e["episodes"] for e in table),
            "attack_entities": len({k for e in table for k in e["entity_keys"]}),
            "benign_windows": len(negatives),
            "benign_entities": len({row.entity_key for row in negatives}),
            "total_rows": len(positives) + len(negatives),
        },
        "priority_family_coverage": {
            family: {
                "represented": any(e["attack_type"] == family for e in table),
                "windows": next(
                    (e["windows"] for e in table if e["attack_type"] == family), 0
                ),
                "episodes": next(
                    (e["episodes"] for e in table if e["attack_type"] == family), 0
                ),
            }
            for family in PRIORITY_FAMILIES
        },
    }
    document["content_sha256"] = canonical_digest(document)
    return document


def verify(
    labels: Sequence[WindowLabel],
    positives: Sequence[Row],
    negatives: Sequence[Row],
    payload: bytes,
    counts: dict[str, int],
) -> list[dict[str, Any]]:
    """Every invariant the corrected dataset must satisfy before publication."""
    checks: list[dict[str, Any]] = []

    def record(name: str, passed: bool, detail: Any) -> None:
        checks.append({"check": name, "passed": bool(passed), "detail": detail})
        if not passed:
            raise ProductionDatasetError(f"{name}: {detail}")

    dispositions = window_label_counts(labels)
    per_family_windows = Counter(str(r.attack_type) for r in positives)
    per_family_episodes = {
        family: len({r.episode_id for r in positives if r.attack_type == family})
        for family in per_family_windows
    }

    record("m6_windows", len(labels) == EXPECTED_M6_WINDOWS, len(labels))
    record("benign_rows", len(negatives) == EXPECTED_BENIGN_ROWS, len(negatives))
    record("attack_windows", len(positives) == EXPECTED_ATTACK_WINDOWS, len(positives))
    record(
        "attack_episodes",
        len({r.episode_id for r in positives}) == EXPECTED_ATTACK_EPISODES,
        len({r.episode_id for r in positives}),
    )
    record(
        "attack_entities",
        len({r.entity_key for r in positives}) == EXPECTED_ATTACK_ENTITIES,
        len({r.entity_key for r in positives}),
    )
    record(
        "total_rows",
        len(positives) + len(negatives) == EXPECTED_TOTAL_ROWS,
        len(positives) + len(negatives),
    )
    record(
        "unknown_windows",
        dispositions["unknown"] == EXPECTED_UNKNOWN_WINDOWS,
        dispositions["unknown"],
    )
    record(
        "per_family_windows",
        dict(per_family_windows) == EXPECTED_ATTACK_TYPE_WINDOWS,
        dict(per_family_windows),
    )
    record(
        "per_family_episodes",
        per_family_episodes == EXPECTED_ATTACK_TYPE_EPISODES,
        per_family_episodes,
    )
    record(
        "every_priority_family_is_represented",
        all(family in per_family_windows for family in PRIORITY_FAMILIES),
        sorted(per_family_windows),
    )
    record(
        "three_families_are_newly_covered",
        all(per_family_windows.get(f, 0) > 0 for f in NEWLY_COVERED_FAMILIES),
        {f: per_family_windows.get(f, 0) for f in NEWLY_COVERED_FAMILIES},
    )
    record(
        "v1_families_are_unchanged",
        all(
            per_family_windows[f] == EXPECTED_ATTACK_TYPE_WINDOWS[f]
            for f in ("botnet/ares", "brute_force/ftp_patator", "brute_force/ssh_patator",
                      "ddos/loit", "dos/hulk")
        ),
        {f: per_family_windows[f] for f in
         ("botnet/ares", "brute_force/ftp_patator", "brute_force/ssh_patator",
          "ddos/loit", "dos/hulk")},
    )
    record(
        "net_gain_matches_the_audit",
        len(positives) - V1_ATTACK_WINDOWS == 88
        and len({r.episode_id for r in positives}) - V1_ATTACK_EPISODES == 14,
        {
            "windows": len(positives) - V1_ATTACK_WINDOWS,
            "episodes": len({r.episode_id for r in positives}) - V1_ATTACK_EPISODES,
        },
    )
    record(
        "unknown_decrease_equals_window_gain",
        counts["v1_unknown"] - dispositions["unknown"] == len(positives) - V1_ATTACK_WINDOWS,
        counts["v1_unknown"] - dispositions["unknown"],
    )
    record(
        "no_benign_on_the_m_chain",
        dispositions["benign_reference"] == 0,
        dispositions["benign_reference"],
    )
    record(
        "uncertainty_never_became_a_negative",
        all(
            label.dataset_label is None
            for label in labels
            if label.disposition in ("unknown", "ambiguous")
        ),
        dispositions["unknown"] + dispositions["ambiguous"],
    )
    record(
        "dispositions_are_supervised_only",
        {r.disposition for r in list(positives) + list(negatives)}
        == {"target_attack", "known_other_attack", "benign_reference"},
        sorted({r.disposition for r in list(positives) + list(negatives)}),
    )
    record(
        "header_is_the_v1_contract",
        payload.split(b"\n", 1)[0] == ",".join(DATASET_COLUMNS).encode("utf-8"),
        ",".join(DATASET_COLUMNS),
    )
    record(
        "v1_dataset_is_untouched",
        sha256_file(V1_DIR / "ml_dataset.csv") == V1_DATASET_FILE_SHA256,
        sha256_file(V1_DIR / "ml_dataset.csv"),
    )
    record(
        "v2_is_strictly_larger_than_v1",
        len(positives) > V1_ATTACK_WINDOWS
        and len(positives) + len(negatives) > V1_TOTAL_ROWS,
        {"v1": V1_TOTAL_ROWS, "v2": len(positives) + len(negatives)},
    )
    return checks


def build_context(progress: bool = True) -> dict[str, Any]:
    v1_manifest = load_label_manifest(REPO_ROOT / "datasets/manifests/cicids2017_labels.yaml")
    v2_manifest = load_m5_v2_manifest(REPO_ROOT)
    v3_manifest = load_m5_v3_manifest(REPO_ROOT)
    policy_checks = verify_v3_is_additive(v1_manifest, v2_manifest, v3_manifest)
    if progress:
        print(f"{len(policy_checks)} policy-additivity checks pass", flush=True)

    upstream = {
        "m6_windows": int(
            read_only_query(
                PRODUCTION_DATABASE, "SELECT count(*) FROM m6_canonical.feature_windows"
            )[0][0]
        ),
        "mb6_windows": int(
            read_only_query(
                MB_DATABASE, "SELECT count(*) FROM mb6_canonical.feature_windows"
            )[0][0]
        ),
        "mb7_window_labels": int(
            read_only_query(
                MB_DATABASE, "SELECT count(*) FROM mb7_canonical.window_labels"
            )[0][0]
        ),
    }
    if upstream["m6_windows"] != EXPECTED_M6_WINDOWS:
        raise ProductionDatasetError(f"M6 changed: {upstream}")
    if upstream["mb6_windows"] != EXPECTED_MB6_WINDOWS:
        raise ProductionDatasetError(f"MB6 changed: {upstream}")
    if upstream["mb7_window_labels"] != EXPECTED_MB7_WINDOW_LABELS:
        raise ProductionDatasetError(f"MB7 changed: {upstream}")

    if progress:
        print("recovering the destination port per window from m4_canonical ...", flush=True)
    ports = window_destination_ports()
    windows = load_m_chain_windows()
    rules = compile_rules(v3_manifest)
    labels, positives = materialise(rules, windows, ports)
    negatives = load_negatives_read_only()
    if progress:
        print(
            f"labelled {len(labels)} M6 windows -> {len(positives)} attack windows",
            flush=True,
        )

    v1_labels = {}
    with (V1_DIR / "window_labels.csv").open(newline="", encoding="utf-8") as stream:
        for record in csv.DictReader(stream):
            v1_labels[record["window_id"]] = record["disposition"]
    v1_unknown = sum(1 for d in v1_labels.values() if d == "unknown")

    rows = list(positives) + list(negatives)
    payload = dataset_bytes(rows)
    checks = verify(labels, positives, negatives, payload, {"v1_unknown": v1_unknown})
    truth = ground_truth(positives, negatives)

    changed = [
        {
            "window_id": label.window_id,
            "entity_key": label.entity_key,
            "window_start_epoch": label.window_start_epoch,
            "v1_disposition": v1_labels.get(label.window_id, "<absent>"),
            "v3_disposition": label.disposition,
            "attack_type": label.attack_type,
        }
        for label in labels
        if v1_labels.get(label.window_id) != label.disposition
    ]
    if progress:
        print(f"{len(changed)} windows change disposition", flush=True)

    return {
        "policy_checks": policy_checks,
        "policy_diff": policy_diff(v2_manifest, v3_manifest),
        "upstream": upstream,
        "labels": labels,
        "positives": positives,
        "negatives": negatives,
        "rows": rows,
        "payload": payload,
        "labels_payload": window_label_bytes(labels),
        "dataset_content_sha256": dataset_digest(rows),
        "checks": checks,
        "ground_truth": truth,
        "changed_windows": changed,
        "v1_unknown": v1_unknown,
    }


def policy_document(context: dict[str, Any]) -> dict[str, Any]:
    document = {
        "policy": "M5 v3 — label-coverage correction",
        "rule_version": M5_V3_RULE_VERSION,
        "derived_from": "frozen M5 v1 manifest, read-only",
        "realigned_rule_ids": sorted(REALIGNED_RULE_IDS_V3),
        "newly_realigned_by_v3": sorted(COVERAGE_CORRECTION_RULE_IDS),
        "deliberately_not_realigned": DELIBERATELY_NOT_REALIGNED,
        "observed_evidence": COVERAGE_EVIDENCE,
        "transformation": (
            "attacker_ips -> ('172.16.0.1',); 172.16.0.1 removed from victim_ips as "
            "required by EndpointSelector role disjointness; nothing else changes"
        ),
        "false_positive_risk": (
            "inside the three intervals, 100% of traffic sourced by 172.16.0.1 targets "
            "192.168.10.50:80/tcp, the declared victim, port and protocol"
        ),
        "m5_v1_modified": False,
        "m5_v2_modified": False,
        "production_v1_modified": False,
        "additivity_checks": context["policy_checks"],
        "per_rule_diff_v2_to_v3": list(context["policy_diff"]),
    }
    document["content_sha256"] = canonical_digest(document)
    return document


def render_report(context: dict[str, Any]) -> str:
    truth = context["ground_truth"]
    lines: list[str] = []
    add = lines.append
    add("# Label-coverage correction — Production Finale v2")
    add("")
    add(
        "Generated from the artifacts of this run. Production Finale v1 is untouched "
        "and remains the dataset of record for every published experiment."
    )
    add("")
    add("## What changed")
    add("")
    add("| Item | v1 | v2 |")
    add("|---|---:|---:|")
    add(f"| Label policy | M5 v2 | **M5 v3** |")
    add(f"| Attack windows | {V1_ATTACK_WINDOWS} | **{truth['totals']['attack_windows']}** |")
    add(f"| Attack episodes | {V1_ATTACK_EPISODES} | **{truth['totals']['attack_episodes']}** |")
    add(f"| Attack entities | {EXPECTED_ATTACK_ENTITIES} | {truth['totals']['attack_entities']} |")
    add(f"| Benign windows | {EXPECTED_BENIGN_ROWS} | {truth['totals']['benign_windows']} |")
    add(f"| Total rows | {V1_TOTAL_ROWS} | **{truth['totals']['total_rows']}** |")
    add(f"| M6 `unknown` | {context['v1_unknown']} | {window_label_counts(context['labels'])['unknown']} |")
    add("")
    add(
        f"{len(context['changed_windows'])} windows changed disposition, all of them "
        "from `unknown` to an attack disposition. No window ever moved towards benign."
    )
    add("")
    add("## Ground truth available in v2")
    add("")
    add("| Attack type | Disposition | Priority | New in v3 | Windows | Episodes | Entities | Partition |")
    add("|---|---|:-:|:-:|---:|---:|---:|---|")
    for entry in truth["families"]:
        add(
            f"| `{entry['attack_type']}` | {entry['disposition']} | "
            f"{'yes' if entry['priority_family'] else '—'} | "
            f"{'**yes**' if entry['newly_covered_by_v3'] else '—'} | "
            f"{entry['windows']} | {entry['episodes']} | {entry['entities']} | "
            f"{', '.join(p.split('_')[1] if '_' in p else p for p in entry['partitions'])} |"
        )
    add("")
    add("## Priority family coverage")
    add("")
    add("| Family | Represented | Windows | Episodes |")
    add("|---|:-:|---:|---:|")
    for family, entry in truth["priority_family_coverage"].items():
        add(
            f"| `{family}` | {'**yes**' if entry['represented'] else 'NO'} | "
            f"{entry['windows']} | {entry['episodes']} |"
        )
    add("")
    add("## Scope and limits")
    add("")
    add(
        "The correction adds windows and episodes but **no new entity**: the two "
        "entity keys involved were already attack entities. The effective sample size "
        "stays at 9 attack entities, and the day/capture confounder is unchanged: all "
        "negatives still come from the parallel Monday capture."
    )
    add("")
    add(
        "`friday-portscan` and `wednesday-heartbleed` were deliberately left "
        "unrealigned, and Thursday remains outside the canonical chain with its NAT "
        "behaviour unverified. Each reason is recorded in `label_policy_v3.json`."
    )
    add("")
    return "\n".join(lines)


def summarise(context: dict[str, Any]) -> dict[str, Any]:
    truth = context["ground_truth"]
    return {
        "status": "preflight_ok",
        "artifacts_written": 0,
        "models_loaded": 0,
        "postgresql_writes": 0,
        "policy_checks": len(context["policy_checks"]),
        "invariant_checks": len(context["checks"]),
        "upstream": context["upstream"],
        "windows_changed_disposition": len(context["changed_windows"]),
        "ground_truth": {
            entry["attack_type"]: {
                "windows": entry["windows"],
                "episodes": entry["episodes"],
                "new_in_v3": entry["newly_covered_by_v3"],
            }
            for entry in truth["families"]
        },
        "totals": truth["totals"],
        "dataset_content_sha256": context["dataset_content_sha256"],
        "dataset_file_sha256": sha256(context["payload"]).hexdigest(),
    }


def publish(context: dict[str, Any]) -> dict[str, Any]:
    if any(not check["passed"] for check in context["checks"]):
        raise ProductionDatasetError("refusing to publish with a failed invariant")
    outputs: dict[str, str] = {}
    outputs["ml_dataset.csv"] = publish_immutable(DATASET_PATH, context["payload"])
    outputs["window_labels.csv"] = publish_immutable(
        WINDOW_LABELS_PATH, context["labels_payload"]
    )
    outputs["label_policy_v3.json"] = publish_immutable(
        POLICY_PATH, json_bytes(policy_document(context))
    )
    outputs["ground_truth.json"] = publish_immutable(
        GROUND_TRUTH_PATH, json_bytes(context["ground_truth"])
    )
    outputs["LABEL_COVERAGE_REPORT.md"] = publish_immutable(
        REPORT_PATH, render_report(context).encode("utf-8")
    )
    truth = context["ground_truth"]
    manifest = {
        "schema_version": "2.0.0",
        "experiment": "Production Finale v2 — label-coverage correction",
        "frozen_at": datetime.now(UTC).isoformat(),
        "label_policy": "M5 v3",
        "label_policy_map": {
            "target_attack": 1,
            "known_other_attack": 1,
            "benign_reference": 0,
            "unknown": "excluded",
            "ambiguous": "excluded",
        },
        "unknown_to_benign_conversion": "forbidden",
        "feature_budget": list(FEATURE_NAMES),
        "feature_count": len(FEATURE_NAMES),
        "dataset_columns": list(DATASET_COLUMNS),
        "window_label_columns": list(WINDOW_LABEL_COLUMNS),
        "observed_counts": {
            **context["upstream"],
            "attack_rows": truth["totals"]["attack_windows"],
            "attack_episodes": truth["totals"]["attack_episodes"],
            "attack_entities": truth["totals"]["attack_entities"],
            "benign_rows": truth["totals"]["benign_windows"],
            "total_rows": truth["totals"]["total_rows"],
            "m_unknown_excluded": window_label_counts(context["labels"])["unknown"],
        },
        "v1_reference": {
            "attack_rows": V1_ATTACK_WINDOWS,
            "attack_episodes": V1_ATTACK_EPISODES,
            "total_rows": V1_TOTAL_ROWS,
            "dataset_file_sha256": V1_DATASET_FILE_SHA256,
            "modified_by_this_run": False,
        },
        "net_gain": {
            "windows": truth["totals"]["attack_windows"] - V1_ATTACK_WINDOWS,
            "episodes": truth["totals"]["attack_episodes"] - V1_ATTACK_EPISODES,
            "entities": 0,
        },
        "dataset_content_sha256": context["dataset_content_sha256"],
        "windows_changed_disposition": len(context["changed_windows"]),
        "models_loaded": 0,
        "models_fitted": 0,
        "performance_measured": False,
        "postgresql_writes": 0,
        "m7_schema_created": False,
        "m5_v1_modified": False,
        "m5_v2_modified": False,
        "production_v1_modified": False,
        "frozen_experiments_modified": False,
        "frozen_inputs": {name: sha256_file(REPO_ROOT / name) for name in FROZEN_INPUTS},
        "outputs": outputs,
    }
    manifest["manifest_content_sha256"] = manifest_identity(manifest)
    if MANIFEST_PATH.exists():
        existing = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        if existing.get("manifest_content_sha256") != manifest["manifest_content_sha256"]:
            raise FileExistsError(f"immutable manifest differs in identity: {MANIFEST_PATH}")
    else:
        publish_immutable(MANIFEST_PATH, json_bytes(manifest))
    return {
        "status": "published",
        "manifest_content_sha256": manifest["manifest_content_sha256"],
        "outputs": {**outputs, "dataset_manifest.json": sha256_file(MANIFEST_PATH)},
    }


def verify_published() -> dict[str, Any]:
    if not MANIFEST_PATH.exists():
        raise ProductionDatasetError("dataset_manifest.json absent; run --publish")
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    mismatched = [
        name
        for name, digest in manifest["outputs"].items()
        if sha256_file(OUT_DIR / name) != digest
    ]
    changed = [
        name
        for name, digest in manifest["frozen_inputs"].items()
        if sha256_file(REPO_ROOT / name) != digest
    ]
    result = {
        "manifest_digest_stable": manifest_identity(manifest)
        == manifest["manifest_content_sha256"],
        "mismatched_outputs": mismatched,
        "frozen_inputs_changed": changed,
        "v1_untouched": sha256_file(V1_DIR / "ml_dataset.csv") == V1_DATASET_FILE_SHA256,
        "observed_counts": manifest["observed_counts"],
    }
    if (
        not result["manifest_digest_stable"]
        or mismatched
        or changed
        or not result["v1_untouched"]
    ):
        raise ProductionDatasetError(f"published verification failed: {result}")
    return result


def parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--preflight", action="store_true")
    action.add_argument("--publish", action="store_true")
    action.add_argument("--verify", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    if args.verify:
        print(json.dumps(verify_published(), indent=2, sort_keys=True))
        return 0
    context = build_context()
    if args.preflight:
        print(json.dumps(summarise(context), indent=2, sort_keys=True))
        return 0
    print(json.dumps(publish(context), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
