"""P1/A supervised dataset construction. Read-only against PostgreSQL.

Scope
-----
Builds the ratified supervised population:

* positives  : the 376 M6 attack windows, typed by the frozen M5 v2 rule that
  matched them (``target_attack`` and ``known_other_attack``);
* negatives  : the 70,578 MB6 windows labelled ``benign_reference`` by MB-LABEL.

``unknown`` and ``ambiguous`` are carried nowhere near supervision. No label is
modified, no row is written to any database, nothing is sampled.

Conservative decisions taken here and recorded in the manifest
--------------------------------------------------------------
D1  The dataset is materialised as **files**, never as a PostgreSQL table, so P1
    performs zero database writes and the M/MB chains stay byte-identical. This
    also sidesteps the M6/MB6 cross-database question without moving any data.
D2  **Episode** = maximal run of consecutive 60-second windows sharing the same
    ``(attack_type, entity_key)``. A gap larger than one window length starts a
    new episode. Deterministic, derived only from published evidence.
D3  **Positive folds** = the five attack types, leave-one-type-out.
D4  **Negative folds** = deterministic SHA-256 of the benign ``entity_key``
    modulo five. No benign entity ever appears in both train and test. This is
    stricter than a random split and requires no randomness at all.
D5  No feature transform of any kind. The five volume features are handed to the
    model exactly as stored.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from decimal import Decimal
from hashlib import sha256
import json
from typing import Any, Final

from modules.detection.src.lineage.labeling import LabelLedger
from modules.detection.src.lineage.m5_policy_v2 import load_m5_v2_manifest
from modules.detection.src.persistence.monday_benign_persistence import (
    get_monday_benign_connection,
)


PRODUCTION_DATABASE: Final[str] = "cybersentinel"
MB_DATABASE: Final[str] = "cybersentinel_test"

#: The only five columns admitted as model input, ratified 2026-08-13.
FEATURE_NAMES: Final[tuple[str, ...]] = (
    "event_count",
    "source_packets_total",
    "destination_packets_total",
    "source_bytes_total",
    "destination_bytes_total",
)

#: Columns proven to separate the classes perfectly and therefore forbidden.
FORBIDDEN_COLUMNS: Final[tuple[str, ...]] = (
    "entity_source_ip",
    "entity_destination_ip",
    "entity_service",
    "entity_transport",
    "distinct_destination_ports",
    "distinct_destination_ips",
    "distinct_source_ips",
    "output_partition",
    "window_start_time",
    "window_end_time",
    "prediction_time",
    "record_available_time",
    "sensor_run_id",
    "capture_id",
    "dataset_snapshot_id",
    "window_id",
    "window_bytes_sha256",
    "persisted_at",
)

WINDOW_LENGTH_SECONDS: Final[int] = 60
NEGATIVE_FOLD_COUNT: Final[int] = 5


class P1DatasetError(RuntimeError):
    """The P1 dataset cannot be built or failed a leakage guard."""


def _query(database: str, sql: str, params: dict | None = None) -> list[tuple]:
    """Run one read-only query on an explicitly named database."""
    conn = get_monday_benign_connection(database)
    try:
        with conn.cursor() as cur:
            cur.execute("SET default_transaction_read_only = on")
            cur.execute(sql, params or {})
            return cur.fetchall()
    finally:
        conn.close()


@dataclass(frozen=True, slots=True)
class Row:
    """One dataset row. Only ``features`` is ever shown to a model."""

    row_id: str
    source: str
    label: int
    disposition: str
    attack_type: str | None
    entity_key: str
    episode_id: str | None
    partition: str
    window_start_epoch: int
    features: tuple[float, ...]


def _compiled_rules(repository_root: str) -> list[dict[str, Any]]:
    """Compile the frozen M5 v2 rules once, for attack typing only."""
    ledger = LabelLedger(load_m5_v2_manifest(repository_root))
    rules = []
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
                "start": Decimal(interval.start_utc.timestamp()),
                "end": Decimal(interval.end_utc.timestamp()),
            }
        )
    return rules


def _classify(rules, src, dst, transport, start, end) -> tuple[str, str | None]:
    """Return ``(disposition, attack_type)`` for one window under M5 v2."""
    hits = []
    for rule in rules:
        if rule["mode"] == "any_network":
            if start < rule["end"] and end > rule["start"]:
                hits.append(rule)
            continue
        if rule["protocols"] and transport not in rule["protocols"]:
            continue
        role = (src in rule["attackers"] and dst in rule["victims"]) or (
            src in rule["victims"] and dst in rule["attackers"]
        )
        if not role:
            continue
        if start < rule["end"] and end > rule["start"]:
            hits.append(rule)
    for wanted in (
        "target_attack",
        "known_other_attack",
        "ambiguous",
        "benign_reference",
    ):
        for rule in hits:
            if rule["disposition"] == wanted:
                return wanted, rule["attack_type"]
    return "unknown", None


def _assign_episodes(rows: list[Row]) -> list[Row]:
    """Attach a deterministic episode id to every positive row (decision D2)."""
    grouped: dict[tuple[str, str], list[Row]] = defaultdict(list)
    for row in rows:
        grouped[(row.attack_type or "", row.entity_key)].append(row)
    out: list[Row] = []
    for (attack_type, entity_key), members in sorted(grouped.items()):
        members.sort(key=lambda r: r.window_start_epoch)
        sequence = 0
        previous: int | None = None
        for member in members:
            if previous is not None and (
                member.window_start_epoch - previous > WINDOW_LENGTH_SECONDS
            ):
                sequence += 1
            previous = member.window_start_epoch
            out.append(
                Row(
                    row_id=member.row_id,
                    source=member.source,
                    label=member.label,
                    disposition=member.disposition,
                    attack_type=member.attack_type,
                    entity_key=member.entity_key,
                    episode_id=f"{attack_type}|{entity_key}|{sequence:03d}",
                    partition=member.partition,
                    window_start_epoch=member.window_start_epoch,
                    features=member.features,
                )
            )
    return out


def negative_fold_of(entity_key: str, fold_count: int = NEGATIVE_FOLD_COUNT) -> int:
    """Deterministic benign fold assignment (decision D4).

    ``fold_count`` defaults to five so P1, P2 and P3 keep byte-identical
    behaviour. P4/C passes three, because excluding the multi-family entities
    removes ``ddos/loit`` and ``dos/hulk`` entirely and leaves three attack types.
    """
    digest = sha256(entity_key.encode("utf-8")).hexdigest()
    return int(digest[:8], 16) % fold_count


def load_positives(repository_root: str) -> list[Row]:
    """Extract and type the M6 attack windows. Read-only."""
    rules = _compiled_rules(repository_root)
    features = ", ".join(FEATURE_NAMES)
    raw = _query(
        PRODUCTION_DATABASE,
        "SELECT window_id::text, output_partition, entity_source_ip,"
        " entity_destination_ip, entity_transport, entity_service,"
        f" window_start_time, window_end_time, {features}"
        " FROM m6_canonical.feature_windows",
    )
    positives: list[Row] = []
    for record in raw:
        wid, partition, src, dst, transport, service, start, end = record[:8]
        disposition, attack_type = _classify(rules, src, dst, transport, start, end)
        if disposition not in ("target_attack", "known_other_attack"):
            continue
        if attack_type is None:
            raise P1DatasetError(f"attack window {wid} has no attack type")
        positives.append(
            Row(
                row_id=wid,
                source="m6",
                label=1,
                disposition=disposition,
                attack_type=attack_type,
                entity_key="|".join((src, dst, transport, service)),
                episode_id=None,
                partition=partition,
                window_start_epoch=int(start),
                features=tuple(float(v) for v in record[8:]),
            )
        )
    return _assign_episodes(positives)


def load_negatives() -> list[Row]:
    """Extract the MB-LABEL ``benign_reference`` windows. Read-only."""
    features = ", ".join(f"f.{name}" for name in FEATURE_NAMES)
    raw = _query(
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


@dataclass(slots=True)
class Fold:
    """One frozen leave-one-attack-type-out fold."""

    index: int
    held_out_attack_type: str
    train_row_ids: list[str] = field(default_factory=list)
    test_row_ids: list[str] = field(default_factory=list)


def build_folds(
    positives: list[Row],
    negatives: list[Row],
    expected_types: int | None = NEGATIVE_FOLD_COUNT,
) -> list[Fold]:
    """Freeze the leave-one-attack-type-out folds (decisions D3 and D4).

    One fold per attack type present. ``expected_types`` guards against silent
    population drift: P1, P2 and P3 pass the default five, so any change in the
    attack-type inventory raises instead of quietly producing a different design.
    P4/C passes ``None`` because it deliberately removes two attack types.
    """
    types = sorted({row.attack_type for row in positives if row.attack_type})
    if expected_types is not None and len(types) != expected_types:
        raise P1DatasetError(
            f"expected {expected_types} attack types, found {len(types)}: {types}"
        )
    if not types:
        raise P1DatasetError("no attack type present")
    fold_count = len(types)
    negative_fold = {
        row.row_id: negative_fold_of(row.entity_key, fold_count)
        for row in negatives
    }
    folds: list[Fold] = []
    for index, attack_type in enumerate(types):
        fold = Fold(index=index, held_out_attack_type=attack_type)
        for row in positives:
            (fold.test_row_ids if row.attack_type == attack_type
             else fold.train_row_ids).append(row.row_id)
        for row in negatives:
            (fold.test_row_ids if negative_fold[row.row_id] == index
             else fold.train_row_ids).append(row.row_id)
        folds.append(fold)
    return folds


def verify_no_leakage(
    folds: list[Fold], rows: dict[str, Row]
) -> list[dict[str, Any]]:
    """Prove every fold is disjoint on window, type, episode and benign entity."""
    checks: list[dict[str, Any]] = []
    for fold in folds:
        train_ids = set(fold.train_row_ids)
        test_ids = set(fold.test_row_ids)
        train = [rows[i] for i in train_ids]
        test = [rows[i] for i in test_ids]

        shared_windows = train_ids & test_ids
        train_types = {r.attack_type for r in train if r.label == 1}
        test_types = {r.attack_type for r in test if r.label == 1}
        train_episodes = {r.episode_id for r in train if r.label == 1}
        test_episodes = {r.episode_id for r in test if r.label == 1}
        train_neg_entities = {r.entity_key for r in train if r.label == 0}
        test_neg_entities = {r.entity_key for r in test if r.label == 0}

        result = {
            "fold": fold.index,
            "held_out_attack_type": fold.held_out_attack_type,
            "train_rows": len(train_ids),
            "test_rows": len(test_ids),
            "train_positives": sum(1 for r in train if r.label == 1),
            "test_positives": sum(1 for r in test if r.label == 1),
            "train_negatives": sum(1 for r in train if r.label == 0),
            "test_negatives": sum(1 for r in test if r.label == 0),
            "shared_window_ids": len(shared_windows),
            "shared_attack_types": sorted(train_types & test_types),
            "shared_episodes": sorted(
                e for e in (train_episodes & test_episodes) if e
            ),
            "shared_benign_entities": len(train_neg_entities & test_neg_entities),
            "test_episode_count": len([e for e in test_episodes if e]),
        }
        failures = []
        if result["shared_window_ids"]:
            failures.append("window ids shared between train and test")
        if result["shared_attack_types"]:
            failures.append("attack type shared between train and test")
        if result["shared_episodes"]:
            failures.append("attack episode shared between train and test")
        if result["shared_benign_entities"]:
            failures.append("benign entity shared between train and test")
        if not result["test_positives"]:
            failures.append("fold has no test positives")
        if not result["train_positives"]:
            failures.append("fold has no train positives")
        result["failures"] = failures
        checks.append(result)
    return checks


def dataset_digest(rows: list[Row]) -> str:
    """Canonical, order-independent SHA-256 over the whole dataset."""
    lines = sorted(
        json.dumps(
            {
                "row_id": r.row_id,
                "source": r.source,
                "label": r.label,
                "disposition": r.disposition,
                "attack_type": r.attack_type,
                "entity_key": r.entity_key,
                "episode_id": r.episode_id,
                "partition": r.partition,
                "window_start_epoch": r.window_start_epoch,
                "features": list(r.features),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        for r in rows
    )
    digest = sha256()
    for line in lines:
        digest.update(line.encode("utf-8") + b"\n")
    return digest.hexdigest()


def folds_digest(folds: list[Fold]) -> str:
    """Canonical SHA-256 over the frozen fold assignment."""
    payload = [
        {
            "index": f.index,
            "held_out_attack_type": f.held_out_attack_type,
            "train": sorted(f.train_row_ids),
            "test": sorted(f.test_row_ids),
        }
        for f in sorted(folds, key=lambda f: f.index)
    ]
    return sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
