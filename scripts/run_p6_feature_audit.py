"""P6 — targeted behavioural feature audit. Read-only, trains nothing, selects nothing.

Answers one question: which behavioural information already in the data actually
distinguishes low-intensity Ares C2 from benign traffic, without leakage or an
identity proxy?

Status assignment is deliberately conservative:

REJECTED       near-perfect separation (leakage or proxy), or degenerate, or a
               restatement of a feature already in the budget.
NEEDS_REVIEW   the R11 question cannot be settled with this evidence, or the family
               is flagged by standing constraint, or availability is too poor.
SAFE           defined for both classes, no leakage found, signal present on more
               than one botnet entity, and the feature does **not** separate the
               botnet entities from each other.

A strong discrimination never produces SAFE on its own.
"""
from __future__ import annotations

import argparse
from collections.abc import Sequence
from datetime import UTC, datetime
from hashlib import sha256
import json
import math
import os
from pathlib import Path
from typing import Any, Final

from modules.detection.src.experiments.p1_dataset import (
    FORBIDDEN_COLUMNS,
    MB_DATABASE,
    PRODUCTION_DATABASE,
    _classify,
    _compiled_rules,
    _query,
)
from modules.detection.src.experiments.p6_analysis import (
    IDENTITY_AUC_CEILING,
    NEAR_PERFECT_AUC,
    consistency_across_entities,
    describe,
    directed_auc,
    episode_coverage,
    identity_dependence,
    redundancy,
    screening_auc,
    transfer_sign_agreement,
)
from modules.detection.src.experiments.p6_feature_audit import (
    DEFINITIONS,
    FAMILIES,
    ONLINE_AVAILABILITY,
    WINDOW_LENGTH_SECONDS,
    compute,
    fetch_events,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
OUT_DIR: Final[Path] = REPO_ROOT / "artifacts" / "experiments" / "p6"

#: Families under a standing constraint, regardless of what the numbers show.
CONSTRAINED_FAMILIES: Final[dict[str, str]] = {
    "B_temporal": (
        "already tested in P5 and NOT a new discovery; P5 did not confirm the "
        "endpoint, so these are reported for continuity only"
    ),
    "E_states_flags": (
        "standing constraint 10: flag-derived signal is dominated by the single "
        "pair 172.16.0.1 -> 192.168.10.50 and may not enter a principal benchmark "
        "without an explicit R11 review"
    ),
}
REFERENCE_FAMILY: Final[str] = "A_volume"


def _publish(path: Path, report: dict[str, Any]) -> tuple[str, str]:
    """Publish once. Idempotent on content, which excludes the clock fields."""
    identity = {
        k: v for k, v in report.items()
        if k not in ("started_at", "completed_at", "content_sha256")
    }
    report = dict(report)
    report["content_sha256"] = sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    payload = json.dumps(report, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        existing = json.loads(path.read_text(encoding="utf-8"))
        if existing.get("content_sha256") != report["content_sha256"]:
            raise FileExistsError(
                f"immutable artifact exists with different content: {path}"
            )
        return report["content_sha256"], sha256(path.read_bytes()).hexdigest()
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
    return report["content_sha256"], sha256(payload).hexdigest()


def _publish_bytes(path: Path, payload: bytes) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() != payload:
            raise FileExistsError(f"immutable artifact differs: {path}")
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


def episode_of(
    entity_key: str, bucket: int, buckets: list[int], attack_type: str
) -> str:
    """Episode id under decision D2, reused verbatim: maximal consecutive run."""
    ordered = sorted(buckets)
    index = 0
    for position, value in enumerate(ordered):
        if value == bucket:
            index = position
            break
    episode = 0
    for position in range(1, index + 1):
        if ordered[position] - ordered[position - 1] > WINDOW_LENGTH_SECONDS:
            episode += 1
    return f"{attack_type}|{entity_key}|{episode:03d}"


def classify_windows() -> dict[str, Any]:
    """Partition the M6 and MB6 windows read-only. Labels are read, never written."""
    rules = _compiled_rules(str(REPO_ROOT))
    m6 = _query(
        PRODUCTION_DATABASE,
        "SELECT output_partition, entity_source_ip, entity_destination_ip,"
        " entity_transport, entity_service, window_start_time, window_end_time"
        " FROM m6_canonical.feature_windows",
    )
    botnet: dict[tuple[str, str, int], str] = {}
    target: dict[tuple[str, str, int], str] = {}
    for part, src, dst, transport, service, start, end in m6:
        disposition, attack_type = _classify(rules, src, dst, transport, start, end)
        key = (part, f"{src}|{dst}|{transport}|{service}", int(start))
        if attack_type == "botnet/ares":
            botnet[key] = attack_type
        elif disposition == "target_attack":
            target[key] = attack_type or "target_attack"

    benign_ids = {
        row[0]
        for row in _query(
            MB_DATABASE,
            "SELECT w.source_window_id::text FROM mb7_canonical.window_labels w"
            " WHERE w.disposition = 'benign_reference'",
        )
    }
    benign: set[tuple[str, str, int]] = set()
    for row in _query(
        MB_DATABASE,
        "SELECT window_id::text, output_partition, entity_source_ip,"
        " entity_destination_ip, entity_transport, entity_service,"
        " window_start_time FROM mb6_canonical.feature_windows",
    ):
        if row[0] in benign_ids:
            benign.add(
                (row[1], f"{row[2]}|{row[3]}|{row[4]}|{row[5]}", int(row[6]))
            )
    return {"botnet": botnet, "target_attack": target, "benign": benign}


def audit_feature(
    name: str,
    family: str,
    botnet_values: list[float],
    benign_values: list[float],
    target_values: list[float],
    per_entity: dict[str, list[float]],
    per_pair: dict[str, list[float]],
    per_episode: dict[str, list[float]],
) -> dict[str, Any]:
    """Audit one candidate end to end and assign a conservative status."""
    botnet_stats = describe(botnet_values)
    benign_stats = describe(benign_values)
    target_stats = describe(target_values)

    discrimination = directed_auc(botnet_values, benign_values)
    target_discrimination = directed_auc(target_values, benign_values)

    per_entity_auc = {
        entity: (
            None
            if (raw := screening_auc(values, benign_values)) is None
            else round(max(raw, 1 - raw), 6)
        )
        for entity, values in sorted(per_entity.items())
    }
    per_pair_auc = {
        pair: (
            None
            if (raw := screening_auc(values, benign_values)) is None
            else round(max(raw, 1 - raw), 6)
        )
        for pair, values in sorted(per_pair.items())
    }
    consistency = consistency_across_entities(per_entity_auc)
    identity = identity_dependence(per_entity)

    transfer = transfer_sign_agreement(
        discrimination["direction"],
        target_discrimination["direction"],
        target_auc=target_discrimination["auc"],
        botnet_auc=discrimination["auc"],
    )

    higher_on_attack = discrimination["direction"] == "higher on attack"
    coverage = episode_coverage(per_episode, benign_values, upper=higher_on_attack)

    # ---- leakage and proxy screens -------------------------------------
    findings: list[str] = []
    botnet_present = botnet_stats.get("available", 0)
    benign_present = benign_stats.get("available", 0)

    disjoint = False
    if botnet_present and benign_present:
        disjoint = (
            botnet_stats["max"] < benign_stats["min"]
            or benign_stats["max"] < botnet_stats["min"]
        )
    if disjoint:
        findings.append(
            "ranges are disjoint: perfect separation, treated as leakage or proxy"
        )
    oriented = discrimination["oriented_auc"]
    if oriented is not None and oriented >= NEAR_PERFECT_AUC:
        findings.append(
            f"near-perfect screening AUC {oriented:.4f} >= {NEAR_PERFECT_AUC}: "
            "investigated as leakage rather than accepted"
        )
    degenerate = (
        botnet_stats.get("distinct", 0) <= 1 and benign_stats.get("distinct", 0) <= 1
    )
    if degenerate:
        findings.append("near-degenerate: one distinct value in both classes")

    identity_bound = identity["max_pairwise_auc"]
    identity_flag = identity_bound is not None and identity_bound >= IDENTITY_AUC_CEILING
    if identity_flag:
        findings.append(
            f"separates botnet entities from each other at AUC "
            f"{identity_bound:.4f}: cannot be distinguished from identity"
        )

    if transfer.get("agrees") is False:
        findings.append(
            "deviates from benign in the OPPOSITE direction to the volumetric "
            "attacks, so leave-one-attack-type-out training learns a harmful sign"
        )
    if transfer.get("undetermined"):
        findings.append(
            "transferability undetermined: the volumetric reference is at chance "
            "on this feature, so no sign can be compared"
        )

    availability_poor = (
        botnet_stats.get("missing_rate", 1.0) > 0.5
        or benign_stats.get("missing_rate", 1.0) > 0.9
    )
    if availability_poor:
        findings.append("availability too poor on at least one class")

    # ---- R11 question, answered explicitly -----------------------------
    if identity_flag:
        r11_answer = (
            "identity or provenance: the feature tells the botnet entities apart, "
            "so its apparent C2 signal cannot be separated from which host is "
            "speaking"
        )
    elif consistency.get("carried_by_all_entities"):
        r11_answer = (
            "behaviour: every botnet entity separates from benign to a similar "
            "degree, which is what shared C2 mechanics would produce"
        )
    elif consistency.get("entities_with_auc_at_least_0_65", 0) >= 3:
        r11_answer = (
            f"probably behaviour, not established: "
            f"{consistency['entities_with_auc_at_least_0_65']} of "
            f"{consistency['entities']} entities separate from benign, so the "
            "signal is not carried by a single host, but it is not uniform either"
        )
    else:
        r11_answer = (
            f"cannot be established: only "
            f"{consistency.get('entities_with_auc_at_least_0_65', 0)} of "
            f"{consistency.get('entities', 0)} botnet entities separate from "
            "benign, so the signal may describe one host rather than the family"
        )

    # ---- status --------------------------------------------------------
    if disjoint or degenerate or (oriented is not None and oriented >= NEAR_PERFECT_AUC):
        status = "REJECTED"
    elif family in CONSTRAINED_FAMILIES:
        status = "NEEDS_REVIEW"
    elif identity_flag or availability_poor:
        status = "NEEDS_REVIEW"
    elif r11_answer.startswith("cannot be established"):
        status = "NEEDS_REVIEW"
    elif botnet_present == 0 or benign_present == 0:
        status = "REJECTED"
    elif transfer.get("agrees") is not True:
        status = "NEEDS_REVIEW"
    else:
        status = "SAFE"

    if family == REFERENCE_FAMILY:
        status = "REFERENCE"
        findings.append(
            "family A is the historical P1 budget, recomputed for comparison only"
        )

    return {
        "feature": name,
        "family": family,
        "definition": DEFINITIONS[name],
        "source": (
            "aggregated over m4_canonical.flow_end_events and "
            "mb4_canonical.flow_end_events within the frozen M6/MB6 windows"
        ),
        "online_availability": ONLINE_AVAILABILITY[name],
        "distribution_botnet": botnet_stats,
        "distribution_benign": benign_stats,
        "distribution_target_attack": target_stats,
        "screening_botnet_vs_benign": discrimination,
        "screening_target_attack_vs_benign": target_discrimination,
        "per_botnet_entity_auc": per_entity_auc,
        "per_botnet_host_pair_auc": per_pair_auc,
        "entity_consistency": consistency,
        "identity_dependence": identity,
        "episode_coverage": coverage,
        "transfer_sign_agreement": transfer,
        "ranges_disjoint": disjoint,
        "findings": findings,
        "r11_question_behaviour_or_identity": r11_answer,
        "status": status,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="P6 behavioural feature audit.")
    parser.add_argument("--execute", action="store_true", required=True)
    parser.parse_args(argv)

    started = datetime.now(UTC).isoformat()

    print("partitioning the frozen windows read-only ...")
    groups = classify_windows()
    print(f"  botnet windows        {len(groups['botnet'])}")
    print(f"  target_attack windows {len(groups['target_attack'])}")
    print(f"  benign windows        {len(groups['benign'])}")

    print("reading persisted events read-only ...")
    m4 = fetch_events(PRODUCTION_DATABASE, "m4_canonical.flow_end_events")
    mb4 = fetch_events(MB_DATABASE, "mb4_canonical.flow_end_events")
    print(f"  M4 windows reconstructed  {len(m4)}")
    print(f"  MB4 windows reconstructed {len(mb4)}")

    all_names = tuple(name for names in FAMILIES.values() for name in names)
    print(f"evaluating {len(all_names)} candidates across {len(FAMILIES)} families ...")

    botnet_keys = sorted(groups["botnet"])
    target_keys = sorted(groups["target_attack"])
    benign_keys = sorted(groups["benign"])

    botnet_features = compute({k: m4[k] for k in botnet_keys}, all_names)
    target_features = compute({k: m4[k] for k in target_keys}, all_names)
    benign_features = compute({k: mb4[k] for k in benign_keys}, all_names)

    entity_buckets: dict[str, list[int]] = {}
    for _, entity_key, bucket in botnet_keys:
        entity_buckets.setdefault(entity_key, []).append(bucket)

    audits: list[dict[str, Any]] = []
    for family, names in FAMILIES.items():
        for name in names:
            botnet_values = [botnet_features[k][name] for k in botnet_keys]
            benign_values = [benign_features[k][name] for k in benign_keys]
            target_values = [target_features[k][name] for k in target_keys]

            per_entity: dict[str, list[float]] = {}
            per_pair: dict[str, list[float]] = {}
            per_episode: dict[str, list[float]] = {}
            for key in botnet_keys:
                _, entity_key, bucket = key
                value = botnet_features[key][name]
                per_entity.setdefault(entity_key, []).append(value)
                source, destination = entity_key.split("|")[0:2]
                per_pair.setdefault(f"{source}->{destination}", []).append(value)
                episode = episode_of(
                    entity_key, bucket, entity_buckets[entity_key], "botnet/ares"
                )
                per_episode.setdefault(episode, []).append(value)

            audit = audit_feature(
                name, family, botnet_values, benign_values, target_values,
                per_entity, per_pair, per_episode,
            )
            audits.append(audit)
            oriented = audit["screening_botnet_vs_benign"]["oriented_auc"]
            print(
                f"  {audit['status']:13} {family:18} {name:30} "
                f"screen {oriented if oriented is not None else float('nan'):.4f}  "
                f"ent {audit['entity_consistency'].get('entities_with_auc_at_least_0_65', 0)}"
                f"/{audit['entity_consistency'].get('entities', 0)}  "
                f"idAUC "
                f"{audit['identity_dependence'].get('max_pairwise_auc') or float('nan'):.4f}"
            )

    # ---- family verdicts ----------------------------------------------
    family_verdicts: list[dict[str, Any]] = []
    for family, names in FAMILIES.items():
        members = [a for a in audits if a["family"] == family]
        safe = [a["feature"] for a in members if a["status"] == "SAFE"]
        review = [a["feature"] for a in members if a["status"] == "NEEDS_REVIEW"]
        rejected = [a["feature"] for a in members if a["status"] == "REJECTED"]
        best = max(
            (
                a["screening_botnet_vs_benign"]["oriented_auc"] or 0.0
                for a in members
            ),
            default=0.0,
        )
        family_verdicts.append(
            {
                "family": family,
                "candidates": len(members),
                "safe": safe,
                "needs_review": review,
                "rejected": rejected,
                "best_oriented_screening_auc": round(best, 6),
                "signal_found": bool(safe),
                "constraint": CONSTRAINED_FAMILIES.get(family),
                "may_enter_xgboost": (
                    "no - reference budget only" if family == REFERENCE_FAMILY
                    else "no - " + CONSTRAINED_FAMILIES[family]
                    if family in CONSTRAINED_FAMILIES
                    else "yes, for the SAFE members only" if safe
                    else "no - no SAFE member"
                ),
            }
        )

    safe_features = sorted(a["feature"] for a in audits if a["status"] == "SAFE")

    # Redundancy among the SAFE candidates, over the combined population, so a
    # minimal set can be justified instead of shipping every survivor.
    combined_keys = botnet_keys + benign_keys
    safe_values = {
        name: [
            (botnet_features[k][name] if k in botnet_features
             else benign_features[k][name])
            for k in combined_keys
        ]
        for name in safe_features
    }
    safe_redundancy = redundancy(safe_values)

    # Minimal set: one member per redundant cluster.
    #
    # The tie-break is **availability first**, not screening strength. Two
    # redundant features are often defined on different subpopulations: a feature
    # requiring event_count >= 2 is scored only on the windows where it exists, so
    # its AUC is not comparable with that of a feature defined everywhere.
    # Comparing them directly would prefer the narrower feature on the strength of
    # a statistic measured on an easier subset. Screening strength decides only
    # when availability is materially equal.
    strength = {
        a["feature"]: (a["screening_botnet_vs_benign"]["oriented_auc"] or 0.0)
        for a in audits
    }
    coverage = {
        a["feature"]: (
            1.0 - (a["distribution_botnet"].get("missing_rate", 1.0)),
            1.0 - (a["distribution_benign"].get("missing_rate", 1.0)),
        )
        for a in audits
    }
    dropped: dict[str, str] = {}
    for pair, rho in safe_redundancy["redundant_pairs"].items():
        left, right = pair.split(" ~ ")
        if left in dropped or right in dropped:
            continue
        left_min, right_min = min(coverage[left]), min(coverage[right])
        if abs(left_min - right_min) > 0.05:
            keep = left if left_min > right_min else right
            drop = right if keep == left else left
            reason = (
                f"restates {keep} at rho {rho}; {keep} is kept because it is "
                f"defined on {min(coverage[keep]):.4f} of windows against "
                f"{min(coverage[drop]):.4f}, and the two screening AUCs are not "
                f"comparable across different defined subpopulations"
            )
        else:
            drop = left if strength[left] < strength[right] else right
            keep = right if drop == left else left
            reason = (
                f"restates {keep} at rho {rho}; availability is comparable, so "
                f"the stronger screener {keep} is kept"
            )
        dropped[drop] = reason
    minimal_set = [f for f in safe_features if f not in dropped]

    report = {
        "experiment": "P6 targeted behavioural feature audit",
        "question": (
            "which behavioural information already present in the data actually "
            "distinguishes low-intensity Ares C2 from benign traffic, without "
            "introducing leakage or an identity proxy?"
        ),
        "started_at": started,
        "completed_at": datetime.now(UTC).isoformat(),
        "postgresql_writes": 0,
        "model_trained": False,
        "features_selected": False,
        "xgboost_trained": False,
        "labels_modified": False,
        "unknown_or_ambiguous_used": False,
        "p1_folds_used": False,
        "forbidden_columns_unchanged": list(FORBIDDEN_COLUMNS),
        "populations": {
            "botnet_windows": len(botnet_keys),
            "botnet_entities": len(entity_buckets),
            "botnet_host_pairs": len(
                {k[1].split("|")[0] + "->" + k[1].split("|")[1] for k in botnet_keys}
            ),
            "botnet_episodes": len(
                {
                    episode_of(
                        k[1], k[2], entity_buckets[k[1]], "botnet/ares"
                    )
                    for k in botnet_keys
                }
            ),
            "target_attack_windows": len(target_keys),
            "benign_reference_windows": len(benign_keys),
        },
        "thresholds": {
            "near_perfect_auc_triggers_leakage_hunt": NEAR_PERFECT_AUC,
            "identity_auc_ceiling": IDENTITY_AUC_CEILING,
        },
        "excluded_columns_and_why": {
            "source_ip / destination_ip / source_port / destination_port / "
            "transport / service": "identity or a direct proxy (constraint 8)",
            "conversation_id": "per-flow unique id; counting it restates event_count",
            "physical_line_number": "position in the capture file, a capture artefact",
            "record_available_time / ingested_at / persisted_at":
                "pipeline clocks, absolute and not properties of the traffic",
            "all provenance columns": "already in FORBIDDEN_COLUMNS",
        },
        "family_verdicts": family_verdicts,
        "audits": audits,
        "safe_features": safe_features,
        "redundancy_among_safe": safe_redundancy,
        "dropped_as_redundant": dropped,
        "smallest_justified_set": minimal_set,
        "limitations": [
            "R11 is unchanged: the botnet is 5 entities reaching a single "
            "destination, so nothing here licenses a claim of general capability",
            "screening AUC is descriptive; it is not a model performance and no "
            "generalisation follows from it",
            "no threshold was calibrated and no recall was computed",
            "family E is withheld by standing constraint, not by measurement",
        ],
    }

    content, file_digest = _publish(OUT_DIR / "p6_feature_audit.json", report)

    header = (
        "feature,family,status,online_availability,"
        "botnet_missing_rate,benign_missing_rate,"
        "botnet_median,benign_median,target_attack_median,"
        "botnet_p05,botnet_p95,benign_p05,benign_p95,"
        "oriented_screening_auc,direction,"
        "entities_at_least_0_65,entities_total,max_pairwise_identity_auc,"
        "episodes_touching_tail,episodes_total\n"
    )
    lines = [header]
    for a in sorted(audits, key=lambda x: (x["family"], x["feature"])):
        b, n, t = (
            a["distribution_botnet"],
            a["distribution_benign"],
            a["distribution_target_attack"],
        )
        c = a["entity_consistency"]
        lines.append(
            ",".join(
                str(v)
                for v in (
                    a["feature"],
                    a["family"],
                    a["status"],
                    a["online_availability"].replace(",", ";"),
                    b.get("missing_rate", 1.0),
                    n.get("missing_rate", 1.0),
                    b.get("median", ""),
                    n.get("median", ""),
                    t.get("median", ""),
                    b.get("p05", ""),
                    b.get("p95", ""),
                    n.get("p05", ""),
                    n.get("p95", ""),
                    a["screening_botnet_vs_benign"]["oriented_auc"],
                    a["screening_botnet_vs_benign"]["direction"],
                    c.get("entities_with_auc_at_least_0_65", 0),
                    c.get("entities", 0),
                    a["identity_dependence"].get("max_pairwise_auc"),
                    a["episode_coverage"].get("episodes_touching_the_tail", 0),
                    a["episode_coverage"].get("episodes", 0),
                )
            )
            + "\n"
        )
    csv_digest = _publish_bytes(
        OUT_DIR / "p6_feature_distributions.csv", "".join(lines).encode("utf-8")
    )

    print()
    print("=== FAMILY VERDICTS ===")
    for verdict in family_verdicts:
        print(
            f"  {verdict['family']:18} safe {len(verdict['safe'])}"
            f"  review {len(verdict['needs_review'])}"
            f"  rejected {len(verdict['rejected'])}"
            f"  best screen {verdict['best_oriented_screening_auc']:.4f}"
        )
    print()
    print(f"SAFE features ({len(safe_features)}): {safe_features}")
    print()
    print("=== REDUNDANCY AMONG SAFE ===")
    for pair, rho in sorted(
        safe_redundancy["redundant_pairs"].items(), key=lambda kv: -abs(kv[1])
    ):
        print(f"  redundant  {pair:62} rho {rho:+.4f}")
    for name, reason in sorted(dropped.items()):
        print(f"  dropped    {name:30} {reason}")
    print()
    print(f"SMALLEST JUSTIFIED SET ({len(minimal_set)}): {minimal_set}")
    print()
    print(f"p6_feature_audit.json content {content[:16]}  file {file_digest[:16]}")
    print(f"p6_feature_distributions.csv {csv_digest[:16]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
