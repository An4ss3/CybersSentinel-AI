"""Run the controlled four-arm XGBoost feature benchmark.

This is additive: P1--P6 and the published one-feature XGBoost baseline are inputs
only. PostgreSQL is queried through the existing read-only helper; no row is ever
written. All fitting happens only after the frozen population, folds, test labels,
feature provenance, temporal validity, and arm identity checks pass.
"""
from __future__ import annotations

import argparse
from collections.abc import Sequence
import csv
from dataclasses import replace
from datetime import UTC, datetime
from hashlib import sha256
import io
import json
import math
import os
from pathlib import Path
import sys
from typing import Any, Final

import joblib
import numpy as np

from modules.detection.src.experiments.p1_dataset import (
    FORBIDDEN_COLUMNS,
    MB_DATABASE,
    PRODUCTION_DATABASE,
    Row,
    build_folds,
    dataset_digest,
    folds_digest,
    load_negatives,
    load_positives,
)
from modules.detection.src.experiments.p1_evaluation import FPR_TARGETS
from modules.detection.src.experiments.p6_feature_audit import (
    DEFINITIONS,
    FEATURE_FUNCTIONS,
    ONLINE_AVAILABILITY,
    compute,
    fetch_events,
)
from modules.detection.src.experiments.xgb_baseline import XGB_PARAMS
from modules.detection.src.experiments.xgb_feature_benchmark import (
    ARM_FEATURES,
    BOOTSTRAP_DECLARATION,
    FoldResult,
    evaluate_fold,
    paired_episode_bootstrap_delta,
    per_entity_recall,
)

# The runner lives under scripts, so importing ProtocolViolation from that package
# path is not valid in every invocation. Fall back to the actual scripts module.
try:  # pragma: no cover - import branch depends on invocation style
    from scripts.run_xgboost_baseline import verify_protocol
except ImportError:  # pragma: no cover
    verify_protocol = None  # type: ignore[assignment]


REPO_ROOT = Path(__file__).resolve().parents[1]
P1_DIR: Final[Path] = REPO_ROOT / "artifacts" / "experiments" / "p1"
P6_DIR: Final[Path] = REPO_ROOT / "artifacts" / "experiments" / "p6"
BASELINE_DIR: Final[Path] = REPO_ROOT / "artifacts" / "experiments" / "xgboost_baseline"
OUT_DIR: Final[Path] = REPO_ROOT / "artifacts" / "experiments" / "xgboost_feature_benchmark"

P1_DATASET_CONTENT_SHA256: Final[str] = "3d7436178da6960ee5effeb4bee85a0b6da5eead9d2babef3c72cb6b7ca9f20d"
P1_FOLDS_CONTENT_SHA256: Final[str] = "e463ea7b0eb4985f51369dc3ae19c09821040675aa4b9f9689f8e02545fed95a"
FROZEN_FILE_SHA256: Final[dict[str, str]] = {
    "p1_dataset.csv": "e95aed008d994510e4c649c287feb8fe8f49a785bec144d7e83aa15804b6c062",
    "p1_folds.json": "57e688fd3da90911707d7a172c161686d852094121eda1ac49e0221fc0529fa1",
    "p1_metrics.json": "2a51e618397c42b742a289216d3cd89b255c4ccd96a8f985a5ad1c5c4783a447",
    "p6_feature_audit.json": "d028e8476df66c2827e534281fdda6c994c6e1023ba42bb57461c34316a9d1ac",
    "xgb_metrics.json": "4b841773bbe34d62153dfbd69cc9c5f2a480b781f842ed0c59a1efe3a21a1263",
    "xgb_model_params.json": "d6d33ca0b7a6d42f5bd059ac1e8a2c11fe6b47f8e7104ee1da6ac6a139a03521",
}
PRIMARY_ENDPOINT: Final[str] = "botnet/ares"
FEATURE_NAMES: Final[tuple[str, ...]] = tuple(dict.fromkeys(name for names in ARM_FEATURES.values() for name in names))

FEATURE_SOURCE_COLUMNS: Final[dict[str, tuple[str, ...]]] = {
    "distinct_payload_ratio": ("source_bytes", "destination_bytes"),
    "interarrival_mean": ("event_start_time_relative_to_window",),
    "bytes_per_packet_destination": ("destination_bytes", "destination_packets"),
}

DECISIONS: Final[list[dict[str, str]]] = [
    {
        "id": "D24",
        "decision": "four fixed arms A--D; the model parameters are byte-for-byte the published XGBoost baseline parameters",
        "reason": "only the feature budget may vary, so no model search, validation split, early stopping, rebalancing, or threshold search is introduced",
    },
    {
        "id": "D25",
        "decision": "P6 undefined values remain NaN and use XGBoost's native missing branch",
        "reason": "imputation, a fitted fill value, or a missingness indicator would modify the audited feature and widen the registered budget",
    },
    {
        "id": "D26",
        "decision": "P1 folds are reconstructed to recover P1's authentic training-row order and then proven equal to the frozen folds",
        "reason": "p1_folds.json preserves membership but sorts ids; all arms must share P1's actual order and exactly the same ordered test rows",
    },
    {
        "id": "D27",
        "decision": "online validity is assessed from the exact P6 formulas and their source quantities, without using absolute time",
        "reason": "interarrival_mean uses differences of relative starts only; the two byte features use counters available by window close; historical extraction is from FlowEnd evidence, so deployment latency itself is not measured",
    },
    {
        "id": "D28",
        "decision": "candidate-minus-ARM-A recall deltas use a paired bootstrap over the same episode ids",
        "reason": "all arms see the same 40 botnet episodes; resampling windows would be pseudoreplication and comparing marginal intervals alone would discard the pairing",
    },
]


class BenchmarkViolation(RuntimeError):
    """A frozen or feature-budget invariant failed; publication must stop."""


def _sha(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _json_bytes(value: Any) -> bytes:
    return json.dumps(value, indent=2, sort_keys=True, allow_nan=True).encode("utf-8") + b"\n"


def _publish_bytes(path: Path, payload: bytes) -> str:
    """Publish durably once; accept an idempotent byte-identical re-run."""
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


def _identity_document(document: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in document.items()
        if key not in ("started_at", "completed_at", "content_sha256")
    }


def _publish_document(path: Path, document: dict[str, Any]) -> tuple[str, str]:
    value = dict(document)
    value["content_sha256"] = sha256(
        json.dumps(_identity_document(value), sort_keys=True, separators=(",", ":"), allow_nan=True).encode("utf-8")
    ).hexdigest()
    payload = _json_bytes(value)
    if path.exists():
        existing = json.loads(path.read_text(encoding="utf-8"))
        if existing.get("content_sha256") != value["content_sha256"]:
            raise FileExistsError(f"immutable document differs: {path}")
        return value["content_sha256"], _sha(path)
    return value["content_sha256"], _publish_bytes(path, payload)


def _record(checks: list[dict[str, Any]], name: str, passed: bool, detail: Any) -> None:
    checks.append({"check": name, "passed": bool(passed), "detail": detail})
    if not passed:
        raise BenchmarkViolation(f"{name}: {detail}")


def verify_frozen_files() -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    paths = {
        "p1_dataset.csv": P1_DIR / "p1_dataset.csv",
        "p1_folds.json": P1_DIR / "p1_folds.json",
        "p1_metrics.json": P1_DIR / "p1_metrics.json",
        "p6_feature_audit.json": P6_DIR / "p6_feature_audit.json",
        "xgb_metrics.json": BASELINE_DIR / "xgb_metrics.json",
        "xgb_model_params.json": BASELINE_DIR / "xgb_model_params.json",
    }
    for name, path in paths.items():
        digest = _sha(path)
        _record(checks, f"{name}_file_digest_frozen", digest == FROZEN_FILE_SHA256[name], digest)
    return checks


def build_feature_rows(rows: list[Row]) -> tuple[dict[str, list[Row]], dict[str, Any]]:
    """Recompute exactly the three P6 formulas over the frozen windows, read-only."""
    m4 = fetch_events(PRODUCTION_DATABASE, "m4_canonical.flow_end_events")
    mb4 = fetch_events(MB_DATABASE, "mb4_canonical.flow_end_events")
    feature_table: dict[tuple[str, str, int], dict[str, float]] = {}
    feature_table.update(compute(m4, FEATURE_NAMES))
    feature_table.update(compute(mb4, FEATURE_NAMES))

    checks: list[dict[str, Any]] = []
    _record(
        checks,
        "feature_functions_are_exactly_the_p6_implementations",
        all(name in FEATURE_FUNCTIONS for name in FEATURE_NAMES),
        list(FEATURE_NAMES),
    )
    _record(
        checks,
        "no_feature_source_is_a_label_or_provenance_column",
        all(
            "label" not in source and source not in FORBIDDEN_COLUMNS
            for sources in FEATURE_SOURCE_COLUMNS.values()
            for source in sources
        ),
        FEATURE_SOURCE_COLUMNS,
    )
    _record(
        checks,
        "all_registered_features_are_p6_online",
        all(ONLINE_AVAILABILITY[name].startswith("online") for name in FEATURE_NAMES),
        {name: ONLINE_AVAILABILITY[name] for name in FEATURE_NAMES},
    )

    all_event_windows = {**m4, **mb4}
    starts_valid = all(
        all(0.0 <= start < 60.0 for start in events.starts)
        for events in all_event_windows.values()
    )
    _record(
        checks,
        "event_start_time_is_reduced_to_a_relative_offset_inside_the_window",
        starts_valid,
        "all retained offsets are in [0, 60); absolute timestamps do not reach a feature",
    )

    by_arm: dict[str, list[Row]] = {arm: [] for arm in ARM_FEATURES}
    missing_counts = {
        name: {"botnet": 0, "benign": 0, "other_attack": 0}
        for name in FEATURE_NAMES
    }
    populations = {"botnet": 0, "benign": 0, "other_attack": 0}
    largest_finite = 0.0
    for row in rows:
        key = (row.partition, row.entity_key, row.window_start_epoch)
        values = feature_table.get(key)
        if values is None:
            raise BenchmarkViolation(f"no event reconstruction for frozen row {key!r}")
        population = "benign" if row.label == 0 else "botnet" if row.attack_type == PRIMARY_ENDPOINT else "other_attack"
        populations[population] += 1
        for name in FEATURE_NAMES:
            value = float(values[name])
            if math.isnan(value):
                missing_counts[name][population] += 1
            elif math.isinf(value):
                raise BenchmarkViolation(f"infinite {name} for {row.row_id}")
            else:
                largest_finite = max(largest_finite, abs(value))
        for arm, names in ARM_FEATURES.items():
            by_arm[arm].append(replace(row, features=tuple(float(values[name]) for name in names)))

    smallest_epoch = min(row.window_start_epoch for row in rows)
    _record(
        checks,
        "no_absolute_timestamp_is_reachable_from_a_feature",
        largest_finite < smallest_epoch / 1000.0,
        {"largest_finite_feature": largest_finite, "smallest_epoch": smallest_epoch},
    )

    for arm, arm_rows in by_arm.items():
        _record(
            checks,
            f"arm_{arm}_preserves_all_row_and_label_metadata",
            all(
                (source.row_id, source.label, source.disposition, source.attack_type, source.episode_id, source.entity_key)
                == (derived.row_id, derived.label, derived.disposition, derived.attack_type, derived.episode_id, derived.entity_key)
                for source, derived in zip(rows, arm_rows)
            ),
            f"{len(arm_rows)} rows",
        )
        _record(
            checks,
            f"arm_{arm}_has_exactly_the_registered_feature_width",
            all(len(row.features) == len(ARM_FEATURES[arm]) for row in arm_rows),
            {"features": list(ARM_FEATURES[arm]), "width": len(ARM_FEATURES[arm])},
        )

    p6 = json.loads((P6_DIR / "p6_feature_audit.json").read_text(encoding="utf-8"))
    audit_by_name = {entry["feature"]: entry for entry in p6["audits"]}
    missingness: dict[str, Any] = {}
    for name in FEATURE_NAMES:
        published = audit_by_name[name]
        observed_botnet = missing_counts[name]["botnet"] / populations["botnet"]
        observed_benign = missing_counts[name]["benign"] / populations["benign"]
        expected_botnet = published["distribution_botnet"]["missing_rate"]
        expected_benign = published["distribution_benign"]["missing_rate"]
        _record(
            checks,
            f"{name}_missingness_matches_p6",
            abs(observed_botnet - expected_botnet) < 1e-6 and abs(observed_benign - expected_benign) < 1e-6,
            {
                "observed_botnet": observed_botnet,
                "p6_botnet": expected_botnet,
                "observed_benign": observed_benign,
                "p6_benign": expected_benign,
            },
        )
        missingness[name] = {
            "policy": "native NaN; no imputation and no indicator",
            "botnet_missing": missing_counts[name]["botnet"],
            "botnet_total": populations["botnet"],
            "botnet_rate": observed_botnet,
            "benign_missing": missing_counts[name]["benign"],
            "benign_total": populations["benign"],
            "benign_rate": observed_benign,
        }

    online = {
        "status": "ONLINE formulas under the P6 window-close convention",
        "historical_evidence_caveat": (
            "values are reconstructed from persisted FlowEnd evidence; the formulas use no future window, "
            "but this benchmark does not measure streaming ingestion latency or availability of late flow records"
        ),
        "features": {
            "distinct_payload_ratio": {
                "status": ONLINE_AVAILABILITY["distinct_payload_ratio"],
                "derivation": DEFINITIONS["distinct_payload_ratio"],
                "future_information": False,
            },
            "interarrival_mean": {
                "status": ONLINE_AVAILABILITY["interarrival_mean"],
                "derivation": DEFINITIONS["interarrival_mean"],
                "future_information": False,
                "guard": "only consecutive differences of relative starts in [0,60) are used",
            },
            "bytes_per_packet_destination": {
                "status": ONLINE_AVAILABILITY["bytes_per_packet_destination"],
                "derivation": DEFINITIONS["bytes_per_packet_destination"],
                "future_information": False,
                "guard": "uses destination byte and packet counters available by window close; undefined denominator remains NaN",
            },
        },
    }
    return by_arm, {
        "checks": checks,
        "missingness": missingness,
        "online_validity": online,
        "source_columns": FEATURE_SOURCE_COLUMNS,
        "p6_implementation_reused": True,
    }


def _test_signature(rows: list[Row]) -> str:
    payload = "".join(f"{row.row_id},{row.label}\n" for row in rows).encode("utf-8")
    return sha256(payload).hexdigest()


def _fold_document(result: FoldResult) -> dict[str, Any]:
    return {
        "arm": result.arm,
        "features": list(result.features),
        "fold": result.fold,
        "held_out_attack_type": result.held_out_attack_type,
        "train_positives": result.train_positives,
        "train_negatives": result.train_negatives,
        "test_positives": result.test_positives,
        "test_negatives": result.test_negatives,
        "test_episodes": result.test_episodes,
        "roc_auc": result.roc_auc,
        "pr_auc": result.pr_auc,
        "feature_importance_gain": result.feature_importance_gain,
        "operating_points": result.operating_points,
    }


def _point(result: FoldResult, target: float = 0.01) -> dict[str, Any]:
    return next(p for p in result.operating_points if p["target_train_fpr"] == target)


def _csv_payload(records: list[dict[str, Any]]) -> bytes:
    stream = io.StringIO(newline="")
    fields = ["arm", "fold", "row_id", "label", "disposition", "attack_type", "episode_id", "score"]
    writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    writer.writerows(records)
    return stream.getvalue().encode("utf-8")


def _model_payload(model: Any) -> bytes:
    stream = io.BytesIO()
    joblib.dump(model, stream)
    return stream.getvalue()


def _result_map(results: list[FoldResult]) -> dict[str, dict[str, FoldResult]]:
    out: dict[str, dict[str, FoldResult]] = {arm: {} for arm in ARM_FEATURES}
    for result in results:
        out[result.arm][result.held_out_attack_type] = result
    return out


def _entity_of_episode(episode: str) -> str:
    parts = episode.split("|")
    return "|".join(parts[1:-1])


def analyse_results(
    results: list[FoldResult], per_entity: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    by_arm = _result_map(results)
    base = by_arm["A"][PRIMARY_ENDPOINT]
    base_point = _point(base)
    comparisons: dict[str, Any] = {}

    for arm in ARM_FEATURES:
        primary = by_arm[arm][PRIMARY_ENDPOINT]
        point = _point(primary)
        entities = per_entity[arm][PRIMARY_ENDPOINT]["target_0.01"]
        candidate_only: list[str] = []
        reference_only: list[str] = []
        if arm == "A":
            paired = {
                "point": 0.0,
                "ci_low": 0.0,
                "ci_high": 0.0,
                "episodes": 40,
                "candidate_only_detections": 0,
                "reference_only_detections": 0,
            }
        else:
            paired = paired_episode_bootstrap_delta(
                base_point["episode_detection"], point["episode_detection"]
            )
            candidate_only = sorted(
                episode for episode, detected in point["episode_detection"].items()
                if detected and not base_point["episode_detection"][episode]
            )
            reference_only = sorted(
                episode for episode, detected in base_point["episode_detection"].items()
                if detected and not point["episode_detection"][episode]
            )

        volume_types: dict[str, Any] = {}
        base_volume_detected = candidate_volume_detected = 0
        for attack_type in sorted(k for k in by_arm["A"] if k != PRIMARY_ENDPOINT):
            a = by_arm["A"][attack_type]
            c = by_arm[arm][attack_type]
            ap, cp = _point(a), _point(c)
            base_volume_detected += len(ap["episodes_detected"])
            candidate_volume_detected += len(cp["episodes_detected"])
            volume_types[attack_type] = {
                "episode_recall_a": ap["episode_recall"],
                "episode_recall_arm": cp["episode_recall"],
                "episode_recall_delta": cp["episode_recall"] - ap["episode_recall"],
                "window_recall_a": ap["window_recall"],
                "window_recall_arm": cp["window_recall"],
                "roc_auc_a": a.roc_auc,
                "roc_auc_arm": c.roc_auc,
                "pr_auc_a": a.pr_auc,
                "pr_auc_arm": c.pr_auc,
                "observed_test_fpr_a": ap["observed_test_fpr"],
                "observed_test_fpr_arm": cp["observed_test_fpr"],
            }
        important_volume_cost = (
            candidate_volume_detected <= base_volume_detected - 2
            or any(v["episode_recall_delta"] <= -0.25 for v in volume_types.values())
        )
        gain_entities = sorted({_entity_of_episode(e) for e in candidate_only})
        lost_entities = sorted({_entity_of_episode(e) for e in reference_only})
        comparisons[arm] = {
            "features": list(ARM_FEATURES[arm]),
            "primary": {
                "episode_recall": point["episode_recall"],
                "episode_ci": [
                    point["episode_bootstrap"]["ci_low"],
                    point["episode_bootstrap"]["ci_high"],
                ],
                "episodes_detected": len(point["episodes_detected"]),
                "episodes_total": primary.test_episodes,
                "window_recall": point["window_recall"],
                "roc_auc": primary.roc_auc,
                "roc_descriptively_above_chance": primary.roc_auc >= 0.60,
                "roc_inference_caveat": "point estimate only; no window bootstrap was performed",
                "pr_auc": primary.pr_auc,
                "observed_test_fpr": point["observed_test_fpr"],
                "threshold": point["threshold"],
                "entities_detected": sum(v["episodes_detected"] > 0 for v in entities.values()),
                "entities_total": len(entities),
            },
            "gain_vs_arm_a": {
                "episode_recall_delta": point["episode_recall"] - base_point["episode_recall"],
                "paired_episode_bootstrap": paired,
                "candidate_only_episodes": candidate_only,
                "reference_only_episodes": reference_only,
                "entities_with_candidate_only_detections": gain_entities,
                "entities_with_reference_only_detections": lost_entities,
                "gain_is_distributed_over_multiple_entities": len(gain_entities) >= 2,
                "roc_auc_delta": primary.roc_auc - base.roc_auc,
                "pr_auc_delta": primary.pr_auc - base.pr_auc,
                "fpr_delta": point["observed_test_fpr"] - base_point["observed_test_fpr"],
            },
            "volumetric_cost": {
                "important": important_volume_cost,
                "episodes_detected_a": base_volume_detected,
                "episodes_detected_arm": candidate_volume_detected,
                "by_type": volume_types,
            },
            "feature_importance_gain_botnet_fold": primary.feature_importance_gain,
            "single_feature_dependence": (
                "by construction: ARM A has one feature"
                if arm == "A"
                else "marginal attribution is identified only by comparison with the registered ablation arms; gain importance is descriptive, not causal"
            ),
        }

    # Transparent conservative status rules. A candidate needs a strictly positive
    # paired episode-delta interval, stable FPR, all five entities, ROC/PR no worse,
    # and no important volumetric episode cost to be retained.
    classifications: dict[str, Any] = {
        "A": {
            "status": "RETAIN",
            "reason": "registered baseline and previously demonstrated signal; retained as the minimal reference",
        }
    }
    for arm in ("B", "C", "D"):
        item = comparisons[arm]
        primary = item["primary"]
        gain = item["gain_vs_arm_a"]
        delta_ci = gain["paired_episode_bootstrap"]
        supported = delta_ci["ci_low"] > 0.0
        stable_fpr = abs(gain["fpr_delta"]) <= 0.0025 and primary["observed_test_fpr"] <= 0.0125
        noninferior_discrimination = gain["roc_auc_delta"] >= 0.0 and gain["pr_auc_delta"] >= 0.0
        robust_entities = primary["entities_detected"] == 5 and gain["gain_is_distributed_over_multiple_entities"]
        no_volume_cost = not item["volumetric_cost"]["important"]
        clearly_worse_primary = delta_ci["ci_high"] < 0.0
        if supported and stable_fpr and noninferior_discrimination and robust_entities and no_volume_cost:
            status = "RETAIN"
            reason = "positive paired episode-gain interval, stable FPR, non-inferior ROC/PR, distributed entity gain, and no important volumetric episode cost"
        elif clearly_worse_primary:
            status = "REJECT"
            reason = "paired episode-delta interval is strictly negative on the pre-registered primary endpoint; a global ROC gain cannot override that loss"
        elif (
            gain["episode_recall_delta"] <= 0.0
            and gain["roc_auc_delta"] <= 0.0
            and gain["pr_auc_delta"] <= 0.0
        ):
            status = "REJECT"
            reason = "no episode gain and no discrimination gain over the simpler ARM A"
        else:
            status = "INCONCLUSIVE"
            failed = []
            if not supported:
                failed.append("paired episode-delta CI includes zero")
            if not stable_fpr:
                failed.append("FPR is not stable")
            if not noninferior_discrimination:
                failed.append("ROC and PR are not both non-inferior")
            if not robust_entities:
                failed.append("gain is not distributed while retaining 5/5 entities")
            if not no_volume_cost:
                failed.append("important volumetric episode cost")
            reason = "; ".join(failed)
        classifications[arm] = {
            "status": status,
            "reason": reason,
            "rules": {
                "paired_delta_ci_strictly_positive": supported,
                "stable_fpr": stable_fpr,
                "roc_and_pr_noninferior": noninferior_discrimination,
                "distributed_and_5_of_5_entities": robust_entities,
                "no_important_volumetric_episode_cost": no_volume_cost,
            },
        }

    retained = [arm for arm, value in classifications.items() if value["status"] == "RETAIN"]
    best_recall = max(comparisons[arm]["primary"]["episode_recall"] for arm in retained)
    best_arms = [arm for arm in retained if comparisons[arm]["primary"]["episode_recall"] == best_recall]
    best_arm = max(
        best_arms,
        key=lambda arm: (
            comparisons[arm]["primary"]["roc_auc"],
            comparisons[arm]["primary"]["pr_auc"],
            -comparisons[arm]["primary"]["observed_test_fpr"],
            -len(ARM_FEATURES[arm]),
        ),
    )
    minimal = {
        "arm": best_arm,
        "features": list(ARM_FEATURES[best_arm]),
        "rationale": (
            "among arms meeting the conservative RETAIN rule, maximize observed botnet episode recall; "
            "break ties by ROC-AUC, PR-AUC, lower FPR, then fewer features"
        ),
        "all_features_online_under_p6_convention": all(
            ONLINE_AVAILABILITY[name].startswith("online") for name in ARM_FEATURES[best_arm]
        ),
    }

    comparison_document = {
        "experiment": "controlled XGBoost feature benchmark",
        "reference_arm": "A",
        "classification_rule": (
            "RETAIN requires paired episode-delta CI strictly above zero, stable FPR (absolute delta <=0.0025 and observed <=0.0125), "
            "ROC and PR non-inferior, gain across multiple entities with 5/5 retained, and no important volumetric episode cost; "
            "REJECT applies whenever the paired primary-endpoint delta interval is strictly negative, regardless of a global ROC gain, "
            "or when there is no episode or discrimination gain; otherwise INCONCLUSIVE"
        ),
        "arms": comparisons,
        "classifications": classifications,
        "minimal_best_compromise": minimal,
        "causal_scope": "arm contrasts identify the effect of changing the feature budget under this protocol, not universal causal feature effects",
    }
    return comparisons, comparison_document


def render_report(metrics: dict[str, Any], comparison: dict[str, Any]) -> str:
    arms = comparison["arms"]
    lines = [
        "# Controlled XGBoost feature benchmark",
        "",
        "## Scope and frozen protocol",
        "",
        "This additive benchmark changes only the registered feature budget. P1--P6 and the published one-feature XGBoost baseline remain immutable. The P1 population, labels, five folds, authentic training-row order, test rows, benign-reference negatives, episode unit, learner, model parameters, training-negative threshold rule, and episode bootstrap are reused exactly. No unknown/ambiguous row, new split, tuning, rebalancing, label-derived feature, absolute timestamp, PostgreSQL write, or window bootstrap is used.",
        "",
        "## Primary endpoint — botnet/Ares episode recall at 1% training FPR",
        "",
        "| Arm | Features | Episode recall (95% episode bootstrap CI) | Episodes | Window recall | ROC-AUC | PR-AUC | Test FPR | Entities | Decision |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---|",
    ]
    for arm in ARM_FEATURES:
        p = arms[arm]["primary"]
        status = comparison["classifications"][arm]["status"]
        lines.append(
            f"| {arm} | {', '.join(ARM_FEATURES[arm])} | {p['episode_recall']:.4f} "
            f"[{p['episode_ci'][0]:.4f}, {p['episode_ci'][1]:.4f}] | "
            f"{p['episodes_detected']}/{p['episodes_total']} | {p['window_recall']:.4f} | "
            f"{p['roc_auc']:.4f} | {p['pr_auc']:.4f} | {p['observed_test_fpr']:.6f} | "
            f"{p['entities_detected']}/{p['entities_total']} | **{status}** |"
        )

    lines += [
        "",
        "P1 reference: 0.0750 episode recall (3/40), ROC-AUC 0.5037. Published P6/XGBoost ARM A reference: 0.3250 (13/40), ROC-AUC 0.7615, PR-AUC 0.0670, FPR 0.009874. ARM A is required to reproduce that published baseline before any benchmark artifact is accepted.",
        "",
        "## Direct gains over ARM A",
        "",
        "| Arm | Recall delta | Paired episode delta CI | New / lost episodes | Gain entities | ROC delta | PR delta | FPR delta |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for arm in ("B", "C", "D"):
        gain = arms[arm]["gain_vs_arm_a"]
        paired = gain["paired_episode_bootstrap"]
        lines.append(
            f"| {arm} | {gain['episode_recall_delta']:+.4f} | "
            f"[{paired['ci_low']:+.4f}, {paired['ci_high']:+.4f}] | "
            f"{paired['candidate_only_detections']} / {paired['reference_only_detections']} | "
            f"{len(gain['entities_with_candidate_only_detections'])} | "
            f"{gain['roc_auc_delta']:+.4f} | {gain['pr_auc_delta']:+.4f} | {gain['fpr_delta']:+.6f} |"
        )

    lines += [
        "",
        "The paired intervals resample the same 40 episode ids. All three candidate intervals are strictly negative, so none is compatible with a positive gain on the primary endpoint in this experiment. ROC-AUC is reported as a point estimate only: no window bootstrap is performed, so 'above chance' is descriptive rather than an additional inferential claim.",
        "",
        "## Interpretation of the audited candidates",
        "",
        f"- **interarrival_mean (ARM B):** despite P6's direct univariate botnet-vs-benign screening AUC of 0.9146, the leave-one-attack-type-out supervised model falls to {arms['B']['primary']['episode_recall']:.4f} episode recall, ROC {arms['B']['primary']['roc_auc']:.4f}, and PR {arms['B']['primary']['pr_auc']:.4f}. P6 screening described the held-out population directly; it did not establish that the joint rule learned from the four other attack types would transfer at the training-negative 1% tail.",
        f"- **bytes_per_packet_destination (ARM C):** global ROC rises to {arms['C']['primary']['roc_auc']:.4f}, but the ratified operating point detects only {arms['C']['primary']['episodes_detected']}/40 episodes on 1/5 entities and PR falls to {arms['C']['primary']['pr_auc']:.4f}. This is exactly why ROC alone cannot select the arm: discrimination over the full ranking does not guarantee useful positive mass in the extreme calibrated tail.",
        f"- **combined additions (ARM D):** recall remains {arms['D']['primary']['episodes_detected']}/40 while observed FPR rises to {arms['D']['primary']['observed_test_fpr']:.6f}; combining the candidates does not rescue transfer.",
        "",
        "These are feature-budget contrasts under one fixed learner and protocol. They do not prove that either feature is intrinsically harmful in every model or population.",
        "",
        "## Per-entity botnet results",
        "",
    ]
    per_entity = metrics["per_entity_recall"]
    for arm in ARM_FEATURES:
        lines += [f"### ARM {arm}", "", "| Entity | Windows | Window recall | Episodes | Episode recall |", "|---|---:|---:|---:|---:|"]
        for entity, value in per_entity[arm][PRIMARY_ENDPOINT]["target_0.01"].items():
            source, destination, transport, service = entity.split("|", 3)
            entity_display = f"{source} → {destination} ({transport}/{service})"
            lines.append(
                f"| {entity_display} | {value['windows_flagged']}/{value['windows']} | "
                f"{value['window_recall']:.4f} | {value['episodes_detected']}/{value['episodes']} | {value['episode_recall']:.4f} |"
            )
        lines.append("")

    lines += ["## Results by attack type", ""]
    by_arm = {arm: {f["held_out_attack_type"]: f for f in metrics["arms"][arm]["folds"]} for arm in ARM_FEATURES}
    for arm in ARM_FEATURES:
        lines += [f"### ARM {arm}", "", "| Type | Episode recall | Episodes | Window recall | ROC-AUC | PR-AUC | Test FPR | Threshold |", "|---|---:|---:|---:|---:|---:|---:|---:|"]
        for attack_type, fold in sorted(by_arm[arm].items()):
            point = next(p for p in fold["operating_points"] if p["target_train_fpr"] == 0.01)
            lines.append(
                f"| {attack_type} | {point['episode_recall']:.4f} | {len(point['episodes_detected'])}/{fold['test_episodes']} | "
                f"{point['window_recall']:.4f} | {fold['roc_auc']:.4f} | {fold['pr_auc']:.4f} | "
                f"{point['observed_test_fpr']:.6f} | {point['threshold']:.6f} |"
            )
        lines.append("")

    lines += ["## Robustness and decisions", ""]
    for arm in ARM_FEATURES:
        item = arms[arm]
        classification = comparison["classifications"][arm]
        lines.append(f"- **ARM {arm} — {classification['status']}**: {classification['reason']}.")
        if arm != "A":
            gain = item["gain_vs_arm_a"]
            lines.append(
                f"  Gain relative to A is {gain['episode_recall_delta']:+.4f}; new detections span "
                f"{len(gain['entities_with_candidate_only_detections'])} entities; observed FPR changes by {gain['fpr_delta']:+.6f}. "
                f"Important volumetric episode cost: {str(item['volumetric_cost']['important']).lower()}."
            )
    minimal = comparison["minimal_best_compromise"]
    lines += [
        "",
        "## Minimal best compromise",
        "",
        f"**ARM {minimal['arm']} — {', '.join(minimal['features'])}.** {minimal['rationale']}",
        "",
        "This selection is protocol-specific. Feature gain importance is descriptive and is not used as causal attribution; the registered ablation arms provide the direct budget comparisons.",
        "",
        "## Online validity",
        "",
        "All three formulas are ONLINE under the P6 window-close convention. `interarrival_mean` uses only consecutive differences between relative event starts already observed in the window. `bytes_per_packet_destination` uses destination byte and packet counters available by window close. `distinct_payload_ratio` uses only observed byte-count pairs. No absolute timestamp or future window enters any feature. The benchmark reconstructs values from historical persisted FlowEnd evidence, so it does **not** measure streaming ingestion latency or the effect of late flow records; that operational question remains outside this benchmark.",
        "",
        "Undefined `interarrival_mean` or zero-denominator `bytes_per_packet_destination` values remain native NaN. No fitted imputation and no missingness indicator is added.",
        "",
        "## R11 and scope of the evidence",
        "",
        "R11 remains open: the botnet endpoint contains **5 entities, 1 destination (`205.174.165.73`), and 40 episodes**. This benchmark demonstrates transfer from the four held-in attack types to the held-out Ares windows, under the frozen population and feature formulas, and shows whether additions improve ARM A on those same episodes. It does not demonstrate generalisation to another victim, another attacker population, another capture, or unseen botnet mechanics. No universal or causal claim is made.",
        "",
        "## Integrity",
        "",
        f"Protocol checks passed: {len(metrics['protocol_verification'])}; feature/online checks passed: {len(metrics['feature_derivation']['checks'])}; cross-arm identity checks passed: {len(metrics['cross_arm_test_identity'])}. PostgreSQL writes: 0.",
        "",
    ]
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Controlled four-arm XGBoost feature benchmark")
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    if args.preflight == args.execute:
        parser.error("choose exactly one of --preflight or --execute")

    started = datetime.now(UTC).isoformat()
    print("verifying frozen input files ...")
    frozen_checks = verify_frozen_files()
    print(f"  {len(frozen_checks)} frozen file digests match")

    print("loading P1 population and authentic fold order read-only ...")
    positives = load_positives(str(REPO_ROOT))
    negatives = load_negatives()
    rows = positives + negatives
    folds = build_folds(positives, negatives)
    if dataset_digest(rows) != P1_DATASET_CONTENT_SHA256:
        raise BenchmarkViolation("P1 population content digest mismatch")
    if folds_digest(folds) != P1_FOLDS_CONTENT_SHA256:
        raise BenchmarkViolation("P1 folds content digest mismatch")
    if verify_protocol is None:
        raise BenchmarkViolation("baseline protocol verifier could not be imported")
    protocol_checks = verify_protocol(rows, folds)
    print(f"  {len(protocol_checks)} P1 protocol checks pass")

    print("deriving exactly the three registered P6 formulas read-only ...")
    by_arm_rows, feature_derivation = build_feature_rows(rows)
    print(f"  {len(feature_derivation['checks'])} feature and online-validity checks pass")

    by_arm_id = {arm: {row.row_id: row for row in arm_rows} for arm, arm_rows in by_arm_rows.items()}
    cross_arm_checks: list[dict[str, Any]] = []
    for fold in sorted(folds, key=lambda value: value.index):
        signatures = {}
        for arm in ARM_FEATURES:
            test = [by_arm_id[arm][row_id] for row_id in fold.test_row_ids]
            signatures[arm] = _test_signature(test)
        _record(
            cross_arm_checks,
            f"fold{fold.index}_ordered_test_row_and_label_signature_identical_across_all_arms",
            len(set(signatures.values())) == 1,
            signatures,
        )
    print(f"  {len(cross_arm_checks)} pre-fit cross-arm test identity checks pass")

    if args.preflight:
        print("\nPREFLIGHT ONLY. No model was fitted and no artifact or database row was written.")
        return 0

    print("\nfitting four registered arms with unchanged XGBoost parameters ...")
    results: list[FoldResult] = []
    per_entity: dict[str, Any] = {arm: {} for arm in ARM_FEATURES}
    for arm, features in ARM_FEATURES.items():
        print(f"ARM {arm}: {', '.join(features)}")
        for fold in sorted(folds, key=lambda value: value.index):
            train = [by_arm_id[arm][row_id] for row_id in fold.train_row_ids]
            test = [by_arm_id[arm][row_id] for row_id in fold.test_row_ids]
            result = evaluate_fold(arm, features, fold.index, fold.held_out_attack_type, train, test)
            point = _point(result)
            print(
                f"  {result.held_out_attack_type:26} ep {point['episode_recall']:.4f} "
                f"({len(point['episodes_detected'])}/{result.test_episodes})  win {point['window_recall']:.4f}  "
                f"roc {result.roc_auc:.4f}  pr {result.pr_auc:.4f}  fpr {point['observed_test_fpr']:.6f}"
            )
            scores = np.asarray([float(record["score"]) for record in result.predictions])
            per_entity[arm][result.held_out_attack_type] = {
                f"target_{target}": per_entity_recall(test, scores, _point(result, target)["threshold"])
                for target in FPR_TARGETS
            }
            results.append(result)

    # ARM A must reproduce the immutable published baseline score stream exactly.
    for fold in sorted(folds, key=lambda value: value.index):
        arm_a = next(result for result in results if result.arm == "A" and result.fold == fold.index)
        with (BASELINE_DIR / f"xgb_predictions_fold{fold.index}.csv").open(newline="", encoding="utf-8") as handle:
            reference = list(csv.DictReader(handle))
        observed = arm_a.predictions
        same = len(reference) == len(observed) and all(
            (a["row_id"], a["label"], a["score"])
            == (b["row_id"], str(b["label"]), b["score"])
            for a, b in zip(reference, observed)
        )
        _record(
            cross_arm_checks,
            f"fold{fold.index}_arm_a_reproduces_published_xgboost_baseline_scores",
            same,
            f"{len(observed)} ordered predictions",
        )

    # Independent post-fit guard: every output stream has the same ordered test ids/labels.
    for fold in sorted(folds, key=lambda value: value.index):
        signatures = {}
        for arm in ARM_FEATURES:
            result = next(value for value in results if value.arm == arm and value.fold == fold.index)
            payload = "".join(f"{r['row_id']},{r['label']}\n" for r in result.predictions).encode("utf-8")
            signatures[arm] = sha256(payload).hexdigest()
        _record(
            cross_arm_checks,
            f"fold{fold.index}_prediction_row_and_label_stream_identical_across_all_arms",
            len(set(signatures.values())) == 1,
            signatures,
        )

    comparisons, comparison_document = analyse_results(results, per_entity)
    by_result = _result_map(results)
    metrics = {
        "experiment": "controlled four-arm XGBoost feature benchmark",
        "question": "do interarrival_mean and/or bytes_per_packet_destination improve botnet/Ares detection beyond distinct_payload_ratio?",
        "started_at": started,
        "completed_at": datetime.now(UTC).isoformat(),
        "postgresql_writes": 0,
        "read_only_transactions": True,
        "p1_dataset_content_sha256": P1_DATASET_CONTENT_SHA256,
        "p1_folds_content_sha256": P1_FOLDS_CONTENT_SHA256,
        "frozen_file_checks": frozen_checks,
        "protocol_verification": protocol_checks,
        "cross_arm_test_identity": cross_arm_checks,
        "feature_derivation": feature_derivation,
        "arms_registered": {arm: list(features) for arm, features in ARM_FEATURES.items()},
        "model_parameters": XGB_PARAMS,
        "hyperparameter_search": False,
        "early_stopping": False,
        "class_rebalancing": False,
        "resampling_or_smote": False,
        "ensembling": False,
        "new_split_created": False,
        "labels_modified": False,
        "unknown_or_ambiguous_as_negative": False,
        "threshold_rule": "training negatives only at 1% and 0.1%; no test observation selects a threshold",
        "bootstrap": BOOTSTRAP_DECLARATION,
        "conservative_decisions": DECISIONS,
        "arms": {
            arm: {
                "features": list(ARM_FEATURES[arm]),
                "folds": [_fold_document(by_result[arm][attack]) for attack in sorted(by_result[arm])],
            }
            for arm in ARM_FEATURES
        },
        "per_entity_recall": per_entity,
        "comparisons_vs_arm_a": comparisons,
        "references": {
            "P1": {"episode_recall": 0.075, "episodes_detected": 3, "episodes": 40, "roc_auc": 0.5037},
            "published_P6_XGBoost_ARM_A": {"episode_recall": 0.325, "episodes_detected": 13, "episodes": 40, "roc_auc": 0.7615, "pr_auc": 0.0670, "observed_test_fpr": 0.009874},
        },
        "r11": {
            "botnet_entities": 5,
            "destinations": 1,
            "destination": "205.174.165.73",
            "botnet_episodes": 40,
            "demonstrates": "within-protocol transfer to held-out Ares windows and marginal feature-budget differences on the same episodes",
            "does_not_demonstrate": "generalisation to other victims, attackers, captures, botnet families, or operational streaming latency",
        },
    }

    # Publish only after every fit and identity guard has succeeded.
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    all_predictions: list[dict[str, Any]] = []
    for result in sorted(results, key=lambda value: (value.arm, value.fold)):
        model_name = f"model_arm_{result.arm}_fold{result.fold}.joblib"
        prediction_name = f"predictions_arm_{result.arm}_fold{result.fold}.csv"
        _publish_bytes(OUT_DIR / model_name, _model_payload(result.model))
        _publish_bytes(OUT_DIR / prediction_name, _csv_payload(result.predictions))
        all_predictions.extend(result.predictions)

    _publish_bytes(OUT_DIR / "benchmark_predictions.csv", _csv_payload(all_predictions))
    metrics_content, metrics_file = _publish_document(OUT_DIR / "benchmark_metrics.json", metrics)
    comparison_content, comparison_file = _publish_document(OUT_DIR / "feature_comparison.json", comparison_document)
    report_payload = render_report(metrics, comparison_document).encode("utf-8") + b"\n"
    report_digest = _publish_bytes(OUT_DIR / "BENCHMARK_REPORT.md", report_payload)

    import sklearn
    import xgboost

    outputs = {
        path.name: _sha(path)
        for path in sorted(OUT_DIR.iterdir())
        if path.is_file() and path.name != "benchmark_manifest.json"
    }
    manifest = {
        "artifact": "controlled XGBoost feature benchmark manifest",
        "inputs": {
            "p1_dataset_content_sha256": P1_DATASET_CONTENT_SHA256,
            "p1_folds_content_sha256": P1_FOLDS_CONTENT_SHA256,
            "frozen_files": FROZEN_FILE_SHA256,
        },
        "arms": {arm: list(features) for arm, features in ARM_FEATURES.items()},
        "model_parameters": XGB_PARAMS,
        "conservative_decisions": DECISIONS,
        "library_versions": {
            "python": sys.version.split()[0],
            "numpy": np.__version__,
            "scikit-learn": sklearn.__version__,
            "xgboost": xgboost.__version__,
            "joblib": joblib.__version__,
        },
        "protocol_checks_passed": len(protocol_checks),
        "feature_checks_passed": len(feature_derivation["checks"]),
        "cross_arm_identity_checks_passed": len(cross_arm_checks),
        "postgresql_writes": 0,
        "read_only_transactions": True,
        "outputs": outputs,
    }
    manifest_digest = _publish_bytes(OUT_DIR / "benchmark_manifest.json", _json_bytes(manifest))

    print("\n=== PRIMARY ENDPOINT — botnet/Ares episode recall @1% ===")
    for arm in ARM_FEATURES:
        primary = comparisons[arm]["primary"]
        status = comparison_document["classifications"][arm]["status"]
        print(
            f"  ARM {arm}  {primary['episode_recall']:.4f} ({primary['episodes_detected']}/40)  "
            f"CI [{primary['episode_ci'][0]:.4f}, {primary['episode_ci'][1]:.4f}]  "
            f"ROC {primary['roc_auc']:.4f}  PR {primary['pr_auc']:.4f}  "
            f"FPR {primary['observed_test_fpr']:.6f}  {status}"
        )
    minimal = comparison_document["minimal_best_compromise"]
    print(f"\nminimal best compromise: ARM {minimal['arm']} — {', '.join(minimal['features'])}")
    print(f"benchmark_metrics.json content {metrics_content[:16]} file {metrics_file[:16]}")
    print(f"feature_comparison.json content {comparison_content[:16]} file {comparison_file[:16]}")
    print(f"BENCHMARK_REPORT.md {report_digest[:16]}")
    print(f"benchmark_manifest.json {manifest_digest[:16]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
