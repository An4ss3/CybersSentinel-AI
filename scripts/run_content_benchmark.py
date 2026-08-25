"""Run the six-arm payload-content benchmark on the frozen P1 protocol.

Strictly additive. P1--P6, the published one-feature XGBoost baseline and the
frozen four-arm A--D benchmark are inputs only; nothing under their directories is
written. PostgreSQL is read through the existing read-only helper. Fitting starts
only after every frozen digest, the population, the folds, the authentic training
order, the ordered test rows and the arm identities have been verified.
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
from typing import Any, Final

import joblib
import numpy as np

from modules.detection.src.experiments.content_benchmark import (
    ARM_FEATURES,
    BASE_FEATURE,
    BOOTSTRAP_DECLARATION,
    CONTENT_FEATURE_NAMES,
    DIAGNOSTIC_FEATURES,
    HEADER_TEMPLATE_METRIC,
    INDICATOR_SUFFIX,
    MODEL_SPECS,
    PRIMARY_ENDPOINT,
    ContentBenchmarkError,
    FoldResult,
    evaluate_fold,
    missingness_attribution,
    paired_episode_bootstrap_delta,
    per_entity_recall,
)
from modules.detection.src.experiments.p1_dataset import (
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

try:  # pragma: no cover - depends on invocation style
    from scripts.run_xgboost_baseline import verify_protocol
except ImportError:  # pragma: no cover
    verify_protocol = None  # type: ignore[assignment]


REPO_ROOT = Path(__file__).resolve().parents[1]
P1_DIR: Final[Path] = REPO_ROOT / "artifacts" / "experiments" / "p1"
P6_DIR: Final[Path] = REPO_ROOT / "artifacts" / "experiments" / "p6"
BASELINE_DIR: Final[Path] = REPO_ROOT / "artifacts" / "experiments" / "xgboost_baseline"
AD_DIR: Final[Path] = (
    REPO_ROOT / "artifacts" / "experiments" / "xgboost_feature_benchmark"
)
CONTENT_DIR: Final[Path] = (
    REPO_ROOT / "artifacts" / "experiments" / "xgboost_content_benchmark"
)

P1_DATASET_CONTENT_SHA256: Final[str] = (
    "3d7436178da6960ee5effeb4bee85a0b6da5eead9d2babef3c72cb6b7ca9f20d"
)
P1_FOLDS_CONTENT_SHA256: Final[str] = (
    "e463ea7b0eb4985f51369dc3ae19c09821040675aa4b9f9689f8e02545fed95a"
)
FROZEN_FILE_SHA256: Final[dict[str, str]] = {
    "p1_dataset.csv": "e95aed008d994510e4c649c287feb8fe8f49a785bec144d7e83aa15804b6c062",
    "p1_folds.json": "57e688fd3da90911707d7a172c161686d852094121eda1ac49e0221fc0529fa1",
    "p1_metrics.json": "2a51e618397c42b742a289216d3cd89b255c4ccd96a8f985a5ad1c5c4783a447",
    "p6_feature_audit.json": "d028e8476df66c2827e534281fdda6c994c6e1023ba42bb57461c34316a9d1ac",
    "xgb_metrics.json": "4b841773bbe34d62153dfbd69cc9c5f2a480b781f842ed0c59a1efe3a21a1263",
    "xgb_model_params.json": "d6d33ca0b7a6d42f5bd059ac1e8a2c11fe6b47f8e7104ee1da6ac6a139a03521",
    "benchmark_manifest.json": "2b6e65e658297dd1d96d3f4d3afce9798a5cf9e99279a70253dbbb022315af88",
    "content_features.csv": "1f831d7e22b2db853713622da2fd7569af768e9884aba04ece6e206fc5896413",
    "content_extraction_audit.json": "617bd3121231fdaf858394ba2b67db34c2e8a8d36cbe3d9b6b94d5d14a2b71f9",
}

#: The published ARM A reference the new ARM A must reproduce exactly.
PUBLISHED_ARM_A: Final[dict[str, Any]] = {
    "episode_recall": 0.325,
    "episodes_detected": 13,
    "episodes": 40,
    "roc_auc": 0.7615,
    "pr_auc": 0.0670,
    "observed_test_fpr": 0.009874,
}

DECISIONS: Final[list[dict[str, str]]] = [
    {
        "id": "D29",
        "decision": "arms A/E/F/G/H/I are taken verbatim from the extractor registry, which was fixed before any content value existed",
        "reason": "ARM I is A plus all six metrics by pre-registration, never a subset selected after reading E--H",
    },
    {
        "id": "D30",
        "decision": "undefined content metrics stay NaN and use XGBoost's native missing branch inside an arm",
        "reason": "imputation, a fitted fill value or an extra indicator inside an arm would widen the registered budget",
    },
    {
        "id": "D31",
        "decision": "the presence indicators appear only in two declared diagnostics, never in an arm, and take part in no ranking",
        "reason": "presence of the header-template metric is exactly service==http, which P1 forbids as a feature; the diagnostics bound that contribution instead of hiding it",
    },
    {
        "id": "D32",
        "decision": "ARM A must reproduce the published baseline score stream byte-for-byte before any artifact is written",
        "reason": "without that identity the six-arm comparison would not be anchored to the ratified 13/40 reference",
    },
    {
        "id": "D33",
        "decision": "no tuning, no validation split, no early stopping, no rebalancing and no threshold search",
        "reason": "only the feature budget varies; thresholds come from training negatives at 1% and 0.1% exactly as ratified",
    },
]


def _sha(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, indent=2, sort_keys=True, allow_nan=True).encode("utf-8")
        + b"\n"
    )


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


def _identity(document: dict[str, Any]) -> dict[str, Any]:
    return {
        k: v
        for k, v in document.items()
        if k not in ("started_at", "completed_at", "content_sha256")
    }


def _publish_document(path: Path, document: dict[str, Any]) -> tuple[str, str]:
    value = dict(document)
    value["content_sha256"] = sha256(
        json.dumps(
            _identity(value), sort_keys=True, separators=(",", ":"), allow_nan=True
        ).encode("utf-8")
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
        raise ContentBenchmarkError(f"{name}: {detail}")


def verify_frozen_files() -> list[dict[str, Any]]:
    """Every frozen input, including the published A--D manifest, must be intact."""
    checks: list[dict[str, Any]] = []
    paths = {
        "p1_dataset.csv": P1_DIR / "p1_dataset.csv",
        "p1_folds.json": P1_DIR / "p1_folds.json",
        "p1_metrics.json": P1_DIR / "p1_metrics.json",
        "p6_feature_audit.json": P6_DIR / "p6_feature_audit.json",
        "xgb_metrics.json": BASELINE_DIR / "xgb_metrics.json",
        "xgb_model_params.json": BASELINE_DIR / "xgb_model_params.json",
        "benchmark_manifest.json": AD_DIR / "benchmark_manifest.json",
        "content_features.csv": CONTENT_DIR / "content_features.csv",
        "content_extraction_audit.json": CONTENT_DIR / "content_extraction_audit.json",
    }
    for name, path in paths.items():
        digest = _sha(path)
        _record(
            checks,
            f"{name}_file_digest_frozen",
            digest == FROZEN_FILE_SHA256[name],
            digest,
        )
    return checks


def load_content_features(rows: list[Row]) -> tuple[dict[str, dict[str, float]], dict[str, Any]]:
    """Join the published aggregates by frozen row id and derive presence indicators."""
    path = CONTENT_DIR / "content_features.csv"
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        fields = list(reader.fieldnames or [])
        table: dict[str, dict[str, float]] = {}
        for record in reader:
            values: dict[str, float] = {}
            for name in CONTENT_FEATURE_NAMES:
                raw = record[name]
                present = raw != ""
                values[name] = float(raw) if present else float("nan")
                values[f"{name}{INDICATOR_SUFFIX}"] = 1.0 if present else 0.0
            table[record["row_id"]] = values

    checks: list[dict[str, Any]] = []
    _record(
        checks,
        "published_content_columns_are_exactly_row_id_plus_the_six_metrics",
        fields == ["row_id", *CONTENT_FEATURE_NAMES],
        fields,
    )
    _record(
        checks,
        "every_frozen_p1_row_has_a_content_record",
        all(row.row_id in table for row in rows) and len(table) == len(rows),
        {"rows": len(rows), "content_rows": len(table)},
    )
    finite = [
        value
        for values in table.values()
        for name, value in values.items()
        if name in CONTENT_FEATURE_NAMES and not math.isnan(value)
    ]
    _record(
        checks,
        "every_content_value_lies_in_the_unit_interval",
        all(0.0 <= value <= 1.0 and math.isfinite(value) for value in finite),
        {"values": len(finite), "min": min(finite), "max": max(finite)},
    )
    return table, {"checks": checks, "content_values_observed": len(finite)}


def build_model_rows(
    rows: list[Row], content: dict[str, dict[str, float]]
) -> tuple[dict[str, list[Row]], dict[str, Any]]:
    """Assemble one row list per model spec, preserving P1 order and metadata."""
    events_m4 = fetch_events(PRODUCTION_DATABASE, "m4_canonical.flow_end_events")
    events_mb4 = fetch_events(MB_DATABASE, "mb4_canonical.flow_end_events")
    base_table: dict[tuple[str, str, int], dict[str, float]] = {}
    base_table.update(compute(events_m4, (BASE_FEATURE,)))
    base_table.update(compute(events_mb4, (BASE_FEATURE,)))

    checks: list[dict[str, Any]] = []
    _record(
        checks,
        "base_feature_is_the_unmodified_p6_implementation",
        BASE_FEATURE in FEATURE_FUNCTIONS,
        BASE_FEATURE,
    )
    _record(
        checks,
        "base_feature_is_p6_online",
        ONLINE_AVAILABILITY[BASE_FEATURE].startswith("online"),
        ONLINE_AVAILABILITY[BASE_FEATURE],
    )

    by_model: dict[str, list[Row]] = {name: [] for name in MODEL_SPECS}
    for row in rows:
        key = (row.partition, row.entity_key, row.window_start_epoch)
        base = base_table.get(key)
        if base is None:
            raise ContentBenchmarkError(f"no P6 reconstruction for frozen row {key!r}")
        available = {BASE_FEATURE: float(base[BASE_FEATURE]), **content[row.row_id]}
        for name, features in MODEL_SPECS.items():
            by_model[name].append(
                replace(row, features=tuple(available[f] for f in features))
            )

    for name, model_rows in by_model.items():
        _record(
            checks,
            f"{name}_preserves_row_and_label_metadata_in_p1_order",
            all(
                (a.row_id, a.label, a.disposition, a.attack_type, a.episode_id, a.entity_key)
                == (b.row_id, b.label, b.disposition, b.attack_type, b.episode_id, b.entity_key)
                for a, b in zip(rows, model_rows)
            ),
            f"{len(model_rows)} rows",
        )
        _record(
            checks,
            f"{name}_has_exactly_the_registered_feature_width",
            all(len(r.features) == len(MODEL_SPECS[name]) for r in model_rows),
            {"features": list(MODEL_SPECS[name])},
        )

    _record(
        checks,
        "arm_a_is_exactly_one_feature_and_carries_no_content_metric",
        ARM_FEATURES["A"] == (BASE_FEATURE,),
        list(ARM_FEATURES["A"]),
    )
    _record(
        checks,
        "no_arm_contains_a_presence_indicator",
        all(
            not f.endswith(INDICATOR_SUFFIX)
            for features in ARM_FEATURES.values()
            for f in features
        ),
        {arm: list(f) for arm, f in ARM_FEATURES.items()},
    )
    _record(
        checks,
        "arm_i_is_arm_a_plus_all_six_metrics",
        ARM_FEATURES["I"] == (BASE_FEATURE, *CONTENT_FEATURE_NAMES),
        list(ARM_FEATURES["I"]),
    )
    return by_model, {"checks": checks}


def _signature(rows: list[Row]) -> str:
    payload = "".join(f"{r.row_id},{r.label}\n" for r in rows).encode("utf-8")
    return sha256(payload).hexdigest()


def _point(result: FoldResult, target: float = 0.01) -> dict[str, Any]:
    return next(p for p in result.operating_points if p["target_train_fpr"] == target)


def _fold_document(result: FoldResult) -> dict[str, Any]:
    return {
        "arm": result.arm,
        "features": list(result.features),
        "fold": result.fold,
        "is_diagnostic": result.is_diagnostic,
        "held_out_attack_type": result.held_out_attack_type,
        "train_positives": result.train_positives,
        "train_negatives": result.train_negatives,
        "test_positives": result.test_positives,
        "test_negatives": result.test_negatives,
        "test_episodes": result.test_episodes,
        "roc_auc": result.roc_auc,
        "pr_auc": result.pr_auc,
        "feature_importance_gain": result.feature_importance_gain,
        "test_missingness_rate": result.missingness,
        "operating_points": result.operating_points,
    }


def _csv_payload(records: list[dict[str, Any]]) -> bytes:
    stream = io.StringIO(newline="")
    fields = [
        "arm",
        "fold",
        "row_id",
        "label",
        "disposition",
        "attack_type",
        "episode_id",
        "score",
    ]
    writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    writer.writerows(records)
    return stream.getvalue().encode("utf-8")


def analyse(
    results: list[FoldResult], per_entity: dict[str, Any]
) -> dict[str, Any]:
    by_model: dict[str, dict[str, FoldResult]] = {name: {} for name in MODEL_SPECS}
    for result in results:
        by_model[result.arm][result.held_out_attack_type] = result

    base = by_model["A"][PRIMARY_ENDPOINT]
    base_point = _point(base)
    comparisons: dict[str, Any] = {}

    for name in MODEL_SPECS:
        primary = by_model[name][PRIMARY_ENDPOINT]
        point = _point(primary)
        strict = _point(primary, 0.001)
        entities = per_entity[name][PRIMARY_ENDPOINT]["target_0.01"]
        if name == "A":
            paired = {
                "point": 0.0,
                "ci_low": 0.0,
                "ci_high": 0.0,
                "episodes": primary.test_episodes,
                "candidate_only_detections": 0,
                "reference_only_detections": 0,
            }
            candidate_only: list[str] = []
            reference_only: list[str] = []
        else:
            paired = paired_episode_bootstrap_delta(
                base_point["episode_detection"], point["episode_detection"]
            )
            candidate_only = sorted(
                e
                for e, d in point["episode_detection"].items()
                if d and not base_point["episode_detection"][e]
            )
            reference_only = sorted(
                e
                for e, d in base_point["episode_detection"].items()
                if d and not point["episode_detection"][e]
            )

        volumetric: dict[str, Any] = {}
        base_detected = candidate_detected = 0
        for attack_type in sorted(k for k in by_model["A"] if k != PRIMARY_ENDPOINT):
            a = by_model["A"][attack_type]
            c = by_model[name][attack_type]
            ap, cp = _point(a), _point(c)
            base_detected += len(ap["episodes_detected"])
            candidate_detected += len(cp["episodes_detected"])
            volumetric[attack_type] = {
                "episode_recall_a": ap["episode_recall"],
                "episode_recall_model": cp["episode_recall"],
                "episode_recall_delta": cp["episode_recall"] - ap["episode_recall"],
                "roc_auc_a": a.roc_auc,
                "roc_auc_model": c.roc_auc,
                "pr_auc_a": a.pr_auc,
                "pr_auc_model": c.pr_auc,
                "observed_test_fpr_model": cp["observed_test_fpr"],
            }
        important_cost = candidate_detected <= base_detected - 2 or any(
            v["episode_recall_delta"] <= -0.25 for v in volumetric.values()
        )

        comparisons[name] = {
            "features": list(MODEL_SPECS[name]),
            "is_diagnostic": name in DIAGNOSTIC_FEATURES,
            "primary_1pct": {
                "episode_recall": point["episode_recall"],
                "episode_ci": [
                    point["episode_bootstrap"]["ci_low"],
                    point["episode_bootstrap"]["ci_high"],
                ],
                "episodes_detected": len(point["episodes_detected"]),
                "episodes_total": primary.test_episodes,
                "window_recall": point["window_recall"],
                "roc_auc": primary.roc_auc,
                "pr_auc": primary.pr_auc,
                "observed_test_fpr": point["observed_test_fpr"],
                "threshold": point["threshold"],
                "entities_detected": sum(
                    v["episodes_detected"] > 0 for v in entities.values()
                ),
                "entities_total": len(entities),
            },
            "primary_0p1pct": {
                "episode_recall": strict["episode_recall"],
                "episodes_detected": len(strict["episodes_detected"]),
                "window_recall": strict["window_recall"],
                "observed_test_fpr": strict["observed_test_fpr"],
                "threshold": strict["threshold"],
            },
            "gain_vs_arm_a_1pct": {
                "episode_recall_delta": point["episode_recall"]
                - base_point["episode_recall"],
                "paired_episode_bootstrap": paired,
                "candidate_only_episodes": candidate_only,
                "reference_only_episodes": reference_only,
                "entities_with_candidate_only_detections": sorted(
                    {"|".join(e.split("|")[1:-1]) for e in candidate_only}
                ),
                "roc_auc_delta": primary.roc_auc - base.roc_auc,
                "pr_auc_delta": primary.pr_auc - base.pr_auc,
                "fpr_delta": point["observed_test_fpr"]
                - base_point["observed_test_fpr"],
            },
            "volumetric_cost": {
                "important": important_cost,
                "episodes_detected_a": base_detected,
                "episodes_detected_model": candidate_detected,
                "by_type": volumetric,
            },
            "feature_importance_gain_primary_fold": primary.feature_importance_gain,
            "test_missingness_rate_primary_fold": primary.missingness,
        }

    # Declared missingness attribution for the two arms that can carry the proxy.
    attribution = {
        "H": missingness_attribution(
            _point(by_model["H"][PRIMARY_ENDPOINT])["episode_detection"],
            _point(by_model["H_IND"][PRIMARY_ENDPOINT])["episode_detection"],
            base_point["episode_detection"],
        ),
        "I": missingness_attribution(
            _point(by_model["I"][PRIMARY_ENDPOINT])["episode_detection"],
            _point(by_model["I_IND"][PRIMARY_ENDPOINT])["episode_detection"],
            base_point["episode_detection"],
        ),
    }

    classifications: dict[str, Any] = {
        "A": {
            "status": "RETAIN",
            "reason": "registered baseline and ratified reference; retained as the minimal comparator",
        }
    }
    for name in ("E", "F", "G", "H", "I"):
        item = comparisons[name]
        primary = item["primary_1pct"]
        gain = item["gain_vs_arm_a_1pct"]
        interval = gain["paired_episode_bootstrap"]
        supported = interval["ci_low"] > 0.0
        stable_fpr = (
            abs(gain["fpr_delta"]) <= 0.0025 and primary["observed_test_fpr"] <= 0.0125
        )
        noninferior = gain["roc_auc_delta"] >= 0.0 and gain["pr_auc_delta"] >= 0.0
        robust = primary["entities_detected"] == 5 and (
            len(gain["entities_with_candidate_only_detections"]) >= 2
        )
        no_cost = not item["volumetric_cost"]["important"]
        share = attribution.get(name, {}).get("share_explained_by_missingness")
        proxy_free = share is None or share < 1.0
        clearly_worse = interval["ci_high"] < 0.0

        if supported and stable_fpr and noninferior and robust and no_cost and proxy_free:
            status, reason = (
                "RETAIN",
                "positive paired episode-gain interval, stable FPR, non-inferior ROC/PR, "
                "gain distributed over multiple entities with 5/5 retained, no important "
                "volumetric cost, and the gain is not fully reproduced by the presence indicator",
            )
        elif clearly_worse:
            status, reason = (
                "REJECT",
                "paired episode-delta interval is strictly negative on the pre-registered "
                "primary endpoint; a global ROC gain cannot override that loss",
            )
        elif (
            gain["episode_recall_delta"] <= 0.0
            and gain["roc_auc_delta"] <= 0.0
            and gain["pr_auc_delta"] <= 0.0
        ):
            status, reason = (
                "REJECT",
                "no episode gain and no discrimination gain over the simpler ARM A",
            )
        else:
            failed = []
            if not supported:
                failed.append("paired episode-delta CI includes zero")
            if not stable_fpr:
                failed.append("FPR is not stable")
            if not noninferior:
                failed.append("ROC and PR are not both non-inferior")
            if not robust:
                failed.append("gain is not distributed while retaining 5/5 entities")
            if not no_cost:
                failed.append("important volumetric episode cost")
            if not proxy_free:
                failed.append(
                    "the presence indicator alone reproduces the whole gain, so it "
                    "cannot be credited to the metric value"
                )
            status, reason = "INCONCLUSIVE", "; ".join(failed)

        classifications[name] = {
            "status": status,
            "reason": reason,
            "rules": {
                "paired_delta_ci_strictly_positive": supported,
                "stable_fpr": stable_fpr,
                "roc_and_pr_noninferior": noninferior,
                "distributed_and_5_of_5_entities": robust,
                "no_important_volumetric_episode_cost": no_cost,
                "not_fully_explained_by_missingness": proxy_free,
            },
        }

    retained = [a for a, v in classifications.items() if v["status"] == "RETAIN"]
    best_recall = max(comparisons[a]["primary_1pct"]["episode_recall"] for a in retained)
    tied = [
        a
        for a in retained
        if comparisons[a]["primary_1pct"]["episode_recall"] == best_recall
    ]
    best = max(
        tied,
        key=lambda a: (
            comparisons[a]["primary_1pct"]["roc_auc"],
            comparisons[a]["primary_1pct"]["pr_auc"],
            -comparisons[a]["primary_1pct"]["observed_test_fpr"],
            -len(MODEL_SPECS[a]),
        ),
    )
    return {
        "experiment": "six-arm payload-content feature benchmark",
        "reference_arm": "A",
        "primary_endpoint": f"{PRIMARY_ENDPOINT} episode recall at 1% training FPR",
        "classification_rule": (
            "RETAIN requires a paired episode-delta interval strictly above zero, stable FPR "
            "(absolute delta <=0.0025 and observed <=0.0125), ROC and PR non-inferior, gain across "
            "multiple entities with 5/5 retained, no important volumetric episode cost, and a gain "
            "not fully reproduced by the presence indicator alone; REJECT applies when the paired "
            "primary interval is strictly negative or when there is neither episode nor "
            "discrimination gain; otherwise INCONCLUSIVE"
        ),
        "models": comparisons,
        "classifications": classifications,
        "missingness_attribution": attribution,
        "minimal_best_compromise": {
            "arm": best,
            "features": list(MODEL_SPECS[best]),
            "rationale": (
                "among arms meeting the conservative RETAIN rule, maximise observed "
                f"{PRIMARY_ENDPOINT} episode recall; break ties by ROC-AUC, PR-AUC, lower FPR, "
                "then fewer features"
            ),
        },
        "diagnostics_are_not_arms": sorted(DIAGNOSTIC_FEATURES),
        "causal_scope": (
            "arm contrasts identify the effect of changing the feature budget under this fixed "
            "learner and protocol, not universal causal feature effects"
        ),
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Six-arm payload-content feature benchmark on the frozen P1 protocol"
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--preflight", action="store_true")
    mode.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)

    started = datetime.now(UTC).isoformat()
    print("verifying frozen input digests ...", flush=True)
    frozen_checks = verify_frozen_files()
    print(f"  {len(frozen_checks)} frozen digests match")

    print("loading the frozen P1 population and authentic fold order ...", flush=True)
    positives = load_positives(str(REPO_ROOT))
    negatives = load_negatives()
    rows = positives + negatives
    folds = build_folds(positives, negatives)
    if dataset_digest(rows) != P1_DATASET_CONTENT_SHA256:
        raise ContentBenchmarkError("P1 population content digest mismatch")
    if folds_digest(folds) != P1_FOLDS_CONTENT_SHA256:
        raise ContentBenchmarkError("P1 folds content digest mismatch")
    if verify_protocol is None:
        raise ContentBenchmarkError("baseline protocol verifier could not be imported")
    protocol_checks = verify_protocol(rows, folds)
    print(f"  {len(protocol_checks)} P1 protocol checks pass")

    print("joining the published content aggregates by frozen row id ...", flush=True)
    content, content_checks = load_content_features(rows)
    print(f"  {len(content_checks['checks'])} content join checks pass")

    print("rebuilding distinct_payload_ratio with the P6 implementation ...", flush=True)
    by_model, build_checks = build_model_rows(rows, content)
    print(f"  {len(build_checks['checks'])} feature assembly checks pass")

    by_id = {name: {r.row_id: r for r in rs} for name, rs in by_model.items()}
    identity_checks: list[dict[str, Any]] = []
    for fold in sorted(folds, key=lambda f: f.index):
        signatures = {
            name: _signature([by_id[name][rid] for rid in fold.test_row_ids])
            for name in MODEL_SPECS
        }
        _record(
            identity_checks,
            f"fold{fold.index}_ordered_test_rows_identical_across_all_models",
            len(set(signatures.values())) == 1,
            signatures["A"],
        )
    print(f"  {len(identity_checks)} pre-fit cross-model identity checks pass")

    if args.preflight:
        print(
            "\nPREFLIGHT ONLY. No model was fitted and no artifact or database row was written."
        )
        return 0

    arm_count = len(ARM_FEATURES) * len(folds)
    diag_count = len(DIAGNOSTIC_FEATURES) * len(folds)
    print(
        f"\nfitting {arm_count} pre-registered arm models and {diag_count} declared "
        f"diagnostic models with unchanged XGBoost parameters ...",
        flush=True,
    )
    results: list[FoldResult] = []
    per_entity: dict[str, Any] = {name: {} for name in MODEL_SPECS}
    for name, features in MODEL_SPECS.items():
        tag = "diagnostic" if name in DIAGNOSTIC_FEATURES else "ARM"
        print(f"{tag} {name}: {', '.join(features)}", flush=True)
        for fold in sorted(folds, key=lambda f: f.index):
            train = [by_id[name][rid] for rid in fold.train_row_ids]
            test = [by_id[name][rid] for rid in fold.test_row_ids]
            result = evaluate_fold(
                name, features, fold.index, fold.held_out_attack_type, train, test
            )
            point = _point(result)
            print(
                f"  {result.held_out_attack_type:26} ep {point['episode_recall']:.4f} "
                f"({len(point['episodes_detected'])}/{result.test_episodes})  "
                f"win {point['window_recall']:.4f}  roc {result.roc_auc:.4f}  "
                f"pr {result.pr_auc:.4f}  fpr {point['observed_test_fpr']:.6f}",
                flush=True,
            )
            scores = np.asarray([float(r["score"]) for r in result.predictions])
            per_entity[name][result.held_out_attack_type] = {
                f"target_{t}": per_entity_recall(
                    test, scores, _point(result, t)["threshold"]
                )
                for t in FPR_TARGETS
            }
            results.append(result)

    # ARM A must reproduce the published baseline score stream byte-for-byte.
    for fold in sorted(folds, key=lambda f: f.index):
        arm_a = next(r for r in results if r.arm == "A" and r.fold == fold.index)
        reference_path = BASELINE_DIR / f"xgb_predictions_fold{fold.index}.csv"
        with reference_path.open(newline="", encoding="utf-8") as handle:
            reference = list(csv.DictReader(handle))
        same = len(reference) == len(arm_a.predictions) and all(
            (a["row_id"], a["label"], a["score"])
            == (b["row_id"], str(b["label"]), b["score"])
            for a, b in zip(reference, arm_a.predictions)
        )
        _record(
            identity_checks,
            f"fold{fold.index}_arm_a_reproduces_published_baseline_scores",
            same,
            f"{len(arm_a.predictions)} ordered predictions",
        )
    primary_a = next(
        r for r in results if r.arm == "A" and r.held_out_attack_type == PRIMARY_ENDPOINT
    )
    point_a = _point(primary_a)
    _record(
        identity_checks,
        "arm_a_reproduces_the_ratified_13_of_40_reference",
        len(point_a["episodes_detected"]) == PUBLISHED_ARM_A["episodes_detected"]
        and primary_a.test_episodes == PUBLISHED_ARM_A["episodes"]
        and abs(point_a["episode_recall"] - PUBLISHED_ARM_A["episode_recall"]) < 1e-12
        and abs(primary_a.roc_auc - PUBLISHED_ARM_A["roc_auc"]) < 5e-5
        and abs(primary_a.pr_auc - PUBLISHED_ARM_A["pr_auc"]) < 5e-5
        and abs(point_a["observed_test_fpr"] - PUBLISHED_ARM_A["observed_test_fpr"]) < 5e-7,
        {
            "episodes_detected": len(point_a["episodes_detected"]),
            "episode_recall": point_a["episode_recall"],
            "roc_auc": primary_a.roc_auc,
            "pr_auc": primary_a.pr_auc,
            "observed_test_fpr": point_a["observed_test_fpr"],
        },
    )
    print(f"  {len(identity_checks)} identity checks pass, ARM A anchored to 13/40")

    comparison = analyse(results, per_entity)

    by_result: dict[str, dict[str, FoldResult]] = {name: {} for name in MODEL_SPECS}
    for result in results:
        by_result[result.arm][result.held_out_attack_type] = result

    extraction_audit = json.loads(
        (CONTENT_DIR / "content_extraction_audit.json").read_text(encoding="utf-8")
    )
    metrics = {
        "experiment": "six-arm payload-content feature benchmark",
        "question": (
            "do the six first-wave payload-content aggregates improve botnet/ares episode "
            "detection beyond distinct_payload_ratio alone, under the frozen P1 protocol?"
        ),
        "started_at": started,
        "completed_at": datetime.now(UTC).isoformat(),
        "postgresql_writes": 0,
        "read_only_transactions": True,
        "p1_dataset_content_sha256": P1_DATASET_CONTENT_SHA256,
        "p1_folds_content_sha256": P1_FOLDS_CONTENT_SHA256,
        "frozen_file_checks": frozen_checks,
        "protocol_verification": protocol_checks,
        "content_join_verification": content_checks,
        "feature_assembly_verification": build_checks,
        "cross_model_identity": identity_checks,
        "arms_registered": {a: list(f) for a, f in ARM_FEATURES.items()},
        "diagnostics_declared": {d: list(f) for d, f in DIAGNOSTIC_FEATURES.items()},
        "model_parameters": XGB_PARAMS,
        "models_fitted": len(results),
        "hyperparameter_search": False,
        "early_stopping": False,
        "class_rebalancing": False,
        "resampling_or_smote": False,
        "new_split_created": False,
        "labels_modified": False,
        "unknown_or_ambiguous_as_negative": False,
        "threshold_rule": (
            "training negatives only at 1% and 0.1%; no test observation selects a threshold"
        ),
        "bootstrap": BOOTSTRAP_DECLARATION,
        "conservative_decisions": DECISIONS,
        "base_feature_definition": DEFINITIONS[BASE_FEATURE],
        "content_feature_definitions": extraction_audit["feature_definitions"],
        "content_availability_by_population": extraction_audit[
            "availability_by_population"
        ],
        "models": {
            name: {
                "features": list(MODEL_SPECS[name]),
                "is_diagnostic": name in DIAGNOSTIC_FEATURES,
                "folds": [
                    _fold_document(by_result[name][a]) for a in sorted(by_result[name])
                ],
            }
            for name in MODEL_SPECS
        },
        "per_entity_recall": per_entity,
        "published_arm_a_reference": PUBLISHED_ARM_A,
        "missingness_confound": {
            "finding": (
                "presence of normalized_header_template_repeat_ratio is exactly equivalent to "
                "service == http (12,279 frozen windows, all http)"
            ),
            "why_it_matters": (
                "P1 forbids entity_service as a feature and XGBoost branches natively on missing "
                "values, so an ARM H or ARM I effect could be carried by missingness rather than "
                "by header-template repetition"
            ),
            "treatment": (
                "the six arms were run exactly as pre-registered; two declared diagnostics replace "
                "the values with presence indicators to bound the contribution, and a RETAIN "
                "verdict additionally requires that the indicator alone does not reproduce the gain"
            ),
        },
        "r11": {
            "botnet_entities": 5,
            "destinations": 1,
            "destination": "205.174.165.73",
            "botnet_episodes": 40,
            "demonstrates": (
                "within-protocol transfer to held-out Ares windows and marginal feature-budget "
                "differences on the same episodes"
            ),
            "does_not_demonstrate": (
                "generalisation to other victims, attackers, captures, botnet families, or "
                "operational streaming latency"
            ),
        },
    }

    CONTENT_DIR.mkdir(parents=True, exist_ok=True)
    all_predictions: list[dict[str, Any]] = []
    for result in sorted(results, key=lambda r: (r.arm, r.fold)):
        _publish_bytes(
            CONTENT_DIR / f"model_{result.arm}_fold{result.fold}.joblib",
            _model_payload(result.model),
        )
        _publish_bytes(
            CONTENT_DIR / f"predictions_{result.arm}_fold{result.fold}.csv",
            _csv_payload(result.predictions),
        )
        all_predictions.extend(result.predictions)
    _publish_bytes(
        CONTENT_DIR / "content_benchmark_predictions.csv", _csv_payload(all_predictions)
    )
    metrics_content, _ = _publish_document(
        CONTENT_DIR / "content_benchmark_metrics.json", metrics
    )
    comparison_content, _ = _publish_document(
        CONTENT_DIR / "content_feature_comparison.json", comparison
    )
    report = render_report(metrics, comparison).encode("utf-8") + b"\n"
    _publish_bytes(CONTENT_DIR / "CONTENT_BENCHMARK_REPORT.md", report)

    import sklearn
    import xgboost

    outputs = {
        p.name: _sha(p)
        for p in sorted(CONTENT_DIR.iterdir())
        if p.is_file() and p.name != "content_benchmark_manifest.json"
    }
    manifest = {
        "experiment": "six-arm payload-content feature benchmark",
        "frozen_inputs": FROZEN_FILE_SHA256,
        "p1_population_or_folds_modified": False,
        "frozen_ad_benchmark_modified": False,
        "published_baseline_modified": False,
        "postgresql_writes": 0,
        "models_fitted": len(results),
        "arms_registered": {a: list(f) for a, f in ARM_FEATURES.items()},
        "diagnostics_declared": {d: list(f) for d, f in DIAGNOSTIC_FEATURES.items()},
        "metrics_content_sha256": metrics_content,
        "comparison_content_sha256": comparison_content,
        "environment": {
            "sklearn": sklearn.__version__,
            "xgboost": xgboost.__version__,
            "numpy": np.__version__,
        },
        "outputs": outputs,
    }
    _publish_bytes(
        CONTENT_DIR / "content_benchmark_manifest.json", _json_bytes(manifest)
    )
    print(f"\npublished {len(outputs) + 1} artifacts under {CONTENT_DIR.name}/")
    return 0


def _model_payload(model: Any) -> bytes:
    stream = io.BytesIO()
    joblib.dump(model, stream)
    return stream.getvalue()


def render_report(metrics: dict[str, Any], comparison: dict[str, Any]) -> str:
    models = comparison["models"]
    lines = [
        "# Six-arm payload-content feature benchmark",
        "",
        "## Scope and frozen protocol",
        "",
        "This additive benchmark changes only the registered feature budget. P1--P6, the published "
        "one-feature XGBoost baseline and the frozen four-arm A--D benchmark remain immutable. The "
        "P1 population, labels, five folds, authentic training-row order, ordered test rows, "
        "benign-reference negatives, episode unit, learner, model parameters, training-negative "
        "threshold rule and episode bootstrap are reused exactly. No unknown/ambiguous row, new "
        "split, tuning, rebalancing, label-derived feature, absolute timestamp, PostgreSQL write or "
        "window bootstrap is used.",
        "",
        "Arms A/E/F/G/H/I were registered before any content value was extracted. ARM I is "
        "`A + all six metrics` by pre-registration, never a subset chosen after reading E--H.",
        "",
        "## Primary endpoint — botnet/Ares episode recall at 1% training FPR",
        "",
        "| Arm | Features | Episode recall (95% episode CI) | Episodes | Window recall | ROC-AUC | PR-AUC | Test FPR | Entities | Decision |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---|",
    ]
    for arm in ARM_FEATURES:
        p = models[arm]["primary_1pct"]
        status = comparison["classifications"][arm]["status"]
        lines.append(
            f"| {arm} | {len(MODEL_SPECS[arm])} feat. | {p['episode_recall']:.4f} "
            f"[{p['episode_ci'][0]:.4f}, {p['episode_ci'][1]:.4f}] | "
            f"{p['episodes_detected']}/{p['episodes_total']} | {p['window_recall']:.4f} | "
            f"{p['roc_auc']:.4f} | {p['pr_auc']:.4f} | {p['observed_test_fpr']:.6f} | "
            f"{p['entities_detected']}/{p['entities_total']} | **{status}** |"
        )

    lines += [
        "",
        "ARM A is required to reproduce the ratified reference exactly before any artifact is "
        "accepted: 13/40 episodes, ROC-AUC 0.7615, PR-AUC 0.0670, test FPR 0.009874.",
        "",
        "## The same arms at 0.1% training FPR",
        "",
        "| Arm | Episode recall | Episodes | Window recall | Test FPR |",
        "|---|---:|---:|---:|---:|",
    ]
    for arm in ARM_FEATURES:
        s = models[arm]["primary_0p1pct"]
        lines.append(
            f"| {arm} | {s['episode_recall']:.4f} | {s['episodes_detected']}/40 | "
            f"{s['window_recall']:.4f} | {s['observed_test_fpr']:.6f} |"
        )

    lines += [
        "",
        "## Paired gains over ARM A at 1% training FPR",
        "",
        "| Arm | Recall delta | Paired episode delta CI | New / lost episodes | Gain entities | ROC delta | PR delta | FPR delta |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for arm in ("E", "F", "G", "H", "I"):
        g = models[arm]["gain_vs_arm_a_1pct"]
        b = g["paired_episode_bootstrap"]
        lines.append(
            f"| {arm} | {g['episode_recall_delta']:+.4f} | "
            f"[{b['ci_low']:+.4f}, {b['ci_high']:+.4f}] | "
            f"{b['candidate_only_detections']} / {b['reference_only_detections']} | "
            f"{len(g['entities_with_candidate_only_detections'])} | "
            f"{g['roc_auc_delta']:+.4f} | {g['pr_auc_delta']:+.4f} | {g['fpr_delta']:+.6f} |"
        )

    attribution = comparison["missingness_attribution"]
    lines += [
        "",
        "The paired intervals resample the same 40 held-out episodes, so every comparison is paired "
        "rather than a visual contrast of two marginal intervals.",
        "",
        "## Declared missingness diagnostic",
        "",
        "Extraction established that the presence of `normalized_header_template_repeat_ratio` is "
        "**exactly equivalent** to `service == http`: 12,279 frozen windows carry it and all of "
        "them are HTTP. All 177 Ares windows are HTTP, against 17.1% of benign windows. Because P1 "
        "forbids `entity_service` as a feature and XGBoost branches natively on missing values, an "
        "ARM H or ARM I effect could be carried by that missingness instead of by header-template "
        "repetition.",
        "",
        "Two diagnostics therefore keep only the presence indicators and discard the values. They "
        "are not arms and take part in no ranking.",
        "",
        "| Arm | Episodes A | Episodes arm | Episodes indicator only | Arm gain | Indicator gain | Share explained |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for arm in ("H", "I"):
        a = attribution[arm]
        share = a["share_explained_by_missingness"]
        share_text = "n/a" if share is None else f"{share:.2f}"
        lines.append(
            f"| {arm} | {a['episodes_detected_arm_a']}/40 | {a['episodes_detected_arm']}/40 | "
            f"{a['episodes_detected_indicator_only']}/40 | {a['arm_gain_over_a']:+d} | "
            f"{a['indicator_gain_over_a']:+d} | {share_text} |"
        )

    lines += [
        "",
        "A share at or above 1.0 means the presence indicator alone reproduces the whole gain, so "
        "the gain cannot be credited to the metric value. A RETAIN verdict requires this not to be "
        "the case.",
        "",
        "## Decisions",
        "",
    ]
    for arm in ARM_FEATURES:
        c = comparison["classifications"][arm]
        lines.append(f"- **ARM {arm} — {c['status']}**: {c['reason']}.")
    best = comparison["minimal_best_compromise"]
    lines += [
        "",
        "## Minimal best compromise",
        "",
        f"**ARM {best['arm']}** — {', '.join(best['features'])}. {best['rationale']}",
        "",
        "## Content metric availability",
        "",
        "| Metric | Benign | Ares | Other attacks |",
        "|---|---:|---:|---:|",
    ]
    availability = metrics["content_availability_by_population"]
    totals = {"benign": 70578, "botnet_ares": 177, "other_attack": 199}
    for name in CONTENT_FEATURE_NAMES:
        row = f"| `{name}` |"
        for group in ("benign", "botnet_ares", "other_attack"):
            count = availability[group][name]
            row += f" {count}/{totals[group]} ({100 * count / totals[group]:.1f}%) |"
        lines.append(row)

    lines += [
        "",
        "Undefined metrics remain native NaN inside every arm. No imputation, fitted fill value or "
        "missingness indicator is added to an arm; indicators exist only in the two diagnostics.",
        "",
        "## R11 and scope of the evidence",
        "",
        "R11 remains open: the botnet endpoint contains **5 entities, 1 destination "
        "(`205.174.165.73`) and 40 episodes**. This benchmark demonstrates transfer from the four "
        "held-in attack types to the held-out Ares windows under the frozen population and the "
        "registered budgets. It does not demonstrate generalisation to another victim, attacker, "
        "capture or botnet family, and it does not measure streaming ingestion latency.",
        "",
        "## Integrity",
        "",
        f"Frozen digests verified: {len(metrics['frozen_file_checks'])}. P1 protocol checks: "
        f"{len(metrics['protocol_verification'])}. Content join checks: "
        f"{len(metrics['content_join_verification']['checks'])}. Feature assembly checks: "
        f"{len(metrics['feature_assembly_verification']['checks'])}. Cross-model identity checks: "
        f"{len(metrics['cross_model_identity'])}. Models fitted: {metrics['models_fitted']}. "
        "PostgreSQL writes: 0.",
        "",
    ]
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
