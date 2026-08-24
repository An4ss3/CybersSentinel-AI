"""Controlled four-arm XGBoost feature benchmark on the frozen P1 protocol.

The learner and all fitting conventions are imported from the published XGBoost
baseline. Only the feature budget varies. Thresholds are calibrated from training
negatives, and every confidence interval resamples episodes rather than windows.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Final

import numpy as np
from sklearn.metrics import average_precision_score, roc_auc_score
from xgboost import XGBClassifier

from modules.detection.src.experiments.p1_dataset import Row
from modules.detection.src.experiments.p1_evaluation import (
    BOOTSTRAP_RESAMPLES,
    BOOTSTRAP_SEED,
    FPR_TARGETS,
    episode_bootstrap_recall,
    episode_recall,
    threshold_at_train_fpr,
)
from modules.detection.src.experiments.xgb_baseline import XGB_PARAMS


ARM_FEATURES: Final[dict[str, tuple[str, ...]]] = {
    "A": ("distinct_payload_ratio",),
    "B": ("distinct_payload_ratio", "interarrival_mean"),
    "C": ("distinct_payload_ratio", "bytes_per_packet_destination"),
    "D": (
        "distinct_payload_ratio",
        "interarrival_mean",
        "bytes_per_packet_destination",
    ),
}

BOOTSTRAP_DECLARATION: Final[dict[str, Any]] = {
    "unit": "episode",
    "resamples": BOOTSTRAP_RESAMPLES,
    "seed": BOOTSTRAP_SEED,
    "window_level_intervals": "forbidden",
}


def build_model() -> XGBClassifier:
    """Return the exact fixed learner used by the published one-feature baseline."""
    return XGBClassifier(**XGB_PARAMS)


def matrix(rows: list[Row], expected_width: int) -> tuple[np.ndarray, np.ndarray]:
    """Build a matrix while permitting only native XGBoost missing values.

    P6 defines some feature values as unavailable. They remain NaN and are handled
    by XGBoost's native missing-value branch; no imputation or indicator is added.
    Infinite values are never admissible.
    """
    features = np.asarray([row.features for row in rows], dtype=float)
    if features.ndim != 2 or features.shape[1] != expected_width:
        width = features.shape[1] if features.ndim == 2 else "not-a-matrix"
        raise ValueError(f"expected exactly {expected_width} features, got {width}")
    if np.isinf(features).any():
        raise ValueError("infinite feature value is forbidden")
    labels = np.asarray([row.label for row in rows], dtype=int)
    return features, labels


@dataclass(slots=True)
class FoldResult:
    arm: str
    features: tuple[str, ...]
    fold: int
    held_out_attack_type: str
    train_positives: int
    train_negatives: int
    test_positives: int
    test_negatives: int
    test_episodes: int
    roc_auc: float
    pr_auc: float
    feature_importance_gain: dict[str, float] = field(default_factory=dict)
    operating_points: list[dict[str, Any]] = field(default_factory=list)
    predictions: list[dict[str, Any]] = field(default_factory=list)
    model: Any = None


def _gain_importance(model: XGBClassifier, features: tuple[str, ...]) -> dict[str, float]:
    raw = model.get_booster().get_score(importance_type="gain")
    values = {name: float(raw.get(f"f{index}", 0.0)) for index, name in enumerate(features)}
    total = sum(values.values())
    if total > 0:
        return {name: value / total for name, value in values.items()}
    return values


def evaluate_fold(
    arm: str,
    features: tuple[str, ...],
    fold_index: int,
    held_out_attack_type: str,
    train_rows: list[Row],
    test_rows: list[Row],
) -> FoldResult:
    """Fit and evaluate one arm/fold using the unchanged baseline conventions."""
    if ARM_FEATURES.get(arm) != features:
        raise ValueError(f"arm {arm} feature budget differs from the registered budget")
    x_train, y_train = matrix(train_rows, len(features))
    x_test, y_test = matrix(test_rows, len(features))

    model = build_model()
    model.fit(x_train, y_train)
    train_scores = model.predict_proba(x_train)[:, 1]
    test_scores = model.predict_proba(x_test)[:, 1]
    train_negative_scores = train_scores[y_train == 0]

    positives = int((y_test == 1).sum())
    negatives = int((y_test == 0).sum())
    roc = float(roc_auc_score(y_test, test_scores)) if positives and negatives else float("nan")
    pr = float(average_precision_score(y_test, test_scores)) if positives and negatives else float("nan")

    result = FoldResult(
        arm=arm,
        features=features,
        fold=fold_index,
        held_out_attack_type=held_out_attack_type,
        train_positives=int((y_train == 1).sum()),
        train_negatives=int((y_train == 0).sum()),
        test_positives=positives,
        test_negatives=negatives,
        test_episodes=len({r.episode_id for r in test_rows if r.label == 1}),
        roc_auc=roc,
        pr_auc=pr,
        feature_importance_gain=_gain_importance(model, features),
        model=model,
    )

    for target in FPR_TARGETS:
        threshold, achieved = threshold_at_train_fpr(train_negative_scores, target)
        flagged = test_scores >= threshold
        tp = int((flagged & (y_test == 1)).sum())
        fp = int((flagged & (y_test == 0)).sum())
        detected, recall = episode_recall(test_rows, test_scores, threshold)
        result.operating_points.append(
            {
                "target_train_fpr": target,
                "threshold": float(threshold),
                "achieved_train_fpr": float(achieved),
                "observed_test_fpr": fp / negatives if negatives else float("nan"),
                "window_recall": tp / positives if positives else float("nan"),
                "window_precision": tp / (tp + fp) if (tp + fp) else float("nan"),
                "true_positives": tp,
                "false_positives": fp,
                "episode_recall": recall,
                "episodes_detected": sorted(k for k, value in detected.items() if value),
                "episodes_missed": sorted(k for k, value in detected.items() if not value),
                "episode_detection": dict(sorted(detected.items())),
                "episode_bootstrap": episode_bootstrap_recall(detected),
            }
        )

    result.predictions = [
        {
            "arm": arm,
            "fold": fold_index,
            "row_id": row.row_id,
            "label": row.label,
            "disposition": row.disposition,
            "attack_type": row.attack_type or "",
            "episode_id": row.episode_id or "",
            "score": f"{float(score):.10f}",
        }
        for row, score in zip(test_rows, test_scores)
    ]
    return result


def per_entity_recall(
    test_rows: list[Row], scores: np.ndarray, threshold: float
) -> dict[str, dict[str, Any]]:
    """Return window and episode recall for each positive entity."""
    buckets: dict[str, dict[str, Any]] = {}
    for row, score in zip(test_rows, scores):
        if row.label != 1:
            continue
        bucket = buckets.setdefault(
            row.entity_key,
            {"windows": 0, "windows_flagged": 0, "episodes": {}},
        )
        bucket["windows"] += 1
        flagged = bool(score >= threshold)
        bucket["windows_flagged"] += int(flagged)
        if row.episode_id:
            bucket["episodes"].setdefault(row.episode_id, False)
            bucket["episodes"][row.episode_id] |= flagged

    out: dict[str, dict[str, Any]] = {}
    for entity, bucket in sorted(buckets.items()):
        episodes = bucket["episodes"]
        detected = sum(episodes.values())
        out[entity] = {
            "windows": bucket["windows"],
            "windows_flagged": bucket["windows_flagged"],
            "window_recall": bucket["windows_flagged"] / bucket["windows"],
            "episodes": len(episodes),
            "episodes_detected": detected,
            "episode_recall": detected / len(episodes) if episodes else float("nan"),
        }
    return out


def paired_episode_bootstrap_delta(
    reference: dict[str, bool], candidate: dict[str, bool]
) -> dict[str, Any]:
    """Bootstrap candidate-minus-reference recall over the shared episodes.

    This paired interval is more informative than visually comparing two marginal
    confidence intervals because every arm is evaluated on exactly the same 40
    botnet episodes.
    """
    if set(reference) != set(candidate):
        raise ValueError("paired bootstrap requires identical episode ids")
    episode_ids = sorted(reference)
    if not episode_ids:
        return {
            "point": float("nan"),
            "ci_low": float("nan"),
            "ci_high": float("nan"),
            "episodes": 0,
        }
    differences = np.asarray(
        [float(candidate[e]) - float(reference[e]) for e in episode_ids], dtype=float
    )
    rng = np.random.default_rng(BOOTSTRAP_SEED)
    draws = np.empty(BOOTSTRAP_RESAMPLES, dtype=float)
    for index in range(BOOTSTRAP_RESAMPLES):
        draws[index] = rng.choice(differences, size=len(differences), replace=True).mean()
    return {
        "point": float(differences.mean()),
        "ci_low": float(np.quantile(draws, 0.025)),
        "ci_high": float(np.quantile(draws, 0.975)),
        "episodes": len(episode_ids),
        "candidate_only_detections": int((differences == 1).sum()),
        "reference_only_detections": int((differences == -1).sum()),
    }
