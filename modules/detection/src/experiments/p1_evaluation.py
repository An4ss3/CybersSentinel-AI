"""P1/A training and evaluation. No sampling, no rebalancing, no augmentation.

Conservative decisions taken here and recorded in the manifest
--------------------------------------------------------------
D6  Model = ``RandomForestClassifier(n_estimators=200, random_state=0,
    n_jobs=1)``. Chosen because it is scale-invariant, so the five volume
    features need no transform, and because a fixed seed with a single worker
    makes it bit-reproducible. **No hyper-parameter search.**
D7  ``class_weight=None``. Class weighting is a form of rebalancing and is
    forbidden by the ratified constraints, so the 1:187.7 imbalance is left
    exactly as it is in the data.
D8  Decision thresholds are derived from the **training** negatives only, at
    target false-positive rates of 1% and 0.1%. Test positives never influence a
    threshold.
D9  Uncertainty is bootstrapped over **episodes**, never over windows, because
    consecutive 60-second windows of one attack are slices of one continuous
    event. 2,000 resamples, seed 0.
D10 Metrics are reported per fold and therefore per attack type. No aggregate
    number is produced that could hide the botnet result.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Final

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    roc_auc_score,
)

from modules.detection.src.experiments.p1_dataset import FEATURE_NAMES, Row


MODEL_SEED: Final[int] = 0
N_ESTIMATORS: Final[int] = 200
BOOTSTRAP_RESAMPLES: Final[int] = 2_000
BOOTSTRAP_SEED: Final[int] = 0
FPR_TARGETS: Final[tuple[float, ...]] = (0.01, 0.001)


def build_model() -> RandomForestClassifier:
    """Return the frozen P1 model (decisions D6 and D7)."""
    return RandomForestClassifier(
        n_estimators=N_ESTIMATORS,
        random_state=MODEL_SEED,
        n_jobs=1,
        class_weight=None,
    )


def matrix(
    rows: list[Row], expected_features: int | None = None
) -> tuple[np.ndarray, np.ndarray]:
    """Return ``(X, y)`` built only from the admitted features.

    ``expected_features`` defaults to the five ratified volume features, so P1 to
    P4 behaviour is unchanged. P5/E passes eight explicitly when evaluating its
    arm B budget. The guard is never disabled: a count must always be asserted,
    so a silent change in feature width remains impossible.
    """
    features = np.asarray([r.features for r in rows], dtype=float)
    width = len(FEATURE_NAMES) if expected_features is None else expected_features
    if features.shape[1] != width:
        raise ValueError(f"expected {width} features, got {features.shape[1]}")
    labels = np.asarray([r.label for r in rows], dtype=int)
    return features, labels


def threshold_at_train_fpr(
    train_negative_scores: np.ndarray, target_fpr: float
) -> tuple[float, float]:
    """Return ``(threshold, achieved_train_fpr)`` for a target training FPR.

    Only training negatives are used, so no test observation and in particular no
    test positive influences the operating point (decision D8).

    A plain quantile is **wrong** for this score distribution. With a 1:187.7
    imbalance and no class weighting, the forest assigns a score of exactly 0.0
    to the overwhelming majority of training negatives, so ``quantile(0.99)``
    returns 0.0 and ``score >= 0.0`` flags every row: false-positive rate 1.0 and
    recall 1.0, a degenerate operating point rather than a result. This was
    observed on the first P1 run and corrected here.

    The threshold is therefore chosen exactly: the smallest candidate ``t`` drawn
    from the observed scores such that ``mean(train_negatives >= t) <= target``.
    The achieved rate is returned alongside, so any gap between target and
    achievement is visible in the report instead of being implied.
    """
    if train_negative_scores.size == 0:
        raise ValueError("no training negatives available for calibration")
    candidates = np.unique(train_negative_scores)
    # A threshold above the maximum observed score flags nothing.
    candidates = np.append(candidates, np.nextafter(candidates[-1], np.inf))
    for threshold in candidates:
        achieved = float((train_negative_scores >= threshold).mean())
        if achieved <= target_fpr:
            return float(threshold), achieved
    # Unreachable: the appended candidate always achieves 0.0.
    return float(candidates[-1]), 0.0


def episode_recall(
    rows: list[Row], scores: np.ndarray, threshold: float
) -> tuple[dict[str, bool], float]:
    """Return per-episode detection and the episode-level recall.

    An episode counts as detected when at least one of its windows scores at or
    above the threshold. This is the operationally meaningful question and its
    denominator is the number of independent attack events, not the number of
    highly autocorrelated 60-second slices.
    """
    detected: dict[str, bool] = {}
    for row, score in zip(rows, scores):
        if row.label != 1 or row.episode_id is None:
            continue
        detected.setdefault(row.episode_id, False)
        if score >= threshold:
            detected[row.episode_id] = True
    if not detected:
        return {}, float("nan")
    return detected, sum(detected.values()) / len(detected)


def episode_bootstrap_recall(
    detected: dict[str, bool],
    resamples: int = BOOTSTRAP_RESAMPLES,
    seed: int = BOOTSTRAP_SEED,
) -> dict[str, float]:
    """Bootstrap the episode-level recall by resampling episodes (decision D9)."""
    if not detected:
        return {"point": float("nan"), "ci_low": float("nan"),
                "ci_high": float("nan"), "episodes": 0}
    flags = np.asarray([1.0 if v else 0.0 for v in detected.values()])
    rng = np.random.default_rng(seed)
    draws = np.empty(resamples, dtype=float)
    for i in range(resamples):
        draws[i] = rng.choice(flags, size=flags.size, replace=True).mean()
    return {
        "point": float(flags.mean()),
        "ci_low": float(np.quantile(draws, 0.025)),
        "ci_high": float(np.quantile(draws, 0.975)),
        "episodes": int(flags.size),
    }


@dataclass(slots=True)
class FoldResult:
    """Everything observed for one leave-one-attack-type-out fold."""

    fold: int
    held_out_attack_type: str
    train_positives: int
    train_negatives: int
    test_positives: int
    test_negatives: int
    test_episodes: int
    pr_auc: float
    roc_auc: float
    default_threshold: dict[str, Any] = field(default_factory=dict)
    operating_points: list[dict[str, Any]] = field(default_factory=list)
    episode_detection: dict[str, bool] = field(default_factory=dict)
    predictions: list[dict[str, Any]] = field(default_factory=list)


def evaluate_fold(
    fold_index: int,
    held_out_attack_type: str,
    train_rows: list[Row],
    test_rows: list[Row],
    expected_features: int | None = None,
) -> FoldResult:
    """Train on one fold and evaluate it, reporting rarity-appropriate metrics.

    ``expected_features`` defaults to the five ratified volume features, leaving
    P1 to P4 byte-identical. P5/E passes its arm width explicitly.
    """
    x_train, y_train = matrix(train_rows, expected_features)
    x_test, y_test = matrix(test_rows, expected_features)

    model = build_model()
    model.fit(x_train, y_train)
    train_scores = model.predict_proba(x_train)[:, 1]
    test_scores = model.predict_proba(x_test)[:, 1]

    train_negative_scores = train_scores[y_train == 0]
    positives = int((y_test == 1).sum())
    negatives = int((y_test == 0).sum())

    pr_auc = (
        float(average_precision_score(y_test, test_scores))
        if positives and negatives
        else float("nan")
    )
    roc = (
        float(roc_auc_score(y_test, test_scores))
        if positives and negatives
        else float("nan")
    )

    hard = (test_scores >= 0.5).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_test, hard, labels=[0, 1]).ravel()
    default = {
        "threshold": 0.5,
        "true_negatives": int(tn),
        "false_positives": int(fp),
        "false_negatives": int(fn),
        "true_positives": int(tp),
        "window_recall": float(tp / positives) if positives else float("nan"),
        "window_precision": float(tp / (tp + fp)) if (tp + fp) else float("nan"),
        "window_fpr": float(fp / negatives) if negatives else float("nan"),
    }

    operating_points: list[dict[str, Any]] = []
    episode_detection: dict[str, bool] = {}
    for target in FPR_TARGETS:
        threshold, achieved_train_fpr = threshold_at_train_fpr(
            train_negative_scores, target
        )
        flagged = test_scores >= threshold
        tp_n = int((flagged & (y_test == 1)).sum())
        fp_n = int((flagged & (y_test == 0)).sum())
        detected, recall = episode_recall(test_rows, test_scores, threshold)
        boot = episode_bootstrap_recall(detected)
        operating_points.append(
            {
                "target_train_fpr": target,
                "achieved_train_fpr": achieved_train_fpr,
                "threshold": threshold,
                "window_recall": float(tp_n / positives) if positives else float("nan"),
                "window_precision": (
                    float(tp_n / (tp_n + fp_n)) if (tp_n + fp_n) else float("nan")
                ),
                "observed_test_fpr": float(fp_n / negatives) if negatives else float("nan"),
                "true_positives": tp_n,
                "false_positives": fp_n,
                "episode_recall": recall,
                "episode_bootstrap": boot,
                "episodes_detected": sorted(k for k, v in detected.items() if v),
                "episodes_missed": sorted(k for k, v in detected.items() if not v),
            }
        )
        if target == FPR_TARGETS[0]:
            episode_detection = detected

    predictions = [
        {
            "row_id": row.row_id,
            "label": row.label,
            "disposition": row.disposition,
            "attack_type": row.attack_type,
            "episode_id": row.episode_id,
            "score": float(score),
        }
        for row, score in zip(test_rows, test_scores)
    ]

    return FoldResult(
        fold=fold_index,
        held_out_attack_type=held_out_attack_type,
        train_positives=int((y_train == 1).sum()),
        train_negatives=int((y_train == 0).sum()),
        test_positives=positives,
        test_negatives=negatives,
        test_episodes=len({r.episode_id for r in test_rows if r.label == 1}),
        pr_auc=pr_auc,
        roc_auc=roc,
        default_threshold=default,
        operating_points=operating_points,
        episode_detection=episode_detection,
        predictions=predictions,
    )
