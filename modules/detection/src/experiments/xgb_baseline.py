"""XGBoost baseline on the single feature P6 retained. Read-only, no tuning.

One question: on the frozen protocol, can XGBoost exploit the signal carried by
``distinct_payload_ratio`` to actually improve episode-level detection of
``botnet/ares``?

Every parameter is fixed in advance and recorded. There is **no hyper-parameter
search**, no early stopping, no ensembling, no resampling and no class rebalancing.
The threshold rule and the bootstrap are reused unchanged from P1.

Conservative decisions taken here, recorded in the manifest
-----------------------------------------------------------
D17 ``scale_pos_weight = 1``, i.e. **no class rebalancing**. Ratified decision D7
    forbids class weighting because it is a form of rebalancing, and the 1:187.7
    imbalance is left exactly as the data presents it. XGBoost's
    ``scale_pos_weight`` is the direct analogue of ``class_weight``, so it is
    pinned to 1 rather than to the imbalance ratio.
D18 ``subsample = 1.0`` and ``colsample_bytree = 1.0``. Both stochastic
    regularisers are disabled, which removes every source of randomness from
    fitting and makes the run reproducible without relying on a seed. With a
    single feature ``colsample_bytree`` could not be below 1.0 anyway.
D19 ``n_estimators = 200`` to match P1's ensemble size, so a difference between the
    two is attributable to the learner and the feature rather than to capacity.
D20 ``max_depth = 3``. With one feature a tree can only threshold that feature, so
    depth controls how many thresholds are available and nothing else. Three is
    below the library default of six and is not tuned.
D21 ``learning_rate = 0.1``, below the library default of 0.3. No early stopping,
    because early stopping requires a validation split and that would be a
    protocol change.
D22 ``eval_metric = "logloss"``, consistent with the objective. It is recorded only;
    nothing selects on it because there is no validation set and no search.
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


#: The only feature admitted, retained by P6 as the smallest justified set.
FEATURE_NAME: Final[str] = "distinct_payload_ratio"

#: Fixed in advance. Not searched, not tuned, not selected on any test set.
XGB_PARAMS: Final[dict[str, Any]] = {
    "objective": "binary:logistic",
    "eval_metric": "logloss",
    "n_estimators": 200,
    "max_depth": 3,
    "learning_rate": 0.1,
    "subsample": 1.0,
    "colsample_bytree": 1.0,
    "scale_pos_weight": 1,
    "random_state": 0,
    "n_jobs": 1,
    "tree_method": "exact",
    "verbosity": 0,
}


def build_model() -> XGBClassifier:
    """The baseline learner. Identical on every fold, no fold-specific choice."""
    return XGBClassifier(**XGB_PARAMS)


def matrix(rows: list[Row]) -> tuple[np.ndarray, np.ndarray]:
    """Return ``(X, y)`` from the single admitted feature.

    The width is asserted at exactly one, so an accidental extra feature raises
    instead of silently widening the budget P6 justified.
    """
    features = np.asarray([r.features for r in rows], dtype=float)
    if features.shape[1] != 1:
        raise ValueError(f"expected exactly 1 feature, got {features.shape[1]}")
    labels = np.asarray([r.label for r in rows], dtype=int)
    return features, labels


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
    roc_auc: float
    pr_auc: float
    operating_points: list[dict[str, Any]] = field(default_factory=list)
    predictions: list[dict[str, Any]] = field(default_factory=list)
    model: Any = None


def evaluate_fold(
    fold_index: int,
    held_out_attack_type: str,
    train_rows: list[Row],
    test_rows: list[Row],
) -> FoldResult:
    """Fit on the fold's training rows and evaluate, reusing P1's rules exactly.

    The threshold comes from **training negatives only** at the ratified targets,
    and uncertainty is bootstrapped over **episodes** only. No test observation,
    and in particular no test positive, influences an operating point.
    """
    x_train, y_train = matrix(train_rows)
    x_test, y_test = matrix(test_rows)

    model = build_model()
    model.fit(x_train, y_train)
    train_scores = model.predict_proba(x_train)[:, 1]
    test_scores = model.predict_proba(x_test)[:, 1]

    train_negative_scores = train_scores[y_train == 0]
    positives = int((y_test == 1).sum())
    negatives = int((y_test == 0).sum())

    roc = (
        float(roc_auc_score(y_test, test_scores))
        if positives and negatives
        else float("nan")
    )
    pr_auc = (
        float(average_precision_score(y_test, test_scores))
        if positives and negatives
        else float("nan")
    )

    result = FoldResult(
        fold=fold_index,
        held_out_attack_type=held_out_attack_type,
        train_positives=int((y_train == 1).sum()),
        train_negatives=int((y_train == 0).sum()),
        test_positives=positives,
        test_negatives=negatives,
        test_episodes=len({r.episode_id for r in test_rows if r.episode_id}),
        roc_auc=roc,
        pr_auc=pr_auc,
        model=model,
    )

    for target in FPR_TARGETS:
        threshold, achieved = threshold_at_train_fpr(train_negative_scores, target)
        flagged = test_scores >= threshold
        true_positives = int((flagged & (y_test == 1)).sum())
        false_positives = int((flagged & (y_test == 0)).sum())
        detected, recall = episode_recall(test_rows, test_scores, threshold)
        boot = episode_bootstrap_recall(detected)
        result.operating_points.append(
            {
                "target_train_fpr": target,
                "threshold": float(threshold),
                "achieved_train_fpr": achieved,
                "observed_test_fpr": (
                    false_positives / negatives if negatives else float("nan")
                ),
                "window_recall": (
                    true_positives / positives if positives else float("nan")
                ),
                "window_precision": (
                    true_positives / (true_positives + false_positives)
                    if (true_positives + false_positives)
                    else float("nan")
                ),
                "true_positives": true_positives,
                "false_positives": false_positives,
                "episode_recall": recall,
                "episodes_detected": sorted(k for k, v in detected.items() if v),
                "episodes_missed": sorted(k for k, v in detected.items() if not v),
                "episode_bootstrap": boot,
            }
        )

    result.predictions = [
        {
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
    """Window and episode recall broken out per attack entity.

    Reported because R11 makes the per-entity picture the only honest one: a gain
    concentrated on one entity is not the same finding as a gain spread over five.
    """
    per_entity: dict[str, dict[str, Any]] = {}
    for row, score in zip(test_rows, scores):
        if row.label != 1:
            continue
        bucket = per_entity.setdefault(
            row.entity_key,
            {"windows": 0, "windows_flagged": 0, "episodes": {}},
        )
        bucket["windows"] += 1
        if score >= threshold:
            bucket["windows_flagged"] += 1
        if row.episode_id is not None:
            bucket["episodes"].setdefault(row.episode_id, False)
            if score >= threshold:
                bucket["episodes"][row.episode_id] = True
    out: dict[str, dict[str, Any]] = {}
    for entity, bucket in sorted(per_entity.items()):
        episodes = bucket["episodes"]
        out[entity] = {
            "windows": bucket["windows"],
            "windows_flagged": bucket["windows_flagged"],
            "window_recall": bucket["windows_flagged"] / bucket["windows"],
            "episodes": len(episodes),
            "episodes_detected": sum(episodes.values()),
            "episode_recall": (
                sum(episodes.values()) / len(episodes) if episodes else float("nan")
            ),
        }
    return out


BOOTSTRAP_DECLARATION: Final[dict[str, Any]] = {
    "unit": "episode",
    "resamples": BOOTSTRAP_RESAMPLES,
    "seed": BOOTSTRAP_SEED,
    "window_level_intervals": "forbidden",
}
