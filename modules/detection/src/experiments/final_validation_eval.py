"""Final scientific validation — Step 2: canonical evaluation engine.

Model
-----
The only canonical 5-feature baseline is the frozen P1 RandomForest. Its
parameters, seed, threshold calibration and episode rules are reused from
``p1_evaluation`` without modification. No tuning, no transform, no rebalancing.

Training order
--------------
Every new fit uses the ratified deterministic order ``(label, row_id)``, which is
the physical order of the frozen production dataset.

Why an order convention is required, and what it costs
------------------------------------------------------
The historical P1 run fitted on ``[index[i] for i in fold.train_row_ids]``, whose
negative segment came from ``load_negatives()``. That SQL statement carries no
``ORDER BY``, so its row order was never contractually defined, and the published
artifacts do not persist it: ``p1_folds.json`` stores ``sorted(train_row_ids)``
and the prediction files are sorted by ``row_id``. ``RandomForestClassifier``
with ``random_state=0`` still depends on input order, because bootstrap samples
index row *positions*. The historical fit order is therefore irrecoverable from
the artifacts alone, and exact re-fit reproduction is impossible. This is not a
model defect: it is an unspecified input order in the historical protocol.

Consequences, applied here:

* protocol ``A`` is a **deterministic reimplementation**, never a reproduction;
* protocol ``D`` is evaluated twice — ``D1`` re-fitted under the convention, and
  ``D2`` re-scored with the historically frozen model as an exact anchor.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from hashlib import sha256
import json
from typing import Any, Final, Sequence

import numpy as np
from sklearn.metrics import average_precision_score, roc_auc_score

from modules.detection.src.experiments.p1_dataset import FEATURE_NAMES, Row
from modules.detection.src.experiments.p1_evaluation import (
    BOOTSTRAP_RESAMPLES,
    BOOTSTRAP_SEED,
    FPR_TARGETS,
    MODEL_SEED,
    N_ESTIMATORS,
    build_model,
    episode_bootstrap_recall,
    episode_recall,
    matrix,
    threshold_at_train_fpr,
)

#: The ratified deterministic training order for every new fit.
TRAINING_ORDER: Final[str] = "label,row_id"

#: The primary operating point. P1 also publishes 0.001; both are recorded.
PRIMARY_FPR_TARGET: Final[float] = 0.01

#: Metadata columns that must never reach the model.
FORBIDDEN_MODEL_INPUTS: Final[tuple[str, ...]] = (
    "row_id",
    "source",
    "label",
    "disposition",
    "attack_type",
    "entity_key",
    "episode_id",
    "partition",
    "window_start_epoch",
)

ARES_FAMILY: Final[str] = "botnet/ares"

#: Published P1 fold-0 values, used only as the D2 anchor expectation.
HISTORICAL_ARES_ANCHOR: Final[dict[str, Any]] = {
    "roc_auc": 0.5037268283238951,
    "pr_auc": 0.01352512611367757,
    "threshold": 0.005,
    "detected_episodes": 3,
    "total_episodes": 40,
    "fpr": 0.00958327283287353,
    "tp": 3,
}


class EvaluationError(RuntimeError):
    """A guard, disjointness requirement or anchor expectation failed."""


@dataclass(frozen=True, slots=True)
class FoldData:
    protocol: str
    fold: int
    held_out: str
    train: tuple[Row, ...]
    test: tuple[Row, ...]


def canonical_order(rows: Sequence[Row]) -> list[Row]:
    """Sort rows by the ratified deterministic convention ``(label, row_id)``."""
    return sorted(rows, key=lambda row: (row.label, row.row_id))


def model_parameters() -> dict[str, Any]:
    """The frozen P1 model description, recorded verbatim in every artifact."""
    return {
        "estimator": "RandomForestClassifier",
        "n_estimators": N_ESTIMATORS,
        "random_state": MODEL_SEED,
        "n_jobs": 1,
        "class_weight": None,
        "hyperparameter_search": "none",
        "feature_transform": "none",
        "class_rebalancing": "none",
        "sampling": "none",
    }


def guard_features(rows: Sequence[Row], where: str) -> None:
    """Assert width and order of the feature vector before any fit."""
    if len(FEATURE_NAMES) != 5:
        raise EvaluationError(f"{where}: feature budget is not five")
    if FEATURE_NAMES != (
        "event_count",
        "source_packets_total",
        "destination_packets_total",
        "source_bytes_total",
        "destination_bytes_total",
    ):
        raise EvaluationError(f"{where}: canonical feature order changed")
    for row in rows:
        if len(row.features) != 5:
            raise EvaluationError(f"{where}: row {row.row_id} has {len(row.features)} features")
        if not all(isinstance(value, float) for value in row.features):
            raise EvaluationError(f"{where}: non-float feature in row {row.row_id}")


def build_fold(
    protocol: str,
    fold: int,
    held_out: str,
    ordered_rows: Sequence[Row],
    assignment: dict[str, int],
) -> FoldData:
    """Split by membership only, preserving the canonical order on both sides."""
    train = tuple(row for row in ordered_rows if assignment[row.row_id] != fold)
    test = tuple(row for row in ordered_rows if assignment[row.row_id] == fold)
    return FoldData(protocol, fold, held_out, train, test)


def fold_guards(
    data: FoldData,
    *,
    require_entity_disjoint: bool,
    require_episode_disjoint: bool,
    forbid_family_in_train: str | None = None,
) -> dict[str, Any]:
    """Run every blocking guard for one fold and return the audit record."""
    guard_features(data.train, f"{data.protocol}/fold{data.fold}/train")
    guard_features(data.test, f"{data.protocol}/fold{data.fold}/test")

    train_ids = {row.row_id for row in data.train}
    test_ids = {row.row_id for row in data.test}
    if train_ids & test_ids:
        raise EvaluationError(
            f"{data.protocol}/fold{data.fold}: {len(train_ids & test_ids)} shared row ids"
        )
    if not data.test:
        raise EvaluationError(f"{data.protocol}/fold{data.fold}: empty test set")

    train_entities = {row.entity_key for row in data.train}
    test_entities = {row.entity_key for row in data.test}
    train_episodes = {row.episode_id for row in data.train if row.label == 1}
    test_episodes = {row.episode_id for row in data.test if row.label == 1}
    entity_intersection = sorted(train_entities & test_entities)
    episode_intersection = sorted(
        str(e) for e in (train_episodes & test_episodes) if e is not None
    )

    if require_entity_disjoint and entity_intersection:
        raise EvaluationError(
            f"{data.protocol}/fold{data.fold}: entity leakage {entity_intersection}"
        )
    if require_episode_disjoint and episode_intersection:
        raise EvaluationError(
            f"{data.protocol}/fold{data.fold}: episode leakage {episode_intersection}"
        )
    if forbid_family_in_train is not None:
        offending = [r for r in data.train if r.attack_type == forbid_family_in_train]
        if offending:
            raise EvaluationError(
                f"{data.protocol}/fold{data.fold}: {len(offending)} "
                f"{forbid_family_in_train} rows present in training"
            )
        offending_entities = {
            r.entity_key for r in data.test if r.attack_type == forbid_family_in_train
        } & {r.entity_key for r in data.train}
        if offending_entities:
            raise EvaluationError(
                f"{data.protocol}/fold{data.fold}: held-out family entities in "
                f"training: {sorted(offending_entities)}"
            )

    return {
        "entity_intersection_count": len(entity_intersection),
        "entity_intersection": entity_intersection,
        "episode_intersection_count": len(episode_intersection),
        "episode_intersection": episode_intersection,
        "entity_count_train": len(train_entities),
        "entity_count_test": len(test_entities),
        "row_ids_disjoint": True,
        "features_guarded": True,
    }


def _operating_point(
    target: float,
    train_negative_scores: np.ndarray,
    test_rows: Sequence[Row],
    test_scores: np.ndarray,
    y_test: np.ndarray,
) -> dict[str, Any]:
    threshold, achieved = threshold_at_train_fpr(train_negative_scores, target)
    flagged = test_scores >= threshold
    tp = int((flagged & (y_test == 1)).sum())
    fp = int((flagged & (y_test == 0)).sum())
    tn = int((~flagged & (y_test == 0)).sum())
    fn = int((~flagged & (y_test == 1)).sum())
    positives = int((y_test == 1).sum())
    negatives = int((y_test == 0).sum())
    detected, recall = episode_recall(list(test_rows), test_scores, threshold)
    precision = tp / (tp + fp) if (tp + fp) else float("nan")
    window_recall = tp / positives if positives else float("nan")
    f1 = (
        2 * precision * window_recall / (precision + window_recall)
        if (tp + fp) and positives and (precision + window_recall) > 0
        else 0.0
    )
    return {
        "target_train_fpr": target,
        "threshold": float(threshold),
        "threshold_calibration_method": (
            "smallest observed train-negative score achieving the target FPR; "
            "training negatives only, no test observation used"
        ),
        "achieved_train_fpr": float(achieved),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "recall": float(window_recall),
        "precision": float(precision),
        "f1": float(f1),
        "fpr": float(fp / negatives) if negatives else float("nan"),
        "episode_recall": float(recall),
        "detected_episodes": int(sum(detected.values())),
        "total_episodes": len(detected),
        "episode_bootstrap": episode_bootstrap_recall(detected),
        "episode_detection": dict(sorted(detected.items())),
    }


def evaluate_fold(
    data: FoldData,
    guards: dict[str, Any],
    *,
    frozen_model: Any | None = None,
) -> dict[str, Any]:
    """Fit (or re-score with a frozen model) and measure one fold."""
    x_train, y_train = matrix(list(data.train))
    x_test, y_test = matrix(list(data.test))
    if frozen_model is None:
        model = build_model()
        model.fit(x_train, y_train)
        model_source = "refitted_under_canonical_order"
    else:
        model = frozen_model
        model_source = "historical_frozen_model"
        if int(getattr(model, "n_features_in_", 0)) != 5:
            raise EvaluationError("frozen model does not take five features")

    train_scores = model.predict_proba(x_train)[:, 1]
    test_scores = model.predict_proba(x_test)[:, 1]
    train_negative_scores = train_scores[y_train == 0]
    if train_negative_scores.size == 0:
        raise EvaluationError(f"{data.protocol}/fold{data.fold}: no training negative")

    positives = int((y_test == 1).sum())
    negatives = int((y_test == 0).sum())
    points = [
        _operating_point(target, train_negative_scores, data.test, test_scores, y_test)
        for target in FPR_TARGETS
    ]
    primary = next(p for p in points if p["target_train_fpr"] == PRIMARY_FPR_TARGET)

    record = {
        "protocol": data.protocol,
        "fold": data.fold,
        "held_out": data.held_out,
        "train_rows": len(data.train),
        "test_rows": len(data.test),
        "train_positive": int((y_train == 1).sum()),
        "train_negative": int((y_train == 0).sum()),
        "test_positive": positives,
        "test_negative": negatives,
        "roc_auc": float(roc_auc_score(y_test, test_scores))
        if positives and negatives
        else float("nan"),
        "pr_auc": float(average_precision_score(y_test, test_scores))
        if positives and negatives
        else float("nan"),
        "test_attack_type_windows": dict(
            sorted(Counter(str(r.attack_type) for r in data.test if r.label == 1).items())
        ),
        "train_attack_type_windows": dict(
            sorted(Counter(str(r.attack_type) for r in data.train if r.label == 1).items())
        ),
        "feature_names": list(FEATURE_NAMES),
        "feature_count": len(FEATURE_NAMES),
        "forbidden_model_inputs": list(FORBIDDEN_MODEL_INPUTS),
        "model_parameters": model_parameters(),
        "random_state": MODEL_SEED,
        "training_order": TRAINING_ORDER,
        "model_source": model_source,
        "historical_anchor": frozen_model is not None,
        "episode_bootstrap_resamples": BOOTSTRAP_RESAMPLES,
        "episode_bootstrap_seed": BOOTSTRAP_SEED,
        "operating_points": points,
        **{k: v for k, v in primary.items() if k not in ("episode_detection",)},
        **guards,
    }
    record["test_scores"] = {
        row.row_id: float(score) for row, score in zip(data.test, test_scores)
    }
    return record


def aggregate(records: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """Pool folds without hiding any single-fold result."""
    tp = sum(r["tp"] for r in records)
    fp = sum(r["fp"] for r in records)
    tn = sum(r["tn"] for r in records)
    fn = sum(r["fn"] for r in records)
    detected = sum(r["detected_episodes"] for r in records)
    episodes = sum(r["total_episodes"] for r in records)
    precision = tp / (tp + fp) if (tp + fp) else float("nan")
    recall = tp / (tp + fn) if (tp + fn) else float("nan")
    return {
        "folds": len(records),
        "train_rows_range": [
            min(r["train_rows"] for r in records),
            max(r["train_rows"] for r in records),
        ],
        "test_rows_total": sum(r["test_rows"] for r in records),
        "test_positive_total": sum(r["test_positive"] for r in records),
        "test_negative_total": sum(r["test_negative"] for r in records),
        "macro_roc_auc": float(np.mean([r["roc_auc"] for r in records])),
        "macro_pr_auc": float(np.mean([r["pr_auc"] for r in records])),
        "pooled_tp": tp,
        "pooled_fp": fp,
        "pooled_tn": tn,
        "pooled_fn": fn,
        "pooled_recall": float(recall),
        "pooled_precision": float(precision),
        "pooled_f1": float(2 * precision * recall / (precision + recall))
        if (tp + fp) and (tp + fn) and (precision + recall) > 0
        else 0.0,
        "pooled_fpr": float(fp / (fp + tn)) if (fp + tn) else float("nan"),
        "pooled_episode_recall": float(detected / episodes) if episodes else float("nan"),
        "detected_episodes": detected,
        "total_episodes": episodes,
        "macro_episode_recall": float(np.mean([r["episode_recall"] for r in records])),
        "entity_count_train_range": [
            min(r["entity_count_train"] for r in records),
            max(r["entity_count_train"] for r in records),
        ],
        "max_entity_intersection": max(r["entity_intersection_count"] for r in records),
        "max_episode_intersection": max(r["episode_intersection_count"] for r in records),
        "per_fold_roc_auc": [r["roc_auc"] for r in records],
        "per_fold_pr_auc": [r["pr_auc"] for r in records],
        "per_fold_episode_recall": [r["episode_recall"] for r in records],
        "per_fold_fpr": [r["fpr"] for r in records],
        "per_fold_threshold": [r["threshold"] for r in records],
    }


def compare(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    """Signed deltas ``right - left`` on the pooled and macro statistics."""
    keys = (
        "macro_roc_auc",
        "macro_pr_auc",
        "pooled_recall",
        "pooled_precision",
        "pooled_f1",
        "pooled_fpr",
        "pooled_episode_recall",
        "macro_episode_recall",
    )
    return {
        "delta": {k: float(right[k] - left[k]) for k in keys},
        "left": {k: float(left[k]) for k in keys},
        "right": {k: float(right[k]) for k in keys},
        "left_detected_episodes": left["detected_episodes"],
        "right_detected_episodes": right["detected_episodes"],
        "left_total_episodes": left["total_episodes"],
        "right_total_episodes": right["total_episodes"],
    }


def verify_historical_anchor(
    record: dict[str, Any], published_scores: dict[str, float]
) -> list[dict[str, Any]]:
    """Prove D2 re-scores the frozen model to the published stream exactly."""
    checks: list[dict[str, Any]] = []

    def note(name: str, passed: bool, detail: Any) -> None:
        checks.append({"check": name, "passed": bool(passed), "detail": detail})
        if not passed:
            raise EvaluationError(f"anchor/{name}: {detail}")

    note("model_source_is_frozen", record["model_source"] == "historical_frozen_model", record["model_source"])
    note("historical_anchor_flag", record["historical_anchor"] is True, record["historical_anchor"])
    scores = record["test_scores"]
    note("same_row_population", set(scores) == set(published_scores), len(scores))
    exact = sum(
        1
        for row_id, value in scores.items()
        if f"{value:.10f}" == f"{published_scores[row_id]:.10f}"
    )
    note("scores_match_to_ten_decimals", exact == len(scores), f"{exact}/{len(scores)}")
    largest = max(abs(scores[k] - published_scores[k]) for k in scores)
    note("max_absolute_score_difference_is_zero", largest == 0.0, largest)
    note("roc_auc_matches", abs(record["roc_auc"] - HISTORICAL_ARES_ANCHOR["roc_auc"]) < 1e-12, record["roc_auc"])
    note("pr_auc_matches", abs(record["pr_auc"] - HISTORICAL_ARES_ANCHOR["pr_auc"]) < 1e-12, record["pr_auc"])
    note("threshold_matches", record["threshold"] == HISTORICAL_ARES_ANCHOR["threshold"], record["threshold"])
    note("fpr_matches", abs(record["fpr"] - HISTORICAL_ARES_ANCHOR["fpr"]) < 1e-12, record["fpr"])
    note("tp_matches", record["tp"] == HISTORICAL_ARES_ANCHOR["tp"], record["tp"])
    note(
        "episodes_match",
        record["detected_episodes"] == HISTORICAL_ARES_ANCHOR["detected_episodes"]
        and record["total_episodes"] == HISTORICAL_ARES_ANCHOR["total_episodes"],
        f"{record['detected_episodes']}/{record['total_episodes']}",
    )
    return checks


def reproducibility_diagnostic() -> dict[str, Any]:
    """State precisely why an exact historical re-fit is impossible."""
    return {
        "subject": "loss of the historical P1 training-row order",
        "statement": (
            "The historical protocol depended on an input order that the SQL "
            "statement did not specify. That order was not persisted in the "
            "published artifacts. Exact reproduction of the re-training is "
            "therefore impossible from the artifacts alone."
        ),
        "not_a_model_defect": True,
        "facts": [
            "P1 fitted on [index[i] for i in fold.train_row_ids], whose negative "
            "segment carried the order returned by load_negatives()",
            "the load_negatives() SQL statement contains no ORDER BY, so its row "
            "order is not contractually defined",
            "p1_folds.json persists sorted(train_row_ids) only",
            "p1_predictions_*.csv are sorted by row_id",
            "RandomForestClassifier with random_state=0 remains order-dependent, "
            "because bootstrap samples index row positions rather than identities",
        ],
        "consequences": [
            "protocol A is a deterministic reimplementation, not a reproduction",
            "protocol D is measured twice: D1 re-fitted, D2 anchored on the frozen model",
            "the A/B/C comparison stays internally controlled: identical model, "
            "features, parameters, order convention, calibration and evaluation rules",
        ],
        "resolution": {
            "training_order": TRAINING_ORDER,
            "order_source": "physical order of the frozen production dataset",
            "postgresql_used_to_recover_order": False,
        },
    }


def canonical_digest(document: Any) -> str:
    return sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
