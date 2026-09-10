"""Leak-free surrogate hyperparameter tuning for the frozen ARM F feature budget.

The final Ares fold is an outer test and is unavailable to every operation in
this module until a candidate has been selected from four internal folds built
exclusively inside ``fold0.train``. No configuration is described as
Ares-optimised: selection uses known-family episode recall as a transfer
surrogate, then Ares is opened once.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
import itertools
import json
import math
from typing import Any, Final

import numpy as np
from sklearn.metrics import average_precision_score, roc_auc_score
from xgboost import XGBClassifier

from modules.detection.src.experiments.content_benchmark import matrix
from modules.detection.src.experiments.p1_dataset import Row
from modules.detection.src.experiments.p1_evaluation import (
    episode_bootstrap_recall,
    episode_recall,
    threshold_at_train_fpr,
)
from modules.detection.src.experiments.ratification import ARM_F_FEATURES
from modules.detection.src.experiments.xgb_baseline import XGB_PARAMS

SEARCH_SEED: Final[int] = 20_260_826
RANDOM_CONFIGURATIONS: Final[int] = 48
EARLY_STOPPING_ROUNDS: Final[int] = 50
PRIMARY_TRAIN_FPR: Final[float] = 0.005
POOLED_VALIDATION_FPR_LIMIT: Final[float] = 0.005
PER_FOLD_VALIDATION_FPR_LIMIT: Final[float] = 0.01
FINAL_EVALUATION_TARGETS: Final[tuple[float, ...]] = (
    0.01,
    0.005,
    0.002,
    0.001,
    0.0005,
)

SEARCH_SPACE: Final[dict[str, tuple[Any, ...]]] = {
    "max_depth": (2, 3, 4, 5),
    "learning_rate": (0.025, 0.05, 0.1),
    "max_n_estimators": (300, 600, 1000),
    "reg_alpha": (0.0, 0.01, 0.1, 1.0),
    "reg_lambda": (1.0, 3.0, 10.0, 30.0),
    "min_child_weight": (1.0, 3.0, 5.0, 10.0),
    "subsample": (0.7, 0.85, 1.0),
    "colsample_bytree": (0.67, 1.0),
}


class TuningError(RuntimeError):
    """The pre-registration, leakage boundary or selection rule was violated."""


def candidate_configurations() -> list[dict[str, Any]]:
    """The exact deterministic candidate list, including the fixed Phase-1 control."""
    names = tuple(SEARCH_SPACE)
    product = list(itertools.product(*(SEARCH_SPACE[n] for n in names)))
    rng = np.random.default_rng(SEARCH_SEED)
    indices = rng.choice(len(product), size=RANDOM_CONFIGURATIONS, replace=False)
    candidates: list[dict[str, Any]] = [
        {
            "candidate_id": "P1_CONTROL",
            "selection_eligible": True,
            "early_stopping": False,
            "params": {
                "max_depth": 3,
                "learning_rate": 0.1,
                "max_n_estimators": 200,
                "reg_alpha": 0.0,
                "reg_lambda": 1.0,
                "min_child_weight": 1.0,
                "subsample": 1.0,
                "colsample_bytree": 1.0,
            },
        }
    ]
    for serial, index in enumerate(indices, start=1):
        values = product[int(index)]
        candidates.append(
            {
                "candidate_id": f"R{serial:03d}",
                "selection_eligible": True,
                "early_stopping": True,
                "params": dict(zip(names, values)),
            }
        )
    if len({json.dumps(c["params"], sort_keys=True) for c in candidates}) != len(candidates):
        raise TuningError("candidate generation produced a duplicate")
    return candidates


def preregistration_document() -> dict[str, Any]:
    """Protocol identity generated before any model is fitted."""
    return {
        "experiment": "Phase 2 production-grade XGBoost tuning on frozen ARM F",
        "scientific_status": "pre-registered before fitting or inspecting outer-test scores",
        "feature_budget": list(ARM_F_FEATURES),
        "outer_test": {
            "membership": "frozen P1 fold0.test",
            "held_out_attack_type": "botnet/ares",
            "rows": 13951,
            "positive_windows": 177,
            "negative_windows": 13774,
            "availability_during_tuning": "strictly forbidden",
            "opening": "once, after selection and final refit",
        },
        "tuning_pool": {
            "membership": "frozen P1 fold0.train",
            "rows": 57003,
            "ares_rows": 0,
        },
        "inner_folds": {
            "construction": (
                "for k=1..4: validation_k = frozen fold_k.test intersect fold0.train; "
                "training_k = fold0.train minus validation_k"
            ),
            "held_out_attack_types": [
                "brute_force/ftp_patator",
                "brute_force/ssh_patator",
                "ddos/loit",
                "dos/hulk",
            ],
            "validation_rows": [14045, 14124, 14770, 14064],
            "outer_test_overlap": 0,
        },
        "surrogate_objective": {
            "primary": (
                "maximise unweighted macro episode recall over FTP, SSH, DDOS and "
                "Hulk at target_train_fpr=0.005"
            ),
            "hard_constraints": {
                "pooled_validation_fpr_max": POOLED_VALIDATION_FPR_LIMIT,
                "every_validation_fold_fpr_max": PER_FOLD_VALIDATION_FPR_LIMIT,
            },
            "lexicographic_tie_breaks": [
                "higher minimum per-family episode recall",
                "higher macro validation PR-AUC",
                "lower maximum validation-fold FPR",
                "lower pooled validation FPR",
                "shallower max_depth",
                "larger min_child_weight",
                "larger reg_alpha",
                "larger reg_lambda",
                "fewer median selected trees",
                "lexicographically smaller candidate_id",
            ],
            "no_feasible_candidate": (
                "declare tuning unsuccessful and retain the Phase-1 control; never "
                "relax a constraint after observing results"
            ),
            "ares_optimisation_claim": "forbidden; Ares is absent from tuning",
        },
        "early_stopping": {
            "metric": "validation AUCPR",
            "rounds": EARLY_STOPPING_ROUNDS,
            "role": (
                "iteration-level regularisation only; candidate selection remains "
                "episode recall under the hard FPR constraints"
            ),
            "phase1_control": "fixed 200 trees, no early stopping",
        },
        "final_refit": {
            "data": "all fold0.train rows",
            "n_estimators": (
                "round-half-up median of best_iteration+1 across the four inner folds "
                "for the selected candidate; P1_CONTROL remains exactly 200"
            ),
            "thresholds": (
                "calibrated only from all fold0.train negatives at the five fixed "
                "FINAL_EVALUATION_TARGETS"
            ),
        },
        "outer_evaluation": {
            "targets": list(FINAL_EVALUATION_TARGETS),
            "primary_transfer_target": PRIMARY_TRAIN_FPR,
            "metrics": [
                "Ares episode recall and 95% episode bootstrap CI",
                "window recall",
                "ROC-AUC",
                "PR-AUC",
                "realised test FPR",
                "per-entity and per-episode results",
                "paired episode deltas against frozen Phase-1 ARM F",
            ],
            "interpretation": (
                "a single zero-day transfer measurement, never an optimisation result"
            ),
        },
        "search": {
            "method": "deterministic random search without replacement plus control",
            "seed": SEARCH_SEED,
            "random_configurations": RANDOM_CONFIGURATIONS,
            "total_configurations": RANDOM_CONFIGURATIONS + 1,
            "space": {k: list(v) for k, v in SEARCH_SPACE.items()},
            "candidates": candidate_configurations(),
        },
        "fixed_xgboost_parameters": {
            k: v
            for k, v in XGB_PARAMS.items()
            if k
            not in {
                "max_depth",
                "learning_rate",
                "n_estimators",
                "subsample",
                "colsample_bytree",
            }
        },
        "forbidden": [
            "using any fold0.test row during fitting, early stopping, selection or threshold calibration",
            "claiming direct optimisation for Ares",
            "changing the frozen ARM F feature budget",
            "new features, external data, label changes or unknown/ambiguous negatives",
            "PostgreSQL writes",
            "post-hoc constraint relaxation or candidate additions",
            "modifying P1-P6, Phase-1 models, folds, predictions or reports",
        ],
    }


def formatting_independent_digest(document: dict[str, Any]) -> str:
    return sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


@dataclass(slots=True)
class InnerFoldResult:
    candidate_id: str
    fold: int
    held_out_attack_type: str
    best_iteration: int
    selected_trees: int
    threshold: float
    achieved_train_fpr: float
    validation_fpr: float
    false_positives: int
    validation_negatives: int
    episode_recall: float
    episode_detection: dict[str, bool]
    episode_bootstrap: dict[str, float]
    window_recall: float
    roc_auc: float
    pr_auc: float


@dataclass(slots=True)
class CandidateResult:
    candidate_id: str
    params: dict[str, Any]
    early_stopping: bool
    folds: list[InnerFoldResult] = field(default_factory=list)
    feasible: bool = False
    pooled_validation_fpr: float = math.nan
    max_fold_validation_fpr: float = math.nan
    macro_episode_recall: float = math.nan
    minimum_family_episode_recall: float = math.nan
    macro_pr_auc: float = math.nan
    final_n_estimators: int = 0


def build_model(params: dict[str, Any], early_stopping: bool) -> XGBClassifier:
    tuned = dict(XGB_PARAMS)
    tuned.update(
        {
            "max_depth": int(params["max_depth"]),
            "learning_rate": float(params["learning_rate"]),
            "n_estimators": int(params["max_n_estimators"]),
            "reg_alpha": float(params["reg_alpha"]),
            "reg_lambda": float(params["reg_lambda"]),
            "min_child_weight": float(params["min_child_weight"]),
            "subsample": float(params["subsample"]),
            "colsample_bytree": float(params["colsample_bytree"]),
            "eval_metric": "aucpr" if early_stopping else "logloss",
        }
    )
    if early_stopping:
        tuned["early_stopping_rounds"] = EARLY_STOPPING_ROUNDS
    return XGBClassifier(**tuned)


def evaluate_inner_fold(
    candidate: dict[str, Any],
    fold_index: int,
    held_out_attack_type: str,
    train_rows: list[Row],
    validation_rows: list[Row],
) -> tuple[InnerFoldResult, XGBClassifier]:
    """Fit without access to any outer-test row and score one internal fold."""
    x_train, y_train = matrix(train_rows, len(ARM_F_FEATURES))
    x_val, y_val = matrix(validation_rows, len(ARM_F_FEATURES))
    model = build_model(candidate["params"], bool(candidate["early_stopping"]))
    fit_kwargs: dict[str, Any] = {"verbose": False}
    if candidate["early_stopping"]:
        fit_kwargs["eval_set"] = [(x_val, y_val)]
    model.fit(x_train, y_train, **fit_kwargs)

    train_scores = model.predict_proba(x_train)[:, 1]
    val_scores = model.predict_proba(x_val)[:, 1]
    threshold, achieved = threshold_at_train_fpr(
        train_scores[y_train == 0], PRIMARY_TRAIN_FPR
    )
    flagged = val_scores >= threshold
    positives = int((y_val == 1).sum())
    negatives = int((y_val == 0).sum())
    tp = int((flagged & (y_val == 1)).sum())
    fp = int((flagged & (y_val == 0)).sum())
    detected, recall = episode_recall(validation_rows, val_scores, threshold)
    best_iteration = (
        int(model.best_iteration)
        if candidate["early_stopping"] and hasattr(model, "best_iteration")
        else int(candidate["params"]["max_n_estimators"]) - 1
    )
    result = InnerFoldResult(
        candidate_id=candidate["candidate_id"],
        fold=fold_index,
        held_out_attack_type=held_out_attack_type,
        best_iteration=best_iteration,
        selected_trees=best_iteration + 1,
        threshold=float(threshold),
        achieved_train_fpr=float(achieved),
        validation_fpr=fp / negatives,
        false_positives=fp,
        validation_negatives=negatives,
        episode_recall=float(recall),
        episode_detection=dict(sorted(detected.items())),
        episode_bootstrap=episode_bootstrap_recall(detected),
        window_recall=tp / positives,
        roc_auc=float(roc_auc_score(y_val, val_scores)),
        pr_auc=float(average_precision_score(y_val, val_scores)),
    )
    return result, model


def summarise_candidate(candidate: dict[str, Any], folds: list[InnerFoldResult]) -> CandidateResult:
    false_positives = sum(f.false_positives for f in folds)
    negatives = sum(f.validation_negatives for f in folds)
    pooled = false_positives / negatives
    maximum = max(f.validation_fpr for f in folds)
    selected = sorted(f.selected_trees for f in folds)
    median = (selected[1] + selected[2]) / 2.0
    final_trees = int(math.floor(median + 0.5))
    if not candidate["early_stopping"]:
        final_trees = int(candidate["params"]["max_n_estimators"])
    return CandidateResult(
        candidate_id=candidate["candidate_id"],
        params=dict(candidate["params"]),
        early_stopping=bool(candidate["early_stopping"]),
        folds=list(folds),
        feasible=(
            pooled <= POOLED_VALIDATION_FPR_LIMIT
            and maximum <= PER_FOLD_VALIDATION_FPR_LIMIT
        ),
        pooled_validation_fpr=pooled,
        max_fold_validation_fpr=maximum,
        macro_episode_recall=float(np.mean([f.episode_recall for f in folds])),
        minimum_family_episode_recall=min(f.episode_recall for f in folds),
        macro_pr_auc=float(np.mean([f.pr_auc for f in folds])),
        final_n_estimators=final_trees,
    )


def selection_key(result: CandidateResult) -> tuple[Any, ...]:
    """Lexicographic ranking fixed in the pre-registration."""
    p = result.params
    return (
        -result.macro_episode_recall,
        -result.minimum_family_episode_recall,
        -result.macro_pr_auc,
        result.max_fold_validation_fpr,
        result.pooled_validation_fpr,
        int(p["max_depth"]),
        -float(p["min_child_weight"]),
        -float(p["reg_alpha"]),
        -float(p["reg_lambda"]),
        result.final_n_estimators,
        result.candidate_id,
    )


def select_candidate(results: list[CandidateResult]) -> CandidateResult:
    feasible = [r for r in results if r.feasible]
    if not feasible:
        controls = [r for r in results if r.candidate_id == "P1_CONTROL"]
        if len(controls) != 1:
            raise TuningError("no feasible candidate and no unique Phase-1 control")
        return controls[0]
    return min(feasible, key=selection_key)


def result_document(result: CandidateResult) -> dict[str, Any]:
    return {
        "candidate_id": result.candidate_id,
        "params": result.params,
        "early_stopping": result.early_stopping,
        "feasible": result.feasible,
        "pooled_validation_fpr": result.pooled_validation_fpr,
        "max_fold_validation_fpr": result.max_fold_validation_fpr,
        "macro_episode_recall": result.macro_episode_recall,
        "minimum_family_episode_recall": result.minimum_family_episode_recall,
        "macro_pr_auc": result.macro_pr_auc,
        "final_n_estimators": result.final_n_estimators,
        "folds": [
            {
                "candidate_id": f.candidate_id,
                "fold": f.fold,
                "held_out_attack_type": f.held_out_attack_type,
                "best_iteration": f.best_iteration,
                "selected_trees": f.selected_trees,
                "threshold": f.threshold,
                "achieved_train_fpr": f.achieved_train_fpr,
                "validation_fpr": f.validation_fpr,
                "false_positives": f.false_positives,
                "validation_negatives": f.validation_negatives,
                "episode_recall": f.episode_recall,
                "episode_detection": f.episode_detection,
                "episode_bootstrap": f.episode_bootstrap,
                "window_recall": f.window_recall,
                "roc_auc": f.roc_auc,
                "pr_auc": f.pr_auc,
            }
            for f in result.folds
        ],
    }
