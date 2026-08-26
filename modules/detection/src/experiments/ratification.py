"""ARM F ratification and the pre-registered ARM J1 hybrid.

Strictly additive. This module never imports a writer for a frozen artifact and
never mutates the frozen four-arm A--D benchmark, the six-arm content benchmark,
P1--P6 or the published XGBoost baseline. It reuses their learner, their episode
unit, their threshold calibration and their bootstrap unchanged, so the only
quantity that varies between arms is the registered feature budget.

Two questions are asked, both fixed before any number was produced:

1. Is ARM F genuinely superior to ARM A? The frozen six-arm benchmark left ARM F
   INCONCLUSIVE because a two-sided FPR stability band flagged
   ``|dFPR| = 0.002686 > 0.0025``. That band fired in the direction where ARM F
   raises *fewer* false alerts than ARM A, which is not a confound. Exact
   realised-test-FPR matching is impossible without choosing a threshold on the
   test set, which the protocol forbids, so the ratified rule is Pareto
   dominance: strictly better episode recall at a realised FPR that is not worse.

2. Does adding the volumetric ``interarrival_mean`` back to ARM F recover
   ``ssh_patator`` without sacrificing the Ares gain? ARM J1 is the single
   pre-registered hybrid for that question.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
import json
from typing import Any, Final

import numpy as np
from xgboost import XGBClassifier

from modules.detection.src.experiments.content_benchmark import (
    BASE_FEATURE,
    build_model,
    matrix,
)
from modules.detection.src.experiments.p1_dataset import FORBIDDEN_COLUMNS, Row
from modules.detection.src.experiments.p1_evaluation import (
    episode_bootstrap_recall,
    episode_recall,
    threshold_at_train_fpr,
)

#: The volumetric feature reinstated by ARM J1, taken verbatim from P6.
VOLUMETRIC_FEATURE: Final[str] = "interarrival_mean"

#: The two payload-content ratios ARM F retained.
NON_PRINTABLE_FEATURES: Final[tuple[str, ...]] = (
    "source_non_printable_ratio",
    "destination_non_printable_ratio",
)

ARM_A_FEATURES: Final[tuple[str, ...]] = (BASE_FEATURE,)
ARM_F_FEATURES: Final[tuple[str, ...]] = (BASE_FEATURE, *NON_PRINTABLE_FEATURES)
ARM_J1_FEATURES: Final[tuple[str, ...]] = (
    BASE_FEATURE,
    *NON_PRINTABLE_FEATURES,
    VOLUMETRIC_FEATURE,
)

#: The only three models this experiment may fit.
RATIFICATION_ARMS: Final[dict[str, tuple[str, ...]]] = {
    "A": ARM_A_FEATURES,
    "F": ARM_F_FEATURES,
    "J1": ARM_J1_FEATURES,
}

#: Five operating points fixed before any result was seen. Every threshold is a
#: quantile of the *training* negatives; the test set never selects a threshold.
RATIFICATION_FPR_TARGETS: Final[tuple[float, ...]] = (0.01, 0.005, 0.002, 0.001, 0.0005)

#: The declared primary point among the grid.
PRIMARY_TARGET: Final[float] = 0.01

PRIMARY_ENDPOINT: Final[str] = "botnet/ares"
CO_PRIMARY_ENDPOINT: Final[str] = "brute_force/ssh_patator"

PRE_REGISTRATION: Final[dict[str, Any]] = {
    "experiment": "ARM-F-RATIFICATION and ARM-J1",
    "registered_before_any_result": True,
    "arms": {name: list(features) for name, features in RATIFICATION_ARMS.items()},
    "arm_j1_selection": {
        "chosen": "J1 = ARM F + interarrival_mean",
        "rejected": ["J2 = ARM F + bytes_per_packet_destination", "J3 = ARM F + both"],
        "reason": (
            "the frozen A--D benchmark shows no volumetric budget beyond ARM A "
            "improves ssh_patator episode recall: interarrival_mean (ARM B) left it "
            "unchanged at 0.1111 and raised its ROC-AUC from 0.9199 to 0.9453, while "
            "bytes_per_packet_destination (ARM C and ARM D) lost the single episode. "
            "interarrival_mean is therefore the smallest budget increase capable of "
            "addressing the stated ssh_patator motivation, and the most conservative "
            "of the three possible hybrids"
        ),
        "premise_correction": (
            "the mission premise named a volumetric budget that had shown utility on "
            "ssh_patator and the volumetric attacks. No such budget exists: ARM A "
            "alone is best on all four held-in types (6 held-in episodes against 4 "
            "for B, C and D, each carrying an important volumetric cost). Because "
            "ARM A's budget is exactly distinct_payload_ratio and ARM F already "
            "contains it, a literal hybrid would duplicate ARM F. ARM J1 therefore "
            "reinstates interarrival_mean, which is a genuine test of whether "
            "content signal rehabilitates a feature that harmed the volumetric arms"
        ),
    },
    "primary_endpoint": f"{PRIMARY_ENDPOINT} episode recall at {PRIMARY_TARGET:.0%} training FPR",
    "co_primary_endpoint": (
        f"{CO_PRIMARY_ENDPOINT} episode recall at {PRIMARY_TARGET:.0%} training FPR, "
        "declared co-primary for ARM J1"
    ),
    "operating_points": list(RATIFICATION_FPR_TARGETS),
    "threshold_rule": (
        "quantile of the training-negative score distribution at each registered "
        "target, identical to the published baseline; the test set never selects a "
        "threshold, a feature, a hyperparameter or an architecture"
    ),
    "arm_f_ratification_rule": {
        "verdict_SUPPORTED": (
            "Ares episode recall strictly above ARM A AND the paired episode-delta "
            "95% interval strictly positive AND realised test FPR not above ARM A's"
        ),
        "verdict_NOT_SUPPORTED": "the paired episode-delta 95% interval is strictly negative",
        "verdict_INCONCLUSIVE": "neither of the above holds",
        "evaluated_at": f"target_train_fpr={PRIMARY_TARGET}",
        "rationale": (
            "higher recall at a not-worse false-alert rate is strictly stronger than "
            "parity, so Pareto dominance ratifies without ever matching a realised "
            "FPR on the test set"
        ),
    },
    "equal_alert_budget_status": (
        "secondary diagnostic only; it aligns budgets using test-set alert counts and "
        "therefore may never ratify ARM F or ARM J1"
    ),
    "bootstrap": {
        "unit": "episode",
        "resamples": 2000,
        "seed": 0,
        "pairing": "candidate minus reference over identical episode ids",
        "window_bootstrap": "forbidden as pseudoreplication",
    },
    "forbidden": [
        "tuning, validation split, early stopping, rebalancing, threshold search",
        "any feature outside the three registered budgets",
        "unknown or ambiguous rows as negatives",
        "label modification",
        "PostgreSQL writes",
        "new external data",
        "modifying P1--P6, the XGBoost baseline, the A--D benchmark or the six-arm benchmark",
    ],
}


class RatificationError(RuntimeError):
    """A frozen identity, protocol or pre-registration invariant failed."""


def pre_registration_digest() -> str:
    """Formatting-independent identity of the pre-registered protocol."""
    return sha256(
        json.dumps(PRE_REGISTRATION, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    ).hexdigest()


def verify_arm_budgets() -> list[dict[str, Any]]:
    """Prove the three budgets are exactly the registered ones and leak nothing."""
    checks: list[dict[str, Any]] = []

    def record(name: str, passed: bool, detail: Any) -> None:
        checks.append({"check": name, "passed": bool(passed), "detail": detail})
        if not passed:
            raise RatificationError(f"{name}: {detail}")

    record("arm_a_is_the_single_base_feature", ARM_A_FEATURES == (BASE_FEATURE,),
           list(ARM_A_FEATURES))
    record("arm_f_is_base_plus_the_two_non_printable_ratios",
           ARM_F_FEATURES == (BASE_FEATURE, *NON_PRINTABLE_FEATURES),
           list(ARM_F_FEATURES))
    record("arm_j1_is_exactly_arm_f_plus_interarrival_mean",
           ARM_J1_FEATURES == (*ARM_F_FEATURES, VOLUMETRIC_FEATURE),
           list(ARM_J1_FEATURES))
    record("arm_j1_adds_exactly_one_feature_to_arm_f",
           len(ARM_J1_FEATURES) == len(ARM_F_FEATURES) + 1
           and set(ARM_F_FEATURES) < set(ARM_J1_FEATURES),
           {"F": len(ARM_F_FEATURES), "J1": len(ARM_J1_FEATURES)})
    record("only_three_arms_are_registered", sorted(RATIFICATION_ARMS) == ["A", "F", "J1"],
           sorted(RATIFICATION_ARMS))
    forbidden = {
        arm: [f for f in features if f in set(FORBIDDEN_COLUMNS)]
        for arm, features in RATIFICATION_ARMS.items()
    }
    record("no_arm_uses_a_forbidden_column", all(not v for v in forbidden.values()),
           forbidden)
    record("no_arm_uses_a_presence_indicator",
           all(not f.endswith("_present") for fs in RATIFICATION_ARMS.values() for f in fs),
           {a: list(f) for a, f in RATIFICATION_ARMS.items()})
    record("five_operating_points_are_pre_registered",
           RATIFICATION_FPR_TARGETS == (0.01, 0.005, 0.002, 0.001, 0.0005),
           list(RATIFICATION_FPR_TARGETS))
    record("the_declared_primary_target_is_in_the_grid",
           PRIMARY_TARGET in RATIFICATION_FPR_TARGETS, PRIMARY_TARGET)
    return checks


@dataclass(slots=True)
class ArmFoldResult:
    """Everything observed for one arm on one leave-one-attack-type-out fold."""

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
    missingness: dict[str, float] = field(default_factory=dict)
    operating_points: list[dict[str, Any]] = field(default_factory=list)
    predictions: list[dict[str, Any]] = field(default_factory=list)
    test_rows: list[Row] = field(default_factory=list)
    test_scores: Any = None
    model: Any = None


def _gain_importance(model: XGBClassifier, features: tuple[str, ...]) -> dict[str, float]:
    raw = model.get_booster().get_score(importance_type="gain")
    values = {n: float(raw.get(f"f{i}", 0.0)) for i, n in enumerate(features)}
    total = sum(values.values())
    return {n: v / total for n, v in values.items()} if total > 0 else values


def evaluate_arm_fold(
    arm: str,
    features: tuple[str, ...],
    fold_index: int,
    held_out_attack_type: str,
    train_rows: list[Row],
    test_rows: list[Row],
) -> ArmFoldResult:
    """Fit one arm on one fold and evaluate it at all five registered points."""
    if RATIFICATION_ARMS.get(arm) != features:
        raise RatificationError(
            f"arm {arm} feature budget differs from the registered budget"
        )
    x_train, y_train = matrix(train_rows, len(features))
    x_test, y_test = matrix(test_rows, len(features))

    model = build_model()
    model.fit(x_train, y_train)
    train_scores = model.predict_proba(x_train)[:, 1]
    test_scores = model.predict_proba(x_test)[:, 1]
    train_negative_scores = train_scores[y_train == 0]

    positives = int((y_test == 1).sum())
    negatives = int((y_test == 0).sum())
    from sklearn.metrics import average_precision_score, roc_auc_score

    roc = (
        float(roc_auc_score(y_test, test_scores))
        if positives and negatives
        else float("nan")
    )
    pr = (
        float(average_precision_score(y_test, test_scores))
        if positives and negatives
        else float("nan")
    )

    result = ArmFoldResult(
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
        missingness={
            name: float(np.isnan(x_test[:, index]).mean())
            for index, name in enumerate(features)
        },
        test_rows=list(test_rows),
        test_scores=test_scores,
        model=model,
    )

    for target in RATIFICATION_FPR_TARGETS:
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
                "alerts": int(flagged.sum()),
                "window_recall": tp / positives if positives else float("nan"),
                "window_precision": tp / (tp + fp) if (tp + fp) else float("nan"),
                "true_positives": tp,
                "false_positives": fp,
                "episode_recall": recall,
                "episodes_detected": sorted(k for k, v in detected.items() if v),
                "episodes_missed": sorted(k for k, v in detected.items() if not v),
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


def point_at(result: ArmFoldResult, target: float = PRIMARY_TARGET) -> dict[str, Any]:
    """The operating point for one registered target."""
    return next(
        p for p in result.operating_points if p["target_train_fpr"] == target
    )


def ratify_arm_f(point_a: dict[str, Any], point_f: dict[str, Any],
                 paired: dict[str, Any]) -> dict[str, Any]:
    """Apply the ratified Pareto-dominance rule. The rule is not result-dependent."""
    recall_strictly_better = point_f["episode_recall"] > point_a["episode_recall"]
    ci_strictly_positive = paired["ci_low"] > 0.0
    fpr_not_worse = point_f["observed_test_fpr"] <= point_a["observed_test_fpr"]
    ci_strictly_negative = paired["ci_high"] < 0.0

    if recall_strictly_better and ci_strictly_positive and fpr_not_worse:
        verdict = "SUPPORTED"
        reason = (
            "Ares episode recall is strictly above ARM A, the paired episode-delta "
            "interval is strictly positive, and the realised test FPR is not above "
            "ARM A's, so ARM F Pareto-dominates ARM A"
        )
    elif ci_strictly_negative:
        verdict = "NOT SUPPORTED"
        reason = "the paired episode-delta interval is strictly negative"
    else:
        verdict = "INCONCLUSIVE"
        reason = (
            "the conjunction required for SUPPORTED does not hold and the paired "
            "interval is not strictly negative"
        )
    return {
        "verdict": verdict,
        "reason": reason,
        "conditions": {
            "episode_recall_strictly_above_arm_a": recall_strictly_better,
            "paired_ci_strictly_positive": ci_strictly_positive,
            "realised_fpr_not_above_arm_a": fpr_not_worse,
            "paired_ci_strictly_negative": ci_strictly_negative,
        },
        "observed": {
            "arm_a_episode_recall": point_a["episode_recall"],
            "arm_f_episode_recall": point_f["episode_recall"],
            "arm_a_observed_test_fpr": point_a["observed_test_fpr"],
            "arm_f_observed_test_fpr": point_f["observed_test_fpr"],
            "paired_delta_point": paired["point"],
            "paired_delta_ci": [paired["ci_low"], paired["ci_high"]],
        },
    }


def classify_paired(paired: dict[str, Any]) -> str:
    """Direction of a paired episode-delta interval, with no result-dependent slack."""
    if paired["ci_low"] > 0.0:
        return "improved"
    if paired["ci_high"] < 0.0:
        return "degraded"
    return "indistinguishable"


def equal_alert_budget_diagnostic(
    test_rows: list[Row], scores: np.ndarray, budget: int
) -> dict[str, Any]:
    """Episode recall when the arm is allowed exactly ``budget`` alerts.

    Secondary diagnostic only. The budget is derived from ARM A's alert count on
    the test set, so this may never ratify an arm. It answers the operational
    question of what an analyst reviewing a fixed number of alerts would find.
    """
    if budget <= 0 or budget > len(scores):
        raise RatificationError(f"alert budget {budget} outside 1..{len(scores)}")
    order = np.argsort(-scores, kind="stable")
    flagged = np.zeros(len(scores), dtype=bool)
    flagged[order[:budget]] = True
    detected: dict[str, bool] = {}
    for row, is_flagged in zip(test_rows, flagged):
        if row.label != 1 or row.episode_id is None:
            continue
        detected.setdefault(row.episode_id, False)
        if is_flagged:
            detected[row.episode_id] = True
    labels = np.asarray([r.label for r in test_rows], dtype=int)
    negatives = int((labels == 0).sum())
    false_positives = int((flagged & (labels == 0)).sum())
    return {
        "alert_budget": budget,
        "episodes": len(detected),
        "episodes_detected": sum(detected.values()),
        "episode_recall": (
            sum(detected.values()) / len(detected) if detected else float("nan")
        ),
        "episode_detection": dict(sorted(detected.items())),
        "observed_test_fpr": false_positives / negatives if negatives else float("nan"),
        "ratifying": False,
    }
