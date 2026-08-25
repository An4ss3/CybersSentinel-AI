"""Six-arm payload-content feature benchmark on the frozen P1 protocol.

Additive by construction. The frozen four-arm A--D benchmark is not imported for
its arm registry and is never modified; only protocol-neutral helpers (the fixed
learner parameters, the matrix builder, the paired episode bootstrap and the
per-entity recall reducer) are reused so that ARM A reproduces the published
one-feature XGBoost baseline exactly.

Arms A/E/F/G/H/I were registered before any content value was extracted. ARM I is
``A + all six metrics``, never a subset chosen after reading E--H.

Declared missingness diagnostics
--------------------------------
Extraction established that the presence of
``normalized_header_template_repeat_ratio`` is exactly equivalent to
``service == http`` (12,279 windows, all http). Because P1 forbids
``entity_service`` as a feature, and XGBoost branches natively on missing values,
an ARM H or ARM I effect could be carried by that missingness rather than by
header-template repetition. Two diagnostic models therefore replace the content
values with their presence indicators alone. They are **not** arms, they take part
in no arm ranking, and they exist only to bound how much of an observed effect is
attributable to the service proxy.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import math
from typing import Any, Final

import numpy as np
from sklearn.metrics import average_precision_score, roc_auc_score
from xgboost import XGBClassifier

from modules.detection.src.experiments.content_extractor import (
    ARM_FEATURES as REGISTERED_ARM_FEATURES,
    FEATURE_NAMES as CONTENT_FEATURE_NAMES,
)
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


BASE_FEATURE: Final[str] = "distinct_payload_ratio"
PRIMARY_ENDPOINT: Final[str] = "botnet/ares"
INDICATOR_SUFFIX: Final[str] = "_present"

#: The six pre-registered arms, taken verbatim from the extractor registry so the
#: benchmark cannot silently diverge from what was registered before extraction.
ARM_FEATURES: Final[dict[str, tuple[str, ...]]] = dict(REGISTERED_ARM_FEATURES)

#: Presence indicators, used only by the declared diagnostics.
INDICATOR_NAMES: Final[tuple[str, ...]] = tuple(
    f"{name}{INDICATOR_SUFFIX}" for name in CONTENT_FEATURE_NAMES
)

HEADER_TEMPLATE_METRIC: Final[str] = "normalized_header_template_repeat_ratio"

DIAGNOSTIC_FEATURES: Final[dict[str, tuple[str, ...]]] = {
    # Bounds ARM H: keeps only "is this metric present", i.e. the service proxy.
    "H_IND": (BASE_FEATURE, f"{HEADER_TEMPLATE_METRIC}{INDICATOR_SUFFIX}"),
    # Bounds ARM I: all six presence indicators, none of the six values.
    "I_IND": (BASE_FEATURE, *INDICATOR_NAMES),
}

MODEL_SPECS: Final[dict[str, tuple[str, ...]]] = {**ARM_FEATURES, **DIAGNOSTIC_FEATURES}

BOOTSTRAP_DECLARATION: Final[dict[str, Any]] = {
    "unit": "episode",
    "resamples": BOOTSTRAP_RESAMPLES,
    "seed": BOOTSTRAP_SEED,
    "window_level_intervals": "forbidden",
}


class ContentBenchmarkError(RuntimeError):
    """A frozen, arm-identity or protocol invariant failed; publication must stop."""


def build_model() -> XGBClassifier:
    """The published baseline learner, byte-for-byte. No tuning is performed."""
    return XGBClassifier(**XGB_PARAMS)


def matrix(rows: list[Row], expected_width: int) -> tuple[np.ndarray, np.ndarray]:
    """Build a design matrix admitting only XGBoost's native missing values.

    Content metrics are undefined for windows without qualifying payload or HTTP
    requests. Those stay NaN and reach XGBoost's native missing branch; no
    imputation, fitted fill value or extra indicator is introduced into an arm.
    """
    features = np.asarray([row.features for row in rows], dtype=float)
    if features.ndim != 2 or features.shape[1] != expected_width:
        width = features.shape[1] if features.ndim == 2 else "not-a-matrix"
        raise ContentBenchmarkError(
            f"expected exactly {expected_width} features, got {width}"
        )
    if np.isinf(features).any():
        raise ContentBenchmarkError("infinite feature value is forbidden")
    labels = np.asarray([row.label for row in rows], dtype=int)
    return features, labels


@dataclass(slots=True)
class FoldResult:
    arm: str
    features: tuple[str, ...]
    fold: int
    held_out_attack_type: str
    is_diagnostic: bool
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
    model: Any = None


def _gain_importance(
    model: XGBClassifier, features: tuple[str, ...]
) -> dict[str, float]:
    raw = model.get_booster().get_score(importance_type="gain")
    values = {
        name: float(raw.get(f"f{index}", 0.0)) for index, name in enumerate(features)
    }
    total = sum(values.values())
    return {n: v / total for n, v in values.items()} if total > 0 else values


def evaluate_fold(
    arm: str,
    features: tuple[str, ...],
    fold_index: int,
    held_out_attack_type: str,
    train_rows: list[Row],
    test_rows: list[Row],
) -> FoldResult:
    """Fit and evaluate one model under the unchanged P1 conventions."""
    if MODEL_SPECS.get(arm) != features:
        raise ContentBenchmarkError(
            f"model {arm} feature budget differs from the registered budget"
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

    missingness = {}
    for index, name in enumerate(features):
        column = x_test[:, index]
        missingness[name] = float(np.isnan(column).mean())

    result = FoldResult(
        arm=arm,
        features=features,
        fold=fold_index,
        held_out_attack_type=held_out_attack_type,
        is_diagnostic=arm in DIAGNOSTIC_FEATURES,
        train_positives=int((y_train == 1).sum()),
        train_negatives=int((y_train == 0).sum()),
        test_positives=positives,
        test_negatives=negatives,
        test_episodes=len({r.episode_id for r in test_rows if r.label == 1}),
        roc_auc=roc,
        pr_auc=pr,
        feature_importance_gain=_gain_importance(model, features),
        missingness=missingness,
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


def paired_episode_bootstrap_delta(
    reference: dict[str, bool], candidate: dict[str, bool]
) -> dict[str, Any]:
    """Bootstrap candidate-minus-reference episode recall over shared episodes.

    Every model sees exactly the same held-out episodes, so the comparison is
    paired. Resampling windows would be pseudoreplication and is forbidden.
    """
    if set(reference) != set(candidate):
        raise ContentBenchmarkError("paired bootstrap requires identical episode ids")
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
        draws[index] = rng.choice(
            differences, size=len(differences), replace=True
        ).mean()
    return {
        "point": float(differences.mean()),
        "ci_low": float(np.quantile(draws, 0.025)),
        "ci_high": float(np.quantile(draws, 0.975)),
        "episodes": len(episode_ids),
        "candidate_only_detections": int((differences == 1).sum()),
        "reference_only_detections": int((differences == -1).sum()),
    }


def per_entity_recall(
    test_rows: list[Row], scores: np.ndarray, threshold: float
) -> dict[str, dict[str, Any]]:
    """Window and episode recall for each positive entity at one threshold."""
    buckets: dict[str, dict[str, Any]] = {}
    for row, score in zip(test_rows, scores):
        if row.label != 1:
            continue
        bucket = buckets.setdefault(
            row.entity_key, {"windows": 0, "windows_flagged": 0, "episodes": {}}
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


def missingness_attribution(
    arm_detection: dict[str, bool],
    indicator_detection: dict[str, bool],
    base_detection: dict[str, bool],
) -> dict[str, Any]:
    """Bound how much of an arm's episode effect the presence indicator alone explains.

    ``share_explained_by_missingness`` is descriptive: it compares the indicator's
    episode gain over ARM A with the arm's own gain over ARM A. It is not a causal
    decomposition, and it is undefined when the arm shows no gain.
    """
    episodes = sorted(base_detection)
    if not (set(arm_detection) == set(indicator_detection) == set(base_detection)):
        raise ContentBenchmarkError("attribution requires identical episode ids")
    base = sum(base_detection[e] for e in episodes)
    arm = sum(arm_detection[e] for e in episodes)
    indicator = sum(indicator_detection[e] for e in episodes)
    arm_gain = arm - base
    indicator_gain = indicator - base
    share: float | None = None
    if arm_gain > 0:
        share = indicator_gain / arm_gain
    return {
        "episodes": len(episodes),
        "episodes_detected_arm_a": base,
        "episodes_detected_arm": arm,
        "episodes_detected_indicator_only": indicator,
        "arm_gain_over_a": arm_gain,
        "indicator_gain_over_a": indicator_gain,
        "share_explained_by_missingness": share,
        "arm_and_indicator_detect_the_same_episodes": all(
            arm_detection[e] == indicator_detection[e] for e in episodes
        ),
        "interpretation": (
            "the arm shows no episode gain over ARM A, so no attribution is defined"
            if arm_gain <= 0
            else "a share at or above 1.0 means the presence indicator alone reproduces "
            "the whole gain, so the gain cannot be credited to the metric value"
        ),
    }
