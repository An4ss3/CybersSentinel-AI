"""Final validation — Step 5: ARM F extension under the established protocol.

Question
--------
Does the frozen ARM F feature budget carry information that lifts the ceiling
observed with the five volume features, in particular on the zero-day Ares
transfer?

Naming, ratified 2026-08-27
---------------------------
``VOL5``    the five frozen volume features. This is the historical P1 baseline.
``ARM_A``   reserved for the repository's historical definition, the single
            feature ``distinct_payload_ratio``. It is **not** VOL5 and is not an
            arm of this experiment.
``ARM_F``   the canonical Phase 1 budget: ``distinct_payload_ratio`` plus the
            source and destination non-printable ratios, fitted with the frozen
            fixed XGBoost parameters. The Phase 2 R006 variant is **not** used.

Arms
----
=================  ==========================  ==========  =====================
arm                features                    learner     role
=================  ==========================  ==========  =====================
``VOL5_RF``        5 volume                    RandomForest historical pipeline,
                                                           results reused from
                                                           Step 2, never refitted
``VOL5_XGB``       5 volume                    XGBoost     **control**: same
                                                           learner as ARM F, so the
                                                           feature effect becomes
                                                           identifiable
``ARMF_XGB``       3 ARM F                     XGBoost     the budget under test
``VOL5_ARMF_XGB``  5 volume + 3 ARM F          XGBoost     union, exploratory
=================  ==========================  ==========  =====================

Why ``VOL5_XGB`` exists
-----------------------
``VOL5_RF`` and ``ARMF_XGB`` differ in **both** features and learner, so their
difference is a pipeline comparison and cannot attribute anything to the feature
budget. ``VOL5_XGB`` holds the learner constant, which is the only construction
here that makes the feature-budget contribution identifiable. Without it, no
statement about ARM F features would be defensible.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from hashlib import sha256
import json
import math
from typing import Any, Final, Sequence

import numpy as np
from sklearn.metrics import average_precision_score, roc_auc_score

from modules.detection.src.experiments.content_benchmark import build_model, matrix
from modules.detection.src.experiments.final_validation_eval import (
    FORBIDDEN_MODEL_INPUTS,
    PRIMARY_FPR_TARGET,
    TRAINING_ORDER,
    FoldData,
    canonical_digest,
)
from modules.detection.src.experiments.p1_dataset import FEATURE_NAMES, Row
from modules.detection.src.experiments.p1_evaluation import (
    BOOTSTRAP_RESAMPLES,
    BOOTSTRAP_SEED,
    FPR_TARGETS,
    episode_bootstrap_recall,
    episode_recall,
    threshold_at_train_fpr,
)
from modules.detection.src.experiments.ratification import ARM_A_FEATURES, ARM_F_FEATURES
from modules.detection.src.experiments.xgb_baseline import XGB_PARAMS

#: The base content feature that has to be rebuilt from canonical events.
BASE_FEATURE: Final[str] = "distinct_payload_ratio"

#: The six persisted content metrics, joined by frozen row id.
PERSISTED_CONTENT_FEATURES: Final[tuple[str, ...]] = (
    "source_payload_entropy_normalized",
    "destination_payload_entropy_normalized",
    "source_non_printable_ratio",
    "destination_non_printable_ratio",
    "payload_prefix_repeat_ratio",
    "normalized_header_template_repeat_ratio",
)

#: Arm name -> ordered feature budget.
ARM_BUDGETS: Final[dict[str, tuple[str, ...]]] = {
    "VOL5_XGB": FEATURE_NAMES,
    "ARMF_XGB": ARM_F_FEATURES,
    "VOL5_ARMF_XGB": FEATURE_NAMES + ARM_F_FEATURES,
}

#: Arms fitted by this step. VOL5_RF is read from Step 2 and never refitted.
FITTED_ARMS: Final[tuple[str, ...]] = ("VOL5_XGB", "ARMF_XGB", "VOL5_ARMF_XGB")
REUSED_ARM: Final[str] = "VOL5_RF"

#: Protocols evaluated, in reporting order.
PROTOCOL_ORDER: Final[tuple[str, ...]] = (
    "A_historical",
    "B_entity_disjoint",
    "C_episode_disjoint_botnet_ares",
    "D_zero_day_ares",
)

ARES: Final[str] = "botnet/ares"


class ArmFExtensionError(RuntimeError):
    """A canonical definition, guard or reproduction gate failed."""


@dataclass(frozen=True, slots=True)
class ArmResult:
    arm: str
    protocol: str
    fold: int
    record: dict[str, Any]


def verify_canonical_definitions() -> list[dict[str, Any]]:
    """Refuse to run unless every canonical definition is exactly as ratified."""
    checks: list[dict[str, Any]] = []

    def record(name: str, passed: bool, detail: Any) -> None:
        checks.append({"check": name, "passed": bool(passed), "detail": detail})
        if not passed:
            raise ArmFExtensionError(f"{name}: {detail}")

    record(
        "arm_f_budget_is_canonical",
        ARM_F_FEATURES
        == (
            "distinct_payload_ratio",
            "source_non_printable_ratio",
            "destination_non_printable_ratio",
        ),
        list(ARM_F_FEATURES),
    )
    record(
        "arm_a_is_the_single_content_feature_not_vol5",
        ARM_A_FEATURES == (BASE_FEATURE,) and ARM_A_FEATURES != FEATURE_NAMES,
        list(ARM_A_FEATURES),
    )
    record(
        "vol5_is_the_five_frozen_volume_features",
        FEATURE_NAMES
        == (
            "event_count",
            "source_packets_total",
            "destination_packets_total",
            "source_bytes_total",
            "destination_bytes_total",
        ),
        list(FEATURE_NAMES),
    )
    record(
        "phase1_xgboost_parameters_are_canonical",
        XGB_PARAMS["n_estimators"] == 200
        and XGB_PARAMS["max_depth"] == 3
        and XGB_PARAMS["learning_rate"] == 0.1
        and XGB_PARAMS["subsample"] == 1.0
        and XGB_PARAMS["colsample_bytree"] == 1.0
        and XGB_PARAMS["scale_pos_weight"] == 1
        and XGB_PARAMS["random_state"] == 0
        and XGB_PARAMS["n_jobs"] == 1
        and XGB_PARAMS["tree_method"] == "exact"
        and XGB_PARAMS["objective"] == "binary:logistic",
        dict(XGB_PARAMS),
    )
    record(
        "union_arm_is_exactly_vol5_then_arm_f",
        ARM_BUDGETS["VOL5_ARMF_XGB"] == FEATURE_NAMES + ARM_F_FEATURES
        and len(ARM_BUDGETS["VOL5_ARMF_XGB"]) == 8,
        list(ARM_BUDGETS["VOL5_ARMF_XGB"]),
    )
    record(
        "no_forbidden_metadata_is_a_feature",
        not (set(FORBIDDEN_MODEL_INPUTS) & set(ARM_BUDGETS["VOL5_ARMF_XGB"])),
        sorted(FORBIDDEN_MODEL_INPUTS),
    )
    record(
        "base_feature_must_be_rebuilt_not_read_from_csv",
        BASE_FEATURE not in PERSISTED_CONTENT_FEATURES,
        BASE_FEATURE,
    )
    return checks


def model_description(arm: str) -> dict[str, Any]:
    if arm == REUSED_ARM:
        return {
            "estimator": "RandomForestClassifier",
            "n_estimators": 200,
            "random_state": 0,
            "n_jobs": 1,
            "class_weight": None,
            "source": "reused from Step 2 artifacts, not refitted here",
        }
    return {
        "estimator": "XGBClassifier",
        **{k: v for k, v in sorted(XGB_PARAMS.items())},
        "source": "frozen Phase 1 ARM F parameters, no tuning",
    }


def assemble_arm_rows(
    rows: Sequence[Row],
    base_values: dict[tuple[str, str, int], float],
    content: dict[str, dict[str, float]],
) -> dict[str, list[Row]]:
    """Project the frozen population onto each arm's ordered feature budget.

    Metadata is carried through untouched so episodes, entities and labels stay
    exactly those of the frozen dataset. Content metrics that are undefined stay
    ``NaN`` and reach XGBoost's native missing branch; no imputation is applied.
    """
    volume = dict(zip(FEATURE_NAMES, range(len(FEATURE_NAMES))))
    out: dict[str, list[Row]] = {arm: [] for arm in ARM_BUDGETS}
    for row in rows:
        key = (row.partition, row.entity_key, row.window_start_epoch)
        if key not in base_values:
            raise ArmFExtensionError(f"no P6 reconstruction for frozen row {key!r}")
        if row.row_id not in content:
            raise ArmFExtensionError(f"no content record for frozen row {row.row_id}")
        available: dict[str, float] = {
            BASE_FEATURE: float(base_values[key]),
            **content[row.row_id],
            **{name: float(row.features[index]) for name, index in volume.items()},
        }
        for arm, budget in ARM_BUDGETS.items():
            out[arm].append(
                Row(
                    row_id=row.row_id,
                    source=row.source,
                    label=row.label,
                    disposition=row.disposition,
                    attack_type=row.attack_type,
                    entity_key=row.entity_key,
                    episode_id=row.episode_id,
                    partition=row.partition,
                    window_start_epoch=row.window_start_epoch,
                    features=tuple(available[name] for name in budget),
                )
            )
    for arm, budget in ARM_BUDGETS.items():
        if any(len(r.features) != len(budget) for r in out[arm]):
            raise ArmFExtensionError(f"{arm}: inconsistent feature width")
    return out


def guard_arm_features(rows: Sequence[Row], budget: Sequence[str], where: str) -> None:
    """Assert the exact width of one arm's feature vector before any fit.

    The Step 2 guard is hard-wired to the five VOL5 features, which is correct
    there. It is deliberately not modified: this step owns a width-aware guard so
    the published Step 2 code path stays byte-identical.
    """
    width = len(budget)
    if width not in (3, 5, 8):
        raise ArmFExtensionError(f"{where}: unexpected arm width {width}")
    for row in rows:
        if len(row.features) != width:
            raise ArmFExtensionError(
                f"{where}: row {row.row_id} has {len(row.features)} features, expected {width}"
            )
        for value in row.features:
            if not isinstance(value, float):
                raise ArmFExtensionError(f"{where}: non-float feature in {row.row_id}")
            if math.isinf(value):
                raise ArmFExtensionError(f"{where}: infinite feature in {row.row_id}")


def armf_fold_guards(
    data: FoldData,
    budget: Sequence[str],
    *,
    require_entity_disjoint: bool,
    require_episode_disjoint: bool,
    forbid_family_in_train: str | None = None,
) -> dict[str, Any]:
    """Width-aware twin of the Step 2 fold guards, with identical semantics."""
    guard_arm_features(data.train, budget, f"{data.protocol}/fold{data.fold}/train")
    guard_arm_features(data.test, budget, f"{data.protocol}/fold{data.fold}/test")

    train_ids = {row.row_id for row in data.train}
    test_ids = {row.row_id for row in data.test}
    if train_ids & test_ids:
        raise ArmFExtensionError(
            f"{data.protocol}/fold{data.fold}: {len(train_ids & test_ids)} shared row ids"
        )
    if not data.test:
        raise ArmFExtensionError(f"{data.protocol}/fold{data.fold}: empty test set")

    train_entities = {row.entity_key for row in data.train}
    test_entities = {row.entity_key for row in data.test}
    train_episodes = {row.episode_id for row in data.train if row.label == 1}
    test_episodes = {row.episode_id for row in data.test if row.label == 1}
    entity_intersection = sorted(train_entities & test_entities)
    episode_intersection = sorted(
        str(e) for e in (train_episodes & test_episodes) if e is not None
    )
    if require_entity_disjoint and entity_intersection:
        raise ArmFExtensionError(
            f"{data.protocol}/fold{data.fold}: entity leakage {entity_intersection}"
        )
    if require_episode_disjoint and episode_intersection:
        raise ArmFExtensionError(
            f"{data.protocol}/fold{data.fold}: episode leakage {episode_intersection}"
        )
    if forbid_family_in_train is not None:
        offending = [r for r in data.train if r.attack_type == forbid_family_in_train]
        if offending:
            raise ArmFExtensionError(
                f"{data.protocol}/fold{data.fold}: {len(offending)} "
                f"{forbid_family_in_train} rows present in training"
            )
        held_out_entities = {
            r.entity_key for r in data.test if r.attack_type == forbid_family_in_train
        } & train_entities
        if held_out_entities:
            raise ArmFExtensionError(
                f"{data.protocol}/fold{data.fold}: held-out family entities in "
                f"training: {sorted(held_out_entities)}"
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
        "guarded_feature_width": len(budget),
    }


def evaluate_arm_fold(arm: str, data: FoldData, guards: dict[str, Any]) -> dict[str, Any]:
    """Fit one arm on one fold and measure it under the established rules."""
    budget = ARM_BUDGETS[arm]
    x_train, y_train = matrix(list(data.train), len(budget))
    x_test, y_test = matrix(list(data.test), len(budget))
    model = build_model()
    model.fit(x_train, y_train)
    train_scores = model.predict_proba(x_train)[:, 1]
    test_scores = model.predict_proba(x_test)[:, 1]
    train_negative_scores = train_scores[y_train == 0]
    if train_negative_scores.size == 0:
        raise ArmFExtensionError(f"{arm}/{data.protocol}/fold{data.fold}: no train negative")

    positives = int((y_test == 1).sum())
    negatives = int((y_test == 0).sum())
    points: list[dict[str, Any]] = []
    for target in FPR_TARGETS:
        threshold, achieved = threshold_at_train_fpr(train_negative_scores, target)
        flagged = test_scores >= threshold
        tp = int((flagged & (y_test == 1)).sum())
        fp = int((flagged & (y_test == 0)).sum())
        tn = int((~flagged & (y_test == 0)).sum())
        fn = int((~flagged & (y_test == 1)).sum())
        detected, recall = episode_recall(list(data.test), test_scores, threshold)
        precision = tp / (tp + fp) if (tp + fp) else float("nan")
        window_recall = tp / positives if positives else float("nan")
        f1 = (
            2 * precision * window_recall / (precision + window_recall)
            if (tp + fp) and positives and (precision + window_recall) > 0
            else 0.0
        )
        points.append(
            {
                "target_train_fpr": target,
                "threshold": float(threshold),
                "threshold_calibration_method": (
                    "smallest observed train-negative score achieving the target; "
                    "training negatives only"
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
            }
        )
    primary = next(p for p in points if p["target_train_fpr"] == PRIMARY_FPR_TARGET)
    record = {
        "arm": arm,
        "protocol": data.protocol,
        "fold": data.fold,
        "held_out": data.held_out,
        "feature_names": list(budget),
        "feature_count": len(budget),
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
        "model_parameters": model_description(arm),
        "training_order": TRAINING_ORDER,
        "hyperparameter_tuning": "none",
        "missing_value_policy": "XGBoost native missing branch; no imputation",
        "operating_points": points,
        "episode_bootstrap_resamples": BOOTSTRAP_RESAMPLES,
        "episode_bootstrap_seed": BOOTSTRAP_SEED,
        **{k: v for k, v in primary.items()},
        **guards,
    }
    record["test_scores"] = {
        row.row_id: float(score) for row, score in zip(data.test, test_scores)
    }
    return record


def aggregate_arm(records: Sequence[dict[str, Any]]) -> dict[str, Any]:
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
        "per_fold_roc_auc": [r["roc_auc"] for r in records],
        "per_fold_episode_recall": [r["episode_recall"] for r in records],
        "per_fold_fpr": [r["fpr"] for r in records],
    }


COMPARISON_KEYS: Final[tuple[str, ...]] = (
    "macro_roc_auc",
    "macro_pr_auc",
    "pooled_recall",
    "pooled_precision",
    "pooled_f1",
    "pooled_fpr",
    "pooled_episode_recall",
    "macro_episode_recall",
)


def contrast(left_name: str, left: dict[str, Any], right_name: str, right: dict[str, Any],
             identifiable: bool, note: str) -> dict[str, Any]:
    """A signed ``right - left`` contrast, carrying its own identifiability flag."""
    return {
        "left": left_name,
        "right": right_name,
        "delta": {k: float(right[k] - left[k]) for k in COMPARISON_KEYS},
        "left_values": {k: float(left[k]) for k in COMPARISON_KEYS},
        "right_values": {k: float(right[k]) for k in COMPARISON_KEYS},
        "left_episodes": f"{left['detected_episodes']}/{left['total_episodes']}",
        "right_episodes": f"{right['detected_episodes']}/{right['total_episodes']}",
        "feature_effect_identifiable": identifiable,
        "interpretation": note,
    }


def experiment_configuration() -> dict[str, Any]:
    return {
        "experiment": "final validation — step 5, ARM F extension",
        "question": (
            "does the frozen ARM F budget carry information that lifts the ceiling "
            "observed with VOL5, in particular on zero-day Ares transfer?"
        ),
        "naming": {
            "VOL5": list(FEATURE_NAMES),
            "ARM_A_reserved_historical_definition": list(ARM_A_FEATURES),
            "ARM_F_canonical_phase1": list(ARM_F_FEATURES),
            "phase2_r006_used": False,
        },
        "arms": {
            REUSED_ARM: {
                "features": list(FEATURE_NAMES),
                "learner": "RandomForest",
                "role": "historical pipeline, reused from Step 2, not refitted",
            },
            "VOL5_XGB": {
                "features": list(FEATURE_NAMES),
                "learner": "XGBoost",
                "role": "control arm holding the learner constant",
            },
            "ARMF_XGB": {
                "features": list(ARM_F_FEATURES),
                "learner": "XGBoost",
                "role": "the budget under test",
            },
            "VOL5_ARMF_XGB": {
                "features": list(ARM_BUDGETS["VOL5_ARMF_XGB"]),
                "learner": "XGBoost",
                "role": "union arm, exploratory, reported separately",
            },
        },
        "protocols": list(PROTOCOL_ORDER),
        "model_parameters": {arm: model_description(arm) for arm in
                             (REUSED_ARM, *FITTED_ARMS)},
        "training_order": TRAINING_ORDER,
        "primary_fpr_target": PRIMARY_FPR_TARGET,
        "threshold_calibration": "train negatives only",
        "hyperparameter_tuning": "none",
        "test_set_used_for_any_choice": False,
        "postgresql_access": "read-only, transaction_read_only asserted on",
        "base_feature_reconstruction": (
            "distinct_payload_ratio rebuilt from m4_canonical.flow_end_events and "
            "mb4_canonical.flow_end_events with the unmodified P6 implementation"
        ),
        "identifiability": {
            "VOL5_RF_vs_ARMF_XGB": (
                "pipeline comparison only; features and learner both change, so no "
                "causal attribution to the feature budget is permitted"
            ),
            "VOL5_XGB_vs_ARMF_XGB": (
                "learner held constant, so the difference is attributable to the "
                "feature budget within this population"
            ),
            "ARMF_XGB_vs_VOL5_ARMF_XGB": (
                "learner held constant; measures what adding the volume features to "
                "ARM F contributes"
            ),
        },
        "forbidden_claims": [
            "calling any arm of this step a historical reproduction",
            "reading an improvement on known-family Ares as zero-day generalisation",
            "attributing a VOL5_RF versus ARMF_XGB difference to the features alone",
        ],
    }


def digest(document: Any) -> str:
    return canonical_digest(document)


def strip_scores(record: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in record.items() if k != "test_scores"}
