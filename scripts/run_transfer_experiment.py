"""Execute the pre-registered priority-family transfer protocol.

Runs the protocol frozen in ``docs/canonical/PROTOCOL_PREREGISTRATION_V1.md`` and
``artifacts/experiments/preregistration_v1/protocol_manifest.json`` exactly as
written. Nothing methodological is decided here.

Per fold, in this order and no other:

1. build TRAIN (six other priority families + Monday benign entity folds 0-3)
   and VALIDATION (Monday benign entity fold 4 only);
2. assert the held-out family F contributes zero rows to both, and that Ares,
   Thursday, ``unknown`` and ``ambiguous`` contribute nothing anywhere;
3. fit one model with the frozen P1 hyperparameters;
4. derive the threshold from VALIDATION benign scores only;
5. write an irreversible freeze record including every digest, the threshold and
   the decision rule;
6. **only then** open the holdout and score it once.

Reused frozen code, imported rather than reimplemented:

* ``p1_dataset.negative_fold_of``  -- benign entity partition (decision D4);
* ``p1_evaluation.build_model``    -- hyperparameters (decisions D6, D7);
* ``p1_evaluation.threshold_at_train_fpr`` -- threshold rule (decision D8),
  applied to VALIDATION negatives instead of training negatives, as the
  pre-registration specifies.

Episodes are taken from the ``episode_id`` column already materialised in the
ratified population, which encodes the frozen definition D2.

Usage::

    python -m scripts.run_transfer_experiment
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from collections.abc import Sequence
import csv
from datetime import datetime, timezone
from hashlib import sha256
import json
import math
from pathlib import Path
from typing import Any, Final

import joblib
import numpy as np
from sklearn.metrics import average_precision_score, roc_auc_score

from modules.detection.src.experiments.p1_dataset import (
    FEATURE_NAMES,
    negative_fold_of,
)
from modules.detection.src.experiments.p1_evaluation import (
    build_model,
    threshold_at_train_fpr,
)


REPO_ROOT = Path(__file__).resolve().parents[1]

DATASET_PATH: Final[str] = "artifacts/production/ml_dataset_v2/ml_dataset.csv"
THURSDAY_BENIGN_PATH: Final[str] = (
    "artifacts/production/thursday_audit_v1/thursday_benign_windows.csv"
)
PROTOCOL_PATH: Final[str] = "docs/canonical/PROTOCOL_PREREGISTRATION_V1.md"
MANIFEST_PATH: Final[str] = (
    "artifacts/experiments/preregistration_v1/protocol_manifest.json"
)
OUTPUT_DIR: Final[str] = "artifacts/experiments/transfer_v1"

PRIORITY_FAMILIES: Final[tuple[str, ...]] = (
    "brute_force/ftp_patator",
    "brute_force/ssh_patator",
    "dos/hulk",
    "dos/slowloris",
    "dos/slowhttptest",
    "dos/goldeneye",
    "ddos/loit",
)
EXCLUDED_FAMILIES: Final[frozenset[str]] = frozenset({"botnet/ares"})

BENIGN_TRAIN_FOLDS: Final[frozenset[int]] = frozenset({0, 1, 2, 3})
BENIGN_VALIDATION_FOLDS: Final[frozenset[int]] = frozenset({4})
BENIGN_FOLD_COUNT: Final[int] = 5

PRIMARY_TARGET_FPR: Final[float] = 0.01
SECONDARY_TARGET_FPR: Final[float] = 0.001
FPR_TRANSFER_TOLERANCE: Final[float] = 0.02

THURSDAY_BENIGN_EXPECTED_ROWS: Final[int] = 32_813

REPORTING_TIER: Final[dict[str, str]] = {
    "brute_force/ftp_patator": "descriptive_high_uncertainty",
    "dos/hulk": "descriptive_high_uncertainty",
    "dos/slowloris": "descriptive_high_uncertainty",
    "ddos/loit": "descriptive_high_uncertainty",
    "dos/goldeneye": "descriptive_high_uncertainty",
    "dos/slowhttptest": "weak_statistical_weight",
    "brute_force/ssh_patator": "weak_statistical_weight",
}


class ProtocolViolation(RuntimeError):
    """A pre-registered invariant does not hold. The run must stop."""


def sha256_file(path: Path) -> str:
    """Return the lowercase SHA-256 of a file, streamed."""
    digest = sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(8 * 1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def wilson_interval(successes: int, total: int, z: float = 1.959963984540054) -> tuple[float, float]:
    """Return the Wilson 95 percent interval, correct at 0 and 1."""
    if total == 0:
        return (float("nan"), float("nan"))
    proportion = successes / total
    denominator = 1.0 + z * z / total
    centre = (proportion + z * z / (2 * total)) / denominator
    margin = (
        z
        * math.sqrt(proportion * (1 - proportion) / total + z * z / (4 * total * total))
        / denominator
    )
    return (max(0.0, centre - margin), min(1.0, centre + margin))


def load_population(path: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Split the ratified population into attack rows and benign rows."""
    attacks: list[dict[str, Any]] = []
    benign: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            disposition = row["disposition"]
            if disposition in {"unknown", "ambiguous"}:
                raise ProtocolViolation(
                    "the ratified population must not contain unknown or ambiguous rows"
                )
            if disposition == "benign_reference":
                benign.append(row)
            else:
                attacks.append(row)
    return attacks, benign


def features_of(rows: Sequence[dict[str, Any]]) -> np.ndarray:
    """Project rows onto VOL5 in the frozen column order."""
    if not rows:
        return np.empty((0, len(FEATURE_NAMES)), dtype=float)
    return np.asarray(
        [[float(row[name]) for name in FEATURE_NAMES] for row in rows], dtype=float
    )


def load_thursday_benign(path: Path) -> list[dict[str, Any]]:
    """Load the pinned Thursday holdout negatives, asserting the row gate."""
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            if row["disposition"] != "benign_reference":
                raise ProtocolViolation(
                    "Thursday holdout negatives must all be benign_reference"
                )
            rows.append(row)
    if len(rows) != THURSDAY_BENIGN_EXPECTED_ROWS:
        raise ProtocolViolation(
            f"Thursday negatives must be exactly {THURSDAY_BENIGN_EXPECTED_ROWS} rows, "
            f"got {len(rows)}"
        )
    return rows


def run(repository_root: Path) -> dict[str, Any]:
    """Execute all seven folds and return the consolidated result."""
    dataset_path = repository_root / DATASET_PATH
    thursday_path = repository_root / THURSDAY_BENIGN_PATH
    output_dir = repository_root / OUTPUT_DIR
    output_dir.mkdir(parents=True, exist_ok=True)

    pinned_digests = {
        DATASET_PATH: sha256_file(dataset_path),
        THURSDAY_BENIGN_PATH: sha256_file(thursday_path),
        PROTOCOL_PATH: sha256_file(repository_root / PROTOCOL_PATH),
        MANIFEST_PATH: sha256_file(repository_root / MANIFEST_PATH),
    }

    attacks, benign = load_population(dataset_path)
    thursday = load_thursday_benign(thursday_path)

    # Ares and every non-priority family are removed from the whole experiment.
    priority_attacks = [
        row for row in attacks if row["attack_type"] in set(PRIORITY_FAMILIES)
    ]
    removed = {row["attack_type"] for row in attacks} - set(PRIORITY_FAMILIES)
    if removed != EXCLUDED_FAMILIES:
        raise ProtocolViolation(f"unexpected non-priority families present: {removed}")

    # Benign entity partition, using the frozen function verbatim.
    benign_train = [
        row
        for row in benign
        if negative_fold_of(row["entity_key"], BENIGN_FOLD_COUNT) in BENIGN_TRAIN_FOLDS
    ]
    benign_validation = [
        row
        for row in benign
        if negative_fold_of(row["entity_key"], BENIGN_FOLD_COUNT)
        in BENIGN_VALIDATION_FOLDS
    ]
    if len(benign_train) + len(benign_validation) != len(benign):
        raise ProtocolViolation("benign partition does not cover the population")
    train_entities = {row["entity_key"] for row in benign_train}
    validation_entities = {row["entity_key"] for row in benign_validation}
    if train_entities & validation_entities:
        raise ProtocolViolation("benign TRAIN and VALIDATION entities overlap")

    x_benign_train = features_of(benign_train)
    x_benign_validation = features_of(benign_validation)

    folds: list[dict[str, Any]] = []

    for family in PRIORITY_FAMILIES:
        holdout_positives = [
            row for row in priority_attacks if row["attack_type"] == family
        ]
        train_positives = [
            row for row in priority_attacks if row["attack_type"] != family
        ]
        if any(row["attack_type"] == family for row in train_positives):
            raise ProtocolViolation(f"{family} leaked into TRAIN positives")
        if not holdout_positives:
            raise ProtocolViolation(f"{family} has no holdout positives")

        x_train = np.vstack([features_of(train_positives), x_benign_train])
        y_train = np.concatenate(
            [np.ones(len(train_positives)), np.zeros(len(benign_train))]
        )

        model = build_model()
        model.fit(x_train, y_train)

        validation_scores = model.predict_proba(x_benign_validation)[:, 1]
        threshold, achieved = threshold_at_train_fpr(
            validation_scores, PRIMARY_TARGET_FPR
        )
        threshold_secondary, achieved_secondary = threshold_at_train_fpr(
            validation_scores, SECONDARY_TARGET_FPR
        )

        # Pre-registered sanity checks, recorded, never used to alter anything.
        sanity = {
            "fit_completed": True,
            "no_nan_or_inf_validation_scores": bool(
                np.all(np.isfinite(validation_scores))
            ),
            "validation_score_distribution_not_degenerate": bool(
                np.unique(validation_scores).size > 1
            ),
            "achieved_validation_fpr_at_or_below_target": bool(
                achieved <= PRIMARY_TARGET_FPR
            ),
            "family_absent_from_train_rows": 0,
            "family_absent_from_validation_rows": 0,
        }
        if not all(value is True or value == 0 for value in sanity.values()):
            raise ProtocolViolation(f"sanity check failed for {family}: {sanity}")

        model_path = output_dir / f"model_{family.replace('/', '_')}.joblib"
        joblib.dump(model, model_path)
        model_digest = sha256_file(model_path)

        # ---- IRREVERSIBLE FREEZE, written before the holdout is opened ----
        freeze = {
            "freeze_version": "1.0.0",
            "frozen_at": datetime.now(timezone.utc).isoformat(),
            "held_out_family": family,
            "pinned_digests": pinned_digests,
            "split": {
                "train_positive_windows": len(train_positives),
                "train_positive_episodes": len(
                    {row["episode_id"] for row in train_positives}
                ),
                "train_benign_windows": len(benign_train),
                "train_benign_entities": len(train_entities),
                "validation_benign_windows": len(benign_validation),
                "validation_benign_entities": len(validation_entities),
                "benign_entity_partition": (
                    "p1_dataset.negative_fold_of, folds 0-3 train, fold 4 validation"
                ),
                "train_row_digest": sha256(
                    "|".join(sorted(row["row_id"] for row in train_positives)).encode()
                ).hexdigest(),
                "validation_row_digest": sha256(
                    "|".join(sorted(row["row_id"] for row in benign_validation)).encode()
                ).hexdigest(),
            },
            "hyperparameters": {
                "model": "sklearn.ensemble.RandomForestClassifier",
                "n_estimators": 200,
                "random_state": 0,
                "class_weight": None,
                "selection_performed": False,
                "source": "p1_evaluation.build_model, imported unchanged",
            },
            "model_artifact": str(model_path.relative_to(repository_root)).replace(
                "\\", "/"
            ),
            "model_sha256": model_digest,
            "threshold": {
                "primary_target_fpr": PRIMARY_TARGET_FPR,
                "primary_threshold": threshold,
                "primary_achieved_validation_fpr": achieved,
                "secondary_target_fpr": SECONDARY_TARGET_FPR,
                "secondary_threshold": threshold_secondary,
                "secondary_achieved_validation_fpr": achieved_secondary,
                "calibration_population": "VALIDATION benign only",
                "rule": "p1_evaluation.threshold_at_train_fpr, imported unchanged",
            },
            "decision_rule": "flag(window) := score >= threshold",
            "episode_definition": (
                "maximal run of consecutive 60-second windows sharing the same "
                "(attack_type, entity_key); materialised as episode_id"
            ),
            "exclusions": {
                "ares": "excluded from TRAIN, VALIDATION and HOLDOUT",
                "thursday_web_attack": "never positive, never negative",
                "unknown": "excluded",
                "ambiguous": "excluded",
                "other_folds": "no result of another fold is consulted",
            },
            "sanity_checks": sanity,
            "holdout_opened": False,
        }
        freeze_path = output_dir / f"freeze_{family.replace('/', '_')}.json"
        freeze_path.write_bytes(
            (json.dumps(freeze, indent=2, sort_keys=True) + "\n").encode("utf-8")
        )
        freeze_digest = sha256_file(freeze_path)

        # ================= HOLDOUT OPENED, ONCE, AFTER THE FREEZE ============
        x_holdout_positive = features_of(holdout_positives)
        x_holdout_negative = features_of(thursday)
        positive_scores = model.predict_proba(x_holdout_positive)[:, 1]
        negative_scores = model.predict_proba(x_holdout_negative)[:, 1]

        flagged_positive = positive_scores >= threshold
        window_detected = int(flagged_positive.sum())
        window_total = len(holdout_positives)

        episodes: dict[str, list[bool]] = defaultdict(list)
        for row, flagged in zip(holdout_positives, flagged_positive):
            episodes[row["episode_id"]].append(bool(flagged))
        episode_total = len(episodes)
        episode_detected = sum(1 for flags in episodes.values() if any(flags))

        false_positives = int((negative_scores >= threshold).sum())
        fpr = false_positives / THURSDAY_BENIGN_EXPECTED_ROWS

        y_true = np.concatenate(
            [np.ones(len(positive_scores)), np.zeros(len(negative_scores))]
        )
        y_score = np.concatenate([positive_scores, negative_scores])
        both_classes = bool(len(positive_scores) and len(negative_scores))
        roc_auc = float(roc_auc_score(y_true, y_score)) if both_classes else None
        pr_auc = (
            float(average_precision_score(y_true, y_score)) if both_classes else None
        )
        base_rate = (
            len(positive_scores) / (len(positive_scores) + len(negative_scores))
            if both_classes
            else None
        )

        episode_ci = wilson_interval(episode_detected, episode_total)
        window_ci = wilson_interval(window_detected, window_total)

        folds.append(
            {
                "family": family,
                "reporting_tier": REPORTING_TIER[family],
                "freeze_path": str(freeze_path.relative_to(repository_root)).replace(
                    "\\", "/"
                ),
                "freeze_sha256": freeze_digest,
                "model_sha256": model_digest,
                "threshold": threshold,
                "achieved_validation_fpr": achieved,
                "train_positive_windows": len(train_positives),
                "train_benign_windows": len(benign_train),
                "validation_benign_windows": len(benign_validation),
                "episode_detected": episode_detected,
                "episode_total": episode_total,
                "episode_recall": episode_detected / episode_total,
                "episode_recall_wilson_95": [episode_ci[0], episode_ci[1]],
                "window_detected": window_detected,
                "window_total": window_total,
                "window_recall": window_detected / window_total,
                "window_recall_wilson_95": [window_ci[0], window_ci[1]],
                "thursday_false_positives": false_positives,
                "thursday_benign_windows": THURSDAY_BENIGN_EXPECTED_ROWS,
                "thursday_fpr": fpr,
                "fpr_within_tolerance_2pct": bool(fpr <= FPR_TRANSFER_TOLERANCE),
                "operating_point": (
                    "transfers" if fpr <= FPR_TRANSFER_TOLERANCE else "degrades"
                ),
                "roc_auc": roc_auc,
                "pr_auc": pr_auc,
                "pr_auc_base_rate": base_rate,
            }
        )

    pooled_detected = sum(item["episode_detected"] for item in folds)
    pooled_total = sum(item["episode_total"] for item in folds)
    pooled_ci = wilson_interval(pooled_detected, pooled_total)

    return {
        "experiment": "priority-family transfer, pre-registered protocol v1",
        "executed_at": datetime.now(timezone.utc).isoformat(),
        "pinned_digests": pinned_digests,
        "benign_partition": {
            "train_windows": len(benign_train),
            "train_entities": len(train_entities),
            "validation_windows": len(benign_validation),
            "validation_entities": len(validation_entities),
            "entity_overlap": 0,
        },
        "excluded_from_experiment": {
            "botnet/ares": len([r for r in attacks if r["attack_type"] == "botnet/ares"]),
            "thursday_web_attack": 0,
            "unknown": 0,
            "ambiguous": 0,
        },
        "folds": folds,
        "pooled": {
            "episode_detected": pooled_detected,
            "episode_total": pooled_total,
            "episode_recall": pooled_detected / pooled_total,
            "episode_recall_wilson_95": [pooled_ci[0], pooled_ci[1]],
            "independence_caveat": (
                "the folds are NOT independent: they share entity keys and a common "
                "benign calibration population"
            ),
        },
        "preregistered_criteria_applied": {
            "episode_recall_vs_fpr_comparison": "not performed, forbidden by protocol",
            "fpr_tolerance": FPR_TRANSFER_TOLERANCE,
            "primary_metric": "episode recall at the frozen threshold with Wilson 95 percent interval",
            "threshold_chosen_post_hoc": False,
            "tuning_performed": False,
            "models_compared": 0,
        },
        "guarantees": {
            "holdout_opened_after_freeze": True,
            "holdout_labels_used_to_modify_anything": False,
            "methodological_decision_after_seeing_results": False,
            "frozen_artifacts_modified": False,
            "postgresql_writes": 0,
        },
    }


def build_parser() -> argparse.ArgumentParser:
    """Return the experiment command-line interface."""
    parser = argparse.ArgumentParser(
        description="Execute the pre-registered priority-family transfer protocol."
    )
    parser.add_argument("--repository-root", type=Path, default=REPO_ROOT)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the experiment and publish the consolidated result."""
    args = build_parser().parse_args(argv)
    root = args.repository_root.resolve(strict=True)
    result = run(root)
    destination = root / OUTPUT_DIR / "transfer_results.json"
    destination.write_bytes(
        (json.dumps(result, indent=2, sort_keys=True) + "\n").encode("utf-8")
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
