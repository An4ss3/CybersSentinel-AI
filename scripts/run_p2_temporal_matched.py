"""Run P2/B: the temporal-matched ablation of R1, on the frozen P1 folds.

Exactly one thing differs from P1
---------------------------------
The **composition of the training negatives**. Everything else is reused
unchanged: the same dataset rows, the same five features, the same labels, the
same five leave-one-attack-type-out folds loaded from ``p1_folds.json``, the same
model, the same threshold selector, the same metrics and the same episode-level
bootstrap. **The test set of every fold is byte-identical to P1**, so recall and
false-positive rates are measured on exactly the same observations.

The matching rule, and why it is leak-free
------------------------------------------
A training negative is retained when its 60-second offset-of-day coincides with
the offset of at least one **training** positive.

Decision D11: the matching offsets are derived from the fold's *training*
positives only, never from the held-out type. Using the held-out type's temporal
signature to choose which negatives to train on would let the test attack shape
the training set — a subtle leak. This is the conservative choice and it means
each fold uses a slightly different matched negative set, which is correct: the
covariate being controlled is defined by what the model is allowed to see.

What this measures
------------------
Whether controlling the hour-of-day covariate changes recall per type and per
episode. If recall is stable between P1 and P2, time-of-day was not an exploited
channel. If it drops, P1 was partly reading the clock. This is the most direct
test of R1 available from this evidence.

The reduction in class imbalance is a **side effect** of covariate matching, not
its purpose, and is reported as such. No row is duplicated, weighted or synthesised.
"""
from __future__ import annotations

import argparse
from collections.abc import Sequence
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
from typing import Any, Final

import joblib

from modules.detection.src.experiments.p1_dataset import (
    FEATURE_NAMES,
    FORBIDDEN_COLUMNS,
    P1DatasetError,
    dataset_digest,
    load_negatives,
    load_positives,
)
from modules.detection.src.experiments.p1_evaluation import (
    BOOTSTRAP_RESAMPLES,
    BOOTSTRAP_SEED,
    FPR_TARGETS,
    MODEL_SEED,
    N_ESTIMATORS,
    build_model,
    episode_bootstrap_recall,
    evaluate_fold,
    matrix,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
P1_DIR: Final[Path] = REPO_ROOT / "artifacts" / "experiments" / "p1"
OUT_DIR: Final[Path] = REPO_ROOT / "artifacts" / "experiments" / "p2"
SECONDS_PER_DAY: Final[int] = 86_400

#: Frozen P1 identities this ablation must reuse without alteration.
P1_DATASET_CONTENT_SHA256: Final[str] = (
    "3d7436178da6960ee5effeb4bee85a0b6da5eead9d2babef3c72cb6b7ca9f20d"
)
P1_FOLDS_CONTENT_SHA256: Final[str] = (
    "e463ea7b0eb4985f51369dc3ae19c09821040675aa4b9f9689f8e02545fed95a"
)


def _write_immutable(path: Path, payload: bytes) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() != payload:
            raise FileExistsError(
                f"immutable artifact already exists with different content: {path}"
            )
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


def _csv(rows, header: Sequence[str], project) -> bytes:
    lines = [",".join(header)]
    for row in rows:
        lines.append(",".join(str(v) for v in project(row)))
    return ("\n".join(lines) + "\n").encode("utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    """Run the P2/B temporal-matched ablation on the frozen P1 folds."""
    parser = argparse.ArgumentParser(description="Run the P2/B ablation.")
    parser.add_argument("--preflight", action="store_true")
    args = parser.parse_args(argv)

    started_at = datetime.now(timezone.utc)

    positives = load_positives(str(REPO_ROOT))
    negatives = load_negatives()
    rows = positives + negatives
    index = {r.row_id: r for r in rows}
    digest = dataset_digest(rows)
    if digest != P1_DATASET_CONTENT_SHA256:
        raise P1DatasetError(
            "P2 must run on the identical P1 population; dataset digest is "
            f"{digest}, expected {P1_DATASET_CONTENT_SHA256}"
        )

    p1_folds = json.loads((P1_DIR / "p1_folds.json").read_text(encoding="utf-8"))
    p1_metrics = json.loads((P1_DIR / "p1_metrics.json").read_text(encoding="utf-8"))
    if p1_metrics["folds_content_sha256"] != P1_FOLDS_CONTENT_SHA256:
        raise P1DatasetError("P1 folds digest does not match the frozen value")

    results = []
    comparisons = []
    matching_report = []
    pooled_detection: dict[str, bool] = {}

    for fold in p1_folds:
        fold_index = fold["index"]
        held_out = fold["held_out_attack_type"]
        train_rows = [index[i] for i in fold["train_row_ids"]]
        test_rows = [index[i] for i in fold["test_row_ids"]]

        # D11: matched offsets come from the TRAINING positives only.
        train_positive_offsets = {
            r.window_start_epoch % SECONDS_PER_DAY
            for r in train_rows
            if r.label == 1
        }
        matched_train = [
            r
            for r in train_rows
            if r.label == 1
            or (r.window_start_epoch % SECONDS_PER_DAY) in train_positive_offsets
        ]

        original_negatives = sum(1 for r in train_rows if r.label == 0)
        retained_negatives = sum(1 for r in matched_train if r.label == 0)
        train_positives = sum(1 for r in matched_train if r.label == 1)
        matching_report.append(
            {
                "fold": fold_index,
                "held_out_attack_type": held_out,
                "matched_offsets_from_train_positives": len(train_positive_offsets),
                "train_negatives_p1": original_negatives,
                "train_negatives_p2": retained_negatives,
                "train_negatives_dropped": original_negatives - retained_negatives,
                "retention_rate": round(retained_negatives / original_negatives, 6),
                "train_positives": train_positives,
                "imbalance_p1": round(original_negatives / train_positives, 4),
                "imbalance_p2": round(retained_negatives / train_positives, 4),
                "test_rows_identical_to_p1": True,
            }
        )
        if retained_negatives == 0:
            raise P1DatasetError(f"fold {fold_index} retained no training negative")

        if args.preflight:
            continue

        result = evaluate_fold(fold_index, held_out, matched_train, test_rows)
        results.append(result)
        pooled_detection.update(result.episode_detection)

        model = build_model()
        x_train, y_train = matrix(matched_train)
        model.fit(x_train, y_train)
        model_path = OUT_DIR / f"p2_model_fold{fold_index}.joblib"
        OUT_DIR.mkdir(parents=True, exist_ok=True)
        if not model_path.exists():
            joblib.dump(model, model_path)

        pred_bytes = _csv(
            sorted(result.predictions, key=lambda p: p["row_id"]),
            ("row_id", "label", "disposition", "attack_type", "episode_id", "score"),
            lambda p: (
                p["row_id"], p["label"], p["disposition"], p["attack_type"] or "",
                p["episode_id"] or "", f"{p['score']:.10f}",
            ),
        )
        _write_immutable(OUT_DIR / f"p2_predictions_fold{fold_index}.csv", pred_bytes)

        p1_fold = next(
            f for f in p1_metrics["folds"] if f["held_out_attack_type"] == held_out
        )
        p1_op = p1_fold["operating_points"][0]
        p2_op = result.operating_points[0]
        comparisons.append(
            {
                "held_out_attack_type": held_out,
                "test_positives": result.test_positives,
                "test_negatives": result.test_negatives,
                "test_episodes": result.test_episodes,
                "identical_test_set": (
                    result.test_positives == p1_fold["test_positives"]
                    and result.test_negatives == p1_fold["test_negatives"]
                    and result.test_episodes == p1_fold["test_episodes"]
                ),
                "pr_auc_p1": p1_fold["pr_auc"],
                "pr_auc_p2": result.pr_auc,
                "pr_auc_delta": result.pr_auc - p1_fold["pr_auc"],
                "roc_auc_p1": p1_fold["roc_auc"],
                "roc_auc_p2": result.roc_auc,
                "roc_auc_delta": result.roc_auc - p1_fold["roc_auc"],
                "window_recall_p1": p1_op["window_recall"],
                "window_recall_p2": p2_op["window_recall"],
                "window_recall_delta": p2_op["window_recall"] - p1_op["window_recall"],
                "episode_recall_p1": p1_op["episode_recall"],
                "episode_recall_p2": p2_op["episode_recall"],
                "episode_recall_delta": (
                    p2_op["episode_recall"] - p1_op["episode_recall"]
                ),
                "episode_ci_p1": [
                    p1_op["episode_bootstrap"]["ci_low"],
                    p1_op["episode_bootstrap"]["ci_high"],
                ],
                "episode_ci_p2": [
                    p2_op["episode_bootstrap"]["ci_low"],
                    p2_op["episode_bootstrap"]["ci_high"],
                ],
                "observed_test_fpr_p1": p1_op["observed_test_fpr"],
                "observed_test_fpr_p2": p2_op["observed_test_fpr"],
            }
        )

    if args.preflight:
        print(json.dumps({"status": "preflight_ok",
                          "dataset_content_sha256": digest,
                          "matching": matching_report}, indent=2, sort_keys=True))
        return 0

    pooled_p2 = episode_bootstrap_recall(pooled_detection)
    pooled_p1 = p1_metrics["pooled_episode_recall_at_train_fpr_1pct"]

    metrics = {
        "experiment": "P2/B temporal-matched ablation of R1",
        "started_at": started_at.isoformat(),
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "single_change_versus_p1": (
            "composition of the training negatives only; test sets are identical"
        ),
        "reused_from_p1_unchanged": [
            "dataset rows and labels",
            "the five features",
            "the five leave-one-attack-type-out folds",
            "the test set of every fold",
            f"model RandomForestClassifier(n_estimators={N_ESTIMATORS}, "
            f"random_state={MODEL_SEED}, n_jobs=1, class_weight=None)",
            "threshold selector, calibrated on training negatives only",
            f"episode bootstrap, {BOOTSTRAP_RESAMPLES} resamples, seed {BOOTSTRAP_SEED}",
            f"fpr targets {list(FPR_TARGETS)}",
        ],
        "p1_dataset_content_sha256": P1_DATASET_CONTENT_SHA256,
        "p1_folds_content_sha256": P1_FOLDS_CONTENT_SHA256,
        "features": list(FEATURE_NAMES),
        "forbidden_columns": list(FORBIDDEN_COLUMNS),
        "matching_rule": {
            "id": "D11",
            "rule": (
                "retain a training negative when its 60-second offset-of-day "
                "coincides with the offset of at least one TRAINING positive"
            ),
            "leak_argument": (
                "offsets are taken from the fold's training positives only. Using "
                "the held-out type's offsets would let the test attack shape the "
                "training set."
            ),
            "not_rebalancing": (
                "no row is duplicated, weighted or synthesised. The imbalance "
                "reduction is a side effect of covariate matching."
            ),
        },
        "matching": matching_report,
        "folds": [
            {
                "fold": r.fold,
                "held_out_attack_type": r.held_out_attack_type,
                "train_positives": r.train_positives,
                "train_negatives": r.train_negatives,
                "test_positives": r.test_positives,
                "test_negatives": r.test_negatives,
                "test_episodes": r.test_episodes,
                "pr_auc": r.pr_auc,
                "roc_auc": r.roc_auc,
                "default_threshold": r.default_threshold,
                "operating_points": r.operating_points,
            }
            for r in results
        ],
        "comparison_p1_vs_p2": comparisons,
        "pooled_episode_recall_at_train_fpr_1pct": {
            "p1": pooled_p1,
            "p2": pooled_p2,
            "delta": pooled_p2["point"] - pooled_p1["point"],
        },
        "r1_interpretation_rules": [
            "stable recall between P1 and P2 indicates hour-of-day was not an "
            "exploited channel",
            "a recall drop in P2 indicates P1 was partly reading the clock",
            "the in-sample threshold calibration bias documented in P1 applies "
            "identically here, so recall deltas remain comparable",
            "a change in observed test FPR is expected because the negative "
            "training distribution changed; it is not itself evidence about R1",
        ],
        "postgresql_writes": 0,
    }
    metrics_bytes = json.dumps(metrics, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    metrics_sha = _write_immutable(OUT_DIR / "p2_metrics.json", metrics_bytes)
    matching_bytes = json.dumps(matching_report, indent=2, sort_keys=True).encode(
        "utf-8"
    ) + b"\n"
    _write_immutable(OUT_DIR / "p2_matching.json", matching_bytes)

    print(json.dumps({
        "status": "verified",
        "metrics_file_sha256": metrics_sha,
        "all_test_sets_identical_to_p1": all(
            c["identical_test_set"] for c in comparisons
        ),
        "comparison": [
            {
                "type": c["held_out_attack_type"],
                "episode_recall_p1": round(c["episode_recall_p1"], 4),
                "episode_recall_p2": round(c["episode_recall_p2"], 4),
                "delta": round(c["episode_recall_delta"], 4),
                "window_recall_p1": round(c["window_recall_p1"], 4),
                "window_recall_p2": round(c["window_recall_p2"], 4),
                "pr_auc_p1": round(c["pr_auc_p1"], 4),
                "pr_auc_p2": round(c["pr_auc_p2"], 4),
                "test_fpr_p1": round(c["observed_test_fpr_p1"], 5),
                "test_fpr_p2": round(c["observed_test_fpr_p2"], 5),
            }
            for c in comparisons
        ],
        "train_negative_retention": [
            {
                "type": m["held_out_attack_type"],
                "p1": m["train_negatives_p1"],
                "p2": m["train_negatives_p2"],
                "retained": m["retention_rate"],
                "imbalance_p1": m["imbalance_p1"],
                "imbalance_p2": m["imbalance_p2"],
            }
            for m in matching_report
        ],
        "pooled": metrics["pooled_episode_recall_at_train_fpr_1pct"],
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
