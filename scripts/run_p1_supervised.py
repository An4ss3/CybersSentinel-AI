"""Run P1/A: the supervised leave-one-attack-type-out benchmark.

Materialises everything as files under ``artifacts/experiments/p1/``. Performs
**zero** PostgreSQL writes: the M and MB chains are read only.
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
    MB_DATABASE,
    PRODUCTION_DATABASE,
    P1DatasetError,
    build_folds,
    dataset_digest,
    folds_digest,
    load_negatives,
    load_positives,
    verify_no_leakage,
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
OUT_DIR: Final[Path] = REPO_ROOT / "artifacts" / "experiments" / "p1"

CONSERVATIVE_DECISIONS: Final[list[dict[str, str]]] = [
    {"id": "D1", "decision": "dataset materialised as files, never a PostgreSQL table",
     "reason": "P1 performs zero database writes; the M/MB chains stay byte-identical, "
               "and the M6/MB6 cross-database question is sidestepped without moving data"},
    {"id": "D2", "decision": "episode = maximal run of consecutive 60s windows sharing "
                             "(attack_type, entity_key)",
     "reason": "consecutive windows of one attack are slices of one continuous event; "
               "a gap larger than one window length starts a new episode"},
    {"id": "D3", "decision": "positive folds = the five attack types, leave-one-type-out",
     "reason": "the only grouping that also groups episodes and poses the honest "
               "question of transfer to an unseen attack type"},
    {"id": "D4", "decision": "negative folds = sha256(benign entity_key) mod 5",
     "reason": "no benign entity crosses train/test, and no randomness is involved"},
    {"id": "D5", "decision": "no feature transform of any kind",
     "reason": "the five volume features are handed to the model exactly as stored"},
    {"id": "D6", "decision": f"RandomForestClassifier(n_estimators={N_ESTIMATORS}, "
                             f"random_state={MODEL_SEED}, n_jobs=1)",
     "reason": "scale-invariant so no transform is needed; fixed seed and single "
               "worker make it reproducible; no hyper-parameter search"},
    {"id": "D7", "decision": "class_weight=None",
     "reason": "class weighting is a form of rebalancing and is forbidden; the "
               "1:187.7 imbalance is left exactly as the data presents it"},
    {"id": "D8", "decision": "thresholds derived from training negatives only, at "
                             "target FPR 1% and 0.1%",
     "reason": "no test observation, and in particular no test positive, may "
               "influence an operating point"},
    {"id": "D9", "decision": f"uncertainty bootstrapped over episodes, "
                             f"{BOOTSTRAP_RESAMPLES} resamples, seed {BOOTSTRAP_SEED}",
     "reason": "window-level bootstrap would treat autocorrelated slices as "
               "independent and produce falsely narrow intervals"},
    {"id": "D10", "decision": "metrics reported per fold, therefore per attack type; "
                              "no aggregate that could hide the botnet result",
     "reason": "botnet/ares density is 4.158 events per window against 5.202 for the "
               "benign class, so it is expected to be invisible to volume features"},
]


def _write_immutable(path: Path, payload: bytes) -> str:
    """Create bytes once, durably; accept an identical rerun, reject a change."""
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
    """Build, freeze, verify, train, evaluate and publish P1."""
    parser = argparse.ArgumentParser(description="Run the P1/A supervised benchmark.")
    parser.add_argument("--preflight", action="store_true")
    args = parser.parse_args(argv)

    started_at = datetime.now(timezone.utc)
    positives = load_positives(str(REPO_ROOT))
    negatives = load_negatives()
    rows = positives + negatives
    index = {r.row_id: r for r in rows}
    if len(index) != len(rows):
        raise P1DatasetError("duplicate row_id in the P1 dataset")

    folds = build_folds(positives, negatives)
    checks = verify_no_leakage(folds, index)
    failures = [c for c in checks if c["failures"]]

    summary: dict[str, Any] = {
        "positives": len(positives),
        "negatives": len(negatives),
        "rows": len(rows),
        "attack_types": sorted({r.attack_type for r in positives}),
        "attack_entities": len({r.entity_key for r in positives}),
        "attack_episodes": len({r.episode_id for r in positives}),
        "benign_entities": len({r.entity_key for r in negatives}),
        "dataset_sha256": dataset_digest(rows),
        "folds_sha256": folds_digest(folds),
        "leakage_failures": failures,
        "feature_names": list(FEATURE_NAMES),
    }
    if args.preflight or failures:
        summary["status"] = "preflight_ok" if not failures else "leakage_detected"
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 1 if failures else 0

    # ---------------------------------------------------------------- dataset
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    dataset_header = (
        "row_id", "source", "label", "disposition", "attack_type", "entity_key",
        "episode_id", "partition", "window_start_epoch", *FEATURE_NAMES,
    )
    dataset_bytes = _csv(
        sorted(rows, key=lambda r: (r.label, r.row_id)),
        dataset_header,
        lambda r: (
            r.row_id, r.source, r.label, r.disposition, r.attack_type or "",
            r.entity_key, r.episode_id or "", r.partition, r.window_start_epoch,
            *r.features,
        ),
    )
    dataset_file_sha = _write_immutable(OUT_DIR / "p1_dataset.csv", dataset_bytes)

    folds_bytes = json.dumps(
        [
            {
                "index": f.index,
                "held_out_attack_type": f.held_out_attack_type,
                "train_row_ids": sorted(f.train_row_ids),
                "test_row_ids": sorted(f.test_row_ids),
            }
            for f in folds
        ],
        indent=2,
        sort_keys=True,
    ).encode("utf-8") + b"\n"
    folds_file_sha = _write_immutable(OUT_DIR / "p1_folds.json", folds_bytes)

    leakage_bytes = json.dumps(checks, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    leakage_file_sha = _write_immutable(
        OUT_DIR / "p1_leakage_verification.json", leakage_bytes
    )

    # ------------------------------------------------------------ train/eval
    results = []
    pooled_episode_detection: dict[str, bool] = {}
    for fold in folds:
        train_rows = [index[i] for i in fold.train_row_ids]
        test_rows = [index[i] for i in fold.test_row_ids]
        result = evaluate_fold(
            fold.index, fold.held_out_attack_type, train_rows, test_rows
        )
        results.append(result)
        pooled_episode_detection.update(result.episode_detection)

        model = build_model()
        x_train, y_train = matrix(train_rows)
        model.fit(x_train, y_train)
        model_path = OUT_DIR / f"p1_model_fold{fold.index}.joblib"
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
        _write_immutable(OUT_DIR / f"p1_predictions_fold{fold.index}.csv", pred_bytes)

    pooled = episode_bootstrap_recall(pooled_episode_detection)

    metrics = {
        "experiment": "P1/A supervised leave-one-attack-type-out",
        "started_at": started_at.isoformat(),
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "population": {
            "positives": len(positives),
            "negatives": len(negatives),
            "imbalance_negative_per_positive": round(
                len(negatives) / len(positives), 4
            ),
            "attack_types": summary["attack_types"],
            "attack_entities": summary["attack_entities"],
            "attack_episodes": summary["attack_episodes"],
            "benign_entities": summary["benign_entities"],
        },
        "features": list(FEATURE_NAMES),
        "forbidden_columns": list(FORBIDDEN_COLUMNS),
        "conservative_decisions": CONSERVATIVE_DECISIONS,
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
        "pooled_episode_recall_at_train_fpr_1pct": pooled,
        "limitations": {
            "R11": {
                "status": "major limitation, benchmark possible",
                "attack_types": 5,
                "attack_entities": summary["attack_entities"],
                "attack_host_pairs": 6,
                "attack_episodes": summary["attack_episodes"],
                "target_attack_host_pairs": 1,
                "statement": (
                    "376 attack windows are not 376 independent observations. All "
                    "target_attack windows originate from the single host pair "
                    "172.16.0.1 -> 192.168.10.50, differing only by service. "
                    "Confidence intervals are bootstrapped over episodes for this "
                    "reason, and no claim of generalisation to unseen attacks or "
                    "hosts is permitted."
                ),
            },
            "expected_botnet_blindness": {
                "botnet_events_per_window": 4.158,
                "benign_events_per_window": 5.202,
                "share_of_positives": 0.4707,
                "statement": (
                    "botnet/ares produces 736 events across 177 windows, a density "
                    "BELOW the benign class. The five admitted features are all "
                    "volume measures, so this fold is expected to fail. That is a "
                    "property of the feature budget, not a defect of the protocol, "
                    "and it is why no aggregate metric is reported."
                ),
            },
            "R1": {
                "status": "not resolved, testable by P1 vs P2",
                "statement": (
                    "Day-level confounding channels were excluded by column, but the "
                    "residual effect on learning remains a HYPOTHESIS until the P2 "
                    "temporal-matched ablation is run on identical folds."
                ),
            },
        },
        "permitted_claims": [
            "on this dataset, these features detect attack type X and not type Y",
            "the false-alert rate at this threshold is measured on 70,578 benign windows",
            "episode-level recall is k out of the episodes present in the fold",
        ],
        "forbidden_claims": [
            "generalisation to unseen attacks, hosts or days",
            "any confidence interval computed at window level",
            "model comparison on F1 differences narrower than the episode bootstrap",
            "any mention of false positives on unknown windows",
        ],
        "artifact_sha256": {
            "p1_dataset.csv": dataset_file_sha,
            "p1_folds.json": folds_file_sha,
            "p1_leakage_verification.json": leakage_file_sha,
        },
        "dataset_content_sha256": summary["dataset_sha256"],
        "folds_content_sha256": summary["folds_sha256"],
        "source_databases": {
            "positives": f"{PRODUCTION_DATABASE}.m6_canonical.feature_windows",
            "negatives": f"{MB_DATABASE}.mb6_canonical + mb7_canonical",
        },
        "postgresql_writes": 0,
    }
    metrics_bytes = json.dumps(metrics, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    metrics_sha = _write_immutable(OUT_DIR / "p1_metrics.json", metrics_bytes)

    print(json.dumps({
        "status": "verified",
        "dataset_content_sha256": summary["dataset_sha256"],
        "folds_content_sha256": summary["folds_sha256"],
        "metrics_file_sha256": metrics_sha,
        "positives": len(positives),
        "negatives": len(negatives),
        "attack_episodes": summary["attack_episodes"],
        "leakage_failures": len(failures),
        "folds": [
            {
                "type": r.held_out_attack_type,
                "test_positives": r.test_positives,
                "test_episodes": r.test_episodes,
                "pr_auc": round(r.pr_auc, 6),
                "episode_recall_at_1pct": r.operating_points[0]["episode_recall"],
                "window_recall_at_1pct": round(
                    r.operating_points[0]["window_recall"], 6
                ),
                "observed_test_fpr_at_1pct": round(
                    r.operating_points[0]["observed_test_fpr"], 6
                ),
            }
            for r in results
        ],
        "pooled_episode_recall": pooled,
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
