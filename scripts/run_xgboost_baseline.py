"""XGBoost baseline on ``distinct_payload_ratio``. Read-only against PostgreSQL.

Answers exactly one question: on the frozen protocol, can XGBoost exploit the signal
carried by ``distinct_payload_ratio`` to actually improve episode-level detection of
``botnet/ares``?

Nothing in the design is reopened. The population, the labels, the folds and every
test set are the frozen ones, and the runner **proves** that before fitting anything:

* the dataset content digest must equal P1's;
* the folds content digest must equal P1's;
* every fold's membership must equal ``p1_folds.json`` exactly, as sets;
* every test set's ``(row_id, label)`` pairs must equal P1's published predictions;
* no ``unknown`` and no ``ambiguous`` row may appear anywhere;
* no attack type, episode or benign entity may cross train and test.

Any failure aborts before a model is built.
"""
from __future__ import annotations

import argparse
from collections.abc import Sequence
import csv
from dataclasses import replace
from datetime import UTC, datetime
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
from typing import Any, Final

import joblib

from modules.detection.src.experiments.p1_dataset import (
    FORBIDDEN_COLUMNS,
    MB_DATABASE,
    PRODUCTION_DATABASE,
    Row,
    build_folds,
    dataset_digest,
    folds_digest,
    load_negatives,
    load_positives,
)
from modules.detection.src.experiments.p1_evaluation import FPR_TARGETS
from modules.detection.src.experiments.p6_feature_audit import compute, fetch_events
from modules.detection.src.experiments.xgb_baseline import (
    BOOTSTRAP_DECLARATION,
    FEATURE_NAME,
    XGB_PARAMS,
    evaluate_fold,
    per_entity_recall,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
P1_DIR: Final[Path] = REPO_ROOT / "artifacts" / "experiments" / "p1"
P5_DIR: Final[Path] = REPO_ROOT / "artifacts" / "experiments" / "p5"
P6_DIR: Final[Path] = REPO_ROOT / "artifacts" / "experiments" / "p6"
OUT_DIR: Final[Path] = REPO_ROOT / "artifacts" / "experiments" / "xgboost_baseline"

P1_DATASET_SHA256: Final[str] = (
    "3d7436178da6960ee5effeb4bee85a0b6da5eead9d2babef3c72cb6b7ca9f20d"
)
P1_FOLDS_SHA256: Final[str] = (
    "e463ea7b0eb4985f51369dc3ae19c09821040675aa4b9f9689f8e02545fed95a"
)
PRIMARY_ENDPOINT: Final[str] = "botnet/ares"

#: Published references, for comparison only. Never recomputed, never modified.
REFERENCES: Final[dict[str, dict[str, Any]]] = {
    "P1": {"episode_recall": 0.075, "episodes_detected": 3, "episodes": 40,
           "roc_auc": 0.5037, "features": 5},
    "P5": {"episode_recall": 0.150, "episodes_detected": 6, "episodes": 40,
           "roc_auc": 0.5119, "features": 8},
}

DECISIONS: Final[list[dict[str, str]]] = [
    {"id": "D17", "decision": "scale_pos_weight = 1, no class rebalancing",
     "reason": "ratified D7 forbids class weighting as a form of rebalancing; "
               "scale_pos_weight is its direct analogue, so it is pinned to 1 and "
               "the 1:187.7 imbalance is left exactly as the data presents it"},
    {"id": "D18", "decision": "subsample = 1.0 and colsample_bytree = 1.0",
     "reason": "both stochastic regularisers disabled, which removes every source "
               "of randomness from fitting; with one feature colsample_bytree "
               "could not be below 1.0 anyway"},
    {"id": "D19", "decision": "n_estimators = 200",
     "reason": "matches P1's ensemble size so a difference is attributable to the "
               "learner and the feature rather than to capacity"},
    {"id": "D20", "decision": "max_depth = 3",
     "reason": "with one feature a tree can only threshold that feature, so depth "
               "controls the number of available thresholds and nothing else; "
               "three is below the library default of six and is not tuned"},
    {"id": "D21", "decision": "learning_rate = 0.1, no early stopping",
     "reason": "below the library default of 0.3; early stopping would require a "
               "validation split, which would be a protocol change"},
    {"id": "D22", "decision": 'eval_metric = "logloss", recorded only',
     "reason": "consistent with the objective; nothing selects on it because there "
               "is no validation set and no search"},
    {"id": "D23", "decision": "the frozen folds are reconstructed to recover P1's "
                              "row order, then proven identical to p1_folds.json",
     "reason": "p1_folds.json stores sorted(train_row_ids) while P1 trained on the "
               "order build_folds produces; the P5 run showed that loading the file "
               "naively reproduces the split but not the ordering, which would "
               "confound a model comparison with a row-ordering effect"},
]


def _publish_report(path: Path, report: dict[str, Any]) -> tuple[str, str]:
    """Publish once. Idempotent on content, which excludes the clock fields."""
    identity = {
        k: v for k, v in report.items()
        if k not in ("started_at", "completed_at", "content_sha256")
    }
    report = dict(report)
    report["content_sha256"] = sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    payload = json.dumps(report, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        existing = json.loads(path.read_text(encoding="utf-8"))
        if existing.get("content_sha256") != report["content_sha256"]:
            raise FileExistsError(
                f"immutable artifact exists with different content: {path}"
            )
        return report["content_sha256"], sha256(path.read_bytes()).hexdigest()
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
    return report["content_sha256"], sha256(payload).hexdigest()


def _publish_bytes(path: Path, payload: bytes) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() != payload:
            raise FileExistsError(f"immutable artifact differs: {path}")
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


class ProtocolViolation(RuntimeError):
    """The frozen protocol was not reproduced exactly. Nothing may be fitted."""


def verify_protocol(
    rows: list[Row], folds: list[Any]
) -> list[dict[str, Any]]:
    """Prove the population, the folds and every test set are the frozen ones."""
    checks: list[dict[str, Any]] = []

    def record(name: str, passed: bool, detail: str) -> None:
        checks.append({"check": name, "passed": bool(passed), "detail": detail})
        if not passed:
            raise ProtocolViolation(f"{name}: {detail}")

    digest = dataset_digest(rows)
    record("population_content_digest_matches_p1", digest == P1_DATASET_SHA256, digest)

    fdigest = folds_digest(folds)
    record("folds_content_digest_matches_p1", fdigest == P1_FOLDS_SHA256, fdigest)

    dispositions = {r.disposition for r in rows}
    record(
        "no_unknown_or_ambiguous_anywhere",
        not (dispositions & {"unknown", "ambiguous"}),
        f"dispositions present: {sorted(dispositions)}",
    )
    record(
        "negatives_are_only_benign_reference",
        all(r.disposition == "benign_reference" for r in rows if r.label == 0),
        "every negative is benign_reference",
    )

    published = sorted(
        json.loads((P1_DIR / "p1_folds.json").read_text(encoding="utf-8")),
        key=lambda f: f["index"],
    )
    ordered = sorted(folds, key=lambda f: f.index)
    record(
        "fold_count_matches_published_file",
        len(published) == len(ordered) == 5,
        f"{len(ordered)} folds",
    )
    for rebuilt, stored in zip(ordered, published):
        tag = f"fold{rebuilt.index}"
        record(
            f"{tag}_holds_out_the_published_attack_type",
            rebuilt.held_out_attack_type == stored["held_out_attack_type"],
            rebuilt.held_out_attack_type,
        )
        record(
            f"{tag}_train_membership_identical_to_published",
            set(rebuilt.train_row_ids) == set(stored["train_row_ids"]),
            f"{len(rebuilt.train_row_ids)} training rows",
        )
        record(
            f"{tag}_test_membership_identical_to_published",
            set(rebuilt.test_row_ids) == set(stored["test_row_ids"]),
            f"{len(rebuilt.test_row_ids)} test rows",
        )

    # The strongest available check: the test sets must agree with P1's published
    # predictions on both row_id and label, so a comparison is attributable to the
    # model rather than to a changed evaluation set.
    by_id = {r.row_id: r for r in rows}
    for fold in ordered:
        path = P1_DIR / f"p1_predictions_fold{fold.index}.csv"
        with path.open(newline="", encoding="utf-8") as handle:
            published_rows = {
                line["row_id"]: int(line["label"]) for line in csv.DictReader(handle)
            }
        mine = {row_id: by_id[row_id].label for row_id in fold.test_row_ids}
        record(
            f"fold{fold.index}_test_set_identical_to_p1_predictions",
            mine == published_rows,
            f"{len(mine)} rows, labels agree",
        )

    # Leakage: nothing may cross train and test.
    for fold in ordered:
        train_ids, test_ids = set(fold.train_row_ids), set(fold.test_row_ids)
        train = [by_id[i] for i in train_ids]
        test = [by_id[i] for i in test_ids]
        record(f"fold{fold.index}_no_shared_window", not (train_ids & test_ids), "0")
        record(
            f"fold{fold.index}_no_shared_attack_type",
            not (
                {r.attack_type for r in train if r.label == 1}
                & {r.attack_type for r in test if r.label == 1}
            ),
            "0",
        )
        record(
            f"fold{fold.index}_no_shared_episode",
            not (
                {r.episode_id for r in train if r.episode_id}
                & {r.episode_id for r in test if r.episode_id}
            ),
            "0",
        )
        record(
            f"fold{fold.index}_no_shared_benign_entity",
            not (
                {r.entity_key for r in train if r.label == 0}
                & {r.entity_key for r in test if r.label == 0}
            ),
            "0",
        )
    return checks


def build_single_feature_rows(rows: list[Row]) -> list[Row]:
    """Replace every row's features with the single retained feature."""
    m4 = fetch_events(PRODUCTION_DATABASE, "m4_canonical.flow_end_events")
    mb4 = fetch_events(MB_DATABASE, "mb4_canonical.flow_end_events")
    table: dict[tuple[str, str, int], dict[str, float]] = {}
    table.update(compute(m4, (FEATURE_NAME,)))
    table.update(compute(mb4, (FEATURE_NAME,)))

    out: list[Row] = []
    for row in rows:
        key = (row.partition, row.entity_key, row.window_start_epoch)
        found = table.get(key)
        if found is None:
            raise ProtocolViolation(
                f"no events reconstructed for window {key!r}; refusing to impute"
            )
        out.append(replace(row, features=(float(found[FEATURE_NAME]),)))
    return out


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="XGBoost baseline, one feature.")
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    if not (args.preflight or args.execute):
        parser.error("choose --preflight or --execute")

    started = datetime.now(UTC).isoformat()

    print("loading the frozen population read-only ...")
    positives = load_positives(str(REPO_ROOT))
    negatives = load_negatives()
    rows = positives + negatives
    folds = build_folds(positives, negatives)

    print("verifying the frozen protocol before fitting anything ...")
    try:
        checks = verify_protocol(rows, folds)
    except ProtocolViolation as error:
        print(f"PROTOCOL VIOLATION: {error}", file=sys.stderr)
        return 2
    print(f"  {len(checks)} checks passed")

    print(f"deriving the single feature {FEATURE_NAME} read-only ...")
    single = build_single_feature_rows(rows)
    widths = {len(r.features) for r in single}
    if widths != {1}:
        print(f"unexpected feature widths {widths}", file=sys.stderr)
        return 2
    print(f"  every row carries exactly 1 feature")

    if args.preflight:
        print()
        print("PREFLIGHT ONLY. Nothing was fitted, nothing was written.")
        return 0

    by_id = {r.row_id: r for r in single}
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    results = []
    per_entity_report: dict[str, Any] = {}
    print()
    print("fitting the baseline per fold ...")
    for fold in sorted(folds, key=lambda f: f.index):
        train = [by_id[i] for i in fold.train_row_ids]
        test = [by_id[i] for i in fold.test_row_ids]
        result = evaluate_fold(
            fold.index, fold.held_out_attack_type, train, test
        )
        point = result.operating_points[0]
        print(
            f"  {result.held_out_attack_type:26} "
            f"roc {result.roc_auc:.4f}  pr {result.pr_auc:.4f}  "
            f"win {point['window_recall']:.4f}  "
            f"ep {point['episode_recall']:.4f} "
            f"({len(point['episodes_detected'])}/{result.test_episodes})  "
            f"fpr {point['observed_test_fpr']:.6f}  thr {point['threshold']:.6f}"
        )

        joblib.dump(
            result.model, OUT_DIR / f"xgb_model_fold{fold.index}.joblib"
        )
        lines = ["row_id,label,disposition,attack_type,episode_id,score\n"]
        for record in result.predictions:
            lines.append(
                f"{record['row_id']},{record['label']},{record['disposition']},"
                f"{record['attack_type']},{record['episode_id']},"
                f"{record['score']}\n"
            )
        _publish_bytes(
            OUT_DIR / f"xgb_predictions_fold{fold.index}.csv",
            "".join(lines).encode("utf-8"),
        )

        import numpy as np

        scores = np.asarray([float(p["score"]) for p in result.predictions])
        per_entity_report[result.held_out_attack_type] = {
            f"target_{target}": per_entity_recall(
                test, scores, result.operating_points[index]["threshold"]
            )
            for index, target in enumerate(FPR_TARGETS)
        }

        results.append(
            {
                "fold": result.fold,
                "held_out_attack_type": result.held_out_attack_type,
                "train_positives": result.train_positives,
                "train_negatives": result.train_negatives,
                "test_positives": result.test_positives,
                "test_negatives": result.test_negatives,
                "test_episodes": result.test_episodes,
                "roc_auc": result.roc_auc,
                "pr_auc": result.pr_auc,
                "operating_points": result.operating_points,
            }
        )

    primary = next(
        r for r in results if r["held_out_attack_type"] == PRIMARY_ENDPOINT
    )
    primary_point = primary["operating_points"][0]
    boot = primary_point["episode_bootstrap"]

    pooled: dict[str, bool] = {}
    for entry in results:
        point = entry["operating_points"][0]
        for episode in point["episodes_detected"]:
            pooled[episode] = True
        for episode in point["episodes_missed"]:
            pooled.setdefault(episode, False)

    report = {
        "experiment": "XGBoost baseline on the single feature retained by P6",
        "question": (
            "on the frozen protocol, can XGBoost exploit the signal carried by "
            "distinct_payload_ratio to actually improve episode-level detection of "
            "botnet/ares?"
        ),
        "started_at": started,
        "completed_at": datetime.now(UTC).isoformat(),
        "postgresql_writes": 0,
        "feature": FEATURE_NAME,
        "feature_count": 1,
        "features_added_beyond_p6": [],
        "hyperparameter_search": False,
        "early_stopping": False,
        "ensembling": False,
        "resampling_or_smote": False,
        "class_rebalancing": False,
        "new_split_created": False,
        "labels_modified": False,
        "unknown_or_ambiguous_as_negative": False,
        "model_parameters": XGB_PARAMS,
        "conservative_decisions": DECISIONS,
        "threshold_rule": (
            "smallest observed training-negative score achieving the target FPR; "
            "training negatives only, no test observation involved (ratified D8)"
        ),
        "fpr_targets": list(FPR_TARGETS),
        "bootstrap": BOOTSTRAP_DECLARATION,
        "p1_dataset_content_sha256": P1_DATASET_SHA256,
        "p1_folds_content_sha256": P1_FOLDS_SHA256,
        "protocol_verification": checks,
        "forbidden_columns": list(FORBIDDEN_COLUMNS),
        "folds": results,
        "per_entity_recall": per_entity_report,
        "pooled_episode_recall_at_train_fpr_1pct": {
            "episodes": len(pooled),
            "detected": sum(pooled.values()),
            "recall": sum(pooled.values()) / len(pooled) if pooled else float("nan"),
        },
        "primary_endpoint": {
            "attack_type": PRIMARY_ENDPOINT,
            "unit": "episode-level recall",
            "target_train_fpr": primary_point["target_train_fpr"],
            "episode_recall": primary_point["episode_recall"],
            "episodes_detected": len(primary_point["episodes_detected"]),
            "episodes_total": primary["test_episodes"],
            "ci_low": boot["ci_low"],
            "ci_high": boot["ci_high"],
            "roc_auc": primary["roc_auc"],
            "pr_auc": primary["pr_auc"],
            "observed_test_fpr": primary_point["observed_test_fpr"],
            "threshold": primary_point["threshold"],
            "references": REFERENCES,
        },
        "limitations": [
            "R11 unchanged: only 5 botnet entities, all reaching the single "
            "destination 205.174.165.73, so host-pair diversity remains limited",
            "performance here is not proof of universal generalisation",
            "distinct_payload_ratio is a candidate justified by P6, not yet "
            "evidence of generalisable detection",
            "a recall rise alone is not evidence of better discrimination; it must "
            "be read together with ROC-AUC, PR-AUC and the observed FPR",
            "the botnet endpoint rests on 40 episodes, so the bootstrap interval is "
            "wide and small differences are not resolvable",
        ],
    }

    content, file_digest = _publish_report(OUT_DIR / "xgb_metrics.json", report)

    manifest = {
        "artifact": "XGBoost baseline reproducibility manifest",
        "feature": FEATURE_NAME,
        "model_parameters": XGB_PARAMS,
        "library_versions": {},
        "inputs": {
            "p1_dataset_content_sha256": P1_DATASET_SHA256,
            "p1_folds_content_sha256": P1_FOLDS_SHA256,
            "p1_folds_file": sha256(
                (P1_DIR / "p1_folds.json").read_bytes()
            ).hexdigest(),
            "p6_feature_audit_file": sha256(
                (P6_DIR / "p6_feature_audit.json").read_bytes()
            ).hexdigest(),
            "p5_metrics_file": sha256(
                (P5_DIR / "p5_metrics.json").read_bytes()
            ).hexdigest(),
        },
        "postgresql_writes": 0,
        "read_only_transactions": True,
        "protocol_checks_passed": len(checks),
    }
    import sklearn
    import xgboost
    import numpy

    manifest["library_versions"] = {
        "xgboost": xgboost.__version__,
        "scikit-learn": sklearn.__version__,
        "numpy": numpy.__version__,
        "joblib": joblib.__version__,
        "python": sys.version.split()[0],
    }
    outputs = {}
    for path in sorted(OUT_DIR.glob("*")):
        if path.name == "xgb_reproducibility_manifest.json":
            continue
        outputs[path.name] = sha256(path.read_bytes()).hexdigest()
    manifest["outputs"] = outputs
    manifest_digest = _publish_bytes(
        OUT_DIR / "xgb_reproducibility_manifest.json",
        json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8") + b"\n",
    )

    print()
    print("=== PRIMARY ENDPOINT: botnet/ares episode recall @1% train FPR ===")
    print(f"  P1 reference  0.0750  (3/40)   ROC 0.5037   5 features")
    print(f"  P5 reference  0.1500  (6/40)   ROC 0.5119   8 features")
    print(
        f"  XGBoost       {primary_point['episode_recall']:.4f}  "
        f"({len(primary_point['episodes_detected'])}/{primary['test_episodes']})   "
        f"ROC {primary['roc_auc']:.4f}   1 feature"
    )
    print(
        f"  CI 95%        [{boot['ci_low']:.4f}, {boot['ci_high']:.4f}]   "
        f"PR {primary['pr_auc']:.4f}   "
        f"FPR {primary_point['observed_test_fpr']:.6f}"
    )
    print()
    print(f"xgb_metrics.json content {content[:16]}  file {file_digest[:16]}")
    print(f"xgb_reproducibility_manifest.json {manifest_digest[:16]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
