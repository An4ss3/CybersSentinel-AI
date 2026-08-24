"""Run P4/C: the conservative benchmark, a robustness control on P1.

Design, as ratified
-------------------
Exclude every attack window whose **entity** carries more than one attack family,
then repeat the P1 protocol exactly. Two of the nine attack entities are
multi-family:

* ``172.16.0.1|192.168.10.50|tcp|none``  — ssh_patator + ddos/loit + dos/hulk
* ``172.16.0.1|192.168.10.50|tcp|http``  — ddos/loit + dos/hulk

Removing them removes the entities whose windows cannot be attributed to a single
phenomenon, at the cost of a smaller and less diverse positive class.

**What this controls for.** P1's leave-one-attack-type-out folds place different
windows of the *same entity* on opposite sides of the split whenever that entity
spans several families. That is not episode leakage — episodes are type-scoped and
verified disjoint — but it does mean the model can see one behaviour of an entity
while being tested on another behaviour of the same entity. P4 removes that
possibility entirely.

Everything else is identical to P1: the same five features, the same labels, the
same negatives, the same negative fold assignment, the same model, the same
threshold selector, the same episode bootstrap. **Only the positive population
changes**, and it changes by exclusion only — nothing is added, duplicated,
weighted or synthesised.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
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
    Row,
    build_folds,
    dataset_digest,
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
P1_DIR: Final[Path] = REPO_ROOT / "artifacts" / "experiments" / "p1"
OUT_DIR: Final[Path] = REPO_ROOT / "artifacts" / "experiments" / "p4"

P1_DATASET_CONTENT_SHA256: Final[str] = (
    "3d7436178da6960ee5effeb4bee85a0b6da5eead9d2babef3c72cb6b7ca9f20d"
)


def _write_immutable(path: Path, payload: bytes) -> str:
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


def _csv(rows, header: Sequence[str], project) -> bytes:
    lines = [",".join(header)]
    for row in rows:
        lines.append(",".join(str(v) for v in project(row)))
    return ("\n".join(lines) + "\n").encode("utf-8")


def families_per_entity(positives: list[Row]) -> dict[str, set[str]]:
    """Return the set of attack families observed for each attack entity."""
    mapping: dict[str, set[str]] = defaultdict(set)
    for row in positives:
        if row.attack_type:
            mapping[row.entity_key].add(row.attack_type)
    return dict(mapping)


def main(argv: Sequence[str] | None = None) -> int:
    """Restrict positives to single-family entities and repeat P1 exactly."""
    parser = argparse.ArgumentParser(description="Run the P4/C conservative control.")
    parser.add_argument("--preflight", action="store_true")
    args = parser.parse_args(argv)

    started_at = datetime.now(timezone.utc)

    positives = load_positives(str(REPO_ROOT))
    negatives = load_negatives()
    digest = dataset_digest(positives + negatives)
    if digest != P1_DATASET_CONTENT_SHA256:
        raise P1DatasetError(
            f"P4 must start from the identical P1 population; digest {digest}"
        )

    per_entity = families_per_entity(positives)
    multi_family = {k: sorted(v) for k, v in per_entity.items() if len(v) > 1}
    retained_positives = [
        r for r in positives if len(per_entity[r.entity_key]) == 1
    ]
    excluded = len(positives) - len(retained_positives)

    exclusion = {
        "rule": (
            "exclude every attack window whose entity carries more than one attack "
            "family; exclusion only, nothing added, duplicated or weighted"
        ),
        "multi_family_entities": multi_family,
        "positives_p1": len(positives),
        "positives_p4": len(retained_positives),
        "positives_excluded": excluded,
        "entities_p1": len(per_entity),
        "entities_p4": len({r.entity_key for r in retained_positives}),
        "attack_types_p1": sorted({r.attack_type for r in positives if r.attack_type}),
        "attack_types_p4": sorted(
            {r.attack_type for r in retained_positives if r.attack_type}
        ),
        "episodes_p1": len({r.episode_id for r in positives}),
        "episodes_p4": len({r.episode_id for r in retained_positives}),
        "negatives_unchanged": len(negatives),
    }

    if args.preflight:
        print(json.dumps({"status": "preflight_ok", "exclusion": exclusion},
                         indent=2, sort_keys=True))
        return 0

    # P4 re-freezes its own folds because the attack-type set shrank.
    folds = build_folds(retained_positives, negatives, expected_types=None)
    rows = retained_positives + negatives
    index = {r.row_id: r for r in rows}
    checks = verify_no_leakage(folds, index)
    failures = [c for c in checks if c["failures"]]
    if failures:
        print(json.dumps({"status": "leakage_detected", "checks": failures},
                         indent=2, sort_keys=True))
        return 1

    p1_metrics = json.loads((P1_DIR / "p1_metrics.json").read_text(encoding="utf-8"))
    p1_by_type = {f["held_out_attack_type"]: f for f in p1_metrics["folds"]}

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    results = []
    comparisons = []
    pooled_detection: dict[str, bool] = {}

    for fold in folds:
        train_rows = [index[i] for i in fold.train_row_ids]
        test_rows = [index[i] for i in fold.test_row_ids]
        result = evaluate_fold(
            fold.index, fold.held_out_attack_type, train_rows, test_rows
        )
        results.append(result)
        pooled_detection.update(result.episode_detection)

        model = build_model()
        x_train, y_train = matrix(train_rows)
        model.fit(x_train, y_train)
        model_path = OUT_DIR / f"p4_model_fold{fold.index}.joblib"
        if not model_path.exists():
            joblib.dump(model, model_path)

        _write_immutable(
            OUT_DIR / f"p4_predictions_fold{fold.index}.csv",
            _csv(
                sorted(result.predictions, key=lambda p: p["row_id"]),
                ("row_id", "label", "disposition", "attack_type", "episode_id",
                 "score"),
                lambda p: (
                    p["row_id"], p["label"], p["disposition"],
                    p["attack_type"] or "", p["episode_id"] or "",
                    f"{p['score']:.10f}",
                ),
            ),
        )

        reference = p1_by_type.get(result.held_out_attack_type)
        p4_op = result.operating_points[0]
        entry: dict[str, Any] = {
            "held_out_attack_type": result.held_out_attack_type,
            "test_positives_p4": result.test_positives,
            "test_episodes_p4": result.test_episodes,
            "pr_auc_p4": result.pr_auc,
            "roc_auc_p4": result.roc_auc,
            "window_recall_p4": p4_op["window_recall"],
            "episode_recall_p4": p4_op["episode_recall"],
            "episode_ci_p4": [
                p4_op["episode_bootstrap"]["ci_low"],
                p4_op["episode_bootstrap"]["ci_high"],
            ],
            "observed_test_fpr_p4": p4_op["observed_test_fpr"],
        }
        if reference is not None:
            p1_op = reference["operating_points"][0]
            entry.update(
                {
                    "test_positives_p1": reference["test_positives"],
                    "test_episodes_p1": reference["test_episodes"],
                    "identical_test_positives": (
                        result.test_positives == reference["test_positives"]
                    ),
                    "pr_auc_p1": reference["pr_auc"],
                    "roc_auc_p1": reference["roc_auc"],
                    "window_recall_p1": p1_op["window_recall"],
                    "episode_recall_p1": p1_op["episode_recall"],
                    "episode_recall_delta": (
                        p4_op["episode_recall"] - p1_op["episode_recall"]
                    ),
                    "episode_ci_p1": [
                        p1_op["episode_bootstrap"]["ci_low"],
                        p1_op["episode_bootstrap"]["ci_high"],
                    ],
                    "observed_test_fpr_p1": p1_op["observed_test_fpr"],
                }
            )
        comparisons.append(entry)

    pooled_p4 = episode_bootstrap_recall(pooled_detection)

    metrics = {
        "experiment": "P4/C conservative benchmark, single-family attack entities",
        "started_at": started_at.isoformat(),
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "single_change_versus_p1": (
            "positive population restricted to single-family entities, by exclusion "
            "only; negatives, features, labels, model, thresholds and bootstrap "
            "unchanged. Folds were re-frozen because the attack-type set shrank."
        ),
        "p1_dataset_content_sha256": P1_DATASET_CONTENT_SHA256,
        "features": list(FEATURE_NAMES),
        "forbidden_columns": list(FORBIDDEN_COLUMNS),
        "exclusion": exclusion,
        "leakage_verification": checks,
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
        "comparison_p1_vs_p4": comparisons,
        "pooled_episode_recall_at_train_fpr_1pct": {
            "p1": p1_metrics["pooled_episode_recall_at_train_fpr_1pct"],
            "p4": pooled_p4,
        },
        "bootstrap": {
            "unit": "attack episode",
            "resamples": BOOTSTRAP_RESAMPLES,
            "seed": BOOTSTRAP_SEED,
            "window_level_bootstrap": "forbidden",
        },
        "interpretation_rules": [
            "P4 is a robustness control, not a better benchmark: it is smaller and "
            "less diverse than P1 by construction",
            "conclusions that survive P4 do not depend on the multi-family entities",
            "a conclusion that changes under P4 was partly an artefact of those "
            "entities appearing on both sides of a type split",
            "P4 removes positives, so its class imbalance is worse than P1's",
        ],
        "r11_note": (
            "P4 makes R11 more severe, not less: fewer positives, fewer entities "
            "and fewer attack types. It is published to show which conclusions are "
            "robust, never to claim improved statistical power."
        ),
        "postgresql_writes": 0,
    }
    metrics_bytes = json.dumps(metrics, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    metrics_sha = _write_immutable(OUT_DIR / "p4_metrics.json", metrics_bytes)

    print(json.dumps({
        "status": "verified",
        "metrics_file_sha256": metrics_sha,
        "exclusion": {
            "positives_p1": exclusion["positives_p1"],
            "positives_p4": exclusion["positives_p4"],
            "excluded": exclusion["positives_excluded"],
            "entities_p1": exclusion["entities_p1"],
            "entities_p4": exclusion["entities_p4"],
            "types_p1": len(exclusion["attack_types_p1"]),
            "types_p4": len(exclusion["attack_types_p4"]),
            "episodes_p1": exclusion["episodes_p1"],
            "episodes_p4": exclusion["episodes_p4"],
        },
        "leakage_failures": len(failures),
        "comparison": [
            {
                "type": c["held_out_attack_type"],
                "test_pos_p1": c.get("test_positives_p1"),
                "test_pos_p4": c["test_positives_p4"],
                "ep_recall_p1": (
                    round(c["episode_recall_p1"], 4) if "episode_recall_p1" in c
                    else None
                ),
                "ep_recall_p4": round(c["episode_recall_p4"], 4),
                "delta": (
                    round(c["episode_recall_delta"], 4)
                    if "episode_recall_delta" in c else None
                ),
                "pr_auc_p1": (
                    round(c["pr_auc_p1"], 4) if "pr_auc_p1" in c else None
                ),
                "pr_auc_p4": round(c["pr_auc_p4"], 4),
                "roc_p4": round(c["roc_auc_p4"], 4),
            }
            for c in comparisons
        ],
        "pooled": metrics["pooled_episode_recall_at_train_fpr_1pct"],
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
