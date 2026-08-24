"""Run P3/D: the unsupervised anomaly benchmark trained on Monday benign only.

Design, as ratified
-------------------
* Training uses **only** MB-LABEL ``benign_reference`` windows. **No positive ever
  enters training**, so the benchmark is entirely independent of attack diversity
  at the learning stage. This is the one design that R11 cannot degrade.
* The 70 578 benign windows are split **by time** into three contiguous blocks
  (decision D12): the first 50% fits the model, the next 25% calibrates the
  threshold, the final 25% measures the false-positive rate. Contiguous temporal
  blocks are used rather than a random split so that no minute of benign traffic
  can inform both the fit and its own evaluation.
* The threshold is derived **exclusively** from the calibration block. Neither the
  attacks nor the ``unknown`` population influence the threshold or any
  hyper-parameter.
* The 376 known attacks are evaluated separately **by type and by episode**.
* The 172 372 M6 ``unknown`` windows are reported as an **alert rate on an
  unlabelled population**. That number is never called a false-positive rate, a
  false positive, or an error, because the true status of those windows is unknown.

The critical distinction this benchmark must preserve
----------------------------------------------------
**Measured FPR** is computed on the held-out benign measurement block: windows whose
``benign_reference`` label comes from the frozen M5 v1 policy, so a flag there is a
genuine false positive.

**Alert rate on unknown** is computed on windows M5 could not classify. A flag there
may be a true positive that no rule covers, or a false positive. It is uninterpretable
as an error rate, and treating it as one would silently convert ``unknown`` into
``benign`` — the invariant the whole project forbids.
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
import numpy as np
from sklearn.ensemble import IsolationForest

from modules.detection.src.experiments.p1_dataset import (
    FEATURE_NAMES,
    FORBIDDEN_COLUMNS,
    PRODUCTION_DATABASE,
    P1DatasetError,
    Row,
    _classify,
    _compiled_rules,
    _query,
    dataset_digest,
    load_negatives,
    load_positives,
)
from modules.detection.src.experiments.p1_evaluation import (
    BOOTSTRAP_RESAMPLES,
    BOOTSTRAP_SEED,
    FPR_TARGETS,
    episode_bootstrap_recall,
    episode_recall,
    threshold_at_train_fpr,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
OUT_DIR: Final[Path] = REPO_ROOT / "artifacts" / "experiments" / "p3"

MODEL_SEED: Final[int] = 0
N_ESTIMATORS: Final[int] = 200
#: Contiguous temporal split of the benign day (decision D12).
FIT_FRACTION: Final[float] = 0.50
CALIBRATION_FRACTION: Final[float] = 0.25

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


def load_m6_unlabelled(repository_root: str) -> list[Row]:
    """Load the M6 windows the frozen M5 v2 policy leaves ``unknown``.

    These are **not** negatives and are never used for fitting, calibration or any
    hyper-parameter choice. They exist in this benchmark only so an alert rate can
    be reported over an explicitly unlabelled population.
    """
    rules = _compiled_rules(repository_root)
    features = ", ".join(FEATURE_NAMES)
    raw = _query(
        PRODUCTION_DATABASE,
        "SELECT window_id::text, output_partition, entity_source_ip,"
        " entity_destination_ip, entity_transport, entity_service,"
        f" window_start_time, window_end_time, {features}"
        " FROM m6_canonical.feature_windows",
    )
    out: list[Row] = []
    for record in raw:
        wid, partition, src, dst, transport, service, start, end = record[:8]
        disposition, _ = _classify(rules, src, dst, transport, start, end)
        if disposition != "unknown":
            continue
        out.append(
            Row(
                row_id=wid,
                source="m6",
                label=-1,  # sentinel: unlabelled, neither positive nor negative
                disposition="unknown",
                attack_type=None,
                entity_key="|".join((src, dst, transport, service)),
                episode_id=None,
                partition=partition,
                window_start_epoch=int(start),
                features=tuple(float(v) for v in record[8:]),
            )
        )
    return out


def anomaly_scores(model: IsolationForest, rows: list[Row]) -> np.ndarray:
    """Return the anomaly score, higher meaning more anomalous.

    ``IsolationForest.score_samples`` returns higher values for more normal points,
    so it is negated. ``predict`` is never used: its operating point comes from the
    ``contamination`` parameter, whereas every threshold in this benchmark is
    derived from the calibration block alone.
    """
    features = np.asarray([r.features for r in rows], dtype=float)
    return -model.score_samples(features)


def main(argv: Sequence[str] | None = None) -> int:
    """Fit on Monday benign, calibrate, measure, evaluate attacks, report."""
    parser = argparse.ArgumentParser(description="Run the P3/D anomaly benchmark.")
    parser.add_argument("--preflight", action="store_true")
    args = parser.parse_args(argv)

    started_at = datetime.now(timezone.utc)

    positives = load_positives(str(REPO_ROOT))
    negatives = load_negatives()
    digest = dataset_digest(positives + negatives)
    if digest != P1_DATASET_CONTENT_SHA256:
        raise P1DatasetError(
            f"P3 must run on the identical P1 population; digest {digest}"
        )
    unlabelled = load_m6_unlabelled(str(REPO_ROOT))

    # ---- decision D12: contiguous temporal split of the benign day -------
    ordered = sorted(negatives, key=lambda r: (r.window_start_epoch, r.row_id))
    n = len(ordered)
    fit_end = int(n * FIT_FRACTION)
    calibration_end = int(n * (FIT_FRACTION + CALIBRATION_FRACTION))
    fit_rows = ordered[:fit_end]
    calibration_rows = ordered[fit_end:calibration_end]
    measurement_rows = ordered[calibration_end:]

    split = {
        "rule": "contiguous temporal blocks over the benign day, no randomness",
        "fit_windows": len(fit_rows),
        "calibration_windows": len(calibration_rows),
        "measurement_windows": len(measurement_rows),
        "fit_epoch_range": [
            fit_rows[0].window_start_epoch, fit_rows[-1].window_start_epoch
        ],
        "calibration_epoch_range": [
            calibration_rows[0].window_start_epoch,
            calibration_rows[-1].window_start_epoch,
        ],
        "measurement_epoch_range": [
            measurement_rows[0].window_start_epoch,
            measurement_rows[-1].window_start_epoch,
        ],
        "blocks_disjoint": (
            fit_rows[-1].window_start_epoch <= calibration_rows[0].window_start_epoch
            and calibration_rows[-1].window_start_epoch
            <= measurement_rows[0].window_start_epoch
        ),
        "positives_in_training": 0,
        "unknown_in_training": 0,
        "unknown_in_calibration": 0,
    }
    if args.preflight:
        print(json.dumps({
            "status": "preflight_ok",
            "dataset_content_sha256": digest,
            "benign_total": len(negatives),
            "positives_available_for_evaluation_only": len(positives),
            "unlabelled_m6_unknown": len(unlabelled),
            "split": split,
        }, indent=2, sort_keys=True))
        return 0

    # ---- fit on benign only ---------------------------------------------
    model = IsolationForest(
        n_estimators=N_ESTIMATORS,
        random_state=MODEL_SEED,
        n_jobs=1,
        contamination="auto",
    )
    model.fit(np.asarray([r.features for r in fit_rows], dtype=float))

    calibration_scores = anomaly_scores(model, calibration_rows)
    measurement_scores = anomaly_scores(model, measurement_rows)
    positive_scores = anomaly_scores(model, positives)
    unlabelled_scores = anomaly_scores(model, unlabelled)

    types = sorted({r.attack_type for r in positives if r.attack_type})
    operating_points: list[dict[str, Any]] = []
    pooled_detection_at_first_target: dict[str, bool] = {}

    for target in FPR_TARGETS:
        threshold, achieved = threshold_at_train_fpr(calibration_scores, target)

        measured_fp = int((measurement_scores >= threshold).sum())
        measured_fpr = measured_fp / len(measurement_rows)

        unlabelled_alerts = int((unlabelled_scores >= threshold).sum())
        unlabelled_rate = unlabelled_alerts / len(unlabelled)

        per_type = []
        for attack_type in types:
            mask = np.asarray(
                [r.attack_type == attack_type for r in positives], dtype=bool
            )
            subset_rows = [r for r, keep in zip(positives, mask) if keep]
            subset_scores = positive_scores[mask]
            detected, recall = episode_recall(subset_rows, subset_scores, threshold)
            boot = episode_bootstrap_recall(detected)
            flagged = int((subset_scores >= threshold).sum())
            per_type.append(
                {
                    "attack_type": attack_type,
                    "windows": int(mask.sum()),
                    "episodes": len(detected),
                    "window_recall": flagged / int(mask.sum()),
                    "episode_recall": recall,
                    "episode_bootstrap": boot,
                    "episodes_missed": sorted(
                        k for k, v in detected.items() if not v
                    ),
                }
            )

        all_detected, all_recall = episode_recall(
            positives, positive_scores, threshold
        )
        pooled = episode_bootstrap_recall(all_detected)
        if target == FPR_TARGETS[0]:
            pooled_detection_at_first_target = all_detected

        operating_points.append(
            {
                "target_calibration_fpr": target,
                "achieved_calibration_fpr": achieved,
                "threshold": threshold,
                "measured_false_positive_rate": {
                    "population": "held-out benign_reference measurement block",
                    "windows": len(measurement_rows),
                    "flagged": measured_fp,
                    "rate": measured_fpr,
                    "interpretation": (
                        "a genuine false-positive rate: every window here carries a "
                        "benign_reference label from the frozen M5 v1 policy"
                    ),
                },
                "alert_rate_on_unlabelled": {
                    "population": "M6 windows the M5 v2 policy leaves unknown",
                    "windows": len(unlabelled),
                    "alerts": unlabelled_alerts,
                    "rate": unlabelled_rate,
                    "interpretation": (
                        "NOT a false-positive rate, NOT an error rate. The true "
                        "status of these windows is unknown; an alert may be a true "
                        "positive no rule covers. Reading this as error would "
                        "convert unknown into benign."
                    ),
                },
                "attack_window_recall": float(
                    (positive_scores >= threshold).sum() / len(positives)
                ),
                "attack_episode_recall": all_recall,
                "attack_episode_bootstrap": pooled,
                "per_attack_type": per_type,
            }
        )

    predictions = []
    for group, rows_, scores in (
        ("attack", positives, positive_scores),
        ("benign_measurement", measurement_rows, measurement_scores),
        ("benign_calibration", calibration_rows, calibration_scores),
        ("unlabelled_unknown", unlabelled, unlabelled_scores),
    ):
        for row, score in zip(rows_, scores):
            predictions.append(
                {
                    "group": group,
                    "row_id": row.row_id,
                    "disposition": row.disposition,
                    "attack_type": row.attack_type or "",
                    "episode_id": row.episode_id or "",
                    "score": float(score),
                }
            )

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    model_path = OUT_DIR / "p3_model_isolation_forest.joblib"
    if not model_path.exists():
        joblib.dump(model, model_path)

    lines = ["group,row_id,disposition,attack_type,episode_id,score"]
    for p in sorted(predictions, key=lambda p: (p["group"], p["row_id"])):
        lines.append(
            f"{p['group']},{p['row_id']},{p['disposition']},{p['attack_type']},"
            f"{p['episode_id']},{p['score']:.10f}"
        )
    _write_immutable(
        OUT_DIR / "p3_predictions.csv",
        ("\n".join(lines) + "\n").encode("utf-8"),
    )

    metrics = {
        "experiment": "P3/D unsupervised anomaly benchmark, Monday benign only",
        "started_at": started_at.isoformat(),
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "p1_dataset_content_sha256": P1_DATASET_CONTENT_SHA256,
        "features": list(FEATURE_NAMES),
        "forbidden_columns": list(FORBIDDEN_COLUMNS),
        "model": {
            "estimator": "IsolationForest",
            "n_estimators": N_ESTIMATORS,
            "random_state": MODEL_SEED,
            "n_jobs": 1,
            "contamination": "auto",
            "predict_never_used": True,
            "note": (
                "score_samples is negated so higher means more anomalous. predict() "
                "is never called because its operating point derives from "
                "contamination, whereas every threshold here comes from the "
                "calibration block alone."
            ),
        },
        "training_composition": {
            "benign_reference_windows_fitted": len(fit_rows),
            "positives_in_training": 0,
            "unknown_in_training": 0,
            "ambiguous_in_training": 0,
            "statement": (
                "No positive, no unknown and no ambiguous window entered fitting, "
                "calibration or any hyper-parameter choice."
            ),
        },
        "temporal_split": split,
        "populations": {
            "benign_reference_total": len(negatives),
            "attack_windows": len(positives),
            "attack_types": types,
            "attack_episodes": len({r.episode_id for r in positives}),
            "m6_unknown_windows": len(unlabelled),
        },
        "operating_points": operating_points,
        "pooled_episode_bootstrap_at_first_target": episode_bootstrap_recall(
            pooled_detection_at_first_target
        ),
        "bootstrap": {
            "unit": "attack episode",
            "resamples": BOOTSTRAP_RESAMPLES,
            "seed": BOOTSTRAP_SEED,
            "window_level_bootstrap": "forbidden",
        },
        "terminology": {
            "measured_false_positive_rate": (
                "computed on held-out benign_reference windows; a flag there is a "
                "genuine false positive"
            ),
            "alert_rate_on_unlabelled": (
                "computed on M6 unknown windows; never a false-positive rate, never "
                "an error rate, never a false positive"
            ),
        },
        "r11_note": (
            "P3 removes attack diversity from the learning stage entirely: no "
            "positive is fitted. It does not make the 376 attacks a statistically "
            "independent sample. Recall uncertainty is still governed by the 54 "
            "episodes drawn from 9 entities and 6 host pairs."
        ),
        "postgresql_writes": 0,
    }
    metrics_bytes = json.dumps(metrics, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    metrics_sha = _write_immutable(OUT_DIR / "p3_metrics.json", metrics_bytes)

    first = operating_points[0]
    print(json.dumps({
        "status": "verified",
        "metrics_file_sha256": metrics_sha,
        "split": {
            "fit": len(fit_rows),
            "calibration": len(calibration_rows),
            "measurement": len(measurement_rows),
            "disjoint": split["blocks_disjoint"],
        },
        "operating_points": [
            {
                "target_calibration_fpr": op["target_calibration_fpr"],
                "achieved_calibration_fpr": round(op["achieved_calibration_fpr"], 6),
                "threshold": round(op["threshold"], 6),
                "measured_FPR_on_known_benign": round(
                    op["measured_false_positive_rate"]["rate"], 6
                ),
                "alert_rate_on_unknown_NOT_an_error_rate": round(
                    op["alert_rate_on_unlabelled"]["rate"], 6
                ),
                "attack_window_recall": round(op["attack_window_recall"], 6),
                "attack_episode_recall": round(op["attack_episode_recall"], 6),
                "per_type": [
                    {
                        "type": t["attack_type"],
                        "window_recall": round(t["window_recall"], 4),
                        "episode_recall": round(t["episode_recall"], 4),
                        "ci": [
                            round(t["episode_bootstrap"]["ci_low"], 4),
                            round(t["episode_bootstrap"]["ci_high"], 4),
                        ],
                    }
                    for t in op["per_attack_type"]
                ],
            }
            for op in operating_points
        ],
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
