"""Decision-threshold analysis for the honest holdout models (Couche 3).

Motivation: under the cross-variant holdout, the models keep a HIGH AUC-PR
(they rank attacks above benign) but collapse at the arbitrary 0.5 threshold
(recall near zero). AUC-PR is threshold-independent; recall/precision are not.
A SOC does not have to use 0.5 — it picks an operating point on the
precision/recall curve. This script quantifies that choice.

For a given attack it:
  * reloads the persisted holdout model + rebuilds the SAME holdout test set,
  * sweeps thresholds and reports precision / recall / FPR / F1,
  * finds the best-F1 threshold and the lowest threshold reaching a target
    recall (default 0.90),
  * saves a precision-recall curve PNG and a JSON summary.

Run from the repo root:
    python -m modules.detection.src.threshold_analysis --attack brute_force
    python -m modules.detection.src.threshold_analysis --attack ddos
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import matplotlib
import numpy as np
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    precision_recall_curve,
)

matplotlib.use("Agg")  # headless: write PNG, no display
import matplotlib.pyplot as plt  # noqa: E402

from .train import load_config, load_frame, split_holdout  # noqa: E402


def metrics_at(y_true, y_proba, thr: float) -> dict:
    y_pred = (y_proba >= thr).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {
        "threshold": round(float(thr), 4),
        "precision": round(precision, 4), "recall": round(recall, 4),
        "fpr": round(fpr, 4), "f1": round(f1, 4),
        "tp": int(tp), "fp": int(fp), "fn": int(fn), "tn": int(tn),
    }


def analyse(attack: str, target_recall: float = 0.90):
    cfg = load_config()
    model_path = Path(cfg["paths"]["models_dir"]) / f"xgboost_{attack}_holdout.joblib"
    if not model_path.exists():
        raise FileNotFoundError(
            f"{model_path} not found. Train it first:\n"
            f"  python -m modules.detection.src.train --attack {attack} --protocol holdout"
        )
    bundle = joblib.load(model_path)
    model, feat = bundle["model"], bundle["features"]

    # Rebuild the identical holdout test set (deterministic split).
    features, labels = load_frame(cfg)
    _, X_test, _, y_test = split_holdout(features, labels, attack, cfg)
    X_test = X_test.reindex(columns=feat, fill_value=0.0)
    y_proba = model.predict_proba(X_test)[:, 1]

    auc_pr = average_precision_score(y_test, y_proba)
    prec, rec, thr = precision_recall_curve(y_test, y_proba)

    # Best-F1 threshold across the curve.
    f1 = np.divide(2 * prec * rec, prec + rec,
                   out=np.zeros_like(prec), where=(prec + rec) > 0)
    best_i = int(np.argmax(f1[:-1])) if len(thr) else 0
    best_f1_thr = float(thr[best_i]) if len(thr) else 0.5

    # Lowest threshold that reaches the target recall (best precision among them).
    ok = np.where(rec[:-1] >= target_recall)[0]
    target_thr = float(thr[ok[-1]]) if len(ok) else None

    sweep = [metrics_at(y_test, y_proba, t) for t in (0.5, 0.3, 0.1, 0.05, 0.01)]
    summary = {
        "attack": attack,
        "protocol": "holdout",
        "auc_pr": round(float(auc_pr), 4),
        "default_0.5": metrics_at(y_test, y_proba, 0.5),
        "best_f1": metrics_at(y_test, y_proba, best_f1_thr),
        f"target_recall_{target_recall}": (
            metrics_at(y_test, y_proba, target_thr) if target_thr is not None
            else f"unreachable (max recall {rec[:-1].max():.4f})"
        ),
        "threshold_sweep": sweep,
    }

    reports_dir = Path(cfg["paths"]["reports_dir"])
    reports_dir.mkdir(parents=True, exist_ok=True)
    (reports_dir / f"{attack}_threshold_analysis_holdout.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8"
    )

    # Precision-recall curve figure.
    plt.figure(figsize=(6, 5))
    plt.plot(rec, prec, label=f"AUC-PR = {auc_pr:.3f}")
    plt.xlabel("Recall"); plt.ylabel("Precision")
    plt.title(f"Precision-Recall — {attack} (holdout)")
    plt.grid(True, alpha=0.3); plt.legend()
    fig_path = reports_dir / f"{attack}_pr_curve_holdout.png"
    plt.tight_layout(); plt.savefig(fig_path, dpi=120); plt.close()

    print(f"\n===== threshold analysis: {attack} (holdout) =====")
    print(f"AUC-PR = {auc_pr:.4f}")
    print(f"  @0.5 (default): recall={summary['default_0.5']['recall']} "
          f"precision={summary['default_0.5']['precision']} "
          f"fpr={summary['default_0.5']['fpr']}")
    print(f"  best-F1 @thr={summary['best_f1']['threshold']}: "
          f"recall={summary['best_f1']['recall']} "
          f"precision={summary['best_f1']['precision']} "
          f"fpr={summary['best_f1']['fpr']} f1={summary['best_f1']['f1']}")
    tr = summary[f"target_recall_{target_recall}"]
    print(f"  target recall {target_recall}: {tr}")
    print("  sweep:")
    for row in sweep:
        print(f"    thr={row['threshold']:<5} recall={row['recall']:<6} "
              f"precision={row['precision']:<6} fpr={row['fpr']:<6} f1={row['f1']}")
    print(f"  saved: {fig_path.name}, {attack}_threshold_analysis_holdout.json")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Threshold analysis for holdout models.")
    parser.add_argument("--attack", default="brute_force")
    parser.add_argument("--target-recall", type=float, default=0.90)
    args = parser.parse_args()
    import os
    os.chdir(Path(__file__).resolve().parents[3])  # run from repo root
    analyse(args.attack, args.target_recall)


if __name__ == "__main__":
    main()
