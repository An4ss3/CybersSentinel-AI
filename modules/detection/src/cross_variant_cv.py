"""Leave-one-variant-out (LOVO) cross-variant evaluation (Couche 3).

Honest generalisation estimate for the PRODUCTION model (which is deployed
trained on ALL variants of a family). For each variant v:

    train on (all variants except v) + benign_train
    test  on  v                       + benign_test   (benign split randomly)

then rotate v and average the per-variant metrics. Because the held-out variant
is never in that fold's training data, there is no single-variant leakage; and
in CICIDS2017 the variants live on different days (DoS = Wed, DDoS = Fri), so
this doubles as a cross-day test. Evaluated at the default 0.5 threshold.

Run from the repo root:
    python -m modules.detection.src.cross_variant_cv --attack ddos
    python -m modules.detection.src.cross_variant_cv --attack brute_force
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

import numpy as np
from sklearn.metrics import average_precision_score, confusion_matrix

from .train import _benign_sample_index, load_config, load_frame


def _fit_eval(features, labels, cfg, train_labels: set, test_label: str) -> dict:
    from imblearn.over_sampling import SMOTE
    from xgboost import XGBClassifier

    benign_idx = _benign_sample_index(labels, cfg)
    benign_test = labels.loc[benign_idx].sample(
        frac=cfg["test_size"], random_state=cfg["random_state"]).index
    benign_train = benign_idx.difference(benign_test)

    tr = benign_train.union(labels[labels.isin(train_labels)].index)
    te = benign_test.union(labels[labels == test_label].index)
    X_tr, y_tr = features.loc[tr], labels.loc[tr].isin(train_labels).astype(int)
    X_te, y_te = features.loc[te], (labels.loc[te] == test_label).astype(int)

    k = max(1, min(5, int(y_tr.sum()) - 1))
    X_res, y_res = SMOTE(random_state=cfg["random_state"], k_neighbors=k).fit_resample(X_tr, y_tr)
    model = XGBClassifier(**cfg["xgboost"], random_state=cfg["random_state"])
    model.fit(X_res, y_res)

    proba = model.predict_proba(X_te)[:, 1]
    pred = (proba >= 0.5).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_te, pred, labels=[0, 1]).ravel()
    return {
        "held_out": test_label,
        "n_test_pos": int(y_te.sum()),
        "recall": round(tp / (tp + fn), 4) if (tp + fn) else 0.0,
        "precision": round(tp / (tp + fp), 4) if (tp + fp) else 0.0,
        "fpr": round(fp / (fp + tn), 4) if (fp + tn) else 0.0,
        "auc_pr": round(float(average_precision_score(y_te, proba)), 4) if y_te.sum() else None,
    }


def lovo(attack: str, cfg: dict) -> dict:
    features, labels = load_frame(cfg)
    variants = cfg["attacks"][attack]["positive_labels"]
    print(f"\n=== leave-one-variant-out CV: {attack} ({len(variants)} variants) ===")
    rows = []
    for v in variants:
        train_labels = {x for x in variants if x != v}
        if not train_labels:
            continue
        res = _fit_eval(features, labels, cfg, train_labels, v)
        print(f"  hold out {v:<18} recall={res['recall']:.4f} "
              f"precision={res['precision']:.4f} fpr={res['fpr']:.4f} "
              f"auc_pr={res['auc_pr']} (n_pos={res['n_test_pos']})")
        rows.append(res)

    avg = {k: round(float(np.mean([r[k] for r in rows])), 4)
           for k in ["recall", "precision", "fpr"]}
    aucs = [r["auc_pr"] for r in rows if r["auc_pr"] is not None]
    avg["auc_pr"] = round(float(np.mean(aucs)), 4) if aucs else None
    print(f"  --> AVERAGE          recall={avg['recall']:.4f} "
          f"precision={avg['precision']:.4f} fpr={avg['fpr']:.4f} auc_pr={avg['auc_pr']}")

    out = {"attack": attack, "protocol": "lovo", "threshold": 0.5,
           "folds": rows, "average": avg}
    reports = Path(cfg["paths"]["reports_dir"])
    reports.mkdir(parents=True, exist_ok=True)
    (reports / f"{attack}_lovo.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description="Leave-one-variant-out CV.")
    parser.add_argument("--attack", default="ddos")
    args = parser.parse_args()
    os.chdir(Path(__file__).resolve().parents[3])
    lovo(args.attack, load_config())


if __name__ == "__main__":
    main()
