"""Train a detection model for an MVP attack family on CICIDS2017 (Couche 3, §6.2).

MVP scope (encadrant): brute_force + ddos.
Extensions (itération 2+): malware (CNN), insider_threat (UEBA).

Evaluation methodology (encadrant KPI feedback) — no hard-coded precision
target; instead a rigorous, reproducible protocol with TWO hardening measures:

  1. Leaky-feature removal: identifier-like columns (Destination Port) are
     dropped so the model cannot memorise lab port assignments.
  2. Split protocol:
       * random  = stratified random split (optimistic baseline).
       * holdout = train on some attack variants, TEST ON UNSEEN variants
                   (brute_force: SSH->FTP ; ddos: Wed DoS -> Fri DDoS).
                   This measures genuine generalisation, not memorisation.

For every run we report precision / recall / F1, the confusion matrix, an
explicit false-positive analysis (FP count + false-positive rate), and AUC-PR.

Run from the repo root:
    python -m modules.detection.src.train --attack brute_force --protocol holdout
    python -m modules.detection.src.train --attack ddos       --protocol random
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import yaml
from sklearn.metrics import (
    average_precision_score,
    classification_report,
    confusion_matrix,
)
from sklearn.model_selection import train_test_split

from .data_loader import load_cicids2017

CONFIG_PATH = Path(__file__).resolve().parents[1] / "config.yaml"


def load_config(path: Path = CONFIG_PATH) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def load_frame(cfg: dict):
    """Load CICIDS2017 and drop leaky/identifier features."""
    features, labels = load_cicids2017(cfg["paths"]["cicids2017_dir"])
    leaky = cfg.get("leaky_features", [])
    dropped = [c for c in leaky if c in features.columns]
    features = features.drop(columns=dropped, errors="ignore")
    if dropped:
        print(f"[hardening] dropped leaky features: {dropped}")
    return features, labels.str.strip()


def _benign_sample_index(labels: pd.Series, cfg: dict):
    """Optionally down-sample the (huge) benign class."""
    benign_idx = labels[labels == cfg["benign_label"]].index
    n = cfg.get("benign_sample_size", 0)
    if n and len(benign_idx) > n:
        benign_idx = labels[labels == cfg["benign_label"]].sample(
            n=n, random_state=cfg["random_state"]
        ).index
    return benign_idx


def split_random(features, labels, attack, cfg):
    """Stratified random split (optimistic baseline)."""
    positive = set(cfg["attacks"][attack]["positive_labels"])
    benign_idx = _benign_sample_index(labels, cfg)
    attack_idx = labels[labels.isin(positive)].index
    keep = benign_idx.union(attack_idx)

    X = features.loc[keep]
    y = labels.loc[keep].isin(positive).astype(int)
    return train_test_split(
        X, y, test_size=cfg["test_size"],
        random_state=cfg["random_state"], stratify=y,
    )


def split_holdout(features, labels, attack, cfg):
    """Cross-variant holdout: unseen attack variant in the test set.

    Attacks are split by label (train_labels vs test_labels); benign flows are
    split randomly between train and test.
    """
    ho = cfg["attacks"][attack]["holdout"]
    train_labels, test_labels = set(ho["train_labels"]), set(ho["test_labels"])

    benign_idx = _benign_sample_index(labels, cfg)
    benign_test = labels.loc[benign_idx].sample(
        frac=cfg["test_size"], random_state=cfg["random_state"]
    ).index
    benign_train = benign_idx.difference(benign_test)

    train_attack = labels[labels.isin(train_labels)].index
    test_attack = labels[labels.isin(test_labels)].index

    train_idx = benign_train.union(train_attack)
    test_idx = benign_test.union(test_attack)

    X_train, X_test = features.loc[train_idx], features.loc[test_idx]
    y_train = labels.loc[train_idx].isin(train_labels).astype(int)
    y_test = labels.loc[test_idx].isin(test_labels).astype(int)

    print(f"[holdout] train attacks={list(train_labels)} "
          f"({int(y_train.sum())} pos) | "
          f"test attacks={list(test_labels)} ({int(y_test.sum())} pos)")
    return X_train, X_test, y_train, y_test


def train(cfg: dict, attack: str, protocol: str):
    from xgboost import XGBClassifier

    if attack not in cfg["attacks"]:
        raise KeyError(f"Unknown attack '{attack}'. Configured: {list(cfg['attacks'])}")

    features, labels = load_frame(cfg)
    feature_names = list(features.columns)

    if protocol in ("random", "production"):
        # 'production' = deployment model: train on ALL variants of the family
        # (mechanically a stratified random split). Its held-out metrics can be
        # optimistic (possible session leakage in CICIDS2017, which lacks
        # session IDs), so the honest generalisation of this all-variants model
        # is measured separately by leave-one-variant-out CV (cross_variant_cv.py).
        X_train, X_test, y_train, y_test = split_random(features, labels, attack, cfg)
    elif protocol == "holdout":
        X_train, X_test, y_train, y_test = split_holdout(features, labels, attack, cfg)
    else:
        raise ValueError(f"Unknown protocol '{protocol}' (use random|holdout|production)")

    print(f"[{attack}/{protocol}] train={len(y_train)} (pos={int(y_train.sum())}) "
          f"test={len(y_test)} (pos={int(y_test.sum())})")

    # Handle class imbalance (§6.2) on the TRAINING split only.
    scale_pos_weight = 1.0
    if cfg.get("use_smote", True):
        from imblearn.over_sampling import SMOTE

        n_pos = int((y_train == 1).sum())
        k = max(1, min(5, n_pos - 1))
        X_train, y_train = SMOTE(
            random_state=cfg["random_state"], k_neighbors=k
        ).fit_resample(X_train, y_train)
        print(f"[{attack}/{protocol}] after SMOTE: {len(y_train)} training rows")
    else:
        neg, pos = int((y_train == 0).sum()), int((y_train == 1).sum())
        scale_pos_weight = neg / max(pos, 1)

    model = XGBClassifier(
        **cfg["xgboost"], scale_pos_weight=scale_pos_weight,
        random_state=cfg["random_state"],
    )
    model.fit(X_train, y_train)

    evaluate(model, X_test, y_test, feature_names, cfg, attack, protocol)
    persist(model, feature_names, cfg, attack, protocol)
    return model


def evaluate(model, X_test, y_test, feature_names, cfg, attack, protocol):
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]

    report = classification_report(
        y_test, y_pred, target_names=["benign", attack], digits=4, zero_division=0
    )
    cm = confusion_matrix(y_test, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    auc_pr = average_precision_score(y_test, y_proba)
    fpr = fp / (fp + tn) if (fp + tn) else 0.0          # false-positive rate
    fdr = fp / (fp + tp) if (fp + tp) else 0.0          # false-discovery rate
    recall = tp / (tp + fn) if (tp + fn) else 0.0

    print(f"\n=== [{attack}/{protocol}] classification report (held-out test set) ===")
    print(report)
    print("=== confusion matrix (rows=true, cols=pred; order [benign, attack]) ===")
    print(cm)
    print("\n=== false-positive analysis ===")
    print(f"  TN={tn}  FP={fp}  FN={fn}  TP={tp}")
    print(f"  recall (detection rate)          : {recall:.4f}")
    print(f"  false-positive rate  (FP/(FP+TN)): {fpr:.4f}")
    print(f"  false-discovery rate (FP/(FP+TP)): {fdr:.4f}")
    print(f"  AUC-PR (average precision)       : {auc_pr:.4f}")

    reports_dir = Path(cfg["paths"]["reports_dir"])
    reports_dir.mkdir(parents=True, exist_ok=True)
    metrics = {
        "attack": attack,
        "protocol": protocol,
        "auc_pr": float(auc_pr),
        "recall": float(recall),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "false_positive_rate": float(fpr),
        "false_discovery_rate": float(fdr),
        "classification_report": report,
    }
    (reports_dir / f"{attack}_metrics_{protocol}.json").write_text(
        json.dumps(metrics, indent=2), encoding="utf-8"
    )
    _export_shap(model, X_test, feature_names, reports_dir, attack, protocol)


def _export_shap(model, X_test, feature_names, reports_dir: Path, attack, protocol):
    """Save a SHAP feature-importance summary (§6.4 XAI groundwork)."""
    try:
        import shap

        sample = X_test.sample(n=min(2000, len(X_test)), random_state=0)
        explainer = shap.TreeExplainer(model)
        shap_values = explainer.shap_values(sample)
        mean_abs = np.abs(shap_values).mean(axis=0)
        importance = (
            pd.Series(mean_abs, index=feature_names).sort_values(ascending=False).head(15)
        )
        importance.to_json(
            reports_dir / f"{attack}_shap_top_features_{protocol}.json", indent=2
        )
        print(f"\n=== [{attack}/{protocol}] top SHAP features (mean |value|) ===")
        print(importance)
    except Exception as exc:  # SHAP is optional at this stage
        print(f"[warn] SHAP export skipped: {exc}")


def persist(model, feature_names, cfg, attack, protocol):
    models_dir = Path(cfg["paths"]["models_dir"])
    models_dir.mkdir(parents=True, exist_ok=True)
    out = models_dir / f"xgboost_{attack}_{protocol}.joblib"
    joblib.dump(
        {"model": model, "features": feature_names, "attack": attack, "protocol": protocol},
        out,
    )
    print(f"\nModel saved to {out}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Train a CyberSentinel detection model.")
    parser.add_argument("--attack", default="brute_force",
                        help="attack family (must exist in config.yaml 'attacks')")
    parser.add_argument("--protocol", default=None,
                        choices=["random", "holdout", "production"],
                        help="split protocol (overrides config.yaml evaluation.protocol)")
    args = parser.parse_args()

    os.chdir(Path(__file__).resolve().parents[3])  # run from repo root
    cfg = load_config()
    protocol = args.protocol or cfg["evaluation"]["protocol"]
    train(cfg, args.attack, protocol)


if __name__ == "__main__":
    main()
