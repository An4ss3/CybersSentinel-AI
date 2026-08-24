"""Runtime alert pipeline (Couche 3 -> 6.3 -> Couche 2).

Streams real CICIDS2017 flows through the trained detectors, applies the §6.3
composite scoring, and persists the resulting alerts.

Sink:
  * PostgreSQL if reachable (schema in modules/storage/schema.sql), else
  * a local JSONL file (artifacts/alerts.jsonl) so the pipeline is fully
    runnable without Docker.

Placeholders (until later modules exist):
  * asset_criticality is drawn from a synthetic distribution (the assets
    inventory / §6.5 CVE enrichment will populate the other scoring factors).
  * cve_severity is 0 (no CVE linked yet).

Run from the repo root:
    python scripts/generate_alerts.py --limit 20000
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path

import numpy as np
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))  # make 'modules' importable regardless of cwd

from modules.backend.app import db  # noqa: E402
from modules.backend.app.predictor import Predictor, available_models  # noqa: E402
from modules.backend.app.scoring import composite_score, score_to_level  # noqa: E402
from modules.detection.src.data_loader import load_cicids2017  # noqa: E402

CONFIG_PATH = REPO_ROOT / "modules" / "detection" / "config.yaml"
# Demo days: brute force (Tuesday) + DDoS (Friday) + their benign traffic.
DEMO_FILES = [
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
]
ASSET_LEVELS = ["Low", "Medium", "High", "Critical"]
ASSET_PROBS = [0.40, 0.35, 0.20, 0.05]  # synthetic placeholder distribution


def load_config() -> dict:
    with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def load_explanation(attack: str, reports_dir: Path, protocol: str) -> dict | None:
    """Top SHAP features saved during training (§6.4 XAI groundwork)."""
    path = reports_dir / f"{attack}_shap_top_features_{protocol}.json"
    if not path.exists():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    top = dict(list(data.items())[:5])
    return {"protocol": protocol, "top_features": top}


def generate(limit: int, protocol: str) -> list[dict]:
    cfg = load_config()
    rng = np.random.default_rng(cfg["random_state"])
    reports_dir = REPO_ROOT / cfg["paths"]["reports_dir"]

    features, _labels = load_cicids2017(
        str(REPO_ROOT / cfg["paths"]["cicids2017_dir"]), filenames=DEMO_FILES
    )
    features = features.drop(columns=cfg.get("leaky_features", []), errors="ignore")

    if limit and len(features) > limit:
        features = features.sample(n=limit, random_state=cfg["random_state"])
    print(f"scoring {len(features)} flows through {available_models(protocol)} ...")

    alerts: list[dict] = []
    for attack in available_models(protocol):
        threshold = cfg["attacks"].get(attack, {}).get("decision_threshold", 0.5)
        predictor = Predictor(attack, protocol=protocol, threshold=threshold)
        proba = predictor.predict_proba_batch(features)

        hit_idx = np.where(proba >= threshold)[0]
        explanation = load_explanation(attack, reports_dir, protocol)
        assets = rng.choice(ASSET_LEVELS, size=len(hit_idx), p=ASSET_PROBS)

        for j, i in enumerate(hit_idx):
            ml_conf = float(proba[i])
            asset = str(assets[j])
            cve = 0.0
            total = composite_score(ml_conf, asset, cve)
            alerts.append({
                "detected_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                "attack_type": attack,
                "ml_confidence": round(ml_conf, 4),
                "asset_criticality": asset,
                "cve_severity": cve,
                "composite_score": total,
                "level": score_to_level(total),
                "model_name": f"xgboost_{attack}_{protocol}",
                "status": "new",
                "explanation": explanation,
            })
    return alerts


def persist(alerts: list[dict], replace: bool = False) -> str:
    """Write to PostgreSQL if reachable, else to a JSONL fallback file."""
    conn = db.get_connection()
    if conn is not None:
        try:
            if replace:
                db.truncate_alerts(conn)
            n = db.insert_alerts(conn, alerts)
            conn.close()
            return f"PostgreSQL ({n} rows -> alerts table{', table reset' if replace else ''})"
        except Exception as exc:  # keep the run recoverable
            print(f"[warn] Postgres insert failed ({exc}); using JSONL fallback")

    out = REPO_ROOT / "artifacts" / "alerts.jsonl"
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        for a in alerts:
            fh.write(json.dumps(a) + "\n")
    return f"JSONL fallback -> {out.relative_to(REPO_ROOT)}"


def summarise(alerts: list[dict]) -> None:
    from collections import Counter

    by_level = Counter(a["level"] for a in alerts)
    by_attack = Counter(a["attack_type"] for a in alerts)
    print(f"\ngenerated {len(alerts)} alerts")
    print("  by attack:", dict(by_attack))
    print("  by level :", {lvl: by_level.get(lvl, 0)
                            for lvl in ["Critical", "High", "Medium", "Low"]})


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate scored alerts from real flows.")
    parser.add_argument("--limit", type=int, default=20000,
                        help="max flows to score (0 = all)")
    parser.add_argument("--protocol", default="production",
                        choices=["random", "holdout", "production"])
    parser.add_argument("--replace", action="store_true",
                        help="reset the alerts table before inserting (Postgres)")
    args = parser.parse_args()

    alerts = generate(args.limit, args.protocol)
    summarise(alerts)
    print("sink:", persist(alerts, replace=args.replace))


if __name__ == "__main__":
    main()
