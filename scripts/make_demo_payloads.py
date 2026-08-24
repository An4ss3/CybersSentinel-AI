"""Build reliable live-demo payloads from real CICIDS2017 flows.

Picks:
  * a real (unseen) FTP-Patator brute-force flow that the holdout model
    actually catches  -> demo of `is_alert: true`, high ML confidence,
  * a real BENIGN flow the model correctly ignores -> `is_alert: false`.

Saves them to artifacts/demo_payloads/*.json and prints the exact /score
response you should expect (verified in-process via TestClient).

Run from the repo root:
    python scripts/make_demo_payloads.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from modules.backend.app.predictor import Predictor  # noqa: E402

DATA = REPO_ROOT / "datasets" / "cicids2017" / "Tuesday-WorkingHours.pcap_ISCX.csv"
OUT = REPO_ROOT / "artifacts" / "demo_payloads"


def clean(df: pd.DataFrame) -> pd.DataFrame:
    df.columns = df.columns.str.strip()
    return df


def row_to_features(row: pd.Series) -> dict:
    """Sanitise a flow row into a JSON-safe feature dict (no inf/nan)."""
    feats = {}
    for k, v in row.items():
        if k == "Label":
            continue
        try:
            fv = float(v)
        except (TypeError, ValueError):
            continue
        if not np.isfinite(fv):
            fv = 0.0
        feats[k] = fv
    return feats


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    if not DATA.exists():
        raise FileNotFoundError(f"{DATA} not found.")

    df = clean(pd.read_csv(DATA, low_memory=False))
    labels = df["Label"].astype(str).str.strip()

    predictor = Predictor("brute_force", protocol="holdout", threshold=0.5)

    # --- attack payload: an FTP-Patator flow the model catches (max proba) ---
    ftp = df[labels == "FTP-Patator"].reset_index(drop=True)
    proba_ftp = predictor.predict_proba_batch(ftp)
    atk_row = ftp.iloc[int(np.argmax(proba_ftp))]
    attack_payload = {
        "attack": "brute_force",
        "features": row_to_features(atk_row),
        "asset_criticality": "High",
        "cve_severity": 7.5,
    }

    # --- benign payload: a benign flow with the lowest attack probability ----
    benign = df[labels == "BENIGN"].sample(n=5000, random_state=0).reset_index(drop=True)
    proba_ben = predictor.predict_proba_batch(benign)
    ben_row = benign.iloc[int(np.argmin(proba_ben))]
    benign_payload = {
        "attack": "brute_force",
        "features": row_to_features(ben_row),
        "asset_criticality": "Low",
        "cve_severity": 0.0,
    }

    (OUT / "bruteforce_attack.json").write_text(
        json.dumps(attack_payload, indent=2), encoding="utf-8")
    (OUT / "benign.json").write_text(
        json.dumps(benign_payload, indent=2), encoding="utf-8")

    # --- verify expected responses in-process (no running server needed) -----
    from fastapi.testclient import TestClient

    from modules.backend.app.main import app
    client = TestClient(app)
    print(f"payloads saved to {OUT.relative_to(REPO_ROOT)}\n")
    for name, payload in [("bruteforce_attack", attack_payload), ("benign", benign_payload)]:
        resp = client.post("/score", json=payload).json()
        print(f"[{name}.json]  (asset={payload['asset_criticality']}, "
              f"cve={payload['cve_severity']})")
        print(f"   -> {resp}\n")


if __name__ == "__main__":
    main()
