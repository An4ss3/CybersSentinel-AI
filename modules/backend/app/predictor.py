"""Prediction service (Couche 3 → 7 bridge).

Loads a persisted model bundle produced by modules/detection (joblib dict with
``model``, ``features``, ``attack``, ``protocol``) and returns the attack
probability for a single network-flow feature dict. Missing features are
filled with 0 and column order is aligned to the training schema.
"""
from __future__ import annotations

from pathlib import Path

import joblib
import pandas as pd

# Repo root = three levels up from this file (modules/backend/app/predictor.py).
REPO_ROOT = Path(__file__).resolve().parents[3]
MODELS_DIR = REPO_ROOT / "models"


class Predictor:
    """Wraps one trained attack-family model."""

    def __init__(self, attack: str, protocol: str = "production", threshold: float = 0.5):
        self.attack = attack
        self.protocol = protocol
        self.threshold = threshold
        path = MODELS_DIR / f"xgboost_{attack}_{protocol}.joblib"
        if not path.exists():
            raise FileNotFoundError(
                f"Model not found: {path}. Train it with "
                f"`python -m modules.detection.src.train --attack {attack} "
                f"--protocol {protocol}`."
            )
        bundle = joblib.load(path)
        self.model = bundle["model"]
        self.features: list[str] = bundle["features"]

    def predict_proba(self, flow: dict[str, float]) -> float:
        """Return the probability (0-1) that ``flow`` is this attack."""
        row = pd.DataFrame([flow]).reindex(columns=self.features, fill_value=0.0)
        row = row.apply(pd.to_numeric, errors="coerce").fillna(0.0)
        return float(self.model.predict_proba(row)[0, 1])

    def predict_proba_batch(self, flows: "pd.DataFrame"):
        """Vectorised probability for many flows at once (returns np.ndarray)."""
        X = flows.reindex(columns=self.features, fill_value=0.0)
        X = X.apply(pd.to_numeric, errors="coerce").fillna(0.0)
        return self.model.predict_proba(X)[:, 1]

    def is_attack(self, proba: float) -> bool:
        return proba >= self.threshold


def available_models(protocol: str = "production") -> list[str]:
    """List attack families that have a persisted model for ``protocol``."""
    if not MODELS_DIR.exists():
        return []
    prefix, suffix = "xgboost_", f"_{protocol}.joblib"
    return sorted(
        p.name[len(prefix):-len(suffix)]
        for p in MODELS_DIR.glob(f"xgboost_*_{protocol}.joblib")
    )
