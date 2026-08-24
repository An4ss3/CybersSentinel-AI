"""CyberSentinel AI — backend API (FastAPI).

Minimal MVP surface:
  * GET  /health            liveness + which models are loaded
  * POST /score             flow features -> attack proba -> §6.3 composite alert

SECURITY NOTE: this API has NO authentication yet. It is fine for the isolated
local lab, but before any shared/VM deployment it must sit behind auth + RBAC
(analyste / superviseur / admin, per §9). Do not expose it publicly as-is.

Run (dev):
    uvicorn modules.backend.app.main:app --reload
"""
from __future__ import annotations

from fastapi import FastAPI, HTTPException

from .predictor import Predictor, available_models
from .schemas import ScoreRequest, ScoreResponse
from .scoring import composite_score, score_to_level

app = FastAPI(title="CyberSentinel AI — Backend", version="0.1.0")

# Lazy model cache: load each attack model on first use.
_predictors: dict[str, Predictor] = {}


def get_predictor(attack: str) -> Predictor:
    if attack not in _predictors:
        try:
            _predictors[attack] = Predictor(attack)
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
    return _predictors[attack]


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "available_models": available_models()}


@app.post("/score", response_model=ScoreResponse)
def score(req: ScoreRequest) -> ScoreResponse:
    predictor = get_predictor(req.attack)
    proba = predictor.predict_proba(req.features)
    total = composite_score(proba, req.asset_criticality, req.cve_severity)
    return ScoreResponse(
        attack=req.attack,
        ml_confidence=round(proba, 4),
        composite_score=total,
        level=score_to_level(total),
        is_alert=predictor.is_attack(proba),
    )
