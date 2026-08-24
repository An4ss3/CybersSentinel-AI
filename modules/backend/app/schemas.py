"""Pydantic schemas for the backend API."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

CriticalityLevel = Literal["Low", "Medium", "High", "Critical"]


class ScoreRequest(BaseModel):
    attack: str = Field(..., description="Attack family, e.g. brute_force or ddos")
    features: dict[str, float] = Field(
        ..., description="CICIDS-style flow features (name -> value)"
    )
    asset_criticality: CriticalityLevel = "Low"
    cve_severity: float = Field(0.0, ge=0.0, le=10.0, description="CVSS base score")


class ScoreResponse(BaseModel):
    attack: str
    ml_confidence: float
    composite_score: float
    level: CriticalityLevel
    is_alert: bool
