"""Composite criticality scoring (§6.3).

A composite score in [0, 100] is built from three factors:
  * ML confidence      — the detector's probability the event is an attack,
  * asset criticality  — how important the targeted asset is,
  * CVE severity        — CVSS base score (0-10) of any linked vulnerability.

The blend is a transparent weighted sum (weights are configurable and sum to
1). The score is then discretised into the 4 levels from the cahier des
charges using the exact thresholds also encoded in modules/storage/schema.sql.
"""
from __future__ import annotations

from typing import Literal

CriticalityLevel = Literal["Low", "Medium", "High", "Critical"]

# Normalised weight of each factor (must sum to 1.0).
WEIGHTS = {"ml_confidence": 0.5, "asset_criticality": 0.3, "cve_severity": 0.2}

# Asset criticality mapped to a [0, 1] weight.
ASSET_CRITICALITY_WEIGHT: dict[str, float] = {
    "Low": 0.25, "Medium": 0.50, "High": 0.75, "Critical": 1.0,
}

# Section 6.3 thresholds (kept in sync with schema.sql score_to_level()).
LEVEL_THRESHOLDS = {"Critical": 80.0, "High": 60.0, "Medium": 35.0}


def _clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def composite_score(
    ml_confidence: float,
    asset_criticality: str = "Low",
    cve_severity: float = 0.0,
) -> float:
    """Return a composite criticality score in [0, 100].

    Parameters
    ----------
    ml_confidence : float
        Detector probability in [0, 1].
    asset_criticality : str
        One of Low / Medium / High / Critical.
    cve_severity : float
        CVSS base score in [0, 10] (0 if no CVE linked).
    """
    ml = _clamp(ml_confidence, 0.0, 1.0)
    asset = ASSET_CRITICALITY_WEIGHT.get(asset_criticality, 0.25)
    cve = _clamp(cve_severity, 0.0, 10.0) / 10.0

    score = 100.0 * (
        WEIGHTS["ml_confidence"] * ml
        + WEIGHTS["asset_criticality"] * asset
        + WEIGHTS["cve_severity"] * cve
    )
    return round(score, 2)


def score_to_level(score: float) -> CriticalityLevel:
    """Discretise a composite score into a criticality level (§6.3)."""
    if score >= LEVEL_THRESHOLDS["Critical"]:
        return "Critical"
    if score >= LEVEL_THRESHOLDS["High"]:
        return "High"
    if score >= LEVEL_THRESHOLDS["Medium"]:
        return "Medium"
    return "Low"
