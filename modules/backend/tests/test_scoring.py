"""Tests for the §6.3 scoring logic and the /score API."""
from modules.backend.app.scoring import composite_score, score_to_level


def test_score_bounds():
    # Max everything -> 100, nothing -> 0.
    assert composite_score(1.0, "Critical", 10.0) == 100.0
    assert composite_score(0.0, "Low", 0.0) == 100.0 * 0.3 * 0.25  # asset floor
    assert 0.0 <= composite_score(0.5, "Medium", 5.0) <= 100.0


def test_level_thresholds():
    # Boundaries from §6.3 (80 / 60 / 35).
    assert score_to_level(80.0) == "Critical"
    assert score_to_level(79.99) == "High"
    assert score_to_level(60.0) == "High"
    assert score_to_level(59.99) == "Medium"
    assert score_to_level(35.0) == "Medium"
    assert score_to_level(34.99) == "Low"
    assert score_to_level(0.0) == "Low"


def test_ml_confidence_dominates_weight():
    # A high-confidence detection on a critical asset with a severe CVE
    # should escalate to Critical.
    s = composite_score(0.95, "Critical", 9.8)
    assert score_to_level(s) == "Critical"


def test_health_and_score_via_testclient():
    """Smoke-test the API end-to-end using a real trained model if present."""
    from fastapi.testclient import TestClient

    from modules.backend.app.main import app
    from modules.backend.app.predictor import available_models

    client = TestClient(app)
    assert client.get("/health").status_code == 200

    models = available_models()
    if not models:
        return  # no trained model in this environment; scoring tests above still cover §6.3

    attack = models[0]
    # Minimal feature dict; predictor fills the rest with 0.
    resp = client.post("/score", json={
        "attack": attack,
        "features": {"Flow Duration": 1000, "Total Fwd Packets": 5},
        "asset_criticality": "High",
        "cve_severity": 7.5,
    })
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["attack"] == attack
    assert 0.0 <= body["ml_confidence"] <= 1.0
    assert 0.0 <= body["composite_score"] <= 100.0
    assert body["level"] in {"Low", "Medium", "High", "Critical"}
