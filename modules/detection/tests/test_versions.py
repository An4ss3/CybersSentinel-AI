"""Tests for mandatory four-part version contracts and compatibility policy."""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from modules.detection.src.contracts import (
    VersionCompatibilityError,
    VersionContract,
    compatibility_issues,
    ensure_compatible,
)
from modules.detection.src.schemas import FlowStart
from modules.detection.tests.conftest import flow_start_payload


def contract(**overrides: str) -> VersionContract:
    values = {
        "schema_version": "1.2.0",
        "event_version": "2.1.0",
        "feature_version": "3.4.0",
        "sensor_version": "6.2.0",
    }
    values.update(overrides)
    return VersionContract(**values)


@pytest.mark.parametrize("invalid", ["1", "1.0", "v1.0.0", "01.0.0", "1.0.0-beta"])
def test_malformed_version_is_rejected(invalid):
    with pytest.raises(ValidationError, match="schema_version"):
        contract(schema_version=invalid)


def test_all_four_versions_are_mandatory_on_payloads():
    payload = flow_start_payload()
    del payload["feature_version"]
    with pytest.raises(ValidationError, match="feature_version"):
        FlowStart.model_validate(payload)


def test_older_minor_contract_is_backward_compatible():
    produced = contract(
        schema_version="1.1.9",
        event_version="2.0.8",
        feature_version="3.3.4",
    )
    supported = contract()
    assert compatibility_issues(produced, supported) == ()
    ensure_compatible(produced, supported)


def test_patch_difference_is_compatible_within_same_minor():
    produced = contract(schema_version="1.2.99")
    supported = contract(schema_version="1.2.0")
    ensure_compatible(produced, supported)


def test_future_minor_is_rejected():
    produced = contract(feature_version="3.5.0")
    with pytest.raises(VersionCompatibilityError, match="feature_version"):
        ensure_compatible(produced, contract())


def test_major_mismatch_is_rejected():
    produced = contract(event_version="3.0.0")
    with pytest.raises(VersionCompatibilityError, match="event_version"):
        ensure_compatible(produced, contract())


def test_sensor_version_requires_exact_match():
    produced = contract(sensor_version="6.2.1")
    issues = compatibility_issues(produced, contract(sensor_version="6.2.0"))
    assert len(issues) == 1
    assert "exact match" in issues[0]
    with pytest.raises(VersionCompatibilityError, match="sensor_version"):
        ensure_compatible(produced, contract(sensor_version="6.2.0"))


def test_payload_can_expose_its_version_contract():
    event = FlowStart.model_validate(flow_start_payload())
    assert event.version_contract() == VersionContract(
        schema_version="1.0.0",
        event_version="1.0.0",
        feature_version="1.0.0",
        sensor_version="6.2.0",
    )
