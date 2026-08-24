"""Tests for causal, finite, traceable, and immutable feature windows."""
from __future__ import annotations

from datetime import timedelta

import pytest
from pydantic import ValidationError

from modules.detection.src.schemas import FeatureWindow
from modules.detection.tests.conftest import (
    BASE_TIME,
    SOURCE_EVENT_1,
    feature_window_payload,
)


def test_feature_window_json_round_trip_preserves_contract():
    window = FeatureWindow.model_validate(feature_window_payload())
    restored = FeatureWindow.model_validate_json(window.model_dump_json())
    assert restored == window
    assert restored.features["flow_rate"] == 2.5


def test_window_requires_nonempty_features():
    payload = feature_window_payload()
    payload["features"] = {}
    with pytest.raises(ValidationError, match="features"):
        FeatureWindow.model_validate(payload)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_non_finite_feature_is_rejected(value):
    payload = feature_window_payload()
    payload["features"] = {"flow_rate": value}
    with pytest.raises(ValidationError, match="finite"):
        FeatureWindow.model_validate(payload)


def test_feature_numeric_string_is_not_coerced():
    payload = feature_window_payload()
    payload["features"] = {"flow_rate": "2.5"}
    with pytest.raises(ValidationError, match="flow_rate"):
        FeatureWindow.model_validate(payload)


def test_duplicate_source_event_ids_are_rejected():
    payload = feature_window_payload()
    payload["source_event_ids"] = (SOURCE_EVENT_1, SOURCE_EVENT_1)
    with pytest.raises(ValidationError, match="unique"):
        FeatureWindow.model_validate(payload)


def test_lineage_count_must_match_source_ids():
    payload = feature_window_payload()
    payload["data_quality"] = {**payload["data_quality"], "source_event_count": 1}
    with pytest.raises(ValidationError, match="source_event_count"):
        FeatureWindow.model_validate(payload)


def test_window_event_cannot_claim_itself_as_source():
    payload = feature_window_payload()
    payload["source_event_ids"] = (
        payload["provenance"].event_id,
        SOURCE_EVENT_1,
    )
    with pytest.raises(ValidationError, match="cannot also be a source"):
        FeatureWindow.model_validate(payload)


def test_window_end_after_prediction_is_rejected():
    payload = feature_window_payload()
    payload["prediction_time"] = BASE_TIME + timedelta(seconds=30)
    with pytest.raises(ValidationError, match="window_end_time"):
        FeatureWindow.model_validate(payload)


def test_prediction_after_availability_is_rejected():
    payload = feature_window_payload()
    payload["record_available_time"] = BASE_TIME + timedelta(seconds=30)
    with pytest.raises(ValidationError, match="prediction_time"):
        FeatureWindow.model_validate(payload)


def test_unknown_window_field_is_rejected():
    payload = feature_window_payload()
    payload["label"] = "attack"
    with pytest.raises(ValidationError, match="extra_forbidden"):
        FeatureWindow.model_validate(payload)
