"""Tests for complete and immutable source/processing provenance."""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from modules.detection.src.lineage import EventProvenance
from modules.detection.tests.conftest import SOURCE_EVENT_1, provenance


def test_provenance_round_trip_preserves_identity():
    value = provenance(
        dataset_snapshot_id="snapshot-20260720",
        model_release_id="model-release-001",
    )
    restored = EventProvenance.model_validate_json(value.model_dump_json())
    assert restored == value
    assert restored.event_id == SOURCE_EVENT_1


@pytest.mark.parametrize("field_name", ["dataset_snapshot_id", "model_release_id"])
def test_not_yet_applicable_ids_must_be_explicit_nulls(field_name):
    value = provenance()
    assert value.dataset_snapshot_id is None
    assert value.model_release_id is None

    payload = value.model_dump()
    del payload[field_name]
    with pytest.raises(ValidationError, match=field_name):
        EventProvenance.model_validate(payload)


def test_every_source_identity_field_is_mandatory():
    payload = provenance().model_dump()
    del payload["capture_id"]
    with pytest.raises(ValidationError, match="capture_id"):
        EventProvenance.model_validate(payload)


def test_blank_or_whitespace_identifier_is_rejected():
    payload = provenance().model_dump()
    payload["sensor_id"] = " "
    with pytest.raises(ValidationError, match="sensor_id"):
        EventProvenance.model_validate(payload)


def test_unknown_provenance_field_is_rejected():
    payload = provenance().model_dump()
    payload["pcap_guess"] = "unknown.pcap"
    with pytest.raises(ValidationError, match="extra_forbidden"):
        EventProvenance.model_validate(payload)


def test_provenance_is_immutable():
    value = provenance()
    with pytest.raises(ValidationError, match="frozen_instance"):
        value.capture_id = "different-capture"
