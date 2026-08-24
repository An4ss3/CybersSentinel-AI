"""Validation and serialization tests for every canonical network-event type."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json

import pytest
from pydantic import ValidationError

from modules.detection.src.schemas import (
    FlowEnd,
    FlowStart,
    FlowUpdate,
    SensorHealthEvent,
    SignatureEvent,
    parse_network_event_json,
)
from modules.detection.tests.conftest import (
    BASE_TIME,
    flow_end_payload,
    flow_start_payload,
    flow_update_payload,
    sensor_health_payload,
    signature_payload,
)


@pytest.mark.parametrize(
    ("model", "factory"),
    [
        (FlowStart, flow_start_payload),
        (FlowUpdate, flow_update_payload),
        (FlowEnd, flow_end_payload),
        (SignatureEvent, signature_payload),
        (SensorHealthEvent, sensor_health_payload),
    ],
)
def test_each_concrete_event_round_trips_through_discriminator(model, factory):
    event = model.model_validate(factory())
    restored = parse_network_event_json(event.model_dump_json())
    assert type(restored) is model
    assert restored == event


def test_missing_nullable_field_is_still_rejected():
    payload = flow_start_payload()
    del payload["service"]
    with pytest.raises(ValidationError, match="service"):
        FlowStart.model_validate(payload)


def test_unknown_top_level_field_is_rejected():
    payload = flow_start_payload()
    payload["legacy_label"] = "BENIGN"
    with pytest.raises(ValidationError, match="extra_forbidden"):
        FlowStart.model_validate(payload)


def test_unknown_nested_field_is_rejected():
    payload = flow_start_payload()
    payload["source"] = {**payload["source"], "hostname": "invented"}
    with pytest.raises(ValidationError, match="extra_forbidden"):
        FlowStart.model_validate(payload)


def test_numeric_strings_are_not_coerced():
    payload = flow_update_payload()
    payload["counters"] = {**payload["counters"], "source_packets": "10"}
    with pytest.raises(ValidationError, match="source_packets"):
        FlowUpdate.model_validate(payload)


def test_integer_ip_representation_is_not_coerced():
    payload = flow_start_payload()
    payload["source"] = {**payload["source"], "ip": 3221225985}
    with pytest.raises(ValidationError, match="IP address must be a string"):
        FlowStart.model_validate(payload)


def test_integer_ip_representation_is_rejected_in_json():
    event = FlowStart.model_validate(flow_start_payload())
    payload = json.loads(event.model_dump_json())
    payload["source"]["ip"] = 3221225985
    with pytest.raises(ValidationError, match="IP address must be a string"):
        parse_network_event_json(json.dumps(payload))


def test_naive_timestamp_is_rejected():
    payload = flow_start_payload()
    payload["event_start_time"] = datetime(2026, 7, 20, 10, 0)
    with pytest.raises(ValidationError, match="timezone-aware UTC"):
        FlowStart.model_validate(payload)


def test_non_utc_timestamp_is_rejected():
    payload = flow_start_payload()
    non_utc = timezone(timedelta(hours=1))
    payload["event_start_time"] = BASE_TIME.astimezone(non_utc)
    with pytest.raises(ValidationError, match="timezone-aware UTC"):
        FlowStart.model_validate(payload)


def test_end_before_start_is_rejected():
    payload = flow_end_payload()
    payload["event_end_time"] = BASE_TIME - timedelta(seconds=1)
    with pytest.raises(ValidationError, match="event_end_time"):
        FlowEnd.model_validate(payload)


def test_record_cannot_be_available_before_final_flow_data():
    payload = flow_end_payload()
    payload["record_available_time"] = BASE_TIME + timedelta(seconds=20)
    with pytest.raises(ValidationError, match="record_available_time"):
        FlowEnd.model_validate(payload)


def test_ingestion_cannot_precede_availability():
    payload = signature_payload()
    payload["ingested_at"] = BASE_TIME
    with pytest.raises(ValidationError, match="ingested_at"):
        SignatureEvent.model_validate(payload)


def test_wrong_discriminator_is_rejected_explicitly():
    payload = flow_start_payload()
    payload["event_type"] = "unknown_event"
    with pytest.raises(ValidationError, match="union_tag_invalid"):
        parse_network_event_json(json.dumps(payload, default=str))


def test_event_is_immutable_after_validation():
    event = FlowStart.model_validate(flow_start_payload())
    with pytest.raises(ValidationError, match="frozen_instance"):
        event.sensor_type = "suricata"
