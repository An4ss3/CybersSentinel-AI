"""Deterministic factories for valid canonical payloads used by Phase 1 tests."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from uuid import UUID

from modules.detection.src.lineage import EventProvenance

BASE_TIME = datetime(2026, 7, 20, 10, 0, tzinfo=timezone.utc)
SOURCE_EVENT_1 = UUID("00000000-0000-4000-8000-000000000001")
SOURCE_EVENT_2 = UUID("00000000-0000-4000-8000-000000000002")
WINDOW_EVENT = UUID("00000000-0000-4000-8000-000000000003")


def version_fields(sensor_version: str = "6.2.0") -> dict[str, str]:
    return {
        "schema_version": "1.0.0",
        "event_version": "1.0.0",
        "feature_version": "1.0.0",
        "sensor_version": sensor_version,
    }


def provenance(
    event_id: UUID = SOURCE_EVENT_1,
    *,
    dataset_snapshot_id: str | None = None,
    model_release_id: str | None = None,
) -> EventProvenance:
    return EventProvenance(
        event_id=event_id,
        sensor_id="um6p-sensor-01",
        sensor_run_id="run-20260720-01",
        capture_id="capture-20260720-01",
        dataset_snapshot_id=dataset_snapshot_id,
        model_release_id=model_release_id,
        normalizer_version="1.0.0",
        pipeline_version="1.0.0",
    )


def endpoints() -> tuple[dict[str, object], dict[str, object]]:
    return (
        {"ip": ip_address("192.0.2.10"), "port": 42424},
        {"ip": ip_address("198.51.100.20"), "port": 443},
    )


def flow_start_payload() -> dict[str, object]:
    source, destination = endpoints()
    return {
        **version_fields(),
        "event_type": "flow_start",
        "sensor_type": "zeek",
        "provenance": provenance(),
        "event_start_time": BASE_TIME,
        "event_end_time": None,
        "record_available_time": BASE_TIME + timedelta(milliseconds=20),
        "ingested_at": BASE_TIME + timedelta(milliseconds=40),
        "conversation_id": "CZeek0001",
        "source": source,
        "destination": destination,
        "transport": "tcp",
        "service": "ssl",
        "initial_state": None,
    }


def flow_update_payload() -> dict[str, object]:
    payload = flow_start_payload()
    payload.update(
        {
            "event_type": "flow_update",
            "provenance": provenance(SOURCE_EVENT_2),
            "record_available_time": BASE_TIME + timedelta(seconds=10),
            "ingested_at": BASE_TIME + timedelta(seconds=10, milliseconds=20),
            "sequence": 1,
            "counters": {
                "source_packets": 10,
                "destination_packets": 8,
                "source_bytes": 1200,
                "destination_bytes": 4200,
            },
        }
    )
    payload.pop("initial_state")
    return payload


def flow_end_payload() -> dict[str, object]:
    payload = flow_update_payload()
    payload.update(
        {
            "event_type": "flow_end",
            "event_end_time": BASE_TIME + timedelta(seconds=30),
            "record_available_time": BASE_TIME + timedelta(seconds=31),
            "ingested_at": BASE_TIME + timedelta(seconds=32),
            "connection_state": "SF",
            "termination_reason": "normal",
        }
    )
    payload.pop("sequence")
    return payload


def signature_payload() -> dict[str, object]:
    source, destination = endpoints()
    return {
        **version_fields(sensor_version="7.0.0"),
        "event_type": "signature",
        "sensor_type": "suricata",
        "provenance": provenance(),
        "event_start_time": BASE_TIME,
        "event_end_time": None,
        "record_available_time": BASE_TIME + timedelta(milliseconds=30),
        "ingested_at": BASE_TIME + timedelta(milliseconds=50),
        "conversation_id": "suricata-flow-42",
        "source": source,
        "destination": destination,
        "transport": "tcp",
        "service": "http",
        "signature_id": "ET-20260720-1",
        "revision": 1,
        "category": "Potentially Bad Traffic",
        "severity": 2,
        "action": "allowed",
        "message": "Controlled test signature",
    }


def sensor_health_payload() -> dict[str, object]:
    return {
        **version_fields(),
        "event_type": "sensor_health",
        "sensor_type": "zeek",
        "provenance": provenance(),
        "event_start_time": BASE_TIME,
        "event_end_time": BASE_TIME + timedelta(minutes=1),
        "record_available_time": BASE_TIME + timedelta(minutes=1, seconds=1),
        "ingested_at": BASE_TIME + timedelta(minutes=1, seconds=2),
        "interface": "eth0",
        "status": "healthy",
        "packets_received": 10000,
        "packets_dropped": 2,
        "events_emitted": 500,
        "queue_depth": 0,
        "message": None,
    }


def feature_window_payload() -> dict[str, object]:
    return {
        **version_fields(),
        "provenance": provenance(WINDOW_EVENT, dataset_snapshot_id="snapshot-001"),
        "window_id": "window-dst-service-001",
        "entity_type": "destination_service",
        "entity_key": ("asset-web-01", "https"),
        "window_start_time": BASE_TIME,
        "window_end_time": BASE_TIME + timedelta(minutes=1),
        "prediction_time": BASE_TIME + timedelta(minutes=1),
        "record_available_time": BASE_TIME + timedelta(minutes=1, milliseconds=50),
        "source_event_ids": (SOURCE_EVENT_1, SOURCE_EVENT_2),
        "features": {"flow_rate": 2.5, "unique_sources": 2.0},
        "data_quality": {
            "source_event_count": 2,
            "late_event_count": 0,
            "dropped_event_count": 0,
            "is_final": True,
            "is_revision": False,
        },
    }



# Full frozen-data M3 v2 runs are integration tests, not default unit regression.
# Each call processes 1,380,057 real Zeek records (and the determinism test does
# so twice). Keeping them in the default run caused a >30-minute silent interval.
# They remain directly executable with ``--run-full-zeek-v2``.
_FULL_ZEEK_V2_TESTS = {
    "test_process_first_partition_produces_valid_result",
    "test_process_first_partition_is_deterministic",
    "test_build_partition_report_from_result",
    "test_full_run_produces_validated_report",
    "test_full_run_is_deterministic",
    "test_immutable_publication_writes_valid_json",
    "test_immutable_publication_fails_on_existing_file",
    "test_immutable_publication_fails_on_existing_staging",
    "test_immutable_publication_no_staging_residue_on_success",
    "test_report_content_hash_is_formatting_independent",
}


def pytest_addoption(parser) -> None:
    parser.addoption(
        "--run-full-zeek-v2",
        action="store_true",
        default=False,
        help="run M3 v2 integration tests over all frozen Zeek records",
    )


def pytest_configure(config) -> None:
    config.addinivalue_line(
        "markers",
        "full_zeek_v2: processes a full frozen Zeek partition or all 1,380,057 records",
    )


def pytest_collection_modifyitems(config, items) -> None:
    if config.getoption("--run-full-zeek-v2"):
        return

    import pytest

    skip = pytest.mark.skip(
        reason="full frozen-data integration test; opt in with --run-full-zeek-v2"
    )
    for item in items:
        path = str(item.path).replace("\\", "/")
        if path.endswith("modules/detection/tests/test_zeek_pipeline_v2.py") and item.name in _FULL_ZEEK_V2_TESTS:
            item.add_marker("full_zeek_v2")
            item.add_marker(skip)
