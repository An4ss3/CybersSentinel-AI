"""Deterministic factories for valid canonical payloads used by Phase 1 tests."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from hashlib import sha256
from ipaddress import ip_address
from pathlib import Path
from uuid import UUID

import pytest

from modules.detection.src.lineage import EventProvenance

BASE_TIME = datetime(2026, 7, 20, 10, 0, tzinfo=timezone.utc)
SOURCE_EVENT_1 = UUID("00000000-0000-4000-8000-000000000001")
SOURCE_EVENT_2 = UUID("00000000-0000-4000-8000-000000000002")
WINDOW_EVENT = UUID("00000000-0000-4000-8000-000000000003")

# --- Frozen production artifact guard ---------------------------------------
#
# The M4 production report is frozen canonical evidence published by a real
# 1,380,057-record materialization. The regression suite must neither fabricate
# nor mutate it. Asserting that the file is simply absent was only correct
# before M4 was executed; that assertion now contradicts the frozen chain. The
# invariant that still has teeth is that this session leaves the artifact
# exactly as it found it, so its digest is captured here, at conftest import
# time, before any test in the session runs.

_REPO_ROOT = Path(__file__).resolve().parents[3]
_PRODUCTION_M4_REPORT = (
    _REPO_ROOT / "artifacts" / "reports" / "m4_v2_materialization_run.json"
)
#: Record count that only a genuine M4 materialization can declare.
AUTHENTIC_M4_PROCESSED_RECORD_COUNT = 1_380_057


def _fingerprint_production_m4_report() -> str | None:
    """Digest of the frozen M4 report, or ``None`` when it does not exist."""
    if not _PRODUCTION_M4_REPORT.exists():
        return None
    return sha256(_PRODUCTION_M4_REPORT.read_bytes()).hexdigest()


_M4_FINGERPRINT_AT_SESSION_START = _fingerprint_production_m4_report()


@pytest.fixture(scope="session")
def production_m4_report_fingerprint() -> str | None:
    """The frozen M4 report digest as observed before any test executed."""
    return _M4_FINGERPRINT_AT_SESSION_START


def assert_production_m4_report_untouched(expected_fingerprint: str | None) -> None:
    """Fail if this session created, deleted or modified the frozen M4 report."""
    observed = _fingerprint_production_m4_report()
    assert observed == expected_fingerprint, (
        "the production M4 report must only be published by a real "
        f"{AUTHENTIC_M4_PROCESSED_RECORD_COUNT}-record materialization, never as "
        "a test side effect; this session changed it from "
        f"{expected_fingerprint} to {observed}"
    )
    if observed is None:
        return
    import json

    report = json.loads(_PRODUCTION_M4_REPORT.read_text(encoding="utf-8"))
    assert report["total_processed_record_count"] == (
        AUTHENTIC_M4_PROCESSED_RECORD_COUNT
    ), (
        "the production M4 report exists but does not declare the authentic "
        "materialization record count, so it cannot be frozen evidence"
    )


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


# Tests that read the frozen Zeek replay logs themselves. Those logs (~2.2 GB)
# are not distributed with the repository (see .gitignore): they are
# regenerated byte-for-byte from the digest-pinned Zeek image. On a fresh clone
# these tests are skipped with an explicit reason instead of failing; wherever
# the logs are present they run unchanged.
_FROZEN_ZEEK_LOG_TESTS = {
    "test_m4_materialization.py": {
        "test_flow_end_row_preserves_provenance_verbatim",
        "test_flow_end_row_preserves_exact_temporal_strings_no_float",
        "test_flow_end_row_preserves_source_coordinate",
        "test_flow_end_row_preserves_endpoints_and_counters",
        "test_flow_end_row_event_bytes_hash_matches_frozen_serialization",
        "test_materialize_partition_logic_on_real_first_line_without_db",
    },
    "test_mb2_replay.py": {"test_frozen_m2_tree_still_holds_ninety_five_files"},
    "test_mb3_normalization.py": {
        "test_first_accepted_event_id_is_reproducible_from_the_uuid5_formula",
        "test_frozen_m2_tree_still_holds_ninety_five_files",
    },
    "test_zeek_conn_normalizer_v2.py": {"test_normalizer_accepts_real_first_line"},
    "test_zeek_normalization_pipeline.py": {
        "test_bounded_real_first_lines_parse_and_obey_frozen_precision_rejection"
    },
    "test_zeek_pipeline_v2.py": {
        "test_process_real_first_line_produces_expected_event",
        "test_preflight_rejects_wrong_size",
    },
}
_FROZEN_M2_TUESDAY_CONN_LOG = (
    _REPO_ROOT
    / "artifacts"
    / "canonical"
    / "cicids2017"
    / "m2"
    / "zeek-8.0.9"
    / "2017-07-04_Tuesday-WorkingHours"
    / "conn.log"
)


def pytest_collection_modifyitems(config, items) -> None:
    import pytest

    if not _FROZEN_M2_TUESDAY_CONN_LOG.is_file():
        skip_logs = pytest.mark.skip(
            reason="requires the frozen Zeek replay logs, which are not "
            "distributed; regenerate them with the digest-pinned zeek-replay service"
        )
        for item in items:
            if item.name in _FROZEN_ZEEK_LOG_TESTS.get(item.path.name, ()):
                item.add_marker(skip_logs)

    if config.getoption("--run-full-zeek-v2"):
        return

    skip = pytest.mark.skip(
        reason="full frozen-data integration test; opt in with --run-full-zeek-v2"
    )
    for item in items:
        path = str(item.path).replace("\\", "/")
        if path.endswith("modules/detection/tests/test_zeek_pipeline_v2.py") and item.name in _FULL_ZEEK_V2_TESTS:
            item.add_marker("full_zeek_v2")
            item.add_marker(skip)
