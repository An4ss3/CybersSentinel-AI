"""Deterministic canonical-event factories for M5 sidecar labeling tests."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from pathlib import Path
from uuid import UUID, uuid5
from zoneinfo import ZoneInfo

from modules.detection.src.lineage import EventProvenance
from modules.detection.src.schemas import (
    FlowEnd,
    SensorHealthEvent,
)

MANIFEST_PATH = Path("datasets/manifests/cicids2017_labels.yaml")
_UUID_NAMESPACE = UUID("10000000-0000-4000-8000-000000000005")
_LOCAL_ZONE = ZoneInfo("America/Moncton")


def local_datetime(value: str) -> datetime:
    """Convert an ISO local CICIDS schedule timestamp to canonical UTC."""
    return datetime.fromisoformat(value).replace(tzinfo=_LOCAL_ZONE).astimezone(timezone.utc)


def flow_event(
    *,
    start_local: str,
    end_local: str | None = None,
    source_ip: str = "205.174.165.73",
    destination_ip: str = "205.174.165.80",
    source_port: int | None = 40000,
    destination_port: int | None = 21,
    transport: str = "tcp",
    service: str | None = "ftp",
    identity: str = "event",
) -> FlowEnd:
    start = local_datetime(start_local)
    end = local_datetime(end_local) if end_local is not None else start
    event_id = uuid5(_UUID_NAMESPACE, identity)
    return FlowEnd(
        schema_version="1.0.0",
        event_version="1.0.0",
        feature_version="1.0.0",
        sensor_version="6.2.0",
        event_type="flow_end",
        sensor_type="zeek",
        provenance=EventProvenance(
            event_id=event_id,
            sensor_id="cicids-zeek",
            sensor_run_id="cicids-replay-001",
            capture_id="cicids2017-capture",
            dataset_snapshot_id=None,
            model_release_id=None,
            normalizer_version="1.0.0",
            pipeline_version="1.0.0",
        ),
        event_start_time=start,
        event_end_time=end,
        record_available_time=end + timedelta(milliseconds=1),
        ingested_at=end + timedelta(milliseconds=2),
        conversation_id=f"zeek-{identity}",
        source={"ip": ip_address(source_ip), "port": source_port},
        destination={"ip": ip_address(destination_ip), "port": destination_port},
        transport=transport,
        service=service,
        counters={
            "source_packets": 10,
            "destination_packets": 8,
            "source_bytes": 1000,
            "destination_bytes": 2000,
        },
        connection_state="SF",
        termination_reason=None,
    )


def sensor_health_event(identity: str = "health") -> SensorHealthEvent:
    start = local_datetime("2017-07-03T10:00:00")
    event_id = uuid5(_UUID_NAMESPACE, identity)
    return SensorHealthEvent(
        schema_version="1.0.0",
        event_version="1.0.0",
        feature_version="1.0.0",
        sensor_version="6.2.0",
        event_type="sensor_health",
        sensor_type="zeek",
        provenance=EventProvenance(
            event_id=event_id,
            sensor_id="cicids-zeek",
            sensor_run_id="cicids-replay-001",
            capture_id="cicids2017-capture",
            dataset_snapshot_id=None,
            model_release_id=None,
            normalizer_version="1.0.0",
            pipeline_version="1.0.0",
        ),
        event_start_time=start,
        event_end_time=start + timedelta(minutes=1),
        record_available_time=start + timedelta(minutes=1, milliseconds=1),
        ingested_at=start + timedelta(minutes=1, milliseconds=2),
        interface="offline-pcap",
        status="healthy",
        packets_received=100,
        packets_dropped=0,
        events_emitted=10,
        queue_depth=0,
        message=None,
    )
