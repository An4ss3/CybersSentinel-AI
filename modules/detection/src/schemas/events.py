"""Canonical network-event models independent of Zeek or Suricata syntax.

The event hierarchy preserves observation time, availability time, ingestion
time, flow identity, and directional counters.  Those fields were absent from
the CICIDS CSV pipeline, making temporal evaluation, event replay, and causal
online features impossible.  Only concrete event types enter the discriminated
canonical-event union.
"""
from __future__ import annotations

from typing import Annotated, Literal, TypeAlias

from pydantic import Field, TypeAdapter, model_validator

from modules.detection.src.contracts import (
    NonEmptyText,
    NonNegativeInt,
    PositiveInt,
    StrictIdentifier,
    UtcDateTime,
    VersionedModel,
)
from modules.detection.src.lineage import EventProvenance

from .common import FlowCounters, NetworkEndpoint

EventType: TypeAlias = Literal[
    "flow_start",
    "flow_update",
    "flow_end",
    "signature",
    "sensor_health",
]
SensorType: TypeAlias = Literal["zeek", "suricata", "derived", "other"]
TransportProtocol: TypeAlias = Literal["tcp", "udp", "icmp", "icmpv6", "sctp", "other"]


class NetworkEvent(VersionedModel):
    """Common immutable envelope inherited by all canonical network events."""

    event_type: EventType
    sensor_type: SensorType
    provenance: EventProvenance
    event_start_time: UtcDateTime
    event_end_time: UtcDateTime | None
    record_available_time: UtcDateTime
    ingested_at: UtcDateTime

    @model_validator(mode="after")
    def validate_temporal_order(self) -> "NetworkEvent":
        if self.event_end_time is not None and self.event_end_time < self.event_start_time:
            raise ValueError("event_end_time cannot precede event_start_time")
        availability_floor = self.event_end_time or self.event_start_time
        if self.record_available_time < availability_floor:
            raise ValueError("record_available_time precedes observable event data")
        if self.ingested_at < self.record_available_time:
            raise ValueError("ingested_at cannot precede record_available_time")
        return self


class _FlowEvent(NetworkEvent):
    """Shared fields for one sensor-observed bidirectional conversation."""

    conversation_id: StrictIdentifier
    source: NetworkEndpoint
    destination: NetworkEndpoint
    transport: TransportProtocol
    service: StrictIdentifier | None


class FlowStart(_FlowEvent):
    """Beginning of an observed flow; no final-flow values are available yet."""

    event_type: Literal["flow_start"]
    event_end_time: None
    initial_state: StrictIdentifier | None


class FlowUpdate(_FlowEvent):
    """Causal periodic flow snapshot used before a long connection closes."""

    event_type: Literal["flow_update"]
    event_end_time: None
    sequence: PositiveInt
    counters: FlowCounters


class FlowEnd(_FlowEvent):
    """Final flow record available only after the connection has ended."""

    event_type: Literal["flow_end"]
    event_end_time: UtcDateTime
    counters: FlowCounters
    connection_state: StrictIdentifier
    termination_reason: StrictIdentifier | None


class SignatureEvent(NetworkEvent):
    """Independently attributable IDS signature evidence, normally from EVE."""

    event_type: Literal["signature"]
    conversation_id: StrictIdentifier | None
    source: NetworkEndpoint
    destination: NetworkEndpoint
    transport: TransportProtocol
    service: StrictIdentifier | None
    signature_id: StrictIdentifier
    revision: PositiveInt
    category: NonEmptyText
    severity: Annotated[int, Field(ge=0, le=255)]
    action: StrictIdentifier
    message: NonEmptyText


class SensorHealthEvent(NetworkEvent):
    """Capture and processing health needed to interpret event-rate features."""

    event_type: Literal["sensor_health"]
    event_end_time: UtcDateTime
    interface: StrictIdentifier
    status: Literal["healthy", "degraded", "unhealthy"]
    packets_received: NonNegativeInt
    packets_dropped: NonNegativeInt
    events_emitted: NonNegativeInt
    queue_depth: NonNegativeInt
    message: NonEmptyText | None


CanonicalNetworkEvent: TypeAlias = Annotated[
    FlowStart | FlowUpdate | FlowEnd | SignatureEvent | SensorHealthEvent,
    Field(discriminator="event_type"),
]
CANONICAL_EVENT_ADAPTER = TypeAdapter(CanonicalNetworkEvent)


def parse_network_event_json(data: str | bytes | bytearray) -> CanonicalNetworkEvent:
    """Deserialize JSON through the concrete discriminated event contract."""
    return CANONICAL_EVENT_ADAPTER.validate_json(data)
