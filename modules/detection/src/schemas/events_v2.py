"""Canonical M3 v2 network events with exact DECIMAL(38,22) time."""
from __future__ import annotations

from typing import Literal, TypeAlias

from pydantic import model_validator

from modules.detection.src.contracts import StrictIdentifier, VersionedModel
from modules.detection.src.lineage.provenance import EventProvenance
from modules.detection.src.schemas.common import FlowCounters, NetworkEndpoint
from modules.detection.src.schemas.exact_time_v2 import (
    ExactDecimalSeconds22,
    unscaled_from_canonical,
)


class FlowEndV2(VersionedModel):
    """Exact final Zeek flow event under the breaking M3 v2 temporal contract."""

    event_type: Literal["flow_end"]
    sensor_type: Literal["zeek"]
    provenance: EventProvenance
    event_start_time: ExactDecimalSeconds22
    event_duration: ExactDecimalSeconds22
    event_end_time: ExactDecimalSeconds22
    record_available_time: ExactDecimalSeconds22
    ingested_at: ExactDecimalSeconds22
    conversation_id: StrictIdentifier
    source: NetworkEndpoint
    destination: NetworkEndpoint
    transport: Literal["tcp", "udp"]
    service: StrictIdentifier | None
    counters: FlowCounters
    connection_state: StrictIdentifier
    termination_reason: None

    @model_validator(mode="after")
    def validate_v2_contract(self) -> "FlowEndV2":
        expected_versions = (
            "2.0.0",
            "2.0.0",
            "1.0.0",
            "8.0.9",
        )
        actual_versions = (
            self.schema_version,
            self.event_version,
            self.feature_version,
            self.sensor_version,
        )
        if actual_versions != expected_versions:
            raise ValueError("FlowEndV2 versions do not match the M3 v2 contract")
        if self.provenance.sensor_id != "zeek":
            raise ValueError("FlowEndV2 provenance sensor_id must be zeek")
        if (
            self.provenance.normalizer_version != "2.0.0"
            or self.provenance.pipeline_version != "2.0.0"
        ):
            raise ValueError("FlowEndV2 provenance versions must be 2.0.0")
        if self.provenance.model_release_id is not None:
            raise ValueError("FlowEndV2 model_release_id must be explicit null")
        start = unscaled_from_canonical(self.event_start_time)
        duration = unscaled_from_canonical(self.event_duration)
        end = unscaled_from_canonical(self.event_end_time)
        available = unscaled_from_canonical(self.record_available_time)
        ingested = unscaled_from_canonical(self.ingested_at)
        if start + duration != end:
            raise ValueError("event_end_time must exactly equal start plus duration")
        if end > available:
            raise ValueError("record_available_time precedes exact event end")
        if available > ingested:
            raise ValueError("ingested_at precedes record_available_time")
        return self


CanonicalNetworkEventV2: TypeAlias = FlowEndV2
