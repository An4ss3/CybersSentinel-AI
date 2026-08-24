"""Reusable value objects for canonical network and feature schemas.

These objects make units and directionality explicit.  The legacy feature table
used opaque column names and silently replaced invalid values, preventing robust
schema checks and making training-serving equivalence unverifiable.
"""
from __future__ import annotations

from pydantic import model_validator

from modules.detection.src.contracts import (
    NonNegativeInt,
    PortNumber,
    StrictIpAddress,
    StrictModel,
)


class NetworkEndpoint(StrictModel):
    """One observed network endpoint; null ports must be explicit."""

    ip: StrictIpAddress
    port: PortNumber | None


class FlowCounters(StrictModel):
    """Monotonic directional packet and byte counters for a flow observation."""

    source_packets: NonNegativeInt
    destination_packets: NonNegativeInt
    source_bytes: NonNegativeInt
    destination_bytes: NonNegativeInt


class WindowDataQuality(StrictModel):
    """Quality metadata retained beside, but never hidden inside, ML features."""

    source_event_count: NonNegativeInt
    late_event_count: NonNegativeInt
    dropped_event_count: NonNegativeInt
    is_final: bool
    is_revision: bool

    @model_validator(mode="after")
    def validate_counts(self) -> "WindowDataQuality":
        if self.late_event_count > self.source_event_count:
            raise ValueError("late_event_count cannot exceed source_event_count")
        return self
