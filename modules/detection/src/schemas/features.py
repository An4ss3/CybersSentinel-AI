"""Canonical feature-window model for future behavioural aggregation.

This phase defines the contract only; it does not aggregate traffic.  Features
are finite, versioned, causal, and linked to source events so later training and
inference cannot reproduce the legacy pipeline's untraceable row-level samples.
"""
from __future__ import annotations

from typing import Annotated, Literal, TypeAlias
from uuid import UUID

from pydantic import Field, model_validator

from modules.detection.src.contracts import (
    FiniteFloat,
    StrictIdentifier,
    UtcDateTime,
    VersionedModel,
)
from modules.detection.src.lineage import EventProvenance

from .common import WindowDataQuality

WindowEntityType: TypeAlias = Literal[
    "source",
    "destination",
    "conversation",
    "source_destination_service",
    "destination_service",
    "sensor",
    "custom",
]


class FeatureWindow(VersionedModel):
    """Immutable behavioural feature vector evaluated at one prediction time."""

    provenance: EventProvenance
    window_id: StrictIdentifier
    entity_type: WindowEntityType
    entity_key: Annotated[tuple[StrictIdentifier, ...], Field(min_length=1)]
    window_start_time: UtcDateTime
    window_end_time: UtcDateTime
    prediction_time: UtcDateTime
    record_available_time: UtcDateTime
    source_event_ids: Annotated[tuple[UUID, ...], Field(min_length=1)]
    features: Annotated[dict[StrictIdentifier, FiniteFloat], Field(min_length=1)]
    data_quality: WindowDataQuality

    @model_validator(mode="after")
    def validate_window_consistency(self) -> "FeatureWindow":
        if self.window_start_time >= self.window_end_time:
            raise ValueError("window_start_time must precede window_end_time")
        if self.window_end_time > self.prediction_time:
            raise ValueError("window_end_time cannot follow prediction_time")
        if self.prediction_time > self.record_available_time:
            raise ValueError("prediction_time cannot follow record_available_time")
        if len(set(self.source_event_ids)) != len(self.source_event_ids):
            raise ValueError("source_event_ids must be unique")
        if self.provenance.event_id in self.source_event_ids:
            raise ValueError("feature-window event_id cannot also be a source event_id")
        if self.data_quality.source_event_count != len(self.source_event_ids):
            raise ValueError("source_event_count must equal the number of source_event_ids")
        return self
