"""Canonical M6 feature windows with exact DECIMAL(38,22) time.

Additive successor to :class:`FeatureWindow`. The v1 contract remains present
and strictly unchanged; this module never imports it and never modifies it.

The breaking difference is temporal representation. ``FeatureWindow`` v1 uses
``UtcDateTime`` (microsecond precision), which cannot represent the frozen M3 v2
evidence: observed durations carry 22 fractional digits and exact end times up
to 32 significant digits, and the frozen M3 v2 protocol declares rounding,
truncation, and float conversion ``forbidden``. Every temporal field here is
therefore an exact ``ExactDecimalSeconds22`` value, and every temporal
comparison uses unscaled integer arithmetic from ``exact_time_v2``.

Labels are structurally excluded: the model forbids extra fields, and no
label-derived field is declared. M5 remains entirely separate.
"""
from __future__ import annotations

from typing import Annotated, Literal, TypeAlias
from uuid import UUID

from pydantic import Field, model_validator

from modules.detection.src.contracts import (
    FiniteFloat,
    StrictIdentifier,
    VersionedModel,
)
from modules.detection.src.lineage.provenance import EventProvenance
from modules.detection.src.schemas.common import WindowDataQuality
from modules.detection.src.schemas.exact_time_v2 import (
    ExactDecimalSeconds22,
    unscaled_from_canonical,
)


#: The only entity type authorized by the frozen M6 protocol.
FeatureWindowEntityTypeV2: TypeAlias = Literal["source_destination_service"]

#: Exact tumbling window length, in unscaled DECIMAL(38,22) seconds (60 s).
WINDOW_LENGTH_UNSCALED: int = 60 * 10**22

#: Canonical sentinel replacing a null ``service`` inside ``entity_key``.
NULL_SERVICE_SENTINEL: str = "none"

#: The eight authorized features, sorted, exactly as frozen in the manifest.
AUTHORIZED_FEATURE_NAMES: tuple[str, ...] = (
    "destination_bytes_total",
    "destination_packets_total",
    "distinct_destination_ips",
    "distinct_destination_ports",
    "distinct_source_ips",
    "event_count",
    "source_bytes_total",
    "source_packets_total",
)

#: Number of ordered components composing ``entity_key``.
ENTITY_KEY_COMPONENT_COUNT: int = 4


class FeatureWindowV2(VersionedModel):
    """Immutable exact-time behavioural feature window over FlowEndV2 events."""

    provenance: EventProvenance
    window_id: StrictIdentifier
    entity_type: FeatureWindowEntityTypeV2
    entity_key: Annotated[
        tuple[StrictIdentifier, ...],
        Field(min_length=ENTITY_KEY_COMPONENT_COUNT,
              max_length=ENTITY_KEY_COMPONENT_COUNT),
    ]
    output_partition: StrictIdentifier
    window_start_time: ExactDecimalSeconds22
    window_end_time: ExactDecimalSeconds22
    prediction_time: ExactDecimalSeconds22
    record_available_time: ExactDecimalSeconds22
    source_event_ids: Annotated[tuple[UUID, ...], Field(min_length=1)]
    features: Annotated[dict[StrictIdentifier, FiniteFloat], Field(min_length=1)]
    data_quality: WindowDataQuality

    @model_validator(mode="after")
    def validate_window_v2_contract(self) -> "FeatureWindowV2":
        expected_versions = ("2.0.0", "2.0.0", "2.0.0")
        actual_versions = (
            self.schema_version,
            self.event_version,
            self.feature_version,
        )
        if actual_versions != expected_versions:
            raise ValueError(
                "FeatureWindowV2 schema/event/feature versions must all be 2.0.0"
            )

        start = unscaled_from_canonical(self.window_start_time)
        end = unscaled_from_canonical(self.window_end_time)
        prediction = unscaled_from_canonical(self.prediction_time)
        available = unscaled_from_canonical(self.record_available_time)

        if start >= end:
            raise ValueError("window_start_time must precede window_end_time")
        if end - start != WINDOW_LENGTH_UNSCALED:
            raise ValueError(
                "FeatureWindowV2 windows must span exactly 60 seconds"
            )
        if start % WINDOW_LENGTH_UNSCALED != 0:
            raise ValueError(
                "window_start_time must be aligned to an exact 60-second boundary"
            )
        if end > prediction:
            raise ValueError("prediction_time cannot precede window_end_time")
        if prediction != end:
            raise ValueError(
                "frozen M6 protocol requires prediction_time == window_end_time"
            )
        if prediction > available:
            raise ValueError("record_available_time cannot precede prediction_time")

        if len(set(self.source_event_ids)) != len(self.source_event_ids):
            raise ValueError("source_event_ids must be unique")
        if self.provenance.event_id in self.source_event_ids:
            raise ValueError(
                "feature-window event_id cannot also be a source event_id"
            )
        if self.data_quality.source_event_count != len(self.source_event_ids):
            raise ValueError(
                "source_event_count must equal the number of source_event_ids"
            )

        if tuple(sorted(self.features)) != AUTHORIZED_FEATURE_NAMES:
            raise ValueError(
                "FeatureWindowV2 must carry exactly the eight authorized features"
            )
        if any(value < 0 for value in self.features.values()):
            raise ValueError("authorized M6 features are non-negative counts")

        if self.window_id != str(self.provenance.event_id):
            raise ValueError(
                "window_id must be the text form of provenance.event_id"
            )
        return self


CanonicalFeatureWindowV2: TypeAlias = FeatureWindowV2
