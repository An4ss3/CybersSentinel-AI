"""Immutable provenance attached to every canonical event and feature window.

The legacy CICIDS rows could not be traced to a sensor, capture, conversation,
processing run, dataset snapshot, or model release.  This contract makes source
and processing identity mandatory.  Dataset and model identifiers are required
keys but explicitly nullable because they do not yet exist for live ingestion.
"""
from __future__ import annotations

from uuid import UUID

from modules.detection.src.contracts import StrictIdentifier, StrictModel, VersionString


class EventProvenance(StrictModel):
    """Source and processing lineage for one canonical payload."""

    event_id: UUID
    sensor_id: StrictIdentifier
    sensor_run_id: StrictIdentifier
    capture_id: StrictIdentifier
    dataset_snapshot_id: StrictIdentifier | None
    model_release_id: StrictIdentifier | None
    normalizer_version: VersionString
    pipeline_version: VersionString
