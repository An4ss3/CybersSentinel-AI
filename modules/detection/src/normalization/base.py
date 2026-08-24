"""Abstract conversion boundary from raw sensor records to canonical events.

Normalization is deliberately separate from parsing.  Future implementations
must provide provenance and all four versions explicitly, eliminating the
silent field loss and unverifiable preprocessing observed in the legacy CSV
loader.
"""
from __future__ import annotations

from abc import ABC, abstractmethod

from modules.detection.src.contracts import VersionContract
from modules.detection.src.ingestion import RawSensorRecord
from modules.detection.src.lineage import EventProvenance
from modules.detection.src.schemas import CanonicalNetworkEvent


class EventNormalizer(ABC):
    """Normalize one sensor record without silent defaults or coercion."""

    @abstractmethod
    def normalize(
        self,
        record: RawSensorRecord,
        provenance: EventProvenance,
        versions: VersionContract,
    ) -> CanonicalNetworkEvent:
        """Return one validated canonical event or raise an explicit error."""
