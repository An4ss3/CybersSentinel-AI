"""Version-neutral abstract Zeek JSON-line parsing boundary for M3.

Concrete v1 and v2 parsers remain private submodule implementations.
"""
from __future__ import annotations

from abc import ABC, abstractmethod

from modules.detection.src.ingestion.adapters import RawSensorRecord
from modules.detection.src.schemas.zeek_normalization import ZeekSourceCoordinate


class ZeekJsonLineParser(ABC):
    """Parse one bound UTF-8 JSON line without creating canonical events."""

    @abstractmethod
    def parse_line(
        self,
        line: bytes,
        source: ZeekSourceCoordinate,
    ) -> RawSensorRecord:
        """Return a raw record or raise an explicit protocol rejection."""
