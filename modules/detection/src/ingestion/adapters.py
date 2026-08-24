"""Abstract sensor-ingestion interfaces; no parsing is implemented in Phase 1.

Separating transport/record reading from canonical normalization prevents Zeek
or Suricata syntax from leaking into feature engineering.  It also permits PCAP
replay and live collection to be tested against the same downstream contracts.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator, Mapping
from typing import Literal, TextIO, TypeAlias

RawSensorRecord: TypeAlias = Mapping[str, object]


class SensorAdapter(ABC):
    """Read raw records from one sensor-specific text stream."""

    @property
    @abstractmethod
    def sensor_type(self) -> Literal["zeek", "suricata"]:
        """Return the sensor family emitted by this adapter."""

    @abstractmethod
    def iter_records(self, stream: TextIO) -> Iterator[RawSensorRecord]:
        """Yield raw records without inventing missing fields or normalizing them."""


class ZeekAdapter(SensorAdapter, ABC):
    """Required interface for a future version-pinned Zeek JSON reader."""

    @property
    def sensor_type(self) -> Literal["zeek"]:
        return "zeek"


class SuricataAdapter(SensorAdapter, ABC):
    """Required interface for a future version-pinned Suricata EVE reader."""

    @property
    def sensor_type(self) -> Literal["suricata"]:
        return "suricata"
