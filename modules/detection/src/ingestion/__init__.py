"""Sensor ingestion boundaries for the canonical IDS data pipeline.

Public exports retain stable abstract adapters and the frozen M2 replay runner.
Concrete M3 parsers exist in versioned private submodules and are intentionally
not package-level exports; parsing does not create or persist canonical events.
"""
from .adapters import RawSensorRecord, SensorAdapter, SuricataAdapter, ZeekAdapter
from .zeek_replay import ZeekReplayError, ZeekReplayRunner

__all__ = [
    "RawSensorRecord",
    "SensorAdapter",
    "SuricataAdapter",
    "ZeekAdapter",
    "ZeekReplayError",
    "ZeekReplayRunner",
]
