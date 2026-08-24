"""Tests preserving the abstract-only boundary of Phase 1 interfaces."""
from __future__ import annotations

import inspect

import pytest

from modules.detection.src.ingestion import SensorAdapter, SuricataAdapter, ZeekAdapter
from modules.detection.src.normalization import EventNormalizer


@pytest.mark.parametrize(
    "interface",
    [SensorAdapter, ZeekAdapter, SuricataAdapter, EventNormalizer],
)
def test_phase_one_interfaces_are_abstract(interface):
    assert inspect.isabstract(interface)
    with pytest.raises(TypeError):
        interface()


def test_sensor_specific_interfaces_declare_their_source_type():
    assert ZeekAdapter.sensor_type.fget(None) == "zeek"
    assert SuricataAdapter.sensor_type.fget(None) == "suricata"


def test_no_concrete_adapter_or_normalizer_is_exported():
    import modules.detection.src.ingestion as ingestion
    import modules.detection.src.normalization as normalization

    assert set(ingestion.__all__) == {
        "RawSensorRecord",
        "SensorAdapter",
        "SuricataAdapter",
        "ZeekAdapter",
        "ZeekReplayError",
        "ZeekReplayRunner",
    }
    assert normalization.__all__ == ["EventNormalizer"]
