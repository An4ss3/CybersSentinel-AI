"""Guards for stable M3 parser and normalizer interface boundaries."""
from __future__ import annotations

import inspect

import pytest

import modules.detection.src.ingestion as ingestion
import modules.detection.src.normalization as normalization
from modules.detection.src.ingestion.zeek_protocol import ZeekJsonLineParser
from modules.detection.src.normalization.zeek import ZeekConnFlowEndNormalizer


def test_zeek_parser_boundary_is_abstract_and_cannot_instantiate() -> None:
    assert inspect.isabstract(ZeekJsonLineParser)
    assert getattr(ZeekJsonLineParser.parse_line, "__isabstractmethod__", False)
    with pytest.raises(TypeError, match="abstract method"):
        ZeekJsonLineParser()


def test_conn_normalizer_boundary_is_abstract_and_cannot_instantiate() -> None:
    assert inspect.isabstract(ZeekConnFlowEndNormalizer)
    assert getattr(
        ZeekConnFlowEndNormalizer.normalize_conn,
        "__isabstractmethod__",
        False,
    )
    with pytest.raises(TypeError, match="abstract method"):
        ZeekConnFlowEndNormalizer()


def test_no_concrete_parser_or_conn_normalizer_is_publicly_exported() -> None:
    parser_types = tuple(
        value
        for name in ingestion.__all__
        if inspect.isclass(value := getattr(ingestion, name))
        and issubclass(value, ZeekJsonLineParser)
    )
    normalizer_types = tuple(
        value
        for name in normalization.__all__
        if inspect.isclass(value := getattr(normalization, name))
        and issubclass(value, ZeekConnFlowEndNormalizer)
    )
    assert parser_types == ()
    assert normalizer_types == ()
    assert not hasattr(ingestion, "ZeekJsonLineParser")
    assert not hasattr(normalization, "ZeekConnFlowEndNormalizer")


def test_boundary_modules_contain_no_decoder_file_io_or_event_constructor() -> None:
    parser_source = inspect.getsource(
        __import__(
            "modules.detection.src.ingestion.zeek_protocol",
            fromlist=["ZeekJsonLineParser"],
        )
    )
    normalizer_source = inspect.getsource(
        __import__(
            "modules.detection.src.normalization.zeek",
            fromlist=["ZeekConnFlowEndNormalizer"],
        )
    )
    assert "json.loads" not in parser_source
    assert "open(" not in parser_source
    assert ".read_" not in parser_source
    assert "FlowEnd(" not in normalizer_source
    assert "open(" not in normalizer_source
    assert ".write_" not in normalizer_source
