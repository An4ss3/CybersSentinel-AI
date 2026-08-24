"""Concrete strict Zeek JSON-line parser for M3 v2."""
from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, DecimalException
import json
from typing import Any

from modules.detection.src.ingestion.adapters import RawSensorRecord
from modules.detection.src.ingestion.zeek_protocol import ZeekJsonLineParser
from modules.detection.src.schemas.zeek_normalization import ZeekSourceCoordinate
from modules.detection.src.schemas.zeek_normalization_run_v2 import (
    ZeekRejectionReasonV2,
)


@dataclass(frozen=True, slots=True)
class ZeekRecordRejectionV2(ValueError):
    reason: ZeekRejectionReasonV2
    source: ZeekSourceCoordinate
    fields: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "fields", tuple(sorted(set(self.fields))))

    def __str__(self) -> str:
        fields = f" fields={','.join(self.fields)}" if self.fields else ""
        return (
            f"{self.reason} at {self.source.output_partition}/"
            f"{self.source.log_name}:{self.source.physical_line_number}{fields}"
        )


class _DuplicateKey(ValueError):
    def __init__(self, key: str) -> None:
        self.key = key
        super().__init__(key)


class _NonFinite(ValueError):
    pass


def _object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKey(key)
        result[key] = value
    return result


def _constant(value: str) -> object:
    raise _NonFinite(value)


class StrictZeekJsonLineParserV2(ZeekJsonLineParser):
    """Parse one UTF-8 object and preserve floating lexemes as Decimal."""

    def parse_line(
        self,
        line: bytes,
        source: ZeekSourceCoordinate,
    ) -> RawSensorRecord:
        if type(line) is not bytes:
            raise TypeError("M3 v2 Zeek JSON line must be bytes")
        payload = line
        if payload.endswith(b"\n"):
            payload = payload[:-1]
            if payload.endswith(b"\r"):
                payload = payload[:-1]
        if not payload or b"\n" in payload or b"\r" in payload:
            raise ZeekRecordRejectionV2("malformed_json", source)
        try:
            decoded = json.loads(
                payload.decode("utf-8", errors="strict"),
                parse_float=Decimal,
                parse_int=int,
                parse_constant=_constant,
                object_pairs_hook=_object_pairs,
            )
        except _NonFinite as error:
            raise ZeekRecordRejectionV2("non_finite_number", source) from error
        except _DuplicateKey as error:
            raise ZeekRecordRejectionV2(
                "malformed_json", source, (error.key,)
            ) from error
        except (
            UnicodeDecodeError, json.JSONDecodeError, DecimalException,
            ValueError, OverflowError, RecursionError,
        ) as error:
            raise ZeekRecordRejectionV2("malformed_json", source) from error
        if not isinstance(decoded, dict):
            raise ZeekRecordRejectionV2("non_object_json", source)
        return decoded
