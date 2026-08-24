"""Concrete strict Zeek JSON-line parser for M3 Step 2."""
from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, DecimalException
import json
from typing import Any

from modules.detection.src.ingestion.adapters import RawSensorRecord
from modules.detection.src.ingestion.zeek_protocol import ZeekJsonLineParser
from modules.detection.src.schemas.zeek_normalization import ZeekSourceCoordinate
from modules.detection.src.schemas.zeek_normalization_run import ZeekRejectionReason


@dataclass(frozen=True, slots=True)
class ZeekRecordRejection(ValueError):
    """One explicit deterministic record rejection at a physical coordinate."""

    reason: ZeekRejectionReason
    source: ZeekSourceCoordinate
    fields: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "fields", tuple(sorted(set(self.fields))))

    def __str__(self) -> str:
        field_text = f" fields={','.join(self.fields)}" if self.fields else ""
        return (
            f"{self.reason} at {self.source.output_partition}/"
            f"{self.source.log_name}:{self.source.physical_line_number}{field_text}"
        )


class _DuplicateJsonKey(ValueError):
    def __init__(self, key: str) -> None:
        self.key = key
        super().__init__(key)


class _NonFiniteJsonNumber(ValueError):
    pass


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey(key)
        result[key] = value
    return result


def _reject_json_constant(value: str) -> object:
    raise _NonFiniteJsonNumber(value)


class StrictZeekJsonLineParser(ZeekJsonLineParser):
    """Decode exactly one UTF-8 JSON object while preserving decimals exactly."""

    def parse_line(
        self,
        line: bytes,
        source: ZeekSourceCoordinate,
    ) -> RawSensorRecord:
        if not isinstance(line, bytes):
            raise TypeError("Zeek JSON line must be bytes")

        payload = line
        if payload.endswith(b"\n"):
            payload = payload[:-1]
            if payload.endswith(b"\r"):
                payload = payload[:-1]
        if not payload or b"\n" in payload or b"\r" in payload:
            raise ZeekRecordRejection("malformed_json", source)
        try:
            text = payload.decode("utf-8", errors="strict")
            decoded = json.loads(
                text,
                parse_float=Decimal,
                parse_int=int,
                parse_constant=_reject_json_constant,
                object_pairs_hook=_object_without_duplicates,
            )
        except _NonFiniteJsonNumber as error:
            raise ZeekRecordRejection(
                "non_finite_number",
                source,
            ) from error
        except _DuplicateJsonKey as error:
            raise ZeekRecordRejection(
                "malformed_json",
                source,
                (error.key,),
            ) from error
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            DecimalException,
            ValueError,
            OverflowError,
            RecursionError,
        ) as error:
            raise ZeekRecordRejection("malformed_json", source) from error

        if not isinstance(decoded, dict):
            raise ZeekRecordRejection("non_object_json", source)
        return decoded
