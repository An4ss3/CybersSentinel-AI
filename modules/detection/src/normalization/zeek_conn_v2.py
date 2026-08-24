"""Concrete v2 conn.log normalizer: raw record → FlowEndV2 or explicit rejection.

This normalizer applies the frozen M3 v2 DECIMAL(38,22) field mapping. It does
not persist output, read files, or create feature windows.
"""
from __future__ import annotations

from decimal import Decimal
from ipaddress import ip_address
from uuid import uuid5

from pydantic import TypeAdapter, ValidationError

from modules.detection.src.contracts import StrictIdentifier
from modules.detection.src.ingestion.adapters import RawSensorRecord
from modules.detection.src.ingestion.zeek_json_v2 import ZeekRecordRejectionV2
from modules.detection.src.lineage.provenance import EventProvenance
from modules.detection.src.schemas.common import FlowCounters, NetworkEndpoint
from modules.detection.src.schemas.events_v2 import FlowEndV2
from modules.detection.src.schemas.exact_time_v2 import (
    ExactDecimalConversionError,
    canonical_seconds_from_unscaled,
    decimal_to_unscaled,
)
from modules.detection.src.schemas.zeek_normalization import ZeekSourceCoordinate
from modules.detection.src.schemas.zeek_normalization_v2 import (
    ZeekNormalizationContextV2,
    ZeekNormalizationSpecificationV2,
)


_IDENTIFIER_ADAPTER = TypeAdapter(StrictIdentifier)

_REQUIRED_FIELDS = frozenset((
    "conn_state", "duration", "id.orig_h", "id.orig_p", "id.resp_h",
    "id.resp_p", "orig_bytes", "orig_pkts", "proto", "resp_bytes",
    "resp_pkts", "ts", "uid",
))

_OPTIONAL_MAPPED = frozenset(("service",))

_ALLOWED_FIELDS = frozenset((
    "conn_state", "duration", "history", "id.orig_h", "id.orig_p",
    "id.resp_h", "id.resp_p", "ip_proto", "local_orig", "local_resp",
    "missed_bytes", "orig_bytes", "orig_ip_bytes", "orig_pkts", "proto",
    "resp_bytes", "resp_ip_bytes", "resp_pkts", "service", "ts",
    "tunnel_parents", "uid",
))

_SUPPORTED_TRANSPORTS = frozenset(("tcp", "udp"))


class ZeekSourceBindingErrorV2(ValueError):
    """Source or context does not match the bound v2 protocol evidence."""


class StrictZeekConnFlowEndNormalizerV2:
    """Map one raw conn.log record to FlowEndV2 under the exact v2 protocol."""

    def __init__(self, specification: ZeekNormalizationSpecificationV2) -> None:
        self._specification = specification
        self._protocol_sha256 = specification.content_sha256()
        self._bindings = {
            binding.output_partition: binding
            for binding in specification.replay_reports
        }
        self._envelope = specification.event_envelope
        self._provenance_policy = specification.provenance

    @property
    def protocol_sha256(self) -> str:
        return self._protocol_sha256

    def _reject(
        self,
        reason: str,
        source: ZeekSourceCoordinate,
        *fields: str,
    ) -> None:
        raise ZeekRecordRejectionV2(reason, source, tuple(fields))  # type: ignore[arg-type]

    def _validate_source(self, context: ZeekNormalizationContextV2) -> None:
        if context.protocol_sha256 != self._protocol_sha256:
            raise ZeekSourceBindingErrorV2(
                "v2 normalization context protocol hash mismatch"
            )
        source = context.source
        binding = self._bindings.get(source.output_partition)
        if binding is None:
            raise ZeekSourceBindingErrorV2(
                "source partition is not bound by v2 protocol"
            )
        expected = binding.supported_log
        if source.replay_report_content_sha256 != binding.report_content_sha256:
            raise ZeekSourceBindingErrorV2(
                "source replay report identity mismatch"
            )
        if source.log_name != expected.log_name:
            raise ZeekSourceBindingErrorV2("source log name mismatch")
        if source.source_log_sha256 != expected.sha256:
            raise ZeekSourceBindingErrorV2("source log hash mismatch")
        if source.reported_record_count != expected.record_count:
            raise ZeekSourceBindingErrorV2("source record count mismatch")

    def normalize_conn(
        self,
        record: RawSensorRecord,
        context: ZeekNormalizationContextV2,
    ) -> FlowEndV2:
        """Return one validated FlowEndV2 or raise ZeekRecordRejectionV2."""
        self._validate_source(context)
        source = context.source

        # --- field inventory ---
        keys = set(record)
        missing = tuple(sorted(_REQUIRED_FIELDS - keys))
        if missing:
            self._reject("missing_required_field", source, *missing)
        null_required = tuple(
            sorted(f for f in _REQUIRED_FIELDS if f in keys and record[f] is None)
        )
        if null_required:
            self._reject("null_required_field", source, *null_required)
        unknown = tuple(sorted(keys - _ALLOWED_FIELDS))
        if unknown:
            self._reject("unknown_field", source, *unknown)

        # --- type validation ---
        invalid: list[str] = []
        for field in ("ts", "duration"):
            value = record.get(field)
            if value is not None and type(value) not in (int, Decimal):
                invalid.append(field)
        for field in ("conn_state", "id.orig_h", "id.resp_h", "proto", "uid"):
            value = record.get(field)
            if value is not None and type(value) is not str:
                invalid.append(field)
        for field in (
            "id.orig_p", "id.resp_p", "orig_bytes", "orig_pkts",
            "resp_bytes", "resp_pkts",
        ):
            value = record.get(field)
            if value is not None and type(value) is not int:
                invalid.append(field)
        service_raw = record.get("service")
        if service_raw is not None and type(service_raw) is not str:
            invalid.append("service")
        if invalid:
            self._reject("invalid_field_type", source, *invalid)

        # --- transport ---
        transport: str = record["ts"]  # type placeholder
        transport = record["proto"]  # type: ignore[assignment]
        if transport not in _SUPPORTED_TRANSPORTS:
            self._reject("unsupported_transport", source, "proto")

        # --- service ---
        if service_raw is not None:
            assert isinstance(service_raw, str)
            if "," in service_raw:
                self._reject("unsupported_service_cardinality", source, "service")

        # --- exact temporal conversion ---
        ts_value = record["ts"]
        duration_value = record["duration"]
        ts_decimal = Decimal(ts_value) if type(ts_value) is int else ts_value
        dur_decimal = (
            Decimal(duration_value) if type(duration_value) is int else duration_value
        )
        assert isinstance(ts_decimal, Decimal)
        assert isinstance(dur_decimal, Decimal)

        if not ts_decimal.is_finite():
            self._reject("non_finite_number", source, "ts")
        if not dur_decimal.is_finite():
            self._reject("non_finite_number", source, "duration")
        if ts_decimal.is_signed() and ts_decimal != 0:
            self._reject("decimal38_22_range_or_scale", source, "ts")
        if dur_decimal.is_signed() and dur_decimal != 0:
            self._reject("decimal38_22_range_or_scale", source, "duration")

        try:
            start_unscaled = decimal_to_unscaled(ts_decimal)
        except ExactDecimalConversionError:
            self._reject("decimal38_22_range_or_scale", source, "ts")
            raise AssertionError("unreachable")

        try:
            duration_unscaled = decimal_to_unscaled(dur_decimal)
        except ExactDecimalConversionError:
            self._reject("decimal38_22_range_or_scale", source, "duration")
            raise AssertionError("unreachable")

        end_unscaled = start_unscaled + duration_unscaled
        from modules.detection.src.schemas.exact_time_v2 import MAX_UNSCALED

        if end_unscaled > MAX_UNSCALED:
            self._reject("decimal38_22_range_or_scale", source, "ts", "duration")

        event_start_time = canonical_seconds_from_unscaled(start_unscaled)
        event_duration = canonical_seconds_from_unscaled(duration_unscaled)
        event_end_time = canonical_seconds_from_unscaled(end_unscaled)

        # --- temporal ordering against context ---
        from modules.detection.src.schemas.exact_time_v2 import unscaled_from_canonical

        available_unscaled = unscaled_from_canonical(context.record_available_time)
        if end_unscaled > available_unscaled:
            self._reject(
                "decimal38_22_range_or_scale", source, "duration", "ts"
            )

        # --- integer counters and ports ---
        for field in ("orig_bytes", "orig_pkts", "resp_bytes", "resp_pkts"):
            if record[field] < 0:  # type: ignore[operator]
                self._reject("invalid_field_type", source, field)
        for field in ("id.orig_p", "id.resp_p"):
            val = record[field]
            if val < 0 or val > 65535:  # type: ignore[operator]
                self._reject("invalid_field_type", source, field)

        # --- identifiers, endpoints, counters ---
        try:
            conversation_id = _IDENTIFIER_ADAPTER.validate_python(
                record["uid"], strict=True
            )
            connection_state = _IDENTIFIER_ADAPTER.validate_python(
                record["conn_state"], strict=True
            )
            canonical_service = (
                None
                if service_raw is None
                else _IDENTIFIER_ADAPTER.validate_python(service_raw, strict=True)
            )
            source_endpoint = NetworkEndpoint(
                ip=ip_address(record["id.orig_h"]),  # type: ignore[arg-type]
                port=record["id.orig_p"],
            )
            destination_endpoint = NetworkEndpoint(
                ip=ip_address(record["id.resp_h"]),  # type: ignore[arg-type]
                port=record["id.resp_p"],
            )
            counters = FlowCounters(
                source_packets=record["orig_pkts"],
                destination_packets=record["resp_pkts"],
                source_bytes=record["orig_bytes"],
                destination_bytes=record["resp_bytes"],
            )
        except (ValidationError, ValueError):
            self._reject("invalid_field_type", source)
            raise AssertionError("unreachable")

        # --- provenance ---
        event_id_name = "|".join((
            self._protocol_sha256,
            source.replay_report_content_sha256,
            source.source_log_sha256,
            source.output_partition,
            source.log_name,
            str(source.physical_line_number),
        ))
        binding = self._bindings[source.output_partition]
        provenance = EventProvenance(
            event_id=uuid5(self._provenance_policy.event_id_namespace, event_id_name),
            sensor_id="zeek",
            sensor_run_id=source.replay_report_content_sha256,
            capture_id=binding.input.sha256,
            dataset_snapshot_id=self._specification.m1_manifest_sha256,
            model_release_id=None,
            normalizer_version="2.0.0",
            pipeline_version="2.0.0",
        )

        # --- construct FlowEndV2 ---
        return FlowEndV2(
            schema_version="2.0.0",
            event_version="2.0.0",
            feature_version="1.0.0",
            sensor_version="8.0.9",
            event_type="flow_end",
            sensor_type="zeek",
            provenance=provenance,
            event_start_time=event_start_time,
            event_duration=event_duration,
            event_end_time=event_end_time,
            record_available_time=context.record_available_time,
            ingested_at=context.ingested_at,
            conversation_id=conversation_id,
            source=source_endpoint,
            destination=destination_endpoint,
            transport=transport,
            service=canonical_service,
            counters=counters,
            connection_state=connection_state,
            termination_reason=None,
        )
