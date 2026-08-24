"""Concrete frozen-protocol conn.log to FlowEnd normalizer for M3 Step 2."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
from ipaddress import ip_address
from uuid import uuid5

from pydantic import TypeAdapter, ValidationError

from modules.detection.src.contracts import StrictIdentifier
from modules.detection.src.ingestion.adapters import RawSensorRecord
from modules.detection.src.ingestion.zeek_json import ZeekRecordRejection
from modules.detection.src.lineage.provenance import EventProvenance
from modules.detection.src.normalization.zeek import ZeekConnFlowEndNormalizer
from modules.detection.src.schemas.common import FlowCounters, NetworkEndpoint
from modules.detection.src.schemas.events import FlowEnd
from modules.detection.src.schemas.zeek_normalization import (
    ZeekNormalizationContext,
    ZeekNormalizationSpecification,
)


_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_MAX_EPOCH_MICROSECONDS = (
    (datetime.max.replace(tzinfo=timezone.utc) - _EPOCH).days * 86_400_000_000
    + (datetime.max.replace(tzinfo=timezone.utc) - _EPOCH).seconds * 1_000_000
    + (datetime.max.replace(tzinfo=timezone.utc) - _EPOCH).microseconds
)
_IDENTIFIER_ADAPTER = TypeAdapter(StrictIdentifier)


class ZeekSourceBindingError(ValueError):
    """A source or context is not the exact conn.log evidence frozen in M3."""


class StrictZeekConnFlowEndNormalizer(ZeekConnFlowEndNormalizer):
    """Construct immutable FlowEnd events without defaults, fallback, or rounding."""

    def __init__(self, specification: ZeekNormalizationSpecification) -> None:
        self._specification = specification
        self._protocol_sha256 = specification.content_sha256()
        self._bindings = {
            binding.output_partition: binding
            for binding in specification.replay_reports
        }
        self._mapping = specification.log_mappings[0]

    @property
    def protocol_sha256(self) -> str:
        return self._protocol_sha256

    def _validate_source(
        self,
        context: ZeekNormalizationContext,
        specification: ZeekNormalizationSpecification,
    ) -> None:
        if context.protocol_sha256 != self._protocol_sha256:
            raise ZeekSourceBindingError("normalization context protocol hash mismatch")
        if specification is not self._specification and (
            specification.content_sha256() != self._protocol_sha256
        ):
            raise ZeekSourceBindingError("normalization specification mismatch")
        source = context.source
        binding = self._bindings.get(source.output_partition)
        if binding is None:
            raise ZeekSourceBindingError("source partition is not bound by protocol")
        expected = binding.supported_log
        if source.replay_report_content_sha256 != binding.report_content_sha256:
            raise ZeekSourceBindingError("source replay report identity mismatch")
        if source.log_name != expected.log_name:
            raise ZeekSourceBindingError("source log name mismatch")
        if source.source_log_sha256 != expected.sha256:
            raise ZeekSourceBindingError("source log hash mismatch")
        if source.reported_record_count != expected.record_count:
            raise ZeekSourceBindingError("source record count mismatch")

    @staticmethod
    def _reject(
        reason: str,
        context: ZeekNormalizationContext,
        *fields: str,
    ) -> None:
        raise ZeekRecordRejection(  # type: ignore[arg-type]
            reason,
            context.source,
            tuple(fields),
        )

    def _validate_inventory(
        self,
        record: RawSensorRecord,
        context: ZeekNormalizationContext,
    ) -> None:
        keys = set(record)
        missing = tuple(sorted(set(self._mapping.required_fields) - keys))
        if missing:
            self._reject("missing_required_field", context, *missing)
        null_required = tuple(
            field for field in self._mapping.required_fields if record[field] is None
        )
        if null_required:
            self._reject("null_required_field", context, *null_required)
        unknown = tuple(sorted(keys - set(self._mapping.allowed_fields)))
        if unknown:
            self._reject("unknown_field", context, *unknown)

    def _validate_mapped_types(
        self,
        record: RawSensorRecord,
        context: ZeekNormalizationContext,
    ) -> None:
        invalid: list[str] = []
        for mapping in self._mapping.field_mappings:
            if mapping.source_field not in record:
                continue
            value = record[mapping.source_field]
            if value is None and mapping.presence == "optional":
                continue
            if mapping.source_type == "string":
                valid = type(value) is str
            elif mapping.source_type == "integer":
                valid = type(value) is int
            else:
                valid = type(value) in (int, Decimal)
            if not valid:
                invalid.append(mapping.source_field)
        if invalid:
            self._reject("invalid_field_type", context, *invalid)

    def _exact_non_negative_microseconds(
        self,
        value: object,
        field: str,
        context: ZeekNormalizationContext,
    ) -> int:
        if type(value) is int:
            if value < 0:  # type: ignore[operator]
                self._reject("invalid_field_type", context, field)
            if value > _MAX_EPOCH_MICROSECONDS // 1_000_000:  # type: ignore[operator]
                self._reject("invalid_field_type", context, field)
            return value * 1_000_000  # type: ignore[operator,return-value]

        assert isinstance(value, Decimal)
        if not value.is_finite():
            self._reject("non_finite_number", context, field)
        sign, digits, exponent = value.as_tuple()
        if sign:
            self._reject("invalid_field_type", context, field)
        if not any(digits):
            return 0

        scaled_exponent = exponent + 6
        significant_digits = digits
        if scaled_exponent < 0:
            fractional_places = -scaled_exponent
            if fractional_places > len(digits) or any(
                digit != 0 for digit in digits[-fractional_places:]
            ):
                self._reject("excess_timestamp_precision", context, field)
            significant_digits = digits[:-fractional_places]
            scaled_exponent = 0

        result_digits = len(significant_digits) + scaled_exponent
        max_digits = len(str(_MAX_EPOCH_MICROSECONDS))
        if result_digits > max_digits:
            self._reject("invalid_field_type", context, field)
        coefficient = 0
        for digit in significant_digits:
            coefficient = coefficient * 10 + digit
        microseconds = coefficient * (10**scaled_exponent)
        if microseconds > _MAX_EPOCH_MICROSECONDS:
            self._reject("invalid_field_type", context, field)
        return microseconds

    def normalize_conn(
        self,
        record: RawSensorRecord,
        context: ZeekNormalizationContext,
        specification: ZeekNormalizationSpecification,
    ) -> FlowEnd:
        self._validate_source(context, specification)
        self._validate_inventory(record, context)
        self._validate_mapped_types(record, context)

        ts_value = record["ts"]
        duration_value = record["duration"]
        for field, value in (("ts", ts_value), ("duration", duration_value)):
            decimal_value = Decimal(value) if type(value) is int else value
            assert isinstance(decimal_value, Decimal)
            if not decimal_value.is_finite():
                self._reject("non_finite_number", context, field)

        integer_fields = (
            "id.orig_p",
            "id.resp_p",
            "orig_bytes",
            "orig_pkts",
            "resp_bytes",
            "resp_pkts",
        )
        negative = tuple(field for field in integer_fields if record[field] < 0)  # type: ignore[operator]
        if negative:
            self._reject("invalid_field_type", context, *negative)
        invalid_ports = tuple(
            field
            for field in ("id.orig_p", "id.resp_p")
            if record[field] > 65535  # type: ignore[operator]
        )
        if invalid_ports:
            self._reject("invalid_field_type", context, *invalid_ports)

        start_microseconds = self._exact_non_negative_microseconds(
            ts_value,
            "ts",
            context,
        )
        duration_microseconds = self._exact_non_negative_microseconds(
            duration_value,
            "duration",
            context,
        )
        try:
            event_start_time = _EPOCH + timedelta(microseconds=start_microseconds)
            event_end_time = event_start_time + timedelta(
                microseconds=duration_microseconds
            )
        except OverflowError:
            self._reject("invalid_field_type", context, "ts", "duration")
            raise AssertionError("unreachable")
        if event_end_time > context.record_available_time:
            self._reject(
                "invalid_field_type",
                context,
                "event_end_time",
                "record_available_time",
            )

        transport = record["proto"]
        assert isinstance(transport, str)
        if transport not in self._specification.event_envelope.supported_transports:
            self._reject("unsupported_transport", context, "proto")

        service = record.get("service")
        if service is not None:
            assert isinstance(service, str)
            if "," in service:
                self._reject("unsupported_service_cardinality", context, "service")

        try:
            conversation_id = _IDENTIFIER_ADAPTER.validate_python(
                record["uid"], strict=True
            )
            connection_state = _IDENTIFIER_ADAPTER.validate_python(
                record["conn_state"], strict=True
            )
            canonical_service = (
                None
                if service is None
                else _IDENTIFIER_ADAPTER.validate_python(service, strict=True)
            )
            source = NetworkEndpoint(
                ip=ip_address(record["id.orig_h"]),  # type: ignore[arg-type]
                port=record["id.orig_p"],
            )
            destination = NetworkEndpoint(
                ip=ip_address(record["id.resp_h"]),  # type: ignore[arg-type]
                port=record["id.resp_p"],
            )
            counters = FlowCounters(
                source_packets=record["orig_pkts"],
                destination_packets=record["resp_pkts"],
                source_bytes=record["orig_bytes"],
                destination_bytes=record["resp_bytes"],
            )
        except (ValidationError, ValueError) as error:
            self._reject("invalid_field_type", context)
            raise AssertionError("unreachable") from error

        provenance_policy = self._specification.provenance
        source_coordinate = context.source
        event_id_name = "|".join(
            (
                self._protocol_sha256,
                source_coordinate.replay_report_content_sha256,
                source_coordinate.source_log_sha256,
                source_coordinate.output_partition,
                source_coordinate.log_name,
                str(source_coordinate.physical_line_number),
            )
        )
        binding = self._bindings[source_coordinate.output_partition]
        provenance = EventProvenance(
            event_id=uuid5(provenance_policy.event_id_namespace, event_id_name),
            sensor_id=provenance_policy.sensor_id,
            sensor_run_id=source_coordinate.replay_report_content_sha256,
            capture_id=binding.input.sha256,
            dataset_snapshot_id=self._specification.m1_manifest_sha256,
            model_release_id=None,
            normalizer_version=self._specification.event_envelope.normalizer_version,
            pipeline_version=self._specification.event_envelope.pipeline_version,
        )
        versions = self._specification.event_envelope.versions
        try:
            return FlowEnd(
                **versions.model_dump(),
                event_type="flow_end",
                sensor_type="zeek",
                provenance=provenance,
                event_start_time=event_start_time,
                event_end_time=event_end_time,
                record_available_time=context.record_available_time,
                ingested_at=context.ingested_at,
                conversation_id=conversation_id,
                source=source,
                destination=destination,
                transport=transport,
                service=canonical_service,
                counters=counters,
                connection_state=connection_state,
                termination_reason=None,
            )
        except ValidationError as error:
            self._reject("invalid_field_type", context)
            raise AssertionError("unreachable") from error
