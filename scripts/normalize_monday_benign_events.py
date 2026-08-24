"""Freeze the MB3 protocol and normalize the Monday conn.log to FlowEndV2.

Ordering, and why it matters
----------------------------
The MB3 evidence profile must describe measured facts, never predictions
(index risk R9). This script therefore always runs in this order:

1. **read-only lexical pre-scan** of the MB2 Monday ``conn.log`` -- counts lines
   and records carrying a duration, and measures the observed decimal widths of
   ``ts``, ``duration`` and the exact end ``ts + duration``. No normalizer is
   involved, so nothing here depends on the protocol hash;
2. build the MB3 specification from those measurements and publish it under the
   existing immutability policy;
3. reload, bind, and stream-normalize the partition, reusing
   ``StrictZeekJsonLineParserV2`` and ``StrictZeekConnFlowEndNormalizerV2``
   unchanged;
4. publish the MB3 run report immutably.

Events are hashed and discarded. **Nothing is persisted to PostgreSQL**: MB4 is
a separate, unstarted milestone.

Temporal context
----------------
``record_available_time`` defaults to the MB2 replay ``completed_at`` -- the
instant the Monday ``conn.log`` actually became available -- and ``ingested_at``
to the invocation time. Both are converted to canonical ``DECIMAL(38,22)``
seconds by **integer arithmetic only**: no float appears anywhere, in keeping
with the frozen ``temporal`` policy that declares ``float_conversion:
forbidden``.
"""
from __future__ import annotations

import argparse
import calendar
from collections.abc import Sequence
from datetime import datetime, timezone
from decimal import Decimal
import json
from pathlib import Path
from typing import Any, Final

import yaml

from modules.detection.src.lineage.dataset_freeze import (
    _write_immutable_bytes,
    load_dataset_freeze_manifest,
)
from modules.detection.src.lineage.monday_benign_replay import (
    load_monday_benign_replay_specification,
)
from modules.detection.src.normalization.monday_benign_pipeline import (
    MondayBenignNormalizationRunner,
    write_immutable_monday_benign_normalization_report,
)
from modules.detection.src.schemas.exact_time_v2 import (
    ExactDecimalSeconds22,
    canonical_seconds_from_unscaled,
)
from modules.detection.src.schemas.monday_benign_normalization import (
    MB3_EVENT_ID_NAMESPACE,
    MB3_NAMESPACE_DERIVATION_NAME,
    MB3_PROTOCOL_RELATIVE_PATH,
    MB3_REPORT_RELATIVE_PATH,
    MondayBenignEvidenceProfile,
    MondayBenignNormalizationSpecification,
    MondayBenignProvenancePolicy,
)
from modules.detection.src.schemas.monday_benign_replay import (
    MB1_MANIFEST_RELATIVE_PATH,
    MB2_OUTPUT_ROOT,
    MB2_SPECIFICATION_RELATIVE_PATH,
    MONDAY_OUTPUT_PARTITION,
    MondayBenignReplayRunReport,
)
from modules.detection.src.schemas.replay import ZeekLogArtifact
from modules.detection.src.schemas.zeek_normalization import (
    ZeekOrderingPolicy,
    ZeekReplayReportBinding,
)
from modules.detection.src.schemas.zeek_normalization_v2 import (
    ZeekConnLogMappingV2,
    ZeekEventEnvelopePolicyV2,
    ZeekFieldMappingV2,
    ZeekParserBoundaryPolicyV2,
    ZeekTemporalPolicyV2,
    ZeekUnsupportedRecordPolicyV2,
)
from modules.detection.src.contracts import VersionContract


REPO_ROOT = Path(__file__).resolve().parents[1]
MB2_REPLAY_REPORT_RELATIVE_PATH: Final[str] = (
    f"{MB2_OUTPUT_ROOT}/{MONDAY_OUTPUT_PARTITION}/replay_run.json"
)
AUTHORITATIVE_SOURCES: Final[tuple[str, ...]] = (
    "https://docs.zeek.org/en/lts/script-reference/log-files.html",
    "https://peps.python.org/pep-0327/",
    "https://www.postgresql.org/docs/16/datatype-numeric.html",
)


# --------------------------------------------------------------------------
# Step 1: read-only lexical pre-scan
# --------------------------------------------------------------------------


def _widths(value: Decimal) -> tuple[int, int]:
    """Return (significant digits, fractional digits) of an exact Decimal."""
    _, digits, exponent = value.as_tuple()
    significant = len(digits)
    fractional = -exponent if isinstance(exponent, int) and exponent < 0 else 0
    if fractional > significant:
        significant = fractional
    return significant, fractional


def prescan_conn_log(path: Path) -> dict[str, int]:
    """Measure the Monday conn.log lexically, without invoking the normalizer."""
    scanned = 0
    with_duration = 0
    ts_significant = ts_fractional = 0
    duration_significant = duration_fractional = 0
    end_significant = end_fractional = 0

    with path.open("rb") as stream:
        for line in stream:
            scanned += 1
            try:
                record = json.loads(line.decode("utf-8"), parse_float=Decimal)
            except (UnicodeDecodeError, json.JSONDecodeError):
                # Malformed transport is a rejection concern for the normalizer,
                # not a lexical measurement. Count the line and move on.
                continue
            if not isinstance(record, dict):
                continue

            ts = record.get("ts")
            if isinstance(ts, (int, Decimal)):
                exact_ts = Decimal(ts) if isinstance(ts, int) else ts
                significant, fractional = _widths(exact_ts)
                ts_significant = max(ts_significant, significant)
                ts_fractional = max(ts_fractional, fractional)
            else:
                exact_ts = None

            duration = record.get("duration")
            if isinstance(duration, (int, Decimal)):
                with_duration += 1
                exact_duration = (
                    Decimal(duration) if isinstance(duration, int) else duration
                )
                significant, fractional = _widths(exact_duration)
                duration_significant = max(duration_significant, significant)
                duration_fractional = max(duration_fractional, fractional)
                if exact_ts is not None:
                    significant, fractional = _widths(exact_ts + exact_duration)
                    end_significant = max(end_significant, significant)
                    end_fractional = max(end_fractional, fractional)

    return {
        "scanned_record_count": scanned,
        "records_with_duration": with_duration,
        "timestamp_max_significant_digits": ts_significant,
        "timestamp_max_fractional_digits": ts_fractional,
        "duration_max_significant_digits": duration_significant,
        "duration_max_fractional_digits": duration_fractional,
        "exact_end_max_significant_digits": end_significant,
        "exact_end_max_fractional_digits": end_fractional,
    }


# --------------------------------------------------------------------------
# Step 2: specification construction
# --------------------------------------------------------------------------


_FIELD_MAPPINGS: Final[tuple[dict[str, Any], ...]] = (
    {"source_field": "conn_state", "target_fields": ("connection_state",), "presence": "required", "source_type": "string", "transform": "strict_identifier", "null_policy": "reject"},
    {"source_field": "duration", "target_fields": ("event_duration", "event_end_time"), "presence": "required", "source_type": "json_number_decimal", "transform": "decimal38_22_exact_duration_and_end", "null_policy": "reject"},
    {"source_field": "id.orig_h", "target_fields": ("source.ip",), "presence": "required", "source_type": "string", "transform": "ip_address", "null_policy": "reject"},
    {"source_field": "id.orig_p", "target_fields": ("source.port",), "presence": "required", "source_type": "integer", "transform": "port", "null_policy": "reject"},
    {"source_field": "id.resp_h", "target_fields": ("destination.ip",), "presence": "required", "source_type": "string", "transform": "ip_address", "null_policy": "reject"},
    {"source_field": "id.resp_p", "target_fields": ("destination.port",), "presence": "required", "source_type": "integer", "transform": "port", "null_policy": "reject"},
    {"source_field": "orig_bytes", "target_fields": ("counters.source_bytes",), "presence": "required", "source_type": "integer", "transform": "non_negative_integer", "null_policy": "reject"},
    {"source_field": "orig_pkts", "target_fields": ("counters.source_packets",), "presence": "required", "source_type": "integer", "transform": "non_negative_integer", "null_policy": "reject"},
    {"source_field": "proto", "target_fields": ("transport",), "presence": "required", "source_type": "string", "transform": "closed_tcp_udp_transport", "null_policy": "reject"},
    {"source_field": "resp_bytes", "target_fields": ("counters.destination_bytes",), "presence": "required", "source_type": "integer", "transform": "non_negative_integer", "null_policy": "reject"},
    {"source_field": "resp_pkts", "target_fields": ("counters.destination_packets",), "presence": "required", "source_type": "integer", "transform": "non_negative_integer", "null_policy": "reject"},
    {"source_field": "service", "target_fields": ("service",), "presence": "optional", "source_type": "string", "transform": "single_strict_identifier_or_null", "null_policy": "map_missing_to_null"},
    {"source_field": "ts", "target_fields": ("event_start_time",), "presence": "required", "source_type": "json_number_decimal", "transform": "decimal38_22_exact_timestamp", "null_policy": "reject"},
    {"source_field": "uid", "target_fields": ("conversation_id",), "presence": "required", "source_type": "string", "transform": "strict_identifier", "null_policy": "reject"},
)


def _conn_log_mapping() -> ZeekConnLogMappingV2:
    """Build the conn.log mapping, identical in semantics to the M3 v2 freeze."""
    return ZeekConnLogMappingV2(
        log_name="conn.log",
        classification="canonical_telemetry",
        target_model="FlowEndV2",
        target_event_type="flow_end",
        required_fields=(
            "conn_state", "duration", "id.orig_h", "id.orig_p", "id.resp_h",
            "id.resp_p", "orig_bytes", "orig_pkts", "proto", "resp_bytes",
            "resp_pkts", "ts", "uid",
        ),
        optional_mapped_fields=("service",),
        optional_ignored_fields=(
            "history", "ip_proto", "local_orig", "local_resp", "missed_bytes",
            "orig_ip_bytes", "resp_ip_bytes", "tunnel_parents",
        ),
        unknown_field_policy="reject_record",
        field_mappings=tuple(
            ZeekFieldMappingV2(**mapping) for mapping in _FIELD_MAPPINGS
        ),
    )


def build_specification(
    repository_root: Path,
    *,
    frozen_at: datetime,
    profile: MondayBenignEvidenceProfile,
) -> MondayBenignNormalizationSpecification:
    """Build the MB3 protocol from published MB1/MB2 evidence and the pre-scan."""
    manifest = load_dataset_freeze_manifest(
        repository_root / MB1_MANIFEST_RELATIVE_PATH
    )
    mb2_specification = load_monday_benign_replay_specification(
        repository_root / MB2_SPECIFICATION_RELATIVE_PATH
    )
    report_path = repository_root / MB2_REPLAY_REPORT_RELATIVE_PATH
    report_bytes = report_path.read_bytes()
    report = MondayBenignReplayRunReport.model_validate_json(
        report_bytes.decode("utf-8")
    )
    conn_log = next(item for item in report.logs if item.log_name == "conn.log")

    from hashlib import sha256 as _sha256

    binding = ZeekReplayReportBinding(
        report_relative_path=MB2_REPLAY_REPORT_RELATIVE_PATH,
        report_file_sha256=_sha256(report_bytes).hexdigest(),
        report_content_sha256=report.content_sha256(),
        output_partition=report.output_partition,
        input=report.input,
        supported_log=ZeekLogArtifact(
            log_name=conn_log.log_name,
            classification=conn_log.classification,
            size_bytes=conn_log.size_bytes,
            sha256=conn_log.sha256,
            record_count=conn_log.record_count,
        ),
    )

    return MondayBenignNormalizationSpecification(
        protocol_version="2.0.0",
        frozen_at=frozen_at,
        track="monday_benign",
        dataset_name=manifest.dataset_name,
        m1_manifest_sha256=manifest.content_sha256(),
        mb2_specification_path=MB2_SPECIFICATION_RELATIVE_PATH,
        mb2_specification_sha256=mb2_specification.content_sha256(),
        mb2_output_root=MB2_OUTPUT_ROOT,
        sensor_type="zeek",
        sensor_version="8.0.9",
        input_format="json_lines",
        replay_reports=(binding,),
        log_mappings=(_conn_log_mapping(),),
        temporal=ZeekTemporalPolicyV2(
            source_decoder="decimal_from_json_lexeme",
            canonical_type="DECIMAL(38,22)",
            json_encoding="fixed_scale_string_22_fractional_digits",
            epoch="unix",
            time_scale="posix",
            display_timezone="UTC",
            unit="seconds",
            precision=38,
            scale=22,
            conversion="append_zeros_only",
            arithmetic="unscaled_integer",
            float_conversion="forbidden",
            rounding="forbidden",
            truncation="forbidden",
            event_end_rule="exact_start_plus_duration",
            exact_temporal_order=(
                "start_le_end_le_record_available_le_ingested"
            ),
        ),
        evidence=profile,
        event_envelope=ZeekEventEnvelopePolicyV2(
            event_type="flow_end",
            target_model="FlowEndV2",
            sensor_type="zeek",
            versions=VersionContract(
                schema_version="2.0.0",
                event_version="2.0.0",
                feature_version="1.0.0",
                sensor_version="8.0.9",
            ),
            normalizer_version="2.0.0",
            pipeline_version="2.0.0",
            termination_reason_policy="explicit_null",
            byte_counter_semantics="zeek_payload_bytes",
            supported_transports=("tcp", "udp"),
            service_policy=(
                "missing_or_null_to_null_single_identifier_only_reject_comma_list"
            ),
        ),
        provenance=MondayBenignProvenancePolicy(
            event_id_algorithm="uuid5",
            event_id_namespace=MB3_EVENT_ID_NAMESPACE,
            event_id_namespace_derivation=MB3_NAMESPACE_DERIVATION_NAME,
            event_id_components=(
                "protocol_sha256",
                "replay_report_content_sha256",
                "source_log_sha256",
                "output_partition",
                "log_name",
                "physical_line_number",
            ),
            event_id_name_encoding=(
                "utf8_component_values_joined_by_single_ascii_pipe_"
                "line_number_base10"
            ),
            sensor_id="zeek",
            sensor_run_id_source="replay_report_content_sha256",
            capture_id_source="input_pcap_sha256",
            dataset_snapshot_id_source="m1_manifest_sha256",
            model_release_id_policy="explicit_null",
        ),
        unsupported_records=ZeekUnsupportedRecordPolicyV2(
            malformed_json="reject_record_with_audit",
            non_object_json="reject_record_with_audit",
            missing_required_field="reject_record_with_audit",
            null_required_field="reject_record_with_audit",
            unknown_field="reject_record_with_audit",
            invalid_field_type="reject_record_with_audit",
            non_finite_number="reject_record_with_audit",
            decimal38_22_range_or_scale="reject_record_with_audit",
            unsupported_transport="reject_record_with_audit",
            unsupported_service_cardinality="reject_record_with_audit",
            source_binding_mismatch="reject_source_with_audit",
            continue_after_record_rejection=True,
            silent_defaults_forbidden=True,
            partial_events_forbidden=True,
        ),
        ordering=ZeekOrderingPolicy(
            partition_order="replay_report_binding_order",
            record_order="physical_jsonl_line_number_ascending",
            line_number_base=1,
            cross_partition_order="concatenate_partitions",
            sort_by_event_time=False,
            sort_by_uid=False,
            deduplicate_records=False,
            rejected_records_retain_coordinates=True,
        ),
        boundaries=ZeekParserBoundaryPolicyV2(
            parser_input="one_utf8_json_object_line_plus_source_coordinate",
            parser_output="raw_sensor_record_or_explicit_rejection",
            normalizer_input="raw_sensor_record_plus_normalization_context",
            normalizer_output="FlowEndV2_or_explicit_rejection",
            parser_creates_events=False,
            parser_persists_output=False,
            normalizer_reads_files=False,
            normalizer_persists_output=False,
            feature_engineering_allowed=False,
        ),
        authoritative_sources=AUTHORITATIVE_SOURCES,
    )


# --------------------------------------------------------------------------
# Temporal context, integer arithmetic only
# --------------------------------------------------------------------------


def exact_seconds_from_datetime(value: datetime) -> ExactDecimalSeconds22:
    """Convert an aware UTC datetime to canonical DECIMAL(38,22) seconds.

    Uses only integer arithmetic. ``datetime.timestamp()`` is deliberately not
    used: it returns a float, which the frozen temporal policy forbids.
    """
    if value.tzinfo is None or value.utcoffset() != timezone.utc.utcoffset(None):
        raise ValueError("temporal context must be explicit UTC")
    epoch_seconds = calendar.timegm(value.utctimetuple())
    unscaled = (epoch_seconds * 1_000_000 + value.microsecond) * 10**16
    return canonical_seconds_from_unscaled(unscaled)


def parse_utc_datetime(value: str) -> datetime:
    """Parse an explicit UTC timestamp without silently converting timezones."""
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"invalid ISO-8601 timestamp: {value}"
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(None):
        raise argparse.ArgumentTypeError("timestamp must be explicit UTC")
    return parsed


def main(argv: Sequence[str] | None = None) -> int:
    """Pre-scan, freeze the MB3 protocol, normalize, and publish the report."""
    parser = argparse.ArgumentParser(
        description="Freeze MB3 and normalize the Monday conn.log."
    )
    parser.add_argument("--frozen-at", type=parse_utc_datetime, required=True)
    parser.add_argument("--ingested-at", type=parse_utc_datetime, default=None)
    parser.add_argument("--prescan-only", action="store_true")
    parser.add_argument("--recompute-only", action="store_true")
    args = parser.parse_args(argv)

    conn_log_path = (
        REPO_ROOT / MB2_OUTPUT_ROOT / MONDAY_OUTPUT_PARTITION / "conn.log"
    )
    measurements = prescan_conn_log(conn_log_path)
    profile = MondayBenignEvidenceProfile(
        measurement_method="read_only_lexical_prescan",
        canonical_type="DECIMAL(38,22)",
        **measurements,
    )
    if args.prescan_only:
        print(json.dumps({"prescan": measurements}, indent=2, sort_keys=True))
        return 0

    specification = build_specification(
        REPO_ROOT, frozen_at=args.frozen_at, profile=profile
    )
    specification_path = REPO_ROOT / MB3_PROTOCOL_RELATIVE_PATH
    payload = yaml.safe_dump(
        specification.model_dump(mode="json"),
        sort_keys=False,
        allow_unicode=False,
    ).encode("utf-8")
    _write_immutable_bytes(specification_path, payload)

    report_path = REPO_ROOT / MB2_REPLAY_REPORT_RELATIVE_PATH
    replay_report = MondayBenignReplayRunReport.model_validate_json(
        report_path.read_text(encoding="utf-8")
    )
    record_available_time = exact_seconds_from_datetime(replay_report.completed_at)
    ingested = args.ingested_at or datetime.now(timezone.utc)
    ingested_at = exact_seconds_from_datetime(ingested)

    runner = MondayBenignNormalizationRunner.from_repository(
        REPO_ROOT, record_available_time, ingested_at
    )
    run_report = runner.run()

    summary: dict[str, object] = {
        "prescan": measurements,
        "protocol_path": MB3_PROTOCOL_RELATIVE_PATH,
        "protocol_sha256": specification.content_sha256(),
        "event_id_namespace": str(specification.provenance.event_id_namespace),
        "record_available_time": record_available_time,
        "ingested_at": ingested_at,
        "output_partition": run_report.partition_reports[0].output_partition,
        "processed": run_report.total_processed_record_count,
        "accepted": run_report.total_accepted_record_count,
        "rejected": run_report.total_rejected_record_count,
        "canonical_event_stream_sha256": (
            run_report.canonical_event_stream_sha256
        ),
        "rejection_audit_stream_sha256": (
            run_report.rejection_audit_stream_sha256
        ),
        "rejection_counts": [
            {"reason": item.reason, "count": item.count}
            for item in run_report.partition_reports[0].rejection_counts
        ],
        "first_accepted_event_id": str(
            run_report.partition_reports[0].first_accepted_event_id
        ),
        "last_accepted_event_id": str(
            run_report.partition_reports[0].last_accepted_event_id
        ),
        "report_content_sha256": run_report.content_sha256(),
    }

    if args.recompute_only:
        summary["status"] = "recomputed_not_published"
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0

    report_file_sha256 = write_immutable_monday_benign_normalization_report(
        run_report, REPO_ROOT / MB3_REPORT_RELATIVE_PATH
    )
    summary["report_path"] = MB3_REPORT_RELATIVE_PATH
    summary["report_file_sha256"] = report_file_sha256
    summary["status"] = "verified"
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
