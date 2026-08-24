"""M3 Step 2 tests for concrete streaming conn.log normalization."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal, localcontext
from hashlib import sha256
import io
import json
import os
from pathlib import Path
from uuid import UUID

from pydantic import ValidationError
import pytest

from modules.detection.src.ingestion.zeek_json import (
    StrictZeekJsonLineParser,
    ZeekRecordRejection,
)
from modules.detection.src.lineage.zeek_normalization import (
    BoundZeekNormalizationSpecification,
    load_and_bind_zeek_normalization_specification,
    load_zeek_normalization_specification,
)
from modules.detection.src.normalization.zeek_conn import (
    StrictZeekConnFlowEndNormalizer,
    ZeekSourceBindingError,
)
from modules.detection.src.normalization.zeek_pipeline import (
    ZeekConnNormalizationRunner,
    canonical_event_bytes,
    write_immutable_normalization_report,
)
from modules.detection.src.schemas.events import FlowEnd
from modules.detection.src.schemas.zeek_normalization import (
    ZeekNormalizationContext,
    ZeekNormalizationSpecification,
    ZeekSourceCoordinate,
)
from modules.detection.src.schemas.zeek_normalization_run import (
    ZeekNormalizationRunReport,
    ZeekPartitionNormalizationReport,
)


ROOT = Path(__file__).resolve().parents[3]
SPEC_PATH = ROOT / "datasets/manifests/cicids2017_zeek_normalization.yaml"
AVAILABLE = datetime(2026, 7, 31, 12, 0, tzinfo=timezone.utc)
INGESTED = AVAILABLE + timedelta(seconds=1)
VALID_JSON = (
    b'{"ts":1499169223.751094,"uid":"CJioLj2aEkGc9R3T0b",'
    b'"id.orig_h":"192.0.2.1","id.orig_p":5353,'
    b'"id.resp_h":"198.51.100.2","id.resp_p":53,'
    b'"proto":"udp","service":"dns","duration":1.000001,'
    b'"orig_bytes":74,"resp_bytes":10,"conn_state":"SF",'
    b'"orig_pkts":2,"resp_pkts":1}\n'
)


@pytest.fixture(scope="module")
def specification() -> ZeekNormalizationSpecification:
    return load_zeek_normalization_specification(SPEC_PATH)


def _source(
    specification: ZeekNormalizationSpecification,
    *,
    partition_index: int = 0,
    line_number: int = 42,
) -> ZeekSourceCoordinate:
    binding = specification.replay_reports[partition_index]
    return ZeekSourceCoordinate(
        output_partition=binding.output_partition,
        replay_report_content_sha256=binding.report_content_sha256,
        log_name="conn.log",
        source_log_sha256=binding.supported_log.sha256,
        reported_record_count=binding.supported_log.record_count,
        physical_line_number=line_number,
    )


def _context(
    specification: ZeekNormalizationSpecification,
    *,
    source: ZeekSourceCoordinate | None = None,
) -> ZeekNormalizationContext:
    return ZeekNormalizationContext(
        protocol_sha256=specification.content_sha256(),
        source=source or _source(specification),
        record_available_time=AVAILABLE,
        ingested_at=INGESTED,
    )


def _valid_record(
    specification: ZeekNormalizationSpecification,
) -> dict[str, object]:
    return dict(StrictZeekJsonLineParser().parse_line(VALID_JSON, _source(specification)))


def _assert_rejection(
    specification: ZeekNormalizationSpecification,
    record: dict[str, object],
    reason: str,
    fields: tuple[str, ...] | None = None,
) -> None:
    normalizer = StrictZeekConnFlowEndNormalizer(specification)
    with pytest.raises(ZeekRecordRejection) as captured:
        normalizer.normalize_conn(record, _context(specification), specification)
    assert captured.value.reason == reason
    if fields is not None:
        assert captured.value.fields == fields


def _synthetic_runner(
    tmp_path: Path,
    specification: ZeekNormalizationSpecification,
    partition_lines: tuple[tuple[bytes, ...], ...],
) -> tuple[ZeekConnNormalizationRunner, ZeekNormalizationSpecification]:
    bindings = []
    for binding, lines in zip(specification.replay_reports, partition_lines, strict=True):
        payload = b"".join(lines)
        artifact = binding.supported_log.model_copy(
            update={
                "size_bytes": len(payload),
                "sha256": sha256(payload).hexdigest(),
                "record_count": len(lines),
            }
        )
        synthetic_binding = binding.model_copy(update={"supported_log": artifact})
        bindings.append(synthetic_binding)
        path = (
            tmp_path
            / specification.m2_output_root
            / binding.output_partition
            / "conn.log"
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
    synthetic_specification = specification.model_copy(
        update={"replay_reports": tuple(bindings)}
    )
    protocol_sha256 = synthetic_specification.content_sha256()
    bound = BoundZeekNormalizationSpecification(
        specification=synthetic_specification,
        specification_sha256=protocol_sha256,
        m1_manifest_sha256=synthetic_specification.m1_manifest_sha256,
        m2_specification_sha256=synthetic_specification.m2_specification_sha256,
        replay_report_count=3,
        supported_record_count=sum(len(lines) for lines in partition_lines),
    )
    return (
        ZeekConnNormalizationRunner(tmp_path, bound, AVAILABLE, INGESTED),
        synthetic_specification,
    )


def test_parser_preserves_decimal_lexemes_and_integer_types(
    specification: ZeekNormalizationSpecification,
) -> None:
    record = StrictZeekJsonLineParser().parse_line(
        VALID_JSON,
        _source(specification),
    )
    assert record["ts"] == Decimal("1499169223.751094")
    assert record["duration"] == Decimal("1.000001")
    assert type(record["ts"]) is Decimal
    assert type(record["orig_bytes"]) is int
    assert record["orig_bytes"] == 74


@pytest.mark.parametrize(
    ("line", "reason", "fields"),
    [
        (b"", "malformed_json", ()),
        (b"not-json\n", "malformed_json", ()),
        (b"{}\n{}\n", "malformed_json", ()),
        (b"\xff\n", "malformed_json", ()),
        (b'{"ts":1,"ts":2}\n', "malformed_json", ("ts",)),
        (b"[]\n", "non_object_json", ()),
        (b"null\n", "non_object_json", ()),
        (b'{"ts":NaN}\n', "non_finite_number", ()),
        (b'{"ts":Infinity}\n', "non_finite_number", ()),
        (
            ('{"value":' + ('9' * 5000) + '}\n').encode(),
            "malformed_json",
            (),
        ),
    ],
)
def test_parser_rejects_malformed_nonobject_duplicate_and_nonfinite_json(
    specification: ZeekNormalizationSpecification,
    line: bytes,
    reason: str,
    fields: tuple[str, ...],
) -> None:
    with pytest.raises(ZeekRecordRejection) as captured:
        StrictZeekJsonLineParser().parse_line(line, _source(specification))
    assert captured.value.reason == reason
    assert captured.value.fields == fields
    assert captured.value.source.physical_line_number == 42


def test_parser_requires_bytes(specification: ZeekNormalizationSpecification) -> None:
    with pytest.raises(TypeError, match="must be bytes"):
        StrictZeekJsonLineParser().parse_line(  # type: ignore[arg-type]
            VALID_JSON.decode(),
            _source(specification),
        )


def test_normalizer_constructs_exact_flow_end_and_complete_provenance(
    specification: ZeekNormalizationSpecification,
) -> None:
    event = StrictZeekConnFlowEndNormalizer(specification).normalize_conn(
        _valid_record(specification),
        _context(specification),
        specification,
    )
    assert isinstance(event, FlowEnd)
    assert event.event_type == "flow_end"
    assert event.sensor_type == "zeek"
    assert event.event_start_time == datetime(
        2017, 7, 4, 11, 53, 43, 751094, tzinfo=timezone.utc
    )
    assert event.event_end_time == datetime(
        2017, 7, 4, 11, 53, 44, 751095, tzinfo=timezone.utc
    )
    assert event.record_available_time == AVAILABLE
    assert event.ingested_at == INGESTED
    assert event.conversation_id == "CJioLj2aEkGc9R3T0b"
    assert str(event.source.ip) == "192.0.2.1"
    assert event.source.port == 5353
    assert str(event.destination.ip) == "198.51.100.2"
    assert event.destination.port == 53
    assert event.transport == "udp"
    assert event.service == "dns"
    assert event.counters.model_dump() == {
        "source_packets": 2,
        "destination_packets": 1,
        "source_bytes": 74,
        "destination_bytes": 10,
    }
    assert event.connection_state == "SF"
    assert event.termination_reason is None
    assert event.version_contract() == specification.event_envelope.versions
    assert event.provenance.event_id == UUID("c258e55a-76b4-53bc-9e44-2e6432ba6c0a")
    assert event.provenance.sensor_id == "zeek"
    assert event.provenance.sensor_run_id == (
        specification.replay_reports[0].report_content_sha256
    )
    assert event.provenance.capture_id == specification.replay_reports[0].input.sha256
    assert event.provenance.dataset_snapshot_id == specification.m1_manifest_sha256
    assert event.provenance.model_release_id is None
    assert event.provenance.normalizer_version == "1.0.0"
    assert event.provenance.pipeline_version == "1.0.0"


def test_event_uuid_and_canonical_bytes_are_deterministic_and_coordinate_bound(
    specification: ZeekNormalizationSpecification,
) -> None:
    normalizer = StrictZeekConnFlowEndNormalizer(specification)
    record = _valid_record(specification)
    first = normalizer.normalize_conn(record, _context(specification), specification)
    repeated = normalizer.normalize_conn(record, _context(specification), specification)
    source_43 = _source(specification, line_number=43)
    next_event = normalizer.normalize_conn(
        record,
        _context(specification, source=source_43),
        specification,
    )
    assert first == repeated
    assert canonical_event_bytes(first) == canonical_event_bytes(repeated)
    assert first.provenance.event_id != next_event.provenance.event_id
    changed_wall_clock = ZeekNormalizationContext(
        protocol_sha256=specification.content_sha256(),
        source=_source(specification),
        record_available_time=AVAILABLE + timedelta(days=1),
        ingested_at=INGESTED + timedelta(days=1),
    )
    changed_time_event = normalizer.normalize_conn(
        record,
        changed_wall_clock,
        specification,
    )
    assert changed_time_event.provenance.event_id == first.provenance.event_id


def test_missing_null_unknown_and_ignored_field_rules(
    specification: ZeekNormalizationSpecification,
) -> None:
    record = _valid_record(specification)
    del record["duration"]
    record["orig_ip_bytes"] = 999
    _assert_rejection(
        specification,
        record,
        "missing_required_field",
        ("duration",),
    )

    record = _valid_record(specification)
    record["orig_bytes"] = None
    _assert_rejection(
        specification,
        record,
        "null_required_field",
        ("orig_bytes",),
    )

    record = _valid_record(specification)
    record["policy_extension"] = "unexpected"
    _assert_rejection(
        specification,
        record,
        "unknown_field",
        ("policy_extension",),
    )

    record = _valid_record(specification)
    record.update(
        {
            "history": "Dd",
            "ip_proto": 17,
            "local_orig": True,
            "local_resp": False,
            "missed_bytes": 0,
            "orig_ip_bytes": 9999,
            "resp_ip_bytes": 8888,
            "tunnel_parents": [],
        }
    )
    event = StrictZeekConnFlowEndNormalizer(specification).normalize_conn(
        record,
        _context(specification),
        specification,
    )
    assert event.counters.source_bytes == 74
    assert event.counters.destination_bytes == 10


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("id.orig_p", True),
        ("id.resp_p", "53"),
        ("orig_bytes", Decimal("1")),
        ("orig_pkts", 1.0),
        ("uid", 42),
        ("duration", "1.0"),
    ],
)
def test_strict_mapped_field_types_are_not_coerced(
    specification: ZeekNormalizationSpecification,
    field: str,
    value: object,
) -> None:
    record = _valid_record(specification)
    record[field] = value
    _assert_rejection(
        specification,
        record,
        "invalid_field_type",
        (field,),
    )


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("ts", Decimal("NaN"), "non_finite_number"),
        ("duration", Decimal("Infinity"), "non_finite_number"),
        ("ts", Decimal("1499169223.7510941"), "excess_timestamp_precision"),
        ("duration", Decimal("1.0000001"), "excess_timestamp_precision"),
        ("ts", Decimal("-0.000001"), "invalid_field_type"),
        ("duration", Decimal("-0.000001"), "invalid_field_type"),
    ],
)
def test_timestamp_and_duration_rules_reject_without_rounding(
    specification: ZeekNormalizationSpecification,
    field: str,
    value: object,
    reason: str,
) -> None:
    record = _valid_record(specification)
    record[field] = value
    _assert_rejection(specification, record, reason, (field,))


def test_trailing_zero_precision_is_exact_not_rounded(
    specification: ZeekNormalizationSpecification,
) -> None:
    record = _valid_record(specification)
    record["duration"] = Decimal("1.0000010")
    event = StrictZeekConnFlowEndNormalizer(specification).normalize_conn(
        record,
        _context(specification),
        specification,
    )
    assert event.event_end_time.microsecond == 751095


@pytest.mark.parametrize("transport", ["icmp", "unknown_transport", "other", "TCP"])
def test_only_exact_tcp_and_udp_transports_are_supported(
    specification: ZeekNormalizationSpecification,
    transport: str,
) -> None:
    record = _valid_record(specification)
    record["proto"] = transport
    _assert_rejection(
        specification,
        record,
        "unsupported_transport",
        ("proto",),
    )


def test_service_absence_null_single_and_multiple_rules(
    specification: ZeekNormalizationSpecification,
) -> None:
    normalizer = StrictZeekConnFlowEndNormalizer(specification)
    record = _valid_record(specification)
    del record["service"]
    assert normalizer.normalize_conn(record, _context(specification), specification).service is None

    record = _valid_record(specification)
    record["service"] = None
    assert normalizer.normalize_conn(record, _context(specification), specification).service is None

    record = _valid_record(specification)
    record["service"] = "ssl"
    assert normalizer.normalize_conn(record, _context(specification), specification).service == "ssl"

    record = _valid_record(specification)
    record["service"] = "gssapi,dce_rpc"
    _assert_rejection(
        specification,
        record,
        "unsupported_service_cardinality",
        ("service",),
    )

    record = _valid_record(specification)
    record["service"] = "bad service"
    _assert_rejection(specification, record, "invalid_field_type", ())


def test_counter_port_ip_identifier_and_temporal_validation(
    specification: ZeekNormalizationSpecification,
) -> None:
    cases = (
        ("orig_bytes", -1),
        ("orig_pkts", -1),
        ("id.orig_p", 65536),
        ("id.orig_h", "not-an-ip"),
        ("uid", "bad uid"),
        ("conn_state", "bad state"),
    )
    for field, value in cases:
        record = _valid_record(specification)
        record[field] = value
        _assert_rejection(specification, record, "invalid_field_type")

    early_context = ZeekNormalizationContext(
        protocol_sha256=specification.content_sha256(),
        source=_source(specification),
        record_available_time=datetime(2017, 7, 4, 11, 53, 43, tzinfo=timezone.utc),
        ingested_at=datetime(2017, 7, 4, 11, 53, 43, tzinfo=timezone.utc),
    )
    with pytest.raises(ZeekRecordRejection) as captured:
        StrictZeekConnFlowEndNormalizer(specification).normalize_conn(
            _valid_record(specification),
            early_context,
            specification,
        )
    assert captured.value.reason == "invalid_field_type"
    assert captured.value.fields == ("event_end_time", "record_available_time")


def test_source_and_protocol_binding_mismatches_abort_not_reject_record(
    specification: ZeekNormalizationSpecification,
) -> None:
    normalizer = StrictZeekConnFlowEndNormalizer(specification)
    context = _context(specification).model_copy(update={"protocol_sha256": "0" * 64})
    with pytest.raises(ZeekSourceBindingError, match="protocol hash"):
        normalizer.normalize_conn(_valid_record(specification), context, specification)

    source = _source(specification).model_copy(update={"source_log_sha256": "0" * 64})
    with pytest.raises(ZeekSourceBindingError, match="log hash"):
        normalizer.normalize_conn(
            _valid_record(specification),
            _context(specification, source=source),
            specification,
        )


def test_synthetic_runner_streams_all_partitions_and_reports_lossless_rejections(
    tmp_path: Path,
    specification: ZeekNormalizationSpecification,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    excess = VALID_JSON.replace(b"1.000001", b"1.0000001")
    icmp = VALID_JSON.replace(b'"proto":"udp"', b'"proto":"icmp"')
    lines = (
        (VALID_JSON, excess, icmp),
        (VALID_JSON,),
        (VALID_JSON, b"not-json\n"),
    )
    runner, synthetic_specification = _synthetic_runner(
        tmp_path,
        specification,
        lines,
    )

    def forbidden_read_bytes(_path: Path) -> bytes:
        raise AssertionError("streaming runner must not call Path.read_bytes")

    monkeypatch.setattr(Path, "read_bytes", forbidden_read_bytes)
    report = runner.run()
    assert isinstance(report, ZeekNormalizationRunReport)
    assert report.protocol_sha256 == synthetic_specification.content_sha256()
    assert report.total_processed_record_count == 6
    assert report.total_accepted_record_count == 3
    assert report.total_rejected_record_count == 3
    assert tuple(item.output_partition for item in report.partition_reports) == tuple(
        item.output_partition for item in synthetic_specification.replay_reports
    )
    first = report.partition_reports[0]
    assert first.processed_record_count == 3
    assert first.accepted_record_count == 1
    assert first.rejected_record_count == 2
    assert tuple((item.reason, item.count) for item in first.rejection_counts) == (
        ("excess_timestamp_precision", 1),
        ("unsupported_transport", 1),
    )
    assert tuple(
        (
            span.first_physical_line_number,
            span.last_physical_line_number,
            span.reason,
            span.fields,
        )
        for span in first.rejection_spans
    ) == (
        (2, 2, "excess_timestamp_precision", ("duration",)),
        (3, 3, "unsupported_transport", ("proto",)),
    )
    assert first.first_accepted_event_id == first.last_accepted_event_id
    assert report.partition_reports[2].rejection_spans[0].reason == "malformed_json"
    assert not list(tmp_path.rglob("*.event*"))


def test_synthetic_reports_are_identical_across_repeated_execution(
    tmp_path: Path,
    specification: ZeekNormalizationSpecification,
) -> None:
    lines = ((VALID_JSON,), (VALID_JSON,), (VALID_JSON,))
    runner, _ = _synthetic_runner(tmp_path, specification, lines)
    first = runner.run()
    second = runner.run()
    assert first == second
    assert first.content_sha256() == second.content_sha256()
    assert first.canonical_event_stream_sha256 == second.canonical_event_stream_sha256
    assert first.rejection_audit_stream_sha256 == second.rejection_audit_stream_sha256


def test_source_preflight_rejects_tampering_before_parsing(
    tmp_path: Path,
    specification: ZeekNormalizationSpecification,
) -> None:
    lines = ((VALID_JSON,), (VALID_JSON,), (VALID_JSON,))
    runner, synthetic_specification = _synthetic_runner(tmp_path, specification, lines)
    path = (
        tmp_path
        / synthetic_specification.m2_output_root
        / synthetic_specification.replay_reports[0].output_partition
        / "conn.log"
    )
    path.write_bytes(VALID_JSON.replace(b"dns", b"ntp"))
    with pytest.raises(ZeekSourceBindingError, match="hash"):
        runner.normalize_partition(synthetic_specification.replay_reports[0])


def test_report_publication_is_report_only_deterministic_and_immutable(
    tmp_path: Path,
    specification: ZeekNormalizationSpecification,
) -> None:
    source_root = tmp_path / "source"
    lines = ((VALID_JSON,), (VALID_JSON,), (VALID_JSON,))
    runner, _ = _synthetic_runner(source_root, specification, lines)
    report = runner.run()
    destination = tmp_path / "reports" / "normalization.json"
    file_sha256 = write_immutable_normalization_report(report, destination)
    raw = destination.read_bytes()
    assert sha256(raw).hexdigest() == file_sha256
    assert ZeekNormalizationRunReport.model_validate_json(raw) == report
    assert list(destination.parent.iterdir()) == [destination]
    with pytest.raises(FileExistsError):
        write_immutable_normalization_report(report, destination)


def test_report_contract_rejects_count_and_span_inconsistency(
    tmp_path: Path,
    specification: ZeekNormalizationSpecification,
) -> None:
    lines = ((VALID_JSON,), (VALID_JSON,), (VALID_JSON,))
    runner, _ = _synthetic_runner(tmp_path, specification, lines)
    report = runner.run()
    partition = report.partition_reports[0]
    with pytest.raises(ValidationError, match="accepted and rejected"):
        ZeekPartitionNormalizationReport.model_validate(
            {
                **partition.model_dump(),
                "accepted_record_count": 0,
            }
        )


def test_bounded_real_first_lines_parse_and_obey_frozen_precision_rejection(
    specification: ZeekNormalizationSpecification,
) -> None:
    parser = StrictZeekJsonLineParser()
    normalizer = StrictZeekConnFlowEndNormalizer(specification)
    for index, binding in enumerate(specification.replay_reports):
        path = (
            ROOT
            / specification.m2_output_root
            / binding.output_partition
            / "conn.log"
        )
        with path.open("rb") as stream:
            line = stream.readline()
            assert stream.tell() == len(line)
        source = _source(specification, partition_index=index, line_number=1)
        record = parser.parse_line(line, source)
        assert isinstance(record["ts"], Decimal)
        assert isinstance(record["duration"], Decimal)
        with pytest.raises(ZeekRecordRejection) as captured:
            normalizer.normalize_conn(
                record,
                _context(specification, source=source),
                specification,
            )
        assert captured.value.reason == "excess_timestamp_precision"
        assert captured.value.fields == ("duration",)


def test_official_bound_specification_remains_exact() -> None:
    bound = load_and_bind_zeek_normalization_specification(ROOT)
    assert bound.specification_sha256 == (
        "99ab724a3d245a352e888e2f4771b5a354b5855180af4a72c36980c9296897d4"
    )
    assert bound.supported_record_count == 1_380_057



def test_published_real_normalization_report_has_frozen_results() -> None:
    path = ROOT / "artifacts/reports/cicids2017_m3_step2_normalization.json"
    raw = path.read_bytes()
    report = ZeekNormalizationRunReport.model_validate_json(raw)
    assert sha256(raw).hexdigest() == (
        "712e0d412f0a10fb301aa524c1be5f09902ee599f97cb2cb81ab5f7384486895"
    )
    assert report.content_sha256() == (
        "a6be7f9c86f4476a7746fef2b025a0311e514ce7145e2c3a470d04d65620f4d0"
    )
    assert report.total_processed_record_count == 1_380_057
    assert report.total_accepted_record_count == 100
    assert report.total_rejected_record_count == 1_379_957
    assert report.canonical_event_stream_sha256 == (
        "7bb930321cafb9d4ee3d1d89f0f10414cfd05cbdc14dc4faa94150d2e4b27764"
    )
    assert report.rejection_audit_stream_sha256 == (
        "77533fb29bf584d0debe37d6a6525a8a20276f98cd5cd2d9b04b14ca47dda6ab"
    )
    assert tuple(
        (
            item.output_partition,
            item.processed_record_count,
            item.accepted_record_count,
            item.rejected_record_count,
            len(item.rejection_spans),
            tuple((count.reason, count.count) for count in item.rejection_counts),
        )
        for item in report.partition_reports
    ) == (
        (
            "2017-07-04_Tuesday-WorkingHours",
            323342,
            24,
            323318,
            5217,
            (
                ("excess_timestamp_precision", 319694),
                ("missing_required_field", 3624),
            ),
        ),
        (
            "2017-07-05_Wednesday-workingHours",
            509362,
            45,
            509317,
            6498,
            (
                ("excess_timestamp_precision", 491573),
                ("missing_required_field", 17744),
            ),
        ),
        (
            "2017-07-07_Friday-WorkingHours",
            547353,
            31,
            547322,
            5702,
            (
                ("excess_timestamp_precision", 543764),
                ("missing_required_field", 3558),
            ),
        ),
    )


def test_exact_timestamp_conversion_is_independent_of_decimal_context(
    specification: ZeekNormalizationSpecification,
) -> None:
    normalizer = StrictZeekConnFlowEndNormalizer(specification)
    record = _valid_record(specification)
    expected = normalizer.normalize_conn(record, _context(specification), specification)
    with localcontext() as decimal_context:
        decimal_context.prec = 10
        actual = normalizer.normalize_conn(record, _context(specification), specification)
    assert actual.event_start_time == expected.event_start_time
    assert actual.event_end_time == expected.event_end_time
    assert actual.provenance.event_id == expected.provenance.event_id

    for precision in (10, 28, 50):
        record = _valid_record(specification)
        record["duration"] = Decimal("1.00000000000000000000000000001")
        with localcontext() as decimal_context:
            decimal_context.prec = precision
            _assert_rejection(
                specification,
                record,
                "excess_timestamp_precision",
                ("duration",),
            )

    record = _valid_record(specification)
    record["duration"] = Decimal("1e999999999")
    _assert_rejection(
        specification,
        record,
        "invalid_field_type",
        ("duration",),
    )


def test_runner_postverifies_bytes_processed_from_same_open_handle(
    tmp_path: Path,
    specification: ZeekNormalizationSpecification,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lines = ((VALID_JSON,), (VALID_JSON,), (VALID_JSON,))
    runner, synthetic_specification = _synthetic_runner(tmp_path, specification, lines)
    binding = synthetic_specification.replay_reports[0]
    source_path = (
        tmp_path
        / synthetic_specification.m2_output_root
        / binding.output_partition
        / "conn.log"
    ).resolve()
    original_payload = source_path.read_bytes()
    changed_payload = original_payload.replace(b"dns", b"ntp")
    original_open = Path.open
    source_open_count = 0

    class ChangingAfterPreflight(io.BytesIO):
        switched = False

        def seek(self, offset: int, whence: int = 0) -> int:
            if offset == 0 and whence == 0 and self.tell() > 0 and not self.switched:
                self.switched = True
                super().seek(0)
                super().truncate(0)
                super().write(changed_payload)
            return super().seek(offset, whence)

    def controlled_open(path: Path, mode: str = "r", *args: object, **kwargs: object):
        nonlocal source_open_count
        if path.resolve() == source_path and mode == "rb":
            source_open_count += 1
            return ChangingAfterPreflight(original_payload)
        return original_open(path, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", controlled_open)
    with pytest.raises(ZeekSourceBindingError, match="changed between"):
        runner.normalize_partition(binding)
    assert source_open_count == 1


def test_report_publication_cannot_overwrite_concurrent_destination(
    tmp_path: Path,
    specification: ZeekNormalizationSpecification,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_root = tmp_path / "source"
    runner, _ = _synthetic_runner(
        source_root,
        specification,
        ((VALID_JSON,), (VALID_JSON,), (VALID_JSON,)),
    )
    report = runner.run()
    destination = tmp_path / "reports" / "normalization.json"
    competitor = b"concurrent-writer\n"
    original_link = os.link

    def racing_link(source: object, target: object, *args: object, **kwargs: object) -> None:
        Path(target).write_bytes(competitor)
        original_link(source, target, *args, **kwargs)

    monkeypatch.setattr(os, "link", racing_link)
    with pytest.raises(FileExistsError):
        write_immutable_normalization_report(report, destination)
    assert destination.read_bytes() == competitor
    assert not destination.with_name(f".{destination.name}.tmp").exists()
