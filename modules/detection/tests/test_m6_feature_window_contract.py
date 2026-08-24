"""Contractual tests for the M6 feature-window protocol and builder.

Written before any materialization. These tests lock every decision authorized
in the M6 owner decision: exact temporal representation, tumbling 60-second
half-open windows on ``event_start_time``, the eight authorized features, total
absence of labels, strict intra-partition isolation, no empty windows,
deterministic UUID5 identity under the frozen M6 namespace, inherited-only
provenance, canonical ordering, and a frozen manifest.

No test materializes production data and none touches the M4 database.
"""
from __future__ import annotations

from pathlib import Path
from uuid import UUID, uuid5

import pytest
from pydantic import ValidationError

from modules.detection.src.lineage.feature_window_v2 import (
    CANONICAL_M6_MANIFEST_RELATIVE_PATH,
    FeatureWindowBindingError,
    load_and_bind_feature_window_specification_v2,
    load_feature_window_specification_v2,
)
from modules.detection.src.feature_engineering.window_builder_v2 import (
    FeatureWindowBuildError,
    FeatureWindowBuilderV2,
    SourceEventRow,
    canonical_window_bytes,
    entity_key_for,
    window_identity,
    window_start_unscaled,
    window_stream_digest,
)
from modules.detection.src.schemas.exact_time_v2 import (
    canonical_seconds_from_unscaled,
    unscaled_from_canonical,
)
from modules.detection.src.schemas.feature_window_v2 import (
    AUTHORIZED_FEATURE_NAMES,
    ENTITY_KEY_COMPONENT_COUNT,
    NULL_SERVICE_SENTINEL,
    WINDOW_LENGTH_UNSCALED,
    FeatureWindowV2,
)


ROOT = Path(__file__).resolve().parents[3]
MANIFEST = ROOT / CANONICAL_M6_MANIFEST_RELATIVE_PATH

# Exact frozen-style temporal constants (22 fractional digits, never floats).
RAT = "1722783600.0000000000000000000000"   # inherited record_available_time
T_BASE = "1499169223.7510940000000000000000"
BUCKET_START_UNSCALED = 1_499_169_180 * 10**22


@pytest.fixture(scope="module")
def specification():
    return load_feature_window_specification_v2(MANIFEST)


@pytest.fixture(scope="module")
def builder(specification):
    return FeatureWindowBuilderV2(specification)


def _row(
    *,
    event_id: str,
    start: str = T_BASE,
    partition: str = "2017-07-04_Tuesday-WorkingHours",
    source_ip: str = "192.168.10.5",
    destination_ip: str = "198.51.100.2",
    destination_port: int | None = 443,
    transport: str = "tcp",
    service: str | None = "ssl",
    source_packets: int = 2,
    destination_packets: int = 1,
    source_bytes: int = 74,
    destination_bytes: int = 10,
    sensor_run_id: str = "a" * 64,
    capture_id: str = "b" * 64,
) -> SourceEventRow:
    return SourceEventRow(
        event_id=UUID(event_id),
        output_partition=partition,
        event_start_time=start,
        record_available_time=RAT,
        source_ip=source_ip,
        source_port=51662,
        destination_ip=destination_ip,
        destination_port=destination_port,
        transport=transport,
        service=service,
        source_packets=source_packets,
        destination_packets=destination_packets,
        source_bytes=source_bytes,
        destination_bytes=destination_bytes,
        sensor_id="zeek",
        sensor_run_id=sensor_run_id,
        capture_id=capture_id,
        dataset_snapshot_id="c" * 64,
        model_release_id=None,
        normalizer_version="2.0.0",
        pipeline_version="2.0.0",
        sensor_version="8.0.9",
    )


def _ids(count: int) -> list[str]:
    return [f"00000000-0000-4000-8000-{index:012d}" for index in range(1, count + 1)]


# =====================================================================
# Frozen manifest (D17)
# =====================================================================


def test_manifest_exists_and_validates(specification) -> None:
    assert MANIFEST.is_file()
    assert specification.milestone == "m6"
    assert specification.protocol_version == "2.0.0"
    assert specification.target_model == "FeatureWindowV2"


def test_manifest_protocol_identity_is_deterministic(specification) -> None:
    reloaded = load_feature_window_specification_v2(MANIFEST)
    assert reloaded.content_sha256() == specification.content_sha256()
    assert reloaded == specification


def test_manifest_carries_no_run_identity(specification) -> None:
    """C1-a: the frozen manifest must not contain a run identity."""
    assert specification.governance.run_identity_in_manifest is False
    assert specification.governance.run_identity_location == (
        "materialization_report_only"
    )
    assert specification.governance.manifest_frozen_before_materialization is True
    assert "run_id" not in specification.model_dump(mode="json")


def test_manifest_binds_every_upstream_identity() -> None:
    bound = load_and_bind_feature_window_specification_v2(ROOT)
    assert bound.specification_sha256 == bound.specification.content_sha256()
    assert bound.m3_report_content_sha256 == (
        "6c9ef7aa545769d0e4b913b1227dc27f43ab1734227f9afeb8d1d642264848e0"
    )
    assert bound.m4_report_content_sha256 == (
        "70b4317f6619da00c6c9dc961dd37187da7afd3a4831e290efc35d6b85701433"
    )
    assert bound.m4_report.verification_status == "verified"
    assert len(bound.partition_order) == 3
    assert bound.sensor_version == "8.0.9"


def test_binding_rejects_tampered_upstream_identity(tmp_path) -> None:
    import yaml

    payload = yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))
    payload["m3_event_stream_sha256"] = "0" * 64
    tampered = tmp_path / "tampered_m6.yaml"
    tampered.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")

    with pytest.raises(FeatureWindowBindingError, match="event stream identity"):
        load_and_bind_feature_window_specification_v2(ROOT, tampered)


def test_manifest_declares_postgresql_as_non_evidence(specification) -> None:
    """D4: PostgreSQL is an operational projection, never independent evidence."""
    assert specification.postgresql_is_independent_evidence is False
    assert specification.evidence_source == "frozen_m2_conn_log_via_m3_v2_protocol"
    assert specification.operational_source == "m4_canonical.flow_end_events"
    assert specification.persistence.projection_is_reconstructible is True
    assert specification.persistence.destructive_modification_of_m4_canonical == (
        "forbidden"
    )


# =====================================================================
# FeatureWindow v1 strictly unchanged (D2/D3)
# =====================================================================


def test_feature_window_v1_is_strictly_unchanged() -> None:
    from datetime import datetime

    from modules.detection.src.schemas import FeatureWindow

    fields = FeatureWindow.model_fields
    assert set(fields) == {
        "schema_version", "event_version", "feature_version", "sensor_version",
        "provenance", "window_id", "entity_type", "entity_key",
        "window_start_time", "window_end_time", "prediction_time",
        "record_available_time", "source_event_ids", "features", "data_quality",
    }
    # v1 remains datetime-based; M6 did not migrate it.
    assert fields["window_start_time"].annotation is datetime
    assert "output_partition" not in fields


def test_feature_window_v2_is_additive_not_a_replacement() -> None:
    from modules.detection.src.schemas import FeatureWindow

    assert FeatureWindowV2 is not FeatureWindow
    assert not issubclass(FeatureWindowV2, FeatureWindow)
    # v2 uses exact decimal strings, not datetime.
    assert FeatureWindowV2.model_fields["window_start_time"].annotation is str


# =====================================================================
# Exact temporal representation (D2/D3, D5, D7, D12)
# =====================================================================


def test_exact_time_primitives_preserve_22_fractional_digits() -> None:
    low = "1499169223.0000000000000000000000"
    high = "1499169223.0000000000000000000001"
    assert unscaled_from_canonical(high) - unscaled_from_canonical(low) == 1


def test_window_start_is_computed_by_exact_integer_flooring() -> None:
    start = window_start_unscaled(T_BASE, WINDOW_LENGTH_UNSCALED)
    assert start == BUCKET_START_UNSCALED
    assert start % WINDOW_LENGTH_UNSCALED == 0
    assert isinstance(start, int)


def test_sub_microsecond_difference_does_not_change_the_bucket() -> None:
    a = window_start_unscaled("1499169223.0000000000000000000000", WINDOW_LENGTH_UNSCALED)
    b = window_start_unscaled("1499169223.0000000000000000000001", WINDOW_LENGTH_UNSCALED)
    assert a == b == BUCKET_START_UNSCALED


def test_window_bounds_are_exact_strings_never_floats(builder) -> None:
    window = builder.build_window(
        "2017-07-04_Tuesday-WorkingHours",
        ("192.168.10.5", "198.51.100.2", "tcp", "ssl"),
        BUCKET_START_UNSCALED,
        [_row(event_id=_ids(1)[0])],
    )
    for field in (
        "window_start_time", "window_end_time",
        "prediction_time", "record_available_time",
    ):
        value = getattr(window, field)
        assert isinstance(value, str), f"{field} must remain an exact decimal string"
        assert len(value.split(".")[1]) == 22


def test_window_spans_exactly_sixty_seconds(builder) -> None:
    window = builder.build_window(
        "2017-07-04_Tuesday-WorkingHours",
        ("192.168.10.5", "198.51.100.2", "tcp", "ssl"),
        BUCKET_START_UNSCALED,
        [_row(event_id=_ids(1)[0])],
    )
    span = unscaled_from_canonical(window.window_end_time) - unscaled_from_canonical(
        window.window_start_time
    )
    assert span == WINDOW_LENGTH_UNSCALED == 60 * 10**22


def test_half_open_boundary_assigns_an_edge_event_to_one_window(builder) -> None:
    """[start, end): an event exactly on a boundary belongs to the later window."""
    edge = canonical_seconds_from_unscaled(BUCKET_START_UNSCALED + WINDOW_LENGTH_UNSCALED)
    before = canonical_seconds_from_unscaled(
        BUCKET_START_UNSCALED + WINDOW_LENGTH_UNSCALED - 1
    )
    assert window_start_unscaled(edge, WINDOW_LENGTH_UNSCALED) == (
        BUCKET_START_UNSCALED + WINDOW_LENGTH_UNSCALED
    )
    assert window_start_unscaled(before, WINDOW_LENGTH_UNSCALED) == BUCKET_START_UNSCALED

    groups = builder.group([
        _row(event_id=_ids(2)[0], start=before),
        _row(event_id=_ids(2)[1], start=edge),
    ])
    assert len(groups) == 2, "a boundary event must not appear in two windows"


def test_temporal_invariants_are_enforced(builder) -> None:
    window = builder.build_window(
        "2017-07-04_Tuesday-WorkingHours",
        ("192.168.10.5", "198.51.100.2", "tcp", "ssl"),
        BUCKET_START_UNSCALED,
        [_row(event_id=_ids(1)[0])],
    )
    start = unscaled_from_canonical(window.window_start_time)
    end = unscaled_from_canonical(window.window_end_time)
    prediction = unscaled_from_canonical(window.prediction_time)
    available = unscaled_from_canonical(window.record_available_time)
    assert start < end <= prediction <= available
    assert prediction == end, "frozen protocol requires prediction_time == window_end"


def test_unaligned_window_start_is_rejected() -> None:
    from modules.detection.src.schemas import FeatureWindowV2 as Contract

    payload = _valid_window_payload()
    payload["window_start_time"] = canonical_seconds_from_unscaled(
        BUCKET_START_UNSCALED + 1
    )
    payload["window_end_time"] = canonical_seconds_from_unscaled(
        BUCKET_START_UNSCALED + 1 + WINDOW_LENGTH_UNSCALED
    )
    payload["prediction_time"] = payload["window_end_time"]
    with pytest.raises(ValidationError, match="aligned"):
        Contract.model_validate(payload)


def test_wrong_window_length_is_rejected() -> None:
    payload = _valid_window_payload()
    payload["window_end_time"] = canonical_seconds_from_unscaled(
        BUCKET_START_UNSCALED + 30 * 10**22
    )
    payload["prediction_time"] = payload["window_end_time"]
    with pytest.raises(ValidationError, match="exactly 60 seconds"):
        FeatureWindowV2.model_validate(payload)


def test_prediction_time_must_equal_window_end() -> None:
    payload = _valid_window_payload()
    payload["prediction_time"] = canonical_seconds_from_unscaled(
        BUCKET_START_UNSCALED + WINDOW_LENGTH_UNSCALED + 10**22
    )
    with pytest.raises(ValidationError, match="prediction_time == window_end_time"):
        FeatureWindowV2.model_validate(payload)


# =====================================================================
# Features (D11)
# =====================================================================


def test_exactly_eight_authorized_features(builder) -> None:
    window = builder.build_window(
        "2017-07-04_Tuesday-WorkingHours",
        ("192.168.10.5", "198.51.100.2", "tcp", "ssl"),
        BUCKET_START_UNSCALED,
        [_row(event_id=_ids(1)[0])],
    )
    assert tuple(sorted(window.features)) == AUTHORIZED_FEATURE_NAMES
    assert len(AUTHORIZED_FEATURE_NAMES) == 8


def test_feature_values_are_correct_aggregations(builder) -> None:
    ids = _ids(3)
    rows = [
        _row(event_id=ids[0], destination_port=443, source_packets=2,
             destination_packets=1, source_bytes=100, destination_bytes=10),
        _row(event_id=ids[1], destination_port=443, source_packets=3,
             destination_packets=4, source_bytes=200, destination_bytes=20),
        _row(event_id=ids[2], destination_port=8443, source_packets=5,
             destination_packets=6, source_bytes=300, destination_bytes=30),
    ]
    window = builder.build_window(
        "2017-07-04_Tuesday-WorkingHours",
        ("192.168.10.5", "198.51.100.2", "tcp", "ssl"),
        BUCKET_START_UNSCALED,
        rows,
    )
    assert window.features["event_count"] == 3.0
    assert window.features["source_packets_total"] == 10.0
    assert window.features["destination_packets_total"] == 11.0
    assert window.features["source_bytes_total"] == 600.0
    assert window.features["destination_bytes_total"] == 60.0
    assert window.features["distinct_destination_ports"] == 2.0
    assert window.features["distinct_destination_ips"] == 1.0
    assert window.features["distinct_source_ips"] == 1.0


def test_forbidden_feature_is_rejected_by_the_contract() -> None:
    payload = _valid_window_payload()
    payload["features"] = {**payload["features"], "bytes_per_second": 12.5}
    with pytest.raises(ValidationError, match="exactly the eight authorized"):
        FeatureWindowV2.model_validate(payload)


def test_missing_feature_is_rejected_by_the_contract() -> None:
    payload = _valid_window_payload()
    features = dict(payload["features"])
    features.pop("event_count")
    payload["features"] = features
    with pytest.raises(ValidationError, match="exactly the eight authorized"):
        FeatureWindowV2.model_validate(payload)


def test_manifest_forbids_rate_and_label_features(specification) -> None:
    forbidden = set(specification.features.forbidden)
    for entry in (
        "rates_or_ratios",
        "averages_requiring_division",
        "label_derived_features",
        "attack_signatures",
        "target_variables",
        "features_from_non_conn_zeek_logs",
    ):
        assert entry in forbidden


# =====================================================================
# Labels absent (D16)
# =====================================================================


def test_no_label_field_exists_on_feature_window_v2() -> None:
    for name in (
        "label", "labels", "attack_family", "attack_subtype",
        "target_profiles", "disposition",
    ):
        assert name not in FeatureWindowV2.model_fields


def test_label_field_is_structurally_rejected() -> None:
    payload = _valid_window_payload()
    payload["label"] = "target_attack"
    with pytest.raises(ValidationError, match="extra_forbidden"):
        FeatureWindowV2.model_validate(payload)


def test_manifest_declares_no_m5_interaction(specification) -> None:
    assert specification.labels.m5_interaction == "none"
    assert specification.labels.m5_contract_modification == "forbidden"


# =====================================================================
# Entity policy (D6)
# =====================================================================


def test_entity_key_has_exactly_four_ordered_components() -> None:
    row = _row(event_id=_ids(1)[0])
    key = entity_key_for(row)
    assert key == ("192.168.10.5", "198.51.100.2", "tcp", "ssl")
    assert len(key) == ENTITY_KEY_COMPONENT_COUNT == 4


def test_null_service_uses_the_frozen_sentinel() -> None:
    row = _row(event_id=_ids(1)[0], service=None)
    assert entity_key_for(row)[3] == NULL_SERVICE_SENTINEL == "none"


def test_entity_key_component_count_is_enforced() -> None:
    payload = _valid_window_payload()
    payload["entity_key"] = ("192.168.10.5", "198.51.100.2", "tcp")
    with pytest.raises(ValidationError):
        FeatureWindowV2.model_validate(payload)


def test_only_the_authorized_entity_type_is_accepted() -> None:
    payload = _valid_window_payload()
    payload["entity_type"] = "conversation"
    with pytest.raises(ValidationError):
        FeatureWindowV2.model_validate(payload)


def test_ipv6_entity_components_are_valid_identifiers(builder) -> None:
    rows = [_row(event_id=_ids(1)[0], source_ip="fe80::8cc1:7756:5ffc:823f",
                 destination_ip="ff02::fb", transport="udp", service="dns")]
    window = builder.build_window(
        "2017-07-04_Tuesday-WorkingHours",
        ("fe80::8cc1:7756:5ffc:823f", "ff02::fb", "udp", "dns"),
        BUCKET_START_UNSCALED,
        rows,
    )
    assert window.entity_key[0] == "fe80::8cc1:7756:5ffc:823f"


# =====================================================================
# Deterministic identity (D14, D6)
# =====================================================================


def test_window_identity_is_deterministic_uuid5(builder, specification) -> None:
    args = dict(
        namespace=specification.identity.namespace,
        protocol_sha256=specification.content_sha256(),
        output_partition="2017-07-04_Tuesday-WorkingHours",
        entity_type="source_destination_service",
        entity_key=("192.168.10.5", "198.51.100.2", "tcp", "ssl"),
        window_start_time=canonical_seconds_from_unscaled(BUCKET_START_UNSCALED),
        window_length_seconds=specification.window.length_seconds,
    )
    first = window_identity(**args)
    second = window_identity(**args)
    assert first == second
    assert first.version == 5


def test_window_identity_uses_the_frozen_m6_namespace(specification) -> None:
    assert str(specification.identity.namespace) == (
        "f787c08a-290e-5b79-a8cb-5bc19ae633dc"
    )
    expected = uuid5(
        specification.identity.namespace,
        "|".join((
            specification.content_sha256(),
            "2017-07-04_Tuesday-WorkingHours",
            "source_destination_service",
            "192.168.10.5", "198.51.100.2", "tcp", "ssl",
            canonical_seconds_from_unscaled(BUCKET_START_UNSCALED),
            specification.window.length_seconds,
        )),
    )
    assert window_identity(
        namespace=specification.identity.namespace,
        protocol_sha256=specification.content_sha256(),
        output_partition="2017-07-04_Tuesday-WorkingHours",
        entity_type="source_destination_service",
        entity_key=("192.168.10.5", "198.51.100.2", "tcp", "ssl"),
        window_start_time=canonical_seconds_from_unscaled(BUCKET_START_UNSCALED),
        window_length_seconds=specification.window.length_seconds,
    ) == expected


def test_identity_changes_with_every_component(specification) -> None:
    base = dict(
        namespace=specification.identity.namespace,
        protocol_sha256=specification.content_sha256(),
        output_partition="2017-07-04_Tuesday-WorkingHours",
        entity_type="source_destination_service",
        entity_key=("192.168.10.5", "198.51.100.2", "tcp", "ssl"),
        window_start_time=canonical_seconds_from_unscaled(BUCKET_START_UNSCALED),
        window_length_seconds=specification.window.length_seconds,
    )
    reference = window_identity(**base)
    variants = [
        {**base, "output_partition": "2017-07-05_Wednesday-workingHours"},
        {**base, "entity_key": ("192.168.10.6", "198.51.100.2", "tcp", "ssl")},
        {**base, "window_start_time": canonical_seconds_from_unscaled(
            BUCKET_START_UNSCALED + WINDOW_LENGTH_UNSCALED)},
        {**base, "protocol_sha256": "0" * 64},
    ]
    for variant in variants:
        assert window_identity(**variant) != reference


def test_window_id_is_the_text_form_of_provenance_event_id(builder) -> None:
    window = builder.build_window(
        "2017-07-04_Tuesday-WorkingHours",
        ("192.168.10.5", "198.51.100.2", "tcp", "ssl"),
        BUCKET_START_UNSCALED,
        [_row(event_id=_ids(1)[0])],
    )
    assert window.window_id == str(window.provenance.event_id)


def test_mismatched_window_id_is_rejected() -> None:
    payload = _valid_window_payload()
    payload["window_id"] = "00000000-0000-5000-8000-000000000999"
    with pytest.raises(ValidationError, match="text form of provenance.event_id"):
        FeatureWindowV2.model_validate(payload)


def test_manifest_forbids_random_identifiers(specification) -> None:
    assert specification.identity.random_identifiers == "forbidden"
    assert specification.identity.algorithm == "uuid5"


# =====================================================================
# Provenance (D5)
# =====================================================================


def test_provenance_is_inherited_never_fabricated(builder) -> None:
    row = _row(event_id=_ids(1)[0])
    window = builder.build_window(
        "2017-07-04_Tuesday-WorkingHours",
        ("192.168.10.5", "198.51.100.2", "tcp", "ssl"),
        BUCKET_START_UNSCALED,
        [row],
    )
    provenance = window.provenance
    assert provenance.sensor_id == row.sensor_id
    assert provenance.sensor_run_id == row.sensor_run_id
    assert provenance.capture_id == row.capture_id
    assert provenance.dataset_snapshot_id == row.dataset_snapshot_id
    assert provenance.model_release_id is row.model_release_id
    assert provenance.normalizer_version == row.normalizer_version
    assert provenance.pipeline_version == row.pipeline_version
    assert window.sensor_version == row.sensor_version
    # No placeholder value anywhere.
    for value in (
        provenance.sensor_id, provenance.sensor_run_id, provenance.capture_id,
        provenance.normalizer_version, provenance.pipeline_version,
    ):
        assert value not in {"unknown", "default", "m6", "none", "null", ""}


def test_heterogeneous_inherited_provenance_is_refused(builder) -> None:
    ids = _ids(2)
    rows = [
        _row(event_id=ids[0], sensor_run_id="a" * 64),
        _row(event_id=ids[1], sensor_run_id="d" * 64),
    ]
    with pytest.raises(FeatureWindowBuildError, match="disagree on inherited field"):
        builder.build_window(
            "2017-07-04_Tuesday-WorkingHours",
            ("192.168.10.5", "198.51.100.2", "tcp", "ssl"),
            BUCKET_START_UNSCALED,
            rows,
        )


def test_window_event_id_is_not_a_source_event_id(builder) -> None:
    window = builder.build_window(
        "2017-07-04_Tuesday-WorkingHours",
        ("192.168.10.5", "198.51.100.2", "tcp", "ssl"),
        BUCKET_START_UNSCALED,
        [_row(event_id=_ids(1)[0])],
    )
    assert window.provenance.event_id not in window.source_event_ids


# =====================================================================
# Lineage and empty windows (D15)
# =====================================================================


def test_source_event_ids_are_unique_and_counted(builder) -> None:
    ids = _ids(3)
    window = builder.build_window(
        "2017-07-04_Tuesday-WorkingHours",
        ("192.168.10.5", "198.51.100.2", "tcp", "ssl"),
        BUCKET_START_UNSCALED,
        [_row(event_id=value) for value in ids],
    )
    assert len(window.source_event_ids) == 3
    assert len(set(window.source_event_ids)) == 3
    assert window.data_quality.source_event_count == 3


def test_empty_window_is_refused_by_the_builder(builder) -> None:
    with pytest.raises(FeatureWindowBuildError, match="empty windows are forbidden"):
        builder.build_window(
            "2017-07-04_Tuesday-WorkingHours",
            ("192.168.10.5", "198.51.100.2", "tcp", "ssl"),
            BUCKET_START_UNSCALED,
            [],
        )


def test_empty_source_event_ids_rejected_by_contract() -> None:
    payload = _valid_window_payload()
    payload["source_event_ids"] = ()
    with pytest.raises(ValidationError):
        FeatureWindowV2.model_validate(payload)


def test_manifest_forbids_empty_windows(specification) -> None:
    assert specification.window.empty_windows == "forbidden"


# =====================================================================
# Partition isolation (D13)
# =====================================================================


def test_events_from_different_partitions_never_share_a_window(builder) -> None:
    ids = _ids(2)
    groups = builder.group([
        _row(event_id=ids[0], partition="2017-07-04_Tuesday-WorkingHours"),
        _row(event_id=ids[1], partition="2017-07-05_Wednesday-workingHours"),
    ])
    assert len(groups) == 2
    partitions = {key[0] for key in groups}
    assert partitions == {
        "2017-07-04_Tuesday-WorkingHours",
        "2017-07-05_Wednesday-workingHours",
    }


def test_manifest_declares_strict_intra_partition(specification) -> None:
    assert specification.window.partition_policy == "strictly_intra_partition"
    assert specification.window.cross_partition_windows is False


# =====================================================================
# Canonical ordering (D20)
# =====================================================================


def test_output_order_is_canonical_and_deterministic(builder) -> None:
    ids = _ids(4)
    rows = [
        _row(event_id=ids[0], partition="2017-07-05_Wednesday-workingHours"),
        _row(event_id=ids[1], source_ip="192.168.10.9"),
        _row(event_id=ids[2], start=canonical_seconds_from_unscaled(
            BUCKET_START_UNSCALED + WINDOW_LENGTH_UNSCALED)),
        _row(event_id=ids[3]),
    ]
    first = [
        (w.output_partition, w.entity_key, w.window_start_time)
        for w in builder.build_ordered(rows)
    ]
    second = [
        (w.output_partition, w.entity_key, w.window_start_time)
        for w in builder.build_ordered(list(reversed(rows)))
    ]
    assert first == second, "ordering must not depend on input order"
    assert first == sorted(first), "ordering must follow the canonical key"


def test_window_stream_digest_is_deterministic(builder) -> None:
    rows = [_row(event_id=value) for value in _ids(3)]
    a_digest, a_count = window_stream_digest(builder.build_ordered(rows))
    b_digest, b_count = window_stream_digest(builder.build_ordered(list(reversed(rows))))
    assert a_digest == b_digest
    assert a_count == b_count == 1


def test_canonical_window_bytes_are_stable(builder) -> None:
    window = builder.build_window(
        "2017-07-04_Tuesday-WorkingHours",
        ("192.168.10.5", "198.51.100.2", "tcp", "ssl"),
        BUCKET_START_UNSCALED,
        [_row(event_id=_ids(1)[0])],
    )
    assert canonical_window_bytes(window) == canonical_window_bytes(window)
    assert canonical_window_bytes(window).endswith(b"\n")


def test_manifest_forbids_value_based_ordering(specification) -> None:
    assert specification.ordering.sort_by_feature_value is False
    assert specification.ordering.dictionary_or_set_iteration_order == "forbidden"
    assert specification.ordering.window_start_comparison == "unscaled_integer"


# =====================================================================
# Deferred policies (D8, D9)
# =====================================================================


def test_no_watermark_or_late_arrival_policy_is_introduced(specification) -> None:
    assert specification.deferred.watermark_policy == (
        "deferred_not_introduced_by_m6"
    )
    assert specification.deferred.late_arrival_policy == (
        "deferred_not_introduced_by_m6"
    )


def test_data_quality_records_no_late_or_dropped_events(builder) -> None:
    window = builder.build_window(
        "2017-07-04_Tuesday-WorkingHours",
        ("192.168.10.5", "198.51.100.2", "tcp", "ssl"),
        BUCKET_START_UNSCALED,
        [_row(event_id=_ids(1)[0])],
    )
    assert window.data_quality.late_event_count == 0
    assert window.data_quality.dropped_event_count == 0
    assert window.data_quality.is_final is True
    assert window.data_quality.is_revision is False


# =====================================================================
# Contract versions (D19)
# =====================================================================


def test_window_contract_versions_are_frozen(builder) -> None:
    window = builder.build_window(
        "2017-07-04_Tuesday-WorkingHours",
        ("192.168.10.5", "198.51.100.2", "tcp", "ssl"),
        BUCKET_START_UNSCALED,
        [_row(event_id=_ids(1)[0])],
    )
    assert window.schema_version == "2.0.0"
    assert window.event_version == "2.0.0"
    assert window.feature_version == "2.0.0"
    assert window.sensor_version == "8.0.9"


def test_source_event_feature_version_dependency_is_declared(specification) -> None:
    assert specification.source_event_feature_version == "1.0.0"
    assert specification.window_contract_versions.feature_version == "2.0.0"


def test_wrong_window_version_is_rejected() -> None:
    payload = _valid_window_payload()
    payload["feature_version"] = "1.0.0"
    with pytest.raises(ValidationError, match="must all be 2.0.0"):
        FeatureWindowV2.model_validate(payload)


# =====================================================================
# Shared valid payload
# =====================================================================


def _valid_window_payload() -> dict[str, object]:
    from modules.detection.src.lineage.provenance import EventProvenance

    identity = UUID("11111111-1111-5111-8111-111111111111")
    start = canonical_seconds_from_unscaled(BUCKET_START_UNSCALED)
    end = canonical_seconds_from_unscaled(
        BUCKET_START_UNSCALED + WINDOW_LENGTH_UNSCALED
    )
    return {
        "schema_version": "2.0.0",
        "event_version": "2.0.0",
        "feature_version": "2.0.0",
        "sensor_version": "8.0.9",
        "provenance": EventProvenance(
            event_id=identity,
            sensor_id="zeek",
            sensor_run_id="a" * 64,
            capture_id="b" * 64,
            dataset_snapshot_id="c" * 64,
            model_release_id=None,
            normalizer_version="2.0.0",
            pipeline_version="2.0.0",
        ),
        "window_id": str(identity),
        "entity_type": "source_destination_service",
        "entity_key": ("192.168.10.5", "198.51.100.2", "tcp", "ssl"),
        "output_partition": "2017-07-04_Tuesday-WorkingHours",
        "window_start_time": start,
        "window_end_time": end,
        "prediction_time": end,
        "record_available_time": RAT,
        "source_event_ids": (UUID(_ids(1)[0]),),
        "features": {name: 1.0 for name in AUTHORIZED_FEATURE_NAMES},
        "data_quality": {
            "source_event_count": 1,
            "late_event_count": 0,
            "dropped_event_count": 0,
            "is_final": True,
            "is_revision": False,
        },
    }
