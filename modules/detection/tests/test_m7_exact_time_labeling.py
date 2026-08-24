"""Contractual tests for the exact-time M5 label adapter and ANY_ATTACK rule.

Proves that the adapter applies the frozen M5 policy without modifying it,
without any float or datetime rounding, and that its labels pass M5's own
``validate_label``. Also locks the documented ANY_ATTACK decision table.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
from ipaddress import ip_address
from pathlib import Path
from uuid import UUID

import pytest

from modules.detection.src.lineage.exact_time_labeling_v2 import (
    ATTACK_DISPOSITIONS,
    WINDOW_DISPOSITION_PRECEDENCE,
    ExactTimeLabelAdapterV2,
    ExactTimeLabelError,
    aggregate_window_disposition,
    exact_unscaled_from_datetime,
    is_attack,
)
from modules.detection.src.lineage.labeling import LabelLedger
from modules.detection.src.lineage.provenance import EventProvenance
from modules.detection.src.schemas.common import FlowCounters, NetworkEndpoint
from modules.detection.src.schemas.events_v2 import FlowEndV2
from modules.detection.src.schemas.exact_time_v2 import (
    UNSCALED_FACTOR,
    canonical_seconds_from_unscaled,
)


ROOT = Path(__file__).resolve().parents[3]
MANIFEST = ROOT / "datasets/manifests/cicids2017_labels.yaml"
RAT = "1722783600.0000000000000000000000"


@pytest.fixture(scope="module")
def ledger() -> LabelLedger:
    return LabelLedger.from_yaml(MANIFEST)


@pytest.fixture(scope="module")
def adapter(ledger) -> ExactTimeLabelAdapterV2:
    return ExactTimeLabelAdapterV2(ledger)


def _event(
    *,
    start_unscaled: int,
    duration_unscaled: int = 0,
    source_ip: str = "192.168.10.5",
    destination_ip: str = "198.51.100.2",
    destination_port: int = 443,
    transport: str = "tcp",
    event_id: str = "00000000-0000-5000-8000-000000000001",
) -> FlowEndV2:
    return FlowEndV2(
        schema_version="2.0.0",
        event_version="2.0.0",
        feature_version="1.0.0",
        sensor_version="8.0.9",
        event_type="flow_end",
        sensor_type="zeek",
        provenance=EventProvenance(
            event_id=UUID(event_id),
            sensor_id="zeek",
            sensor_run_id="a" * 64,
            capture_id="b" * 64,
            dataset_snapshot_id="c" * 64,
            model_release_id=None,
            normalizer_version="2.0.0",
            pipeline_version="2.0.0",
        ),
        event_start_time=canonical_seconds_from_unscaled(start_unscaled),
        event_duration=canonical_seconds_from_unscaled(duration_unscaled),
        event_end_time=canonical_seconds_from_unscaled(
            start_unscaled + duration_unscaled
        ),
        record_available_time=RAT,
        ingested_at=RAT,
        conversation_id="CExact1",
        source=NetworkEndpoint(ip=ip_address(source_ip), port=51662),
        destination=NetworkEndpoint(ip=ip_address(destination_ip), port=destination_port),
        transport=transport,
        service="ssl",
        counters=FlowCounters(
            source_packets=2, destination_packets=1,
            source_bytes=74, destination_bytes=10,
        ),
        connection_state="SF",
        termination_reason=None,
    )


# ---------------------------------------------------------------- exactness


def test_interval_bounds_convert_exactly(adapter) -> None:
    """Every frozen M5 interval bound is a whole second, converted losslessly."""
    assert adapter.intervals, "adapter must compile the frozen M5 intervals"
    for interval in adapter.intervals:
        assert interval.start_unscaled % UNSCALED_FACTOR == 0
        assert interval.end_unscaled % UNSCALED_FACTOR == 0
        assert interval.end_unscaled > interval.start_unscaled


def test_adapter_compiles_the_same_interval_count_as_m5(adapter, ledger) -> None:
    assert len(adapter.intervals) == len(ledger.compiled_intervals)


def test_sub_second_bound_is_refused_not_truncated() -> None:
    """A sub-second bound must fail loudly rather than be truncated."""
    value = datetime(2017, 7, 4, 9, 30, 0, 500000, tzinfo=timezone.utc)
    with pytest.raises(ExactTimeLabelError, match="refusing to truncate"):
        exact_unscaled_from_datetime(value)


def test_naive_datetime_is_refused() -> None:
    with pytest.raises(ExactTimeLabelError, match="timezone-aware UTC"):
        exact_unscaled_from_datetime(datetime(2017, 7, 4, 9, 30, 0))


def test_conversion_matches_integer_seconds_without_float() -> None:
    value = datetime(2017, 7, 4, 13, 30, 0, tzinfo=timezone.utc)
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    expected_seconds = (value - epoch) // timedelta(seconds=1)
    assert exact_unscaled_from_datetime(value) == expected_seconds * UNSCALED_FACTOR
    # No float anywhere: the result is an exact int multiple of the scale factor.
    assert isinstance(exact_unscaled_from_datetime(value), int)


def test_22_digit_precision_is_preserved_in_matching(adapter) -> None:
    """Two events differing in the 22nd digit are both handled exactly."""
    interval = adapter.intervals[0]
    base = interval.start_unscaled
    low = adapter.assign(_event(start_unscaled=base))
    high = adapter.assign(_event(start_unscaled=base + 1))
    assert low.disposition in set(WINDOW_DISPOSITION_PRECEDENCE)
    assert high.disposition in set(WINDOW_DISPOSITION_PRECEDENCE)


# ------------------------------------------------- M5 policy equivalence


def test_every_label_passes_m5_own_validation(adapter, ledger) -> None:
    """Adapter output must be accepted by the frozen M5 validator."""
    interval = adapter.intervals[0]
    probes = [
        _event(start_unscaled=interval.start_unscaled),
        _event(start_unscaled=interval.start_unscaled + 30 * UNSCALED_FACTOR),
        _event(start_unscaled=interval.end_unscaled - 1),
        _event(start_unscaled=interval.end_unscaled + 10 * UNSCALED_FACTOR),
        _event(start_unscaled=1 * UNSCALED_FACTOR),
    ]
    for event in probes:
        label = adapter.assign(event)
        ledger.validate_label(label)  # raises if provenance/outcome diverge


def test_label_provenance_comes_from_the_frozen_ledger(adapter, ledger) -> None:
    label = adapter.assign(_event(start_unscaled=1 * UNSCALED_FACTOR))
    assert label.provenance.manifest_hash == ledger.manifest_hash
    assert label.provenance.rule_version == ledger.manifest.rule_version
    assert label.provenance.timezone == ledger.manifest.timezone
    assert label.provenance.authoritative_source == (
        ledger.manifest.authoritative_source
    )


def test_unmatched_event_is_unknown_never_benign(adapter) -> None:
    """An event outside every schedule window must be unknown, not benign."""
    label = adapter.assign(_event(start_unscaled=1 * UNSCALED_FACTOR))
    assert label.disposition == "unknown"
    assert label.matched_rule_ids == ()
    assert label.matched_direction == "indeterminate"
    assert label.attack_family is None
    assert label.attack_subtype is None


def test_label_event_id_is_the_source_event_id(adapter) -> None:
    event = _event(start_unscaled=1 * UNSCALED_FACTOR)
    label = adapter.assign(event)
    assert label.event_id == event.provenance.event_id


def test_boundary_crossing_event_is_ambiguous(adapter) -> None:
    """A flow straddling a schedule boundary must be ambiguous, per M5."""
    candidate = None
    for interval in adapter.intervals:
        selector = interval.rule.selector
        if selector.mode != "role_constrained":
            continue
        if not selector.attacker_ips or not selector.victim_ips:
            continue
        protocols = selector.protocols or ("tcp",)
        usable = [p for p in protocols if p in ("tcp", "udp")]
        if usable:
            candidate = (interval, usable[0])
            break
    assert candidate is not None, "frozen M5 policy has no role-constrained tcp/udp rule"

    interval, transport = candidate
    selector = interval.rule.selector
    event = _event(
        start_unscaled=interval.end_unscaled - 5 * UNSCALED_FACTOR,
        duration_unscaled=10 * UNSCALED_FACTOR,
        source_ip=str(selector.attacker_ips[0]),
        destination_ip=str(selector.victim_ips[0]),
        destination_port=(
            selector.victim_ports[0] if selector.victim_ports else 443
        ),
        transport=transport,
    )
    label = adapter.assign(event)
    assert label.disposition == "ambiguous"
    assert label.matched_direction == "indeterminate"
    assert label.matched_rule_ids


def test_contained_attack_event_is_labelled_attack(adapter, ledger) -> None:
    """An event fully inside a role-constrained attack window is an attack."""
    candidate = None
    for interval in adapter.intervals:
        selector = interval.rule.selector
        if interval.rule.disposition not in ATTACK_DISPOSITIONS:
            continue
        if selector.mode != "role_constrained":
            continue
        protocols = selector.protocols or ("tcp",)
        usable = [p for p in protocols if p in ("tcp", "udp")]
        if usable and selector.attacker_ips and selector.victim_ips:
            candidate = (interval, usable[0])
            break
    assert candidate is not None, "frozen M5 policy has no attack rule usable here"

    interval, transport = candidate
    selector = interval.rule.selector
    midpoint = (interval.start_unscaled + interval.end_unscaled) // 2
    event = _event(
        start_unscaled=midpoint,
        duration_unscaled=1 * UNSCALED_FACTOR,
        source_ip=str(selector.attacker_ips[0]),
        destination_ip=str(selector.victim_ips[0]),
        destination_port=(
            selector.victim_ports[0] if selector.victim_ports else 443
        ),
        transport=transport,
    )
    label = adapter.assign(event)
    assert is_attack(label.disposition)
    assert label.disposition == interval.rule.disposition
    assert label.matched_rule_ids == (interval.rule.rule_id,)
    assert label.matched_direction == "attacker_to_victim"
    ledger.validate_label(label)


def test_adapter_does_not_modify_the_ledger(adapter, ledger) -> None:
    before = ledger.manifest_hash
    adapter.assign(_event(start_unscaled=1 * UNSCALED_FACTOR))
    assert ledger.manifest_hash == before
    assert adapter.ledger is ledger


# --------------------------------------------------- ANY_ATTACK aggregation


def test_precedence_table_is_frozen() -> None:
    assert WINDOW_DISPOSITION_PRECEDENCE == (
        "target_attack",
        "known_other_attack",
        "ambiguous",
        "unknown",
        "benign_reference",
    )
    assert ATTACK_DISPOSITIONS == {"target_attack", "known_other_attack"}
    assert is_attack("target_attack") and is_attack("known_other_attack")
    assert not is_attack("benign_reference")
    assert not is_attack("unknown")
    assert not is_attack("ambiguous")


@pytest.mark.parametrize(
    ("present", "expected"),
    [
        (["benign_reference"], "benign_reference"),
        (["unknown"], "unknown"),
        (["ambiguous"], "ambiguous"),
        (["target_attack"], "target_attack"),
        (["known_other_attack"], "known_other_attack"),
        # attack dominates everything
        (["benign_reference", "target_attack"], "target_attack"),
        (["unknown", "target_attack"], "target_attack"),
        (["ambiguous", "target_attack"], "target_attack"),
        (["benign_reference", "known_other_attack"], "known_other_attack"),
        (["unknown", "ambiguous", "known_other_attack"], "known_other_attack"),
        (["target_attack", "known_other_attack"], "target_attack"),
        # uncertainty is never downgraded to benign
        (["benign_reference", "unknown"], "unknown"),
        (["benign_reference", "ambiguous"], "ambiguous"),
        (["unknown", "ambiguous"], "ambiguous"),
        (["benign_reference", "unknown", "ambiguous"], "ambiguous"),
    ],
)
def test_any_attack_decision_table(present, expected) -> None:
    assert aggregate_window_disposition(present) == expected


def test_aggregation_is_order_independent() -> None:
    values = ["benign_reference", "unknown", "target_attack", "ambiguous"]
    assert aggregate_window_disposition(values) == "target_attack"
    assert aggregate_window_disposition(list(reversed(values))) == "target_attack"


def test_aggregation_refuses_empty_window() -> None:
    with pytest.raises(ExactTimeLabelError, match="empty window"):
        aggregate_window_disposition([])


def test_aggregation_refuses_unknown_disposition() -> None:
    with pytest.raises(ExactTimeLabelError, match="unknown dispositions"):
        aggregate_window_disposition(["benign_reference", "malicious"])


def test_a_single_attack_event_flips_a_large_benign_window() -> None:
    """The core ANY_ATTACK property: one attack among many benigns wins."""
    dispositions = ["benign_reference"] * 999 + ["target_attack"]
    assert aggregate_window_disposition(dispositions) == "target_attack"


# ------------------------------------------------------ no label in M6


def test_feature_window_v2_still_carries_no_label_field() -> None:
    from modules.detection.src.schemas import FeatureWindowV2

    for name in ("label", "labels", "disposition", "attack_family",
                 "attack_subtype", "target_profiles"):
        assert name not in FeatureWindowV2.model_fields
