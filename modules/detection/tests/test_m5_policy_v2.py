"""Contractual tests for the additive M5 v2 observable-attacker policy.

Covers the sixteen mandatory checks: v1 unchanged, v2 additive, the four
realigned families matching from 172.16.0.1, negative controls on window/port/
destination, and the absence of any write, label-in-M6, or m7 schema.
"""
from __future__ import annotations

from ipaddress import ip_address
from pathlib import Path
from uuid import UUID

import pytest

from modules.detection.src.lineage.exact_time_labeling_v2 import (
    ExactTimeLabelAdapterV2,
    is_attack,
)
from modules.detection.src.lineage.labeling import LabelLedger, load_label_manifest
from modules.detection.src.lineage.m5_policy_v2 import (
    CANONICAL_M5_V1_MANIFEST_PATH,
    OBSERVABLE_ATTACKER_IP,
    REALIGNED_RULE_IDS,
    UNOBSERVABLE_ATTACKER_IPS,
    M5PolicyV2Error,
    build_m5_v2_adapter,
    derive_m5_v2_manifest,
    load_m5_v2_manifest,
    realignment_summary,
)
from modules.detection.src.lineage.provenance import EventProvenance
from modules.detection.src.schemas.common import FlowCounters, NetworkEndpoint
from modules.detection.src.schemas.events_v2 import FlowEndV2
from modules.detection.src.schemas.exact_time_v2 import (
    UNSCALED_FACTOR,
    canonical_seconds_from_unscaled,
)


ROOT = Path(__file__).resolve().parents[3]
V1_PATH = ROOT / CANONICAL_M5_V1_MANIFEST_PATH
RAT = "1722783600.0000000000000000000000"
VICTIM = "192.168.10.50"

# Exact UTC epoch seconds of the frozen v1 intervals, taken from the compiled
# ledger at runtime rather than hard-coded (see the fixtures below).
FAMILY_PORTS = {
    "tuesday-ftp-patator": 21,
    "tuesday-ssh-patator": 22,
    "wednesday-hulk": 80,
    "friday-ddos-loit": 80,  # v1 declares no port constraint for this family
}


@pytest.fixture(scope="module")
def v1_manifest():
    return load_label_manifest(V1_PATH)


@pytest.fixture(scope="module")
def v1_ledger(v1_manifest):
    return LabelLedger(v1_manifest)


@pytest.fixture(scope="module")
def v2_manifest():
    return load_m5_v2_manifest(ROOT)


@pytest.fixture(scope="module")
def v2_adapter():
    return build_m5_v2_adapter(ROOT)


@pytest.fixture(scope="module")
def v1_adapter(v1_ledger):
    return ExactTimeLabelAdapterV2(v1_ledger)


def _interval_for(adapter: ExactTimeLabelAdapterV2, rule_id: str):
    matches = [i for i in adapter.intervals if i.rule.rule_id == rule_id]
    assert matches, f"no compiled interval for {rule_id}"
    return matches[0]


def _event(
    *,
    start_unscaled: int,
    source_ip: str = OBSERVABLE_ATTACKER_IP,
    destination_ip: str = VICTIM,
    destination_port: int = 80,
    transport: str = "tcp",
    duration_unscaled: int = 0,
    event_id: str = "00000000-0000-5000-8000-00000000abcd",
) -> FlowEndV2:
    return FlowEndV2(
        schema_version="2.0.0", event_version="2.0.0",
        feature_version="1.0.0", sensor_version="8.0.9",
        event_type="flow_end", sensor_type="zeek",
        provenance=EventProvenance(
            event_id=UUID(event_id), sensor_id="zeek",
            sensor_run_id="a" * 64, capture_id="b" * 64,
            dataset_snapshot_id="c" * 64, model_release_id=None,
            normalizer_version="2.0.0", pipeline_version="2.0.0",
        ),
        event_start_time=canonical_seconds_from_unscaled(start_unscaled),
        event_duration=canonical_seconds_from_unscaled(duration_unscaled),
        event_end_time=canonical_seconds_from_unscaled(
            start_unscaled + duration_unscaled
        ),
        record_available_time=RAT, ingested_at=RAT,
        conversation_id="CV2test",
        source=NetworkEndpoint(ip=ip_address(source_ip), port=45678),
        destination=NetworkEndpoint(
            ip=ip_address(destination_ip), port=destination_port
        ),
        transport=transport, service=None,
        counters=FlowCounters(
            source_packets=2, destination_packets=1,
            source_bytes=74, destination_bytes=10,
        ),
        connection_state="SF", termination_reason=None,
    )


# ---------------------------------------------- 1. M5 v1 remains unchanged


def test_m5_v1_manifest_file_is_untouched(v1_manifest) -> None:
    """Deriving v2 must not alter the v1 manifest object or its hash."""
    ledger = LabelLedger(v1_manifest)
    before = ledger.manifest_hash
    load_m5_v2_manifest(ROOT)
    assert LabelLedger(load_label_manifest(V1_PATH)).manifest_hash == before
    assert v1_manifest.manifest_version == "1.0.0"
    assert v1_manifest.rule_version == "1.0.0"


def test_v1_rules_keep_their_original_attackers(v1_manifest) -> None:
    for rule in v1_manifest.rules:
        if rule.rule_id in REALIGNED_RULE_IDS:
            declared = {str(x) for x in rule.selector.attacker_ips}
            assert declared <= UNOBSERVABLE_ATTACKER_IPS
            assert OBSERVABLE_ATTACKER_IP not in declared


# ------------------------------------------------------- 2. v2 is additive


def test_v2_is_a_separate_policy_with_distinct_identity(
    v1_manifest, v2_manifest
) -> None:
    assert v2_manifest is not v1_manifest
    assert v2_manifest.manifest_version == "2.0.0"
    assert v2_manifest.rule_version == "2.0.0"
    assert LabelLedger(v2_manifest).manifest_hash != LabelLedger(
        v1_manifest
    ).manifest_hash


def test_v2_changes_only_the_attacker_identity(v1_manifest, v2_manifest) -> None:
    assert len(v2_manifest.rules) == len(v1_manifest.rules)
    for row in realignment_summary(v1_manifest, v2_manifest):
        assert row["intervals_unchanged"], row["rule_id"]
        assert row["ports_unchanged"], row["rule_id"]
        assert row["protocols_unchanged"], row["rule_id"]
        assert row["disposition_unchanged"], row["rule_id"]
        assert row["family_unchanged"], row["rule_id"]
        assert row["targets_unchanged"], row["rule_id"]
        if row["realigned"]:
            assert row["attackers_v2"] == (OBSERVABLE_ATTACKER_IP,)
            # only 172.16.0.1 leaves the victim set, forced by role disjointness
            assert set(row["victims_v1"]) - set(row["victims_v2"]) == {
                OBSERVABLE_ATTACKER_IP
            }
        else:
            assert row["attackers_v2"] == row["attackers_v1"]
            assert row["victims_v2"] == row["victims_v1"]


def test_non_realigned_rules_are_byte_identical(v1_manifest, v2_manifest) -> None:
    v1_rules = {r.rule_id: r for r in v1_manifest.rules}
    for rule in v2_manifest.rules:
        if rule.rule_id not in REALIGNED_RULE_IDS:
            assert rule == v1_rules[rule.rule_id]


def test_v2_preserves_ontology_and_defaults(v1_manifest, v2_manifest) -> None:
    assert v2_manifest.default_disposition == v1_manifest.default_disposition == "unknown"
    assert v2_manifest.timezone == v1_manifest.timezone
    assert v2_manifest.authoritative_source == v1_manifest.authoritative_source
    assert v2_manifest.source_time_precision == v1_manifest.source_time_precision
    assert v2_manifest.source_end_semantics == v1_manifest.source_end_semantics
    assert v2_manifest.dataset_name == v1_manifest.dataset_name


def test_v2_compiles_the_same_intervals_as_v1(v1_adapter, v2_adapter) -> None:
    v1 = {(i.rule.rule_id, i.start_unscaled, i.end_unscaled) for i in v1_adapter.intervals}
    v2 = {(i.rule.rule_id, i.start_unscaled, i.end_unscaled) for i in v2_adapter.intervals}
    assert v1 == v2, "v2 must reuse the exact v1 intervals"


# --------------------------------- 3 & 4. observable vs unobservable attacker


def test_observable_gateway_is_recognised_as_attacker(v2_manifest) -> None:
    for rule in v2_manifest.rules:
        if rule.rule_id in REALIGNED_RULE_IDS:
            attackers = {str(x) for x in rule.selector.attacker_ips}
            assert attackers == {OBSERVABLE_ATTACKER_IP}


def test_gateway_is_never_declared_a_victim(v2_manifest) -> None:
    for rule in v2_manifest.rules:
        if rule.rule_id in REALIGNED_RULE_IDS:
            victims = {str(x) for x in rule.selector.victim_ips}
            assert OBSERVABLE_ATTACKER_IP not in victims
            assert VICTIM in victims


def test_unobservable_attacker_does_not_become_a_source(v2_adapter) -> None:
    """205.174.165.73 must not match as a source under v2."""
    interval = _interval_for(v2_adapter, "wednesday-hulk")
    midpoint = (interval.start_unscaled + interval.end_unscaled) // 2
    label = v2_adapter.assign(
        _event(start_unscaled=midpoint, source_ip="205.174.165.73")
    )
    assert label.disposition == "unknown"
    assert not is_attack(label.disposition)


# ---------------------------------- 5-8. the four families match from the gateway


@pytest.mark.parametrize(
    ("rule_id", "expected_family", "expected_subtype"),
    [
        ("wednesday-hulk", "dos", "hulk"),
        ("tuesday-ftp-patator", "brute_force", "ftp_patator"),
        ("tuesday-ssh-patator", "brute_force", "ssh_patator"),
        ("friday-ddos-loit", "ddos", "loit"),
    ],
)
def test_family_matches_from_observable_gateway(
    v2_adapter, rule_id, expected_family, expected_subtype
) -> None:
    interval = _interval_for(v2_adapter, rule_id)
    midpoint = (interval.start_unscaled + interval.end_unscaled) // 2
    event = _event(
        start_unscaled=midpoint,
        source_ip=OBSERVABLE_ATTACKER_IP,
        destination_ip=VICTIM,
        destination_port=FAMILY_PORTS[rule_id],
        transport="tcp",
    )
    label = v2_adapter.assign(event)
    assert is_attack(label.disposition), f"{rule_id} did not match"
    assert label.disposition == "target_attack"
    assert label.attack_family == expected_family
    assert label.attack_subtype == expected_subtype
    assert label.matched_rule_ids == (rule_id,)
    assert label.matched_direction == "attacker_to_victim"
    v2_adapter.ledger.validate_label(label)


def test_the_same_events_are_unknown_under_v1(v1_adapter, v2_adapter) -> None:
    """Regression proof: v1 could not label these events at all."""
    for rule_id in ("wednesday-hulk", "tuesday-ftp-patator",
                    "tuesday-ssh-patator", "friday-ddos-loit"):
        interval = _interval_for(v2_adapter, rule_id)
        midpoint = (interval.start_unscaled + interval.end_unscaled) // 2
        event = _event(
            start_unscaled=midpoint, destination_port=FAMILY_PORTS[rule_id]
        )
        assert v1_adapter.assign(event).disposition == "unknown"
        assert is_attack(v2_adapter.assign(event).disposition)


# ------------------------------------------- 9-12. negative controls


def test_gateway_traffic_outside_any_window_is_not_attack(v2_adapter) -> None:
    """Source 172.16.0.1 alone must never imply attack."""
    interval = _interval_for(v2_adapter, "wednesday-hulk")
    far_before = interval.start_unscaled - 3600 * UNSCALED_FACTOR
    label = v2_adapter.assign(_event(start_unscaled=far_before))
    assert label.disposition == "unknown"
    assert label.matched_rule_ids == ()


def test_wrong_destination_port_is_not_attack(v2_adapter) -> None:
    """Hulk constrains port 80; port 8080 must not match it."""
    interval = _interval_for(v2_adapter, "wednesday-hulk")
    midpoint = (interval.start_unscaled + interval.end_unscaled) // 2
    label = v2_adapter.assign(
        _event(start_unscaled=midpoint, destination_port=8080)
    )
    assert label.disposition == "unknown"


def test_wrong_destination_ip_is_not_attack(v2_adapter) -> None:
    interval = _interval_for(v2_adapter, "wednesday-hulk")
    midpoint = (interval.start_unscaled + interval.end_unscaled) // 2
    label = v2_adapter.assign(
        _event(start_unscaled=midpoint, destination_ip="192.168.10.9")
    )
    assert label.disposition == "unknown"


def test_event_immediately_before_window_does_not_match(v2_adapter) -> None:
    interval = _interval_for(v2_adapter, "wednesday-hulk")
    label = v2_adapter.assign(_event(start_unscaled=interval.start_unscaled - 1))
    assert label.disposition == "unknown"


def test_event_at_window_end_does_not_match_half_open(v2_adapter) -> None:
    """The interval is half-open: end is exclusive."""
    interval = _interval_for(v2_adapter, "wednesday-hulk")
    label = v2_adapter.assign(_event(start_unscaled=interval.end_unscaled))
    assert label.disposition == "unknown"
    inside = v2_adapter.assign(_event(start_unscaled=interval.end_unscaled - 1))
    assert is_attack(inside.disposition)


def test_wrong_transport_is_not_attack(v2_adapter) -> None:
    """Hulk constrains tcp; udp must not match."""
    interval = _interval_for(v2_adapter, "wednesday-hulk")
    midpoint = (interval.start_unscaled + interval.end_unscaled) // 2
    label = v2_adapter.assign(
        _event(start_unscaled=midpoint, transport="udp")
    )
    assert label.disposition == "unknown"


# --------------------------------- 13. untouched v1 rules keep behaviour


def test_untouched_rule_behaviour_is_identical_between_v1_and_v2(
    v1_adapter, v2_adapter
) -> None:
    """friday-botnet-ares was not realigned; both policies must agree."""
    interval = _interval_for(v2_adapter, "friday-botnet-ares")
    midpoint = (interval.start_unscaled + interval.end_unscaled) // 2
    rule = interval.rule
    victim = str(rule.selector.victim_ips[0])
    attacker = str(rule.selector.attacker_ips[0])
    # reverse path, exactly how M4 traffic presents for this family
    event = _event(
        start_unscaled=midpoint, source_ip=victim, destination_ip=attacker,
        destination_port=443,
    )
    a = v1_adapter.assign(event)
    b = v2_adapter.assign(event)
    assert a.disposition == b.disposition
    assert a.attack_family == b.attack_family
    assert a.matched_rule_ids == b.matched_rule_ids
    assert a.matched_direction == b.matched_direction


def test_unmatched_traffic_stays_unknown_never_benign(v2_adapter) -> None:
    label = v2_adapter.assign(_event(start_unscaled=1 * UNSCALED_FACTOR))
    assert label.disposition == "unknown"
    assert label.disposition != "benign_reference"


# ------------------------------------ 14-16. no leakage, no schema, no write


def test_no_label_field_in_m6_contract() -> None:
    from modules.detection.src.schemas import FeatureWindowV2

    for name in ("label", "labels", "disposition", "attack_family",
                 "attack_subtype", "target_profiles"):
        assert name not in FeatureWindowV2.model_fields


def test_module_contains_no_write_statement() -> None:
    """The v2 policy module must be incapable of writing anywhere."""
    from modules.detection.src.lineage import m5_policy_v2

    source = Path(m5_policy_v2.__file__).read_text(encoding="utf-8")
    for forbidden in (
        "INSERT", "UPDATE ", "DELETE", "CREATE ", "DROP", "ALTER",
        "TRUNCATE", "write_text", "write_bytes", "open(",
    ):
        assert forbidden not in source, f"policy module must not contain {forbidden!r}"


def test_derivation_refuses_unexpected_attackers(v1_manifest) -> None:
    """A tampered v1 policy must not be silently realigned."""
    import json

    payload = json.loads(v1_manifest.model_dump_json())
    for rule in payload["rules"]:
        if rule["rule_id"] == "wednesday-hulk":
            rule["selector"]["attacker_ips"] = ["10.0.0.1"]
    from modules.detection.src.schemas.labels import LabelManifest

    tampered = LabelManifest.model_validate_json(json.dumps(payload))
    with pytest.raises(M5PolicyV2Error, match="unexpected attackers"):
        derive_m5_v2_manifest(tampered)


def test_derivation_is_deterministic() -> None:
    a = load_m5_v2_manifest(ROOT)
    b = load_m5_v2_manifest(ROOT)
    assert a == b
    assert LabelLedger(a).manifest_hash == LabelLedger(b).manifest_hash
