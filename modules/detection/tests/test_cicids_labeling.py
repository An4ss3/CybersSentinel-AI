"""Behavioral tests for official CICIDS2017 schedule matching."""
from __future__ import annotations

import pytest

from modules.detection.src.lineage import LabelLedger
from modules.detection.tests.label_fixtures import (
    MANIFEST_PATH,
    flow_event,
    sensor_health_event,
)


@pytest.fixture(scope="module")
def ledger() -> LabelLedger:
    return LabelLedger.from_yaml(MANIFEST_PATH)


def test_exact_start_boundary_is_included(ledger: LabelLedger):
    label = ledger.assign(flow_event(start_local="2017-07-04T09:20:00"))
    assert label.disposition == "target_attack"
    assert label.attack_subtype == "ftp_patator"


def test_official_end_minute_is_included(ledger: LabelLedger):
    label = ledger.assign(flow_event(start_local="2017-07-04T10:20:59"))
    assert label.disposition == "target_attack"


def test_half_open_end_after_inclusive_minute_is_excluded(ledger: LabelLedger):
    label = ledger.assign(flow_event(start_local="2017-07-04T10:21:00"))
    assert label.disposition == "unknown"


def test_flow_crossing_attack_start_is_ambiguous(ledger: LabelLedger):
    label = ledger.assign(
        flow_event(
            start_local="2017-07-04T09:19:59",
            end_local="2017-07-04T09:20:01",
        )
    )
    assert label.disposition == "ambiguous"
    assert label.matched_rule_ids == ("tuesday-ftp-patator",)
    assert "crosses" in label.reason


def test_flow_crossing_attack_end_is_ambiguous(ledger: LabelLedger):
    label = ledger.assign(
        flow_event(
            start_local="2017-07-04T10:20:59",
            end_local="2017-07-04T10:21:01",
        )
    )
    assert label.disposition == "ambiguous"


@pytest.mark.parametrize(
    "victim_ip",
    ["205.174.165.80", "172.16.0.1", "205.174.165.68", "192.168.10.50"],
)
def test_documented_nat_victim_aliases_match(ledger: LabelLedger, victim_ip: str):
    label = ledger.assign(
        flow_event(
            start_local="2017-07-04T09:30:00",
            destination_ip=victim_ip,
            identity=f"nat-{victim_ip}",
        )
    )
    assert label.disposition == "target_attack"
    assert label.matched_direction == "attacker_to_victim"


def test_reverse_victim_to_attacker_direction_matches(ledger: LabelLedger):
    label = ledger.assign(
        flow_event(
            start_local="2017-07-04T09:30:00",
            source_ip="192.168.10.50",
            destination_ip="205.174.165.73",
            source_port=21,
            destination_port=40000,
            identity="reverse",
        )
    )
    assert label.disposition == "target_attack"
    assert label.matched_direction == "victim_to_attacker"


def test_wrong_attacker_role_remains_unknown(ledger: LabelLedger):
    label = ledger.assign(
        flow_event(
            start_local="2017-07-04T09:30:00",
            source_ip="203.0.113.50",
            identity="wrong-attacker",
        )
    )
    assert label.disposition == "unknown"


def test_two_victim_aliases_do_not_impersonate_attacker(ledger: LabelLedger):
    label = ledger.assign(
        flow_event(
            start_local="2017-07-04T09:30:00",
            source_ip="192.168.10.50",
            destination_ip="205.174.165.80",
            source_port=21,
            identity="role-conflict",
        )
    )
    assert label.disposition == "unknown"


def test_wrong_victim_port_remains_unknown(ledger: LabelLedger):
    label = ledger.assign(
        flow_event(
            start_local="2017-07-04T09:30:00",
            destination_port=22,
            service="ssh",
            identity="wrong-port",
        )
    )
    assert label.disposition == "unknown"


def test_wrong_protocol_remains_unknown(ledger: LabelLedger):
    label = ledger.assign(
        flow_event(
            start_local="2017-07-04T09:30:00",
            transport="udp",
            identity="wrong-protocol",
        )
    )
    assert label.disposition == "unknown"


def test_slow_dos_is_known_other_not_target(ledger: LabelLedger):
    label = ledger.assign(
        flow_event(
            start_local="2017-07-05T09:50:00",
            destination_port=80,
            service="http",
            identity="slowloris",
        )
    )
    assert label.disposition == "known_other_attack"
    assert label.attack_subtype == "slowloris"
    assert label.target_profiles == ()


def test_hulk_is_fast_dos_target(ledger: LabelLedger):
    label = ledger.assign(
        flow_event(
            start_local="2017-07-05T10:50:00",
            destination_port=80,
            service="http",
            identity="hulk",
        )
    )
    assert label.disposition == "target_attack"
    assert label.target_profiles == ("fast_dos_ddos",)


def test_heartbleed_attack_nat_alias_matches(ledger: LabelLedger):
    label = ledger.assign(
        flow_event(
            start_local="2017-07-05T15:20:00",
            destination_ip="172.16.0.11",
            destination_port=444,
            service="ssl",
            identity="heartbleed-attack-nat",
        )
    )
    assert label.disposition == "known_other_attack"
    assert label.attack_subtype == "heartbleed"
    assert label.matched_direction == "attacker_to_victim"


def test_heartbleed_reply_nat_alias_matches_reverse_direction(ledger: LabelLedger):
    label = ledger.assign(
        flow_event(
            start_local="2017-07-05T15:20:00",
            source_ip="172.16.0.1",
            destination_ip="205.174.165.73",
            source_port=444,
            destination_port=40000,
            service="ssl",
            identity="heartbleed-reply-nat",
        )
    )
    assert label.disposition == "known_other_attack"
    assert label.attack_subtype == "heartbleed"
    assert label.matched_direction == "victim_to_attacker"


def test_monday_only_rule_is_explicit_benign_reference(ledger: LabelLedger):
    label = ledger.assign(
        flow_event(
            start_local="2017-07-03T10:00:00",
            source_ip="198.51.100.1",
            destination_ip="192.0.2.1",
            destination_port=443,
            identity="monday-benign",
        )
    )
    assert label.disposition == "benign_reference"
    assert label.matched_direction == "not_applicable"


def test_unmatched_attack_day_traffic_is_unknown_not_benign(ledger: LabelLedger):
    label = ledger.assign(
        flow_event(
            start_local="2017-07-04T11:30:00",
            identity="unknown-tuesday",
        )
    )
    assert label.disposition == "unknown"
    assert label.disposition != "benign_reference"


def test_ddos_accepts_each_documented_attacker(ledger: LabelLedger):
    for attacker in ("205.174.165.69", "205.174.165.70", "205.174.165.71"):
        label = ledger.assign(
            flow_event(
                start_local="2017-07-07T16:00:00",
                source_ip=attacker,
                destination_port=80,
                service="http",
                identity=f"ddos-{attacker}",
            )
        )
        assert label.disposition == "target_attack"
        assert label.attack_family == "ddos"


def test_endpointless_sensor_health_is_unknown(ledger: LabelLedger):
    label = ledger.assign(sensor_health_event())
    assert label.disposition == "unknown"
    assert "no network endpoints" in label.reason


def test_every_outcome_has_complete_policy_provenance(ledger: LabelLedger):
    events = (
        flow_event(start_local="2017-07-04T09:30:00", identity="prov-target"),
        flow_event(start_local="2017-07-04T11:30:00", identity="prov-unknown"),
        flow_event(
            start_local="2017-07-04T09:19:59",
            end_local="2017-07-04T09:20:01",
            identity="prov-ambiguous",
        ),
    )
    for label in ledger.assign_many(events):
        assert label.provenance.rule_version == "1.0.0"
        assert len(label.provenance.rule_hash) == 64
        assert label.provenance.manifest_hash == ledger.manifest_hash
        assert label.provenance.authoritative_source.url.startswith("https://")
        assert label.provenance.timezone == "America/Moncton"


def test_assignment_does_not_mutate_event(ledger: LabelLedger):
    event = flow_event(start_local="2017-07-04T09:30:00", identity="immutable")
    before = event.model_dump_json()
    label = ledger.assign(event)
    assert event.model_dump_json() == before
    assert label.event_id == event.provenance.event_id
