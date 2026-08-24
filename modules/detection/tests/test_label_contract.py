"""Contract and manifest validation tests for the M5 sidecar label system."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError
import yaml

from modules.detection.src.lineage import (
    LabelLedger,
    LabelManifestOverlapError,
    hash_manifest,
    load_label_manifest,
)
from modules.detection.src.schemas import EventLabel, FeatureWindow, NetworkEvent
from modules.detection.tests.label_fixtures import MANIFEST_PATH


EXPECTED_ONTOLOGY = {
    "target_attack",
    "known_other_attack",
    "benign_reference",
    "unknown",
    "ambiguous",
}


def _manifest_payload() -> dict:
    return yaml.safe_load(MANIFEST_PATH.read_text(encoding="utf-8"))


def _validate_payload(payload: dict):
    from modules.detection.src.schemas import LabelManifest

    return LabelManifest.model_validate_json(json.dumps(payload))


def test_label_ontology_is_complete_and_closed():
    schema = EventLabel.model_json_schema()
    assert set(schema["properties"]["disposition"]["enum"]) == EXPECTED_ONTOLOGY


def test_official_manifest_loads_strictly_and_is_versioned():
    manifest = load_label_manifest(MANIFEST_PATH)
    assert manifest.manifest_version == "1.0.0"
    assert manifest.rule_version == "1.0.0"
    assert manifest.default_disposition == "unknown"
    assert manifest.timezone == "America/Moncton"
    assert len(manifest.rules) == 16
    assert sum(len(rule.intervals) for rule in manifest.rules) == 45


def test_unknown_manifest_field_is_rejected(tmp_path: Path):
    payload = _manifest_payload()
    payload["silently_trusted"] = True
    path = tmp_path / "invalid.yaml"
    path.write_text(yaml.safe_dump(payload), encoding="utf-8")
    with pytest.raises(ValidationError, match="extra_forbidden"):
        load_label_manifest(path)


def test_missing_authoritative_source_is_rejected():
    payload = _manifest_payload()
    del payload["authoritative_source"]
    with pytest.raises(ValidationError, match="authoritative_source"):
        _validate_payload(payload)


def test_unknown_timezone_is_rejected():
    payload = _manifest_payload()
    payload["timezone"] = "Mars/Olympus_Mons"
    with pytest.raises(ValidationError, match="unknown IANA timezone"):
        _validate_payload(payload)


def test_manifest_rule_cannot_assign_unknown_or_ambiguous():
    payload = _manifest_payload()
    payload["rules"][1]["disposition"] = "unknown"
    with pytest.raises(ValidationError, match="disposition"):
        _validate_payload(payload)


def test_benign_reference_requires_explicit_any_network_rule():
    payload = _manifest_payload()
    payload["rules"][0]["selector"] = payload["rules"][1]["selector"]
    with pytest.raises(ValidationError, match="any_network"):
        _validate_payload(payload)


def test_target_attack_requires_a_target_profile():
    payload = _manifest_payload()
    payload["rules"][1]["target_profiles"] = []
    with pytest.raises(ValidationError, match="target_attack"):
        _validate_payload(payload)


def test_attacker_and_victim_roles_must_be_disjoint():
    payload = _manifest_payload()
    payload["rules"][1]["selector"]["victim_ips"].append("205.174.165.73")
    with pytest.raises(ValidationError, match="disjoint"):
        _validate_payload(payload)


def test_role_compatible_schedule_overlap_is_rejected():
    payload = _manifest_payload()
    duplicate = json.loads(json.dumps(payload["rules"][1]))
    duplicate["rule_id"] = "overlapping-ftp-rule"
    duplicate["attack_subtype"] = "other_ftp_attack"
    payload["rules"].append(duplicate)
    manifest = _validate_payload(payload)
    with pytest.raises(LabelManifestOverlapError, match="overlapping label rules"):
        LabelLedger(manifest)




def test_role_swapped_schedule_overlap_is_rejected():
    payload = _manifest_payload()
    swapped = json.loads(json.dumps(payload["rules"][1]))
    swapped["rule_id"] = "role-swapped-ftp-rule"
    swapped["selector"]["attacker_ips"] = ["205.174.165.80"]
    swapped["selector"]["victim_ips"] = ["205.174.165.73"]
    swapped["selector"]["victim_ports"] = [40000]
    payload["rules"].append(swapped)
    with pytest.raises(LabelManifestOverlapError, match="overlapping label rules"):
        LabelLedger(_validate_payload(payload))

def test_temporal_overlap_with_disjoint_roles_is_allowed():
    payload = _manifest_payload()
    duplicate = json.loads(json.dumps(payload["rules"][1]))
    duplicate["rule_id"] = "disjoint-lab-rule"
    duplicate["selector"]["attacker_ips"] = ["203.0.113.1"]
    duplicate["selector"]["victim_ips"] = ["203.0.113.2"]
    payload["rules"].append(duplicate)
    ledger = LabelLedger(_validate_payload(payload))
    assert len(ledger.manifest.rules) == 17


def test_manifest_hash_is_stable_but_rule_change_changes_it():
    manifest = load_label_manifest(MANIFEST_PATH)
    assert hash_manifest(manifest) == hash_manifest(load_label_manifest(MANIFEST_PATH))
    payload = _manifest_payload()
    payload["rules"][1]["notes"] = "A scientifically material rule revision."
    assert hash_manifest(_validate_payload(payload)) != hash_manifest(manifest)


def test_event_label_provenance_is_mandatory():
    ledger = LabelLedger.from_yaml(MANIFEST_PATH)
    from modules.detection.tests.label_fixtures import flow_event

    label = ledger.assign(flow_event(start_local="2017-07-04T09:30:00"))
    payload = label.model_dump()
    del payload["provenance"]
    with pytest.raises(ValidationError, match="provenance"):
        EventLabel.model_validate(payload)


def test_sidecar_contract_does_not_modify_canonical_models():
    assert "label" not in NetworkEvent.model_fields
    assert "labels" not in NetworkEvent.model_fields
    assert "label" not in FeatureWindow.model_fields
    assert "labels" not in FeatureWindow.model_fields


def test_sidecar_contract_does_not_leak_into_feature_window_v2():
    """M6 addition: FeatureWindowV2 must carry no M5-derived field."""
    from modules.detection.src.schemas import FeatureWindowV2

    for name in (
        "label",
        "labels",
        "attack_family",
        "attack_subtype",
        "target_profiles",
        "disposition",
        "matched_rule_ids",
        "matched_direction",
    ):
        assert name not in FeatureWindowV2.model_fields
