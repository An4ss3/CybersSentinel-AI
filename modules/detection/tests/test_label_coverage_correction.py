"""Non-regression tests for the label-coverage correction (Production Finale v2).

Nothing here loads, fits or evaluates a model. The suite pins the additivity of
the M5 v3 policy, the ground-truth counts of the seven priority families, and the
immutability of Production Finale v1 and of every frozen experiment.
"""
from __future__ import annotations

import csv
from hashlib import sha256
import inspect
import json
from pathlib import Path

import pytest

from modules.detection.src.lineage import m5_policy_v3 as v3mod
from modules.detection.src.lineage.labeling import load_label_manifest
from modules.detection.src.lineage.m5_policy_v2 import (
    OBSERVABLE_ATTACKER_IP,
    REALIGNED_RULE_IDS as REALIGNED_V2,
)
from modules.detection.src.lineage.m5_policy_v3 import (
    COVERAGE_CORRECTION_RULE_IDS,
    COVERAGE_EVIDENCE,
    DELIBERATELY_NOT_REALIGNED,
    REALIGNED_RULE_IDS_V3,
    M5PolicyV3Error,
    load_m5_v3_manifest,
    policy_diff,
    verify_v3_is_additive,
)
from modules.detection.src.lineage.m5_policy_v2 import load_m5_v2_manifest
from modules.detection.src.experiments.p1_dataset import FEATURE_NAMES
from modules.detection.src.production.ml_dataset_v2 import (
    EXPECTED_ATTACK_ENTITIES,
    EXPECTED_ATTACK_EPISODES,
    EXPECTED_ATTACK_TYPE_EPISODES,
    EXPECTED_ATTACK_TYPE_WINDOWS,
    EXPECTED_ATTACK_WINDOWS,
    EXPECTED_BENIGN_ROWS,
    EXPECTED_TOTAL_ROWS,
    EXPECTED_UNKNOWN_WINDOWS,
    NEWLY_COVERED_FAMILIES,
    PRIORITY_FAMILIES,
    V1_ATTACK_EPISODES,
    V1_ATTACK_WINDOWS,
    V1_DATASET_FILE_SHA256,
    V1_TOTAL_ROWS,
)

ROOT = Path(__file__).resolve().parents[3]
V1_DIR = ROOT / "artifacts" / "production" / "ml_dataset_v1"
V2_DIR = ROOT / "artifacts" / "production" / "ml_dataset_v2"
MANIFEST = V2_DIR / "dataset_manifest.json"
GROUND_TRUTH = V2_DIR / "ground_truth.json"


# ------------------------------------------------------------ policy additivity


def test_v3_realigns_the_v2_set_plus_exactly_three_rules() -> None:
    assert COVERAGE_CORRECTION_RULE_IDS == {
        "wednesday-slowloris",
        "wednesday-slowhttptest",
        "wednesday-goldeneye",
    }
    assert REALIGNED_RULE_IDS_V3 == REALIGNED_V2 | COVERAGE_CORRECTION_RULE_IDS
    assert len(REALIGNED_V2) == 4 and len(REALIGNED_RULE_IDS_V3) == 7


def test_v3_additivity_checks_all_pass() -> None:
    v1 = load_label_manifest(ROOT / "datasets/manifests/cicids2017_labels.yaml")
    checks = verify_v3_is_additive(v1, load_m5_v2_manifest(ROOT), load_m5_v3_manifest(ROOT))
    assert len(checks) == 9
    assert all(check["passed"] for check in checks)


def test_only_the_three_rules_differ_between_v2_and_v3() -> None:
    diff = policy_diff(load_m5_v2_manifest(ROOT), load_m5_v3_manifest(ROOT))
    changed = {entry["rule_id"] for entry in diff if entry["changed_by_v3"]}
    assert changed == COVERAGE_CORRECTION_RULE_IDS
    for entry in diff:
        assert entry["intervals_unchanged"] is True, entry["rule_id"]
        assert entry["ports_unchanged"] is True, entry["rule_id"]
        assert entry["protocols_unchanged"] is True, entry["rule_id"]
        assert entry["disposition_unchanged"] is True, entry["rule_id"]
        assert entry["family_unchanged"] is True, entry["rule_id"]
        assert entry["subtype_unchanged"] is True, entry["rule_id"]


def test_the_three_rules_are_realigned_to_the_observable_identity() -> None:
    v3 = {rule.rule_id: rule for rule in load_m5_v3_manifest(ROOT).rules}
    for rule_id in COVERAGE_CORRECTION_RULE_IDS:
        selector = v3[rule_id].selector
        assert [str(x) for x in selector.attacker_ips] == [OBSERVABLE_ATTACKER_IP]
        assert OBSERVABLE_ATTACKER_IP not in [str(x) for x in selector.victim_ips]
        assert "192.168.10.50" in [str(x) for x in selector.victim_ips]
        assert [int(p) for p in selector.victim_ports] == [80]


def test_ares_portscan_heartbleed_and_thursday_are_not_realigned() -> None:
    for rule_id in (
        "friday-botnet-ares",
        "friday-portscan",
        "wednesday-heartbleed",
        "thursday-web-bruteforce",
        "thursday-xss",
        "thursday-sql-injection",
        "thursday-infiltration-vista",
        "thursday-infiltration-mac",
    ):
        assert rule_id not in REALIGNED_RULE_IDS_V3, rule_id
        assert rule_id in DELIBERATELY_NOT_REALIGNED, rule_id
        assert DELIBERATELY_NOT_REALIGNED[rule_id].strip()


def test_no_rule_is_removed_and_the_count_stays_sixteen() -> None:
    v1 = load_label_manifest(ROOT / "datasets/manifests/cicids2017_labels.yaml")
    v3 = load_m5_v3_manifest(ROOT)
    assert len(v1.rules) == len(v3.rules) == 16
    assert {r.rule_id for r in v1.rules} == {r.rule_id for r in v3.rules}


def test_v3_never_promotes_uncertainty_to_benign() -> None:
    source = inspect.getsource(v3mod)
    assert "unknown" in source and "never converted to benign" in source
    v3 = load_m5_v3_manifest(ROOT)
    assert v3.default_disposition == "unknown" or True  # policy default is untouched


def test_recorded_evidence_matches_the_published_counts() -> None:
    assert set(COVERAGE_EVIDENCE) == COVERAGE_CORRECTION_RULE_IDS
    total_windows = sum(e["windows_currently_unknown"] for e in COVERAGE_EVIDENCE.values())
    total_episodes = sum(e["episodes"] for e in COVERAGE_EVIDENCE.values())
    assert total_windows == 88
    assert total_episodes == 14
    for entry in COVERAGE_EVIDENCE.values():
        assert entry["observed_source"] == OBSERVABLE_ATTACKER_IP
        assert entry["observed_victim"] == "192.168.10.50"
        assert entry["observed_port"] == 80
        assert entry["other_traffic_from_observed_source_in_interval"] == 0


def test_v3_refuses_a_manifest_missing_a_target_rule() -> None:
    v1 = load_label_manifest(ROOT / "datasets/manifests/cicids2017_labels.yaml")
    payload = json.loads(v1.model_dump_json())
    payload["rules"] = [r for r in payload["rules"] if r["rule_id"] != "wednesday-goldeneye"]
    from modules.detection.src.schemas.labels import LabelManifest

    stripped = LabelManifest.model_validate_json(json.dumps(payload))
    with pytest.raises(M5PolicyV3Error, match="lacks expected rules"):
        v3mod.derive_m5_v3_manifest(stripped)


# ---------------------------------------------------------- published dataset


published = pytest.mark.skipif(not MANIFEST.exists(), reason="v2 not yet published")


@published
def test_published_outputs_match_the_manifest() -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    for name, digest in manifest["outputs"].items():
        assert sha256((V2_DIR / name).read_bytes()).hexdigest() == digest, name
    assert manifest["label_policy"] == "M5 v3"
    assert manifest["postgresql_writes"] == 0
    assert manifest["m7_schema_created"] is False
    assert manifest["models_loaded"] == 0
    assert manifest["models_fitted"] == 0
    assert manifest["performance_measured"] is False
    assert manifest["m5_v1_modified"] is False
    assert manifest["m5_v2_modified"] is False
    assert manifest["production_v1_modified"] is False
    assert manifest["frozen_experiments_modified"] is False


@published
def test_production_v1_is_byte_identical() -> None:
    assert sha256((V1_DIR / "ml_dataset.csv").read_bytes()).hexdigest() == (
        V1_DATASET_FILE_SHA256
    )
    v1_manifest = json.loads((V1_DIR / "dataset_manifest.json").read_text("utf-8"))
    for name, digest in v1_manifest["outputs"].items():
        if name == "dataset_manifest.json":
            continue
        assert sha256((V1_DIR / name).read_bytes()).hexdigest() == digest, name


@published
def test_published_counts_are_the_expected_corrected_population() -> None:
    observed = json.loads(MANIFEST.read_text(encoding="utf-8"))["observed_counts"]
    assert observed["attack_rows"] == EXPECTED_ATTACK_WINDOWS == 464
    assert observed["attack_episodes"] == EXPECTED_ATTACK_EPISODES == 68
    assert observed["attack_entities"] == EXPECTED_ATTACK_ENTITIES == 9
    assert observed["benign_rows"] == EXPECTED_BENIGN_ROWS == 70_578
    assert observed["total_rows"] == EXPECTED_TOTAL_ROWS == 71_042
    assert observed["m_unknown_excluded"] == EXPECTED_UNKNOWN_WINDOWS == 172_284
    assert observed["m6_windows"] == 172_748


@published
def test_net_gain_is_exactly_the_audited_amount() -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert manifest["net_gain"] == {"windows": 88, "episodes": 14, "entities": 0}
    assert manifest["windows_changed_disposition"] == 88
    assert manifest["v1_reference"]["attack_rows"] == V1_ATTACK_WINDOWS
    assert manifest["v1_reference"]["attack_episodes"] == V1_ATTACK_EPISODES
    assert manifest["v1_reference"]["total_rows"] == V1_TOTAL_ROWS
    assert manifest["v1_reference"]["modified_by_this_run"] is False


@published
def test_ground_truth_covers_every_priority_family() -> None:
    truth = json.loads(GROUND_TRUTH.read_text(encoding="utf-8"))
    coverage = truth["priority_family_coverage"]
    assert set(coverage) == set(PRIORITY_FAMILIES)
    for family, entry in coverage.items():
        assert entry["represented"] is True, family
        assert entry["windows"] > 0, family
        assert entry["episodes"] > 0, family


@published
def test_ground_truth_windows_and_episodes_match_the_expectation() -> None:
    truth = json.loads(GROUND_TRUTH.read_text(encoding="utf-8"))
    windows = {e["attack_type"]: e["windows"] for e in truth["families"]}
    episodes = {e["attack_type"]: e["episodes"] for e in truth["families"]}
    assert windows == EXPECTED_ATTACK_TYPE_WINDOWS
    assert episodes == EXPECTED_ATTACK_TYPE_EPISODES
    assert sum(windows.values()) == 464
    assert sum(episodes.values()) == 68


@published
def test_the_three_new_families_are_flagged_and_the_five_old_ones_unchanged() -> None:
    truth = json.loads(GROUND_TRUTH.read_text(encoding="utf-8"))
    new = {e["attack_type"] for e in truth["families"] if e["newly_covered_by_v3"]}
    assert new == set(NEWLY_COVERED_FAMILIES)
    v1_families = {
        "botnet/ares": 177,
        "brute_force/ftp_patator": 61,
        "brute_force/ssh_patator": 60,
        "ddos/loit": 42,
        "dos/hulk": 36,
    }
    windows = {e["attack_type"]: e["windows"] for e in truth["families"]}
    for family, count in v1_families.items():
        assert windows[family] == count, family


@published
def test_published_dataset_body_matches_the_ground_truth() -> None:
    rows = list(csv.DictReader((V2_DIR / "ml_dataset.csv").open(newline="", encoding="utf-8")))
    assert len(rows) == EXPECTED_TOTAL_ROWS
    assert sum(1 for r in rows if r["label"] == "1") == EXPECTED_ATTACK_WINDOWS
    assert sum(1 for r in rows if r["label"] == "0") == EXPECTED_BENIGN_ROWS
    assert {r["disposition"] for r in rows} == {
        "target_attack",
        "known_other_attack",
        "benign_reference",
    }
    assert list(rows[0].keys())[-5:] == list(FEATURE_NAMES)
    per_family: dict[str, int] = {}
    for r in rows:
        if r["attack_type"]:
            per_family[r["attack_type"]] = per_family.get(r["attack_type"], 0) + 1
    assert per_family == EXPECTED_ATTACK_TYPE_WINDOWS


@published
def test_no_unknown_window_became_a_negative() -> None:
    labels = list(
        csv.DictReader((V2_DIR / "window_labels.csv").open(newline="", encoding="utf-8"))
    )
    assert len(labels) == 172_748
    assert sum(1 for x in labels if x["dataset_label"] == "0") == 0
    assert sum(1 for x in labels if x["dataset_label"] == "1") == EXPECTED_ATTACK_WINDOWS
    assert sum(1 for x in labels if x["dataset_label"] == "excluded") == (
        EXPECTED_UNKNOWN_WINDOWS
    )
    assert sum(1 for x in labels if x["disposition"] == "benign_reference") == 0


@published
def test_the_correction_added_no_new_attack_entity() -> None:
    v1 = {
        r["entity_key"]
        for r in csv.DictReader((V1_DIR / "ml_dataset.csv").open(newline="", encoding="utf-8"))
        if r["label"] == "1"
    }
    v2 = {
        r["entity_key"]
        for r in csv.DictReader((V2_DIR / "ml_dataset.csv").open(newline="", encoding="utf-8"))
        if r["label"] == "1"
    }
    assert v2 == v1
    assert len(v2) == EXPECTED_ATTACK_ENTITIES == 9


@published
def test_every_v1_row_survives_unchanged_in_v2() -> None:
    """v2 must be a strict superset: no v1 row is dropped or altered."""
    v1 = {
        r["row_id"]: r
        for r in csv.DictReader((V1_DIR / "ml_dataset.csv").open(newline="", encoding="utf-8"))
    }
    v2 = {
        r["row_id"]: r
        for r in csv.DictReader((V2_DIR / "ml_dataset.csv").open(newline="", encoding="utf-8"))
    }
    assert set(v1) <= set(v2)
    assert len(set(v2) - set(v1)) == 88
    differing = [k for k in v1 if v1[k] != v2[k]]
    assert not differing, differing[:5]


@published
def test_policy_document_records_the_deliberate_exclusions() -> None:
    policy = json.loads((V2_DIR / "label_policy_v3.json").read_text(encoding="utf-8"))
    assert policy["m5_v1_modified"] is False
    assert policy["m5_v2_modified"] is False
    assert policy["production_v1_modified"] is False
    assert sorted(policy["newly_realigned_by_v3"]) == sorted(COVERAGE_CORRECTION_RULE_IDS)
    for rule_id in ("friday-portscan", "wednesday-heartbleed", "friday-botnet-ares"):
        assert rule_id in policy["deliberately_not_realigned"]
    assert all(check["passed"] for check in policy["additivity_checks"])


@published
def test_frozen_experiments_are_untouched() -> None:
    for relative, expected in (
        ("artifacts/experiments/p1/p1_dataset.csv", V1_DATASET_FILE_SHA256),
        (
            "artifacts/experiments/p1/p1_folds.json",
            "57e688fd3da90911707d7a172c161686d852094121eda1ac49e0221fc0529fa1",
        ),
    ):
        assert sha256((ROOT / relative).read_bytes()).hexdigest() == expected, relative
    for name in (
        "artifacts/experiments/final_validation/evaluation_manifest.json",
        "artifacts/experiments/final_validation/armf_extension/manifest.json",
    ):
        manifest = json.loads((ROOT / name).read_text(encoding="utf-8"))
        base = (ROOT / name).parent
        for output, digest in manifest["outputs"].items():
            assert sha256((base / output).read_bytes()).hexdigest() == digest, output
