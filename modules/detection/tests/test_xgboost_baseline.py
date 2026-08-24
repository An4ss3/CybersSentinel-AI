"""Guards for the XGBoost baseline on the single feature retained by P6.

These tests train nothing and touch no database. They protect the properties that
make the run interpretable: that the frozen protocol was reproduced and proven, that
the budget stayed at one feature, that no rebalancing or tuning crept in, and that
the verdict is not upgraded beyond what the numbers support — in particular that the
gain is attributed to the feature rather than to the learner.
"""
from __future__ import annotations

import csv
from hashlib import sha256
import json
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[3]
EXP = REPO_ROOT / "artifacts" / "experiments"
OUT = EXP / "xgboost_baseline"


@pytest.fixture(scope="module")
def xgb() -> dict:
    return json.loads((OUT / "xgb_metrics.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def manifest() -> dict:
    return json.loads(
        (OUT / "xgb_reproducibility_manifest.json").read_text(encoding="utf-8")
    )


@pytest.fixture(scope="module")
def params() -> dict:
    return json.loads((OUT / "xgb_model_params.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def report() -> str:
    """Whitespace-normalised and emphasis-stripped, so assertions test prose."""
    raw = (OUT / "XGBOOST_BASELINE_REPORT.md").read_text(encoding="utf-8")
    return " ".join(raw.replace("**", "").replace("`", "").split())


def _fold(xgb: dict, attack_type: str) -> dict:
    return next(f for f in xgb["folds"] if f["held_out_attack_type"] == attack_type)


# ---------------------------------------------------------------------------
# frozen protocol
# ---------------------------------------------------------------------------


def test_the_protocol_verification_passed_entirely(xgb: dict) -> None:
    checks = xgb["protocol_verification"]
    assert len(checks) == 45
    assert all(c["passed"] for c in checks)


def test_population_and_folds_are_the_frozen_ones(xgb: dict) -> None:
    assert xgb["p1_dataset_content_sha256"] == (
        "3d7436178da6960ee5effeb4bee85a0b6da5eead9d2babef3c72cb6b7ca9f20d"
    )
    assert xgb["p1_folds_content_sha256"] == (
        "e463ea7b0eb4985f51369dc3ae19c09821040675aa4b9f9689f8e02545fed95a"
    )


def test_every_test_set_was_proven_identical_to_p1_predictions(xgb: dict) -> None:
    names = {c["check"] for c in xgb["protocol_verification"]}
    for index in range(5):
        assert f"fold{index}_test_set_identical_to_p1_predictions" in names


def test_test_sets_really_match_p1_row_for_row() -> None:
    """Independent recheck, straight off disk, not trusting the recorded flag."""
    for index in range(5):
        with (EXP / f"p1/p1_predictions_fold{index}.csv").open(
            newline="", encoding="utf-8"
        ) as handle:
            reference = {r["row_id"]: r["label"] for r in csv.DictReader(handle)}
        with (OUT / f"xgb_predictions_fold{index}.csv").open(
            newline="", encoding="utf-8"
        ) as handle:
            mine = {r["row_id"]: r["label"] for r in csv.DictReader(handle)}
        assert mine == reference, f"fold {index}"


def test_no_unknown_or_ambiguous_was_used(xgb: dict) -> None:
    assert xgb["unknown_or_ambiguous_as_negative"] is False
    names = {c["check"] for c in xgb["protocol_verification"]}
    assert "no_unknown_or_ambiguous_anywhere" in names
    assert "negatives_are_only_benign_reference" in names


def test_predictions_contain_only_permitted_dispositions() -> None:
    permitted = {"benign_reference", "target_attack", "known_other_attack"}
    for index in range(5):
        with (OUT / f"xgb_predictions_fold{index}.csv").open(
            newline="", encoding="utf-8"
        ) as handle:
            found = {r["disposition"] for r in csv.DictReader(handle)}
        assert found <= permitted, f"fold {index}: {found - permitted}"


def test_no_leakage_checks_are_present_for_every_fold(xgb: dict) -> None:
    names = {c["check"] for c in xgb["protocol_verification"]}
    for index in range(5):
        for kind in ("window", "attack_type", "episode", "benign_entity"):
            assert f"fold{index}_no_shared_{kind}" in names


def test_zero_postgresql_writes(xgb: dict, manifest: dict) -> None:
    assert xgb["postgresql_writes"] == 0
    assert manifest["postgresql_writes"] == 0
    assert manifest["read_only_transactions"] is True


def test_the_row_ordering_lesson_from_p5_was_applied(xgb: dict) -> None:
    d23 = next(d for d in xgb["conservative_decisions"] if d["id"] == "D23")
    assert "sorted(train_row_ids)" in d23["reason"]
    assert "row-ordering effect" in d23["reason"]


# ---------------------------------------------------------------------------
# the budget and the model stayed conservative
# ---------------------------------------------------------------------------


def test_exactly_one_feature_was_used(xgb: dict, params: dict) -> None:
    assert xgb["feature"] == "distinct_payload_ratio"
    assert xgb["feature_count"] == 1
    assert xgb["features_added_beyond_p6"] == []
    assert params["feature_count"] == 1


def test_nothing_was_tuned_or_rebalanced(xgb: dict, params: dict) -> None:
    for doc in (xgb, params):
        assert doc["hyperparameter_search"] is False
        assert doc["early_stopping"] is False
        assert doc["class_rebalancing"] is False
    assert xgb["ensembling"] is False
    assert xgb["resampling_or_smote"] is False
    assert xgb["new_split_created"] is False
    assert xgb["labels_modified"] is False


def test_every_required_parameter_is_documented(xgb: dict) -> None:
    required = {
        "objective",
        "eval_metric",
        "n_estimators",
        "max_depth",
        "learning_rate",
        "subsample",
        "colsample_bytree",
        "random_state",
        "scale_pos_weight",
    }
    assert required <= set(xgb["model_parameters"])
    assert xgb["model_parameters"]["scale_pos_weight"] == 1
    assert xgb["model_parameters"]["subsample"] == 1.0
    assert xgb["model_parameters"]["colsample_bytree"] == 1.0
    assert xgb["model_parameters"]["random_state"] == 0


def test_the_threshold_came_from_training_negatives_only(xgb: dict) -> None:
    assert "training negatives only" in xgb["threshold_rule"]
    assert xgb["fpr_targets"] == [0.01, 0.001]
    for fold in xgb["folds"]:
        for point in fold["operating_points"]:
            assert point["achieved_train_fpr"] <= point["target_train_fpr"] + 1e-12


def test_uncertainty_is_episode_level_only(xgb: dict) -> None:
    assert xgb["bootstrap"]["unit"] == "episode"
    assert xgb["bootstrap"]["resamples"] == 2000
    assert xgb["bootstrap"]["seed"] == 0
    assert xgb["bootstrap"]["window_level_intervals"] == "forbidden"


# ---------------------------------------------------------------------------
# the primary endpoint, and the discipline around reading it
# ---------------------------------------------------------------------------


def test_the_primary_endpoint_is_the_botnet_episode_recall(xgb: dict) -> None:
    primary = xgb["primary_endpoint"]
    assert primary["attack_type"] == "botnet/ares"
    assert primary["unit"] == "episode-level recall"
    assert primary["episodes_total"] == 40


def test_the_measured_primary_result(xgb: dict) -> None:
    primary = xgb["primary_endpoint"]
    assert primary["episode_recall"] == pytest.approx(0.325, abs=1e-9)
    assert primary["episodes_detected"] == 13
    assert primary["roc_auc"] == pytest.approx(0.7615, abs=5e-4)
    assert primary["pr_auc"] == pytest.approx(0.0670, abs=5e-4)


def test_the_gain_is_not_a_moved_operating_point(xgb: dict, report: str) -> None:
    """Discrimination up AND recall up AND the FPR flat is the deciding pattern."""
    primary = xgb["primary_endpoint"]
    # P1's observed test FPR at the same target was 0.009583
    assert primary["observed_test_fpr"] == pytest.approx(0.009874, abs=5e-6)
    assert abs(primary["observed_test_fpr"] - 0.009583) < 0.002
    assert primary["roc_auc"] > 0.70
    assert "not a moved operating point" in report


def test_the_confidence_interval_is_reported_and_compared(xgb: dict) -> None:
    primary = xgb["primary_endpoint"]
    assert primary["ci_low"] == pytest.approx(0.1994, abs=5e-3)
    assert primary["ci_high"] == pytest.approx(0.4750, abs=5e-3)
    # separated from P1, not separated from P5 - both must be stated
    assert primary["ci_low"] > primary["references"]["P1"]["episode_recall"]
    assert primary["ci_low"] < 0.275  # P5 upper bound, so it overlaps P5


def test_the_p5_comparison_is_not_claimed_as_resolved(report: str) -> None:
    assert "does not overlap P1" in report
    assert "overlap P5" in report
    assert "not resolved" in report


def test_all_five_botnet_entities_are_reported(xgb: dict) -> None:
    per_entity = xgb["per_entity_recall"]["botnet/ares"]["target_0.01"]
    assert len(per_entity) == 5
    assert all(v["episodes_detected"] >= 1 for v in per_entity.values())
    assert sum(v["episodes"] for v in per_entity.values()) == 40


def test_the_zero_point_one_percent_collapse_is_recorded(xgb: dict, report: str) -> None:
    botnet = _fold(xgb, "botnet/ares")
    tight = next(
        p for p in botnet["operating_points"] if p["target_train_fpr"] == 0.001
    )
    assert tight["window_recall"] == 0.0
    assert tight["episode_recall"] == 0.0
    assert tight["episodes_detected"] == []
    assert "collapses completely" in report


def test_the_volumetric_window_level_cost_is_recorded(xgb: dict, report: str) -> None:
    """Episode recall held on all four volumetric types; window metrics did not."""
    for attack_type, expected in (
        ("brute_force/ftp_patator", 1.0),
        ("brute_force/ssh_patator", 0.1111),
        ("ddos/loit", 1.0),
        ("dos/hulk", 1.0),
    ):
        point = _fold(xgb, attack_type)["operating_points"][0]
        assert point["episode_recall"] == pytest.approx(expected, abs=1e-3)
    ftp = _fold(xgb, "brute_force/ftp_patator")
    assert ftp["pr_auc"] < 0.05  # was 0.3007 in P1
    assert "the volumetric types pay for it" in report.lower()


# ---------------------------------------------------------------------------
# the verdict must attribute the gain honestly
# ---------------------------------------------------------------------------


def test_the_gain_is_attributed_to_the_feature_not_the_learner(report: str) -> None:
    assert "the gain belongs to the feature, not to the learner" in report.lower()
    assert "0.7632" in report
    assert "0.0016" in report
    assert "no remaining headroom" in report


def test_the_verdict_is_c_with_its_headline_corrected(report: str) -> None:
    assert "C - the remaining problem is the feature set" in report.replace(
        "\u2014", "-"
    )
    assert "understates" in report
    assert "no headroom to recover" in report


def test_r11_limits_are_restated(xgb: dict, report: str) -> None:
    limits = " ".join(xgb["limitations"])
    assert "R11 unchanged" in limits
    assert "5 botnet entities" in limits
    assert "not proof of universal generalisation" in limits
    assert "not yet" in limits
    assert "205.174.165.73" in report
    assert "40 episodes" in report


def test_a_recall_rise_alone_is_declared_insufficient(xgb: dict) -> None:
    limits = " ".join(xgb["limitations"])
    assert "a recall rise alone is not evidence of better discrimination" in limits


# ---------------------------------------------------------------------------
# artifacts
# ---------------------------------------------------------------------------


def test_all_required_artifacts_exist(manifest: dict) -> None:
    outputs = manifest["outputs"]
    for index in range(5):
        assert f"xgb_model_fold{index}.joblib" in outputs
        assert f"xgb_predictions_fold{index}.csv" in outputs
    for name in (
        "xgb_metrics.json",
        "xgb_model_params.json",
        "XGBOOST_BASELINE_REPORT.md",
    ):
        assert name in outputs, name


def test_manifest_digests_match_the_files_on_disk(manifest: dict) -> None:
    for name, digest in manifest["outputs"].items():
        actual = sha256((OUT / name).read_bytes()).hexdigest()
        assert actual == digest, name


def test_manifest_records_library_versions(manifest: dict) -> None:
    versions = manifest["library_versions"]
    for library in ("xgboost", "scikit-learn", "numpy", "joblib", "python"):
        assert library in versions and versions[library]


def test_p1_through_p6_are_untouched() -> None:
    expected = {
        "p1/p1_dataset.csv": "e95aed008d994510",
        "p1/p1_folds.json": "57e688fd3da90911",
        "p1/p1_metrics.json": "2a51e618397c42b7",
        "p2/p2_metrics.json": "67d2f60bc57d03bb",
        "p3/p3_metrics.json": "a3e9f1c7175594c9",
        "p4/p4_metrics.json": "3df92eda32d943b6",
        "p5/p5_metrics.json": "87055c8b14623581",
        "p6/p6_feature_audit.json": "d028e8476df66c28",
    }
    for name, prefix in expected.items():
        digest = sha256((EXP / name).read_bytes()).hexdigest()
        assert digest.startswith(prefix), name
