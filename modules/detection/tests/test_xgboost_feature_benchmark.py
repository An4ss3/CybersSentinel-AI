"""Artifact-level guards for the controlled four-arm XGBoost benchmark.

These tests never query PostgreSQL and never fit a model. They independently check
that the published artifacts preserve the frozen P1 protocol, use the registered
arms, keep episode recall primary, and do not retain a feature on ROC alone.
"""
from __future__ import annotations

import csv
from hashlib import sha256
import json
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[3]
EXP = REPO_ROOT / "artifacts" / "experiments"
OUT = EXP / "xgboost_feature_benchmark"
ARMS = {
    "A": ["distinct_payload_ratio"],
    "B": ["distinct_payload_ratio", "interarrival_mean"],
    "C": ["distinct_payload_ratio", "bytes_per_packet_destination"],
    "D": [
        "distinct_payload_ratio",
        "interarrival_mean",
        "bytes_per_packet_destination",
    ],
}


@pytest.fixture(scope="module")
def metrics() -> dict:
    return json.loads((OUT / "benchmark_metrics.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def comparison() -> dict:
    return json.loads((OUT / "feature_comparison.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def manifest() -> dict:
    return json.loads((OUT / "benchmark_manifest.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def report() -> str:
    return " ".join(
        (OUT / "BENCHMARK_REPORT.md").read_text(encoding="utf-8").replace("**", "").split()
    )


def _botnet(metrics: dict, arm: str) -> dict:
    return next(
        fold
        for fold in metrics["arms"][arm]["folds"]
        if fold["held_out_attack_type"] == "botnet/ares"
    )


def _point(fold: dict, target: float = 0.01) -> dict:
    return next(p for p in fold["operating_points"] if p["target_train_fpr"] == target)


# Frozen protocol and budget -------------------------------------------------


def test_all_frozen_file_digests_passed(metrics: dict) -> None:
    assert len(metrics["frozen_file_checks"]) == 6
    assert all(check["passed"] for check in metrics["frozen_file_checks"])


def test_all_p1_protocol_checks_passed(metrics: dict) -> None:
    assert len(metrics["protocol_verification"]) == 45
    assert all(check["passed"] for check in metrics["protocol_verification"])


def test_population_and_folds_are_exactly_p1(metrics: dict) -> None:
    assert metrics["p1_dataset_content_sha256"] == (
        "3d7436178da6960ee5effeb4bee85a0b6da5eead9d2babef3c72cb6b7ca9f20d"
    )
    assert metrics["p1_folds_content_sha256"] == (
        "e463ea7b0eb4985f51369dc3ae19c09821040675aa4b9f9689f8e02545fed95a"
    )


def test_registered_arms_are_exact(metrics: dict, manifest: dict) -> None:
    assert metrics["arms_registered"] == ARMS
    assert manifest["arms"] == ARMS
    assert {arm: value["features"] for arm, value in metrics["arms"].items()} == ARMS


def test_no_tuning_rebalancing_or_new_split(metrics: dict) -> None:
    for key in (
        "hyperparameter_search",
        "early_stopping",
        "class_rebalancing",
        "resampling_or_smote",
        "ensembling",
        "new_split_created",
        "labels_modified",
        "unknown_or_ambiguous_as_negative",
    ):
        assert metrics[key] is False, key
    assert metrics["model_parameters"]["scale_pos_weight"] == 1
    assert metrics["model_parameters"]["subsample"] == 1.0
    assert metrics["model_parameters"]["colsample_bytree"] == 1.0


def test_thresholds_and_bootstrap_follow_the_ratified_rules(metrics: dict) -> None:
    assert "training negatives only" in metrics["threshold_rule"]
    assert metrics["bootstrap"] == {
        "unit": "episode",
        "resamples": 2000,
        "seed": 0,
        "window_level_intervals": "forbidden",
    }
    for arm in ARMS:
        for fold in metrics["arms"][arm]["folds"]:
            assert [p["target_train_fpr"] for p in fold["operating_points"]] == [0.01, 0.001]
            for point in fold["operating_points"]:
                assert point["achieved_train_fpr"] <= point["target_train_fpr"] + 1e-12


def test_every_test_stream_is_identical_across_arms(metrics: dict) -> None:
    checks = metrics["cross_arm_test_identity"]
    assert len(checks) == 15
    assert all(check["passed"] for check in checks)
    names = {check["check"] for check in checks}
    for fold in range(5):
        assert f"fold{fold}_ordered_test_row_and_label_signature_identical_across_all_arms" in names
        assert f"fold{fold}_arm_a_reproduces_published_xgboost_baseline_scores" in names
        assert f"fold{fold}_prediction_row_and_label_stream_identical_across_all_arms" in names


def test_prediction_files_really_share_ordered_row_and_label_streams() -> None:
    for fold in range(5):
        streams = {}
        for arm in ARMS:
            with (OUT / f"predictions_arm_{arm}_fold{fold}.csv").open(
                newline="", encoding="utf-8"
            ) as handle:
                streams[arm] = [
                    (row["row_id"], row["label"]) for row in csv.DictReader(handle)
                ]
        assert all(streams[arm] == streams["A"] for arm in ARMS)
        with (EXP / "p1" / f"p1_predictions_fold{fold}.csv").open(
            newline="", encoding="utf-8"
        ) as handle:
            p1 = [(row["row_id"], row["label"]) for row in csv.DictReader(handle)]
        assert set(streams["A"]) == set(p1)


def test_arm_a_reproduces_every_published_baseline_score() -> None:
    for fold in range(5):
        with (OUT / f"predictions_arm_A_fold{fold}.csv").open(
            newline="", encoding="utf-8"
        ) as handle:
            observed = [(r["row_id"], r["label"], r["score"]) for r in csv.DictReader(handle)]
        with (EXP / "xgboost_baseline" / f"xgb_predictions_fold{fold}.csv").open(
            newline="", encoding="utf-8"
        ) as handle:
            expected = [(r["row_id"], r["label"], r["score"]) for r in csv.DictReader(handle)]
        assert observed == expected


# Feature provenance and online validity -----------------------------------


def test_all_feature_derivation_checks_passed(metrics: dict) -> None:
    checks = metrics["feature_derivation"]["checks"]
    assert len(checks) == 16
    assert all(check["passed"] for check in checks)


def test_no_absolute_time_or_label_source_enters_features(metrics: dict) -> None:
    names = {check["check"] for check in metrics["feature_derivation"]["checks"]}
    assert "no_absolute_timestamp_is_reachable_from_a_feature" in names
    assert "no_feature_source_is_a_label_or_provenance_column" in names
    sources = metrics["feature_derivation"]["source_columns"]
    assert sources["interarrival_mean"] == ["event_start_time_relative_to_window"]
    assert all("label" not in source for values in sources.values() for source in values)


def test_missing_values_are_native_nan_without_new_feature(metrics: dict) -> None:
    missing = metrics["feature_derivation"]["missingness"]
    assert all(value["policy"] == "native NaN; no imputation and no indicator" for value in missing.values())
    assert missing["distinct_payload_ratio"]["benign_missing"] == 0
    assert missing["interarrival_mean"]["botnet_missing"] > 0
    assert missing["bytes_per_packet_destination"]["benign_missing"] > 0


def test_online_validity_is_bounded_honestly(metrics: dict, report: str) -> None:
    online = metrics["feature_derivation"]["online_validity"]
    assert all(not value["future_information"] for value in online["features"].values())
    assert "historical persisted FlowEnd evidence" in report
    assert "does not measure streaming ingestion latency" in report
    assert "relative event starts" in report


# Primary endpoint and robustness ------------------------------------------


@pytest.mark.parametrize(
    ("arm", "recall", "detected", "roc", "pr", "fpr"),
    [
        ("A", 0.325, 13, 0.7615, 0.0670, 0.009874),
        ("B", 0.000, 0, 0.5321, 0.0177, 0.012632),
        ("C", 0.025, 1, 0.8154, 0.0394, 0.010745),
        ("D", 0.025, 1, 0.7453, 0.0294, 0.014012),
    ],
)
def test_primary_results(
    metrics: dict, arm: str, recall: float, detected: int, roc: float, pr: float, fpr: float
) -> None:
    fold = _botnet(metrics, arm)
    point = _point(fold)
    assert fold["test_episodes"] == 40
    assert point["episode_recall"] == pytest.approx(recall)
    assert len(point["episodes_detected"]) == detected
    assert fold["roc_auc"] == pytest.approx(roc, abs=5e-5)
    assert fold["pr_auc"] == pytest.approx(pr, abs=5e-5)
    assert point["observed_test_fpr"] == pytest.approx(fpr, abs=5e-7)


def test_all_candidate_episode_deltas_are_strictly_negative(comparison: dict) -> None:
    expected = {"B": -0.325, "C": -0.300, "D": -0.300}
    for arm, delta in expected.items():
        gain = comparison["arms"][arm]["gain_vs_arm_a"]
        paired = gain["paired_episode_bootstrap"]
        assert gain["episode_recall_delta"] == pytest.approx(delta)
        assert paired["ci_high"] < 0
        assert paired["episodes"] == 40
        assert paired["candidate_only_detections"] == 0


def test_no_candidate_gain_is_hidden_on_one_entity(comparison: dict) -> None:
    for arm in ("B", "C", "D"):
        gain = comparison["arms"][arm]["gain_vs_arm_a"]
        assert gain["candidate_only_episodes"] == []
        assert gain["entities_with_candidate_only_detections"] == []
        assert gain["gain_is_distributed_over_multiple_entities"] is False


def test_per_entity_results_preserve_r11_picture(metrics: dict) -> None:
    expected_detected_entities = {"A": 5, "B": 0, "C": 1, "D": 1}
    for arm, expected in expected_detected_entities.items():
        entities = metrics["per_entity_recall"][arm]["botnet/ares"]["target_0.01"]
        assert len(entities) == 5
        assert sum(value["episodes"] for value in entities.values()) == 40
        assert sum(value["episodes_detected"] > 0 for value in entities.values()) == expected


def test_candidate_arms_have_an_important_volumetric_cost(comparison: dict) -> None:
    for arm in ("B", "C", "D"):
        cost = comparison["arms"][arm]["volumetric_cost"]
        assert cost["important"] is True
        assert cost["episodes_detected_arm"] < cost["episodes_detected_a"]


def test_roc_alone_does_not_rescue_arm_c(comparison: dict, report: str) -> None:
    c = comparison["arms"]["C"]
    assert c["gain_vs_arm_a"]["roc_auc_delta"] > 0
    assert c["gain_vs_arm_a"]["pr_auc_delta"] < 0
    assert c["gain_vs_arm_a"]["paired_episode_bootstrap"]["ci_high"] < 0
    assert comparison["classifications"]["C"]["status"] == "REJECT"
    assert "ROC alone cannot select the arm" in report


def test_final_classifications_and_minimal_set(comparison: dict) -> None:
    assert {
        arm: value["status"] for arm, value in comparison["classifications"].items()
    } == {"A": "RETAIN", "B": "REJECT", "C": "REJECT", "D": "REJECT"}
    assert comparison["minimal_best_compromise"]["arm"] == "A"
    assert comparison["minimal_best_compromise"]["features"] == ["distinct_payload_ratio"]


def test_report_keeps_episode_recall_primary(report: str) -> None:
    assert "Primary endpoint — botnet/Ares episode recall" in report
    assert "All three candidate intervals are strictly negative" in report
    assert "global ROC gain cannot override" in report
    assert "ARM A — distinct_payload_ratio" in report


def test_r11_scope_is_explicit(metrics: dict, report: str) -> None:
    assert metrics["r11"]["botnet_entities"] == 5
    assert metrics["r11"]["destinations"] == 1
    assert metrics["r11"]["botnet_episodes"] == 40
    assert "5 entities, 1 destination" in report
    assert "another victim" in report
    assert "No universal or causal claim" in report


def test_zero_postgresql_writes(metrics: dict, manifest: dict) -> None:
    assert metrics["postgresql_writes"] == 0
    assert manifest["postgresql_writes"] == 0
    assert metrics["read_only_transactions"] is True
    assert manifest["read_only_transactions"] is True


# Artifact integrity --------------------------------------------------------


def test_all_required_outputs_exist(manifest: dict) -> None:
    outputs = manifest["outputs"]
    for arm in ARMS:
        for fold in range(5):
            assert f"model_arm_{arm}_fold{fold}.joblib" in outputs
            assert f"predictions_arm_{arm}_fold{fold}.csv" in outputs
    for name in (
        "benchmark_metrics.json",
        "benchmark_predictions.csv",
        "feature_comparison.json",
        "BENCHMARK_REPORT.md",
    ):
        assert name in outputs
    assert len(outputs) == 44


def test_manifest_hashes_match_every_output(manifest: dict) -> None:
    for name, expected in manifest["outputs"].items():
        assert sha256((OUT / name).read_bytes()).hexdigest() == expected, name


def test_arm_a_models_are_the_published_baseline_models(manifest: dict) -> None:
    baseline = json.loads(
        (EXP / "xgboost_baseline" / "xgb_reproducibility_manifest.json").read_text(
            encoding="utf-8"
        )
    )
    for fold in range(5):
        assert manifest["outputs"][f"model_arm_A_fold{fold}.joblib"] == baseline["outputs"][f"xgb_model_fold{fold}.joblib"]


def test_p1_through_p6_and_baseline_are_untouched() -> None:
    expected = {
        "p1/p1_dataset.csv": "e95aed008d994510",
        "p1/p1_folds.json": "57e688fd3da90911",
        "p1/p1_metrics.json": "2a51e618397c42b7",
        "p2/p2_metrics.json": "67d2f60bc57d03bb",
        "p3/p3_metrics.json": "a3e9f1c7175594c9",
        "p4/p4_metrics.json": "3df92eda32d943b6",
        "p5/p5_metrics.json": "87055c8b14623581",
        "p6/p6_feature_audit.json": "d028e8476df66c28",
        "xgboost_baseline/xgb_metrics.json": "4b841773bbe34d62",
    }
    for name, prefix in expected.items():
        assert sha256((EXP / name).read_bytes()).hexdigest().startswith(prefix), name
