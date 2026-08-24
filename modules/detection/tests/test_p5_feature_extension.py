"""Guards for P5/E — feature budget extension.

These tests train nothing and touch no database. They protect the three things that
make P5 interpretable: that arm A really is P1, that the missingness policy is not
quietly turned into a behavioural feature, and that the verdict on the
pre-registered endpoint is not upgraded beyond what the numbers support.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[3]
EXP = REPO_ROOT / "artifacts" / "experiments"
P5_CONTENT_SHA256 = (
    "6d3f51af4bce3e15c7278870f98feee0d44b0b4bdd7ae7e415b20748c595ea2b"
)


@pytest.fixture(scope="module")
def p5() -> dict:
    return json.loads((EXP / "p5/p5_metrics.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def p1() -> dict:
    return json.loads((EXP / "p1/p1_metrics.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def report() -> str:
    return " ".join(
        (EXP / "p5/P5_REPORT.md").read_text(encoding="utf-8").split()
    )


# ---------------------------------------------------------------------------
# provenance and isolation
# ---------------------------------------------------------------------------


def test_published_identity_is_the_frozen_one(p5: dict) -> None:
    assert p5["content_sha256"] == P5_CONTENT_SHA256


def test_p5_wrote_nothing_to_postgresql(p5: dict) -> None:
    assert p5["postgresql_writes"] == 0


def test_p5_starts_from_the_frozen_population_and_folds(p5: dict) -> None:
    assert p5["p1_dataset_content_sha256"] == (
        "3d7436178da6960ee5effeb4bee85a0b6da5eead9d2babef3c72cb6b7ca9f20d"
    )
    assert p5["p1_folds_content_sha256"] == (
        "e463ea7b0eb4985f51369dc3ae19c09821040675aa4b9f9689f8e02545fed95a"
    )
    assert p5["frozen_folds_reused_verbatim"] is True


def test_the_two_arms_differ_only_by_three_features(p5: dict) -> None:
    a, b = p5["arm_a_features"], p5["arm_b_features"]
    assert b[: len(a)] == a
    assert b[len(a):] == p5["temporal_features_added"]
    assert p5["temporal_features_added"] == [
        "duration_mean",
        "interarrival_mean",
        "interarrival_cv",
    ]


def test_no_tuning_and_no_selection_on_the_test_set(p5: dict) -> None:
    assert p5["model"]["hyperparameters_tuned"] is False
    assert p5["model"]["features_selected_on_test"] is False
    assert p5["model"]["class_weight"] is None
    assert p5["model"]["random_state"] == 0


def test_uncertainty_is_bootstrapped_over_episodes_not_windows(p5: dict) -> None:
    assert p5["bootstrap"]["unit"] == "episode"
    assert p5["bootstrap"]["resamples"] == 2000
    assert p5["bootstrap"]["seed"] == 0


# ---------------------------------------------------------------------------
# the control must really be P1
# ---------------------------------------------------------------------------


def test_arm_a_reproduces_published_p1_on_every_fold(p5: dict, p1: dict) -> None:
    """Without this, an arm A to arm B delta is not attributable to features."""
    p1_by = {f["held_out_attack_type"]: f for f in p1["folds"]}
    a_by = {f["held_out_attack_type"]: f for f in p5["arm_a"]}
    assert set(p1_by) == set(a_by)
    for attack_type, reference in p1_by.items():
        arm = a_by[attack_type]
        assert arm["roc_auc"] == pytest.approx(reference["roc_auc"], abs=1e-12)
        assert arm["pr_auc"] == pytest.approx(reference["pr_auc"], abs=1e-12)
        ref_op = reference["operating_points"][0]
        arm_op = arm["operating_points"][0]
        for key in (
            "window_recall",
            "episode_recall",
            "observed_test_fpr",
            "threshold",
        ):
            assert arm_op[key] == pytest.approx(ref_op[key], abs=1e-12), (
                f"{attack_type}:{key}"
            )


def test_every_fold_uses_an_identical_test_set_across_arms(p5: dict) -> None:
    assert all(c["identical_test_set"] for c in p5["comparison_a_vs_b"])


def test_the_row_ordering_defect_is_documented(p5: dict, report: str) -> None:
    d16 = next(d for d in p5["conservative_decisions"] if d["id"] == "D16")
    assert "sorted(train_row_ids)" in d16["reason"]
    assert "order sensitive" in d16["reason"]
    assert "reproduces the split but not the model" in report
    assert "defect in P1's published artifacts, not in P1's results" in report


# ---------------------------------------------------------------------------
# missingness must not become a behavioural feature
# ---------------------------------------------------------------------------


def test_missingness_uses_a_sentinel_and_adds_no_indicator(p5: dict) -> None:
    missing = p5["leakage_audit"]["missingness"]
    assert missing["sentinel"] == -1.0
    assert missing["indicator_feature_added"] is False
    assert "event_count" in missing["why_no_indicator"]


def test_the_measured_missing_rate_is_recorded(p5: dict) -> None:
    missing = p5["leakage_audit"]["missingness"]
    assert missing["interarrival_mean_missing_negatives"] == 41411
    assert missing["interarrival_mean_missing_negative_rate"] == pytest.approx(
        0.5867, abs=5e-5
    )


def test_the_sentinel_is_not_called_an_independent_signal(
    p5: dict, report: str
) -> None:
    d13 = next(d for d in p5["conservative_decisions"] if d["id"] == "D13")
    assert "must not be called an independent behavioural signal" in d13["reason"]
    assert "re-encoding of window length" in report


# ---------------------------------------------------------------------------
# duration must not be claimed online
# ---------------------------------------------------------------------------


def test_duration_is_not_claimed_to_be_an_online_feature(
    p5: dict, report: str
) -> None:
    d14 = next(d for d in p5["conservative_decisions"] if d["id"] == "D14")
    assert "not claimed to be available online" in d14["decision"]
    assert "FlowEnd" in p5["leakage_audit"]["duration_caveat"]
    assert "not claimed to be an online feature" in report
    assert "Availability in a real-time detector" in report


# ---------------------------------------------------------------------------
# leakage audit
# ---------------------------------------------------------------------------


def test_the_leakage_audit_passed_every_check(p5: dict) -> None:
    audit = p5["leakage_audit"]
    assert audit["failures"] == []
    assert len(audit["checks"]) == 11
    assert all(c["passed"] for c in audit["checks"])


def test_no_absolute_timestamp_can_reach_a_feature(p5: dict) -> None:
    check = next(
        c for c in p5["leakage_audit"]["checks"]
        if c["check"] == "no_absolute_timestamp_is_reachable_from_a_feature"
    )
    assert check["passed"] is True
    assert "differences only" in check["detail"]


def test_no_new_feature_separates_the_classes_perfectly(p5: dict) -> None:
    for name in p5["temporal_features_added"]:
        check = next(
            c for c in p5["leakage_audit"]["checks"]
            if c["check"] == f"{name}_does_not_separate_the_classes_perfectly"
        )
        assert check["passed"] is True


# ---------------------------------------------------------------------------
# the verdict must not be upgraded
# ---------------------------------------------------------------------------


def test_the_primary_endpoint_is_the_botnet_episode_recall(p5: dict) -> None:
    primary = p5["primary_endpoint"]
    assert primary["attack_type"] == "botnet/ares"
    assert primary["unit"] == "episode-level recall"
    assert primary["pre_registered"] is True
    assert primary["p1_reference_recall"] == 0.075
    assert primary["p1_reference_ci"] == [0.0, 0.175]
    assert primary["p1_reference_episodes"] == 40


def test_the_primary_endpoint_did_not_resolve(p5: dict) -> None:
    """The measured facts that force the NOT CONFIRMED verdict."""
    primary = p5["primary_endpoint"]
    assert primary["arm_a_recall"] == pytest.approx(0.075)
    assert primary["arm_b_recall"] == pytest.approx(0.150)
    # the intervals overlap, so the difference is not resolved
    assert primary["confidence_intervals_overlap"] is True
    # ranking did not improve: still chance
    assert primary["roc_auc_a"] < 0.55
    assert primary["roc_auc_b"] < 0.55


def test_the_report_states_the_endpoint_was_not_confirmed(report: str) -> None:
    assert "NOT CONFIRMED" in report
    assert "suggestive, not established" in report
    assert "Do not proceed to XGBoost" in report


def test_the_false_positive_rise_is_reported_beside_the_recall_gain(
    p5: dict, report: str
) -> None:
    botnet = next(
        c for c in p5["comparison_a_vs_b"]
        if c["held_out_attack_type"] == "botnet/ares"
    )
    assert botnet["observed_test_fpr_b"] > botnet["observed_test_fpr_a"]
    assert "0.009583 to 0.016045" in report


def test_the_hulk_regression_is_reported(p5: dict, report: str) -> None:
    hulk = next(
        c for c in p5["comparison_a_vs_b"]
        if c["held_out_attack_type"] == "dos/hulk"
    )
    assert hulk["roc_auc_b"] < hulk["roc_auc_a"]
    assert hulk["pr_auc_b"] < hulk["pr_auc_a"]
    assert hulk["window_recall_b"] < hulk["window_recall_a"]
    assert "regressed on every ranking axis" in report


def test_the_ssh_gain_is_reported_as_secondary_not_as_the_result(
    report: str,
) -> None:
    assert "not the pre-registered endpoint" in report
    assert "must not be presented as P5's result" in report


def test_r11_is_restated_as_binding(p5: dict, report: str) -> None:
    assert any("R11 is unchanged" in limit for limit in p5["limitations"])
    assert "R11 remains in force" in report
    assert "no feature can create attack diversity" in report.lower()


def test_xgboost_was_not_trained(p5: dict) -> None:
    assert p5["model"]["estimator"] == "RandomForestClassifier"
