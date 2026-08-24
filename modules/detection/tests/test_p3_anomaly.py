"""Contractual tests for the P3/D unsupervised anomaly benchmark.

Read-only against the published artifacts. Nothing is trained here.
"""
from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[3]
P3_DIR = REPO_ROOT / "artifacts" / "experiments" / "p3"
P3_METRICS = P3_DIR / "p3_metrics.json"
P3_REPORT = P3_DIR / "P3_REPORT.md"

BENIGN_TOTAL = 70_578
ATTACKS = 376
EPISODES = 54
M6_UNKNOWN = 172_372

pytestmark = pytest.mark.skipif(
    not P3_METRICS.is_file(), reason="P3 artifacts must be published"
)


@pytest.fixture(scope="module")
def p3() -> dict:
    return json.loads(P3_METRICS.read_text(encoding="utf-8"))


# --------------------------------------------------------------------------
# Training composition: benign only
# --------------------------------------------------------------------------


def test_no_positive_entered_training(p3) -> None:
    comp = p3["training_composition"]
    assert comp["positives_in_training"] == 0
    assert comp["unknown_in_training"] == 0
    assert comp["ambiguous_in_training"] == 0
    assert comp["benign_reference_windows_fitted"] > 0


def test_fit_uses_only_part_of_the_benign_day(p3) -> None:
    split = p3["temporal_split"]
    total = (
        split["fit_windows"] + split["calibration_windows"]
        + split["measurement_windows"]
    )
    assert total == BENIGN_TOTAL
    assert split["fit_windows"] == 35_289
    assert split["calibration_windows"] == 17_644
    assert split["measurement_windows"] == 17_645


def test_temporal_blocks_are_contiguous_and_disjoint(p3) -> None:
    split = p3["temporal_split"]
    assert split["blocks_disjoint"] is True
    fit_lo, fit_hi = split["fit_epoch_range"]
    cal_lo, cal_hi = split["calibration_epoch_range"]
    mea_lo, mea_hi = split["measurement_epoch_range"]
    assert fit_lo < fit_hi <= cal_lo < cal_hi <= mea_lo < mea_hi
    assert "no randomness" in split["rule"]


def test_model_never_uses_predict(p3) -> None:
    model = p3["model"]
    assert model["estimator"] == "IsolationForest"
    assert model["predict_never_used"] is True
    assert model["random_state"] == 0
    assert model["n_jobs"] == 1


# --------------------------------------------------------------------------
# The threshold comes from calibration only
# --------------------------------------------------------------------------


def test_threshold_is_calibrated_and_achieves_its_target(p3) -> None:
    for op in p3["operating_points"]:
        assert op["achieved_calibration_fpr"] <= op["target_calibration_fpr"]
        assert op["threshold"] > 0.0


def test_measurement_block_is_distinct_from_calibration(p3) -> None:
    """The FPR must be measured on windows that did not set the threshold."""
    for op in p3["operating_points"]:
        fpr = op["measured_false_positive_rate"]
        assert fpr["windows"] == 17_645
        assert fpr["population"].startswith("held-out")
    assert p3["temporal_split"]["calibration_windows"] != 17_645


# --------------------------------------------------------------------------
# Terminology discipline: FPR versus alert rate
# --------------------------------------------------------------------------


def test_unknown_population_is_never_called_a_false_positive_rate(p3) -> None:
    for op in p3["operating_points"]:
        alert = op["alert_rate_on_unlabelled"]
        assert alert["windows"] == M6_UNKNOWN
        assert "alerts" in alert and "rate" in alert
        assert "false_positive" not in alert
        assert "fpr" not in {k.lower() for k in alert}
        interpretation = alert["interpretation"].lower()
        assert "not a false-positive rate" in interpretation
        assert "not an error rate" in interpretation
        assert "unknown into benign" in interpretation


def test_terminology_block_separates_the_two_rates(p3) -> None:
    terms = p3["terminology"]
    assert "genuine false positive" in terms["measured_false_positive_rate"]
    assert "never a false-positive rate" in terms["alert_rate_on_unlabelled"]


def test_report_refuses_to_conclude_unknown_is_benign() -> None:
    report = P3_REPORT.read_text(encoding="utf-8")
    assert "does not mean `unknown` is benign" in report
    assert "not evidence that it is" in report
    # The report must state that the similarity has multiple explanations.
    assert "three explanations" in report


# --------------------------------------------------------------------------
# Results
# --------------------------------------------------------------------------


def test_botnet_recall_is_exactly_zero_at_every_threshold(p3) -> None:
    """The strongest statement of blindness produced by any design so far."""
    for op in p3["operating_points"]:
        botnet = next(
            t for t in op["per_attack_type"] if t["attack_type"] == "botnet/ares"
        )
        assert botnet["windows"] == 177
        assert botnet["episodes"] == 40
        assert botnet["window_recall"] == 0.0
        assert botnet["episode_recall"] == 0.0
        assert botnet["episode_bootstrap"]["ci_high"] == 0.0


def test_every_attack_type_is_reported_separately(p3) -> None:
    expected = {
        "botnet/ares",
        "brute_force/ftp_patator",
        "brute_force/ssh_patator",
        "ddos/loit",
        "dos/hulk",
    }
    for op in p3["operating_points"]:
        assert {t["attack_type"] for t in op["per_attack_type"]} == expected
    assert set(p3["populations"]["attack_types"]) == expected


def test_populations_match_the_frozen_evidence(p3) -> None:
    pop = p3["populations"]
    assert pop["benign_reference_total"] == BENIGN_TOTAL
    assert pop["attack_windows"] == ATTACKS
    assert pop["attack_episodes"] == EPISODES
    assert pop["m6_unknown_windows"] == M6_UNKNOWN


def test_calibration_overshoot_is_documented_as_non_stationarity() -> None:
    report = P3_REPORT.read_text(encoding="utf-8")
    assert "non-stationarity" in report
    assert "not overfitting" in report or "not memorisation" in report


# --------------------------------------------------------------------------
# Bootstrap discipline
# --------------------------------------------------------------------------


def test_bootstrap_is_episode_level_only(p3) -> None:
    boot = p3["bootstrap"]
    assert boot["unit"] == "attack episode"
    assert boot["window_level_bootstrap"] == "forbidden"
    for op in p3["operating_points"]:
        assert op["attack_episode_bootstrap"]["episodes"] == EPISODES
        for t in op["per_attack_type"]:
            assert t["episode_bootstrap"]["episodes"] == t["episodes"]


def test_wide_intervals_are_preserved_not_hidden(p3) -> None:
    """Two-episode folds must show their full uncertainty."""
    op = p3["operating_points"][0]
    loit = next(t for t in op["per_attack_type"] if t["attack_type"] == "ddos/loit")
    assert loit["episodes"] == 2
    assert loit["episode_bootstrap"]["ci_low"] == 0.0
    assert loit["episode_bootstrap"]["ci_high"] == 1.0


# --------------------------------------------------------------------------
# Predictions and isolation
# --------------------------------------------------------------------------


def test_predictions_cover_the_four_declared_groups() -> None:
    groups = {
        row["group"]
        for row in csv.DictReader(
            (P3_DIR / "p3_predictions.csv").open(encoding="utf-8")
        )
    }
    assert groups == {
        "attack",
        "benign_calibration",
        "benign_measurement",
        "unlabelled_unknown",
    }


def test_no_unknown_row_is_labelled_benign_in_the_predictions() -> None:
    for row in csv.DictReader(
        (P3_DIR / "p3_predictions.csv").open(encoding="utf-8")
    ):
        if row["group"] == "unlabelled_unknown":
            assert row["disposition"] == "unknown"


def test_p3_records_zero_postgresql_writes(p3) -> None:
    assert p3["postgresql_writes"] == 0


def test_p3_source_issues_no_write_statement() -> None:
    text = (REPO_ROOT / "scripts/run_p3_anomaly.py").read_text(encoding="utf-8")
    for statement in ("INSERT ", "UPDATE ", "DELETE ", "CREATE SCHEMA",
                      "CREATE TABLE", "DROP ", "TRUNCATE"):
        assert statement not in text


def test_p3_reuses_the_frozen_p1_population(p3) -> None:
    assert p3["p1_dataset_content_sha256"] == (
        "3d7436178da6960ee5effeb4bee85a0b6da5eead9d2babef3c72cb6b7ca9f20d"
    )


def test_r11_is_not_claimed_solved_by_p3(p3) -> None:
    note = p3["r11_note"]
    assert "does not make the 376 attacks a statistically" in note
    assert "54" in note and "9 entities" in note


def test_p3_did_not_modify_p1_or_p2() -> None:
    p1 = json.loads(
        (REPO_ROOT / "artifacts/experiments/p1/p1_metrics.json").read_text(
            encoding="utf-8"
        )
    )
    p2 = json.loads(
        (REPO_ROOT / "artifacts/experiments/p2/p2_metrics.json").read_text(
            encoding="utf-8"
        )
    )
    assert p1["experiment"].startswith("P1/A")
    assert p2["experiment"].startswith("P2/B")
    assert p1["dataset_content_sha256"] == (
        "3d7436178da6960ee5effeb4bee85a0b6da5eead9d2babef3c72cb6b7ca9f20d"
    )
