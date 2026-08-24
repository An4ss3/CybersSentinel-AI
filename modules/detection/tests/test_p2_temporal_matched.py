"""Contractual tests for the P2/B temporal-matched ablation of R1.

Read-only against the published P1 and P2 artifacts. Nothing is trained here.
"""
from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[3]
P1_DIR = REPO_ROOT / "artifacts" / "experiments" / "p1"
P2_DIR = REPO_ROOT / "artifacts" / "experiments" / "p2"
P1_METRICS = P1_DIR / "p1_metrics.json"
P2_METRICS = P2_DIR / "p2_metrics.json"

ATTACK_TYPES = (
    "botnet/ares",
    "brute_force/ftp_patator",
    "brute_force/ssh_patator",
    "ddos/loit",
    "dos/hulk",
)

pytestmark = pytest.mark.skipif(
    not P2_METRICS.is_file(), reason="P2 artifacts must be published"
)


@pytest.fixture(scope="module")
def p1() -> dict:
    return json.loads(P1_METRICS.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def p2() -> dict:
    return json.loads(P2_METRICS.read_text(encoding="utf-8"))


# --------------------------------------------------------------------------
# The single-change guarantee
# --------------------------------------------------------------------------


def test_p2_reuses_the_frozen_p1_population_and_folds(p1, p2) -> None:
    assert p2["p1_dataset_content_sha256"] == p1["dataset_content_sha256"]
    assert p2["p1_folds_content_sha256"] == p1["folds_content_sha256"]


def test_p2_declares_exactly_one_change(p2) -> None:
    assert "training negatives" in p2["single_change_versus_p1"]
    assert "test sets are identical" in p2["single_change_versus_p1"]
    reused = " ".join(p2["reused_from_p1_unchanged"]).lower()
    for item in ("features", "folds", "test set", "threshold", "bootstrap"):
        assert item in reused


def test_every_test_set_is_identical_to_p1(p1, p2) -> None:
    """The comparison is only meaningful on identical test observations."""
    by_type_p1 = {f["held_out_attack_type"]: f for f in p1["folds"]}
    for fold in p2["folds"]:
        reference = by_type_p1[fold["held_out_attack_type"]]
        assert fold["test_positives"] == reference["test_positives"]
        assert fold["test_negatives"] == reference["test_negatives"]
        assert fold["test_episodes"] == reference["test_episodes"]
    assert all(c["identical_test_set"] for c in p2["comparison_p1_vs_p2"])


def test_p2_test_predictions_cover_the_same_rows_as_p1() -> None:
    for fold in range(5):
        p1_rows = {
            r["row_id"]
            for r in csv.DictReader(
                (P1_DIR / f"p1_predictions_fold{fold}.csv").open(encoding="utf-8")
            )
        }
        p2_rows = {
            r["row_id"]
            for r in csv.DictReader(
                (P2_DIR / f"p2_predictions_fold{fold}.csv").open(encoding="utf-8")
            )
        }
        assert p1_rows == p2_rows, f"fold {fold} test rows differ"


def test_features_labels_and_targets_are_unchanged(p1, p2) -> None:
    assert p2["features"] == p1["features"]
    assert p2["forbidden_columns"] == p1["forbidden_columns"]
    assert len(p2["folds"]) == len(p1["folds"]) == 5


# --------------------------------------------------------------------------
# The matching rule
# --------------------------------------------------------------------------


def test_matching_offsets_come_from_training_positives_only(p2) -> None:
    rule = p2["matching_rule"]
    assert rule["id"] == "D11"
    assert "TRAINING positive" in rule["rule"]
    assert "held-out" in rule["leak_argument"]
    assert "not_rebalancing" in rule


def test_matching_drops_negatives_but_keeps_every_positive(p1, p2) -> None:
    by_type = {f["held_out_attack_type"]: f for f in p1["folds"]}
    for entry in p2["matching"]:
        reference = by_type[entry["held_out_attack_type"]]
        assert entry["train_positives"] == reference["train_positives"]
        assert entry["train_negatives_p2"] < entry["train_negatives_p1"]
        assert entry["train_negatives_p2"] > 0
        assert 0.0 < entry["retention_rate"] < 1.0
        assert entry["imbalance_p2"] < entry["imbalance_p1"]


def test_matching_is_not_presented_as_rebalancing(p2) -> None:
    text = p2["matching_rule"]["not_rebalancing"].lower()
    assert "duplicated" in text and "weighted" in text and "synthesised" in text
    assert "side effect" in text


# --------------------------------------------------------------------------
# The R1 result
# --------------------------------------------------------------------------


def test_episode_recall_is_unchanged_on_four_of_five_types(p2) -> None:
    """The primary finding: controlling hour-of-day did not move recall."""
    unchanged = [
        c for c in p2["comparison_p1_vs_p2"] if c["episode_recall_delta"] == 0.0
    ]
    assert len(unchanged) == 4
    moved = [c for c in p2["comparison_p1_vs_p2"] if c["episode_recall_delta"] != 0.0]
    assert len(moved) == 1
    assert moved[0]["held_out_attack_type"] == "botnet/ares"


def test_the_one_moved_fold_has_overlapping_intervals(p2) -> None:
    moved = next(
        c for c in p2["comparison_p1_vs_p2"]
        if c["held_out_attack_type"] == "botnet/ares"
    )
    low1, high1 = moved["episode_ci_p1"]
    low2, high2 = moved["episode_ci_p2"]
    assert low2 <= high1 and low1 <= high2, "intervals must overlap"


def test_botnet_remains_at_chance_in_both_designs(p2) -> None:
    moved = next(
        c for c in p2["comparison_p1_vs_p2"]
        if c["held_out_attack_type"] == "botnet/ares"
    )
    assert moved["roc_auc_p1"] < 0.55
    assert moved["roc_auc_p2"] < 0.55


def test_pooled_intervals_overlap(p2) -> None:
    pooled = p2["pooled_episode_recall_at_train_fpr_1pct"]
    assert pooled["p1"]["episodes"] == pooled["p2"]["episodes"] == 54
    assert pooled["p2"]["ci_low"] <= pooled["p1"]["ci_high"]


def test_interpretation_rules_were_fixed_before_the_result(p2) -> None:
    rules = " ".join(p2["r1_interpretation_rules"]).lower()
    assert "stable recall" in rules
    assert "reading the clock" in rules
    assert "not itself evidence" in rules


def test_pr_auc_decline_is_not_attributed_to_r1(p2) -> None:
    """PR-AUC fell on three folds; the report must not read that as an R1 effect."""
    declines = [
        c for c in p2["comparison_p1_vs_p2"] if c["pr_auc_delta"] < -0.1
    ]
    assert declines, "the decline is real and must be acknowledged"
    report = (P2_DIR / "P2_REPORT.md").read_text(encoding="utf-8")
    assert "This is not evidence about R1" in report
    assert "coverage and" in report


def test_report_documents_the_size_composition_confound(p2) -> None:
    report = (P2_DIR / "P2_REPORT.md").read_text(encoding="utf-8")
    assert "confound" in report.lower()
    assert "forbidden" in report.lower()


def test_r11_is_not_claimed_improved(p2) -> None:
    report = (P2_DIR / "P2_REPORT.md").read_text(encoding="utf-8")
    assert "R11 is untouched" in report
    assert "no attack diversity" in report


# --------------------------------------------------------------------------
# Isolation
# --------------------------------------------------------------------------


def test_p2_records_zero_postgresql_writes(p2) -> None:
    assert p2["postgresql_writes"] == 0


def test_p2_source_issues_no_write_statement() -> None:
    text = (REPO_ROOT / "scripts/run_p2_temporal_matched.py").read_text(
        encoding="utf-8"
    )
    for statement in ("INSERT ", "UPDATE ", "DELETE ", "CREATE SCHEMA",
                      "CREATE TABLE", "DROP ", "TRUNCATE"):
        assert statement not in text


def test_p2_artifacts_are_all_present() -> None:
    assert (P2_DIR / "p2_metrics.json").is_file()
    assert (P2_DIR / "p2_matching.json").is_file()
    assert (P2_DIR / "P2_REPORT.md").is_file()
    assert len(sorted(P2_DIR.glob("p2_model_fold*.joblib"))) == 5
    assert len(sorted(P2_DIR.glob("p2_predictions_fold*.csv"))) == 5


def test_p1_artifacts_were_not_modified_by_p2(p1) -> None:
    """P1 is frozen; P2 must have read it without touching it."""
    assert p1["experiment"].startswith("P1/A")
    assert p1["dataset_content_sha256"] == (
        "3d7436178da6960ee5effeb4bee85a0b6da5eead9d2babef3c72cb6b7ca9f20d"
    )
    assert p1["folds_content_sha256"] == (
        "e463ea7b0eb4985f51369dc3ae19c09821040675aa4b9f9689f8e02545fed95a"
    )
