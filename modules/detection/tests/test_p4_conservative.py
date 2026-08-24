"""Contractual tests for the P4/C conservative robustness control.

Read-only against the published artifacts. Nothing is trained here.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from modules.detection.src.experiments.p1_dataset import (
    NEGATIVE_FOLD_COUNT,
    negative_fold_of,
)


REPO_ROOT = Path(__file__).resolve().parents[3]
P1_METRICS = REPO_ROOT / "artifacts" / "experiments" / "p1" / "p1_metrics.json"
P4_DIR = REPO_ROOT / "artifacts" / "experiments" / "p4"
P4_METRICS = P4_DIR / "p4_metrics.json"
P4_REPORT = P4_DIR / "P4_REPORT.md"

pytestmark = pytest.mark.skipif(
    not P4_METRICS.is_file(), reason="P4 artifacts must be published"
)


@pytest.fixture(scope="module")
def p4() -> dict:
    return json.loads(P4_METRICS.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def p1() -> dict:
    return json.loads(P1_METRICS.read_text(encoding="utf-8"))


# --------------------------------------------------------------------------
# The exclusion and its consequence
# --------------------------------------------------------------------------


def test_exclusion_is_by_removal_only(p4) -> None:
    exclusion = p4["exclusion"]
    assert "exclusion only" in exclusion["rule"]
    assert "nothing added, duplicated or weighted" in exclusion["rule"]
    assert exclusion["positives_p4"] < exclusion["positives_p1"]
    assert exclusion["negatives_unchanged"] == 70_578


def test_the_two_multi_family_entities_are_the_excluded_ones(p4) -> None:
    multi = p4["exclusion"]["multi_family_entities"]
    assert set(multi) == {
        "172.16.0.1|192.168.10.50|tcp|none",
        "172.16.0.1|192.168.10.50|tcp|http",
    }
    assert set(multi["172.16.0.1|192.168.10.50|tcp|http"]) == {
        "ddos/loit", "dos/hulk"
    }


def test_exclusion_deletes_two_attack_types_entirely(p4) -> None:
    """The consequence the design phase did not anticipate."""
    exclusion = p4["exclusion"]
    assert len(exclusion["attack_types_p1"]) == 5
    assert len(exclusion["attack_types_p4"]) == 3
    deleted = set(exclusion["attack_types_p1"]) - set(exclusion["attack_types_p4"])
    assert deleted == {"ddos/loit", "dos/hulk"}


def test_measured_population_matches_the_report(p4) -> None:
    exclusion = p4["exclusion"]
    assert exclusion["positives_p4"] == 290
    assert exclusion["positives_excluded"] == 86
    assert exclusion["entities_p4"] == 7
    assert exclusion["episodes_p4"] == 42


def test_report_corrects_the_design_phase_estimate() -> None:
    report = P4_REPORT.read_text(encoding="utf-8")
    assert "3 attack types, not the 4 the design phase estimated" in report
    assert "That estimate was wrong" in report


# --------------------------------------------------------------------------
# P1 must remain reproducible after the fold-count parameterisation
# --------------------------------------------------------------------------


def test_p1_digests_are_unchanged(p1) -> None:
    assert p1["dataset_content_sha256"] == (
        "3d7436178da6960ee5effeb4bee85a0b6da5eead9d2babef3c72cb6b7ca9f20d"
    )
    assert p1["folds_content_sha256"] == (
        "e463ea7b0eb4985f51369dc3ae19c09821040675aa4b9f9689f8e02545fed95a"
    )
    assert len(p1["folds"]) == 5


def test_negative_fold_default_is_still_five() -> None:
    """P1/P2/P3 depend on the default; only P4 passes a different count."""
    key = "10.0.0.1|10.0.0.2|tcp|http"
    assert negative_fold_of(key) == negative_fold_of(key, NEGATIVE_FOLD_COUNT)
    assert 0 <= negative_fold_of(key) < NEGATIVE_FOLD_COUNT
    assert 0 <= negative_fold_of(key, 3) < 3


def test_p4_uses_three_folds(p4) -> None:
    assert len(p4["folds"]) == 3
    assert {f["held_out_attack_type"] for f in p4["folds"]} == {
        "botnet/ares",
        "brute_force/ftp_patator",
        "brute_force/ssh_patator",
    }


def test_p4_has_no_leakage(p4) -> None:
    for check in p4["leakage_verification"]:
        assert check["failures"] == []
        assert check["shared_window_ids"] == 0
        assert check["shared_episodes"] == []
        assert check["shared_benign_entities"] == 0


# --------------------------------------------------------------------------
# The findings, and the artefact that must not be spun
# --------------------------------------------------------------------------


def test_botnet_conclusion_is_robust(p4) -> None:
    """Same test set, essentially identical metrics: the conclusion survives."""
    botnet = next(
        c for c in p4["comparison_p1_vs_p4"]
        if c["held_out_attack_type"] == "botnet/ares"
    )
    assert botnet["identical_test_positives"] is True
    assert botnet["test_episodes_p4"] == botnet["test_episodes_p1"] == 40
    assert botnet["roc_auc_p4"] < 0.55
    assert botnet["roc_auc_p1"] < 0.55
    assert abs(botnet["roc_auc_p4"] - botnet["roc_auc_p1"]) < 0.01


def test_ftp_discrimination_collapses_on_an_identical_test_set(p4) -> None:
    """The finding that recasts P1's headline result."""
    ftp = next(
        c for c in p4["comparison_p1_vs_p4"]
        if c["held_out_attack_type"] == "brute_force/ftp_patator"
    )
    assert ftp["identical_test_positives"] is True
    assert ftp["roc_auc_p1"] > 0.95
    assert ftp["roc_auc_p4"] < 0.70
    assert ftp["pr_auc_p4"] < ftp["pr_auc_p1"] / 10


def test_ssh_test_set_is_not_comparable_and_is_flagged(p4) -> None:
    """The apparent +0.889 gain is an exclusion artefact, not a result."""
    ssh = next(
        c for c in p4["comparison_p1_vs_p4"]
        if c["held_out_attack_type"] == "brute_force/ssh_patator"
    )
    assert ssh["identical_test_positives"] is False
    assert ssh["test_positives_p1"] == 60
    assert ssh["test_positives_p4"] == 52
    assert ssh["test_episodes_p1"] == 9
    assert ssh["test_episodes_p4"] == 1
    assert ssh["episode_recall_delta"] > 0.8


def _report_text() -> str:
    """Return the report with whitespace normalised.

    Markdown wraps sentences across lines, so substring assertions must not
    depend on where a line happens to break.
    """
    return " ".join(P4_REPORT.read_text(encoding="utf-8").split())


def test_report_refuses_to_present_the_ssh_change_as_an_improvement() -> None:
    report = _report_text()
    assert "is an artefact and must not be read as a gain" in report
    assert "removed precisely the hard cases" in report
    assert "not comparable" in report


def test_report_states_loit_and_hulk_cannot_be_validated() -> None:
    report = _report_text()
    assert "cannot validate the loit and hulk conclusions" in report
    assert "remains **untested**" in report


def test_r11_is_documented_as_worsened(p4) -> None:
    assert "more severe, not less" in p4["r11_note"]
    report = _report_text()
    assert "makes R11 more severe" in report
    assert "never to claim improved statistical power" in report


def test_interpretation_rules_forbid_reading_p4_as_better(p4) -> None:
    rules = " ".join(p4["interpretation_rules"]).lower()
    assert "not a better benchmark" in rules
    assert "smaller and" in rules


def test_pooled_recall_denominators_differ_and_are_stated(p4) -> None:
    pooled = p4["pooled_episode_recall_at_train_fpr_1pct"]
    assert pooled["p1"]["episodes"] == 54
    assert pooled["p4"]["episodes"] == 42
    assert pooled["p4"]["point"] < pooled["p1"]["point"]


# --------------------------------------------------------------------------
# Isolation
# --------------------------------------------------------------------------


def test_p4_records_zero_postgresql_writes(p4) -> None:
    assert p4["postgresql_writes"] == 0


def test_p4_source_issues_no_write_statement() -> None:
    text = (REPO_ROOT / "scripts/run_p4_conservative.py").read_text(encoding="utf-8")
    for statement in ("INSERT ", "UPDATE ", "DELETE ", "CREATE SCHEMA",
                      "CREATE TABLE", "DROP ", "TRUNCATE"):
        assert statement not in text


def test_p4_starts_from_the_frozen_p1_population(p4) -> None:
    assert p4["p1_dataset_content_sha256"] == (
        "3d7436178da6960ee5effeb4bee85a0b6da5eead9d2babef3c72cb6b7ca9f20d"
    )


def test_p4_artifacts_are_all_present() -> None:
    assert P4_METRICS.is_file()
    assert P4_REPORT.is_file()
    assert len(sorted(P4_DIR.glob("p4_model_fold*.joblib"))) == 3
    assert len(sorted(P4_DIR.glob("p4_predictions_fold*.csv"))) == 3
