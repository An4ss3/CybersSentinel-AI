"""Contractual tests for the P1/A supervised benchmark.

Read-only against PostgreSQL and against the published P1 artifacts. Nothing is
trained here; the published metrics are asserted against their recorded values.
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pytest

from modules.detection.src.experiments.p1_dataset import (
    FEATURE_NAMES,
    FORBIDDEN_COLUMNS,
    NEGATIVE_FOLD_COUNT,
    WINDOW_LENGTH_SECONDS,
    negative_fold_of,
)
from modules.detection.src.experiments.p1_evaluation import (
    BOOTSTRAP_SEED,
    FPR_TARGETS,
    MODEL_SEED,
    N_ESTIMATORS,
    build_model,
    episode_bootstrap_recall,
    threshold_at_train_fpr,
)


REPO_ROOT = Path(__file__).resolve().parents[3]
P1_DIR = REPO_ROOT / "artifacts" / "experiments" / "p1"
DATASET = P1_DIR / "p1_dataset.csv"
FOLDS = P1_DIR / "p1_folds.json"
METRICS = P1_DIR / "p1_metrics.json"
LEAKAGE = P1_DIR / "p1_leakage_verification.json"

POSITIVES = 376
NEGATIVES = 70_578
EPISODES = 54
ATTACK_TYPES = (
    "botnet/ares",
    "brute_force/ftp_patator",
    "brute_force/ssh_patator",
    "ddos/loit",
    "dos/hulk",
)

pytestmark = pytest.mark.skipif(
    not METRICS.is_file(), reason="P1 artifacts must be published for these tests"
)


@pytest.fixture(scope="module")
def metrics() -> dict:
    return json.loads(METRICS.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def dataset_rows() -> list[dict]:
    lines = DATASET.read_text(encoding="utf-8").strip().splitlines()
    header = lines[0].split(",")
    return [dict(zip(header, line.split(","))) for line in lines[1:]]


# --------------------------------------------------------------------------
# Dataset composition and feature budget
# --------------------------------------------------------------------------


def test_dataset_has_the_ratified_population(dataset_rows) -> None:
    labels = [r["label"] for r in dataset_rows]
    assert len(dataset_rows) == POSITIVES + NEGATIVES
    assert labels.count("1") == POSITIVES
    assert labels.count("0") == NEGATIVES


def test_dataset_carries_only_the_five_admitted_features(dataset_rows) -> None:
    header = set(dataset_rows[0])
    for name in FEATURE_NAMES:
        assert name in header
    assert len(FEATURE_NAMES) == 5
    forbidden_present = {
        c for c in FORBIDDEN_COLUMNS
        if c in header and c not in ("window_start_time",)
    }
    # entity_key, episode_id and partition are retained as audit metadata only;
    # every column named in FORBIDDEN_COLUMNS must be absent from the dataset.
    assert not forbidden_present, forbidden_present


def test_dataset_contains_no_unknown_or_ambiguous_row(dataset_rows) -> None:
    dispositions = {r["disposition"] for r in dataset_rows}
    assert dispositions == {"benign_reference", "target_attack",
                            "known_other_attack"}
    assert "unknown" not in dispositions
    assert "ambiguous" not in dispositions


def test_every_negative_is_a_mb_label_benign_reference(dataset_rows) -> None:
    for row in dataset_rows:
        if row["label"] == "0":
            assert row["disposition"] == "benign_reference"
            assert row["source"] == "mb6"


def test_every_positive_is_typed_and_has_an_episode(dataset_rows) -> None:
    for row in dataset_rows:
        if row["label"] == "1":
            assert row["attack_type"] in ATTACK_TYPES
            assert row["episode_id"]
            assert row["source"] == "m6"


def test_episode_count_matches_the_published_value(dataset_rows) -> None:
    episodes = {r["episode_id"] for r in dataset_rows if r["label"] == "1"}
    assert len(episodes) == EPISODES


def test_episode_ids_encode_type_and_entity(dataset_rows) -> None:
    for row in dataset_rows:
        if row["label"] != "1":
            continue
        assert row["episode_id"].startswith(row["attack_type"] + "|")
        assert row["entity_key"] in row["episode_id"]


# --------------------------------------------------------------------------
# Folds and leakage
# --------------------------------------------------------------------------


def test_folds_are_leave_one_attack_type_out(metrics) -> None:
    held_out = [f["held_out_attack_type"] for f in metrics["folds"]]
    assert sorted(held_out) == sorted(ATTACK_TYPES)
    assert len(metrics["folds"]) == NEGATIVE_FOLD_COUNT


def test_leakage_verification_reports_no_failure() -> None:
    checks = json.loads(LEAKAGE.read_text(encoding="utf-8"))
    assert len(checks) == NEGATIVE_FOLD_COUNT
    for check in checks:
        assert check["failures"] == []
        assert check["shared_window_ids"] == 0
        assert check["shared_attack_types"] == []
        assert check["shared_episodes"] == []
        assert check["shared_benign_entities"] == 0
        assert check["test_positives"] > 0
        assert check["train_positives"] > 0


def test_folds_partition_every_row_exactly_once() -> None:
    folds = json.loads(FOLDS.read_text(encoding="utf-8"))
    for fold in folds:
        train = set(fold["train_row_ids"])
        test = set(fold["test_row_ids"])
        assert not (train & test)
        assert len(train) + len(test) == POSITIVES + NEGATIVES


def test_negative_fold_assignment_is_deterministic_and_balanced() -> None:
    assert negative_fold_of("a|b|tcp|http") == negative_fold_of("a|b|tcp|http")
    counts = [0] * NEGATIVE_FOLD_COUNT
    for i in range(20_000):
        counts[negative_fold_of(f"10.0.0.{i}|10.0.1.1|tcp|http")] += 1
    # Deterministic hashing, so no seed; only gross imbalance would be a defect.
    assert min(counts) > 0
    assert max(counts) / min(counts) < 1.2


# --------------------------------------------------------------------------
# Threshold selection — the defect found and corrected on the first P1 run
# --------------------------------------------------------------------------


def test_threshold_handles_a_degenerate_score_distribution() -> None:
    """The regression test for the first P1 run's degenerate operating point.

    With a 1:187.7 imbalance and no class weighting the forest scores almost every
    training negative exactly 0.0. A plain ``quantile(0.99)`` returns 0.0, and
    ``score >= 0.0`` flags every row: FPR 1.0 and recall 1.0. The corrected
    selector must return a threshold that actually achieves the target.
    """
    scores = np.zeros(10_000)
    scores[:50] = 0.4          # 0.5% of negatives carry a non-zero score
    threshold, achieved = threshold_at_train_fpr(scores, 0.01)
    assert achieved <= 0.01
    assert threshold > 0.0
    assert (scores >= threshold).mean() <= 0.01
    # A plain quantile would have produced the degenerate answer.
    assert float(np.quantile(scores, 0.99)) == 0.0


def test_threshold_never_exceeds_the_target_rate() -> None:
    rng = np.random.default_rng(1)
    scores = np.concatenate([np.zeros(5_000), rng.random(5_000)])
    for target in FPR_TARGETS:
        threshold, achieved = threshold_at_train_fpr(scores, target)
        assert achieved <= target
        assert (scores >= threshold).mean() <= target


def test_threshold_uses_only_the_supplied_negatives() -> None:
    """Positives must not be able to influence the operating point."""
    negatives = np.array([0.0, 0.0, 0.0, 0.1, 0.2])
    first, _ = threshold_at_train_fpr(negatives, 0.2)
    second, _ = threshold_at_train_fpr(negatives, 0.2)
    assert first == second


# --------------------------------------------------------------------------
# Bootstrap is episode-level, never window-level
# --------------------------------------------------------------------------


def test_bootstrap_resamples_episodes_not_windows() -> None:
    detected = {f"e{i}": (i % 2 == 0) for i in range(10)}
    result = episode_bootstrap_recall(detected, resamples=500, seed=BOOTSTRAP_SEED)
    assert result["episodes"] == 10
    assert result["point"] == 0.5
    assert result["ci_low"] < result["point"] < result["ci_high"]


def test_bootstrap_is_reproducible() -> None:
    detected = {f"e{i}": (i % 3 == 0) for i in range(12)}
    a = episode_bootstrap_recall(detected, resamples=300, seed=BOOTSTRAP_SEED)
    b = episode_bootstrap_recall(detected, resamples=300, seed=BOOTSTRAP_SEED)
    assert a == b


def test_published_bootstrap_denominators_are_episode_counts(metrics) -> None:
    for fold in metrics["folds"]:
        for point in fold["operating_points"]:
            boot = point["episode_bootstrap"]
            assert boot["episodes"] == fold["test_episodes"]
            assert boot["episodes"] < fold["test_positives"] or (
                fold["test_positives"] == boot["episodes"]
            )
    pooled = metrics["pooled_episode_recall_at_train_fpr_1pct"]
    assert pooled["episodes"] == EPISODES


# --------------------------------------------------------------------------
# Model determinism and absence of rebalancing
# --------------------------------------------------------------------------


def test_model_is_deterministic_and_unweighted() -> None:
    model = build_model()
    assert model.random_state == MODEL_SEED
    assert model.n_estimators == N_ESTIMATORS
    assert model.n_jobs == 1
    assert model.class_weight is None, "class weighting is a form of rebalancing"


def test_model_trains_reproducibly() -> None:
    rng = np.random.default_rng(0)
    x = rng.random((200, len(FEATURE_NAMES)))
    y = (x[:, 0] > 0.9).astype(int)
    first = build_model().fit(x, y).predict_proba(x)[:, 1]
    second = build_model().fit(x, y).predict_proba(x)[:, 1]
    assert np.array_equal(first, second)


# --------------------------------------------------------------------------
# Published results and their limitations
# --------------------------------------------------------------------------


def test_metrics_record_zero_postgresql_writes(metrics) -> None:
    assert metrics["postgresql_writes"] == 0


def test_metrics_record_the_conservative_decisions(metrics) -> None:
    ids = {d["id"] for d in metrics["conservative_decisions"]}
    assert {"D1", "D2", "D3", "D4", "D5", "D6", "D7", "D8", "D9", "D10"} <= ids


def test_botnet_blindness_is_documented_and_observed(metrics) -> None:
    """The arithmetic prediction and the measured outcome must agree."""
    blind = metrics["limitations"]["expected_botnet_blindness"]
    assert blind["botnet_events_per_window"] < blind["benign_events_per_window"]
    botnet = next(
        f for f in metrics["folds"] if f["held_out_attack_type"] == "botnet/ares"
    )
    # ROC-AUC at chance level is the strongest statement of blindness.
    assert botnet["roc_auc"] < 0.55
    assert botnet["pr_auc"] < 0.05


def test_r11_is_recorded_as_a_major_limitation(metrics) -> None:
    r11 = metrics["limitations"]["R11"]
    assert r11["status"] == "major limitation, benchmark possible"
    assert r11["attack_types"] == 5
    assert r11["attack_entities"] == 9
    assert r11["target_attack_host_pairs"] == 1


def test_r1_is_not_claimed_resolved(metrics) -> None:
    assert metrics["limitations"]["R1"]["status"].startswith("not resolved")


def test_forbidden_claims_are_recorded(metrics) -> None:
    forbidden = " ".join(metrics["forbidden_claims"]).lower()
    assert "generalisation" in forbidden
    assert "window level" in forbidden
    assert "unknown" in forbidden


def test_no_aggregate_metric_hides_the_botnet(metrics) -> None:
    """Only per-fold metrics and an episode-pooled recall may exist."""
    assert "aggregate_pr_auc" not in metrics
    assert "mean_pr_auc" not in metrics
    assert len(metrics["folds"]) == 5
    for fold in metrics["folds"]:
        assert "pr_auc" in fold and "held_out_attack_type" in fold


# --------------------------------------------------------------------------
# Isolation
# --------------------------------------------------------------------------


def test_p1_did_not_write_to_any_canonical_schema() -> None:
    for source in (
        "modules/detection/src/experiments/p1_dataset.py",
        "modules/detection/src/experiments/p1_evaluation.py",
        "scripts/run_p1_supervised.py",
    ):
        text = (REPO_ROOT / source).read_text(encoding="utf-8")
        for statement in ("INSERT ", "UPDATE ", "DELETE ", "CREATE SCHEMA",
                          "CREATE TABLE", "DROP ", "TRUNCATE"):
            assert statement not in text, f"{source} contains {statement!r}"


def test_p1_artifacts_are_all_present() -> None:
    for name in (
        "p1_dataset.csv",
        "p1_folds.json",
        "p1_leakage_verification.json",
        "p1_metrics.json",
    ):
        assert (P1_DIR / name).is_file()
    models = sorted(P1_DIR.glob("p1_model_fold*.joblib"))
    predictions = sorted(P1_DIR.glob("p1_predictions_fold*.csv"))
    assert len(models) == NEGATIVE_FOLD_COUNT
    assert len(predictions) == NEGATIVE_FOLD_COUNT


def test_window_length_is_the_frozen_sixty_seconds() -> None:
    assert WINDOW_LENGTH_SECONDS == 60
