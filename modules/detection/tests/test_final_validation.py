"""Non-regression tests for final-validation Step 2 (canonical evaluation).

Fast unit tests exercise the guards on synthetic rows. Artifact tests read the
published metrics. Exactly one real fold is re-fitted, to prove determinism
without paying for all 29 fits twice.
"""
from __future__ import annotations

import csv
from hashlib import sha256
import inspect
import json
from pathlib import Path

import joblib
import pytest

from modules.detection.src.experiments import final_validation_eval as fve
from modules.detection.src.experiments.final_validation_eval import (
    HISTORICAL_ARES_ANCHOR,
    PRIMARY_FPR_TARGET,
    TRAINING_ORDER,
    EvaluationError,
    FoldData,
    build_fold,
    canonical_order,
    evaluate_fold,
    fold_guards,
    model_parameters,
    reproducibility_diagnostic,
)
from modules.detection.src.experiments.p1_dataset import FEATURE_NAMES, Row
from modules.detection.src.experiments.p1_evaluation import MODEL_SEED, N_ESTIMATORS
from scripts.run_final_validation_eval import (
    ARES_FAMILY,
    BASELINE_PATH,
    COMPARISON_PATH,
    DATASET,
    EXPECTED_DATASET_SHA256,
    FROZEN_P1_MODEL,
    FV_DIR,
    LEAKAGE_PATH,
    MANIFEST_PATH,
    P1_PREDICTIONS_FOLD0,
    PROTOCOLS,
    REPRODUCIBILITY_PATH,
    ZERO_DAY_PATH,
    held_out_names,
    load_assignment,
    load_rows,
)

ROOT = Path(__file__).resolve().parents[3]


def synthetic(
    row_id: str,
    label: int,
    *,
    entity: str = "e1",
    episode: str | None = None,
    attack: str | None = None,
    features: tuple[float, ...] = (1.0, 2.0, 3.0, 4.0, 5.0),
) -> Row:
    return Row(
        row_id=row_id,
        source="m6" if label else "mb6",
        label=label,
        disposition="target_attack" if label else "benign_reference",
        attack_type=attack,
        entity_key=entity,
        episode_id=episode,
        partition="p",
        window_start_epoch=60,
        features=features,
    )


# ------------------------------------------------------------ model and order


def test_canonical_model_is_the_frozen_p1_random_forest() -> None:
    parameters = model_parameters()
    assert parameters["estimator"] == "RandomForestClassifier"
    assert parameters["n_estimators"] == N_ESTIMATORS == 200
    assert parameters["random_state"] == MODEL_SEED == 0
    assert parameters["class_weight"] is None
    assert parameters["hyperparameter_search"] == "none"
    assert parameters["feature_transform"] == "none"
    assert parameters["class_rebalancing"] == "none"


def test_training_order_is_the_ratified_convention() -> None:
    assert TRAINING_ORDER == "label,row_id"
    rows = [synthetic("b", 1), synthetic("a", 0), synthetic("c", 1), synthetic("a0", 0)]
    assert [r.row_id for r in canonical_order(rows)] == ["a", "a0", "b", "c"]


def test_frozen_dataset_is_stored_in_the_canonical_order() -> None:
    rows = load_rows()
    assert [r.row_id for r in canonical_order(rows)] == [r.row_id for r in rows]
    assert sha256(DATASET.read_bytes()).hexdigest() == EXPECTED_DATASET_SHA256


def test_primary_operating_point_is_one_percent() -> None:
    assert PRIMARY_FPR_TARGET == 0.01


def test_no_postgresql_access_in_the_evaluation_module() -> None:
    source = inspect.getsource(fve)
    for forbidden in ("psycopg", "get_monday_benign_connection", "SELECT ", "cursor"):
        assert forbidden not in source, forbidden


# ------------------------------------------------------------------- guards


def test_feature_width_and_order_are_guarded() -> None:
    assert FEATURE_NAMES == (
        "event_count",
        "source_packets_total",
        "destination_packets_total",
        "source_bytes_total",
        "destination_bytes_total",
    )
    bad = [synthetic("x", 1, features=(1.0, 2.0))]
    with pytest.raises(EvaluationError, match="features"):
        fold_guards(
            FoldData("t", 0, "h", tuple(bad), (synthetic("y", 0),)),
            require_entity_disjoint=False,
            require_episode_disjoint=False,
        )


def test_forbidden_metadata_is_never_a_model_input() -> None:
    forbidden = set(fve.FORBIDDEN_MODEL_INPUTS)
    assert forbidden & {"entity_key", "row_id", "attack_type", "episode_id", "partition"}
    assert not forbidden & set(FEATURE_NAMES)


def test_overlapping_row_ids_are_rejected() -> None:
    row = synthetic("shared", 0)
    with pytest.raises(EvaluationError, match="shared row ids"):
        fold_guards(
            FoldData("t", 0, "h", (row,), (row,)),
            require_entity_disjoint=False,
            require_episode_disjoint=False,
        )


def test_entity_leakage_is_blocking_when_required() -> None:
    train = (synthetic("a", 1, entity="shared", episode="e1", attack="x"),)
    test = (synthetic("b", 1, entity="shared", episode="e2", attack="x"),)
    with pytest.raises(EvaluationError, match="entity leakage"):
        fold_guards(
            FoldData("t", 0, "h", train, test),
            require_entity_disjoint=True,
            require_episode_disjoint=True,
        )


def test_episode_leakage_is_blocking_when_required() -> None:
    train = (synthetic("a", 1, entity="e1", episode="shared", attack="x"),)
    test = (synthetic("b", 1, entity="e2", episode="shared", attack="x"),)
    with pytest.raises(EvaluationError, match="episode leakage"):
        fold_guards(
            FoldData("t", 0, "h", train, test),
            require_entity_disjoint=False,
            require_episode_disjoint=True,
        )


def test_held_out_family_in_training_is_blocking() -> None:
    train = (synthetic("a", 1, entity="e1", episode="e1|000", attack=ARES_FAMILY),)
    test = (synthetic("b", 1, entity="e2", episode="e2|000", attack=ARES_FAMILY),)
    with pytest.raises(EvaluationError, match="rows present in training"):
        fold_guards(
            FoldData("t", 0, "h", train, test),
            require_entity_disjoint=False,
            require_episode_disjoint=True,
            forbid_family_in_train=ARES_FAMILY,
        )


# ----------------------------------------------------- real fold determinism


@pytest.fixture(scope="module")
def zero_day_fold():
    rows = canonical_order(load_rows())
    assignment = load_assignment(PROTOCOLS["D_zero_day_ares"][0])
    names = held_out_names("D_zero_day_ares")
    return rows, build_fold("D_zero_day_ares", 0, names[0], rows, assignment)


def test_zero_day_split_excludes_ares_from_training(zero_day_fold) -> None:
    _, data = zero_day_fold
    guards = fold_guards(
        data,
        require_entity_disjoint=True,
        require_episode_disjoint=True,
        forbid_family_in_train=ARES_FAMILY,
    )
    assert guards["entity_intersection_count"] == 0
    assert guards["episode_intersection_count"] == 0
    assert not any(r.attack_type == ARES_FAMILY for r in data.train)
    assert sum(1 for r in data.test if r.attack_type == ARES_FAMILY) == 177
    assert len(data.train) == 57_003 and len(data.test) == 13_951


def test_refitting_the_same_fold_twice_gives_identical_metrics(zero_day_fold) -> None:
    _, data = zero_day_fold
    guards = fold_guards(
        data,
        require_entity_disjoint=True,
        require_episode_disjoint=True,
        forbid_family_in_train=ARES_FAMILY,
    )
    first = evaluate_fold(data, guards)
    second = evaluate_fold(data, guards)
    for key in ("roc_auc", "pr_auc", "threshold", "fpr", "tp", "fp", "tn", "fn"):
        assert first[key] == second[key], key
    assert first["test_scores"] == second["test_scores"]
    assert first["training_order"] == TRAINING_ORDER
    assert first["model_source"] == "refitted_under_canonical_order"


def test_threshold_uses_training_negatives_only(zero_day_fold) -> None:
    """A threshold derived from train negatives cannot depend on test rows."""
    rows, data = zero_day_fold
    guards = fold_guards(
        data,
        require_entity_disjoint=True,
        require_episode_disjoint=True,
        forbid_family_in_train=ARES_FAMILY,
    )
    baseline = evaluate_fold(data, guards)
    # Corrupt every test label; the calibrated threshold must not move.
    corrupted = FoldData(
        data.protocol,
        data.fold,
        data.held_out,
        data.train,
        tuple(
            Row(
                r.row_id,
                r.source,
                1 - r.label,
                r.disposition,
                r.attack_type,
                r.entity_key,
                r.episode_id,
                r.partition,
                r.window_start_epoch,
                r.features,
            )
            for r in data.test
        ),
    )
    altered = evaluate_fold(corrupted, guards)
    assert altered["threshold"] == baseline["threshold"]
    assert altered["achieved_train_fpr"] == baseline["achieved_train_fpr"]


def test_historical_anchor_uses_the_frozen_model_and_reproduces_it(zero_day_fold) -> None:
    _, data = zero_day_fold
    guards = fold_guards(
        data,
        require_entity_disjoint=True,
        require_episode_disjoint=True,
        forbid_family_in_train=ARES_FAMILY,
    )
    frozen = joblib.load(FROZEN_P1_MODEL)
    record = evaluate_fold(data, guards, frozen_model=frozen)
    assert record["model_source"] == "historical_frozen_model"
    assert record["historical_anchor"] is True
    with P1_PREDICTIONS_FOLD0.open(newline="", encoding="utf-8") as stream:
        published = {r["row_id"]: float(r["score"]) for r in csv.DictReader(stream)}
    assert set(record["test_scores"]) == set(published)
    assert all(
        f"{value:.10f}" == f"{published[row_id]:.10f}"
        for row_id, value in record["test_scores"].items()
    )
    assert record["threshold"] == HISTORICAL_ARES_ANCHOR["threshold"]
    assert record["tp"] == HISTORICAL_ARES_ANCHOR["tp"]
    assert record["detected_episodes"] == HISTORICAL_ARES_ANCHOR["detected_episodes"]
    assert record["roc_auc"] == pytest.approx(HISTORICAL_ARES_ANCHOR["roc_auc"], abs=1e-12)
    assert record["fpr"] == pytest.approx(HISTORICAL_ARES_ANCHOR["fpr"], abs=1e-12)


# ------------------------------------------------------------- diagnostic text


def test_reproducibility_diagnostic_states_the_cause_without_blaming_the_model() -> None:
    document = reproducibility_diagnostic()
    assert document["not_a_model_defect"] is True
    assert "no ORDER BY" in " ".join(document["facts"])
    assert "index row positions" in " ".join(document["facts"])
    assert document["resolution"]["postgresql_used_to_recover_order"] is False
    assert document["resolution"]["training_order"] == TRAINING_ORDER


# --------------------------------------------------------- published artifacts


published = pytest.mark.skipif(
    not MANIFEST_PATH.exists(), reason="step 2 metrics not yet published"
)


@published
def test_published_outputs_match_the_manifest() -> None:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    for name, digest in manifest["outputs"].items():
        assert sha256((FV_DIR / name).read_bytes()).hexdigest() == digest, name
    assert manifest["postgresql_connections"] == 0
    assert manifest["postgresql_writes"] == 0
    assert manifest["hyperparameter_tuning"] == "none"
    assert manifest["threshold_selected_on_test"] is False
    assert manifest["arm_f_evaluated"] is False
    assert manifest["models_fitted"] == 29
    assert manifest["frozen_models_rescored"] == 1


@published
def test_protocol_a_is_not_claimed_as_a_reproduction() -> None:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    assert manifest["protocol_A_is_a_reproduction_of_p1"] is False
    assert "reimplementation" in manifest["protocol_A_label"]


@published
def test_published_baseline_records_every_required_field() -> None:
    document = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    required = {
        "train_rows",
        "test_rows",
        "train_positive",
        "train_negative",
        "test_positive",
        "test_negative",
        "threshold",
        "roc_auc",
        "pr_auc",
        "fpr",
        "recall",
        "precision",
        "tp",
        "fp",
        "tn",
        "fn",
        "episode_recall",
        "detected_episodes",
        "total_episodes",
        "entity_count_train",
        "entity_count_test",
        "entity_intersection_count",
        "episode_intersection_count",
        "feature_names",
        "feature_count",
        "model_parameters",
        "random_state",
        "training_order",
    }
    for key, protocol in document["protocols"].items():
        for fold in protocol["folds"]:
            assert required <= set(fold), (key, sorted(required - set(fold)))
            assert fold["feature_count"] == 5
            assert fold["feature_names"] == list(FEATURE_NAMES)
            assert fold["training_order"] == "label,row_id"
            assert "test_scores" not in fold


@published
def test_published_disjointness_matches_each_protocol_contract() -> None:
    document = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    protocols = document["protocols"]
    for fold in protocols["B_entity_disjoint"]["folds"]:
        assert fold["entity_intersection_count"] == 0
    for key, protocol in protocols.items():
        for fold in protocol["folds"]:
            assert fold["episode_intersection_count"] == 0, key
    for fold in protocols["D_zero_day_ares"]["folds"]:
        assert fold["entity_intersection_count"] == 0
        assert fold["train_attack_type_windows"].get(ARES_FAMILY, 0) == 0


@published
def test_published_zero_day_separates_refit_from_anchor() -> None:
    document = json.loads(ZERO_DAY_PATH.read_text(encoding="utf-8"))
    d1 = document["D1_refitted"]
    d2 = document["D2_historical_anchor"]
    assert d1["model_source"] == "refitted_under_canonical_order"
    assert d1["historical_anchor"] is False
    assert d2["model_source"] == "historical_frozen_model"
    assert d2["historical_anchor"] is True
    assert "not a new training run" in d2["description"]
    assert all(check["passed"] for check in d2["anchor_checks"])
    assert d2["roc_auc"] == pytest.approx(0.5037, abs=5e-5)
    assert d2["pr_auc"] == pytest.approx(0.0135, abs=5e-5)
    assert d2["threshold"] == 0.005
    assert d2["fpr"] == pytest.approx(0.009583, abs=5e-7)
    assert d2["detected_episodes"] == 3 and d2["total_episodes"] == 40
    assert document["ares_absent_from_training"] == {"D1": True, "D2": True}


@published
def test_published_leakage_diagnostic_is_measured_not_asserted() -> None:
    document = json.loads(LEAKAGE_PATH.read_text(encoding="utf-8"))
    assert document["measured_leakage_in_A"]["folds_with_shared_attack_entity"] == [2, 3, 4]
    assert document["entity_disjointness_in_B"]["max_entity_intersection"] == 0
    assert "quantifies its impact" in document["statement"]
    assert "do not answer the same question" in document["caution"]
    assert set(document["variation_A_to_B"]["delta"])


@published
def test_published_reproducibility_diagnostic_is_present() -> None:
    document = json.loads(REPRODUCIBILITY_PATH.read_text(encoding="utf-8"))
    assert document["not_a_model_defect"] is True
    assert "impossible from the artifacts alone" in document["statement"]


@published
def test_step1_split_artifacts_were_not_modified() -> None:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    assert manifest["step1_artifacts_modified"] is False
    splits = json.loads(
        (FV_DIR / "splits" / "splits_manifest.json").read_text(encoding="utf-8")
    )
    for name, digest in splits["outputs"].items():
        assert sha256((FV_DIR / "splits" / name).read_bytes()).hexdigest() == digest, name


@published
def test_no_frozen_input_changed_since_publication() -> None:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    for name, digest in manifest["frozen_inputs"].items():
        assert sha256((ROOT / name).read_bytes()).hexdigest() == digest, name


@published
def test_split_comparison_keeps_interpretations_separate() -> None:
    document = json.loads(COMPARISON_PATH.read_text(encoding="utf-8"))
    boundaries = document["interpretation_boundaries"]
    assert set(boundaries) == {"A", "B", "C", "D1", "D2"}
    assert "family novelty" in boundaries["A"]
    assert "entity novelty" in boundaries["B"]
    assert "episode novelty" in boundaries["C"]
    assert {row["protocol"] for row in document["table"]} == set(PROTOCOLS) | {
        "D2_historical_anchor"
    }
