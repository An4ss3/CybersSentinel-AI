"""Non-regression tests for final-validation Step 3 (A versus A').

Fast tests exercise the A' construction on synthetic rows. One real fold pair is
re-fitted to prove determinism. Artifact tests read the published comparison.
"""
from __future__ import annotations

from hashlib import sha256
import inspect
import json
from pathlib import Path

import pytest

from modules.detection.src.experiments import final_validation_leakage as fvl
from modules.detection.src.experiments.final_validation_eval import (
    FoldData,
    TRAINING_ORDER,
    canonical_order,
    evaluate_fold,
    fold_guards,
)
from modules.detection.src.experiments.final_validation_leakage import (
    COMPARED_METRICS,
    TARGET_FOLDS,
    LeakageExperimentError,
    build_a_prime,
    delta,
    experiment_configuration,
    removal_diagnostic,
    shared_attack_entities,
)
from modules.detection.src.experiments.p1_dataset import FEATURE_NAMES, Row
from scripts.run_final_validation_eval import BASELINE_PATH, FV_DIR
from scripts.run_final_validation_leakage import (
    COMPARISON_PATH,
    CONFIG_PATH,
    DIAGNOSTIC_PATH,
    MANIFEST_PATH,
    OUT_DIR,
    build_folds,
)

ROOT = Path(__file__).resolve().parents[3]
DATASET = ROOT / "artifacts" / "production" / "ml_dataset_v1" / "ml_dataset.csv"
P1_FOLDS = ROOT / "artifacts" / "experiments" / "p1" / "p1_folds.json"
SPLITS_DIR = FV_DIR / "splits"


def synthetic(
    row_id: str,
    label: int,
    *,
    entity: str,
    episode: str | None = None,
    attack: str | None = None,
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
        features=(1.0, 2.0, 3.0, 4.0, 5.0),
    )


# ------------------------------------------------------------- A' construction


def test_a_prime_removes_only_shared_entity_positives() -> None:
    train = (
        synthetic("t1", 1, entity="shared", episode="hulk|shared|000", attack="hulk"),
        synthetic("t2", 1, entity="kept", episode="ares|kept|000", attack="ares"),
        synthetic("t3", 0, entity="benign1"),
    )
    test = (
        synthetic("e1", 1, entity="shared", episode="ddos|shared|000", attack="ddos"),
        synthetic("e2", 0, entity="benign2"),
    )
    data = FoldData("A_historical", 3, "ddos", train, test)
    assert shared_attack_entities(data) == ("shared",)
    prime, removal = build_a_prime(data)
    assert removal.removed_row_ids == ("t1",)
    assert [r.row_id for r in prime.train] == ["t2", "t3"]
    assert prime.test == data.test
    assert removal.removed_by_attack_type == {"hulk": 1}


def test_a_prime_keeps_negatives_and_test_untouched() -> None:
    train = (
        synthetic("t1", 1, entity="shared", episode="a|shared|000", attack="a"),
        synthetic("t2", 1, entity="kept", episode="b|kept|000", attack="b"),
        synthetic("n1", 0, entity="benign1"),
        synthetic("n2", 0, entity="benign2"),
    )
    test = (synthetic("e1", 1, entity="shared", episode="c|shared|000", attack="c"),
            synthetic("n3", 0, entity="benign3"))
    data = FoldData("A_historical", 2, "c", train, test)
    prime, removal = build_a_prime(data)
    diagnostic = removal_diagnostic(data, prime, removal)
    assert diagnostic["negatives_unchanged"] is True
    assert diagnostic["test_is_byte_identical"] is True
    assert diagnostic["train_negatives_before"] == diagnostic["train_negatives_after"] == 2
    assert diagnostic["shared_entities_still_present_in_test"] is True
    assert diagnostic["shared_entities_absent_from_A_prime_train_positives"] is True


def test_a_prime_preserves_the_canonical_training_order() -> None:
    rows = canonical_order(
        [
            synthetic("b", 1, entity="shared", episode="x|shared|000", attack="x"),
            synthetic("c", 1, entity="kept", episode="y|kept|000", attack="y"),
            synthetic("a", 0, entity="benign"),
        ]
    )
    data = FoldData(
        "A_historical",
        2,
        "z",
        tuple(rows),
        (synthetic("t", 1, entity="shared", episode="z|shared|000", attack="z"),
         synthetic("tn", 0, entity="benign2")),
    )
    prime, _ = build_a_prime(data)
    assert [r.row_id for r in prime.train] == ["a", "c"]


def test_a_prime_refuses_a_fold_without_shared_entity() -> None:
    train = (synthetic("t1", 1, entity="one", episode="a|one|000", attack="a"),)
    test = (synthetic("e1", 1, entity="two", episode="b|two|000", attack="b"),
            synthetic("n", 0, entity="benign"))
    with pytest.raises(LeakageExperimentError, match="no shared attack entity"):
        build_a_prime(FoldData("A_historical", 0, "b", train, test))


def test_configuration_forbids_over_claiming() -> None:
    configuration = experiment_configuration()
    assert configuration["folds"] == [2, 3, 4]
    assert configuration["randomness_added"] is False
    assert configuration["hyperparameter_tuning"] == "none"
    assert configuration["postgresql_connections"] == 0
    assert configuration["feature_names"] == list(FEATURE_NAMES)
    assert configuration["training_order"] == TRAINING_ORDER
    joined = " ".join(configuration["forbidden_claims"])
    assert "explains, or fails to explain" in joined
    assert "not identity leakage isolated" in configuration["known_coupling"]


def test_no_postgresql_and_no_rng_in_the_leakage_module() -> None:
    source = inspect.getsource(fvl)
    for forbidden in (
        "psycopg",
        "get_monday_benign_connection",
        "SELECT ",
        "cursor",
        "import random",
        "np.random",
        "default_rng",
        "shuffle",
    ):
        assert forbidden not in source, forbidden


# ------------------------------------------------------- real folds, determinism


@pytest.fixture(scope="module")
def real_folds():
    return build_folds()


def test_target_folds_are_exactly_the_leaking_historical_folds(real_folds) -> None:
    assert set(real_folds) == set(TARGET_FOLDS) == {2, 3, 4}
    for fold, data in real_folds.items():
        assert shared_attack_entities(data), fold


def test_real_diagnostics_pass_every_guard(real_folds) -> None:
    expected_removed = {2: 39, 3: 44, 4: 50}
    for fold, data in real_folds.items():
        prime, removal = build_a_prime(data)
        diagnostic = removal_diagnostic(data, prime, removal)
        assert diagnostic["positive_rows_removed_from_train"] == expected_removed[fold]
        assert diagnostic["test_is_byte_identical"] is True
        assert diagnostic["negatives_unchanged"] is True
        assert diagnostic["held_out_family_absent_from_train_A_prime"] is True
        assert diagnostic["shared_entities_absent_from_A_prime_train_positives"] is True
        assert diagnostic["shared_entities_still_present_in_test"] is True
        assert diagnostic["train_positives_after"] > 0


def test_test_population_is_byte_identical_between_a_and_a_prime(real_folds) -> None:
    for data in real_folds.values():
        prime, _ = build_a_prime(data)
        assert [r.row_id for r in prime.test] == [r.row_id for r in data.test]
        assert prime.test == data.test


def test_shared_entities_absent_from_train_positives_present_in_test(real_folds) -> None:
    for data in real_folds.values():
        prime, removal = build_a_prime(data)
        train_positive_entities = {r.entity_key for r in prime.train if r.label == 1}
        test_positive_entities = {r.entity_key for r in prime.test if r.label == 1}
        for entity in removal.shared_entities:
            assert entity not in train_positive_entities
            assert entity in test_positive_entities


def test_features_are_exactly_the_five_frozen_ones(real_folds) -> None:
    assert FEATURE_NAMES == (
        "event_count",
        "source_packets_total",
        "destination_packets_total",
        "source_bytes_total",
        "destination_bytes_total",
    )
    for data in real_folds.values():
        prime, _ = build_a_prime(data)
        assert all(len(r.features) == 5 for r in prime.train)
        assert all(len(r.features) == 5 for r in prime.test)


@pytest.fixture(scope="module")
def fold2_pair(real_folds):
    data = real_folds[2]
    prime, _ = build_a_prime(data)
    guards = fold_guards(prime, require_entity_disjoint=True, require_episode_disjoint=True)
    return prime, guards


def test_a_prime_is_deterministic(fold2_pair) -> None:
    prime, guards = fold2_pair
    first = evaluate_fold(prime, guards)
    second = evaluate_fold(prime, guards)
    for key in COMPARED_METRICS:
        assert first[key] == second[key], key
    assert first["test_scores"] == second["test_scores"]
    assert first["training_order"] == TRAINING_ORDER


def test_a_prime_threshold_uses_train_negatives_only(fold2_pair) -> None:
    prime, guards = fold2_pair
    baseline = evaluate_fold(prime, guards)
    flipped = FoldData(
        prime.protocol,
        prime.fold,
        prime.held_out,
        prime.train,
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
            for r in prime.test
        ),
    )
    altered = evaluate_fold(flipped, guards)
    assert altered["threshold"] == baseline["threshold"]


def test_a_prime_is_entity_disjoint_after_removal(fold2_pair) -> None:
    _, guards = fold2_pair
    assert guards["entity_intersection_count"] == 0
    assert guards["episode_intersection_count"] == 0


def test_delta_is_signed_a_prime_minus_a() -> None:
    a = {key: 1.0 for key in COMPARED_METRICS}
    prime = {key: 2.0 for key in COMPARED_METRICS}
    result = delta(a, prime)
    assert all(value == 1.0 for value in result["delta"].values())


# ------------------------------------------------------------ frozen artifacts


def test_production_dataset_is_unchanged() -> None:
    assert sha256(DATASET.read_bytes()).hexdigest() == (
        "e95aed008d994510e4c649c287feb8fe8f49a785bec144d7e83aa15804b6c062"
    )


def test_p1_folds_is_unchanged() -> None:
    assert sha256(P1_FOLDS.read_bytes()).hexdigest() == (
        "57e688fd3da90911707d7a172c161686d852094121eda1ac49e0221fc0529fa1"
    )


def test_step1_split_artifacts_are_unchanged() -> None:
    manifest = json.loads((SPLITS_DIR / "splits_manifest.json").read_text("utf-8"))
    for name, digest in manifest["outputs"].items():
        assert sha256((SPLITS_DIR / name).read_bytes()).hexdigest() == digest, name


def test_step2_artifacts_are_unchanged() -> None:
    manifest = json.loads(
        (FV_DIR / "evaluation_manifest.json").read_text(encoding="utf-8")
    )
    for name, digest in manifest["outputs"].items():
        assert sha256((FV_DIR / name).read_bytes()).hexdigest() == digest, name


# --------------------------------------------------------- published artifacts


published = pytest.mark.skipif(
    not MANIFEST_PATH.exists(), reason="step 3 artifacts not yet published"
)


@published
def test_published_outputs_match_the_manifest() -> None:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    for name, digest in manifest["outputs"].items():
        assert sha256((OUT_DIR / name).read_bytes()).hexdigest() == digest, name
    assert manifest["models_fitted"] == 6
    assert manifest["postgresql_connections"] == 0
    assert manifest["postgresql_writes"] == 0
    assert manifest["randomness_added"] is False
    assert manifest["hyperparameter_tuning"] == "none"
    assert manifest["threshold_selected_on_test"] is False
    assert manifest["step1_artifacts_modified"] is False
    assert manifest["step2_artifacts_modified"] is False
    assert manifest["recomputed_A_matches_published_step2"] is True


@published
def test_recomputed_a_equals_published_step2_values() -> None:
    published_a = {
        int(f["fold"]): f
        for f in json.loads(BASELINE_PATH.read_text(encoding="utf-8"))["protocols"][
            "A_historical"
        ]["folds"]
    }
    for fold in TARGET_FOLDS:
        document = json.loads((OUT_DIR / f"ap_fold{fold}.json").read_text("utf-8"))
        reference = published_a[fold]
        for key in ("roc_auc", "pr_auc", "threshold", "fpr", "tp", "fp", "tn", "fn"):
            assert document["A"][key] == reference[key], (fold, key)
        assert document["consistency_with_step2"][
            "recomputed_A_matches_published_step2"
        ] is True


@published
def test_published_diagnostic_records_the_family_coupling() -> None:
    document = json.loads(DIAGNOSTIC_PATH.read_text(encoding="utf-8"))
    by_fold = {entry["fold"]: entry for entry in document["folds"]}
    assert by_fold[2]["families_fully_emptied_from_train_by_the_removal"] == []
    assert by_fold[3]["families_fully_emptied_from_train_by_the_removal"] == ["dos/hulk"]
    assert by_fold[4]["families_fully_emptied_from_train_by_the_removal"] == ["ddos/loit"]
    assert document["models_fitted"] == 0


@published
def test_published_comparison_reports_every_metric_and_direction() -> None:
    document = json.loads(COMPARISON_PATH.read_text(encoding="utf-8"))
    assert document["folds"] == [2, 3, 4]
    assert set(document["per_fold_direction"]) == {"2", "3", "4"}
    for row in document["table"]:
        for key in COMPARED_METRICS:
            assert f"A_{key}" in row and f"Aprime_{key}" in row
    assert "not identity leakage isolated" in document["known_coupling"]


@published
def test_published_config_matches_the_executable_definition() -> None:
    assert json.loads(CONFIG_PATH.read_text(encoding="utf-8")) == (
        experiment_configuration()
    )


@published
def test_published_report_states_the_scope_limit() -> None:
    text = (OUT_DIR / "AP_IDENTITY_LEAKAGE_REPORT.md").read_text(encoding="utf-8")
    assert "does not state that leakage explains" in text
    assert "marginal effect" in text
