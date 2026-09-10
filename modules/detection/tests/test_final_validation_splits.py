"""Non-regression tests for final-validation Step 1 (split construction).

Nothing here fits a model or opens PostgreSQL. The suite pins determinism, the
absence of randomness, entity and episode disjointness, the reproduction of the
published historical protocol, and the immutability of every frozen input.
"""
from __future__ import annotations

import csv
from hashlib import sha256
import inspect
import json
from pathlib import Path

import pytest

from modules.detection.src.experiments import final_validation as fv
from modules.detection.src.experiments.final_validation import (
    ALWAYS_TRAIN,
    ARES_EPISODE_FOLD_COUNT,
    ARES_FAMILY,
    MODEL_FEATURE_COLUMNS,
    SPLIT_METADATA_COLUMNS,
    SSH_FAMILY,
    FinalValidationError,
    load_population,
    protocol_a_historical,
    protocol_b_entity_disjoint,
    protocol_c_episode_disjoint,
    protocol_d_zero_day_ares,
    verify_population,
    verify_protocol,
)
from modules.detection.src.experiments.p1_dataset import FEATURE_NAMES
from scripts.run_final_validation_splits import (
    EXPECTED_PRODUCTION_SHA256,
    HISTORICAL_FOLDS,
    MANIFEST_PATH,
    OUT_DIR,
    PRODUCTION_DATASET,
    assignment_bytes,
    build_context,
    compare_with_historical_folds,
    compare_zero_day_with_historical_fold0,
)

ROOT = Path(__file__).resolve().parents[3]
P1_DATASET = ROOT / "artifacts" / "experiments" / "p1" / "p1_dataset.csv"


@pytest.fixture(scope="module")
def population():
    with PRODUCTION_DATASET.open(newline="", encoding="utf-8") as stream:
        return load_population(csv.DictReader(stream))


@pytest.fixture(scope="module")
def index(population):
    return {row.row_id: row for row in population}


# ------------------------------------------------------- frozen inputs (7, 8, 9)


def test_production_dataset_sha256_is_unchanged() -> None:
    assert sha256(PRODUCTION_DATASET.read_bytes()).hexdigest() == (
        EXPECTED_PRODUCTION_SHA256
    )


def test_production_dataset_is_still_byte_identical_to_the_p1_population() -> None:
    assert PRODUCTION_DATASET.read_bytes() == P1_DATASET.read_bytes()


def test_frozen_population_expectations_hold(population) -> None:
    checks = verify_population(population)
    assert checks and all(check["passed"] for check in checks)
    assert len(population) == 70_954
    assert sum(1 for r in population if r.label == 1) == 376
    assert sum(1 for r in population if r.label == 0) == 70_578


# --------------------------------------------------- no features, no randomness


def test_split_construction_never_reads_a_model_feature_column() -> None:
    source = inspect.getsource(fv)
    for column in MODEL_FEATURE_COLUMNS:
        # The name may appear only inside the explicit forbidden-column tuple.
        assert source.count(f'"{column}"') == 1, column
    assert "features" not in {field for field in SPLIT_METADATA_COLUMNS}


def test_population_row_carries_no_feature_field(population) -> None:
    row = population[0]
    assert not hasattr(row, "features")
    assert set(vars(type(row))["__slots__"]) == set(SPLIT_METADATA_COLUMNS) - {
        "row_id"
    } | {"row_id"}


def test_no_random_number_generator_is_used() -> None:
    source = inspect.getsource(fv)
    for forbidden in ("import random", "np.random", "default_rng", "shuffle", "sample("):
        assert forbidden not in source, forbidden


def test_no_database_access_in_the_split_module() -> None:
    source = inspect.getsource(fv)
    for forbidden in ("psycopg", "get_monday_benign_connection", "SELECT ", "cursor"):
        assert forbidden not in source, forbidden


def test_feature_budget_and_order_are_untouched() -> None:
    assert FEATURE_NAMES == (
        "event_count",
        "source_packets_total",
        "destination_packets_total",
        "source_bytes_total",
        "destination_bytes_total",
    )


# ------------------------------------------------------------ protocol A and D


def test_protocol_a_reproduces_the_published_folds(population) -> None:
    protocol = protocol_a_historical(population)
    comparison = compare_with_historical_folds(protocol)
    assert comparison["identical_membership"] is True
    assert comparison["published_folds"] == 5
    assert comparison["differences"] == []


def test_protocol_a_is_not_entity_disjoint_and_says_so(population, index) -> None:
    """The historical protocol's real defect must stay visible, not be smoothed."""
    protocol = protocol_a_historical(population)
    _, statistics = verify_protocol(protocol, index)
    intersections = {s["fold"]: s["attack_entity_intersection"] for s in statistics}
    assert intersections[0] == [] and intersections[1] == []
    assert intersections[2] == ["172.16.0.1|192.168.10.50|tcp|none"]
    assert len(intersections[3]) == 2 and len(intersections[4]) == 2
    assert protocol.requires_entity_disjoint is False


def test_protocol_d_reproduces_published_fold_zero(population) -> None:
    protocol = protocol_d_zero_day_ares(population)
    comparison = compare_zero_day_with_historical_fold0(protocol)
    assert comparison["same_test_membership"] is True
    assert comparison["same_train_membership"] is True
    assert comparison["published_test_rows"] == 13_951


def test_zero_day_excludes_every_ares_window_from_training(population, index) -> None:
    protocol = protocol_d_zero_day_ares(population)
    _, statistics = verify_protocol(protocol, index)
    stat = statistics[0]
    assert stat["ares_windows_in_train"] == 0
    assert stat["ares_windows_in_test"] == 177
    assert len(stat["test_attack_episodes"]) == 40
    assert stat["train_rows"] == 57_003 and stat["test_rows"] == 13_951
    assert stat["entity_intersection"] == []


# ------------------------------------------------------------------ protocol B


def test_protocol_b_is_strictly_entity_disjoint(population, index) -> None:
    protocol = protocol_b_entity_disjoint(population)
    checks, statistics = verify_protocol(protocol, index)
    assert all(check["passed"] for check in checks)
    assert protocol.fold_count == 9
    for stat in statistics:
        assert stat["entity_intersection"] == []
        assert stat["benign_entity_intersection_count"] == 0
        assert stat["episode_intersection"] == []
        assert stat["test_positives"] > 0
    assert sum(s["test_positives"] for s in statistics) == 376


def test_protocol_b_tests_each_attack_entity_exactly_once(population, index) -> None:
    protocol = protocol_b_entity_disjoint(population)
    _, statistics = verify_protocol(protocol, index)
    tested = [e for stat in statistics for e in stat["test_attack_entities"]]
    assert len(tested) == 9 and len(set(tested)) == 9


# ------------------------------------------------------------------ protocol C


def test_protocol_c_ares_is_episode_disjoint_with_balanced_folds(population, index) -> None:
    protocol = protocol_c_episode_disjoint(population, ARES_FAMILY, ARES_EPISODE_FOLD_COUNT)
    checks, statistics = verify_protocol(protocol, index)
    assert all(check["passed"] for check in checks)
    assert [len(s["test_attack_episodes"]) for s in statistics] == [8, 8, 8, 8, 8]
    assert sum(s["test_positives"] for s in statistics) == 177
    for stat in statistics:
        assert stat["episode_intersection"] == []


def test_protocol_c_ares_cannot_be_entity_disjoint_and_reports_it(population, index) -> None:
    protocol = protocol_c_episode_disjoint(population, ARES_FAMILY, ARES_EPISODE_FOLD_COUNT)
    _, statistics = verify_protocol(protocol, index)
    assert protocol.requires_entity_disjoint is False
    assert any(stat["attack_entity_intersection"] for stat in statistics)
    assert any("entity-disjointness is NOT achievable" in note for note in protocol.notes)


def test_protocol_c_keeps_other_families_in_training_only(population, index) -> None:
    protocol = protocol_c_episode_disjoint(population, ARES_FAMILY, ARES_EPISODE_FOLD_COUNT)
    _, statistics = verify_protocol(protocol, index)
    for stat in statistics:
        assert set(stat["test_attack_type_windows"]) == {ARES_FAMILY}
        assert ARES_FAMILY in stat["train_attack_type_windows"]
    non_ares = [
        row.row_id
        for row in population
        if row.label == 1 and row.attack_type != ARES_FAMILY
    ]
    assert all(protocol.assignment[row_id] == ALWAYS_TRAIN for row_id in non_ares)


def test_protocol_c_ssh_is_leave_one_episode_out_and_degenerate(population, index) -> None:
    protocol = protocol_c_episode_disjoint(population, SSH_FAMILY, None)
    checks, statistics = verify_protocol(protocol, index)
    assert all(check["passed"] for check in checks)
    assert protocol.fold_count == 9
    counts = sorted(s["test_positives"] for s in statistics)
    # Eight SSH episodes contain a single window; one contains 52.
    assert counts == [1, 1, 1, 1, 1, 1, 1, 1, 52]


@pytest.mark.parametrize(
    "family", ["brute_force/ftp_patator", "ddos/loit", "dos/hulk"]
)
def test_protocol_c_is_refused_for_families_with_too_few_episodes(
    population, family
) -> None:
    episodes = len({r.episode_id for r in population if r.attack_type == family})
    if episodes < 2:
        with pytest.raises(FinalValidationError, match="no intra-family split"):
            protocol_c_episode_disjoint(population, family, None)
    else:
        # Buildable in principle, but excluded by the ratified eligibility rule.
        from scripts.run_final_validation_splits import episode_eligibility

        assert episode_eligibility(population)[family]["protocol_c_built"] is False


# ----------------------------------------------------------------- determinism


def test_two_independent_builds_produce_identical_assignments(population) -> None:
    first = [
        protocol_a_historical(population),
        protocol_b_entity_disjoint(population),
        protocol_c_episode_disjoint(population, ARES_FAMILY, ARES_EPISODE_FOLD_COUNT),
        protocol_c_episode_disjoint(population, SSH_FAMILY, None),
        protocol_d_zero_day_ares(population),
    ]
    second = [
        protocol_a_historical(population),
        protocol_b_entity_disjoint(population),
        protocol_c_episode_disjoint(population, ARES_FAMILY, ARES_EPISODE_FOLD_COUNT),
        protocol_c_episode_disjoint(population, SSH_FAMILY, None),
        protocol_d_zero_day_ares(population),
    ]
    for left, right in zip(first, second):
        assert left.key == right.key
        assert assignment_bytes(left) == assignment_bytes(right)


def test_row_order_does_not_change_the_assignment(population) -> None:
    reversed_population = list(reversed(population))
    assert assignment_bytes(protocol_a_historical(population)) == assignment_bytes(
        protocol_a_historical(reversed_population)
    )
    assert assignment_bytes(protocol_b_entity_disjoint(population)) == assignment_bytes(
        protocol_b_entity_disjoint(reversed_population)
    )


def test_build_context_declares_no_model_and_no_database() -> None:
    context = build_context()
    for document in context["documents"].values():
        assert document["model_feature_columns_read"] == []
        assert document["seed_used"] is None
        assert document["random_number_generator_used"] is False


# ------------------------------------------------------- published artifacts


published = pytest.mark.skipif(
    not MANIFEST_PATH.exists(), reason="splits not yet published"
)


@published
def test_published_outputs_match_the_manifest() -> None:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    for name, digest in manifest["outputs"].items():
        assert sha256((OUT_DIR / name).read_bytes()).hexdigest() == digest, name
    assert manifest["models_fitted"] == 0
    assert manifest["postgresql_connections"] == 0
    assert manifest["postgresql_writes"] == 0
    assert manifest["randomness_used"] is False
    assert manifest["seed_used"] is None
    assert manifest["production_dataset_modified"] is False


@published
def test_published_manifest_records_the_disjointness_outcome() -> None:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    protocols = manifest["protocols"]
    assert protocols["A_historical"]["max_entity_intersection"] == 2
    assert protocols["B_entity_disjoint"]["max_entity_intersection"] == 0
    assert protocols["D_zero_day_ares"]["max_entity_intersection"] == 0
    for key in protocols:
        assert protocols[key]["max_episode_intersection"] == 0


@published
def test_published_assignments_are_reproducible_from_the_frozen_population(
    population,
) -> None:
    builders = {
        "A_historical": lambda: protocol_a_historical(population),
        "B_entity_disjoint": lambda: protocol_b_entity_disjoint(population),
        "C_episode_disjoint_botnet_ares": lambda: protocol_c_episode_disjoint(
            population, ARES_FAMILY, ARES_EPISODE_FOLD_COUNT
        ),
        "C_episode_disjoint_brute_force_ssh_patator": lambda: protocol_c_episode_disjoint(
            population, SSH_FAMILY, None
        ),
        "D_zero_day_ares": lambda: protocol_d_zero_day_ares(population),
    }
    for key, builder in builders.items():
        published_bytes = (OUT_DIR / f"{key}_assignment.csv").read_bytes()
        assert published_bytes == assignment_bytes(builder()), key


@published
def test_no_frozen_input_changed_since_publication() -> None:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    for name, digest in manifest["frozen_inputs"].items():
        assert sha256((ROOT / name).read_bytes()).hexdigest() == digest, name
    assert sha256(HISTORICAL_FOLDS.read_bytes()).hexdigest() == (
        "57e688fd3da90911707d7a172c161686d852094121eda1ac49e0221fc0529fa1"
    )
