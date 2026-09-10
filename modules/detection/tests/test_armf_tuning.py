"""Regression tests for leak-free ARM F surrogate tuning.

No test here fits a model or opens PostgreSQL. The suite pins the pre-registration,
outer-test boundary, deterministic candidate list, selection rule and artifact
digests.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path

import pytest

from modules.detection.src.experiments.armf_tuning import (
    FINAL_EVALUATION_TARGETS,
    POOLED_VALIDATION_FPR_LIMIT,
    PRIMARY_TRAIN_FPR,
    RANDOM_CONFIGURATIONS,
    SEARCH_SEED,
    CandidateResult,
    candidate_configurations,
    formatting_independent_digest,
    preregistration_document,
    select_candidate,
)
from modules.detection.src.experiments.ratification import ARM_F_FEATURES

ROOT = Path(__file__).resolve().parents[3]
OUT = ROOT / "artifacts" / "experiments" / "xgboost_armf_tuning"
EXPECTED_PROTOCOL_SHA256 = "623e7521ecfefc7f60533f9e187c0880ae08295e22f4a21178e6a557f39c7ca6"


def test_feature_budget_is_exactly_frozen_arm_f() -> None:
    assert ARM_F_FEATURES == (
        "distinct_payload_ratio",
        "source_non_printable_ratio",
        "destination_non_printable_ratio",
    )


def test_search_seed_and_size_are_frozen() -> None:
    assert SEARCH_SEED == 20_260_826
    assert RANDOM_CONFIGURATIONS == 48
    configs = candidate_configurations()
    assert len(configs) == 49
    assert configs[0]["candidate_id"] == "P1_CONTROL"
    assert configs[-1]["candidate_id"] == "R048"
    assert len({json.dumps(c["params"], sort_keys=True) for c in configs}) == 49


def test_phase1_control_is_the_published_fixed_model() -> None:
    control = candidate_configurations()[0]
    assert control["early_stopping"] is False
    assert control["params"] == {
        "max_depth": 3,
        "learning_rate": 0.1,
        "max_n_estimators": 200,
        "reg_alpha": 0.0,
        "reg_lambda": 1.0,
        "min_child_weight": 1.0,
        "subsample": 1.0,
        "colsample_bytree": 1.0,
    }


def test_protocol_identity_is_stable() -> None:
    document = preregistration_document()
    assert formatting_independent_digest(document) == EXPECTED_PROTOCOL_SHA256
    assert formatting_independent_digest(json.loads(json.dumps(document))) == (
        EXPECTED_PROTOCOL_SHA256
    )


def test_outer_test_is_explicitly_forbidden_during_tuning() -> None:
    document = preregistration_document()
    assert document["outer_test"]["availability_during_tuning"] == "strictly forbidden"
    assert document["outer_test"]["opening"] == "once, after selection and final refit"
    assert document["tuning_pool"]["ares_rows"] == 0
    assert document["inner_folds"]["outer_test_overlap"] == 0


def test_surrogate_claim_cannot_be_relabelled_as_ares_optimisation() -> None:
    document = preregistration_document()
    assert document["surrogate_objective"]["ares_optimisation_claim"].startswith(
        "forbidden"
    )


def test_fpr_constraints_and_targets_are_frozen() -> None:
    document = preregistration_document()
    constraints = document["surrogate_objective"]["hard_constraints"]
    assert PRIMARY_TRAIN_FPR == 0.005
    assert POOLED_VALIDATION_FPR_LIMIT == 0.005
    assert constraints["pooled_validation_fpr_max"] == 0.005
    assert constraints["every_validation_fold_fpr_max"] == 0.01
    assert FINAL_EVALUATION_TARGETS == (0.01, 0.005, 0.002, 0.001, 0.0005)


def test_p1_fold0_test_is_fully_exposed_by_other_original_trains() -> None:
    """Pin the leakage finding that forced the nested construction."""
    folds = sorted(
        json.loads((ROOT / "artifacts/experiments/p1/p1_folds.json").read_text("utf-8")),
        key=lambda f: f["index"],
    )
    outer = set(folds[0]["test_row_ids"])
    assert len(outer) == 13_951
    for fold in folds[1:]:
        assert outer <= set(fold["train_row_ids"])


def test_leak_free_inner_validations_partition_fold0_train() -> None:
    folds = sorted(
        json.loads((ROOT / "artifacts/experiments/p1/p1_folds.json").read_text("utf-8")),
        key=lambda f: f["index"],
    )
    outer_train = set(folds[0]["train_row_ids"])
    outer_test = set(folds[0]["test_row_ids"])
    validations = [set(f["test_row_ids"]) & outer_train for f in folds[1:]]
    assert [len(v) for v in validations] == [14045, 14124, 14770, 14064]
    assert set().union(*validations) == outer_train
    assert all(not (v & outer_test) for v in validations)
    assert all(not (validations[i] & validations[j]) for i in range(4) for j in range(i))


def _candidate(candidate_id: str, *, feasible: bool, recall: float, pr: float) -> CandidateResult:
    return CandidateResult(
        candidate_id=candidate_id,
        params={
            "max_depth": 3,
            "learning_rate": 0.1,
            "max_n_estimators": 300,
            "reg_alpha": 0.0,
            "reg_lambda": 1.0,
            "min_child_weight": 1.0,
            "subsample": 1.0,
            "colsample_bytree": 1.0,
        },
        early_stopping=True,
        feasible=feasible,
        pooled_validation_fpr=0.001,
        max_fold_validation_fpr=0.002,
        macro_episode_recall=recall,
        minimum_family_episode_recall=0.1,
        macro_pr_auc=pr,
        final_n_estimators=30,
    )


def test_selection_ignores_an_infeasible_high_recall_candidate() -> None:
    infeasible = _candidate("BAD", feasible=False, recall=1.0, pr=1.0)
    feasible = _candidate("GOOD", feasible=True, recall=0.5, pr=0.5)
    assert select_candidate([infeasible, feasible]).candidate_id == "GOOD"


def test_selection_maximises_episode_recall_before_pr_auc() -> None:
    high_recall = _candidate("RECALL", feasible=True, recall=0.75, pr=0.2)
    high_pr = _candidate("PR", feasible=True, recall=0.5, pr=0.99)
    assert select_candidate([high_pr, high_recall]).candidate_id == "RECALL"


pytestmark_artifacts = pytest.mark.skipif(
    not (OUT / "manifest.json").exists(), reason="tuning run not yet published"
)


@pytestmark_artifacts
def test_published_preregistration_matches_executable_protocol() -> None:
    published = json.loads((OUT / "PRE_REGISTRATION.json").read_text("utf-8"))
    assert published["pre_registration_sha256"] == EXPECTED_PROTOCOL_SHA256
    assert published["protocol"] == preregistration_document()


@pytestmark_artifacts
def test_every_output_matches_its_manifest_digest() -> None:
    manifest = json.loads((OUT / "manifest.json").read_text("utf-8"))
    bad = [
        name
        for name, digest in manifest["outputs"].items()
        if sha256((OUT / name).read_bytes()).hexdigest() != digest
    ]
    assert not bad, bad


@pytestmark_artifacts
def test_manifest_proves_no_ares_or_outer_test_selection() -> None:
    manifest = json.loads((OUT / "manifest.json").read_text("utf-8"))
    assert manifest["outer_test_used_for_selection"] is False
    assert manifest["ares_rows_used_during_tuning"] == 0
    assert manifest["postgresql_writes"] == 0
    assert manifest["frozen_artifacts_modified"] is False
    assert manifest["candidates_evaluated"] == 49
    assert manifest["inner_models_fitted"] == 196
    assert manifest["final_models_fitted"] == 1


@pytestmark_artifacts
def test_published_selected_candidate_is_the_rule_derived_winner() -> None:
    document = json.loads((OUT / "search_results.json").read_text("utf-8"))
    assert document["selection_rule_applied_without_change"] is True
    assert document["selected_candidate_id"] == "R006"
    assert document["selected_candidate"]["feasible"] is True
    assert document["selected_candidate"]["macro_episode_recall"] == pytest.approx(
        0.7777777777777778
    )


@pytestmark_artifacts
def test_outer_transfer_result_was_not_used_to_change_the_search() -> None:
    document = json.loads((OUT / "transfer_comparison.json").read_text("utf-8"))
    assert "not direct Ares optimisation" in document["scientific_claim"]
    assert document["pre_registration_sha256"] == EXPECTED_PROTOCOL_SHA256


@pytestmark_artifacts
def test_primary_transfer_is_exactly_tied_at_seventeen_episodes() -> None:
    document = json.loads((OUT / "transfer_comparison.json").read_text("utf-8"))
    primary = document["comparison"]["primary_transfer_result"]
    assert primary["target_train_fpr"] == 0.005
    assert primary["phase1"]["episodes_detected"] == 17
    assert primary["tuned"]["episodes_detected"] == 17
    assert primary["paired_episode_delta"]["ci_low"] == 0.0
    assert primary["paired_episode_delta"]["ci_high"] == 0.0
