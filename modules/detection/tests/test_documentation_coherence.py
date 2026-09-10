"""Coherence tests between the documentation and the published artifacts.

`README.md` and `docs/PROJECT_INDEX.md` are the authoritative human-readable
status. Every figure they quote must match the artifacts, and the scientific
distinctions established during the validation must not be flattened.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
README = ROOT / "README.md"
INDEX = ROOT / "docs" / "PROJECT_INDEX.md"
FV = ROOT / "artifacts" / "experiments" / "final_validation"
PRODUCTION = ROOT / "artifacts" / "production" / "ml_dataset_v1"

DATASET_SHA256 = "e95aed008d994510e4c649c287feb8fe8f49a785bec144d7e83aa15804b6c062"


@pytest.fixture(scope="module")
def readme() -> str:
    return README.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def index() -> str:
    return INDEX.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def documents() -> str:
    return README.read_text(encoding="utf-8") + INDEX.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def artifacts() -> dict:
    return {
        "production": json.loads(
            (PRODUCTION / "dataset_manifest.json").read_text(encoding="utf-8")
        ),
        "baseline": json.loads(
            (FV / "baseline_metrics.json").read_text(encoding="utf-8")
        ),
        "zero_day": json.loads((FV / "zero_day_ares.json").read_text(encoding="utf-8")),
        "armf_zero_day": json.loads(
            (FV / "armf_extension" / "armf_zero_day.json").read_text(encoding="utf-8")
        ),
        "armf_metrics": json.loads(
            (FV / "armf_extension" / "armf_metrics.json").read_text(encoding="utf-8")
        ),
        "report_manifest": json.loads(
            (FV / "report_manifest.json").read_text(encoding="utf-8")
        ),
    }


# ---------------------------------------------------------- no stale statements


def test_no_document_still_claims_the_ml_dataset_is_unimplemented(documents) -> None:
    for stale in (
        "Label materialization | **NOT IMPLEMENTED**",
        "ML dataset | **NOT IMPLEMENTED**",
        "Label materialization on the main chain | **Not implemented**",
        "ML dataset for production use / training beyond P1 | **NOT IMPLEMENTED**",
        "Label materialization — NOT IMPLEMENTED",
        "ML dataset — NOT IMPLEMENTED",
        "ML dataset NOT CREATED",
        "any ML dataset beyond the P1 population are **not implemented**",
    ):
        assert stale not in documents, stale


def test_mb_track_is_no_longer_described_as_unimplemented(index) -> None:
    assert "designed but not implemented" not in index
    assert "is implemented and verified through MB-LABEL" in index


# ------------------------------------------------------------- production facts


def test_production_counts_quoted_in_documentation_match_the_manifest(
    documents, artifacts
) -> None:
    counts = artifacts["production"]["observed_counts"]
    assert "70,954" in documents
    assert f"{counts['attack_rows']} attack" in documents
    assert "70,578 benign" in documents
    assert "172,372" in documents
    assert "199 `target_attack`" in documents
    assert "177 `known_other_attack`" in documents


def test_dataset_digest_quoted_in_documentation_is_current(documents) -> None:
    assert DATASET_SHA256 in documents
    assert sha256((PRODUCTION / "ml_dataset.csv").read_bytes()).hexdigest() == (
        DATASET_SHA256
    )


def test_documentation_states_zero_writes_and_no_m7_schema(documents) -> None:
    assert "zero PostgreSQL writes" in documents or "PostgreSQL writes | **0**" in documents
    assert "`m7_*` schema" in documents


def test_label_policy_is_stated_with_the_exclusion_rule(documents) -> None:
    assert "never negative" in documents or "never negatives" in documents
    assert "excluded" in documents


# ---------------------------------------------------- validation distinctions


def test_protocol_a_is_never_called_a_reproduction(documents) -> None:
    assert "deterministic reimplementation" in documents
    assert "not a reproduction of P1" in documents or "not a reproduction" in documents
    assert "A reproduces P1 exactly" not in documents


def test_d1_and_d2_are_documented_separately(index) -> None:
    assert "**D1**" in index and "**D2**" in index
    assert "frozen P1 model re-scored" in index
    assert "exact historical anchor" in index


def test_a_prime_is_documented_without_causal_attribution(index) -> None:
    assert "**A′**" in index
    assert "no causal attribution" in index or "not an isolated leakage measure" in index


def test_identifiability_of_the_feature_contrast_is_documented(index) -> None:
    assert "VOL5_XGB → ARMF_XGB" in index
    assert "pipeline comparison only" in index
    assert "identifies a feature-budget effect" in index


def test_vol5_and_arm_a_naming_is_disambiguated(index) -> None:
    assert "**VOL5**" in index
    assert "**ARM_A** remains reserved" in index
    assert "distinct_payload_ratio" in index
    assert "not the same object" in index


# ------------------------------------------------------- validation figures


def test_zero_day_figures_quoted_in_documentation_match_the_artifacts(
    documents, artifacts
) -> None:
    arms = artifacts["armf_zero_day"]["arms"]
    assert f"{arms['VOL5_XGB']['roc_auc']:.4f}" == "0.4470"
    assert f"{arms['ARMF_XGB']['roc_auc']:.4f}" == "0.9713"
    assert "0.4470" in documents
    assert "0.9713" in documents
    assert arms["VOL5_XGB"]["detected_episodes"] == 0
    assert arms["ARMF_XGB"]["detected_episodes"] == 21
    assert "**0/40**" in documents
    assert "**21/40**" in documents


def test_protocol_episode_counts_quoted_in_the_index_match_the_artifacts(
    index, artifacts
) -> None:
    baseline = artifacts["baseline"]["protocols"]
    expected = {
        "A_historical": "9/54",
        "B_entity_disjoint": "46/54",
        "C_episode_disjoint_botnet_ares": "40/40",
    }
    for protocol, quoted in expected.items():
        summary = baseline[protocol]["summary"]
        assert (
            f"{summary['detected_episodes']}/{summary['total_episodes']}" == quoted
        ), protocol
        assert quoted in index, protocol
    armf = artifacts["armf_metrics"]["arms"]
    for arm, protocol, quoted in (
        ("VOL5_XGB", "A_historical", "5/54"),
        ("ARMF_XGB", "A_historical", "26/54"),
        ("VOL5_ARMF_XGB", "A_historical", "21/54"),
        ("VOL5_XGB", "B_entity_disjoint", "43/54"),
        ("ARMF_XGB", "C_episode_disjoint_botnet_ares", "21/40"),
        ("VOL5_ARMF_XGB", "D_zero_day_ares", "16/40"),
    ):
        summary = armf[arm][protocol]["summary"]
        assert (
            f"{summary['detected_episodes']}/{summary['total_episodes']}" == quoted
        ), (arm, protocol)
        assert quoted in index, (arm, protocol)


def test_consistency_check_count_quoted_matches_the_report_manifest(
    documents, artifacts
) -> None:
    count = artifacts["report_manifest"]["consistency_checks"]
    assert count == 61
    assert f"{count} cross-artifact consistency checks" in documents or (
        f"**{count}** cross-artifact consistency checks" in documents
    )


def test_step_five_correction_of_step_four_is_documented(index) -> None:
    assert "corrects the Step 4 interpretation" in index
    assert "**both** a family-transfer limit **and** a representational limit" in index


def test_documentation_refuses_the_generalisation_claim(documents) -> None:
    assert "not a generalisation claim" in documents
    assert "single family" in documents
    assert "No generalisation to real traffic is demonstrated" in documents


def test_every_mandated_limit_appears_in_the_index(index) -> None:
    for fragment in (
        "376 attack windows",
        "9 entities",
        "54 episodes",
        "1:187.7",
        "day and capture confounding is not lifted",
        "172,372",
        "C SSH statistically weak",
        "unable to separate family from entity",
        "training row order was never specified",
    ):
        assert fragment in index, fragment


def test_temporal_persistence_negative_result_is_not_hidden(readme) -> None:
    assert "temporal_persistence" in readme
    assert "negative methodological result" in readme
    assert "21/40 episodes" in readme
    assert "99/13,774" in readme
