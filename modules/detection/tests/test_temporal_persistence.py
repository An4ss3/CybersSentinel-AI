"""Tests for the additive ARM F two-hit temporal-persistence experiment."""
from __future__ import annotations

from dataclasses import fields
from hashlib import sha256
import json
from pathlib import Path

import pytest

from modules.detection.src.experiments.temporal_persistence import (
    CALIBRATION_FOLDS,
    MAX_GAP_SECONDS,
    ScoreWindow,
    apply_temporal_rule,
    calibrate_highest_feasible_threshold,
    pseudoepisode_memberships,
)
from scripts.run_temporal_persistence import (
    CALIBRATION_PATH,
    EXPECTED_BASELINE,
    MANIFEST_PATH,
    OUT_DIR,
    PRE_REGISTRATION_PATH,
    RESULTS_PATH,
    canonical_digest,
    preregistration_document,
    verify_baseline,
)


def window(row_id: str, entity: str, epoch: int, score: float) -> ScoreWindow:
    return ScoreWindow(row_id, entity, epoch, score)


def test_rule_alerts_only_on_second_consecutive_window() -> None:
    values = [window("a", "entity", 60, 0.2), window("b", "entity", 120, 0.2)]
    decisions = apply_temporal_rule(values, official_threshold=0.8, persistence_threshold=0.1)
    assert not decisions["a"].alert
    assert decisions["b"].persistence_alert
    assert decisions["b"].previous_row_id == "a"
    assert decisions["b"].delta_seconds == MAX_GAP_SECONDS


def test_three_high_windows_form_two_overlapping_adjacent_pairs() -> None:
    """Exactly two means a sliding adjacent pair, not a one-alert latch."""
    values = [
        window("a", "entity", 60, 0.2),
        window("b", "entity", 120, 0.2),
        window("c", "entity", 180, 0.2),
    ]
    decisions = apply_temporal_rule(
        values, official_threshold=0.8, persistence_threshold=0.1
    )
    assert not decisions["a"].persistence_alert
    assert decisions["b"].persistence_alert
    assert decisions["c"].persistence_alert
    assert decisions["c"].previous_row_id == "b"


def test_rule_rejects_zero_or_over_sixty_second_gaps_and_other_entities() -> None:
    values = [
        window("a", "one", 60, 0.2),
        window("b", "one", 121, 0.2),
        window("c", "two", 180, 0.2),
        window("d", "three", 180, 0.2),
    ]
    decisions = apply_temporal_rule(values, official_threshold=0.8, persistence_threshold=0.1)
    assert not any(value.persistence_alert for value in decisions.values())


def test_baseline_or_is_preserved_without_temporal_predecessor() -> None:
    decisions = apply_temporal_rule(
        [window("a", "entity", 60, 0.9)],
        official_threshold=0.8,
        persistence_threshold=0.95,
    )
    assert decisions["a"].baseline_alert
    assert decisions["a"].alert
    assert not decisions["a"].persistence_alert


def test_operational_window_has_no_label_family_host_or_service_fields() -> None:
    assert [value.name for value in fields(ScoreWindow)] == [
        "row_id",
        "entity_key",
        "window_start_epoch",
        "score",
    ]


def test_pseudoepisodes_are_observable_entity_runs() -> None:
    episodes = pseudoepisode_memberships(
        [
            window("a", "one", 60, 0.1),
            window("b", "one", 120, 0.1),
            window("c", "one", 240, 0.1),
            window("d", "two", 240, 0.1),
        ]
    )
    assert set(episodes) == {("a", "b"), ("c",), ("d",)}


def test_calibration_literal_rule_selects_highest_feasible_observed_score() -> None:
    by_fold: dict[int, tuple[ScoreWindow, ...]] = {}
    for fold in CALIBRATION_FOLDS:
        values = [
            window(f"{fold}-high-1", f"entity-{fold}", 60, 0.4),
            window(f"{fold}-high-2", f"entity-{fold}", 120, 0.4),
        ]
        values.extend(
            window(f"{fold}-low-{i}", f"isolated-{fold}-{i}", 300, 0.0)
            for i in range(198)
        )
        by_fold[fold] = tuple(values)
    result, candidates = calibrate_highest_feasible_threshold(
        by_fold, {fold: 0.9 for fold in CALIBRATION_FOLDS}
    )
    assert candidates[-1] == 0.4
    assert result.threshold == candidates[-1]
    assert result.stable
    assert result.pooled_fpr == pytest.approx(0.005)


def test_preregistration_forbids_fold0_during_calibration() -> None:
    protocol = preregistration_document()
    assert protocol["calibration"]["folds"] == [1, 2, 3, 4]
    assert protocol["calibration"]["population"] == "benign OOF windows only"
    assert protocol["calibration"]["attack_rows_used"] == 0
    assert protocol["calibration"]["ares_prediction_file_opened"] is False
    assert protocol["operational_rule"]["pair_size"] == 2
    assert protocol["claims"]["threshold_may_change_after_manifest"] is False


def test_frozen_baseline_is_reproduced_exactly() -> None:
    assert verify_baseline() == {
        **EXPECTED_BASELINE,
        "prediction_rows": 13_951,
        "rule_windows": 13_951,
    }


artifact_mark = pytest.mark.skipif(
    not CALIBRATION_PATH.exists(), reason="calibration has not been published"
)
final_mark = pytest.mark.skipif(
    not MANIFEST_PATH.exists(), reason="final evaluation has not been published"
)


@artifact_mark
def test_published_calibration_is_benign_only_and_frozen() -> None:
    document = json.loads(CALIBRATION_PATH.read_text(encoding="utf-8"))
    digest = document.pop("calibration_content_sha256")
    assert canonical_digest(document) == digest
    assert document["calibration_status"] == "PASS_FROZEN"
    assert document["calibration_access"]["prediction_folds_opened"] == [1, 2, 3, 4]
    assert document["calibration_access"]["fold0_prediction_opened"] is False
    assert document["calibration_access"]["attack_rows_used"] == 0
    assert document["threshold_frozen_no_posthoc_changes"] is True
    assert document["selected"]["threshold"] == document["candidate_maximum"]


@artifact_mark
def test_published_preregistration_matches_current_protocol() -> None:
    document = json.loads(PRE_REGISTRATION_PATH.read_text(encoding="utf-8"))
    assert document["protocol"] == preregistration_document()
    assert document["protocol_sha256"] == canonical_digest(preregistration_document())


@final_mark
def test_final_manifest_hashes_every_output() -> None:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    for name, digest in manifest["outputs"].items():
        assert sha256((OUT_DIR / name).read_bytes()).hexdigest() == digest
    assert manifest["threshold_changed_after_calibration"] is False
    assert manifest["fold0_opened_after_calibration_manifest"] is True
    assert manifest["models_fitted"] == 0
    assert manifest["frozen_artifacts_modified"] is False


@final_mark
def test_final_result_uses_the_frozen_calibration_threshold() -> None:
    calibration = json.loads(CALIBRATION_PATH.read_text(encoding="utf-8"))
    results = json.loads(RESULTS_PATH.read_text(encoding="utf-8"))
    assert results["persistence_threshold"] == calibration["selected"]["threshold"]
    assert results["operational_rule_uses_labels"] is False
    assert results["operational_rule_uses_attack_type"] is False
    # The published run used this legacy claim; the audit addendum narrows it to
    # "no IP/service-specific condition" because entity_key encodes the tuple.
    if "operational_rule_uses_ip_or_service" in results:
        assert results["operational_rule_uses_ip_or_service"] is False
    else:
        assert results["operational_rule_uses_ip_or_service_specific_condition"] is False
        assert results["entity_key_contains_network_tuple"] is True
    assert results["models_fitted"] == 0
