"""Regression tests for the ARM F ratification and the ARM J1 hybrid.

These tests never fit a model and never touch PostgreSQL. They pin the
pre-registered protocol, the verdict logic and the integrity of the published
artifacts, so a later edit cannot silently loosen a rule or restate a verdict.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path

import numpy as np
import pytest

from modules.detection.src.experiments.p1_dataset import FORBIDDEN_COLUMNS, Row
from modules.detection.src.experiments.ratification import (
    ARM_A_FEATURES,
    ARM_F_FEATURES,
    ARM_J1_FEATURES,
    CO_PRIMARY_ENDPOINT,
    NON_PRINTABLE_FEATURES,
    PRE_REGISTRATION,
    PRIMARY_ENDPOINT,
    PRIMARY_TARGET,
    RATIFICATION_ARMS,
    RATIFICATION_FPR_TARGETS,
    VOLUMETRIC_FEATURE,
    RatificationError,
    classify_paired,
    equal_alert_budget_diagnostic,
    pre_registration_digest,
    ratify_arm_f,
    verify_arm_budgets,
)

ROOT = Path(__file__).resolve().parents[3]
OUT = ROOT / "artifacts" / "experiments" / "armf_ratification_armj1"


# --- 1. The pre-registered protocol is exactly what was agreed --------------


def test_only_three_arms_are_registered() -> None:
    assert sorted(RATIFICATION_ARMS) == ["A", "F", "J1"]


def test_arm_budgets_are_exactly_the_agreed_ones() -> None:
    assert ARM_A_FEATURES == ("distinct_payload_ratio",)
    assert ARM_F_FEATURES == ("distinct_payload_ratio", *NON_PRINTABLE_FEATURES)
    assert NON_PRINTABLE_FEATURES == (
        "source_non_printable_ratio",
        "destination_non_printable_ratio",
    )
    assert VOLUMETRIC_FEATURE == "interarrival_mean"


def test_arm_j1_is_arm_f_plus_exactly_one_volumetric_feature() -> None:
    assert ARM_J1_FEATURES == (*ARM_F_FEATURES, VOLUMETRIC_FEATURE)
    assert len(ARM_J1_FEATURES) == len(ARM_F_FEATURES) + 1
    assert set(ARM_F_FEATURES) < set(ARM_J1_FEATURES)


def test_no_j2_or_j3_variant_is_present() -> None:
    """J2 and J3 were explicitly excluded; no arm may carry their features."""
    every = {f for features in RATIFICATION_ARMS.values() for f in features}
    assert "bytes_per_packet_destination" not in every


def test_five_operating_points_are_pre_registered_in_order() -> None:
    assert RATIFICATION_FPR_TARGETS == (0.01, 0.005, 0.002, 0.001, 0.0005)
    assert PRIMARY_TARGET == 0.01
    assert PRIMARY_TARGET in RATIFICATION_FPR_TARGETS


def test_endpoints_are_the_declared_ones() -> None:
    assert PRIMARY_ENDPOINT == "botnet/ares"
    assert CO_PRIMARY_ENDPOINT == "brute_force/ssh_patator"


def test_no_arm_uses_a_forbidden_column() -> None:
    every = {f for features in RATIFICATION_ARMS.values() for f in features}
    assert not (every & set(FORBIDDEN_COLUMNS))


def test_no_arm_uses_a_presence_indicator() -> None:
    every = {f for features in RATIFICATION_ARMS.values() for f in features}
    assert not any(f.endswith("_present") for f in every)


def test_budget_verification_passes_and_is_exhaustive() -> None:
    checks = verify_arm_budgets()
    assert all(c["passed"] for c in checks)
    assert len(checks) == 9


def test_pre_registration_digest_is_stable_and_formatting_independent() -> None:
    first = pre_registration_digest()
    reserialised = json.loads(json.dumps(PRE_REGISTRATION))
    second = sha256(
        json.dumps(reserialised, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    assert first == second


def test_pre_registration_forbids_tuning_and_postgres_writes() -> None:
    forbidden = " ".join(PRE_REGISTRATION["forbidden"]).lower()
    assert "tuning" in forbidden
    assert "postgresql writes" in forbidden
    assert "label modification" in forbidden


def test_equal_alert_budget_is_declared_non_ratifying() -> None:
    assert "may never ratify" in PRE_REGISTRATION["equal_alert_budget_status"]


# --- 2. The verdict rule is fixed and cannot drift with results -------------


def _paired(low: float, high: float, point: float = 0.0) -> dict[str, float]:
    return {"ci_low": low, "ci_high": high, "point": point}


def test_supported_requires_all_three_conditions() -> None:
    point_a = {"episode_recall": 0.325, "observed_test_fpr": 0.009874}
    point_f = {"episode_recall": 0.525, "observed_test_fpr": 0.007187}
    verdict = ratify_arm_f(point_a, point_f, _paired(0.075, 0.325, 0.2))
    assert verdict["verdict"] == "SUPPORTED"


def test_higher_recall_at_a_worse_fpr_is_not_supported() -> None:
    """Pareto dominance is required; buying recall with false alerts is not enough."""
    point_a = {"episode_recall": 0.325, "observed_test_fpr": 0.009}
    point_f = {"episode_recall": 0.525, "observed_test_fpr": 0.020}
    verdict = ratify_arm_f(point_a, point_f, _paired(0.075, 0.325, 0.2))
    assert verdict["verdict"] == "INCONCLUSIVE"
    assert verdict["conditions"]["realised_fpr_not_above_arm_a"] is False


def test_an_interval_touching_zero_is_not_supported() -> None:
    point_a = {"episode_recall": 0.325, "observed_test_fpr": 0.009}
    point_f = {"episode_recall": 0.375, "observed_test_fpr": 0.007}
    verdict = ratify_arm_f(point_a, point_f, _paired(0.0, 0.125, 0.05))
    assert verdict["verdict"] == "INCONCLUSIVE"


def test_a_strictly_negative_interval_is_not_supported_verdict() -> None:
    point_a = {"episode_recall": 0.325, "observed_test_fpr": 0.009}
    point_f = {"episode_recall": 0.000, "observed_test_fpr": 0.007}
    verdict = ratify_arm_f(point_a, point_f, _paired(-0.475, -0.199, -0.325))
    assert verdict["verdict"] == "NOT SUPPORTED"


def test_equal_recall_is_not_supported() -> None:
    point_a = {"episode_recall": 0.325, "observed_test_fpr": 0.009}
    point_f = {"episode_recall": 0.325, "observed_test_fpr": 0.007}
    verdict = ratify_arm_f(point_a, point_f, _paired(0.0, 0.0, 0.0))
    assert verdict["verdict"] == "INCONCLUSIVE"


@pytest.mark.parametrize(
    ("low", "high", "expected"),
    [
        (0.05, 0.30, "improved"),
        (-0.30, -0.05, "degraded"),
        (0.0, 0.30, "indistinguishable"),
        (-0.30, 0.0, "indistinguishable"),
        (-0.10, 0.10, "indistinguishable"),
    ],
)
def test_paired_direction_classification(low: float, high: float, expected: str) -> None:
    assert classify_paired(_paired(low, high)) == expected


# --- 3. The equal-alert-budget diagnostic behaves and stays non-ratifying ---


def _row(row_id: str, label: int, episode: str | None) -> Row:
    return Row(
        row_id=row_id,
        source="test",
        label=label,
        disposition="attack" if label else "benign_reference",
        attack_type="botnet/ares" if label else None,
        entity_key="e",
        episode_id=episode,
        partition="p",
        window_start_epoch=0,
        features=(0.0,),
    )


def test_equal_alert_budget_flags_exactly_the_budget_and_is_non_ratifying() -> None:
    rows = [_row(f"r{i}", 1 if i < 2 else 0, f"ep{i}" if i < 2 else None) for i in range(6)]
    scores = np.asarray([0.9, 0.1, 0.8, 0.7, 0.2, 0.3])
    out = equal_alert_budget_diagnostic(rows, scores, budget=2)
    assert out["alert_budget"] == 2
    assert out["ratifying"] is False
    # top two scores are r0 (positive, ep0) and r2 (negative)
    assert out["episodes_detected"] == 1
    assert out["episodes"] == 2


def test_equal_alert_budget_rejects_an_impossible_budget() -> None:
    rows = [_row("r0", 1, "ep0")]
    with pytest.raises(RatificationError):
        equal_alert_budget_diagnostic(rows, np.asarray([0.5]), budget=0)
    with pytest.raises(RatificationError):
        equal_alert_budget_diagnostic(rows, np.asarray([0.5]), budget=2)


# --- 4. Published artifact integrity ---------------------------------------

pytestmark_artifacts = pytest.mark.skipif(
    not (OUT / "manifest.json").exists(), reason="ratification run not yet published"
)


@pytestmark_artifacts
def test_every_published_output_matches_its_digest() -> None:
    manifest = json.loads((OUT / "manifest.json").read_text(encoding="utf-8"))
    bad = [
        name
        for name, digest in manifest["outputs"].items()
        if sha256((OUT / name).read_bytes()).hexdigest() != digest
    ]
    assert not bad, bad


@pytestmark_artifacts
def test_manifest_asserts_the_frozen_chain_was_not_modified() -> None:
    manifest = json.loads((OUT / "manifest.json").read_text(encoding="utf-8"))
    for key in (
        "p1_population_or_folds_modified",
        "frozen_ad_benchmark_modified",
        "six_arm_content_benchmark_modified",
        "published_baseline_modified",
    ):
        assert manifest[key] is False
    assert manifest["postgresql_writes"] == 0
    assert manifest["models_fitted"] == 15


@pytestmark_artifacts
def test_published_pre_registration_matches_the_module() -> None:
    published = json.loads((OUT / "PRE_REGISTRATION.json").read_text(encoding="utf-8"))
    assert published == PRE_REGISTRATION
    manifest = json.loads((OUT / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["pre_registration_sha256"] == pre_registration_digest()


@pytestmark_artifacts
def test_arm_a_and_arm_f_reproduce_the_frozen_content_benchmark_scores() -> None:
    """The ratification run must not have changed the published score streams."""
    content = ROOT / "artifacts" / "experiments" / "xgboost_content_benchmark"
    for arm in ("A", "F"):
        for fold in range(5):
            produced = (OUT / f"predictions_{arm}_fold{fold}.csv").read_text("utf-8")
            frozen = (content / f"predictions_{arm}_fold{fold}.csv").read_text("utf-8")
            produced_rows = [line.split(",") for line in produced.strip().split("\n")[1:]]
            frozen_rows = [line.split(",") for line in frozen.strip().split("\n")[1:]]
            assert len(produced_rows) == len(frozen_rows)
            for p, f in zip(produced_rows, frozen_rows):
                # row_id, label and score must agree; column order is identical
                assert (p[2], p[3], p[7]) == (f[2], f[3], f[7])


@pytestmark_artifacts
def test_arm_f_verdict_is_recorded_and_derived_from_the_ratified_rule() -> None:
    comparison = json.loads((OUT / "comparison.json").read_text(encoding="utf-8"))
    verdict = comparison["arm_f_ratification"]
    recomputed = ratify_arm_f(
        {
            "episode_recall": verdict["observed"]["arm_a_episode_recall"],
            "observed_test_fpr": verdict["observed"]["arm_a_observed_test_fpr"],
        },
        {
            "episode_recall": verdict["observed"]["arm_f_episode_recall"],
            "observed_test_fpr": verdict["observed"]["arm_f_observed_test_fpr"],
        },
        {
            "ci_low": verdict["observed"]["paired_delta_ci"][0],
            "ci_high": verdict["observed"]["paired_delta_ci"][1],
            "point": verdict["observed"]["paired_delta_point"],
        },
    )
    assert recomputed["verdict"] == verdict["verdict"]


@pytestmark_artifacts
def test_the_curve_covers_every_registered_point_for_every_arm() -> None:
    comparison = json.loads((OUT / "comparison.json").read_text(encoding="utf-8"))
    curve = comparison["operating_point_curve"]
    assert len(curve) == 5  # five leave-one-attack-type-out folds
    for per_target in curve.values():
        assert sorted(per_target) == sorted(
            f"target_{t}" for t in RATIFICATION_FPR_TARGETS
        )
        for arms in per_target.values():
            assert sorted(arms) == ["A", "F", "J1"]


@pytestmark_artifacts
def test_equal_alert_budget_diagnostic_is_marked_non_ratifying_in_the_artifact() -> None:
    comparison = json.loads((OUT / "comparison.json").read_text(encoding="utf-8"))
    for entry in comparison["equal_alert_budget_diagnostic"].values():
        assert entry["ratifying"] is False
        for arm in entry["arms"].values():
            assert arm["ratifying"] is False
