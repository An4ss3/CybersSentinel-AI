"""Non-regression tests for final-validation Step 5 (ARM F extension).

Fast tests pin the canonical definitions, the naming decisions and the guards.
Artifact tests read the published metrics. Database-backed tests are read-only
and skip cleanly when PostgreSQL is down.
"""
from __future__ import annotations

import csv
from hashlib import sha256
import inspect
import json
import math
from pathlib import Path

import pytest

from modules.detection.src.experiments import final_validation_armf as fva
from modules.detection.src.experiments.final_validation_armf import (
    ARM_BUDGETS,
    BASE_FEATURE,
    FITTED_ARMS,
    PERSISTED_CONTENT_FEATURES,
    PROTOCOL_ORDER,
    REUSED_ARM,
    ArmFExtensionError,
    armf_fold_guards,
    assemble_arm_rows,
    experiment_configuration,
    guard_arm_features,
    model_description,
    verify_canonical_definitions,
)
from modules.detection.src.experiments.final_validation_eval import FoldData
from modules.detection.src.experiments.p1_dataset import FEATURE_NAMES, Row
from modules.detection.src.experiments.ratification import ARM_A_FEATURES, ARM_F_FEATURES
from modules.detection.src.experiments.xgb_baseline import XGB_PARAMS
from scripts.run_final_validation_armf import (
    COMPARISON_PATH,
    CONFIG_PATH,
    FROZEN_INPUTS,
    MANIFEST_PATH,
    METRICS_PATH,
    OUT_DIR,
    REPORT_PATH,
    REPRODUCTION_PATH,
    ZERO_DAY_PATH,
    load_content_table,
)

ROOT = Path(__file__).resolve().parents[3]
FV_DIR = ROOT / "artifacts" / "experiments" / "final_validation"
ARES = "botnet/ares"


def synthetic(row_id: str, label: int, *, entity: str, width: int,
              episode: str | None = None, attack: str | None = None) -> Row:
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
        features=tuple(float(i) for i in range(width)),
    )


# --------------------------------------------------------- canonical definitions


def test_canonical_definition_checks_all_pass() -> None:
    checks = verify_canonical_definitions()
    assert len(checks) == 7
    assert all(check["passed"] for check in checks)


def test_arm_a_is_not_vol5_and_stays_the_historical_definition() -> None:
    assert ARM_A_FEATURES == ("distinct_payload_ratio",)
    assert ARM_A_FEATURES != FEATURE_NAMES
    assert "ARM_A" not in ARM_BUDGETS
    naming = experiment_configuration()["naming"]
    assert naming["ARM_A_reserved_historical_definition"] == ["distinct_payload_ratio"]
    assert naming["VOL5"] == list(FEATURE_NAMES)


def test_arm_f_is_the_canonical_phase1_budget_and_phase2_is_unused() -> None:
    assert ARM_F_FEATURES == (
        "distinct_payload_ratio",
        "source_non_printable_ratio",
        "destination_non_printable_ratio",
    )
    assert ARM_BUDGETS["ARMF_XGB"] == ARM_F_FEATURES
    assert experiment_configuration()["naming"]["phase2_r006_used"] is False


def test_phase1_xgboost_parameters_are_used_verbatim() -> None:
    description = model_description("ARMF_XGB")
    assert description["estimator"] == "XGBClassifier"
    for key, value in XGB_PARAMS.items():
        assert description[key] == value, key
    assert description["n_estimators"] == 200
    assert description["max_depth"] == 3
    assert description["learning_rate"] == 0.1
    assert description["subsample"] == 1.0


def test_union_arm_is_vol5_then_arm_f_in_order() -> None:
    assert ARM_BUDGETS["VOL5_ARMF_XGB"] == FEATURE_NAMES + ARM_F_FEATURES
    assert len(ARM_BUDGETS["VOL5_ARMF_XGB"]) == 8


def test_vol5_rf_is_never_refitted_by_this_step() -> None:
    assert REUSED_ARM == "VOL5_RF"
    assert REUSED_ARM not in FITTED_ARMS
    assert "not refitted" in model_description(REUSED_ARM)["source"]


def test_configuration_blocks_the_forbidden_claims() -> None:
    configuration = experiment_configuration()
    joined = " ".join(configuration["forbidden_claims"])
    assert "historical reproduction" in joined
    assert "zero-day generalisation" in joined
    assert "features alone" in joined
    assert configuration["identifiability"]["VOL5_RF_vs_ARMF_XGB"].startswith(
        "pipeline comparison only"
    )
    assert configuration["test_set_used_for_any_choice"] is False
    assert configuration["hyperparameter_tuning"] == "none"


# ------------------------------------------------------------------- guards


def test_width_guard_accepts_only_the_declared_arm_widths() -> None:
    for arm, budget in ARM_BUDGETS.items():
        rows = [synthetic("a", 1, entity="e", width=len(budget))]
        guard_arm_features(rows, budget, arm)
    with pytest.raises(ArmFExtensionError, match="expected 3"):
        guard_arm_features(
            [synthetic("a", 1, entity="e", width=5)], ARM_F_FEATURES, "bad"
        )


def test_width_guard_rejects_an_infinite_feature() -> None:
    row = Row("a", "m6", 1, "target_attack", "x", "e", "ep", "p", 60, (math.inf, 1.0, 2.0))
    with pytest.raises(ArmFExtensionError, match="infinite"):
        guard_arm_features([row], ARM_F_FEATURES, "bad")


def test_step2_guard_is_not_reused_or_modified() -> None:
    """Step 5 owns a width-aware guard so the Step 2 code path stays untouched."""
    source = inspect.getsource(fva)
    assert "def armf_fold_guards" in source
    assert "fold_guards" in source and "from modules" in source

    from modules.detection.src.experiments import final_validation_eval as fve

    # Step 2's guard is still hard-wired to five features, hence unusable for the
    # three- and eight-feature arms. That is exactly why Step 5 has its own.
    three_feature_row = Row(
        "a", "m6", 1, "target_attack", "x", "e", "ep", "p", 60, (0.1, 0.2, 0.3)
    )
    with pytest.raises(Exception, match="has 3 features"):
        fve.guard_features([three_feature_row], "step2-guard")
    eight_feature_row = Row(
        "b", "m6", 1, "target_attack", "x", "e", "ep", "p", 60, tuple(0.1 for _ in range(8))
    )
    with pytest.raises(Exception, match="has 8 features"):
        fve.guard_features([eight_feature_row], "step2-guard")


def test_entity_and_episode_leakage_remain_blocking() -> None:
    train = (synthetic("a", 1, entity="shared", width=3, episode="e1", attack="x"),)
    test = (synthetic("b", 1, entity="shared", width=3, episode="e2", attack="x"),)
    with pytest.raises(ArmFExtensionError, match="entity leakage"):
        armf_fold_guards(
            FoldData("t", 0, "h", train, test),
            ARM_F_FEATURES,
            require_entity_disjoint=True,
            require_episode_disjoint=True,
        )
    shared_episode = (
        synthetic("c", 1, entity="one", width=3, episode="same", attack="x"),
    )
    other = (synthetic("d", 1, entity="two", width=3, episode="same", attack="x"),)
    with pytest.raises(ArmFExtensionError, match="episode leakage"):
        armf_fold_guards(
            FoldData("t", 0, "h", shared_episode, other),
            ARM_F_FEATURES,
            require_entity_disjoint=False,
            require_episode_disjoint=True,
        )


def test_held_out_family_in_training_is_blocking() -> None:
    train = (synthetic("a", 1, entity="e1", width=3, episode="a|1", attack=ARES),)
    test = (synthetic("b", 1, entity="e2", width=3, episode="b|1", attack=ARES),)
    with pytest.raises(ArmFExtensionError, match="rows present in training"):
        armf_fold_guards(
            FoldData("t", 0, "h", train, test),
            ARM_F_FEATURES,
            require_entity_disjoint=False,
            require_episode_disjoint=True,
            forbid_family_in_train=ARES,
        )


# ------------------------------------------------------- feature assembly


def test_assembly_preserves_metadata_and_orders_each_budget() -> None:
    rows = [
        Row("r1", "m6", 1, "target_attack", ARES, "ent", "ep|1", "part", 60,
            (1.0, 2.0, 3.0, 4.0, 5.0))
    ]
    base = {("part", "ent", 60): 0.25}
    content = {
        "r1": {name: 0.5 for name in PERSISTED_CONTENT_FEATURES},
    }
    assembled = assemble_arm_rows(rows, base, content)
    assert assembled["VOL5_XGB"][0].features == (1.0, 2.0, 3.0, 4.0, 5.0)
    assert assembled["ARMF_XGB"][0].features == (0.25, 0.5, 0.5)
    assert assembled["VOL5_ARMF_XGB"][0].features == (
        1.0, 2.0, 3.0, 4.0, 5.0, 0.25, 0.5, 0.5
    )
    for arm in ARM_BUDGETS:
        row = assembled[arm][0]
        assert (row.row_id, row.label, row.episode_id, row.entity_key, row.attack_type) == (
            "r1", 1, "ep|1", "ent", ARES
        )


def test_assembly_refuses_a_row_without_reconstruction() -> None:
    rows = [Row("r1", "m6", 1, "t", None, "ent", None, "part", 60, (1.0,) * 5)]
    with pytest.raises(ArmFExtensionError, match="no P6 reconstruction"):
        assemble_arm_rows(rows, {}, {"r1": {n: 0.0 for n in PERSISTED_CONTENT_FEATURES}})


def test_persisted_content_csv_does_not_contain_the_base_feature() -> None:
    table = load_content_table()
    assert len(table) == 70_954
    sample = next(iter(table.values()))
    assert set(sample) == set(PERSISTED_CONTENT_FEATURES)
    assert BASE_FEATURE not in sample


# ------------------------------------------------------ published artifacts


published = pytest.mark.skipif(
    not MANIFEST_PATH.exists(), reason="step 5 artifacts not yet published"
)


@published
def test_published_outputs_match_the_manifest() -> None:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    for name, digest in manifest["outputs"].items():
        assert sha256((OUT_DIR / name).read_bytes()).hexdigest() == digest, name
    assert manifest["postgresql_writes"] == 0
    assert manifest["postgresql_transaction_read_only"] == {
        "cybersentinel": "on",
        "cybersentinel_test": "on",
    }
    assert manifest["hyperparameter_tuning"] == "none"
    assert manifest["threshold_selected_on_test"] is False
    assert manifest["arm_f_variant"] == "phase1_canonical"
    assert manifest["phase2_r006_used"] is False
    assert manifest["is_a_historical_reproduction_claim"] is False
    assert manifest["arm_reused_without_refit"] == "VOL5_RF"
    assert manifest["models_fitted"] == 65


@published
def test_reconstruction_reproduces_every_published_arm_f_fold() -> None:
    document = json.loads(REPRODUCTION_PATH.read_text(encoding="utf-8"))
    assert document["all_folds_reproduce_exactly"] is True
    assert document["is_a_historical_reproduction_claim_for_this_step"] is False
    assert len(document["folds"]) == 5
    for entry in document["folds"]:
        assert entry["scores_matching_to_ten_decimals"] == entry["rows"]
        assert entry["max_absolute_difference"] < 1e-9


@published
def test_published_arm_f_matches_the_frozen_ratification_value_on_ares() -> None:
    """Independent cross-check against the historical ARM F publication."""
    metrics = json.loads(METRICS_PATH.read_text(encoding="utf-8"))
    fold = metrics["arms"]["ARMF_XGB"]["D_zero_day_ares"]["folds"][0]
    historical = json.loads(
        (
            ROOT / "artifacts/experiments/armf_ratification_armj1/metrics.json"
        ).read_text(encoding="utf-8")
    )
    reference = next(
        f for f in historical["folds"] if f["arm"] == "F" and f["fold"] == 0
    )
    point = next(
        p for p in reference["operating_points"] if p["target_train_fpr"] == 0.01
    )
    assert fold["threshold"] == point["threshold"]
    assert fold["fpr"] == pytest.approx(point["observed_test_fpr"], abs=1e-12)
    assert fold["episode_recall"] == pytest.approx(point["episode_recall"], abs=1e-12)
    assert fold["detected_episodes"] == 21 and fold["total_episodes"] == 40


@published
def test_every_arm_used_only_its_declared_features() -> None:
    metrics = json.loads(METRICS_PATH.read_text(encoding="utf-8"))
    for arm, protocols in metrics["arms"].items():
        for protocol, entry in protocols.items():
            for fold in entry["folds"]:
                assert fold["feature_names"] == list(ARM_BUDGETS[arm]), (arm, protocol)
                assert fold["feature_count"] == len(ARM_BUDGETS[arm])
                assert fold["training_order"] == "label,row_id"
                assert fold["hyperparameter_tuning"] == "none"
                assert "test_scores" not in fold


@published
def test_disjointness_contracts_hold_for_every_arm() -> None:
    metrics = json.loads(METRICS_PATH.read_text(encoding="utf-8"))
    for arm, protocols in metrics["arms"].items():
        for fold in protocols["B_entity_disjoint"]["folds"]:
            assert fold["entity_intersection_count"] == 0, arm
        for protocol, entry in protocols.items():
            for fold in entry["folds"]:
                assert fold["episode_intersection_count"] == 0, (arm, protocol)
        zero_day = protocols["D_zero_day_ares"]["folds"][0]
        assert zero_day["entity_intersection_count"] == 0, arm
        assert zero_day["train_attack_type_windows"].get(ARES, 0) == 0, arm


@published
def test_zero_day_declares_ares_absent_for_every_fitted_arm() -> None:
    document = json.loads(ZERO_DAY_PATH.read_text(encoding="utf-8"))
    assert document["ares_absent_from_training"] == {
        arm: True for arm in FITTED_ARMS
    }
    assert "not evidence of zero-day generalisation" in document["caution"]
    for arm in FITTED_ARMS:
        assert document["arms"][arm]["total_episodes"] == 40
    assert "not refitted" in document["arms"][REUSED_ARM]["note"]


@published
def test_all_arms_share_the_same_test_population_per_fold() -> None:
    comparison = json.loads(COMPARISON_PATH.read_text(encoding="utf-8"))
    assert comparison["same_test_population_checks"] == 60
    metrics = json.loads(METRICS_PATH.read_text(encoding="utf-8"))
    baseline = json.loads((FV_DIR / "baseline_metrics.json").read_text(encoding="utf-8"))
    for protocol in PROTOCOL_ORDER:
        reference = {
            f["fold"]: f for f in baseline["protocols"][protocol]["folds"]
        }
        for arm in FITTED_ARMS:
            for fold in metrics["arms"][arm][protocol]["folds"]:
                other = reference[fold["fold"]]
                assert fold["test_rows"] == other["test_rows"], (arm, protocol)
                assert fold["test_positive"] == other["test_positive"]
                assert fold["total_episodes"] == other["total_episodes"]


@published
def test_contrasts_flag_the_unidentifiable_comparison() -> None:
    comparison = json.loads(COMPARISON_PATH.read_text(encoding="utf-8"))
    for protocol in PROTOCOL_ORDER:
        contrasts = comparison["contrasts"][protocol]
        assert contrasts["VOL5_RF_vs_ARMF_XGB"]["feature_effect_identifiable"] is False
        assert contrasts["VOL5_XGB_vs_ARMF_XGB"]["feature_effect_identifiable"] is True
        assert (
            contrasts["ARMF_XGB_vs_VOL5_ARMF_XGB"]["feature_effect_identifiable"] is True
        )


@published
def test_report_separates_zero_day_from_known_family() -> None:
    text = REPORT_PATH.read_text(encoding="utf-8")
    assert "not evidence of zero-day generalisation" in text
    assert "not** a claim that this step reproduces history" in text
    assert "Feature effect identifiable" in text
    assert "**no**" in text


@published
def test_published_config_matches_the_executable_definition() -> None:
    assert json.loads(CONFIG_PATH.read_text(encoding="utf-8")) == (
        experiment_configuration()
    )


# ------------------------------------------------------------- non-regression


def test_frozen_inputs_are_unchanged() -> None:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    for name, digest in manifest["frozen_inputs"].items():
        assert sha256((ROOT / name).read_bytes()).hexdigest() == digest, name
    assert set(manifest["frozen_inputs"]) == set(FROZEN_INPUTS)


def test_earlier_steps_are_untouched() -> None:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    for key in (
        "step1_artifacts_modified",
        "step2_artifacts_modified",
        "step3_artifacts_modified",
        "step4_artifacts_modified",
        "frozen_artifacts_modified",
    ):
        assert manifest[key] is False, key
    for name in ("evaluation_manifest.json", "report_manifest.json"):
        document = json.loads((FV_DIR / name).read_text(encoding="utf-8"))
        outputs = document["outputs"]
        for output, digest in outputs.items():
            assert sha256((FV_DIR / output).read_bytes()).hexdigest() == digest, output


def test_production_dataset_and_historical_arm_f_are_untouched() -> None:
    assert sha256(
        (ROOT / "artifacts/production/ml_dataset_v1/ml_dataset.csv").read_bytes()
    ).hexdigest() == "e95aed008d994510e4c649c287feb8fe8f49a785bec144d7e83aa15804b6c062"
    for fold in range(5):
        path = (
            ROOT
            / f"artifacts/experiments/xgboost_content_benchmark/predictions_F_fold{fold}.csv"
        )
        assert path.exists()
    reproduction = json.loads(REPRODUCTION_PATH.read_text(encoding="utf-8"))
    for entry in reproduction["folds"]:
        path = (
            ROOT
            / "artifacts/experiments/xgboost_content_benchmark"
            / f"predictions_F_fold{entry['fold']}.csv"
        )
        assert sha256(path.read_bytes()).hexdigest() == entry["published_stream_sha256"]


# ------------------------------------------------------ read-only database


def _database_available() -> bool:
    try:
        from modules.detection.src.persistence.monday_benign_persistence import (
            get_monday_benign_connection,
        )

        connection = get_monday_benign_connection("cybersentinel")
        try:
            connection.read_only = True
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
                cursor.fetchone()
        finally:
            connection.rollback()
            connection.close()
        return True
    except Exception:
        return False


@pytest.mark.skipif(not _database_available(), reason="PostgreSQL unavailable")
def test_event_fetch_runs_in_a_genuinely_read_only_transaction() -> None:
    """The frozen P6 helper sets a *next-transaction* default; this one is effective."""
    from scripts.run_final_validation_armf import fetch_window_events

    windows, mode = fetch_window_events(
        "cybersentinel_test", "mb4_canonical.flow_end_events"
    )
    assert mode == "on"
    assert len(windows) == 70_921


@pytest.mark.skipif(not _database_available(), reason="PostgreSQL unavailable")
def test_a_write_is_refused_on_the_read_only_connection() -> None:
    from modules.detection.src.persistence.monday_benign_persistence import (
        get_monday_benign_connection,
    )

    connection = get_monday_benign_connection("cybersentinel")
    try:
        connection.read_only = True
        with connection.cursor() as cursor:
            with pytest.raises(Exception, match="read-only transaction"):
                cursor.execute("CREATE TABLE public.__armf_guard(x int)")
    finally:
        connection.rollback()
        connection.close()
