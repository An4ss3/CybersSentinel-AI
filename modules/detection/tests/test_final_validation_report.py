"""Non-regression tests for final-validation Step 4 (report rendering only).

The report must be derived from artifacts, never retyped. These tests assert that
its figures equal the frozen artifact values, that the mandated distinctions are
present, and that no experiment was run by this step.
"""
from __future__ import annotations

from hashlib import sha256
import inspect
import json
from pathlib import Path
import re

import pytest

from scripts import run_final_validation_report as rep
from scripts.run_final_validation_report import (
    FV_DIR,
    REPORT_MANIFEST_PATH,
    REPORT_PATH,
    SOURCE_ARTIFACTS,
    ReportError,
    ares_subset_of_b,
    consistency_gate,
    load_sources,
    render,
)

ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture(scope="module")
def sources():
    return load_sources()


@pytest.fixture(scope="module")
def report_text():
    return REPORT_PATH.read_text(encoding="utf-8")


# ------------------------------------------------------- step 4 runs no science


def test_step4_module_never_fits_a_model_or_opens_a_database() -> None:
    """The step-4 module may *describe* the model, but must never invoke one."""
    source = inspect.getsource(rep)
    for forbidden in (
        "build_model",
        ".fit(",
        "predict_proba",
        "RandomForestClassifier(",
        "psycopg",
        "get_monday_benign_connection",
        "cursor(",
        "np.random",
        "default_rng",
        "train_test_split",
    ):
        assert forbidden not in source, forbidden


def test_published_manifest_declares_no_experiment() -> None:
    manifest = json.loads(REPORT_MANIFEST_PATH.read_text(encoding="utf-8"))
    assert manifest["experiments_run"] == 0
    assert manifest["splits_created"] == 0
    assert manifest["models_fitted"] == 0
    assert manifest["postgresql_connections"] == 0
    assert manifest["generated_from_artifacts_only"] is True
    assert manifest["consistency_checks_failed"] == 0
    assert manifest["step1_artifacts_modified"] is False
    assert manifest["step2_artifacts_modified"] is False
    assert manifest["step3_artifacts_modified"] is False
    assert manifest["frozen_artifacts_modified"] is False


def test_consistency_gate_passes_and_is_non_trivial(sources) -> None:
    checks = consistency_gate(sources)
    assert len(checks) >= 40
    assert all(check["passed"] for check in checks)


def test_gate_refuses_an_inconsistent_source(sources) -> None:
    corrupted = json.loads(json.dumps(sources))
    corrupted["zero_day"]["D2_historical_anchor"]["tp"] = 999
    with pytest.raises(ReportError, match="D2_matches_published_values"):
        consistency_gate(corrupted)


def test_report_regenerates_byte_identically(sources, report_text) -> None:
    assert render(sources, consistency_gate(sources)) == report_text


# ------------------------------------------------------ mandated distinctions


def test_protocol_a_is_never_called_a_reproduction(report_text) -> None:
    assert "deterministic reimplementation" in report_text
    assert "not a reproduction" in report_text
    lowered = report_text.lower()
    assert "a is a reproduction" not in lowered
    assert "reproduction of p1" not in lowered
    manifest = json.loads(REPORT_MANIFEST_PATH.read_text(encoding="utf-8"))
    assert manifest["protocol_A_is_a_reproduction_of_p1"] is False


def test_all_six_measurements_are_named_separately(report_text) -> None:
    for label in ("**D2**", "**A**", "**B**", "**C Ares**", "**D1**", "**A′**"):
        assert label in report_text, label
    assert "D1 and D2, reported separately" in report_text
    assert "D2 is not a new training run" in report_text


def test_ab_gap_is_not_attributed_to_leakage(report_text) -> None:
    assert "reported without causal attribution" in report_text
    assert "not** attributed to identity leakage" in report_text
    assert (
        "does\n**not** state that leakage explains, or fails to explain, the A versus B"
        in report_text
        or "not** state that leakage explains, or fails to explain" in report_text
    )


def test_principal_result_is_present_with_both_sides(report_text, sources) -> None:
    assert "## 11. Principal result" in report_text
    subset = ares_subset_of_b(sources)
    d1 = sources["zero_day"]["D1_refitted"]
    assert f"**{subset['detected_episodes']}/{subset['total_episodes']}**" in report_text
    assert f"**{d1['detected_episodes']}/{d1['total_episodes']}**" in report_text
    assert "failure of **zero-day transfer to an unseen family**" in report_text


# ------------------------------------------------------------- figure fidelity


def test_dataset_counts_match_the_production_manifest(report_text, sources) -> None:
    counts = sources["production"]["observed_counts"]
    for value in (
        counts["total_rows"],
        counts["attack_rows"],
        counts["benign_rows"],
        counts["m_unknown_excluded"],
    ):
        assert f"{value}" in report_text


def test_every_protocol_summary_appears_verbatim(report_text, sources) -> None:
    for key in (
        "A_historical",
        "B_entity_disjoint",
        "C_episode_disjoint_botnet_ares",
        "C_episode_disjoint_brute_force_ssh_patator",
    ):
        summary = sources["baseline"]["protocols"][key]["summary"]
        assert f"{summary['macro_roc_auc']:.4f}" in report_text, key
        assert (
            f"{summary['detected_episodes']}/{summary['total_episodes']}" in report_text
        ), key


def test_every_fold_row_matches_the_baseline_artifact(report_text, sources) -> None:
    for key, protocol in sources["baseline"]["protocols"].items():
        for fold in protocol["folds"]:
            row = (
                f"| {fold['fold']} | `{fold['held_out'].replace('|', chr(92) + '|')}` "
                f"| {fold['train_rows']} | "
                f"{fold['test_rows']} | {fold['test_positive']} | "
                f"{fold['roc_auc']:.4f} | {fold['pr_auc']:.4f} | "
                f"{fold['threshold']:.6f} | {fold['fpr']:.6f} | "
                f"{fold['recall']:.4f} | {fold['precision']:.4f} | "
                f"{fold['f1']:.4f} | "
                f"{fold['detected_episodes']}/{fold['total_episodes']} |"
            )
            assert row in report_text, (key, fold["fold"])


def test_entity_keys_are_pipe_escaped_so_tables_stay_valid(report_text) -> None:
    """An unescaped `|` inside an entity key would silently split a column."""
    checked = 0
    for line in report_text.splitlines():
        if line.startswith("|") and "192.168.10.50" in line:
            assert "\\|" in line, line
            checked += 1
    assert checked > 0


def test_zero_day_values_match_the_artifact(report_text, sources) -> None:
    d1 = sources["zero_day"]["D1_refitted"]
    d2 = sources["zero_day"]["D2_historical_anchor"]
    for record in (d1, d2):
        assert f"{record['roc_auc']:.4f}" in report_text
        assert f"{record['pr_auc']:.4f}" in report_text
        assert f"{record['fpr']:.6f}" in report_text
    assert f"| TP | {d1['tp']} | {d2['tp']} |" in report_text
    assert f"| FP | {d1['fp']} | {d2['fp']} |" in report_text
    assert f"{len(d2['anchor_checks'])} anchor" in report_text


def test_leakage_deltas_match_the_ap_comparison(report_text, sources) -> None:
    for row in sources["ap_comparison"]["table"]:
        line = (
            f"| {row['fold']} | {row['delta_roc_auc']:+.4f} | "
            f"{row['delta_pr_auc']:+.4f} | {row['delta_recall']:+.4f} | "
            f"{row['delta_precision']:+.4f} | {row['delta_episode_recall']:+.4f} | "
            f"{row['delta_detected_episodes']:+d} |"
        )
        assert line in report_text, row["fold"]


def test_source_artifact_digests_in_the_report_are_current(report_text) -> None:
    for relative in SOURCE_ARTIFACTS:
        digest = sha256((ROOT / relative).read_bytes()).hexdigest()
        assert f"| `{relative}` | `{digest}` |" in report_text, relative


def test_no_placeholder_or_unresolved_value_remains(report_text) -> None:
    # `None` legitimately appears inside `class_weight=None`, so it is not a
    # placeholder marker here; unformatted f-string braces would be.
    for pattern in ("TODO", "TBD", "FIXME", "{", "}"):
        assert pattern not in report_text, pattern
    assert not re.search(r"\bnan\b", report_text)
    assert not re.search(r"\bXX+\b", report_text)


# ------------------------------------------------------------------- limits


def test_every_mandated_limit_is_documented(report_text) -> None:
    for fragment in (
        "9 entities",
        "54 episodes",
        "376 attack windows",
        "1:187.7",
        "Day and capture confounding is not lifted",
        "172372 M6 `unknown` windows are excluded",
        "C SSH is statistically weak",
        "cannot separate family from entity",
        "No generalisation to real traffic is demonstrated",
        "zero-day evidence rests on a single family",
        "ARM F depends on payload availability",
    ):
        assert fragment in report_text, fragment


def test_step2_manifest_still_records_that_it_did_not_evaluate_arm_f(sources) -> None:
    """Step 2 genuinely did not run ARM F; Step 5 did. Both facts must coexist."""
    assert sources["evaluation_manifest"]["arm_f_evaluated"] is False
    assert sources["armf_manifest"]["arm_f_variant"] == "phase1_canonical"


def test_arm_f_section_reports_the_executed_step5_experiment(report_text, sources) -> None:
    assert "## 13. ARM F extension and the representational ceiling" in report_text
    assert "**Executed in Step 5.**" in report_text
    assert "Not executed in this validation" not in report_text
    assert sources["armf_manifest"]["arm_f_variant"] == "phase1_canonical"
    assert sources["armf_config"]["naming"]["phase2_r006_used"] is False
    assert "phase2_r006_used = false" in report_text


def test_arm_f_contrast_identifiability_is_stated_both_ways(report_text) -> None:
    assert "| `VOL5_RF` → `ARMF_XGB` | **no** — pipeline comparison only |" in report_text
    assert "| `VOL5_XGB` → `ARMF_XGB` | **yes** — learner held constant |" in report_text


def test_zero_day_arm_f_figures_match_the_step5_artifact(report_text, sources) -> None:
    arms = sources["armf_zero_day"]["arms"]
    for arm in ("VOL5_RF", "VOL5_XGB", "ARMF_XGB", "VOL5_ARMF_XGB"):
        record = arms[arm]
        row = (
            f"| `{arm}` | {len(sources['armf_config']['arms'][arm]['features'])} | "
            f"{sources['armf_config']['arms'][arm]['learner']} | "
            f"{record['roc_auc']:.4f} | {record['pr_auc']:.4f} | "
            f"{record['threshold']:.6f} | {record['fpr']:.6f} | "
            f"{record['recall']:.4f} | "
            f"{record['detected_episodes']}/{record['total_episodes']} |"
        )
        assert row in report_text, arm
    assert "0/40" in report_text and "21/40" in report_text
    assert f"{arms['VOL5_XGB']['roc_auc']:.4f}" == "0.4470"
    assert f"{arms['ARMF_XGB']['roc_auc']:.4f}" == "0.9713"


def test_step4_interpretation_is_explicitly_corrected(report_text) -> None:
    assert "### 13.6 Correction of the Step 4 interpretation" in report_text
    assert "**corrects that reading**" in report_text
    assert "*both* the transfer" in report_text
    assert "representational limitation of the five volume" in report_text
    assert "The Step 4 evidence remains valid on its own terms" in report_text


def test_zero_day_result_is_not_turned_into_a_generalisation_claim(report_text) -> None:
    assert "This is **not** a generalisation claim" in report_text
    assert "evaluated on\nAres only" in report_text or "evaluated on Ares only" in report_text
    assert "40 episodes drawn from 5 entities" in report_text
    assert "No second zero-day family" in report_text


def test_reconstruction_proof_is_not_sold_as_a_reproduction(report_text) -> None:
    assert "### 13.2 Reconstruction proof" in report_text
    assert "not a claim that Step 5" in report_text
    assert "reproduces the **published Phase 1 score streams exactly**" in report_text


def test_union_arm_stays_separate_and_its_cost_is_stated(report_text) -> None:
    assert "### 13.5 The union arm, reported separately" in report_text
    assert "costs episodes in zero-day transfer" in report_text
    assert "relocates it" in report_text


def test_conclusion_carries_the_step5_result_and_the_complementarity(report_text) -> None:
    assert "representational limit of the volume budget" in report_text
    assert "Neither budget dominates" in report_text
    assert "This is a complementarity, not a ranking" in report_text


def test_canonical_dataset_is_still_declared_free_of_arm_f(report_text) -> None:
    assert "not** part of the canonical production" in report_text
    assert "the ARM F content budget enters only in section 13" in report_text


def test_report_manifest_records_step5_integration() -> None:
    manifest = json.loads(REPORT_MANIFEST_PATH.read_text(encoding="utf-8"))
    assert manifest["arm_f_evaluated_in_step5"] is True
    assert manifest["step5_arm_f_variant"] == "phase1_canonical"
    assert manifest["step5_artifacts_modified"] is False
    assert manifest["consistency_checks"] >= 61


def test_report_states_the_reproducibility_limit(report_text) -> None:
    assert "Reproducibility limit" in report_text
    assert "impossible from the artifacts alone" in report_text


# --------------------------------------------------------------- integrity


def test_source_artifacts_are_unchanged_since_publication() -> None:
    manifest = json.loads(REPORT_MANIFEST_PATH.read_text(encoding="utf-8"))
    for name, digest in manifest["source_artifacts"].items():
        assert sha256((ROOT / name).read_bytes()).hexdigest() == digest, name


def test_published_report_matches_its_manifest_digest() -> None:
    manifest = json.loads(REPORT_MANIFEST_PATH.read_text(encoding="utf-8"))
    for name, digest in manifest["outputs"].items():
        assert sha256((FV_DIR / name).read_bytes()).hexdigest() == digest, name


def test_production_dataset_and_p1_folds_are_untouched() -> None:
    assert sha256(
        (ROOT / "artifacts/production/ml_dataset_v1/ml_dataset.csv").read_bytes()
    ).hexdigest() == "e95aed008d994510e4c649c287feb8fe8f49a785bec144d7e83aa15804b6c062"
    assert sha256(
        (ROOT / "artifacts/experiments/p1/p1_folds.json").read_bytes()
    ).hexdigest() == "57e688fd3da90911707d7a172c161686d852094121eda1ac49e0221fc0529fa1"
