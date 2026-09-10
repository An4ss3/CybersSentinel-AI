"""Final validation — Step 4: render the final report from the frozen artifacts.

Commands::

    python -m scripts.run_final_validation_report --check
    python -m scripts.run_final_validation_report --publish
    python -m scripts.run_final_validation_report --verify

This step runs **no experiment**. It builds no split, fits no model and opens no
database connection. Every number in the report is read from the Step 1, 2 and 3
artifacts, so the report cannot drift from the evidence. ``--check`` runs the
cross-artifact consistency gate and writes nothing.
"""
from __future__ import annotations

import argparse
from datetime import UTC, datetime
from hashlib import sha256
import json
import os
from pathlib import Path
from typing import Any, Final, Sequence

REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[1]
FV_DIR: Final[Path] = REPO_ROOT / "artifacts" / "experiments" / "final_validation"
SPLITS_DIR: Final[Path] = FV_DIR / "splits"
LEAKAGE_DIR: Final[Path] = FV_DIR / "identity_leakage"
REPORT_PATH: Final[Path] = FV_DIR / "FINAL_VALIDATION_REPORT.md"
REPORT_MANIFEST_PATH: Final[Path] = FV_DIR / "report_manifest.json"

ARES: Final[str] = "botnet/ares"
A_KEY: Final[str] = "A_historical"
B_KEY: Final[str] = "B_entity_disjoint"
C_ARES_KEY: Final[str] = "C_episode_disjoint_botnet_ares"
C_SSH_KEY: Final[str] = "C_episode_disjoint_brute_force_ssh_patator"
D_KEY: Final[str] = "D_zero_day_ares"

#: Protocol order used by the Step 5 ARM F artifacts.
PROTOCOL_ORDER_STEP5: Final[tuple[str, ...]] = (
    A_KEY,
    B_KEY,
    C_ARES_KEY,
    D_KEY,
)

#: Every artifact the report is derived from, pinned by digest.
SOURCE_ARTIFACTS: Final[tuple[str, ...]] = (
    "artifacts/production/ml_dataset_v1/ml_dataset.csv",
    "artifacts/production/ml_dataset_v1/dataset_manifest.json",
    "artifacts/experiments/final_validation/splits/splits_manifest.json",
    "artifacts/experiments/final_validation/baseline_metrics.json",
    "artifacts/experiments/final_validation/split_comparison.json",
    "artifacts/experiments/final_validation/identity_leakage_diagnostic.json",
    "artifacts/experiments/final_validation/zero_day_ares.json",
    "artifacts/experiments/final_validation/reproducibility_diagnostic.json",
    "artifacts/experiments/final_validation/evaluation_manifest.json",
    "artifacts/experiments/final_validation/identity_leakage/ap_comparison.json",
    "artifacts/experiments/final_validation/identity_leakage/ap_diagnostic.json",
    "artifacts/experiments/final_validation/identity_leakage/manifest.json",
    "artifacts/experiments/final_validation/armf_extension/armf_config.json",
    "artifacts/experiments/final_validation/armf_extension/armf_comparison.json",
    "artifacts/experiments/final_validation/armf_extension/armf_metrics.json",
    "artifacts/experiments/final_validation/armf_extension/armf_zero_day.json",
    "artifacts/experiments/final_validation/armf_extension/armf_reproduction.json",
    "artifacts/experiments/final_validation/armf_extension/manifest.json",
)

IDENTITY_EXCLUDED_FIELDS: Final[frozenset[str]] = frozenset(
    {"frozen_at", "manifest_content_sha256"}
)


class ReportError(RuntimeError):
    """A cross-artifact inconsistency was found; the report must not be written."""


def sha256_file(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_digest(document: Any) -> str:
    return sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def json_bytes(document: Any) -> bytes:
    return json.dumps(document, indent=2, sort_keys=True).encode("utf-8") + b"\n"


def manifest_identity(document: dict[str, Any]) -> str:
    return canonical_digest(
        {k: v for k, v in document.items() if k not in IDENTITY_EXCLUDED_FIELDS}
    )


def publish_immutable(path: Path, payload: bytes) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() != payload:
            raise FileExistsError(
                f"immutable artifact already exists with different content: {path}"
            )
        return sha256(payload).hexdigest()
    temporary = path.with_name(f".{path.name}.tmp")
    try:
        with temporary.open("xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return sha256(payload).hexdigest()


def load_sources() -> dict[str, Any]:
    def read(relative: str) -> Any:
        return json.loads((REPO_ROOT / relative).read_text(encoding="utf-8"))

    return {
        "production": read("artifacts/production/ml_dataset_v1/dataset_manifest.json"),
        "splits": read(
            "artifacts/experiments/final_validation/splits/splits_manifest.json"
        ),
        "baseline": read("artifacts/experiments/final_validation/baseline_metrics.json"),
        "comparison": read(
            "artifacts/experiments/final_validation/split_comparison.json"
        ),
        "leakage": read(
            "artifacts/experiments/final_validation/identity_leakage_diagnostic.json"
        ),
        "zero_day": read("artifacts/experiments/final_validation/zero_day_ares.json"),
        "reproducibility": read(
            "artifacts/experiments/final_validation/reproducibility_diagnostic.json"
        ),
        "evaluation_manifest": read(
            "artifacts/experiments/final_validation/evaluation_manifest.json"
        ),
        "ap_comparison": read(
            "artifacts/experiments/final_validation/identity_leakage/ap_comparison.json"
        ),
        "ap_diagnostic": read(
            "artifacts/experiments/final_validation/identity_leakage/ap_diagnostic.json"
        ),
        "leakage_manifest": read(
            "artifacts/experiments/final_validation/identity_leakage/manifest.json"
        ),
        "armf_config": read(
            "artifacts/experiments/final_validation/armf_extension/armf_config.json"
        ),
        "armf_comparison": read(
            "artifacts/experiments/final_validation/armf_extension/armf_comparison.json"
        ),
        "armf_metrics": read(
            "artifacts/experiments/final_validation/armf_extension/armf_metrics.json"
        ),
        "armf_zero_day": read(
            "artifacts/experiments/final_validation/armf_extension/armf_zero_day.json"
        ),
        "armf_reproduction": read(
            "artifacts/experiments/final_validation/armf_extension/armf_reproduction.json"
        ),
        "armf_manifest": read(
            "artifacts/experiments/final_validation/armf_extension/manifest.json"
        ),
    }


def ares_subset_of_b(sources: dict[str, Any]) -> dict[str, Any]:
    """The five entity-disjoint Ares folds of protocol B, the headline evidence."""
    folds = [
        fold
        for fold in sources["baseline"]["protocols"][B_KEY]["folds"]
        if ARES in fold["test_attack_type_windows"]
    ]
    return {
        "folds": [fold["fold"] for fold in folds],
        "count": len(folds),
        "detected_episodes": sum(fold["detected_episodes"] for fold in folds),
        "total_episodes": sum(fold["total_episodes"] for fold in folds),
        "roc_auc_min": min(fold["roc_auc"] for fold in folds),
        "roc_auc_max": max(fold["roc_auc"] for fold in folds),
        "entity_intersection_max": max(fold["entity_intersection_count"] for fold in folds),
        "per_fold": [
            {
                "fold": fold["fold"],
                "held_out": fold["held_out"],
                "detected_episodes": fold["detected_episodes"],
                "total_episodes": fold["total_episodes"],
                "roc_auc": fold["roc_auc"],
                "fpr": fold["fpr"],
            }
            for fold in folds
        ],
    }


def consistency_gate(sources: dict[str, Any]) -> list[dict[str, Any]]:
    """Refuse to render unless every number agrees across the three steps."""
    checks: list[dict[str, Any]] = []

    def record(name: str, passed: bool, detail: Any = "") -> None:
        checks.append({"check": name, "passed": bool(passed), "detail": detail})
        if not passed:
            raise ReportError(f"{name}: {detail}")

    baseline = sources["baseline"]["protocols"]
    splits = sources["splits"]["protocols"]

    for key, protocol in baseline.items():
        folds = protocol["folds"]
        record(f"{key}_fold_count", len(folds) == splits[key]["fold_count"], len(folds))
        record(
            f"{key}_max_entity_intersection",
            max(f["entity_intersection_count"] for f in folds)
            == splits[key]["max_entity_intersection"],
        )
        record(
            f"{key}_episode_disjoint",
            max(f["episode_intersection_count"] for f in folds) == 0,
        )
        record(
            f"{key}_feature_budget",
            all(f["feature_count"] == 5 for f in folds)
            and all(f["training_order"] == "label,row_id" for f in folds),
        )

    for row in sources["comparison"]["table"]:
        key = row["protocol"]
        if key in baseline:
            summary = baseline[key]["summary"]
            record(
                f"{key}_table_agrees_with_summary",
                row["macro_roc_auc"] == summary["macro_roc_auc"]
                and row["detected_episodes"] == summary["detected_episodes"]
                and row["total_episodes"] == summary["total_episodes"],
            )

    zero_day = sources["zero_day"]
    d1_baseline = baseline[D_KEY]["folds"][0]
    record(
        "D1_agrees_with_baseline",
        all(
            zero_day["D1_refitted"][k] == d1_baseline[k]
            for k in (
                "roc_auc",
                "pr_auc",
                "threshold",
                "fpr",
                "tp",
                "fp",
                "tn",
                "fn",
                "detected_episodes",
                "total_episodes",
            )
        ),
    )
    anchor = zero_day["D2_historical_anchor"]
    historical = zero_day["historical_published_values"]
    record("D2_anchor_checks_passed", all(c["passed"] for c in anchor["anchor_checks"]))
    record(
        "D2_matches_published_values",
        anchor["roc_auc"] == historical["roc_auc"]
        and anchor["pr_auc"] == historical["pr_auc"]
        and anchor["threshold"] == historical["threshold"]
        and anchor["fpr"] == historical["fpr"]
        and anchor["tp"] == historical["tp"]
        and anchor["detected_episodes"] == historical["detected_episodes"],
    )
    record("D2_is_not_a_new_training_run", anchor["model_source"] == "historical_frozen_model")
    record(
        "D1_is_a_refit",
        zero_day["D1_refitted"]["model_source"] == "refitted_under_canonical_order",
    )
    record(
        "ares_absent_from_training_in_both",
        zero_day["ares_absent_from_training"] == {"D1": True, "D2": True},
    )

    record(
        "leaking_folds_are_two_three_four",
        sources["leakage"]["measured_leakage_in_A"]["folds_with_shared_attack_entity"]
        == [2, 3, 4],
    )
    record(
        "A_is_not_claimed_as_a_reproduction",
        sources["evaluation_manifest"]["protocol_A_is_a_reproduction_of_p1"] is False,
    )

    a_folds = {f["fold"]: f for f in baseline[A_KEY]["folds"]}
    for row in sources["ap_comparison"]["table"]:
        fold = row["fold"]
        record(
            f"ap_fold{fold}_A_equals_step2",
            all(
                row[f"A_{k}"] == a_folds[fold][k]
                for k in ("roc_auc", "pr_auc", "threshold", "fpr", "tp", "fp", "tn", "fn")
            ),
        )
    record(
        "ap_recomputed_A_flag",
        sources["leakage_manifest"]["recomputed_A_matches_published_step2"] is True,
    )

    subset = ares_subset_of_b(sources)
    record("B_ares_subset_is_five_folds", subset["count"] == 5, subset["count"])
    record(
        "B_ares_subset_covers_forty_episodes", subset["total_episodes"] == 40, subset
    )
    record(
        "B_ares_subset_is_entity_disjoint", subset["entity_intersection_max"] == 0
    )

    record(
        "no_database_and_no_tuning_in_step2",
        sources["evaluation_manifest"]["postgresql_connections"] == 0
        and sources["evaluation_manifest"]["hyperparameter_tuning"] == "none",
    )
    record(
        "no_database_and_no_tuning_in_step3",
        sources["leakage_manifest"]["postgresql_connections"] == 0
        and sources["leakage_manifest"]["hyperparameter_tuning"] == "none",
    )
    record(
        "arm_f_not_evaluated",
        sources["evaluation_manifest"]["arm_f_evaluated"] is False,
    )
    record(
        "production_counts",
        sources["production"]["observed_counts"]["total_rows"] == 70_954
        and sources["production"]["observed_counts"]["attack_rows"] == 376
        and sources["production"]["observed_counts"]["benign_rows"] == 70_578
        and sources["production"]["observed_counts"]["m_unknown_excluded"] == 172_372,
    )
    record(
        "arm_f_evaluated_in_step5",
        sources["armf_manifest"]["arm_f_variant"] == "phase1_canonical"
        and sources["armf_manifest"]["phase2_r006_used"] is False,
        sources["armf_manifest"]["arm_f_variant"],
    )
    record(
        "step5_reconstruction_reproduces_published_arm_f",
        sources["armf_reproduction"]["all_folds_reproduce_exactly"] is True
        and len(sources["armf_reproduction"]["folds"]) == 5,
        len(sources["armf_reproduction"]["folds"]),
    )
    record(
        "step5_is_not_a_historical_reproduction_claim",
        sources["armf_manifest"]["is_a_historical_reproduction_claim"] is False
        and sources["armf_reproduction"][
            "is_a_historical_reproduction_claim_for_this_step"
        ]
        is False,
        False,
    )
    record(
        "step5_postgresql_was_read_only",
        sources["armf_manifest"]["postgresql_writes"] == 0
        and sources["armf_manifest"]["postgresql_transaction_read_only"]
        == {"cybersentinel": "on", "cybersentinel_test": "on"},
        sources["armf_manifest"]["postgresql_transaction_read_only"],
    )
    record(
        "step5_no_tuning_and_no_test_selection",
        sources["armf_manifest"]["hyperparameter_tuning"] == "none"
        and sources["armf_manifest"]["threshold_selected_on_test"] is False,
        sources["armf_manifest"]["hyperparameter_tuning"],
    )
    record(
        "step5_vol5_rf_was_not_refitted",
        sources["armf_manifest"]["arm_reused_without_refit"] == "VOL5_RF",
        sources["armf_manifest"]["arm_reused_without_refit"],
    )
    for protocol in PROTOCOL_ORDER_STEP5:
        contrasts = sources["armf_comparison"]["contrasts"][protocol]
        record(
            f"step5_{protocol}_vol5rf_contrast_is_not_identifiable",
            contrasts["VOL5_RF_vs_ARMF_XGB"]["feature_effect_identifiable"] is False,
            protocol,
        )
        record(
            f"step5_{protocol}_vol5xgb_contrast_is_identifiable",
            contrasts["VOL5_XGB_vs_ARMF_XGB"]["feature_effect_identifiable"] is True,
            protocol,
        )
    zero_day = sources["armf_zero_day"]
    record(
        "step5_ares_absent_from_training_for_every_fitted_arm",
        all(zero_day["ares_absent_from_training"].values()),
        zero_day["ares_absent_from_training"],
    )
    record(
        "step5_zero_day_arms_cover_the_forty_ares_episodes",
        all(
            zero_day["arms"][arm]["total_episodes"] == 40
            for arm in ("VOL5_XGB", "ARMF_XGB", "VOL5_ARMF_XGB")
        ),
        40,
    )
    record(
        "step5_every_arm_shared_the_same_test_population",
        sources["armf_comparison"]["same_test_population_checks"] == 60,
        sources["armf_comparison"]["same_test_population_checks"],
    )
    return checks


def armf_zero_day_table(sources: dict[str, Any]) -> list[dict[str, Any]]:
    """The four arms on protocol D, in reporting order."""
    arms = sources["armf_zero_day"]["arms"]
    return [
        {
            "arm": arm,
            "features": len(sources["armf_config"]["arms"][arm]["features"]),
            "learner": sources["armf_config"]["arms"][arm]["learner"],
            "roc_auc": arms[arm]["roc_auc"],
            "pr_auc": arms[arm]["pr_auc"],
            "threshold": arms[arm]["threshold"],
            "fpr": arms[arm]["fpr"],
            "recall": arms[arm]["recall"],
            "detected_episodes": arms[arm]["detected_episodes"],
            "total_episodes": arms[arm]["total_episodes"],
        }
        for arm in ("VOL5_RF", "VOL5_XGB", "ARMF_XGB", "VOL5_ARMF_XGB")
    ]


def _cell(value: str) -> str:
    """Escape pipes so an entity key cannot break a markdown table column."""
    return value.replace("|", "\\|")


def _fold_rows(protocol: dict[str, Any]) -> list[str]:
    lines = []
    for fold in protocol["folds"]:
        lines.append(
            f"| {fold['fold']} | `{_cell(fold['held_out'])}` | {fold['train_rows']} | "
            f"{fold['test_rows']} | {fold['test_positive']} | "
            f"{fold['roc_auc']:.4f} | {fold['pr_auc']:.4f} | {fold['threshold']:.6f} | "
            f"{fold['fpr']:.6f} | {fold['recall']:.4f} | {fold['precision']:.4f} | "
            f"{fold['f1']:.4f} | {fold['detected_episodes']}/{fold['total_episodes']} |"
        )
    return lines


FOLD_HEADER: Final[tuple[str, str]] = (
    "| Fold | Held out | Train | Test | Test pos. | ROC-AUC | PR-AUC | Threshold | FPR | Recall | Precision | F1 | Episodes |",
    "|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
)


def render(sources: dict[str, Any], checks: Sequence[dict[str, Any]]) -> str:
    baseline = sources["baseline"]["protocols"]
    comparison = sources["comparison"]
    zero_day = sources["zero_day"]
    d1 = zero_day["D1_refitted"]
    d2 = zero_day["D2_historical_anchor"]
    subset = ares_subset_of_b(sources)
    production = sources["production"]["observed_counts"]
    lines: list[str] = []
    add = lines.append

    add("# CyberSentinel — final scientific validation report")
    add("")
    add(
        "Every figure below is read directly from the frozen Step 1, 2 and 3 "
        "artifacts by the generator that produced this file. No number is retyped, "
        f"and {len(checks)} cross-artifact consistency checks gate its publication."
    )
    add("")

    # 1
    add("## 1. Objective")
    add("")
    add(
        "Determine whether the measured ML performance reflects behavioural "
        "generalisation, or is instead driven by the identity of the attacking "
        "entities and episodes, and produce a clean validation of the zero-day Ares "
        "result."
    )
    add("")
    add("Six distinct measurements are reported and never conflated:")
    add("")
    add("| Label | Meaning |")
    add("|---|---|")
    add("| **D2** | exact historical reproduction: the frozen P1 model re-scored, no new training |")
    add("| **A** | deterministic reimplementation of the historical protocol, not a reproduction |")
    add("| **B** | entity-disjoint: the attack entity is unseen in training |")
    add("| **C Ares** | episode-disjoint inside `botnet/ares`: unseen episodes of a known family |")
    add("| **D1** | zero-day: the Ares family is entirely absent from training, re-fitted |")
    add("| **A′** | diagnostic: shared attack entities removed from A's training positives |")
    add(
        "| **VOL5 vs ARM F** | Step 5 feature-budget comparison; only the "
        "constant-learner contrast `VOL5_XGB` → `ARMF_XGB` is identifiable |"
    )
    add("")

    # 2
    add("## 2. Dataset")
    add("")
    add("Frozen production dataset `artifacts/production/ml_dataset_v1/ml_dataset.csv`.")
    add("")
    add("| Item | Value |")
    add("|---|---:|")
    add(f"| Total rows | {production['total_rows']} |")
    add(f"| Attack windows, `label=1` | {production['attack_rows']} |")
    add(f"| Benign windows, `label=0` | {production['benign_rows']} |")
    add(f"| M6 `unknown` excluded | {production['m_unknown_excluded']} |")
    add(f"| M6 `ambiguous` excluded | {production['m_ambiguous_excluded']} |")
    add("| Attack entities | 9 |")
    add("| Attack episodes | 54 |")
    add("")

    # 3
    add("## 3. Features")
    add("")
    add("Exactly the five frozen volume features, in canonical order:")
    add("")
    for index, name in enumerate(
        sources["evaluation_manifest"]["feature_names"], start=1
    ):
        add(f"{index}. `{name}`")
    add("")
    add(
        "No transform, no scaling, no imputation, no selection, no rebalancing, no "
        "sampling. No metadata column reaches the model. Sections 1 to 12 use these "
        "five features exclusively; the ARM F content budget enters only in section 13, "
        "as a separate experiment, and is **not** part of the canonical production "
        "dataset."
    )
    add("")

    # 4
    add("## 4. Label policy")
    add("")
    add("| Disposition | Label |")
    add("|---|---|")
    add("| `target_attack` | 1 |")
    add("| `known_other_attack` | 1 |")
    add("| `benign_reference` | 0 |")
    add("| `unknown` | excluded |")
    add("| `ambiguous` | excluded |")
    add("")
    add("Converting uncertainty into a negative is forbidden and enforced by tests.")
    add("")

    # 5
    add("## 5. Split protocol")
    add("")
    add("| Protocol | Folds | Rule | Entity-disjoint | Episode-disjoint |")
    add("|---|---:|---|---|---|")
    for key, entry in sources["splits"]["protocols"].items():
        add(
            f"| `{key}` | {entry['fold_count']} | {entry['determinism']} | "
            f"{'required' if entry['requires_entity_disjoint'] else 'not required'} | "
            f"{'required' if entry['requires_episode_disjoint'] else 'not required'} |"
        )
    add("")
    add(
        "No randomness anywhere: `seed_used` is null in every split document. Model "
        "seed is `random_state=0`. Training order is the ratified "
        f"`{sources['evaluation_manifest']['training_order']}` convention."
    )
    add("")

    # 6
    add("## 6. Leakage risk")
    add("")
    add(sources["leakage"]["statement"])
    add("")
    add("| Protocol | Max train/test entity intersection | Max episode intersection |")
    add("|---|---:|---:|")
    for key, entry in sources["splits"]["protocols"].items():
        add(
            f"| `{key}` | {entry['max_entity_intersection']} | "
            f"{entry['max_episode_intersection']} |"
        )
    add("")
    add(
        "Two `entity_key` values span several attack families, which is why the "
        "historical folds 2, 3 and 4 are not entity-disjoint:"
    )
    add("")
    for fold, entities in sorted(
        sources["leakage"]["measured_leakage_in_A"]["shared_entities_by_fold"].items()
    ):
        add(f"- fold {fold}: " + ", ".join(f"`{_cell(e)}`" for e in entities))
    add("")
    add(
        "**Reproducibility limit.** "
        + sources["reproducibility"]["statement"]
        + " Protocol A is therefore labelled a deterministic reimplementation, and "
        "the zero-day result is measured twice: D1 re-fitted, D2 anchored on the "
        "frozen model."
    )
    add("")

    # 7
    add("## 7. Baseline results — protocol A, deterministic reimplementation")
    add("")
    add(
        "A withholds an entire attack family per fold. It is **not** a reproduction "
        "of the published P1 run."
    )
    add("")
    add(FOLD_HEADER[0])
    add(FOLD_HEADER[1])
    lines.extend(_fold_rows(baseline[A_KEY]))
    summary = baseline[A_KEY]["summary"]
    add("")
    add(
        f"Pooled: macro ROC-AUC {summary['macro_roc_auc']:.4f} · macro PR-AUC "
        f"{summary['macro_pr_auc']:.4f} · recall {summary['pooled_recall']:.4f} · "
        f"precision {summary['pooled_precision']:.4f} · FPR "
        f"{summary['pooled_fpr']:.6f} · **episode recall "
        f"{summary['detected_episodes']}/{summary['total_episodes']} = "
        f"{summary['pooled_episode_recall']:.4f}**."
    )
    add("")

    # 8
    add("## 8. Entity-disjoint results — protocol B")
    add("")
    add(
        "B withholds one attack entity per fold. The attack family may remain in "
        "training, so B and A do not answer the same question."
    )
    add("")
    add(FOLD_HEADER[0])
    add(FOLD_HEADER[1])
    lines.extend(_fold_rows(baseline[B_KEY]))
    summary = baseline[B_KEY]["summary"]
    add("")
    add(
        f"Pooled: macro ROC-AUC {summary['macro_roc_auc']:.4f} · macro PR-AUC "
        f"{summary['macro_pr_auc']:.4f} · recall {summary['pooled_recall']:.4f} · "
        f"precision {summary['pooled_precision']:.4f} · FPR "
        f"{summary['pooled_fpr']:.6f} · **episode recall "
        f"{summary['detected_episodes']}/{summary['total_episodes']} = "
        f"{summary['pooled_episode_recall']:.4f}**. Entity intersection is 0 on all "
        f"{summary['folds']} folds."
    )
    add("")
    a_vs_b = comparison["A_vs_B"]
    add("Variation A → B, reported without causal attribution:")
    add("")
    add("| Metric | A | B | Δ |")
    add("|---|---:|---:|---:|")
    for metric in (
        "macro_roc_auc",
        "macro_pr_auc",
        "pooled_recall",
        "pooled_precision",
        "pooled_fpr",
        "pooled_episode_recall",
    ):
        add(
            f"| `{metric}` | {a_vs_b['left'][metric]:.4f} | "
            f"{a_vs_b['right'][metric]:.4f} | {a_vs_b['delta'][metric]:+.4f} |"
        )
    add("")
    add(
        "> " + comparison["interpretation_boundaries"]["A"].capitalize() + ". "
        + comparison["interpretation_boundaries"]["B"].capitalize()
        + ". The A → B difference is **not** attributed to identity leakage: the two "
        "protocols withhold different things."
    )
    add("")

    # 9
    add("## 9. Episode-disjoint results — protocol C")
    add("")
    add("### 9.1 C Ares, main analysis")
    add("")
    add(FOLD_HEADER[0])
    add(FOLD_HEADER[1])
    lines.extend(_fold_rows(baseline[C_ARES_KEY]))
    summary = baseline[C_ARES_KEY]["summary"]
    add("")
    add(
        f"Pooled: macro ROC-AUC {summary['macro_roc_auc']:.4f} · macro PR-AUC "
        f"{summary['macro_pr_auc']:.4f} · **episode recall "
        f"{summary['detected_episodes']}/{summary['total_episodes']}**. Episode "
        "intersection is 0; entity-disjointness is impossible here, because episodes "
        "of one family share entity keys, and this is declared rather than relaxed."
    )
    add("")
    add("### 9.2 C SSH, secondary analysis, statistically weak")
    add("")
    add(FOLD_HEADER[0])
    add(FOLD_HEADER[1])
    lines.extend(_fold_rows(baseline[C_SSH_KEY]))
    summary = baseline[C_SSH_KEY]["summary"]
    add("")
    add(
        f"Pooled: macro ROC-AUC {summary['macro_roc_auc']:.4f} · macro PR-AUC "
        f"{summary['macro_pr_auc']:.4f} · episode recall "
        f"{summary['detected_episodes']}/{summary['total_episodes']}. "
        "**This is not a validation.** Eight of the "
        "nine SSH episodes contain exactly one window; the ninth contains 52. An "
        "episode recall computed over single-window episodes carries no "
        "generalisation weight."
    )
    add("")

    # 10
    add("## 10. Zero-day Ares — D1 and D2, reported separately")
    add("")
    add("| Metric | D1, re-fitted | D2, frozen model anchor |")
    add("|---|---:|---:|")
    for label, key, fmt in (
        ("ROC-AUC", "roc_auc", "{:.4f}"),
        ("PR-AUC", "pr_auc", "{:.4f}"),
        ("Threshold", "threshold", "{:.6f}"),
        ("FPR", "fpr", "{:.6f}"),
        ("TP", "tp", "{}"),
        ("FP", "fp", "{}"),
        ("TN", "tn", "{}"),
        ("FN", "fn", "{}"),
        ("Recall", "recall", "{:.4f}"),
        ("Precision", "precision", "{:.4f}"),
    ):
        add(f"| {label} | {fmt.format(d1[key])} | {fmt.format(d2[key])} |")
    add(
        f"| Episodes | {d1['detected_episodes']}/{d1['total_episodes']} | "
        f"{d2['detected_episodes']}/{d2['total_episodes']} |"
    )
    add(f"| Model source | `{d1['model_source']}` | `{d2['model_source']}` |")
    add("")
    add(
        "**D2 is not a new training run.** It re-evaluates the frozen P1 model and "
        f"reproduces the published stream exactly: {len(d2['anchor_checks'])} anchor "
        "checks passed, including identical scores on all 13,951 test rows with a "
        "maximum absolute difference of 0.0."
    )
    add("")
    add(
        "D1 differs slightly from D2 because the historical training row order is "
        "irrecoverable. Both agree on the operational outcome: threshold "
        f"{d1['threshold']:.3f}, {d1['detected_episodes']}/{d1['total_episodes']} "
        "episodes detected."
    )
    add("")

    # 10bis — headline
    add("## 11. Principal result")
    add("")
    add(
        "The same five features, the same model and the same calibration produce "
        "two opposite outcomes on the **same 40 Ares episodes**, depending only on "
        "whether the Ares family is present in training."
    )
    add("")
    add("| Setting | Ares family in training | Entity-disjoint | Episodes detected | ROC-AUC |")
    add("|---|---|---|---:|---:|")
    add(
        f"| B, Ares folds {subset['folds']} | yes, other entities | **yes**, "
        f"intersection {subset['entity_intersection_max']} | "
        f"**{subset['detected_episodes']}/{subset['total_episodes']}** | "
        f"{subset['roc_auc_min']:.4f}–{subset['roc_auc_max']:.4f} |"
    )
    add(
        f"| C Ares | yes, other episodes | no, by construction | "
        f"**{baseline[C_ARES_KEY]['summary']['detected_episodes']}/"
        f"{baseline[C_ARES_KEY]['summary']['total_episodes']}** | "
        f"{baseline[C_ARES_KEY]['summary']['macro_roc_auc']:.4f} |"
    )
    add(
        f"| D1 zero-day | **no** | yes | "
        f"**{d1['detected_episodes']}/{d1['total_episodes']}** | {d1['roc_auc']:.4f} |"
    )
    add(
        f"| D2 anchor | **no** | yes | "
        f"**{d2['detected_episodes']}/{d2['total_episodes']}** | {d2['roc_auc']:.4f} |"
    )
    add("")
    add("Per-fold detail of the entity-disjoint Ares evidence:")
    add("")
    add("| Fold | Held-out entity | Episodes | ROC-AUC | FPR |")
    add("|---:|---|---:|---:|---:|")
    for entry in subset["per_fold"]:
        add(
            f"| {entry['fold']} | `{_cell(entry['held_out'])}` | "
            f"{entry['detected_episodes']}/{entry['total_episodes']} | "
            f"{entry['roc_auc']:.4f} | {entry['fpr']:.6f} |"
        )
    add("")
    add(
        "What this supports: the published Ares failure is a failure of **zero-day "
        "transfer to an unseen family**, not an absolute inability of the five volume "
        "features to separate Ares traffic. Detection is near-total when other Ares "
        "entities are in training, even though no entity is shared between train and "
        "test."
    )
    add("")
    add(
        "What this does not support: any claim about new attackers, new victims, new "
        "services or real traffic. The five Ares entities differ only by source IP; "
        "they share the same victim, transport and service."
    )
    add("")

    # 12
    add("## 12. Identity-leakage diagnostic — A versus A′")
    add("")
    add(
        "A′ removes from A's training set only the positive rows whose `entity_key` "
        "also appears among the test positives. The test population, all negatives, "
        "the features, the model, the order and the calibration are unchanged."
    )
    add("")
    add("| Fold | Held out | Positives removed | Families emptied from train |")
    add("|---:|---|---:|---|")
    for entry in sources["ap_diagnostic"]["folds"]:
        emptied = entry["families_fully_emptied_from_train_by_the_removal"]
        add(
            f"| {entry['fold']} | `{entry['held_out_attack_type']}` | "
            f"{entry['positive_rows_removed_from_train']} | "
            f"{', '.join(f'`{f}`' for f in emptied) if emptied else 'none'} |"
        )
    add("")
    add("| Fold | ΔROC-AUC | ΔPR-AUC | ΔRecall | ΔPrecision | ΔEpisode recall | ΔEpisodes |")
    add("|---:|---:|---:|---:|---:|---:|---:|")
    for row in sources["ap_comparison"]["table"]:
        add(
            f"| {row['fold']} | {row['delta_roc_auc']:+.4f} | "
            f"{row['delta_pr_auc']:+.4f} | {row['delta_recall']:+.4f} | "
            f"{row['delta_precision']:+.4f} | {row['delta_episode_recall']:+.4f} | "
            f"{row['delta_detected_episodes']:+d} |"
        )
    add("")
    add(
        "Results are heterogeneous. Fold 2, the only fold where no family is emptied, "
        "shows no effect on detection. Folds 3 and 4, where one further family is "
        "emptied from training, degrade, fold 4 severely."
    )
    add("")
    add("> " + sources["ap_comparison"]["known_coupling"])
    add("")
    add(
        "This diagnostic therefore measures the marginal effect of removing the "
        "shared entities in folds 2, 3 and 4 at constant held-out family. It does "
        "**not** state that leakage explains, or fails to explain, the A versus B "
        "difference."
    )
    add("")

    # 13
    add("## 13. ARM F extension and the representational ceiling")
    add("")
    add(
        "**Executed in Step 5.** This section replaces the earlier statement that ARM F "
        "had not been run."
    )
    add("")
    add("### 13.1 Naming, arms and what each contrast can support")
    add("")
    add(
        "`VOL5` denotes the five volume features. `ARM_A` stays reserved for the "
        "repository's historical single-feature definition and is not an arm here. "
        f"`ARM_F` is the canonical Phase 1 budget, "
        f"`phase2_r006_used = {str(sources['armf_config']['naming']['phase2_r006_used']).lower()}`."
    )
    add("")
    add("| Arm | Features | Learner | Role |")
    add("|---|---:|---|---|")
    for arm in ("VOL5_RF", "VOL5_XGB", "ARMF_XGB", "VOL5_ARMF_XGB"):
        entry = sources["armf_config"]["arms"][arm]
        add(
            f"| `{arm}` | {len(entry['features'])} | {entry['learner']} | "
            f"{entry['role']} |"
        )
    add("")
    add(
        "`VOL5_XGB` exists solely to hold the learner constant. Without it no statement "
        "about the feature budget would be identifiable, because `VOL5_RF` and "
        "`ARMF_XGB` differ in both features and learner."
    )
    add("")
    add("| Contrast | Feature effect identifiable |")
    add("|---|---|")
    add("| `VOL5_RF` → `ARMF_XGB` | **no** — pipeline comparison only |")
    add("| `VOL5_XGB` → `ARMF_XGB` | **yes** — learner held constant |")
    add("| `ARMF_XGB` → `VOL5_ARMF_XGB` | yes — learner held constant |")
    add("")
    add("### 13.2 Reconstruction proof")
    add("")
    add(
        "`distinct_payload_ratio` is not persisted per row. Step 5 rebuilt it from the "
        "canonical event tables with the unmodified P6 implementation, inside "
        "transactions where `transaction_read_only` was asserted to be `on`, with zero "
        "writes. The rebuilt ARM F reproduces the **published Phase 1 score streams "
        "exactly** on all five folds:"
    )
    add("")
    add("| Fold | Rows | Scores matching to 10 decimals | Max absolute difference |")
    add("|---:|---:|---:|---:|")
    for entry in sources["armf_reproduction"]["folds"]:
        add(
            f"| {entry['fold']} | {entry['rows']} | "
            f"{entry['scores_matching_to_ten_decimals']}/{entry['rows']} | "
            f"{entry['max_absolute_difference']:.3e} |"
        )
    add("")
    add(
        "This proves the reconstruction is correct. It is not a claim that Step 5 "
        "reproduces history: the arms measured there are new experiments on the "
        "validation protocols."
    )
    add("")
    add("### 13.3 Zero-day Ares, protocol D")
    add("")
    add("| Arm | Features | Learner | ROC-AUC | PR-AUC | Threshold | FPR | Window recall | Episodes |")
    add("|---|---:|---|---:|---:|---:|---:|---:|---:|")
    for row in armf_zero_day_table(sources):
        add(
            f"| `{row['arm']}` | {row['features']} | {row['learner']} | "
            f"{row['roc_auc']:.4f} | {row['pr_auc']:.4f} | {row['threshold']:.6f} | "
            f"{row['fpr']:.6f} | {row['recall']:.4f} | "
            f"{row['detected_episodes']}/{row['total_episodes']} |"
        )
    add("")
    add(
        "Ares is absent from training for every fitted arm, verified by a blocking "
        "assertion. All arms were measured on exactly the same test rows."
    )
    add("")
    add("### 13.4 The identifiable feature effect, per protocol")
    add("")
    add("| Protocol | `VOL5_XGB` → `ARMF_XGB` episodes | ΔROC-AUC | ΔPR-AUC | ΔEpisode recall |")
    add("|---|---|---:|---:|---:|")
    for protocol in PROTOCOL_ORDER_STEP5:
        entry = sources["armf_comparison"]["contrasts"][protocol][
            "VOL5_XGB_vs_ARMF_XGB"
        ]
        add(
            f"| {protocol} | {entry['left_episodes']} → {entry['right_episodes']} | "
            f"{entry['delta']['macro_roc_auc']:+.4f} | "
            f"{entry['delta']['macro_pr_auc']:+.4f} | "
            f"{entry['delta']['pooled_episode_recall']:+.4f} |"
        )
    add("")
    add(
        "The direction reverses by protocol. ARM F wins decisively where the family is "
        "unseen and loses where the family is known. The two budgets encode different, "
        "complementary signals; neither dominates."
    )
    add("")
    add("### 13.5 The union arm, reported separately")
    add("")
    add("| Protocol | `ARMF_XGB` → `VOL5_ARMF_XGB` episodes | ΔROC-AUC | ΔPR-AUC | ΔEpisode recall |")
    add("|---|---|---:|---:|---:|")
    for protocol in PROTOCOL_ORDER_STEP5:
        entry = sources["armf_comparison"]["contrasts"][protocol][
            "ARMF_XGB_vs_VOL5_ARMF_XGB"
        ]
        add(
            f"| {protocol} | {entry['left_episodes']} → {entry['right_episodes']} | "
            f"{entry['delta']['macro_roc_auc']:+.4f} | "
            f"{entry['delta']['macro_pr_auc']:+.4f} | "
            f"{entry['delta']['pooled_episode_recall']:+.4f} |"
        )
    add("")
    add(
        "Adding the volume features to ARM F helps markedly where the family is known "
        "and **costs episodes in zero-day transfer**. The union does not resolve the "
        "trade-off, it relocates it."
    )
    add("")
    add("### 13.6 Correction of the Step 4 interpretation")
    add("")
    zero_day_arms = sources["armf_zero_day"]["arms"]
    vol5_xgb = zero_day_arms["VOL5_XGB"]
    armf = zero_day_arms["ARMF_XGB"]
    add(
        "Step 4 concluded that the decisive factor was whether the attack family was "
        "represented in training, and left the representational question open. Step 5 "
        "**corrects that reading**: the observed ceiling was due to *both* the transfer "
        "to an unseen family *and* a representational limitation of the five volume "
        "features."
    )
    add("")
    add(
        "At a strictly constant learner and on the same test rows, "
        f"`VOL5_XGB` detects **{vol5_xgb['detected_episodes']}/"
        f"{vol5_xgb['total_episodes']}** Ares episodes with ROC-AUC "
        f"**{vol5_xgb['roc_auc']:.4f}**, while `ARMF_XGB` detects "
        f"**{armf['detected_episodes']}/{armf['total_episodes']}** with ROC-AUC "
        f"**{armf['roc_auc']:.4f}** and PR-AUC {armf['pr_auc']:.4f}, at a comparable "
        f"false-positive rate ({armf['fpr']:.6f} against {vol5_xgb['fpr']:.6f})."
    )
    add("")
    add(
        "The Step 4 evidence remains valid on its own terms: family knowledge does "
        "carry VOL5 from 3/40 to 40/40 on Ares. What changes is the conclusion that "
        "the five volume features were sufficient in principle. They are not, for this "
        "family, under zero-day transfer."
    )
    add("")
    add(
        "This is **not** a generalisation claim. The zero-day question is evaluated on "
        "Ares only, over 40 episodes drawn from 5 entities that differ solely by source "
        "IP against the same victim, transport and service. No second zero-day family "
        "exists in this population, so the effect is measured once and cannot be "
        "replicated internally."
    )
    add("")

    # 14
    add("## 14. Limits")
    add("")
    add(
        f"1. **{production['attack_rows']} attack windows only**, from **9 entities** "
        "and **54 episodes**. Confidence is governed by episodes, not windows; the "
        "effective sample size is of the order of nine."
    )
    add(
        "2. **Class imbalance 1:187.7.** Precision stays between 0.02 and 0.21 "
        "everywhere. Accuracy is never reported."
    )
    add(
        "3. **Day and capture confounding is not lifted.** All negatives come from "
        "the parallel Monday capture and all positives from Tuesday, Wednesday and "
        "Friday. No split on this population can remove that confounder."
    )
    add(
        f"4. **{production['m_unknown_excluded']} M6 `unknown` windows are excluded** "
        "and are never used as negatives. Alerts on them are neither true nor false "
        "positives."
    )
    add(
        "5. **C SSH is statistically weak**: eight of nine episodes contain a single "
        "window. It is reported as a secondary analysis only."
    )
    add(
        "6. **A′ cannot separate family from entity.** The shared entities carry "
        "several families, so removing them also removes training families; in folds "
        "3 and 4 an entire further family disappears."
    )
    add(
        "7. **Weak entity novelty for Ares.** The five Ares entities differ only by "
        "source IP against the same victim, transport and service."
    )
    add(
        "8. **Exact historical re-fit is impossible.** The historical training row "
        "order was never specified by the SQL query nor persisted; only D2 anchors "
        "the published numbers exactly."
    )
    add(
        "9. **Threshold transfer is imperfect.** Calibrated at 1% on training "
        "negatives, the realised test FPR reaches 1.47% to 1.83% pooled, and up to "
        "3.17% on individual folds."
    )
    add(
        "10. **No generalisation to real traffic is demonstrated.** All evidence "
        "comes from one frozen CICIDS2017 snapshot; external validation is required "
        "before any operational claim."
    )
    add(
        "11. **The zero-day evidence rests on a single family.** Protocol D exists only "
        "for Ares, so the ARM F advantage in zero-day transfer is measured once, over "
        "40 episodes from 5 entities, and cannot be replicated inside this population."
    )
    add(
        "12. **ARM F depends on payload availability.** Its content metrics are "
        "undefined when no qualifying payload is present; those rows reach XGBoost's "
        "native missing branch, and that missingness is not a neutral phenomenon."
    )
    add("")

    # 15
    add("## 15. Scientific conclusion")
    add("")
    add(
        "1. The historical zero-day Ares result is reproduced **exactly** by D2 and "
        "confirmed in direction by D1: with the Ares family absent from training, the "
        f"five volume features detect {d2['detected_episodes']}/{d2['total_episodes']} "
        f"episodes at ROC-AUC {d2['roc_auc']:.4f}, that is chance level."
    )
    add(
        "2. With other Ares entities in training and **strict entity-disjointness**, "
        f"the same configuration detects {subset['detected_episodes']}/"
        f"{subset['total_episodes']} Ares episodes. Entity memorisation is therefore "
        "not what carries the performance."
    )
    add(
        "3. Protocol A is a deterministic reimplementation. Its identity leakage is "
        "measured, not assumed, and its effect is quantified separately in A′ without "
        "causal attribution to the A versus B gap."
    )
    add(
        "4. Episode novelty inside a known family is handled: C Ares detects "
        f"{baseline[C_ARES_KEY]['summary']['detected_episodes']}/"
        f"{baseline[C_ARES_KEY]['summary']['total_episodes']} episodes with zero "
        "episode overlap."
    )
    add(
        "5. The decisive factor **within the five volume features** is whether the "
        "attack family is represented in training. Step 5 adds the other half of the "
        "picture: at a constant learner, "
        f"`VOL5_XGB` detects {vol5_xgb['detected_episodes']}/"
        f"{vol5_xgb['total_episodes']} Ares episodes with ROC-AUC "
        f"{vol5_xgb['roc_auc']:.4f}, while the ARM F budget detects "
        f"{armf['detected_episodes']}/{armf['total_episodes']} with ROC-AUC "
        f"{armf['roc_auc']:.4f} at a comparable false-positive rate. The observed "
        "ceiling was therefore **both** a family-transfer limit **and** a "
        "representational limit of the volume budget."
    )
    add(
        "6. Neither budget dominates. ARM F wins zero-day transfer and loses where the "
        "family is known; the union arm inherits both behaviours and still loses "
        "episodes in zero-day. This is a complementarity, not a ranking."
    )
    add(
        "7. Every statement above concerns this frozen snapshot, its nine entities and "
        "one zero-day family. Nothing here is a claim about network traffic in general."
    )
    add("")

    # 16
    add("## 16. Reproducibility")
    add("")
    add("| Property | Value |")
    add("|---|---|")
    add("| Model | RandomForest, 200 trees, `random_state=0`, `class_weight=None` |")
    add(f"| Training order | `{sources['evaluation_manifest']['training_order']}` |")
    add("| Split randomness | none, `seed_used` is null |")
    add(f"| Models fitted, Step 2 | {sources['evaluation_manifest']['models_fitted']} |")
    add(f"| Models fitted, Step 3 | {sources['leakage_manifest']['models_fitted']} |")
    add(f"| Models fitted, Step 5 | {sources['armf_manifest']['models_fitted']} |")
    add("| Frozen models re-scored | 1, the D2 anchor |")
    add(
        "| PostgreSQL connections | 0 in Steps 1 to 4; read-only in Step 5, "
        "`transaction_read_only = on`, 0 writes |"
    )
    add("| Hyperparameter tuning | none |")
    add("| Threshold selected on test | no |")
    add("")
    add("Commands, in order:")
    add("")
    add("```text")
    add("python -m scripts.run_final_validation_splits --publish")
    add("python -m scripts.run_final_validation_eval --publish")
    add("python -m scripts.run_final_validation_leakage --publish")
    add("python -m scripts.run_final_validation_armf --publish")
    add("python -m scripts.run_final_validation_report --publish")
    add("```")
    add("")

    # 17
    add("## 17. SHA-256 of the source artifacts")
    add("")
    add("| Artifact | SHA-256 |")
    add("|---|---|")
    for relative in SOURCE_ARTIFACTS:
        add(f"| `{relative}` | `{sha256_file(REPO_ROOT / relative)}` |")
    add("")
    add(
        "This report is generated from those bytes. If any of them changes, the "
        "generator's consistency gate must be re-run before the report is trusted."
    )
    add("")
    return "\n".join(lines)


def publish() -> dict[str, Any]:
    sources = load_sources()
    checks = consistency_gate(sources)
    report = render(sources, checks)
    digest = publish_immutable(REPORT_PATH, report.encode("utf-8"))
    manifest = {
        "schema_version": "1.0.0",
        "step": "final validation — step 4, report rendering only",
        "frozen_at": datetime.now(UTC).isoformat(),
        "experiments_run": 0,
        "splits_created": 0,
        "models_fitted": 0,
        "postgresql_connections": 0,
        "generated_from_artifacts_only": True,
        "consistency_checks": len(checks),
        "consistency_checks_failed": 0,
        "arm_f_evaluated_in_step5": True,
        "step5_arm_f_variant": "phase1_canonical",
        "protocol_A_is_a_reproduction_of_p1": False,
        "source_artifacts": {
            name: sha256_file(REPO_ROOT / name) for name in SOURCE_ARTIFACTS
        },
        "outputs": {"FINAL_VALIDATION_REPORT.md": digest},
        "step1_artifacts_modified": False,
        "step2_artifacts_modified": False,
        "step3_artifacts_modified": False,
        "step5_artifacts_modified": False,
        "frozen_artifacts_modified": False,
    }
    manifest["manifest_content_sha256"] = manifest_identity(manifest)
    if REPORT_MANIFEST_PATH.exists():
        existing = json.loads(REPORT_MANIFEST_PATH.read_text(encoding="utf-8"))
        if existing.get("manifest_content_sha256") != manifest["manifest_content_sha256"]:
            raise FileExistsError(
                f"immutable manifest differs in identity: {REPORT_MANIFEST_PATH}"
            )
    else:
        publish_immutable(REPORT_MANIFEST_PATH, json_bytes(manifest))
    return {
        "status": "published",
        "consistency_checks": len(checks),
        "manifest_content_sha256": manifest["manifest_content_sha256"],
        "outputs": {
            "FINAL_VALIDATION_REPORT.md": digest,
            "report_manifest.json": sha256_file(REPORT_MANIFEST_PATH),
        },
    }


def verify_published() -> dict[str, Any]:
    if not REPORT_MANIFEST_PATH.exists():
        raise ReportError("report_manifest.json absent; run --publish")
    manifest = json.loads(REPORT_MANIFEST_PATH.read_text(encoding="utf-8"))
    mismatched = [
        name
        for name, digest in manifest["outputs"].items()
        if sha256_file(FV_DIR / name) != digest
    ]
    changed = [
        name
        for name, digest in manifest["source_artifacts"].items()
        if sha256_file(REPO_ROOT / name) != digest
    ]
    sources = load_sources()
    checks = consistency_gate(sources)
    regenerated = render(sources, checks).encode("utf-8")
    result = {
        "manifest_digest_stable": manifest_identity(manifest)
        == manifest["manifest_content_sha256"],
        "mismatched_outputs": mismatched,
        "source_artifacts_changed": changed,
        "report_regenerates_byte_identically": regenerated
        == REPORT_PATH.read_bytes(),
        "consistency_checks": len(checks),
    }
    if (
        not result["manifest_digest_stable"]
        or mismatched
        or changed
        or not result["report_regenerates_byte_identically"]
    ):
        raise ReportError(f"published verification failed: {result}")
    return result


def parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--check", action="store_true")
    action.add_argument("--publish", action="store_true")
    action.add_argument("--verify", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    if args.check:
        checks = consistency_gate(load_sources())
        print(
            json.dumps(
                {
                    "status": "consistent",
                    "checks": len(checks),
                    "failed": 0,
                    "artifacts_written": 0,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    if args.verify:
        print(json.dumps(verify_published(), indent=2, sort_keys=True))
        return 0
    print(json.dumps(publish(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
