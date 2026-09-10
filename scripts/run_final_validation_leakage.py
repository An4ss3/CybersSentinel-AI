"""Final validation — Step 3 runner: measure A versus A' on folds 2, 3 and 4.

Commands::

    python -m scripts.run_final_validation_leakage --diagnostic
    python -m scripts.run_final_validation_leakage --preflight
    python -m scripts.run_final_validation_leakage --publish
    python -m scripts.run_final_validation_leakage --verify

``--diagnostic`` prints the pre-training facts only: nothing is fitted and nothing
is written. No PostgreSQL connection is ever opened.
"""
from __future__ import annotations

import argparse
from datetime import UTC, datetime
from hashlib import sha256
import json
import os
from pathlib import Path
from typing import Any, Final, Sequence

from modules.detection.src.experiments.final_validation_leakage import (
    COMPARED_METRICS,
    TARGET_FOLDS,
    LeakageExperimentError,
    build_a_prime,
    delta,
    evaluate_pair,
    experiment_configuration,
    removal_diagnostic,
    shared_attack_entities,
    summarise_pair,
)
from modules.detection.src.experiments.final_validation_eval import (
    TRAINING_ORDER,
    build_fold,
    canonical_digest,
    canonical_order,
    model_parameters,
)
from modules.detection.src.experiments.p1_dataset import FEATURE_NAMES
from scripts.run_final_validation_eval import (
    BASELINE_PATH,
    FV_DIR,
    PROTOCOLS,
    held_out_names,
    load_assignment,
    load_rows,
    sha256_file,
    strip_scores,
)

REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[1]
OUT_DIR: Final[Path] = FV_DIR / "identity_leakage"
CONFIG_PATH: Final[Path] = OUT_DIR / "ap_config.json"
DIAGNOSTIC_PATH: Final[Path] = OUT_DIR / "ap_diagnostic.json"
COMPARISON_PATH: Final[Path] = OUT_DIR / "ap_comparison.json"
MANIFEST_PATH: Final[Path] = OUT_DIR / "manifest.json"
REPORT_PATH: Final[Path] = OUT_DIR / "AP_IDENTITY_LEAKAGE_REPORT.md"

A_PROTOCOL: Final[str] = "A_historical"

FROZEN_INPUTS: Final[tuple[str, ...]] = (
    "artifacts/production/ml_dataset_v1/ml_dataset.csv",
    "artifacts/experiments/p1/p1_folds.json",
    "artifacts/experiments/final_validation/splits/A_historical_assignment.csv",
    "artifacts/experiments/final_validation/splits/splits_manifest.json",
    "artifacts/experiments/final_validation/baseline_metrics.json",
    "artifacts/experiments/final_validation/evaluation_manifest.json",
)

IDENTITY_EXCLUDED_FIELDS: Final[frozenset[str]] = frozenset(
    {"frozen_at", "manifest_content_sha256"}
)


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


def build_folds() -> dict[int, Any]:
    """Rebuild protocol A folds 2, 3 and 4 from the frozen step-1 assignment."""
    ordered = canonical_order(load_rows())
    assignment = load_assignment(PROTOCOLS[A_PROTOCOL][0])
    names = held_out_names(A_PROTOCOL)
    folds: dict[int, Any] = {}
    for fold in TARGET_FOLDS:
        folds[fold] = build_fold(A_PROTOCOL, fold, names[fold], ordered, assignment)
    return folds


def run_diagnostic() -> dict[str, Any]:
    """Produce every pre-training fact. Fits nothing, writes nothing."""
    folds = build_folds()
    entries = []
    for fold in TARGET_FOLDS:
        data = folds[fold]
        prime, removal = build_a_prime(data)
        entries.append(removal_diagnostic(data, prime, removal))
    document = {
        "experiment": "final validation — step 3 pre-training diagnostic",
        "models_fitted": 0,
        "artifacts_written": 0,
        "postgresql_connections": 0,
        "folds": entries,
    }
    document["content_sha256"] = canonical_digest(document)
    return document


def published_a_baseline() -> dict[int, dict[str, Any]]:
    """The step-2 protocol A results, read only to cross-check determinism."""
    document = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    return {
        int(fold["fold"]): fold
        for fold in document["protocols"][A_PROTOCOL]["folds"]
        if int(fold["fold"]) in TARGET_FOLDS
    }


def build_context(progress: bool = True) -> dict[str, Any]:
    folds = build_folds()
    published = published_a_baseline()
    diagnostics: list[dict[str, Any]] = []
    records_a: list[dict[str, Any]] = []
    records_prime: list[dict[str, Any]] = []
    comparisons: dict[str, Any] = {}
    consistency: list[dict[str, Any]] = []

    for fold in TARGET_FOLDS:
        data = folds[fold]
        prime, removal = build_a_prime(data)
        diagnostic = removal_diagnostic(data, prime, removal)
        diagnostics.append(diagnostic)
        record_a, record_prime = evaluate_pair(data, prime)

        # Determinism cross-check against the frozen step-2 numbers.
        reference = published[fold]
        mismatched = [
            key
            for key in ("roc_auc", "pr_auc", "threshold", "fpr", "tp", "fp", "tn", "fn")
            if reference[key] != record_a[key]
        ]
        if mismatched:
            raise LeakageExperimentError(
                f"fold{fold}: recomputed A diverges from published step 2 on {mismatched}"
            )
        consistency.append(
            {
                "fold": fold,
                "recomputed_A_matches_published_step2": True,
                "compared_keys": [
                    "roc_auc",
                    "pr_auc",
                    "threshold",
                    "fpr",
                    "tp",
                    "fp",
                    "tn",
                    "fn",
                ],
            }
        )

        records_a.append(record_a)
        records_prime.append(record_prime)
        comparisons[str(fold)] = {
            "held_out_attack_type": data.held_out,
            "shared_entities": list(removal.shared_entities),
            "positive_rows_removed_from_train": len(removal.removed_row_ids),
            **delta(record_a, record_prime),
        }
        if progress:
            print(
                f"  fold{fold} {data.held_out:26} "
                f"A roc={record_a['roc_auc']:.4f} ep={record_a['detected_episodes']}/"
                f"{record_a['total_episodes']} fpr={record_a['fpr']:.6f}  ->  "
                f"A' roc={record_prime['roc_auc']:.4f} "
                f"ep={record_prime['detected_episodes']}/{record_prime['total_episodes']} "
                f"fpr={record_prime['fpr']:.6f}",
                flush=True,
            )

    return {
        "diagnostics": diagnostics,
        "records_a": records_a,
        "records_prime": records_prime,
        "comparisons": comparisons,
        "consistency": consistency,
        "summary": summarise_pair(records_a, records_prime),
    }


def fold_document(
    fold: int, context: dict[str, Any]
) -> dict[str, Any]:
    index = TARGET_FOLDS.index(fold)
    document = {
        "fold": fold,
        "diagnostic": context["diagnostics"][index],
        "A": strip_scores(context["records_a"][index]),
        "A_prime": strip_scores(context["records_prime"][index]),
        "comparison": context["comparisons"][str(fold)],
        "consistency_with_step2": context["consistency"][index],
    }
    document["content_sha256"] = canonical_digest(document)
    return document


def comparison_document(context: dict[str, Any]) -> dict[str, Any]:
    table = []
    for fold in TARGET_FOLDS:
        entry = context["comparisons"][str(fold)]
        row = {
            "fold": fold,
            "held_out_attack_type": entry["held_out_attack_type"],
            "positive_rows_removed_from_train": entry["positive_rows_removed_from_train"],
        }
        for key in COMPARED_METRICS:
            row[f"A_{key}"] = entry["A"][key]
            row[f"Aprime_{key}"] = entry["A_prime"][key]
            if key in entry["delta"]:
                row[f"delta_{key}"] = entry["delta"][key]
        table.append(row)
    directions = {
        str(fold): {
            "episode_recall": _direction(
                context["comparisons"][str(fold)]["delta"]["episode_recall"]
            ),
            "roc_auc": _direction(
                context["comparisons"][str(fold)]["delta"]["roc_auc"]
            ),
            "pr_auc": _direction(context["comparisons"][str(fold)]["delta"]["pr_auc"]),
        }
        for fold in TARGET_FOLDS
    }
    document = {
        "experiment": "final validation — step 3 A versus A'",
        "folds": list(TARGET_FOLDS),
        "table": table,
        "per_fold_direction": directions,
        "pooled": context["summary"],
        "scope": (
            "marginal effect of removing the shared attack entities in historical "
            "folds 2, 3 and 4, at constant held-out family"
        ),
        "forbidden_claims": experiment_configuration()["forbidden_claims"],
        "known_coupling": experiment_configuration()["known_coupling"],
    }
    document["content_sha256"] = canonical_digest(document)
    return document


def _direction(value: float) -> str:
    if value > 0:
        return "A_prime_higher"
    if value < 0:
        return "A_prime_lower"
    return "identical"


def render_report(context: dict[str, Any], comparison: dict[str, Any]) -> str:
    lines = [
        "# A versus A' — marginal effect of removing shared attack entities",
        "",
        "## Question",
        "",
        "Inside the historical protocol A, with the held-out attack family held "
        "constant, does the presence of the same `entity_key` in train and test "
        "change the measured performance?",
        "",
        "## Construction",
        "",
        "`A'` differs from `A` by exactly one operation: the positive training rows "
        "whose `entity_key` also appears among the test positives are removed. The "
        "test population, every negative, the five frozen features, the model, the "
        f"`{TRAINING_ORDER}` training order and the train-negative-only threshold "
        "calibration are unchanged.",
        "",
        "## Removal performed",
        "",
        "| Fold | Held-out family | Shared entities | Positives removed | Train positives |",
        "|---:|---|---|---:|---|",
    ]
    for diagnostic in context["diagnostics"]:
        lines.append(
            f"| {diagnostic['fold']} | `{diagnostic['held_out_attack_type']}` | "
            f"{len(diagnostic['shared_entities'])} | "
            f"{diagnostic['positive_rows_removed_from_train']} | "
            f"{diagnostic['train_positives_before']} → "
            f"{diagnostic['train_positives_after']} |"
        )
    lines.extend(
        [
            "",
            "## Results",
            "",
            "| Fold | Variant | ROC-AUC | PR-AUC | Threshold | FPR | TP | FP | Recall | Precision | F1 | Episodes |",
            "|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for fold in TARGET_FOLDS:
        entry = context["comparisons"][str(fold)]
        for name, values in (("A", entry["A"]), ("A'", entry["A_prime"])):
            lines.append(
                f"| {fold} | {name} | {values['roc_auc']:.4f} | {values['pr_auc']:.4f} | "
                f"{values['threshold']:.6f} | {values['fpr']:.6f} | {values['tp']} | "
                f"{values['fp']} | {values['recall']:.4f} | {values['precision']:.4f} | "
                f"{values['f1']:.4f} | {values['detected_episodes']}/{values['total_episodes']} |"
            )
    lines.extend(
        [
            "",
            "## Delta, A' minus A",
            "",
            "| Fold | ΔROC-AUC | ΔPR-AUC | ΔFPR | ΔRecall | ΔPrecision | ΔEpisode recall | ΔEpisodes |",
            "|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for fold in TARGET_FOLDS:
        d = context["comparisons"][str(fold)]["delta"]
        lines.append(
            f"| {fold} | {d['roc_auc']:+.4f} | {d['pr_auc']:+.4f} | {d['fpr']:+.6f} | "
            f"{d['recall']:+.4f} | {d['precision']:+.4f} | {d['episode_recall']:+.4f} | "
            f"{d['detected_episodes']:+d} |"
        )
    lines.extend(
        [
            "",
            "## Scope and coupling",
            "",
            comparison["known_coupling"],
            "",
            "This experiment measures only the marginal effect of removing the shared "
            "entities in folds 2, 3 and 4 at constant held-out family. It does not "
            "state that leakage explains, or fails to explain, the A versus B "
            "difference.",
            "",
        ]
    )
    return "\n".join(lines)


def summarise(context: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": "preflight_ok",
        "artifacts_written": 0,
        "models_fitted": 2 * len(TARGET_FOLDS),
        "postgresql_connections": 0,
        "training_order": TRAINING_ORDER,
        "recomputed_A_matches_published_step2": all(
            entry["recomputed_A_matches_published_step2"]
            for entry in context["consistency"]
        ),
        "folds": {
            str(fold): {
                "held_out": context["comparisons"][str(fold)]["held_out_attack_type"],
                "removed": context["comparisons"][str(fold)][
                    "positive_rows_removed_from_train"
                ],
                "A": {
                    k: context["comparisons"][str(fold)]["A"][k]
                    for k in ("roc_auc", "pr_auc", "fpr", "detected_episodes", "total_episodes")
                },
                "A_prime": {
                    k: context["comparisons"][str(fold)]["A_prime"][k]
                    for k in ("roc_auc", "pr_auc", "fpr", "detected_episodes", "total_episodes")
                },
                "delta_episode_recall": context["comparisons"][str(fold)]["delta"][
                    "episode_recall"
                ],
            }
            for fold in TARGET_FOLDS
        },
    }


def publish(context: dict[str, Any]) -> dict[str, Any]:
    outputs: dict[str, str] = {}
    outputs["ap_config.json"] = publish_immutable(
        CONFIG_PATH, json_bytes(experiment_configuration())
    )
    diagnostic = {
        "experiment": "final validation — step 3 pre-training diagnostic",
        "models_fitted": 0,
        "postgresql_connections": 0,
        "folds": context["diagnostics"],
    }
    diagnostic["content_sha256"] = canonical_digest(diagnostic)
    outputs["ap_diagnostic.json"] = publish_immutable(
        DIAGNOSTIC_PATH, json_bytes(diagnostic)
    )
    for fold in TARGET_FOLDS:
        name = f"ap_fold{fold}.json"
        outputs[name] = publish_immutable(
            OUT_DIR / name, json_bytes(fold_document(fold, context))
        )
    comparison = comparison_document(context)
    outputs["ap_comparison.json"] = publish_immutable(
        COMPARISON_PATH, json_bytes(comparison)
    )
    outputs["AP_IDENTITY_LEAKAGE_REPORT.md"] = publish_immutable(
        REPORT_PATH, render_report(context, comparison).encode("utf-8")
    )
    manifest = {
        "schema_version": "1.0.0",
        "step": "final validation — step 3, shared-entity removal (A vs A')",
        "frozen_at": datetime.now(UTC).isoformat(),
        "model": model_parameters(),
        "feature_names": list(FEATURE_NAMES),
        "training_order": TRAINING_ORDER,
        "folds": list(TARGET_FOLDS),
        "models_fitted": 2 * len(TARGET_FOLDS),
        "postgresql_connections": 0,
        "postgresql_writes": 0,
        "randomness_added": False,
        "hyperparameter_tuning": "none",
        "threshold_selected_on_test": False,
        "recomputed_A_matches_published_step2": True,
        "step1_artifacts_modified": False,
        "step2_artifacts_modified": False,
        "frozen_artifacts_modified": False,
        "frozen_inputs": {name: sha256_file(REPO_ROOT / name) for name in FROZEN_INPUTS},
        "outputs": outputs,
    }
    manifest["manifest_content_sha256"] = manifest_identity(manifest)
    if MANIFEST_PATH.exists():
        existing = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        if existing.get("manifest_content_sha256") != manifest["manifest_content_sha256"]:
            raise FileExistsError(f"immutable manifest differs in identity: {MANIFEST_PATH}")
    else:
        publish_immutable(MANIFEST_PATH, json_bytes(manifest))
    return {
        "status": "published",
        "manifest_content_sha256": manifest["manifest_content_sha256"],
        "outputs": {**outputs, "manifest.json": sha256_file(MANIFEST_PATH)},
    }


def verify_published() -> dict[str, Any]:
    if not MANIFEST_PATH.exists():
        raise LeakageExperimentError("manifest.json absent; run --publish")
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    mismatched = [
        name
        for name, digest in manifest["outputs"].items()
        if sha256_file(OUT_DIR / name) != digest
    ]
    frozen_changed = [
        name
        for name, digest in manifest["frozen_inputs"].items()
        if sha256_file(REPO_ROOT / name) != digest
    ]
    result = {
        "manifest_digest_stable": manifest_identity(manifest)
        == manifest["manifest_content_sha256"],
        "mismatched_outputs": mismatched,
        "frozen_inputs_changed": frozen_changed,
        "outputs": sorted(manifest["outputs"]),
    }
    if not result["manifest_digest_stable"] or mismatched or frozen_changed:
        raise LeakageExperimentError(f"published verification failed: {result}")
    return result


def parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--diagnostic", action="store_true")
    action.add_argument("--preflight", action="store_true")
    action.add_argument("--publish", action="store_true")
    action.add_argument("--verify", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    if args.diagnostic:
        print(json.dumps(run_diagnostic(), indent=2, sort_keys=True))
        return 0
    if args.verify:
        print(json.dumps(verify_published(), indent=2, sort_keys=True))
        return 0
    context = build_context()
    if args.preflight:
        print(json.dumps(summarise(context), indent=2, sort_keys=True))
        return 0
    print(json.dumps(publish(context), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
