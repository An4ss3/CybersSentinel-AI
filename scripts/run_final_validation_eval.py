"""Final scientific validation — Step 2 runner: train, evaluate, publish.

Commands::

    python -m scripts.run_final_validation_eval --preflight
    python -m scripts.run_final_validation_eval --publish
    python -m scripts.run_final_validation_eval --verify

No PostgreSQL connection is opened. Every input is a frozen artifact read by
digest. Outputs are additive, under ``artifacts/experiments/final_validation/``.
"""
from __future__ import annotations

import argparse
import csv
from datetime import UTC, datetime
from hashlib import sha256
import json
import os
from pathlib import Path
from typing import Any, Final, Sequence

import joblib

from modules.detection.src.experiments.final_validation_eval import (
    ARES_FAMILY,
    HISTORICAL_ARES_ANCHOR,
    PRIMARY_FPR_TARGET,
    TRAINING_ORDER,
    EvaluationError,
    aggregate,
    build_fold,
    canonical_digest,
    canonical_order,
    compare,
    evaluate_fold,
    fold_guards,
    model_parameters,
    reproducibility_diagnostic,
    verify_historical_anchor,
)
from modules.detection.src.experiments.p1_dataset import FEATURE_NAMES, Row

REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[1]
FV_DIR: Final[Path] = REPO_ROOT / "artifacts" / "experiments" / "final_validation"
SPLITS_DIR: Final[Path] = FV_DIR / "splits"
P1_DIR: Final[Path] = REPO_ROOT / "artifacts" / "experiments" / "p1"
DATASET: Final[Path] = (
    REPO_ROOT / "artifacts" / "production" / "ml_dataset_v1" / "ml_dataset.csv"
)
FROZEN_P1_MODEL: Final[Path] = P1_DIR / "p1_model_fold0.joblib"
P1_PREDICTIONS_FOLD0: Final[Path] = P1_DIR / "p1_predictions_fold0.csv"

BASELINE_PATH: Final[Path] = FV_DIR / "baseline_metrics.json"
COMPARISON_PATH: Final[Path] = FV_DIR / "split_comparison.json"
LEAKAGE_PATH: Final[Path] = FV_DIR / "identity_leakage_diagnostic.json"
ZERO_DAY_PATH: Final[Path] = FV_DIR / "zero_day_ares.json"
REPRODUCIBILITY_PATH: Final[Path] = FV_DIR / "reproducibility_diagnostic.json"
MANIFEST_PATH: Final[Path] = FV_DIR / "evaluation_manifest.json"

EXPECTED_DATASET_SHA256: Final[str] = (
    "e95aed008d994510e4c649c287feb8fe8f49a785bec144d7e83aa15804b6c062"
)

#: protocol key -> (assignment file, requires entity-disjoint, requires episode-disjoint)
PROTOCOLS: Final[dict[str, tuple[str, bool, bool]]] = {
    "A_historical": ("A_historical_assignment.csv", False, True),
    "B_entity_disjoint": ("B_entity_disjoint_assignment.csv", True, True),
    "C_episode_disjoint_botnet_ares": (
        "C_episode_disjoint_botnet_ares_assignment.csv",
        False,
        True,
    ),
    "C_episode_disjoint_brute_force_ssh_patator": (
        "C_episode_disjoint_brute_force_ssh_patator_assignment.csv",
        False,
        True,
    ),
    "D_zero_day_ares": ("D_zero_day_ares_assignment.csv", True, True),
}

PROTOCOL_TITLES: Final[dict[str, str]] = {
    "A_historical": "A — deterministic reimplementation of the historical protocol",
    "B_entity_disjoint": "B — entity-disjoint (unseen attack entity)",
    "C_episode_disjoint_botnet_ares": "C — episode-disjoint inside botnet/ares (main)",
    "C_episode_disjoint_brute_force_ssh_patator": (
        "C — episode-disjoint inside brute_force/ssh_patator (secondary, weak)"
    ),
    "D_zero_day_ares": "D1 — zero-day Ares, re-fitted under the canonical order",
}

FROZEN_INPUTS: Final[tuple[str, ...]] = (
    "artifacts/production/ml_dataset_v1/ml_dataset.csv",
    "artifacts/experiments/p1/p1_folds.json",
    "artifacts/experiments/p1/p1_model_fold0.joblib",
    "artifacts/experiments/p1/p1_predictions_fold0.csv",
    "artifacts/experiments/p1/p1_metrics.json",
    "artifacts/experiments/final_validation/splits/splits_manifest.json",
)

IDENTITY_EXCLUDED_FIELDS: Final[frozenset[str]] = frozenset(
    {"frozen_at", "manifest_content_sha256"}
)


def sha256_file(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


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


def load_rows() -> list[Row]:
    """Read the frozen dataset, features included, after checking its identity."""
    actual = sha256_file(DATASET)
    if actual != EXPECTED_DATASET_SHA256:
        raise EvaluationError(f"production dataset digest changed: {actual}")
    rows: list[Row] = []
    with DATASET.open(newline="", encoding="utf-8") as stream:
        for record in csv.DictReader(stream):
            rows.append(
                Row(
                    row_id=record["row_id"],
                    source=record["source"],
                    label=int(record["label"]),
                    disposition=record["disposition"],
                    attack_type=record["attack_type"] or None,
                    entity_key=record["entity_key"],
                    episode_id=record["episode_id"] or None,
                    partition=record["partition"],
                    window_start_epoch=int(record["window_start_epoch"]),
                    features=tuple(float(record[name]) for name in FEATURE_NAMES),
                )
            )
    return rows


def load_assignment(name: str) -> dict[str, int]:
    with (SPLITS_DIR / name).open(newline="", encoding="utf-8") as stream:
        return {r["row_id"]: int(r["test_fold"]) for r in csv.DictReader(stream)}


def held_out_names(protocol: str) -> dict[int, str]:
    document = json.loads((SPLITS_DIR / f"{protocol}.json").read_text(encoding="utf-8"))
    return {int(f["fold"]): str(f["held_out"]) for f in document["folds"]}


def strip_scores(record: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in record.items() if k != "test_scores"}


def run_protocol(
    protocol: str, ordered: Sequence[Row], progress: bool
) -> list[dict[str, Any]]:
    assignment_file, entity_disjoint, episode_disjoint = PROTOCOLS[protocol]
    assignment = load_assignment(assignment_file)
    if set(assignment) != {row.row_id for row in ordered}:
        raise EvaluationError(f"{protocol}: assignment does not cover the population")
    names = held_out_names(protocol)
    forbid = ARES_FAMILY if protocol == "D_zero_day_ares" else None
    records: list[dict[str, Any]] = []
    for fold in sorted(names):
        data = build_fold(protocol, fold, names[fold], ordered, assignment)
        guards = fold_guards(
            data,
            require_entity_disjoint=entity_disjoint,
            require_episode_disjoint=episode_disjoint,
            forbid_family_in_train=forbid,
        )
        record = evaluate_fold(data, guards)
        records.append(record)
        if progress:
            print(
                f"  {protocol} fold{fold} roc={record['roc_auc']:.4f} "
                f"pr={record['pr_auc']:.4f} thr={record['threshold']:.6f} "
                f"ep={record['detected_episodes']}/{record['total_episodes']} "
                f"fpr={record['fpr']:.6f}",
                flush=True,
            )
    return records


def run_historical_anchor(ordered: Sequence[Row], progress: bool) -> dict[str, Any]:
    """D2 — re-score the frozen P1 model. This is not a new training run."""
    assignment = load_assignment(PROTOCOLS["D_zero_day_ares"][0])
    names = held_out_names("D_zero_day_ares")
    data = build_fold("D2_historical_anchor", 0, names[0], ordered, assignment)
    guards = fold_guards(
        data,
        require_entity_disjoint=True,
        require_episode_disjoint=True,
        forbid_family_in_train=ARES_FAMILY,
    )
    frozen = joblib.load(FROZEN_P1_MODEL)
    record = evaluate_fold(data, guards, frozen_model=frozen)
    with P1_PREDICTIONS_FOLD0.open(newline="", encoding="utf-8") as stream:
        published = {r["row_id"]: float(r["score"]) for r in csv.DictReader(stream)}
    checks = verify_historical_anchor(record, published)
    record["anchor_checks"] = checks
    record["frozen_model_sha256"] = sha256_file(FROZEN_P1_MODEL)
    record["published_predictions_sha256"] = sha256_file(P1_PREDICTIONS_FOLD0)
    record["note"] = (
        "D2 is not a new training run. It is a re-evaluation of the frozen P1 "
        "model, used as the exact historical anchor."
    )
    if progress:
        print(
            f"  D2 anchor roc={record['roc_auc']:.4f} pr={record['pr_auc']:.4f} "
            f"thr={record['threshold']:.6f} "
            f"ep={record['detected_episodes']}/{record['total_episodes']} "
            f"fpr={record['fpr']:.6f} anchor_checks={len(checks)}",
            flush=True,
        )
    return record


def build_context(progress: bool = True) -> dict[str, Any]:
    rows = load_rows()
    ordered = canonical_order(rows)
    if [r.row_id for r in ordered] != [r.row_id for r in rows]:
        raise EvaluationError("frozen dataset is not stored in (label, row_id) order")
    if progress:
        print(f"population {len(ordered)} rows, training order {TRAINING_ORDER}", flush=True)

    results: dict[str, list[dict[str, Any]]] = {}
    for protocol in PROTOCOLS:
        if progress:
            print(f"{PROTOCOL_TITLES[protocol]}", flush=True)
        results[protocol] = run_protocol(protocol, ordered, progress)
    anchor = run_historical_anchor(ordered, progress)

    summaries = {key: aggregate(records) for key, records in results.items()}
    summaries["D2_historical_anchor"] = aggregate([anchor])
    return {
        "ordered": ordered,
        "results": results,
        "anchor": anchor,
        "summaries": summaries,
    }


def baseline_document(context: dict[str, Any]) -> dict[str, Any]:
    document = {
        "experiment": "final validation — step 2 canonical baseline evaluation",
        "model": model_parameters(),
        "feature_names": list(FEATURE_NAMES),
        "feature_count": len(FEATURE_NAMES),
        "training_order": TRAINING_ORDER,
        "primary_fpr_target": PRIMARY_FPR_TARGET,
        "postgresql_connections": 0,
        "hyperparameter_tuning": "none",
        "threshold_selected_on_test": False,
        "protocol_titles": PROTOCOL_TITLES,
        "protocols": {
            key: {
                "title": PROTOCOL_TITLES[key],
                "summary": context["summaries"][key],
                "folds": [strip_scores(r) for r in records],
            }
            for key, records in context["results"].items()
        },
    }
    document["content_sha256"] = canonical_digest(document)
    return document


def comparison_document(context: dict[str, Any]) -> dict[str, Any]:
    summaries = context["summaries"]
    table = []
    for key in list(PROTOCOLS) + ["D2_historical_anchor"]:
        summary = summaries[key]
        title = PROTOCOL_TITLES.get(
            key, "D2 — historical anchor, frozen P1 model, no new training"
        )
        table.append(
            {
                "protocol": key,
                "title": title,
                "folds": summary["folds"],
                "train_rows_range": summary["train_rows_range"],
                "test_rows_total": summary["test_rows_total"],
                "entity_count_train_range": summary["entity_count_train_range"],
                "max_entity_intersection": summary["max_entity_intersection"],
                "max_episode_intersection": summary["max_episode_intersection"],
                "macro_roc_auc": summary["macro_roc_auc"],
                "macro_pr_auc": summary["macro_pr_auc"],
                "pooled_recall": summary["pooled_recall"],
                "pooled_precision": summary["pooled_precision"],
                "pooled_f1": summary["pooled_f1"],
                "pooled_fpr": summary["pooled_fpr"],
                "pooled_episode_recall": summary["pooled_episode_recall"],
                "detected_episodes": summary["detected_episodes"],
                "total_episodes": summary["total_episodes"],
            }
        )
    document = {
        "experiment": "final validation — step 2 split comparison",
        "interpretation_boundaries": {
            "A": "family novelty, but identity leakage is possible and measured",
            "B": "entity novelty; the attack family may already be known",
            "C": "episode novelty inside a family that is present in training",
            "D1": "the Ares family is completely absent from training, re-fitted",
            "D2": "historical anchor: frozen P1 model re-scored, no new training",
        },
        "table": table,
        "A_vs_B": compare(summaries["A_historical"], summaries["B_entity_disjoint"]),
        "A_vs_C_ares": compare(
            summaries["A_historical"], summaries["C_episode_disjoint_botnet_ares"]
        ),
        "A_vs_D1": compare(summaries["A_historical"], summaries["D_zero_day_ares"]),
        "D1_vs_D2": compare(
            summaries["D_zero_day_ares"], summaries["D2_historical_anchor"]
        ),
    }
    document["content_sha256"] = canonical_digest(document)
    return document


def leakage_document(context: dict[str, Any]) -> dict[str, Any]:
    summaries = context["summaries"]
    a = summaries["A_historical"]
    b = summaries["B_entity_disjoint"]
    a_folds = context["results"]["A_historical"]
    b_folds = context["results"]["B_entity_disjoint"]
    document = {
        "experiment": "final validation — step 2 identity leakage diagnostic",
        "statement": (
            "Protocol A carries a measured identity leakage: two entity_key values "
            "span several attack types, so folds 2, 3 and 4 share an attack entity "
            "between train and test. Experiment B quantifies its impact by forbidding "
            "any shared entity."
        ),
        "measured_leakage_in_A": {
            "folds_with_shared_attack_entity": [
                r["fold"] for r in a_folds if r["entity_intersection_count"] > 0
            ],
            "shared_entities_by_fold": {
                str(r["fold"]): r["entity_intersection"]
                for r in a_folds
                if r["entity_intersection_count"] > 0
            },
            "max_entity_intersection": a["max_entity_intersection"],
        },
        "entity_disjointness_in_B": {
            "max_entity_intersection": b["max_entity_intersection"],
            "folds": b["folds"],
        },
        "variation_A_to_B": compare(a, b),
        "per_fold": {
            "A": [
                {
                    "fold": r["fold"],
                    "held_out": r["held_out"],
                    "roc_auc": r["roc_auc"],
                    "pr_auc": r["pr_auc"],
                    "recall": r["recall"],
                    "precision": r["precision"],
                    "fpr": r["fpr"],
                    "episode_recall": r["episode_recall"],
                    "detected_episodes": r["detected_episodes"],
                    "total_episodes": r["total_episodes"],
                    "entity_intersection_count": r["entity_intersection_count"],
                }
                for r in a_folds
            ],
            "B": [
                {
                    "fold": r["fold"],
                    "held_out": r["held_out"],
                    "roc_auc": r["roc_auc"],
                    "pr_auc": r["pr_auc"],
                    "recall": r["recall"],
                    "precision": r["precision"],
                    "fpr": r["fpr"],
                    "episode_recall": r["episode_recall"],
                    "detected_episodes": r["detected_episodes"],
                    "total_episodes": r["total_episodes"],
                    "entity_intersection_count": r["entity_intersection_count"],
                    "test_attack_type_windows": r["test_attack_type_windows"],
                }
                for r in b_folds
            ],
        },
        "caution": (
            "A and B do not answer the same question. A withholds an attack family; "
            "B withholds an attack entity while the family may remain in training. A "
            "difference between them is therefore not attributable to identity "
            "leakage alone."
        ),
    }
    document["content_sha256"] = canonical_digest(document)
    return document


def zero_day_document(context: dict[str, Any]) -> dict[str, Any]:
    d1 = context["results"]["D_zero_day_ares"][0]
    d2 = context["anchor"]
    document = {
        "experiment": "final validation — step 2 zero-day Ares",
        "protocol": "Ares completely absent from training; threshold from train negatives only",
        "D1_refitted": {
            "description": "re-fitted RandomForest P1 under the canonical (label,row_id) order",
            **strip_scores(d1),
        },
        "D2_historical_anchor": {
            "description": (
                "D2 is not a new training run. It is a re-evaluation of the frozen "
                "P1 model, used as the exact historical anchor."
            ),
            **strip_scores(d2),
        },
        "historical_published_values": HISTORICAL_ARES_ANCHOR,
        "D1_vs_D2": {
            "roc_auc": [d1["roc_auc"], d2["roc_auc"]],
            "pr_auc": [d1["pr_auc"], d2["pr_auc"]],
            "threshold": [d1["threshold"], d2["threshold"]],
            "fpr": [d1["fpr"], d2["fpr"]],
            "tp": [d1["tp"], d2["tp"]],
            "detected_episodes": [d1["detected_episodes"], d2["detected_episodes"]],
            "identical_test_membership": d1["test_rows"] == d2["test_rows"],
        },
        "ares_absent_from_training": {
            "D1": d1["train_attack_type_windows"].get(ARES_FAMILY, 0) == 0,
            "D2": d2["train_attack_type_windows"].get(ARES_FAMILY, 0) == 0,
        },
    }
    document["content_sha256"] = canonical_digest(document)
    return document


def summarise(context: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": "preflight_ok",
        "artifacts_written": 0,
        "training_order": TRAINING_ORDER,
        "models_fitted": sum(len(v) for v in context["results"].values()),
        "frozen_models_rescored": 1,
        "postgresql_connections": 0,
        "protocols": {
            key: {
                "folds": summary["folds"],
                "macro_roc_auc": round(summary["macro_roc_auc"], 4),
                "macro_pr_auc": round(summary["macro_pr_auc"], 4),
                "pooled_recall": round(summary["pooled_recall"], 4),
                "pooled_precision": round(summary["pooled_precision"], 4),
                "pooled_fpr": round(summary["pooled_fpr"], 6),
                "pooled_episode_recall": round(summary["pooled_episode_recall"], 4),
                "episodes": f"{summary['detected_episodes']}/{summary['total_episodes']}",
                "max_entity_intersection": summary["max_entity_intersection"],
                "max_episode_intersection": summary["max_episode_intersection"],
            }
            for key, summary in context["summaries"].items()
        },
        "anchor_checks_passed": len(context["anchor"]["anchor_checks"]),
    }


def publish(context: dict[str, Any]) -> dict[str, Any]:
    outputs: dict[str, str] = {}
    outputs["baseline_metrics.json"] = publish_immutable(
        BASELINE_PATH, json_bytes(baseline_document(context))
    )
    outputs["split_comparison.json"] = publish_immutable(
        COMPARISON_PATH, json_bytes(comparison_document(context))
    )
    outputs["identity_leakage_diagnostic.json"] = publish_immutable(
        LEAKAGE_PATH, json_bytes(leakage_document(context))
    )
    outputs["zero_day_ares.json"] = publish_immutable(
        ZERO_DAY_PATH, json_bytes(zero_day_document(context))
    )
    outputs["reproducibility_diagnostic.json"] = publish_immutable(
        REPRODUCIBILITY_PATH, json_bytes(reproducibility_diagnostic())
    )
    manifest = {
        "schema_version": "1.0.0",
        "step": "final validation — step 2, canonical evaluation",
        "frozen_at": datetime.now(UTC).isoformat(),
        "model": model_parameters(),
        "feature_names": list(FEATURE_NAMES),
        "training_order": TRAINING_ORDER,
        "models_fitted": sum(len(v) for v in context["results"].values()),
        "frozen_models_rescored": 1,
        "postgresql_connections": 0,
        "postgresql_writes": 0,
        "hyperparameter_tuning": "none",
        "threshold_selected_on_test": False,
        "arm_f_evaluated": False,
        "protocol_A_is_a_reproduction_of_p1": False,
        "protocol_A_label": PROTOCOL_TITLES["A_historical"],
        "historical_anchor_verified": True,
        "frozen_inputs": {name: sha256_file(REPO_ROOT / name) for name in FROZEN_INPUTS},
        "outputs": outputs,
        "step1_artifacts_modified": False,
        "frozen_artifacts_modified": False,
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
        "outputs": {**outputs, "evaluation_manifest.json": sha256_file(MANIFEST_PATH)},
    }


def verify_published() -> dict[str, Any]:
    if not MANIFEST_PATH.exists():
        raise EvaluationError("evaluation_manifest.json absent; run --publish")
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    mismatched = [
        name
        for name, digest in manifest["outputs"].items()
        if sha256_file(FV_DIR / name) != digest
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
        raise EvaluationError(f"published verification failed: {result}")
    return result


def parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--preflight", action="store_true")
    action.add_argument("--publish", action="store_true")
    action.add_argument("--verify", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
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
