"""Pre-register and execute leak-free surrogate tuning for frozen ARM F.

Commands:
    python -m scripts.run_armf_tuning --preregister
    python -m scripts.run_armf_tuning --preflight
    python -m scripts.run_armf_tuning --execute

The execute command refuses to fit unless the immutable pre-registration exists
and exactly matches the code-generated protocol. The outer Ares test is withheld
from every candidate fit, early-stopping evaluation, threshold and selection.
"""
from __future__ import annotations

import argparse
from collections.abc import Sequence
import csv
from dataclasses import replace
from datetime import UTC, datetime
from hashlib import sha256
import io
import json
import math
import os
from pathlib import Path
from typing import Any, Final

import joblib
import numpy as np
from sklearn.metrics import average_precision_score, roc_auc_score

from modules.detection.src.experiments.armf_tuning import (
    FINAL_EVALUATION_TARGETS,
    PRIMARY_TRAIN_FPR,
    CandidateResult,
    TuningError,
    build_model,
    candidate_configurations,
    evaluate_inner_fold,
    formatting_independent_digest,
    preregistration_document,
    result_document,
    select_candidate,
    summarise_candidate,
)
from modules.detection.src.experiments.content_benchmark import (
    paired_episode_bootstrap_delta,
    per_entity_recall,
)
from modules.detection.src.experiments.p1_dataset import (
    Row,
    build_folds,
    dataset_digest,
    folds_digest,
    load_negatives,
    load_positives,
)
from modules.detection.src.experiments.p1_evaluation import (
    episode_bootstrap_recall,
    episode_recall,
    threshold_at_train_fpr,
)
from modules.detection.src.experiments.ratification import ARM_F_FEATURES
from scripts.run_content_benchmark import (
    P1_DATASET_CONTENT_SHA256,
    P1_FOLDS_CONTENT_SHA256,
    build_model_rows,
    load_content_features,
    verify_frozen_files,
    verify_protocol,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
P1_DIR: Final[Path] = REPO_ROOT / "artifacts" / "experiments" / "p1"
PHASE1_DIR: Final[Path] = (
    REPO_ROOT / "artifacts" / "experiments" / "armf_ratification_armj1"
)
OUT_DIR: Final[Path] = (
    REPO_ROOT / "artifacts" / "experiments" / "xgboost_armf_tuning"
)


def _sha(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, indent=2, sort_keys=True, allow_nan=True).encode("utf-8")
        + b"\n"
    )


def _publish_bytes(path: Path, payload: bytes) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() != payload:
            raise FileExistsError(f"immutable artifact differs: {path}")
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


def _identity(document: dict[str, Any]) -> dict[str, Any]:
    return {
        k: v
        for k, v in document.items()
        if k not in ("started_at", "completed_at", "content_sha256")
    }


def _publish_document(path: Path, document: dict[str, Any]) -> tuple[str, str]:
    value = dict(document)
    value["content_sha256"] = sha256(
        json.dumps(
            _identity(value), sort_keys=True, separators=(",", ":"), allow_nan=True
        ).encode("utf-8")
    ).hexdigest()
    payload = _json_bytes(value)
    if path.exists():
        existing = json.loads(path.read_text(encoding="utf-8"))
        if existing.get("content_sha256") != value["content_sha256"]:
            raise FileExistsError(f"immutable document differs: {path}")
        return value["content_sha256"], _sha(path)
    return value["content_sha256"], _publish_bytes(path, payload)


def _record(checks: list[dict[str, Any]], name: str, passed: bool, detail: Any) -> None:
    checks.append({"check": name, "passed": bool(passed), "detail": detail})
    if not passed:
        raise TuningError(f"{name}: {detail}")


def render_search_space(document: dict[str, Any], digest: str) -> str:
    search = document["search"]
    lines = [
        "# Phase 2 ARM F tuning — immutable pre-registration",
        "",
        f"Protocol identity: `{digest}`",
        "",
        "This document was published before any candidate was fitted or any outer-test",
        "score was inspected. The final Ares test is unavailable during tuning.",
        "",
        "## Leakage boundary",
        "",
        "- outer test: frozen `fold0.test`, 13,951 rows, 177 Ares positives; forbidden during tuning",
        "- tuning pool: frozen `fold0.train`, 57,003 rows, zero Ares",
        "- four internal validations: `fold_k.test ∩ fold0.train`, k=1..4",
        "- outer-test overlap of every internal train and validation: zero",
        "",
        "## Surrogate objective",
        "",
        "Maximise unweighted macro episode recall over FTP, SSH, DDOS and Hulk at",
        "`target_train_fpr=0.005`, subject to pooled validation FPR <= 0.005 and",
        "every validation-fold FPR <= 0.01. Constraints are never relaxed post hoc.",
        "Ares optimisation claims are forbidden; Ares is a one-shot transfer test.",
        "",
        "## Search space",
        "",
        "| Parameter | Values |",
        "|---|---|",
    ]
    for name, values in search["space"].items():
        lines.append(f"| `{name}` | {', '.join(str(v) for v in values)} |")
    lines.extend(
        [
            "",
            f"Method: deterministic random search without replacement, seed "
            f"`{search['seed']}`, {search['random_configurations']} random configurations",
            "plus the fixed 200-tree Phase-1 control. Early stopping: validation AUCPR,",
            "50 rounds. Selection remains episode recall under hard FPR constraints.",
            "",
            "## Exact candidate list",
            "",
            "| ID | depth | eta | max trees | alpha | lambda | child | subsample | colsample | ES |",
            "|---|---:|---:|---:|---:|---:|---:|---:|---:|---|",
        ]
    )
    for c in search["candidates"]:
        p = c["params"]
        lines.append(
            f"| {c['candidate_id']} | {p['max_depth']} | {p['learning_rate']} | "
            f"{p['max_n_estimators']} | {p['reg_alpha']} | {p['reg_lambda']} | "
            f"{p['min_child_weight']} | {p['subsample']} | "
            f"{p['colsample_bytree']} | {'yes' if c['early_stopping'] else 'no'} |"
        )
    return "\n".join(lines) + "\n"


def publish_preregistration() -> str:
    document = preregistration_document()
    digest = formatting_independent_digest(document)
    wrapper = {"pre_registration_sha256": digest, "protocol": document}
    _publish_bytes(OUT_DIR / "PRE_REGISTRATION.json", _json_bytes(wrapper))
    _publish_bytes(
        OUT_DIR / "SEARCH_SPACE.md",
        render_search_space(document, digest).encode("utf-8"),
    )
    return digest


def verify_preregistration() -> tuple[dict[str, Any], str]:
    path = OUT_DIR / "PRE_REGISTRATION.json"
    if not path.exists():
        raise TuningError("PRE_REGISTRATION.json is absent; run --preregister first")
    published = json.loads(path.read_text(encoding="utf-8"))
    expected = preregistration_document()
    digest = formatting_independent_digest(expected)
    if published != {"pre_registration_sha256": digest, "protocol": expected}:
        raise TuningError("published pre-registration differs from executable protocol")
    expected_markdown = render_search_space(expected, digest).encode("utf-8")
    if (OUT_DIR / "SEARCH_SPACE.md").read_bytes() != expected_markdown:
        raise TuningError("published search-space document differs")
    return expected, digest


def build_context() -> tuple[
    list[Row], list[Any], dict[str, Row], list[dict[str, Any]], list[dict[str, Any]]
]:
    frozen_checks = verify_frozen_files()
    positives = load_positives(str(REPO_ROOT))
    negatives = load_negatives()
    rows = positives + negatives
    folds = build_folds(positives, negatives)
    if dataset_digest(rows) != P1_DATASET_CONTENT_SHA256:
        raise TuningError("P1 population content digest mismatch")
    if folds_digest(folds) != P1_FOLDS_CONTENT_SHA256:
        raise TuningError("P1 folds content digest mismatch")
    protocol_checks = verify_protocol(rows, folds)
    content, content_info = load_content_features(rows)
    by_model, build_info = build_model_rows(rows, content)
    arm_rows = by_model["F"]
    if tuple(ARM_F_FEATURES) != (
        "distinct_payload_ratio",
        "source_non_printable_ratio",
        "destination_non_printable_ratio",
    ):
        raise TuningError("ARM F budget changed")
    by_id = {r.row_id: r for r in arm_rows}
    checks: list[dict[str, Any]] = []
    checks.extend(content_info["checks"])
    checks.extend(build_info["checks"])
    return rows, folds, by_id, frozen_checks + protocol_checks, checks


def build_inner_memberships(
    folds: list[Any], by_id: dict[str, Row]
) -> tuple[list[dict[str, Any]], set[str], set[str], list[dict[str, Any]]]:
    outer = next(f for f in folds if f.index == 0)
    outer_train = set(outer.train_row_ids)
    outer_test = set(outer.test_row_ids)
    checks: list[dict[str, Any]] = []
    inner: list[dict[str, Any]] = []
    validation_union: set[str] = set()
    for fold in sorted((f for f in folds if f.index != 0), key=lambda f: f.index):
        validation_ids = [rid for rid in fold.test_row_ids if rid in outer_train]
        validation_set = set(validation_ids)
        training_ids = [rid for rid in outer.train_row_ids if rid not in validation_set]
        train_set = set(training_ids)
        validation_union.update(validation_set)
        _record(checks, f"inner{fold.index}_training_excludes_outer_test",
                not (train_set & outer_test), len(train_set & outer_test))
        _record(checks, f"inner{fold.index}_validation_excludes_outer_test",
                not (validation_set & outer_test), len(validation_set & outer_test))
        _record(checks, f"inner{fold.index}_train_validation_disjoint",
                not (train_set & validation_set), len(train_set & validation_set))
        attack_types = {
            by_id[rid].attack_type
            for rid in validation_ids
            if by_id[rid].label == 1
        }
        _record(checks, f"inner{fold.index}_holds_only_declared_positive_type",
                attack_types == {fold.held_out_attack_type}, sorted(attack_types))
        inner.append(
            {
                "fold": fold.index,
                "held_out_attack_type": fold.held_out_attack_type,
                "training_ids": training_ids,
                "validation_ids": validation_ids,
            }
        )
    _record(checks, "inner_validation_union_is_exactly_outer_train",
            validation_union == outer_train,
            {"union": len(validation_union), "outer_train": len(outer_train)})
    _record(checks, "outer_train_contains_zero_ares_rows",
            not any(by_id[rid].attack_type == "botnet/ares" for rid in outer_train), 0)
    _record(checks, "outer_test_is_exactly_13951_rows",
            len(outer_test) == 13951, len(outer_test))
    _record(checks, "outer_test_is_disjoint_from_tuning_pool",
            not (outer_train & outer_test), len(outer_train & outer_test))
    return inner, outer_train, outer_test, checks


def candidate_result_rows(result: CandidateResult) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for fold in result.folds:
        rows.append(
            {
                "candidate_id": result.candidate_id,
                "feasible": int(result.feasible),
                "fold": fold.fold,
                "held_out_attack_type": fold.held_out_attack_type,
                "selected_trees": fold.selected_trees,
                "validation_fpr": f"{fold.validation_fpr:.12g}",
                "episode_recall": f"{fold.episode_recall:.12g}",
                "window_recall": f"{fold.window_recall:.12g}",
                "roc_auc": f"{fold.roc_auc:.12g}",
                "pr_auc": f"{fold.pr_auc:.12g}",
                "pooled_validation_fpr": f"{result.pooled_validation_fpr:.12g}",
                "macro_episode_recall": f"{result.macro_episode_recall:.12g}",
                "minimum_family_episode_recall": f"{result.minimum_family_episode_recall:.12g}",
                "macro_pr_auc": f"{result.macro_pr_auc:.12g}",
                "final_n_estimators": result.final_n_estimators,
            }
        )
    return rows


def _csv_payload(rows: list[dict[str, Any]]) -> bytes:
    stream = io.StringIO(newline="")
    if not rows:
        return b""
    writer = csv.DictWriter(stream, fieldnames=list(rows[0]), lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue().encode("utf-8")


def _prediction_payload(rows: list[Row], scores: np.ndarray) -> bytes:
    records = [
        {
            "row_id": r.row_id,
            "label": r.label,
            "disposition": r.disposition,
            "attack_type": r.attack_type or "",
            "episode_id": r.episode_id or "",
            "entity_key": r.entity_key,
            "score": f"{float(s):.10f}",
        }
        for r, s in zip(rows, scores)
    ]
    return _csv_payload(records)


def _model_payload(model: Any) -> bytes:
    stream = io.BytesIO()
    joblib.dump(model, stream)
    return stream.getvalue()


def evaluate_outer(
    selected: CandidateResult,
    train_rows: list[Row],
    test_rows: list[Row],
) -> tuple[Any, np.ndarray, dict[str, Any]]:
    final_params = dict(selected.params)
    final_params["max_n_estimators"] = selected.final_n_estimators
    model = build_model(final_params, early_stopping=False)
    x_train = np.asarray([r.features for r in train_rows], dtype=float)
    y_train = np.asarray([r.label for r in train_rows], dtype=int)
    x_test = np.asarray([r.features for r in test_rows], dtype=float)
    y_test = np.asarray([r.label for r in test_rows], dtype=int)
    model.fit(x_train, y_train, verbose=False)
    train_scores = model.predict_proba(x_train)[:, 1]
    test_scores = model.predict_proba(x_test)[:, 1]
    negatives = int((y_test == 0).sum())
    positives = int((y_test == 1).sum())
    points: list[dict[str, Any]] = []
    for target in FINAL_EVALUATION_TARGETS:
        threshold, achieved = threshold_at_train_fpr(train_scores[y_train == 0], target)
        flagged = test_scores >= threshold
        tp = int((flagged & (y_test == 1)).sum())
        fp = int((flagged & (y_test == 0)).sum())
        detected, recall = episode_recall(test_rows, test_scores, threshold)
        points.append(
            {
                "target_train_fpr": target,
                "threshold": float(threshold),
                "achieved_train_fpr": float(achieved),
                "observed_test_fpr": fp / negatives,
                "window_recall": tp / positives,
                "window_precision": tp / (tp + fp) if tp + fp else math.nan,
                "true_positives": tp,
                "false_positives": fp,
                "episode_recall": recall,
                "episodes_detected": sorted(k for k, v in detected.items() if v),
                "episodes_missed": sorted(k for k, v in detected.items() if not v),
                "episode_detection": dict(sorted(detected.items())),
                "episode_bootstrap": episode_bootstrap_recall(detected),
                "per_entity": per_entity_recall(test_rows, test_scores, threshold),
            }
        )
    return model, test_scores, {
        "selected_candidate_id": selected.candidate_id,
        "final_params": {**final_params, "n_estimators": selected.final_n_estimators},
        "test_rows": len(test_rows),
        "test_positives": positives,
        "test_negatives": negatives,
        "roc_auc": float(roc_auc_score(y_test, test_scores)),
        "pr_auc": float(average_precision_score(y_test, test_scores)),
        "operating_points": points,
    }


def phase1_outer_reference() -> dict[str, Any]:
    metrics = json.loads((PHASE1_DIR / "metrics.json").read_text(encoding="utf-8"))
    fold = next(
        f
        for f in metrics["folds"]
        if f["arm"] == "F" and f["held_out_attack_type"] == "botnet/ares"
    )
    return {
        "params": {
            "max_depth": 3,
            "learning_rate": 0.1,
            "n_estimators": 200,
            "reg_alpha": 0.0,
            "reg_lambda": 1.0,
            "min_child_weight": 1.0,
            "subsample": 1.0,
            "colsample_bytree": 1.0,
        },
        "roc_auc": fold["roc_auc"],
        "pr_auc": fold["pr_auc"],
        "operating_points": fold["operating_points"],
    }


def compare_outer(phase1: dict[str, Any], tuned: dict[str, Any]) -> dict[str, Any]:
    comparisons: list[dict[str, Any]] = []
    for target in FINAL_EVALUATION_TARGETS:
        a = next(p for p in phase1["operating_points"] if p["target_train_fpr"] == target)
        b = next(p for p in tuned["operating_points"] if p["target_train_fpr"] == target)
        paired = paired_episode_bootstrap_delta(
            a["episode_detection"], b["episode_detection"]
        )
        comparisons.append(
            {
                "target_train_fpr": target,
                "phase1": {
                    "episode_recall": a["episode_recall"],
                    "episodes_detected": len(a["episodes_detected"]),
                    "window_recall": a["window_recall"],
                    "observed_test_fpr": a["observed_test_fpr"],
                },
                "tuned": {
                    "episode_recall": b["episode_recall"],
                    "episodes_detected": len(b["episodes_detected"]),
                    "window_recall": b["window_recall"],
                    "observed_test_fpr": b["observed_test_fpr"],
                },
                "paired_episode_delta": paired,
            }
        )
    primary = next(c for c in comparisons if c["target_train_fpr"] == PRIMARY_TRAIN_FPR)
    return {
        "phase1_roc_auc": phase1["roc_auc"],
        "tuned_roc_auc": tuned["roc_auc"],
        "roc_auc_delta": tuned["roc_auc"] - phase1["roc_auc"],
        "phase1_pr_auc": phase1["pr_auc"],
        "tuned_pr_auc": tuned["pr_auc"],
        "pr_auc_delta": tuned["pr_auc"] - phase1["pr_auc"],
        "operating_points": comparisons,
        "primary_transfer_result": primary,
    }


def render_report(
    prereg_digest: str,
    selected: CandidateResult,
    control: CandidateResult,
    search_results: list[CandidateResult],
    outer: dict[str, Any],
    comparison: dict[str, Any],
) -> str:
    lines = [
        "# Phase 2 — leak-free surrogate tuning of XGBoost on ARM F",
        "",
        f"Pre-registration identity: `{prereg_digest}`",
        "",
        "Ares was absent from every fit, early-stopping evaluation, threshold and",
        "selection. The final Ares fold was opened only after candidate selection and",
        "refit, so the result is a zero-day transfer measurement, not Ares tuning.",
        "",
        "## Selected candidate",
        "",
        f"`{selected.candidate_id}` — feasible: **{selected.feasible}**",
        "",
        "| Parameter | Phase 1 | Tuned |",
        "|---|---:|---:|",
    ]
    p1 = phase1_outer_reference()["params"]
    tuned = outer["final_params"]
    for name in (
        "max_depth", "learning_rate", "n_estimators", "reg_alpha", "reg_lambda",
        "min_child_weight", "subsample", "colsample_bytree",
    ):
        lines.append(f"| `{name}` | {p1[name]} | {tuned[name]} |")
    lines.extend(
        [
            "",
            "## Internal known-family validation",
            "",
            "| Model | Feasible | Macro episode recall | Min family recall | Macro PR-AUC | Pooled FPR | Max fold FPR |",
            "|---|---|---:|---:|---:|---:|---:|",
            f"| Phase-1 control | {control.feasible} | {control.macro_episode_recall:.4f} | {control.minimum_family_episode_recall:.4f} | {control.macro_pr_auc:.4f} | {control.pooled_validation_fpr:.6f} | {control.max_fold_validation_fpr:.6f} |",
            f"| Selected | {selected.feasible} | {selected.macro_episode_recall:.4f} | {selected.minimum_family_episode_recall:.4f} | {selected.macro_pr_auc:.4f} | {selected.pooled_validation_fpr:.6f} | {selected.max_fold_validation_fpr:.6f} |",
            "",
            f"Feasible candidates: {sum(r.feasible for r in search_results)}/{len(search_results)}.",
            "",
            "## One-shot Ares transfer",
            "",
            f"ROC-AUC: {comparison['phase1_roc_auc']:.4f} -> {comparison['tuned_roc_auc']:.4f} "
            f"(delta {comparison['roc_auc_delta']:+.4f})",
            "",
            f"PR-AUC: {comparison['phase1_pr_auc']:.4f} -> {comparison['tuned_pr_auc']:.4f} "
            f"(delta {comparison['pr_auc_delta']:+.4f})",
            "",
            "| Target train FPR | Phase-1 episodes | Phase-1 FPR | Tuned episodes | Tuned FPR | Paired delta CI |",
            "|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for c in comparison["operating_points"]:
        d = c["paired_episode_delta"]
        lines.append(
            f"| {c['target_train_fpr']:g} | {c['phase1']['episodes_detected']}/40 | "
            f"{c['phase1']['observed_test_fpr']:.6f} | {c['tuned']['episodes_detected']}/40 | "
            f"{c['tuned']['observed_test_fpr']:.6f} | [{d['ci_low']:+.4f}, {d['ci_high']:+.4f}] |"
        )
    primary = next(
        p for p in outer["operating_points"]
        if p["target_train_fpr"] == PRIMARY_TRAIN_FPR
    )
    lines.extend(
        [
            "",
            "## Per-entity Ares transfer at the primary 0.5% target",
            "",
            "| Entity | Tuned episodes | Tuned recall |",
            "|---|---:|---:|",
        ]
    )
    for entity, data in primary["per_entity"].items():
        lines.append(
            f"| `{entity}` | {data['episodes_detected']}/{data['episodes']} | "
            f"{data['episode_recall']:.4f} |"
        )
    lines.extend(
        [
            "",
            "## Interpretation boundary",
            "",
            "The selected hyperparameters optimise transfer surrogates on four known",
            "families. Any Ares change is an observed transfer effect. It cannot be used",
            "to add candidates, alter constraints or rerun selection. R11 remains open:",
            "five entities, one destination host and no demonstrated generalisation to",
            "another capture, victim, attacker or botnet family.",
        ]
    )
    return "\n".join(lines) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Leak-free surrogate tuning of ARM F")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--preregister", action="store_true")
    mode.add_argument("--preflight", action="store_true")
    mode.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)

    if args.preregister:
        digest = publish_preregistration()
        print(f"published immutable pre-registration {digest}")
        print(f"49 exact candidates documented under {OUT_DIR.name}/")
        print("No model was fitted and the outer test was not read.")
        return 0

    protocol, prereg_digest = verify_preregistration()
    print(f"pre-registration verified: {prereg_digest}", flush=True)
    print("reconstructing frozen context without fitting ...", flush=True)
    rows, folds, by_id, frozen_protocol_checks, feature_checks = build_context()
    inner, outer_train, outer_test, leakage_checks = build_inner_memberships(folds, by_id)
    print(
        f"  {len(frozen_protocol_checks)} frozen/protocol checks, "
        f"{len(feature_checks)} feature checks, {len(leakage_checks)} leakage checks pass"
    )
    print(
        f"  tuning pool={len(outer_train)}, outer test={len(outer_test)}, "
        "Ares in tuning=0, outer-test overlap=0"
    )
    if args.preflight:
        print("PREFLIGHT ONLY. No model was fitted and the outer test was not read.")
        return 0

    started = datetime.now(UTC).isoformat()
    candidates = protocol["search"]["candidates"]
    results: list[CandidateResult] = []
    print(f"\nfitting {len(candidates)} candidates x {len(inner)} inner folds ...", flush=True)
    for index, candidate in enumerate(candidates, start=1):
        fold_results = []
        for spec in inner:
            train_rows = [by_id[rid] for rid in spec["training_ids"]]
            validation_rows = [by_id[rid] for rid in spec["validation_ids"]]
            result, _ = evaluate_inner_fold(
                candidate,
                spec["fold"],
                spec["held_out_attack_type"],
                train_rows,
                validation_rows,
            )
            fold_results.append(result)
        summary = summarise_candidate(candidate, fold_results)
        results.append(summary)
        print(
            f"  [{index:02d}/{len(candidates)}] {summary.candidate_id} "
            f"macro_ep={summary.macro_episode_recall:.4f} "
            f"pooled_fpr={summary.pooled_validation_fpr:.6f} "
            f"max_fpr={summary.max_fold_validation_fpr:.6f} "
            f"trees={summary.final_n_estimators} "
            f"{'FEASIBLE' if summary.feasible else 'infeasible'}",
            flush=True,
        )

    selected = select_candidate(results)
    control = next(r for r in results if r.candidate_id == "P1_CONTROL")
    print(
        f"\nselected {selected.candidate_id}: macro_ep={selected.macro_episode_recall:.4f}, "
        f"pooled_fpr={selected.pooled_validation_fpr:.6f}, "
        f"trees={selected.final_n_estimators}",
        flush=True,
    )

    # The outer test is first materialised for scoring only after selection.
    print("refitting on all fold0.train; opening fold0.test once for transfer ...", flush=True)
    train_rows = [by_id[rid] for rid in next(f for f in folds if f.index == 0).train_row_ids]
    test_rows = [by_id[rid] for rid in next(f for f in folds if f.index == 0).test_row_ids]
    model, test_scores, outer = evaluate_outer(selected, train_rows, test_rows)
    phase1 = phase1_outer_reference()
    comparison = compare_outer(phase1, outer)

    search_document = {
        "experiment": protocol["experiment"],
        "started_at": started,
        "completed_at": datetime.now(UTC).isoformat(),
        "pre_registration_sha256": prereg_digest,
        "selection_rule_applied_without_change": True,
        "feasible_candidates": sum(r.feasible for r in results),
        "selected_candidate_id": selected.candidate_id,
        "phase1_control": result_document(control),
        "selected_candidate": result_document(selected),
        "candidates": [result_document(r) for r in results],
    }
    search_content, _ = _publish_document(OUT_DIR / "search_results.json", search_document)
    comparison_document = {
        "experiment": protocol["experiment"],
        "pre_registration_sha256": prereg_digest,
        "phase1_reference": phase1,
        "tuned_outer_evaluation": outer,
        "comparison": comparison,
        "scientific_claim": (
            "known-family surrogate tuning followed by one zero-day Ares transfer test; "
            "not direct Ares optimisation"
        ),
    }
    comparison_content, _ = _publish_document(
        OUT_DIR / "transfer_comparison.json", comparison_document
    )
    _publish_bytes(OUT_DIR / "optimized_model.joblib", _model_payload(model))
    _publish_bytes(
        OUT_DIR / "optimized_predictions.csv",
        _prediction_payload(test_rows, test_scores),
    )
    table_rows = [row for result in results for row in candidate_result_rows(result)]
    _publish_bytes(OUT_DIR / "candidate_fold_metrics.csv", _csv_payload(table_rows))
    _publish_bytes(
        OUT_DIR / "TUNING_REPORT.md",
        render_report(prereg_digest, selected, control, results, outer, comparison).encode("utf-8"),
    )

    outputs = {
        p.name: _sha(p)
        for p in sorted(OUT_DIR.iterdir())
        if p.is_file() and p.name != "manifest.json"
    }
    manifest = {
        "experiment": protocol["experiment"],
        "pre_registration_sha256": prereg_digest,
        "feature_budget": list(ARM_F_FEATURES),
        "outer_test_opened_after_selection": True,
        "outer_test_used_for_selection": False,
        "ares_rows_used_during_tuning": 0,
        "postgresql_writes": 0,
        "frozen_artifacts_modified": False,
        "candidates_evaluated": len(results),
        "inner_models_fitted": len(results) * len(inner),
        "final_models_fitted": 1,
        "selected_candidate_id": selected.candidate_id,
        "selected_candidate_feasible": selected.feasible,
        "search_results_content_sha256": search_content,
        "transfer_comparison_content_sha256": comparison_content,
        "outputs": outputs,
    }
    _publish_bytes(OUT_DIR / "manifest.json", _json_bytes(manifest))
    print(f"published {len(outputs) + 1} artifacts under {OUT_DIR.name}/")
    primary = comparison["primary_transfer_result"]
    delta = primary["paired_episode_delta"]
    print(
        f"Ares transfer at 0.5%: Phase1={primary['phase1']['episodes_detected']}/40, "
        f"tuned={primary['tuned']['episodes_detected']}/40, "
        f"paired CI=[{delta['ci_low']:+.4f},{delta['ci_high']:+.4f}]"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
