"""Run the additive, no-retraining ARM F temporal-persistence experiment.

Commands must be run in order::

    python -m scripts.run_temporal_persistence --preregister
    python -m scripts.run_temporal_persistence --calibrate
    python -m scripts.run_temporal_persistence --evaluate

The calibration command never opens fold0 predictions. The evaluation command
refuses to run until an immutable passing calibration manifest exists.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
import csv
from datetime import UTC, datetime
from hashlib import sha256
import json
import math
import os
from pathlib import Path
from typing import Any, Final

from modules.detection.src.experiments.temporal_persistence import (
    CALIBRATION_FOLDS,
    MAX_FPR_SPREAD,
    MAX_GAP_SECONDS,
    PER_FOLD_FPR_LIMIT,
    POOLED_FPR_LIMIT,
    SELECTION_RULE,
    TARGET_TRAIN_FPR,
    AlertDecision,
    BenignFoldMetrics,
    CalibrationResult,
    ScoreWindow,
    TemporalPersistenceError,
    apply_temporal_rule,
    calibrate_highest_feasible_threshold,
    evaluate_benign_fold,
    evaluate_calibration_threshold,
    neighbouring_thresholds,
    pseudoepisode_memberships,
)

REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[1]
P1_DATASET: Final[Path] = REPO_ROOT / "artifacts/experiments/p1/p1_dataset.csv"
P1_FOLDS: Final[Path] = REPO_ROOT / "artifacts/experiments/p1/p1_folds.json"
SCORE_DIR: Final[Path] = REPO_ROOT / "artifacts/experiments/xgboost_content_benchmark"
RATIFICATION_DIR: Final[Path] = REPO_ROOT / "artifacts/experiments/armf_ratification_armj1"
METRICS_PATH: Final[Path] = RATIFICATION_DIR / "metrics.json"
OUT_DIR: Final[Path] = REPO_ROOT / "artifacts/experiments/temporal_persistence"
PRE_REGISTRATION_PATH: Final[Path] = OUT_DIR / "PRE_REGISTRATION.json"
CALIBRATION_PATH: Final[Path] = OUT_DIR / "calibration_manifest.json"
RESULTS_PATH: Final[Path] = OUT_DIR / "results.json"
REPORT_PATH: Final[Path] = OUT_DIR / "TEMPORAL_PERSISTENCE_REPORT.md"
FIGURE_PATH: Final[Path] = OUT_DIR / "temporal_persistence_summary.png"
MANIFEST_PATH: Final[Path] = OUT_DIR / "manifest.json"
EXPECTED_BASELINE: Final[dict[str, Any]] = {
    "threshold": 0.0024790484458208084,
    "ares_detected": 21,
    "ares_total": 40,
    "false_positives": 99,
    "benign_windows": 13_774,
    "fpr": 99 / 13_774,
}


class ExperimentStop(TemporalPersistenceError):
    """A mandatory STOP gate failed."""


def sha256_file(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_digest(value: Any) -> str:
    return sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def json_bytes(value: Any) -> bytes:
    return json.dumps(value, indent=2, sort_keys=True).encode("utf-8") + b"\n"


def publish_immutable(path: Path, payload: bytes) -> str:
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


def prediction_path(fold: int) -> Path:
    return SCORE_DIR / f"predictions_F_fold{fold}.csv"


def load_dataset() -> dict[str, dict[str, str]]:
    with P1_DATASET.open(newline="", encoding="utf-8") as stream:
        rows = {row["row_id"]: row for row in csv.DictReader(stream)}
    if len(rows) != 70_954:
        raise TemporalPersistenceError(f"unexpected P1 population: {len(rows)}")
    return rows


def load_scores(
    fold: int,
    dataset: dict[str, dict[str, str]],
    *,
    benign_only: bool,
) -> tuple[tuple[ScoreWindow, ...], dict[str, float], dict[str, int]]:
    windows: list[ScoreWindow] = []
    all_scores: dict[str, float] = {}
    counts = {"rows_read": 0, "benign_used": 0, "attack_used": 0}
    with prediction_path(fold).open(newline="", encoding="utf-8") as stream:
        for prediction in csv.DictReader(stream):
            counts["rows_read"] += 1
            if int(prediction["fold"]) != fold or prediction["arm"] != "F":
                raise TemporalPersistenceError("prediction arm/fold mismatch")
            row_id = prediction["row_id"]
            metadata = dataset[row_id]
            if prediction["label"] != metadata["label"]:
                raise TemporalPersistenceError(f"label mismatch: {row_id}")
            score = float(prediction["score"])
            all_scores[row_id] = score
            if benign_only and metadata["label"] != "0":
                continue
            counts["benign_used" if metadata["label"] == "0" else "attack_used"] += 1
            windows.append(
                ScoreWindow(
                    row_id=row_id,
                    entity_key=metadata["entity_key"],
                    window_start_epoch=int(metadata["window_start_epoch"]),
                    score=score,
                )
            )
    return tuple(windows), all_scores, counts


def official_thresholds(folds: tuple[int, ...]) -> dict[int, float]:
    document = json.loads(METRICS_PATH.read_text(encoding="utf-8"))
    result: dict[int, float] = {}
    for fold in folds:
        arm_fold = next(
            item
            for item in document["folds"]
            if item["arm"] == "F" and int(item["fold"]) == fold
        )
        point = next(
            item
            for item in arm_fold["operating_points"]
            if float(item["target_train_fpr"]) == TARGET_TRAIN_FPR
        )
        result[fold] = float(point["threshold"])
    return result


def verify_baseline() -> dict[str, Any]:
    dataset = load_dataset()
    windows, scores, counts = load_scores(0, dataset, benign_only=False)
    threshold = official_thresholds((0,))[0]
    benign_ids = [row_id for row_id in scores if dataset[row_id]["label"] == "0"]
    false_positives = sum(scores[row_id] >= threshold for row_id in benign_ids)
    episodes: dict[str, list[str]] = defaultdict(list)
    for row_id in scores:
        metadata = dataset[row_id]
        if metadata["attack_type"] == "botnet/ares":
            episodes[metadata["episode_id"]].append(row_id)
    detected = sum(
        any(scores[row_id] >= threshold for row_id in members)
        for members in episodes.values()
    )
    actual = {
        "threshold": threshold,
        "ares_detected": detected,
        "ares_total": len(episodes),
        "false_positives": false_positives,
        "benign_windows": len(benign_ids),
        "fpr": false_positives / len(benign_ids),
        "prediction_rows": counts["rows_read"],
        "rule_windows": len(windows),
    }
    mismatches = {
        key: {"expected": expected, "actual": actual[key]}
        for key, expected in EXPECTED_BASELINE.items()
        if actual[key] != expected
    }
    if mismatches:
        raise ExperimentStop(f"baseline mismatch: {mismatches}")
    return actual


def preregistration_document() -> dict[str, Any]:
    return {
        "experiment": "additive ARM F two-hit temporal persistence",
        "scientific_status": (
            "hypothesis generated after prior Ares inspection; threshold calibration "
            "is nevertheless restricted to benign OOF folds 1-4"
        ),
        "baseline_gate": EXPECTED_BASELINE,
        "operational_rule": {
            "alert": (
                "score_t >= official_fold_threshold OR "
                "(score_t_minus_1 >= persistence_threshold AND "
                "score_t >= persistence_threshold AND same entity_key AND "
                "0 < delta_seconds <= 60)"
            ),
            "pair_size": 2,
            "alert_window": "second window",
            "observable_fields": ["score", "entity_key", "window_start_epoch"],
            "forbidden_fields": ["attack_type", "label", "IP-specific rule", "service"],
            "forbidden_variants": [
                "mean",
                "top-k",
                "third window",
                "smoothing",
                "new model",
            ],
        },
        "calibration": {
            "folds": list(CALIBRATION_FOLDS),
            "population": "benign OOF windows only",
            "attack_rows_used": 0,
            "ares_prediction_file_opened": False,
            "candidate_values": "observed minima of valid consecutive benign score pairs",
            "selection_rule": SELECTION_RULE,
            "pooled_fpr_max": POOLED_FPR_LIMIT,
            "every_fold_fpr_max": PER_FOLD_FPR_LIMIT,
            "maximum_fold_fpr_spread": MAX_FPR_SPREAD,
            "tie_break_or_alternative_rules": "none",
        },
        "neighbour_analysis": {
            "role": "sensitivity only; may never replace the selected threshold",
            "lower": "immediately lower observed candidate",
            "upper": (
                "immediately higher observed candidate, or next representable float "
                "when the selected threshold is the observed maximum"
            ),
        },
        "opening_order": [
            "verify exact baseline",
            "publish this pre-registration",
            "calibrate using folds 1-4 benign only",
            "publish immutable calibration_manifest.json",
            "open fold0 exactly once for final evaluation",
        ],
        "stop": {
            "pooled_fpr_above": POOLED_FPR_LIMIT,
            "any_fold_fpr_above": PER_FOLD_FPR_LIMIT,
            "fold_fpr_spread_above": MAX_FPR_SPREAD,
            "action": "publish failure and do not evaluate Ares",
        },
        "claims": {
            "confirmatory_or_blind": False,
            "reason": "Ares distributions informed the hypothesis before this run",
            "threshold_may_change_after_manifest": False,
        },
        "frozen_inputs": {
            "p1_dataset.csv": sha256_file(P1_DATASET),
            "p1_folds.json": sha256_file(P1_FOLDS),
            "metrics.json": sha256_file(METRICS_PATH),
            **{
                f"predictions_F_fold{fold}.csv": sha256_file(prediction_path(fold))
                for fold in CALIBRATION_FOLDS
            },
        },
    }


def publish_preregistration() -> str:
    baseline = verify_baseline()
    protocol = preregistration_document()
    wrapper = {
        "protocol_sha256": canonical_digest(protocol),
        "published_at": datetime.now(UTC).isoformat(),
        "baseline_reproduced": baseline,
        "protocol": protocol,
    }
    publish_immutable(PRE_REGISTRATION_PATH, json_bytes(wrapper))
    return wrapper["protocol_sha256"]


def verify_preregistration() -> tuple[dict[str, Any], str]:
    if not PRE_REGISTRATION_PATH.exists():
        raise ExperimentStop("PRE_REGISTRATION.json absent; run --preregister")
    wrapper = json.loads(PRE_REGISTRATION_PATH.read_text(encoding="utf-8"))
    expected = preregistration_document()
    digest = canonical_digest(expected)
    if wrapper["protocol_sha256"] != digest or wrapper["protocol"] != expected:
        raise ExperimentStop("published pre-registration differs from executable protocol")
    return wrapper, digest


def fold_metrics_document(metrics: BenignFoldMetrics) -> dict[str, Any]:
    return {
        "fold": metrics.fold,
        "windows": metrics.windows,
        "false_positives": metrics.false_positives,
        "fpr": metrics.fpr,
        "baseline_false_positives": metrics.baseline_false_positives,
        "baseline_fpr": metrics.baseline_fpr,
        "persistence_alert_windows": metrics.persistence_alert_windows,
        "incremental_false_positives": metrics.incremental_false_positives,
        "pseudoepisodes": metrics.pseudoepisodes,
        "alerted_pseudoepisodes": metrics.alerted_pseudoepisodes,
        "pseudoepisodes_with_two_hits": metrics.pseudoepisodes_with_two_hits,
    }


def calibration_result_document(result: CalibrationResult) -> dict[str, Any]:
    return {
        "threshold": result.threshold,
        "pooled_windows": result.pooled_windows,
        "pooled_false_positives": result.pooled_false_positives,
        "pooled_fpr": result.pooled_fpr,
        "max_fold_fpr": result.max_fold_fpr,
        "min_fold_fpr": result.min_fold_fpr,
        "fpr_spread": result.fpr_spread,
        "stable": result.stable,
        "folds": [fold_metrics_document(value) for value in result.folds],
    }


def run_calibration() -> dict[str, Any]:
    # Phase-1 baseline evidence is already embedded in the immutable
    # pre-registration. Calibration must not reopen fold0 predictions.
    preregistration, protocol_digest = verify_preregistration()
    if preregistration["baseline_reproduced"] != {
        **EXPECTED_BASELINE,
        "prediction_rows": 13_951,
        "rule_windows": 13_951,
    }:
        raise ExperimentStop("pre-registered baseline evidence differs")
    if CALIBRATION_PATH.exists():
        raise FileExistsError(f"calibration already frozen: {CALIBRATION_PATH}")
    dataset = load_dataset()
    thresholds = official_thresholds(CALIBRATION_FOLDS)
    windows_by_fold: dict[int, tuple[ScoreWindow, ...]] = {}
    access_log: dict[str, Any] = {}
    for fold in CALIBRATION_FOLDS:
        windows, _, counts = load_scores(fold, dataset, benign_only=True)
        if counts["attack_used"] != 0:
            raise ExperimentStop(f"attack row entered calibration fold {fold}")
        windows_by_fold[fold] = windows
        access_log[str(fold)] = counts
    try:
        selected, candidates = calibrate_highest_feasible_threshold(
            windows_by_fold, thresholds
        )
    except TemporalPersistenceError as error:
        # Preserve a complete failure record instead of stopping before publication.
        failure = {
            "experiment": "additive ARM F two-hit temporal persistence",
            "calibration_status": "STOP",
            "frozen_at": datetime.now(UTC).isoformat(),
            "protocol_sha256": protocol_digest,
            "selection_rule": SELECTION_RULE,
            "selected": None,
            "sensitivity_only": None,
            "official_thresholds": {
                str(key): value for key, value in thresholds.items()
            },
            "calibration_access": {
                "prediction_folds_opened": list(CALIBRATION_FOLDS),
                "fold0_prediction_opened": False,
                "benign_rows_used": sum(
                    value["benign_used"] for value in access_log.values()
                ),
                "attack_rows_used": 0,
                "details": access_log,
            },
            "input_sha256": {
                "p1_dataset.csv": sha256_file(P1_DATASET),
                "metrics.json": sha256_file(METRICS_PATH),
                **{
                    f"predictions_F_fold{fold}.csv": sha256_file(
                        prediction_path(fold)
                    )
                    for fold in CALIBRATION_FOLDS
                },
            },
            "stop_reasons": [str(error)],
            "threshold_frozen_no_posthoc_changes": False,
        }
        failure["calibration_content_sha256"] = canonical_digest(failure)
        publish_immutable(CALIBRATION_PATH, json_bytes(failure))
        raise ExperimentStop(str(error)) from error
    lower, upper = neighbouring_thresholds(selected.threshold, candidates)
    lower_result = evaluate_calibration_threshold(lower, windows_by_fold, thresholds)
    upper_result = evaluate_calibration_threshold(upper, windows_by_fold, thresholds)
    stop_reasons: list[str] = []
    if selected.pooled_fpr > POOLED_FPR_LIMIT:
        stop_reasons.append("pooled FPR exceeds 1%")
    if selected.max_fold_fpr > PER_FOLD_FPR_LIMIT:
        stop_reasons.append("a fold FPR exceeds 1.30%")
    if selected.fpr_spread > MAX_FPR_SPREAD:
        stop_reasons.append("fold FPR spread exceeds 0.50 percentage point")
    document = {
        "experiment": "additive ARM F two-hit temporal persistence",
        "calibration_status": "STOP" if stop_reasons else "PASS_FROZEN",
        "frozen_at": datetime.now(UTC).isoformat(),
        "protocol_sha256": protocol_digest,
        "selection_rule": SELECTION_RULE,
        "selected": calibration_result_document(selected),
        "sensitivity_only": {
            "immediately_lower": calibration_result_document(lower_result),
            "immediately_upper": calibration_result_document(upper_result),
        },
        "candidate_count": len(candidates),
        "candidate_minimum": candidates[0],
        "candidate_maximum": candidates[-1],
        "official_thresholds": {str(key): value for key, value in thresholds.items()},
        "calibration_access": {
            "prediction_folds_opened": list(CALIBRATION_FOLDS),
            "fold0_prediction_opened": False,
            "benign_rows_used": sum(
                value["benign_used"] for value in access_log.values()
            ),
            "attack_rows_used": 0,
            "details": access_log,
        },
        "input_sha256": {
            "p1_dataset.csv": sha256_file(P1_DATASET),
            "metrics.json": sha256_file(METRICS_PATH),
            **{
                f"predictions_F_fold{fold}.csv": sha256_file(prediction_path(fold))
                for fold in CALIBRATION_FOLDS
            },
        },
        "stop_reasons": stop_reasons,
        "threshold_frozen_no_posthoc_changes": not stop_reasons,
    }
    document["calibration_content_sha256"] = canonical_digest(document)
    publish_immutable(CALIBRATION_PATH, json_bytes(document))
    if stop_reasons:
        raise ExperimentStop("; ".join(stop_reasons))
    return document


def verify_calibration() -> dict[str, Any]:
    if not CALIBRATION_PATH.exists():
        raise ExperimentStop("calibration manifest absent; run --calibrate")
    document = json.loads(CALIBRATION_PATH.read_text(encoding="utf-8"))
    digest = document.pop("calibration_content_sha256")
    if canonical_digest(document) != digest:
        raise ExperimentStop("calibration manifest content digest mismatch")
    document["calibration_content_sha256"] = digest
    _, protocol_digest = verify_preregistration()
    if document["protocol_sha256"] != protocol_digest:
        raise ExperimentStop("calibration uses another protocol")
    if document["calibration_status"] != "PASS_FROZEN":
        raise ExperimentStop("calibration STOP gate did not pass")
    if not document["threshold_frozen_no_posthoc_changes"]:
        raise ExperimentStop("threshold is not marked frozen")
    return document


def episode_category(length: int) -> str:
    if length == 1:
        return "1"
    if length == 2:
        return "2"
    if length <= 4:
        return "3-4"
    return ">=5"


def episode_evaluation(
    dataset: dict[str, dict[str, str]],
    scores: dict[str, float],
    decisions: dict[str, AlertDecision],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    grouped: dict[str, list[str]] = defaultdict(list)
    for row_id in scores:
        row = dataset[row_id]
        if row["attack_type"] == "botnet/ares":
            grouped[row["episode_id"]].append(row_id)
    episodes: list[dict[str, Any]] = []
    for episode_id, members in sorted(grouped.items()):
        ordered = sorted(members, key=lambda key: int(dataset[key]["window_start_epoch"]))
        baseline = any(decisions[row_id].baseline_alert for row_id in ordered)
        temporal = any(decisions[row_id].alert for row_id in ordered)
        entity_key = dataset[ordered[0]]["entity_key"]
        host = entity_key.split("|", 1)[0]
        episodes.append(
            {
                "episode_id": episode_id,
                "entity_key": entity_key,
                "source_host": host,
                "windows": len(ordered),
                "length_group": episode_category(len(ordered)),
                "baseline_detected": baseline,
                "temporal_detected": temporal,
                "newly_detected": temporal and not baseline,
                "lost": baseline and not temporal,
                "persistence_alert_windows": sum(
                    decisions[row_id].persistence_alert for row_id in ordered
                ),
                "maximum_score": max(scores[row_id] for row_id in ordered),
            }
        )
    baseline_count = sum(value["baseline_detected"] for value in episodes)
    temporal_count = sum(value["temporal_detected"] for value in episodes)
    summary = {
        "total": len(episodes),
        "baseline_detected": baseline_count,
        "baseline_recall": baseline_count / len(episodes),
        "temporal_detected": temporal_count,
        "temporal_recall": temporal_count / len(episodes),
        "delta_episodes": temporal_count - baseline_count,
        "delta_percentage_points": 100 * (temporal_count - baseline_count) / len(episodes),
        "newly_detected": [
            value["episode_id"] for value in episodes if value["newly_detected"]
        ],
        "lost": [value["episode_id"] for value in episodes if value["lost"]],
    }
    return episodes, summary


def grouped_episode_results(
    episodes: list[dict[str, Any]], key: str, order: list[str]
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for value in order:
        selected = [episode for episode in episodes if episode[key] == value]
        baseline = sum(episode["baseline_detected"] for episode in selected)
        temporal = sum(episode["temporal_detected"] for episode in selected)
        result.append(
            {
                key: value,
                "episodes": len(selected),
                "baseline_detected": baseline,
                "temporal_detected": temporal,
                "newly_detected": sum(
                    episode["newly_detected"] for episode in selected
                ),
                "lost": sum(episode["lost"] for episode in selected),
                "baseline_recall": baseline / len(selected) if selected else math.nan,
                "temporal_recall": temporal / len(selected) if selected else math.nan,
            }
        )
    return result


def false_positive_analysis(
    benign_windows: tuple[ScoreWindow, ...],
    decisions: dict[str, AlertDecision],
    official_threshold: float,
    persistence_threshold: float,
) -> dict[str, Any]:
    metrics = evaluate_benign_fold(
        0, benign_windows, official_threshold, persistence_threshold
    )
    epochs = [window.window_start_epoch for window in benign_windows]
    capture_hours = (max(epochs) - min(epochs) + 60) / 3600
    entity_window_hours = len(benign_windows) / 60
    return {
        **fold_metrics_document(metrics),
        "additional_false_positives": (
            metrics.false_positives - metrics.baseline_false_positives
        ),
        "capture_span_hours": capture_hours,
        "false_alert_windows_per_capture_hour": metrics.false_positives / capture_hours,
        "entity_window_hours": entity_window_hours,
        "false_alert_windows_per_entity_hour": (
            metrics.false_positives / entity_window_hours
        ),
    }


def matched_fpr_threshold(
    benign_scores: list[float], false_positive_budget: int
) -> tuple[float, int]:
    unique = sorted(set(benign_scores))
    feasible = [
        (threshold, sum(score >= threshold for score in benign_scores))
        for threshold in unique
        if sum(score >= threshold for score in benign_scores) <= false_positive_budget
    ]
    if not feasible:
        return math.nextafter(max(unique), math.inf), 0
    return min(feasible, key=lambda item: item[0])


def render_report(results: dict[str, Any]) -> str:
    episode = results["episode"]
    false_positive = results["false_positives"]
    classification = results["conclusion"]["classification"]
    lines = [
        "# ARM F temporal persistence — final exploratory report",
        "",
        f"Protocol: `{results['protocol_sha256']}`  ",
        f"Calibration: `{results['calibration_content_sha256']}`  ",
        "",
        "> This is an additive exploratory result, not a blind or confirmatory test. "
        "The hypothesis was generated after prior inspection of Ares, but the "
        "persistence threshold was frozen using benign OOF folds 1–4 only.",
        "",
        "## Frozen rule",
        "",
        f"Persistence threshold: `{results['persistence_threshold']}`.",
        "",
        "Alert on the official ARM F decision OR on the second of exactly two "
        "consecutive windows from the same `entity_key`, with `0 < delta <= 60` "
        "and both scores at or above the frozen persistence threshold.",
        "",
        "## Baseline versus temporal",
        "",
        "| Metric | ARM F baseline | ARM F + persistence | Delta |",
        "|---|---:|---:|---:|",
        f"| Ares episodes | {episode['baseline_detected']}/{episode['total']} | "
        f"{episode['temporal_detected']}/{episode['total']} | "
        f"{episode['delta_episodes']:+d} |",
        f"| Episode recall | {episode['baseline_recall']:.4f} | "
        f"{episode['temporal_recall']:.4f} | "
        f"{episode['delta_percentage_points']:+.2f} pp |",
        f"| Benign false positives | {false_positive['baseline_false_positives']} | "
        f"{false_positive['false_positives']} | "
        f"{false_positive['additional_false_positives']:+d} |",
        f"| Window FPR | {false_positive['baseline_fpr']:.6f} | "
        f"{false_positive['fpr']:.6f} | "
        f"{false_positive['fpr']-false_positive['baseline_fpr']:+.6f} |",
        f"| Alerted benign pseudoepisodes | — | "
        f"{false_positive['alerted_pseudoepisodes']} | — |",
        "",
        "## Results by source host",
        "",
        "| Host | Episodes | Baseline | Temporal | New | Lost |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for row in results["by_host"]:
        lines.append(
            f"| {row['source_host']} | {row['episodes']} | "
            f"{row['baseline_detected']} | {row['temporal_detected']} | "
            f"{row['newly_detected']} | {row['lost']} |"
        )
    lines.extend(
        [
            "",
            "## Results by episode length",
            "",
            "| Windows | Episodes | Baseline | Temporal | New | Lost |",
            "|---|---:|---:|---:|---:|---:|",
        ]
    )
    for row in results["by_length"]:
        lines.append(
            f"| {row['length_group']} | {row['episodes']} | "
            f"{row['baseline_detected']} | {row['temporal_detected']} | "
            f"{row['newly_detected']} | {row['lost']} |"
        )
    calibration = results["calibration"]
    lines.extend(
        [
            "",
            "## Calibration and stability",
            "",
            f"Pooled benign FPR: `{calibration['selected']['pooled_fpr']:.6f}`. "
            f"Maximum fold FPR: `{calibration['selected']['max_fold_fpr']:.6f}`. "
            f"Fold spread: `{calibration['selected']['fpr_spread']:.6f}`.",
            "",
            "| Fold | Benign windows | Baseline FP | Temporal FP | FPR | "
            "Pseudoepisodes with two hits |",
            "|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for fold in calibration["selected"]["folds"]:
        lines.append(
            f"| {fold['fold']} | {fold['windows']} | "
            f"{fold['baseline_false_positives']} | {fold['false_positives']} | "
            f"{fold['fpr']:.6f} | {fold['pseudoepisodes_with_two_hits']} |"
        )
    sensitivity = results["sensitivity"]
    lines.extend(
        [
            "",
            "## Neighbour sensitivity",
            "",
            "| Threshold | Role | Ares episodes | Fold0 FP | Fold0 FPR |",
            "|---:|---|---:|---:|---:|",
        ]
    )
    for role in ("lower", "selected", "upper"):
        value = sensitivity[role]
        lines.append(
            f"| {value['threshold']:.10g} | {role} | "
            f"{value['ares_episodes_detected']} | {value['false_positives']} | "
            f"{value['fpr']:.6f} |"
        )
    matched = results["matched_fpr_single_window"]
    lines.extend(
        [
            "",
            "## Comparable-FPR diagnostic",
            "",
            f"A single-window ARM F threshold selected descriptively at no more than "
            f"the temporal false-positive budget gives {matched['episodes_detected']}/40 "
            f"episodes with {matched['false_positives']} false positives. This diagnostic "
            "was computed after opening the final fold and did not select the temporal rule.",
            "",
            "## Critical interpretation",
            "",
            f"Classification: **{classification}**.",
            "",
        ]
    )
    for finding in results["conclusion"]["findings"]:
        lines.append(f"- {finding}")
    lines.extend(
        [
            "",
            "The rule uses no attack label or IP/service-specific branch at "
            "decision time. The frozen `entity_key` does encode the flow network "
            "tuple, so equality of endpoints and service is used indirectly for "
            "sequence membership. External generalisation is not established: "
            "all evidence comes from one frozen CICIDS2017 population and quantised "
            "scores from family-specific fold models.",
            "",
        ]
    )
    return "\n".join(lines)


def create_figure(results: dict[str, Any], output: Path) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    hosts = results["by_host"]
    lengths = results["by_length"]
    figure, axes = plt.subplots(1, 2, figsize=(11, 4.6))
    for axis, rows, key, title in (
        (axes[0], hosts, "source_host", "Ares detection by source host"),
        (axes[1], lengths, "length_group", "Ares detection by episode length"),
    ):
        labels = [row[key] for row in rows]
        if key == "source_host":
            labels = [f".{label.rsplit('.', 1)[-1]}" for label in labels]
        positions = list(range(len(rows)))
        width = 0.36
        axis.bar(
            [value - width / 2 for value in positions],
            [row["baseline_detected"] for row in rows],
            width,
            label="ARM F baseline",
            color="#4C78A8",
        )
        axis.bar(
            [value + width / 2 for value in positions],
            [row["temporal_detected"] for row in rows],
            width,
            label="+ two-hit persistence",
            color="#F58518",
        )
        axis.set_xticks(positions, labels)
        axis.set_ylabel("Detected episodes")
        axis.set_title(title)
        axis.grid(axis="y", alpha=0.25)
    axes[0].legend(loc="upper left", fontsize=8)
    fp = results["false_positives"]
    figure.suptitle(
        f"Frozen persistence threshold {results['persistence_threshold']:.6g} — "
        f"window FPR {fp['baseline_fpr']*100:.3f}% → {fp['fpr']*100:.3f}%",
        fontsize=11,
    )
    figure.tight_layout(rect=(0, 0, 1, 0.93))
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.tmp.png")
    figure.savefig(temporary, dpi=180, metadata={"Software": "CyberSentinel"})
    plt.close(figure)
    if output.exists():
        if output.read_bytes() != temporary.read_bytes():
            temporary.unlink(missing_ok=True)
            raise FileExistsError(f"immutable figure differs: {output}")
        temporary.unlink()
    else:
        os.replace(temporary, output)


def evaluate_threshold_on_fold0(
    threshold: float,
    all_windows: tuple[ScoreWindow, ...],
    benign_windows: tuple[ScoreWindow, ...],
    official_threshold: float,
    dataset: dict[str, dict[str, str]],
    scores: dict[str, float],
) -> dict[str, Any]:
    decisions = apply_temporal_rule(all_windows, official_threshold, threshold)
    _, episode = episode_evaluation(dataset, scores, decisions)
    false_positive = false_positive_analysis(
        benign_windows, decisions, official_threshold, threshold
    )
    return {
        "threshold": threshold,
        "ares_episodes_detected": episode["temporal_detected"],
        "false_positives": false_positive["false_positives"],
        "fpr": false_positive["fpr"],
    }


def run_final_evaluation() -> dict[str, Any]:
    calibration = verify_calibration()
    preregistration, _ = verify_preregistration()
    baseline = dict(preregistration["baseline_reproduced"])
    if any(path.exists() for path in (RESULTS_PATH, REPORT_PATH, FIGURE_PATH, MANIFEST_PATH)):
        raise FileExistsError("final evaluation artifacts already exist; refusing rerun")
    threshold = float(calibration["selected"]["threshold"])
    dataset = load_dataset()
    all_windows, scores, counts = load_scores(0, dataset, benign_only=False)
    if counts["rows_read"] != 13_951:
        raise ExperimentStop("unexpected fold0 prediction population")
    benign_windows = tuple(
        window for window in all_windows if dataset[window.row_id]["label"] == "0"
    )
    official = official_thresholds((0,))[0]
    decisions = apply_temporal_rule(all_windows, official, threshold)
    episodes, episode_summary = episode_evaluation(dataset, scores, decisions)
    by_host = grouped_episode_results(
        episodes, "source_host", ["192.168.10.5", "192.168.10.8", "192.168.10.9", "192.168.10.14", "192.168.10.15"]
    )
    by_length = grouped_episode_results(
        episodes, "length_group", ["1", "2", "3-4", ">=5"]
    )
    false_positive = false_positive_analysis(
        benign_windows, decisions, official, threshold
    )
    computed_baseline = {
        "threshold": official,
        "ares_detected": episode_summary["baseline_detected"],
        "ares_total": episode_summary["total"],
        "false_positives": false_positive["baseline_false_positives"],
        "benign_windows": false_positive["windows"],
        "fpr": false_positive["baseline_fpr"],
    }
    if computed_baseline != EXPECTED_BASELINE:
        raise ExperimentStop(f"single-read final baseline mismatch: {computed_baseline}")
    benign_scores = [window.score for window in benign_windows]
    matched_threshold, matched_fp = matched_fpr_threshold(
        benign_scores, false_positive["false_positives"]
    )
    matched_decisions = apply_temporal_rule(
        all_windows, matched_threshold, math.nextafter(max(scores.values()), math.inf)
    )
    _, matched_episode = episode_evaluation(dataset, scores, matched_decisions)
    lower_threshold = float(
        calibration["sensitivity_only"]["immediately_lower"]["threshold"]
    )
    upper_threshold = float(
        calibration["sensitivity_only"]["immediately_upper"]["threshold"]
    )
    sensitivity = {
        "lower": evaluate_threshold_on_fold0(
            lower_threshold,
            all_windows,
            benign_windows,
            official,
            dataset,
            scores,
        ),
        "selected": evaluate_threshold_on_fold0(
            threshold, all_windows, benign_windows, official, dataset, scores
        ),
        "upper": evaluate_threshold_on_fold0(
            upper_threshold,
            all_windows,
            benign_windows,
            official,
            dataset,
            scores,
        ),
    }
    new_episodes = [value for value in episodes if value["newly_detected"]]
    hosts_with_gain = len({value["source_host"] for value in new_episodes})
    short_gain = sum(value["windows"] <= 2 for value in new_episodes)
    if episode_summary["delta_episodes"] >= 5 and false_positive["fpr"] <= 0.015:
        classification = "A — amélioration nette sous le plafond final prédéfini"
    elif episode_summary["delta_episodes"] > 0:
        classification = "B — amélioration faible ou coûteuse, résultat secondaire"
    else:
        classification = "C — aucune amélioration; résultat négatif"
    findings = [
        (
            f"{episode_summary['delta_episodes']} nouveaux épisodes et "
            f"{len(episode_summary['lost'])} épisode perdu."
        ),
        (
            f"{short_gain}/{len(new_episodes)} nouveaux épisodes ont une longueur "
            "de une ou deux fenêtres."
            if new_episodes
            else "Aucun épisode nouvellement détecté; l’hypothèse des épisodes courts n’est pas soutenue."
        ),
        f"Le gain couvre {hosts_with_gain} hôte(s) source.",
        (
            f"Le coût est de {false_positive['additional_false_positives']} faux positifs "
            f"fenêtre supplémentaires; FPR {false_positive['baseline_fpr']:.6f} → "
            f"{false_positive['fpr']:.6f}."
        ),
        (
            f"À budget FPR comparable, le seuil fenêtre seul détecte "
            f"{matched_episode['temporal_detected']}/40 épisodes."
        ),
        (
            "Les seuils voisins donnent respectivement "
            f"{sensitivity['lower']['ares_episodes_detected']}, "
            f"{sensitivity['selected']['ares_episodes_detected']} et "
            f"{sensitivity['upper']['ares_episodes_detected']} épisodes."
        ),
    ]
    _, protocol_digest = verify_preregistration()
    results = {
        "experiment": "additive ARM F two-hit temporal persistence",
        "completed_at": datetime.now(UTC).isoformat(),
        "scientific_status": "exploratory post-hypothesis-generation evaluation",
        "protocol_sha256": protocol_digest,
        "calibration_content_sha256": calibration["calibration_content_sha256"],
        "persistence_threshold": threshold,
        "official_arm_f_threshold": official,
        "baseline_reproduction": baseline,
        "calibration": calibration,
        "episode": episode_summary,
        "by_host": by_host,
        "by_length": by_length,
        "false_positives": false_positive,
        "matched_fpr_single_window": {
            "threshold": matched_threshold,
            "false_positives": matched_fp,
            "fpr": matched_fp / len(benign_scores),
            "episodes_detected": matched_episode["temporal_detected"],
            "episode_recall": matched_episode["temporal_recall"],
            "post_final_descriptive_only": True,
        },
        "sensitivity": sensitivity,
        "episodes": episodes,
        "conclusion": {"classification": classification, "findings": findings},
        "operational_rule_uses_labels": False,
        "operational_rule_uses_attack_type": False,
        "operational_rule_uses_ip_or_service_specific_condition": False,
        "entity_key_contains_network_tuple": True,
        "models_fitted": 0,
        "frozen_artifacts_modified": False,
    }
    results["results_content_sha256"] = canonical_digest(results)
    publish_immutable(RESULTS_PATH, json_bytes(results))
    create_figure(results, FIGURE_PATH)
    publish_immutable(REPORT_PATH, render_report(results).encode("utf-8"))
    manifest = {
        "experiment": results["experiment"],
        "completed_at": results["completed_at"],
        "protocol_sha256": protocol_digest,
        "calibration_content_sha256": calibration["calibration_content_sha256"],
        "selected_threshold": threshold,
        "threshold_changed_after_calibration": False,
        "fold0_opened_after_calibration_manifest": True,
        "models_fitted": 0,
        "postgresql_reads": 0,
        "postgresql_writes": 0,
        "frozen_artifacts_modified": False,
        "inputs": {
            "p1_dataset.csv": sha256_file(P1_DATASET),
            "p1_folds.json": sha256_file(P1_FOLDS),
            "metrics.json": sha256_file(METRICS_PATH),
            **{
                f"predictions_F_fold{fold}.csv": sha256_file(prediction_path(fold))
                for fold in range(5)
            },
        },
        "outputs": {
            PRE_REGISTRATION_PATH.name: sha256_file(PRE_REGISTRATION_PATH),
            CALIBRATION_PATH.name: sha256_file(CALIBRATION_PATH),
            RESULTS_PATH.name: sha256_file(RESULTS_PATH),
            REPORT_PATH.name: sha256_file(REPORT_PATH),
            FIGURE_PATH.name: sha256_file(FIGURE_PATH),
        },
    }
    manifest["manifest_content_sha256"] = canonical_digest(manifest)
    publish_immutable(MANIFEST_PATH, json_bytes(manifest))
    return results


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--preregister", action="store_true")
    action.add_argument("--calibrate", action="store_true")
    action.add_argument("--evaluate", action="store_true")
    action.add_argument("--verify-baseline", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.verify_baseline:
        print(json.dumps(verify_baseline(), indent=2, sort_keys=True))
    elif args.preregister:
        print(json.dumps({"protocol_sha256": publish_preregistration()}, indent=2))
    elif args.calibrate:
        print(json.dumps(run_calibration(), indent=2, sort_keys=True))
    elif args.evaluate:
        print(json.dumps(run_final_evaluation()["conclusion"], indent=2, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
