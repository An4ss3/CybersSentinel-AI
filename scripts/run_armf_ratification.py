"""Execute the ARM F ratification and the pre-registered ARM J1 hybrid.

Strictly additive. P1--P6, the published XGBoost baseline, the frozen four-arm
A--D benchmark and the six-arm content benchmark are inputs only; nothing under
their directories is written. PostgreSQL is read through the existing read-only
helper and never written. Fitting starts only after every frozen digest, the
population, the folds, the authentic training order, the ordered test rows, the
absence of forbidden columns and the arm identities have been verified.

Usage:
    python -m scripts.run_armf_ratification --preflight
    python -m scripts.run_armf_ratification --execute
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

from modules.detection.src.experiments.content_benchmark import (
    BASE_FEATURE,
    CONTENT_FEATURE_NAMES,
    paired_episode_bootstrap_delta,
    per_entity_recall,
)
from modules.detection.src.experiments.p1_dataset import (
    FORBIDDEN_COLUMNS,
    MB_DATABASE,
    PRODUCTION_DATABASE,
    Row,
    build_folds,
    dataset_digest,
    folds_digest,
    load_negatives,
    load_positives,
)
from modules.detection.src.experiments.p6_feature_audit import (
    FEATURE_FUNCTIONS,
    ONLINE_AVAILABILITY,
    compute,
    fetch_events,
)
from modules.detection.src.experiments.ratification import (
    ARM_J1_FEATURES,
    CO_PRIMARY_ENDPOINT,
    PRE_REGISTRATION,
    PRIMARY_ENDPOINT,
    PRIMARY_TARGET,
    RATIFICATION_ARMS,
    RATIFICATION_FPR_TARGETS,
    VOLUMETRIC_FEATURE,
    ArmFoldResult,
    RatificationError,
    classify_paired,
    equal_alert_budget_diagnostic,
    evaluate_arm_fold,
    point_at,
    pre_registration_digest,
    ratify_arm_f,
    verify_arm_budgets,
)

try:  # pragma: no cover - depends on invocation style
    from scripts.run_xgboost_baseline import verify_protocol
except ImportError:  # pragma: no cover
    verify_protocol = None  # type: ignore[assignment]

REPO_ROOT = Path(__file__).resolve().parents[1]
P1_DIR: Final[Path] = REPO_ROOT / "artifacts" / "experiments" / "p1"
P6_DIR: Final[Path] = REPO_ROOT / "artifacts" / "experiments" / "p6"
BASELINE_DIR: Final[Path] = REPO_ROOT / "artifacts" / "experiments" / "xgboost_baseline"
AD_DIR: Final[Path] = REPO_ROOT / "artifacts" / "experiments" / "xgboost_feature_benchmark"
CONTENT_DIR: Final[Path] = (
    REPO_ROOT / "artifacts" / "experiments" / "xgboost_content_benchmark"
)
OUT_DIR: Final[Path] = (
    REPO_ROOT / "artifacts" / "experiments" / "armf_ratification_armj1"
)

P1_DATASET_CONTENT_SHA256: Final[str] = (
    "3d7436178da6960ee5effeb4bee85a0b6da5eead9d2babef3c72cb6b7ca9f20d"
)
P1_FOLDS_CONTENT_SHA256: Final[str] = (
    "e463ea7b0eb4985f51369dc3ae19c09821040675aa4b9f9689f8e02545fed95a"
)

#: Every frozen input, with the identity it must still carry.
FROZEN_FILE_SHA256: Final[dict[str, str]] = {
    "p1_dataset.csv": "e95aed008d994510e4c649c287feb8fe8f49a785bec144d7e83aa15804b6c062",
    "p1_folds.json": "57e688fd3da90911707d7a172c161686d852094121eda1ac49e0221fc0529fa1",
    "p1_metrics.json": "2a51e618397c42b742a289216d3cd89b255c4ccd96a8f985a5ad1c5c4783a447",
    "p6_feature_audit.json": "d028e8476df66c2827e534281fdda6c994c6e1023ba42bb57461c34316a9d1ac",
    "xgb_metrics.json": "4b841773bbe34d62153dfbd69cc9c5f2a480b781f842ed0c59a1efe3a21a1263",
    "xgb_model_params.json": "d6d33ca0b7a6d42f5bd059ac1e8a2c11fe6b47f8e7104ee1da6ac6a139a03521",
    "benchmark_manifest.json": "2b6e65e658297dd1d96d3f4d3afce9798a5cf9e99279a70253dbbb022315af88",
    "content_features.csv": "1f831d7e22b2db853713622da2fd7569af768e9884aba04ece6e206fc5896413",
    "content_extraction_audit.json": (
        "617bd3121231fdaf858394ba2b67db34c2e8a8d36cbe3d9b6b94d5d14a2b71f9"
    ),
    "content_feature_comparison.json": (
        "1d1d0be1548f231924c8d0b1db459d59f780a827a8aa564849502cf0d3464fa6"
    ),
}

#: Published references the reproduced arms must match exactly.
PUBLISHED_REFERENCE: Final[dict[str, dict[str, Any]]] = {
    "A": {
        "episodes_detected": 13,
        "episodes": 40,
        "episode_recall": 0.325,
        "roc_auc": 0.7615389758318096,
        "pr_auc": 0.0670200698009214,
        "observed_test_fpr": 0.009873675039930304,
    },
    "F": {
        "episodes_detected": 21,
        "episodes": 40,
        "episode_recall": 0.525,
        "roc_auc": 0.9712706901318213,
        "pr_auc": 0.45704719677233957,
        "observed_test_fpr": 0.007187454624655147,
    },
}


def _sha(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, indent=2, sort_keys=True, allow_nan=True).encode("utf-8")
        + b"\n"
    )


def _publish_bytes(path: Path, payload: bytes) -> str:
    """Write once. A differing re-run raises instead of overwriting."""
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
        raise RatificationError(f"{name}: {detail}")


def verify_frozen_files() -> list[dict[str, Any]]:
    """Step B: every frozen input must still carry its published identity."""
    checks: list[dict[str, Any]] = []
    paths = {
        "p1_dataset.csv": P1_DIR / "p1_dataset.csv",
        "p1_folds.json": P1_DIR / "p1_folds.json",
        "p1_metrics.json": P1_DIR / "p1_metrics.json",
        "p6_feature_audit.json": P6_DIR / "p6_feature_audit.json",
        "xgb_metrics.json": BASELINE_DIR / "xgb_metrics.json",
        "xgb_model_params.json": BASELINE_DIR / "xgb_model_params.json",
        "benchmark_manifest.json": AD_DIR / "benchmark_manifest.json",
        "content_benchmark_manifest.json": CONTENT_DIR / "content_benchmark_manifest.json",
        "content_features.csv": CONTENT_DIR / "content_features.csv",
        "content_extraction_audit.json": CONTENT_DIR / "content_extraction_audit.json",
        "content_feature_comparison.json": CONTENT_DIR / "content_feature_comparison.json",
    }
    for name, expected in sorted(FROZEN_FILE_SHA256.items()):
        _record(checks, f"frozen_input_{name}", _sha(paths[name]) == expected,
                _sha(paths[name]))
    content_digest = _sha(CONTENT_DIR / "content_benchmark_manifest.json")
    checks.append(
        {
            "check": "recorded_digest_content_benchmark_manifest.json",
            "passed": True,
            "detail": content_digest,
        }
    )

    content_manifest = json.loads(
        (CONTENT_DIR / "content_benchmark_manifest.json").read_text(encoding="utf-8")
    )
    bad = [n for n, d in content_manifest["outputs"].items() if _sha(CONTENT_DIR / n) != d]
    _record(
        checks,
        "all_six_arm_content_benchmark_outputs_still_match_their_digests",
        not bad,
        {"checked": len(content_manifest["outputs"]), "mismatched": bad[:5]},
    )
    ad_manifest = json.loads(
        (AD_DIR / "benchmark_manifest.json").read_text(encoding="utf-8")
    )
    bad = [n for n, d in ad_manifest["outputs"].items() if _sha(AD_DIR / n) != d]
    _record(
        checks,
        "all_frozen_four_arm_benchmark_outputs_still_match_their_digests",
        not bad,
        {"checked": len(ad_manifest["outputs"]), "mismatched": bad[:5]},
    )
    return checks


def load_content_features(rows: list[Row]) -> tuple[dict[str, dict[str, float]], list[dict[str, Any]]]:
    """Join the frozen content aggregates by frozen row id."""
    path = CONTENT_DIR / "content_features.csv"
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        fields = list(reader.fieldnames or [])
        table: dict[str, dict[str, float]] = {}
        for record in reader:
            table[record["row_id"]] = {
                name: (float(record[name]) if record[name] != "" else float("nan"))
                for name in CONTENT_FEATURE_NAMES
            }
    checks: list[dict[str, Any]] = []
    _record(
        checks,
        "published_content_columns_are_exactly_row_id_plus_the_six_metrics",
        fields == ["row_id", *CONTENT_FEATURE_NAMES],
        fields,
    )
    _record(
        checks,
        "every_frozen_p1_row_has_a_content_record",
        all(r.row_id in table for r in rows) and len(table) == len(rows),
        {"rows": len(rows), "content_rows": len(table)},
    )
    finite = [
        v
        for values in table.values()
        for v in values.values()
        if not math.isnan(v)
    ]
    _record(
        checks,
        "every_content_value_lies_in_the_unit_interval",
        all(0.0 <= v <= 1.0 and math.isfinite(v) for v in finite),
        {"values": len(finite)},
    )
    return table, checks


def build_arm_rows(
    rows: list[Row], content: dict[str, dict[str, float]]
) -> tuple[dict[str, list[Row]], list[dict[str, Any]]]:
    """Step E/F: assemble one row list per arm, preserving P1 order and metadata."""
    events_m4 = fetch_events(PRODUCTION_DATABASE, "m4_canonical.flow_end_events")
    events_mb4 = fetch_events(MB_DATABASE, "mb4_canonical.flow_end_events")
    p6_features = (BASE_FEATURE, VOLUMETRIC_FEATURE)
    base_table: dict[tuple[str, str, int], dict[str, float]] = {}
    base_table.update(compute(events_m4, p6_features))
    base_table.update(compute(events_mb4, p6_features))

    checks: list[dict[str, Any]] = []
    for name in p6_features:
        _record(checks, f"{name}_is_the_unmodified_p6_implementation",
                name in FEATURE_FUNCTIONS, name)
        _record(checks, f"{name}_is_p6_online",
                ONLINE_AVAILABILITY[name].startswith("online"),
                ONLINE_AVAILABILITY[name])

    by_arm: dict[str, list[Row]] = {name: [] for name in RATIFICATION_ARMS}
    for row in rows:
        key = (row.partition, row.entity_key, row.window_start_epoch)
        base = base_table.get(key)
        if base is None:
            raise RatificationError(f"no P6 reconstruction for frozen row {key!r}")
        available = {
            BASE_FEATURE: float(base[BASE_FEATURE]),
            VOLUMETRIC_FEATURE: float(base[VOLUMETRIC_FEATURE]),
            **content[row.row_id],
        }
        for name, features in RATIFICATION_ARMS.items():
            by_arm[name].append(
                replace(row, features=tuple(available[f] for f in features))
            )

    for name, arm_rows in by_arm.items():
        _record(
            checks,
            f"arm_{name}_preserves_row_and_label_metadata_in_p1_order",
            all(
                (a.row_id, a.label, a.disposition, a.attack_type, a.episode_id, a.entity_key)
                == (b.row_id, b.label, b.disposition, b.attack_type, b.episode_id, b.entity_key)
                for a, b in zip(rows, arm_rows)
            ),
            f"{len(arm_rows)} rows",
        )
        _record(
            checks,
            f"arm_{name}_has_exactly_the_registered_feature_width",
            all(len(r.features) == len(RATIFICATION_ARMS[name]) for r in arm_rows),
            {"features": list(RATIFICATION_ARMS[name])},
        )
    _record(
        checks,
        "arm_j1_row_prefix_is_byte_identical_to_arm_f",
        all(
            f.features == j.features[: len(f.features)]
            for f, j in zip(by_arm["F"], by_arm["J1"])
        ),
        "J1 extends F without disturbing its columns",
    )
    return by_arm, checks


def verify_no_leakage(rows: list[Row], folds: list[Any]) -> list[dict[str, Any]]:
    """Step D: forbidden columns, train/test disjointness and label integrity."""
    checks: list[dict[str, Any]] = []
    _record(
        checks,
        "no_registered_feature_name_is_a_forbidden_column",
        not (
            {f for features in RATIFICATION_ARMS.values() for f in features}
            & set(FORBIDDEN_COLUMNS)
        ),
        sorted({f for fs in RATIFICATION_ARMS.values() for f in fs}),
    )
    dispositions = {r.disposition for r in rows}
    _record(
        checks,
        "no_unknown_or_ambiguous_row_anywhere",
        not (dispositions & {"unknown", "ambiguous"}),
        sorted(dispositions),
    )
    _record(
        checks,
        "every_negative_is_benign_reference",
        all(r.disposition == "benign_reference" for r in rows if r.label == 0),
        "negatives are benign_reference only",
    )
    for fold in sorted(folds, key=lambda f: f.index):
        overlap = set(fold.train_row_ids) & set(fold.test_row_ids)
        _record(
            checks,
            f"fold{fold.index}_train_and_test_are_disjoint",
            not overlap,
            f"{len(overlap)} shared row ids",
        )
        held_out = {
            r.attack_type
            for r in rows
            if r.label == 1 and r.row_id in set(fold.test_row_ids)
        }
        _record(
            checks,
            f"fold{fold.index}_test_positives_are_only_the_held_out_type",
            held_out <= {fold.held_out_attack_type},
            sorted(held_out),
        )
        train_positive_types = {
            r.attack_type
            for r in rows
            if r.label == 1 and r.row_id in set(fold.train_row_ids)
        }
        _record(
            checks,
            f"fold{fold.index}_held_out_type_is_absent_from_training_positives",
            fold.held_out_attack_type not in train_positive_types,
            sorted(train_positive_types),
        )
    return checks


def verify_published_reproduction(
    results: dict[str, dict[int, ArmFoldResult]], folds: list[Any]
) -> list[dict[str, Any]]:
    """Step C: ARM A and ARM F must reproduce the published score streams."""
    checks: list[dict[str, Any]] = []
    for arm in ("A", "F"):
        for fold in sorted(folds, key=lambda f: f.index):
            published = CONTENT_DIR / f"predictions_{arm}_fold{fold.index}.csv"
            with published.open(newline="", encoding="utf-8") as handle:
                reference = list(csv.DictReader(handle))
            produced = results[arm][fold.index].predictions
            same = len(reference) == len(produced) and all(
                (a["row_id"], a["label"], a["score"])
                == (b["row_id"], str(b["label"]), b["score"])
                for a, b in zip(reference, produced)
            )
            _record(
                checks,
                f"arm_{arm}_fold{fold.index}_reproduces_the_published_score_stream",
                same,
                f"{len(produced)} ordered predictions",
            )
    for arm, reference in PUBLISHED_REFERENCE.items():
        primary = next(
            r for r in results[arm].values()
            if r.held_out_attack_type == PRIMARY_ENDPOINT
        )
        point = point_at(primary, PRIMARY_TARGET)
        _record(
            checks,
            f"arm_{arm}_reproduces_the_published_primary_endpoint",
            len(point["episodes_detected"]) == reference["episodes_detected"]
            and primary.test_episodes == reference["episodes"]
            and abs(point["episode_recall"] - reference["episode_recall"]) < 1e-12
            and abs(primary.roc_auc - reference["roc_auc"]) < 1e-9
            and abs(primary.pr_auc - reference["pr_auc"]) < 1e-9
            and abs(point["observed_test_fpr"] - reference["observed_test_fpr"]) < 1e-12,
            {
                "episodes_detected": len(point["episodes_detected"]),
                "episode_recall": point["episode_recall"],
                "roc_auc": primary.roc_auc,
                "pr_auc": primary.pr_auc,
                "observed_test_fpr": point["observed_test_fpr"],
            },
        )
    return checks


def _csv_payload(rows: list[dict[str, Any]]) -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(
        stream,
        fieldnames=["arm", "fold", "row_id", "label", "disposition", "attack_type",
                    "episode_id", "score"],
        lineterminator="\n",
    )
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue().encode("utf-8")


def _model_payload(model: Any) -> bytes:
    stream = io.BytesIO()
    joblib.dump(model, stream)
    return stream.getvalue()


def analyse(results: dict[str, dict[int, ArmFoldResult]]) -> dict[str, Any]:
    """Build the full comparison. No threshold, feature or arm is chosen here."""
    by_type: dict[str, dict[str, ArmFoldResult]] = {}
    for arm, folds in results.items():
        for result in folds.values():
            by_type.setdefault(result.held_out_attack_type, {})[arm] = result

    arms = list(RATIFICATION_ARMS)
    curve: dict[str, Any] = {}
    for attack_type, per_arm in sorted(by_type.items()):
        curve[attack_type] = {}
        for target in RATIFICATION_FPR_TARGETS:
            key = f"target_{target}"
            curve[attack_type][key] = {}
            for arm in arms:
                point = point_at(per_arm[arm], target)
                curve[attack_type][key][arm] = {
                    "episode_recall": point["episode_recall"],
                    "episodes_detected": len(point["episodes_detected"]),
                    "episodes_total": per_arm[arm].test_episodes,
                    "episode_ci": [
                        point["episode_bootstrap"]["ci_low"],
                        point["episode_bootstrap"]["ci_high"],
                    ],
                    "window_recall": point["window_recall"],
                    "roc_auc": per_arm[arm].roc_auc,
                    "pr_auc": per_arm[arm].pr_auc,
                    "observed_test_fpr": point["observed_test_fpr"],
                    "achieved_train_fpr": point["achieved_train_fpr"],
                    "threshold": point["threshold"],
                    "alerts": point["alerts"],
                }

    paired: dict[str, Any] = {}
    for attack_type, per_arm in sorted(by_type.items()):
        paired[attack_type] = {}
        for target in RATIFICATION_FPR_TARGETS:
            key = f"target_{target}"
            paired[attack_type][key] = {}
            for candidate, reference in (("F", "A"), ("J1", "A"), ("J1", "F")):
                delta = paired_episode_bootstrap_delta(
                    point_at(per_arm[reference], target)["episode_detection"],
                    point_at(per_arm[candidate], target)["episode_detection"],
                )
                paired[attack_type][key][f"{candidate}_minus_{reference}"] = {
                    **delta,
                    "direction": classify_paired(delta),
                }

    per_entity: dict[str, Any] = {}
    for attack_type, per_arm in sorted(by_type.items()):
        per_entity[attack_type] = {}
        for arm in arms:
            result = per_arm[arm]
            point = point_at(result, PRIMARY_TARGET)
            per_entity[attack_type][arm] = per_entity_recall(
                result.test_rows, result.test_scores, point["threshold"]
            )

    diagnostic: dict[str, Any] = {}
    for attack_type, per_arm in sorted(by_type.items()):
        budget = point_at(per_arm["A"], PRIMARY_TARGET)["alerts"]
        diagnostic[attack_type] = {
            "alert_budget_from_arm_a": budget,
            "ratifying": False,
            "arms": {
                arm: equal_alert_budget_diagnostic(
                    per_arm[arm].test_rows, per_arm[arm].test_scores, budget
                )
                for arm in arms
            },
        }

    primary = by_type[PRIMARY_ENDPOINT]
    point_a = point_at(primary["A"], PRIMARY_TARGET)
    point_f = point_at(primary["F"], PRIMARY_TARGET)
    arm_f_verdict = ratify_arm_f(
        point_a,
        point_f,
        paired[PRIMARY_ENDPOINT][f"target_{PRIMARY_TARGET}"]["F_minus_A"],
    )

    ares = paired[PRIMARY_ENDPOINT][f"target_{PRIMARY_TARGET}"]
    ssh = paired[CO_PRIMARY_ENDPOINT][f"target_{PRIMARY_TARGET}"]
    arm_j1_assessment = {
        "ares_vs_arm_f": ares["J1_minus_F"]["direction"],
        "ares_vs_arm_a": ares["J1_minus_A"]["direction"],
        "ssh_vs_arm_f": ssh["J1_minus_F"]["direction"],
        "ssh_vs_arm_a": ssh["J1_minus_A"]["direction"],
        "note": (
            "the ssh_patator fold contains 9 episodes, so a one-episode difference "
            "cannot reach significance at this sample size; directions labelled "
            "indistinguishable are genuinely undetermined, not neutral findings"
        ),
    }
    return {
        "experiment": "ARM-F-RATIFICATION and ARM-J1",
        "pre_registration": PRE_REGISTRATION,
        "pre_registration_sha256": pre_registration_digest(),
        "primary_endpoint": PRIMARY_ENDPOINT,
        "co_primary_endpoint": CO_PRIMARY_ENDPOINT,
        "operating_point_curve": curve,
        "paired_episode_deltas": paired,
        "per_entity_at_primary_target": per_entity,
        "equal_alert_budget_diagnostic": diagnostic,
        "arm_f_ratification": arm_f_verdict,
        "arm_j1_assessment": arm_j1_assessment,
        "r11_scope": {
            "entities": 5,
            "destinations": 1,
            "destination_host": "205.174.165.73",
            "episodes": 40,
            "limitations": [
                "limited entity diversity",
                "limited host-pair diversity",
                "risk of memorising behaviour specific to this capture",
                "no generalisation beyond the observed population",
            ],
            "statement": (
                "an improvement measured on the same entities is not evidence of "
                "global generalisation to another victim, attacker, capture or "
                "botnet family"
            ),
        },
    }



def _fmt(value: float, digits: int = 4) -> str:
    return "n/a" if value is None or (isinstance(value, float) and math.isnan(value)) else f"{value:.{digits}f}"


def _ci(pair: list[float]) -> str:
    if any(math.isnan(v) for v in pair):
        return "n/a"
    return f"[{pair[0]:+.4f}, {pair[1]:+.4f}]"


def render_report(comparison: dict[str, Any]) -> str:
    curve = comparison["operating_point_curve"]
    paired = comparison["paired_episode_deltas"]
    primary = comparison["primary_endpoint"]
    co = comparison["co_primary_endpoint"]
    key = f"target_{PRIMARY_TARGET}"
    arms = ["A", "F", "J1"]
    lines: list[str] = []
    add = lines.append

    add("# ARM F ratification and the pre-registered ARM J1 hybrid")
    add("")
    add(f"Pre-registration identity: `{comparison['pre_registration_sha256']}`")
    add("")
    add("Every threshold is a quantile of the training negatives at a registered")
    add("target. The test set never selected a threshold, a feature, a")
    add("hyperparameter or an architecture. Only the feature budget varies.")
    add("")
    add("## Registered budgets")
    add("")
    add("| Arm | Features |")
    add("|---|---|")
    for arm in arms:
        add(f"| {arm} | `{'`, `'.join(RATIFICATION_ARMS[arm])}` |")
    add("")

    add(f"## 1. Primary endpoint — {primary} at {PRIMARY_TARGET:.0%} training FPR")
    add("")
    add("| Arm | Episodes | Episode recall | 95% episode CI | Window recall | ROC-AUC | PR-AUC | Test FPR | Alerts |")
    add("|---|---:|---:|---:|---:|---:|---:|---:|---:|")
    for arm in arms:
        c = curve[primary][key][arm]
        add(
            f"| {arm} | {c['episodes_detected']}/{c['episodes_total']} | "
            f"{_fmt(c['episode_recall'])} | {_ci(c['episode_ci'])} | "
            f"{_fmt(c['window_recall'])} | {_fmt(c['roc_auc'])} | {_fmt(c['pr_auc'])} | "
            f"{_fmt(c['observed_test_fpr'], 6)} | {c['alerts']} |"
        )
    add("")
    add("### Paired episode deltas on the primary endpoint")
    add("")
    add("| Contrast | Delta | Paired 95% CI | New / lost | Direction |")
    add("|---|---:|---:|---:|---|")
    for name, d in paired[primary][key].items():
        add(
            f"| {name.replace('_minus_', ' - ')} | {d['point']:+.4f} | "
            f"{_ci([d['ci_low'], d['ci_high']])} | "
            f"{d['candidate_only_detections']} / {d['reference_only_detections']} | "
            f"{d['direction']} |"
        )
    add("")

    add(f"## 2. Co-primary endpoint — {co} at {PRIMARY_TARGET:.0%} training FPR")
    add("")
    add("| Arm | Episodes | Episode recall | 95% episode CI | Window recall | ROC-AUC | PR-AUC | Test FPR |")
    add("|---|---:|---:|---:|---:|---:|---:|---:|")
    for arm in arms:
        c = curve[co][key][arm]
        add(
            f"| {arm} | {c['episodes_detected']}/{c['episodes_total']} | "
            f"{_fmt(c['episode_recall'])} | {_ci(c['episode_ci'])} | "
            f"{_fmt(c['window_recall'])} | {_fmt(c['roc_auc'])} | {_fmt(c['pr_auc'])} | "
            f"{_fmt(c['observed_test_fpr'], 6)} |"
        )
    add("")
    add("| Contrast | Delta | Paired 95% CI | New / lost | Direction |")
    add("|---|---:|---:|---:|---|")
    for name, d in paired[co][key].items():
        add(
            f"| {name.replace('_minus_', ' - ')} | {d['point']:+.4f} | "
            f"{_ci([d['ci_low'], d['ci_high']])} | "
            f"{d['candidate_only_detections']} / {d['reference_only_detections']} | "
            f"{d['direction']} |"
        )
    add("")

    add("## 3. All five pre-registered operating points")
    add("")
    for attack_type in sorted(curve):
        add(f"### {attack_type}")
        add("")
        add("| Target train FPR | " + " | ".join(
            f"{a} episodes | {a} test FPR" for a in arms) + " |")
        add("|---|" + "---:|---:|" * len(arms))
        for target in RATIFICATION_FPR_TARGETS:
            cells = []
            for arm in arms:
                c = curve[attack_type][f"target_{target}"][arm]
                cells.append(f"{c['episodes_detected']}/{c['episodes_total']}")
                cells.append(_fmt(c["observed_test_fpr"], 6))
            add(f"| {target:g} | " + " | ".join(cells) + " |")
        add("")

    add("## 4. Verdicts")
    add("")
    v = comparison["arm_f_ratification"]
    add(f"**ARM F: {v['verdict']}** — {v['reason']}")
    add("")
    add("| Ratified condition | Met |")
    add("|---|---|")
    for name, met in v["conditions"].items():
        add(f"| {name} | {'yes' if met else 'no'} |")
    add("")
    j = comparison["arm_j1_assessment"]
    add("ARM J1 directions from the paired intervals:")
    add("")
    add("| Contrast | Direction |")
    add("|---|---|")
    for name, direction in j.items():
        if name != "note":
            add(f"| {name} | {direction} |")
    add("")
    add(j["note"])
    add("")

    add("## 5. Equal-alert-budget diagnostic — secondary, never ratifying")
    add("")
    diag = comparison["equal_alert_budget_diagnostic"]
    add("| Attack type | Alert budget | " + " | ".join(f"{a} episodes" for a in arms) + " |")
    add("|---|---:|" + "---:|" * len(arms))
    for attack_type in sorted(diag):
        d = diag[attack_type]
        cells = [
            f"{d['arms'][a]['episodes_detected']}/{d['arms'][a]['episodes']}"
            for a in arms
        ]
        add(f"| {attack_type} | {d['alert_budget_from_arm_a']} | " + " | ".join(cells) + " |")
    add("")
    add("This table aligns budgets using ARM A's test-set alert count. It informs")
    add("the operational reading and may never ratify an arm.")
    add("")

    add("## 6. R11 scope")
    add("")
    r11 = comparison["r11_scope"]
    add(
        f"The botnet endpoint contains {r11['entities']} entities, "
        f"{r11['destinations']} destination (`{r11['destination_host']}`) and "
        f"{r11['episodes']} episodes."
    )
    add("")
    for item in r11["limitations"]:
        add(f"- {item}")
    add("")
    add(r11["statement"])
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="ARM F ratification and the pre-registered ARM J1 hybrid"
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--preflight", action="store_true")
    mode.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)

    started = datetime.now(UTC).isoformat()

    print("step B: verifying frozen input digests ...", flush=True)
    frozen_checks = verify_frozen_files()
    print(f"  {len(frozen_checks)} frozen digest checks pass")

    print("step E: verifying the registered arm budgets ...", flush=True)
    budget_checks = verify_arm_budgets()
    print(f"  {len(budget_checks)} budget checks pass")
    print(f"  pre-registration sha256 = {pre_registration_digest()}")

    print("step A/F: loading the frozen P1 population and authentic fold order ...", flush=True)
    positives = load_positives(str(REPO_ROOT))
    negatives = load_negatives()
    rows = positives + negatives
    folds = build_folds(positives, negatives)
    if dataset_digest(rows) != P1_DATASET_CONTENT_SHA256:
        raise RatificationError("P1 population content digest mismatch")
    if folds_digest(folds) != P1_FOLDS_CONTENT_SHA256:
        raise RatificationError("P1 folds content digest mismatch")
    if verify_protocol is None:
        raise RatificationError("baseline protocol verifier could not be imported")
    protocol_checks = verify_protocol(rows, folds)
    print(f"  {len(protocol_checks)} P1 protocol checks pass")

    print("step D: verifying leakage rules ...", flush=True)
    leakage_checks = verify_no_leakage(rows, folds)
    print(f"  {len(leakage_checks)} leakage checks pass")

    print("joining the frozen content aggregates by row id ...", flush=True)
    content, content_checks = load_content_features(rows)
    print(f"  {len(content_checks)} content join checks pass")

    print("rebuilding the P6 features for the three arms ...", flush=True)
    by_arm, build_checks = build_arm_rows(rows, content)
    print(f"  {len(build_checks)} feature assembly checks pass")

    by_id = {arm: {r.row_id: r for r in rs} for arm, rs in by_arm.items()}
    identity_checks: list[dict[str, Any]] = []
    for fold in sorted(folds, key=lambda f: f.index):
        signatures = {
            arm: sha256(
                "".join(
                    f"{by_id[arm][rid].row_id},{by_id[arm][rid].label}\n"
                    for rid in fold.test_row_ids
                ).encode("utf-8")
            ).hexdigest()
            for arm in RATIFICATION_ARMS
        }
        _record(
            identity_checks,
            f"fold{fold.index}_ordered_test_rows_identical_across_all_arms",
            len(set(signatures.values())) == 1,
            signatures["A"],
        )
    print(f"  {len(identity_checks)} pre-fit cross-arm identity checks pass")

    if args.preflight:
        print("\nPREFLIGHT ONLY. No model was fitted and nothing was written.")
        return 0

    total = len(RATIFICATION_ARMS) * len(folds)
    print(f"\nfitting {total} models with unchanged XGBoost parameters ...", flush=True)
    results: dict[str, dict[int, ArmFoldResult]] = {a: {} for a in RATIFICATION_ARMS}
    for arm, features in RATIFICATION_ARMS.items():
        print(f"ARM {arm}: {', '.join(features)}", flush=True)
        for fold in sorted(folds, key=lambda f: f.index):
            train = [by_id[arm][rid] for rid in fold.train_row_ids]
            test = [by_id[arm][rid] for rid in fold.test_row_ids]
            result = evaluate_arm_fold(
                arm, features, fold.index, fold.held_out_attack_type, train, test
            )
            results[arm][fold.index] = result
            point = point_at(result, PRIMARY_TARGET)
            print(
                f"  {result.held_out_attack_type:26} "
                f"ep {point['episode_recall']:.4f} "
                f"({len(point['episodes_detected'])}/{result.test_episodes})  "
                f"win {point['window_recall']:.4f}  roc {result.roc_auc:.4f}  "
                f"pr {result.pr_auc:.4f}  fpr {point['observed_test_fpr']:.6f}",
                flush=True,
            )

    print("\nstep C: verifying ARM A and ARM F reproduce the published references ...", flush=True)
    reproduction_checks = verify_published_reproduction(results, folds)
    print(f"  {len(reproduction_checks)} reproduction checks pass")

    comparison = analyse(results)

    all_predictions: list[dict[str, Any]] = []
    for arm in RATIFICATION_ARMS:
        for fold_index in sorted(results[arm]):
            result = results[arm][fold_index]
            _publish_bytes(
                OUT_DIR / f"model_{arm}_fold{fold_index}.joblib",
                _model_payload(result.model),
            )
            _publish_bytes(
                OUT_DIR / f"predictions_{arm}_fold{fold_index}.csv",
                _csv_payload(result.predictions),
            )
            all_predictions.extend(result.predictions)
    _publish_bytes(OUT_DIR / "predictions.csv", _csv_payload(all_predictions))

    metrics = {
        "experiment": "ARM-F-RATIFICATION and ARM-J1",
        "started_at": started,
        "completed_at": datetime.now(UTC).isoformat(),
        "pre_registration": PRE_REGISTRATION,
        "pre_registration_sha256": pre_registration_digest(),
        "checks": {
            "frozen_digests": frozen_checks,
            "arm_budgets": budget_checks,
            "p1_protocol": protocol_checks,
            "leakage": leakage_checks,
            "content_join": content_checks,
            "feature_assembly": build_checks,
            "cross_arm_identity": identity_checks,
            "published_reproduction": reproduction_checks,
        },
        "folds": [
            {
                "arm": arm,
                "fold": r.fold,
                "held_out_attack_type": r.held_out_attack_type,
                "features": list(r.features),
                "train_positives": r.train_positives,
                "train_negatives": r.train_negatives,
                "test_positives": r.test_positives,
                "test_negatives": r.test_negatives,
                "test_episodes": r.test_episodes,
                "roc_auc": r.roc_auc,
                "pr_auc": r.pr_auc,
                "feature_importance_gain": r.feature_importance_gain,
                "missingness": r.missingness,
                "operating_points": r.operating_points,
            }
            for arm in RATIFICATION_ARMS
            for r in (results[arm][i] for i in sorted(results[arm]))
        ],
    }
    metrics_content, _ = _publish_document(OUT_DIR / "metrics.json", metrics)
    comparison_content, _ = _publish_document(OUT_DIR / "comparison.json", comparison)
    _publish_bytes(
        OUT_DIR / "PRE_REGISTRATION.json", _json_bytes(PRE_REGISTRATION)
    )
    _publish_bytes(
        OUT_DIR / "RATIFICATION_REPORT.md",
        render_report(comparison).encode("utf-8") + b"\n",
    )

    import sklearn
    import xgboost

    outputs = {
        p.name: _sha(p)
        for p in sorted(OUT_DIR.iterdir())
        if p.is_file() and p.name != "manifest.json"
    }
    manifest = {
        "experiment": "ARM-F-RATIFICATION and ARM-J1",
        "pre_registration_sha256": pre_registration_digest(),
        "arms": {a: list(f) for a, f in RATIFICATION_ARMS.items()},
        "operating_points": list(RATIFICATION_FPR_TARGETS),
        "frozen_inputs": FROZEN_FILE_SHA256,
        "p1_population_or_folds_modified": False,
        "frozen_ad_benchmark_modified": False,
        "six_arm_content_benchmark_modified": False,
        "published_baseline_modified": False,
        "postgresql_writes": 0,
        "models_fitted": total,
        "arm_f_verdict": comparison["arm_f_ratification"]["verdict"],
        "metrics_content_sha256": metrics_content,
        "comparison_content_sha256": comparison_content,
        "environment": {
            "sklearn": sklearn.__version__,
            "xgboost": xgboost.__version__,
            "numpy": np.__version__,
        },
        "outputs": outputs,
    }
    _publish_bytes(OUT_DIR / "manifest.json", _json_bytes(manifest))
    print(f"\npublished {len(outputs) + 1} artifacts under {OUT_DIR.name}/")
    print(f"ARM F verdict: {comparison['arm_f_ratification']['verdict']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
