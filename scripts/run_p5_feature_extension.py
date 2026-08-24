"""P5/E — feature budget extension. Two arms, one pre-registered endpoint.

Hypothesis: the five volume features cannot express low-intensity C2 behaviour, but
the data contain temporal beaconing signal.

* Arm A = the five current features (the P1 reference).
* Arm B = arm A plus ``duration_mean``, ``interarrival_mean``, ``interarrival_cv``.

Pre-registered primary endpoint: **``botnet/ares`` episode-level recall**, against
the P1 reference 0.075 [0.000, 0.175] on 40 episodes.

The frozen P1 folds are reused strictly. Same population, same labels, same
partitioning, same test sets, same evaluation unit. Zero PostgreSQL writes. No
hyper-parameter is tuned, no feature is selected on the test set.

Modes
-----
``--preflight``  verify the population, the folds and the leakage audit, then stop
                 without training anything.
``--execute``    run both arms and publish.
"""
from __future__ import annotations

import argparse
from collections.abc import Sequence
from datetime import UTC, datetime
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
from typing import Any, Final

from modules.detection.src.experiments.p1_dataset import (
    FORBIDDEN_COLUMNS,
    Row,
    build_folds,
    dataset_digest,
    folds_digest,
    load_negatives,
    load_positives,
)
from modules.detection.src.experiments.p1_evaluation import (
    BOOTSTRAP_RESAMPLES,
    BOOTSTRAP_SEED,
    MODEL_SEED,
    N_ESTIMATORS,
    evaluate_fold,
)
from modules.detection.src.experiments.p5_features import (
    ARM_A_FEATURES,
    ARM_B_FEATURES,
    MISSING_SENTINEL,
    TEMPORAL_FEATURE_NAMES,
    P5FeatureError,
    audit_temporal_features,
    extend_rows,
    load_temporal_features,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
P1_DIR: Final[Path] = REPO_ROOT / "artifacts" / "experiments" / "p1"
OUT_DIR: Final[Path] = REPO_ROOT / "artifacts" / "experiments" / "p5"

P1_DATASET_SHA256: Final[str] = (
    "3d7436178da6960ee5effeb4bee85a0b6da5eead9d2babef3c72cb6b7ca9f20d"
)
P1_FOLDS_SHA256: Final[str] = (
    "e463ea7b0eb4985f51369dc3ae19c09821040675aa4b9f9689f8e02545fed95a"
)
PRIMARY_ENDPOINT: Final[str] = "botnet/ares"
P1_BOTNET_EPISODE_RECALL: Final[float] = 0.075
P1_BOTNET_CI: Final[tuple[float, float]] = (0.0, 0.175)
P1_BOTNET_EPISODES: Final[int] = 40

DECISIONS: Final[list[dict[str, str]]] = [
    {
        "id": "D13",
        "decision": (
            f"missing temporal values encoded as the explicit sentinel "
            f"{MISSING_SENTINEL}; no missingness indicator feature is added"
        ),
        "reason": (
            "imputation would introduce a fitted parameter outside the ratified "
            "protocol, and fitting it across train and test would be leakage. The "
            "sentinel is constant, deterministic, and cannot collide with a real "
            "value because durations, gaps and coefficients of variation are all "
            "non-negative. No indicator is added because availability is exactly "
            "event_count >= 2, and event_count is already an admitted feature, so "
            "an indicator would duplicate it. The sentinel is a re-encoding of "
            "window length and must not be called an independent behavioural signal"
        ),
    },
    {
        "id": "D14",
        "decision": (
            "duration_mean is documented as computed over FlowEnd records and is "
            "therefore not claimed to be available online"
        ),
        "reason": (
            "a duration exists only once a flow has ended. The benchmark is valid "
            "at flow level; a real-time detector at window close would hold flows "
            "that have not ended and would have no duration for them. This is a "
            "limitation on operational availability, not on benchmark validity"
        ),
    },
    {
        "id": "D15",
        "decision": "no absolute timestamp may enter any feature; the audit asserts it",
        "reason": (
            "inter-arrival values are differences of timestamps. The audit bounds "
            "every temporal value far below the epoch magnitude rather than "
            "trusting the construction"
        ),
    },
    {
        "id": "D16",
        "decision": (
            "the frozen folds are reconstructed to recover P1's authentic row "
            "order, then proven identical to the published p1_folds.json two ways: "
            "canonical folds digest, and per-fold set equality of membership"
        ),
        "reason": (
            "p1_folds.json stores sorted(train_row_ids), but P1 trained on the "
            "order build_folds produces, which places training positives before "
            "training negatives. RandomForest bootstrap sampling is order "
            "sensitive, so loading the file naively reproduces the split but not "
            "the model, and would confound an arm A versus arm B comparison with a "
            "row-ordering effect. Reconstructing recovers the order while the two "
            "cross-checks keep the reuse provable"
        ),
    },
]


def _identity_payload(report: dict[str, Any]) -> dict[str, Any]:
    """The report minus its clock fields (ratified report identity rule)."""
    return {
        key: value
        for key, value in report.items()
        if key not in ("started_at", "completed_at", "content_sha256")
    }


def _content_sha256(report: dict[str, Any]) -> str:
    return sha256(
        json.dumps(
            _identity_payload(report), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()


def _publish_report(path: Path, report: dict[str, Any]) -> tuple[str, str]:
    """Publish once, durably. Idempotent on identical *content*, not bytes.

    ``started_at`` and ``completed_at`` legitimately differ between runs, so
    comparing raw bytes would reject a faithful re-run. The comparison is made on
    ``content_sha256``, which excludes the clock fields, matching the report
    identity rule already in force elsewhere in the project.
    """
    report = dict(report)
    report["content_sha256"] = _content_sha256(report)
    payload = json.dumps(report, indent=2, sort_keys=True).encode("utf-8") + b"\n"

    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        existing = json.loads(path.read_text(encoding="utf-8"))
        if existing.get("content_sha256") != report["content_sha256"]:
            raise FileExistsError(
                f"immutable artifact already exists with different content: {path}\n"
                f"  published content_sha256 {existing.get('content_sha256')}\n"
                f"  recomputed content_sha256 {report['content_sha256']}"
            )
        return report["content_sha256"], sha256(path.read_bytes()).hexdigest()

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
    return report["content_sha256"], sha256(payload).hexdigest()


def load_frozen_folds(
    positives: list[Row], negatives: list[Row]
) -> list[dict[str, Any]]:
    """Recover the frozen folds **with P1's authentic row ordering** (D16).

    A subtlety that must not be glossed over. ``build_folds`` appends training
    positives before training negatives, and ``run_p1_supervised.py`` trains on
    that order, but it writes ``sorted(train_row_ids)`` to ``p1_folds.json``. The
    published file therefore preserves fold **membership** but not the row
    **order** P1 actually trained on, and ``RandomForestClassifier`` bootstrap
    sampling is order-sensitive. Loading the file naively reproduces the split but
    not the model, which would silently confound an arm A versus arm B comparison
    with a row-ordering effect.

    So the folds are rebuilt to recover the authentic order, and then proven to be
    the frozen ones two independent ways: the canonical folds digest must equal
    the published identity, and every fold's membership must equal the published
    file's membership exactly as sets.
    """
    folds = build_folds(positives, negatives)

    digest = folds_digest(folds)
    if digest != P1_FOLDS_SHA256:
        raise P5FeatureError(
            f"rebuilt folds digest mismatch: expected {P1_FOLDS_SHA256}, "
            f"got {digest}"
        )

    published = sorted(
        json.loads((P1_DIR / "p1_folds.json").read_text(encoding="utf-8")),
        key=lambda f: f["index"],
    )
    if len(published) != len(folds):
        raise P5FeatureError("fold count differs from the published file")
    for rebuilt, stored in zip(sorted(folds, key=lambda f: f.index), published):
        if rebuilt.index != stored["index"]:
            raise P5FeatureError("fold index order differs from the published file")
        if rebuilt.held_out_attack_type != stored["held_out_attack_type"]:
            raise P5FeatureError(
                f"fold {rebuilt.index} holds out "
                f"{rebuilt.held_out_attack_type!r}, published file says "
                f"{stored['held_out_attack_type']!r}"
            )
        if set(rebuilt.train_row_ids) != set(stored["train_row_ids"]):
            raise P5FeatureError(
                f"fold {rebuilt.index} training membership differs from the "
                f"published file"
            )
        if set(rebuilt.test_row_ids) != set(stored["test_row_ids"]):
            raise P5FeatureError(
                f"fold {rebuilt.index} test membership differs from the "
                f"published file"
            )

    return [
        {
            "index": f.index,
            "held_out_attack_type": f.held_out_attack_type,
            "train_row_ids": list(f.train_row_ids),
            "test_row_ids": list(f.test_row_ids),
        }
        for f in sorted(folds, key=lambda f: f.index)
    ]


def build_population() -> tuple[list[Row], list[Row], list[Row]]:
    """Load the ratified population read-only and prove it is unchanged.

    Returns ``(all_rows, positives, negatives)``; the split is needed to recover
    P1's fold ordering.
    """
    positives = load_positives(str(REPO_ROOT))
    negatives = load_negatives()
    rows = positives + negatives
    digest = dataset_digest(rows)
    if digest != P1_DATASET_SHA256:
        raise P5FeatureError(
            f"population digest mismatch: expected {P1_DATASET_SHA256}, got {digest}"
        )
    return rows, positives, negatives


def _split(
    fold: dict[str, Any], by_id: dict[str, Row]
) -> tuple[list[Row], list[Row]]:
    train = [by_id[r] for r in fold["train_row_ids"]]
    test = [by_id[r] for r in fold["test_row_ids"]]
    return train, test


def run_arm(
    name: str,
    features: tuple[str, ...],
    rows: list[Row],
    folds: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Evaluate one arm over the frozen folds. Identical code path for both arms."""
    by_id = {r.row_id: r for r in rows}
    results: list[dict[str, Any]] = []
    for fold in folds:
        train, test = _split(fold, by_id)
        result = evaluate_fold(
            fold["index"],
            fold["held_out_attack_type"],
            train,
            test,
            expected_features=len(features),
        )
        results.append(
            {
                "arm": name,
                "features": list(features),
                "fold": result.fold,
                "held_out_attack_type": result.held_out_attack_type,
                "train_positives": result.train_positives,
                "train_negatives": result.train_negatives,
                "test_positives": result.test_positives,
                "test_negatives": result.test_negatives,
                "test_episodes": result.test_episodes,
                "roc_auc": result.roc_auc,
                "pr_auc": result.pr_auc,
                "operating_points": result.operating_points,
            }
        )
        point = result.operating_points[0]
        print(
            f"  [{name}] {result.held_out_attack_type:26} "
            f"roc {result.roc_auc:.4f}  pr {result.pr_auc:.4f}  "
            f"win {point['window_recall']:.4f}  "
            f"ep {point['episode_recall']:.4f}  "
            f"fpr {point['observed_test_fpr']:.6f}"
        )
    return results


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="P5/E feature extension.")
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    if not (args.preflight or args.execute):
        parser.error("choose --preflight or --execute")

    started = datetime.now(UTC).isoformat()

    print("loading the ratified population read-only ...")
    rows, positives, negatives = build_population()
    print(f"  population digest verified: {P1_DATASET_SHA256[:16]}...")
    print(f"  rows {len(rows)}  positives {sum(r.label for r in rows)}")

    folds = load_frozen_folds(positives, negatives)
    print(f"  frozen folds digest verified: {P1_FOLDS_SHA256[:16]}...")
    print("  membership cross-checked against p1_folds.json; P1 row order "
          "recovered")
    print(f"  folds {len(folds)}")

    print("deriving the three temporal features read-only ...")
    table = load_temporal_features()
    extended = extend_rows(rows, table)
    print(f"  reconstructed windows {len(table)}")

    print("auditing the three additions for leakage ...")
    audit = audit_temporal_features(rows, extended)
    for entry in audit["checks"]:
        flag = "ok  " if entry["passed"] else "FAIL"
        print(f"  {flag} {entry['check']}")
        if not entry["passed"]:
            print(f"       {entry['detail']}")
    if audit["failures"]:
        print(f"LEAKAGE AUDIT FAILED: {audit['failures']}", file=sys.stderr)
        return 2
    missing = audit["missingness"]
    print(
        f"  missingness: interarrival_mean absent on "
        f"{missing['interarrival_mean_missing_negatives']} negatives "
        f"({missing['interarrival_mean_missing_negative_rate']:.4f}), "
        f"sentinel {MISSING_SENTINEL}, indicator added "
        f"{missing['indicator_feature_added']}"
    )

    if args.preflight:
        print()
        print("PREFLIGHT ONLY. Nothing was trained, nothing was written.")
        return 0

    print()
    print("arm A — five volume features (P1 reference budget)")
    arm_a = run_arm("A", ARM_A_FEATURES, rows, folds)
    print()
    print("arm B — five volume features plus three temporal features")
    arm_b = run_arm("B", ARM_B_FEATURES, extended, folds)

    by_type_a = {r["held_out_attack_type"]: r for r in arm_a}
    by_type_b = {r["held_out_attack_type"]: r for r in arm_b}
    comparison = []
    for attack_type in sorted(by_type_a):
        a, b = by_type_a[attack_type], by_type_b[attack_type]
        pa, pb = a["operating_points"][0], b["operating_points"][0]
        comparison.append(
            {
                "held_out_attack_type": attack_type,
                "test_positives": a["test_positives"],
                "test_episodes": a["test_episodes"],
                "identical_test_set": (
                    a["test_positives"] == b["test_positives"]
                    and a["test_negatives"] == b["test_negatives"]
                    and a["test_episodes"] == b["test_episodes"]
                ),
                "window_recall_a": pa["window_recall"],
                "window_recall_b": pb["window_recall"],
                "episode_recall_a": pa["episode_recall"],
                "episode_recall_b": pb["episode_recall"],
                "episode_ci_a": [
                    pa["episode_bootstrap"]["ci_low"],
                    pa["episode_bootstrap"]["ci_high"],
                ],
                "episode_ci_b": [
                    pb["episode_bootstrap"]["ci_low"],
                    pb["episode_bootstrap"]["ci_high"],
                ],
                "episodes_detected_a": pa["episodes_detected"],
                "episodes_detected_b": pb["episodes_detected"],
                "roc_auc_a": a["roc_auc"],
                "roc_auc_b": b["roc_auc"],
                "pr_auc_a": a["pr_auc"],
                "pr_auc_b": b["pr_auc"],
                "observed_test_fpr_a": pa["observed_test_fpr"],
                "observed_test_fpr_b": pb["observed_test_fpr"],
                "episode_recall_delta": (
                    pb["episode_recall"] - pa["episode_recall"]
                ),
            }
        )

    primary = next(
        c for c in comparison if c["held_out_attack_type"] == PRIMARY_ENDPOINT
    )
    ci_overlap = not (
        primary["episode_ci_b"][0] > primary["episode_ci_a"][1]
        or primary["episode_ci_a"][0] > primary["episode_ci_b"][1]
    )

    report = {
        "experiment": "P5/E feature budget extension",
        "hypothesis": (
            "the five volume features cannot express low-intensity C2 behaviour, "
            "but the data contain temporal beaconing signal"
        ),
        "started_at": started,
        "completed_at": datetime.now(UTC).isoformat(),
        "postgresql_writes": 0,
        "p1_dataset_content_sha256": P1_DATASET_SHA256,
        "p1_folds_content_sha256": P1_FOLDS_SHA256,
        "frozen_folds_reused_verbatim": True,
        "arm_a_features": list(ARM_A_FEATURES),
        "arm_b_features": list(ARM_B_FEATURES),
        "temporal_features_added": list(TEMPORAL_FEATURE_NAMES),
        "forbidden_columns": list(FORBIDDEN_COLUMNS),
        "conservative_decisions": DECISIONS,
        "model": {
            "estimator": "RandomForestClassifier",
            "n_estimators": N_ESTIMATORS,
            "random_state": MODEL_SEED,
            "class_weight": None,
            "hyperparameters_tuned": False,
            "features_selected_on_test": False,
        },
        "bootstrap": {"resamples": BOOTSTRAP_RESAMPLES, "seed": BOOTSTRAP_SEED,
                      "unit": "episode"},
        "leakage_audit": audit,
        "arm_a": arm_a,
        "arm_b": arm_b,
        "comparison_a_vs_b": comparison,
        "primary_endpoint": {
            "attack_type": PRIMARY_ENDPOINT,
            "unit": "episode-level recall",
            "pre_registered": True,
            "p1_reference_recall": P1_BOTNET_EPISODE_RECALL,
            "p1_reference_ci": list(P1_BOTNET_CI),
            "p1_reference_episodes": P1_BOTNET_EPISODES,
            "arm_a_recall": primary["episode_recall_a"],
            "arm_b_recall": primary["episode_recall_b"],
            "arm_a_ci": primary["episode_ci_a"],
            "arm_b_ci": primary["episode_ci_b"],
            "episodes_detected_a": primary["episodes_detected_a"],
            "episodes_detected_b": primary["episodes_detected_b"],
            "episodes_total": primary["test_episodes"],
            "delta": primary["episode_recall_delta"],
            "confidence_intervals_overlap": ci_overlap,
            "roc_auc_a": primary["roc_auc_a"],
            "roc_auc_b": primary["roc_auc_b"],
        },
        "limitations": [
            "R11 is unchanged: 5 attack types, 9 entities, 6 host pairs, 54 "
            "episodes. Any improvement on the botnet remains a result about five "
            "entities reaching one destination, not a general capability",
            "duration_mean is computed over FlowEnd records and is not available "
            "to a real-time detector at window close (decision D14)",
            "inter-arrival availability is exactly event_count >= 2, so the "
            "sentinel re-encodes window length and is not an independent signal "
            "(decision D13)",
            "the botnet endpoint rests on 40 episodes, so the bootstrap interval "
            "is wide and small differences are not resolvable",
        ],
    }

    content, file_digest = _publish_report(OUT_DIR / "p5_metrics.json", report)

    print()
    print("=== PRIMARY ENDPOINT: botnet/ares episode recall ===")
    print(f"  P1 reference : {P1_BOTNET_EPISODE_RECALL:.4f} "
          f"[{P1_BOTNET_CI[0]:.4f}, {P1_BOTNET_CI[1]:.4f}] on "
          f"{P1_BOTNET_EPISODES} episodes")
    print(f"  arm A        : {primary['episode_recall_a']:.4f} "
          f"[{primary['episode_ci_a'][0]:.4f}, {primary['episode_ci_a'][1]:.4f}]"
          f"  {primary['episodes_detected_a']}/{primary['test_episodes']}")
    print(f"  arm B        : {primary['episode_recall_b']:.4f} "
          f"[{primary['episode_ci_b'][0]:.4f}, {primary['episode_ci_b'][1]:.4f}]"
          f"  {primary['episodes_detected_b']}/{primary['test_episodes']}")
    print(f"  delta        : {primary['episode_recall_delta']:+.4f}")
    print(f"  CIs overlap  : {ci_overlap}")
    print(f"  ROC A -> B   : {primary['roc_auc_a']:.4f} -> "
          f"{primary['roc_auc_b']:.4f}")
    print()
    print(f"p5_metrics.json content {content[:16]}  file {file_digest[:16]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
