"""Final validation — Step 5 runner: ARM F extension.

Commands::

    python -m scripts.run_final_validation_armf --preflight
    python -m scripts.run_final_validation_armf --publish
    python -m scripts.run_final_validation_armf --verify

PostgreSQL is read **only**: the connection is switched to read-only before the
transaction begins and ``transaction_read_only`` is asserted to be ``on`` before
any statement runs. Outputs are additive, under
``artifacts/experiments/final_validation/armf_extension/``.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
import csv
from datetime import UTC, datetime
from decimal import Decimal
from hashlib import sha256
import json
import os
from pathlib import Path
from typing import Any, Final, Sequence

from modules.detection.src.experiments.final_validation_armf import (
    ARES,
    ARM_BUDGETS,
    BASE_FEATURE,
    COMPARISON_KEYS,
    FITTED_ARMS,
    PERSISTED_CONTENT_FEATURES,
    PROTOCOL_ORDER,
    REUSED_ARM,
    ArmFExtensionError,
    aggregate_arm,
    armf_fold_guards,
    assemble_arm_rows,
    contrast,
    evaluate_arm_fold,
    experiment_configuration,
    model_description,
    strip_scores,
    verify_canonical_definitions,
)
from modules.detection.src.experiments.final_validation_eval import (
    TRAINING_ORDER,
    build_fold,
    canonical_digest,
    canonical_order,
)
from modules.detection.src.experiments.p6_feature_audit import (
    WINDOW_LENGTH_SECONDS,
    WindowEvents,
    compute,
)
from modules.detection.src.experiments.p1_dataset import FEATURE_NAMES
from modules.detection.src.experiments.ratification import ARM_F_FEATURES
from modules.detection.src.persistence.monday_benign_persistence import (
    get_monday_benign_connection,
)
from scripts.run_final_validation_eval import (
    BASELINE_PATH,
    FV_DIR,
    PROTOCOLS,
    held_out_names,
    load_assignment,
    load_rows,
    sha256_file,
)

REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[1]
OUT_DIR: Final[Path] = FV_DIR / "armf_extension"
CONFIG_PATH: Final[Path] = OUT_DIR / "armf_config.json"
METRICS_PATH: Final[Path] = OUT_DIR / "armf_metrics.json"
COMPARISON_PATH: Final[Path] = OUT_DIR / "armf_comparison.json"
ZERO_DAY_PATH: Final[Path] = OUT_DIR / "armf_zero_day.json"
REPRODUCTION_PATH: Final[Path] = OUT_DIR / "armf_reproduction.json"
REPORT_PATH: Final[Path] = OUT_DIR / "ARMF_EXTENSION_REPORT.md"
MANIFEST_PATH: Final[Path] = OUT_DIR / "manifest.json"

CONTENT_FEATURES_CSV: Final[Path] = (
    REPO_ROOT
    / "artifacts"
    / "experiments"
    / "xgboost_content_benchmark"
    / "content_features.csv"
)
PUBLISHED_F_PREDICTIONS: Final[Path] = (
    REPO_ROOT / "artifacts" / "experiments" / "xgboost_content_benchmark"
)

PRODUCTION_DATABASE: Final[str] = "cybersentinel"
MB_DATABASE: Final[str] = "cybersentinel_test"
EVENT_SOURCES: Final[tuple[tuple[str, str], ...]] = (
    (PRODUCTION_DATABASE, "m4_canonical.flow_end_events"),
    (MB_DATABASE, "mb4_canonical.flow_end_events"),
)

FROZEN_INPUTS: Final[tuple[str, ...]] = (
    "artifacts/production/ml_dataset_v1/ml_dataset.csv",
    "artifacts/experiments/xgboost_content_benchmark/content_features.csv",
    "artifacts/experiments/xgboost_content_benchmark/predictions_F_fold0.csv",
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


def fetch_window_events(database: str, table: str) -> tuple[dict, str]:
    """Group persisted events into M6/MB6 windows inside a read-only transaction.

    Mirrors ``p6_feature_audit.fetch_events`` exactly, but sets
    ``connection.read_only`` before the transaction starts and proves that the
    server reports ``transaction_read_only = on``. The frozen P6 module sets
    ``default_transaction_read_only``, which only affects *later* transactions.
    """
    connection = get_monday_benign_connection(database)
    try:
        connection.read_only = True
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT current_database(), current_setting('transaction_read_only')"
            )
            observed_database, mode = cursor.fetchone()
            if observed_database != database:
                raise ArmFExtensionError(
                    f"expected database {database!r}, connected to {observed_database!r}"
                )
            if mode != "on":
                raise ArmFExtensionError(f"{database}: transaction is not read-only")
            cursor.execute(
                f"""
                SELECT output_partition,
                       host(source_ip) || '|' || host(destination_ip) || '|'
                         || transport || '|' || coalesce(service, 'none') AS entity_key,
                       event_start_time::text, event_duration::text,
                       source_packets, destination_packets,
                       source_bytes, destination_bytes, connection_state
                FROM {table}
                """
            )
            rows = cursor.fetchall()
    finally:
        connection.rollback()
        connection.close()

    staged: dict[tuple[str, str, int], list[tuple]] = defaultdict(list)
    for row in rows:
        start = Decimal(row[2])
        bucket = int(start) // WINDOW_LENGTH_SECONDS * WINDOW_LENGTH_SECONDS
        staged[(row[0], row[1], bucket)].append(
            (
                float(start) - float(bucket),
                float(Decimal(row[3])),
                int(row[4]),
                int(row[5]),
                int(row[6]),
                int(row[7]),
                row[8],
            )
        )
    windows: dict[tuple[str, str, int], WindowEvents] = {}
    for key, events in staged.items():
        events.sort(key=lambda event: event[0])
        windows[key] = WindowEvents(
            starts=tuple(e[0] for e in events),
            durations=tuple(e[1] for e in events),
            source_packets=tuple(e[2] for e in events),
            destination_packets=tuple(e[3] for e in events),
            source_bytes=tuple(e[4] for e in events),
            destination_bytes=tuple(e[5] for e in events),
            states=tuple(e[6] for e in events),
        )
    return windows, mode


def rebuild_base_feature() -> tuple[dict[tuple[str, str, int], float], dict[str, Any]]:
    """Rebuild ``distinct_payload_ratio`` with the unmodified P6 implementation."""
    values: dict[tuple[str, str, int], float] = {}
    access: dict[str, Any] = {"sources": [], "transaction_read_only": {}}
    for database, table in EVENT_SOURCES:
        windows, mode = fetch_window_events(database, table)
        computed = compute(windows, (BASE_FEATURE,))
        values.update({key: float(v[BASE_FEATURE]) for key, v in computed.items()})
        access["sources"].append(
            {"database": database, "table": table, "windows": len(windows)}
        )
        access["transaction_read_only"][database] = mode
    access["windows_total"] = len(values)
    access["postgresql_writes"] = 0
    return values, access


def load_content_table() -> dict[str, dict[str, float]]:
    """Join the six published content metrics by frozen row id, keeping NaN."""
    with CONTENT_FEATURES_CSV.open(newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        fields = list(reader.fieldnames or [])
        if fields != ["row_id", *PERSISTED_CONTENT_FEATURES]:
            raise ArmFExtensionError(f"unexpected content columns: {fields}")
        table: dict[str, dict[str, float]] = {}
        for record in reader:
            table[record["row_id"]] = {
                name: (float(record[name]) if record[name] != "" else float("nan"))
                for name in PERSISTED_CONTENT_FEATURES
            }
    return table


def reproduction_gate(arm_rows: dict[str, list], ordered_ids: Sequence[str]) -> dict[str, Any]:
    """Prove the rebuilt ARM F reproduces the published Phase 1 score streams.

    This is a correctness proof for the reconstruction, not a claim that this step
    reproduces history: the published streams are the reference, and the arms
    fitted here are new experiments on new protocols.
    """
    by_id = {row.row_id: row for row in arm_rows["ARMF_XGB"]}
    ordered = [by_id[row_id] for row_id in ordered_ids]
    assignment = load_assignment(PROTOCOLS["A_historical"][0])
    names = held_out_names("A_historical")
    results: list[dict[str, Any]] = []
    for fold in sorted(names):
        data = build_fold("A_historical", fold, names[fold], ordered, assignment)
        guards = armf_fold_guards(
            data,
            ARM_BUDGETS["ARMF_XGB"],
            require_entity_disjoint=False,
            require_episode_disjoint=True,
        )
        record = evaluate_arm_fold("ARMF_XGB", data, guards)
        path = PUBLISHED_F_PREDICTIONS / f"predictions_F_fold{fold}.csv"
        with path.open(newline="", encoding="utf-8") as stream:
            published = {r["row_id"]: float(r["score"]) for r in csv.DictReader(stream)}
        scores = record["test_scores"]
        if set(scores) != set(published):
            raise ArmFExtensionError(f"fold{fold}: published row set differs")
        exact = sum(
            1
            for row_id, value in scores.items()
            if f"{value:.10f}" == f"{published[row_id]:.10f}"
        )
        largest = max(abs(scores[k] - published[k]) for k in scores)
        if exact != len(scores):
            raise ArmFExtensionError(
                f"fold{fold}: only {exact}/{len(scores)} scores reproduce the published stream"
            )
        results.append(
            {
                "fold": fold,
                "rows": len(scores),
                "scores_matching_to_ten_decimals": exact,
                "max_absolute_difference": largest,
                "published_stream_sha256": sha256_file(path),
            }
        )
    return {
        "purpose": (
            "correctness proof of the rebuilt distinct_payload_ratio; the published "
            "Phase 1 stream is the reference"
        ),
        "is_a_historical_reproduction_claim_for_this_step": False,
        "folds": results,
        "all_folds_reproduce_exactly": True,
    }


def vol5_reference() -> dict[str, Any]:
    """Read the Step 2 VOL5 results. Nothing is refitted."""
    document = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    out: dict[str, Any] = {}
    for protocol in PROTOCOL_ORDER:
        entry = document["protocols"][protocol]
        out[protocol] = {
            "summary": entry["summary"],
            "folds": entry["folds"],
        }
    return out


def build_context(progress: bool = True) -> dict[str, Any]:
    definition_checks = verify_canonical_definitions()
    if progress:
        print(f"{len(definition_checks)} canonical-definition checks pass", flush=True)

    rows = canonical_order(load_rows())
    base_values, access = rebuild_base_feature()
    if progress:
        print(
            f"rebuilt {BASE_FEATURE} for {access['windows_total']} windows, "
            f"read-only={access['transaction_read_only']}",
            flush=True,
        )
    content = load_content_table()
    arm_rows = assemble_arm_rows(rows, base_values, content)
    ordered_ids = [row.row_id for row in rows]

    reproduction = reproduction_gate(arm_rows, ordered_ids)
    if progress:
        print("ARM F reconstruction reproduces all five published folds", flush=True)

    results: dict[str, dict[str, list[dict[str, Any]]]] = {
        arm: {} for arm in FITTED_ARMS
    }
    for protocol in PROTOCOL_ORDER:
        assignment_file, entity_disjoint, episode_disjoint = PROTOCOLS[protocol]
        assignment = load_assignment(assignment_file)
        names = held_out_names(protocol)
        forbid = ARES if protocol == "D_zero_day_ares" else None
        for arm in FITTED_ARMS:
            by_id = {row.row_id: row for row in arm_rows[arm]}
            ordered = [by_id[row_id] for row_id in ordered_ids]
            records: list[dict[str, Any]] = []
            for fold in sorted(names):
                data = build_fold(protocol, fold, names[fold], ordered, assignment)
                guards = armf_fold_guards(
                    data,
                    ARM_BUDGETS[arm],
                    require_entity_disjoint=entity_disjoint,
                    require_episode_disjoint=episode_disjoint,
                    forbid_family_in_train=forbid,
                )
                records.append(evaluate_arm_fold(arm, data, guards))
            results[arm][protocol] = records
            summary = aggregate_arm(records)
            if progress:
                print(
                    f"  {protocol:32} {arm:14} roc={summary['macro_roc_auc']:.4f} "
                    f"pr={summary['macro_pr_auc']:.4f} ep="
                    f"{summary['detected_episodes']}/{summary['total_episodes']} "
                    f"fpr={summary['pooled_fpr']:.6f}",
                    flush=True,
                )

    summaries: dict[str, dict[str, Any]] = {}
    for arm in FITTED_ARMS:
        summaries[arm] = {
            protocol: aggregate_arm(results[arm][protocol]) for protocol in PROTOCOL_ORDER
        }
    vol5 = vol5_reference()
    summaries[REUSED_ARM] = {p: vol5[p]["summary"] for p in PROTOCOL_ORDER}

    return {
        "definition_checks": definition_checks,
        "access": access,
        "reproduction": reproduction,
        "results": results,
        "summaries": summaries,
        "vol5": vol5,
    }


def _test_population_identity(context: dict[str, Any]) -> list[dict[str, Any]]:
    """Prove every arm was measured on exactly the same test rows per fold."""
    checks: list[dict[str, Any]] = []
    for protocol in PROTOCOL_ORDER:
        vol5_folds = {f["fold"]: f for f in context["vol5"][protocol]["folds"]}
        for arm in FITTED_ARMS:
            for record in context["results"][arm][protocol]:
                reference = vol5_folds[record["fold"]]
                same = (
                    record["test_rows"] == reference["test_rows"]
                    and record["test_positive"] == reference["test_positive"]
                    and record["test_negative"] == reference["test_negative"]
                    and record["total_episodes"] == reference["total_episodes"]
                )
                checks.append(
                    {
                        "check": f"{protocol}/fold{record['fold']}/{arm}_same_test_population",
                        "passed": bool(same),
                        "detail": {
                            "arm": [record["test_rows"], record["test_positive"]],
                            "VOL5_RF": [reference["test_rows"], reference["test_positive"]],
                        },
                    }
                )
                if not same:
                    raise ArmFExtensionError(
                        f"{protocol}/fold{record['fold']}/{arm}: test population differs from VOL5"
                    )
    return checks


def comparison_document(context: dict[str, Any]) -> dict[str, Any]:
    summaries = context["summaries"]
    identity_checks = _test_population_identity(context)
    contrasts: dict[str, Any] = {}
    identifiability = experiment_configuration()["identifiability"]
    for protocol in PROTOCOL_ORDER:
        contrasts[protocol] = {
            "VOL5_RF_vs_ARMF_XGB": contrast(
                REUSED_ARM,
                summaries[REUSED_ARM][protocol],
                "ARMF_XGB",
                summaries["ARMF_XGB"][protocol],
                identifiable=False,
                note=identifiability["VOL5_RF_vs_ARMF_XGB"],
            ),
            "VOL5_XGB_vs_ARMF_XGB": contrast(
                "VOL5_XGB",
                summaries["VOL5_XGB"][protocol],
                "ARMF_XGB",
                summaries["ARMF_XGB"][protocol],
                identifiable=True,
                note=identifiability["VOL5_XGB_vs_ARMF_XGB"],
            ),
            "ARMF_XGB_vs_VOL5_ARMF_XGB": contrast(
                "ARMF_XGB",
                summaries["ARMF_XGB"][protocol],
                "VOL5_ARMF_XGB",
                summaries["VOL5_ARMF_XGB"][protocol],
                identifiable=True,
                note=identifiability["ARMF_XGB_vs_VOL5_ARMF_XGB"],
            ),
        }
    table = []
    for protocol in PROTOCOL_ORDER:
        for arm in (REUSED_ARM, *FITTED_ARMS):
            summary = summaries[arm][protocol]
            table.append(
                {
                    "protocol": protocol,
                    "arm": arm,
                    "features": list(
                        FEATURE_NAMES if arm == REUSED_ARM else ARM_BUDGETS[arm]
                    ),
                    "learner": model_description(arm)["estimator"],
                    "folds": summary["folds"],
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
        "experiment": "final validation — step 5 ARM F comparison",
        "table": table,
        "contrasts": contrasts,
        "same_test_population_checks": len(identity_checks),
        "interpretation_boundaries": {
            "A_historical": "family novelty, identity leakage present on folds 2-4",
            "B_entity_disjoint": "entity novelty, family may be known",
            "C_episode_disjoint_botnet_ares": "episode novelty inside a known family",
            "D_zero_day_ares": "Ares family entirely absent from training",
        },
        "forbidden_claims": experiment_configuration()["forbidden_claims"],
    }
    document["content_sha256"] = canonical_digest(document)
    return document


def zero_day_document(context: dict[str, Any]) -> dict[str, Any]:
    protocol = "D_zero_day_ares"
    entries: dict[str, Any] = {}
    for arm in FITTED_ARMS:
        record = context["results"][arm][protocol][0]
        entries[arm] = strip_scores(record)
    vol5 = context["vol5"][protocol]["folds"][0]
    entries[REUSED_ARM] = {
        **{k: v for k, v in vol5.items() if k != "operating_points"},
        "note": "reused from Step 2, not refitted in this step",
    }
    known_family = {
        "B_ares_folds": [
            {
                "fold": record["fold"],
                "held_out": record["held_out"],
                "arm": arm,
                "detected_episodes": record["detected_episodes"],
                "total_episodes": record["total_episodes"],
                "roc_auc": record["roc_auc"],
            }
            for arm in FITTED_ARMS
            for record in context["results"][arm]["B_entity_disjoint"]
            if ARES in record["test_attack_type_windows"]
        ],
        "C_ares": {
            arm: aggregate_arm(context["results"][arm]["C_episode_disjoint_botnet_ares"])
            for arm in FITTED_ARMS
        },
    }
    document = {
        "experiment": "final validation — step 5 zero-day Ares diagnostic",
        "protocol": "Ares absent from training; threshold from train negatives only",
        "ares_absent_from_training": {
            arm: context["results"][arm][protocol][0]["train_attack_type_windows"].get(
                ARES, 0
            )
            == 0
            for arm in FITTED_ARMS
        },
        "arms": entries,
        "known_family_comparison": known_family,
        "caution": (
            "a gain measured where Ares is present in training, in protocols B or C, "
            "is not evidence of zero-day generalisation; only protocol D speaks to "
            "the zero-day question"
        ),
    }
    document["content_sha256"] = canonical_digest(document)
    return document


def metrics_document(context: dict[str, Any]) -> dict[str, Any]:
    document = {
        "experiment": "final validation — step 5 ARM F per-fold metrics",
        "definition_checks": context["definition_checks"],
        "postgresql_access": context["access"],
        "arms": {
            arm: {
                protocol: {
                    "summary": aggregate_arm(context["results"][arm][protocol]),
                    "folds": [
                        strip_scores(record)
                        for record in context["results"][arm][protocol]
                    ],
                }
                for protocol in PROTOCOL_ORDER
            }
            for arm in FITTED_ARMS
        },
        "VOL5_RF_reference": {
            protocol: context["vol5"][protocol]["summary"] for protocol in PROTOCOL_ORDER
        },
        "VOL5_RF_source": "artifacts/experiments/final_validation/baseline_metrics.json",
    }
    document["content_sha256"] = canonical_digest(document)
    return document


def render_report(context: dict[str, Any], comparison: dict[str, Any]) -> str:
    summaries = context["summaries"]
    lines: list[str] = []
    add = lines.append
    add("# ARM F extension — does the ARM F budget lift the VOL5 ceiling?")
    add("")
    add(
        "Generated from the artifacts of this step. `VOL5_RF` figures are read from "
        "the Step 2 artifacts and were **not** refitted here."
    )
    add("")
    add("## Arms")
    add("")
    add("| Arm | Features | Learner | Role |")
    add("|---|---|---|---|")
    for arm in (REUSED_ARM, *FITTED_ARMS):
        budget = FEATURE_NAMES if arm == REUSED_ARM else ARM_BUDGETS[arm]
        role = experiment_configuration()["arms"][arm]["role"]
        add(
            f"| `{arm}` | {len(budget)} | "
            f"{model_description(arm)['estimator']} | {role} |"
        )
    add("")
    add("## Reconstruction proof")
    add("")
    reproduction = context["reproduction"]
    add(
        "`distinct_payload_ratio` was rebuilt from the canonical event tables with "
        "the unmodified P6 implementation, inside read-only transactions. The rebuilt "
        "ARM F reproduces the **published Phase 1 score streams exactly** on all five "
        "folds:"
    )
    add("")
    add("| Fold | Rows | Scores matching to 10 decimals | Max absolute difference |")
    add("|---:|---:|---:|---:|")
    for entry in reproduction["folds"]:
        add(
            f"| {entry['fold']} | {entry['rows']} | "
            f"{entry['scores_matching_to_ten_decimals']}/{entry['rows']} | "
            f"{entry['max_absolute_difference']:.3e} |"
        )
    add("")
    add(
        "This proves the reconstruction is correct. It is **not** a claim that this "
        "step reproduces history: the arms below are new experiments on the "
        "validation protocols."
    )
    add("")
    add("## Results by protocol")
    add("")
    for protocol in PROTOCOL_ORDER:
        add(f"### {protocol}")
        add("")
        add("| Arm | Features | Learner | ROC-AUC | PR-AUC | Recall | Precision | FPR | Episodes |")
        add("|---|---:|---|---:|---:|---:|---:|---:|---:|")
        for arm in (REUSED_ARM, *FITTED_ARMS):
            summary = summaries[arm][protocol]
            budget = FEATURE_NAMES if arm == REUSED_ARM else ARM_BUDGETS[arm]
            add(
                f"| `{arm}` | {len(budget)} | "
                f"{model_description(arm)['estimator']} | "
                f"{summary['macro_roc_auc']:.4f} | {summary['macro_pr_auc']:.4f} | "
                f"{summary['pooled_recall']:.4f} | {summary['pooled_precision']:.4f} | "
                f"{summary['pooled_fpr']:.6f} | "
                f"{summary['detected_episodes']}/{summary['total_episodes']} |"
            )
        add("")
    add("## Identifiable contrasts")
    add("")
    add(
        "Only contrasts that hold the learner constant support a statement about the "
        "feature budget."
    )
    add("")
    add("| Protocol | Contrast | Feature effect identifiable | ΔROC-AUC | ΔPR-AUC | ΔEpisode recall | Episodes |")
    add("|---|---|---|---:|---:|---:|---|")
    for protocol in PROTOCOL_ORDER:
        for name, entry in comparison["contrasts"][protocol].items():
            add(
                f"| {protocol} | {name} | "
                f"{'yes' if entry['feature_effect_identifiable'] else '**no**'} | "
                f"{entry['delta']['macro_roc_auc']:+.4f} | "
                f"{entry['delta']['macro_pr_auc']:+.4f} | "
                f"{entry['delta']['pooled_episode_recall']:+.4f} | "
                f"{entry['left_episodes']} → {entry['right_episodes']} |"
            )
    add("")
    add("## Zero-day Ares")
    add("")
    add("| Arm | ROC-AUC | PR-AUC | Threshold | FPR | Window recall | Episodes |")
    add("|---|---:|---:|---:|---:|---:|---:|")
    for arm in (REUSED_ARM, *FITTED_ARMS):
        summary = summaries[arm]["D_zero_day_ares"]
        record = (
            context["vol5"]["D_zero_day_ares"]["folds"][0]
            if arm == REUSED_ARM
            else context["results"][arm]["D_zero_day_ares"][0]
        )
        add(
            f"| `{arm}` | {record['roc_auc']:.4f} | {record['pr_auc']:.4f} | "
            f"{record['threshold']:.6f} | {record['fpr']:.6f} | "
            f"{record['recall']:.4f} | "
            f"{record['detected_episodes']}/{record['total_episodes']} |"
        )
    add("")
    add(
        "A gain measured where Ares is present in training, in protocols B or C, is "
        "not evidence of zero-day generalisation. Only protocol D speaks to the "
        "zero-day question."
    )
    add("")
    return "\n".join(lines)


def summarise(context: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": "preflight_ok",
        "artifacts_written": 0,
        "definition_checks": len(context["definition_checks"]),
        "models_fitted": sum(
            len(records)
            for arm in FITTED_ARMS
            for records in context["results"][arm].values()
        )
        + len(context["reproduction"]["folds"]),
        "postgresql_transaction_read_only": context["access"]["transaction_read_only"],
        "postgresql_writes": 0,
        "reconstruction_reproduces_published_arm_f": context["reproduction"][
            "all_folds_reproduce_exactly"
        ],
        "zero_day": {
            arm: {
                "roc_auc": round(
                    context["summaries"][arm]["D_zero_day_ares"]["macro_roc_auc"], 4
                ),
                "episodes": f"{context['summaries'][arm]['D_zero_day_ares']['detected_episodes']}"
                f"/{context['summaries'][arm]['D_zero_day_ares']['total_episodes']}",
            }
            for arm in (REUSED_ARM, *FITTED_ARMS)
        },
        "protocols": {
            protocol: {
                arm: f"{context['summaries'][arm][protocol]['detected_episodes']}"
                f"/{context['summaries'][arm][protocol]['total_episodes']}"
                for arm in (REUSED_ARM, *FITTED_ARMS)
            }
            for protocol in PROTOCOL_ORDER
        },
    }


def publish(context: dict[str, Any]) -> dict[str, Any]:
    outputs: dict[str, str] = {}
    outputs["armf_config.json"] = publish_immutable(
        CONFIG_PATH, json_bytes(experiment_configuration())
    )
    outputs["armf_reproduction.json"] = publish_immutable(
        REPRODUCTION_PATH, json_bytes(context["reproduction"])
    )
    outputs["armf_metrics.json"] = publish_immutable(
        METRICS_PATH, json_bytes(metrics_document(context))
    )
    comparison = comparison_document(context)
    outputs["armf_comparison.json"] = publish_immutable(
        COMPARISON_PATH, json_bytes(comparison)
    )
    outputs["armf_zero_day.json"] = publish_immutable(
        ZERO_DAY_PATH, json_bytes(zero_day_document(context))
    )
    outputs["ARMF_EXTENSION_REPORT.md"] = publish_immutable(
        REPORT_PATH, render_report(context, comparison).encode("utf-8")
    )
    manifest = {
        "schema_version": "1.0.0",
        "step": "final validation — step 5, ARM F extension",
        "frozen_at": datetime.now(UTC).isoformat(),
        "arms_fitted": list(FITTED_ARMS),
        "arm_reused_without_refit": REUSED_ARM,
        "arm_f_variant": "phase1_canonical",
        "phase2_r006_used": False,
        "models_fitted": sum(
            len(records)
            for arm in FITTED_ARMS
            for records in context["results"][arm].values()
        )
        + len(context["reproduction"]["folds"]),
        "training_order": TRAINING_ORDER,
        "hyperparameter_tuning": "none",
        "threshold_selected_on_test": False,
        "postgresql_writes": 0,
        "postgresql_transaction_read_only": context["access"]["transaction_read_only"],
        "reconstruction_reproduces_published_arm_f": True,
        "is_a_historical_reproduction_claim": False,
        "step1_artifacts_modified": False,
        "step2_artifacts_modified": False,
        "step3_artifacts_modified": False,
        "step4_artifacts_modified": False,
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
        raise ArmFExtensionError("manifest.json absent; run --publish")
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    mismatched = [
        name
        for name, digest in manifest["outputs"].items()
        if sha256_file(OUT_DIR / name) != digest
    ]
    changed = [
        name
        for name, digest in manifest["frozen_inputs"].items()
        if sha256_file(REPO_ROOT / name) != digest
    ]
    result = {
        "manifest_digest_stable": manifest_identity(manifest)
        == manifest["manifest_content_sha256"],
        "mismatched_outputs": mismatched,
        "frozen_inputs_changed": changed,
        "outputs": sorted(manifest["outputs"]),
    }
    if not result["manifest_digest_stable"] or mismatched or changed:
        raise ArmFExtensionError(f"published verification failed: {result}")
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
