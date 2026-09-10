"""Production Finale v1 — build, validate and publish the canonical ML dataset.

Commands::

    python -m scripts.run_production_ml_dataset --preflight
    python -m scripts.run_production_ml_dataset --publish
    python -m scripts.run_production_ml_dataset --verify

``--preflight`` reads PostgreSQL read-only, materialises the M-chain window
labels in memory, builds the dataset, checks every invariant and writes nothing.
``--publish`` repeats the same computation and only then publishes five immutable
artifacts. Any failed invariant aborts before a single byte is written.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import UTC, datetime
from hashlib import sha256
import json
import os
from pathlib import Path
from typing import Any, Final, Sequence

from modules.detection.src.experiments.p1_dataset import (
    FEATURE_NAMES,
    Row,
    dataset_digest,
)

# The frozen P1/P3 rule-overlap classifier and episode assignment are reused
# deliberately: they are the exact published code path behind the 376 / 172,372
# window counts. Re-deriving them would risk a silent divergence from ratified
# evidence. Their read path is not reused, because production enforces a
# genuinely read-only transaction instead of a next-transaction default.
from modules.detection.src.experiments.p1_dataset import (  # noqa: PLC2701
    _assign_episodes,
    _classify,
    _compiled_rules,
)
from modules.detection.src.persistence.monday_benign_persistence import (
    get_monday_benign_connection,
)
from modules.detection.src.production.ml_dataset import (
    DATASET_COLUMNS,
    EXCLUDED_M6_FEATURES,
    EXPECTED_ATTACK_WINDOWS,
    EXPECTED_BENIGN_ROWS,
    EXPECTED_M6_WINDOWS,
    EXPECTED_MB6_WINDOWS,
    EXPECTED_MB7_WINDOW_LABELS,
    EXPECTED_P1_DATASET_CONTENT_SHA256,
    EXPECTED_P1_DATASET_FILE_SHA256,
    EXPECTED_TOTAL_ROWS,
    FORBIDDEN_CONTENT_FEATURES,
    LABEL_POLICY,
    WINDOW_LABEL_COLUMNS,
    ProductionDatasetError,
    WindowLabel,
    canonical_digest,
    dataset_bytes,
    verify_dataset,
    verify_materialization,
    verify_policy_consistency,
    window_label_bytes,
    window_label_counts,
)

REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[1]
OUT_DIR: Final[Path] = REPO_ROOT / "artifacts" / "production" / "ml_dataset_v1"
DATASET_PATH: Final[Path] = OUT_DIR / "ml_dataset.csv"
WINDOW_LABELS_PATH: Final[Path] = OUT_DIR / "window_labels.csv"
MATERIALIZATION_REPORT_PATH: Final[Path] = OUT_DIR / "label_materialization_report.json"
MANIFEST_PATH: Final[Path] = OUT_DIR / "dataset_manifest.json"
REPORT_PATH: Final[Path] = OUT_DIR / "DATASET_REPORT.md"

PRODUCTION_DATABASE: Final[str] = "cybersentinel"
MB_DATABASE: Final[str] = "cybersentinel_test"

#: Frozen inputs whose identity is pinned in the manifest, never rewritten.
FROZEN_INPUTS: Final[tuple[str, ...]] = (
    "artifacts/reports/m6_v2_feature_window_run.json",
    "artifacts/reports/mb6_monday_benign_feature_window_run.json",
    "artifacts/reports/mb7_monday_benign_labeling_run.json",
    "datasets/manifests/cicids2017_feature_window_v2.yaml",
    "datasets/manifests/cicids2017_labels.yaml",
    "datasets/manifests/monday_benign_labeling.yaml",
    "artifacts/experiments/p1/p1_dataset.csv",
)

SCHEMA_VERSION: Final[str] = "1.0.0"

#: Fields deliberately excluded from the manifest identity. Wall-clock values
#: must never affect ``manifest_content_sha256``, otherwise a deterministic rerun
#: cannot reproduce the published identity. This mirrors the rule ratified for
#: MB2 and reused by the Phase 2 tuning experiment.
IDENTITY_EXCLUDED_FIELDS: Final[frozenset[str]] = frozenset(
    {"frozen_at", "manifest_content_sha256"}
)


def manifest_identity(document: dict[str, Any]) -> str:
    """Formatting- and clock-independent identity of the manifest."""
    return canonical_digest(
        {
            key: value
            for key, value in document.items()
            if key not in IDENTITY_EXCLUDED_FIELDS
        }
    )


def sha256_file(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def json_bytes(document: Any) -> bytes:
    return json.dumps(document, indent=2, sort_keys=True).encode("utf-8") + b"\n"


def publish_immutable(path: Path, payload: bytes) -> str:
    """Create bytes once, durably; accept an identical rerun, reject a change."""
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


def read_only_query(database: str, sql: str) -> list[tuple]:
    """Run one query inside a genuinely read-only transaction.

    ``SET default_transaction_read_only = on`` only affects *future*
    transactions, so it cannot protect the statement that follows it in the same
    transaction. Production therefore owns its queries and sets
    ``connection.read_only`` before the transaction begins, then proves that the
    server really reports ``transaction_read_only = on``.
    """
    conn = get_monday_benign_connection(database)
    try:
        conn.read_only = True
        with conn.cursor() as cur:
            cur.execute("SELECT current_setting('transaction_read_only')")
            mode = cur.fetchone()[0]
            if mode != "on":
                raise ProductionDatasetError(
                    f"{database} transaction is not read-only: {mode!r}"
                )
            cur.execute(sql)
            return cur.fetchall()
    finally:
        conn.rollback()
        conn.close()


def scalar(database: str, sql: str) -> int:
    """One read-only scalar count."""
    return int(read_only_query(database, sql)[0][0])


def read_only_mode_report() -> dict[str, str]:
    """Record the observed transaction mode of both databases."""
    report: dict[str, str] = {}
    for database in (PRODUCTION_DATABASE, MB_DATABASE):
        report[database] = str(
            read_only_query(
                database, "SELECT current_setting('transaction_read_only')"
            )[0][0]
        )
    return report


def load_positives_read_only() -> list[Row]:
    """Type the M6 attack windows, reusing the frozen classifier and episodes.

    Identical logic to the frozen ``load_positives``, but every read runs in a
    provably read-only transaction. Equivalence is not assumed: it is proven by
    the byte-parity invariant against the ratified ``p1_dataset.csv``.
    """
    rules = _compiled_rules(str(REPO_ROOT))
    features = ", ".join(FEATURE_NAMES)
    raw = read_only_query(
        PRODUCTION_DATABASE,
        "SELECT window_id::text, output_partition, entity_source_ip,"
        " entity_destination_ip, entity_transport, entity_service,"
        f" window_start_time, window_end_time, {features}"
        " FROM m6_canonical.feature_windows",
    )
    positives: list[Row] = []
    for record in raw:
        wid, partition, src, dst, transport, service, start, end = record[:8]
        disposition, attack_type = _classify(rules, src, dst, transport, start, end)
        if disposition not in ("target_attack", "known_other_attack"):
            continue
        if attack_type is None:
            raise ProductionDatasetError(f"attack window {wid} has no attack type")
        positives.append(
            Row(
                row_id=wid,
                source="m6",
                label=1,
                disposition=disposition,
                attack_type=attack_type,
                entity_key="|".join((src, dst, transport, service)),
                episode_id=None,
                partition=partition,
                window_start_epoch=int(start),
                features=tuple(float(value) for value in record[8:]),
            )
        )
    return _assign_episodes(positives)


def load_negatives_read_only() -> list[Row]:
    """Load the MB-LABEL ``benign_reference`` windows in a read-only transaction."""
    features = ", ".join(f"f.{name}" for name in FEATURE_NAMES)
    raw = read_only_query(
        MB_DATABASE,
        "SELECT f.window_id::text, f.output_partition, f.entity_source_ip,"
        " f.entity_destination_ip, f.entity_transport, f.entity_service,"
        f" f.window_start_time, {features}"
        " FROM mb6_canonical.feature_windows f"
        " JOIN mb7_canonical.window_labels w ON w.source_window_id = f.window_id"
        " WHERE w.disposition = 'benign_reference'",
    )
    negatives: list[Row] = []
    for record in raw:
        wid, partition, src, dst, transport, service, start = record[:7]
        negatives.append(
            Row(
                row_id=wid,
                source="mb6",
                label=0,
                disposition="benign_reference",
                attack_type=None,
                entity_key="|".join((src, dst, transport, service)),
                episode_id=None,
                partition=partition,
                window_start_epoch=int(start),
                features=tuple(float(value) for value in record[7:]),
            )
        )
    return negatives


def read_upstream_counts() -> dict[str, int]:
    """Count the frozen upstream populations. Read-only."""
    return {
        "m6_windows": scalar(
            PRODUCTION_DATABASE, "SELECT count(*) FROM m6_canonical.feature_windows"
        ),
        "mb6_windows": scalar(
            MB_DATABASE, "SELECT count(*) FROM mb6_canonical.feature_windows"
        ),
        "mb7_window_labels": scalar(
            MB_DATABASE, "SELECT count(*) FROM mb7_canonical.window_labels"
        ),
    }


def materialize_window_labels() -> list[WindowLabel]:
    """Label every M6 window out of band, using the frozen M5 v2 policy."""
    rules = _compiled_rules(str(REPO_ROOT))
    raw = read_only_query(
        PRODUCTION_DATABASE,
        "SELECT window_id::text, output_partition, entity_source_ip,"
        " entity_destination_ip, entity_transport, entity_service,"
        " window_start_time, window_end_time"
        " FROM m6_canonical.feature_windows",
    )
    labels: list[WindowLabel] = []
    for window_id, partition, src, dst, transport, service, start, end in raw:
        disposition, attack_type = _classify(rules, src, dst, transport, start, end)
        labels.append(
            WindowLabel(
                window_id=window_id,
                output_partition=partition,
                entity_key="|".join((src, dst, transport, service)),
                window_start_epoch=int(start),
                disposition=disposition,
                attack_type=attack_type,
            )
        )
    return labels


def cross_check_attack_windows(
    labels: Sequence[WindowLabel], positives: Sequence[Row]
) -> list[dict[str, Any]]:
    """Prove the materialised attack set equals the dataset positive set."""
    checks: list[dict[str, Any]] = []

    def record(name: str, passed: bool, detail: Any) -> None:
        checks.append({"check": name, "passed": bool(passed), "detail": detail})
        if not passed:
            raise ProductionDatasetError(f"{name}: {detail}")

    materialised = {
        label.window_id: (label.disposition, label.attack_type)
        for label in labels
        if label.dataset_label == 1
    }
    dataset = {row.row_id: (row.disposition, row.attack_type) for row in positives}
    record("attack_window_ids_match", set(materialised) == set(dataset), len(materialised))
    record(
        "attack_dispositions_and_types_match",
        materialised == dataset,
        len([k for k in materialised if materialised[k] != dataset.get(k)]),
    )
    return checks


def build_context() -> dict[str, Any]:
    """Read, materialise, build and validate everything without writing."""
    policy_checks = verify_policy_consistency()
    counts = read_upstream_counts()
    upstream_checks: list[dict[str, Any]] = []

    def record(name: str, passed: bool, detail: Any) -> None:
        upstream_checks.append({"check": name, "passed": bool(passed), "detail": detail})
        if not passed:
            raise ProductionDatasetError(f"{name}: {detail}")

    record("m6_windows", counts["m6_windows"] == EXPECTED_M6_WINDOWS, counts["m6_windows"])
    record("mb6_windows", counts["mb6_windows"] == EXPECTED_MB6_WINDOWS, counts["mb6_windows"])
    record(
        "mb7_window_labels",
        counts["mb7_window_labels"] == EXPECTED_MB7_WINDOW_LABELS,
        counts["mb7_window_labels"],
    )

    labels = materialize_window_labels()
    materialization_checks = verify_materialization(labels, counts["m6_windows"])

    transaction_modes = read_only_mode_report()
    record(
        "transactions_are_read_only",
        all(mode == "on" for mode in transaction_modes.values()),
        transaction_modes,
    )

    positives = load_positives_read_only()
    negatives = load_negatives_read_only()
    rows = positives + negatives
    payload = dataset_bytes(rows)
    content_digest = dataset_digest(rows)
    dataset_checks = verify_dataset(rows, payload, content_digest)
    parity_checks = cross_check_attack_windows(labels, positives)

    labels_payload = window_label_bytes(labels)
    return {
        "counts": counts,
        "transaction_modes": transaction_modes,
        "labels": labels,
        "rows": rows,
        "positives": positives,
        "negatives": negatives,
        "dataset_payload": payload,
        "dataset_content_sha256": content_digest,
        "labels_payload": labels_payload,
        "checks": (
            policy_checks
            + upstream_checks
            + materialization_checks
            + dataset_checks
            + parity_checks
        ),
    }


def materialization_report(context: dict[str, Any]) -> dict[str, Any]:
    labels: Sequence[WindowLabel] = context["labels"]
    counts = window_label_counts(labels)
    per_partition = Counter(label.output_partition for label in labels)
    per_type = Counter(
        label.attack_type for label in labels if label.dataset_label == 1
    )
    document = {
        "report_version": SCHEMA_VERSION,
        "experiment": "Production Finale v1 — M-chain window label materialization",
        "materialized_out_of_band": True,
        "postgresql_writes": 0,
        "postgresql_transaction_read_only": context["transaction_modes"],
        "m7_schema_created": False,
        "frozen_artifacts_modified": False,
        "policy": {
            "label_manifest": "datasets/manifests/cicids2017_labels.yaml",
            "policy_variant": "m5_v2_observable_attacker_derived_from_v1",
            "classifier": "frozen P1/P3 rule-overlap classifier (p1_dataset._classify)",
            "aggregation_reference": "ANY_ATTACK precedence verified against the freeze",
            "semantics_note": (
                "window dispositions are resolved against rule intervals, not by "
                "folding event dispositions; on the M chain this yields zero "
                "ambiguous windows although M5 v2 marks 164 events ambiguous"
            ),
            "unknown_to_benign_conversion": "forbidden",
            "ambiguous_to_benign_conversion": "forbidden",
        },
        "total_window_count": len(labels),
        "window_disposition_counts": counts,
        "attack_window_count": counts["target_attack"] + counts["known_other_attack"],
        "excluded_window_count": counts["unknown"] + counts["ambiguous"],
        "windows_per_partition": dict(sorted(per_partition.items())),
        "attack_windows_per_type": dict(sorted(per_type.items())),
        "supervised_label_counts": {
            "1": counts["target_attack"] + counts["known_other_attack"],
            "0": 0,
            "excluded": counts["unknown"] + counts["ambiguous"],
        },
        "negatives_source": {
            "database": MB_DATABASE,
            "windows": "mb6_canonical.feature_windows",
            "labels": "mb7_canonical.window_labels",
            "disposition": "benign_reference",
            "rows": len(context["negatives"]),
        },
        "checks": context["checks"],
    }
    document["content_sha256"] = canonical_digest(document)
    return document


def dataset_manifest(context: dict[str, Any], outputs: dict[str, str]) -> dict[str, Any]:
    labels: Sequence[WindowLabel] = context["labels"]
    counts = window_label_counts(labels)
    document = {
        "schema_version": SCHEMA_VERSION,
        "experiment": "Production Finale v1 — canonical supervised ML dataset",
        "frozen_at": datetime.now(UTC).isoformat(),
        "label_policy": {
            "target_attack": 1,
            "known_other_attack": 1,
            "benign_reference": 0,
            "unknown": "excluded",
            "ambiguous": "excluded",
        },
        "unknown_to_benign_conversion": "forbidden",
        "ambiguous_to_benign_conversion": "forbidden",
        "feature_budget": list(FEATURE_NAMES),
        "feature_count": len(FEATURE_NAMES),
        "feature_order_source": "modules/detection/src/experiments/p1_dataset.py::FEATURE_NAMES",
        "excluded_m6_features": list(EXCLUDED_M6_FEATURES),
        "arm_f_features_included": False,
        "forbidden_content_features": list(FORBIDDEN_CONTENT_FEATURES),
        "dataset_columns": list(DATASET_COLUMNS),
        "window_label_columns": list(WINDOW_LABEL_COLUMNS),
        "sources": {
            "attacks": f"{PRODUCTION_DATABASE}/m6_canonical.feature_windows",
            "benign_windows": f"{MB_DATABASE}/mb6_canonical.feature_windows",
            "benign_labels": f"{MB_DATABASE}/mb7_canonical.window_labels",
        },
        "observed_counts": {
            "m6_windows": context["counts"]["m6_windows"],
            "mb6_windows": context["counts"]["mb6_windows"],
            "mb7_window_labels": context["counts"]["mb7_window_labels"],
            "attack_rows": sum(1 for row in context["rows"] if row.label == 1),
            "benign_rows": sum(1 for row in context["rows"] if row.label == 0),
            "total_rows": len(context["rows"]),
            "m_unknown_excluded": counts["unknown"],
            "m_ambiguous_excluded": counts["ambiguous"],
        },
        "expected_counts": {
            "m6_windows": EXPECTED_M6_WINDOWS,
            "mb6_windows": EXPECTED_MB6_WINDOWS,
            "mb7_window_labels": EXPECTED_MB7_WINDOW_LABELS,
            "attack_rows": EXPECTED_ATTACK_WINDOWS,
            "benign_rows": EXPECTED_BENIGN_ROWS,
            "total_rows": EXPECTED_TOTAL_ROWS,
        },
        "p1_parity": {
            "dataset_content_sha256": context["dataset_content_sha256"],
            "expected_dataset_content_sha256": EXPECTED_P1_DATASET_CONTENT_SHA256,
            "dataset_file_sha256": outputs["ml_dataset.csv"],
            "expected_dataset_file_sha256": EXPECTED_P1_DATASET_FILE_SHA256,
            "byte_identical_to_p1_dataset_csv": (
                outputs["ml_dataset.csv"] == EXPECTED_P1_DATASET_FILE_SHA256
            ),
        },
        "frozen_inputs": {
            name: sha256_file(REPO_ROOT / name) for name in FROZEN_INPUTS
        },
        "outputs": outputs,
        "postgresql_writes": 0,
        "postgresql_transaction_read_only": context["transaction_modes"],
        "postgresql_transaction_mode_enforcement": (
            "connection.read_only set before the transaction begins, then "
            "current_setting('transaction_read_only') asserted to be 'on'"
        ),
        "frozen_artifacts_modified": False,
        "m1_to_m6_modified": False,
        "mb1_to_mb7_modified": False,
        "models_fitted": 0,
        "scientific_scope": (
            "one frozen CICIDS2017 snapshot; 376 attack windows from 9 entities and "
            "54 episodes; entity identity separates the classes perfectly, so the "
            "effective attack sample size is of the order of nine"
        ),
    }
    document["manifest_content_sha256"] = manifest_identity(document)
    return document


def render_report(context: dict[str, Any], manifest: dict[str, Any]) -> str:
    counts = window_label_counts(context["labels"])
    observed = manifest["observed_counts"]
    per_type = Counter(
        row.attack_type for row in context["positives"] if row.attack_type
    )
    lines = [
        "# Production Finale v1 — canonical supervised ML dataset",
        "",
        f"Dataset content digest: `{context['dataset_content_sha256']}`  ",
        f"Dataset file digest: `{sha256(context['dataset_payload']).hexdigest()}`",
        "",
        "The manifest hashes this report, so this report deliberately does not embed "
        "the manifest identity: that would create a circular reference and break "
        "deterministic reruns.",
        "",
        "## Label policy",
        "",
        "| Disposition | Dataset label |",
        "|---|---|",
        "| `target_attack` | `1` |",
        "| `known_other_attack` | `1` |",
        "| `benign_reference` | `0` |",
        "| `unknown` | **excluded** |",
        "| `ambiguous` | **excluded** |",
        "",
        "Converting `unknown` or `ambiguous` into a negative is forbidden and is "
        "enforced by code and by tests.",
        "",
        "## Feature budget",
        "",
        "Exactly the five P1 features, in the canonical `FEATURE_NAMES` order:",
        "",
    ]
    for index, name in enumerate(FEATURE_NAMES, start=1):
        lines.append(f"{index}. `{name}`")
    lines.extend(
        [
            "",
            "Excluded M6 features: "
            + ", ".join(f"`{name}`" for name in EXCLUDED_M6_FEATURES)
            + ". ARM F content features are deliberately absent; ARM F/Ares remains a "
            "separate scientific experiment on the representational ceiling.",
            "",
            "## M-chain window label materialization",
            "",
            "| Window disposition | Windows | Dataset label |",
            "|---|---:|---|",
            f"| `target_attack` | {counts['target_attack']} | 1 |",
            f"| `known_other_attack` | {counts['known_other_attack']} | 1 |",
            f"| `ambiguous` | {counts['ambiguous']} | excluded |",
            f"| `unknown` | {counts['unknown']} | excluded |",
            f"| `benign_reference` | {counts['benign_reference']} | 0 |",
            f"| **Total** | **{len(context['labels'])}** | — |",
            "",
            "Labels are materialised **out of band**, as files. No `m7_canonical` "
            "schema was created and PostgreSQL received zero writes.",
            "",
            "## Supervised population",
            "",
            "| Population | Rows | Source |",
            "|---|---:|---|",
            f"| `target_attack` | {sum(1 for r in context['positives'] if r.disposition == 'target_attack')} | `m6` |",
            f"| `known_other_attack` | {sum(1 for r in context['positives'] if r.disposition == 'known_other_attack')} | `m6` |",
            f"| Attack, `label=1` | **{observed['attack_rows']}** | `m6` |",
            f"| Benign, `label=0` | **{observed['benign_rows']}** | `mb6` + `mb7` |",
            f"| **Total** | **{observed['total_rows']}** | — |",
            f"| `unknown` excluded (M) | {observed['m_unknown_excluded']} | never negative |",
            f"| `ambiguous` excluded (M) | {observed['m_ambiguous_excluded']} | never negative |",
            "",
            "Attack windows per type:",
            "",
            "| Attack type | Windows |",
            "|---|---:|",
        ]
    )
    for name, value in sorted(per_type.items()):
        lines.append(f"| `{name}` | {value} |")
    parity = manifest["p1_parity"]
    lines.extend(
        [
            "",
            "## Parity with the ratified P1 population",
            "",
            f"- content digest: `{parity['dataset_content_sha256']}`",
            f"- file digest: `{parity['dataset_file_sha256']}`",
            f"- byte-identical to `artifacts/experiments/p1/p1_dataset.csv`: "
            f"**{str(parity['byte_identical_to_p1_dataset_csv']).lower()}**",
            "",
            "P1 remains untouched as experimental evidence. This artifact is a "
            "separate production output whose equivalence is proven by digest.",
            "",
            "## Semantics note, recorded rather than hidden",
            "",
            "Window dispositions are resolved by the frozen P1/P3 rule-overlap "
            "classifier, not by folding event dispositions. The `ANY_ATTACK` "
            "precedence is verified against the freeze, but the two computations are "
            "not identical: on the M chain this yields zero `ambiguous` windows even "
            "though M5 v2 marks 164 individual events `ambiguous`. Attack detection "
            "is unaffected; the distinction matters only for how uncertainty is "
            "named, and in both readings uncertainty is excluded, never benign.",
            "",
            "## Scientific limits",
            "",
            f"- {manifest['scientific_scope']}.",
            "- `benign_reference` is absent from the M chain, so negatives come "
            "exclusively from the parallel Monday capture; any day-correlated "
            "artefact is a confounder that this dataset cannot rule out.",
            "- 172,372 M windows remain of unknown status. Alerts on them are not "
            "false positives, and treating them as benign would destroy that "
            "distinction.",
            "",
        ]
    )
    return "\n".join(lines)


def summarise(context: dict[str, Any]) -> dict[str, Any]:
    counts = window_label_counts(context["labels"])
    return {
        "status": "preflight_ok",
        "upstream": context["counts"],
        "window_disposition_counts": counts,
        "attack_rows": sum(1 for row in context["rows"] if row.label == 1),
        "benign_rows": sum(1 for row in context["rows"] if row.label == 0),
        "total_rows": len(context["rows"]),
        "dataset_content_sha256": context["dataset_content_sha256"],
        "dataset_file_sha256": sha256(context["dataset_payload"]).hexdigest(),
        "p1_content_parity": (
            context["dataset_content_sha256"] == EXPECTED_P1_DATASET_CONTENT_SHA256
        ),
        "p1_file_parity": (
            sha256(context["dataset_payload"]).hexdigest()
            == EXPECTED_P1_DATASET_FILE_SHA256
        ),
        "checks_passed": len(context["checks"]),
        "checks_failed": sum(1 for check in context["checks"] if not check["passed"]),
        "artifacts_written": 0,
    }


def publish_manifest(document: dict[str, Any]) -> str:
    """Publish the manifest idempotently on identity, not on wall-clock bytes."""
    payload = json_bytes(document)
    if MANIFEST_PATH.exists():
        existing = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        if existing.get("manifest_content_sha256") != document["manifest_content_sha256"]:
            raise FileExistsError(
                f"immutable manifest differs in identity: {MANIFEST_PATH}"
            )
        return sha256_file(MANIFEST_PATH)
    return publish_immutable(MANIFEST_PATH, payload)


def publish(context: dict[str, Any]) -> dict[str, Any]:
    """Publish the five deliverables only after every invariant has passed."""
    if any(check["passed"] is False for check in context["checks"]):
        raise ProductionDatasetError("refusing to publish with a failed invariant")
    outputs: dict[str, str] = {}
    outputs["ml_dataset.csv"] = publish_immutable(
        DATASET_PATH, context["dataset_payload"]
    )
    outputs["window_labels.csv"] = publish_immutable(
        WINDOW_LABELS_PATH, context["labels_payload"]
    )
    report = materialization_report(context)
    outputs["label_materialization_report.json"] = publish_immutable(
        MATERIALIZATION_REPORT_PATH, json_bytes(report)
    )
    manifest = dataset_manifest(context, dict(outputs))
    narrative = render_report(context, manifest)
    outputs["DATASET_REPORT.md"] = publish_immutable(
        REPORT_PATH, narrative.encode("utf-8")
    )
    manifest = dataset_manifest(context, dict(outputs))
    manifest_file_sha = publish_manifest(manifest)
    return {
        "status": "published",
        "outputs": {**outputs, "dataset_manifest.json": manifest_file_sha},
        "manifest_content_sha256": manifest["manifest_content_sha256"],
        "p1_byte_identical": manifest["p1_parity"]["byte_identical_to_p1_dataset_csv"],
    }


def verify_published() -> dict[str, Any]:
    """Recompute every published digest against the manifest. Read-only."""
    if not MANIFEST_PATH.exists():
        raise ProductionDatasetError("dataset_manifest.json absent; run --publish")
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    digest = manifest["manifest_content_sha256"]
    recomputed = manifest_identity(manifest)
    mismatched = [
        name
        for name, value in manifest["outputs"].items()
        if name != "dataset_manifest.json" and sha256_file(OUT_DIR / name) != value
    ]
    frozen_changed = [
        name
        for name, value in manifest["frozen_inputs"].items()
        if sha256_file(REPO_ROOT / name) != value
    ]
    result = {
        "manifest_digest_stable": recomputed == digest,
        "mismatched_outputs": mismatched,
        "frozen_inputs_changed": frozen_changed,
        "p1_byte_identical": manifest["p1_parity"]["byte_identical_to_p1_dataset_csv"],
        "observed_counts": manifest["observed_counts"],
    }
    if not result["manifest_digest_stable"] or mismatched or frozen_changed:
        raise ProductionDatasetError(f"published verification failed: {result}")
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
