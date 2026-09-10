"""Final scientific validation — Step 1: publish the deterministic splits.

Commands::

    python -m scripts.run_final_validation_splits --preflight
    python -m scripts.run_final_validation_splits --publish
    python -m scripts.run_final_validation_splits --verify

This step performs **no training**, opens **no database connection**, and writes
only under ``artifacts/experiments/final_validation/splits/``. Every input is a
frozen artifact read by digest.
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

from modules.detection.src.experiments.final_validation import (
    ARES_EPISODE_FOLD_COUNT,
    ARES_FAMILY,
    MINIMUM_EPISODES_FOR_EPISODE_PROTOCOL,
    SSH_FAMILY,
    FinalValidationError,
    PopulationRow,
    Protocol,
    assignment_bytes,
    canonical_digest,
    load_population,
    protocol_a_historical,
    protocol_b_entity_disjoint,
    protocol_c_episode_disjoint,
    protocol_d_zero_day_ares,
    protocol_document,
    shared_entities_across_attack_types,
    verify_population,
    verify_protocol,
)

REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[1]
PRODUCTION_DATASET: Final[Path] = (
    REPO_ROOT / "artifacts" / "production" / "ml_dataset_v1" / "ml_dataset.csv"
)
PRODUCTION_MANIFEST: Final[Path] = (
    REPO_ROOT / "artifacts" / "production" / "ml_dataset_v1" / "dataset_manifest.json"
)
HISTORICAL_FOLDS: Final[Path] = (
    REPO_ROOT / "artifacts" / "experiments" / "p1" / "p1_folds.json"
)
OUT_DIR: Final[Path] = (
    REPO_ROOT / "artifacts" / "experiments" / "final_validation" / "splits"
)
MANIFEST_PATH: Final[Path] = OUT_DIR / "splits_manifest.json"

EXPECTED_PRODUCTION_SHA256: Final[str] = (
    "e95aed008d994510e4c649c287feb8fe8f49a785bec144d7e83aa15804b6c062"
)
EXPECTED_HISTORICAL_FOLDS_SHA256: Final[str] = (
    "57e688fd3da90911707d7a172c161686d852094121eda1ac49e0221fc0529fa1"
)

#: Frozen inputs pinned by digest. None of them is ever written.
FROZEN_INPUTS: Final[tuple[str, ...]] = (
    "artifacts/production/ml_dataset_v1/ml_dataset.csv",
    "artifacts/production/ml_dataset_v1/dataset_manifest.json",
    "artifacts/experiments/p1/p1_folds.json",
    "artifacts/experiments/p1/p1_dataset.csv",
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


def read_production_population() -> list[PopulationRow]:
    """Load the frozen production dataset after checking its identity."""
    actual = sha256_file(PRODUCTION_DATASET)
    if actual != EXPECTED_PRODUCTION_SHA256:
        raise FinalValidationError(
            f"production dataset digest changed: {actual} != {EXPECTED_PRODUCTION_SHA256}"
        )
    with PRODUCTION_DATASET.open(newline="", encoding="utf-8") as stream:
        return load_population(csv.DictReader(stream))


def compare_with_historical_folds(protocol: Protocol) -> dict[str, Any]:
    """Prove protocol A reproduces the published folds, membership for membership."""
    actual = sha256_file(HISTORICAL_FOLDS)
    if actual != EXPECTED_HISTORICAL_FOLDS_SHA256:
        raise FinalValidationError(f"p1_folds.json digest changed: {actual}")
    published = {
        int(fold["index"]): fold
        for fold in json.loads(HISTORICAL_FOLDS.read_text(encoding="utf-8"))
    }
    differences: list[dict[str, Any]] = []
    for fold in protocol.folds:
        reference = published[fold.index]
        same_type = reference["held_out_attack_type"] == fold.held_out
        same_train = set(reference["train_row_ids"]) == set(fold.train_row_ids)
        same_test = set(reference["test_row_ids"]) == set(fold.test_row_ids)
        if not (same_type and same_train and same_test):
            differences.append(
                {
                    "fold": fold.index,
                    "same_held_out_attack_type": same_type,
                    "same_train_membership": same_train,
                    "same_test_membership": same_test,
                }
            )
    return {
        "published_folds": len(published),
        "reproduced_folds": len(protocol.folds),
        "identical_membership": not differences,
        "differences": differences,
    }


def compare_zero_day_with_historical_fold0(protocol: Protocol) -> dict[str, Any]:
    """Prove protocol D equals published fold 0, so Ares results stay comparable."""
    published = {
        int(fold["index"]): fold
        for fold in json.loads(HISTORICAL_FOLDS.read_text(encoding="utf-8"))
    }[0]
    fold = protocol.folds[0]
    return {
        "same_test_membership": set(published["test_row_ids"]) == set(fold.test_row_ids),
        "same_train_membership": set(published["train_row_ids"])
        == set(fold.train_row_ids),
        "published_test_rows": len(published["test_row_ids"]),
        "protocol_test_rows": len(fold.test_row_ids),
    }


def episode_eligibility(population: Sequence[PopulationRow]) -> dict[str, Any]:
    """Record, per family, whether an intra-family episode split is defensible."""
    counts: dict[str, dict[str, int]] = {}
    for row in population:
        if row.label == 1 and row.attack_type:
            entry = counts.setdefault(
                row.attack_type, {"windows": 0, "episodes": 0, "entities": 0}
            )
            entry["windows"] += 1
    for family in counts:
        counts[family]["episodes"] = len(
            {r.episode_id for r in population if r.attack_type == family}
        )
        counts[family]["entities"] = len(
            {r.entity_key for r in population if r.attack_type == family}
        )
    eligibility: dict[str, Any] = {}
    for family, entry in sorted(counts.items()):
        episodes = entry["episodes"]
        if family == ARES_FAMILY:
            decision, role = True, "main protocol C analysis"
        elif family == SSH_FAMILY:
            decision, role = True, "secondary analysis only, statistically weak"
        elif episodes < MINIMUM_EPISODES_FOR_EPISODE_PROTOCOL:
            decision, role = False, (
                f"excluded: only {episodes} episode(s), no robust intra-family split"
            )
        else:  # pragma: no cover - defensive
            decision, role = False, "excluded by owner decision"
        eligibility[family] = {**entry, "protocol_c_built": decision, "role": role}
    return eligibility


def build_context() -> dict[str, Any]:
    """Build and verify every protocol. Writes nothing."""
    population = read_production_population()
    population_checks = verify_population(population)
    index = {row.row_id: row for row in population}

    protocols: list[Protocol] = [
        protocol_a_historical(population),
        protocol_b_entity_disjoint(population),
        protocol_c_episode_disjoint(population, ARES_FAMILY, ARES_EPISODE_FOLD_COUNT),
        protocol_c_episode_disjoint(population, SSH_FAMILY, None),
        protocol_d_zero_day_ares(population),
    ]
    documents: dict[str, dict[str, Any]] = {}
    for protocol in protocols:
        checks, statistics = verify_protocol(protocol, index)
        documents[protocol.key] = protocol_document(protocol, checks, statistics)

    by_key = {protocol.key: protocol for protocol in protocols}
    documents["A_historical"]["historical_reproduction"] = compare_with_historical_folds(
        by_key["A_historical"]
    )
    if not documents["A_historical"]["historical_reproduction"]["identical_membership"]:
        raise FinalValidationError(
            "protocol A does not reproduce the published p1_folds.json"
        )
    documents["D_zero_day_ares"]["historical_fold0_reproduction"] = (
        compare_zero_day_with_historical_fold0(by_key["D_zero_day_ares"])
    )
    if not all(documents["D_zero_day_ares"]["historical_fold0_reproduction"][k] for k in ("same_test_membership", "same_train_membership")):
        raise FinalValidationError("protocol D does not reproduce published fold 0")
    for key in ("A_historical", "D_zero_day_ares"):
        documents[key]["content_sha256"] = canonical_digest(
            {k: v for k, v in documents[key].items() if k != "content_sha256"}
        )

    return {
        "population": population,
        "population_checks": population_checks,
        "shared_entities": shared_entities_across_attack_types(population),
        "episode_eligibility": episode_eligibility(population),
        "protocols": protocols,
        "documents": documents,
    }


def summarise(context: dict[str, Any]) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "status": "preflight_ok",
        "artifacts_written": 0,
        "population_rows": len(context["population"]),
        "population_checks_passed": len(context["population_checks"]),
        "shared_entities_across_attack_types": context["shared_entities"],
        "episode_eligibility": context["episode_eligibility"],
        "protocols": {},
    }
    for protocol in context["protocols"]:
        document = context["documents"][protocol.key]
        folds = document["folds"]
        summary["protocols"][protocol.key] = {
            "folds": document["fold_count"],
            "checks_passed": sum(1 for c in document["checks"] if c["passed"]),
            "checks_failed": sum(1 for c in document["checks"] if not c["passed"]),
            "entity_disjoint_required": document["requires_entity_disjoint"],
            "max_entity_intersection": max(f["entity_intersection_count"] for f in folds),
            "max_episode_intersection": max(
                f["episode_intersection_count"] for f in folds
            ),
            "test_positives_per_fold": [f["test_positives"] for f in folds],
            "test_rows_per_fold": [f["test_rows"] for f in folds],
            "assignment_sha256": document["assignment_sha256"],
        }
    return summary


def publish(context: dict[str, Any]) -> dict[str, Any]:
    """Publish assignments, per-protocol documents and the manifest."""
    for document in context["documents"].values():
        failed = [c for c in document["checks"] if not c["passed"]]
        if failed:
            raise FinalValidationError(f"refusing to publish with failed checks: {failed}")

    outputs: dict[str, str] = {}
    for protocol in context["protocols"]:
        name = f"{protocol.key}_assignment.csv"
        outputs[name] = publish_immutable(OUT_DIR / name, assignment_bytes(protocol))
        document_name = f"{protocol.key}.json"
        outputs[document_name] = publish_immutable(
            OUT_DIR / document_name, json_bytes(context["documents"][protocol.key])
        )

    manifest = {
        "schema_version": "1.0.0",
        "step": "final validation — step 1, split construction only",
        "frozen_at": datetime.now(UTC).isoformat(),
        "models_fitted": 0,
        "postgresql_connections": 0,
        "postgresql_writes": 0,
        "randomness_used": False,
        "seed_used": None,
        "population_source": "artifacts/production/ml_dataset_v1/ml_dataset.csv",
        "population_rows": len(context["population"]),
        "split_metadata_columns_used": list(
            context["documents"]["A_historical"]["split_metadata_columns_used"]
        ),
        "model_feature_columns_read": [],
        "shared_entities_across_attack_types": context["shared_entities"],
        "episode_eligibility": context["episode_eligibility"],
        "protocols": {
            key: {
                "title": document["title"],
                "rule": document["rule"],
                "determinism": document["determinism"],
                "fold_count": document["fold_count"],
                "requires_entity_disjoint": document["requires_entity_disjoint"],
                "requires_episode_disjoint": document["requires_episode_disjoint"],
                "content_sha256": document["content_sha256"],
                "assignment_sha256": document["assignment_sha256"],
                "max_entity_intersection": max(
                    f["entity_intersection_count"] for f in document["folds"]
                ),
                "max_episode_intersection": max(
                    f["episode_intersection_count"] for f in document["folds"]
                ),
            }
            for key, document in sorted(context["documents"].items())
        },
        "frozen_inputs": {name: sha256_file(REPO_ROOT / name) for name in FROZEN_INPUTS},
        "outputs": outputs,
        "frozen_artifacts_modified": False,
        "production_dataset_modified": False,
    }
    manifest["manifest_content_sha256"] = manifest_identity(manifest)
    payload = json_bytes(manifest)
    if MANIFEST_PATH.exists():
        existing = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        if existing.get("manifest_content_sha256") != manifest["manifest_content_sha256"]:
            raise FileExistsError(f"immutable manifest differs in identity: {MANIFEST_PATH}")
    else:
        publish_immutable(MANIFEST_PATH, payload)
    return {
        "status": "published",
        "manifest_content_sha256": manifest["manifest_content_sha256"],
        "outputs": {**outputs, "splits_manifest.json": sha256_file(MANIFEST_PATH)},
    }


def verify_published() -> dict[str, Any]:
    if not MANIFEST_PATH.exists():
        raise FinalValidationError("splits_manifest.json absent; run --publish")
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    recomputed = manifest_identity(manifest)
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
        "manifest_digest_stable": recomputed == manifest["manifest_content_sha256"],
        "mismatched_outputs": mismatched,
        "frozen_inputs_changed": frozen_changed,
        "protocols": sorted(manifest["protocols"]),
    }
    if not result["manifest_digest_stable"] or mismatched or frozen_changed:
        raise FinalValidationError(f"published verification failed: {result}")
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
