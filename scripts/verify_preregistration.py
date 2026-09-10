"""Verify the pre-registration freeze of the priority-family transfer protocol.

Purpose
-------
Recompute every digest pinned in ``protocol_manifest.json`` and prove that
nothing changed. It is intended to be run **twice**:

1. before the holdout is opened, to establish the baseline;
2. after the results are published, so that "nothing was modified after the
   holdout was opened" is demonstrable rather than asserted.

It also re-asserts the invariants that must hold while the protocol is
un-executed, and the arithmetic of the pre-registered populations.

This script loads no model, fits nothing, materialises no split, reads no
score, and computes no metric. It exits non-zero on any divergence.

Usage::

    python -m scripts.verify_preregistration
    python -m scripts.verify_preregistration --expect-holdout-opened
"""
from __future__ import annotations

import argparse
from collections.abc import Sequence
from hashlib import sha256
import json
from pathlib import Path
from typing import Any, Final


REPO_ROOT = Path(__file__).resolve().parents[1]
MANIFEST_RELATIVE_PATH: Final[str] = (
    "artifacts/experiments/preregistration_v1/protocol_manifest.json"
)
PROTOCOL_DOCUMENT_RELATIVE_PATH: Final[str] = (
    "docs/canonical/PROTOCOL_PREREGISTRATION_V1.md"
)

#: Frozen artifacts that this protocol must never modify.
MUST_REMAIN_UNCHANGED: Final[dict[str, str]] = {
    "artifacts/experiments/p1/p1_dataset.csv": (
        "e95aed008d994510e4c649c287feb8fe8f49a785bec144d7e83aa15804b6c062"
    ),
    "artifacts/experiments/p1/p1_folds.json": (
        "57e688fd3da90911707d7a172c161686d852094121eda1ac49e0221fc0529fa1"
    ),
    "artifacts/production/ml_dataset_v1/ml_dataset.csv": (
        "e95aed008d994510e4c649c287feb8fe8f49a785bec144d7e83aa15804b6c062"
    ),
    "artifacts/production/ml_dataset_v1/window_labels.csv": (
        "b3ddad6bf2ee26590dadbf0c0ec1b23899924ea2b44d9de9736b8465cad24d74"
    ),
    "datasets/manifests/cicids2017_labels.yaml": (
        "e9d9b00fc25db444f61d47a7f6b1d6ffec055870fa40c1ce22f50b49b65af843"
    ),
}

#: Per-family ground truth, pre-registered. Used to re-derive TRAIN counts.
PRIORITY_GROUND_TRUTH: Final[dict[str, tuple[int, int]]] = {
    "brute_force/ftp_patator": (61, 1),
    "brute_force/ssh_patator": (60, 9),
    "dos/hulk": (36, 2),
    "dos/slowloris": (46, 2),
    "dos/slowhttptest": (26, 8),
    "dos/goldeneye": (16, 4),
    "ddos/loit": (42, 2),
}

TOTAL_PRIORITY_WINDOWS: Final[int] = 287
TOTAL_PRIORITY_EPISODES: Final[int] = 28
THURSDAY_BENIGN_WINDOWS: Final[int] = 32_813


class PreRegistrationVerificationError(RuntimeError):
    """A pinned digest, invariant, or arithmetic check failed."""


def sha256_file(path: Path) -> str:
    """Return the lowercase SHA-256 of a file, streamed."""
    digest = sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(8 * 1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def verify(
    repository_root: Path, *, expect_holdout_opened: bool
) -> dict[str, Any]:
    """Run every check and return a structured report."""
    checks: list[dict[str, Any]] = []
    failures: list[str] = []

    def record(name: str, passed: bool, detail: Any) -> None:
        checks.append({"check": name, "passed": bool(passed), "detail": detail})
        if not passed:
            failures.append(f"{name}: {detail!r}")

    manifest_path = repository_root / MANIFEST_RELATIVE_PATH
    record("manifest_exists", manifest_path.is_file(), str(manifest_path))
    if not manifest_path.is_file():
        raise PreRegistrationVerificationError(f"manifest missing: {manifest_path}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    document_path = repository_root / PROTOCOL_DOCUMENT_RELATIVE_PATH
    record("protocol_document_exists", document_path.is_file(), str(document_path))
    record(
        "manifest_points_at_the_protocol_document",
        manifest.get("protocol_document") == PROTOCOL_DOCUMENT_RELATIVE_PATH,
        manifest.get("protocol_document"),
    )

    # --- 1. every pinned input still hashes to its recorded digest ----------
    pinned = manifest.get("pinned_inputs", {})
    record("pinned_input_count", len(pinned) == 16, len(pinned))
    for relative_path, expected in sorted(pinned.items()):
        target = repository_root / relative_path
        if not target.is_file():
            record(f"pinned_present::{relative_path}", False, "missing")
            continue
        observed = sha256_file(target)
        record(
            f"pinned_digest::{relative_path}",
            observed == expected,
            {"expected": expected, "observed": observed},
        )

    # --- 2. frozen artifacts untouched -------------------------------------
    for relative_path, expected in MUST_REMAIN_UNCHANGED.items():
        target = repository_root / relative_path
        if not target.is_file():
            record(f"frozen_present::{relative_path}", False, "missing")
            continue
        observed = sha256_file(target)
        record(
            f"frozen_unchanged::{relative_path}",
            observed == expected,
            {"expected": expected, "observed": observed},
        )

    # --- 3. population arithmetic re-derived, not trusted ------------------
    windows_sum = sum(w for w, _ in PRIORITY_GROUND_TRUTH.values())
    episodes_sum = sum(e for _, e in PRIORITY_GROUND_TRUTH.values())
    record("priority_windows_sum", windows_sum == TOTAL_PRIORITY_WINDOWS, windows_sum)
    record(
        "priority_episodes_sum", episodes_sum == TOTAL_PRIORITY_EPISODES, episodes_sum
    )

    folds = manifest.get("folds", [])
    record("fold_count", len(folds) == 7, len(folds))
    for fold in folds:
        family = fold["family"]
        if family not in PRIORITY_GROUND_TRUTH:
            record(f"fold_family_known::{family}", False, family)
            continue
        holdout_windows, holdout_episodes = PRIORITY_GROUND_TRUTH[family]
        record(
            f"fold_holdout_windows::{family}",
            fold["holdout_windows"] == holdout_windows,
            fold["holdout_windows"],
        )
        record(
            f"fold_holdout_episodes::{family}",
            fold["holdout_episodes"] == holdout_episodes,
            fold["holdout_episodes"],
        )
        record(
            f"fold_train_windows_complement::{family}",
            fold["train_positive_windows"] == TOTAL_PRIORITY_WINDOWS - holdout_windows,
            fold["train_positive_windows"],
        )
        record(
            f"fold_train_episodes_complement::{family}",
            fold["train_positive_episodes"]
            == TOTAL_PRIORITY_EPISODES - holdout_episodes,
            fold["train_positive_episodes"],
        )

    record(
        "every_priority_family_has_exactly_one_fold",
        sorted(item["family"] for item in folds) == sorted(PRIORITY_GROUND_TRUTH),
        sorted(item["family"] for item in folds),
    )
    record(
        "only_ftp_patator_is_entity_key_disjoint",
        [
            item["family"]
            for item in folds
            if item.get("entity_key_disjoint_when_held_out")
        ]
        == ["brute_force/ftp_patator"],
        [
            item["family"]
            for item in folds
            if item.get("entity_key_disjoint_when_held_out")
        ],
    )

    # --- 4. Thursday benign population -------------------------------------
    thursday = manifest.get("thursday_benign_definition", {})
    record(
        "thursday_benign_window_count",
        thursday.get("windows") == THURSDAY_BENIGN_WINDOWS,
        thursday.get("windows"),
    )
    record(
        "thursday_benign_not_reconstructed",
        thursday.get("reconstructed") is False,
        thursday.get("reconstructed"),
    )
    record(
        "unknown_to_benign_forbidden",
        thursday.get("unknown_to_benign_conversion") == "forbidden",
        thursday.get("unknown_to_benign_conversion"),
    )
    audit_path = repository_root / thursday.get("source_of_truth", "")
    record("thursday_source_of_truth_exists", audit_path.is_file(), str(audit_path))
    if audit_path.is_file():
        audit = json.loads(audit_path.read_text(encoding="utf-8"))
        observed = audit.get("disposition_counts", {}).get("benign_reference")
        record(
            "audit_agrees_on_benign_window_count",
            observed == THURSDAY_BENIGN_WINDOWS,
            observed,
        )
        record(
            "audit_reports_zero_postgresql_writes",
            audit.get("guarantees", {}).get("postgresql_writes") == 0,
            audit.get("guarantees", {}).get("postgresql_writes"),
        )

    # --- 4b. emitted holdout negatives, if already produced ----------------
    emitted = manifest.get("emitted_holdout_negatives")
    if emitted is not None:
        csv_path = repository_root / emitted["path"]
        record("emitted_csv_exists", csv_path.is_file(), str(csv_path))
        if csv_path.is_file():
            observed_digest = sha256_file(csv_path)
            record(
                "emitted_csv_digest",
                observed_digest == emitted["file_sha256"],
                {"expected": emitted["file_sha256"], "observed": observed_digest},
            )
            lines = csv_path.read_text(encoding="utf-8").rstrip("\n").split("\n")
            record(
                "emitted_csv_header",
                lines[0] == ",".join(emitted["columns"]),
                lines[0],
            )
            record(
                "emitted_csv_row_count",
                len(lines) - 1 == THURSDAY_BENIGN_WINDOWS,
                len(lines) - 1,
            )
            record(
                "emitted_csv_row_count_matches_manifest",
                emitted["row_count"] == THURSDAY_BENIGN_WINDOWS,
                emitted["row_count"],
            )
            dispositions = {line.rsplit(",", 1)[-1] for line in lines[1:]}
            record(
                "emitted_csv_all_rows_benign_reference",
                dispositions == {"benign_reference"},
                sorted(dispositions),
            )
            keys = [line.split(",", 2)[:2] for line in lines[1:]]
            record(
                "emitted_csv_rows_are_unique",
                len({tuple(item) for item in keys}) == len(keys),
                len(keys),
            )
            record(
                "emitted_csv_is_sorted",
                keys == sorted(keys, key=lambda item: (item[0], int(item[1]))),
                "ascending (entity_key, window_start_epoch)",
            )
            record(
                "emitted_csv_no_new_labelling_decision",
                emitted.get("new_labelling_decisions") == 0
                and emitted.get("additional_filters_applied") == 0,
                emitted,
            )

    # --- 5. the not-entity-disjoint declaration is present and explicit ----
    declaration = manifest.get("not_entity_disjoint_declaration", {})
    record(
        "explicit_not_entity_disjoint_statement",
        declaration.get("statement", "").startswith(
            "The holdout is NOT entity-disjoint"
        ),
        declaration.get("statement"),
    )
    record(
        "claimed_property_is_family_plus_capture",
        declaration.get("claimed_property")
        == "unseen attack family + independent capture/day for benign FPR",
        declaration.get("claimed_property"),
    )
    record(
        "thursday_shares_three_priority_entity_keys",
        len(declaration.get("thursday_shared_priority_entity_keys", [])) == 3,
        declaration.get("thursday_shared_priority_entity_keys"),
    )

    # --- 6. no-tuning and scope invariants ---------------------------------
    hyperparameters = manifest.get("hyperparameters", {})
    record(
        "hyperparameter_selection_not_performed",
        hyperparameters.get("selection_performed") is False,
        hyperparameters.get("selection_performed"),
    )
    record(
        "hyperparameters_are_p1",
        (
            hyperparameters.get("n_estimators") == 200
            and hyperparameters.get("random_state") == 0
            and hyperparameters.get("class_weight") is None
        ),
        hyperparameters,
    )
    record("ares_out_of_scope", manifest.get("ares_in_scope") is False, manifest.get("ares_in_scope"))
    record(
        "threshold_calibrated_on_validation_only",
        "VALIDATION benign only"
        in manifest.get("threshold_rule", {}).get("calibration_population", ""),
        manifest.get("threshold_rule", {}).get("calibration_population"),
    )

    # --- 7. execution state ------------------------------------------------
    state = manifest.get("state", {})
    record("p1_artifacts_not_modified", state.get("p1_artifacts_modified") is False, state)
    record("no_postgresql_writes", state.get("postgresql_writes") == 0, state)
    if expect_holdout_opened:
        record("holdout_opened_as_expected", state.get("holdout_opened") is True, state)
    else:
        record(
            "holdout_still_closed",
            state.get("holdout_opened") is False
            and state.get("models_fitted") == 0
            and state.get("thresholds_computed") == 0
            and state.get("splits_materialised") == 0
            and state.get("metrics_computed") == 0,
            state,
        )

    manifest_bytes = manifest_path.read_bytes()
    return {
        "verification_version": "1.0.0",
        "manifest_path": MANIFEST_RELATIVE_PATH,
        "manifest_file_sha256": sha256(manifest_bytes).hexdigest(),
        "protocol_document_sha256": (
            sha256_file(document_path) if document_path.is_file() else None
        ),
        "expect_holdout_opened": expect_holdout_opened,
        "checks_run": len(checks),
        "checks_failed": len(failures),
        "failures": failures,
        "checks": checks,
    }


def build_parser() -> argparse.ArgumentParser:
    """Return the verification command-line interface."""
    parser = argparse.ArgumentParser(
        description="Verify the pre-registration freeze; exits non-zero on divergence."
    )
    parser.add_argument("--repository-root", type=Path, default=REPO_ROOT)
    parser.add_argument(
        "--expect-holdout-opened",
        action="store_true",
        help="assert the holdout has been opened, for the post-publication run",
    )
    parser.add_argument(
        "--quiet", action="store_true", help="print only the summary line"
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Verify and report; return 1 on any failure."""
    args = build_parser().parse_args(argv)
    report = verify(
        args.repository_root.resolve(strict=True),
        expect_holdout_opened=args.expect_holdout_opened,
    )
    if args.quiet:
        print(
            json.dumps(
                {
                    key: report[key]
                    for key in (
                        "checks_run",
                        "checks_failed",
                        "failures",
                        "manifest_file_sha256",
                        "protocol_document_sha256",
                    )
                },
                indent=2,
                sort_keys=True,
            )
        )
    else:
        print(json.dumps(report, indent=2, sort_keys=True))
    return 1 if report["checks_failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
