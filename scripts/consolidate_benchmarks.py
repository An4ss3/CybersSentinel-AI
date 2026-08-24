"""Consolidate P1/P2/P3/P4 into one artifact. Read-only, runs no model.

Verifies cross-benchmark consistency before writing anything, then emits
``final_benchmark_metrics.json``. No benchmark is re-executed, no label is
touched, no PostgreSQL statement is issued.
"""
from __future__ import annotations

import argparse
from collections.abc import Sequence
from hashlib import sha256
import json
import os
from pathlib import Path
from typing import Any, Final


REPO_ROOT = Path(__file__).resolve().parents[1]
EXP = REPO_ROOT / "artifacts" / "experiments"
OUT_DIR: Final[Path] = EXP / "final"

P1_DATASET_SHA: Final[str] = (
    "3d7436178da6960ee5effeb4bee85a0b6da5eead9d2babef3c72cb6b7ca9f20d"
)
P1_FOLDS_SHA: Final[str] = (
    "e463ea7b0eb4985f51369dc3ae19c09821040675aa4b9f9689f8e02545fed95a"
)
ATTACK_TYPES: Final[tuple[str, ...]] = (
    "botnet/ares",
    "brute_force/ftp_patator",
    "brute_force/ssh_patator",
    "ddos/loit",
    "dos/hulk",
)


class ConsistencyError(RuntimeError):
    """The four benchmarks do not agree on something they must agree on."""


def _load(name: str) -> dict:
    return json.loads((EXP / name).read_text(encoding="utf-8"))


def _file_sha(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _write_immutable(path: Path, payload: bytes) -> str:
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


def verify(p1: dict, p2: dict, p3: dict, p4: dict) -> list[dict[str, Any]]:
    """Cross-check the four benchmarks. Raises on any disagreement."""
    checks: list[dict[str, Any]] = []

    def record(name: str, ok: bool, detail: str) -> None:
        checks.append({"check": name, "passed": bool(ok), "detail": detail})
        if not ok:
            raise ConsistencyError(f"{name}: {detail}")

    record(
        "p1_dataset_digest_frozen",
        p1["dataset_content_sha256"] == P1_DATASET_SHA,
        p1["dataset_content_sha256"],
    )
    record(
        "p1_folds_digest_frozen",
        p1["folds_content_sha256"] == P1_FOLDS_SHA,
        p1["folds_content_sha256"],
    )
    for name, doc in (("p2", p2), ("p3", p3), ("p4", p4)):
        record(
            f"{name}_starts_from_the_same_population",
            doc["p1_dataset_content_sha256"] == P1_DATASET_SHA,
            doc["p1_dataset_content_sha256"],
        )
    record(
        "p2_reuses_frozen_folds",
        p2["p1_folds_content_sha256"] == P1_FOLDS_SHA,
        p2["p1_folds_content_sha256"],
    )
    record(
        "all_four_declare_zero_postgresql_writes",
        all(d["postgresql_writes"] == 0 for d in (p1, p2, p3, p4)),
        "0 writes in every benchmark",
    )
    record(
        "identical_feature_budget",
        p1["features"] == p2["features"] == p3["features"] == p4["features"],
        ", ".join(p1["features"]),
    )
    record(
        "p1_and_p2_cover_five_types",
        {f["held_out_attack_type"] for f in p1["folds"]} == set(ATTACK_TYPES)
        and {f["held_out_attack_type"] for f in p2["folds"]} == set(ATTACK_TYPES),
        "5 leave-one-attack-type-out folds each",
    )
    record(
        "p2_test_sets_identical_to_p1",
        all(c["identical_test_set"] for c in p2["comparison_p1_vs_p2"]),
        "every P2 fold reuses the P1 test set",
    )
    record(
        "p3_trained_without_positives",
        p3["training_composition"]["positives_in_training"] == 0
        and p3["training_composition"]["unknown_in_training"] == 0,
        "0 positives and 0 unknown fitted",
    )
    record(
        "p4_lost_two_attack_types",
        len(p4["exclusion"]["attack_types_p4"]) == 3
        and set(p4["exclusion"]["attack_types_p1"])
        - set(p4["exclusion"]["attack_types_p4"])
        == {"ddos/loit", "dos/hulk"},
        "ddos/loit and dos/hulk deleted by the exclusion",
    )
    record(
        "p4_ssh_test_set_is_not_comparable",
        any(
            c["held_out_attack_type"] == "brute_force/ssh_patator"
            and c["identical_test_positives"] is False
            for c in p4["comparison_p1_vs_p4"]
        ),
        "P4 ssh test set holds 52 windows / 1 episode against P1's 60 / 9",
    )
    # The four designs must agree that botnet is not detected.
    botnet = {
        "p1": next(
            f for f in p1["folds"] if f["held_out_attack_type"] == "botnet/ares"
        )["roc_auc"],
        "p2": next(
            c for c in p2["comparison_p1_vs_p2"]
            if c["held_out_attack_type"] == "botnet/ares"
        )["roc_auc_p2"],
        "p4": next(
            c for c in p4["comparison_p1_vs_p4"]
            if c["held_out_attack_type"] == "botnet/ares"
        )["roc_auc_p4"],
    }
    record(
        "botnet_roc_at_chance_in_every_supervised_design",
        all(v < 0.55 for v in botnet.values()),
        json.dumps({k: round(v, 4) for k, v in botnet.items()}),
    )
    p3_botnet = [
        t
        for op in p3["operating_points"]
        for t in op["per_attack_type"]
        if t["attack_type"] == "botnet/ares"
    ]
    record(
        "botnet_recall_exactly_zero_in_p3",
        all(t["episode_recall"] == 0.0 and t["window_recall"] == 0.0
            for t in p3_botnet),
        "0 of 177 windows and 0 of 40 episodes at both thresholds",
    )
    return checks


def main(argv: Sequence[str] | None = None) -> int:
    """Verify the four benchmarks and consolidate them."""
    parser = argparse.ArgumentParser(description="Consolidate P1..P4.")
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args(argv)

    p1 = _load("p1/p1_metrics.json")
    p2 = _load("p2/p2_metrics.json")
    p3 = _load("p3/p3_metrics.json")
    p4 = _load("p4/p4_metrics.json")
    checks = verify(p1, p2, p3, p4)

    if args.verify_only:
        print(json.dumps({"status": "consistent", "checks": checks},
                         indent=2, sort_keys=True))
        return 0

    p1_by_type = {f["held_out_attack_type"]: f for f in p1["folds"]}
    p2_by_type = {c["held_out_attack_type"]: c for c in p2["comparison_p1_vs_p2"]}
    p4_by_type = {c["held_out_attack_type"]: c for c in p4["comparison_p1_vs_p4"]}
    p3_first = p3["operating_points"][0]
    p3_by_type = {t["attack_type"]: t for t in p3_first["per_attack_type"]}

    per_type = []
    for attack_type in ATTACK_TYPES:
        f1 = p1_by_type[attack_type]
        op1 = f1["operating_points"][0]
        entry: dict[str, Any] = {
            "attack_type": attack_type,
            "test_windows": f1["test_positives"],
            "test_episodes": f1["test_episodes"],
            "p1": {
                "window_recall": op1["window_recall"],
                "episode_recall": op1["episode_recall"],
                "episode_ci": [
                    op1["episode_bootstrap"]["ci_low"],
                    op1["episode_bootstrap"]["ci_high"],
                ],
                "roc_auc": f1["roc_auc"],
                "pr_auc": f1["pr_auc"],
                "observed_test_fpr": op1["observed_test_fpr"],
            },
            "p2": {
                "window_recall": p2_by_type[attack_type]["window_recall_p2"],
                "episode_recall": p2_by_type[attack_type]["episode_recall_p2"],
                "episode_ci": p2_by_type[attack_type]["episode_ci_p2"],
                "roc_auc": p2_by_type[attack_type]["roc_auc_p2"],
                "pr_auc": p2_by_type[attack_type]["pr_auc_p2"],
                "observed_test_fpr": p2_by_type[attack_type][
                    "observed_test_fpr_p2"
                ],
                "identical_test_set": p2_by_type[attack_type]["identical_test_set"],
            },
            "p3": {
                "window_recall": p3_by_type[attack_type]["window_recall"],
                "episode_recall": p3_by_type[attack_type]["episode_recall"],
                "episode_ci": [
                    p3_by_type[attack_type]["episode_bootstrap"]["ci_low"],
                    p3_by_type[attack_type]["episode_bootstrap"]["ci_high"],
                ],
                "note": "trained on Monday benign only; no positive in training",
            },
        }
        if attack_type in p4_by_type:
            c4 = p4_by_type[attack_type]
            entry["p4"] = {
                "window_recall": c4["window_recall_p4"],
                "episode_recall": c4["episode_recall_p4"],
                "episode_ci": c4["episode_ci_p4"],
                "roc_auc": c4["roc_auc_p4"],
                "pr_auc": c4["pr_auc_p4"],
                "test_windows": c4["test_positives_p4"],
                "test_episodes": c4["test_episodes_p4"],
                "identical_test_positives": c4["identical_test_positives"],
            }
        else:
            entry["p4"] = {
                "status": "deleted by the multi-family entity exclusion",
                "reason": (
                    "this family is carried only by "
                    "172.16.0.1|192.168.10.50|tcp|none and |tcp|http"
                ),
            }
        per_type.append(entry)

    final = {
        "artifact": "CyberSentinel consolidated benchmark result",
        "consolidates": ["P1/A", "P2/B", "P3/D", "P4/C"],
        "benchmarks_re_executed": 0,
        "postgresql_writes": 0,
        "consistency_checks": checks,
        "source_artifacts": {
            name: _file_sha(EXP / name)
            for name in (
                "p1/p1_metrics.json",
                "p1/p1_dataset.csv",
                "p1/p1_folds.json",
                "p1/p1_leakage_verification.json",
                "p2/p2_metrics.json",
                "p3/p3_metrics.json",
                "p4/p4_metrics.json",
            )
        },
        "population": {
            "positives": 376,
            "negatives": 70578,
            "attack_types": 5,
            "attack_entities": 9,
            "attack_host_pairs": 6,
            "attack_episodes": 54,
            "benign_entities": 27715,
            "imbalance_negative_per_positive": 187.7074,
            "share_of_positives_below_benign_density": 0.4707,
        },
        "feature_budget": p1["features"],
        "forbidden_columns": p1["forbidden_columns"],
        "per_attack_type": per_type,
        "pooled_episode_recall": {
            "p1": p1["pooled_episode_recall_at_train_fpr_1pct"],
            "p2": p2["pooled_episode_recall_at_train_fpr_1pct"]["p2"],
            "p3": p3["pooled_episode_bootstrap_at_first_target"],
            "p4": p4["pooled_episode_recall_at_train_fpr_1pct"]["p4"],
        },
        "p3_rates": {
            "measured_false_positive_rate_on_known_benign": {
                target["target_calibration_fpr"]: target[
                    "measured_false_positive_rate"
                ]["rate"]
                for target in p3["operating_points"]
            },
            "alert_rate_on_unlabelled_unknown": {
                target["target_calibration_fpr"]: target[
                    "alert_rate_on_unlabelled"
                ]["rate"]
                for target in p3["operating_points"]
            },
            "terminology": p3["terminology"],
        },
        "central_conclusion": (
            "With the five volume features currently admitted, the system detects "
            "some attacks when similar volume signatures are present in training, "
            "but it is blind to low-intensity Ares C2 traffic, which is 47.1% of "
            "the positives. P1's strongest volumetric results therefore do not "
            "demonstrate a general ability to detect unknown attacks: P4 shows "
            "that at least part of that performance depends on other volumetric "
            "attacks being present in training."
        ),
        "confidence_tiers": {
            "robust": [
                "botnet/ares is undetectable by the five volume features: "
                "ROC-AUC 0.5037 (P1), 0.5195 (P2), 0.5035 (P4), and exactly "
                "0.0000 recall in P3 at both thresholds",
                "no convincing evidence of an hour-of-day effect on recall: "
                "P2 left episode recall unchanged on 4 of 5 types on identical "
                "test sets",
                "detection depends on volume signatures present in training: "
                "removing ddos/loit and dos/hulk from training collapses "
                "ftp_patator ROC-AUC from 0.9866 to 0.6037 on an identical test set",
            ],
            "partially_supported": [
                "ftp_patator is detected (episode recall 1.000 in P1, P2 and P3) "
                "but on a single test episode, and its discrimination collapses in P4",
                "ssh_patator is largely missed at episode level (0.111 in P1, P2 "
                "and P3); its P4 value of 1.000 is an exclusion artefact on a "
                "non-comparable test set",
                "ddos/loit is detected in P1 and P2 (1.000) and partially in P3 "
                "(0.500), on two episodes, and is untested by P4",
                "dos/hulk is detected in P1, P2 and P3 (1.000), on two episodes, "
                "and is untested by P4",
            ],
            "not_demonstrable_with_this_dataset": [
                "generalisation to entirely new attacks",
                "generalisation to entirely new hosts",
                "separation of behavioural detection from host-pair memorisation",
                "true performance on the 172,372 unknown windows",
                "definitive absence of a temporal confounder",
            ],
        },
        "risks": {
            "R11": {
                "status": "major limitation, unchanged",
                "attack_types": 5,
                "attack_entities": 9,
                "attack_host_pairs": 6,
                "target_attack_host_pairs": 1,
                "volumetric_types_sharing_one_attacker_victim_pair": 4,
                "share_of_positives_below_benign_density": 0.4707,
                "statement": (
                    "All 199 target_attack windows come from the single host pair "
                    "172.16.0.1 -> 192.168.10.50, so the four volumetric types test "
                    "four mechanics of one attacker against one victim. Only "
                    "botnet/ares interrogates other host pairs, and it is exactly "
                    "the case the current features cannot see. 47.1% of positives "
                    "sit below the benign density."
                ),
            },
            "R1": {
                "status": "NOT RESOLVED / no evidence of an effect on recall",
                "statement": (
                    "P2 is an informative ablation, not proof of absence. It shows "
                    "episode recall is unchanged on 4 of 5 types when the "
                    "hour-of-day covariate is controlled. It cannot establish "
                    "absence because it rests on 54 episodes, because composition "
                    "and size of the negative set changed together, and because "
                    "failing to find an effect is not the same as showing there is "
                    "none."
                ),
                "why_pr_auc_is_not_attributable_to_r1": (
                    "P2 trains on 26-40% of P1's negatives, confined to "
                    "attack-coincident offsets, so the model sees a narrower slice "
                    "of benign behaviour. The PR-AUC decline is a coverage and "
                    "sample-size effect on an identical test set, not a "
                    "confounding effect."
                ),
            },
        },
        "can_assert": [
            "on this evidence, the five volume features detect ddos/loit, dos/hulk "
            "and ftp_patator, partially detect ssh_patator at window level, and do "
            "not detect botnet/ares",
            "the measured false-alert rate at each stated threshold, on 17,645 "
            "held-out benign windows in P3 and on the per-fold test negatives in P1",
            "episode-level recall as k out of the episodes present in a fold",
            "that at least part of P1's volumetric performance depends on other "
            "volumetric attacks being in training",
            "that threshold calibration drifts within a single day: P3 target 1% "
            "produced 1.59% on a later block of the same Monday",
        ],
        "cannot_assert": [
            "any generalisation to unseen attacks, hosts or days",
            "any confidence interval computed at window level",
            "model comparison on differences narrower than the episode bootstrap",
            "any characterisation of alerts on unknown windows as false positives, "
            "errors, or evidence that unknown is benign",
            "that the temporal confounder is absent",
            "that the system would perform comparably online",
        ],
    }

    payload = json.dumps(final, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    sha = _write_immutable(OUT_DIR / "final_benchmark_metrics.json", payload)
    print(json.dumps({
        "status": "consolidated",
        "final_benchmark_metrics_sha256": sha,
        "checks_passed": len(checks),
        "attack_types_consolidated": len(per_type),
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
