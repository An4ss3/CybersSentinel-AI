"""Final validation — Step 3: marginal effect of removing shared attack entities.

Question
--------
Inside the historical protocol A, with the held-out attack family held constant,
does the presence of the same ``entity_key`` in both train and test change the
measured performance?

Construction
------------
``A``  the historical protocol exactly as built in Steps 1 and 2.
``A'`` the same fold, with **only** the positive training rows whose
       ``entity_key`` also appears among the test positives removed.

Nothing else changes: the held-out family, the whole test population, every
negative, the five frozen features, the model, the ``(label, row_id)`` training
order and the train-negative-only threshold calibration are all identical.

Unavoidable coupling, recorded rather than corrected
---------------------------------------------------
The two shared entities carry positives of several families. Removing their
training positives therefore also removes training windows of families that are
*not* the held-out one. In folds 3 and 4 this empties one further family from the
training set entirely. ``A' - A`` is consequently the effect of *removing the
shared entities*, which is what was asked, and not a clean isolation of identity
leakage at constant training composition. The diagnostic quantifies this for
every fold so the reader can see it.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Any, Final, Sequence

from modules.detection.src.experiments.final_validation_eval import (
    TRAINING_ORDER,
    EvaluationError,
    FoldData,
    aggregate,
    canonical_digest,
    evaluate_fold,
    fold_guards,
    model_parameters,
)
from modules.detection.src.experiments.p1_dataset import FEATURE_NAMES, Row

#: Only these historical folds carry a train/test attack-entity intersection.
TARGET_FOLDS: Final[tuple[int, ...]] = (2, 3, 4)

#: Metrics compared between A and A'.
COMPARED_METRICS: Final[tuple[str, ...]] = (
    "roc_auc",
    "pr_auc",
    "threshold",
    "fpr",
    "tp",
    "fp",
    "tn",
    "fn",
    "precision",
    "recall",
    "f1",
    "episode_recall",
    "detected_episodes",
    "total_episodes",
)


class LeakageExperimentError(EvaluationError):
    """The A' construction or one of its blocking guards failed."""


@dataclass(frozen=True, slots=True)
class SharedEntityRemoval:
    """Exactly what A' removed from one fold's training set."""

    fold: int
    held_out: str
    shared_entities: tuple[str, ...]
    removed_row_ids: tuple[str, ...]
    removed_by_attack_type: dict[str, int]
    removed_by_entity: dict[str, int]


def shared_attack_entities(data: FoldData) -> tuple[str, ...]:
    """Entities present among both the training and the test positives."""
    train_entities = {row.entity_key for row in data.train if row.label == 1}
    test_entities = {row.entity_key for row in data.test if row.label == 1}
    return tuple(sorted(train_entities & test_entities))


def build_a_prime(data: FoldData) -> tuple[FoldData, SharedEntityRemoval]:
    """Remove only the positive training rows of the shared entities."""
    shared = shared_attack_entities(data)
    if not shared:
        raise LeakageExperimentError(
            f"fold{data.fold}: no shared attack entity, A' is undefined here"
        )
    removed = tuple(
        row for row in data.train if row.label == 1 and row.entity_key in shared
    )
    if not removed:
        raise LeakageExperimentError(f"fold{data.fold}: shared entities removed nothing")
    kept = tuple(row for row in data.train if row not in set(removed))
    # Order is preserved: `data.train` is already in (label, row_id) order and a
    # filter never reorders, so no re-sort is applied or needed.
    prime = FoldData(
        protocol=f"{data.protocol}_prime",
        fold=data.fold,
        held_out=data.held_out,
        train=kept,
        test=data.test,
    )
    removal = SharedEntityRemoval(
        fold=data.fold,
        held_out=data.held_out,
        shared_entities=shared,
        removed_row_ids=tuple(row.row_id for row in removed),
        removed_by_attack_type=dict(
            sorted(Counter(str(row.attack_type) for row in removed).items())
        ),
        removed_by_entity=dict(
            sorted(Counter(row.entity_key for row in removed).items())
        ),
    )
    return prime, removal


def removal_diagnostic(
    data: FoldData, prime: FoldData, removal: SharedEntityRemoval
) -> dict[str, Any]:
    """Every pre-training fact required before A' may be fitted."""
    a_pos = [r for r in data.train if r.label == 1]
    p_pos = [r for r in prime.train if r.label == 1]
    a_neg = [r for r in data.train if r.label == 0]
    p_neg = [r for r in prime.train if r.label == 0]
    prime_train_pos_entities = {r.entity_key for r in p_pos}
    test_pos_entities = {r.entity_key for r in data.test if r.label == 1}

    document = {
        "fold": data.fold,
        "held_out_attack_type": data.held_out,
        "shared_entities": list(removal.shared_entities),
        "positive_rows_removed_from_train": len(removal.removed_row_ids),
        "removed_by_attack_type": removal.removed_by_attack_type,
        "removed_by_entity": removal.removed_by_entity,
        "train_positives_before": len(a_pos),
        "train_positives_after": len(p_pos),
        "train_negatives_before": len(a_neg),
        "train_negatives_after": len(p_neg),
        "train_rows_before": len(data.train),
        "train_rows_after": len(prime.train),
        "test_rows_before": len(data.test),
        "test_rows_after": len(prime.test),
        "train_attack_type_windows_before": dict(
            sorted(Counter(str(r.attack_type) for r in a_pos).items())
        ),
        "train_attack_type_windows_after": dict(
            sorted(Counter(str(r.attack_type) for r in p_pos).items())
        ),
        "test_is_byte_identical": [r.row_id for r in data.test]
        == [r.row_id for r in prime.test],
        "test_row_id_digest": canonical_digest([r.row_id for r in data.test]),
        "held_out_family_absent_from_train_A": not any(
            r.attack_type == data.held_out for r in data.train
        ),
        "held_out_family_absent_from_train_A_prime": not any(
            r.attack_type == data.held_out for r in prime.train
        ),
        "shared_entities_absent_from_A_prime_train_positives": not (
            prime_train_pos_entities & set(removal.shared_entities)
        ),
        "shared_entities_still_present_in_test": bool(
            set(removal.shared_entities) & test_pos_entities
        ),
        "negatives_unchanged": [r.row_id for r in a_neg] == [r.row_id for r in p_neg],
        "negative_removal_rule": (
            "none; A' removes positive rows only, so the historical negative "
            "membership of protocol A is preserved exactly"
        ),
        "families_fully_emptied_from_train_by_the_removal": sorted(
            family
            for family, count in Counter(str(r.attack_type) for r in a_pos).items()
            if Counter(str(r.attack_type) for r in p_pos).get(family, 0) == 0
        ),
    }
    for key in (
        "test_is_byte_identical",
        "held_out_family_absent_from_train_A",
        "held_out_family_absent_from_train_A_prime",
        "shared_entities_absent_from_A_prime_train_positives",
        "shared_entities_still_present_in_test",
        "negatives_unchanged",
    ):
        if document[key] is not True:
            raise LeakageExperimentError(f"fold{data.fold}: guard {key} failed")
    if document["train_positives_after"] == 0:
        raise LeakageExperimentError(f"fold{data.fold}: A' has no training positive")
    return document


def evaluate_pair(
    data: FoldData, prime: FoldData
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Evaluate A and A' with identical guards, model, order and calibration."""
    a_guards = fold_guards(
        data, require_entity_disjoint=False, require_episode_disjoint=True
    )
    p_guards = fold_guards(
        prime, require_entity_disjoint=True, require_episode_disjoint=True
    )
    return evaluate_fold(data, a_guards), evaluate_fold(prime, p_guards)


def delta(a: dict[str, Any], prime: dict[str, Any]) -> dict[str, Any]:
    """Signed ``A' - A`` on every compared metric."""
    return {
        "A": {key: a[key] for key in COMPARED_METRICS},
        "A_prime": {key: prime[key] for key in COMPARED_METRICS},
        "delta": {
            key: (prime[key] - a[key])
            for key in COMPARED_METRICS
            if isinstance(a[key], (int, float))
        },
    }


def experiment_configuration() -> dict[str, Any]:
    """The frozen definition of what this experiment does and refuses to do."""
    return {
        "experiment": "final validation — step 3, A vs A' shared-entity removal",
        "question": (
            "inside protocol A, with the held-out family held constant, does the "
            "presence of the same entity_key in train and test change performance?"
        ),
        "folds": list(TARGET_FOLDS),
        "fold_selection_reason": (
            "only historical folds 2, 3 and 4 have a train/test attack-entity "
            "intersection; folds 0 and 1 already have none"
        ),
        "a_prime_definition": [
            "build protocol A exactly as in steps 1 and 2",
            "find entity_key values present in both train positives and test positives",
            "remove from the train only the positive rows of those entity_key values",
            "do not remove them from the test",
            "do not change the test population",
            "do not remove any negative; the historical negative membership stands",
            "keep the held-out attack family unchanged",
            "keep every other family in the train",
            "keep the (label, row_id) training order",
            "refit the identical RandomForest",
            "calibrate the threshold on the A' train negatives only",
            "evaluate on exactly the same test as A",
        ],
        "model": model_parameters(),
        "feature_names": list(FEATURE_NAMES),
        "feature_count": len(FEATURE_NAMES),
        "training_order": TRAINING_ORDER,
        "threshold_calibration": "train negatives only, identical to step 2",
        "randomness_added": False,
        "hyperparameter_tuning": "none",
        "postgresql_connections": 0,
        "known_coupling": (
            "the shared entities carry positives of several families, so removing "
            "their training rows also removes training windows of families other "
            "than the held-out one; in folds 3 and 4 one further family is emptied "
            "from the training set entirely. A' - A therefore measures the effect of "
            "removing the shared entities, not identity leakage isolated at constant "
            "training composition."
        ),
        "forbidden_claims": [
            "that leakage explains, or fails to explain, the whole A versus B difference",
            "any statement beyond the marginal effect measured on folds 2, 3 and 4",
        ],
    }


def summarise_pair(
    records_a: Sequence[dict[str, Any]], records_prime: Sequence[dict[str, Any]]
) -> dict[str, Any]:
    """Pool the three folds without hiding any single-fold result."""
    return {
        "A": aggregate(list(records_a)),
        "A_prime": aggregate(list(records_prime)),
        "folds": list(TARGET_FOLDS),
    }
