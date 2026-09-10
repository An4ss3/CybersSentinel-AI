"""Final scientific validation — deterministic split construction (Step 1 only).

This module builds validation protocols over the **frozen** production dataset.
It reads metadata only: `row_id`, `label`, `attack_type`, `entity_key`,
`episode_id`, `partition`, `window_start_epoch`. Model features are never loaded
here, which makes it structurally impossible for a split to depend on a feature
value, and equally impossible for a metadata column to leak into a model through
this path.

No randomness is used anywhere. Every assignment is one of:

* the sorted position of an attack type, entity or episode identifier;
* the frozen ``p1_dataset.negative_fold_of`` hash over a benign ``entity_key``.

Protocols
---------
``A`` historical baseline
    Leave-one-attack-type-out for positives plus the frozen benign entity hash.
    Reproduces the published ``p1_folds.json`` so later metrics stay comparable.
    Documented defect: two ``entity_key`` values span several attack types, so
    folds 2, 3 and 4 are **not** entity-disjoint.

``B`` entity-disjoint
    Leave-one-attack-entity-out over the nine attack entities, with benign
    entities hashed into the same number of folds. Isolates entity memorisation.
    It is deliberately *not* attack-type-disjoint.

``C`` episode-disjoint inside one attack family
    Tests generalisation to unseen episodes of a family already seen in
    training. Only families with enough episodes are eligible.

``D`` zero-day
    Leave-Ares-out, single fold, identical to protocol ``A`` fold 0 so it can be
    compared directly with the published Phase 1 and Phase 2 Ares results.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from hashlib import sha256
import json
from typing import Any, Final, Iterable, Sequence

from modules.detection.src.experiments.p1_dataset import negative_fold_of

#: Metadata columns admitted for split construction. Features are absent.
SPLIT_METADATA_COLUMNS: Final[tuple[str, ...]] = (
    "row_id",
    "label",
    "disposition",
    "attack_type",
    "entity_key",
    "episode_id",
    "partition",
    "window_start_epoch",
)

#: Columns that must never be read by this module, because they are model input.
MODEL_FEATURE_COLUMNS: Final[tuple[str, ...]] = (
    "event_count",
    "source_packets_total",
    "destination_packets_total",
    "source_bytes_total",
    "destination_bytes_total",
)

#: Sentinel meaning "this row is in the training set of every fold".
ALWAYS_TRAIN: Final[int] = -1

#: Frozen expectations, taken from the ratified production dataset.
EXPECTED_TOTAL_ROWS: Final[int] = 70_954
EXPECTED_ATTACK_ROWS: Final[int] = 376
EXPECTED_BENIGN_ROWS: Final[int] = 70_578
EXPECTED_ATTACK_ENTITIES: Final[int] = 9
EXPECTED_ATTACK_EPISODES: Final[int] = 54
EXPECTED_BENIGN_ENTITIES: Final[int] = 27_715
EXPECTED_ARES_WINDOWS: Final[int] = 177
EXPECTED_ARES_EPISODES: Final[int] = 40

#: Historical protocol constants, reproduced rather than reinvented.
HISTORICAL_FOLD_COUNT: Final[int] = 5
ENTITY_PROTOCOL_FOLD_COUNT: Final[int] = 9
ARES_EPISODE_FOLD_COUNT: Final[int] = 5
ARES_FAMILY: Final[str] = "botnet/ares"
SSH_FAMILY: Final[str] = "brute_force/ssh_patator"

#: A family needs at least this many episodes for a protocol C main analysis.
MINIMUM_EPISODES_FOR_EPISODE_PROTOCOL: Final[int] = 9


class FinalValidationError(RuntimeError):
    """A split invariant or population expectation was violated."""


@dataclass(frozen=True, slots=True)
class PopulationRow:
    """One dataset row, metadata only. No feature is carried."""

    row_id: str
    label: int
    disposition: str
    attack_type: str | None
    entity_key: str
    episode_id: str | None
    partition: str
    window_start_epoch: int


@dataclass(frozen=True, slots=True)
class Fold:
    index: int
    name: str
    held_out: str
    test_row_ids: tuple[str, ...]
    train_row_ids: tuple[str, ...]


@dataclass(slots=True)
class Protocol:
    key: str
    title: str
    rule: str
    determinism: str
    fold_count: int
    requires_entity_disjoint: bool
    requires_episode_disjoint: bool
    assignment: dict[str, int]
    folds: list[Fold] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def load_population(rows: Iterable[dict[str, str]]) -> list[PopulationRow]:
    """Project the frozen dataset onto split metadata, dropping every feature."""
    population: list[PopulationRow] = []
    for record in rows:
        missing = [c for c in SPLIT_METADATA_COLUMNS if c not in record]
        if missing:
            raise FinalValidationError(f"dataset is missing metadata columns: {missing}")
        population.append(
            PopulationRow(
                row_id=record["row_id"],
                label=int(record["label"]),
                disposition=record["disposition"],
                attack_type=record["attack_type"] or None,
                entity_key=record["entity_key"],
                episode_id=record["episode_id"] or None,
                partition=record["partition"],
                window_start_epoch=int(record["window_start_epoch"]),
            )
        )
    return population


def verify_population(population: Sequence[PopulationRow]) -> list[dict[str, Any]]:
    """Confirm the frozen population before any split is derived from it."""
    checks: list[dict[str, Any]] = []

    def record(name: str, passed: bool, detail: Any) -> None:
        checks.append({"check": name, "passed": bool(passed), "detail": detail})
        if not passed:
            raise FinalValidationError(f"{name}: {detail}")

    positives = [r for r in population if r.label == 1]
    negatives = [r for r in population if r.label == 0]
    record("total_rows", len(population) == EXPECTED_TOTAL_ROWS, len(population))
    record("attack_rows", len(positives) == EXPECTED_ATTACK_ROWS, len(positives))
    record("benign_rows", len(negatives) == EXPECTED_BENIGN_ROWS, len(negatives))
    record(
        "unique_row_ids",
        len({r.row_id for r in population}) == len(population),
        len(population),
    )
    record(
        "attack_entities",
        len({r.entity_key for r in positives}) == EXPECTED_ATTACK_ENTITIES,
        len({r.entity_key for r in positives}),
    )
    record(
        "attack_episodes",
        len({r.episode_id for r in positives}) == EXPECTED_ATTACK_EPISODES,
        len({r.episode_id for r in positives}),
    )
    record(
        "benign_entities",
        len({r.entity_key for r in negatives}) == EXPECTED_BENIGN_ENTITIES,
        len({r.entity_key for r in negatives}),
    )
    record(
        "attack_and_benign_entities_disjoint",
        not ({r.entity_key for r in positives} & {r.entity_key for r in negatives}),
        0,
    )
    record(
        "every_positive_has_a_type_and_episode",
        all(r.attack_type and r.episode_id for r in positives),
        len(positives),
    )
    record(
        "no_negative_has_a_type_or_episode",
        all(r.attack_type is None and r.episode_id is None for r in negatives),
        len(negatives),
    )
    record(
        "dispositions_are_supervised_only",
        {r.disposition for r in population}
        == {"target_attack", "known_other_attack", "benign_reference"},
        sorted({r.disposition for r in population}),
    )
    return checks


def shared_entities_across_attack_types(
    population: Sequence[PopulationRow],
) -> dict[str, list[str]]:
    """Expose the entities that make leave-one-type-out non entity-disjoint."""
    owners: dict[str, set[str]] = defaultdict(set)
    for row in population:
        if row.label == 1 and row.attack_type:
            owners[row.entity_key].add(row.attack_type)
    return {
        entity: sorted(types) for entity, types in sorted(owners.items()) if len(types) > 1
    }


def _finalise(protocol: Protocol, population: Sequence[PopulationRow]) -> Protocol:
    """Materialise explicit train/test row lists from the fold assignment."""
    by_fold: dict[int, list[str]] = defaultdict(list)
    for row in population:
        by_fold[protocol.assignment[row.row_id]].append(row.row_id)
    everything = sorted(row.row_id for row in population)
    for fold in protocol.folds:
        test = sorted(by_fold.get(fold.index, ()))
        train = sorted(set(everything) - set(test))
        protocol.folds[fold.index] = Fold(
            index=fold.index,
            name=fold.name,
            held_out=fold.held_out,
            test_row_ids=tuple(test),
            train_row_ids=tuple(train),
        )
    return protocol


def protocol_a_historical(population: Sequence[PopulationRow]) -> Protocol:
    """Reproduce the published leave-one-attack-type-out protocol exactly."""
    types = sorted({r.attack_type for r in population if r.label == 1 and r.attack_type})
    if len(types) != HISTORICAL_FOLD_COUNT:
        raise FinalValidationError(f"expected 5 attack types, found {types}")
    type_fold = {name: index for index, name in enumerate(types)}
    assignment: dict[str, int] = {}
    for row in population:
        if row.label == 1:
            assignment[row.row_id] = type_fold[str(row.attack_type)]
        else:
            assignment[row.row_id] = negative_fold_of(
                row.entity_key, HISTORICAL_FOLD_COUNT
            )
    protocol = Protocol(
        key="A_historical",
        title="Protocol A — historical baseline (leave-one-attack-type-out)",
        rule=(
            "positives: test fold = index of their attack_type in the sorted type "
            "list; negatives: test fold = frozen negative_fold_of(entity_key, 5); "
            "train = the whole population minus the test fold"
        ),
        determinism=(
            "no randomness; sorted attack-type order and the frozen SHA-256 benign "
            "entity hash from p1_dataset.negative_fold_of"
        ),
        fold_count=HISTORICAL_FOLD_COUNT,
        requires_entity_disjoint=False,
        requires_episode_disjoint=True,
        assignment=assignment,
        folds=[
            Fold(index, f"fold{index}", name, (), ())
            for index, name in enumerate(types)
        ],
        notes=[
            "reproduces the published p1_folds.json so later metrics remain comparable",
            "NOT entity-disjoint: two entity_key values span several attack types",
        ],
    )
    return _finalise(protocol, population)


def protocol_b_entity_disjoint(population: Sequence[PopulationRow]) -> Protocol:
    """Leave-one-attack-entity-out, with benign entities hashed to the same folds."""
    entities = sorted({r.entity_key for r in population if r.label == 1})
    if len(entities) != ENTITY_PROTOCOL_FOLD_COUNT:
        raise FinalValidationError(f"expected 9 attack entities, found {len(entities)}")
    entity_fold = {name: index for index, name in enumerate(entities)}
    assignment: dict[str, int] = {}
    for row in population:
        if row.label == 1:
            assignment[row.row_id] = entity_fold[row.entity_key]
        else:
            assignment[row.row_id] = negative_fold_of(
                row.entity_key, ENTITY_PROTOCOL_FOLD_COUNT
            )
    protocol = Protocol(
        key="B_entity_disjoint",
        title="Protocol B — entity-disjoint (leave-one-attack-entity-out)",
        rule=(
            "positives: test fold = index of their entity_key in the sorted attack "
            "entity list; negatives: test fold = negative_fold_of(entity_key, 9); "
            "train = the whole population minus the test fold"
        ),
        determinism=(
            "no randomness; sorted entity order and the frozen SHA-256 benign entity "
            "hash"
        ),
        fold_count=ENTITY_PROTOCOL_FOLD_COUNT,
        requires_entity_disjoint=True,
        requires_episode_disjoint=True,
        assignment=assignment,
        folds=[
            Fold(index, f"fold{index}", name, (), ())
            for index, name in enumerate(entities)
        ],
        notes=[
            "entity-disjoint by construction, for attacks and for benign traffic",
            "deliberately NOT attack-type-disjoint: an attack family can appear in "
            "train and test through different entities",
        ],
    )
    return _finalise(protocol, population)


def protocol_c_episode_disjoint(
    population: Sequence[PopulationRow],
    family: str,
    fold_count: int | None,
) -> Protocol:
    """Episode-disjoint folds inside one attack family.

    ``fold_count=None`` selects leave-one-episode-out. Episodes are assigned by
    their sorted position, so folds are balanced in episode count without any
    random choice. Positives of other families are always training rows, which
    keeps the question focused: can unseen episodes of a *known* family be
    detected?
    """
    episodes = sorted(
        {r.episode_id for r in population if r.label == 1 and r.attack_type == family}
    )
    if not episodes:
        raise FinalValidationError(f"family {family!r} has no episode")
    if len(episodes) < 2:
        raise FinalValidationError(
            f"family {family!r} has {len(episodes)} episode; no intra-family split "
            "is informative"
        )
    folds = len(episodes) if fold_count is None else fold_count
    if folds > len(episodes):
        raise FinalValidationError(f"cannot build {folds} folds from {len(episodes)} episodes")
    episode_fold = {name: index % folds for index, name in enumerate(episodes)}
    assignment: dict[str, int] = {}
    for row in population:
        if row.label == 1:
            assignment[row.row_id] = (
                episode_fold[str(row.episode_id)]
                if row.attack_type == family
                else ALWAYS_TRAIN
            )
        else:
            assignment[row.row_id] = negative_fold_of(row.entity_key, folds)
    slug = family.replace("/", "_")
    scheme = (
        "leave-one-episode-out"
        if fold_count is None
        else f"round-robin over sorted episodes into {folds} folds"
    )
    protocol = Protocol(
        key=f"C_episode_disjoint_{slug}",
        title=f"Protocol C — episode-disjoint inside {family}",
        rule=(
            f"{family} positives: test fold = sorted episode index modulo {folds}; "
            "positives of every other family are always training rows; negatives: "
            f"test fold = negative_fold_of(entity_key, {folds})"
        ),
        determinism=f"no randomness; {scheme} over lexicographically sorted episode_id",
        fold_count=folds,
        requires_entity_disjoint=False,
        requires_episode_disjoint=True,
        assignment=assignment,
        folds=[
            Fold(index, f"fold{index}", f"{family} episode group {index}", (), ())
            for index in range(folds)
        ],
        notes=[
            f"{len(episodes)} episodes of {family} are split across {folds} folds",
            "entity-disjointness is NOT achievable here: episodes of one family share "
            "entity_key, so the same entity appears in train and test by construction; "
            "this is reported explicitly rather than silently relaxed",
        ],
    )
    return _finalise(protocol, population)


def protocol_d_zero_day_ares(population: Sequence[PopulationRow]) -> Protocol:
    """Single-fold leave-Ares-out, identical to protocol A fold 0."""
    assignment: dict[str, int] = {}
    for row in population:
        if row.label == 1:
            assignment[row.row_id] = 0 if row.attack_type == ARES_FAMILY else ALWAYS_TRAIN
        else:
            assignment[row.row_id] = (
                0
                if negative_fold_of(row.entity_key, HISTORICAL_FOLD_COUNT) == 0
                else ALWAYS_TRAIN
            )
    protocol = Protocol(
        key="D_zero_day_ares",
        title="Protocol D — zero-day, leave-Ares-out",
        rule=(
            "test = all botnet/ares windows plus the benign entities whose frozen "
            "negative_fold_of(entity_key, 5) equals 0; train = everything else, "
            "which contains no Ares window"
        ),
        determinism="no randomness; identical construction to protocol A fold 0",
        fold_count=1,
        requires_entity_disjoint=True,
        requires_episode_disjoint=True,
        assignment=assignment,
        folds=[Fold(0, "fold0", ARES_FAMILY, (), ())],
        notes=[
            "byte-comparable with the published Phase 1 and Phase 2 Ares evaluations",
            "Ares must be completely absent from training",
        ],
    )
    return _finalise(protocol, population)


def fold_statistics(
    fold: Fold, index: dict[str, PopulationRow]
) -> dict[str, Any]:
    """Compute sizes, distributions and every requested intersection."""
    train = [index[i] for i in fold.train_row_ids]
    test = [index[i] for i in fold.test_row_ids]
    train_pos = [r for r in train if r.label == 1]
    test_pos = [r for r in test if r.label == 1]
    train_neg = [r for r in train if r.label == 0]
    test_neg = [r for r in test if r.label == 0]

    train_attack_entities = {r.entity_key for r in train_pos}
    test_attack_entities = {r.entity_key for r in test_pos}
    train_episodes = {str(r.episode_id) for r in train_pos}
    test_episodes = {str(r.episode_id) for r in test_pos}
    train_benign_entities = {r.entity_key for r in train_neg}
    test_benign_entities = {r.entity_key for r in test_neg}
    train_entities = train_attack_entities | train_benign_entities
    test_entities = test_attack_entities | test_benign_entities

    return {
        "fold": fold.index,
        "held_out": fold.held_out,
        "train_rows": len(train),
        "test_rows": len(test),
        "train_positives": len(train_pos),
        "test_positives": len(test_pos),
        "train_negatives": len(train_neg),
        "test_negatives": len(test_neg),
        "train_attack_type_windows": dict(
            sorted(Counter(str(r.attack_type) for r in train_pos).items())
        ),
        "test_attack_type_windows": dict(
            sorted(Counter(str(r.attack_type) for r in test_pos).items())
        ),
        "train_attack_entities": sorted(train_attack_entities),
        "test_attack_entities": sorted(test_attack_entities),
        "train_attack_episodes": sorted(train_episodes),
        "test_attack_episodes": sorted(test_episodes),
        "train_benign_entity_count": len(train_benign_entities),
        "test_benign_entity_count": len(test_benign_entities),
        "test_benign_entities_sha256": sha256(
            "\n".join(sorted(test_benign_entities)).encode("utf-8")
        ).hexdigest(),
        "entity_intersection": sorted(train_entities & test_entities),
        "entity_intersection_count": len(train_entities & test_entities),
        "attack_entity_intersection": sorted(
            train_attack_entities & test_attack_entities
        ),
        "benign_entity_intersection_count": len(
            train_benign_entities & test_benign_entities
        ),
        "episode_intersection": sorted(train_episodes & test_episodes),
        "episode_intersection_count": len(train_episodes & test_episodes),
        "ares_windows_in_train": sum(
            1 for r in train_pos if r.attack_type == ARES_FAMILY
        ),
        "ares_windows_in_test": sum(1 for r in test_pos if r.attack_type == ARES_FAMILY),
    }


def verify_protocol(
    protocol: Protocol, index: dict[str, PopulationRow]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Verify coverage, disjointness and the protocol's own declared guarantees."""
    checks: list[dict[str, Any]] = []
    statistics = [fold_statistics(fold, index) for fold in protocol.folds]

    def record(name: str, passed: bool, detail: Any) -> None:
        checks.append({"check": name, "passed": bool(passed), "detail": detail})
        if not passed:
            raise FinalValidationError(f"{protocol.key}/{name}: {detail}")

    total = len(index)
    record("fold_count", len(protocol.folds) == protocol.fold_count, len(protocol.folds))
    for fold, stat in zip(protocol.folds, statistics):
        tag = f"fold{fold.index}"
        record(
            f"{tag}_train_and_test_partition_the_population",
            stat["train_rows"] + stat["test_rows"] == total
            and not (set(fold.train_row_ids) & set(fold.test_row_ids)),
            stat["train_rows"] + stat["test_rows"],
        )
        record(f"{tag}_has_test_positives", stat["test_positives"] > 0, stat["test_positives"])
        record(f"{tag}_has_train_positives", stat["train_positives"] > 0, stat["train_positives"])
        record(f"{tag}_has_test_negatives", stat["test_negatives"] > 0, stat["test_negatives"])
        record(
            f"{tag}_benign_entities_are_disjoint",
            stat["benign_entity_intersection_count"] == 0,
            stat["benign_entity_intersection_count"],
        )
        if protocol.requires_episode_disjoint:
            record(
                f"{tag}_episodes_are_disjoint",
                stat["episode_intersection_count"] == 0,
                stat["episode_intersection"],
            )
        if protocol.requires_entity_disjoint:
            record(
                f"{tag}_entities_are_disjoint",
                stat["entity_intersection_count"] == 0,
                stat["entity_intersection"],
            )
    if protocol.key == "D_zero_day_ares":
        record(
            "ares_absent_from_training",
            statistics[0]["ares_windows_in_train"] == 0,
            statistics[0]["ares_windows_in_train"],
        )
        record(
            "all_ares_windows_are_tested",
            statistics[0]["ares_windows_in_test"] == EXPECTED_ARES_WINDOWS,
            statistics[0]["ares_windows_in_test"],
        )
        record(
            "all_ares_episodes_are_tested",
            len(statistics[0]["test_attack_episodes"]) == EXPECTED_ARES_EPISODES,
            len(statistics[0]["test_attack_episodes"]),
        )
    return checks, statistics


def assignment_bytes(protocol: Protocol) -> bytes:
    """Serialise the fold assignment: the complete, exact split definition."""
    lines = ["row_id,test_fold"]
    for row_id in sorted(protocol.assignment):
        lines.append(f"{row_id},{protocol.assignment[row_id]}")
    return ("\n".join(lines) + "\n").encode("utf-8")


def canonical_digest(document: Any) -> str:
    return sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def protocol_document(
    protocol: Protocol,
    checks: Sequence[dict[str, Any]],
    statistics: Sequence[dict[str, Any]],
) -> dict[str, Any]:
    document = {
        "protocol": protocol.key,
        "title": protocol.title,
        "rule": protocol.rule,
        "determinism": protocol.determinism,
        "seed_used": None,
        "random_number_generator_used": False,
        "fold_count": protocol.fold_count,
        "requires_entity_disjoint": protocol.requires_entity_disjoint,
        "requires_episode_disjoint": protocol.requires_episode_disjoint,
        "notes": list(protocol.notes),
        "split_metadata_columns_used": list(SPLIT_METADATA_COLUMNS),
        "model_feature_columns_read": [],
        "folds": list(statistics),
        "checks": list(checks),
        "assignment_sha256": sha256(assignment_bytes(protocol)).hexdigest(),
    }
    document["content_sha256"] = canonical_digest(document)
    return document
