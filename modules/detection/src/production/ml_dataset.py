"""Production Finale v1 — canonical supervised ML dataset contract.

Scope and guarantees
--------------------
This module is **additive**. It never writes to PostgreSQL, never mutates a
frozen artifact, and never changes M1-M6, MB1-MB7 or any published experiment.

Label policy, ratified by the owner on 2026-08-27:

======================  =====================
disposition             dataset label
======================  =====================
``target_attack``       ``1``
``known_other_attack``  ``1``
``benign_reference``    ``0``
``unknown``             **excluded**
``ambiguous``           **excluded**
======================  =====================

Converting ``unknown`` or ``ambiguous`` into a negative is forbidden and raises.

Window-label semantics
----------------------
Window dispositions are materialised with the **frozen P1/P3 rule-overlap
classifier** (`p1_dataset._classify`) over the frozen M5 v2 policy, because that
is the exact code path whose published counts are 376 attack windows and 172,372
``unknown`` windows. Its per-hit precedence is verified here against the frozen
``ANY_ATTACK`` table.

The two are equivalent for attack detection on the M chain but are not the same
computation: `_classify` resolves a *window* against rule intervals, whereas
``aggregate_window_disposition`` folds *event* dispositions. A consequence is
recorded rather than hidden: on the M chain this yields zero ``ambiguous``
windows, even though M5 v2 marks 164 individual events ``ambiguous``.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from typing import Any, Callable, Final, Iterable, Sequence

from modules.detection.src.experiments.p1_dataset import (
    FEATURE_NAMES,
    FORBIDDEN_COLUMNS,
    Row,
)
from modules.detection.src.lineage.exact_time_labeling_v2 import (
    ATTACK_DISPOSITIONS,
    WINDOW_DISPOSITION_PRECEDENCE,
)

#: Dispositions promoted to a supervised label, and the label they receive.
LABEL_POLICY: Final[dict[str, int]] = {
    "target_attack": 1,
    "known_other_attack": 1,
    "benign_reference": 0,
}

#: Dispositions that are excluded from supervision and never become negatives.
EXCLUDED_DISPOSITIONS: Final[frozenset[str]] = frozenset({"unknown", "ambiguous"})

#: Sentinel written in the window-label artifact for an excluded window.
EXCLUDED_SENTINEL: Final[str] = "excluded"

#: The canonical dataset header. The five features keep ``FEATURE_NAMES`` order.
DATASET_COLUMNS: Final[tuple[str, ...]] = (
    "row_id",
    "source",
    "label",
    "disposition",
    "attack_type",
    "entity_key",
    "episode_id",
    "partition",
    "window_start_epoch",
    *FEATURE_NAMES,
)

#: The materialised window-label header for the whole M chain.
WINDOW_LABEL_COLUMNS: Final[tuple[str, ...]] = (
    "window_id",
    "output_partition",
    "entity_key",
    "window_start_epoch",
    "disposition",
    "attack_type",
    "dataset_label",
)

#: M6 features deliberately absent from the canonical budget.
EXCLUDED_M6_FEATURES: Final[tuple[str, ...]] = (
    "distinct_destination_ports",
    "distinct_destination_ips",
    "distinct_source_ips",
)

#: Content features that must never enter the canonical production dataset.
FORBIDDEN_CONTENT_FEATURES: Final[tuple[str, ...]] = (
    "distinct_payload_ratio",
    "source_non_printable_ratio",
    "destination_non_printable_ratio",
    "source_payload_entropy_normalized",
    "destination_payload_entropy_normalized",
    "payload_prefix_repeat_ratio",
    "normalized_header_template_repeat_ratio",
)

#: Frozen upstream population sizes that must be observed exactly.
EXPECTED_M6_WINDOWS: Final[int] = 172_748
EXPECTED_MB6_WINDOWS: Final[int] = 70_921
EXPECTED_MB7_WINDOW_LABELS: Final[int] = 70_921

#: Frozen materialisation outcome on the M chain.
EXPECTED_TARGET_ATTACK_WINDOWS: Final[int] = 199
EXPECTED_KNOWN_OTHER_ATTACK_WINDOWS: Final[int] = 177
EXPECTED_ATTACK_WINDOWS: Final[int] = 376
EXPECTED_M_UNKNOWN_WINDOWS: Final[int] = 172_372
EXPECTED_M_AMBIGUOUS_WINDOWS: Final[int] = 0
EXPECTED_M_BENIGN_WINDOWS: Final[int] = 0

#: Frozen supervised population.
EXPECTED_BENIGN_ROWS: Final[int] = 70_578
EXPECTED_TOTAL_ROWS: Final[int] = 70_954
EXPECTED_ATTACK_ENTITIES: Final[int] = 9
EXPECTED_ATTACK_EPISODES: Final[int] = 54
EXPECTED_ATTACK_TYPE_WINDOWS: Final[dict[str, int]] = {
    "botnet/ares": 177,
    "brute_force/ftp_patator": 61,
    "brute_force/ssh_patator": 60,
    "ddos/loit": 42,
    "dos/hulk": 36,
}

#: Published P1 identities. Byte parity against them is the strongest available
#: proof that production reproduces the ratified population exactly.
EXPECTED_P1_DATASET_FILE_SHA256: Final[str] = (
    "e95aed008d994510e4c649c287feb8fe8f49a785bec144d7e83aa15804b6c062"
)
EXPECTED_P1_DATASET_CONTENT_SHA256: Final[str] = (
    "3d7436178da6960ee5effeb4bee85a0b6da5eead9d2babef3c72cb6b7ca9f20d"
)


class ProductionDatasetError(RuntimeError):
    """A production invariant, label policy or feature budget was violated."""


@dataclass(frozen=True, slots=True)
class WindowLabel:
    """One materialised M-chain window label. Additive, never persisted in SQL."""

    window_id: str
    output_partition: str
    entity_key: str
    window_start_epoch: int
    disposition: str
    attack_type: str | None

    @property
    def dataset_label(self) -> int | None:
        """The supervised label, or ``None`` when the window is excluded."""
        return label_of(self.disposition)


def label_of(disposition: str) -> int | None:
    """Map a disposition to its supervised label under the ratified policy.

    Returns ``None`` for ``unknown`` and ``ambiguous``. Raises rather than
    guessing for anything outside the frozen disposition vocabulary.
    """
    if disposition in EXCLUDED_DISPOSITIONS:
        return None
    if disposition in LABEL_POLICY:
        return LABEL_POLICY[disposition]
    raise ProductionDatasetError(f"disposition outside the frozen vocabulary: {disposition!r}")


def assert_never_benign(disposition: str, label: int | None) -> None:
    """Refuse any promotion of uncertainty to a negative."""
    if disposition in EXCLUDED_DISPOSITIONS and label is not None:
        raise ProductionDatasetError(
            f"forbidden conversion: {disposition!r} was assigned label {label!r}"
        )


def verify_policy_consistency() -> list[dict[str, Any]]:
    """Prove the policy agrees with the frozen contracts before any read."""
    checks: list[dict[str, Any]] = []

    def record(name: str, passed: bool, detail: Any) -> None:
        checks.append({"check": name, "passed": bool(passed), "detail": detail})
        if not passed:
            raise ProductionDatasetError(f"{name}: {detail}")

    record(
        "feature_budget_is_exactly_p1",
        FEATURE_NAMES
        == (
            "event_count",
            "source_packets_total",
            "destination_packets_total",
            "source_bytes_total",
            "destination_bytes_total",
        ),
        list(FEATURE_NAMES),
    )
    record(
        "degenerate_m6_features_excluded",
        all(name not in FEATURE_NAMES for name in EXCLUDED_M6_FEATURES)
        and all(name in FORBIDDEN_COLUMNS for name in EXCLUDED_M6_FEATURES),
        list(EXCLUDED_M6_FEATURES),
    )
    record(
        "content_features_absent",
        all(name not in DATASET_COLUMNS for name in FORBIDDEN_CONTENT_FEATURES),
        list(FORBIDDEN_CONTENT_FEATURES),
    )
    record(
        "attack_dispositions_receive_label_one",
        {d for d, v in LABEL_POLICY.items() if v == 1} == set(ATTACK_DISPOSITIONS),
        sorted(ATTACK_DISPOSITIONS),
    )
    record(
        "uncertainty_is_excluded_not_benign",
        EXCLUDED_DISPOSITIONS == frozenset({"unknown", "ambiguous"})
        and not (EXCLUDED_DISPOSITIONS & set(LABEL_POLICY)),
        sorted(EXCLUDED_DISPOSITIONS),
    )
    record(
        "policy_covers_the_frozen_vocabulary",
        set(LABEL_POLICY) | EXCLUDED_DISPOSITIONS
        == set(WINDOW_DISPOSITION_PRECEDENCE),
        sorted(WINDOW_DISPOSITION_PRECEDENCE),
    )
    record(
        "dataset_header_is_p1_shaped",
        DATASET_COLUMNS[-len(FEATURE_NAMES):] == FEATURE_NAMES
        and len(DATASET_COLUMNS) == 14,
        list(DATASET_COLUMNS),
    )
    return checks


def render_csv(
    header: Sequence[str],
    rows: Iterable[Any],
    project: Callable[[Any], Sequence[Any]],
) -> bytes:
    """Serialise exactly like the frozen P1 writer: ``\\n``, no quoting, UTF-8."""
    lines = [",".join(header)]
    for row in rows:
        lines.append(",".join(str(value) for value in project(row)))
    return ("\n".join(lines) + "\n").encode("utf-8")


def project_dataset_row(row: Row) -> tuple[Any, ...]:
    """Project one supervised row in canonical column order."""
    label = label_of(row.disposition)
    assert_never_benign(row.disposition, label)
    if label is None:
        raise ProductionDatasetError(
            f"excluded disposition reached the dataset: {row.disposition!r}"
        )
    if label != row.label:
        raise ProductionDatasetError(
            f"label disagrees with the policy for {row.row_id}: "
            f"{row.label!r} vs {label!r}"
        )
    if len(row.features) != len(FEATURE_NAMES):
        raise ProductionDatasetError(f"row {row.row_id} has a non-canonical feature vector")
    return (
        row.row_id,
        row.source,
        row.label,
        row.disposition,
        row.attack_type or "",
        row.entity_key,
        row.episode_id or "",
        row.partition,
        row.window_start_epoch,
        *row.features,
    )


def dataset_bytes(rows: Sequence[Row]) -> bytes:
    """Render the canonical dataset, ordered exactly as the frozen P1 artifact."""
    ordered = sorted(rows, key=lambda row: (row.label, row.row_id))
    return render_csv(DATASET_COLUMNS, ordered, project_dataset_row)


def project_window_label(label: WindowLabel) -> tuple[Any, ...]:
    """Project one materialised window label."""
    value = label.dataset_label
    assert_never_benign(label.disposition, value)
    return (
        label.window_id,
        label.output_partition,
        label.entity_key,
        label.window_start_epoch,
        label.disposition,
        label.attack_type or "",
        EXCLUDED_SENTINEL if value is None else value,
    )


def window_label_bytes(labels: Sequence[WindowLabel]) -> bytes:
    """Render window labels in the frozen M6 canonical ordering."""
    ordered = sorted(
        labels,
        key=lambda item: (
            item.output_partition,
            item.entity_key,
            item.window_start_epoch,
            item.window_id,
        ),
    )
    return render_csv(WINDOW_LABEL_COLUMNS, ordered, project_window_label)


def window_label_counts(labels: Iterable[WindowLabel]) -> dict[str, int]:
    """Count materialised dispositions."""
    counts: dict[str, int] = {name: 0 for name in WINDOW_DISPOSITION_PRECEDENCE}
    for label in labels:
        if label.disposition not in counts:
            raise ProductionDatasetError(
                f"disposition outside the frozen vocabulary: {label.disposition!r}"
            )
        counts[label.disposition] += 1
    return counts


def canonical_digest(document: Any) -> str:
    """Formatting-independent digest over a JSON-serialisable document."""
    return sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def verify_materialization(
    labels: Sequence[WindowLabel],
    m6_window_count: int,
) -> list[dict[str, Any]]:
    """Enforce every frozen M-chain materialisation invariant."""
    checks: list[dict[str, Any]] = []

    def record(name: str, passed: bool, detail: Any) -> None:
        checks.append({"check": name, "passed": bool(passed), "detail": detail})
        if not passed:
            raise ProductionDatasetError(f"{name}: {detail}")

    counts = window_label_counts(labels)
    attack = counts["target_attack"] + counts["known_other_attack"]
    record("m6_window_count", m6_window_count == EXPECTED_M6_WINDOWS, m6_window_count)
    record("window_labels_cover_every_window", len(labels) == m6_window_count, len(labels))
    record(
        "unique_window_ids",
        len({label.window_id for label in labels}) == len(labels),
        len(labels),
    )
    record(
        "target_attack_windows",
        counts["target_attack"] == EXPECTED_TARGET_ATTACK_WINDOWS,
        counts["target_attack"],
    )
    record(
        "known_other_attack_windows",
        counts["known_other_attack"] == EXPECTED_KNOWN_OTHER_ATTACK_WINDOWS,
        counts["known_other_attack"],
    )
    record("attack_windows", attack == EXPECTED_ATTACK_WINDOWS, attack)
    record(
        "unknown_windows",
        counts["unknown"] == EXPECTED_M_UNKNOWN_WINDOWS,
        counts["unknown"],
    )
    record(
        "ambiguous_windows",
        counts["ambiguous"] == EXPECTED_M_AMBIGUOUS_WINDOWS,
        counts["ambiguous"],
    )
    record(
        "no_benign_on_the_m_chain",
        counts["benign_reference"] == EXPECTED_M_BENIGN_WINDOWS,
        counts["benign_reference"],
    )
    record(
        "every_attack_window_is_typed",
        all(
            label.attack_type
            for label in labels
            if label.disposition in ATTACK_DISPOSITIONS
        ),
        attack,
    )
    record(
        "no_excluded_window_became_a_negative",
        all(
            label.dataset_label is None
            for label in labels
            if label.disposition in EXCLUDED_DISPOSITIONS
        ),
        counts["unknown"] + counts["ambiguous"],
    )
    return checks


def verify_dataset(
    rows: Sequence[Row],
    payload: bytes,
    content_digest: str,
) -> list[dict[str, Any]]:
    """Enforce every frozen supervised-population invariant."""
    checks: list[dict[str, Any]] = []

    def record(name: str, passed: bool, detail: Any) -> None:
        checks.append({"check": name, "passed": bool(passed), "detail": detail})
        if not passed:
            raise ProductionDatasetError(f"{name}: {detail}")

    positives = [row for row in rows if row.label == 1]
    negatives = [row for row in rows if row.label == 0]
    per_type: dict[str, int] = {}
    for row in positives:
        per_type[row.attack_type or ""] = per_type.get(row.attack_type or "", 0) + 1

    record("total_rows", len(rows) == EXPECTED_TOTAL_ROWS, len(rows))
    record("attack_rows", len(positives) == EXPECTED_ATTACK_WINDOWS, len(positives))
    record("benign_rows", len(negatives) == EXPECTED_BENIGN_ROWS, len(negatives))
    record(
        "attack_rows_come_from_m6",
        all(row.source == "m6" for row in positives),
        sorted({row.source for row in positives}),
    )
    record(
        "benign_rows_come_from_mb6",
        all(row.source == "mb6" for row in negatives),
        sorted({row.source for row in negatives}),
    )
    record(
        "dispositions_are_supervised_only",
        {row.disposition for row in rows} == set(LABEL_POLICY),
        sorted({row.disposition for row in rows}),
    )
    record(
        "no_excluded_disposition_present",
        not ({row.disposition for row in rows} & EXCLUDED_DISPOSITIONS),
        sorted(EXCLUDED_DISPOSITIONS),
    )
    record("per_attack_type_windows", per_type == EXPECTED_ATTACK_TYPE_WINDOWS, per_type)
    record(
        "attack_entities",
        len({row.entity_key for row in positives}) == EXPECTED_ATTACK_ENTITIES,
        len({row.entity_key for row in positives}),
    )
    record(
        "attack_episodes",
        len({row.episode_id for row in positives}) == EXPECTED_ATTACK_EPISODES,
        len({row.episode_id for row in positives}),
    )
    record(
        "attack_and_benign_entities_are_disjoint",
        not (
            {row.entity_key for row in positives}
            & {row.entity_key for row in negatives}
        ),
        0,
    )
    record(
        "unique_row_ids",
        len({row.row_id for row in rows}) == len(rows),
        len(rows),
    )
    record(
        "header_is_byte_identical_to_p1",
        payload.split(b"\n", 1)[0] == ",".join(DATASET_COLUMNS).encode("utf-8"),
        ",".join(DATASET_COLUMNS),
    )
    record("row_count_in_payload", payload.count(b"\n") == len(rows) + 1, payload.count(b"\n"))
    record(
        "p1_content_digest_parity",
        content_digest == EXPECTED_P1_DATASET_CONTENT_SHA256,
        content_digest,
    )
    record(
        "p1_file_digest_parity",
        sha256(payload).hexdigest() == EXPECTED_P1_DATASET_FILE_SHA256,
        sha256(payload).hexdigest(),
    )
    return checks
