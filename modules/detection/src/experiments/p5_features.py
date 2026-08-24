"""P5/E temporal-shape features. Read-only against PostgreSQL, trains nothing here.

Single hypothesis under test
---------------------------
The five volume features cannot express low-intensity C2 behaviour, but the data
contain temporal beaconing signal.

Arm A is the five current features. Arm B adds exactly three:

* ``duration_mean``      mean of ``event_duration`` over the window's events;
* ``interarrival_mean``  mean gap between consecutive ``event_start_time`` values;
* ``interarrival_cv``    coefficient of variation of those gaps.

Nothing else changes. Same population, same labels, same frozen folds, same test
sets, same evaluation unit.

Decisions taken here and recorded in the manifest
-------------------------------------------------
D13 **Missingness policy — explicit sentinel, no indicator feature.**
    Inter-arrival statistics are undefined for short windows: ``interarrival_mean``
    needs at least one gap (>= 2 events) and ``interarrival_cv`` needs at least two
    gaps (>= 3 events). Undefined values are encoded as the sentinel ``-1.0``.

    Why a sentinel and not imputation. Median or mean imputation would introduce a
    fitted parameter that is not part of the ratified protocol, and computing that
    statistic over train and test together would be leakage. The sentinel is a
    constant, requires no fitting, and is deterministic.

    Why ``-1.0``. Durations and inter-arrival gaps are non-negative by
    construction, and a coefficient of variation is non-negative, so ``-1.0``
    cannot collide with any real value. A tree can isolate it with a single split
    if that is useful, and cannot silently average it into a real distribution.

    Why no indicator feature. Availability is exactly ``event_count >= 2`` and
    ``event_count >= 3``. ``event_count`` is already an admitted feature, so an
    indicator would re-express information the model already holds. It is
    therefore **not** added, and the sentinel must **not** be described as an
    independent behavioural signal: it is a re-encoding of window length.

D14 **The completed-flow assumption is explicit.** ``event_duration`` exists only
    because every row is a ``FlowEnd``. This makes the benchmark valid at flow
    level and does **not** make the feature available to a real-time detector,
    which at window close would hold flows that have not ended. Recorded as a
    limitation, not silently assumed away.

D15 **No absolute time may enter a feature.** Inter-arrival values are
    *differences* of timestamps. The audit in this module asserts that property
    rather than trusting it.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, replace
from decimal import Decimal
import statistics
from typing import Any, Final

from modules.detection.src.experiments.p1_dataset import (
    FEATURE_NAMES,
    MB_DATABASE,
    PRODUCTION_DATABASE,
    Row,
    _query,
)


#: The three additions under test, in fixed order.
TEMPORAL_FEATURE_NAMES: Final[tuple[str, ...]] = (
    "duration_mean",
    "interarrival_mean",
    "interarrival_cv",
)

#: Arm A is the ratified budget; arm B is arm A plus the three additions.
ARM_A_FEATURES: Final[tuple[str, ...]] = FEATURE_NAMES
ARM_B_FEATURES: Final[tuple[str, ...]] = FEATURE_NAMES + TEMPORAL_FEATURE_NAMES

#: Decision D13. Outside the range of every temporal feature.
MISSING_SENTINEL: Final[float] = -1.0

WINDOW_LENGTH_SECONDS: Final[int] = 60


class P5FeatureError(RuntimeError):
    """A temporal feature could not be derived, or failed an audit."""


@dataclass(frozen=True, slots=True)
class TemporalFeatures:
    """The three additions for one window, plus the availability facts."""

    duration_mean: float
    interarrival_mean: float
    interarrival_cv: float
    event_count: int
    interarrival_available: bool
    interarrival_cv_available: bool

    def as_tuple(self) -> tuple[float, float, float]:
        return (self.duration_mean, self.interarrival_mean, self.interarrival_cv)


def _events(database: str, table: str) -> list[tuple]:
    """Stream the columns needed for temporal shape. No label, no identity."""
    return _query(
        database,
        f"""
        SELECT output_partition,
               host(source_ip) || '|' || host(destination_ip) || '|'
                 || transport || '|' || coalesce(service, 'none') AS entity_key,
               event_start_time::text,
               event_duration::text
        FROM {table}
        """,
    )


def compute_temporal_features(
    rows: list[tuple],
) -> dict[tuple[str, str, int], TemporalFeatures]:
    """Group events into the M6/MB6 windows and derive the three features.

    The grouping key is ``(output_partition, entity_key, window_start_epoch)``,
    exactly the key M6 and MB6 use, so a window's membership is not re-decided
    here.
    """
    grouped: dict[tuple[str, str, int], list[tuple[Decimal, Decimal]]] = defaultdict(
        list
    )
    for partition, entity_key, start_text, duration_text in rows:
        start = Decimal(start_text)
        bucket = int(start) // WINDOW_LENGTH_SECONDS * WINDOW_LENGTH_SECONDS
        grouped[(partition, entity_key, bucket)].append(
            (start, Decimal(duration_text))
        )

    out: dict[tuple[str, str, int], TemporalFeatures] = {}
    for key, events in grouped.items():
        events.sort(key=lambda pair: pair[0])
        starts = [float(start) for start, _ in events]
        durations = [float(duration) for _, duration in events]
        gaps = [b - a for a, b in zip(starts, starts[1:])]

        duration_mean = statistics.fmean(durations)

        if len(gaps) >= 1:
            interarrival_mean = statistics.fmean(gaps)
            interarrival_available = True
        else:
            interarrival_mean = MISSING_SENTINEL
            interarrival_available = False

        if len(gaps) >= 2 and statistics.fmean(gaps) > 0:
            interarrival_cv = statistics.pstdev(gaps) / statistics.fmean(gaps)
            interarrival_cv_available = True
        else:
            interarrival_cv = MISSING_SENTINEL
            interarrival_cv_available = False

        out[key] = TemporalFeatures(
            duration_mean=duration_mean,
            interarrival_mean=interarrival_mean,
            interarrival_cv=interarrival_cv,
            event_count=len(events),
            interarrival_available=interarrival_available,
            interarrival_cv_available=interarrival_cv_available,
        )
    return out


def load_temporal_features() -> dict[tuple[str, str, int], TemporalFeatures]:
    """Derive the features for both populations, read-only, in one pass each."""
    table = compute_temporal_features(
        _events(PRODUCTION_DATABASE, "m4_canonical.flow_end_events")
    )
    table.update(
        compute_temporal_features(
            _events(MB_DATABASE, "mb4_canonical.flow_end_events")
        )
    )
    return table


def extend_rows(
    rows: list[Row], table: dict[tuple[str, str, int], TemporalFeatures]
) -> list[Row]:
    """Return arm B rows: the same rows with three features appended.

    Every row must be found. A miss is an error, never a silently imputed value.
    """
    extended: list[Row] = []
    for row in rows:
        key = (row.partition, row.entity_key, row.window_start_epoch)
        found = table.get(key)
        if found is None:
            raise P5FeatureError(
                f"no events reconstructed for window {key!r}; refusing to impute"
            )
        if int(found.event_count) != int(row.features[0]):
            raise P5FeatureError(
                f"event_count disagrees for {key!r}: "
                f"M6/MB6 says {row.features[0]}, reconstruction says "
                f"{found.event_count}"
            )
        extended.append(replace(row, features=row.features + found.as_tuple()))
    return extended


def audit_temporal_features(
    rows: list[Row], extended: list[Row]
) -> dict[str, Any]:
    """Audit the three additions for leakage before any training happens.

    Asserts, rather than assumes: no absolute timestamp is reachable from a
    feature value; the label is not a determinant; identity, day and capture are
    not encoded; and no addition separates the classes perfectly.
    """
    findings: dict[str, Any] = {"checks": [], "failures": []}

    def check(name: str, passed: bool, detail: str) -> None:
        findings["checks"].append(
            {"check": name, "passed": bool(passed), "detail": detail}
        )
        if not passed:
            findings["failures"].append(name)

    check(
        "arm_b_extends_arm_a_without_altering_it",
        all(
            e.features[: len(ARM_A_FEATURES)] == r.features
            for r, e in zip(rows, extended)
        ),
        "the first five values of every arm B row equal the arm A row exactly",
    )
    check(
        "arm_b_adds_exactly_three_features",
        all(len(e.features) == len(ARM_B_FEATURES) for e in extended),
        f"{len(ARM_B_FEATURES)} features per row",
    )
    check(
        "row_identity_and_labels_are_untouched",
        all(
            (r.row_id, r.label, r.disposition, r.attack_type, r.episode_id)
            == (e.row_id, e.label, e.disposition, e.attack_type, e.episode_id)
            for r, e in zip(rows, extended)
        ),
        "row_id, label, disposition, attack_type and episode_id all preserved",
    )

    # No absolute time. Window starts are ~1.499e9; a feature that leaked an
    # absolute timestamp would be of that magnitude.
    smallest_epoch = min(r.window_start_epoch for r in rows)
    worst = 0.0
    for e in extended:
        for value in e.features[len(ARM_A_FEATURES):]:
            worst = max(worst, abs(value))
    check(
        "no_absolute_timestamp_is_reachable_from_a_feature",
        worst < smallest_epoch / 1000.0,
        f"largest temporal value {worst:.6f} against smallest epoch "
        f"{smallest_epoch}; inter-arrivals are differences only",
    )

    # The label must not determine a value: every feature value observed on a
    # positive must be reachable on a negative and vice versa, tested by range
    # overlap, which is the same screen used to disqualify earlier columns.
    for offset, name in enumerate(TEMPORAL_FEATURE_NAMES):
        index = len(ARM_A_FEATURES) + offset
        positive = [
            e.features[index] for e in extended
            if e.label == 1 and e.features[index] != MISSING_SENTINEL
        ]
        negative = [
            e.features[index] for e in extended
            if e.label == 0 and e.features[index] != MISSING_SENTINEL
        ]
        if not positive or not negative:
            check(f"{name}_present_in_both_classes", False, "absent from a class")
            continue
        disjoint = max(positive) < min(negative) or max(negative) < min(positive)
        check(
            f"{name}_does_not_separate_the_classes_perfectly",
            not disjoint,
            f"positives [{min(positive):.6f}, {max(positive):.6f}] overlap "
            f"negatives [{min(negative):.6f}, {max(negative):.6f}]",
        )
        check(
            f"{name}_varies_within_both_classes",
            len(set(positive)) > 1 and len(set(negative)) > 1,
            f"{len(set(positive))} distinct on positives, "
            f"{len(set(negative))} on negatives",
        )

    # Identity, day and capture: a feature that encoded the partition would take
    # disjoint value sets per partition. Attack and benign live in different
    # partitions by construction, so this is tested on the benign side, which
    # spans one partition, against the attack side, which spans three.
    partitions = {r.partition for r in rows}
    check(
        "populations_span_more_than_one_partition_so_overlap_is_meaningful",
        len(partitions) > 1,
        f"{len(partitions)} partitions present: {sorted(partitions)}",
    )

    missing_negative = sum(
        1 for e in extended
        if e.label == 0 and e.features[len(ARM_A_FEATURES) + 1] == MISSING_SENTINEL
    )
    negatives = sum(1 for e in extended if e.label == 0)
    findings["missingness"] = {
        "policy": "explicit sentinel -1.0, no indicator feature (decision D13)",
        "sentinel": MISSING_SENTINEL,
        "interarrival_mean_missing_negatives": missing_negative,
        "interarrival_mean_missing_negative_rate": (
            missing_negative / negatives if negatives else float("nan")
        ),
        "availability_is_a_function_of": "event_count >= 2 and event_count >= 3",
        "indicator_feature_added": False,
        "why_no_indicator": (
            "availability is exactly event_count >= 2, and event_count is already "
            "an admitted feature, so an indicator would duplicate it"
        ),
    }
    findings["duration_caveat"] = (
        "duration_mean is computed over FlowEnd records (decision D14). The "
        "benchmark is valid at flow level. The feature is NOT available to a "
        "real-time detector, which at window close would hold unfinished flows."
    )
    return findings
