"""Frozen two-hit temporal persistence rule for ARM F scores.

The operational decision function uses only score, entity key and timestamp.
Labels, attack families and host identities are evaluation-only metadata and are
intentionally absent from :func:`apply_temporal_rule`.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import math
from typing import Final, Iterable

CALIBRATION_FOLDS: Final[tuple[int, ...]] = (1, 2, 3, 4)
POOLED_FPR_LIMIT: Final[float] = 0.01
PER_FOLD_FPR_LIMIT: Final[float] = 0.013
MAX_FPR_SPREAD: Final[float] = 0.005
MAX_GAP_SECONDS: Final[int] = 60
TARGET_TRAIN_FPR: Final[float] = 0.01
SELECTION_RULE: Final[str] = (
    "highest observed consecutive-pair minimum score satisfying pooled FPR <= 0.01, "
    "every fold FPR <= 0.013 and max-minus-min fold FPR <= 0.005"
)


class TemporalPersistenceError(RuntimeError):
    """The frozen protocol, input population or temporal invariant was violated."""


@dataclass(frozen=True, slots=True)
class ScoreWindow:
    row_id: str
    entity_key: str
    window_start_epoch: int
    score: float


@dataclass(frozen=True, slots=True)
class AlertDecision:
    row_id: str
    baseline_alert: bool
    persistence_alert: bool
    alert: bool
    previous_row_id: str | None
    delta_seconds: int | None


@dataclass(frozen=True, slots=True)
class BenignFoldMetrics:
    fold: int
    windows: int
    false_positives: int
    fpr: float
    baseline_false_positives: int
    baseline_fpr: float
    persistence_alert_windows: int
    incremental_false_positives: int
    pseudoepisodes: int
    alerted_pseudoepisodes: int
    pseudoepisodes_with_two_hits: int


@dataclass(frozen=True, slots=True)
class CalibrationResult:
    threshold: float
    pooled_windows: int
    pooled_false_positives: int
    pooled_fpr: float
    max_fold_fpr: float
    min_fold_fpr: float
    fpr_spread: float
    stable: bool
    folds: tuple[BenignFoldMetrics, ...]


def apply_temporal_rule(
    windows: Iterable[ScoreWindow],
    official_threshold: float,
    persistence_threshold: float,
) -> dict[str, AlertDecision]:
    """Apply the fixed rule using no evaluation metadata.

    A persistence alert is emitted on the second member of an adjacent pair in
    the same entity when ``0 < delta <= 60`` and both scores reach the frozen
    persistence threshold.
    """
    if not math.isfinite(official_threshold) or not math.isfinite(
        persistence_threshold
    ):
        raise TemporalPersistenceError("thresholds must be finite")
    grouped: dict[str, list[ScoreWindow]] = defaultdict(list)
    seen_ids: set[str] = set()
    seen_slots: set[tuple[str, int]] = set()
    for window in windows:
        if window.row_id in seen_ids:
            raise TemporalPersistenceError(f"duplicate row_id: {window.row_id}")
        slot = (window.entity_key, window.window_start_epoch)
        if slot in seen_slots:
            raise TemporalPersistenceError(f"duplicate entity/time slot: {slot}")
        if not math.isfinite(window.score):
            raise TemporalPersistenceError(f"non-finite score: {window.row_id}")
        seen_ids.add(window.row_id)
        seen_slots.add(slot)
        grouped[window.entity_key].append(window)

    decisions: dict[str, AlertDecision] = {}
    for entity_windows in grouped.values():
        previous: ScoreWindow | None = None
        for current in sorted(
            entity_windows, key=lambda value: (value.window_start_epoch, value.row_id)
        ):
            delta = (
                current.window_start_epoch - previous.window_start_epoch
                if previous is not None
                else None
            )
            consecutive = delta is not None and 0 < delta <= MAX_GAP_SECONDS
            persistence = bool(
                consecutive
                and previous is not None
                and previous.score >= persistence_threshold
                and current.score >= persistence_threshold
            )
            baseline = current.score >= official_threshold
            decisions[current.row_id] = AlertDecision(
                row_id=current.row_id,
                baseline_alert=baseline,
                persistence_alert=persistence,
                alert=baseline or persistence,
                previous_row_id=previous.row_id if consecutive and previous else None,
                delta_seconds=delta if consecutive else None,
            )
            previous = current
    return decisions


def pseudoepisode_memberships(
    windows: Iterable[ScoreWindow],
) -> tuple[tuple[str, ...], ...]:
    """Create observable label-free runs of consecutive windows per entity."""
    grouped: dict[str, list[ScoreWindow]] = defaultdict(list)
    for window in windows:
        grouped[window.entity_key].append(window)
    episodes: list[tuple[str, ...]] = []
    for entity_windows in grouped.values():
        current: list[str] = []
        previous_epoch: int | None = None
        for window in sorted(
            entity_windows, key=lambda value: (value.window_start_epoch, value.row_id)
        ):
            delta = (
                window.window_start_epoch - previous_epoch
                if previous_epoch is not None
                else None
            )
            if current and not (delta is not None and 0 < delta <= MAX_GAP_SECONDS):
                episodes.append(tuple(current))
                current = []
            current.append(window.row_id)
            previous_epoch = window.window_start_epoch
        if current:
            episodes.append(tuple(current))
    return tuple(episodes)


def evaluate_benign_fold(
    fold: int,
    windows: Iterable[ScoreWindow],
    official_threshold: float,
    persistence_threshold: float,
) -> BenignFoldMetrics:
    values = tuple(windows)
    decisions = apply_temporal_rule(values, official_threshold, persistence_threshold)
    pseudoepisodes = pseudoepisode_memberships(values)
    false_positives = sum(decision.alert for decision in decisions.values())
    baseline = sum(decision.baseline_alert for decision in decisions.values())
    persistence = sum(decision.persistence_alert for decision in decisions.values())
    incremental = sum(
        decision.persistence_alert and not decision.baseline_alert
        for decision in decisions.values()
    )
    alerted_episodes = sum(
        any(decisions[row_id].alert for row_id in episode) for episode in pseudoepisodes
    )
    two_hit_episodes = sum(
        any(decisions[row_id].persistence_alert for row_id in episode)
        for episode in pseudoepisodes
    )
    count = len(values)
    if count == 0:
        raise TemporalPersistenceError(f"fold {fold} has no benign windows")
    return BenignFoldMetrics(
        fold=fold,
        windows=count,
        false_positives=false_positives,
        fpr=false_posititives_ratio(false_positives, count),
        baseline_false_positives=baseline,
        baseline_fpr=false_posititives_ratio(baseline, count),
        persistence_alert_windows=persistence,
        incremental_false_positives=incremental,
        pseudoepisodes=len(pseudoepisodes),
        alerted_pseudoepisodes=alerted_episodes,
        pseudoepisodes_with_two_hits=two_hit_episodes,
    )


def false_posititives_ratio(numerator: int, denominator: int) -> float:
    """Keep the ratio operation explicit and deterministic."""
    return numerator / denominator


def consecutive_pair_minima(windows: Iterable[ScoreWindow]) -> tuple[float, ...]:
    """Return unique observed pair-minimum scores from valid adjacent pairs."""
    values = tuple(windows)
    grouped: dict[str, list[ScoreWindow]] = defaultdict(list)
    for window in values:
        grouped[window.entity_key].append(window)
    candidates: set[float] = set()
    for entity_windows in grouped.values():
        previous: ScoreWindow | None = None
        for current in sorted(
            entity_windows, key=lambda value: (value.window_start_epoch, value.row_id)
        ):
            if previous is not None:
                delta = current.window_start_epoch - previous.window_start_epoch
                if 0 < delta <= MAX_GAP_SECONDS:
                    candidates.add(min(previous.score, current.score))
            previous = current
    if not candidates:
        raise TemporalPersistenceError("no valid consecutive benign pair")
    return tuple(sorted(candidates))


def evaluate_calibration_threshold(
    threshold: float,
    windows_by_fold: dict[int, tuple[ScoreWindow, ...]],
    official_thresholds: dict[int, float],
) -> CalibrationResult:
    fold_metrics = tuple(
        evaluate_benign_fold(
            fold, windows_by_fold[fold], official_thresholds[fold], threshold
        )
        for fold in CALIBRATION_FOLDS
    )
    windows = sum(value.windows for value in fold_metrics)
    false_positives = sum(value.false_positives for value in fold_metrics)
    pooled_fpr = false_positives / windows
    fold_fprs = [value.fpr for value in fold_metrics]
    maximum = max(fold_fprs)
    minimum = min(fold_fprs)
    spread = maximum - minimum
    stable = (
        pooled_fpr <= POOLED_FPR_LIMIT
        and maximum <= PER_FOLD_FPR_LIMIT
        and spread <= MAX_FPR_SPREAD
    )
    return CalibrationResult(
        threshold=threshold,
        pooled_windows=windows,
        pooled_false_positives=false_positives,
        pooled_fpr=pooled_fpr,
        max_fold_fpr=maximum,
        min_fold_fpr=minimum,
        fpr_spread=spread,
        stable=stable,
        folds=fold_metrics,
    )


def calibrate_highest_feasible_threshold(
    windows_by_fold: dict[int, tuple[ScoreWindow, ...]],
    official_thresholds: dict[int, float],
) -> tuple[CalibrationResult, tuple[float, ...]]:
    """Apply the frozen literal selection rule without attack observations."""
    if set(windows_by_fold) != set(CALIBRATION_FOLDS):
        raise TemporalPersistenceError("calibration windows must contain folds 1-4")
    if set(official_thresholds) != set(CALIBRATION_FOLDS):
        raise TemporalPersistenceError("official thresholds must contain folds 1-4")
    candidates = consecutive_pair_minima(
        window for fold in CALIBRATION_FOLDS for window in windows_by_fold[fold]
    )
    for candidate in reversed(candidates):
        result = evaluate_calibration_threshold(
            candidate, windows_by_fold, official_thresholds
        )
        if result.stable:
            return result, candidates
    raise TemporalPersistenceError("no observed persistence threshold meets STOP gates")


def neighbouring_thresholds(
    selected: float, candidates: tuple[float, ...]
) -> tuple[float, float]:
    """Return deterministic mathematical upper and observed lower neighbours."""
    index = candidates.index(selected)
    lower = candidates[index - 1] if index > 0 else math.nextafter(selected, -math.inf)
    upper = (
        candidates[index + 1]
        if index + 1 < len(candidates)
        else math.nextafter(selected, math.inf)
    )
    return lower, upper
