"""Exact-time adapter applying the frozen M5 label policy to FlowEndV2 events.

Why this module exists
---------------------
``LabelLedger.assign`` is annotated for ``NetworkEvent`` (M3 v1), whose
temporal fields are ``UtcDateTime``. It compares event times against
``datetime`` interval bounds. ``FlowEndV2`` carries exact
``ExactDecimalSeconds22`` strings, so passing one to ``LabelLedger`` would
compare ``str`` against ``datetime`` and raise ``TypeError``.

This adapter is **additive**. It never modifies ``LabelLedger``, the M5
contracts, or any M5 artefact. It reuses the frozen policy directly:

* ``LabelLedger.compiled_intervals`` supplies the half-open UTC intervals that
  M5 itself derived from the published minute-precision schedule;
* ``lineage.labeling._endpoint_direction`` supplies the role/port matching, so
  endpoint semantics are not reimplemented;
* the ledger's own provenance builders produce every ``EventLabel``, so labels
  emitted here are byte-identical to those M5 would emit and pass
  ``LabelLedger.validate_label`` unchanged.

Exactness guarantee
-------------------
M5 interval bounds are whole seconds by construction: ``LocalScheduleInterval``
rejects any ``start_time``/``end_time_inclusive`` carrying seconds or
microseconds, and ``compile_rule_intervals`` only adds one whole minute. The
conversion to unscaled ``DECIMAL(38,22)`` is therefore exact. It is performed
with integer ``timedelta`` division — never ``datetime.timestamp()``, which
would introduce a float — and guarded by an assertion that rejects any
sub-second remainder instead of truncating it.

All temporal comparisons happen on unscaled integers, identical to the
arithmetic already used by M3 v2, M4, and M6.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Final, Iterable, Literal

from modules.detection.src.lineage.labeling import (
    LabelLedger,
    _endpoint_direction,
)
from modules.detection.src.schemas.events_v2 import FlowEndV2
from modules.detection.src.schemas.exact_time_v2 import (
    UNSCALED_FACTOR,
    unscaled_from_canonical,
)
from modules.detection.src.schemas.labels import EventLabel, LabelDisposition, LabelRule


_EPOCH: Final[datetime] = datetime(1970, 1, 1, tzinfo=timezone.utc)
_ONE_SECOND: Final[timedelta] = timedelta(seconds=1)

#: Dispositions that count as an attack for the ANY_ATTACK aggregation.
ATTACK_DISPOSITIONS: Final[frozenset[str]] = frozenset(
    {"target_attack", "known_other_attack"}
)

#: Frozen ANY_ATTACK precedence, highest priority first.
#:
#: An attack anywhere in the window makes the window an attack. Absent any
#: attack, uncertainty is preserved and never silently downgraded to benign:
#: ``ambiguous`` outranks ``unknown``, which outranks ``benign_reference``.
WINDOW_DISPOSITION_PRECEDENCE: Final[tuple[str, ...]] = (
    "target_attack",
    "known_other_attack",
    "ambiguous",
    "unknown",
    "benign_reference",
)


class ExactTimeLabelError(RuntimeError):
    """The frozen M5 policy cannot be applied exactly to an exact-time event."""


def exact_unscaled_from_datetime(value: datetime) -> int:
    """Convert a whole-second aware UTC datetime to unscaled DECIMAL(38,22).

    Uses integer ``timedelta`` division only. Raises rather than truncating if
    the value carries any sub-second component.
    """
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ExactTimeLabelError("M5 interval bound must be timezone-aware UTC")
    delta = value - _EPOCH
    if delta % _ONE_SECOND != timedelta(0):
        raise ExactTimeLabelError(
            f"refusing to truncate a sub-second M5 interval bound: {value!r}"
        )
    return (delta // _ONE_SECOND) * UNSCALED_FACTOR


@dataclass(frozen=True, slots=True)
class ExactCompiledInterval:
    """One frozen M5 rule interval expressed in exact unscaled seconds."""

    rule: LabelRule
    start_unscaled: int
    end_unscaled: int


def _relation(
    event_start: int,
    event_end: int,
    rule_start: int,
    rule_end: int,
) -> Literal["contained", "partial", "disjoint"]:
    """Exact-integer twin of ``lineage.labeling._event_time_relation``.

    The branch structure is deliberately identical to the frozen M5 function;
    only the operand type changes from ``datetime`` to ``int``.
    """
    if event_start == event_end:
        return "contained" if rule_start <= event_start < rule_end else "disjoint"
    if event_start >= rule_start and event_end <= rule_end and event_start < rule_end:
        return "contained"
    if event_start < rule_end and event_end > rule_start:
        return "partial"
    return "disjoint"


class ExactTimeLabelAdapterV2:
    """Assign frozen M5 sidecar labels to exact-time ``FlowEndV2`` events."""

    def __init__(self, ledger: LabelLedger) -> None:
        self._ledger = ledger
        self._intervals: tuple[ExactCompiledInterval, ...] = tuple(
            ExactCompiledInterval(
                rule=interval.rule,
                start_unscaled=exact_unscaled_from_datetime(interval.start_utc),
                end_unscaled=exact_unscaled_from_datetime(interval.end_utc),
            )
            for interval in ledger.compiled_intervals
        )

    @property
    def ledger(self) -> LabelLedger:
        return self._ledger

    @property
    def intervals(self) -> tuple[ExactCompiledInterval, ...]:
        return self._intervals

    def assign(self, event: FlowEndV2) -> EventLabel:
        """Return one immutable M5 sidecar label for an exact-time event.

        Mirrors ``LabelLedger.assign`` decision-for-decision, substituting exact
        unscaled-integer time comparison for datetime comparison. Provenance is
        produced by the ledger itself, never rebuilt here.
        """
        event_start = unscaled_from_canonical(event.event_start_time)
        event_end = unscaled_from_canonical(event.event_end_time)

        contained: list[tuple[LabelRule, str]] = []
        partial_rule_ids: list[str] = []

        for interval in self._intervals:
            # Cheap exact time test first; the outcome set is identical to M5's
            # ordering because an interval contributes only when both the
            # endpoint role and the time relation match.
            relation = _relation(
                event_start, event_end, interval.start_unscaled, interval.end_unscaled
            )
            if relation == "disjoint":
                continue
            direction = _endpoint_direction(event, interval.rule.selector)
            if direction is None:
                continue
            if relation == "contained":
                contained.append((interval.rule, direction))
            else:
                partial_rule_ids.append(interval.rule.rule_id)

        candidate_rule_ids = [rule.rule_id for rule, _ in contained]
        candidate_rule_ids.extend(partial_rule_ids)
        unique_candidate_ids = tuple(sorted(set(candidate_rule_ids)))

        if partial_rule_ids:
            return self._ledger._ambiguous(  # noqa: SLF001 - frozen M5 builder
                event,
                unique_candidate_ids,
                "event interval crosses a matched schedule boundary",
            )
        if len(unique_candidate_ids) > 1:
            return self._ledger._ambiguous(  # noqa: SLF001
                event, unique_candidate_ids, "event matches multiple schedule rules"
            )
        if not contained:
            return self._ledger._unknown(  # noqa: SLF001
                event, "no schedule rule matched time and endpoint roles"
            )

        rule, direction = contained[0]
        return EventLabel(
            event_id=event.provenance.event_id,
            disposition=rule.disposition,
            attack_family=rule.attack_family,
            attack_subtype=rule.attack_subtype,
            target_profiles=rule.target_profiles,
            matched_rule_ids=(rule.rule_id,),
            matched_direction=direction,  # type: ignore[arg-type]
            reason=f"matched versioned schedule rule {rule.rule_id}",
            provenance=self._ledger._provenance(  # noqa: SLF001
                self._ledger.rule_hash(rule.rule_id)
            ),
        )

    def assign_many(self, events: Iterable[FlowEndV2]) -> tuple[EventLabel, ...]:
        return tuple(self.assign(event) for event in events)


def is_attack(disposition: str) -> bool:
    """Return whether a disposition counts as an attack under ANY_ATTACK."""
    return disposition in ATTACK_DISPOSITIONS


def aggregate_window_disposition(
    dispositions: Iterable[str],
) -> LabelDisposition:
    """Aggregate event dispositions into one window disposition (ANY_ATTACK).

    Decision table, applied to the *set* of dispositions present in a window:

    ==========================================  ==================
    present in window                           window disposition
    ==========================================  ==================
    any ``target_attack``                       ``target_attack``
    any ``known_other_attack`` (no target)      ``known_other_attack``
    any ``ambiguous`` (no attack)               ``ambiguous``
    any ``unknown`` (no attack, no ambiguous)   ``unknown``
    only ``benign_reference``                   ``benign_reference``
    ==========================================  ==================

    An attack anywhere makes the window an attack. Uncertainty is never
    silently converted to benign.
    """
    present = set(dispositions)
    if not present:
        raise ExactTimeLabelError("cannot aggregate an empty window")
    unexpected = present - set(WINDOW_DISPOSITION_PRECEDENCE)
    if unexpected:
        raise ExactTimeLabelError(f"unknown dispositions: {sorted(unexpected)}")
    for disposition in WINDOW_DISPOSITION_PRECEDENCE:
        if disposition in present:
            return disposition  # type: ignore[return-value]
    raise ExactTimeLabelError("unreachable disposition aggregation")
