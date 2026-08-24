"""P6 — targeted behavioural feature audit for low-intensity C2. Read-only.

Single question
---------------
Which behavioural information already present in the data actually distinguishes
low-intensity Ares C2 traffic from benign traffic, without introducing leakage or a
proxy for identity?

This module **audits**. It trains no model, selects no feature, writes no database
row, and touches no label. Discrimination is measured only as a *screening*
statistic and a strong value is treated as a reason to hunt for leakage, never as
validation.

Families
--------
A  volume            the five P1 features. Historical reference, recomputed only
                     for comparison.
B  temporal          ``duration_mean``, ``interarrival_mean``, ``interarrival_cv``.
                     Already tested in P5 and NOT a new discovery.
C  direction         ``bytes_per_packet_destination``, ``byte_direction_ratio``.
                     Is the shape of the exchange informative independently of raw
                     volume?
D  flow behaviour    aggregate statistics describing how flows behave in a window,
                     using no identity, no absolute timestamp, no label, and no
                     information unavailable under the protocol.
E  states / flags    derived from ``connection_state``. Forced to NEEDS_REVIEW: the
                     volumetric attacks concentrate on one host pair, so a flag
                     feature cannot be separated from that pair with this evidence.

Admissible source columns
-------------------------
Only these persisted columns are read, and only in the stated way:

* ``event_start_time``, ``event_end_time``, ``event_duration`` — used exclusively as
  **differences and durations**. No absolute value ever reaches a feature.
* ``source_packets``, ``destination_packets``, ``source_bytes``,
  ``destination_bytes`` — counters.
* ``connection_state`` — family E only.

Deliberately excluded, with reasons:

* ``source_ip``, ``destination_ip``, ``source_port``, ``destination_port``,
  ``transport``, ``service`` — identity or a direct proxy for it (constraint 8).
* ``conversation_id`` — a per-flow unique identifier; counting distinct values only
  restates ``event_count``.
* ``physical_line_number`` — position in the capture file, a capture artefact.
* ``record_available_time``, ``ingested_at``, ``persisted_at`` — pipeline clocks,
  absolute and not properties of the traffic.
* ``sensor_run_id``, ``capture_id``, ``dataset_snapshot_id``, ``output_partition``
  and every provenance column — already in ``FORBIDDEN_COLUMNS``.
* ``termination_reason`` — audited for content, reported, not proposed.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from decimal import Decimal
import statistics
from typing import Any, Callable, Final

from modules.detection.src.experiments.p1_dataset import (
    MB_DATABASE,
    PRODUCTION_DATABASE,
    _query,
)


WINDOW_LENGTH_SECONDS: Final[int] = 60

#: Family A, the historical reference. Recomputed only for comparison.
FAMILY_A: Final[tuple[str, ...]] = (
    "event_count",
    "source_packets_total",
    "destination_packets_total",
    "source_bytes_total",
    "destination_bytes_total",
)
#: Family B, already tested in P5. Not a new discovery.
FAMILY_B: Final[tuple[str, ...]] = (
    "duration_mean",
    "interarrival_mean",
    "interarrival_cv",
)
FAMILY_C: Final[tuple[str, ...]] = (
    "bytes_per_packet_destination",
    "byte_direction_ratio",
)
FAMILY_D: Final[tuple[str, ...]] = (
    "idle_ratio",
    "duty_cycle",
    "max_concurrency",
    "active_span_ratio",
    "bytes_per_second",
    "packets_per_second",
    "packets_per_flow",
    "response_ratio",
    "payload_repeat_ratio",
    "distinct_payload_ratio",
)
FAMILY_E: Final[tuple[str, ...]] = (
    "state_sf_ratio",
    "state_distinct_count",
)

FAMILIES: Final[dict[str, tuple[str, ...]]] = {
    "A_volume": FAMILY_A,
    "B_temporal": FAMILY_B,
    "C_direction": FAMILY_C,
    "D_flow_behaviour": FAMILY_D,
    "E_states_flags": FAMILY_E,
}

MISSING: Final[float] = float("nan")


@dataclass(frozen=True, slots=True)
class WindowEvents:
    """The events of one window, already reduced to admissible quantities."""

    starts: tuple[float, ...]
    durations: tuple[float, ...]
    source_packets: tuple[int, ...]
    destination_packets: tuple[int, ...]
    source_bytes: tuple[int, ...]
    destination_bytes: tuple[int, ...]
    states: tuple[str, ...]

    @property
    def n(self) -> int:
        return len(self.starts)


def fetch_events(database: str, table: str) -> dict[tuple[str, str, int], WindowEvents]:
    """Group persisted events into the M6/MB6 windows. Read-only.

    ``event_start_time`` is used to derive the window bucket, which M6 and MB6
    already did, and thereafter only as *relative* offsets inside the window. No
    absolute value survives into a feature.
    """
    rows = _query(
        database,
        f"""
        SELECT output_partition,
               host(source_ip) || '|' || host(destination_ip) || '|'
                 || transport || '|' || coalesce(service, 'none') AS entity_key,
               event_start_time::text, event_duration::text,
               source_packets, destination_packets,
               source_bytes, destination_bytes, connection_state
        FROM {table}
        """,
    )
    staged: dict[tuple[str, str, int], list[tuple]] = defaultdict(list)
    for row in rows:
        start = Decimal(row[2])
        bucket = int(start) // WINDOW_LENGTH_SECONDS * WINDOW_LENGTH_SECONDS
        staged[(row[0], row[1], bucket)].append(
            (
                float(start) - float(bucket),  # relative offset only
                float(Decimal(row[3])),
                int(row[4]),
                int(row[5]),
                int(row[6]),
                int(row[7]),
                row[8],
            )
        )
    out: dict[tuple[str, str, int], WindowEvents] = {}
    for key, events in staged.items():
        events.sort(key=lambda e: e[0])
        out[key] = WindowEvents(
            starts=tuple(e[0] for e in events),
            durations=tuple(e[1] for e in events),
            source_packets=tuple(e[2] for e in events),
            destination_packets=tuple(e[3] for e in events),
            source_bytes=tuple(e[4] for e in events),
            destination_bytes=tuple(e[5] for e in events),
            states=tuple(e[6] for e in events),
        )
    return out


# ---------------------------------------------------------------------------
# feature definitions. Each returns a float or NaN for "undefined".
# ---------------------------------------------------------------------------


def _union_active_seconds(w: WindowEvents) -> float:
    """Total seconds covered by the union of the flows' active intervals."""
    intervals = sorted(
        (start, start + duration) for start, duration in zip(w.starts, w.durations)
    )
    total = 0.0
    current_start, current_end = intervals[0]
    for start, end in intervals[1:]:
        if start > current_end:
            total += current_end - current_start
            current_start, current_end = start, end
        else:
            current_end = max(current_end, end)
    total += current_end - current_start
    return total


def _max_concurrency(w: WindowEvents) -> float:
    """Largest number of flows simultaneously active at any instant."""
    edges: list[tuple[float, int]] = []
    for start, duration in zip(w.starts, w.durations):
        edges.append((start, 1))
        edges.append((start + duration, -1))
    edges.sort(key=lambda e: (e[0], -e[1]))
    best = current = 0
    for _, delta in edges:
        current += delta
        best = max(best, current)
    return float(best)


def _gaps(w: WindowEvents) -> list[float]:
    return [b - a for a, b in zip(w.starts, w.starts[1:])]


FEATURE_FUNCTIONS: Final[dict[str, Callable[[WindowEvents], float]]] = {
    # ---- family A, reference only
    "event_count": lambda w: float(w.n),
    "source_packets_total": lambda w: float(sum(w.source_packets)),
    "destination_packets_total": lambda w: float(sum(w.destination_packets)),
    "source_bytes_total": lambda w: float(sum(w.source_bytes)),
    "destination_bytes_total": lambda w: float(sum(w.destination_bytes)),
    # ---- family B, already tested in P5
    "duration_mean": lambda w: statistics.fmean(w.durations),
    "interarrival_mean": lambda w: (
        statistics.fmean(_gaps(w)) if w.n >= 2 else MISSING
    ),
    "interarrival_cv": lambda w: (
        statistics.pstdev(_gaps(w)) / statistics.fmean(_gaps(w))
        if w.n >= 3 and statistics.fmean(_gaps(w)) > 0
        else MISSING
    ),
    # ---- family C, direction and exchange shape
    "bytes_per_packet_destination": lambda w: (
        sum(w.destination_bytes) / sum(w.destination_packets)
        if sum(w.destination_packets) > 0
        else MISSING
    ),
    "byte_direction_ratio": lambda w: (
        sum(w.source_bytes) / (sum(w.source_bytes) + sum(w.destination_bytes))
        if (sum(w.source_bytes) + sum(w.destination_bytes)) > 0
        else MISSING
    ),
    # ---- family D, flow behaviour
    "idle_ratio": lambda w: max(
        0.0, 1.0 - _union_active_seconds(w) / WINDOW_LENGTH_SECONDS
    ),
    "duty_cycle": lambda w: sum(w.durations) / WINDOW_LENGTH_SECONDS,
    "max_concurrency": _max_concurrency,
    "active_span_ratio": lambda w: (
        (max(s + d for s, d in zip(w.starts, w.durations)) - min(w.starts))
        / WINDOW_LENGTH_SECONDS
    ),
    "bytes_per_second": lambda w: (
        (sum(w.source_bytes) + sum(w.destination_bytes)) / sum(w.durations)
        if sum(w.durations) > 0
        else MISSING
    ),
    "packets_per_second": lambda w: (
        (sum(w.source_packets) + sum(w.destination_packets)) / sum(w.durations)
        if sum(w.durations) > 0
        else MISSING
    ),
    "packets_per_flow": lambda w: (
        sum(w.source_packets) + sum(w.destination_packets)
    ) / w.n,
    "response_ratio": lambda w: sum(
        1 for packets in w.destination_packets if packets > 0
    ) / w.n,
    "payload_repeat_ratio": lambda w: (
        1.0
        - len(set(zip(w.source_bytes, w.destination_bytes))) / w.n
        if w.n >= 2
        else MISSING
    ),
    "distinct_payload_ratio": lambda w: (
        len(set(zip(w.source_bytes, w.destination_bytes))) / w.n
    ),
    # ---- family E, states and flags. NEEDS_REVIEW by construction.
    "state_sf_ratio": lambda w: sum(1 for s in w.states if s == "SF") / w.n,
    "state_distinct_count": lambda w: float(len(set(w.states))),
}

#: How each feature would behave in a live detector at window close.
ONLINE_AVAILABILITY: Final[dict[str, str]] = {
    "event_count": "online",
    "source_packets_total": "online",
    "destination_packets_total": "online",
    "source_bytes_total": "online",
    "destination_bytes_total": "online",
    "duration_mean": "requires completed flows",
    "interarrival_mean": "online (start times only)",
    "interarrival_cv": "online (start times only)",
    "bytes_per_packet_destination": "online",
    "byte_direction_ratio": "online",
    "idle_ratio": "requires completed flows",
    "duty_cycle": "requires completed flows",
    "max_concurrency": "requires completed flows",
    "active_span_ratio": "requires completed flows",
    "bytes_per_second": "requires completed flows",
    "packets_per_second": "requires completed flows",
    "packets_per_flow": "online",
    "response_ratio": "online",
    "payload_repeat_ratio": "online",
    "distinct_payload_ratio": "online",
    "state_sf_ratio": "requires completed flows",
    "state_distinct_count": "requires completed flows",
}

DEFINITIONS: Final[dict[str, str]] = {
    "event_count": "number of flow-end events in the window",
    "source_packets_total": "sum of source_packets",
    "destination_packets_total": "sum of destination_packets",
    "source_bytes_total": "sum of source_bytes",
    "destination_bytes_total": "sum of destination_bytes",
    "duration_mean": "mean of event_duration",
    "interarrival_mean": "mean of consecutive start-time differences; undefined for n<2",
    "interarrival_cv": "pstdev(gaps)/mean(gaps); undefined for n<3 or mean(gaps)=0",
    "bytes_per_packet_destination":
        "sum(destination_bytes)/sum(destination_packets); undefined when no packet returns",
    "byte_direction_ratio":
        "sum(source_bytes)/(sum(source_bytes)+sum(destination_bytes)); undefined when both are 0",
    "idle_ratio":
        "1 - (seconds covered by the union of flow active intervals)/60, floored at 0",
    "duty_cycle": "sum(event_duration)/60; may exceed 1 when flows overlap",
    "max_concurrency":
        "largest number of flows simultaneously active at any instant in the window",
    "active_span_ratio": "(max(start+duration) - min(start))/60",
    "bytes_per_second":
        "(sum(source_bytes)+sum(destination_bytes))/sum(event_duration); undefined when total duration is 0",
    "packets_per_second":
        "(sum(source_packets)+sum(destination_packets))/sum(event_duration); undefined when total duration is 0",
    "packets_per_flow":
        "(sum(source_packets)+sum(destination_packets))/event_count",
    "response_ratio":
        "fraction of flows in the window with destination_packets > 0",
    "payload_repeat_ratio":
        "1 - |distinct (source_bytes, destination_bytes) pairs| / event_count; undefined for n<2",
    "distinct_payload_ratio":
        "|distinct (source_bytes, destination_bytes) pairs| / event_count",
    "state_sf_ratio": "fraction of flows whose connection_state is SF",
    "state_distinct_count": "number of distinct connection_state values",
}


def compute(
    windows: dict[tuple[str, str, int], WindowEvents], names: tuple[str, ...]
) -> dict[tuple[str, str, int], dict[str, float]]:
    """Evaluate the named features on every window."""
    out: dict[tuple[str, str, int], dict[str, float]] = {}
    for key, events in windows.items():
        out[key] = {name: FEATURE_FUNCTIONS[name](events) for name in names}
    return out
