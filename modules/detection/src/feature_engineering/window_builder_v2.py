"""Deterministic M6 feature-window construction from FlowEndV2 events.

Builds exact-time tumbling windows under the frozen M6 protocol. All temporal
arithmetic uses unscaled integers from ``exact_time_v2``; no float, rounding,
truncation, ``datetime`` or ``timedelta`` is used for any bound.

Windows are strictly intra-partition, never empty, never overlapping, and carry
no label-derived information. Provenance is inherited from the source events and
never fabricated.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from typing import Iterable, Iterator, Mapping
from uuid import UUID, uuid5

from modules.detection.src.lineage.provenance import EventProvenance
from modules.detection.src.schemas.common import WindowDataQuality
from modules.detection.src.schemas.exact_time_v2 import (
    canonical_seconds_from_unscaled,
    unscaled_from_canonical,
)
from modules.detection.src.schemas.feature_window_protocol_v2 import (
    FeatureWindowSpecificationV2,
)
from modules.detection.src.schemas.feature_window_v2 import (
    AUTHORIZED_FEATURE_NAMES,
    NULL_SERVICE_SENTINEL,
    FeatureWindowV2,
)


class FeatureWindowBuildError(RuntimeError):
    """A window cannot be built from the supplied source events."""


@dataclass(frozen=True, slots=True)
class SourceEventRow:
    """One FlowEndV2 projection required to build windows.

    Every field is read from an existing canonical event; nothing is invented.
    """

    event_id: UUID
    output_partition: str
    event_start_time: str
    record_available_time: str
    source_ip: str
    source_port: int | None
    destination_ip: str
    destination_port: int | None
    transport: str
    service: str | None
    source_packets: int
    destination_packets: int
    source_bytes: int
    destination_bytes: int
    sensor_id: str
    sensor_run_id: str
    capture_id: str
    dataset_snapshot_id: str | None
    model_release_id: str | None
    normalizer_version: str
    pipeline_version: str
    sensor_version: str


def entity_key_for(row: SourceEventRow) -> tuple[str, str, str, str]:
    """Return the canonical four-component entity key.

    A null ``service`` is represented by the frozen sentinel declared in the
    manifest rather than converted implicitly.
    """
    service = NULL_SERVICE_SENTINEL if row.service is None else row.service
    return (row.source_ip, row.destination_ip, row.transport, service)


def window_start_unscaled(event_start_time: str, length_unscaled: int) -> int:
    """Floor an exact event time to its tumbling window start, exactly."""
    start = unscaled_from_canonical(event_start_time)
    return (start // length_unscaled) * length_unscaled


def window_identity(
    *,
    namespace: UUID,
    protocol_sha256: str,
    output_partition: str,
    entity_type: str,
    entity_key: tuple[str, ...],
    window_start_time: str,
    window_length_seconds: str,
) -> UUID:
    """Derive the deterministic UUID5 identity of one window.

    Components are joined by a single ASCII pipe, exactly as the frozen M6
    manifest declares. No component may contain a pipe: partitions, entity
    types, entity-key elements and canonical decimal strings are all
    ``StrictIdentifier``-compatible or fixed-scale numerals.
    """
    name = "|".join(
        (
            protocol_sha256,
            output_partition,
            entity_type,
            *entity_key,
            window_start_time,
            window_length_seconds,
        )
    )
    return uuid5(namespace, name)


def canonical_window_bytes(window: FeatureWindowV2) -> bytes:
    """Stable semantic JSON bytes for window-stream hashing."""
    return (
        json.dumps(
            window.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        + b"\n"
    )


def _aggregate_features(rows: list[SourceEventRow]) -> dict[str, float]:
    """Compute exactly the eight authorized features from source events."""
    features = {
        "event_count": float(len(rows)),
        "source_packets_total": float(sum(r.source_packets for r in rows)),
        "destination_packets_total": float(
            sum(r.destination_packets for r in rows)
        ),
        "source_bytes_total": float(sum(r.source_bytes for r in rows)),
        "destination_bytes_total": float(sum(r.destination_bytes for r in rows)),
        "distinct_destination_ports": float(
            len({r.destination_port for r in rows})
        ),
        "distinct_destination_ips": float(len({r.destination_ip for r in rows})),
        "distinct_source_ips": float(len({r.source_ip for r in rows})),
    }
    if tuple(sorted(features)) != AUTHORIZED_FEATURE_NAMES:
        raise FeatureWindowBuildError(
            "computed features diverge from the authorized eight"
        )
    return features


def _inherited(rows: list[SourceEventRow], attribute: str) -> object:
    """Return one inherited value, refusing heterogeneous windows."""
    values = {getattr(row, attribute) for row in rows}
    if len(values) != 1:
        raise FeatureWindowBuildError(
            f"window source events disagree on inherited field {attribute!r}"
        )
    return values.pop()


class FeatureWindowBuilderV2:
    """Group FlowEndV2 events into deterministic exact-time tumbling windows."""

    def __init__(self, specification: FeatureWindowSpecificationV2) -> None:
        self._specification = specification
        self._protocol_sha256 = specification.content_sha256()
        self._namespace = specification.identity.namespace
        self._entity_type = specification.entity.entity_type
        self._length_text = specification.window.length_seconds
        self._length_unscaled = unscaled_from_canonical(self._length_text)

    @property
    def protocol_sha256(self) -> str:
        return self._protocol_sha256

    @property
    def window_length_unscaled(self) -> int:
        return self._length_unscaled

    def group(
        self, rows: Iterable[SourceEventRow]
    ) -> dict[tuple[str, tuple[str, ...], int], list[SourceEventRow]]:
        """Bucket events by (partition, entity_key, window_start) exactly."""
        groups: dict[tuple[str, tuple[str, ...], int], list[SourceEventRow]] = {}
        for row in rows:
            start = window_start_unscaled(row.event_start_time, self._length_unscaled)
            key = (row.output_partition, entity_key_for(row), start)
            groups.setdefault(key, []).append(row)
        return groups

    def build_window(
        self,
        output_partition: str,
        entity_key: tuple[str, ...],
        start_unscaled: int,
        rows: list[SourceEventRow],
    ) -> FeatureWindowV2:
        """Build and validate one window; empty groups are refused."""
        if not rows:
            raise FeatureWindowBuildError("empty windows are forbidden")

        start_text = canonical_seconds_from_unscaled(start_unscaled)
        end_text = canonical_seconds_from_unscaled(
            start_unscaled + self._length_unscaled
        )

        identity = window_identity(
            namespace=self._namespace,
            protocol_sha256=self._protocol_sha256,
            output_partition=output_partition,
            entity_type=self._entity_type,
            entity_key=entity_key,
            window_start_time=start_text,
            window_length_seconds=self._length_text,
        )

        provenance = EventProvenance(
            event_id=identity,
            sensor_id=_inherited(rows, "sensor_id"),  # type: ignore[arg-type]
            sensor_run_id=_inherited(rows, "sensor_run_id"),  # type: ignore[arg-type]
            capture_id=_inherited(rows, "capture_id"),  # type: ignore[arg-type]
            dataset_snapshot_id=_inherited(rows, "dataset_snapshot_id"),  # type: ignore[arg-type]
            model_release_id=_inherited(rows, "model_release_id"),  # type: ignore[arg-type]
            normalizer_version=_inherited(rows, "normalizer_version"),  # type: ignore[arg-type]
            pipeline_version=_inherited(rows, "pipeline_version"),  # type: ignore[arg-type]
        )

        # Source event IDs sorted for a deterministic, order-independent lineage.
        source_event_ids = tuple(sorted((row.event_id for row in rows), key=str))

        return FeatureWindowV2(
            schema_version="2.0.0",
            event_version="2.0.0",
            feature_version="2.0.0",
            sensor_version=_inherited(rows, "sensor_version"),  # type: ignore[arg-type]
            provenance=provenance,
            window_id=str(identity),
            entity_type=self._entity_type,
            entity_key=entity_key,
            output_partition=output_partition,
            window_start_time=start_text,
            window_end_time=end_text,
            prediction_time=end_text,
            record_available_time=_inherited(rows, "record_available_time"),  # type: ignore[arg-type]
            source_event_ids=source_event_ids,
            features=_aggregate_features(rows),
            data_quality=WindowDataQuality(
                source_event_count=len(rows),
                late_event_count=0,
                dropped_event_count=0,
                is_final=True,
                is_revision=False,
            ),
        )

    def build_ordered(
        self, rows: Iterable[SourceEventRow]
    ) -> Iterator[FeatureWindowV2]:
        """Yield windows in the frozen canonical order.

        Order: (output_partition, entity_type, entity_key, window_start_time).
        ``entity_type`` is constant under the frozen protocol, so it contributes
        no variation but is retained for explicitness. Sorting never depends on
        dictionary or set iteration order, nor on any computed feature value.
        """
        groups = self.group(rows)
        for output_partition, entity_key, start_unscaled in sorted(groups):
            yield self.build_window(
                output_partition, entity_key, start_unscaled, groups[
                    (output_partition, entity_key, start_unscaled)
                ]
            )

    def partition_order_key(
        self, partition_order: Mapping[str, int]
    ) -> None:  # pragma: no cover - documented boundary
        """Reserved: partition sequencing is supplied by the caller.

        The frozen manifest declares ``m3_replay_report_binding_order``; the
        runner supplies partitions in that order rather than the builder
        inferring one.
        """
        raise NotImplementedError(
            "partition sequencing belongs to the M6 runner, not the builder"
        )


def window_stream_digest(windows: Iterable[FeatureWindowV2]) -> tuple[str, int]:
    """Return the canonical window-stream SHA-256 and the window count."""
    digest = sha256()
    count = 0
    for window in windows:
        digest.update(canonical_window_bytes(window))
        count += 1
    return digest.hexdigest(), count
