"""Versioned sidecar label loading and matching for canonical network events.

The matcher uses only event time and explicit endpoint-role metadata from the
published CICIDS2017 schedule.  It never mutates events, never inserts labels
into model features, and never treats an unmatched event as benign.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from pathlib import Path
from typing import TYPE_CHECKING, Iterable, Literal
from zoneinfo import ZoneInfo

import yaml

from modules.detection.src.schemas.labels import (
    EndpointSelector,
    EventLabel,
    LabelAssignmentProvenance,
    LabelManifest,
    LabelRule,
    MatchedDirection,
)

if TYPE_CHECKING:
    from modules.detection.src.schemas.events import NetworkEvent


@dataclass(frozen=True, slots=True)
class CompiledRuleInterval:
    """One source interval compiled to an unambiguous half-open UTC interval."""

    rule: LabelRule
    start_utc: datetime
    end_utc: datetime


@dataclass(frozen=True, slots=True)
class ManifestOverlap:
    """Two role-compatible schedule intervals that overlap in UTC."""

    first_rule_id: str
    second_rule_id: str
    start_utc: datetime
    end_utc: datetime


@dataclass(frozen=True, slots=True)
class LabelManifestOverlapError(ValueError):
    """Raised when schedule rules can assign contradictory labels."""

    overlaps: tuple[ManifestOverlap, ...]

    def __str__(self) -> str:
        pairs = ", ".join(
            f"{item.first_rule_id}/{item.second_rule_id}" for item in self.overlaps
        )
        return f"overlapping label rules: {pairs}"


@dataclass(frozen=True, slots=True)
class _MatchCandidate:
    rule: LabelRule
    direction: MatchedDirection


def _canonical_hash(value: object) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return sha256(payload).hexdigest()


def hash_manifest(manifest: LabelManifest) -> str:
    """Hash normalized manifest content independently of YAML formatting."""
    return _canonical_hash(manifest.model_dump(mode="json"))


def hash_rule(rule: LabelRule) -> str:
    """Hash one normalized rule for per-assignment provenance."""
    return _canonical_hash(rule.model_dump(mode="json"))


def load_label_manifest(path: str | Path) -> LabelManifest:
    """Load YAML through strict JSON-mode Pydantic validation.

    JSON-mode validation accepts YAML's JSON-compatible arrays and ISO strings
    while preserving strict rejection of unknown fields and invalid scalar types.
    """
    source = Path(path)
    raw = yaml.safe_load(source.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("label manifest root must be a mapping")
    return LabelManifest.model_validate_json(json.dumps(raw))


def compile_rule_intervals(manifest: LabelManifest) -> tuple[CompiledRuleInterval, ...]:
    """Convert official inclusive minute ranges to half-open UTC intervals."""
    local_zone = ZoneInfo(manifest.timezone)
    compiled: list[CompiledRuleInterval] = []
    for rule in manifest.rules:
        for interval in rule.intervals:
            start_local = datetime.combine(
                interval.date,
                interval.start_time,
                tzinfo=local_zone,
            )
            # The official source reports minute precision and inclusive end
            # minutes. Add one minute to obtain a deterministic half-open range.
            end_local = datetime.combine(
                interval.date,
                interval.end_time_inclusive,
                tzinfo=local_zone,
            ) + timedelta(minutes=1)
            compiled.append(
                CompiledRuleInterval(
                    rule=rule,
                    start_utc=start_local.astimezone(timezone.utc),
                    end_utc=end_local.astimezone(timezone.utc),
                )
            )
    return tuple(
        sorted(
            compiled,
            key=lambda item: (item.start_utc, item.end_utc, item.rule.rule_id),
        )
    )


def _set_constraints_overlap(first: tuple, second: tuple) -> bool:
    return not first or not second or bool(set(first) & set(second))


def _selectors_overlap(first: EndpointSelector, second: EndpointSelector) -> bool:
    if first.mode == "any_network" or second.mode == "any_network":
        return True
    protocols_overlap = _set_constraints_overlap(first.protocols, second.protocols)
    same_roles_overlap = (
        bool(set(first.attacker_ips) & set(second.attacker_ips))
        and bool(set(first.victim_ips) & set(second.victim_ips))
        and _set_constraints_overlap(first.victim_ports, second.victim_ports)
    )
    # A bidirectional event can satisfy role-swapped rules with each rule's
    # victim-port constraint applying to a different endpoint. Therefore port
    # sets need not intersect in the swapped orientation.
    swapped_roles_overlap = (
        bool(set(first.attacker_ips) & set(second.victim_ips))
        and bool(set(first.victim_ips) & set(second.attacker_ips))
    )
    return protocols_overlap and (same_roles_overlap or swapped_roles_overlap)


def find_manifest_overlaps(manifest: LabelManifest) -> tuple[ManifestOverlap, ...]:
    """Return all temporally and semantically overlapping rule intervals."""
    intervals = compile_rule_intervals(manifest)
    overlaps: list[ManifestOverlap] = []
    for index, first in enumerate(intervals):
        for second in intervals[index + 1 :]:
            if second.start_utc >= first.end_utc:
                break
            overlap_start = max(first.start_utc, second.start_utc)
            overlap_end = min(first.end_utc, second.end_utc)
            if overlap_start >= overlap_end:
                continue
            if _selectors_overlap(first.rule.selector, second.rule.selector):
                overlaps.append(
                    ManifestOverlap(
                        first_rule_id=first.rule.rule_id,
                        second_rule_id=second.rule.rule_id,
                        start_utc=overlap_start,
                        end_utc=overlap_end,
                    )
                )
    return tuple(overlaps)


def _event_time_relation(
    event_start: datetime,
    event_end: datetime,
    rule_start: datetime,
    rule_end: datetime,
) -> Literal["contained", "partial", "disjoint"]:
    if event_start == event_end:
        return "contained" if rule_start <= event_start < rule_end else "disjoint"
    if event_start >= rule_start and event_end <= rule_end and event_start < rule_end:
        return "contained"
    if event_start < rule_end and event_end > rule_start:
        return "partial"
    return "disjoint"


def _endpoint_direction(event: NetworkEvent, selector: EndpointSelector) -> MatchedDirection | None:
    if selector.mode == "any_network":
        return "not_applicable"

    source = getattr(event, "source", None)
    destination = getattr(event, "destination", None)
    transport = getattr(event, "transport", None)
    if source is None or destination is None or transport is None:
        return None
    if selector.protocols and transport not in selector.protocols:
        return None

    source_ip = str(source.ip)
    destination_ip = str(destination.ip)
    attacker_ips = {str(value) for value in selector.attacker_ips}
    victim_ips = {str(value) for value in selector.victim_ips}

    if source_ip in attacker_ips and destination_ip in victim_ips:
        if selector.victim_ports and destination.port not in selector.victim_ports:
            return None
        return "attacker_to_victim"
    if source_ip in victim_ips and destination_ip in attacker_ips:
        if selector.victim_ports and source.port not in selector.victim_ports:
            return None
        return "victim_to_attacker"
    return None


class LabelLedger:
    """Immutable manifest-backed service assigning sidecar event labels."""

    def __init__(self, manifest: LabelManifest) -> None:
        overlaps = find_manifest_overlaps(manifest)
        if overlaps:
            raise LabelManifestOverlapError(overlaps)
        self._manifest = manifest
        self._manifest_hash = hash_manifest(manifest)
        self._rules_by_id = {
            rule.rule_id: rule
            for rule in manifest.rules
        }
        self._rule_hashes = {
            rule.rule_id: hash_rule(rule)
            for rule in manifest.rules
        }
        self._compiled = compile_rule_intervals(manifest)
        self._default_rule_hash = _canonical_hash(
            {
                "manifest_hash": self._manifest_hash,
                "rule_version": manifest.rule_version,
                "default_disposition": manifest.default_disposition,
            }
        )

    @classmethod
    def from_yaml(cls, path: str | Path) -> "LabelLedger":
        return cls(load_label_manifest(path))

    @property
    def manifest(self) -> LabelManifest:
        return self._manifest

    @property
    def manifest_hash(self) -> str:
        return self._manifest_hash

    @property
    def compiled_intervals(self) -> tuple[CompiledRuleInterval, ...]:
        return self._compiled

    def rule_hash(self, rule_id: str) -> str:
        return self._rule_hashes[rule_id]

    def _provenance(self, rule_hash: str) -> LabelAssignmentProvenance:
        return LabelAssignmentProvenance(
            rule_version=self._manifest.rule_version,
            rule_hash=rule_hash,
            manifest_hash=self._manifest_hash,
            authoritative_source=self._manifest.authoritative_source,
            timezone=self._manifest.timezone,
        )

    def _unknown(self, event: NetworkEvent, reason: str) -> EventLabel:
        return EventLabel(
            event_id=event.provenance.event_id,
            disposition="unknown",
            attack_family=None,
            attack_subtype=None,
            target_profiles=(),
            matched_rule_ids=(),
            matched_direction="indeterminate",
            reason=reason,
            provenance=self._provenance(self._default_rule_hash),
        )

    def _ambiguity_rule_hash(self, rule_ids: tuple[str, ...]) -> str:
        unique_ids = tuple(sorted(set(rule_ids)))
        return _canonical_hash(
            {
                "manifest_hash": self._manifest_hash,
                "candidate_rule_hashes": [self._rule_hashes[value] for value in unique_ids],
                "outcome": "ambiguous",
            }
        )

    def _ambiguous(
        self,
        event: NetworkEvent,
        rule_ids: tuple[str, ...],
        reason: str,
    ) -> EventLabel:
        unique_ids = tuple(sorted(set(rule_ids)))
        return EventLabel(
            event_id=event.provenance.event_id,
            disposition="ambiguous",
            attack_family=None,
            attack_subtype=None,
            target_profiles=(),
            matched_rule_ids=unique_ids,
            matched_direction="indeterminate",
            reason=reason,
            provenance=self._provenance(self._ambiguity_rule_hash(unique_ids)),
        )

    def validate_label(self, label: EventLabel) -> None:
        """Reject a label not reproducibly issued by this manifest policy."""
        provenance = label.provenance
        checks = {
            "manifest_hash": (provenance.manifest_hash, self._manifest_hash),
            "rule_version": (provenance.rule_version, self._manifest.rule_version),
            "authoritative_source": (
                provenance.authoritative_source,
                self._manifest.authoritative_source,
            ),
            "timezone": (provenance.timezone, self._manifest.timezone),
        }
        for field_name, (actual, expected) in checks.items():
            if actual != expected:
                raise ValueError(
                    f"label provenance {field_name} mismatch: {actual!r} != {expected!r}"
                )

        unknown_rule_ids = [
            rule_id for rule_id in label.matched_rule_ids
            if rule_id not in self._rule_hashes
        ]
        if unknown_rule_ids:
            raise ValueError(f"label references unknown rule IDs: {unknown_rule_ids}")

        if label.disposition == "unknown":
            expected_rule_hash = self._default_rule_hash
        elif label.disposition == "ambiguous":
            expected_rule_hash = self._ambiguity_rule_hash(label.matched_rule_ids)
        else:
            expected_rule_hash = self._rule_hashes[label.matched_rule_ids[0]]
        if provenance.rule_hash != expected_rule_hash:
            raise ValueError(
                "label provenance rule_hash mismatch: "
                f"{provenance.rule_hash} != {expected_rule_hash}"
            )

        if label.disposition not in ("unknown", "ambiguous"):
            rule = self._rules_by_id[label.matched_rule_ids[0]]
            semantic_checks = {
                "disposition": (label.disposition, rule.disposition),
                "attack_family": (label.attack_family, rule.attack_family),
                "attack_subtype": (label.attack_subtype, rule.attack_subtype),
                "target_profiles": (label.target_profiles, rule.target_profiles),
            }
            for field_name, (actual, expected) in semantic_checks.items():
                if actual != expected:
                    raise ValueError(
                        f"label outcome {field_name} mismatch: {actual!r} != {expected!r}"
                    )
            if rule.selector.mode == "any_network":
                allowed_directions = {"not_applicable"}
            else:
                allowed_directions = {"attacker_to_victim", "victim_to_attacker"}
            if label.matched_direction not in allowed_directions:
                raise ValueError(
                    "label outcome matched_direction is incompatible with referenced rule"
                )

    def assign(self, event: NetworkEvent) -> EventLabel:
        """Return one immutable sidecar label without modifying ``event``."""
        if getattr(event, "source", None) is None or getattr(event, "destination", None) is None:
            return self._unknown(event, "event type has no network endpoints")

        event_start = event.event_start_time
        event_end = event.event_end_time or event.event_start_time
        contained: list[_MatchCandidate] = []
        partial_rule_ids: list[str] = []

        for interval in self._compiled:
            direction = _endpoint_direction(event, interval.rule.selector)
            if direction is None:
                continue
            relation = _event_time_relation(
                event_start,
                event_end,
                interval.start_utc,
                interval.end_utc,
            )
            if relation == "contained":
                contained.append(_MatchCandidate(interval.rule, direction))
            elif relation == "partial":
                partial_rule_ids.append(interval.rule.rule_id)

        candidate_rule_ids = [candidate.rule.rule_id for candidate in contained]
        candidate_rule_ids.extend(partial_rule_ids)
        unique_candidate_ids = tuple(sorted(set(candidate_rule_ids)))

        if partial_rule_ids:
            return self._ambiguous(
                event,
                unique_candidate_ids,
                "event interval crosses a matched schedule boundary",
            )
        if len(unique_candidate_ids) > 1:
            return self._ambiguous(
                event,
                unique_candidate_ids,
                "event matches multiple schedule rules",
            )
        if not contained:
            return self._unknown(event, "no schedule rule matched time and endpoint roles")

        candidate = contained[0]
        rule = candidate.rule
        return EventLabel(
            event_id=event.provenance.event_id,
            disposition=rule.disposition,
            attack_family=rule.attack_family,
            attack_subtype=rule.attack_subtype,
            target_profiles=rule.target_profiles,
            matched_rule_ids=(rule.rule_id,),
            matched_direction=candidate.direction,
            reason=f"matched versioned schedule rule {rule.rule_id}",
            provenance=self._provenance(self._rule_hashes[rule.rule_id]),
        )

    def assign_many(self, events: Iterable[NetworkEvent]) -> tuple[EventLabel, ...]:
        """Assign labels in input order, preserving one result per event."""
        return tuple(self.assign(event) for event in events)
