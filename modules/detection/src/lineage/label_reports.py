"""Coverage and ambiguity reporting for sidecar label outcomes.

Event-level reports become available once canonical M3/M4 data exists.  M5 can
already emit a manifest-level coverage and overlap audit without inventing event
counts from the legacy CSVs.
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Annotated, Iterable

from pydantic import Field, model_validator

from modules.detection.src.contracts import (
    NonEmptyText,
    NonNegativeInt,
    Probability,
    StrictIdentifier,
    StrictModel,
    VersionString,
)
from modules.detection.src.schemas.labels import (
    AuthoritativeSource,
    EventLabel,
    LabelDisposition,
    Sha256Digest,
)

from .labeling import LabelLedger, ManifestOverlap, find_manifest_overlaps


class LabelCoverageReport(StrictModel):
    """Observed event-label coverage; unknown and ambiguity remain explicit."""

    report_version: VersionString
    manifest_hash: Sha256Digest
    rule_version: VersionString
    authoritative_source: AuthoritativeSource
    timezone: StrictIdentifier
    total_events: NonNegativeInt
    classified_events: NonNegativeInt
    coverage_ratio: Probability
    counts_by_disposition: dict[LabelDisposition, NonNegativeInt]
    counts_by_family: dict[StrictIdentifier, NonNegativeInt]

    @model_validator(mode="after")
    def validate_counts(self) -> "LabelCoverageReport":
        if sum(self.counts_by_disposition.values()) != self.total_events:
            raise ValueError("disposition counts must sum to total_events")
        if self.classified_events > self.total_events:
            raise ValueError("classified_events cannot exceed total_events")
        expected = self.classified_events / self.total_events if self.total_events else 0.0
        if abs(self.coverage_ratio - expected) > 1e-12:
            raise ValueError("coverage_ratio does not match report counts")
        return self


class AmbiguousEvent(StrictModel):
    """One ambiguous event and the candidate rules requiring review."""

    event_id: str
    matched_rule_ids: tuple[StrictIdentifier, ...]
    reason: NonEmptyText


class LabelAmbiguityReport(StrictModel):
    """Observed ambiguity report linked to the same manifest provenance."""

    report_version: VersionString
    manifest_hash: Sha256Digest
    rule_version: VersionString
    authoritative_source: AuthoritativeSource
    timezone: StrictIdentifier
    total_events: NonNegativeInt
    ambiguous_events: NonNegativeInt
    ambiguity_ratio: Probability
    events: tuple[AmbiguousEvent, ...]

    @model_validator(mode="after")
    def validate_counts(self) -> "LabelAmbiguityReport":
        if self.ambiguous_events != len(self.events):
            raise ValueError("ambiguous_events must equal ambiguity entry count")
        if self.ambiguous_events > self.total_events:
            raise ValueError("ambiguous_events cannot exceed total_events")
        expected = self.ambiguous_events / self.total_events if self.total_events else 0.0
        if abs(self.ambiguity_ratio - expected) > 1e-12:
            raise ValueError("ambiguity_ratio does not match report counts")
        return self


class ManifestCoverageReport(StrictModel):
    """Static coverage of the official schedule rules, not traffic events."""

    report_version: VersionString
    report_scope: LiteralScope
    dataset_name: StrictIdentifier
    manifest_hash: Sha256Digest
    rule_version: VersionString
    authoritative_source: AuthoritativeSource
    timezone: StrictIdentifier
    total_rules: NonNegativeInt
    total_intervals: NonNegativeInt
    total_scheduled_seconds: NonNegativeInt
    rules_by_disposition: dict[str, NonNegativeInt]
    rules_by_family: dict[str, NonNegativeInt]
    intervals_by_date: dict[str, NonNegativeInt]


LiteralScope = Annotated[
    str,
    Field(pattern=r"^manifest_schedule_only_no_canonical_events$")
]


class ManifestOverlapEntry(StrictModel):
    first_rule_id: StrictIdentifier
    second_rule_id: StrictIdentifier
    start_utc: str
    end_utc: str


class ManifestAmbiguityReport(StrictModel):
    """Static overlap audit; event-boundary ambiguity is reported after matching."""

    report_version: VersionString
    report_scope: Annotated[
        str,
        Field(pattern=r"^manifest_rule_overlap_audit$")
    ]
    dataset_name: StrictIdentifier
    manifest_hash: Sha256Digest
    overlap_count: NonNegativeInt
    overlaps: tuple[ManifestOverlapEntry, ...]

    @model_validator(mode="after")
    def validate_overlap_count(self) -> "ManifestAmbiguityReport":
        if self.overlap_count != len(self.overlaps):
            raise ValueError("overlap_count must equal overlap entry count")
        return self


def build_label_reports(
    labels: Iterable[EventLabel],
    ledger: LabelLedger,
) -> tuple[LabelCoverageReport, LabelAmbiguityReport]:
    """Build event-level coverage and ambiguity reports from sidecar labels."""
    values = tuple(labels)
    seen_event_ids: set = set()
    for label in values:
        if label.event_id in seen_event_ids:
            raise ValueError(f"duplicate event_id in label report: {label.event_id}")
        seen_event_ids.add(label.event_id)
        ledger.validate_label(label)
    disposition_counts = Counter(label.disposition for label in values)
    all_dispositions: tuple[LabelDisposition, ...] = (
        "target_attack",
        "known_other_attack",
        "benign_reference",
        "unknown",
        "ambiguous",
    )
    counts_by_disposition = {
        disposition: disposition_counts.get(disposition, 0)
        for disposition in all_dispositions
    }
    family_counts = Counter(
        label.attack_family
        for label in values
        if label.attack_family is not None
    )
    classified = sum(
        counts_by_disposition[value]
        for value in ("target_attack", "known_other_attack", "benign_reference")
    )
    total = len(values)
    common = {
        "report_version": "1.0.0",
        "manifest_hash": ledger.manifest_hash,
        "rule_version": ledger.manifest.rule_version,
        "authoritative_source": ledger.manifest.authoritative_source,
        "timezone": ledger.manifest.timezone,
    }
    coverage = LabelCoverageReport(
        **common,
        total_events=total,
        classified_events=classified,
        coverage_ratio=classified / total if total else 0.0,
        counts_by_disposition=counts_by_disposition,
        counts_by_family=dict(sorted(family_counts.items())),
    )
    ambiguous = tuple(
        AmbiguousEvent(
            event_id=str(label.event_id),
            matched_rule_ids=label.matched_rule_ids,
            reason=label.reason,
        )
        for label in values
        if label.disposition == "ambiguous"
    )
    ambiguity = LabelAmbiguityReport(
        **common,
        total_events=total,
        ambiguous_events=len(ambiguous),
        ambiguity_ratio=len(ambiguous) / total if total else 0.0,
        events=ambiguous,
    )
    return coverage, ambiguity


def build_manifest_audit(
    ledger: LabelLedger,
) -> tuple[ManifestCoverageReport, ManifestAmbiguityReport]:
    """Build honest M5 reports before canonical event partitions exist."""
    rules_by_disposition = Counter(rule.disposition for rule in ledger.manifest.rules)
    rules_by_family = Counter(
        rule.attack_family
        for rule in ledger.manifest.rules
        if rule.attack_family is not None
    )
    intervals_by_date = Counter(
        interval.start_utc.date().isoformat()
        for interval in ledger.compiled_intervals
    )
    scheduled_seconds = int(
        sum(
            (interval.end_utc - interval.start_utc).total_seconds()
            for interval in ledger.compiled_intervals
        )
    )
    coverage = ManifestCoverageReport(
        report_version="1.0.0",
        report_scope="manifest_schedule_only_no_canonical_events",
        dataset_name=ledger.manifest.dataset_name,
        manifest_hash=ledger.manifest_hash,
        rule_version=ledger.manifest.rule_version,
        authoritative_source=ledger.manifest.authoritative_source,
        timezone=ledger.manifest.timezone,
        total_rules=len(ledger.manifest.rules),
        total_intervals=len(ledger.compiled_intervals),
        total_scheduled_seconds=scheduled_seconds,
        rules_by_disposition=dict(sorted(rules_by_disposition.items())),
        rules_by_family=dict(sorted(rules_by_family.items())),
        intervals_by_date=dict(sorted(intervals_by_date.items())),
    )
    overlaps = find_manifest_overlaps(ledger.manifest)
    ambiguity = ManifestAmbiguityReport(
        report_version="1.0.0",
        report_scope="manifest_rule_overlap_audit",
        dataset_name=ledger.manifest.dataset_name,
        manifest_hash=ledger.manifest_hash,
        overlap_count=len(overlaps),
        overlaps=tuple(_overlap_entry(item) for item in overlaps),
    )
    return coverage, ambiguity


def _overlap_entry(value: ManifestOverlap) -> ManifestOverlapEntry:
    return ManifestOverlapEntry(
        first_rule_id=value.first_rule_id,
        second_rule_id=value.second_rule_id,
        start_utc=value.start_utc.isoformat(),
        end_utc=value.end_utc.isoformat(),
    )


def write_reports(
    coverage: StrictModel,
    ambiguity: StrictModel,
    output_directory: str | Path,
    prefix: str,
) -> tuple[Path, Path]:
    """Atomically replace deterministic JSON report files."""
    destination = Path(output_directory)
    destination.mkdir(parents=True, exist_ok=True)
    coverage_path = destination / f"{prefix}_coverage.json"
    ambiguity_path = destination / f"{prefix}_ambiguity.json"
    coverage_path.write_text(coverage.model_dump_json(indent=2) + "\n", encoding="utf-8")
    ambiguity_path.write_text(ambiguity.model_dump_json(indent=2) + "\n", encoding="utf-8")
    return coverage_path, ambiguity_path
