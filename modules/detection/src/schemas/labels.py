"""Strict sidecar label contracts for canonical IDS events.

Labels are deliberately separate from ``NetworkEvent`` and ``FeatureWindow`` so
attack knowledge cannot leak into telemetry or model features.  The ontology
represents project targets, other known attacks, explicit benign references,
unknown traffic, and ambiguity rather than collapsing every unmatched event to
benign.
"""
from __future__ import annotations

from datetime import date, time
from typing import Annotated, Literal, TypeAlias
from uuid import UUID
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import Field, StringConstraints, field_validator, model_validator

from modules.detection.src.contracts import (
    NonEmptyText,
    PortNumber,
    StrictIdentifier,
    StrictIpAddress,
    StrictModel,
    VersionString,
)

LabelDisposition: TypeAlias = Literal[
    "target_attack",
    "known_other_attack",
    "benign_reference",
    "unknown",
    "ambiguous",
]
RuleDisposition: TypeAlias = Literal[
    "target_attack",
    "known_other_attack",
    "benign_reference",
]
MatchedDirection: TypeAlias = Literal[
    "attacker_to_victim",
    "victim_to_attacker",
    "not_applicable",
    "indeterminate",
]
EndpointMatchMode: TypeAlias = Literal["role_constrained", "any_network"]
TransportName: TypeAlias = Literal["tcp", "udp", "icmp", "icmpv6", "sctp", "other"]
Sha256Digest = Annotated[
    str,
    StringConstraints(pattern=r"^[0-9a-f]{64}$"),
]


class AuthoritativeSource(StrictModel):
    """Human-auditable source from which schedule rules were transcribed."""

    name: NonEmptyText
    url: NonEmptyText
    retrieved_at: date

    @field_validator("url")
    @classmethod
    def require_https_url(cls, value: str) -> str:
        if not value.startswith("https://"):
            raise ValueError("authoritative source URL must use https")
        return value


class LocalScheduleInterval(StrictModel):
    """Minute-precision source interval whose published end minute is inclusive."""

    date: date
    start_time: time
    end_time_inclusive: time

    @model_validator(mode="after")
    def validate_same_day_order(self) -> "LocalScheduleInterval":
        if self.end_time_inclusive < self.start_time:
            raise ValueError("schedule intervals cannot cross midnight")
        if self.start_time.second or self.start_time.microsecond:
            raise ValueError("start_time must use official minute precision")
        if self.end_time_inclusive.second or self.end_time_inclusive.microsecond:
            raise ValueError("end_time_inclusive must use official minute precision")
        return self


class EndpointSelector(StrictModel):
    """Role-aware endpoint and protocol constraints for one schedule rule."""

    mode: EndpointMatchMode
    attacker_ips: tuple[StrictIpAddress, ...]
    victim_ips: tuple[StrictIpAddress, ...]
    victim_ports: tuple[PortNumber, ...]
    protocols: tuple[TransportName, ...]

    @model_validator(mode="after")
    def validate_selector(self) -> "EndpointSelector":
        if len(set(self.attacker_ips)) != len(self.attacker_ips):
            raise ValueError("attacker_ips must be unique")
        if len(set(self.victim_ips)) != len(self.victim_ips):
            raise ValueError("victim_ips must be unique")
        if len(set(self.victim_ports)) != len(self.victim_ports):
            raise ValueError("victim_ports must be unique")
        if len(set(self.protocols)) != len(self.protocols):
            raise ValueError("protocols must be unique")

        if self.mode == "any_network":
            if self.attacker_ips or self.victim_ips or self.victim_ports or self.protocols:
                raise ValueError("any_network selector cannot contain role constraints")
            return self

        if not self.attacker_ips or not self.victim_ips:
            raise ValueError("role_constrained selector requires attacker and victim IPs")
        if set(self.attacker_ips) & set(self.victim_ips):
            raise ValueError("attacker and victim role sets must be disjoint")
        return self


class LabelRule(StrictModel):
    """One versioned schedule rule; unknown and ambiguity are matcher outcomes."""

    rule_id: StrictIdentifier
    disposition: RuleDisposition
    attack_family: StrictIdentifier | None
    attack_subtype: StrictIdentifier | None
    target_profiles: tuple[StrictIdentifier, ...]
    intervals: Annotated[tuple[LocalScheduleInterval, ...], Field(min_length=1)]
    selector: EndpointSelector
    notes: NonEmptyText

    @model_validator(mode="after")
    def validate_semantics(self) -> "LabelRule":
        if len(set(self.target_profiles)) != len(self.target_profiles):
            raise ValueError("target_profiles must be unique")
        if self.disposition in ("target_attack", "known_other_attack"):
            if self.attack_family is None or self.attack_subtype is None:
                raise ValueError("attack rules require family and subtype")
        if self.disposition == "target_attack" and not self.target_profiles:
            raise ValueError("target_attack requires at least one target profile")
        if self.disposition != "target_attack" and self.target_profiles:
            raise ValueError("only target_attack rules may name target profiles")
        if self.disposition == "benign_reference":
            if self.attack_family is not None or self.attack_subtype is not None:
                raise ValueError("benign_reference cannot carry attack taxonomy")
            if self.selector.mode != "any_network":
                raise ValueError("benign_reference must use an explicit any_network rule")
        return self


class LabelManifest(StrictModel):
    """Complete versioned policy used to assign CICIDS2017 sidecar labels."""

    manifest_version: VersionString
    rule_version: VersionString
    dataset_name: StrictIdentifier
    authoritative_source: AuthoritativeSource
    timezone: StrictIdentifier
    source_time_precision: Literal["minute"]
    source_end_semantics: Literal["inclusive_minute_to_half_open"]
    default_disposition: Literal["unknown"]
    rules: Annotated[tuple[LabelRule, ...], Field(min_length=1)]

    @field_validator("timezone")
    @classmethod
    def require_iana_timezone(cls, value: str) -> str:
        try:
            ZoneInfo(value)
        except ZoneInfoNotFoundError as exc:
            raise ValueError(f"unknown IANA timezone: {value}") from exc
        return value

    @model_validator(mode="after")
    def validate_unique_rules(self) -> "LabelManifest":
        rule_ids = [rule.rule_id for rule in self.rules]
        if len(set(rule_ids)) != len(rule_ids):
            raise ValueError("rule_id values must be unique")
        return self


class LabelAssignmentProvenance(StrictModel):
    """Policy provenance attached to every sidecar label outcome."""

    rule_version: VersionString
    rule_hash: Sha256Digest
    manifest_hash: Sha256Digest
    authoritative_source: AuthoritativeSource
    timezone: StrictIdentifier


class EventLabel(StrictModel):
    """Immutable sidecar result linked to an event only by its event UUID."""

    event_id: UUID
    disposition: LabelDisposition
    attack_family: StrictIdentifier | None
    attack_subtype: StrictIdentifier | None
    target_profiles: tuple[StrictIdentifier, ...]
    matched_rule_ids: tuple[StrictIdentifier, ...]
    matched_direction: MatchedDirection
    reason: NonEmptyText
    provenance: LabelAssignmentProvenance

    @model_validator(mode="after")
    def validate_outcome(self) -> "EventLabel":
        if len(set(self.matched_rule_ids)) != len(self.matched_rule_ids):
            raise ValueError("matched_rule_ids must be unique")
        if self.disposition in ("target_attack", "known_other_attack"):
            if self.attack_family is None or self.attack_subtype is None:
                raise ValueError("attack outcomes require family and subtype")
            if len(self.matched_rule_ids) != 1:
                raise ValueError("unambiguous attack outcomes require one matched rule")
            if self.matched_direction not in (
                "attacker_to_victim",
                "victim_to_attacker",
            ):
                raise ValueError("attack outcomes require an endpoint-role direction")
        if self.disposition == "target_attack" and not self.target_profiles:
            raise ValueError("target_attack outcome requires target profiles")
        if self.disposition != "target_attack" and self.target_profiles:
            raise ValueError("only target_attack outcomes may carry target profiles")
        if self.disposition == "benign_reference":
            if self.attack_family is not None or self.attack_subtype is not None:
                raise ValueError("benign_reference cannot carry attack taxonomy")
            if len(self.matched_rule_ids) != 1:
                raise ValueError("benign_reference requires one explicit rule")
            if self.matched_direction != "not_applicable":
                raise ValueError("benign_reference direction must be not_applicable")
        if self.disposition == "unknown":
            if self.attack_family is not None or self.attack_subtype is not None:
                raise ValueError("unknown cannot carry attack taxonomy")
            if self.matched_rule_ids:
                raise ValueError("unknown cannot claim a matched rule")
            if self.matched_direction != "indeterminate":
                raise ValueError("unknown direction must be indeterminate")
        if self.disposition == "ambiguous":
            if self.attack_family is not None or self.attack_subtype is not None:
                raise ValueError("ambiguous cannot select one attack taxonomy")
            if not self.matched_rule_ids:
                raise ValueError("ambiguous requires candidate rule IDs")
            if self.matched_direction != "indeterminate":
                raise ValueError("ambiguous direction must be indeterminate")
        return self
