"""Tests for honest M5 coverage and ambiguity reporting."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from modules.detection.src.lineage import (
    LabelLedger,
    build_label_reports,
    build_manifest_audit,
    write_reports,
)
from modules.detection.src.schemas import EventLabel
from modules.detection.tests.label_fixtures import MANIFEST_PATH, flow_event


def _five_outcomes(ledger: LabelLedger):
    events = (
        flow_event(start_local="2017-07-04T09:30:00", identity="report-target"),
        flow_event(
            start_local="2017-07-05T09:50:00",
            destination_port=80,
            service="http",
            identity="report-known",
        ),
        flow_event(
            start_local="2017-07-03T10:00:00",
            source_ip="198.51.100.1",
            destination_ip="192.0.2.1",
            identity="report-benign",
        ),
        flow_event(start_local="2017-07-04T11:30:00", identity="report-unknown"),
        flow_event(
            start_local="2017-07-04T09:19:59",
            end_local="2017-07-04T09:20:01",
            identity="report-ambiguous",
        ),
    )
    return ledger.assign_many(events)


def test_event_coverage_keeps_all_five_outcomes_explicit():
    ledger = LabelLedger.from_yaml(MANIFEST_PATH)
    coverage, ambiguity = build_label_reports(_five_outcomes(ledger), ledger)
    assert coverage.total_events == 5
    assert coverage.classified_events == 3
    assert coverage.coverage_ratio == 0.6
    assert coverage.counts_by_disposition == {
        "target_attack": 1,
        "known_other_attack": 1,
        "benign_reference": 1,
        "unknown": 1,
        "ambiguous": 1,
    }
    assert coverage.counts_by_family == {"brute_force": 1, "dos": 1}
    assert ambiguity.total_events == 5
    assert ambiguity.ambiguous_events == 1
    assert ambiguity.ambiguity_ratio == 0.2
    assert ambiguity.events[0].matched_rule_ids == ("tuesday-ftp-patator",)


def test_event_reports_round_trip_to_deterministic_json(tmp_path: Path):
    ledger = LabelLedger.from_yaml(MANIFEST_PATH)
    coverage, ambiguity = build_label_reports(_five_outcomes(ledger), ledger)
    coverage_path, ambiguity_path = write_reports(
        coverage,
        ambiguity,
        tmp_path,
        "event_labels",
    )
    assert json.loads(coverage_path.read_text(encoding="utf-8"))["total_events"] == 5
    assert json.loads(ambiguity_path.read_text(encoding="utf-8"))["ambiguous_events"] == 1


def test_manifest_audit_reports_schedule_not_invented_event_coverage():
    ledger = LabelLedger.from_yaml(MANIFEST_PATH)
    coverage, ambiguity = build_manifest_audit(ledger)
    assert coverage.report_scope == "manifest_schedule_only_no_canonical_events"
    assert coverage.total_rules == 16
    assert coverage.total_intervals == 45
    assert coverage.rules_by_disposition == {
        "benign_reference": 1,
        "known_other_attack": 10,
        "target_attack": 5,
    }
    assert coverage.intervals_by_date == {
        "2017-07-03": 1,
        "2017-07-04": 2,
        "2017-07-05": 5,
        "2017-07-06": 8,
        "2017-07-07": 29,
    }
    assert ambiguity.report_scope == "manifest_rule_overlap_audit"
    assert ambiguity.overlap_count == 0
    assert ambiguity.overlaps == ()


def test_event_report_rejects_duplicate_event_ids():
    ledger = LabelLedger.from_yaml(MANIFEST_PATH)
    label = _five_outcomes(ledger)[0]
    with pytest.raises(ValueError, match="duplicate event_id"):
        build_label_reports((label, label), ledger)


def test_event_report_rejects_foreign_manifest_provenance():
    ledger = LabelLedger.from_yaml(MANIFEST_PATH)
    foreign_manifest = ledger.manifest.model_copy(
        update={"manifest_version": "1.0.1"}
    )
    foreign_ledger = LabelLedger(foreign_manifest)
    foreign_label = foreign_ledger.assign(
        flow_event(start_local="2017-07-04T09:30:00", identity="foreign-label")
    )
    with pytest.raises(ValueError, match="manifest_hash"):
        build_label_reports((foreign_label,), ledger)


def test_event_report_rejects_forged_rule_hash():
    ledger = LabelLedger.from_yaml(MANIFEST_PATH)
    label = _five_outcomes(ledger)[0]
    forged_provenance = label.provenance.model_copy(update={"rule_hash": "0" * 64})
    forged_label = label.model_copy(update={"provenance": forged_provenance})
    with pytest.raises(ValueError, match="rule_hash"):
        build_label_reports((forged_label,), ledger)


def test_event_report_rejects_disposition_substitution_with_genuine_hash():
    ledger = LabelLedger.from_yaml(MANIFEST_PATH)
    label = _five_outcomes(ledger)[0]
    payload = label.model_dump()
    payload.update(
        {
            "disposition": "benign_reference",
            "attack_family": None,
            "attack_subtype": None,
            "target_profiles": (),
            "matched_direction": "not_applicable",
        }
    )
    forged_label = EventLabel.model_validate(payload)
    with pytest.raises(ValueError, match="outcome disposition"):
        build_label_reports((forged_label,), ledger)


def test_event_report_rejects_taxonomy_substitution_with_genuine_hash():
    ledger = LabelLedger.from_yaml(MANIFEST_PATH)
    label = _five_outcomes(ledger)[0]
    payload = label.model_dump()
    payload["attack_family"] = "forged_family"
    forged_label = EventLabel.model_validate(payload)
    with pytest.raises(ValueError, match="outcome attack_family"):
        build_label_reports((forged_label,), ledger)


def test_empty_event_reports_are_valid_and_honest():
    ledger = LabelLedger.from_yaml(MANIFEST_PATH)
    coverage, ambiguity = build_label_reports((), ledger)
    assert coverage.total_events == 0
    assert coverage.coverage_ratio == 0.0
    assert coverage.counts_by_disposition["unknown"] == 0
    assert ambiguity.ambiguity_ratio == 0.0
