"""Guards for the consolidated benchmark synthesis and the feature audit.

These tests do not train anything and do not touch PostgreSQL. They exist so that no
future edit can silently weaken the scientific scope of the published conclusions,
in particular the terminology discipline around ``unknown`` and the four claims that
P4 explicitly could not support.
"""
from __future__ import annotations

import json
from pathlib import Path
import re

import pytest


REPO_ROOT = Path(__file__).resolve().parents[3]
FINAL = REPO_ROOT / "artifacts" / "experiments" / "final"
FINAL_METRICS_SHA256 = (
    "9954d0cb1b41134cc7413cda7b733b508e927f1ae82ec1f023e6ba3d0f78ecbd"
)


def _flat(path: Path) -> str:
    return " ".join(path.read_text(encoding="utf-8").split())


@pytest.fixture(scope="module")
def metrics() -> dict:
    return json.loads(
        (FINAL / "final_benchmark_metrics.json").read_text(encoding="utf-8")
    )


@pytest.fixture(scope="module")
def report() -> str:
    return _flat(FINAL / "FINAL_BENCHMARK_REPORT.md")


@pytest.fixture(scope="module")
def audit() -> str:
    return _flat(FINAL / "FEATURE_AUDIT_REPORT.md")


# --------------------------------------------------------------------------
# consolidation integrity
# --------------------------------------------------------------------------


def test_the_consolidation_is_reproducible_and_verifies() -> None:
    from scripts.consolidate_benchmarks import verify

    def load(name: str) -> dict:
        base = REPO_ROOT / "artifacts" / "experiments"
        return json.loads((base / name).read_text(encoding="utf-8"))

    checks = verify(
        load("p1/p1_metrics.json"),
        load("p2/p2_metrics.json"),
        load("p3/p3_metrics.json"),
        load("p4/p4_metrics.json"),
    )
    assert len(checks) == 15
    assert all(c["passed"] for c in checks)


def test_the_published_metrics_identity_is_the_frozen_one() -> None:
    from hashlib import sha256

    payload = (FINAL / "final_benchmark_metrics.json").read_bytes()
    assert sha256(payload).hexdigest() == FINAL_METRICS_SHA256


def test_the_synthesis_re_executed_no_benchmark_and_wrote_no_row(
    metrics: dict,
) -> None:
    assert metrics["benchmarks_re_executed"] == 0
    assert metrics["postgresql_writes"] == 0


def test_the_feature_budget_recorded_is_still_only_the_five_volume_features(
    metrics: dict,
) -> None:
    assert metrics["feature_budget"] == [
        "event_count",
        "source_packets_total",
        "destination_packets_total",
        "source_bytes_total",
        "destination_bytes_total",
    ]


def test_every_attack_type_is_consolidated(metrics: dict) -> None:
    types = {entry["attack_type"] for entry in metrics["per_attack_type"]}
    assert types == {
        "botnet/ares",
        "brute_force/ftp_patator",
        "brute_force/ssh_patator",
        "ddos/loit",
        "dos/hulk",
    }


# --------------------------------------------------------------------------
# scope discipline: the conclusions must not drift upward
# --------------------------------------------------------------------------


def test_the_central_conclusion_keeps_its_hedges(metrics: dict) -> None:
    claim = metrics["central_conclusion"]
    assert "do not" in claim
    assert "47.1%" in claim
    assert "depends on other volumetric attacks being present in training" in claim


def test_botnet_blindness_is_recorded_as_robust(metrics: dict) -> None:
    robust = " ".join(metrics["confidence_tiers"]["robust"])
    assert "botnet/ares is undetectable" in robust
    botnet = next(
        e for e in metrics["per_attack_type"] if e["attack_type"] == "botnet/ares"
    )
    assert botnet["p3"]["window_recall"] == 0.0
    assert botnet["p3"]["episode_recall"] == 0.0
    assert botnet["p1"]["roc_auc"] < 0.55
    assert botnet["p4"]["roc_auc"] < 0.55


def test_loit_and_hulk_are_not_claimed_as_validated_by_p4(metrics: dict) -> None:
    for name in ("ddos/loit", "dos/hulk"):
        entry = next(
            e for e in metrics["per_attack_type"] if e["attack_type"] == name
        )
        assert entry["p4"]["status"].startswith("deleted")
    partial = " ".join(metrics["confidence_tiers"]["partially_supported"])
    assert "untested by P4" in partial


def test_the_ssh_p4_rise_is_recorded_as_an_artefact(
    metrics: dict, report: str
) -> None:
    ssh = next(
        e
        for e in metrics["per_attack_type"]
        if e["attack_type"] == "brute_force/ssh_patator"
    )
    assert ssh["p4"]["identical_test_positives"] is False
    partial = " ".join(metrics["confidence_tiers"]["partially_supported"])
    assert "exclusion artefact" in partial
    assert "is not an improvement" in report


def test_r1_final_status_is_not_resolved(metrics: dict, report: str) -> None:
    assert metrics["risks"]["R1"]["status"].startswith("NOT RESOLVED")
    assert "not proof of absence" in metrics["risks"]["R1"]["statement"]
    assert "NOT RESOLVED / no evidence of an effect on recall" in report


def test_the_pr_auc_decline_is_not_attributed_to_r1(
    metrics: dict, report: str
) -> None:
    reason = metrics["risks"]["R1"]["why_pr_auc_is_not_attributable_to_r1"]
    assert "coverage" in reason and "sample-size" in reason
    assert "not a confounding effect" in reason
    assert "The PR-AUC decline is not attributable to R1" in report


def test_r11_remains_a_major_limitation(metrics: dict) -> None:
    r11 = metrics["risks"]["R11"]
    assert r11["status"].startswith("major limitation")
    assert r11["attack_types"] == 5
    assert r11["attack_entities"] == 9
    assert r11["attack_host_pairs"] == 6
    assert r11["target_attack_host_pairs"] == 1
    assert r11["share_of_positives_below_benign_density"] == pytest.approx(0.4707)


def test_the_ftp_roc_collapse_is_documented_as_volume_dependence(
    metrics: dict, report: str
) -> None:
    ftp = next(
        e
        for e in metrics["per_attack_type"]
        if e["attack_type"] == "brute_force/ftp_patator"
    )
    assert ftp["p4"]["identical_test_positives"] is True
    assert ftp["p1"]["roc_auc"] > 0.98
    assert ftp["p4"]["roc_auc"] < 0.65
    assert "evidence of dependence on volume signal in training" in report


# --------------------------------------------------------------------------
# terminology discipline on `unknown`
# --------------------------------------------------------------------------


def test_unknown_is_never_called_a_false_positive_or_benign(
    metrics: dict, report: str
) -> None:
    assert "alert_rate_on_unlabelled_unknown" in metrics["p3_rates"]
    assert "is not evidence that `unknown` is benign" in report
    assert "These are not the same quantity" in report
    forbidden = (
        r"unknown\s+false\s+positive",
        r"false\s+positive\s+rate\s+on\s+unknown",
        r"unknown\s+(?:windows\s+)?are\s+benign",
        r"unknown\s+is\s+benign\b(?!\.\s*Recall)",
    )
    for pattern in forbidden:
        assert not re.search(pattern, report, re.IGNORECASE), pattern


def test_the_two_p3_rates_are_reported_as_distinct_quantities(
    metrics: dict,
) -> None:
    measured = metrics["p3_rates"]["measured_false_positive_rate_on_known_benign"]
    alerts = metrics["p3_rates"]["alert_rate_on_unlabelled_unknown"]
    assert set(measured) == set(alerts)
    assert measured != alerts


def test_within_day_non_stationarity_is_the_stated_cause(report: str) -> None:
    assert "within-day non-stationarity" in report.lower()
    assert "not memorisation" in report


# --------------------------------------------------------------------------
# the feature audit selected nothing
# --------------------------------------------------------------------------


def test_the_audit_states_that_no_feature_was_selected(audit: str) -> None:
    assert "No feature was selected, no model was trained" in audit
    assert "Choosing features is a separate decision" in audit


def test_the_audit_reconstruction_matched_the_frozen_populations(audit: str) -> None:
    assert "376 attack windows, 70 578 benign windows, 177 botnet windows" in audit


def test_every_measured_candidate_carries_a_verdict(audit: str) -> None:
    raw = json.loads((FINAL / "feature_audit_raw.json").read_text(encoding="utf-8"))
    assert len(raw) == 17
    for candidate in raw:
        assert f"`{candidate}`" in audit, candidate


def test_no_candidate_was_a_perfect_separator() -> None:
    raw = json.loads((FINAL / "feature_audit_raw.json").read_text(encoding="utf-8"))
    assert all(entry["range_disjoint"] is False for entry in raw.values())


def test_the_audit_measured_all_three_populations_including_botnet() -> None:
    raw = json.loads((FINAL / "feature_audit_raw.json").read_text(encoding="utf-8"))
    for name, entry in raw.items():
        assert set(entry) >= {"attack", "benign", "botnet"}, name
        assert entry["attack"]["n"] == 376
        assert entry["benign"]["n"] == 70578
        assert entry["botnet"]["n"] == 177


def test_high_separation_is_treated_as_a_warning_not_as_merit(audit: str) -> None:
    assert "treated as a leakage warning, not as merit" in audit


def test_the_online_availability_caveat_is_recorded(audit: str) -> None:
    assert "completed-flow assumption" in audit.lower()
    assert "would have no duration for them" in audit


def test_the_non_random_missingness_caveat_is_recorded(audit: str) -> None:
    assert "Missingness is not random" in audit
    assert "`event_count >= 2`" in audit


def test_the_label_induced_selection_effect_is_recorded(audit: str) -> None:
    assert "label-induced selection effect" in audit
    assert "0.18%" in audit


def test_the_redundant_candidates_are_rejected(audit: str) -> None:
    for candidate in ("distinct_source_ports", "distinct_conversations"):
        assert f"`{candidate}` | **INVALID**" in audit


def test_the_connection_state_fraction_candidate_is_deferred_under_r11(
    audit: str,
) -> None:
    assert "NEEDS REVIEW" in audit
    assert "cannot be distinguished from a feature that keys on that host pair" in audit


def test_r11_is_restated_as_binding_on_any_future_feature_work(audit: str) -> None:
    assert "No feature can create attack diversity" in audit
