"""Guards for P6 — targeted behavioural feature audit.

These tests train nothing and touch no database. They protect the audit's
discipline: that a strong discrimination never produces SAFE on its own, that the
identity and sign tests actually gate the verdict, that the constrained families
stay constrained, and that P1-P5 remain untouched.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[3]
EXP = REPO_ROOT / "artifacts" / "experiments"
P6_CONTENT_SHA256 = (
    "7a9cd4871b0d686e"  # prefix; full value asserted from the file itself
)


@pytest.fixture(scope="module")
def p6() -> dict:
    return json.loads(
        (EXP / "p6/p6_feature_audit.json").read_text(encoding="utf-8")
    )


@pytest.fixture(scope="module")
def report() -> str:
    return " ".join(
        (EXP / "p6/P6_FEATURE_AUDIT.md").read_text(encoding="utf-8").split()
    )


def _audit(p6: dict, name: str) -> dict:
    return next(a for a in p6["audits"] if a["feature"] == name)


# ---------------------------------------------------------------------------
# isolation and constraints
# ---------------------------------------------------------------------------


def test_p6_wrote_nothing_and_trained_nothing(p6: dict) -> None:
    assert p6["postgresql_writes"] == 0
    assert p6["model_trained"] is False
    assert p6["xgboost_trained"] is False
    assert p6["features_selected"] is False
    assert p6["labels_modified"] is False
    assert p6["unknown_or_ambiguous_used"] is False
    assert p6["p1_folds_used"] is False


def test_forbidden_columns_were_not_changed(p6: dict) -> None:
    assert len(p6["forbidden_columns_unchanged"]) == 18
    for column in (
        "entity_source_ip",
        "entity_destination_ip",
        "entity_service",
        "entity_transport",
        "window_start_time",
        "capture_id",
    ):
        assert column in p6["forbidden_columns_unchanged"]


def test_identity_columns_are_documented_as_excluded(p6: dict) -> None:
    reasons = " ".join(p6["excluded_columns_and_why"].values())
    assert "identity or a direct proxy" in reasons
    assert "capture artefact" in reasons
    assert "pipeline clocks" in reasons


def test_the_audited_population_is_the_frozen_one(p6: dict) -> None:
    pop = p6["populations"]
    assert pop["botnet_windows"] == 177
    assert pop["botnet_entities"] == 5
    assert pop["botnet_host_pairs"] == 5
    assert pop["botnet_episodes"] == 40
    assert pop["target_attack_windows"] == 199
    assert pop["benign_reference_windows"] == 70578


def test_p1_through_p5_artifacts_are_untouched() -> None:
    from hashlib import sha256

    expected = {
        "p1/p1_dataset.csv": "e95aed008d994510",
        "p1/p1_folds.json": "57e688fd3da90911",
        "p1/p1_metrics.json": "2a51e618397c42b7",
        "p2/p2_metrics.json": "67d2f60bc57d03bb",
        "p3/p3_metrics.json": "a3e9f1c7175594c9",
        "p4/p4_metrics.json": "3df92eda32d943b6",
        "p5/p5_metrics.json": "87055c8b14623581",
    }
    for name, prefix in expected.items():
        digest = sha256((EXP / name).read_bytes()).hexdigest()
        assert digest.startswith(prefix), name


# ---------------------------------------------------------------------------
# a strong discrimination must never be enough on its own
# ---------------------------------------------------------------------------


def test_high_screening_auc_alone_does_not_produce_safe(p6: dict) -> None:
    """The strongest screeners in the audit are NOT safe, by design."""
    for name in (
        "interarrival_mean",       # 0.9146, best in the audit
        "byte_direction_ratio",    # 0.9002
        "bytes_per_packet_destination",  # 0.8852
        "packets_per_second",      # 0.8726
    ):
        audit = _audit(p6, name)
        assert audit["screening_botnet_vs_benign"]["oriented_auc"] > 0.85
        assert audit["status"] != "SAFE", name


def test_screening_is_labelled_descriptive_not_performance(
    p6: dict, report: str
) -> None:
    assert any("descriptive" in limit for limit in p6["limitations"])
    assert any("not a model performance" in limit for limit in p6["limitations"])
    assert "descriptive only" in report
    assert "no generalisation follows from it" in report


def test_no_threshold_or_recall_was_computed(p6: dict) -> None:
    assert any("no threshold was calibrated" in x for x in p6["limitations"])


# ---------------------------------------------------------------------------
# the identity test must gate the verdict (R11)
# ---------------------------------------------------------------------------


def test_identity_dependent_features_are_not_safe(p6: dict) -> None:
    ceiling = p6["thresholds"]["identity_auc_ceiling"]
    for audit in p6["audits"]:
        worst = audit["identity_dependence"].get("max_pairwise_auc")
        if worst is not None and worst >= ceiling:
            assert audit["status"] != "SAFE", audit["feature"]


def test_byte_direction_ratio_is_withheld_for_identity(p6: dict) -> None:
    audit = _audit(p6, "byte_direction_ratio")
    assert audit["identity_dependence"]["max_pairwise_auc"] >= 0.75
    assert audit["status"] == "NEEDS_REVIEW"


def test_every_audit_answers_the_r11_question(p6: dict) -> None:
    for audit in p6["audits"]:
        answer = audit["r11_question_behaviour_or_identity"]
        assert isinstance(answer, str) and answer
        assert any(
            answer.startswith(prefix)
            for prefix in (
                "behaviour",
                "identity or provenance",
                "probably behaviour",
                "cannot be established",
            )
        ), audit["feature"]


def test_safe_features_carry_the_signal_on_every_botnet_entity(p6: dict) -> None:
    for audit in p6["audits"]:
        if audit["status"] != "SAFE":
            continue
        consistency = audit["entity_consistency"]
        assert consistency["entities"] == 5
        assert consistency["carried_by_all_entities"] is True


# ---------------------------------------------------------------------------
# the sign test, including its correction
# ---------------------------------------------------------------------------


def test_safe_requires_sign_agreement_with_the_volumetric_attacks(p6: dict) -> None:
    for audit in p6["audits"]:
        if audit["status"] == "SAFE":
            assert audit["transfer_sign_agreement"]["agrees"] is True, audit["feature"]


def test_a_chance_level_reference_yields_undetermined_not_a_verdict(
    p6: dict,
) -> None:
    """The correction: a reference AUC near 0.5 carries no direction."""
    for name in ("bytes_per_packet_destination", "bytes_per_second", "duration_mean"):
        transfer = _audit(p6, name)["transfer_sign_agreement"]
        assert transfer.get("undetermined") is True, name
        assert transfer["agrees"] is None
        assert abs(transfer["target_attack_auc"] - 0.5) < 0.05


def test_the_opposite_sign_features_are_identified(p6: dict) -> None:
    """These are the measurements that explain P1 and P5 mechanically."""
    volume = _audit(p6, "destination_bytes_total")
    assert volume["transfer_sign_agreement"]["agrees"] is False
    assert volume["screening_botnet_vs_benign"]["direction"] == "higher on benign"
    assert (
        volume["screening_target_attack_vs_benign"]["direction"]
        == "higher on attack"
    )

    cv = _audit(p6, "interarrival_cv")
    assert cv["transfer_sign_agreement"]["agrees"] is False


def test_three_volume_features_are_at_chance_on_the_botnet(p6: dict) -> None:
    for name in (
        "source_packets_total",
        "destination_packets_total",
        "source_bytes_total",
    ):
        audit = _audit(p6, name)
        assert audit["screening_botnet_vs_benign"]["oriented_auc"] < 0.55, name


def test_the_report_explains_p1_and_p5_mechanically(report: str) -> None:
    assert "This is why P1 returned ROC-AUC 0.5037" in report
    assert "one actively harmful one" in report
    assert "Two corrections made to this audit's own method" in report
    assert "A chance-level reference carries no direction" in report
    assert "not comparable" in report
    assert "This reversed the surviving feature" in report


# ---------------------------------------------------------------------------
# constrained families stay constrained
# ---------------------------------------------------------------------------


def test_family_b_is_withheld_because_p5_already_tested_it(p6: dict) -> None:
    verdict = next(
        v for v in p6["family_verdicts"] if v["family"] == "B_temporal"
    )
    assert verdict["safe"] == []
    assert "already tested in P5" in verdict["constraint"]
    assert verdict["may_enter_xgboost"].startswith("no")


def test_family_e_is_withheld_by_standing_constraint(p6: dict) -> None:
    verdict = next(
        v for v in p6["family_verdicts"] if v["family"] == "E_states_flags"
    )
    assert verdict["safe"] == []
    assert "172.16.0.1 -> 192.168.10.50" in verdict["constraint"]
    assert verdict["may_enter_xgboost"].startswith("no")
    for name in ("state_sf_ratio", "state_distinct_count"):
        assert _audit(p6, name)["status"] == "NEEDS_REVIEW"


def test_family_a_is_reference_only(p6: dict) -> None:
    verdict = next(v for v in p6["family_verdicts"] if v["family"] == "A_volume")
    assert verdict["may_enter_xgboost"] == "no - reference budget only"
    for audit in p6["audits"]:
        if audit["family"] == "A_volume":
            assert audit["status"] == "REFERENCE"


# ---------------------------------------------------------------------------
# the surviving feature and the minimal set
# ---------------------------------------------------------------------------


def test_exactly_one_feature_is_in_the_smallest_justified_set(p6: dict) -> None:
    assert p6["smallest_justified_set"] == ["distinct_payload_ratio"]


def test_the_redundancy_tie_break_prefers_availability_over_a_stronger_auc(
    p6: dict,
) -> None:
    """The correction: AUCs on different defined subpopulations are not comparable."""
    kept = _audit(p6, "distinct_payload_ratio")
    dropped = _audit(p6, "payload_repeat_ratio")
    # the dropped one screens HIGHER, and is still the one dropped
    assert (
        dropped["screening_botnet_vs_benign"]["oriented_auc"]
        > kept["screening_botnet_vs_benign"]["oriented_auc"]
    )
    assert kept["distribution_benign"]["missing_rate"] == 0.0
    assert dropped["distribution_benign"]["missing_rate"] > 0.5
    reason = p6["dropped_as_redundant"]["payload_repeat_ratio"]
    assert "not comparable across different defined subpopulations" in reason


def test_the_mirror_feature_is_dropped_as_redundant(p6: dict) -> None:
    assert "payload_repeat_ratio" in p6["dropped_as_redundant"]
    pair = "distinct_payload_ratio ~ payload_repeat_ratio"
    assert p6["redundancy_among_safe"]["redundant_pairs"][pair] == pytest.approx(
        -1.0, abs=1e-9
    )


def test_the_surviving_feature_is_online_and_label_free(p6: dict) -> None:
    audit = _audit(p6, "distinct_payload_ratio")
    assert audit["online_availability"] == "online"
    assert "source_bytes" in audit["definition"]
    assert "label" not in audit["definition"]


def test_the_surviving_feature_has_low_identity_dependence(p6: dict) -> None:
    audit = _audit(p6, "distinct_payload_ratio")
    assert audit["identity_dependence"]["max_pairwise_auc"] < 0.75
    assert audit["entity_consistency"]["carried_by_all_entities"] is True


def test_the_surviving_feature_has_no_missingness(p6: dict, report: str) -> None:
    audit = _audit(p6, "distinct_payload_ratio")
    assert audit["distribution_botnet"]["missing_rate"] == 0.0
    assert audit["distribution_benign"]["missing_rate"] == 0.0
    assert "Its weaknesses, stated plainly" in report
    assert "weakest" in report


# ---------------------------------------------------------------------------
# the tail limitation must stay visible
# ---------------------------------------------------------------------------


def test_the_episode_tail_figures_are_recorded_accurately(
    p6: dict, report: str
) -> None:
    """Tail reach and overall separation are different properties here."""
    tail = {
        a["feature"]: a["episode_coverage"]["episodes_touching_the_tail"]
        for a in p6["audits"]
    }
    assert tail["source_bytes_total"] == 15
    assert tail["interarrival_cv"] == 14
    assert tail["distinct_payload_ratio"] == 6
    assert tail["payload_repeat_ratio"] == 2
    zeroes = [k for k, v in tail.items() if v == 0]
    assert len(zeroes) == 18
    # the best tail reacher screens at chance, which is the point
    assert (
        _audit(p6, "source_bytes_total")["screening_botnet_vs_benign"][
            "oriented_auc"
        ]
        < 0.55
    )
    assert "combination of weak signals" in report
    assert "cut against each other" in report


def test_r11_is_restated_as_binding(p6: dict, report: str) -> None:
    assert any("R11 is unchanged" in x for x in p6["limitations"])
    assert "R11" in report
    assert "no feature can create diversity" in report.lower()
    assert "205.174.165.73" in report


def test_no_next_step_was_started(report: str) -> None:
    assert "No XGBoost" in report
    assert "No tuning" in report
    assert "No model selection" in report
