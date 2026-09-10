"""Additive M5 v3 label policy: complete the NAT realignment coverage.

Why this module exists
---------------------
M5 v2 corrected the unobservable attacker identity for four rules. A read-only
label-coverage audit established that **three further rules describe attacks that
are fully present in the canonical events but were left unrealigned**, so they
matched nothing and their windows stayed ``unknown``:

=========================  =====  ==================  =========  ========
rule                       port   flows in interval   windows    episodes
=========================  =====  ==================  =========  ========
``wednesday-slowloris``    80     3 869               46         2
``wednesday-slowhttptest`` 80     4 556               26         8
``wednesday-goldeneye``    80     7 716               16         4
=========================  =====  ==================  =========  ========

All three declare attacker ``205.174.165.73``, which appears **0 times as a
source** and 4 805 times as a destination in ``m4_canonical``. The observable
identity is ``172.16.0.1``, with 437 032 source events. Inside the three declared
intervals, **100 % of the traffic sourced by ``172.16.0.1`` goes to
``192.168.10.50:80/tcp``**, the declared victim, port and protocol, so promoting
that identity cannot capture anything but the declared attack.

Why this is a new version instead of an edit to v2
--------------------------------------------------
Extending ``m5_policy_v2.REALIGNED_RULE_IDS`` in place would move the attack
window count from 376 to 464, which would change the content digest of
``p1_dataset.csv`` and therefore invalidate every published experiment, the
frozen production dataset and the five validation steps. v3 is additive: v1 and
v2 are read, never written, and both remain the policies of record for all
existing artefacts.

What this module never does
---------------------------
It does not modify M5 v1, M5 v2, their manifests, ``LabelLedger``,
``exact_time_labeling_v2``, M6, or any upstream artefact. It creates no table and
writes nothing. ``unknown`` and ``ambiguous`` are never converted to benign, and
no rule is removed.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Final

from modules.detection.src.lineage.labeling import LabelLedger, load_label_manifest
from modules.detection.src.lineage.m5_policy_v2 import (
    CANONICAL_M5_V1_MANIFEST_PATH,
    OBSERVABLE_ATTACKER_IP,
    REALIGNED_RULE_IDS as REALIGNED_RULE_IDS_V2,
    UNOBSERVABLE_ATTACKER_IPS,
)
from modules.detection.src.schemas.labels import LabelManifest

#: The three rules the coverage audit proved were missing from v2.
COVERAGE_CORRECTION_RULE_IDS: Final[frozenset[str]] = frozenset(
    {
        "wednesday-slowloris",
        "wednesday-slowhttptest",
        "wednesday-goldeneye",
    }
)

#: v3 realigns the v2 set plus the three corrected rules. Nothing else changes.
REALIGNED_RULE_IDS_V3: Final[frozenset[str]] = (
    REALIGNED_RULE_IDS_V2 | COVERAGE_CORRECTION_RULE_IDS
)

#: Rules deliberately left unrealigned, with the reason recorded.
DELIBERATELY_NOT_REALIGNED: Final[dict[str, str]] = {
    "friday-botnet-ares": (
        "already functional through the inverted role branch: the bots are the "
        "declared victims and the C2 is the declared attacker, so the observed "
        "direction 192.168.10.x -> 205.174.165.73 already matches"
    ),
    "friday-portscan": (
        "traffic is present but carries no victim-port constraint and spans dozens "
        "of destination ports, which would create many new entity keys and change "
        "the nature of the population; needs a separate ratified decision"
    ),
    "wednesday-heartbleed": (
        "only 1 event observed towards the declared victim 192.168.10.51:444 in the "
        "whole interval, so realignment would add about one window"
    ),
    "monday-benign-reference": "benign reference rule, no attacker declared",
    "thursday-web-bruteforce": "Thursday is not in the canonical chain; NAT unverified",
    "thursday-xss": "Thursday is not in the canonical chain; NAT unverified",
    "thursday-sql-injection": "Thursday is not in the canonical chain; NAT unverified",
    "thursday-infiltration-vista": "Thursday is not in the canonical chain; NAT unverified",
    "thursday-infiltration-mac": "Thursday is not in the canonical chain; NAT unverified",
}

M5_V3_MANIFEST_VERSION: Final[str] = "3.0.0"
M5_V3_RULE_VERSION: Final[str] = "3.0.0"

#: Observations that justify the correction, recorded for the audit trail.
COVERAGE_EVIDENCE: Final[dict[str, dict[str, object]]] = {
    "wednesday-slowloris": {
        "events_matching_realigned_selector": 3_869,
        "windows_currently_unknown": 46,
        "episodes": 2,
        "observed_source": OBSERVABLE_ATTACKER_IP,
        "observed_victim": "192.168.10.50",
        "observed_port": 80,
        "other_traffic_from_observed_source_in_interval": 0,
    },
    "wednesday-slowhttptest": {
        "events_matching_realigned_selector": 4_556,
        "windows_currently_unknown": 26,
        "episodes": 8,
        "observed_source": OBSERVABLE_ATTACKER_IP,
        "observed_victim": "192.168.10.50",
        "observed_port": 80,
        "other_traffic_from_observed_source_in_interval": 0,
    },
    "wednesday-goldeneye": {
        "events_matching_realigned_selector": 7_716,
        "windows_currently_unknown": 16,
        "episodes": 4,
        "observed_source": OBSERVABLE_ATTACKER_IP,
        "observed_victim": "192.168.10.50",
        "observed_port": 80,
        "other_traffic_from_observed_source_in_interval": 0,
    },
}


class M5PolicyV3Error(RuntimeError):
    """The v3 policy cannot be derived from the frozen v1 policy."""


def derive_m5_v3_manifest(v1_manifest: LabelManifest) -> LabelManifest:
    """Derive the additive v3 manifest from a frozen v1 manifest.

    Identical mechanics to v2, applied to a strictly larger rule set. Intervals,
    victims other than the promoted identity, ports, protocols, families,
    dispositions, ontology and timezone are carried over structurally.
    """
    payload = json.loads(v1_manifest.model_dump_json())

    present = {rule["rule_id"] for rule in payload["rules"]}
    missing = REALIGNED_RULE_IDS_V3 - present
    if missing:
        raise M5PolicyV3Error(f"frozen v1 policy lacks expected rules: {sorted(missing)}")

    realigned = 0
    for rule in payload["rules"]:
        if rule["rule_id"] not in REALIGNED_RULE_IDS_V3:
            continue
        selector = rule["selector"]
        if selector["mode"] != "role_constrained":
            raise M5PolicyV3Error(
                f"{rule['rule_id']} is not role_constrained; refusing to realign"
            )
        declared = set(selector["attacker_ips"])
        if not declared <= UNOBSERVABLE_ATTACKER_IPS:
            raise M5PolicyV3Error(
                f"{rule['rule_id']} declares unexpected attackers: {sorted(declared)}"
            )
        selector["attacker_ips"] = [OBSERVABLE_ATTACKER_IP]
        # Forced by EndpointSelector: attacker and victim roles must be disjoint.
        selector["victim_ips"] = [
            ip for ip in selector["victim_ips"] if ip != OBSERVABLE_ATTACKER_IP
        ]
        if not selector["victim_ips"]:
            raise M5PolicyV3Error(
                f"{rule['rule_id']} would have no victim left after realignment"
            )
        realigned += 1

    if realigned != len(REALIGNED_RULE_IDS_V3):
        raise M5PolicyV3Error(
            f"realigned {realigned} rules, expected {len(REALIGNED_RULE_IDS_V3)}"
        )

    payload["manifest_version"] = M5_V3_MANIFEST_VERSION
    payload["rule_version"] = M5_V3_RULE_VERSION
    return LabelManifest.model_validate_json(json.dumps(payload))


def load_m5_v3_manifest(
    repository_root: str | Path,
    v1_manifest_path: str | Path = CANONICAL_M5_V1_MANIFEST_PATH,
) -> LabelManifest:
    """Load the frozen v1 manifest and return its derived v3 counterpart."""
    root = Path(repository_root).resolve(strict=True)
    return derive_m5_v3_manifest(load_label_manifest(root / v1_manifest_path))


def load_m5_v3_ledger(
    repository_root: str | Path,
    v1_manifest_path: str | Path = CANONICAL_M5_V1_MANIFEST_PATH,
) -> LabelLedger:
    """Build a ``LabelLedger`` over the derived v3 policy, reusing v1 machinery."""
    return LabelLedger(load_m5_v3_manifest(repository_root, v1_manifest_path))


def policy_diff(
    v2_manifest: LabelManifest, v3_manifest: LabelManifest
) -> tuple[dict[str, object], ...]:
    """Per-rule diff between v2 and v3, so the correction is auditable."""
    v2_rules = {rule.rule_id: rule for rule in v2_manifest.rules}
    diff: list[dict[str, object]] = []
    for rule in v3_manifest.rules:
        before = v2_rules[rule.rule_id]
        attackers_v2 = tuple(str(x) for x in before.selector.attacker_ips)
        attackers_v3 = tuple(str(x) for x in rule.selector.attacker_ips)
        diff.append(
            {
                "rule_id": rule.rule_id,
                "changed_by_v3": attackers_v2 != attackers_v3,
                "attackers_v2": attackers_v2,
                "attackers_v3": attackers_v3,
                "victims_v2": tuple(str(x) for x in before.selector.victim_ips),
                "victims_v3": tuple(str(x) for x in rule.selector.victim_ips),
                "intervals_unchanged": before.intervals == rule.intervals,
                "ports_unchanged": (
                    before.selector.victim_ports == rule.selector.victim_ports
                ),
                "protocols_unchanged": before.selector.protocols == rule.selector.protocols,
                "disposition_unchanged": before.disposition == rule.disposition,
                "family_unchanged": before.attack_family == rule.attack_family,
                "subtype_unchanged": before.attack_subtype == rule.attack_subtype,
            }
        )
    return tuple(diff)


def verify_v3_is_additive(
    v1_manifest: LabelManifest,
    v2_manifest: LabelManifest,
    v3_manifest: LabelManifest,
) -> list[dict[str, object]]:
    """Prove v3 only extends the realignment and changes nothing else."""
    checks: list[dict[str, object]] = []

    def record(name: str, passed: bool, detail: object) -> None:
        checks.append({"check": name, "passed": bool(passed), "detail": detail})
        if not passed:
            raise M5PolicyV3Error(f"{name}: {detail}")

    record(
        "v3_realigns_exactly_the_v2_set_plus_three",
        REALIGNED_RULE_IDS_V3 == REALIGNED_RULE_IDS_V2 | COVERAGE_CORRECTION_RULE_IDS
        and len(COVERAGE_CORRECTION_RULE_IDS) == 3,
        sorted(COVERAGE_CORRECTION_RULE_IDS),
    )
    record(
        "v2_set_is_preserved_untouched",
        REALIGNED_RULE_IDS_V2 <= REALIGNED_RULE_IDS_V3,
        sorted(REALIGNED_RULE_IDS_V2),
    )
    record(
        "same_rule_count_as_v1",
        len(v1_manifest.rules) == len(v3_manifest.rules) == 16,
        len(v3_manifest.rules),
    )
    record(
        "no_rule_removed",
        {r.rule_id for r in v1_manifest.rules} == {r.rule_id for r in v3_manifest.rules},
        0,
    )
    diff = policy_diff(v2_manifest, v3_manifest)
    changed = {entry["rule_id"] for entry in diff if entry["changed_by_v3"]}
    record(
        "only_the_three_corrected_rules_differ_from_v2",
        changed == COVERAGE_CORRECTION_RULE_IDS,
        sorted(changed),
    )
    record(
        "intervals_ports_protocols_dispositions_families_unchanged",
        all(
            entry["intervals_unchanged"]
            and entry["ports_unchanged"]
            and entry["protocols_unchanged"]
            and entry["disposition_unchanged"]
            and entry["family_unchanged"]
            and entry["subtype_unchanged"]
            for entry in diff
        ),
        len(diff),
    )
    record(
        "ares_is_never_realigned",
        "friday-botnet-ares" not in REALIGNED_RULE_IDS_V3,
        DELIBERATELY_NOT_REALIGNED["friday-botnet-ares"],
    )
    record(
        "portscan_and_heartbleed_left_out_with_a_recorded_reason",
        "friday-portscan" not in REALIGNED_RULE_IDS_V3
        and "wednesday-heartbleed" not in REALIGNED_RULE_IDS_V3
        and "friday-portscan" in DELIBERATELY_NOT_REALIGNED
        and "wednesday-heartbleed" in DELIBERATELY_NOT_REALIGNED,
        ["friday-portscan", "wednesday-heartbleed"],
    )
    record(
        "thursday_rules_are_not_realigned",
        not any(r.startswith("thursday-") for r in REALIGNED_RULE_IDS_V3),
        "Thursday is absent from the canonical chain; its NAT behaviour is unverified",
    )
    return checks
