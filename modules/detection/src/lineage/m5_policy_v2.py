"""Additive M5 v2 label policy: observable attacker identity realignment.

Why this module exists
---------------------
The frozen M5 v1 policy names the *logical* CICIDS2017 attacker addresses
(``205.174.165.x``). The M2 replay captured traffic from a vantage point behind
network address translation, so in M4 every attack flow originates from the
gateway identity ``172.16.0.1``. Read-only diagnostics established that the
attacks are fully present, aimed at the declared victim, on the declared port
and protocol, inside the declared interval — only the attacker identity differs.

Verified evidence (flows inside the exact v1 interval, all from ``172.16.0.1``
towards ``192.168.10.50``):

===================  =====  ==========
family               port   flows
===================  =====  ==========
wednesday-hulk       80     158 781
friday-ddos-loit     any    95 683
tuesday-ftp-patator  21     3 951
tuesday-ssh-patator  22     2 511
===================  =====  ==========

What this module changes
-----------------------
Exactly one thing: the observable attacker identity of four rules. The v2
manifest is *derived programmatically* from the frozen v1 manifest, so intervals,
victims, ports, protocols, attack families, target profiles, ontology, default
disposition and timezone are carried over structurally rather than retyped.

One consequence is forced by the frozen contract rather than chosen here:
``EndpointSelector`` requires attacker and victim role sets to be disjoint, so
promoting ``172.16.0.1`` to attacker removes it from those rules' victim sets.
Every remaining victim is preserved. The direction stays consistent with the M4
vantage point: source is the attacker, destination is the victim; ``172.16.0.1``
is never declared a victim.

What this module never does
---------------------------
It does not modify M5 v1, its YAML manifest, ``LabelLedger``,
``exact_time_labeling_v2``, M6, or any upstream artefact. It creates no table
and writes nothing. Labelling remains sidecar-only, and ``unknown`` is never
converted to benign.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Final

from modules.detection.src.lineage.exact_time_labeling_v2 import (
    ExactTimeLabelAdapterV2,
)
from modules.detection.src.lineage.labeling import LabelLedger, load_label_manifest
from modules.detection.src.schemas.labels import LabelManifest


#: The only attacker identity observable from the M2 replay vantage point.
OBSERVABLE_ATTACKER_IP: Final[str] = "172.16.0.1"

#: The four attack families whose attacker identity is realigned in v2.
REALIGNED_RULE_IDS: Final[frozenset[str]] = frozenset(
    {
        "tuesday-ftp-patator",
        "tuesday-ssh-patator",
        "wednesday-hulk",
        "friday-ddos-loit",
    }
)

#: Logical attacker addresses that are unreachable from the M4 vantage point.
UNOBSERVABLE_ATTACKER_IPS: Final[frozenset[str]] = frozenset(
    {
        "205.174.165.69",
        "205.174.165.70",
        "205.174.165.71",
        "205.174.165.73",
    }
)

M5_V2_MANIFEST_VERSION: Final[str] = "2.0.0"
M5_V2_RULE_VERSION: Final[str] = "2.0.0"

CANONICAL_M5_V1_MANIFEST_PATH: Final[str] = "datasets/manifests/cicids2017_labels.yaml"


class M5PolicyV2Error(RuntimeError):
    """The v2 policy cannot be derived from the frozen v1 policy."""


def derive_m5_v2_manifest(v1_manifest: LabelManifest) -> LabelManifest:
    """Derive the additive v2 manifest from a frozen v1 manifest.

    Only the attacker identity of :data:`REALIGNED_RULE_IDS` changes, plus the
    contract-mandated removal of that identity from those rules' victim sets and
    the version bump that distinguishes the two policies in provenance.
    """
    payload = json.loads(v1_manifest.model_dump_json())

    present_ids = {rule["rule_id"] for rule in payload["rules"]}
    missing = REALIGNED_RULE_IDS - present_ids
    if missing:
        raise M5PolicyV2Error(
            f"frozen v1 policy lacks expected rules: {sorted(missing)}"
        )

    realigned = 0
    for rule in payload["rules"]:
        if rule["rule_id"] not in REALIGNED_RULE_IDS:
            continue
        selector = rule["selector"]
        if selector["mode"] != "role_constrained":
            raise M5PolicyV2Error(
                f"{rule['rule_id']} is not role_constrained; refusing to realign"
            )
        declared = set(selector["attacker_ips"])
        if not declared <= UNOBSERVABLE_ATTACKER_IPS:
            raise M5PolicyV2Error(
                f"{rule['rule_id']} declares unexpected attackers: {sorted(declared)}"
            )

        selector["attacker_ips"] = [OBSERVABLE_ATTACKER_IP]
        # Forced by EndpointSelector: attacker and victim roles must be disjoint.
        selector["victim_ips"] = [
            ip for ip in selector["victim_ips"] if ip != OBSERVABLE_ATTACKER_IP
        ]
        if not selector["victim_ips"]:
            raise M5PolicyV2Error(
                f"{rule['rule_id']} would have no victim left after realignment"
            )
        realigned += 1

    if realigned != len(REALIGNED_RULE_IDS):
        raise M5PolicyV2Error(
            f"realigned {realigned} rules, expected {len(REALIGNED_RULE_IDS)}"
        )

    payload["manifest_version"] = M5_V2_MANIFEST_VERSION
    payload["rule_version"] = M5_V2_RULE_VERSION
    return LabelManifest.model_validate_json(json.dumps(payload))


def load_m5_v2_manifest(
    repository_root: str | Path,
    v1_manifest_path: str | Path = CANONICAL_M5_V1_MANIFEST_PATH,
) -> LabelManifest:
    """Load the frozen v1 manifest and return its derived v2 counterpart."""
    root = Path(repository_root).resolve(strict=True)
    return derive_m5_v2_manifest(load_label_manifest(root / v1_manifest_path))


def load_m5_v2_ledger(
    repository_root: str | Path,
    v1_manifest_path: str | Path = CANONICAL_M5_V1_MANIFEST_PATH,
) -> LabelLedger:
    """Build a ``LabelLedger`` over the derived v2 policy.

    ``LabelLedger`` is reused unchanged: it compiles the intervals, detects rule
    overlaps, and produces all label provenance, so v2 labels carry the same
    provenance semantics as v1 with a distinct manifest hash and rule version.
    """
    return LabelLedger(load_m5_v2_manifest(repository_root, v1_manifest_path))


def build_m5_v2_adapter(
    repository_root: str | Path,
    v1_manifest_path: str | Path = CANONICAL_M5_V1_MANIFEST_PATH,
) -> ExactTimeLabelAdapterV2:
    """Return the existing exact-time adapter bound to the v2 policy."""
    return ExactTimeLabelAdapterV2(
        load_m5_v2_ledger(repository_root, v1_manifest_path)
    )


def realignment_summary(
    v1_manifest: LabelManifest, v2_manifest: LabelManifest
) -> tuple[dict[str, object], ...]:
    """Return a per-rule diff of the two policies, for audit and reporting."""
    v1_rules = {rule.rule_id: rule for rule in v1_manifest.rules}
    summary: list[dict[str, object]] = []
    for rule in v2_manifest.rules:
        before = v1_rules[rule.rule_id]
        summary.append(
            {
                "rule_id": rule.rule_id,
                "realigned": rule.rule_id in REALIGNED_RULE_IDS,
                "attackers_v1": tuple(str(x) for x in before.selector.attacker_ips),
                "attackers_v2": tuple(str(x) for x in rule.selector.attacker_ips),
                "victims_v1": tuple(str(x) for x in before.selector.victim_ips),
                "victims_v2": tuple(str(x) for x in rule.selector.victim_ips),
                "intervals_unchanged": before.intervals == rule.intervals,
                "ports_unchanged": (
                    before.selector.victim_ports == rule.selector.victim_ports
                ),
                "protocols_unchanged": (
                    before.selector.protocols == rule.selector.protocols
                ),
                "disposition_unchanged": before.disposition == rule.disposition,
                "family_unchanged": (
                    before.attack_family == rule.attack_family
                    and before.attack_subtype == rule.attack_subtype
                ),
                "targets_unchanged": (
                    before.target_profiles == rule.target_profiles
                ),
            }
        )
    return tuple(summary)
