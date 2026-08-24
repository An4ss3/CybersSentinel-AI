"""P6 analysis — descriptive discrimination and the R11 identity tests. Read-only.

Nothing here validates a feature. ``screening_auc`` is a *screening* statistic and a
high value is a trigger to hunt for leakage, not evidence of usefulness.

The decisive test in this module is ``identity_dependence``. A feature that is
genuinely about C2 *behaviour* should separate every botnet entity from benign in a
similar way, and should be poor at telling the botnet entities apart from each
other. A feature that separates the botnet entities from one another is encoding
*who they are*, not *what they do*, and cannot be called SAFE under R11.
"""
from __future__ import annotations

from itertools import combinations
import math
import statistics
from typing import Any, Final

import numpy as np
from sklearn.metrics import roc_auc_score


#: A feature separating the classes at or above this is treated as suspect and is
#: investigated for leakage rather than accepted.
NEAR_PERFECT_AUC: Final[float] = 0.98

#: Above this, a feature can tell botnet entities apart well enough that its signal
#: cannot be distinguished from entity identity with this evidence.
IDENTITY_AUC_CEILING: Final[float] = 0.75


def _clean(values: list[float]) -> list[float]:
    return [v for v in values if not math.isnan(v)]


def describe(values: list[float]) -> dict[str, Any]:
    """Distribution summary, not just a mean. Quantiles are reported explicitly."""
    present = _clean(values)
    total = len(values)
    if not present:
        return {"n": total, "available": 0, "missing_rate": 1.0}
    ordered = sorted(present)

    def q(p: float) -> float:
        if len(ordered) == 1:
            return ordered[0]
        position = p * (len(ordered) - 1)
        low = int(math.floor(position))
        high = min(low + 1, len(ordered) - 1)
        weight = position - low
        return ordered[low] * (1 - weight) + ordered[high] * weight

    return {
        "n": total,
        "available": len(present),
        "missing_rate": round(1 - len(present) / total, 6),
        "min": round(ordered[0], 6),
        "p05": round(q(0.05), 6),
        "p25": round(q(0.25), 6),
        "median": round(q(0.50), 6),
        "p75": round(q(0.75), 6),
        "p95": round(q(0.95), 6),
        "max": round(ordered[-1], 6),
        "mean": round(statistics.fmean(present), 6),
        "stdev": round(statistics.pstdev(present), 6) if len(present) > 1 else 0.0,
        "distinct": len({round(v, 9) for v in present}),
    }


def screening_auc(positive: list[float], negative: list[float]) -> float | None:
    """Rank-based AUC on the rows where the feature is defined. Screening only.

    Rows with a missing value are dropped rather than imputed, so the statistic
    describes the feature where it exists and never smuggles in the missingness
    pattern, which is a function of ``event_count``.
    """
    pos, neg = _clean(positive), _clean(negative)
    if not pos or not neg:
        return None
    scores = np.asarray(pos + neg, dtype=float)
    labels = np.asarray([1] * len(pos) + [0] * len(neg), dtype=int)
    if len({round(float(v), 12) for v in scores}) == 1:
        return 0.5
    return float(roc_auc_score(labels, scores))


def directed_auc(positive: list[float], negative: list[float]) -> dict[str, Any]:
    """AUC plus the direction that makes it >= 0.5, so tables stay readable."""
    raw = screening_auc(positive, negative)
    if raw is None:
        return {"auc": None, "oriented_auc": None, "direction": None}
    return {
        "auc": round(raw, 6),
        "oriented_auc": round(max(raw, 1 - raw), 6),
        "direction": "higher on attack" if raw >= 0.5 else "higher on benign",
    }


def identity_dependence(groups: dict[str, list[float]]) -> dict[str, Any]:
    """Can the feature tell the attack entities apart from each other?

    Every pair of entities is scored against every other. A high value means the
    feature carries entity identity, so its apparent C2 signal cannot be separated
    from provenance with this evidence. This is the R11 test.
    """
    usable = {name: _clean(v) for name, v in groups.items()}
    usable = {name: v for name, v in usable.items() if v}
    if len(usable) < 2:
        return {
            "pairwise_auc": {},
            "max_pairwise_auc": None,
            "mean_pairwise_auc": None,
            "entities_compared": len(usable),
            "verdict": "not testable: fewer than two entities carry a value",
        }
    pairwise: dict[str, float] = {}
    for left, right in combinations(sorted(usable), 2):
        raw = screening_auc(usable[left], usable[right])
        if raw is not None:
            pairwise[f"{left} vs {right}"] = round(max(raw, 1 - raw), 6)
    if not pairwise:
        return {
            "pairwise_auc": {},
            "max_pairwise_auc": None,
            "mean_pairwise_auc": None,
            "entities_compared": len(usable),
            "verdict": "not testable",
        }
    worst = max(pairwise.values())
    return {
        "pairwise_auc": pairwise,
        "max_pairwise_auc": worst,
        "mean_pairwise_auc": round(statistics.fmean(pairwise.values()), 6),
        "entities_compared": len(usable),
        "verdict": (
            "separates entities from each other: signal cannot be distinguished "
            "from identity or provenance"
            if worst >= IDENTITY_AUC_CEILING
            else "entities look alike on this feature, consistent with shared "
            "behaviour rather than identity"
        ),
    }


def consistency_across_entities(
    per_entity_auc: dict[str, float | None],
) -> dict[str, Any]:
    """Is the botnet signal carried by every entity, or by one?

    A behavioural feature should separate each entity from benign to a similar
    degree. A feature that works on one entity and not the others is describing
    that entity, not the malware family.
    """
    values = [v for v in per_entity_auc.values() if v is not None]
    if not values:
        return {"entities": 0, "verdict": "no entity carries a usable value"}
    above = sum(1 for v in values if v >= 0.65)
    return {
        "entities": len(values),
        "min_auc": round(min(values), 6),
        "max_auc": round(max(values), 6),
        "spread": round(max(values) - min(values), 6),
        "entities_with_auc_at_least_0_65": above,
        "carried_by_all_entities": above == len(values),
        "verdict": (
            f"{above} of {len(values)} entities reach 0.65; spread "
            f"{max(values) - min(values):.4f}"
        ),
    }


#: A reference AUC inside 0.5 +/- this band carries no directional information, so
#: a sign comparison against it is undetermined rather than agreeing or disagreeing.
SIGN_INDETERMINATE_BAND: Final[float] = 0.05


def transfer_sign_agreement(
    botnet_direction: str | None,
    target_direction: str | None,
    target_auc: float | None = None,
    botnet_auc: float | None = None,
) -> dict[str, Any]:
    """Do the botnet and the volumetric attacks deviate from benign the same way?

    This is the property that decides whether leave-one-attack-type-out can
    transfer at all. A model trained on the volumetric attacks learns the sign of
    each feature from *them*. If the botnet deviates from benign in the **opposite**
    direction, the learned sign actively pushes botnet windows towards benign, and
    more training data cannot fix it.

    A comparison is only meaningful when **both** sides carry a direction. An AUC of
    0.5109 is chance; calling it "higher on attack" and concluding disagreement
    would be an artefact of floating-point noise, not a finding. Whenever either
    side sits inside ``SIGN_INDETERMINATE_BAND`` of 0.5 the verdict is
    ``undetermined``, which is a reason for NEEDS_REVIEW rather than for SAFE.
    """
    if botnet_direction is None or target_direction is None:
        return {"agrees": None, "verdict": "not testable on one of the classes"}

    reference_flat = (
        target_auc is not None and abs(target_auc - 0.5) < SIGN_INDETERMINATE_BAND
    )
    subject_flat = (
        botnet_auc is not None and abs(botnet_auc - 0.5) < SIGN_INDETERMINATE_BAND
    )
    if reference_flat or subject_flat:
        which = []
        if reference_flat:
            which.append(f"volumetric reference AUC {target_auc:.4f}")
        if subject_flat:
            which.append(f"botnet AUC {botnet_auc:.4f}")
        return {
            "botnet_direction": botnet_direction,
            "target_attack_direction": target_direction,
            "botnet_auc": botnet_auc,
            "target_attack_auc": target_auc,
            "agrees": None,
            "undetermined": True,
            "verdict": (
                "undetermined: " + " and ".join(which) + " is within "
                f"{SIGN_INDETERMINATE_BAND} of chance, so its direction carries no "
                "information and transferability cannot be established"
            ),
        }

    agrees = botnet_direction == target_direction
    return {
        "botnet_direction": botnet_direction,
        "target_attack_direction": target_direction,
        "botnet_auc": botnet_auc,
        "target_attack_auc": target_auc,
        "agrees": agrees,
        "undetermined": False,
        "verdict": (
            "same sign as the volumetric attacks, so a model trained on them "
            "learns a sign that also helps on the botnet"
            if agrees
            else "OPPOSITE sign to the volumetric attacks: a model trained on them "
            "learns a sign that pushes botnet windows towards benign"
        ),
    }


def spearman(left: list[float], right: list[float]) -> float | None:
    """Rank correlation on the rows where both values are defined."""
    pairs = [
        (a, b)
        for a, b in zip(left, right)
        if not math.isnan(a) and not math.isnan(b)
    ]
    if len(pairs) < 3:
        return None
    a_values = [p[0] for p in pairs]
    b_values = [p[1] for p in pairs]
    if len(set(a_values)) == 1 or len(set(b_values)) == 1:
        return None

    def rank(values: list[float]) -> list[float]:
        order = sorted(range(len(values)), key=lambda i: values[i])
        ranks = [0.0] * len(values)
        position = 0
        while position < len(order):
            end = position
            while (
                end + 1 < len(order)
                and values[order[end + 1]] == values[order[position]]
            ):
                end += 1
            shared = (position + end) / 2.0 + 1.0
            for index in range(position, end + 1):
                ranks[order[index]] = shared
            position = end + 1
        return ranks

    ra, rb = rank(a_values), rank(b_values)
    mean_a, mean_b = statistics.fmean(ra), statistics.fmean(rb)
    numerator = sum((x - mean_a) * (y - mean_b) for x, y in zip(ra, rb))
    denominator = math.sqrt(
        sum((x - mean_a) ** 2 for x in ra) * sum((y - mean_b) ** 2 for y in rb)
    )
    if denominator == 0:
        return None
    return round(numerator / denominator, 6)


def redundancy(
    values_by_feature: dict[str, list[float]], ceiling: float = 0.95
) -> dict[str, Any]:
    """Find candidates that restate one another, so a minimal set can be chosen."""
    names = sorted(values_by_feature)
    pairs: dict[str, float] = {}
    for left, right in combinations(names, 2):
        rho = spearman(values_by_feature[left], values_by_feature[right])
        if rho is not None:
            pairs[f"{left} ~ {right}"] = rho
    duplicates = {k: v for k, v in pairs.items() if abs(v) >= ceiling}
    return {
        "pairwise_spearman": pairs,
        "ceiling": ceiling,
        "redundant_pairs": duplicates,
        "verdict": (
            f"{len(duplicates)} pair(s) at |rho| >= {ceiling} restate one another"
            if duplicates
            else "no pair reaches the redundancy ceiling"
        ),
    }
def episode_coverage(
    episode_values: dict[str, list[float]], benign: list[float], upper: bool
) -> dict[str, Any]:
    """How many episodes contain a window beyond the benign 99th percentile.

    Descriptive only. This is not a recall, no threshold is calibrated, and no
    model is involved: it answers whether the feature is extreme on many episodes
    or on a few.
    """
    reference = _clean(benign)
    if not reference:
        return {"episodes": 0, "verdict": "no benign reference available"}
    ordered = sorted(reference)
    index = int(0.99 * (len(ordered) - 1))
    cut = ordered[index] if upper else sorted(reference)[int(0.01 * (len(ordered) - 1))]
    flagged = 0
    for values in episode_values.values():
        present = _clean(values)
        if not present:
            continue
        if upper and max(present) > cut:
            flagged += 1
        elif not upper and min(present) < cut:
            flagged += 1
    return {
        "episodes": len(episode_values),
        "benign_cut": round(cut, 6),
        "side": "above benign p99" if upper else "below benign p01",
        "episodes_touching_the_tail": flagged,
        "fraction": round(flagged / len(episode_values), 6) if episode_values else 0.0,
    }
