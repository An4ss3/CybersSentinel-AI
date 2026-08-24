# P6 — Targeted behavioural feature audit

**Question.** Which behavioural information already present in the data actually
distinguishes low-intensity Ares C2 from benign traffic, without introducing
leakage or a proxy for identity?

**Answer.** One family holds exploitable signal: **payload repetition**, in family
D. Two candidates express it and they are the same information (Spearman
**−1.0000**). The one that survives is **`distinct_payload_ratio`**, because it is
defined on **100%** of windows against 41.33% for its mirror. Everything else is at
chance on the botnet, dependent on entity identity, of undetermined
transferability, or withheld by standing constraint.

No model was trained, no feature was adopted, no threshold was calibrated, no label
was touched, and zero PostgreSQL writes occurred. `FORBIDDEN_COLUMNS` is unchanged
at 18 columns. P1–P5 artifacts are untouched.

## Populations audited

| | Count |
|---|---|
`botnet/ares` windows | 177 |
botnet entities | **5** |
botnet host pairs | **5** |
botnet episodes | **40** |
`target_attack` windows (volumetric reference) | 199 |
`benign_reference` windows | 70 578 |

Candidates: **22** across five families. Screening AUC is **descriptive only** — not
a model performance, and no generalisation follows from it. A near-perfect value
triggers a leakage hunt rather than acceptance.

## Columns deliberately excluded, and why

| Excluded | Reason |
|---|---|
`source_ip`, `destination_ip`, `source_port`, `destination_port`, `transport`, `service` | identity or a direct proxy (constraint 8) |
`conversation_id` | per-flow unique id; counting distinct values only restates `event_count` |
`physical_line_number` | position in the capture file, a capture artefact |
`record_available_time`, `ingested_at`, `persisted_at` | pipeline clocks, absolute, not properties of the traffic |
all provenance columns | already in `FORBIDDEN_COLUMNS` |

`event_start_time` is used only to assign the window bucket M6/MB6 already assigned,
and thereafter as **relative offsets**. No absolute timestamp reaches any feature.

## The mechanical explanation of P1 through P5

For each feature the audit measured whether the botnet deviates from benign in the
**same direction** as the volumetric attacks. This decides whether
leave-one-attack-type-out can transfer at all: the model learns each sign from the
volumetric attacks, so a feature on which the botnet deviates the *other* way is not
merely uninformative — it is **harmful**.

Family A, the ratified budget:

| Feature | Botnet AUC | Volumetric AUC | Sign |
|---|---|---|---|
`event_count` | 0.6956 ↑attack | 0.9594 ↑attack | agrees |
`source_packets_total` | **0.5307** ≈ chance | 0.9696 ↑attack | agrees, botnet at chance |
`destination_packets_total` | **0.5372** ≈ chance | 0.9733 ↑attack | agrees, botnet at chance |
`source_bytes_total` | **0.5123** ≈ chance | 0.8718 ↑attack | agrees, botnet at chance |
`destination_bytes_total` | **0.2830 ↑BENIGN** | 0.8902 ↑attack | **OPPOSITE** |

Three of five are at chance on the botnet, and the one with real magnitude points the
**wrong way**: `destination_bytes_total` median is **640** on the botnet against
**4 367** benign and **137 250** on `target_attack`. A model trained on the
volumetric attacks learns "high means attack"; the botnet is *low*. **This is why P1
returned ROC-AUC 0.5037** — now measured, not conjectured.

The same test accounts for P5:

| P5 addition | Botnet AUC | Volumetric AUC | Sign |
|---|---|---|---|
`interarrival_mean` | 0.9146 ↑attack | 0.6169 ↑attack | **agrees** |
`duration_mean` | 0.1758 ↑benign | **0.5053 ≈ chance** | undetermined |
`interarrival_cv` | 0.1254 ↑benign | 0.6592 ↑attack | **OPPOSITE** |

P5 added one helpful feature, one uninformative one and **one actively harmful one**,
then measured the combination. That is a precise account of why its botnet ROC-AUC
moved only 0.5037 → 0.5119.

## Two corrections made to this audit's own method

Both were caught by the audit's own guards, and both changed a conclusion.

**1. A chance-level reference carries no direction.** The sign test initially
compared directions unconditionally. It classified `bytes_per_packet_destination` as
*disagreeing* on a reference AUC of **0.5109**, and `bytes_per_second` as *agreeing*
on **0.5052**. Neither number has a direction. The test now returns **undetermined**
whenever either side lies within 0.05 of 0.5 — a reason for NEEDS_REVIEW, never for
SAFE. `bytes_per_second` lost its SAFE status under the corrected rule.

**2. AUCs measured on different defined subpopulations are not comparable.** The
redundancy tie-break initially kept the *stronger screener* of a redundant pair. That
kept `payload_repeat_ratio` (AUC 0.8546) over `distinct_payload_ratio` (0.7632) —
but `payload_repeat_ratio` requires `event_count >= 2` and is therefore scored only
on the **41.33%** of windows where it exists, while its mirror is defined everywhere.
Preferring it meant preferring a statistic computed on an easier subset. The
tie-break is now **availability first**, and screening strength decides only when
availability is materially equal. **This reversed the surviving feature.**

## Final candidate table

| Feature | Family | Botnet signal | Missingness (botnet / benign) | Leakage | Host dependency | Online availability | Status |
|---|---|---|---|---|---|---|---|
`event_count` | A | 0.6956 ↑attack | 0.000 / 0.000 | none found | idAUC 0.6303, 4/5 entities | online | REFERENCE |
`source_packets_total` | A | 0.5307 ≈ chance | 0.000 / 0.000 | none found | 0/5 entities | online | REFERENCE |
`destination_packets_total` | A | 0.5372 ≈ chance | 0.000 / 0.000 | none found | 0/5 entities | online | REFERENCE |
`source_bytes_total` | A | 0.5123 ≈ chance | 0.000 / 0.000 | none found | 0/5 entities | online | REFERENCE |
`destination_bytes_total` | A | 0.7170 **↑benign, opposite sign** | 0.000 / 0.000 | none found | idAUC 0.6257, 5/5 | online | REFERENCE |
`duration_mean` | B | 0.8242 ↑benign | 0.000 / 0.000 | none found | idAUC 0.6563, 5/5 | requires completed flows | NEEDS_REVIEW |
`interarrival_mean` | B | **0.9146 ↑attack, sign agrees** | 0.311 / 0.587 | none found | **idAUC 0.5797, 5/5** | online | NEEDS_REVIEW |
`interarrival_cv` | B | 0.8746 **↑benign, opposite sign** | 0.418 / 0.791 | none found | idAUC 0.6827, 5/5 | online | NEEDS_REVIEW |
`bytes_per_packet_destination` | C | **0.8852 ↑benign** | 0.000 / 0.035 | none found | **idAUC 0.5698, spread 0.0028** | online | NEEDS_REVIEW |
`byte_direction_ratio` | C | 0.9002 ↑attack | 0.000 / 0.076 | none found | **idAUC 0.7914 — identity** | online | NEEDS_REVIEW |
`idle_ratio` | D | 0.7849 ↑attack | 0.000 / 0.000 | none found | idAUC 0.6101, 5/5 | requires completed flows | NEEDS_REVIEW |
`duty_cycle` | D | 0.7908 ↑benign, opposite | 0.000 / 0.000 | none found | idAUC 0.6101, 5/5 | requires completed flows | NEEDS_REVIEW |
`max_concurrency` | D | 0.6676 ↑benign, opposite | 0.000 / 0.000 | none found | **idAUC 0.5000**, 5/5 | requires completed flows | NEEDS_REVIEW |
`active_span_ratio` | D | 0.5549 ≈ chance | 0.000 / 0.000 | none found | 0/5 entities | requires completed flows | NEEDS_REVIEW |
`bytes_per_second` | D | 0.7913 ↑attack, **undetermined** | 0.000 / 0.000 | none found | idAUC 0.7233 | requires completed flows | NEEDS_REVIEW |
`packets_per_second` | D | 0.8726 ↑attack | 0.000 / 0.000 | none found | **idAUC 0.7792 — identity** | requires completed flows | NEEDS_REVIEW |
`packets_per_flow` | D | 0.6879 ↑benign, opposite | 0.000 / 0.000 | none found | idAUC 0.5704, 5/5 | online | NEEDS_REVIEW |
`response_ratio` | D | 0.5180 ≈ chance | 0.000 / 0.000 | none found | 0/5 entities | online | NEEDS_REVIEW |
**`distinct_payload_ratio`** | **D** | **0.7632 ↑benign, sign agrees** | **0.000 / 0.000** | **none found** | **idAUC 0.6528, 5/5** | **online** | **SAFE — kept** |
`payload_repeat_ratio` | D | 0.8546 ↑attack, sign agrees | **0.311 / 0.587** | none found | idAUC 0.5505, 5/5 | online | SAFE — dropped as redundant |
`state_sf_ratio` | E | 0.5604 ≈ chance | 0.000 / 0.000 | not assessed | constant 1.0 on botnet | requires completed flows | NEEDS_REVIEW |
`state_distinct_count` | E | 0.5153 ≈ chance | 0.000 / 0.000 | not assessed | 0/5 entities | requires completed flows | NEEDS_REVIEW |

"idAUC" is the largest pairwise AUC for telling two botnet **entities** apart. High
means the feature carries *who is speaking* rather than *what they do*; the ceiling
is 0.75.

## Family verdict table

| Famille | Signal trouvé ? | Qualité | R11 | Peut entrer dans XGBoost ? |
|---|---|---|---|---|
**A — volume** | no | 3 of 5 at chance on the botnet; the strongest points the **wrong way** | not carried per-entity for 4 of 5 members | no — reference budget only |
**B — temporal** | partly | best screen 0.9146 (`interarrival_mean`); one member has an **opposite sign**, one is undetermined | `interarrival_mean` looks behavioural: idAUC 0.5797, all 5 entities | no — already tested in P5, which did not confirm; withheld by **constraint, not by measurement** |
**C — direction** | partly | best screen 0.9002; `bytes_per_packet_destination` has the cleanest R11 profile in the audit | `byte_direction_ratio` fails at idAUC **0.7914**; `bytes_per_packet_destination` passes R11 but transferability is **undetermined** | no — not yet |
**D — flow behaviour** | **yes** | payload repetition: `distinct_payload_ratio` 0.7632, sign agrees, zero missingness | behaviour: all 5 entities separate from benign, spread 0.1511 | **yes — `distinct_payload_ratio` only** |
**E — states / flags** | no | 0.5604 and 0.5153, both at chance | withheld by standing constraint 10; `state_sf_ratio` is constant 1.0 across all botnet windows | no — withheld, and the measurement gives no reason to revisit |

## The surviving feature

**`distinct_payload_ratio`** = `|distinct (source_bytes, destination_bytes) pairs| / event_count`.

| Property | Value |
|---|---|
Definition domain | every window with at least one flow — **zero missingness on both classes** |
Median botnet / benign / volumetric | **0.5000** / **1.0000** / 0.0625 |
Botnet quartiles | p05 0.1429 · p25 0.2308 · median 0.5000 · p75 1.0 |
Benign quartiles | p05 0.5000 · p25 1.0 · median 1.0 · p75 1.0 |
Screening AUC botnet vs benign | 0.7632, higher on benign |
Sign agreement with volumetric attacks | **agrees** (volumetric AUC 0.0392, also higher on benign) |
Per-entity AUC | 0.6827 to 0.8337, **all 5 entities ≥ 0.65**, spread 0.1511 |
Identity dependence | max pairwise **0.6528**, mean 0.5680 — below the 0.75 ceiling |
Online availability | **online** — byte counters at window close, no completed flow needed |
Episodes reaching the benign tail | **6 of 40** |

**Why it is credible.** It measures how many of a window's flows carry *distinct*
request/response byte-size pairs. A benign window's median is exactly **1.0**: every
flow has its own byte signature. The botnet median is **0.5**, meaning half its flows
repeat a signature already seen — which is what a beacon does. The signal is present
on all five botnet entities, the feature is poor at telling those entities apart, and
it agrees in sign with the volumetric attacks, so a model trained without the botnet
can still learn a sign that helps on it.

**Its weaknesses, stated plainly.** Its screening AUC, 0.7632, is the **weakest** of
the candidates that survived any screen — it was kept for availability and
transferability, not for strength. Its per-entity spread, 0.1511, is wider than that
of `bytes_per_packet_destination` (0.0028), so the entities are less alike on it than
on the feature that was withheld. And its benign distribution is heavily massed at
1.0, so much of the discrimination comes from a single dense value.

## The limitation that constrains every candidate

Counting episodes containing at least one window beyond the benign 99th percentile
in the discriminating direction:

| Feature | Episodes reaching the tail |
|---|---|
`source_bytes_total` | **15 of 40** |
`interarrival_cv` | **14 of 40** |
`distinct_payload_ratio` | 6 of 40 |
`payload_repeat_ratio` | 2 of 40 |
every other audited feature | **0 of 40** |

Two observations follow, and they cut against each other.

The features that reach the tail most often are **not** the ones that discriminate
overall: `source_bytes_total` touches 15 episodes while screening at 0.5123, i.e.
chance. A handful of botnet windows are extreme on raw volume while the bulk is not.
So tail behaviour and overall separation are different properties here, and neither
one alone identifies a usable feature.

For the surviving feature the separation lives mainly in the **bulk** of the
distribution, not the extreme: 6 episodes of 40 reach the benign tail. A
high-specificity single-feature threshold will therefore not catch this botnet, which
is consistent with everything P1 through P5 measured. Any future benchmark must
expect a **combination of weak signals**, not a decisive one.

## R11

Unchanged and binding. The botnet is **5 entities reaching one destination**,
`205.174.165.73`. Every per-entity AUC in this audit is therefore also a per-host-pair
AUC — the two tables are identical, because each botnet entity is its own pair. The
audit can show that the five behave alike; it cannot show that a sixth would.

The `target_attack` reference used for the sign test is itself a **single host pair**,
`172.16.0.1 → 192.168.10.50`. So "agrees with the volumetric attacks" means "agrees
with one attacker against one victim". That limits the sign test exactly as much as it
limits everything else, and it is why family E stays withheld.

Nothing here licenses a claim about Ares in general, still less about C2 in general.
No feature can create diversity the data does not contain.

## Smallest justified set for the next benchmark

```
distinct_payload_ratio
```

**One feature.** It is the only candidate that simultaneously separates botnet from
benign above chance, carries the signal on all five entities, fails to distinguish
those entities from one another, agrees in sign with the volumetric attacks so
leave-one-type-out can transfer it, is computable online, has **zero missingness**,
and is not a restatement of a feature already in the budget.

`payload_repeat_ratio` is excluded as its exact mirror (ρ = −1.0000) with far worse
availability.

If a second feature is wanted later, the two best-argued candidates are
`bytes_per_packet_destination` — the cleanest R11 profile measured, per-entity spread
0.0028 — and `interarrival_mean`, which passes every measured test. Both need a
decision that is not mine to take: the first requires a way to establish
transferability when the volumetric reference sits at chance, and the second requires
the P5 constraint to be revisited, noting that P5 bundled it with a feature of
opposite sign.

## Not done, deliberately

No XGBoost. No tuning. No model selection. No new performance benchmark. No feature
adopted into any budget. This audit answers which family holds exploitable
behavioural signal and stops there.

## Artifacts

| File | Digest |
|---|---|
`p6_feature_audit.json` content | `5f4acbf089f5d2a6…` |
`p6_feature_audit.json` file | `d028e8476df66c28` |
`p6_feature_distributions.csv` | `4a2ac96eefe36f3d` |

Three earlier P6 outputs were replaced during this session, all created minutes
earlier and none frozen: `43c952b383555f10` lacked the sign-agreement and redundancy
analyses; `32443466bc55bc20` used the uncorrected sign test; `26ac1a3fc0331970` used
the uncorrected redundancy tie-break. No P1–P5 artifact was modified.
