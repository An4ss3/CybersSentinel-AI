# CyberSentinel — context checkpoint after P6

Reconstructed **from the artifacts**, not from conversational memory, on
2026-08-18. Supersedes `final/CONTEXT_CHECKPOINT.md`, which predates P5 and P6.
This file is the continuity reference for the next step.

## Verification performed this session

| Item | Verified value |
|---|---|
Docker daemon | was stopped; restarted, ready in 5 s, version 29.6.1 |
`cybersentinel` | `m4_canonical.flow_end_events` **1 353 467**, `m6_canonical.feature_windows` **172 748**, tables matching `mb%` **0** |
`cybersentinel_test` | `mb4_canonical.flow_end_events` **368 202**, `mb6_canonical.feature_windows` **70 921**, `mb7_canonical.window_labels` **70 921** |
MB7 dispositions | `benign_reference` **70 578** · `unknown` **216** · `ambiguous` **127** — unchanged |
P1–P5 artifacts | all file digests match the previous checkpoint; see below |

Every database connection used `SET default_transaction_read_only = on`.

## Frozen historical artifacts — do not modify

| Artifact | File digest |
|---|---|
`p1/p1_dataset.csv` | `e95aed008d994510` |
`p1/p1_folds.json` | `57e688fd3da90911` |
`p1/p1_leakage_verification.json` | `9581b38af679ac4a` |
`p1/p1_metrics.json` | `2a51e618397c42b7` |
`p1/P1_REPORT.md` | `7a559ecee8a3c3ee` |
`p2/p2_metrics.json` | `67d2f60bc57d03bb` |
`p2/p2_matching.json` | `4685188b514af996` |
`p2/P2_REPORT.md` | `d169a50306487ec3` |
`p3/p3_metrics.json` | `a3e9f1c7175594c9` |
`p3/P3_REPORT.md` | `3ef43116df20e2d5` |
`p4/p4_metrics.json` | `3df92eda32d943b6` |
`p4/P4_REPORT.md` | `7d681e125c52672c` |
`p5/p5_metrics.json` | `87055c8b14623581` |
`p5/P5_REPORT.md` | `d1184a5240c2965d` |
`final/final_benchmark_metrics.json` | `9954d0cb1b41134c` |
`final/FINAL_BENCHMARK_REPORT.md` | `344cb5b14e81aa64` |
`final/FEATURE_AUDIT_REPORT.md` | `2e472216aaa1eb19` |
`final/feature_audit_raw.json` | `29710b9c8af4f624` |

Plus all P1/P2/P3/P4 prediction CSVs and model files. Canonical chain unchanged:
`m3` `62426406249a96eb`, `m4` `6b4252a12c3de769`, `m6` `273cd64335cc5300`,
`mb3` `5afd957ee2e41d18`, `mb4` `52aec252884bdb90`, `mb6` `2f8bcde806cfe5c6`,
`mb7` `76d0fe7a97519175`.

## New P6 artifacts

| Artifact | Digest |
|---|---|
`p6/p6_feature_audit.json` content | `5f4acbf089f5d2a6` |
`p6/p6_feature_audit.json` file | `d028e8476df66c28` |
`p6/p6_feature_distributions.csv` | `4a2ac96eefe36f3d` |
`p6/P6_FEATURE_AUDIT.md` | see repository |

## Reference invariants, unchanged

Population 70 954 rows = **376 positives** (199 `target_attack` + 177
`known_other_attack`) + **70 578** `benign_reference`. Zero `unknown`, zero
`ambiguous` in supervision. Dataset content digest
`3d7436178da6960ee5effeb4bee85a0b6da5eead9d2babef3c72cb6b7ca9f20d`; folds content
digest `e463ea7b0eb4985f51369dc3ae19c09821040675aa4b9f9689f8e02545fed95a`.

Decisions D1–D16 remain in force. `FORBIDDEN_COLUMNS` is **18 columns, unchanged by
P6**. Episode = maximal run of consecutive 60 s windows sharing
`(attack_type, entity_key)`. Bootstrap is **episode level only**, 2 000 resamples,
seed 0; window-level intervals remain forbidden.

## Results so far

| Benchmark | Botnet episode recall | Botnet ROC-AUC | Verdict |
|---|---|---|---|
P1/A supervised | 0.075 (3/40) | 0.5037 | volume features insufficient |
P2/B temporal-matched | 0.150 | 0.5195 | no clear hour-of-day effect on recall |
P3/D anomaly, benign only | **0.000** | — | totally blind to low-intensity C2 |
P4/C conservative | 0.050 | 0.5035 | blindness robust; volumetric results depend on volumetric attacks in training |
P5/E +3 temporal features | 0.150 (6/40) | 0.5119 | **NOT CONFIRMED**: CIs overlap, ROC at chance, FPR rose |

## What P6 established

**One family holds signal: payload repetition (family D).** Two candidates express
it and they are the same information, Spearman **−1.0000**.

**Surviving feature: `distinct_payload_ratio`** = `|distinct (source_bytes,
destination_bytes) pairs| / event_count`, defined for every window with at least one
flow.

| Property | Value |
|---|---|
| Missingness | **0.000 botnet / 0.000 benign** |
| Median botnet / benign / volumetric | **0.5000** / **1.0000** / 0.0625 |
| Screening AUC | 0.7632, higher on benign |
| Sign vs volumetric attacks | **agrees** (volumetric AUC 0.0392, also higher on benign) |
| Per-entity AUC | 0.6827–0.8337, all 5 entities ≥ 0.65, spread 0.1511 |
| Identity dependence | max pairwise **0.6528**, mean 0.5680 |
| Online | yes |
| Episodes reaching benign tail | 6 of 40 |

`payload_repeat_ratio` is its mirror and screens **higher** (0.8546) but requires
`event_count >= 2`, so it is defined on only **41.33%** of windows. It was dropped:
two AUCs measured on different defined subpopulations are not comparable, and the
tie-break is availability first.

**Smallest justified set: `distinct_payload_ratio` alone.**

Its weaknesses are recorded: it is the weakest screener among the survivors, its
per-entity spread (0.1511) is wider than that of the withheld
`bytes_per_packet_destination` (0.0028), and its benign distribution is heavily
massed at 1.0.

### The mechanical explanation of P1–P5, now measured

A feature only transfers under leave-one-attack-type-out if the botnet deviates from
benign in the **same direction** as the volumetric attacks, because the model learns
each sign from them.

In family A, three of five features are at chance on the botnet (0.5123, 0.5307,
0.5372) and `destination_bytes_total` points the **opposite way** — botnet AUC 0.2830
"higher on benign" against volumetric 0.8902 "higher on attack"; medians 640 botnet,
4 367 benign, 137 250 volumetric. **That is why P1 returned ROC 0.5037.**

In P5's three additions, `interarrival_mean` agrees, `duration_mean` is undetermined,
and `interarrival_cv` **actively disagrees**. P5 measured one helpful, one
uninformative and one harmful feature in combination.

### The limitation that constrains everything

Episodes containing a window beyond the benign 99th percentile in the discriminating
direction: `source_bytes_total` **15 of 40**, `interarrival_cv` **14 of 40**,
`distinct_payload_ratio` 6 of 40, `payload_repeat_ratio` 2 of 40, and **0 of 40** for
the other 18 candidates.

Two facts cut against each other. The best tail reacher, `source_bytes_total`,
screens at **0.5123**, i.e. chance — a few botnet windows are extreme on raw volume
while the bulk is not. So tail reach and overall separation are different properties
and neither alone identifies a usable feature. For the surviving feature the
separation lives mainly in the **bulk** of the distribution. A high-specificity
single-feature threshold cannot catch this botnet, and any future benchmark must
expect a **combination of weak signals**.

### R11, unchanged

The botnet is 5 entities reaching **one** destination `205.174.165.73`. The
volumetric reference used for the sign test is itself **one** host pair
`172.16.0.1 → 192.168.10.50`. Nothing in P6 licenses a claim about Ares in general
or C2 in general.

## Withheld, with reasons

| Candidate | Why not SAFE |
|---|---|
`interarrival_mean` | passes **every measured test** (0.9146, idAUC 0.5797, 5/5 entities, sign agrees); withheld only because P5 already tested it — a **constraint, not a measurement** |
`bytes_per_packet_destination` | cleanest R11 profile in the audit (per-entity spread **0.0028**, idAUC 0.5698) but transferability **undetermined**: the volumetric reference is at 0.5109, i.e. chance |
`byte_direction_ratio` | identity dependence **0.7914**, above the 0.75 ceiling |
`packets_per_second` | identity dependence **0.7792** |
family E (`state_sf_ratio`, `state_distinct_count`) | withheld by standing constraint 10; also at chance (0.5604, 0.5153) and `state_sf_ratio` is constant 1.0 on botnet |

## Next step — requires ratification, not yet authorised

Not done and not to be started without explicit approval: XGBoost, tuning, model
selection, threshold calibration, any new performance benchmark, production dataset
construction, deployment.

Two decisions are open and are **not** mine to take:

1. Whether `interarrival_mean` may be reconsidered despite the P5 constraint, given
   that P5 bundled it with a feature of opposite sign.
2. How to establish transferability for `bytes_per_packet_destination` when the
   volumetric reference sits at chance — the current evidence cannot settle it.
