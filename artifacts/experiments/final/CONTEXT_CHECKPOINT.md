# CyberSentinel — context checkpoint

Reconstructed **from the artifacts, not from memory**, on 2026-08-17. Every value
below was read out of a published file or measured read-only against the databases.
Nothing was inferred. This file is the continuity reference for subsequent steps.

## Verification performed

Thirteen required items, all confirmed:

| # | Item | Verified value | Evidence |
|---|---|---|---|
1 | Frozen supervised population | 70 954 rows = **376 positives + 70 578 negatives** | `p1_dataset.csv` read; content digest recomputed |
2 | Five reference features | `event_count`, `source_packets_total`, `destination_packets_total`, `source_bytes_total`, `destination_bytes_total` | `p1_metrics.json` → `features`; identical in P2/P3/P4 |
3 | Validated labels | only `target_attack` 199, `known_other_attack` 177, `benign_reference` 70 578 | disposition inventory over the CSV |
4 | `unknown` / `ambiguous` handling | **0 rows of either** in the supervised population; they exist only in MB7 (216 / 127) and M6 (172 372 unknown) | CSV inventory + read-only MB7 query |
5 | Frozen P1 folds | 5 folds, leave-one-attack-type-out, test rows 13 951 / 14 045 / 14 124 / 14 770 / 14 064 | `p1_folds.json` |
6 | Group split unit | **attack type** (D3); benign negatives split by `sha256(entity_key) mod 5` (D4) | `p1_dataset.py` docstring + `build_folds` |
7 | Window-level bootstrap forbidden | `"any confidence interval computed at window level"` | `p1_metrics.json` → `forbidden_claims` |
8 | Episode-level bootstrap | 2 000 resamples, seed 0, per-fold `episode_bootstrap` with `ci_low`/`ci_high`/`episodes`/`point` | `p1_evaluation.py` constants + metrics |
9 | R11 | **major limitation, unchanged**: 5 types, 9 entities, **6 host pairs**, 1 `target_attack` pair, 47.07% of positives below benign density | `final_benchmark_metrics.json` → `risks.R11` |
10 | R1 | **NOT RESOLVED / no evidence of an effect on recall** | `final_benchmark_metrics.json` → `risks.R1` |
11 | `FORBIDDEN_COLUMNS` | **18 columns** enumerated | `p1_metrics.json` → `forbidden_columns` |
12 | Production / test separation | positives ← `cybersentinel.m6_canonical.feature_windows`; negatives ← `cybersentinel_test.mb6_canonical + mb7_canonical` | `p1_metrics.json` → `source_databases` |
13 | Zero PostgreSQL writes | `postgresql_writes = 0` in P1, P2, P3, P4 | all four metrics files |

### Digest reproduction (the decisive check)

Both canonical content digests were **recomputed from the published files alone**,
with no database access, and match exactly:

```
dataset content sha256  3d7436178da6960ee5effeb4bee85a0b6da5eead9d2babef3c72cb6b7ca9f20d  MATCH
folds   content sha256  e463ea7b0eb4985f51369dc3ae19c09821040675aa4b9f9689f8e02545fed95a  MATCH
```

Note the distinction that must not be confused: the **file** digest of
`p1_dataset.csv` is `e95aed00…` while its **content** digest is `3d743617…`. The
content digest is canonical and order-independent, computed over the logical rows
per `dataset_digest()`; the file digest is merely the bytes on disk. P2, P3 and P4
each record `p1_dataset_content_sha256 = 3d743617…`, so all four benchmarks are
provably bound to the same population.

## Immutable artifacts (file digests, first 16 hex)

| Artifact | Digest |
|---|---|
`p1/p1_dataset.csv` | `e95aed008d994510` |
`p1/p1_folds.json` | `57e688fd3da90911` |
`p1/p1_leakage_verification.json` | `9581b38af679ac4a` |
`p1/p1_metrics.json` | `2a51e618397c42b7` |
`p2/p2_metrics.json` | `67d2f60bc57d03bb` |
`p2/p2_matching.json` | `4685188b514af996` |
`p3/p3_metrics.json` | `a3e9f1c7175594c9` |
`p4/p4_metrics.json` | `3df92eda32d943b6` |
`final/final_benchmark_metrics.json` | `9954d0cb1b41134c` |
`final/FINAL_BENCHMARK_REPORT.md` | `344cb5b14e81aa64` |
`final/FEATURE_AUDIT_REPORT.md` | `2e472216aaa1eb19` |
`final/feature_audit_raw.json` | `29710b9c8af4f624` |

Plus 5 P1 models + 5 P1 prediction files, 5 P2 models + 5 P2 predictions, 1 P3
model + 1 P3 prediction file, 3 P4 models + 3 P4 predictions. **None may be
modified or deleted.**

Frozen upstream chain, all verified unchanged:

```
m3_v2_normalization_run.json                62426406249a96eb
m4_v2_materialization_run.json              6b4252a12c3de769
m6_v2_feature_window_run.json               273cd64335cc5300
mb3_monday_benign_normalization_run.json    5afd957ee2e41d18
mb4_monday_benign_materialization_run.json  52aec252884bdb90
mb6_monday_benign_feature_window_run.json   2f8bcde806cfe5c6
mb7_monday_benign_labeling_run.json         76d0fe7a97519175
```

## Database state (must remain exactly this)

```
cybersentinel      : m4_canonical.flow_end_events   1 353 467
                     m6_canonical.feature_windows     172 748
                     tables matching 'mb%'                  0
cybersentinel_test : mb4_canonical.flow_end_events    368 202
                     mb6_canonical.feature_windows     70 921
                     mb7_canonical.window_labels       70 921
                       benign_reference 70 578 · unknown 216 · ambiguous 127
```

## Ratified decisions in force

| ID | Decision |
|---|---|
D1 | Dataset materialised as **files**, never a PostgreSQL table. Zero DB writes. |
D2 | **Episode** = maximal run of consecutive 60 s windows sharing `(attack_type, entity_key)`; a gap > one window starts a new episode. |
D3 | **Positive folds = the attack types**, leave-one-type-out. |
D4 | **Negative folds** = `sha256(entity_key) mod fold_count`. No benign entity in both train and test. No randomness. |
D5 | **No feature transform** of any kind. |
D6 | `RandomForestClassifier(n_estimators=200, random_state=0, n_jobs=1)`. |
D7 | `class_weight=None`. Class weighting is rebalancing and is forbidden. |
D8 | Thresholds derived from **training negatives only**. |
D9 | **Episode-level** bootstrap, 2 000 resamples, seed 0. |
D10 | Per-fold metrics only; no aggregate that hides the botnet result. |
D11 | (P2) matched offsets drawn from **training** positives only. |
D12 | (P3) contiguous temporal benign split; `predict()` never used. |

Standing prohibitions: no sampling, SMOTE, cloning, augmentation, pseudo-labeling,
rebalancing or class weighting · no window-level bootstrap · never convert `unknown`
or `ambiguous` to `benign` · never call alerts on `unknown` a FPR, false positive or
error · R11 must remain visible, never engineered away · no new features beyond the
authorised budget without explicit authorisation.

## Principal results P1–P4

Episode recall at the 1% training-FPR operating point:

| Attack type | Test win. | Ep. | P1 | P2 | P3 | P4 |
|---|---|---|---|---|---|---|
`botnet/ares` | 177 | 40 | **0.075** | 0.150 | **0.000** | 0.050 |
`brute_force/ftp_patator` | 61 | 1 | 1.000 | 1.000 | 1.000 | 1.000 |
`brute_force/ssh_patator` | 60 | 9 | 0.111 | 0.111 | 0.111 | 1.000 ⚠️ artefact |
`ddos/loit` | 42 | 2 | 1.000 | 1.000 | 0.500 | deleted |
`dos/hulk` | 36 | 2 | 1.000 | 1.000 | 1.000 | deleted |

Botnet ROC-AUC: **0.5037** (P1) · 0.5195 (P2) · 0.5035 (P4) — chance everywhere.
P1 botnet 95% CI **[0.000, 0.175]** on 40 episodes: the pre-registered reference.

`ftp_patator` ROC-AUC collapses **0.9866 → 0.6037** in P4 on an **identical** test
set, because `ddos/loit` and `dos/hulk` left training. Detection depends on volume
signatures being present in training.

P3 measured FPR on held-out known benign 0.015925 against a target of 1%
(within-day non-stationarity, 1.6×); alert rate on unlabelled `unknown` 0.014585 —
**a different quantity, not a false-positive rate**.

## Confidence tiers

**Robust (3)** — botnet blindness; no convincing hour-of-day effect on recall;
dependence on volume signatures in training.

**Partially supported (4)** — `ftp_patator` (1 episode), `ssh_patator` (missed at
episode level; P4 rise is an exclusion artefact), `ddos/loit` and `dos/hulk` (2
episodes each, untested by P4).

**Not demonstrable (5)** — generalisation to new attacks, to new hosts; behaviour
versus host-pair memorisation; true performance on `unknown`; definitive absence of
a temporal confounder.

## Next authorised step

**P5/E — feature budget extension.** Single hypothesis: the five volume features
cannot express low-intensity C2 behaviour, but the data contain temporal beaconing
signal.

- Arm A = the five current features, P1 reference.
- Arm B = the five current features **+ `duration_mean`, `interarrival_mean`,
  `interarrival_cv`**. Nothing else changes.
- Pre-registered primary endpoint: **`botnet/ares` episode-level recall**, against
  0.075 [0.000, 0.175] on 40 episodes.
- Frozen P1 folds reused strictly identically: same population, same labels, same
  partitioning, same test sets, same evaluation unit.
- Mandatory before training: explicit missingness policy; documentation that
  `duration_mean` is computed on `FlowEnd` and is therefore not strictly online; a
  re-run leakage audit on the three new features; R11 retained.

Not authorised without new ratification: XGBoost final model, tuning, threshold
calibration, production dataset construction, deployment, model serving.
