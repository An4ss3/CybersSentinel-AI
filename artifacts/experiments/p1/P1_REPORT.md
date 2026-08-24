# P1/A — Supervised leave-one-attack-type-out benchmark

Executed 2026-08-17. Zero PostgreSQL writes. The M and MB chains were read only
and are byte-identical afterwards.

## What this benchmark measures

Whether five volume features, computed over 60-second tumbling windows, separate
the CICIDS2017 attacks present in M6 from the Monday benign traffic labelled by
MB-LABEL — **and whether that ability transfers to an attack type absent from
training**. Each of the five folds holds out one entire attack type.

It measures nothing about attacks, hosts or days not present in this evidence.

## Population

| | Windows | Entities | Episodes | Events/window |
|---|---|---|---|---|
Positives (M6 attack) | 376 | 9 | 54 | — |
Negatives (MB-LABEL `benign_reference`) | 70 578 | 27 715 | — | 5.202 |
**Total** | **70 954** | | | |

Imbalance 1:187.7. `unknown` and `ambiguous` were excluded from supervision at
both levels and appear nowhere in the dataset.

Features, exactly five, untransformed: `event_count`, `source_packets_total`,
`destination_packets_total`, `source_bytes_total`, `destination_bytes_total`.

## Results per attack type

| Held-out type | Test pos | Episodes | **ROC-AUC** | **PR-AUC** | Window recall @1% | **Episode recall @1%** | 95% CI | Test FPR |
|---|---|---|---|---|---|---|---|---|
`botnet/ares` | 177 | 40 | **0.5037** | **0.0135** | 0.017 | **0.075** | [0.000, 0.175] | 0.0096 |
`brute_force/ftp_patator` | 61 | 1 | 0.9866 | 0.3007 | 0.984 | 1.000 | [1.000, 1.000] | 0.0122 |
`brute_force/ssh_patator` | 60 | 9 | 0.9279 | 0.3541 | 0.867 | **0.111** | [0.000, 0.333] | 0.0233 |
`ddos/loit` | 42 | 2 | 0.9972 | 0.5919 | 1.000 | 1.000 | [1.000, 1.000] | 0.0248 |
`dos/hulk` | 36 | 2 | 0.8842 | 0.5552 | 0.778 | 1.000 | [1.000, 1.000] | 0.0232 |

**Pooled episode recall: 0.167, 95% CI [0.074, 0.278], over 54 episodes.**

Thresholds were calibrated on **training negatives only**, at a 1% target
false-positive rate. No test observation influenced an operating point.

## Three findings

### 1. The botnet blindness was predicted arithmetically and observed exactly

`botnet/ares` produces 736 events across 177 windows — **4.158 events per
window, below the benign class's 5.202**. Every admitted feature is a volume
measure, so the fold was expected to fail before any model was trained.

Observed **ROC-AUC 0.5037**: indistinguishable from chance. PR-AUC 0.0135 against
a base rate of 0.0127, i.e. essentially no lift. This is a property of the feature
budget, not a defect of the protocol, and it concerns **47.1% of all positives**.

### 2. Window-level recall systematically overstates detection

`brute_force/ssh_patator`: window recall **0.867** but episode recall **0.111**.
52 of 60 windows are detected — yet only 1 of 9 episodes. One large episode is
caught while eight small ones are missed entirely, and the window count is
dominated by the large one.

Reporting window recall alone would have claimed 87% detection where the
operationally meaningful figure is 11%. This vindicates episode-level reporting
and the prohibition on window-level bootstrap.

### 3. The default 0.5 threshold is unusable

With no class weighting, recall at threshold 0.5 is **0.000** for `botnet/ares`,
`ftp_patator` and `ssh_patator`; 0.452 for `ddos/loit`; 0.500 for `dos/hulk`. Any
report using the default threshold would have concluded the model detects nothing
for three of five types. The calibrated operating points are the meaningful ones.

## A methodological defect found and corrected during this run

The first P1 execution produced `observed_test_fpr = 1.0` on four of five folds,
with episode recall 1.0 everywhere and a pooled bootstrap of 1.0 [1.0, 1.0].

Cause: with a 1:187.7 imbalance and `class_weight=None`, the forest scores the
overwhelming majority of training negatives at exactly 0.0. `quantile(0.99)` of
that distribution is 0.0, and `score >= 0.0` flags every row. The operating point
was degenerate — "alert on everything" — not a result.

The selector now chooses the smallest candidate threshold drawn from the observed
scores such that the achieved training false-positive rate is at or below target,
and it returns the achieved rate so any gap is visible. The defective
`p1_metrics.json` (`c052b81d…`) was deleted and republished; the dataset, folds,
predictions and models were unaffected and retain their original digests.
`test_threshold_handles_a_degenerate_score_distribution` is the regression test.

## Leakage verification

All five folds pass, automatically, with zero failures: no shared window id, no
shared attack type, no shared episode, no shared benign entity, and both train and
test positives non-empty in every fold. Benign folds are assigned by
`sha256(entity_key) mod 5`, so no benign entity crosses train and test, with no
randomness involved.

## Conservative decisions, taken without further ratification

| | Decision | Reason |
|---|---|---|
D1 | dataset materialised as files, never a PostgreSQL table | zero database writes; sidesteps the M6/MB6 cross-database question without moving data |
D2 | episode = maximal run of consecutive 60 s windows sharing `(attack_type, entity_key)` | consecutive windows of one attack are slices of one event |
D3 | positive folds = the five attack types | the only grouping that also groups episodes |
D4 | negative folds = `sha256(entity_key) mod 5` | no benign entity crosses train/test; no randomness |
D5 | no feature transform | features handed to the model exactly as stored |
D6 | `RandomForestClassifier(n_estimators=200, random_state=0, n_jobs=1)` | scale-invariant, reproducible, no hyper-parameter search |
D7 | `class_weight=None` | weighting is rebalancing, which is forbidden |
D8 | thresholds from training negatives only | no test positive may influence an operating point |
D9 | bootstrap over episodes, 2 000 resamples, seed 0 | window-level bootstrap would treat autocorrelated slices as independent |
D10 | metrics per fold only | no aggregate may hide the botnet result |

## Limitations

**R11 — major limitation, benchmark possible.** 5 attack types, 9 entities, 6 host
pairs, 54 episodes. All 199 `target_attack` windows originate from the single host
pair `172.16.0.1 → 192.168.10.50`, differing only by service. The four volumetric
folds therefore test four mechanics of the same attacker against the same victim;
only the botnet fold interrogates different host pairs, and it is the fold the
features cannot win. **This benchmark cannot separate behaviour detection from
host-pair memorisation.**

**R1 — not resolved.** Day-level channels were excluded by column, but the residual
effect on learning remains a hypothesis until P2 runs the temporal-matched ablation
on these identical folds.

## Permitted and forbidden claims

**Permitted**: on this dataset, these features detect `ddos/loit`, `dos/hulk`,
`ftp_patator` and partially `ssh_patator`, and do not detect `botnet/ares`; the
false-alert rate at each stated threshold, measured on 70 578 benign windows;
episode-level recall as k out of the episodes present in the fold.

**Forbidden**: any claim of generalisation to unseen attacks, hosts or days; any
confidence interval computed at window level; model comparison on differences
narrower than the episode bootstrap; any description of alerts on `unknown`
windows as false positives.

## Targeted threshold verification (2026-08-17, post-freeze control)

### The selector, stated precisely

```python
train_scores = model.predict_proba(x_train)[:, 1]     # in-sample, training rows
train_negative_scores = train_scores[y_train == 0]    # training NEGATIVES only
threshold, achieved = threshold_at_train_fpr(train_negative_scores, target)
```

Inside the selector, `candidates = np.unique(train_negative_scores)`. **"Observed
scores" therefore means: the model's predicted probability for each training
negative row, and nothing else.** The candidate set is drawn exclusively from the
training partition's negative rows. One sentinel candidate just above the maximum
is appended so a threshold that flags nothing always exists. The selector walks
the candidates in ascending order and returns the first one whose achieved rate
`mean(train_negative_scores >= t)` is at or below target, together with that
achieved rate.

`threshold_at_train_fpr` receives exactly one data array, verified by AST
inspection of the call site: `['train_negative_scores', 'target']`. Its signature
admits no other array. **No test positive and no test negative can reach it.**

### Per-fold operating points

| Held-out type | Train neg. | Target | Threshold | Achieved train FPR | Train FP | Test neg. | **Measured test FPR** | Test FP | ratio |
|---|---|---|---|---|---|---|---|---|---|
`botnet/ares` | 56 804 | 1% | 0.0050 | 0.005052 | 287 | 13 774 | 0.009583 | 132 | 0.96× |
`botnet/ares` | 56 804 | 0.1% | 0.0250 | 0.000757 | 43 | 13 774 | 0.001742 | 24 | 1.74× |
`ftp_patator` | 56 594 | 1% | 0.0100 | 0.004735 | 268 | 13 984 | 0.012157 | 170 | 1.22× |
`ftp_patator` | 56 594 | 0.1% | 0.0400 | 0.000883 | 50 | 13 984 | 0.002288 | 32 | 2.29× |
`ssh_patator` | 56 514 | 1% | 0.0050 | 0.009626 | 544 | 14 064 | 0.023251 | 327 | 2.33× |
`ssh_patator` | 56 514 | 0.1% | 0.0350 | 0.000902 | 51 | 14 064 | 0.002346 | 33 | 2.35× |
`ddos/loit` | 55 850 | 1% | 0.0050 | 0.009167 | 512 | 14 728 | 0.024783 | 365 | 2.48× |
`ddos/loit` | 55 850 | 0.1% | 0.0350 | 0.000931 | 52 | 14 728 | 0.008012 | 118 | **8.01×** |
`dos/hulk` | 56 550 | 1% | 0.0050 | 0.009620 | 544 | 14 028 | 0.023168 | 325 | 2.32× |
`dos/hulk` | 56 550 | 0.1% | 0.0350 | 0.000778 | 44 | 14 028 | 0.002709 | 38 | 2.71× |

### A calibration bias this control exposes

The threshold is train-only, so there is **no leakage**. But it is calibrated on
**in-sample** scores: the forest was fitted on those very rows and has partly
memorised them, so training negatives score artificially low, the threshold lands
too low, and the false-positive rate on unseen negatives comes out **0.96× to
8.01× the target**. The worst case is `ddos/loit` at the 0.1% target: 8.01×.

This is a property of in-sample calibration, not of leakage, and it is **reported
rather than corrected**, because correcting it would require out-of-bag scores or
a held-out calibration split — a protocol change that was not ratified. It applies
**identically to P1 and P2**, so the A/B comparison of recall remains valid: both
sides carry the same bias. Any absolute false-alert rate quoted from P1 must be
read as the measured test FPR column, never as the target.

### Freshness and provenance of the published results

- **No degenerate result survives.** A scan of every operating point for
  `achieved_train_fpr >= 0.999` or `observed_test_fpr >= 0.999` returns **none**.
  The old run's signature was `observed_test_fpr = 1.0` on four folds; it is absent.
- **`achieved_train_fpr` is present in all ten operating points.** That field did
  not exist in the degenerate run's schema, so its presence everywhere proves the
  file was produced entirely by the corrected code.
- **The bootstrap uses the corrected protocol's final predictions.** Recomputing
  episode recall independently from the published `p1_predictions_fold*.csv` and
  the published thresholds reproduces every published `episode_recall` and
  `window_recall` to within 1e-12, and re-running `episode_bootstrap_recall` on
  those recomputed detections returns the published bootstrap objects exactly.

| Type | Threshold | Published ep. recall | Recomputed | Published win. recall | Recomputed |
|---|---|---|---|---|---|
`botnet/ares` | 0.0050 | 0.075000 | 0.075000 | 0.016949 | 0.016949 |
`ftp_patator` | 0.0100 | 1.000000 | 1.000000 | 0.983607 | 0.983607 |
`ssh_patator` | 0.0050 | 0.111111 | 0.111111 | 0.866667 | 0.866667 |
`ddos/loit` | 0.0050 | 1.000000 | 1.000000 | 1.000000 | 1.000000 |
`dos/hulk` | 0.0050 | 1.000000 | 1.000000 | 0.777778 | 0.777778 |

**P1 is frozen.**

## Artifacts

| File | SHA-256 |
|---|---|
`p1_dataset.csv` | `e95aed008d994510e4c649c287feb8fe8f49a785bec144d7e83aa15804b6c062` |
`p1_folds.json` | `57e688fd3da90911707d7a172c161686d852094121eda1ac49e0221fc0529fa1` |
`p1_leakage_verification.json` | `9581b38af679ac4a0d89b9c8f69a2049bef4ad067613028415e8e585441f3b1e` |
`p1_metrics.json` | `2a51e618397c42b742a289216d3cd89b255c4ccd96a8f985a5ad1c5c4783a447` |

Content digests, order-independent and reproducible:
dataset `3d7436178da6960ee5effeb4bee85a0b6da5eead9d2babef3c72cb6b7ca9f20d`,
folds `e463ea7b0eb4985f51369dc3ae19c09821040675aa4b9f9689f8e02545fed95a`.

Five models `p1_model_fold{0..4}.joblib` and five prediction files
`p1_predictions_fold{0..4}.csv` accompany them.
