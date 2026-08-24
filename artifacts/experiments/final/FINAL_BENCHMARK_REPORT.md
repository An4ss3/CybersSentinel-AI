# CyberSentinel — Final consolidated benchmark report

Consolidates P1/A, P2/B, P3/D and P4/C. **No benchmark was re-executed**, no label
was modified, no artifact was deleted, and no PostgreSQL statement was issued.

Fifteen cross-benchmark consistency checks pass, including: all four designs start
from the frozen population `3d743617…`; P2 reuses the frozen folds `e463ea7b…`;
every P2 test set is identical to P1's; P3 fitted zero positives and zero
`unknown`; and all four declare zero database writes.

## Population

| | Value |
|---|---|
Positives (M6 attack windows) | 376 |
Negatives (MB-LABEL `benign_reference`) | 70 578 |
Imbalance | 1:187.7 |
Attack types | **5** |
Attack entities | **9** |
Attack host pairs | **6** |
Attack episodes | **54** |
Benign entities | 27 715 |
**Share of positives below benign density** | **47.1%** |

Feature budget, five, untransformed: `event_count`, `source_packets_total`,
`destination_packets_total`, `source_bytes_total`, `destination_bytes_total`.

---

## P1/A — Supervised leave-one-attack-type-out

Thresholds calibrated on training negatives only, 1% target.

| Attack type | Test win. | Ep. | Window recall | **Episode recall** | 95% CI | ROC-AUC | PR-AUC | Test FPR |
|---|---|---|---|---|---|---|---|---|
`botnet/ares` | 177 | 40 | 0.017 | **0.075** | [0.000, 0.175] | **0.5037** | **0.0135** | 0.0096 |
`brute_force/ftp_patator` | 61 | 1 | 0.984 | 1.000 | [1.000, 1.000] | 0.9866 | 0.3007 | 0.0122 |
`brute_force/ssh_patator` | 60 | 9 | 0.867 | **0.111** | [0.000, 0.333] | 0.9279 | 0.3541 | 0.0233 |
`ddos/loit` | 42 | 2 | 1.000 | 1.000 | [1.000, 1.000] | 0.9972 | 0.5919 | 0.0248 |
`dos/hulk` | 36 | 2 | 0.778 | 1.000 | [1.000, 1.000] | 0.8842 | 0.5552 | 0.0232 |

**Pooled episode recall 0.167 [0.074, 0.278] over 54 episodes.**

**Conclusion on leave-one-attack-type-out transfer.** Transfer succeeds for the
four volumetric types and fails completely for the one low-intensity type. Two
caveats bound the reading: `ftp_patator`, `ddos/loit` and `dos/hulk` are each
measured on one or two episodes, so their perfect episode recall carries almost no
information about variability; and `ssh_patator` exposes a systematic reporting
trap — window recall 0.867 against episode recall 0.111, because one large episode
is detected while eight small ones are missed. Window-level recall overstates
detection wherever episode sizes are unequal.

---

## P2/B — Temporal-matched ablation of R1

Only the composition of training negatives changed. Test sets byte-identical.
Retention of training negatives: 26.1% to 40.1%, reducing imbalance from
166–285:1 down to 47–95:1.

| Attack type | Episode recall P1 → P2 | Δ | 95% CI P1 | 95% CI P2 | ROC P1 → P2 | PR P1 → P2 |
|---|---|---|---|---|---|---|
`botnet/ares` | 0.075 → 0.150 | +0.075 | [0.000, 0.175] | [0.050, 0.250] | 0.5037 → 0.5195 | 0.014 → 0.014 |
`brute_force/ftp_patator` | 1.000 → 1.000 | **0.000** | [1.000, 1.000] | [1.000, 1.000] | 0.9866 → 0.9734 | 0.301 → 0.135 |
`brute_force/ssh_patator` | 0.111 → 0.111 | **0.000** | [0.000, 0.333] | [0.000, 0.333] | 0.9279 → 0.9175 | 0.354 → 0.152 |
`ddos/loit` | 1.000 → 1.000 | **0.000** | [1.000, 1.000] | [1.000, 1.000] | 0.9972 → 0.9947 | 0.592 → 0.382 |
`dos/hulk` | 1.000 → 1.000 | **0.000** | [1.000, 1.000] | [1.000, 1.000] | 0.8842 → 0.9770 | 0.555 → 0.518 |

**Pooled 0.167 [0.074, 0.278] → 0.222 [0.111, 0.333].** Intervals overlap across
most of their range.

**Effect of the hour-of-day control**: none on the primary metric. Episode recall is
identical on four of five types. The single movement, `botnet/ares` +0.075, is three
episodes of forty becoming six of forty, with overlapping intervals and a ROC-AUC
still at chance.

**Conclusion on R1**: **no evidence that P1's recall depended on the time-of-day
confounder.**

**The PR-AUC decline is not attributable to R1.** PR-AUC fell on three folds
(`ftp_patator` 0.301 → 0.135, `ssh_patator` 0.354 → 0.152, `ddos/loit` 0.592 →
0.382) on **identical test sets**, so the change originates entirely in training.
P2 trains on 26–40% of P1's negatives, confined to attack-coincident offsets, so
the model sees a narrower slice of benign behaviour and ranks the full benign
distribution less well. **Composition and size of the negative set changed
together**, and isolating the covariate effect would require subsampling P1's
negatives to equal size, which is forbidden. The confound is reported, not resolved:
the recall comparison is meaningful, the PR-AUC comparison is not.

---

## P3/D — Unsupervised anomaly detector, Monday benign only

`IsolationForest`, fitted on 35 289 benign windows. Zero positives, zero `unknown`,
zero `ambiguous` in fitting, calibration or any hyper-parameter choice. Contiguous
temporal split: 35 289 fit / 17 644 calibration / 17 645 measurement.

| | Target 1% | Target 0.1% |
|---|---|---|
Threshold (calibration block only) | 0.729957 | 0.828481 |
Achieved rate on calibration block | 0.009975 | 0.000964 |
**Measured false-positive rate**, held-out benign | 281/17 645 = **0.015925** | 30/17 645 = **0.001700** |
**Alert rate on unlabelled `unknown`** | 2 514/172 372 = **0.014585** | 293/172 372 = **0.001700** |
Attack window recall | 0.4468 | 0.1436 |
Attack episode recall | 0.0926 [0.0185, 0.1667] | 0.0556 [0.0000, 0.1296] |

| Attack type | Window recall @1% | Episode recall @1% | 95% CI |
|---|---|---|---|
`botnet/ares` | **0.0000** | **0.0000** | [0.000, 0.000] |
`brute_force/ftp_patator` | 0.9672 | 1.0000 | [1.000, 1.000] |
`brute_force/ssh_patator` | 0.8667 | 0.1111 | [0.000, 0.333] |
`ddos/loit` | 0.5000 | 0.5000 | [0.000, 1.000] |
`dos/hulk` | 1.0000 | 1.0000 | [1.000, 1.000] |

**Difference between threshold target and observed rate.** Target 1% produced
0.9975% on the calibration block and **1.59% on the measurement block**, a 1.6×
overshoot. The calibration block was **not** fitted, so this is not memorisation.

**Conclusion on within-day non-stationarity.** The last quarter of the Monday
differs from the third quarter enough to move the false-positive rate by 60%. Any
threshold calibrated on one part of a day should be expected to drift on another
part of the same day.

**On the `unknown` population.** The alert rate on unlabelled windows is 1.46%
against a measured false-positive rate of 1.59% on known benign. **These are not
the same quantity.** A flag on a `benign_reference` window is a genuine false
positive because the label comes from the frozen M5 v1 rule. A flag on an
`unknown` window is uninterpretable: it may be a true positive no rule covers.
The similarity of the two rates is consistent with several explanations this
benchmark cannot distinguish, and **is not evidence that `unknown` is benign**.
Recall that 359 M6 `unknown` windows carry `172.16.0.1` as source entity.

---

## P4/C — Conservative robustness control

Excluding the two multi-family entities removes 86 windows. **It also deletes
`ddos/loit` and `dos/hulk` entirely**, because those families are carried only by
`172.16.0.1|192.168.10.50|tcp|none` and `|tcp|http`. P4 therefore has 3 attack
types, 290 positives, 7 entities, 42 episodes and 3 folds.

| Attack type | Test win. P1 → P4 | Ep. P1 → P4 | Episode recall | ROC P1 → P4 | PR P1 → P4 | Same test set |
|---|---|---|---|---|---|---|
`botnet/ares` | 177 → 177 | 40 → 40 | 0.075 → 0.050 | 0.5037 → 0.5035 | 0.0135 → 0.0077 | **yes** |
`brute_force/ftp_patator` | 61 → 61 | 1 → 1 | 1.000 → 1.000 | **0.9866 → 0.6037** | 0.3007 → 0.0089 | **yes** |
`brute_force/ssh_patator` | 60 → **52** | 9 → **1** | 0.111 → 1.000 | 0.9279 → 0.7153 | 0.3541 → 0.0187 | **no** |
`ddos/loit` | — | — | **deleted** | — | — | — |
`dos/hulk` | — | — | **deleted** | — | — | — |

**What robustness was actually tested.** Only the `botnet/ares` conclusion: same
test set, ROC-AUC 0.5037 → 0.5035. It survives.

**The ssh test set is not identical** — 52 windows on 1 episode against P1's 60 on
9. The eight missed episodes belonged to the excluded entity. **P4 removed
precisely the hard cases and kept the easy one.** The apparent rise from 0.111 to
1.000 measures the exclusion, not the model, and **is not an improvement.**

**`ddos/loit` and `dos/hulk` are not validated by P4** — it deletes them. Their
robustness to entity multi-family contamination remains untested, and cannot be
tested by this control.

**The ftp ROC collapse is evidence of dependence on volume signal in training.**
On an **identical** test set of 61 windows, ROC-AUC falls from 0.9866 to 0.6037 and
PR-AUC from 0.3007 to 0.0089. The only change is that `ddos/loit` and `dos/hulk`
left the training set. Those were the very high-volume attacks teaching the model
"large volume means attack". Their removal collapses discrimination.

---

## Central scientific conclusion

> With the five volume features currently admitted, the system detects some attacks
> when similar volume signatures are present in training, but it is **blind to
> low-intensity Ares C2 traffic, which is 47.1% of the positives**. P1's strongest
> volumetric results therefore **do not** demonstrate a general ability to detect
> unknown attacks: P4 shows that at least part of that performance depends on other
> volumetric attacks being present in training.

---

## Conclusions by confidence level

### Robust

1. **`botnet/ares` is undetectable by the five volume features.** ROC-AUC 0.5037
   (P1), 0.5195 (P2), 0.5035 (P4) — chance in every supervised design — and exactly
   **0.0000** window and episode recall in P3 at both thresholds. Predicted
   arithmetically before any training: 4.158 events per window against 5.202 for
   the benign class.
2. **No convincing evidence of an hour-of-day effect on recall.** P2 left episode
   recall unchanged on four of five types on identical test sets.
3. **Detection depends on volume signatures present in training.** Removing
   `ddos/loit` and `dos/hulk` from training collapses `ftp_patator` ROC-AUC from
   0.9866 to 0.6037 on an identical test set.

### Partially supported

4. **`ftp_patator` is detected** — episode recall 1.000 in P1, P2 and P3 — but on a
   **single test episode**, and its discrimination collapses in P4.
5. **`ssh_patator` is largely missed at episode level** — 0.111 in P1, P2 and P3.
   Its P4 value of 1.000 is an exclusion artefact on a non-comparable test set.
   Window recall of 0.867 must not be quoted as detection.
6. **`ddos/loit` is detected** in P1 and P2 (1.000) and partially in P3 (0.500), on
   **two episodes**, and is untested by P4.
7. **`dos/hulk` is detected** in P1, P2 and P3 (1.000), on **two episodes**, and is
   untested by P4.

### Not demonstrable with this dataset

8. Generalisation to entirely new attacks.
9. Generalisation to entirely new hosts.
10. Separation of behavioural detection from host-pair memorisation.
11. True performance on the 172 372 `unknown` windows.
12. Definitive absence of a temporal confounder.

---

## Risk register update

### R11 — major limitation, unchanged

5 attack types · 9 entities · **6 host pairs** · 54 episodes.

All 199 `target_attack` windows come from the **single** host pair
`172.16.0.1 → 192.168.10.50`, differing only by service. The four volumetric types
therefore test four mechanics of **one attacker against one victim**. Only
`botnet/ares` interrogates other host pairs — and it is exactly the case the current
features cannot see. **47.1% of positives sit below the benign density.**

The consequence is structural: this evidence cannot distinguish behavioural
detection from host-pair memorisation, and no sampling or splitting technique
creates diversity that does not exist.

### R1 — NOT RESOLVED / no evidence of an effect on recall

P2 is an informative ablation, **not proof of absence**, for three reasons stated
precisely:

- it rests on **54 episodes**, so its power to detect a modest effect is low;
- **composition and size** of the negative set changed together, so a null result on
  recall coexists with a real PR-AUC change that has a different cause;
- **failing to find an effect is not the same as showing there is none.** The
  day-level channels were already excluded by column, so P2 tested only the residual
  hour-of-day distribution shift, not every possible temporal confounder.

R1 therefore stays open at 🟠.

---

## What we can assert

- On this evidence, the five volume features detect `ddos/loit`, `dos/hulk` and
  `ftp_patator`, partially detect `ssh_patator` at window level only, and do not
  detect `botnet/ares`.
- The measured false-alert rate at each stated threshold, on 17 645 held-out benign
  windows in P3 and on the per-fold test negatives in P1.
- Episode-level recall as k out of the episodes present in a fold.
- That at least part of P1's volumetric performance depends on other volumetric
  attacks being in training.
- That threshold calibration drifts within a single day: a 1% target produced 1.59%
  on a later block of the same Monday.

## What we cannot assert

- Any generalisation to unseen attacks, hosts or days.
- Any confidence interval computed at window level.
- Model comparison on differences narrower than the episode bootstrap.
- Any characterisation of alerts on `unknown` windows as false positives, errors, or
  as evidence that `unknown` is benign.
- That the temporal confounder is absent.
- That the system would perform comparably online.

---

## Artifacts

| File | SHA-256 |
|---|---|
`final_benchmark_metrics.json` | `9954d0cb1b41134cc7413cda7b733b508e927f1ae82ec1f023e6ba3d0f78ecbd` |

Source artifacts consolidated, all unmodified: `p1_metrics.json`, `p1_dataset.csv`,
`p1_folds.json`, `p1_leakage_verification.json`, `p2_metrics.json`,
`p3_metrics.json`, `p4_metrics.json`. Their digests are recorded inside the
consolidated file.
