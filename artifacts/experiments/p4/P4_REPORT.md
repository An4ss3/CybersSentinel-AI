# P4/C — Conservative benchmark, single-family attack entities

Executed 2026-08-17. Zero PostgreSQL writes. P1, P2 and P3 untouched.

## The exclusion, and its unintended consequence

Two of the nine attack entities carry more than one attack family:

| Entity | Families |
|---|---|
`172.16.0.1\|192.168.10.50\|tcp\|none` | `ssh_patator` + `ddos/loit` + `dos/hulk` |
`172.16.0.1\|192.168.10.50\|tcp\|http` | `ddos/loit` + `dos/hulk` |

Excluding them removes **86 windows**, leaving 290 positives, 7 entities and 42
episodes. Negatives, features, labels, model, thresholds and bootstrap are
unchanged. Nothing was added, duplicated or weighted.

**But those two entities are the only carriers of `ddos/loit` and `dos/hulk`.**
Excluding them therefore deletes two of the five attack types entirely. P4 has
**3 attack types, not the 4 the design phase estimated.** That estimate was wrong
and is corrected here.

| | P1 | P4 |
|---|---|---|
Positives | 376 | 290 |
Entities | 9 | 7 |
Episodes | 54 | 42 |
**Attack types** | **5** | **3** |
Negatives | 70 578 | 70 578 |
Folds | 5 | 3 |

Folds were re-frozen because the attack-type inventory shrank. `build_folds` now
derives its fold count from the types present; P1, P2 and P3 still pass the
default of five and their digests are unchanged — verified: dataset
`3d743617…`, folds `e463ea7b…`.

## Results

| Held-out type | Test pos. P1 → P4 | Episodes P1 → P4 | **Episode recall P1 → P4** | Δ | ROC P1 → P4 | PR P1 → P4 | Same test set |
|---|---|---|---|---|---|---|---|
`botnet/ares` | 177 → 177 | 40 → 40 | 0.075 → 0.050 | −0.025 | 0.5037 → 0.5035 | 0.0135 → 0.0077 | **yes** |
`brute_force/ftp_patator` | 61 → 61 | 1 → 1 | 1.000 → 1.000 | +0.000 | **0.9866 → 0.6037** | 0.3007 → 0.0089 | **yes** |
`brute_force/ssh_patator` | 60 → **52** | 9 → **1** | 0.111 → 1.000 | +0.889 | **0.9279 → 0.7153** | 0.3541 → 0.0187 | **no** |
`ddos/loit` | 42 → — | 2 → — | 1.000 → **deleted** | — | — | — | — |
`dos/hulk` | 36 → — | 2 → — | 1.000 → **deleted** | — | — | — | — |

**Pooled episode recall: 0.167 [0.074, 0.278] over 54 → 0.095 [0.024, 0.190] over 42.**

## What P4 actually establishes

### 1. The botnet blindness conclusion is robust

Same 177 windows, same 40 episodes, ROC-AUC 0.5037 → 0.5035, episode recall
0.075 → 0.050. Nothing about that conclusion depended on the multi-family
entities. Combined with P3's exact 0.0000, the blindness now holds across four
independent designs.

### 2. The ftp and ssh detection conclusions are **not** robust

`ftp_patator` keeps its identical test set — 61 windows, 1 episode — yet ROC-AUC
falls from **0.9866 to 0.6037** and PR-AUC from 0.3007 to 0.0089. Episode recall
stays 1.000 only because a single episode is a coarse measure.

The cause is in the training set, not the test set. P4 removes `ddos/loit` and
`dos/hulk` from training, and those were the very high-volume attacks that taught
the model "large volume means attack". Without them, training positives are only
ftp, ssh and botnet — far lower volume — and discrimination collapses.

**This recasts P1's headline result.** P1's leave-one-type-out transfer for
`ftp_patator` was largely transfer *from* very-high-volume attacks *to* a
moderately-high-volume attack. It was not evidence of a general ability to
recognise an unseen attack type from benign traffic alone.

### 3. The apparent ssh improvement is an artefact and must not be read as a gain

Episode recall for `ssh_patator` rises 0.111 → 1.000, which looks like a large
improvement. It is not. P1's ssh test set held 60 windows across **9 episodes**;
P4's holds 52 windows across **1 episode**. The eight missed episodes belonged
entirely to the excluded `172.16.0.1|…|tcp|none` entity.

**P4 removed precisely the hard cases and kept the easy one.** The test sets are
not comparable — `same_test_set = false` for this fold — and the delta of +0.889
measures the exclusion, not the model. Quoting it as an improvement would be
straightforwardly wrong.

### 4. P4 cannot validate the loit and hulk conclusions at all

It deletes them. Those two types were P1's strongest results (episode recall 1.000,
PR-AUC 0.592 and 0.555). Their robustness to entity multi-family contamination
remains **untested** and cannot be tested by this control, because no
single-family entity carries either family.

## Limitations

**P4 makes R11 more severe, not less.** Fewer positives (290 vs 376), fewer
entities (7 vs 9), fewer types (3 vs 5), fewer episodes (42 vs 54), and a worse
imbalance. It is published to show which conclusions survive, never to claim
improved statistical power.

**Two of three P4 folds test a single episode.** `ftp_patator` and `ssh_patator`
each have one test episode, so their episode-level confidence intervals are
degenerate ([1.000, 1.000]) and carry no information about variability.

**Window-level bootstrap remains forbidden** and is not used.

## Verdict across the four designs

| Conclusion | P1 | P2 | P3 | P4 | Status |
|---|---|---|---|---|---|
`botnet/ares` is undetectable by volume features | 0.075 | 0.150 | **0.000** | 0.050 | **robust across four designs** |
Hour-of-day is not the channel driving recall | — | recall unchanged on 4/5 | — | — | supported by one ablation |
`ddos/loit` and `dos/hulk` are detected | 1.000 | 1.000 | 0.500 / 1.000 | **deleted** | supported by P1–P3, untested by P4 |
`ftp_patator` and `ssh_patator` transfer | 1.000 / 0.111 | 1.000 / 0.111 | 1.000 / 0.111 | ROC collapses | **depends on high-volume attacks in training** |

## Artifacts

| File | SHA-256 |
|---|---|
`p4_metrics.json` | `3df92eda32d943b6cfba440eb61ca0fc3b1e11a0ed26b170ac6a3485ed911783` |

Three models `p4_model_fold{0..2}.joblib` and three prediction files
`p4_predictions_fold{0..2}.csv` accompany it.
