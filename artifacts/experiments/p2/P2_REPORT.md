# P2/B — Temporal-matched ablation of R1

Executed 2026-08-17 on the **frozen P1 folds**. Zero PostgreSQL writes.

## The single change

Only the **composition of the training negatives** differs from P1. A training
negative is retained when its 60-second offset-of-day coincides with the offset of
at least one **training** positive.

Everything else is byte-identical to P1: the dataset rows and labels, the five
features, the five leave-one-attack-type-out folds loaded from `p1_folds.json`,
**the test set of every fold**, the model, the threshold selector, the metrics and
the episode bootstrap. Verified programmatically: the reproduced dataset content
digest equals the frozen `3d743617…`, the folds digest equals `e463ea7b…`, and
`all_test_sets_identical_to_p1 = true` on test positives, test negatives and test
episode counts.

**Decision D11**: matched offsets come from the fold's **training** positives only,
never from the held-out type. Using the held-out attack's temporal signature to
choose training negatives would let the test attack shape the training set — a
subtle leak. Each fold therefore uses a slightly different matched set, which is
correct: the covariate being controlled is defined by what the model may see.

Nothing was duplicated, weighted or synthesised. The imbalance reduction is a
side effect of covariate matching, not its purpose.

## Training negative retention

| Held-out type | Matched offsets | Train neg. P1 | Train neg. P2 | Retained | Imbalance P1 | Imbalance P2 |
|---|---|---|---|---|---|---|
`botnet/ares` | 133 | 56 804 | 18 870 | 33.2% | 285.4:1 | 94.8:1 |
`brute_force/ftp_patator` | 132 | 56 594 | 14 772 | 26.1% | 179.7:1 | 46.9:1 |
`brute_force/ssh_patator` | 124 | 56 514 | 18 281 | 32.3% | 178.8:1 | 57.9:1 |
`ddos/loit` | 155 | 55 850 | 20 725 | 37.1% | 167.2:1 | 62.1:1 |
`dos/hulk` | 176 | 56 550 | 22 671 | 40.1% | 166.3:1 | 66.7:1 |

## P1 versus P2 on identical test sets

| Held-out type | **Episode recall P1** | **P2** | Δ | 95% CI P1 | 95% CI P2 | Window P1 | P2 | ROC P1 | P2 | PR P1 | P2 |
|---|---|---|---|---|---|---|---|---|---|---|---|
`botnet/ares` | 0.075 | 0.150 | **+0.075** | [0.000, 0.175] | [0.050, 0.250] | 0.017 | 0.045 | 0.5037 | 0.5195 | 0.014 | 0.014 |
`brute_force/ftp_patator` | 1.000 | 1.000 | **+0.000** | [1.000, 1.000] | [1.000, 1.000] | 0.984 | 0.984 | 0.9866 | 0.9734 | 0.301 | 0.135 |
`brute_force/ssh_patator` | 0.111 | 0.111 | **+0.000** | [0.000, 0.333] | [0.000, 0.333] | 0.867 | 0.533 | 0.9279 | 0.9175 | 0.354 | 0.152 |
`ddos/loit` | 1.000 | 1.000 | **+0.000** | [1.000, 1.000] | [1.000, 1.000] | 1.000 | 1.000 | 0.9972 | 0.9947 | 0.592 | 0.382 |
`dos/hulk` | 1.000 | 1.000 | **+0.000** | [1.000, 1.000] | [1.000, 1.000] | 0.778 | 0.889 | 0.8842 | 0.9770 | 0.555 | 0.518 |

**Pooled episode recall: 0.167 [0.074, 0.278] → 0.222 [0.111, 0.333], Δ +0.056.**
The intervals overlap across most of their range.

## Interpretation, under the ratified rules

**On the primary metric, controlling the hour-of-day covariate changed nothing.**
Episode recall is identical for four of the five types. The only movement is
`botnet/ares`, and it moved **upward** by 0.075 with heavily overlapping confidence
intervals, while its ROC-AUC stayed at chance level (0.5037 → 0.5195). The botnet
remains undetected in both designs; the small recall gain is 3 episodes of 40
becoming 6 of 40, well inside bootstrap noise.

Under the interpretation rule ratified before the run — *stable recall between P1
and P2 indicates hour-of-day was not an exploited channel* — **this ablation finds
no evidence that P1's recall depended on the time-of-day confounder.**

ROC-AUC is likewise stable within a few points on every fold, and improved on
`dos/hulk` (0.884 → 0.977).

## What the PR-AUC decline is, and is not

PR-AUC fell materially on three folds: `ftp_patator` 0.301 → 0.135, `ssh_patator`
0.354 → 0.152, `ddos/loit` 0.592 → 0.382. Window recall on `ssh_patator` also fell,
0.867 → 0.533.

**This is not evidence about R1.** The test sets are identical, so the change comes
entirely from training. P2 trains on 26–40% of P1's negatives, and the retained
ones are confined to attack-coincident offsets, so the model sees a **narrower
slice of benign behaviour** and ranks the full benign distribution of the test set
less well. Precision at a given recall therefore degrades. That is a coverage and
sample-size effect.

**A confound this ablation cannot separate.** P2 changes the negative composition
*and* the negative count at the same time. Isolating the covariate effect would
require holding the count constant — that is, subsampling P1's negatives to the
same size — which is sampling and is forbidden. The confound is therefore reported,
not corrected. Its practical consequence: the **recall** comparison is meaningful,
because recall at a fixed training-FPR target is largely insensitive to how many
negatives were seen, while the **PR-AUC** comparison is not attributable to R1.

## Inherited limitations

The in-sample threshold calibration bias documented in the P1 report applies
identically here: thresholds are calibrated on in-sample training-negative scores,
so measured test FPR exceeds the target. Because the bias is the same on both
sides, the recall deltas remain comparable. Observed test FPR did shift
(e.g. `ftp_patator` 0.0122 → 0.0227), which is expected since the negative
training distribution changed, and is not itself evidence about R1.

R11 is untouched. P2 adds no attack diversity: still 5 types, 9 entities, 6 host
pairs, 54 episodes, and all `target_attack` on one host pair.

## Conclusion on R1

**Not resolved, but the available ablation found no effect on recall.** The
day-level channels were already excluded by column; this test shows that the
residual hour-of-day distribution shift does not drive the recall that P1 reports.
R1 stays open at 🟠 because a single ablation on 54 episodes, confounded with
negative-set size, cannot establish absence of an effect — only fail to find one.

## Artifacts

| File | SHA-256 |
|---|---|
`p2_metrics.json` | `67d2f60bc57d03bbc990fda14951d4acfb2d718db838b2fbf5b9bb3ee1b0241a` |
`p2_matching.json` | see repository |

Five models `p2_model_fold{0..4}.joblib` and five prediction files
`p2_predictions_fold{0..4}.csv` accompany them.
