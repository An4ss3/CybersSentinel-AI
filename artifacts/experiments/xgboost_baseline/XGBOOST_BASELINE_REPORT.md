# XGBoost baseline — one feature, frozen protocol

**Question.** On the frozen protocol, can XGBoost exploit the signal carried by
`distinct_payload_ratio` to actually improve episode-level detection of
`botnet/ares`?

**Answer.** Yes, and by a margin that is for the first time statistically separated
from P1. Botnet episode recall goes **0.075 → 0.325**, ROC-AUC **0.5037 → 0.7615**,
PR-AUC **0.0135 → 0.0670**, and the observed test FPR stays at target
(0.0096 → 0.0099). The 95% interval **does not overlap P1's**.

**But the gain belongs to the feature, not to the learner.** P6 measured the
univariate separation of this feature at **0.7632**; the fitted model reaches
**0.7615** — a difference of 0.0016. A monotone single-feature model cannot exceed
its feature's own separation, and this one essentially attains it. XGBoost has no
remaining headroom here. **Tuning it would be spending effort where there is
demonstrably none to recover.**

## Protocol reproduction — verified before fitting

45 checks passed, all of them before any model was built:

- population content digest equals P1's `3d743617…`;
- folds content digest equals P1's `e463ea7b…`;
- per fold, training and test **membership identical** to `p1_folds.json` as sets;
- per fold, the test set's `(row_id, label)` pairs **identical to P1's published
  predictions** — so any difference is attributable to the model and the feature,
  never to a changed evaluation set;
- no `unknown` and no `ambiguous` row anywhere; every negative is
  `benign_reference`;
- no shared window, attack type, episode or benign entity between train and test.

The folds are **reconstructed** rather than loaded, to recover P1's row ordering:
`p1_folds.json` stores `sorted(train_row_ids)` while P1 trained on the order
`build_folds` produces. The P5 run established that loading the file naively
reproduces the split but not the ordering. Membership is still proven two ways
(decision D23).

Zero PostgreSQL writes. One feature, no additions. No hyper-parameter search, no
early stopping, no ensembling, no resampling, no class rebalancing, no new split.

## Model parameters

| Parameter | Value |
|---|---|
`objective` | `binary:logistic` |
`eval_metric` | `logloss` (recorded only; nothing selects on it) |
`n_estimators` | 200 |
`max_depth` | 3 |
`learning_rate` | 0.1 |
`subsample` | 1.0 |
`colsample_bytree` | 1.0 |
`scale_pos_weight` | **1 — no class rebalancing** |
`random_state` | 0 |
`n_jobs` | 1 |
`tree_method` | `exact` |

Conservative choices, all recorded in the manifest: **D17** `scale_pos_weight = 1`
because ratified D7 forbids class weighting as a form of rebalancing; **D18** both
stochastic regularisers disabled, removing every source of randomness from fitting;
**D19** 200 estimators to match P1's capacity; **D20** depth 3, below the library
default of 6, and with one feature depth only controls how many thresholds exist;
**D21** learning rate 0.1, below the default 0.3, no early stopping because that
would require a validation split; **D22** `eval_metric` recorded only.

Threshold rule unchanged from P1 and P5: the smallest observed **training-negative**
score achieving the target FPR. Targets 1% and 0.1%. No test observation, and in
particular no test positive, influences an operating point. Bootstrap is
**episode-level only**, 2 000 resamples, seed 0.

## Results, 1% training-FPR operating point

| Attack type | ROC-AUC | PR-AUC | Window recall | Episode recall | Episodes | Test FPR | Threshold |
|---|---|---|---|---|---|---|---|
**`botnet/ares`** | **0.7615** | **0.0670** | 0.1356 | **0.3250** | **13 / 40** | 0.009874 | 0.022657 |
`brute_force/ftp_patator` | 0.8881 | 0.0336 | 0.0492 | 1.0000 | 1 / 1 | 0.007366 | 0.065382 |
`brute_force/ssh_patator` | 0.9199 | 0.5534 | 0.5500 | 0.1111 | 1 / 9 | 0.009101 | 0.060507 |
`ddos/loit` | 0.9903 | 0.3113 | 1.0000 | 1.0000 | 2 / 2 | 0.017042 | 0.061925 |
`dos/hulk` | 0.9680 | 0.1639 | 0.5833 | 1.0000 | 2 / 2 | 0.010265 | 0.076837 |

Pooled episode recall **19 / 54 = 0.3519**, against 0.167 in P1 and 0.222 in P5.

## Primary endpoint, read against the seven required criteria

| | P1 (5 features, RF) | P5 arm B (8 features, RF) | **XGBoost (1 feature)** |
|---|---|---|---|
Episode recall | 0.0750 | 0.1500 | **0.3250** |
Episodes detected | 3 / 40 | 6 / 40 | **13 / 40** |
95% CI (episode bootstrap) | [0.0000, 0.1750] | [0.0500, 0.2750] | **[0.1994, 0.4750]** |
ROC-AUC | 0.5037 | 0.5119 | **0.7615** |
PR-AUC | 0.0135 | 0.0145 | **0.0670** |
Observed test FPR | 0.009583 | 0.016045 | **0.009874** |
Botnet hosts with a detected episode | 2 of 5 | 3 of 5 | **5 of 5** |

1. **Episode recall** rose 4.3×.
2. **ROC-AUC left chance**, 0.5037 → 0.7615. This is the first design in the project
   where the botnet is ranked above benign at all.
3. **PR-AUC rose 5×**, from 0.0135 to 0.0670. Still low in absolute terms at 1:187.7.
4. **The FPR did not inflate**: 0.009583 → 0.009874, both at the 1% target. The recall
   gain is therefore **not** a moved operating point.
5. **The interval does not overlap P1's** — XGBoost's lower bound 0.1994 exceeds P1's
   upper bound 0.1750. It **does** overlap P5's ([0.0500, 0.2750]), so the difference
   against P5 is not resolved.
6. **13 of 40 episodes** against 3 and 6.
7. **Per entity**, at the 1% point:

| Botnet entity | Windows flagged | Window recall | Episodes detected | Episode recall |
|---|---|---|---|---|
`192.168.10.5 → 205.174.165.73` | 5 / 27 | 0.1852 | 3 / 7 | 0.4286 |
`192.168.10.8 → 205.174.165.73` | 5 / 26 | 0.1923 | 2 / 2 | 1.0000 |
`192.168.10.9 → 205.174.165.73` | 4 / 44 | 0.0909 | 2 / 15 | 0.1333 |
`192.168.10.14 → 205.174.165.73` | 6 / 31 | 0.1935 | 4 / 8 | 0.5000 |
`192.168.10.15 → 205.174.165.73` | 4 / 49 | 0.0816 | 2 / 8 | 0.2500 |

**All five entities are detected**, and window recall is fairly uniform across them
(0.0816 to 0.1935). The gain is spread rather than concentrated on one host, which is
what shared C2 behaviour would produce and what P6's per-entity analysis predicted.
P1 reached two hosts, P5 three.

This is the pattern that counts as interesting rather than as a moved operating
point: **discrimination and episode recall both improved, with the false-positive
rate flat.**

## Three findings that qualify the result

**1. The gain is the feature's, not the model's.** P6 measured this feature's
univariate separation on the botnet at oriented AUC **0.7632**. The fitted model
achieves **0.7615** on the fold's test negatives — a gap of 0.0016. With a single
feature a boosted tree ensemble can only learn a monotone step function on it, so its
ceiling *is* the univariate AUC, and it has essentially reached it. What changed
relative to P1 is not the learner's capacity: it is that this feature carries botnet
signal **with the sign the volumetric attacks teach**, whereas three of P1's five
features were at chance on the botnet and the fourth pointed the opposite way.

**2. Detection exists only at the permissive operating point.** At the 0.1% target
the result collapses completely: threshold 0.322967, window recall **0.0000 (0 of
177)**, episode recall **0.0000 (0 of 40)**. P6 had measured that only 6 of 40
episodes reach the benign 99th percentile on this feature; at 0.1% none survive. The
separation lives in the bulk of the distribution, not the tail, and the operating
point cannot be tightened without losing everything.

**3. The volumetric types pay for it, at window level.** Going from five features to
one leaves **episode recall unchanged on all four** volumetric types (1.000, 0.1111,
1.000, 1.000 — identical to P1) but degrades the other metrics:

| Type | ROC P1 → XGB | PR P1 → XGB | Window recall P1 → XGB |
|---|---|---|---|
`ftp_patator` | 0.9866 → 0.8881 | 0.3007 → **0.0336** | 0.9836 → **0.0492** |
`ssh_patator` | 0.9279 → 0.9199 | 0.3541 → 0.5534 | 0.8667 → 0.5500 |
`ddos/loit` | 0.9972 → 0.9903 | 0.5919 → **0.3113** | 1.0000 → 1.0000 |
`dos/hulk` | 0.8842 → 0.9680 | 0.5552 → **0.1639** | 0.7778 → 0.5833 |

At the ratified evaluation unit — the episode — nothing was lost and the botnet
quadrupled. At window level three of four types got worse. Anyone quoting window
recall would read this run as a regression; at episode level it is a clear gain. The
ratified unit is the episode.

## R11 — unchanged and binding

- Only **5 botnet entities**, all reaching the single destination
  `205.174.165.73`. Host-pair diversity remains limited.
- This performance is **not** proof of universal generalisation.
- `distinct_payload_ratio` is a **candidate justified by P6**, not yet evidence of
  generalisable detection.
- The botnet endpoint rests on **40 episodes**, so the interval is wide and small
  differences are not resolvable — which is exactly why the comparison against P5
  remains unresolved.

## Verdict

The three offered options do not map cleanly, so both parts are stated.

On the **feature**, the evidence is convincing: a non-overlapping interval against
P1, discrimination leaving chance, PR-AUC up fivefold, a flat false-positive rate,
and all five botnet entities detected.

On the **model**, the answer is **C — the remaining problem is the feature set and
the protocol, not the choice of learner.** C's headline wording, "no convincing
gain", understates what happened: there is a real and measurable gain. But C's
operative clause is exactly right, and it is what should drive the next decision.
XGBoost sits 0.0016 below the ceiling its single feature permits, so **a controlled
tuning campaign has no headroom to recover** and would not be a productive next step.

Where headroom does exist, on the evidence: the two candidates P6 withheld and you
chose not to reopen — `interarrival_mean` (univariate 0.9146, identity AUC 0.5797,
all 5 entities, sign agrees) and `bytes_per_packet_destination` (univariate 0.8852,
the cleanest R11 profile measured, per-entity spread 0.0028). Both screen well above
the 0.7632 that currently caps this model. Neither is reopened here.

## Artifacts

| File | SHA-256 |
|---|---|
`xgb_metrics.json` content | `9a15697031591f61…` |
`xgb_metrics.json` file | `4b841773bbe34d62` |
`xgb_reproducibility_manifest.json` | `8ed7e84218359e8d` |

Plus `xgb_model_fold0..4.joblib`, `xgb_predictions_fold0..4.csv` and
`xgb_model_params.json`; every digest is recorded in the manifest.

No P1–P6 artifact was modified, no label was changed, and no PostgreSQL statement
was issued.
