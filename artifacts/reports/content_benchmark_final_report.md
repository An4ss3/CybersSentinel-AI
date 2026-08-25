# Six-arm payload-content feature benchmark — final experiment report

Status: **executed, independently verified, frozen.**
Primary endpoint: held-out **botnet/Ares episode recall at 1% training FPR**, 40 episodes.
Evidence directory: `artifacts/experiments/xgboost_content_benchmark/`
Manifest: `content_benchmark_manifest.json`
Reproduction command: `python -m scripts.run_content_benchmark --execute`

This report summarises the experiment. It does not replace the artifacts, and it
introduces no number that is not already published under
`artifacts/experiments/xgboost_content_benchmark/`.

## 1. What was tested and what was held fixed

Only the **registered feature budget** varies. The P1 population (70,954 windows;
376 positives, 70,578 benign-reference negatives), the five folds, the authentic
training-row order, the ordered test rows, the episode unit, the learner, the
XGBoost parameters, the training-negative threshold rule and the episode
bootstrap are reused exactly as ratified.

Six arms were registered **before any content value was extracted**. ARM I is
`A + all six metrics` by pre-registration, never a subset chosen after reading
E–H.

| Arm | Features |
|---|---|
| A | `distinct_payload_ratio` (registered baseline) |
| E | A + `source_payload_entropy_normalized`, `destination_payload_entropy_normalized` |
| F | A + `source_non_printable_ratio`, `destination_non_printable_ratio` |
| G | A + `payload_prefix_repeat_ratio` |
| H | A + `normalized_header_template_repeat_ratio` |
| I | A + all six content metrics |

30 arm models (6 × 5 folds) plus 10 declared diagnostic models were fitted: 40
models, 0 PostgreSQL writes.

## 2. ARM A anchor — the run gate

The benchmark refuses to write any artifact unless ARM A reproduces the ratified
reference. The gate is enforced in `scripts/run_content_benchmark.py` and raises
`ContentBenchmarkError` before publication.

| Quantity | Ratified reference | Reproduced |
|---|---|---|
| Ares episodes detected | 13/40 | **13/40** |
| Episode recall | 0.3250 | 0.3250 |
| ROC-AUC | 0.7615 | 0.761539 |
| PR-AUC | 0.0670 | 0.067020 |
| Observed test FPR | 0.009874 | 0.009874 |

Beyond the metric equality, ARM A's **models and ordered score streams are
bit-identical** to the frozen A–D benchmark on all 5/5 folds.

## 3. Comparison matrix — A versus E, F, G, H, I

At the pre-registered primary operating point, 1% training FPR:

| Arm | Feat. | Ares episodes | Episode recall | Window recall | ROC-AUC | PR-AUC | Observed test FPR | Entities | Decision |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| A | 1 | 13/40 | 0.3250 | 0.1356 | 0.7615 | 0.0670 | 0.009874 | 5/5 | RETAIN |
| E | 3 | 0/40 | 0.0000 | 0.0000 | 0.7374 | 0.0518 | 0.006897 | 0/5 | REJECT |
| F | 3 | **21/40** | 0.5250 | 0.5593 | **0.9713** | **0.4570** | 0.007187 | 5/5 | INCONCLUSIVE |
| G | 2 | 0/40 | 0.0000 | 0.0000 | 0.5535 | 0.0233 | 0.006679 | 0/5 | REJECT |
| H | 2 | 0/40 | 0.0000 | 0.0000 | 0.3070 | 0.0153 | 0.009728 | 0/5 | REJECT |
| I | 7 | 6/40 | 0.1500 | 0.0452 | 0.8310 | 0.1818 | 0.004211 | 5/5 | REJECT |

The same arms at 0.1% training FPR:

| Arm | Ares episodes | Episode recall | Window recall | Observed test FPR |
|---|---:|---:|---:|---:|
| A | 0/40 | 0.0000 | 0.0000 | 0.000726 |
| E | 0/40 | 0.0000 | 0.0000 | 0.000508 |
| F | **14/40** | 0.3500 | 0.1582 | 0.001597 |
| G | 0/40 | 0.0000 | 0.0000 | 0.001162 |
| H | 0/40 | 0.0000 | 0.0000 | 0.000944 |
| I | 0/40 | 0.0000 | 0.0000 | 0.001960 |

ARM F is the only arm that detects any Ares episode at the stricter operating
point, where the volumetric baseline detects none.

### Paired deltas against ARM A at 1% training FPR

Every interval resamples the **same 40 held-out episodes**, so each comparison is
paired rather than a visual contrast of two marginal intervals.

| Arm | Episode recall delta | Paired 95% episode-delta CI | New / lost episodes | Gain entities | ROC delta | PR delta | FPR delta |
|---|---:|---:|---:|---:|---:|---:|---:|
| E | −0.3250 | [−0.4750, −0.1994] | 0 / 13 | 0 | −0.0241 | −0.0152 | −0.002977 |
| F | **+0.2000** | **[+0.0750, +0.3250]** | **8 / 0** | 2 | +0.2097 | +0.3900 | −0.002686 |
| G | −0.3250 | [−0.4750, −0.1994] | 0 / 13 | 0 | −0.2080 | −0.0437 | −0.003194 |
| H | −0.3250 | [−0.4750, −0.1994] | 0 / 13 | 0 | −0.4546 | −0.0518 | −0.000145 |
| I | −0.1750 | [−0.3250, −0.0500] | 1 / 8 | 1 | +0.0695 | +0.1147 | −0.005663 |

ARM F is the only arm whose paired interval lies strictly above zero. E, G, H and
I are all strictly negative on the pre-registered primary endpoint; a global
ROC-AUC or PR-AUC gain does not override an episode loss on the registered
endpoint.

## 4. ARM F in detail

Features: `distinct_payload_ratio`, `source_non_printable_ratio`,
`destination_non_printable_ratio`.

Primary endpoint at 1% training FPR:

- 21/40 Ares episodes, episode recall 0.5250, episode CI [0.3750, 0.6750]
- window recall 0.5593, ROC-AUC 0.9713, PR-AUC 0.4570
- observed test FPR 0.007187, threshold 0.0024790484458208084
- 5/5 entities detected

Paired gain over ARM A: **+8 episodes gained, 0 lost**, spread across two
distinct victim entities (`192.168.10.15` and `192.168.10.9`, both against
`205.174.165.73|tcp|http`). The gain is therefore not concentrated on a single
host.

Fold-0 feature importance (gain): `distinct_payload_ratio` 0.4850,
`destination_non_printable_ratio` 0.4323, `source_non_printable_ratio` 0.0826.
The new content signal carries roughly as much of the model as the volumetric
feature it extends.

Volumetric cost on the four held-in attack types, judged **not important** by the
registered rule:

| Held-out type | Episode recall A | Episode recall F | Delta | ROC A → F | PR A → F |
|---|---:|---:|---:|---|---|
| brute_force/ftp_patator | 1.0000 | 1.0000 | 0.0000 | 0.8881 → 0.9973 | 0.0336 → 0.6524 |
| brute_force/ssh_patator | 0.1111 | 0.0000 | **−0.1111** | 0.9199 → **0.3992** | 0.5534 → **0.0048** |
| ddos/loit | 1.0000 | 1.0000 | 0.0000 | 0.9903 → 0.9999 | 0.3113 → 0.9623 |
| dos/hulk | 1.0000 | 1.0000 | 0.0000 | 0.9680 → 0.9768 | 0.1639 → 0.5921 |

Total across held-in types: 6 episodes for A versus 5 for F. The single
regression is real and is recorded here rather than smoothed over: on
`ssh_patator`, ARM F loses the one episode ARM A detected and its discrimination
collapses below chance (ROC 0.3992). Non-printable ratios help HTTP-carried
command-and-control and hurt interactive SSH brute force.

## 5. Why ARM F is INCONCLUSIVE and not RETAIN

The registered classification rule is:

> RETAIN requires a paired episode-delta interval strictly above zero, stable FPR
> (absolute delta ≤ 0.0025 and observed ≤ 0.0125), ROC and PR non-inferior, gain
> across multiple entities with 5/5 retained, no important volumetric episode
> cost, and a gain not fully reproduced by the presence indicator alone; REJECT
> applies when the paired primary interval is strictly negative or when there is
> neither episode nor discrimination gain; otherwise INCONCLUSIVE.

ARM F satisfies **five of the six** conditions:

| Condition | ARM F |
|---|---|
| paired delta CI strictly positive | pass |
| ROC and PR non-inferior | pass |
| gain distributed, 5/5 entities | pass |
| no important volumetric episode cost | pass |
| not fully explained by missingness | pass |
| **stable FPR** | **fail** |

The failing quantity is the FPR stability band:

```
|ΔFPR| = |0.007187 − 0.009874| = 0.002686  >  0.0025   (band exceeded)
 observed FPR = 0.007187                   ≤  0.0125   (satisfied)
```

The excess over the band is 0.000186 in absolute FPR.

**The direction matters and must not be misread.** ARM F's observed FPR is
*lower* than ARM A's, 0.007187 against 0.009874. ARM F is not buying episodes by
firing more often; it fires **less** often and still detects eight more episodes.
The stability rule is deliberately two-sided because a shifted operating point —
in either direction — means the two arms are not being compared at the same
alert budget. The 21/40 versus 13/40 contrast is therefore a comparison of two
models at two different points on their respective curves, not a clean
same-budget contrast.

Both arms derive their threshold from the same rule, the 1% quantile of the
training-negative score distribution. Because F's score distribution over benign
traffic has a different shape, that same rule lands at a different realised
test-set FPR. Nothing was tuned; the drift is a property of the score
distribution.

This is why the status is INCONCLUSIVE rather than RETAIN or REJECT: the evidence
of a real gain is strong, and it is not yet evidence at a matched alert budget.

### What a matched-operating-point re-evaluation requires

To convert ARM F from INCONCLUSIVE to a ratifiable verdict, the following must be
**pre-registered before any new number is computed**, and must be additive:

1. **A matched-FPR threshold rule.** Replace the training-quantile threshold with
   one that equalises the *realised* operating point across arms, then declare it
   in advance. Two defensible choices:
   - fix the alert budget on the test negatives so both arms are evaluated at an
     identical observed FPR;
   - or fix the absolute alert count per fold, which is what an analyst actually
     experiences.
2. **A declared primary point plus a curve.** Report Ares episode recall as a
   function of alert budget across at least the 1%, 0.5%, 0.1% and 0.05% points,
   with one of them named in advance as primary. ARM F already detects 14/40 at
   0.1% where ARM A detects 0/40; a pre-registered curve would make that
   comparison admissible instead of incidental.
3. **A paired episode bootstrap at the matched point**, resampling the same 40
   episodes, with the same interval rule. The verdict rests on that interval, not
   on the point estimate.
4. **A declared position on the `ssh_patator` regression.** Either accept it with
   a stated tolerance, or add it as a co-primary constraint. It must be decided
   before the run, not after seeing the result.
5. **Unchanged everything else.** The same P1 population, folds, row order,
   learner, parameters and episode unit. ARM A must again reproduce its anchor —
   13/40 at its own registered point — or the run is void.
6. **A fresh isolated directory.** The frozen A–D benchmark and this six-arm
   benchmark must not be modified. A matched-point re-evaluation is a new
   experiment with its own manifest.

Until that run exists and is verified, the **minimal best compromise remains
ARM A**, and ARM F must be described as a strong but unratified candidate.

## 6. Missingness confounder analysis

Extraction established that the presence of
`normalized_header_template_repeat_ratio` is **exactly equivalent** to
`service == http`: 12,279 frozen windows carry it and all are HTTP. All 177 Ares
windows are HTTP, against 17.1% of benign windows. Because P1 forbids
`entity_service` as a feature and XGBoost branches natively on missing values, an
ARM H or ARM I effect could in principle be carried by that missingness rather
than by header-template repetition.

Two diagnostics therefore keep only the **presence indicators** and discard the
values. They are not arms, they are flagged `is_diagnostic`, and they take part
in no ranking.

| Model | Ares episodes | Gain over A | ROC-AUC | Observed test FPR |
|---|---:|---:|---:|---:|
| A (reference) | 13/40 | — | 0.7615 | 0.009874 |
| H | 0/40 | −13 | 0.3070 | 0.009728 |
| H_IND (indicator only) | 0/40 | −13 | 0.4637 | 0.008567 |
| I | 6/40 | −7 | 0.8310 | 0.004211 |
| I_IND (indicator only) | 4/40 | −9 | 0.4644 | 0.006244 |

**Result: the leakage concern does not materialise, and not for the reason
anticipated.** There is no gain to attribute. Both H and I *lose* episodes
relative to A, so `share_explained_by_missingness` is `null` by construction for
both. ARM H does not merely fail to gain; it collapses well below chance
(ROC-AUC 0.3070), and the indicator-only variants are near-random
(0.4637, 0.4644).

`normalized_header_template_repeat_ratio` therefore did not act as a disguised
proxy for `service == http`. Had it done so, H would have shown an inflated gain
reproducible by H_IND alone. Instead the metric actively degraded the model. The
bound the diagnostics were built to establish is in place and published; it
happens to be empty.

The guard remains necessary for any future arm that uses this metric: presence is
still exactly `service == http`, and a future arm that did show a gain would have
to clear the same attribution test.

Undefined metrics remain native NaN inside every arm. No imputation, fitted fill
value or missingness indicator exists inside any arm; indicators appear only in
the two diagnostics.

## 7. Content metric availability

| Metric | Benign | Ares | Other attacks |
|---|---:|---:|---:|
| `source_payload_entropy_normalized` | 64675/70578 (91.6%) | 177/177 (100.0%) | 160/199 (80.4%) |
| `destination_payload_entropy_normalized` | 62394/70578 (88.4%) | 177/177 (100.0%) | 196/199 (98.5%) |
| `source_non_printable_ratio` | 64683/70578 (91.6%) | 177/177 (100.0%) | 160/199 (80.4%) |
| `destination_non_printable_ratio` | 62394/70578 (88.4%) | 177/177 (100.0%) | 196/199 (98.5%) |
| `payload_prefix_repeat_ratio` | 64683/70578 (91.6%) | 177/177 (100.0%) | 160/199 (80.4%) |
| `normalized_header_template_repeat_ratio` | 12063/70578 (17.1%) | 177/177 (100.0%) | 39/199 (19.6%) |

## 8. Integrity and isolation

Verified by re-executing the benchmark end-to-end and by an independent audit
pass over the published bytes:

- 9 frozen input digests match; 45 P1 protocol checks; 3 content join checks;
  21 feature assembly checks; 11 cross-model identity checks.
- 87 published output digests recomputed from the bytes on disk; all match the
  manifest. The directory contains exactly the declared artifacts.
- A full re-run refitting all 40 models left **no tracked file modified**. The
  publication path is immutable-or-raise, so every artifact was reproduced
  byte-for-byte.
- ARM A models and score streams bit-identical to the frozen A–D benchmark on
  5/5 folds.
- Frozen A–D benchmark manifest digest unchanged at
  `2b6e65e658297dd1d96d3f4d3afce9798a5cf9e99279a70253dbbb022315af88`; all 44 of
  its outputs still match their published digests.
- `p1_population_or_folds_modified: false`, `frozen_ad_benchmark_modified:
  false`, `published_baseline_modified: false`, `postgresql_writes: 0`.
- No presence indicator appears inside any arm.

Environment: xgboost 2.1.0, scikit-learn 1.5.1, numpy 1.26.4.

## 9. Scope of the evidence — R11 remains open

The botnet endpoint contains **5 entities, 1 destination (`205.174.165.73`) and
40 episodes**. Arm contrasts identify the effect of changing the feature budget
under this fixed learner and protocol; they are not universal causal feature
effects.

This benchmark demonstrates transfer from the four held-in attack types to the
held-out Ares windows under the frozen population and the registered budgets. It
does **not** demonstrate generalisation to another victim, attacker, capture or
botnet family, and it does not measure streaming ingestion latency. A single
destination host carries the entire primary endpoint, so ARM F's advantage over
ARM A is established against one attacker infrastructure only.

## 10. Conclusions

1. ARM A reproduced its ratified 13/40 anchor exactly, including bit-identical
   models and score streams. The run is validly anchored.
2. **ARM F is the first feature budget to exceed the volumetric plateau on the
   pre-registered primary endpoint**: 21/40 versus 13/40 at 1% training FPR,
   paired interval [+0.0750, +0.3250], eight episodes gained and none lost across
   two entities, and 14/40 versus 0/40 at 0.1%. Non-printable byte ratios, not
   entropy and not template repetition, carry that signal.
3. ARM F is **INCONCLUSIVE, not ratified**, solely because |ΔFPR| = 0.002686
   exceeds the 0.0025 stability band. The plateau is exceeded at the observed
   operating point; it has not been shown exceeded at a matched alert budget.
   Section 5 states what a matched-point re-evaluation requires.
4. Entropy (E), prefix repetition (G) and header-template repetition (H) are
   REJECT. The seven-feature union (I) is also REJECT and is worse than its own
   best component, consistent with dilution under a fixed learner.
5. The missingness confounder is bounded and did not materialise: H and I show no
   gain to attribute, and the indicator-only diagnostics are near-random.
6. The minimal best compromise remains **ARM A**, one feature.
