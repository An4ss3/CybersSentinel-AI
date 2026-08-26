# ARM F ratification and ARM J1 — final scientific report

Status: **executed, verified, frozen.**
Pre-registration identity: `ef2e85daba806e3a59e66c8f599aa380853f9ba69bbdc81ef7586014bee01bc0`
Evidence directory: `artifacts/experiments/armf_ratification_armj1/`
Reproduction: `python -m scripts.run_armf_ratification --execute`

Primary endpoint: held-out **botnet/Ares episode recall at 1% training FPR**, 40 episodes.
Co-primary endpoint for ARM J1: held-out **brute_force/ssh_patator episode recall**, 9 episodes.

**Verdict: option B — ARM F is ratified, ARM J1 fails to recover ssh_patator.**
ARM J1 additionally degrades the Ares gain relative to ARM F.

## 1. Registered budgets and what varied

| Arm | Features |
|---|---|
| A | `distinct_payload_ratio` |
| F | `distinct_payload_ratio`, `source_non_printable_ratio`, `destination_non_printable_ratio` |
| J1 | ARM F + `interarrival_mean` |

Only the feature budget varied. The P1 population (70,954 windows), the five
folds, the authentic training-row order, the ordered test rows, the labels, the
episode unit, the learner, the XGBoost parameters, the threshold rule and the
episode bootstrap were reused unchanged. 15 models were fitted, 0 PostgreSQL
writes were performed, and no P1–P6, baseline, A–D or six-arm artifact was
modified.

Every threshold is a quantile of the **training** negatives at a registered
target. The test set never selected a threshold, a feature, a hyperparameter or
an architecture.

### Pre-registration correction, recorded before training

The mission asked ARM J1 to combine "the reference volumetric budget that showed
utility on the volumetric attacks / ssh_patator" with ARM F's non-printable
ratios. **No such budget exists.** In the frozen A–D benchmark ARM A alone is
best on all four held-in types (6 held-in episodes against 4 for B, C and D, each
carrying an important volumetric cost); on ssh_patator, `interarrival_mean` (B)
left recall unchanged and `bytes_per_packet_destination` (C, D) lost the single
episode. Because ARM A's budget is exactly `distinct_payload_ratio` and ARM F
already contains it, a literal hybrid would have duplicated ARM F.

ARM J1 therefore reinstates `interarrival_mean`: the only volumetric candidate
that did not reduce ssh_patator episode recall and that raised its ROC-AUC from
0.9199 to 0.9453, and the smallest budget increase capable of addressing the
stated ssh motivation. J2 and J3 were excluded and never fitted.

## 2. Protocol verification, all before any model was fitted

| Gate | Checks |
|---|---|
| B — frozen input digests, incl. all 87 six-arm and 44 A–D outputs | 13 |
| E — registered arm budgets, forbidden columns, indicator ban | 9 |
| A/F — P1 population, folds, authentic order, published membership | 45 |
| D — leakage: train/test disjoint, held-out type absent from training positives, no unknown/ambiguous, negatives benign_reference only | 18 |
| content join by frozen row id | 3 |
| P6 feature assembly and J1-extends-F column identity | 11 |
| cross-arm ordered test-row identity | 5 |
| C — ARM A and ARM F reproduce the published score streams and primary endpoint | 12 |

All pass. ARM A and ARM F reproduce the frozen six-arm benchmark score streams
value-for-value on 5/5 folds, and both reproduce their published primary endpoint
(ARM A 13/40, ROC 0.7615389758318096, PR 0.0670200698009214, FPR
0.009873675039930304; ARM F 21/40, ROC 0.9712706901318213, PR 0.45704719677233957,
FPR 0.007187454624655147) to within 1e-9.

## 3. Primary endpoint — Ares at 1% training FPR

| Arm | Episodes | Episode recall | 95% episode CI | Window recall | ROC-AUC | PR-AUC | Test FPR | Alerts |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| A | 13/40 | 0.3250 | [0.1994, 0.4750] | 0.1356 | 0.7615 | 0.0670 | 0.009874 | 160 |
| **F** | **21/40** | **0.5250** | **[0.3750, 0.6750]** | 0.5593 | **0.9713** | **0.4570** | **0.007187** | 198 |
| J1 | 15/40 | 0.3750 | [0.2250, 0.5250] | 0.2203 | 0.9430 | 0.2043 | 0.007478 | 142 |

Paired episode deltas over the same 40 episodes:

| Contrast | Delta | Paired 95% CI | New / lost | Direction |
|---|---:|---:|---:|---|
| F − A | +0.2000 | **[+0.0750, +0.3250]** | 8 / 0 | **improved** |
| J1 − A | +0.0500 | [+0.0000, +0.1250] | 2 / 0 | indistinguishable |
| J1 − F | −0.1500 | **[−0.2750, −0.0500]** | 0 / 6 | **degraded** |

## 4. Co-primary endpoint — ssh_patator at 1% training FPR

| Arm | Episodes | Episode recall | 95% episode CI | Window recall | ROC-AUC | PR-AUC | Test FPR | Alerts |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| A | **1/9** | 0.1111 | [0.0000, 0.3333] | 0.5500 | 0.9199 | **0.5534** | 0.009101 | 161 |
| F | 0/9 | 0.0000 | [0.0000, 0.0000] | 0.0000 | **0.3992** | 0.0048 | 0.006613 | 93 |
| J1 | 0/9 | 0.0000 | [0.0000, 0.0000] | 0.0000 | 0.9049 | 0.0331 | 0.004693 | 66 |

| Contrast | Delta | Paired 95% CI | New / lost | Direction |
|---|---:|---:|---:|---|
| F − A | −0.1111 | [−0.3333, +0.0000] | 0 / 1 | indistinguishable |
| J1 − A | −0.1111 | [−0.3333, +0.0000] | 0 / 1 | indistinguishable |
| J1 − F | +0.0000 | [+0.0000, +0.0000] | 0 / 0 | indistinguishable |

**`interarrival_mean` partially rehabilitated ssh ranking but recovered no
episode.** ARM F's ssh ROC-AUC is 0.3992, below chance. ARM J1 restores it to
0.9049, close to ARM A's 0.9199 — so the volumetric feature does repair the
ordering that the content ratios destroyed. But PR-AUC stays at 0.0331 against
ARM A's 0.5534, and episode recall stays at 0.0000 at every one of the five
operating points. Restoring a ranking is not the same as putting a positive
window above the alert threshold.

The ssh fold contains 9 episodes across 2 entities. Only one episode is
detectable by any arm: `172.16.0.1|192.168.10.50|tcp|ssh` (1 episode), which ARM
A catches with window recall 0.635 and both F and J1 miss entirely. The other 8
episodes, on `172.16.0.1|192.168.10.50|tcp|none`, are missed by all three arms.
With 9 episodes, a one-episode difference cannot reach significance: all three
ssh contrasts are **indistinguishable**, which is genuinely undetermined, not a
neutral finding.

## 5. The five pre-registered operating points

### Ares — episodes detected / realised test FPR

| Target train FPR | A | F | J1 |
|---|---|---|---|
| 0.01 | 13/40 @ 0.009874 | 21/40 @ 0.007187 | 15/40 @ 0.007478 |
| 0.005 | 2/40 @ 0.005590 | 17/40 @ 0.003122 | 15/40 @ 0.003557 |
| **0.002** | **0/40 @ 0.002033** | **15/40 @ 0.002033** | 3/40 @ 0.000799 |
| 0.001 | 0/40 @ 0.000726 | 14/40 @ 0.001597 | 3/40 @ 0.000799 |
| 0.0005 | 0/40 @ 0.000290 | 12/40 @ 0.000145 | 0/40 @ 0.000363 |

**The 0.002 row is an exactly matched operating point that arose from the
pre-registered grid without ever touching the test set.** ARM A and ARM F land on
the *identical* realised test FPR of 0.0020328154493974154, and at that shared
false-alarm burden ARM F detects 15/40 episodes while ARM A detects 0/40. The
paired interval there is [+0.2250, +0.5250] with 15 episodes gained and 0 lost.
This is the strict same-budget comparison the previous benchmark could not
produce, and it is stronger than the 1% contrast.

ARM A's Ares detection is brittle: it collapses from 13/40 to 2/40 between the 1%
and 0.5% targets and to 0/40 at 0.2% and below. ARM F still detects 12/40 at
0.0005 with a realised FPR of 0.000145, an order of magnitude below ARM A's rate
at 1%.

### ssh_patator — episodes detected / realised test FPR

| Target train FPR | A | F | J1 |
|---|---|---|---|
| 0.01 | 1/9 @ 0.009101 | 0/9 @ 0.006613 | 0/9 @ 0.004693 |
| 0.005 | 1/9 @ 0.003626 | 0/9 @ 0.006613 | 0/9 @ 0.004693 |
| 0.002 | 1/9 @ 0.001351 | 0/9 @ 0.002844 | 0/9 @ 0.003555 |
| 0.001 | 1/9 @ 0.001209 | 0/9 @ 0.002133 | 0/9 @ 0.002702 |
| 0.0005 | 1/9 @ 0.000213 | 0/9 @ 0.001564 | 0/9 @ 0.001991 |

ARM A holds its single ssh episode at every point, down to a realised FPR of
0.000213. Neither F nor J1 detects it anywhere.

### The four other attack families at 1%

| Family | A | F | J1 |
|---|---|---|---|
| ftp_patator | 1/1, ROC 0.8881, PR 0.0336, FPR 0.007366 | 1/1, ROC 0.9973, PR 0.6524, FPR 0.004005 | 1/1, ROC 0.9453, PR 0.0724, FPR 0.001716 |
| ddos/loit | 2/2, ROC 0.9903, PR 0.3113, FPR 0.017042 | 2/2, ROC 0.9999, PR 0.9623, FPR 0.006111 | 2/2, ROC 0.9999, PR 0.9550, FPR 0.003666 |
| dos/hulk | 2/2, ROC 0.9680, PR 0.1639, FPR 0.010265 | 2/2, ROC 0.9768, PR 0.5921, FPR 0.005133 | 2/2, ROC 0.9739, PR 0.5287, FPR 0.004919 |

No major regression elsewhere. F and J1 keep full episode recall on all three at
1% and improve ROC, PR and FPR. Across the curve, J1 loses one dos/hulk episode
at the two strictest points (1/2 at 0.001 and 0.0005) where F keeps 2/2.
**ssh_patator is the only family where ARM F regresses.**

## 6. Answers to the eight questions

**1. Is ARM F genuinely superior to ARM A at a comparable operating point?**
Yes, ratified **SUPPORTED**. All three pre-registered conditions hold: episode
recall 0.5250 > 0.3250, paired interval [+0.0750, +0.3250] strictly positive, and
realised test FPR 0.007187 ≤ 0.009874. ARM F Pareto-dominates ARM A — more
episodes for fewer false alerts, which is strictly stronger than parity. The
0.002 grid point adds an exactly matched-FPR confirmation: 15/40 against 0/40 at
an identical realised FPR of 0.0020328154493974154.

**2. Does ARM J1 gain simultaneously on Ares and ssh_patator?**
No. On ssh it recovers nothing: 0/9 at all five points, same as ARM F, with the
paired interval indistinguishable from both A and F. On Ares it is strictly worse
than ARM F: 15/40 against 21/40, paired interval [−0.2750, −0.0500], six episodes
lost and none gained. Against ARM A its Ares gain is +2 episodes with interval
[+0.0000, +0.1250], whose lower bound touches zero, so it is **not** a
demonstrated improvement over ARM A either. ARM J1 is worse than F on the primary
endpoint and no better than F on the co-primary.

**3. Best observed compromise?**
**ARM F**, on the evidence and only under R11. It is the sole arm with a ratified
gain on the primary endpoint, it dominates on FPR at every operating point, and
it improves ROC, PR and FPR on the three non-ssh held-in families. Its one real
cost is ssh_patator, where it drops ARM A's single episode and its ROC-AUC falls
below chance to 0.3992. If detecting interactive SSH brute force matters
operationally, ARM F alone is not sufficient and ARM A retains a capability F
lacks.

**4. Cost in false alerts?**
None; ARM F is cheaper everywhere. At 1% Ares its realised FPR is 0.007187
against ARM A's 0.009874. At every one of the five points and on every family
except the two strictest ssh rows, F's realised FPR is at or below A's. ARM J1 is
cheaper still (0.007478 Ares, 0.004693 ssh) but buys nothing with the saving. The
trade-off is not recall against false alarms — it is Ares recall against ssh
capability.

**5. Are the gains distributed across entities or concentrated?**
**Concentrated.** ARM F's eight new Ares episodes come from two of five entities,
and six of the eight from a single one:

| Entity | A | F | F − A | J1 | J1 − A |
|---|---:|---:|---:|---:|---:|
| 192.168.10.14 | 4/8 | 4/8 | +0 | 4/8 | +0 |
| **192.168.10.15** | 2/8 | **8/8** | **+6** | 4/8 | +2 |
| 192.168.10.5 | 3/7 | 3/7 | +0 | 3/7 | +0 |
| 192.168.10.8 | 2/2 | 2/2 | +0 | 2/2 | +0 |
| **192.168.10.9** | 2/15 | 4/15 | **+2** | 2/15 | +0 |

Three of five entities are unchanged. `192.168.10.9` remains poorly detected by
every arm (4/15 at best). ARM J1's smaller gain comes entirely from
`192.168.10.15`. This concentration is the single most important caveat on the
result: ARM F's advantage rests largely on one victim host's traffic against one
attacker.

**6. Do the 95% intervals allow a conclusion?**
On Ares, yes. F − A is [+0.0750, +0.3250] and J1 − F is [−0.2750, −0.0500]; both
exclude zero, so ARM F beats ARM A and ARM J1 is worse than ARM F. J1 − A is
[+0.0000, +0.1250], which touches zero and therefore concludes nothing.
On ssh, no. With 9 episodes and a one-episode difference, all three intervals
include zero. The ssh comparison is **underpowered by construction**; the honest
statement is that it is undetermined, not that the arms are equivalent.

**7. What can be concluded under R11?**
Only that, on this capture, non-printable byte ratios raise Ares episode recall
at a lower false-alarm rate than the volumetric baseline, for these five victim
entities against this single attacker host `205.174.165.73`. Given that six of
eight new episodes come from one entity, the mechanism may be specific to one
host's payload behaviour rather than to Ares command-and-control in general.
Nothing here demonstrates transfer to another victim, attacker, capture or botnet
family, and no streaming ingestion latency was measured. R11 remains open.

**8. Which configuration should be the final PFA model?**
**ARM F**, declared as a ratified improvement on the Ares endpoint under R11,
with its ssh_patator regression stated as a known limitation rather than
omitted. ARM J1 must not be presented as an improvement: it is worse than F on
the primary endpoint and indistinguishable from F on the co-primary.

If the deliverable needs coverage of both threat classes, the honest engineering
answer is that **no single arm tested achieves it**. The Ares/ssh trade-off
remains **unresolved**: `distinct_payload_ratio` alone detects the ssh episode
and few Ares episodes; adding non-printable ratios reverses that; adding
`interarrival_mean` back repairs ssh *ranking* (ROC 0.3992 → 0.9049) without
recovering the episode, while sacrificing six Ares episodes. Resolving it would
require a new pre-registered experiment — for example two specialised detectors
rather than one shared budget — which is outside the scope authorised here.

## 7. Why `interarrival_mean` did not deliver

Its test-set missingness is **59.0% on the Ares fold and 61.9% on the ssh fold**:
the P6 definition is the mean of consecutive start-time differences and is
undefined for windows containing fewer than two flows. Undefined values remain
native NaN and reach XGBoost's missing branch, as ratified. A feature absent from
roughly three windows in five can repair a global ranking, which it did, but it
cannot reliably lift a specific episode above a strict threshold.

Its gain share is 0.1674 on the Ares fold and 0.0356 on the ssh fold, so the
model leant on it least exactly where it was supposed to help.

## 8. Integrity and reproducibility

- 36 artifacts published under `artifacts/experiments/armf_ratification_armj1/`,
  each digest recorded in `manifest.json`.
- **Idempotence verified**: a second full `--execute` refitting all 15 models
  reproduced every artifact byte-for-byte. The publication path is
  immutable-or-raise, so any drift would have aborted the run.
- All 87 six-arm content benchmark outputs and all 44 frozen A–D outputs still
  match their published digests.
- `p1_population_or_folds_modified: false`, `frozen_ad_benchmark_modified:
  false`, `six_arm_content_benchmark_modified: false`,
  `published_baseline_modified: false`, `postgresql_writes: 0`.
- 31 regression tests pin the pre-registered budgets, the five operating points,
  the verdict rule, the non-ratifying status of the equal-alert-budget
  diagnostic and the published digests.

Environment: xgboost 2.1.0, scikit-learn 1.5.1, numpy 1.26.4.

## 9. Secondary diagnostic — equal alert budget, never ratifying

| Family | ARM A alert budget | A | F | J1 |
|---|---:|---:|---:|---:|
| botnet/ares | 160 | 13/40 | 21/40 | 15/40 |
| ftp_patator | 106 | 1/1 | 1/1 | 1/1 |
| ssh_patator | 161 | 1/9 | 0/9 | 0/9 |
| ddos/loit | 293 | 2/2 | 2/2 | 2/2 |
| dos/hulk | 165 | 2/2 | 2/2 | 2/2 |

Granted exactly ARM A's alert count, ARM F still finds 21/40 against 13/40, and
ARM J1 still recovers no ssh episode — so J1's ssh failure is not a threshold
artefact, it genuinely does not rank that episode's windows in the top 161. This
table aligns budgets using test-set alert counts and therefore informs the
operational reading without ratifying any arm.
