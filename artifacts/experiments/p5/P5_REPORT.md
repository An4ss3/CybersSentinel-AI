# P5/E — Feature budget extension

**Hypothesis under test.** The five volume features cannot express low-intensity C2
behaviour, but the data contain temporal beaconing signal.

**Verdict on the pre-registered endpoint: NOT CONFIRMED.** Botnet episode recall
doubled, from 0.075 to 0.150, but the confidence intervals overlap, ROC-AUC stayed
at chance, and the false-positive rate rose by a comparable factor. The result is
suggestive, not established. **XGBoost was not trained** and no further step was
taken, per the standing instruction.

## Design

| | Arm A | Arm B |
|---|---|---|
Features | the five volume features | the same five **+ `duration_mean`, `interarrival_mean`, `interarrival_cv`** |
Population | identical, digest `3d743617…` | identical |
Folds | frozen P1 folds, digest `e463ea7b…` | identical |
Test sets | identical in all five folds | identical |
Model | `RandomForestClassifier(200, random_state=0)` | identical |
Threshold rule | training negatives only, 1% target | identical |
Bootstrap | episode level, 2 000 resamples, seed 0 | identical |

Nothing else changed. No hyper-parameter was tuned, no feature was selected on the
test set, and zero PostgreSQL writes occurred.

**Arm A reproduces published P1 exactly** on all five folds — ROC-AUC, PR-AUC,
window recall, episode recall, threshold and observed FPR all agree to within
1e-12. The control is therefore anchored to the published reference, and any arm A
to arm B difference is attributable to the feature budget alone.

### A reproducibility defect found in P1's artifacts, and worked around

`p1_folds.json` stores `sorted(train_row_ids)`, but `run_p1_supervised.py` trained
on the order `build_folds` produces, which places training positives **before**
training negatives. `RandomForestClassifier` bootstrap sampling is order-sensitive,
so **loading the published folds file reproduces the split but not the model.**

A first P5 execution did exactly that and produced a baseline that was not P1:
botnet ROC 0.5068 instead of 0.5037, and `ftp_patator` window recall 0.1803 instead
of 0.9836. That output was discarded and the run repeated after recovering the
authentic ordering. Membership is still proven against the published file two
independent ways: the canonical folds digest, and per-fold set equality.

**This is a defect in P1's published artifacts, not in P1's results.** P1 remains
internally reproducible and was not modified. The folds file is sufficient to audit
the split and insufficient to re-fit the model; that limitation is now recorded.

## Missingness policy (decision D13)

`interarrival_mean` requires at least one gap (≥ 2 events) and `interarrival_cv` at
least two gaps (≥ 3 events). Undefined values are encoded as the explicit sentinel
**`-1.0`**. Measured: `interarrival_mean` is absent on **41 411 of 70 578
negatives, 58.67%**.

Imputation was rejected because a median or mean would introduce a fitted parameter
outside the ratified protocol, and fitting it across train and test would be
leakage. The sentinel is constant, deterministic, and cannot collide with a real
value because durations, gaps and coefficients of variation are all non-negative.

**No missingness indicator feature was added.** Availability is exactly
`event_count >= 2`, and `event_count` is already an admitted feature, so an
indicator would duplicate information the model already holds. The sentinel is
therefore **a re-encoding of window length and must not be described as an
independent behavioural signal.**

## Duration and operational availability (decision D14)

`duration_mean` is computed over `FlowEnd` records. Two different statements must
not be conflated:

- **Benchmark validity at flow level** — sound. Every row in this evidence is a
  completed flow, so the feature is well defined throughout.
- **Availability in a real-time detector** — *not* established. A duration exists
  only once a flow has ended. At window close an online detector would hold flows
  that have not ended and would have no duration for them.

`duration_mean` is therefore **not claimed to be an online feature.**

## Leakage audit (decision D15)

Eleven checks, **all passed**, run before any training:

| Check | Result |
|---|---|
Arm B extends arm A without altering its first five values | pass |
Arm B adds exactly three features | pass |
`row_id`, label, disposition, attack type and episode id untouched | pass |
**No absolute timestamp reachable from any feature value** | pass |
`duration_mean` does not separate the classes perfectly | pass |
`interarrival_mean` does not separate the classes perfectly | pass |
`interarrival_cv` does not separate the classes perfectly | pass |
All three vary within both classes | pass |
Populations span more than one partition, so overlap is meaningful | pass |

Inter-arrival values are **differences** of timestamps; the audit bounds every
temporal value far below the epoch magnitude rather than trusting the construction.
No feature depends on the label, and none encodes a host, a day or a capture.

## Results

All five test sets identical between arms.

| Attack type | Ep. recall A → B | Episodes | 95% CI A | 95% CI B | ROC A → B | PR A → B | Window A → B | Test FPR A → B |
|---|---|---|---|---|---|---|---|---|
**`botnet/ares`** | **0.0750 → 0.1500** | **3 → 6 / 40** | [0.0000, 0.1750] | [0.0500, 0.2750] | **0.5037 → 0.5119** | 0.0135 → 0.0145 | 0.0169 → 0.0395 | 0.009583 → 0.016045 |
`brute_force/ftp_patator` | 1.0000 → 1.0000 | 1 → 1 / 1 | [1.000, 1.000] | [1.000, 1.000] | 0.9866 → 0.9958 | 0.3007 → 0.3537 | 0.9836 → 0.9836 | 0.012157 → 0.017019 |
`brute_force/ssh_patator` | **0.1111 → 0.4444** | **1 → 4 / 9** | [0.0000, 0.3333] | [0.1111, 0.7778] | 0.9279 → 0.9554 | 0.3541 → 0.5855 | 0.8667 → 0.9167 | 0.023251 → **0.019198** |
`ddos/loit` | 1.0000 → 1.0000 | 2 → 2 / 2 | [1.000, 1.000] | [1.000, 1.000] | 0.9972 → 0.9861 | 0.5919 → 0.6962 | 1.0000 → 0.9762 | 0.024783 → 0.022882 |
`dos/hulk` | 1.0000 → 1.0000 | 2 → 2 / 2 | [1.000, 1.000] | [1.000, 1.000] | **0.8842 → 0.8629** | **0.5552 → 0.5209** | **0.7778 → 0.6389** | 0.023168 → 0.027588 |

**Every confidence interval overlaps.** No per-type difference is resolved at this
sample size.

## Primary endpoint, read strictly

Botnet episode recall moved **0.0750 → 0.1500**, that is **3 of 40 episodes to 6 of
40**. Three reasons this does not confirm the hypothesis:

1. **The intervals overlap.** [0.0000, 0.1750] against [0.0500, 0.2750]. At 40
   episodes the design cannot resolve a difference this size.
2. **ROC-AUC stayed at chance: 0.5037 → 0.5119.** The model still cannot *rank*
   botnet windows above benign ones. Had the temporal features supplied genuine
   discriminative signal, ranking would have improved; it barely moved.
3. **The false-positive rate rose from 0.009583 to 0.016045, a factor 1.67**, while
   recall rose by a factor 2.0. The gain is therefore only marginally better than
   what moving to a looser operating point would produce on its own.

Detection also remains concentrated: arm A found episodes on two botnet hosts
(`192.168.10.5`, `192.168.10.9`), arm B on three (adding `192.168.10.15`). **Two of
the five botnet hosts, `192.168.10.8` and `192.168.10.14`, are missed entirely by
both arms.**

## Secondary observations, reported and not promoted

These are not the pre-registered endpoint and must not be presented as P5's result.

**`ssh_patator` is the one unambiguous improvement.** Episode recall 0.1111 →
0.4444 on an identical test set, ROC 0.9279 → 0.9554, PR 0.3541 → 0.5855, and
crucially at a **lower** false-positive rate, 0.023251 → 0.019198. More recall for
less cost is the signature of genuinely better discrimination rather than a looser
threshold. It rests on **9 episodes** and its interval still overlaps.

**`dos/hulk` regressed on every ranking axis.** ROC 0.8842 → 0.8629, PR 0.5552 →
0.5209, window recall 0.7778 → 0.6389, at a higher FPR 0.023168 → 0.027588.
Episode recall stays 1.000 only because the fold contains 2 episodes. Adding
features made this fold worse, which is a real cost of the extension and not noise
to be dismissed.

`ftp_patator` gained in ranking (ROC 0.9866 → 0.9958) with window recall unchanged
and FPR up. `ddos/loit` gained PR (0.5919 → 0.6962) while losing slightly on ROC
and window recall.

## R11 remains in force

5 attack types, 9 entities, **6 host pairs**, 54 episodes. The botnet is 5 entities
reaching a **single** destination `205.174.165.73`. Arm B reaching one additional
host does not change that. **No improvement here licenses a claim of general
detection capability**, and no feature can create attack diversity that the
evidence does not contain.

## What P5 establishes and what it does not

**Can assert.** With identical population, labels, folds and test sets, adding
these three temporal features doubled botnet episode detection from 3 to 6 of 40
while roughly doubling the false-positive rate, left botnet ROC-AUC at chance,
improved `ssh_patator` on every axis including a lower FPR, and degraded `dos/hulk`
on every ranking axis.

**Cannot assert.** That the temporal features make low-intensity C2 detectable;
that any per-type difference is statistically resolved; that `duration_mean` is
available to a real-time detector; that the sentinel encodes behaviour rather than
window length; or any generalisation beyond these 9 entities and 6 host pairs.

## Recommendation

**Do not proceed to XGBoost.** The pre-registered endpoint did not confirm the
signal, so the condition for advancing was not met.

The evidence points at a specific diagnosis rather than a dead end: the botnet's
ranking did not improve, which suggests these three features do not capture what
distinguishes Ares C2 from benign traffic, while the `ssh_patator` result shows
they do carry real information for some attacks. The `dos/hulk` regression shows
that widening the budget is not free.

Both a further feature investigation and accepting the current benchmark as a
statement of local validity are outside what has been ratified. **Reporting and
stopping here.**

## Artifacts

| File | Digest |
|---|---|
`p5_metrics.json` content | `6d3f51af4bce3e15c7278870f98feee0d44b0b4bdd7ae7e415b20748c595ea2b` |
`p5_metrics.json` file | `87055c8b14623581` |

One artifact from a first execution, file `84dfe31518eff186`, was **deleted and
replaced**: it was computed under the wrong row ordering described above, so its
arm A was not P1. It was created during this session and was not a frozen artifact.
No P1, P2, P3 or P4 artifact was modified, and no label was changed.
