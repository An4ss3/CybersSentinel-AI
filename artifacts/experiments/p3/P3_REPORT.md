# P3/D — Unsupervised anomaly benchmark, Monday benign only

Executed 2026-08-17. Zero PostgreSQL writes. P1 and P2 untouched.

## Design

`IsolationForest(n_estimators=200, random_state=0, n_jobs=1)` fitted on
`benign_reference` windows **only**. No positive, no `unknown` and no `ambiguous`
window entered fitting, calibration or any hyper-parameter choice.

`predict()` is never called: its operating point derives from `contamination`,
whereas every threshold here comes from the calibration block alone.
`score_samples` is negated so higher means more anomalous.

**Decision D12 — contiguous temporal split of the benign day**, no randomness:

| Block | Windows | Epoch range | Purpose |
|---|---|---|---|
Fit | 35 289 | 1499083200 – 1499094120 | fits the model |
Calibration | 17 644 | 1499094120 – 1499102820 | sets the threshold, nothing else |
Measurement | 17 645 | 1499102820 – 1499112000 | measures the false-positive rate |

Blocks are disjoint and ordered in time, so no minute of benign traffic informs
both the fit and its own evaluation.

## The two rates, and why they are not the same thing

| | **Measured false-positive rate** | **Alert rate on unlabelled** |
|---|---|---|
Population | held-out `benign_reference` measurement block | M6 windows the M5 v2 policy leaves `unknown` |
Size | 17 645 | 172 372 |
Label provenance | frozen M5 v1 `monday-benign-reference` rule | **none — M5 could not classify them** |
A flag there is | a genuine false positive | uninterpretable: possibly a true positive no rule covers |
May be called | FPR, false positive, error | **none of those** |

Reading the second column as an error rate would silently convert `unknown` into
`benign`, which the project forbids without an explicit M5 rule.

## Results

### Operating point: 1% calibration target

Threshold 0.729957, achieved calibration rate 0.009975.

| | Value |
|---|---|
**Measured FPR** on known benign | 281 / 17 645 = **0.015925** |
**Alert rate** on unknown (not an FPR) | 2 514 / 172 372 = **0.014585** |
Attack window recall | 0.4468 |
Attack episode recall | **0.0926**, 95% CI [0.0185, 0.1667] over 54 episodes |

| Attack type | Windows | Episodes | Window recall | **Episode recall** | 95% CI |
|---|---|---|---|---|---|
`botnet/ares` | 177 | 40 | **0.0000** | **0.0000** | [0.000, 0.000] |
`brute_force/ftp_patator` | 61 | 1 | 0.9672 | 1.0000 | [1.000, 1.000] |
`brute_force/ssh_patator` | 60 | 9 | 0.8667 | 0.1111 | [0.000, 0.333] |
`ddos/loit` | 42 | 2 | 0.5000 | 0.5000 | [0.000, 1.000] |
`dos/hulk` | 36 | 2 | 1.0000 | 1.0000 | [1.000, 1.000] |

### Operating point: 0.1% calibration target

Threshold 0.828481, achieved calibration rate 0.000964.

| | Value |
|---|---|
**Measured FPR** on known benign | 30 / 17 645 = **0.001700** |
**Alert rate** on unknown (not an FPR) | 293 / 172 372 = **0.001700** |
Attack window recall | 0.1436 |
Attack episode recall | **0.0556**, 95% CI [0.0000, 0.1296] |

Only `dos/hulk` (episode recall 1.000) and `ddos/loit` (0.500) survive this
threshold. `ftp_patator`, `ssh_patator` and `botnet/ares` all fall to **0.0000**.

## Three findings

### 1. The botnet blindness is total, not merely weak

`botnet/ares` window recall and episode recall are **exactly 0.0000 at both
thresholds** — 0 of 177 windows, 0 of 40 episodes. P1 managed 0.017 window / 0.075
episode; P2 reached 0.045 / 0.150. A detector trained only on benign traffic cannot
flag traffic that is **less** voluminous than benign, and `botnet/ares` averages
4.158 events per window against the benign 5.202.

This is now confirmed by three independent designs. It is a property of the
five-feature volume budget, not of any model or protocol.

### 2. Calibration transfers imperfectly across the day, and this is not overfitting

Target 1% → achieved 0.9975% on the calibration block → **1.59% on the measurement
block**, a 1.6× overshoot. Unlike the in-sample bias documented in P1, the
calibration block here was **not** fitted, so this is not memorisation. It measures
**within-day non-stationarity**: the last quarter of the Monday differs from the
third quarter enough to move the false-positive rate by 60%.

Any deployed threshold calibrated on one part of a day should therefore be expected
to drift on another part of the same day.

### 3. The unknown population alerts at a rate close to the known-benign rate

At the 1% operating point: 1.46% on `unknown` against 1.59% on known benign. At the
0.1% point the two rates are 0.0017 and 0.0017.

**This does not mean `unknown` is benign, and it is not evidence that it is.** The
similarity is consistent with at least three explanations that this benchmark cannot
distinguish: most `unknown` windows really are ordinary traffic; or the detector is
insensitive to whatever distinguishes them; or true positives hide among them in a
proportion too small to move the rate. Recall that 359 M6 windows have the attacker
`172.16.0.1` as source entity and are labelled `unknown`. The number is reported
because it is the honest way to describe behaviour on an unlabelled population, not
as a validation of the labels.

## Comparison with P1 and P2, episode recall

| Attack type | P1 | P2 | **P3** |
|---|---|---|---|
`botnet/ares` | 0.075 | 0.150 | **0.000** |
`brute_force/ftp_patator` | 1.000 | 1.000 | 1.000 |
`brute_force/ssh_patator` | 0.111 | 0.111 | 0.111 |
`ddos/loit` | 1.000 | 1.000 | 0.500 |
`dos/hulk` | 1.000 | 1.000 | 1.000 |
**Pooled** | 0.167 | 0.222 | **0.093** |

P3 is the hardest and most honest of the three: P1 and P2 saw four of the five
attack types during training, P3 saw none. Its lower pooled recall is expected and
should not be read as a worse method — it answers a stricter question.

## Limitations

**R11 is removed from the learning stage but not from the evaluation.** No positive
is fitted, so attack diversity cannot bias the model. It does not make the 376
attacks an independent sample: recall uncertainty is still governed by 54 episodes
drawn from 9 entities and 6 host pairs, which is why every interval here is
bootstrapped over episodes and several are extremely wide — `ddos/loit` spans
[0.000, 1.000] on two episodes.

**Window-level bootstrap remains forbidden** and is not used anywhere.

## Artifacts

| File | SHA-256 |
|---|---|
`p3_metrics.json` | see repository |
`p3_predictions.csv` | scores for attack, benign calibration, benign measurement and unlabelled groups |
`p3_model_isolation_forest.joblib` | the single fitted model |
