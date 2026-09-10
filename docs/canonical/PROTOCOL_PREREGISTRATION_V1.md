# Pre-registration — Priority-family transfer protocol, v1

> **STATUS: PRE-REGISTERED, NOT EXECUTED.**
> No model has been fitted, no split materialised, no threshold computed, no
> metric measured. This document and its manifest exist so that the protocol is
> fixed *before* any result can influence it.

## 1. Question

Two questions, kept separate throughout:

1. **Family transfer.** Can a detector trained on six priority attack families
   detect a seventh priority family that is entirely absent from its training
   and validation data?
2. **False-positive robustness across captures.** Does the operating point
   calibrated on Monday benign traffic hold on an independent capture day
   (Thursday) that never contributed to training, validation, or threshold
   calibration?

These are reported separately and never combined into a single score.

## 2. Scope

**In scope — the seven priority families**, with their frozen ground truth from
`artifacts/production/ml_dataset_v2/ground_truth.json` (M5 v3):

| Family | Windows | Episodes | Entities | Capture | Disposition |
|---|---:|---:|---:|---|---|
| `brute_force/ftp_patator` | 61 | 1 | 1 | Tuesday | target_attack |
| `brute_force/ssh_patator` | 60 | 9 | 2 | Tuesday | target_attack |
| `dos/hulk` | 36 | 2 | 2 | Wednesday | target_attack |
| `dos/slowloris` | 46 | 2 | 2 | Wednesday | known_other_attack |
| `dos/slowhttptest` | 26 | 8 | 2 | Wednesday | known_other_attack |
| `dos/goldeneye` | 16 | 4 | 2 | Wednesday | target_attack |
| `ddos/loit` | 42 | 2 | 2 | Friday | target_attack |
| **Total** | **287** | **28** | **4 distinct keys** | — | — |

**Out of scope, and physically excluded from every population:**

- `botnet/ares` — 177 windows, 40 episodes, 5 entities. Never in TRAIN, never in
  VALIDATION, never in HOLDOUT. Out of perimeter by decision.
- The three Thursday Web Attack families — `web_attack/web_bruteforce` (79
  windows, 2 episodes), `web_attack/xss` (41, 3), `web_attack/sql_injection`
  (3, 1). They remain `known_other_attack` and are **never** used as primary
  evidence of transfer to the priority families. They are neither positives nor
  negatives in this protocol.
- Every `unknown` and `ambiguous` window, on all captures.
- ARM F, payload/content features, temporal-persistence rules, Ares diagnostics.

**Feature budget: VOL5**, in the frozen order of `p1_dataset.FEATURE_NAMES`:
`event_count`, `source_packets_total`, `destination_packets_total`,
`source_bytes_total`, `destination_bytes_total`. No content feature, no
transform, no scaling.

## 3. Design: seven folds, one per priority family

For each priority family **F**, exactly one fold is built.

### 3.1 TRAIN

| Component | Content |
|---|---|
| Positives | the **6** priority families other than F, from `ml_dataset_v2` |
| Negatives | Monday `benign_reference` windows whose entity falls in the TRAIN benign partition (§3.2) |
| Excluded | every window of F; all Ares; all Thursday; all `unknown`; all `ambiguous`; all Thursday Web Attack windows |

Positive counts per fold, derived by subtraction from the frozen ground truth:

| Fold (F held out) | TRAIN positive windows | TRAIN positive episodes |
|---|---:|---:|
| FTP-Patator | 226 | 27 |
| SSH-Patator | 227 | 19 |
| DoS Hulk | 251 | 26 |
| DoS Slowloris | 241 | 26 |
| DoS SlowHTTPTest | 261 | 20 |
| DoS GoldenEye | 271 | 24 |
| DDoS LOIT | 245 | 26 |

**Explicit non-claim.** The six training families are **not** entity-disjoint
from F. All seven priority families are carried by only four entity keys, all
sharing a single attacker IP and a single victim IP:

```
172.16.0.1|192.168.10.50|tcp|ftp    ftp_patator only
172.16.0.1|192.168.10.50|tcp|ssh    ssh_patator only
172.16.0.1|192.168.10.50|tcp|none   ssh_patator, hulk, slowloris, slowhttptest, goldeneye, loit
172.16.0.1|192.168.10.50|tcp|http   hulk, slowloris, slowhttptest, goldeneye, loit
```

Only for **FTP-Patator** does holding out F also remove its entity key from
TRAIN. For the six others the key persists through another family. This is stated
in every fold's record and is never described as entity-disjointness.

### 3.2 Monday benign partition — TRAIN versus VALIDATION

Deterministic, no randomness, reusing the frozen rule of
`p1_dataset.negative_fold_of`:

```
fold(entity_key) = int(sha256(entity_key).hexdigest(), 16) mod 5
folds 0,1,2,3  -> TRAIN benign
fold 4         -> VALIDATION benign
```

Consequences, pre-registered:

- benign entities are **entity-disjoint** between TRAIN and VALIDATION: no
  benign entity contributes to both;
- the partition depends only on the entity key, never on a feature value, a
  label, a score, or a model;
- expected magnitude, from the observed fold sizes in
  `artifacts/experiments/p1/p1_leakage_verification.json` (13,774 to 14,728
  negatives per fifth of the 70,578 Monday windows): roughly 56,000 TRAIN benign
  and roughly 14,000 VALIDATION benign. Exact counts are computed at execution
  and recorded then; they are not needed to fix the protocol.

### 3.3 VALIDATION INTERNAL

**No hyperparameter selection. No tuning. No model selection.** The
hyperparameters are those of P1, adopted unchanged and declared here:

```
RandomForestClassifier(n_estimators=200, random_state=0, class_weight=None)
```

Source: `modules/detection/src/experiments/p1_evaluation.py`, decisions D6 and
D7. Nothing is searched, compared, or chosen. One model is fitted per fold.

The internal validation set has exactly **two** pre-registered roles:

1. **Threshold derivation.** The decision threshold is computed on
   VALIDATION benign scores only, by the frozen rule of
   `p1_evaluation.threshold_at_train_fpr`: the smallest candidate score `t` drawn
   from the observed negative scores such that
   `mean(validation_negative_scores >= t) <= target_fpr`.
   Targets: **primary 1 %**, secondary 0.1 %. Both are the frozen `FPR_TARGETS`
   of P1; neither is invented here.
2. **Sanity checks**, each with a pre-registered pass condition, recorded but
   never used to alter the model: the fit completed; no score is NaN or
   infinite; the negative score distribution is not degenerate (more than one
   distinct value); the achieved validation FPR is at or below its target; F
   contributes zero rows to TRAIN and zero rows to VALIDATION.

**This is the methodological improvement over P1.** P1 derived its threshold from
the *training* negatives, in-sample. Here the threshold comes from benign
entities that are entity-disjoint from the fitting set and never seen during
fitting. The holdout is never consulted for any purpose.

### 3.4 GEL — cryptographic freeze before the holdout is opened

Before a single holdout row is read, the following are hashed and recorded in
`protocol_manifest.json`, and a per-fold `fold_freeze.json` is written after
fitting but before scoring the holdout:

| Frozen item | How it is pinned |
|---|---|
| Attack population and labels | SHA-256 of `ml_dataset_v2/{ml_dataset.csv, window_labels.csv, ground_truth.json, label_policy_v3.json}` |
| Label policy | SHA-256 of `m5_policy_v3.py` and `cicids2017_labels.yaml` |
| Thursday benign definition | SHA-256 of `THURSDAY_WINDOW_LABEL_AUDIT.json`, `audit_thursday_windows.py`, the TH2 `replay_run.json` and `conn.log`, the TH1 freeze and the TH2 specification |
| Preparation code | SHA-256 of `p1_dataset.py`, `p1_evaluation.py`, and the new runner once written |
| Model and hyperparameters | the literal string above, plus the SHA-256 of each fitted `.joblib` recorded at gel time |
| Threshold | the numeric value, its target, its achieved validation FPR, recorded before holdout scoring |
| Decision rule | `flag(window) := score >= threshold` |
| Episode definition | §5.1, fixed text |
| Metric definitions | §5, fixed text |
| Exclusion criteria | §2 and §4.2, fixed text |

`scripts/verify_preregistration.py` recomputes every pinned digest and fails on
any divergence. It is intended to be run twice: once before the holdout is
opened and once after the results are published, so that "nothing changed after
opening the holdout" is demonstrable rather than asserted.

### 3.5 HOLDOUT — opened once, per fold

| Component | Content | Count |
|---|---|---:|
| Positives | all windows of family F | 16 to 61 per fold |
| Negatives | Thursday `benign_reference` | **32,813** |

The Thursday negative population is **not reconstructed**. It is exactly the
population defined by the already-ratified audit, pinned by hash:
`artifacts/production/thursday_audit_v1/THURSDAY_WINDOW_LABEL_AUDIT.json`
(`cf32b489c5fa3162f1d6eeb0a37a58ad5e9bc319acc9ed18383f05fdd156530f`), produced by
`scripts/audit_thursday_windows.py`
(`ae4a29d17010b77c42214d3ce33818c5fb74d6663a4ba6033f2d7b0b1c97f98c`) from the TH2
`conn.log` (`2180f823988d4cad0067910a5290e503f081e2aa8ef1cacf1c4852a2cd227fc1`).

Its ratified exclusions, restated verbatim as the definition:

- outside every declared attack interval, including the two unlabelled
  Infiltration rules (17,615 windows excluded on this ground);
- `192.168.10.8` and `192.168.10.25` excluded across the whole capture, in both
  directions (5,155 windows);
- `172.16.0.1 -> 192.168.10.50` never a negative (50 windows);
- `205.174.165.73` excluded whenever it is an endpoint (3 windows);
- every ambiguous window excluded;
- **no `unknown -> benign_reference` conversion, ever.**

**One additional artifact is required, and here is precisely why.** The audit JSON
is an *aggregate* report: it records counts, not per-window rows. Scoring
requires the VOL5 feature vector of each of the 32,813 windows. A per-window
table must therefore be emitted — `thursday_benign_windows.csv`, columns
`entity_key, window_start_epoch, event_count, source_packets_total,
destination_packets_total, source_bytes_total, destination_bytes_total,
disposition` — by the **same already-hashed policy code path**, with no new
labelling decision. It must be generated and hashed **before** the holdout is
opened, and its row count must equal 32,813 exactly. That equality is a
pre-registered gate: if it does not hold, the protocol halts.

## 4. Separation guarantees

### 4.1 What the protocol guarantees

| Guarantee | Basis |
|---|---|
| **Family-disjoint holdout positives** | F contributes zero rows to TRAIN and VALIDATION, asserted per fold |
| **Capture-disjoint negatives** | threshold calibrated on Monday; FPR measured on Thursday |
| **Benign entity-disjointness between TRAIN and VALIDATION** | deterministic `sha256(entity_key) mod 5` |
| **Threshold never touches the holdout** | derived from VALIDATION benign only, recorded before opening |
| **No tuning** | hyperparameters fixed to P1's, single fit per fold |
| **Determinism** | `random_state=0`, no sampling, no randomised split |
| **Temporal separation of negatives** | Monday (2017-07-03) for calibration, Thursday (2017-07-06) for measurement |

### 4.2 What the protocol explicitly does NOT guarantee

> **The holdout is not entity-disjoint at the IP or entity_key level.**

- The six training families share entity keys with F for every family except
  FTP-Patator.
- Thursday shares **three of the four** priority entity keys with P1:
  `172.16.0.1|192.168.10.50|tcp|{ftp, http, none}`. Those keys are excluded from
  the Thursday negatives by the ratified policy, but their presence in the
  capture means Thursday is the **same network environment**, not new
  infrastructure.

The claimed property is therefore:

**unseen attack family + independent capture/day for benign FPR**

and explicitly **not**:

**unseen infrastructure / entity generalisation**.

## 5. Metrics, pre-registered

### 5.1 Episode definition

Frozen, identical to `p1_dataset` decision D2: an **episode** is a maximal run of
consecutive 60-second windows sharing the same `(attack_type, entity_key)`; a gap
larger than one window length starts a new episode. An episode is **detected**
if **at least one** of its windows has `score >= threshold`.

### 5.2 Primary metric

**Episode recall at the frozen threshold** = `episodes detected / total episodes`,
reported per family with a **Wilson 95 % confidence interval**, chosen in advance
because it behaves correctly at small denominators and at proportions of 0 and 1,
where a normal-approximation interval does not.

### 5.3 Secondary metrics

- **Window recall** at the frozen threshold.
- **Thursday FPR** = `false positives / benign_reference windows`, denominator
  exactly **32,813**, reported together with the **absolute** false-positive
  count.
- **ROC-AUC and PR-AUC**, reported only on the pooled holdout population
  (F positives together with the 32,813 Thursday negatives), where both classes
  are present. They are reported as threshold-free descriptors and are never
  used to choose a threshold or a model. PR-AUC is accompanied by its base rate,
  since the class ratio varies across folds.
- The achieved **validation** FPR at gel time, for comparison with the measured
  Thursday FPR.

### 5.4 Comparison with the known performance on seen families

For the four families with a published P1 family-novelty result
(`artifacts/experiments/p1/P1_REPORT.md`), the new result is tabulated beside it,
with the differences in protocol stated in the same table: P1 calibrated its
threshold in-sample on training negatives and measured its FPR on Monday
negatives, whereas this protocol calibrates on held-out Monday validation
negatives and measures FPR on Thursday. **P1 is not modified, not re-run, and
not re-interpreted.** The comparison is qualitative and directional; no
statistical test between the two protocols is pre-registered, because their
negative populations differ.

### 5.5 Handling small episode counts

No family is declared invalid for having few episodes. Instead, a fixed
three-tier reporting rule applies, assigned by episode count **before** any
result is seen:

| Tier | Families | Reporting rule |
|---|---|---|
| **Descriptive, high uncertainty** | FTP-Patator (1), Hulk (2), Slowloris (2), LOIT (2), GoldenEye (4) | point estimate plus Wilson CI, explicitly labelled as not supporting a statistical conclusion on its own |
| **Weak statistical weight** | SlowHTTPTest (8), SSH-Patator (9) | point estimate plus Wilson CI; carries more weight, still reported as prudent and not conclusive |
| **Pooled** | all 7, over the 28 episodes | pooled episode recall plus Wilson CI, with the explicit caveat that the folds are not independent because they share entity keys and a common benign calibration population |

## 6. Success criterion, pre-registered and descriptive

No arbitrary count such as "4 of 7" is used.

**Episode recall and FPR are never compared to each other.** They measure
different things on different populations, and a direct comparison would not be a
sound statistical justification — least of all for the five families with one to
four episodes. They are therefore reported as two independent quantities, and the
transfer conclusion is qualitative.

### 6.1 Transfer conclusion — descriptive, three fixed categories

Assigned per family from the episode recall point estimate, the width and
position of its Wilson 95 % interval, and the observed FPR reported alongside.
The wording is fixed here, before any result exists:

| Category | Meaning |
|---|---|
| **Results compatible with transfer** | episode recall is substantial and its Wilson interval excludes zero, at an operating point whose measured FPR is within the pre-registered tolerance |
| **Limited or inconclusive evidence** | episode recall is non-zero but its Wilson interval is too wide to distinguish outcomes, or the measured FPR exceeds the tolerance so the recall cannot be read cleanly |
| **No evidence of transfer** | episode recall point estimate is zero, or its Wilson interval is consistent with zero |

Every assignment is reported with the numbers that produced it, so a reader can
disagree with the wording while seeing the same evidence. No family in the
"descriptive, high uncertainty" tier of §5.5 supports a conclusion on its own,
whichever category it lands in. None of these categories is a claim about
generalisation beyond CICIDS2017.

### 6.2 Operating-point transfer — the one numeric criterion

Pre-registered, evaluated independently of any recall figure:

- **"Operating point transfers"** if the Thursday-measured FPR is at most
  **2 %**, that is twice the 1 % calibration target. The factor two is fixed here,
  before any measurement, as the tolerance for a change of capture day.
- **"Operating point degrades"** otherwise, in which case the fold's recall
  figures must be read against the inflated FPR and cannot support a transfer
  statement.

### 6.3 Aggregate reporting

No pass/fail threshold. Reported as-is: the category of each of the seven
families, the pooled episode recall over the 28 episodes with its Wilson
interval, and the seven Thursday FPR values with their absolute false-positive
counts. **No success threshold may be introduced after the results are seen.**

## 7. What remains impossible to guarantee, by construction of CICIDS2017

1. **Entity-disjoint evaluation of the DoS and DDoS families.** All six
   DoS/DDoS-family populations sit on the same two entity keys. No split can
   separate them. Only FTP-Patator is entity-key-disjoint when held out, and even
   it shares the single attacker and victim IP pair.
2. **Separating "detects a DoS" from "recognises this network pair".** Would
   require the same families launched from other attackers against other victims.
3. **New infrastructure.** Thursday is the same topology and address plan; three
   of the four priority entity keys reappear there.
4. **Narrow confidence intervals.** 28 episodes across seven families, five of
   them with four episodes or fewer.
5. **A statistical conclusion for FTP-Patator.** One episode, whatever the
   method.
6. **Priority-family positives on an independent capture.** Thursday contains no
   FTP, SSH, DoS or DDoS family; its three web families are `known_other_attack`
   and are excluded from the transfer question by decision.
7. **Any claim about real-world traffic.** One synthetic environment, one week of
   2017, a single topology.

Lifting items 1 to 3 and 6 requires captures with the same families on different
entities — for example CSE-CIC-IDS2018 — which is outside the current perimeter.

## 8. Execution order, once authorised

1. Emit and hash `thursday_benign_windows.csv`; assert 32,813 rows.
2. Build the seven folds; assert per fold that F contributes zero TRAIN and zero
   VALIDATION rows, that Ares and Thursday contribute nothing, and that benign
   TRAIN and VALIDATION entities are disjoint.
3. Fit one model per fold with the frozen hyperparameters.
4. Derive the threshold from VALIDATION benign only; run the sanity checks.
5. Write `fold_freeze.json` per fold, including model digest and threshold.
6. Run `verify_preregistration.py`.
7. **Open the holdout once.** Score F positives and the 32,813 Thursday negatives.
8. Compute only the metrics of §5.
9. Run `verify_preregistration.py` again and publish both results.

Steps 3 onward require explicit authorisation and are **not** performed by this
pre-registration.
