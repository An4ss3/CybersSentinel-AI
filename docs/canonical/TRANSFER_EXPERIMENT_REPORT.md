# Cross-family transfer of a volume-feature detector — pre-registered experiment

> Generated from frozen artifacts only. No experiment was run, no model retrained,
> no threshold recalibrated and no result altered to produce this report.
>
> Experiment executed 2026-09-08T19:59:19Z. Results artifact
> `artifacts/experiments/transfer_v1/transfer_results.json`, SHA-256
> `0de99ef1d852f675913d3de8e30d25a5b9c6180c4f108dcb5d32050724891050`.

---

## 1. Objective and research question

The experiment answers one question, under a leave-one-family-out protocol fixed
in advance:

> **Does a detector trained on six priority attack families retain useful
> detection capability on a seventh priority family that is entirely absent from
> its training and validation data?**

A second, deliberately separate question is answered on an independent capture:

> **Does the operating point calibrated on Monday benign traffic still produce a
> low false-positive rate on Thursday, a capture day that contributed nothing to
> training, validation or threshold calibration?**

The two are reported separately and never combined into a single score.

The property under test is **unseen attack-family transfer**, also called
cross-family transfer. The following are explicitly **not** claimed anywhere in
this report:

- generalisation to new infrastructure or to unseen network entities;
- generalisation to real-world production traffic;
- universal or general-purpose IDS capability;
- zero-day detection in the broad sense.

The reason is structural and is documented in section 11: the seven priority
families are carried by only four entity keys sharing a single attacker IP and a
single victim IP, so no split of this dataset can separate the attack behaviour
from the network identity that carries it.

---

## 2. Attack families and folds

Seven folds, one per priority family. Ground truth is the frozen M5 v3 population
`artifacts/production/ml_dataset_v2/ml_dataset.csv`.

| Fold — held-out family | Held-out windows | Held-out episodes | TRAIN positive windows | TRAIN positive episodes |
|---|---:|---:|---:|---:|
| `brute_force/ftp_patator` | 61 | 1 | 226 | 27 |
| `brute_force/ssh_patator` | 60 | 9 | 227 | 19 |
| `dos/hulk` | 36 | 2 | 251 | 26 |
| `dos/slowloris` | 46 | 2 | 241 | 26 |
| `dos/slowhttptest` | 26 | 8 | 261 | 20 |
| `dos/goldeneye` | 16 | 4 | 271 | 24 |
| `ddos/loit` | 42 | 2 | 245 | 26 |
| **Total priority population** | **287** | **28** | — | — |

TRAIN positives are the complement within the priority population: 287 minus the
held-out windows, and 28 minus the held-out episodes.

### What an episode is, and is not

An **episode** is a maximal run of consecutive 60-second windows sharing the same
`(attack_type, entity_key)`; a gap larger than one window length starts a new
episode. It is materialised as the `episode_id` column of the frozen population,
following decision D2 of `modules/detection/src/experiments/p1_dataset.py`. An
episode is **detected** if at least one of its windows scores at or above the
frozen threshold.

An episode is **not an independent attack in the statistical sense**. It is the
operational unit of this experiment: a contiguous stretch of activity from one
attacker–victim–service pair. Several episodes of the same family often share the
same entity key and differ only by a temporal gap, so they are correlated
observations rather than independent replicates.

### Small-sample caveat, stated before any result

| Episodes | Families |
|---:|---|
| 1 | FTP-Patator |
| 2 | DoS Hulk, DoS Slowloris, DDoS LOIT |
| 4 | DoS GoldenEye |
| 8 | DoS SlowHTTPTest |
| 9 | SSH-Patator |

Five of the seven families have four episodes or fewer. Their point estimates
carry very wide confidence intervals and support no conclusion on their own. The
pre-registration assigned each family a reporting tier before any result existed:
`descriptive_high_uncertainty` for FTP-Patator, Hulk, Slowloris, LOIT and
GoldenEye, and `weak_statistical_weight` for SlowHTTPTest and SSH-Patator.

---

## 3. Experimental protocol

### Populations

**TRAIN**

- positives: the six priority families other than the held-out one;
- negatives: **56,550** Monday `benign_reference` windows over **22,257** entities,
  namely benign entity folds 0–3.

**VALIDATION INTERNAL**

- negatives only: **14,028** Monday `benign_reference` windows over **5,458**
  entities, namely benign entity fold 4;
- the benign entity overlap between TRAIN and VALIDATION is **0**.

The benign partition is deterministic and depends only on the entity key, never
on a feature value, a label, a score or a model. It reuses the frozen function
`p1_dataset.negative_fold_of`, which assigns
`int(sha256(entity_key).hexdigest()[:8], 16) mod 5`.

**HOLDOUT**

- positives: exclusively the held-out family;
- negatives: exclusively the **32,813** Thursday `benign_reference` windows
  described in section 6.

**Excluded from every population**: `botnet/ares` (177 windows), the three
Thursday Web Attack families, and every `unknown` or `ambiguous` window. The
results artifact records `unknown: 0` and `ambiguous: 0` in all populations.

### Sequence, per fold

1. pin the protocol, the manifest, the attack population and the Thursday
   negative population by SHA-256;
2. fit one model on TRAIN;
3. calibrate the decision threshold on **validation negatives only**;
4. write the freeze record containing the model digest, the threshold, the
   decision rule, the episode definition and the exclusions;
5. **open the HOLDOUT**, once;
6. evaluate the held-out family;
7. evaluate the Thursday false-positive rate.

Every one of the seven freeze records
`artifacts/experiments/transfer_v1/freeze_*.json` was written with
`holdout_opened: false`, which is the machine-checkable evidence that the holdout
was not consulted while the model and threshold were being fixed. The results
artifact records `holdout_opened_after_freeze: true` and
`holdout_labels_used_to_modify_anything: false`.

### Precise separation statement

> The threshold was calibrated on a benign validation partition that is
> entity-disjoint from the benign training partition.

This is the exact scope of the entity-disjointness in this experiment. The
experiment as a whole is **not** entity-disjoint: see section 11.

---

## 4. Model

The P1 configuration, adopted unchanged and with no hyperparameter search:

```python
RandomForestClassifier(n_estimators=200, random_state=0, class_weight=None)
```

Source: `modules/detection/src/experiments/p1_evaluation.py`, decisions D6 and
D7, imported rather than reimplemented. `class_weight=None` is deliberate:
class weighting is a form of rebalancing and was excluded by the original
decision.

Feature budget, the five VOL5 columns in the frozen order of
`p1_dataset.FEATURE_NAMES`, handed to the model without any transform
(decision D5):

1. `event_count`
2. `source_packets_total`
3. `destination_packets_total`
4. `source_bytes_total`
5. `destination_bytes_total`

The results artifact records `tuning_performed: false` and `models_compared: 0`.
One model was fitted per fold, seven in total, each persisted and hashed.

---

## 5. Threshold calibration

The frozen rule is `p1_evaluation.threshold_at_train_fpr`, imported unchanged and
applied to the **validation** negatives instead of the training negatives. It
returns the smallest candidate score `t`, drawn from the observed negative
scores, such that `mean(negative_scores >= t) <= target`. The decision rule is
`flag(window) := score >= threshold`.

A plain quantile would be wrong for this score distribution: with a class
imbalance near 1:188 and no class weighting, the forest assigns a score of exactly
0.0 to the large majority of negatives, so a 99th-percentile threshold would be
0.0 and would flag every row. The frozen rule avoids that degenerate operating
point by construction.

Pre-registered targets, the frozen `FPR_TARGETS` of P1: **1 % primary** and
**0.1 % secondary**. The results reported here use the primary point.

| Fold | Primary threshold | Achieved validation FPR |
|---|---:|---:|
| `brute_force/ftp_patator` | 0.015 | 0.8198 % |
| `brute_force/ssh_patator` | 0.010 | 0.9410 % |
| `dos/hulk` | 0.015 | 0.7699 % |
| `dos/slowloris` | 0.015 | 0.8626 % |
| `dos/slowhttptest` | 0.010 | 0.9338 % |
| `dos/goldeneye` | 0.010 | 0.8127 % |
| `ddos/loit` | 0.010 | 0.9410 % |

Every achieved validation rate is at or below the 1 % target, which was a
pre-registered sanity condition.

Three properties matter and are all verifiable in the freeze records:

- the threshold comes from validation negatives, which are Monday windows from
  entities absent from the fitting set;
- **no holdout positive and no holdout negative influenced the threshold**;
- the threshold was frozen, with its digest chain, before the holdout was opened.

The Thursday false-positive rate reported in section 10 is therefore a
**measurement**, not a calibration target. It was never used to select a
threshold.

---

## 6. Thursday control population

TH2 produces **363,788** `conn.log` records. The M3 v2 admission contract accepts
**357,563** and rejects **6,225**. Under the M6-compatible 60-second
`event_start_time` windowing protocol, these produce **55,759 Thursday windows**.
Of these, **32,813** satisfy the conservative `benign_reference` policy and
constitute the frozen negative holdout.

Rejections, by the reason recorded in the audit:

| Reason | Records |
|---|---:|
| `missing_required_field` | 5,471 |
| `unsupported_service_cardinality` | 538 |
| `unsupported_transport` | 216 |
| **Total** | **6,225** |

### On the number 64,197

An exploratory audit, `scripts/audit_thursday_replay.py`, reported **64,197
candidate** windows. That count used the flow-end instant `ts + duration` as the
windowing basis, in floating-point arithmetic, and applied **no admission
contract**. Its own docstring states that this is a counting convention for the
audit only.

**64,197 must not be presented as the number of Thursday windows.** A forensic
reconciliation, recomputed from `conn.log`, decomposes the gap exactly:

| Population | Windows |
|---|---:|
| all records, flow-**end** basis | 64,197 |
| all records, flow-**start** basis | 57,255 |
| admitted records, flow-**start** basis | **55,759** |

The change of temporal basis removes 6,942 windows and the admission contract a
further 1,496, for a total gap of 8,438. The M6-consistent count, and the only
one used scientifically, is **55,759**. Its conformity rests on five properties
declared in frozen sources: `windowing_basis: event_start_time`,
`length_seconds: 60`, `boundary_semantics:
half_open_start_inclusive_end_exclusive`, `alignment:
floor_to_multiple_of_length_from_unix_epoch` and `empty_windows: forbidden`, in
`datasets/manifests/cicids2017_feature_window_v2.yaml` and
`modules/detection/src/schemas/feature_window_protocol_v2.py`.

### Exact decomposition

```
55,759  definitive Thursday windows
   123  known_other_attack
            web_attack/web_bruteforce    79 windows /  2 episodes / 2 entities
            web_attack/xss               41 windows /  3 episodes / 2 entities
            web_attack/sql_injection      3 windows /  1 episode  / 1 entity
22,823  unknown
        17,615  inside a declared attack interval
         5,155  compromised host, excluded across the whole capture
            50  gateway to web server, never a negative
             3  declared-attacker endpoint
32,813  benign_reference
```

Arithmetic: `123 + 22,823 + 32,813 = 55,759`; `79 + 41 + 3 = 123`;
`17,615 + 5,155 + 50 + 3 = 22,823`; `55,759 − 123 − 22,823 = 32,813`.

### Conservative gate

A window becomes `benign_reference` only if it passes every test, in this order,
any failure yielding `unknown`:

1. it is outside **all** declared attack intervals, including the two Infiltration
   intervals whose rules were deliberately left unlabelled;
2. neither endpoint is `192.168.10.8` or `192.168.10.25`, the two compromised
   hosts, excluded across the whole capture and in both directions;
3. it is not `172.16.0.1 → 192.168.10.50`, the gateway-to-web-server pair that
   carries the priority attacks;
4. `205.174.165.73`, the declared attacker, is neither source nor destination.

**No `unknown` or `ambiguous` window was ever converted to `benign_reference`.**
Uncertainty is excluded from the negatives rather than absorbed into them, which
makes the reported false-positive rate conservative: a window that might belong
to attack activity is removed from the denominator instead of being counted as a
benign window the detector is expected to leave alone.

Frozen negative population, `artifacts/production/thursday_audit_v1/thursday_benign_windows.csv`,
SHA-256 **`9cd046d46829ac9ef67fbd1df6d40dcd75fc1236c04cf433eceecf60abd278f9`**.

---

## 7. Results

All values are the published values of `transfer_results.json`, at the primary
1 % operating point. The Thursday false-positive denominator is 32,813 for every
fold.

| Family | Episode recall | Wilson 95 % CI | Window recall | Thursday FP | Thursday FPR | ROC-AUC | PR-AUC |
|---|---:|---|---:|---:|---:|---:|---:|
| FTP-Patator | 1/1 | [0.2065, 1.0000] | 61/61 | 120 | 0.3657 % | 0.999169 | 0.526277 |
| SSH-Patator | **1/9** | [0.0199, 0.4350] | **9/60** | 189 | 0.5760 % | **0.585866** | **0.008778** |
| DoS Hulk | 2/2 | [0.3424, 1.0000] | 35/36 | 117 | 0.3566 % | 0.985805 | 0.903019 |
| DoS Slowloris | 2/2 | [0.3424, 1.0000] | 43/46 | 123 | 0.3749 % | 0.966914 | 0.869932 |
| DoS SlowHTTPTest | 7/8 | [0.5291, 0.9776] | 21/26 | 187 | 0.5699 % | 0.902312 | 0.615712 |
| DoS GoldenEye | 4/4 | [0.5101, 1.0000] | 13/16 | 162 | 0.4937 % | 0.904825 | 0.529360 |
| DDoS LOIT | 2/2 | [0.3424, 1.0000] | 42/42 | 211 | 0.6430 % | 0.999915 | 0.944242 |

ROC-AUC and PR-AUC are computed on the pooled holdout population of the fold,
where both classes are present: the held-out family positives together with the
32,813 Thursday negatives. They are reported as threshold-free descriptors and
were **never** used to choose a threshold or a model. Because the positive count
varies across folds, PR-AUC must be read against its base rate, which ranges
from 0.000487 for GoldenEye to 0.001856 for FTP-Patator.

---

## 8. Pooled result

**19 of the 28 held-out episodes were detected**, that is 67.8571 %, with a
Wilson 95 % interval of **[0.493388, 0.820668]**.

This figure is **descriptive**. The 28 episodes are not fully independent
statistical replicates:

- the folds share entity structure, since six of the seven families sit on the
  same two entity keys;
- all seven folds share the same benign calibration framework and the same
  Monday validation partition;
- within a family, several episodes belong to the same entity key and differ only
  by a temporal gap.

The pooled interval should therefore be read as a summary of this particular
experiment, not as an estimate of a population detection rate. The correct
phrasing is *19 of the 28 held-out episodes were detected*. Restating the pooled
proportion as a percentage of "unseen attacks detected" would be wrong twice
over: episodes are not attacks, and the folds are not independent samples of any
population.

---

## 9. Interpretation

The pre-registration fixed three descriptive categories before any result
existed, and forbade comparing episode recall to the false-positive rate on the
grounds that they measure different things on different populations. The
assignment is:

**Results compatible with transfer** — episode recall substantial, Wilson
interval excluding zero, measured FPR within the pre-registered tolerance:

- FTP-Patator, DoS Hulk, DoS Slowloris, DoS SlowHTTPTest, DoS GoldenEye,
  DDoS LOIT.

**Limited or inconclusive evidence** — episode recall non-zero but its Wilson
interval too wide to distinguish outcomes:

- SSH-Patator.

**Absence of evidence of transfer** — episode recall zero or interval consistent
with zero:

- none.

These are descriptive categories. They are not statistical tests and must not be
restated as stronger claims. In particular, the five families in the
`descriptive_high_uncertainty` tier carry no conclusion on their own, whichever
category they fall in: FTP-Patator reaches 1/1 episodes, yet its Wilson lower
bound is 0.2065, which is what a single observation permits.

### The SSH-Patator counterexample

SSH-Patator is the most informative fold and must remain visible.

It detects **9 of 60 windows** but only **1 of 9 episodes**, with
**ROC-AUC 0.585866** and **PR-AUC 0.008778** — the latter against a base rate of
0.001825, so barely above chance. Two facts explain the divergence and both were
known before the experiment: eight of the nine SSH episodes consist of a single
window, so a missed window is a missed episode with no second chance; and the
volume features carry little signal for this family, as the near-chance ROC-AUC
shows.

This is a genuine negative result within an otherwise favourable set. It
demonstrates that a favourable pooled figure can coexist with a family the
detector essentially fails to transfer to, and that window-level recall can
overstate operational capability when episodes are short.

---

## 10. Thursday false-positive result

All seven folds produce a false-positive rate **below 1 %** on the independent
Thursday control population:

| Statistic | Value |
|---|---|
| Range | **0.3566 % – 0.6430 %** |
| Absolute false positives, out of 32,813 | 117, 120, 123, 162, 187, 189, 211 |
| Pre-registered descriptive ceiling | 2 % |
| Folds within the ceiling | **7 of 7** |
| Calibration target on Monday validation | 1 % |

Every measured rate is not only inside the 2 % ceiling but also **below the 1 %
calibration target**, so the operating point is in fact tighter on Thursday than
on the Monday partition it was derived from.

What this demonstrates, precisely: **conservative false-positive behaviour on an
independent capture and day**, using a negative population that contributed
nothing to training, validation or threshold calibration.

What it does **not** demonstrate: generalisation to unseen infrastructure.
Thursday is the same synthetic environment and the same address plan, and it
shares **three of the four** priority entity keys with P1 —
`172.16.0.1|192.168.10.50|tcp|{ftp, http, none}`. Those keys are excluded from the
Thursday negatives by the conservative policy, but their presence in the capture
means Thursday is a new day, not a new network.

---

## 11. Scientific limitations

1. **The experiment is not entity-disjoint as a whole.** Entity-disjointness holds
   only between the benign training and validation partitions. It does not hold
   between the training positives and the held-out family.
2. **Six of the seven priority families share the same source and victim IP
   structure.** The four priority entity keys all have attacker `172.16.0.1` and
   victim `192.168.10.50`, differing only by service. Only FTP-Patator becomes
   entity-key-disjoint when held out, and even it retains the same IP pair.
3. **Thursday shares three of the four priority entity keys** with P1, so it is an
   independent capture and day, not independent infrastructure.
4. **Only 28 held-out episodes in total**, across all seven folds.
5. **Several families have very few episodes**: five of seven have four or fewer.
6. **FTP-Patator has a single episode.** Its 1/1 result must not be generalised;
   the Wilson interval [0.2065, 1.0000] is the honest summary.
7. **No priority-family attack was used as a Thursday positive.** Thursday
   contains no FTP, SSH, DoS or DDoS family; its three web families are
   `known_other_attack` and are excluded from the transfer question by decision.
8. **Unknown and ambiguous Thursday windows were excluded, not treated as
   benign.** 22,823 windows were removed from the negative population rather than
   absorbed into it.
9. **This is CICIDS2017**, a synthetic environment captured over one week in 2017,
   not production traffic.
10. **No claim of new-infrastructure generalisation** is made or supported.
11. **No claim of universal or general-purpose IDS performance** is made or
    supported.

Lifting limitations 1 to 3 and 7 would require captures containing the same
families launched from different attackers against different victims — for
example CSE-CIC-IDS2018 — which is outside the scope of this experiment.

---

## 12. Reproducibility and integrity

| Property | Evidence |
|---|---|
| Pre-registration checks | **83 run, 0 failed**, `scripts/verify_preregistration.py` |
| Frozen artifacts | **0 divergence** across the reference digest set |
| Holdout discipline | all seven `freeze_*.json` written with `holdout_opened: false`; results record `holdout_opened_after_freeze: true` |
| Tuning | `tuning_performed: false`, `models_compared: 0`, `threshold_chosen_post_hoc: false` |
| Post-hoc decisions | `methodological_decision_after_seeing_results: false` |
| PostgreSQL writes | **0** |
| Determinism | `random_state=0`, no sampling, entity partition by SHA-256 |
| Frozen artifacts modified | `false` |

Verified digests:

| Artifact | SHA-256 |
|---|---|
| `artifacts/experiments/transfer_v1/transfer_results.json` | `0de99ef1d852f675913d3de8e30d25a5b9c6180c4f108dcb5d32050724891050` |
| `artifacts/production/ml_dataset_v2/ml_dataset.csv` | `bf04ec1a6937f96ee766e67b308ff13355057c26bb5d0256206bd017148b634a` |
| `artifacts/production/thursday_audit_v1/thursday_benign_windows.csv` | `9cd046d46829ac9ef67fbd1df6d40dcd75fc1236c04cf433eceecf60abd278f9` |
| `artifacts/experiments/preregistration_v1/protocol_manifest.json` | `95b18893d8c2a427412a01285947ca44156869f5dc4a8d57760e97f019016cea` |
| `docs/canonical/PROTOCOL_PREREGISTRATION_V1.md` | `0ed22dabaa711bc3390decc4794988c488f5d6a71046c00c42a953076713bc84` |

The first four are the digests the experiment itself pinned in
`transfer_results.json::pinned_digests`, so the run is bound to exactly these
bytes.

Per-fold model digests, abbreviated to their first 16 hexadecimal characters, are
recorded in full in each freeze record:

| Fold | Model digest prefix |
|---|---|
| `brute_force/ftp_patator` | `bace1443ec8554d6` |
| `brute_force/ssh_patator` | `d959805346976ff6` |
| `dos/hulk` | `00979db3de1082a1` |
| `dos/slowloris` | `7f4bd761d768a823` |
| `dos/slowhttptest` | `7c9a7a3981835340` |
| `dos/goldeneye` | `afa4a87d45cc6d47` |
| `ddos/loit` | `0c2a1c517cb7eb69` |

Each freeze record also carries a `train_row_digest` and a
`validation_row_digest` over the sorted row identifiers, so the exact split can
be re-verified without re-deriving it.

### One anomaly, reported rather than worked around

Before execution, a documentation imprecision was found and deliberately not
patched: the manifest prose glossed the benign partition as
`int(hexdigest, 16) mod 5`, whereas the frozen `negative_fold_of` uses
`int(hexdigest[:8], 16) mod 5`. Since the manifest designates the **function** as
the source of truth, the function was imported unchanged and neither the manifest
nor the protocol was edited. The discrepancy is one of wording, not of behaviour.

---

## 13. Conclusion

The experiment provides **preliminary evidence** that a volume-feature detector
trained on six priority attack families retains useful detection capability when
evaluated on a held-out seventh family, and that this capability is heterogeneous
across families.

Across seven leave-one-family-out folds, **19 of the 28 held-out episodes were
detected**. Six families fall in the pre-registered category *results compatible
with transfer*; SSH-Patator falls in *limited or inconclusive evidence*, detecting
1 of 9 episodes with a near-chance ROC-AUC of 0.586, and no family shows an
absence of evidence. On the independent Thursday benign control population, all
seven folds produced a false-positive rate below 1 %, in the range
**0.3566 % to 0.6430 %**, comfortably inside the pre-registered 2 % ceiling and
below the 1 % Monday calibration target.

Three qualifications bound these findings, and none of them is a formality. The
protocol establishes neither entity-disjoint nor new-infrastructure
generalisation, because the priority families share a single attacker–victim IP
pair and Thursday reuses three of the four priority entity keys. The total of 28
held-out episodes, five families having four or fewer, limits the strength of any
statistical conclusion. And SSH-Patator stands as an explicit example of weak
transfer within an otherwise favourable set, showing that a favourable pooled
count can coexist with a family the detector largely fails on.

The defensible claim is therefore narrow and specific: **on this frozen
CICIDS2017 evidence, cross-family transfer is observed for most priority families
at a conservative false-positive rate on an independent capture day, with one
clear failure and with no demonstrated generalisation beyond this environment.**

---

## 14. Audit trail

| Claim | Source artifact or code |
|---|---|
| Protocol, populations, metrics, success criterion | `docs/canonical/PROTOCOL_PREREGISTRATION_V1.md` |
| Pinned inputs, tiers, tolerance, transfer categories | `artifacts/experiments/preregistration_v1/protocol_manifest.json` |
| All seven folds' results, pooled figure, guarantees | `artifacts/experiments/transfer_v1/transfer_results.json` |
| Per-fold freeze, threshold, model digest, split digests | `artifacts/experiments/transfer_v1/freeze_*.json` |
| Fitted models | `artifacts/experiments/transfer_v1/model_*.joblib` |
| Experiment runner | `scripts/run_transfer_experiment.py` |
| Freeze verification, 83 checks | `scripts/verify_preregistration.py` |
| Attack population and labels, M5 v3 | `artifacts/production/ml_dataset_v2/` |
| M5 v3 policy and its additivity proof | `modules/detection/src/lineage/m5_policy_v3.py` |
| Thursday windows, dispositions, exclusion counts | `artifacts/production/thursday_audit_v1/THURSDAY_WINDOW_LABEL_AUDIT.json` |
| Thursday negative holdout rows | `artifacts/production/thursday_audit_v1/thursday_benign_windows.csv` |
| Thursday CSV integrity checks | `artifacts/production/thursday_audit_v1/thursday_benign_windows_verification.json` |
| Thursday labelling policy implementation | `scripts/audit_thursday_windows.py` |
| Exploratory 64,197 candidate count | `scripts/audit_thursday_replay.py` |
| Thursday evidence freeze and replay identity | `artifacts/canonical/cicids2017/th1/`, `artifacts/canonical/cicids2017/th2/` |
| Model hyperparameters, threshold rule, FPR targets | `modules/detection/src/experiments/p1_evaluation.py` |
| Feature budget, episode definition, benign partition | `modules/detection/src/experiments/p1_dataset.py` |
| M6 windowing semantics | `datasets/manifests/cicids2017_feature_window_v2.yaml`, `modules/detection/src/schemas/feature_window_protocol_v2.py` |
| M3 v2 admission contract | `datasets/manifests/cicids2017_zeek_normalization_v2.yaml` |
| Monday benign reference population | `artifacts/reports/mb7_monday_benign_labeling_run.json` |
