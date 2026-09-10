# CyberSentinel — final scientific validation report

Every figure below is read directly from the frozen Step 1, 2 and 3 artifacts by the generator that produced this file. No number is retyped, and 61 cross-artifact consistency checks gate its publication.

## 1. Objective

Determine whether the measured ML performance reflects behavioural generalisation, or is instead driven by the identity of the attacking entities and episodes, and produce a clean validation of the zero-day Ares result.

Six distinct measurements are reported and never conflated:

| Label | Meaning |
|---|---|
| **D2** | exact historical reproduction: the frozen P1 model re-scored, no new training |
| **A** | deterministic reimplementation of the historical protocol, not a reproduction |
| **B** | entity-disjoint: the attack entity is unseen in training |
| **C Ares** | episode-disjoint inside `botnet/ares`: unseen episodes of a known family |
| **D1** | zero-day: the Ares family is entirely absent from training, re-fitted |
| **A′** | diagnostic: shared attack entities removed from A's training positives |
| **VOL5 vs ARM F** | Step 5 feature-budget comparison; only the constant-learner contrast `VOL5_XGB` → `ARMF_XGB` is identifiable |

## 2. Dataset

Frozen production dataset `artifacts/production/ml_dataset_v1/ml_dataset.csv`.

| Item | Value |
|---|---:|
| Total rows | 70954 |
| Attack windows, `label=1` | 376 |
| Benign windows, `label=0` | 70578 |
| M6 `unknown` excluded | 172372 |
| M6 `ambiguous` excluded | 0 |
| Attack entities | 9 |
| Attack episodes | 54 |

## 3. Features

Exactly the five frozen volume features, in canonical order:

1. `event_count`
2. `source_packets_total`
3. `destination_packets_total`
4. `source_bytes_total`
5. `destination_bytes_total`

No transform, no scaling, no imputation, no selection, no rebalancing, no sampling. No metadata column reaches the model. Sections 1 to 12 use these five features exclusively; the ARM F content budget enters only in section 13, as a separate experiment, and is **not** part of the canonical production dataset.

## 4. Label policy

| Disposition | Label |
|---|---|
| `target_attack` | 1 |
| `known_other_attack` | 1 |
| `benign_reference` | 0 |
| `unknown` | excluded |
| `ambiguous` | excluded |

Converting uncertainty into a negative is forbidden and enforced by tests.

## 5. Split protocol

| Protocol | Folds | Rule | Entity-disjoint | Episode-disjoint |
|---|---:|---|---|---|
| `A_historical` | 5 | no randomness; sorted attack-type order and the frozen SHA-256 benign entity hash from p1_dataset.negative_fold_of | not required | required |
| `B_entity_disjoint` | 9 | no randomness; sorted entity order and the frozen SHA-256 benign entity hash | required | required |
| `C_episode_disjoint_botnet_ares` | 5 | no randomness; round-robin over sorted episodes into 5 folds over lexicographically sorted episode_id | not required | required |
| `C_episode_disjoint_brute_force_ssh_patator` | 9 | no randomness; leave-one-episode-out over lexicographically sorted episode_id | not required | required |
| `D_zero_day_ares` | 1 | no randomness; identical construction to protocol A fold 0 | required | required |

No randomness anywhere: `seed_used` is null in every split document. Model seed is `random_state=0`. Training order is the ratified `label,row_id` convention.

## 6. Leakage risk

Protocol A carries a measured identity leakage: two entity_key values span several attack types, so folds 2, 3 and 4 share an attack entity between train and test. Experiment B quantifies its impact by forbidding any shared entity.

| Protocol | Max train/test entity intersection | Max episode intersection |
|---|---:|---:|
| `A_historical` | 2 | 0 |
| `B_entity_disjoint` | 0 | 0 |
| `C_episode_disjoint_botnet_ares` | 5 | 0 |
| `C_episode_disjoint_brute_force_ssh_patator` | 1 | 0 |
| `D_zero_day_ares` | 0 | 0 |

Two `entity_key` values span several attack families, which is why the historical folds 2, 3 and 4 are not entity-disjoint:

- fold 2: `172.16.0.1\|192.168.10.50\|tcp\|none`
- fold 3: `172.16.0.1\|192.168.10.50\|tcp\|http`, `172.16.0.1\|192.168.10.50\|tcp\|none`
- fold 4: `172.16.0.1\|192.168.10.50\|tcp\|http`, `172.16.0.1\|192.168.10.50\|tcp\|none`

**Reproducibility limit.** The historical protocol depended on an input order that the SQL statement did not specify. That order was not persisted in the published artifacts. Exact reproduction of the re-training is therefore impossible from the artifacts alone. Protocol A is therefore labelled a deterministic reimplementation, and the zero-day result is measured twice: D1 re-fitted, D2 anchored on the frozen model.

## 7. Baseline results — protocol A, deterministic reimplementation

A withholds an entire attack family per fold. It is **not** a reproduction of the published P1 run.

| Fold | Held out | Train | Test | Test pos. | ROC-AUC | PR-AUC | Threshold | FPR | Recall | Precision | F1 | Episodes |
|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 0 | `botnet/ares` | 57003 | 13951 | 177 | 0.5049 | 0.0136 | 0.005000 | 0.007115 | 0.0169 | 0.0297 | 0.0216 | 3/40 |
| 1 | `brute_force/ftp_patator` | 56909 | 14045 | 61 | 0.9806 | 0.1649 | 0.010000 | 0.011156 | 0.5902 | 0.1875 | 0.2846 | 1/1 |
| 2 | `brute_force/ssh_patator` | 56830 | 14124 | 60 | 0.9207 | 0.1122 | 0.005000 | 0.021971 | 0.8667 | 0.1440 | 0.2470 | 1/9 |
| 3 | `ddos/loit` | 56184 | 14770 | 42 | 0.9971 | 0.5802 | 0.005000 | 0.025598 | 1.0000 | 0.1002 | 0.1822 | 2/2 |
| 4 | `dos/hulk` | 56890 | 14064 | 36 | 0.9390 | 0.5808 | 0.010000 | 0.012546 | 0.7500 | 0.1330 | 0.2259 | 2/2 |

Pooled: macro ROC-AUC 0.8685 · macro PR-AUC 0.2903 · recall 0.4255 · precision 0.1254 · FPR 0.015812 · **episode recall 9/54 = 0.1667**.

## 8. Entity-disjoint results — protocol B

B withholds one attack entity per fold. The attack family may remain in training, so B and A do not answer the same question.

| Fold | Held out | Train | Test | Test pos. | ROC-AUC | PR-AUC | Threshold | FPR | Recall | Precision | F1 | Episodes |
|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 0 | `172.16.0.1\|192.168.10.50\|tcp\|ftp` | 63251 | 7703 | 61 | 0.7947 | 0.1663 | 0.005000 | 0.020414 | 0.6066 | 0.1917 | 0.2913 | 1/1 |
| 1 | `172.16.0.1\|192.168.10.50\|tcp\|http` | 63038 | 7916 | 39 | 0.9990 | 0.8138 | 0.010000 | 0.006855 | 1.0000 | 0.4194 | 0.5909 | 2/2 |
| 2 | `172.16.0.1\|192.168.10.50\|tcp\|none` | 62635 | 8319 | 47 | 0.8902 | 0.5233 | 0.005000 | 0.023211 | 0.7872 | 0.1616 | 0.2681 | 2/10 |
| 3 | `172.16.0.1\|192.168.10.50\|tcp\|ssh` | 63383 | 7571 | 52 | 0.9925 | 0.3216 | 0.005000 | 0.014497 | 1.0000 | 0.3230 | 0.4883 | 1/1 |
| 4 | `192.168.10.14\|205.174.165.73\|tcp\|http` | 63092 | 7862 | 31 | 1.0000 | 1.0000 | 0.010000 | 0.021964 | 1.0000 | 0.1527 | 0.2650 | 8/8 |
| 5 | `192.168.10.15\|205.174.165.73\|tcp\|http` | 63537 | 7417 | 49 | 0.9999 | 0.9842 | 0.005000 | 0.016694 | 1.0000 | 0.2849 | 0.4434 | 8/8 |
| 6 | `192.168.10.5\|205.174.165.73\|tcp\|http` | 62850 | 8104 | 27 | 1.0000 | 0.9924 | 0.005000 | 0.015847 | 1.0000 | 0.1742 | 0.2967 | 7/7 |
| 7 | `192.168.10.8\|205.174.165.73\|tcp\|http` | 63191 | 7763 | 26 | 1.0000 | 0.9870 | 0.005000 | 0.016544 | 1.0000 | 0.1688 | 0.2889 | 2/2 |
| 8 | `192.168.10.9\|205.174.165.73\|tcp\|http` | 62655 | 8299 | 44 | 1.0000 | 1.0000 | 0.005000 | 0.028104 | 1.0000 | 0.1594 | 0.2750 | 15/15 |

Pooled: macro ROC-AUC 0.9640 · macro PR-AUC 0.7543 · recall 0.9096 · precision 0.2090 · FPR 0.018334 · **episode recall 46/54 = 0.8519**. Entity intersection is 0 on all 9 folds.

Variation A → B, reported without causal attribution:

| Metric | A | B | Δ |
|---|---:|---:|---:|
| `macro_roc_auc` | 0.8685 | 0.9640 | +0.0955 |
| `macro_pr_auc` | 0.2903 | 0.7543 | +0.4640 |
| `pooled_recall` | 0.4255 | 0.9096 | +0.4840 |
| `pooled_precision` | 0.1254 | 0.2090 | +0.0837 |
| `pooled_fpr` | 0.0158 | 0.0183 | +0.0025 |
| `pooled_episode_recall` | 0.1667 | 0.8519 | +0.6852 |

> Family novelty, but identity leakage is possible and measured. Entity novelty; the attack family may already be known. The A → B difference is **not** attributed to identity leakage: the two protocols withhold different things.

## 9. Episode-disjoint results — protocol C

### 9.1 C Ares, main analysis

| Fold | Held out | Train | Test | Test pos. | ROC-AUC | PR-AUC | Threshold | FPR | Recall | Precision | F1 | Episodes |
|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 0 | `botnet/ares episode group 0` | 57148 | 13806 | 32 | 1.0000 | 1.0000 | 0.010000 | 0.010454 | 1.0000 | 0.1818 | 0.3077 | 8/8 |
| 1 | `botnet/ares episode group 1` | 56932 | 14022 | 38 | 0.9731 | 0.9461 | 0.010000 | 0.013015 | 0.9474 | 0.1651 | 0.2812 | 8/8 |
| 2 | `botnet/ares episode group 2` | 56861 | 14093 | 29 | 0.9998 | 0.9418 | 0.010000 | 0.010452 | 1.0000 | 0.1648 | 0.2829 | 8/8 |
| 3 | `botnet/ares episode group 3` | 56193 | 14761 | 33 | 0.9999 | 0.9787 | 0.005000 | 0.025326 | 1.0000 | 0.0813 | 0.1503 | 8/8 |
| 4 | `botnet/ares episode group 4` | 56881 | 14073 | 45 | 1.0000 | 1.0000 | 0.010000 | 0.013829 | 1.0000 | 0.1883 | 0.3169 | 8/8 |

Pooled: macro ROC-AUC 0.9946 · macro PR-AUC 0.9733 · **episode recall 40/40**. Episode intersection is 0; entity-disjointness is impossible here, because episodes of one family share entity keys, and this is declared rather than relaxed.

### 9.2 C SSH, secondary analysis, statistically weak

| Fold | Held out | Train | Test | Test pos. | ROC-AUC | PR-AUC | Threshold | FPR | Recall | Precision | F1 | Episodes |
|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 0 | `brute_force/ssh_patator episode group 0` | 63311 | 7643 | 1 | 1.0000 | 1.0000 | 0.010000 | 0.011908 | 1.0000 | 0.0109 | 0.0215 | 1/1 |
| 1 | `brute_force/ssh_patator episode group 1` | 63076 | 7878 | 1 | 1.0000 | 1.0000 | 0.010000 | 0.007998 | 1.0000 | 0.0156 | 0.0308 | 1/1 |
| 2 | `brute_force/ssh_patator episode group 2` | 62681 | 8273 | 1 | 0.9999 | 0.5000 | 0.005000 | 0.028167 | 1.0000 | 0.0043 | 0.0085 | 1/1 |
| 3 | `brute_force/ssh_patator episode group 3` | 63434 | 7520 | 1 | 1.0000 | 1.0000 | 0.005000 | 0.019683 | 1.0000 | 0.0067 | 0.0133 | 1/1 |
| 4 | `brute_force/ssh_patator episode group 4` | 63122 | 7832 | 1 | 0.9997 | 0.3333 | 0.005000 | 0.031669 | 1.0000 | 0.0040 | 0.0080 | 1/1 |
| 5 | `brute_force/ssh_patator episode group 5` | 63585 | 7369 | 1 | 1.0000 | 1.0000 | 0.010000 | 0.009908 | 1.0000 | 0.0135 | 0.0267 | 1/1 |
| 6 | `brute_force/ssh_patator episode group 6` | 62876 | 8078 | 1 | 1.0000 | 1.0000 | 0.010000 | 0.006809 | 1.0000 | 0.0179 | 0.0351 | 1/1 |
| 7 | `brute_force/ssh_patator episode group 7` | 63216 | 7738 | 1 | 1.0000 | 1.0000 | 0.010000 | 0.007884 | 1.0000 | 0.0161 | 0.0317 | 1/1 |
| 8 | `brute_force/ssh_patator episode group 8` | 62647 | 8307 | 52 | 0.9871 | 0.2379 | 0.005000 | 0.030890 | 1.0000 | 0.1694 | 0.2897 | 1/1 |

Pooled: macro ROC-AUC 0.9985 · macro PR-AUC 0.7857 · episode recall 9/9. **This is not a validation.** Eight of the nine SSH episodes contain exactly one window; the ninth contains 52. An episode recall computed over single-window episodes carries no generalisation weight.

## 10. Zero-day Ares — D1 and D2, reported separately

| Metric | D1, re-fitted | D2, frozen model anchor |
|---|---:|---:|
| ROC-AUC | 0.5049 | 0.5037 |
| PR-AUC | 0.0136 | 0.0135 |
| Threshold | 0.005000 | 0.005000 |
| FPR | 0.007115 | 0.009583 |
| TP | 3 | 3 |
| FP | 98 | 132 |
| TN | 13676 | 13642 |
| FN | 174 | 174 |
| Recall | 0.0169 | 0.0169 |
| Precision | 0.0297 | 0.0222 |
| Episodes | 3/40 | 3/40 |
| Model source | `refitted_under_canonical_order` | `historical_frozen_model` |

**D2 is not a new training run.** It re-evaluates the frozen P1 model and reproduces the published stream exactly: 11 anchor checks passed, including identical scores on all 13,951 test rows with a maximum absolute difference of 0.0.

D1 differs slightly from D2 because the historical training row order is irrecoverable. Both agree on the operational outcome: threshold 0.005, 3/40 episodes detected.

## 11. Principal result

The same five features, the same model and the same calibration produce two opposite outcomes on the **same 40 Ares episodes**, depending only on whether the Ares family is present in training.

| Setting | Ares family in training | Entity-disjoint | Episodes detected | ROC-AUC |
|---|---|---|---:|---:|
| B, Ares folds [4, 5, 6, 7, 8] | yes, other entities | **yes**, intersection 0 | **40/40** | 0.9999–1.0000 |
| C Ares | yes, other episodes | no, by construction | **40/40** | 0.9946 |
| D1 zero-day | **no** | yes | **3/40** | 0.5049 |
| D2 anchor | **no** | yes | **3/40** | 0.5037 |

Per-fold detail of the entity-disjoint Ares evidence:

| Fold | Held-out entity | Episodes | ROC-AUC | FPR |
|---:|---|---:|---:|---:|
| 4 | `192.168.10.14\|205.174.165.73\|tcp\|http` | 8/8 | 1.0000 | 0.021964 |
| 5 | `192.168.10.15\|205.174.165.73\|tcp\|http` | 8/8 | 0.9999 | 0.016694 |
| 6 | `192.168.10.5\|205.174.165.73\|tcp\|http` | 7/7 | 1.0000 | 0.015847 |
| 7 | `192.168.10.8\|205.174.165.73\|tcp\|http` | 2/2 | 1.0000 | 0.016544 |
| 8 | `192.168.10.9\|205.174.165.73\|tcp\|http` | 15/15 | 1.0000 | 0.028104 |

What this supports: the published Ares failure is a failure of **zero-day transfer to an unseen family**, not an absolute inability of the five volume features to separate Ares traffic. Detection is near-total when other Ares entities are in training, even though no entity is shared between train and test.

What this does not support: any claim about new attackers, new victims, new services or real traffic. The five Ares entities differ only by source IP; they share the same victim, transport and service.

## 12. Identity-leakage diagnostic — A versus A′

A′ removes from A's training set only the positive rows whose `entity_key` also appears among the test positives. The test population, all negatives, the features, the model, the order and the calibration are unchanged.

| Fold | Held out | Positives removed | Families emptied from train |
|---:|---|---:|---|
| 2 | `brute_force/ssh_patator` | 39 | none |
| 3 | `ddos/loit` | 44 | `dos/hulk` |
| 4 | `dos/hulk` | 50 | `ddos/loit` |

| Fold | ΔROC-AUC | ΔPR-AUC | ΔRecall | ΔPrecision | ΔEpisode recall | ΔEpisodes |
|---:|---:|---:|---:|---:|---:|---:|
| 2 | +0.0015 | +0.0197 | +0.0000 | +0.0237 | +0.0000 | +0 |
| 3 | -0.0165 | -0.4172 | -0.0238 | +0.0196 | +0.0000 | +0 |
| 4 | -0.2123 | -0.5462 | -0.2778 | -0.0774 | -0.5000 | -1 |

Results are heterogeneous. Fold 2, the only fold where no family is emptied, shows no effect on detection. Folds 3 and 4, where one further family is emptied from training, degrade, fold 4 severely.

> the shared entities carry positives of several families, so removing their training rows also removes training windows of families other than the held-out one; in folds 3 and 4 one further family is emptied from the training set entirely. A' - A therefore measures the effect of removing the shared entities, not identity leakage isolated at constant training composition.

This diagnostic therefore measures the marginal effect of removing the shared entities in folds 2, 3 and 4 at constant held-out family. It does **not** state that leakage explains, or fails to explain, the A versus B difference.

## 13. ARM F extension and the representational ceiling

**Executed in Step 5.** This section replaces the earlier statement that ARM F had not been run.

### 13.1 Naming, arms and what each contrast can support

`VOL5` denotes the five volume features. `ARM_A` stays reserved for the repository's historical single-feature definition and is not an arm here. `ARM_F` is the canonical Phase 1 budget, `phase2_r006_used = false`.

| Arm | Features | Learner | Role |
|---|---:|---|---|
| `VOL5_RF` | 5 | RandomForest | historical pipeline, reused from Step 2, not refitted |
| `VOL5_XGB` | 5 | XGBoost | control arm holding the learner constant |
| `ARMF_XGB` | 3 | XGBoost | the budget under test |
| `VOL5_ARMF_XGB` | 8 | XGBoost | union arm, exploratory, reported separately |

`VOL5_XGB` exists solely to hold the learner constant. Without it no statement about the feature budget would be identifiable, because `VOL5_RF` and `ARMF_XGB` differ in both features and learner.

| Contrast | Feature effect identifiable |
|---|---|
| `VOL5_RF` → `ARMF_XGB` | **no** — pipeline comparison only |
| `VOL5_XGB` → `ARMF_XGB` | **yes** — learner held constant |
| `ARMF_XGB` → `VOL5_ARMF_XGB` | yes — learner held constant |

### 13.2 Reconstruction proof

`distinct_payload_ratio` is not persisted per row. Step 5 rebuilt it from the canonical event tables with the unmodified P6 implementation, inside transactions where `transaction_read_only` was asserted to be `on`, with zero writes. The rebuilt ARM F reproduces the **published Phase 1 score streams exactly** on all five folds:

| Fold | Rows | Scores matching to 10 decimals | Max absolute difference |
|---:|---:|---:|---:|
| 0 | 13951 | 13951/13951 | 4.984e-11 |
| 1 | 14045 | 14045/14045 | 4.959e-11 |
| 2 | 14124 | 14124/14124 | 4.979e-11 |
| 3 | 14770 | 14770/14770 | 4.984e-11 |
| 4 | 14064 | 14064/14064 | 4.991e-11 |

This proves the reconstruction is correct. It is not a claim that Step 5 reproduces history: the arms measured there are new experiments on the validation protocols.

### 13.3 Zero-day Ares, protocol D

| Arm | Features | Learner | ROC-AUC | PR-AUC | Threshold | FPR | Window recall | Episodes |
|---|---:|---|---:|---:|---:|---:|---:|---:|
| `VOL5_RF` | 5 | RandomForest | 0.5049 | 0.0136 | 0.005000 | 0.007115 | 0.0169 | 3/40 |
| `VOL5_XGB` | 5 | XGBoost | 0.4470 | 0.0145 | 0.001477 | 0.012415 | 0.0000 | 0/40 |
| `ARMF_XGB` | 3 | XGBoost | 0.9713 | 0.4570 | 0.002479 | 0.007187 | 0.5593 | 21/40 |
| `VOL5_ARMF_XGB` | 8 | XGBoost | 0.9012 | 0.3220 | 0.000304 | 0.005590 | 0.3051 | 16/40 |

Ares is absent from training for every fitted arm, verified by a blocking assertion. All arms were measured on exactly the same test rows.

### 13.4 The identifiable feature effect, per protocol

| Protocol | `VOL5_XGB` → `ARMF_XGB` episodes | ΔROC-AUC | ΔPR-AUC | ΔEpisode recall |
|---|---|---:|---:|---:|
| A_historical | 5/54 → 26/54 | +0.0626 | +0.3692 | +0.3889 |
| B_entity_disjoint | 43/54 → 26/54 | +0.0359 | -0.0594 | -0.3148 |
| C_episode_disjoint_botnet_ares | 40/40 → 21/40 | -0.0115 | -0.3959 | -0.4750 |
| D_zero_day_ares | 0/40 → 21/40 | +0.5243 | +0.4425 | +0.5250 |

The direction reverses by protocol. ARM F wins decisively where the family is unseen and loses where the family is known. The two budgets encode different, complementary signals; neither dominates.

### 13.5 The union arm, reported separately

| Protocol | `ARMF_XGB` → `VOL5_ARMF_XGB` episodes | ΔROC-AUC | ΔPR-AUC | ΔEpisode recall |
|---|---|---:|---:|---:|
| A_historical | 26/54 → 21/54 | +0.0923 | +0.0964 | -0.0926 |
| B_entity_disjoint | 26/54 → 46/54 | +0.0137 | +0.4134 | +0.3704 |
| C_episode_disjoint_botnet_ares | 21/40 → 40/40 | +0.0118 | +0.4408 | +0.4750 |
| D_zero_day_ares | 21/40 → 16/40 | -0.0700 | -0.1350 | -0.1250 |

Adding the volume features to ARM F helps markedly where the family is known and **costs episodes in zero-day transfer**. The union does not resolve the trade-off, it relocates it.

### 13.6 Correction of the Step 4 interpretation

Step 4 concluded that the decisive factor was whether the attack family was represented in training, and left the representational question open. Step 5 **corrects that reading**: the observed ceiling was due to *both* the transfer to an unseen family *and* a representational limitation of the five volume features.

At a strictly constant learner and on the same test rows, `VOL5_XGB` detects **0/40** Ares episodes with ROC-AUC **0.4470**, while `ARMF_XGB` detects **21/40** with ROC-AUC **0.9713** and PR-AUC 0.4570, at a comparable false-positive rate (0.007187 against 0.012415).

The Step 4 evidence remains valid on its own terms: family knowledge does carry VOL5 from 3/40 to 40/40 on Ares. What changes is the conclusion that the five volume features were sufficient in principle. They are not, for this family, under zero-day transfer.

This is **not** a generalisation claim. The zero-day question is evaluated on Ares only, over 40 episodes drawn from 5 entities that differ solely by source IP against the same victim, transport and service. No second zero-day family exists in this population, so the effect is measured once and cannot be replicated internally.

## 14. Limits

1. **376 attack windows only**, from **9 entities** and **54 episodes**. Confidence is governed by episodes, not windows; the effective sample size is of the order of nine.
2. **Class imbalance 1:187.7.** Precision stays between 0.02 and 0.21 everywhere. Accuracy is never reported.
3. **Day and capture confounding is not lifted.** All negatives come from the parallel Monday capture and all positives from Tuesday, Wednesday and Friday. No split on this population can remove that confounder.
4. **172372 M6 `unknown` windows are excluded** and are never used as negatives. Alerts on them are neither true nor false positives.
5. **C SSH is statistically weak**: eight of nine episodes contain a single window. It is reported as a secondary analysis only.
6. **A′ cannot separate family from entity.** The shared entities carry several families, so removing them also removes training families; in folds 3 and 4 an entire further family disappears.
7. **Weak entity novelty for Ares.** The five Ares entities differ only by source IP against the same victim, transport and service.
8. **Exact historical re-fit is impossible.** The historical training row order was never specified by the SQL query nor persisted; only D2 anchors the published numbers exactly.
9. **Threshold transfer is imperfect.** Calibrated at 1% on training negatives, the realised test FPR reaches 1.47% to 1.83% pooled, and up to 3.17% on individual folds.
10. **No generalisation to real traffic is demonstrated.** All evidence comes from one frozen CICIDS2017 snapshot; external validation is required before any operational claim.
11. **The zero-day evidence rests on a single family.** Protocol D exists only for Ares, so the ARM F advantage in zero-day transfer is measured once, over 40 episodes from 5 entities, and cannot be replicated inside this population.
12. **ARM F depends on payload availability.** Its content metrics are undefined when no qualifying payload is present; those rows reach XGBoost's native missing branch, and that missingness is not a neutral phenomenon.

## 15. Scientific conclusion

1. The historical zero-day Ares result is reproduced **exactly** by D2 and confirmed in direction by D1: with the Ares family absent from training, the five volume features detect 3/40 episodes at ROC-AUC 0.5037, that is chance level.
2. With other Ares entities in training and **strict entity-disjointness**, the same configuration detects 40/40 Ares episodes. Entity memorisation is therefore not what carries the performance.
3. Protocol A is a deterministic reimplementation. Its identity leakage is measured, not assumed, and its effect is quantified separately in A′ without causal attribution to the A versus B gap.
4. Episode novelty inside a known family is handled: C Ares detects 40/40 episodes with zero episode overlap.
5. The decisive factor **within the five volume features** is whether the attack family is represented in training. Step 5 adds the other half of the picture: at a constant learner, `VOL5_XGB` detects 0/40 Ares episodes with ROC-AUC 0.4470, while the ARM F budget detects 21/40 with ROC-AUC 0.9713 at a comparable false-positive rate. The observed ceiling was therefore **both** a family-transfer limit **and** a representational limit of the volume budget.
6. Neither budget dominates. ARM F wins zero-day transfer and loses where the family is known; the union arm inherits both behaviours and still loses episodes in zero-day. This is a complementarity, not a ranking.
7. Every statement above concerns this frozen snapshot, its nine entities and one zero-day family. Nothing here is a claim about network traffic in general.

## 16. Reproducibility

| Property | Value |
|---|---|
| Model | RandomForest, 200 trees, `random_state=0`, `class_weight=None` |
| Training order | `label,row_id` |
| Split randomness | none, `seed_used` is null |
| Models fitted, Step 2 | 29 |
| Models fitted, Step 3 | 6 |
| Models fitted, Step 5 | 65 |
| Frozen models re-scored | 1, the D2 anchor |
| PostgreSQL connections | 0 in Steps 1 to 4; read-only in Step 5, `transaction_read_only = on`, 0 writes |
| Hyperparameter tuning | none |
| Threshold selected on test | no |

Commands, in order:

```text
python -m scripts.run_final_validation_splits --publish
python -m scripts.run_final_validation_eval --publish
python -m scripts.run_final_validation_leakage --publish
python -m scripts.run_final_validation_armf --publish
python -m scripts.run_final_validation_report --publish
```

## 17. SHA-256 of the source artifacts

| Artifact | SHA-256 |
|---|---|
| `artifacts/production/ml_dataset_v1/ml_dataset.csv` | `e95aed008d994510e4c649c287feb8fe8f49a785bec144d7e83aa15804b6c062` |
| `artifacts/production/ml_dataset_v1/dataset_manifest.json` | `f792748334a643c5cb0451656f996dc77d755935c13fcc94fd60fb640f59d325` |
| `artifacts/experiments/final_validation/splits/splits_manifest.json` | `5967044a41c2acb327bfd2698ab8ece2de5cd56f5dd1237a1853eceeef51f8f3` |
| `artifacts/experiments/final_validation/baseline_metrics.json` | `3f40749f5bc9cecbc92ea0dbef5de91ca06dee7f31aa0a99aceba03337271fb2` |
| `artifacts/experiments/final_validation/split_comparison.json` | `e4ce292526b27e7d8740ff82f4d18d8fad16d4ec64fa2076fb152ae2a1ba2982` |
| `artifacts/experiments/final_validation/identity_leakage_diagnostic.json` | `e58049d38d677e2cf95bccb44e4aca44dd512dd2d0dad054a0a1324ef01db8fd` |
| `artifacts/experiments/final_validation/zero_day_ares.json` | `36ce1c66c48772118ffef7e3dbdd16c770fc43371a2043d0df86163346dc8603` |
| `artifacts/experiments/final_validation/reproducibility_diagnostic.json` | `0e45e944744ab704186df7995d0532351aa0038a48f361e15b21fb12d4d799e2` |
| `artifacts/experiments/final_validation/evaluation_manifest.json` | `5b5b2be2c01dfb7a17a588ceb81aaa339089efaf0966fb862d7ad7f5c015a093` |
| `artifacts/experiments/final_validation/identity_leakage/ap_comparison.json` | `c856e3406e9392810d63655dfd21cd871f0bee71bb8b4b760ee092769b77384d` |
| `artifacts/experiments/final_validation/identity_leakage/ap_diagnostic.json` | `5c5942d1f02d932c846437e354b0577a2b8e2953b6da1ce361ca9ce9a887e2e6` |
| `artifacts/experiments/final_validation/identity_leakage/manifest.json` | `695081f260551e25b5e924dcd7d6a69d65fb89b4db84246dcf95785ca0c77cd6` |
| `artifacts/experiments/final_validation/armf_extension/armf_config.json` | `0cfa085bd51c2fd9a5eb2f4c1a9d96b7aa5d212f7ab2758d7b14362989dd760f` |
| `artifacts/experiments/final_validation/armf_extension/armf_comparison.json` | `84a6b510c1892b8ded07691cb6bb2d2aac44ed64f0f1eea62e2afbf152c97889` |
| `artifacts/experiments/final_validation/armf_extension/armf_metrics.json` | `f5196e91845c6d005e963d065a73deea555328228bc4c176eaa89b21dbbb9227` |
| `artifacts/experiments/final_validation/armf_extension/armf_zero_day.json` | `05a8e3fc060630dcbf32dd97a5e417f2c321e686eb1f1b1887431aa16d0acc43` |
| `artifacts/experiments/final_validation/armf_extension/armf_reproduction.json` | `5499317af0655efa4d866ff95a00cb3a1324aada71c261fe76949b235eab0410` |
| `artifacts/experiments/final_validation/armf_extension/manifest.json` | `bfff801430829d119ee676dfc80def3d3d87f35e7e47876e2357b3c77fac515b` |

This report is generated from those bytes. If any of them changes, the generator's consistency gate must be re-run before the report is trusted.
