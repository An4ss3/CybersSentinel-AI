# ARM F extension — does the ARM F budget lift the VOL5 ceiling?

Generated from the artifacts of this step. `VOL5_RF` figures are read from the Step 2 artifacts and were **not** refitted here.

## Arms

| Arm | Features | Learner | Role |
|---|---|---|---|
| `VOL5_RF` | 5 | RandomForestClassifier | historical pipeline, reused from Step 2, not refitted |
| `VOL5_XGB` | 5 | XGBClassifier | control arm holding the learner constant |
| `ARMF_XGB` | 3 | XGBClassifier | the budget under test |
| `VOL5_ARMF_XGB` | 8 | XGBClassifier | union arm, exploratory, reported separately |

## Reconstruction proof

`distinct_payload_ratio` was rebuilt from the canonical event tables with the unmodified P6 implementation, inside read-only transactions. The rebuilt ARM F reproduces the **published Phase 1 score streams exactly** on all five folds:

| Fold | Rows | Scores matching to 10 decimals | Max absolute difference |
|---:|---:|---:|---:|
| 0 | 13951 | 13951/13951 | 4.984e-11 |
| 1 | 14045 | 14045/14045 | 4.959e-11 |
| 2 | 14124 | 14124/14124 | 4.979e-11 |
| 3 | 14770 | 14770/14770 | 4.984e-11 |
| 4 | 14064 | 14064/14064 | 4.991e-11 |

This proves the reconstruction is correct. It is **not** a claim that this step reproduces history: the arms below are new experiments on the validation protocols.

## Results by protocol

### A_historical

| Arm | Features | Learner | ROC-AUC | PR-AUC | Recall | Precision | FPR | Episodes |
|---|---:|---|---:|---:|---:|---:|---:|---:|
| `VOL5_RF` | 5 | RandomForestClassifier | 0.8685 | 0.2903 | 0.4255 | 0.1254 | 0.015812 | 9/54 |
| `VOL5_XGB` | 5 | XGBClassifier | 0.8063 | 0.1646 | 0.1410 | 0.0608 | 0.011604 | 5/54 |
| `ARMF_XGB` | 3 | XGBClassifier | 0.8689 | 0.5337 | 0.5957 | 0.3533 | 0.005809 | 26/54 |
| `VOL5_ARMF_XGB` | 8 | XGBClassifier | 0.9612 | 0.6302 | 0.5133 | 0.2159 | 0.009932 | 21/54 |

### B_entity_disjoint

| Arm | Features | Learner | ROC-AUC | PR-AUC | Recall | Precision | FPR | Episodes |
|---|---:|---|---:|---:|---:|---:|---:|---:|
| `VOL5_RF` | 5 | RandomForestClassifier | 0.9640 | 0.7543 | 0.9096 | 0.2090 | 0.018334 | 46/54 |
| `VOL5_XGB` | 5 | XGBClassifier | 0.9396 | 0.5990 | 0.5426 | 0.1960 | 0.011859 | 43/54 |
| `ARMF_XGB` | 3 | XGBClassifier | 0.9755 | 0.5396 | 0.6383 | 0.3093 | 0.007594 | 26/54 |
| `VOL5_ARMF_XGB` | 8 | XGBClassifier | 0.9891 | 0.9529 | 0.9734 | 0.3376 | 0.010173 | 46/54 |

### C_episode_disjoint_botnet_ares

| Arm | Features | Learner | ROC-AUC | PR-AUC | Recall | Precision | FPR | Episodes |
|---|---:|---|---:|---:|---:|---:|---:|---:|
| `VOL5_RF` | 5 | RandomForestClassifier | 0.9946 | 0.9733 | 0.9887 | 0.1440 | 0.014735 | 40/40 |
| `VOL5_XGB` | 5 | XGBClassifier | 0.9992 | 0.9402 | 0.9831 | 0.1743 | 0.011675 | 40/40 |
| `ARMF_XGB` | 3 | XGBClassifier | 0.9878 | 0.5444 | 0.6836 | 0.1787 | 0.007878 | 21/40 |
| `VOL5_ARMF_XGB` | 8 | XGBClassifier | 0.9996 | 0.9851 | 0.9944 | 0.1888 | 0.010712 | 40/40 |

### D_zero_day_ares

| Arm | Features | Learner | ROC-AUC | PR-AUC | Recall | Precision | FPR | Episodes |
|---|---:|---|---:|---:|---:|---:|---:|---:|
| `VOL5_RF` | 5 | RandomForestClassifier | 0.5049 | 0.0136 | 0.0169 | 0.0297 | 0.007115 | 3/40 |
| `VOL5_XGB` | 5 | XGBClassifier | 0.4470 | 0.0145 | 0.0000 | 0.0000 | 0.012415 | 0/40 |
| `ARMF_XGB` | 3 | XGBClassifier | 0.9713 | 0.4570 | 0.5593 | 0.5000 | 0.007187 | 21/40 |
| `VOL5_ARMF_XGB` | 8 | XGBClassifier | 0.9012 | 0.3220 | 0.3051 | 0.4122 | 0.005590 | 16/40 |

## Identifiable contrasts

Only contrasts that hold the learner constant support a statement about the feature budget.

| Protocol | Contrast | Feature effect identifiable | ΔROC-AUC | ΔPR-AUC | ΔEpisode recall | Episodes |
|---|---|---|---:|---:|---:|---|
| A_historical | VOL5_RF_vs_ARMF_XGB | **no** | +0.0004 | +0.2434 | +0.3148 | 9/54 → 26/54 |
| A_historical | VOL5_XGB_vs_ARMF_XGB | yes | +0.0626 | +0.3692 | +0.3889 | 5/54 → 26/54 |
| A_historical | ARMF_XGB_vs_VOL5_ARMF_XGB | yes | +0.0923 | +0.0964 | -0.0926 | 26/54 → 21/54 |
| B_entity_disjoint | VOL5_RF_vs_ARMF_XGB | **no** | +0.0115 | -0.2147 | -0.3704 | 46/54 → 26/54 |
| B_entity_disjoint | VOL5_XGB_vs_ARMF_XGB | yes | +0.0359 | -0.0594 | -0.3148 | 43/54 → 26/54 |
| B_entity_disjoint | ARMF_XGB_vs_VOL5_ARMF_XGB | yes | +0.0137 | +0.4134 | +0.3704 | 26/54 → 46/54 |
| C_episode_disjoint_botnet_ares | VOL5_RF_vs_ARMF_XGB | **no** | -0.0068 | -0.4289 | -0.4750 | 40/40 → 21/40 |
| C_episode_disjoint_botnet_ares | VOL5_XGB_vs_ARMF_XGB | yes | -0.0115 | -0.3959 | -0.4750 | 40/40 → 21/40 |
| C_episode_disjoint_botnet_ares | ARMF_XGB_vs_VOL5_ARMF_XGB | yes | +0.0118 | +0.4408 | +0.4750 | 21/40 → 40/40 |
| D_zero_day_ares | VOL5_RF_vs_ARMF_XGB | **no** | +0.4663 | +0.4435 | +0.4500 | 3/40 → 21/40 |
| D_zero_day_ares | VOL5_XGB_vs_ARMF_XGB | yes | +0.5243 | +0.4425 | +0.5250 | 0/40 → 21/40 |
| D_zero_day_ares | ARMF_XGB_vs_VOL5_ARMF_XGB | yes | -0.0700 | -0.1350 | -0.1250 | 21/40 → 16/40 |

## Zero-day Ares

| Arm | ROC-AUC | PR-AUC | Threshold | FPR | Window recall | Episodes |
|---|---:|---:|---:|---:|---:|---:|
| `VOL5_RF` | 0.5049 | 0.0136 | 0.005000 | 0.007115 | 0.0169 | 3/40 |
| `VOL5_XGB` | 0.4470 | 0.0145 | 0.001477 | 0.012415 | 0.0000 | 0/40 |
| `ARMF_XGB` | 0.9713 | 0.4570 | 0.002479 | 0.007187 | 0.5593 | 21/40 |
| `VOL5_ARMF_XGB` | 0.9012 | 0.3220 | 0.000304 | 0.005590 | 0.3051 | 16/40 |

A gain measured where Ares is present in training, in protocols B or C, is not evidence of zero-day generalisation. Only protocol D speaks to the zero-day question.
