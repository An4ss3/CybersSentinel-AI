# ARM F ratification and the pre-registered ARM J1 hybrid

Pre-registration identity: `ef2e85daba806e3a59e66c8f599aa380853f9ba69bbdc81ef7586014bee01bc0`

Every threshold is a quantile of the training negatives at a registered
target. The test set never selected a threshold, a feature, a
hyperparameter or an architecture. Only the feature budget varies.

## Registered budgets

| Arm | Features |
|---|---|
| A | `distinct_payload_ratio` |
| F | `distinct_payload_ratio`, `source_non_printable_ratio`, `destination_non_printable_ratio` |
| J1 | `distinct_payload_ratio`, `source_non_printable_ratio`, `destination_non_printable_ratio`, `interarrival_mean` |

## 1. Primary endpoint — botnet/ares at 1% training FPR

| Arm | Episodes | Episode recall | 95% episode CI | Window recall | ROC-AUC | PR-AUC | Test FPR | Alerts |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| A | 13/40 | 0.3250 | [+0.1994, +0.4750] | 0.1356 | 0.7615 | 0.0670 | 0.009874 | 160 |
| F | 21/40 | 0.5250 | [+0.3750, +0.6750] | 0.5593 | 0.9713 | 0.4570 | 0.007187 | 198 |
| J1 | 15/40 | 0.3750 | [+0.2250, +0.5250] | 0.2203 | 0.9430 | 0.2043 | 0.007478 | 142 |

### Paired episode deltas on the primary endpoint

| Contrast | Delta | Paired 95% CI | New / lost | Direction |
|---|---:|---:|---:|---|
| F - A | +0.2000 | [+0.0750, +0.3250] | 8 / 0 | improved |
| J1 - A | +0.0500 | [+0.0000, +0.1250] | 2 / 0 | indistinguishable |
| J1 - F | -0.1500 | [-0.2750, -0.0500] | 0 / 6 | degraded |

## 2. Co-primary endpoint — brute_force/ssh_patator at 1% training FPR

| Arm | Episodes | Episode recall | 95% episode CI | Window recall | ROC-AUC | PR-AUC | Test FPR |
|---|---:|---:|---:|---:|---:|---:|---:|
| A | 1/9 | 0.1111 | [+0.0000, +0.3333] | 0.5500 | 0.9199 | 0.5534 | 0.009101 |
| F | 0/9 | 0.0000 | [+0.0000, +0.0000] | 0.0000 | 0.3992 | 0.0048 | 0.006613 |
| J1 | 0/9 | 0.0000 | [+0.0000, +0.0000] | 0.0000 | 0.9049 | 0.0331 | 0.004693 |

| Contrast | Delta | Paired 95% CI | New / lost | Direction |
|---|---:|---:|---:|---|
| F - A | -0.1111 | [-0.3333, +0.0000] | 0 / 1 | indistinguishable |
| J1 - A | -0.1111 | [-0.3333, +0.0000] | 0 / 1 | indistinguishable |
| J1 - F | +0.0000 | [+0.0000, +0.0000] | 0 / 0 | indistinguishable |

## 3. All five pre-registered operating points

### botnet/ares

| Target train FPR | A episodes | A test FPR | F episodes | F test FPR | J1 episodes | J1 test FPR |
|---|---:|---:|---:|---:|---:|---:|
| 0.01 | 13/40 | 0.009874 | 21/40 | 0.007187 | 15/40 | 0.007478 |
| 0.005 | 2/40 | 0.005590 | 17/40 | 0.003122 | 15/40 | 0.003557 |
| 0.002 | 0/40 | 0.002033 | 15/40 | 0.002033 | 3/40 | 0.000799 |
| 0.001 | 0/40 | 0.000726 | 14/40 | 0.001597 | 3/40 | 0.000799 |
| 0.0005 | 0/40 | 0.000290 | 12/40 | 0.000145 | 0/40 | 0.000363 |

### brute_force/ftp_patator

| Target train FPR | A episodes | A test FPR | F episodes | F test FPR | J1 episodes | J1 test FPR |
|---|---:|---:|---:|---:|---:|---:|
| 0.01 | 1/1 | 0.007366 | 1/1 | 0.004005 | 1/1 | 0.001716 |
| 0.005 | 1/1 | 0.002932 | 1/1 | 0.002503 | 1/1 | 0.001716 |
| 0.002 | 0/1 | 0.001216 | 1/1 | 0.001144 | 1/1 | 0.001001 |
| 0.001 | 0/1 | 0.000644 | 1/1 | 0.000429 | 1/1 | 0.000644 |
| 0.0005 | 0/1 | 0.000644 | 1/1 | 0.000358 | 0/1 | 0.000429 |

### brute_force/ssh_patator

| Target train FPR | A episodes | A test FPR | F episodes | F test FPR | J1 episodes | J1 test FPR |
|---|---:|---:|---:|---:|---:|---:|
| 0.01 | 1/9 | 0.009101 | 0/9 | 0.006613 | 0/9 | 0.004693 |
| 0.005 | 1/9 | 0.003626 | 0/9 | 0.006613 | 0/9 | 0.004693 |
| 0.002 | 1/9 | 0.001351 | 0/9 | 0.002844 | 0/9 | 0.003555 |
| 0.001 | 1/9 | 0.001209 | 0/9 | 0.002133 | 0/9 | 0.002702 |
| 0.0005 | 1/9 | 0.000213 | 0/9 | 0.001564 | 0/9 | 0.001991 |

### ddos/loit

| Target train FPR | A episodes | A test FPR | F episodes | F test FPR | J1 episodes | J1 test FPR |
|---|---:|---:|---:|---:|---:|---:|
| 0.01 | 2/2 | 0.017042 | 2/2 | 0.006111 | 2/2 | 0.003666 |
| 0.005 | 1/2 | 0.008080 | 2/2 | 0.003395 | 2/2 | 0.003666 |
| 0.002 | 1/2 | 0.002648 | 2/2 | 0.000883 | 2/2 | 0.002512 |
| 0.001 | 1/2 | 0.002173 | 2/2 | 0.000679 | 2/2 | 0.001222 |
| 0.0005 | 1/2 | 0.001154 | 2/2 | 0.000339 | 2/2 | 0.000611 |

### dos/hulk

| Target train FPR | A episodes | A test FPR | F episodes | F test FPR | J1 episodes | J1 test FPR |
|---|---:|---:|---:|---:|---:|---:|
| 0.01 | 2/2 | 0.010265 | 2/2 | 0.005133 | 2/2 | 0.004919 |
| 0.005 | 2/2 | 0.007129 | 2/2 | 0.004990 | 2/2 | 0.004919 |
| 0.002 | 2/2 | 0.003208 | 2/2 | 0.001640 | 2/2 | 0.003137 |
| 0.001 | 2/2 | 0.001853 | 2/2 | 0.000784 | 1/2 | 0.001212 |
| 0.0005 | 2/2 | 0.001853 | 2/2 | 0.000642 | 1/2 | 0.000855 |

## 4. Verdicts

**ARM F: SUPPORTED** — Ares episode recall is strictly above ARM A, the paired episode-delta interval is strictly positive, and the realised test FPR is not above ARM A's, so ARM F Pareto-dominates ARM A

| Ratified condition | Met |
|---|---|
| episode_recall_strictly_above_arm_a | yes |
| paired_ci_strictly_positive | yes |
| realised_fpr_not_above_arm_a | yes |
| paired_ci_strictly_negative | no |

ARM J1 directions from the paired intervals:

| Contrast | Direction |
|---|---|
| ares_vs_arm_f | degraded |
| ares_vs_arm_a | indistinguishable |
| ssh_vs_arm_f | indistinguishable |
| ssh_vs_arm_a | indistinguishable |

the ssh_patator fold contains 9 episodes, so a one-episode difference cannot reach significance at this sample size; directions labelled indistinguishable are genuinely undetermined, not neutral findings

## 5. Equal-alert-budget diagnostic — secondary, never ratifying

| Attack type | Alert budget | A episodes | F episodes | J1 episodes |
|---|---:|---:|---:|---:|
| botnet/ares | 160 | 13/40 | 21/40 | 15/40 |
| brute_force/ftp_patator | 106 | 1/1 | 1/1 | 1/1 |
| brute_force/ssh_patator | 161 | 1/9 | 0/9 | 0/9 |
| ddos/loit | 293 | 2/2 | 2/2 | 2/2 |
| dos/hulk | 165 | 2/2 | 2/2 | 2/2 |

This table aligns budgets using ARM A's test-set alert count. It informs
the operational reading and may never ratify an arm.

## 6. R11 scope

The botnet endpoint contains 5 entities, 1 destination (`205.174.165.73`) and 40 episodes.

- limited entity diversity
- limited host-pair diversity
- risk of memorising behaviour specific to this capture
- no generalisation beyond the observed population

an improvement measured on the same entities is not evidence of global generalisation to another victim, attacker, capture or botnet family
