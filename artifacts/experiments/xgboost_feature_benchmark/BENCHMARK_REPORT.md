# Controlled XGBoost feature benchmark

## Scope and frozen protocol

This additive benchmark changes only the registered feature budget. P1--P6 and the published one-feature XGBoost baseline remain immutable. The P1 population, labels, five folds, authentic training-row order, test rows, benign-reference negatives, episode unit, learner, model parameters, training-negative threshold rule, and episode bootstrap are reused exactly. No unknown/ambiguous row, new split, tuning, rebalancing, label-derived feature, absolute timestamp, PostgreSQL write, or window bootstrap is used.

## Primary endpoint — botnet/Ares episode recall at 1% training FPR

| Arm | Features | Episode recall (95% episode bootstrap CI) | Episodes | Window recall | ROC-AUC | PR-AUC | Test FPR | Entities | Decision |
|---|---|---:|---:|---:|---:|---:|---:|---:|---|
| A | distinct_payload_ratio | 0.3250 [0.1994, 0.4750] | 13/40 | 0.1356 | 0.7615 | 0.0670 | 0.009874 | 5/5 | **RETAIN** |
| B | distinct_payload_ratio, interarrival_mean | 0.0000 [0.0000, 0.0000] | 0/40 | 0.0000 | 0.5321 | 0.0177 | 0.012632 | 0/5 | **REJECT** |
| C | distinct_payload_ratio, bytes_per_packet_destination | 0.0250 [0.0000, 0.0750] | 1/40 | 0.0113 | 0.8154 | 0.0394 | 0.010745 | 1/5 | **REJECT** |
| D | distinct_payload_ratio, interarrival_mean, bytes_per_packet_destination | 0.0250 [0.0000, 0.0750] | 1/40 | 0.0113 | 0.7453 | 0.0294 | 0.014012 | 1/5 | **REJECT** |

P1 reference: 0.0750 episode recall (3/40), ROC-AUC 0.5037. Published P6/XGBoost ARM A reference: 0.3250 (13/40), ROC-AUC 0.7615, PR-AUC 0.0670, FPR 0.009874. ARM A is required to reproduce that published baseline before any benchmark artifact is accepted.

## Direct gains over ARM A

| Arm | Recall delta | Paired episode delta CI | New / lost episodes | Gain entities | ROC delta | PR delta | FPR delta |
|---|---:|---:|---:|---:|---:|---:|---:|
| B | -0.3250 | [-0.4750, -0.1994] | 0 / 13 | 0 | -0.2294 | -0.0493 | +0.002759 |
| C | -0.3000 | [-0.4500, -0.1750] | 0 / 12 | 0 | +0.0538 | -0.0276 | +0.000871 |
| D | -0.3000 | [-0.4500, -0.1750] | 0 / 12 | 0 | -0.0162 | -0.0376 | +0.004138 |

The paired intervals resample the same 40 episode ids. All three candidate intervals are strictly negative, so none is compatible with a positive gain on the primary endpoint in this experiment. ROC-AUC is reported as a point estimate only: no window bootstrap is performed, so 'above chance' is descriptive rather than an additional inferential claim.

## Interpretation of the audited candidates

- **interarrival_mean (ARM B):** despite P6's direct univariate botnet-vs-benign screening AUC of 0.9146, the leave-one-attack-type-out supervised model falls to 0.0000 episode recall, ROC 0.5321, and PR 0.0177. P6 screening described the held-out population directly; it did not establish that the joint rule learned from the four other attack types would transfer at the training-negative 1% tail.
- **bytes_per_packet_destination (ARM C):** global ROC rises to 0.8154, but the ratified operating point detects only 1/40 episodes on 1/5 entities and PR falls to 0.0394. This is exactly why ROC alone cannot select the arm: discrimination over the full ranking does not guarantee useful positive mass in the extreme calibrated tail.
- **combined additions (ARM D):** recall remains 1/40 while observed FPR rises to 0.014012; combining the candidates does not rescue transfer.

These are feature-budget contrasts under one fixed learner and protocol. They do not prove that either feature is intrinsically harmful in every model or population.

## Per-entity botnet results

### ARM A

| Entity | Windows | Window recall | Episodes | Episode recall |
|---|---:|---:|---:|---:|
| 192.168.10.14 → 205.174.165.73 (tcp/http) | 6/31 | 0.1935 | 4/8 | 0.5000 |
| 192.168.10.15 → 205.174.165.73 (tcp/http) | 4/49 | 0.0816 | 2/8 | 0.2500 |
| 192.168.10.5 → 205.174.165.73 (tcp/http) | 5/27 | 0.1852 | 3/7 | 0.4286 |
| 192.168.10.8 → 205.174.165.73 (tcp/http) | 5/26 | 0.1923 | 2/2 | 1.0000 |
| 192.168.10.9 → 205.174.165.73 (tcp/http) | 4/44 | 0.0909 | 2/15 | 0.1333 |

### ARM B

| Entity | Windows | Window recall | Episodes | Episode recall |
|---|---:|---:|---:|---:|
| 192.168.10.14 → 205.174.165.73 (tcp/http) | 0/31 | 0.0000 | 0/8 | 0.0000 |
| 192.168.10.15 → 205.174.165.73 (tcp/http) | 0/49 | 0.0000 | 0/8 | 0.0000 |
| 192.168.10.5 → 205.174.165.73 (tcp/http) | 0/27 | 0.0000 | 0/7 | 0.0000 |
| 192.168.10.8 → 205.174.165.73 (tcp/http) | 0/26 | 0.0000 | 0/2 | 0.0000 |
| 192.168.10.9 → 205.174.165.73 (tcp/http) | 0/44 | 0.0000 | 0/15 | 0.0000 |

### ARM C

| Entity | Windows | Window recall | Episodes | Episode recall |
|---|---:|---:|---:|---:|
| 192.168.10.14 → 205.174.165.73 (tcp/http) | 0/31 | 0.0000 | 0/8 | 0.0000 |
| 192.168.10.15 → 205.174.165.73 (tcp/http) | 0/49 | 0.0000 | 0/8 | 0.0000 |
| 192.168.10.5 → 205.174.165.73 (tcp/http) | 2/27 | 0.0741 | 1/7 | 0.1429 |
| 192.168.10.8 → 205.174.165.73 (tcp/http) | 0/26 | 0.0000 | 0/2 | 0.0000 |
| 192.168.10.9 → 205.174.165.73 (tcp/http) | 0/44 | 0.0000 | 0/15 | 0.0000 |

### ARM D

| Entity | Windows | Window recall | Episodes | Episode recall |
|---|---:|---:|---:|---:|
| 192.168.10.14 → 205.174.165.73 (tcp/http) | 0/31 | 0.0000 | 0/8 | 0.0000 |
| 192.168.10.15 → 205.174.165.73 (tcp/http) | 0/49 | 0.0000 | 0/8 | 0.0000 |
| 192.168.10.5 → 205.174.165.73 (tcp/http) | 2/27 | 0.0741 | 1/7 | 0.1429 |
| 192.168.10.8 → 205.174.165.73 (tcp/http) | 0/26 | 0.0000 | 0/2 | 0.0000 |
| 192.168.10.9 → 205.174.165.73 (tcp/http) | 0/44 | 0.0000 | 0/15 | 0.0000 |

## Results by attack type

### ARM A

| Type | Episode recall | Episodes | Window recall | ROC-AUC | PR-AUC | Test FPR | Threshold |
|---|---:|---:|---:|---:|---:|---:|---:|
| botnet/ares | 0.3250 | 13/40 | 0.1356 | 0.7615 | 0.0670 | 0.009874 | 0.022657 |
| brute_force/ftp_patator | 1.0000 | 1/1 | 0.0492 | 0.8881 | 0.0336 | 0.007366 | 0.065382 |
| brute_force/ssh_patator | 0.1111 | 1/9 | 0.5500 | 0.9199 | 0.5534 | 0.009101 | 0.060507 |
| ddos/loit | 1.0000 | 2/2 | 1.0000 | 0.9903 | 0.3113 | 0.017042 | 0.061925 |
| dos/hulk | 1.0000 | 2/2 | 0.5833 | 0.9680 | 0.1639 | 0.010265 | 0.076837 |

### ARM B

| Type | Episode recall | Episodes | Window recall | ROC-AUC | PR-AUC | Test FPR | Threshold |
|---|---:|---:|---:|---:|---:|---:|---:|
| botnet/ares | 0.0000 | 0/40 | 0.0000 | 0.5321 | 0.0177 | 0.012632 | 0.005655 |
| brute_force/ftp_patator | 0.0000 | 0/1 | 0.0000 | 0.3466 | 0.0065 | 0.009797 | 0.025546 |
| brute_force/ssh_patator | 0.1111 | 1/9 | 0.7500 | 0.9453 | 0.3974 | 0.008319 | 0.029211 |
| ddos/loit | 1.0000 | 2/2 | 0.8095 | 0.9928 | 0.5096 | 0.013580 | 0.028970 |
| dos/hulk | 0.5000 | 1/2 | 0.0833 | 0.6196 | 0.0242 | 0.012475 | 0.022900 |

### ARM C

| Type | Episode recall | Episodes | Window recall | ROC-AUC | PR-AUC | Test FPR | Threshold |
|---|---:|---:|---:|---:|---:|---:|---:|
| botnet/ares | 0.0250 | 1/40 | 0.0113 | 0.8154 | 0.0394 | 0.010745 | 0.002098 |
| brute_force/ftp_patator | 1.0000 | 1/1 | 1.0000 | 0.9999 | 0.9911 | 0.006078 | 0.007443 |
| brute_force/ssh_patator | 0.0000 | 0/9 | 0.0000 | 0.9209 | 0.0843 | 0.007750 | 0.004776 |
| ddos/loit | 1.0000 | 2/2 | 1.0000 | 0.9995 | 0.8316 | 0.014666 | 0.008883 |
| dos/hulk | 0.5000 | 1/2 | 0.5000 | 0.8625 | 0.1822 | 0.010978 | 0.008622 |

### ARM D

| Type | Episode recall | Episodes | Window recall | ROC-AUC | PR-AUC | Test FPR | Threshold |
|---|---:|---:|---:|---:|---:|---:|---:|
| botnet/ares | 0.0250 | 1/40 | 0.0113 | 0.7453 | 0.0294 | 0.014012 | 0.001367 |
| brute_force/ftp_patator | 1.0000 | 1/1 | 1.0000 | 0.9996 | 0.8688 | 0.009153 | 0.005552 |
| brute_force/ssh_patator | 0.0000 | 0/9 | 0.0000 | 0.9355 | 0.1667 | 0.006257 | 0.001714 |
| ddos/loit | 1.0000 | 2/2 | 1.0000 | 0.9998 | 0.9298 | 0.011271 | 0.004706 |
| dos/hulk | 0.5000 | 1/2 | 0.5000 | 0.7832 | 0.1735 | 0.011976 | 0.004794 |

## Robustness and decisions

- **ARM A — RETAIN**: registered baseline and previously demonstrated signal; retained as the minimal reference.
- **ARM B — REJECT**: paired episode-delta interval is strictly negative on the pre-registered primary endpoint; a global ROC gain cannot override that loss.
  Gain relative to A is -0.3250; new detections span 0 entities; observed FPR changes by +0.002759. Important volumetric episode cost: true.
- **ARM C — REJECT**: paired episode-delta interval is strictly negative on the pre-registered primary endpoint; a global ROC gain cannot override that loss.
  Gain relative to A is -0.3000; new detections span 0 entities; observed FPR changes by +0.000871. Important volumetric episode cost: true.
- **ARM D — REJECT**: paired episode-delta interval is strictly negative on the pre-registered primary endpoint; a global ROC gain cannot override that loss.
  Gain relative to A is -0.3000; new detections span 0 entities; observed FPR changes by +0.004138. Important volumetric episode cost: true.

## Minimal best compromise

**ARM A — distinct_payload_ratio.** among arms meeting the conservative RETAIN rule, maximize observed botnet episode recall; break ties by ROC-AUC, PR-AUC, lower FPR, then fewer features

This selection is protocol-specific. Feature gain importance is descriptive and is not used as causal attribution; the registered ablation arms provide the direct budget comparisons.

## Online validity

All three formulas are ONLINE under the P6 window-close convention. `interarrival_mean` uses only consecutive differences between relative event starts already observed in the window. `bytes_per_packet_destination` uses destination byte and packet counters available by window close. `distinct_payload_ratio` uses only observed byte-count pairs. No absolute timestamp or future window enters any feature. The benchmark reconstructs values from historical persisted FlowEnd evidence, so it does **not** measure streaming ingestion latency or the effect of late flow records; that operational question remains outside this benchmark.

Undefined `interarrival_mean` or zero-denominator `bytes_per_packet_destination` values remain native NaN. No fitted imputation and no missingness indicator is added.

## R11 and scope of the evidence

R11 remains open: the botnet endpoint contains **5 entities, 1 destination (`205.174.165.73`), and 40 episodes**. This benchmark demonstrates transfer from the four held-in attack types to the held-out Ares windows, under the frozen population and feature formulas, and shows whether additions improve ARM A on those same episodes. It does not demonstrate generalisation to another victim, another attacker population, another capture, or unseen botnet mechanics. No universal or causal claim is made.

## Integrity

Protocol checks passed: 45; feature/online checks passed: 16; cross-arm identity checks passed: 15. PostgreSQL writes: 0.

