# Phase 2 — leak-free surrogate tuning of XGBoost on ARM F

Pre-registration identity: `623e7521ecfefc7f60533f9e187c0880ae08295e22f4a21178e6a557f39c7ca6`

Ares was absent from every fit, early-stopping evaluation, threshold and
selection. The final Ares fold was opened only after candidate selection and
refit, so the result is a zero-day transfer measurement, not Ares tuning.

## Selected candidate

`R006` — feasible: **True**

| Parameter | Phase 1 | Tuned |
|---|---:|---:|
| `max_depth` | 3 | 2 |
| `learning_rate` | 0.1 | 0.1 |
| `n_estimators` | 200 | 31 |
| `reg_alpha` | 0.0 | 0.01 |
| `reg_lambda` | 1.0 | 1.0 |
| `min_child_weight` | 1.0 | 10.0 |
| `subsample` | 1.0 | 0.85 |
| `colsample_bytree` | 1.0 | 1.0 |

## Internal known-family validation

| Model | Feasible | Macro episode recall | Min family recall | Macro PR-AUC | Pooled FPR | Max fold FPR |
|---|---|---:|---:|---:|---:|---:|
| Phase-1 control | True | 0.5000 | 0.0000 | 0.4853 | 0.002975 | 0.006826 |
| Selected | True | 0.7778 | 0.1111 | 0.7617 | 0.001549 | 0.002923 |

Feasible candidates: 49/49.

## One-shot Ares transfer

ROC-AUC: 0.9713 -> 0.9624 (delta -0.0089)

PR-AUC: 0.4570 -> 0.3742 (delta -0.0828)

| Target train FPR | Phase-1 episodes | Phase-1 FPR | Tuned episodes | Tuned FPR | Paired delta CI |
|---:|---:|---:|---:|---:|---:|
| 0.01 | 21/40 | 0.007187 | 17/40 | 0.009583 | [-0.2000, -0.0250] |
| 0.005 | 17/40 | 0.003122 | 17/40 | 0.002251 | [+0.0000, +0.0000] |
| 0.002 | 15/40 | 0.002033 | 17/40 | 0.002251 | [+0.0000, +0.1250] |
| 0.001 | 14/40 | 0.001597 | 0/40 | 0.000000 | [-0.5000, -0.2000] |
| 0.0005 | 12/40 | 0.000145 | 0/40 | 0.000000 | [-0.4500, -0.1750] |

## Per-entity Ares transfer at the primary 0.5% target

| Entity | Tuned episodes | Tuned recall |
|---|---:|---:|
| `192.168.10.14|205.174.165.73|tcp|http` | 4/8 | 0.5000 |
| `192.168.10.15|205.174.165.73|tcp|http` | 4/8 | 0.5000 |
| `192.168.10.5|205.174.165.73|tcp|http` | 3/7 | 0.4286 |
| `192.168.10.8|205.174.165.73|tcp|http` | 2/2 | 1.0000 |
| `192.168.10.9|205.174.165.73|tcp|http` | 4/15 | 0.2667 |

## Interpretation boundary

The selected hyperparameters optimise transfer surrogates on four known
families. Any Ares change is an observed transfer effect. It cannot be used
to add candidates, alter constraints or rerun selection. R11 remains open:
five entities, one destination host and no demonstrated generalisation to
another capture, victim, attacker or botnet family.
