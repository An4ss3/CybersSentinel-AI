# Phase 2 ARM F tuning — immutable pre-registration

Protocol identity: `623e7521ecfefc7f60533f9e187c0880ae08295e22f4a21178e6a557f39c7ca6`

This document was published before any candidate was fitted or any outer-test
score was inspected. The final Ares test is unavailable during tuning.

## Leakage boundary

- outer test: frozen `fold0.test`, 13,951 rows, 177 Ares positives; forbidden during tuning
- tuning pool: frozen `fold0.train`, 57,003 rows, zero Ares
- four internal validations: `fold_k.test ∩ fold0.train`, k=1..4
- outer-test overlap of every internal train and validation: zero

## Surrogate objective

Maximise unweighted macro episode recall over FTP, SSH, DDOS and Hulk at
`target_train_fpr=0.005`, subject to pooled validation FPR <= 0.005 and
every validation-fold FPR <= 0.01. Constraints are never relaxed post hoc.
Ares optimisation claims are forbidden; Ares is a one-shot transfer test.

## Search space

| Parameter | Values |
|---|---|
| `max_depth` | 2, 3, 4, 5 |
| `learning_rate` | 0.025, 0.05, 0.1 |
| `max_n_estimators` | 300, 600, 1000 |
| `reg_alpha` | 0.0, 0.01, 0.1, 1.0 |
| `reg_lambda` | 1.0, 3.0, 10.0, 30.0 |
| `min_child_weight` | 1.0, 3.0, 5.0, 10.0 |
| `subsample` | 0.7, 0.85, 1.0 |
| `colsample_bytree` | 0.67, 1.0 |

Method: deterministic random search without replacement, seed `20260826`, 48 random configurations
plus the fixed 200-tree Phase-1 control. Early stopping: validation AUCPR,
50 rounds. Selection remains episode recall under hard FPR constraints.

## Exact candidate list

| ID | depth | eta | max trees | alpha | lambda | child | subsample | colsample | ES |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| P1_CONTROL | 3 | 0.1 | 200 | 0.0 | 1.0 | 1.0 | 1.0 | 1.0 | no |
| R001 | 5 | 0.1 | 300 | 0.01 | 10.0 | 5.0 | 0.85 | 0.67 | yes |
| R002 | 4 | 0.1 | 1000 | 0.1 | 30.0 | 5.0 | 1.0 | 1.0 | yes |
| R003 | 4 | 0.025 | 600 | 0.1 | 30.0 | 5.0 | 0.85 | 0.67 | yes |
| R004 | 2 | 0.025 | 1000 | 0.1 | 1.0 | 1.0 | 1.0 | 0.67 | yes |
| R005 | 4 | 0.05 | 1000 | 0.1 | 3.0 | 3.0 | 0.85 | 0.67 | yes |
| R006 | 2 | 0.1 | 300 | 0.01 | 1.0 | 10.0 | 0.85 | 1.0 | yes |
| R007 | 2 | 0.05 | 600 | 1.0 | 1.0 | 3.0 | 1.0 | 1.0 | yes |
| R008 | 2 | 0.05 | 600 | 0.01 | 1.0 | 5.0 | 0.7 | 1.0 | yes |
| R009 | 3 | 0.025 | 600 | 1.0 | 30.0 | 5.0 | 1.0 | 1.0 | yes |
| R010 | 4 | 0.05 | 600 | 0.0 | 30.0 | 10.0 | 1.0 | 0.67 | yes |
| R011 | 2 | 0.05 | 1000 | 1.0 | 1.0 | 5.0 | 0.85 | 0.67 | yes |
| R012 | 5 | 0.05 | 600 | 0.0 | 30.0 | 3.0 | 1.0 | 1.0 | yes |
| R013 | 2 | 0.1 | 300 | 1.0 | 10.0 | 3.0 | 0.85 | 0.67 | yes |
| R014 | 5 | 0.05 | 300 | 0.0 | 3.0 | 3.0 | 0.85 | 0.67 | yes |
| R015 | 2 | 0.05 | 600 | 0.01 | 30.0 | 10.0 | 1.0 | 1.0 | yes |
| R016 | 3 | 0.1 | 300 | 1.0 | 1.0 | 1.0 | 0.85 | 0.67 | yes |
| R017 | 3 | 0.05 | 600 | 0.1 | 30.0 | 5.0 | 0.7 | 1.0 | yes |
| R018 | 4 | 0.025 | 1000 | 0.1 | 3.0 | 1.0 | 0.85 | 0.67 | yes |
| R019 | 4 | 0.025 | 600 | 0.01 | 10.0 | 3.0 | 0.7 | 1.0 | yes |
| R020 | 5 | 0.05 | 600 | 0.01 | 30.0 | 1.0 | 1.0 | 0.67 | yes |
| R021 | 3 | 0.05 | 300 | 0.1 | 1.0 | 10.0 | 0.85 | 1.0 | yes |
| R022 | 4 | 0.025 | 300 | 0.01 | 1.0 | 1.0 | 0.7 | 0.67 | yes |
| R023 | 5 | 0.05 | 1000 | 0.01 | 3.0 | 1.0 | 1.0 | 0.67 | yes |
| R024 | 3 | 0.1 | 1000 | 0.1 | 10.0 | 5.0 | 1.0 | 0.67 | yes |
| R025 | 4 | 0.1 | 1000 | 0.0 | 1.0 | 3.0 | 1.0 | 0.67 | yes |
| R026 | 2 | 0.1 | 300 | 0.01 | 30.0 | 10.0 | 1.0 | 1.0 | yes |
| R027 | 4 | 0.025 | 300 | 1.0 | 30.0 | 3.0 | 0.85 | 1.0 | yes |
| R028 | 4 | 0.025 | 300 | 1.0 | 1.0 | 3.0 | 0.85 | 0.67 | yes |
| R029 | 3 | 0.025 | 300 | 0.01 | 3.0 | 3.0 | 0.85 | 0.67 | yes |
| R030 | 2 | 0.05 | 600 | 0.1 | 1.0 | 1.0 | 0.7 | 0.67 | yes |
| R031 | 3 | 0.05 | 1000 | 0.0 | 10.0 | 1.0 | 1.0 | 0.67 | yes |
| R032 | 5 | 0.05 | 300 | 0.01 | 10.0 | 3.0 | 0.7 | 0.67 | yes |
| R033 | 2 | 0.025 | 1000 | 0.01 | 30.0 | 1.0 | 0.7 | 0.67 | yes |
| R034 | 3 | 0.05 | 1000 | 0.01 | 30.0 | 10.0 | 0.85 | 1.0 | yes |
| R035 | 2 | 0.05 | 1000 | 0.1 | 10.0 | 1.0 | 0.85 | 0.67 | yes |
| R036 | 2 | 0.025 | 600 | 0.1 | 10.0 | 1.0 | 1.0 | 0.67 | yes |
| R037 | 2 | 0.05 | 300 | 1.0 | 1.0 | 3.0 | 0.85 | 0.67 | yes |
| R038 | 4 | 0.05 | 600 | 0.01 | 3.0 | 1.0 | 1.0 | 1.0 | yes |
| R039 | 3 | 0.05 | 1000 | 0.0 | 1.0 | 1.0 | 0.85 | 0.67 | yes |
| R040 | 2 | 0.05 | 1000 | 0.1 | 30.0 | 5.0 | 0.85 | 1.0 | yes |
| R041 | 2 | 0.05 | 300 | 1.0 | 1.0 | 5.0 | 0.85 | 1.0 | yes |
| R042 | 5 | 0.025 | 1000 | 1.0 | 10.0 | 5.0 | 1.0 | 0.67 | yes |
| R043 | 2 | 0.05 | 600 | 0.01 | 3.0 | 3.0 | 0.7 | 0.67 | yes |
| R044 | 2 | 0.05 | 1000 | 0.01 | 30.0 | 1.0 | 0.85 | 0.67 | yes |
| R045 | 2 | 0.1 | 600 | 0.1 | 3.0 | 3.0 | 1.0 | 0.67 | yes |
| R046 | 3 | 0.05 | 300 | 0.0 | 30.0 | 3.0 | 0.7 | 0.67 | yes |
| R047 | 3 | 0.025 | 600 | 0.01 | 10.0 | 10.0 | 0.7 | 1.0 | yes |
| R048 | 2 | 0.025 | 600 | 0.1 | 10.0 | 3.0 | 0.85 | 1.0 | yes |
