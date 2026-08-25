# Six-arm payload-content feature benchmark

## Scope and frozen protocol

This additive benchmark changes only the registered feature budget. P1--P6, the published one-feature XGBoost baseline and the frozen four-arm A--D benchmark remain immutable. The P1 population, labels, five folds, authentic training-row order, ordered test rows, benign-reference negatives, episode unit, learner, model parameters, training-negative threshold rule and episode bootstrap are reused exactly. No unknown/ambiguous row, new split, tuning, rebalancing, label-derived feature, absolute timestamp, PostgreSQL write or window bootstrap is used.

Arms A/E/F/G/H/I were registered before any content value was extracted. ARM I is `A + all six metrics` by pre-registration, never a subset chosen after reading E--H.

## Primary endpoint — botnet/Ares episode recall at 1% training FPR

| Arm | Features | Episode recall (95% episode CI) | Episodes | Window recall | ROC-AUC | PR-AUC | Test FPR | Entities | Decision |
|---|---|---:|---:|---:|---:|---:|---:|---:|---|
| A | 1 feat. | 0.3250 [0.1994, 0.4750] | 13/40 | 0.1356 | 0.7615 | 0.0670 | 0.009874 | 5/5 | **RETAIN** |
| E | 3 feat. | 0.0000 [0.0000, 0.0000] | 0/40 | 0.0000 | 0.7374 | 0.0518 | 0.006897 | 0/5 | **REJECT** |
| F | 3 feat. | 0.5250 [0.3750, 0.6750] | 21/40 | 0.5593 | 0.9713 | 0.4570 | 0.007187 | 5/5 | **INCONCLUSIVE** |
| G | 2 feat. | 0.0000 [0.0000, 0.0000] | 0/40 | 0.0000 | 0.5535 | 0.0233 | 0.006679 | 0/5 | **REJECT** |
| H | 2 feat. | 0.0000 [0.0000, 0.0000] | 0/40 | 0.0000 | 0.3070 | 0.0153 | 0.009728 | 0/5 | **REJECT** |
| I | 7 feat. | 0.1500 [0.0500, 0.2750] | 6/40 | 0.0452 | 0.8310 | 0.1818 | 0.004211 | 5/5 | **REJECT** |

ARM A is required to reproduce the ratified reference exactly before any artifact is accepted: 13/40 episodes, ROC-AUC 0.7615, PR-AUC 0.0670, test FPR 0.009874.

## The same arms at 0.1% training FPR

| Arm | Episode recall | Episodes | Window recall | Test FPR |
|---|---:|---:|---:|---:|
| A | 0.0000 | 0/40 | 0.0000 | 0.000726 |
| E | 0.0000 | 0/40 | 0.0000 | 0.000508 |
| F | 0.3500 | 14/40 | 0.1582 | 0.001597 |
| G | 0.0000 | 0/40 | 0.0000 | 0.001162 |
| H | 0.0000 | 0/40 | 0.0000 | 0.000944 |
| I | 0.0000 | 0/40 | 0.0000 | 0.001960 |

## Paired gains over ARM A at 1% training FPR

| Arm | Recall delta | Paired episode delta CI | New / lost episodes | Gain entities | ROC delta | PR delta | FPR delta |
|---|---:|---:|---:|---:|---:|---:|---:|
| E | -0.3250 | [-0.4750, -0.1994] | 0 / 13 | 0 | -0.0241 | -0.0152 | -0.002977 |
| F | +0.2000 | [+0.0750, +0.3250] | 8 / 0 | 2 | +0.2097 | +0.3900 | -0.002686 |
| G | -0.3250 | [-0.4750, -0.1994] | 0 / 13 | 0 | -0.2080 | -0.0437 | -0.003194 |
| H | -0.3250 | [-0.4750, -0.1994] | 0 / 13 | 0 | -0.4546 | -0.0518 | -0.000145 |
| I | -0.1750 | [-0.3250, -0.0500] | 1 / 8 | 1 | +0.0695 | +0.1147 | -0.005663 |

The paired intervals resample the same 40 held-out episodes, so every comparison is paired rather than a visual contrast of two marginal intervals.

## Declared missingness diagnostic

Extraction established that the presence of `normalized_header_template_repeat_ratio` is **exactly equivalent** to `service == http`: 12,279 frozen windows carry it and all of them are HTTP. All 177 Ares windows are HTTP, against 17.1% of benign windows. Because P1 forbids `entity_service` as a feature and XGBoost branches natively on missing values, an ARM H or ARM I effect could be carried by that missingness instead of by header-template repetition.

Two diagnostics therefore keep only the presence indicators and discard the values. They are not arms and take part in no ranking.

| Arm | Episodes A | Episodes arm | Episodes indicator only | Arm gain | Indicator gain | Share explained |
|---|---:|---:|---:|---:|---:|---:|
| H | 13/40 | 0/40 | 0/40 | -13 | -13 | n/a |
| I | 13/40 | 6/40 | 4/40 | -7 | -9 | n/a |

A share at or above 1.0 means the presence indicator alone reproduces the whole gain, so the gain cannot be credited to the metric value. A RETAIN verdict requires this not to be the case.

## Decisions

- **ARM A — RETAIN**: registered baseline and ratified reference; retained as the minimal comparator.
- **ARM E — REJECT**: paired episode-delta interval is strictly negative on the pre-registered primary endpoint; a global ROC gain cannot override that loss.
- **ARM F — INCONCLUSIVE**: FPR is not stable.
- **ARM G — REJECT**: paired episode-delta interval is strictly negative on the pre-registered primary endpoint; a global ROC gain cannot override that loss.
- **ARM H — REJECT**: paired episode-delta interval is strictly negative on the pre-registered primary endpoint; a global ROC gain cannot override that loss.
- **ARM I — REJECT**: paired episode-delta interval is strictly negative on the pre-registered primary endpoint; a global ROC gain cannot override that loss.

## Minimal best compromise

**ARM A** — distinct_payload_ratio. among arms meeting the conservative RETAIN rule, maximise observed botnet/ares episode recall; break ties by ROC-AUC, PR-AUC, lower FPR, then fewer features

## Content metric availability

| Metric | Benign | Ares | Other attacks |
|---|---:|---:|---:|
| `source_payload_entropy_normalized` | 64675/70578 (91.6%) | 177/177 (100.0%) | 160/199 (80.4%) |
| `destination_payload_entropy_normalized` | 62394/70578 (88.4%) | 177/177 (100.0%) | 196/199 (98.5%) |
| `source_non_printable_ratio` | 64683/70578 (91.6%) | 177/177 (100.0%) | 160/199 (80.4%) |
| `destination_non_printable_ratio` | 62394/70578 (88.4%) | 177/177 (100.0%) | 196/199 (98.5%) |
| `payload_prefix_repeat_ratio` | 64683/70578 (91.6%) | 177/177 (100.0%) | 160/199 (80.4%) |
| `normalized_header_template_repeat_ratio` | 12063/70578 (17.1%) | 177/177 (100.0%) | 39/199 (19.6%) |

Undefined metrics remain native NaN inside every arm. No imputation, fitted fill value or missingness indicator is added to an arm; indicators exist only in the two diagnostics.

## R11 and scope of the evidence

R11 remains open: the botnet endpoint contains **5 entities, 1 destination (`205.174.165.73`) and 40 episodes**. This benchmark demonstrates transfer from the four held-in attack types to the held-out Ares windows under the frozen population and the registered budgets. It does not demonstrate generalisation to another victim, attacker, capture or botnet family, and it does not measure streaming ingestion latency.

## Integrity

Frozen digests verified: 9. P1 protocol checks: 45. Content join checks: 3. Feature assembly checks: 21. Cross-model identity checks: 11. Models fitted: 40. PostgreSQL writes: 0.

