# A versus A' — marginal effect of removing shared attack entities

## Question

Inside the historical protocol A, with the held-out attack family held constant, does the presence of the same `entity_key` in train and test change the measured performance?

## Construction

`A'` differs from `A` by exactly one operation: the positive training rows whose `entity_key` also appears among the test positives are removed. The test population, every negative, the five frozen features, the model, the `label,row_id` training order and the train-negative-only threshold calibration are unchanged.

## Removal performed

| Fold | Held-out family | Shared entities | Positives removed | Train positives |
|---:|---|---|---:|---|
| 2 | `brute_force/ssh_patator` | 1 | 39 | 316 → 277 |
| 3 | `ddos/loit` | 2 | 44 | 334 → 290 |
| 4 | `dos/hulk` | 2 | 50 | 340 → 290 |

## Results

| Fold | Variant | ROC-AUC | PR-AUC | Threshold | FPR | TP | FP | Recall | Precision | F1 | Episodes |
|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 2 | A | 0.9207 | 0.1122 | 0.005000 | 0.021971 | 52 | 309 | 0.8667 | 0.1440 | 0.2470 | 1/9 |
| 2 | A' | 0.9222 | 0.1319 | 0.005000 | 0.018345 | 52 | 258 | 0.8667 | 0.1677 | 0.2811 | 1/9 |
| 3 | A | 0.9971 | 0.5802 | 0.005000 | 0.025598 | 42 | 377 | 1.0000 | 0.1002 | 0.1822 | 2/2 |
| 3 | A' | 0.9805 | 0.1630 | 0.005000 | 0.020437 | 41 | 301 | 0.9762 | 0.1199 | 0.2135 | 2/2 |
| 4 | A | 0.9390 | 0.5808 | 0.010000 | 0.012546 | 27 | 176 | 0.7500 | 0.1330 | 0.2259 | 2/2 |
| 4 | A' | 0.7267 | 0.0346 | 0.005000 | 0.020602 | 17 | 289 | 0.4722 | 0.0556 | 0.0994 | 1/2 |

## Delta, A' minus A

| Fold | ΔROC-AUC | ΔPR-AUC | ΔFPR | ΔRecall | ΔPrecision | ΔEpisode recall | ΔEpisodes |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 2 | +0.0015 | +0.0197 | -0.003626 | +0.0000 | +0.0237 | +0.0000 | +0 |
| 3 | -0.0165 | -0.4172 | -0.005160 | -0.0238 | +0.0196 | +0.0000 | +0 |
| 4 | -0.2123 | -0.5462 | +0.008055 | -0.2778 | -0.0774 | -0.5000 | -1 |

## Scope and coupling

the shared entities carry positives of several families, so removing their training rows also removes training windows of families other than the held-out one; in folds 3 and 4 one further family is emptied from the training set entirely. A' - A therefore measures the effect of removing the shared entities, not identity leakage isolated at constant training composition.

This experiment measures only the marginal effect of removing the shared entities in folds 2, 3 and 4 at constant held-out family. It does not state that leakage explains, or fails to explain, the A versus B difference.
