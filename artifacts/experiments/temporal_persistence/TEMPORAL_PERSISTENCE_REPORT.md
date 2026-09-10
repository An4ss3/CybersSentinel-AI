# ARM F temporal persistence — final exploratory report

Protocol: `0639860f1bb759d2b559db91604ecfc96a3afb8843e8a61755a5abd2d295a6ee`  
Calibration: `8f747e6aec9649ea214d51878949743b193165a0733ee8283408cbf817d8b00f`  

> This is an additive exploratory result, not a blind or confirmatory test. The hypothesis was generated after prior inspection of Ares, but the persistence threshold was frozen using benign OOF folds 1–4 only.

## Frozen rule

Persistence threshold: `0.8922511339`.

Alert on the official ARM F decision OR on the second of exactly two consecutive windows from the same `entity_key`, with `0 < delta <= 60` and both scores at or above the frozen persistence threshold.

## Baseline versus temporal

| Metric | ARM F baseline | ARM F + persistence | Delta |
|---|---:|---:|---:|
| Ares episodes | 21/40 | 21/40 | +0 |
| Episode recall | 0.5250 | 0.5250 | +0.00 pp |
| Benign false positives | 99 | 99 | +0 |
| Window FPR | 0.007187 | 0.007187 | +0.000000 |
| Alerted benign pseudoepisodes | — | 61 | — |

## Results by source host

| Host | Episodes | Baseline | Temporal | New | Lost |
|---|---:|---:|---:|---:|---:|
| 192.168.10.5 | 7 | 3 | 3 | 0 | 0 |
| 192.168.10.8 | 2 | 2 | 2 | 0 | 0 |
| 192.168.10.9 | 15 | 4 | 4 | 0 | 0 |
| 192.168.10.14 | 8 | 4 | 4 | 0 | 0 |
| 192.168.10.15 | 8 | 8 | 8 | 0 | 0 |

## Results by episode length

| Windows | Episodes | Baseline | Temporal | New | Lost |
|---|---:|---:|---:|---:|---:|
| 1 | 9 | 0 | 0 | 0 | 0 |
| 2 | 10 | 0 | 0 | 0 | 0 |
| 3-4 | 9 | 9 | 9 | 0 | 0 |
| >=5 | 12 | 12 | 12 | 0 | 0 |

## Calibration and stability

Pooled benign FPR: `0.005387`. Maximum fold FPR: `0.006257`. Fold spread: `0.002253`.

| Fold | Benign windows | Baseline FP | Temporal FP | FPR | Pseudoepisodes with two hits |
|---:|---:|---:|---:|---:|---:|
| 1 | 13984 | 56 | 56 | 0.004005 | 0 |
| 2 | 14064 | 88 | 88 | 0.006257 | 1 |
| 3 | 14728 | 90 | 90 | 0.006111 | 0 |
| 4 | 14028 | 72 | 72 | 0.005133 | 0 |

## Neighbour sensitivity

| Threshold | Role | Ares episodes | Fold0 FP | Fold0 FPR |
|---:|---|---:|---:|---:|
| 0.8286380768 | lower | 21 | 99 | 0.007187 |
| 0.8922511339 | selected | 21 | 99 | 0.007187 |
| 0.8922511339 | upper | 21 | 99 | 0.007187 |

## Comparable-FPR diagnostic

A single-window ARM F threshold selected descriptively at no more than the temporal false-positive budget gives 21/40 episodes with 99 false positives. This diagnostic was computed after opening the final fold and did not select the temporal rule.

## Critical interpretation

Classification: **C — aucune amélioration; résultat négatif**.

- 0 nouveaux épisodes et 0 épisode perdu.
- Aucun épisode nouvellement détecté; l’hypothèse des épisodes courts n’est pas soutenue.
- Le gain couvre 0 hôte(s) source.
- Le coût est de 0 faux positifs fenêtre supplémentaires; FPR 0.007187 → 0.007187.
- À budget FPR comparable, le seuil fenêtre seul détecte 21/40 épisodes.
- Les seuils voisins donnent respectivement 21, 21 et 21 épisodes.

The rule uses no attack label, host-specific condition, service or IP identity at decision time. External generalisation is not established: all evidence comes from one frozen CICIDS2017 population and quantised scores from family-specific fold models.
