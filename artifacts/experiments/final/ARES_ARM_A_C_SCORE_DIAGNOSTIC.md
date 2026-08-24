# Diagnostic ciblé — chute de détection Ares, ARM A vs ARM C

Date : 2026-08-24

## Périmètre

Analyse post hoc des prédictions déjà publiées pour le fold `botnet/ares` :

- ARM A : `distinct_payload_ratio` ;
- ARM C : `distinct_payload_ratio + bytes_per_packet_destination` ;
- 177 fenêtres Ares, 13 774 fenêtres négatives `benign_reference`, 40 épisodes ;
- aucun entraînement, tuning, nouveau split, nouveau seuil opérationnel ou accès PostgreSQL.

Les seuils contrefactuels ci-dessous servent uniquement au diagnostic. Ils utilisent les prédictions test et ne sont donc pas admissibles comme points de fonctionnement.

## Résultat officiel

| Bras | Seuil, dérivé des négatifs train | FPR train obtenu | FPR test | Recall fenêtre | Recall épisode | ROC-AUC | PR-AUC |
|---|---:|---:|---:|---:|---:|---:|---:|
| A | 0,022657 | 0,009964 | 0,009874 | 0,1356 | **13/40 = 0,325** | 0,7615 | 0,0670 |
| C | 0,002098 | 0,009295 | 0,010745 | 0,0113 | **1/40 = 0,025** | 0,8154 | 0,0394 |

Le seuil C est déjà environ 10,8 fois plus bas que le seuil A. La calibration sur les négatifs s'adapte donc largement à l'échelle inférieure des scores C. Son FPR test reste proche de la cible de 1 %.

## Distribution des scores

| Distribution | ARM A | ARM C |
|---|---:|---:|
| Score médian des fenêtres Ares | 0,000770 | 0,000152 |
| 90e percentile des fenêtres Ares | 0,032562 | 0,000588 |
| 99e percentile des négatifs test | 0,022601 | 0,003175 |
| Médiane des maxima des 40 épisodes | 0,000770 | 0,000041 |
| 75e percentile des maxima épisode | 0,032562 | 0,000588 |
| Maximum épisode | 0,061905 | 0,324061 |

ARM C améliore le classement global — ROC 0,8154 contre 0,7615 — parce que la masse des fenêtres Ares est généralement au-dessus de la masse centrale des négatifs. Mais cette amélioration ne se prolonge pas dans la queue supérieure des négatifs, qui détermine le fonctionnement à faible FPR.

## Maxima des épisodes ARM C

Les maxima C sont fortement quantifiés :

| Maximum C | Épisodes | FPR test nécessaire pour les inclure |
|---:|---:|---:|
| 0,324061 | 1 | 0,000073 |
| 0,000603 | 6 | 0,090170 |
| 0,000588 | 6 | 0,090388 |
| 0,000329 à 0,000160 | 4 | 0,095760 à 0,119138 |
| 0,000041 | 23 | 0,327646 |

Au seuil officiel C, un seul épisode est détecté :

```text
botnet/ares|192.168.10.5|205.174.165.73|tcp|http|002
```

ARM C ne crée aucun nouvel épisode détecté par rapport à A : 1 épisode est commun, 12 sont détectés uniquement par A, et 27 ne sont détectés par aucun des deux bras.

## Test de l'hypothèse de calibration

Un recalibrage diagnostique utilisant uniquement les négatifs test donne :

| FPR test diagnostique | Seuil C | Épisodes C détectés |
|---:|---:|---:|
| 0,001 | 0,033691 | 1/40 |
| 0,005 | 0,007033 | 1/40 |
| 0,010 | 0,003209 | 1/40 |
| 0,020 | 0,000870 | 1/40 |
| 0,0281, maximum réalisable avant le palier suivant | 0,000656 | 1/40 |
| 0,0999 | 0,000298 | 14/40 |

Le seuil officiel C, 0,002098, est même plus permissif que le seuil test-négatif donnant exactement environ 1 %, 0,003209. Malgré cela, il ne récupère aucun épisode supplémentaire.

Pour atteindre rétrospectivement 13 épisodes, ARM C devrait descendre à 0,000588. Ce seuil produirait un FPR test de **0,090388**, soit environ neuf fois le budget ratifié. Le recall fenêtre serait alors 0,1469, mais ce point est méthodologiquement inadmissible et opérationnellement trop coûteux.

## Conclusion

**La chute d'ARM C n'est pas un simple problème de calibration globale ou un décalage uniforme des scores.** Les trois observations décisives sont :

1. le seuil C est déjà fortement abaissé et son FPR test reste proche de 1 % ;
2. un recalibrage indépendant sur les négatifs test à 1 % détecte toujours 1/40 épisode ;
3. retrouver 13 épisodes exige environ 9 % de FPR.

Le problème est un **chevauchement réel dans la queue opérationnelle à faible FPR** : `bytes_per_packet_destination` améliore le ranking moyen, donc le ROC, mais les maxima de 12 épisodes supplémentaires restent au niveau d'environ 90e percentile des négatifs au lieu d'atteindre leur queue à 99 %. La baisse de PR-AUC, de 0,0670 à 0,0394, est cohérente avec cette absence d'enrichissement positif dans la queue supérieure.

Le contraste A/C montre que l'élargissement du budget avec `bytes_per_packet_destination` produit ce comportement sous ce protocole et cet apprenant. Il ne démontre pas causalement que la feature serait nuisible dans toute population ou tout modèle.

**Décision inchangée : conserver ARM A. Aucun tuning ou nouveau benchmark n'est justifié par ce diagnostic seul.**

## Intégrité

Sources vérifiées contre `artifacts/experiments/xgboost_feature_benchmark/benchmark_manifest.json` :

- `benchmark_metrics.json` ;
- `predictions_arm_A_fold0.csv` ;
- `predictions_arm_C_fold0.csv`.

Le manifeste du benchmark reste inchangé, SHA-256 :

```text
2b6e65e658297dd1d96d3f4d3afce9798a5cf9e99279a70253dbbb022315af88
```
