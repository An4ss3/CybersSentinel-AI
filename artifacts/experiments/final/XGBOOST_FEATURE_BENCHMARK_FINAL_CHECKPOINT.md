# Checkpoint final — benchmark XGBoost à quatre bras

Date de vérification : 2026-08-24

## Statut final

La régression normale est verte. Aucun benchmark, dataset, split, modèle, fichier de prédictions ou métrique n'a été régénéré pendant cette vérification. Les intégrations Zeek v2 sur données complètes n'ont pas été lancées.

## Régression complète normale

Commande :

```powershell
python -m pytest modules/detection/tests -q -rs `
  --deselect modules/detection/tests/test_m4_production_entrypoint.py::test_no_production_report_is_created_by_these_tests `
  --deselect modules/detection/tests/test_m4_report_publication.py::test_no_production_m4_report_is_created_by_these_tests
```

Résultat :

```text
981 tests collectés
979 tests sélectionnés
967 passed
12 skipped
2 deselected
0 failed
Durée : 100.20 s
```

Les 12 skips sont attendus :

- 2 tests de liens symboliques indisponibles ou non privilégiés sous Windows ;
- 10 tests d'intégration M3 v2 sur les données Zeek gelées, désormais opt-in avec `--run-full-zeek-v2`.

Les deux seules désélections historiques sont :

1. `modules/detection/tests/test_m4_production_entrypoint.py::test_no_production_report_is_created_by_these_tests`
2. `modules/detection/tests/test_m4_report_publication.py::test_no_production_m4_report_is_created_by_these_tests`

## Garde-fous ciblés du benchmark

Exécution séparée :

```text
30 passed in 0.75s
```

Statut : **30/30 verts**.

## Intégrité P1–P6

Les huit ancrages gelés ont été recalculés et correspondent exactement :

| Artefact | SHA-256 |
|---|---|
| `p1/p1_dataset.csv` | `e95aed008d994510e4c649c287feb8fe8f49a785bec144d7e83aa15804b6c062` |
| `p1/p1_folds.json` | `57e688fd3da90911707d7a172c161686d852094121eda1ac49e0221fc0529fa1` |
| `p1/p1_metrics.json` | `2a51e618397c42b742a289216d3cd89b255c4ccd96a8f985a5ad1c5c4783a447` |
| `p2/p2_metrics.json` | `67d2f60bc57d03bbc990fda14951d4acfb2d718db838b2fbf5b9bb3ee1b0241a` |
| `p3/p3_metrics.json` | `a3e9f1c7175594c94d84ec6a6284d5529fc003bfe7a72845983c0967f4c8d94c` |
| `p4/p4_metrics.json` | `3df92eda32d943b6cfba440eb61ca0fc3b1e11a0ed26b170ac6a3485ed911783` |
| `p5/p5_metrics.json` | `87055c8b14623581c338bc6d56ea183000d4e1e27d4dae3815bf9ec87e3248d7` |
| `p6/p6_feature_audit.json` | `d028e8476df66c2827e534281fdda6c994c6e1023ba42bb57461c34316a9d1ac` |

Statut : **P1–P6 bit-identiques**.

## Baseline XGBoost et benchmark à quatre bras

- Les 13 sorties enregistrées par le manifeste de la baseline XGBoost correspondent à leurs SHA-256.
- SHA-256 du manifeste baseline : `e97a4ca5a6be7f86618e2c8ee8608c2ad4baa9e9c9431ca42e56ed364b516910`.
- Les 44 sorties enregistrées par le manifeste du benchmark à quatre bras correspondent à leurs SHA-256.
- SHA-256 du manifeste benchmark : `2b6e65e658297dd1d96d3f4d3afce9798a5cf9e99279a70253dbbb022315af88`.
- Les cinq modèles ARM A sont bit-identiques aux cinq modèles publiés de la baseline XGBoost.
- Les identités de contenu de `benchmark_metrics.json` et `feature_comparison.json` ont été reproduites.

## Idempotence

Les 44 sorties du benchmark et son manifeste, soit 45 fichiers existants, ont été présentés à leurs publishers immuables avec leurs propres bytes :

```text
IDEMPOTENT_ACCEPTANCE_NO_WRITE_OK=45
```

Tous ont été acceptés comme identiques. Les mtimes nanoseconde mesurés avant et après sont strictement égaux : aucune réécriture n'a eu lieu.

## Processus résiduels

Dernière vérification :

```text
NO_ACTIVE_PYTEST_PYTHON_PROCESS
```

Aucun processus `pytest`, `python` ou `pythonw` associé aux tests ne reste actif.

## Arrêt expérimental

Le benchmark est clos à ce checkpoint. Aucun nouveau benchmark, tuning XGBoost ou changement de protocole n'est autorisé sans accord explicite ultérieur.
