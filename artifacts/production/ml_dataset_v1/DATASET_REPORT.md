# Production Finale v1 — canonical supervised ML dataset

Dataset content digest: `3d7436178da6960ee5effeb4bee85a0b6da5eead9d2babef3c72cb6b7ca9f20d`  
Dataset file digest: `e95aed008d994510e4c649c287feb8fe8f49a785bec144d7e83aa15804b6c062`

The manifest hashes this report, so this report deliberately does not embed the manifest identity: that would create a circular reference and break deterministic reruns.

## Label policy

| Disposition | Dataset label |
|---|---|
| `target_attack` | `1` |
| `known_other_attack` | `1` |
| `benign_reference` | `0` |
| `unknown` | **excluded** |
| `ambiguous` | **excluded** |

Converting `unknown` or `ambiguous` into a negative is forbidden and is enforced by code and by tests.

## Feature budget

Exactly the five P1 features, in the canonical `FEATURE_NAMES` order:

1. `event_count`
2. `source_packets_total`
3. `destination_packets_total`
4. `source_bytes_total`
5. `destination_bytes_total`

Excluded M6 features: `distinct_destination_ports`, `distinct_destination_ips`, `distinct_source_ips`. ARM F content features are deliberately absent; ARM F/Ares remains a separate scientific experiment on the representational ceiling.

## M-chain window label materialization

| Window disposition | Windows | Dataset label |
|---|---:|---|
| `target_attack` | 199 | 1 |
| `known_other_attack` | 177 | 1 |
| `ambiguous` | 0 | excluded |
| `unknown` | 172372 | excluded |
| `benign_reference` | 0 | 0 |
| **Total** | **172748** | — |

Labels are materialised **out of band**, as files. No `m7_canonical` schema was created and PostgreSQL received zero writes.

## Supervised population

| Population | Rows | Source |
|---|---:|---|
| `target_attack` | 199 | `m6` |
| `known_other_attack` | 177 | `m6` |
| Attack, `label=1` | **376** | `m6` |
| Benign, `label=0` | **70578** | `mb6` + `mb7` |
| **Total** | **70954** | — |
| `unknown` excluded (M) | 172372 | never negative |
| `ambiguous` excluded (M) | 0 | never negative |

Attack windows per type:

| Attack type | Windows |
|---|---:|
| `botnet/ares` | 177 |
| `brute_force/ftp_patator` | 61 |
| `brute_force/ssh_patator` | 60 |
| `ddos/loit` | 42 |
| `dos/hulk` | 36 |

## Parity with the ratified P1 population

- content digest: `3d7436178da6960ee5effeb4bee85a0b6da5eead9d2babef3c72cb6b7ca9f20d`
- file digest: `e95aed008d994510e4c649c287feb8fe8f49a785bec144d7e83aa15804b6c062`
- byte-identical to `artifacts/experiments/p1/p1_dataset.csv`: **true**

P1 remains untouched as experimental evidence. This artifact is a separate production output whose equivalence is proven by digest.

## Semantics note, recorded rather than hidden

Window dispositions are resolved by the frozen P1/P3 rule-overlap classifier, not by folding event dispositions. The `ANY_ATTACK` precedence is verified against the freeze, but the two computations are not identical: on the M chain this yields zero `ambiguous` windows even though M5 v2 marks 164 individual events `ambiguous`. Attack detection is unaffected; the distinction matters only for how uncertainty is named, and in both readings uncertainty is excluded, never benign.

## Scientific limits

- one frozen CICIDS2017 snapshot; 376 attack windows from 9 entities and 54 episodes; entity identity separates the classes perfectly, so the effective attack sample size is of the order of nine.
- `benign_reference` is absent from the M chain, so negatives come exclusively from the parallel Monday capture; any day-correlated artefact is a confounder that this dataset cannot rule out.
- 172,372 M windows remain of unknown status. Alerts on them are not false positives, and treating them as benign would destroy that distinction.
