# Label-coverage correction — Production Finale v2

Generated from the artifacts of this run. Production Finale v1 is untouched and remains the dataset of record for every published experiment.

## What changed

| Item | v1 | v2 |
|---|---:|---:|
| Label policy | M5 v2 | **M5 v3** |
| Attack windows | 376 | **464** |
| Attack episodes | 54 | **68** |
| Attack entities | 9 | 9 |
| Benign windows | 70578 | 70578 |
| Total rows | 70954 | **71042** |
| M6 `unknown` | 172372 | 172284 |

88 windows changed disposition, all of them from `unknown` to an attack disposition. No window ever moved towards benign.

## Ground truth available in v2

| Attack type | Disposition | Priority | New in v3 | Windows | Episodes | Entities | Partition |
|---|---|:-:|:-:|---:|---:|---:|---|
| `botnet/ares` | known_other_attack | — | — | 177 | 40 | 5 | Friday-WorkingHours |
| `brute_force/ftp_patator` | target_attack | yes | — | 61 | 1 | 1 | Tuesday-WorkingHours |
| `brute_force/ssh_patator` | target_attack | yes | — | 60 | 9 | 2 | Tuesday-WorkingHours |
| `ddos/loit` | target_attack | yes | — | 42 | 2 | 2 | Friday-WorkingHours |
| `dos/goldeneye` | target_attack | yes | **yes** | 16 | 4 | 2 | Wednesday-workingHours |
| `dos/hulk` | target_attack | yes | — | 36 | 2 | 2 | Wednesday-workingHours |
| `dos/slowhttptest` | known_other_attack | yes | **yes** | 26 | 8 | 2 | Wednesday-workingHours |
| `dos/slowloris` | known_other_attack | yes | **yes** | 46 | 2 | 2 | Wednesday-workingHours |

## Priority family coverage

| Family | Represented | Windows | Episodes |
|---|:-:|---:|---:|
| `brute_force/ftp_patator` | **yes** | 61 | 1 |
| `brute_force/ssh_patator` | **yes** | 60 | 9 |
| `dos/hulk` | **yes** | 36 | 2 |
| `dos/slowloris` | **yes** | 46 | 2 |
| `dos/slowhttptest` | **yes** | 26 | 8 |
| `dos/goldeneye` | **yes** | 16 | 4 |
| `ddos/loit` | **yes** | 42 | 2 |

## Scope and limits

The correction adds windows and episodes but **no new entity**: the two entity keys involved were already attack entities. The effective sample size stays at 9 attack entities, and the day/capture confounder is unchanged: all negatives still come from the parallel Monday capture.

`friday-portscan` and `wednesday-heartbleed` were deliberately left unrealigned, and Thursday remains outside the canonical chain with its NAT behaviour unverified. Each reason is recorded in `label_policy_v3.json`.
