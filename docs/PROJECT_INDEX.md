# CyberSentinel — Project Index

> **READ THIS FILE FIRST.**
> Then follow only the referenced documents needed for the current milestone.

## Purpose

Single authoritative entry point for any new chat session, contributor, or reviewer. Contains the current project state, milestone status, identity ledger, repository layout, and documentation map. Does not duplicate content that belongs in referenced documents.

## Authoritative scope

This file is the **only** document that must be read to understand the project's current position. Detailed evidence, verification, history, and debt are maintained in the referenced documents below.

## Status legend

Throughout this document:

- **DONE / FROZEN** — implemented, verified, published, and immutable. Never modify.
- **VERIFIED** — a fact established by direct read-only observation of project evidence.
- **PLANNED — NOT CREATED YET** — designed and approved in principle, but no file exists.
- **NOT IMPLEMENTED** — not designed or not authorized.

## Terminology

Use these names consistently. They are not interchangeable.

| Term | Meaning |
|---|---|
| **chaîne M** / M chain | The existing canonical chain M1 → M2 → M3 v2 → M4 → M5 → M6. Frozen. |
| **piste MB** / MB track | The parallel Monday Benign track. Never merged into the M chain. |
| **MB1** | Monday evidence freeze |
| **MB2** | Monday Zeek replay |
| **MB3** | Monday exact-time normalization |
| **MB4** | Monday canonical persistence |
| **MB6** | Monday feature windows |
| **MB-LABEL** | Monday labeling to `benign_reference` |

There is deliberately no MB5: the MB track reuses the frozen M5 v1 policy rather than defining its own.

## Related documents

| Document | Responsibility |
|---|---|
| [Development history](CYBERSENTINEL_DEVELOPMENT_HISTORY.md) | Historical narrative of scientific evolution |
| [M2 summary](canonical/M2_SUMMARY.md) | Frozen M2 replay facts |
| [M2 verification](canonical/M2_VERIFICATION.md) | Immutable M2 integrity evidence |
| [M3 v2 status](canonical/M3_READINESS.md) | M3 v2 implementation and freeze status |
| [M3 v2 synchronization](canonical/M3_V2_SYNCHRONIZATION.md) | Repair record for the 3 Aug 2026 consistency fix |
| [Technical debt](canonical/TECHNICAL_DEBT.md) | All known non-blocking issues |
| [Historical progress report](archive/PROGRESS_REPORT_2026-07-08.md) | Legacy July 2026 report — historical only |

---

## Project overview

CyberSentinel is a network intrusion detection research project with two coexisting tracks:

1. **Frozen legacy track** — XGBoost classifiers, FastAPI scoring API, PostgreSQL alerts, Grafana dashboards. Preserved for comparison and demonstration.
2. **Canonical track** — strict data-contract pipeline built from immutable CICIDS2017 PCAP evidence through deterministic Zeek replay toward reproducible, provenance-bound detection.

A third, **strictly parallel** track (**MB — Monday Benign**) is implemented and verified through MB-LABEL. See "Monday Benign track" below.

---

## Milestone status

| Milestone | Status | Frozen |
|---|---|---|
| M1 — PCAP acquisition and dataset freeze | **DONE** | Yes |
| M2 — deterministic Zeek replay | **DONE** | Yes |
| M3 v1 — microsecond normalization | Verified then superseded | Preserved |
| M3 v2 — exact-time normalization | **DONE** | Yes |
| M4 — canonical event persistence | **DONE** | Yes |
| M5 — sidecar label ledger (v1) | **DONE** | Yes |
| M5 v2 — observable-attacker policy (additive) | **DONE** | Additive, v1 untouched |
| M6 — canonical feature windows | **DONE** | Yes |
| Label materialization | **DONE, out of band** — 172,748 window labels as files, no `m7_*` schema | Yes |
| ML dataset | **DONE** — Production Finale v1, 70,954 rows | Yes |
| MB1 — Monday Benign freeze | **IMPLEMENTED / VERIFIED** — manifest and report published | Yes |
| MB2 — Monday Benign Zeek replay: **Docker routing** | **VERIFIED / READY** | — |
| MB2 — Monday Benign Zeek replay: **contracts + runner + tests** | **IMPLEMENTED, 41 tests passing** | Yes |
| MB2 — Monday Benign Zeek replay: **manifest YAML** | **PUBLISHED** | Yes |
| MB2 — Monday Benign Zeek replay: **actual replay execution** | **EXECUTED / VERIFIED** 2026-08-13, 764 s | Yes |
| MB3 — Monday Benign exact-time normalization | **EXECUTED / VERIFIED** 2026-08-13, 46.6 s | Yes |
| MB4 — Monday Benign canonical persistence | **EXECUTED / VERIFIED** 2026-08-13, 91.8 s, in `cybersentinel_test` | Yes |
| MB6 — Monday Benign feature windows | **EXECUTED / VERIFIED** 2026-08-13, 70,921 windows | Yes |
| MB-LABEL (MB7) — Monday Benign sidecar labeling | **EXECUTED / VERIFIED** 2026-08-13 | Yes |
| P1/A — supervised leave-one-attack-type-out benchmark | **EXECUTED / VERIFIED** 2026-08-17 | Yes |
| P2/B — temporal-matched ablation of R1 | **EXECUTED / VERIFIED** 2026-08-17 | Yes |
| P3/D — unsupervised anomaly benchmark | **EXECUTED / VERIFIED** 2026-08-17 | Yes |
| P4/C — conservative robustness control | **EXECUTED / VERIFIED** 2026-08-17 | Yes |
| P5–P6 — feature extension and audit | **EXECUTED / VERIFIED** 2026-08-17/18 | Yes |
| XGBoost baseline and four-arm A–D benchmark | **EXECUTED / VERIFIED / FROZEN** 2026-08-18/24 | Yes |
| Six-arm payload-content benchmark A/E/F/G/H/I | **EXECUTED / VERIFIED / FROZEN** 2026-08-25 | Yes |
| ARM F ratification and ARM J1 control | **EXECUTED / VERIFIED / FROZEN** 2026-08-26 — ARM F supported; J1 rejected | Yes |
| Phase 2 — leak-free surrogate XGBoost tuning on ARM F | **EXECUTED / VERIFIED** 2026-08-26 — R006 selected internally; no Ares recall gain on one-shot transfer | Yes |
| ARM F temporal persistence (additive) | **EXECUTED / VERIFIED** 2026-08-26 — negative result: rule inactive, Ares 21/40 unchanged | Yes |
| Production Finale v1 — canonical supervised ML dataset | **EXECUTED / VERIFIED / FROZEN** 2026-08-27 — 70,954 rows, byte-identical to P1 | Yes |
| Final validation step 1 — deterministic splits A/B/C/D | **EXECUTED / VERIFIED** 2026-08-27 | Yes |
| Final validation step 2 — VOL5 evaluation, D1/D2 | **EXECUTED / VERIFIED** 2026-08-27 — D2 reproduces the published Ares stream exactly | Yes |
| Final validation step 3 — A′ shared-entity diagnostic | **EXECUTED / VERIFIED** 2026-08-27 — heterogeneous, no causal attribution | Yes |
| Final validation step 4 — final report generated from artifacts | **EXECUTED / VERIFIED** 2026-08-27 — 61 consistency checks | Yes |
| Final validation step 5 — ARM F extension | **EXECUTED / VERIFIED** 2026-08-27 — zero-day: VOL5 0/40, ARM F 21/40 | Yes |

Roadmap beyond this point is defined in `CYBERSENTINEL_DEVELOPMENT_HISTORY.md` only as a single grouped line: `M6–M13 windows, splits, models, reproducibility`. Individual milestones after M6 are **not** individually scoped in the repository.

---

## Production Finale v1 and the final scientific validation

### Production Finale v1 — canonical supervised ML dataset

Published under `artifacts/production/ml_dataset_v1/`, additive, byte-identical in content to the ratified P1 population.

| Item | Value |
|---|---|
| Rows | **70,954** = 376 attack + 70,578 benign |
| Attack composition | 199 `target_attack` + 177 `known_other_attack` |
| Excluded | 172,372 M6 `unknown`, 0 M6 `ambiguous`; never negatives |
| Label policy | attack → 1, `benign_reference` → 0, `unknown` / `ambiguous` **excluded** |
| Feature budget | **VOL5**, the five volume features in `p1_dataset.FEATURE_NAMES` order |
| `ml_dataset.csv` | `e95aed008d994510e4c649c287feb8fe8f49a785bec144d7e83aa15804b6c062` |
| `window_labels.csv` | `b3ddad6bf2ee26590dadbf0c0ec1b23899924ea2b44d9de9736b8465cad24d74` |
| Window labels | 172,748 rows covering the whole M chain |
| PostgreSQL writes | **0**; `m7_*` schema **not** created |

Naming, ratified 2026-08-27: **VOL5** is the five-volume baseline. **ARM_A** remains reserved for the repository's historical single-feature definition, `distinct_payload_ratio`, and is not the same object.

### Final scientific validation — five additive steps

Published under `artifacts/experiments/final_validation/`. `FINAL_VALIDATION_REPORT.md` is generated from the artifacts and gated by **61** cross-artifact consistency checks; it regenerates byte-identically.

| Step | Content | Key outcome |
|---|---|---|
| 1 | deterministic splits A/B/C/D, no randomness | A reproduces `p1_folds.json` membership; B entity-disjoint on 9 folds |
| 2 | VOL5 evaluation on all protocols, D1 and D2 | D2 reproduces the published Ares stream exactly, 13,951/13,951 scores |
| 3 | A′ shared-entity removal diagnostic | heterogeneous across folds 2–4; no causal attribution |
| 4 | report generation only | no experiment, no split, no model |
| 5 | ARM F extension, read-only PostgreSQL | zero-day Ares: VOL5 **0/40**, ARM F **21/40** |

Protocol semantics, never to be conflated:

| Label | Meaning |
|---|---|
| **A** | family novelty; **deterministic reimplementation**, not a reproduction of P1 |
| **B** | entity novelty; the family may still be in training |
| **C Ares** | episode novelty inside a known family; entity-disjointness impossible by construction |
| **D1** | zero-day Ares, re-fitted under the `label,row_id` order |
| **D2** | zero-day Ares, frozen P1 model re-scored; the exact historical anchor |
| **A′** | shared-entity removal diagnostic; coupled with family removal, so not an isolated leakage measure |

Feature-budget results, at the primary 1% operating point:

| Protocol | VOL5 (RandomForest) | VOL5 (XGBoost) | ARM F (XGBoost) | VOL5+ARM F (XGBoost) |
|---|---:|---:|---:|---:|
| A | 9/54 | 5/54 | 26/54 | 21/54 |
| B entity-disjoint | 46/54 | 43/54 | 26/54 | 46/54 |
| C Ares episode-disjoint | 40/40 | 40/40 | 21/40 | 40/40 |
| **D zero-day Ares** | 3/40 | **0/40** | **21/40** | 16/40 |

Only the constant-learner contrast **VOL5_XGB → ARMF_XGB** identifies a feature-budget effect. The **VOL5_RF → ARMF_XGB** comparison changes both features and learner and is a pipeline comparison only.

Zero-day Ares detail: `VOL5_XGB` ROC-AUC 0.4470 with 0/40 episodes; `ARMF_XGB` ROC-AUC 0.9713, PR-AUC 0.4570, 21/40 episodes, at a comparable false-positive rate (0.007187 against 0.012415). The ARM F reconstruction reproduces the published Phase 1 streams exactly on all five folds, which validates the rebuilt `distinct_payload_ratio`.

**Scientific reading.** The observed ceiling was **both** a family-transfer limit **and** a representational limit of the volume features. This corrects the Step 4 interpretation, which had attributed it to family novelty alone and left the representational question open. Neither budget dominates: ARM F wins zero-day transfer and loses where the family is known.

**Limits that must accompany any citation of these numbers.** 376 attack windows, 9 entities, 54 episodes; class imbalance 1:187.7; negatives exclusively from the parallel Monday capture, so day and capture confounding is not lifted; 172,372 `unknown` windows excluded and never counted as errors; C SSH statistically weak, eight of nine episodes being single-window; A′ unable to separate family from entity; the zero-day evidence resting on a **single** family whose five entities differ only by source IP against the same victim, transport and service; exact re-fitting of the historical P1 run impossible because its training row order was never specified nor persisted. No generalisation to real traffic is demonstrated.

---

## Identity ledger

All values are SHA-256 unless noted.

### Frozen upstream chain

| Item | Value |
|---|---|
| M1 dataset manifest | `feab8d4fbd8454cd12723368704e1e7311853a4316efec7f94bf11726ebb984e` |
| M2 replay specification | `e52c183a315c1ac38cbf1e64155489f5f041e95aa5d2e5cbb82e31f03ac4c455` |
| M2 tree fingerprint (95 files) | `22df7f5a0e3b1ff42b0dad45090fce3647fc1640013401b806d416da5656fcb5` |
| M3 v1 protocol | `99ab724a3d245a352e888e2f4771b5a354b5855180af4a72c36980c9296897d4` |
| M3 v2 protocol (authoritative) | `5286ddde937ad132afdeb8814e0e0af01745afbb7d1d446ae8860b7701fea210` |
| M3 v2 UUID5 namespace | `f7dad188-04cb-5859-81a0-014329de2899` |

Pre-repair M3 v2 identity `617298f5…` is audit history only.

### Supervised experiment identities

| Item | Value |
|---|---|
| P1 frozen population `p1_dataset.csv` | `e95aed008d994510e4c649c287feb8fe8f49a785bec144d7e83aa15804b6c062` |
| P1 frozen folds `p1_folds.json` | `57e688fd3da90911707d7a172c161686d852094121eda1ac49e0221fc0529fa1` |
| Four-arm A–D benchmark manifest | `2b6e65e658297dd1d96d3f4d3afce9798a5cf9e99279a70253dbbb022315af88` |
| Phase 2 ARM F tuning pre-registration | `623e7521ecfefc7f60533f9e187c0880ae08295e22f4a21178e6a557f39c7ca6` |
| Phase 2 ARM F tuning manifest file | `78d40ab46f86c415eab723eefb53fee60b4a1d7ca5f9fa29191de6afd4d45490` |

Phase 2 tuning used only `fold0.train` (zero Ares) with four internal leave-one-known-family-out validations. `fold0.test` was opened once after selection. R006 improved the known-family surrogate objective but did not improve Ares episode recall at the registered 0.5% point (17/40 for both Phase 1 and R006); see `artifacts/reports/xgboost_armf_tuning_final_report.md`.

### M3 v2 published run — `artifacts/reports/m3_v2_normalization_run.json`

| Item | Value |
|---|---|
| Report file SHA-256 | `62426406249a96eb991a0c6bdcde78cd0b730afaa7de057d7740c2d5f62a8032` |
| Report content SHA-256 | `6c9ef7aa545769d0e4b913b1227dc27f43ab1734227f9afeb8d1d642264848e0` |
| Canonical event stream SHA-256 | `ce71a3401f606ecedac11007fdd9d649d32d10b969c53e961db6b96710b1d82f` |
| Rejection audit stream SHA-256 | `b443b14c9894ea342b199e9c9880360a9cf3d00cf490164e7d2cf2f2d2f09b5f` |
| Processed / accepted / rejected | 1,380,057 / 1,353,467 / 26,590 |

### M4 published run — `artifacts/reports/m4_v2_materialization_run.json`

| Item | Value |
|---|---|
| `run_id` | `b1bd37dd-28ce-47e7-b8a0-4205d3062394` |
| Report file SHA-256 | `6b4252a12c3de76935c49a15a5bfb849769ffdcb8ed7090358cd4457ec2d28e0` |
| Report content SHA-256 | `70b4317f6619da00c6c9dc961dd37187da7afd3a4831e290efc35d6b85701433` |
| Persisted `FlowEndV2` events | **1,353,467** in `m4_canonical.flow_end_events` |
| Materialized stream digests | Reproduce the frozen M3 v2 values exactly |

### M6 published run — `artifacts/reports/m6_v2_feature_window_run.json`

| Item | Value |
|---|---|
| M6 protocol SHA-256 | `09e0f97797fd9b435c7d06427d18460281eac37b2adcab25f5bef554f106d277` |
| M6 UUID5 namespace | `f787c08a-290e-5b79-a8cb-5bc19ae633dc` |
| `run_id` | `0d3a12c8-61fc-414c-a418-5ffecf4ad048` |
| Report file SHA-256 | `273cd64335cc53004129515414afb43721e2c249dc12fe2697967ab379724045` |
| Report content SHA-256 | `ee6bbf2afb2e42e61c8ab2bdfe5bc0a8b47c052e3cc2f761d22a0f035d7aced4` |
| Window stream SHA-256 | `530c8363784f5ac84d612080b3e93b9261a0cebd651cb4feab85a4dd3b625bfa` |
| Windows materialized | **172,748** in `m6_canonical.feature_windows` |
| Lineage rows | **1,353,467** in `m6_canonical.feature_window_sources` |

Per-partition window-stream digests:

| Partition | Windows | Digest |
|---|---|---|
| `2017-07-04_Tuesday-WorkingHours` | 59,824 | `354915d7fb6920994e614fa03c36c39878a98222e50e0497b790e2776a4b9b0f` |
| `2017-07-05_Wednesday-workingHours` | 58,514 | `6579e86ae9d6dc3b36553824cfc79b93f00b420f692dc0855fc18a68eeed2660` |
| `2017-07-07_Friday-WorkingHours` | 54,410 | `c115abb61b216ccd8e9d1c0f35ef98edfcc3d2bfb40d1dd22ec91872ba922beb` |

### M5 label policy

| Item | Value |
|---|---|
| M5 v1 manifest hash (frozen) | `7ff2e52bf3485929b6a4260a7f4451fbaa8119273500f0b9a27f5a1c5b48c676` |
| M5 v2 manifest hash (additive, derived) | `9ebfbb1c393e499f929994fb6da69de1c7acf8dcae565db2c6b2cc497f451c5d` |
| M5 v1 / v2 `rule_version` | `1.0.0` / `2.0.0` |

### MB1 Monday Benign freeze (VERIFIED 2026-08-13)

| Item | Value |
|---|---|
| Monday PCAP **SHA-256** | `f6eac599358f216b074338813a1cf7be3cc4e91d116e13efc0dc71f2cca11972` |
| Monday PCAP size | 10,822,507,416 bytes (10.08 GiB) |
| MB1 manifest `content_sha256` | `d56fd5261b0a42917f7fee5a447f2fa8429a12ac8d0456e1f32d7d5ac8b66a6e` |
| MB1 manifest file SHA-256 | `9858d2d18fb5e18033beed767462b3ed9accdbba978078eef9dfa6d27f04bf7c` |
| MB1 verification report `content_sha256` | `dcf7acdd990659d754402d2036549523aafd3ce130bf51176423bb5168c22956` |
| MB1 verification report file SHA-256 | `ad28c8a12a81011ddd47e59559e2ddff7096be37f60c5a4a7a1934ab5ed5bc13` |
| MB1 manifest path | `datasets/manifests/monday_benign_pcap_freeze.yaml` |
| MB1 report path | `artifacts/canonical/cicids2017/mb1/dataset_freeze_verification.json` |
| `frozen_at` | `2026-08-13T12:19:23.073762Z` |
| `retrieved_at` | `2026-07-28T13:08:25.402744Z` — same publisher-gate session as M1 |

The MB1 manifest `content_sha256` `d56fd526…` is the value the MB2 specification must carry in `m1_manifest_sha256`.

### MB2 published replay (VERIFIED 2026-08-13)

| Item | Value |
|---|---|
| MB2 specification `content_sha256` | `6de09b2fa740fc7b3075e91abfbf056a89f938c43163d1cedf8d27dd28d6e38f` |
| MB2 specification file SHA-256 | `a0863a5e46200c8a85504605c43dfbea996a5b0d991147e3002aa6676dc261bf` |
| MB2 report `content_sha256` | `966ffc228f79c069c52f31baab814355ed28dce0d84f402906cc4857daae62db` |
| MB2 report file SHA-256 | `72776b110b6fb726d17a0b934592ac6e1013d6d39150cb11c7c5a4d803d22aa8` |
| MB2 tree inventory digest (31 files) | `503ef3eef69b5ca262f69e9e87bb9b14652aaf2882c2831aa768c3ba01c931e8` |
| Partition | `2017-07-03_Monday-WorkingHours` |
| `conn.log` SHA-256 | `358f337b9df3bafeb0da800ab228fd7d1118ccb283f7ae4db4f1d67025f44f4f` |
| `conn.log` records / bytes | **375,432** / 151,704,205 |
| Logs published | 30 (27 canonical telemetry, 3 operational runtime) + `replay_run.json` |
| MB2 tree total bytes | 508,773,282 |
| Zeek image digest | `sha256:c7dfad9ab8296b2994d113222e77a22ebc9c8963b2b1200b798484ac923bc94f` — identical to M2 |
| Compose service / profile used | `zeek-replay-mb` / `zeek-replay-mb` |
| Wall clock | 764 s (12 min 44 s) |

`replay_run.json` carries `input.sha256 = f6eac599…`, identical to the MB1 frozen evidence, so the MB1 → MB2 binding is provable from the published artifact alone. `m1_manifest_sha256 = d56fd526…` matches MB1. The report `content_sha256` was recomputed from disk after publication and reproduced exactly.

### MB3 published normalization (VERIFIED 2026-08-13)

| Item | Value |
|---|---|
| MB3 protocol `content_sha256` | `ea16017266042cc95bd36fcddbc34c917f7b66e3b98e9bed1c478be301810c7c` |
| MB3 protocol file SHA-256 | `ef3d44049a41e6a6bd60bf228042d0b1d30484a6d71bd944c09d0699ef036c10` |
| MB3 **UUID5 namespace** | `c81ae3e0-7738-5413-80f2-8c2755418232` |
| Namespace derivation | `uuid5(NAMESPACE_URL, "https://cybersentinel.invalid/mb3/monday-benign/exact-time-normalization/2.0.0")` |
| MB3 report `content_sha256` | `de3146976148dc1d61e5690d6eb7b6acc6a446130787964d3b1bb4888c5ec6ab` |
| MB3 report file SHA-256 | `5afd957ee2e41d18ac604426759afe775f4eaccd84d6ff453dec162ea0d5aff9` |
| Canonical event stream SHA-256 | `ed558ab37f984960816c2370fc3046a0c8d1d2bfbdd4dc353f7a6fbf95c7706a` |
| Rejection audit stream SHA-256 | `13e7538cc71a8492189e01aa4ad1ef1f29d16476cd82a3171156175d46f06342` |
| Processed / accepted / rejected | **375,432 / 368,202 / 7,230** (98.074% acceptance) |
| First / last accepted `event_id` | `ccd1c0c7-49aa-579b-9d2e-6c73c47ca522` / `3963129e-fb7d-5c07-a1ac-2e7b02d73313` |
| Protocol path | `datasets/manifests/monday_benign_zeek_normalization.yaml` |
| Report path | `artifacts/reports/mb3_monday_benign_normalization_run.json` |
| `record_available_time` | `1786625789.3422550000000000000000` — the MB2 replay `completed_at` |
| Wall clock | 46.6 s |

**The MB3 namespace is provably distinct from both M chain namespaces**: `c81ae3e0…` ≠ M3 v2 `f7dad188-04cb-5859-81a0-014329de2899` ≠ M6 `f787c08a-290e-5b79-a8cb-5bc19ae633dc`. The contract raises on either M-chain value and additionally re-derives the namespace from its declared derivation string, so a mismatched pair cannot validate.

### MB4 published materialization (VERIFIED 2026-08-13)

| Item | Value |
|---|---|
| `run_id` | `b043c624-c000-4037-b9c8-100a590ad97e` |
| MB4 report `content_sha256` | `27896bbbc49940c2c245bc3aac2062cd6d5d78304c009008c1741313f1061034` |
| MB4 report file SHA-256 | `52aec252884bdb902464fd1ed7aa06e8a645501c2a2c7c424b4af9b95285cf81` |
| Report path | `artifacts/reports/mb4_monday_benign_materialization_run.json` |
| Target database | **`cybersentinel_test`** |
| Target schema | `mb4_canonical` |
| Persisted events | **368,202** in `mb4_canonical.flow_end_events` |
| Persisted rejection spans / count rows | 3,580 / 3 |
| Recomputed event stream digest | `ed558ab3…` — **equals** the frozen MB3 value |
| Recomputed rejection digest | `13e7538c…` — **equals** the frozen MB3 value |
| Wall clock | 91.8 s |

> **MB4 lives in `cybersentinel_test`, not `cybersentinel`.** This was an explicit owner instruction and it has two consequences a future agent must know. First, the eventual ML dataset needs `m6_canonical` and `mb6_canonical` reachable from one connection, so an MB re-materialization into `cybersentinel` will be required before dataset construction; MB4 is fully deterministic from the MB3 artifacts, so this costs one re-run and loses nothing. Second, `cybersentinel_test` is the database used for destructive test isolation — **the MB4 test suite is therefore strictly read-only against PostgreSQL**, and every future MB test must stay that way. A `DELETE` there would repeat the M4 data-loss incident.

### MB6 published feature windows (VERIFIED 2026-08-13)

| Item | Value |
|---|---|
| MB6 protocol `content_sha256` | `93804dc23f52e92d94bdfe286b029f3d2b52037efccd5a139187f9218036c22e` |
| MB6 protocol file SHA-256 | `a6b2a912ccc7fa7b407f53f5644c0ed08aff0e616d48878f387d651d4d45ef72` |
| MB6 **UUID5 namespace** | `5cd6a350-cf38-5b3a-ab35-9b5128cdede3` |
| Namespace derivation | `uuid5(NAMESPACE_URL, "https://cybersentinel.invalid/mb6/monday-benign/feature-window/2.0.0")` |
| `run_id` (**deterministic**) | `55b0f291-e321-5d41-8bdd-50a257581480` |
| `run_id` derivation | `uuid5(MB6_NS, "mb6-run\|" + protocol_sha256 + "\|" + mb4_run_id)` |
| MB6 report `content_sha256` | `a9600fcd64112e041b86e478f6bd5b9a96a2a8d40f881106d9729488d7371bb7` |
| MB6 report file SHA-256 | `2f8bcde806cfe5c655f67efe82fa8875602eb582bd7e5a54d891178262e84219` |
| Window stream SHA-256 | `e1efc5fca09c9763a4939b485456461ef362faa93bf2330cb69fd201c86cedd2` |
| Windows / source events / lineage rows | **70,921 / 368,202 / 368,202** |
| Distinct entities | **27,788** |
| First / last `window_id` | `a6792e05-8f3c-53a5-953b-7516bd5052ee` / `02f9d964-abe0-5220-afb3-1e97511ec429` |
| Target database / schema | `cybersentinel_test` / `mb6_canonical` |
| Operational source | `mb4_canonical.flow_end_events` |

**MB6 is more deterministic than M6.** M6 declared `run_identity_algorithm = "uuid4_at_execution"`, which is why the M6 report digest is knowingly irreproducible. MB6 forbids randomness: `run_id` is `uuid5` over the protocol hash and the MB4 run identity, and wall-clock fields stay outside `content_sha256` under the rule ratified for MB2. A full `--recompute-only` reproduced **every** value including `report_content_sha256`.

**Window-identity derivation**, reusing the frozen M6 formula through `FeatureWindowBuilderV2` unchanged:

```
window_id = uuid5(MB6_NS, "|".join([
    protocol_sha256, output_partition, entity_type,
    *entity_key,                      # source_ip, destination_ip, transport, service
    window_start_time, window_length_seconds,
]))
```

### MB-LABEL published labeling (VERIFIED 2026-08-13)

| Item | Value |
|---|---|
| MB7 protocol `content_sha256` | `775c50454b851681e5e25655eee3530db8ff9c010804eb50cf778cf9180f3df9` |
| MB7 protocol file SHA-256 | `b989058c0e9a68513fa05d9689b61486bd4f7d0d2a44361ab824d40ca6f13909` |
| MB7 **UUID5 namespace** | `1cef710b-751b-584e-b361-d264c8a70eeb` |
| `run_id` (**deterministic**) | `c756da09-3a58-54e8-97e3-34645b87f064` |
| MB7 report `content_sha256` | `5457b98749dca166470a8435502485305ef8228651f8ae79e45a4d33238aef5b` |
| MB7 report file SHA-256 | `76d0fe7a97519175beaa2a649f127329bd3eea88f227cec856d3a5ef65947056` |
| Event label stream SHA-256 | `da43a8e4c50cf2888736ea8dba62450fe95d5aca548c288614d306c5fbff8a7f` |
| Window label stream SHA-256 | `a8cc4a5a4994a93178e89196a6015eecd9ec429ecdf394948343792cd23a2dce` |
| M5 policy applied | **v1 unchanged**, manifest `7ff2e52bf3485929b6a4260a7f4451fbaa8119273500f0b9a27f5a1c5b48c676` |
| Monday rule hash | `092756ab0def352e64889c19672905146f01f052bc10df6f2da2f4420e12ee09` |
| Target database / schema | `cybersentinel_test` / `mb7_canonical` |

**Event labels — 368,202**: `benign_reference` 367,171 · `unknown` 813 · `ambiguous` 218 · attack **0**.

**Window labels — 70,921**: `benign_reference` 70,578 · `unknown` 216 · `ambiguous` 127 · attack **0**.

**Interval partition**: inside `[12:00:00Z, 20:01:00Z)` = 70,697 (70,578 benign + 119 ambiguous); outside = 224 (216 unknown + 8 ambiguous), of which 198 before the opening and 26 after the close.

> **Correction of the MB-LABEL preflight.** The preflight predicted 70,697 `benign_reference` and 224 `unknown`. Measurement falsified the **disposition** split while confirming the **temporal** partition exactly. Cause: 218 events carry the frozen M5 reason `"event interval crosses a matched schedule boundary"` — long-lived Monday flows whose exact interval straddles a rule bound — and `LabelLedger` maps a `partial` overlap to `ambiguous` before any other consideration. The preflight had reasoned only at window level. `ambiguous` was ratified as a first-class disposition on 2026-08-13; **M5 v1 was not modified**, and no `unknown` or `ambiguous` was ever promoted to `benign_reference`. Three artefacts had to be corrected because they encoded the falsified assumption: the MB7 DDL, the run-report contract, and the runner assertions.

### P1/A supervised benchmark (EXECUTED / VERIFIED 2026-08-17)

| Item | Value |
|---|---|
Dataset content SHA-256 | `3d7436178da6960ee5effeb4bee85a0b6da5eead9d2babef3c72cb6b7ca9f20d` |
Folds content SHA-256 | `e463ea7b0eb4985f51369dc3ae19c09821040675aa4b9f9689f8e02545fed95a` |
`p1_dataset.csv` | `e95aed008d994510e4c649c287feb8fe8f49a785bec144d7e83aa15804b6c062` |
`p1_folds.json` | `57e688fd3da90911707d7a172c161686d852094121eda1ac49e0221fc0529fa1` |
`p1_leakage_verification.json` | `9581b38af679ac4a0d89b9c8f69a2049bef4ad067613028415e8e585441f3b1e` |
`p1_metrics.json` | `2a51e618397c42b742a289216d3cd89b255c4ccd96a8f985a5ad1c5c4783a447` |
Population | 376 positives (9 entities, **54 episodes**) + 70 578 negatives, 1:187.7 |
Leakage failures | **0** across all five folds |
PostgreSQL writes | **0** — dataset materialised as files |

**Results per attack type**, thresholds calibrated on training negatives only at 1% target FPR:

| Held-out type | ROC-AUC | PR-AUC | Window recall | **Episode recall** | 95% CI |
|---|---|---|---|---|---|
`botnet/ares` (177 win, 40 ep) | **0.5037** | **0.0135** | 0.017 | **0.075** | [0.000, 0.175] |
`brute_force/ftp_patator` (61, 1) | 0.9866 | 0.3007 | 0.984 | 1.000 | [1.000, 1.000] |
`brute_force/ssh_patator` (60, 9) | 0.9279 | 0.3541 | 0.867 | **0.111** | [0.000, 0.333] |
`ddos/loit` (42, 2) | 0.9972 | 0.5919 | 1.000 | 1.000 | [1.000, 1.000] |
`dos/hulk` (36, 2) | 0.8842 | 0.5552 | 0.778 | 1.000 | [1.000, 1.000] |

**Pooled episode recall 0.167, 95% CI [0.074, 0.278] over 54 episodes.**

Three findings recorded in `artifacts/experiments/p1/P1_REPORT.md`:

1. **The botnet blindness was predicted arithmetically and observed exactly.** `botnet/ares` density is 4.158 events per window against 5.202 for the benign class; ROC-AUC came out at **0.5037**, chance level. This concerns 47.1% of all positives and is a property of the five-feature volume budget, not of the protocol.
2. **Window recall systematically overstates detection.** `ssh_patator` shows window recall 0.867 but episode recall 0.111 — one large episode detected, eight small ones missed. Reporting window recall alone would have claimed 87% where the operational figure is 11%.
3. **The default 0.5 threshold is unusable** without class weighting: recall 0.000 for three of five types.

> **A methodological defect was found and corrected during this run.** The first execution produced `observed_test_fpr = 1.0` on four folds and a pooled bootstrap of 1.0 [1.0, 1.0]. Cause: with `class_weight=None` at 1:187.7 the forest scores almost every training negative at exactly 0.0, so `quantile(0.99)` is 0.0 and `score >= 0.0` flags everything. The threshold selector now picks the smallest observed-score candidate achieving the target rate and reports the achieved rate. The defective `p1_metrics.json` (`c052b81d…`) was deleted and republished; dataset, folds, predictions and models were unaffected. `test_threshold_handles_a_degenerate_score_distribution` guards it.

### External evidence

| Item | Value |
|---|---|
| Monday PCAP official MD5 | `8525733283c2c5f98891a0dca036e7c7` (**VERIFIED** — computed MD5 matches) |

### MB2 routing infrastructure (VERIFIED 2026-08-11)

| Item | Value |
|---|---|
| `docker-compose.yml` SHA-256 **before** | `3344f6828c7b1d87b673cbeeddcfae05695c89f1fb824f0470dd807fbfe1928e` |
| `docker-compose.yml` SHA-256 **after** | `58a3bb94616cb89bf203805914fbe9fd68a4dbf6f3859c80b528e9977eb0c623` |
| Zeek image digest (M2 **and** MB2, identical) | `sha256:c7dfad9ab8296b2994d113222e77a22ebc9c8963b2b1200b798484ac923bc94f` |
| M2 tree inventory digest (95 files) | `fc3b3c686fab98dd2d9d7f9177f8ac29538d015e9034a218c4f845863b3c0dee` |

The M2 tree inventory digest is a reproducible integrity measure computed for this step: SHA-256 over the newline-joined, path-sorted list of `relative_path:sha256` for every file under `artifacts/canonical/cicids2017/m2/zeek-8.0.9/`. It was computed **before** and **after** the compose change and was **identical**, proving the frozen M2 tree was untouched. It is distinct from, and complementary to, the published M2 tree fingerprint `22df7f5a…`.

---

## Architectural boundary (current, all DONE)

```text
Frozen M1 PCAP evidence (3 partitions)
        ↓
Frozen M2 conn.log + replay_run.json
        ↓
StrictZeekJsonLineParserV2 (private submodule)
        ↓ raw sensor record or explicit rejection
StrictZeekConnFlowEndNormalizerV2 (private submodule)
        ↓ FlowEndV2 or explicit rejection
ZeekConnNormalizationRunnerV2 (private submodule)          [M3 v2]
        ↓ deterministic streaming → report construction
ZeekNormalizationRunReportV2 (published immutable artifact)
        ↓
ZeekConnMaterializationAdapterV2 → m4_canonical            [M4]
        ↓ 1,353,467 FlowEndV2 events persisted
M4MaterializationReportV2 (published immutable artifact)
        ↓
FeatureWindowBuilderV2 → m6_canonical                      [M6]
        ↓ 172,748 FeatureWindowV2, 60 s tumbling, [start,end)
FeatureWindowRunReportV2 (published immutable artifact)
        ↓
Label materialization — DONE, out of band as files (no m7_* schema)
        ↓
ML dataset — DONE, Production Finale v1 (70,954 rows)
        ↓
Final scientific validation — DONE, five additive steps
```

Sidecar, never merged into the window contract:

```text
M5 v1 LabelLedger (frozen policy)
        ↓ ExactTimeLabelAdapterV2  (additive exact-time adapter)
        ↓ M5 v2 policy             (additive attacker realignment)
EventLabel — joined to events by event_id VALUE only
```

---

## M6 — canonical feature windows (DONE, FROZEN)

Frozen manifest: `datasets/manifests/cicids2017_feature_window_v2.yaml`.

Authorized and frozen semantics:

| Decision | Value |
|---|---|
| Window type | Tumbling, length = slide = **60 seconds exact** |
| Boundaries | Half-open `[start, end)` |
| Temporal basis | `event_start_time` |
| Temporal representation | `ExactDecimalSeconds22` / `NUMERIC(38,22)`, unscaled-integer arithmetic only |
| `prediction_time` | Equals `window_end_time` |
| `record_available_time` | Inherited from source events |
| Entity type | `source_destination_service` only |
| `entity_key` | Ordered 4-tuple: `source_ip`, `destination_ip`, `transport`, `service` |
| Null service sentinel | `"none"` (collision-free **for this snapshot only**) |
| Partition policy | Strictly intra-partition; never crosses the Tue/Wed/Fri gaps |
| Empty windows | Forbidden |
| Canonical order | `(output_partition, entity_type, entity_key, window_start_time)` |
| Identity | UUID5; `window_id` is the text form of `provenance.event_id` |
| Labels in windows | **Forbidden** — enforced by a test |
| Watermark / late arrival | Explicitly **deferred**, not introduced by M6 |

The eight authorized features (exactly these, no more, no fewer):

`event_count`, `source_packets_total`, `destination_packets_total`, `source_bytes_total`, `destination_bytes_total`, `distinct_destination_ports`, `distinct_destination_ips`, `distinct_source_ips`

**VERIFIED observations about the feature set** (documented, deliberately not changed):

- `distinct_source_ips` and `distinct_destination_ips` are **constant 1.0 across all 172,748 windows** — mathematically inevitable because both IPs are part of the entity key. They carry no information.
- `distinct_destination_ports` is nearly degenerate: 1.0 in 393 of 398 sampled windows.
- Strong multicollinearity: `corr(source_packets_total, destination_packets_total) = 0.9972`; `corr(source_packets_total, destination_bytes_total) = 0.9916`; `corr(destination_packets_total, destination_bytes_total) = 0.9945`.
- 58.59% of windows contain exactly one event (101,209 of 172,748).
- 39.28% of rows are duplicate feature vectors (104,894 distinct vectors for 172,748 rows).
- Distributions are extremely skewed (`source_bytes_total` median 1,027, max 103,794,239,489).

These are modelling characteristics to be handled **downstream**, never by modifying M6.

---

## M5 v2 — observable-attacker policy (DONE, additive)

### Files

| File | Status |
|---|---|
| `modules/detection/src/lineage/m5_policy_v2.py` | **Created** |
| `modules/detection/tests/test_m5_policy_v2.py` | **Created** — **27 contractual tests passed** |
| `modules/detection/src/lineage/exact_time_labeling_v2.py` | Created earlier — **34 tests passed** |
| `modules/detection/tests/test_m7_exact_time_labeling.py` | Created earlier |

M5 v1 (`datasets/manifests/cicids2017_labels.yaml`, `lineage/labeling.py`, `LabelLedger`) is **untouched**.

### Why it exists

M5 v1 names the *logical* CICIDS2017 attacker addresses (`205.174.165.x`). The M2 replay captured traffic from a vantage point behind network address translation, so in M4 every attack flow originates from the gateway identity `172.16.0.1`. **VERIFIED**: `205.174.165.73` appears **0 times as a source** in M4 (4,805 times as a destination); `205.174.165.69/70/71` appear **nowhere**.

### What changed

The v2 manifest is **derived programmatically** from the frozen v1 manifest — no timestamp is retyped. Exactly one thing changes, on four rules only:

`attacker_ips` → `('172.16.0.1',)` for `tuesday-ftp-patator`, `tuesday-ssh-patator`, `wednesday-hulk`, `friday-ddos-loit`.

One consequence is **forced by the frozen contract**, not chosen: `EndpointSelector` requires attacker and victim role sets to be disjoint, so `172.16.0.1` is removed from those four rules' victim sets. All other victims are preserved. Intervals, ports, protocols, families, subtypes, target profiles, dispositions, ontology, timezone and defaults are **unchanged**, verified rule by rule. The other 12 rules are **byte-identical** to v1.

`172.16.0.1` is declared **attacker**, never victim. Direction stays consistent with the M4 vantage point: source = attacker, destination = victim.

### Quantitative result (VERIFIED, read-only preview over all 1,353,467 events)

| Metric | v1 | v2 |
|---|---|---|
| `target_attack` events | 0 | **260,783** |
| `known_other_attack` events | 736 | 736 |
| `ambiguous` events | 0 | 164 |
| `unknown` events | 1,352,731 | 1,091,784 |
| `benign_reference` events | **0** | **0** |
| Event attack rate | 0.0544% | **19.3222%** |
| Events changing disposition | — | **260,947** |
| **Attack windows (ANY_ATTACK)** | **177** | **376** |

Matched events per rule: `wednesday-hulk` 158,781 · `friday-ddos-loit` 95,683 · `tuesday-ftp-patator` 3,972 · `tuesday-ssh-patator` 2,511 · `friday-botnet-ares` 736 (unchanged rule). All realigned matches come 100% from `172.16.0.1` → `192.168.10.50` on the declared ports.

### Safety guarantees (VERIFIED)

- No label field added to M6 — `FeatureWindowV2` carries none.
- No `m7_*` schema created.
- No `UPDATE` / `DELETE` / DDL executed; the preview ran with `default_transaction_read_only = on`.
- M4 (1,353,467 events) and M6 (172,748 windows) unchanged.
- Labels are **not materialized** anywhere.

### Aggregation rule — `ANY_ATTACK` (authorized, frozen)

Applied to the set of dispositions present in a window, highest precedence first:

| Present in window | Window disposition |
|---|---|
| any `target_attack` | `target_attack` |
| any `known_other_attack` (no target) | `known_other_attack` |
| any `ambiguous` (no attack) | `ambiguous` |
| any `unknown` (no attack, no ambiguous) | `unknown` |
| only `benign_reference` | `benign_reference` |

An attack anywhere makes the window an attack. **`unknown` and `ambiguous` are never silently converted to benign.**

### Three known anomalies

1. **`ambiguous` explains the matched-vs-family gap.** `wednesday-hulk` matches 158,781 events but family `dos/hulk` counts 158,648 (gap 133); `ssh_patator` 2,511 vs 2,501 (gap 10); `ftp_patator` 3,972 vs 3,951 (gap 21). Total 164 — exactly the `ambiguous` count. These events straddle an interval boundary and M5 then clears the family. **Conforming v1 behaviour, not a defect.**
2. **`benign_reference` remains 0.** The only benign rule targets Monday 2017-07-03, a day not present in M1/M2/M4. M5 v2 corrects only the network-identity cause; the missing-negative-class cause is untouched.
3. **Attack events are highly concentrated.** Despite 19.32% of events being attacks, only 376 of 172,748 windows (0.218%) are attacks, ratio `(unknown+ambiguous):attack` = **458 : 1**. Cause: 158,781 Hulk events fall inside roughly 18 minutes.

---

## Monday Benign discovery (VERIFIED, frozen as MB1)

### The data exists and is valid

| Item | Value |
|---|---|
| Path | `datasets/cicids2017/pcap/Monday-WorkingHours.pcap` |
| Size | **10,822,507,416 bytes** (10.08 GiB) |
| Official MD5 | `8525733283c2c5f98891a0dca036e7c7` |
| Computed MD5 | **Matches exactly** |
| Computed SHA-256 | `f6eac599358f216b074338813a1cf7be3cc4e91d116e13efc0dc71f2cca11972` — measured by MB1 on 2026-08-13 |
| Official CSV | `datasets/cicids2017/Monday-WorkingHours.pcap_ISCX.csv` (176,927,918 bytes) |
| CSV rows | **529,918** |
| CSV labels | **All 529,918 rows labelled `BENIGN`** — zero exceptions |

The Thursday PCAP is also present (`Thursday-WorkingHours.pcap`, 7.73 GiB, declared MD5 `043d37cd08de4e165a5498d0d6564a65`), **not verified**.

### M5 already covers Monday

| Item | Value |
|---|---|
| Rule | `monday-benign-reference` |
| Disposition | `benign_reference` |
| Selector mode | **`any_network`** |
| Local window | 2017-07-03 09:00:00 → 17:00:00 (end inclusive) |
| Compiled UTC window | **2017-07-03 12:00:00Z → 20:01:00Z** |
| Attacker / victim IPs required | **None** |
| 2017-07-03 | Confirmed **Monday** |

Because the selector is `any_network`, **the M5 v2 attacker-IP correction is irrelevant to this rule.** It will match as soon as Monday data exists.

---

## The actual blocker — it is NOT missing data

The Monday data is present, intact, and semantically ideal. **The blocker is that the canonical M1→M2→M3 v2→M4→M6 chain is frozen around exactly three partitions.**

Seven hard-coded constraints, **VERIFIED** by inspection:

| # | Location | Constraint |
|---|---|---|
| 1 | `scripts/freeze_cicids2017_pcaps.py` | `APPROVED_CAPTURE_DATES = {2017-07-04, 2017-07-05, 2017-07-07}`; raises for any other date |
| 2 | `modules/detection/src/schemas/zeek_normalization.py` | `len(replay_reports) != 3 → raise` |
| 3 | `modules/detection/src/schemas/zeek_normalization_v2.py` | `len(replay_reports) != 3 → raise` |
| 4 | `modules/detection/src/schemas/zeek_normalization_run_v2.py` | `len(partition_reports) != 3 → raise` |
| 5 | `modules/detection/src/persistence/run_report_v2.py` | `len(partition_counts) != 3 → raise` |
| 6 | `modules/detection/src/schemas/feature_window_protocol_v2.py` | `len(partition_reports) != 3 → raise` |
| 7 | `modules/detection/src/lineage/feature_window_v2.py` | requires `len(partition_order) == 3` |

Constraint **#3** lives in the contract whose content produces `protocol_sha256 = 5286ddde…`. Changing that validator would change the M3 v2 protocol identity, invalidate the published M3 v2 report, therefore the M4 binding, therefore the M6 binding — a **complete cascade through the frozen identity chain**.

> ### 🚫 RULE
> **Never modify the existing canonical M1–M6 chain just to add Monday.**

---

## Monday Benign track (MB) — MB1 through MB-LABEL VERIFIED; ML dataset PUBLISHED as Production Finale v1

### Approved direction

A **strictly parallel canonical track**, sharing no identity with the M chain.

```text
Monday PCAP
    ↓
MB1 — evidence freeze
    ↓
MB2 — Zeek replay
    ↓
MB3 — exact-time normalization
    ↓
MB4 — canonical persistence
    ↓
MB6 — 60-second tumbling windows
    ↓
MB-LABEL — benign_reference
```

### Mandatory isolation properties

The MB track must have:

- its own manifests;
- its own hashes;
- its own reports;
- its own UUID namespaces;
- its own PostgreSQL schemas;
- **no foreign keys into `m4_canonical` / `m6_canonical`**;
- **no modification of M1–M6**;
- **no reuse of the M3 v2 or M6 UUID namespaces.**

The **only** convergence point is the future ML dataset, through read-only selection from both tracks.

### MB1 Monday Benign freeze — IMPLEMENTED / VERIFIED (2026-08-13)

**No new contract was needed.** `lineage/dataset_freeze.py` imposes no date restriction; the Monday exclusion lives only in `scripts/freeze_cicids2017_pcaps.py` via `APPROVED_CAPTURE_DATES`, which is untouched. MB1 is therefore a **new script reusing every M1 primitive unmodified**: `inventory_pcap_evidence`, `build_dataset_freeze_manifest`, `verify_dataset_freeze`, `build_dataset_verification_report`, `write_immutable_dataset_manifest`, `write_immutable_verification_report`.

| File | Role | SHA-256 |
|---|---|---|
| `scripts/freeze_monday_benign_pcap.py` | MB1 entrypoint, Monday-only scope guard | `e368d22737f18410f4ddd88e452dfb82dd23ff0fcdef9d48d3ed319156bfe736` |
| `modules/detection/tests/test_mb1_freeze.py` | 23 tests (22 passed, 1 skipped) | `4c3857c335eef9b784b8bc9b5d0640e60eb3b2095d5f38765cb99a8db2dd5f4a` |

The publish-then-reload-then-verify ordering of the M1 script is reproduced exactly, so the MB1 report is bound to the serialized repository bytes rather than to the in-memory manifest.

**Artifact convention.** The verification report is **JSON under `artifacts/canonical/cicids2017/mb1/`**, mirroring the existing `.../m1/dataset_freeze_verification.json`. `write_immutable_verification_report` emits JSON, so a `.yaml` report path would have produced a misnamed file; the established convention was followed instead of the initially proposed `datasets/manifests/..._verification.yaml`.

**Verified facts:**

- `selected_capture_days == ('2017-07-03',)`, exactly one file, `Monday-WorkingHours.pcap`;
- size 10,822,507,416 bytes and SHA-256 `f6eac599…` measured from the real capture, not declared;
- the freeze completed in **77.8 s** across three full SHA-256 passes over 10.08 GiB;
- **idempotence proven in production**: re-running with the same `frozen_at` reproduced identical manifest, report and PCAP digests with status `verified`;
- **immutability proven in production**: re-running with a different `frozen_at` raised `FileExistsError: immutable artifact already exists with different content`, and the published bytes survived unchanged;
- the four other captures under `datasets/cicids2017/pcap/` are **not consumed** — a test tracks every `Path.open` call and asserts none of them is ever opened;
- the Monday PCAP is opened **only** in mode `rb`, asserted by the same tracking test;
- PCAP bytes, size and `st_mtime_ns` are unchanged by a freeze.

### MB2 Docker routing — VERIFIED / READY (2026-08-11)

**Why this service exists.** `ZeekReplayRunner.replay()` computes the host staging directory from `specification.output.output_root`, while the container writes to `/output`, whose bind mount is fixed by `docker-compose.yml`. Before this step the repository had exactly **one** `/output` mount, pointing at the frozen M2 tree. Replaying Monday through it would have written roughly 31 new files into `artifacts/canonical/cicids2017/m2/zeek-8.0.9/`, taking the inventory from 95 files to about 126 and making the published M2 tree fingerprint `22df7f5a…` unverifiable. MB2 therefore required its own `/output` mount.

**Resolution.** An **additive** service `zeek-replay-mb` was added to `docker-compose.yml`. The M2 service `zeek-replay` was left unchanged.

| Property | `zeek-replay` (M2) | `zeek-replay-mb` (MB2) |
|---|---|---|
| `profiles` | `["zeek-replay"]` | `["zeek-replay-mb"]` — **different** |
| `/output` bind | `./artifacts/canonical/cicids2017/m2/zeek-8.0.9` | `./artifacts/canonical/cicids2017/mb2/zeek-8.0.9` — **different** |
| `/input` bind | `./datasets/cicids2017/pcap` read-only | identical, read-only |
| `image` | `zeek/zeek@sha256:c7dfad9a…c94f` | **identical digest** |
| `platform` | `linux/amd64` | identical |
| `network_mode` | `none` | identical |
| `read_only` | `true` | identical |
| `cap_drop` | `["ALL"]` | identical |
| `security_opt` | `no-new-privileges:true` | identical |
| `environment` | `TZ=UTC`, `LC_ALL=C`, `LANG=C` | identical |
| `working_dir` | `/output` | identical |
| `tmpfs` | `/tmp:rw,noexec,nosuid,size=64m` | identical |

Exactly **two of twelve** fields differ: `profiles` and the `/output` entry of `volumes`. Everything governing Zeek behaviour, determinism, and provenance is identical, so an MB2 report can legitimately carry the same `ZeekRuntimePin` as M2.

**Isolation, verified:**

- the M2 service is unchanged, confirmed by Docker's own resolver;
- the MB service is purely additive;
- profiles are **disjoint** — `--profile zeek-replay` cannot start the MB service and vice versa;
- `/output` roots are **distinct**, and **neither is an ancestor of the other**;
- `/input` is shared but **read-only in both** services;
- the frozen M2 tree still holds exactly **95 files**, inventory digest `fc3b3c686fab98dd2d9d7f9177f8ac29538d015e9034a218c4f845863b3c0dee`, identical before and after;
- `artifacts/canonical/cicids2017/mb2/` did not exist at the time of this routing step. It was created later by the real MB2 replay of 2026-08-13 and holds only the Monday partition; the M2 digest above was re-verified after that run and is unchanged.

**Repository change actually made.** The only repository file modified for this step is `docker-compose.yml`: **35 lines added, zero existing lines deleted or modified**, inserting the `zeek-replay-mb` service between the end of the `zeek-replay` block and the top-level `volumes:` section. Hashes are in the identity ledger above.

### MB2 contracts and runner — IMPLEMENTED (2026-08-13)

Three source files and one test file were created. **No MB2 artifact was published and no Zeek replay was executed.**

| File | Role | SHA-256 |
|---|---|---|
| `modules/detection/src/schemas/monday_benign_replay.py` | `MondayBenignReplaySpecification`, `MondayBenignReplayRunReport`, MB constants | `7c592bd4a1a0ea15df769c40d7ed8e93bbb1969a70e4f6486abeb1c6d39cabfd` |
| `modules/detection/src/lineage/monday_benign_replay.py` | MB2 YAML loader + MB1 binding | `ef68437aeb22828489815df91b651c8014b1d578f153d7d846360006f014043f` |
| `modules/detection/src/ingestion/monday_benign_replay.py` | `MondayBenignReplayRunner` | `c67ddb66e968615c4226c348b3410d8624284e31bc49980d7374b7d594ff00df` |
| `modules/detection/tests/test_mb2_replay.py` | 41 contractual tests | `913a085afad746d6f87f780e7de208f2efe84fd83aae16cfa6dd0ced0d938cc2` |

**Design decision — autonomous contract, not a subclass.** `ZeekReplaySpecification` is *not* cardinality-constrained and could have been reused directly. An autonomous `MondayBenignReplaySpecification` was written anyway, so that MB invariants are **unrepresentable rather than merely untested**: the output root must be exactly the MB2 tree, there must be exactly one input and it must be the Monday capture, the runtime pin must equal the M2 pin, and the bound manifest must be the MB1 manifest. Subclassing was rejected because Pydantic executes parent validators, which would have reintroduced the free-form `output_root`. Safe M2 primitives *are* reused unchanged: `PcapEvidenceFile`, `ZeekRuntimePin`, `ZeekDeterminismPolicy`, `ZeekOutputPolicy`, `ZeekLogArtifact`, `ZeekLogName`, `Sha256Digest`, `RepositoryRelativePath`.

**Runner reuse boundary.** `MondayBenignReplayRunner` **subclasses** `ZeekReplayRunner`, which is left unmodified, and inherits the already-verified generic logic: input selection, PCAP size/SHA-256 verification, staging creation, Zeek log validation, operational-log retention, and atomic publication by directory rename. It overrides exactly three things:

- `_compose_command` — always `--profile zeek-replay-mb` and service `zeek-replay-mb`, with a defensive assertion that the string `zeek-replay` never appears as a command element;
- `replay` — publishes a `MondayBenignReplayRunReport` instead of a `ZeekReplayRunReport`;
- `_evidence` — re-raises as `MondayBenignReplayError` so the MB track surfaces a single error type.

**Risk R10 is now enforced in code, not only documented.** `_verify_compose_pairing()` parses `docker-compose.yml` before any execution and refuses to run unless: the `zeek-replay-mb` service exists, it declares the `zeek-replay-mb` profile, it has exactly one `/output` bind mount whose host path equals the specification's `output_root`, that host path is not inside the frozen M2 tree, and its single `/input` mount is read-only. Any mismatch raises `MondayBenignReplayError` before the container is invoked.

**Report contents.** `MondayBenignReplayRunReport` carries `specification_sha256`, `m1_manifest_sha256`, the full `ZeekRuntimePin` (hence the image digest), `output_root`, `output_partition`, `compose_service`, `compose_profile`, the Zeek command actually executed, the per-log SHA-256 and record-count inventory, and `started_at` / `completed_at`.

> **Identity determinism decision requiring ratification.** `content_sha256()` deliberately **excludes** `started_at` and `completed_at` via `identity_payload()`. MB3 will consume the report content digest as an `event_id` component; if wall-clock timestamps entered that digest, MB3 event identities would change on every re-run and determinism would be unprovable. The frozen M2 report avoids the problem by carrying no timestamps at all; M6 took the opposite path and its report digest is knowingly irreproducible. MB2 records timestamps for auditability but keeps them outside the identity payload. A test locks this behaviour. **Please confirm this choice before MB3 binds to it.**

### MB6 feature windows — EXECUTED / VERIFIED (2026-08-13)

Six files created, one MB4 test repurposed.

| File | Role | SHA-256 |
|---|---|---|
| `modules/detection/src/schemas/monday_benign_feature_window.py` | MB6 contracts, namespace, run derivation | `57fc25cfb77c71d8866c45b4fa6d995830ac08fb99ff49ef9888ab38655034f6` |
| `modules/detection/src/lineage/monday_benign_feature_window.py` | MB1→MB2→MB3→MB4→MB6 binding | `2b55ae4df7ca3c21d9766bb34c2ca505340cbaff92dd31835f50cb2a339612ae` |
| `modules/detection/src/persistence/schema_mb6.sql` | `mb6_canonical` DDL | `1dd80d27a7839601b1503cd8498da7848af5ef5b19b490cd241d8bf229efb6c7` |
| `modules/detection/src/persistence/monday_benign_window_persistence.py` | runner + persistence | `c1b510e763f364b0feda5914399eb0cf201868cef3f14ecc71c2a31198b93585` |
| `scripts/materialize_monday_benign_windows.py` | MB6 entrypoint | `6fb9410ed3feeebefca42a5b423f3982f8636f28ce8d34e63e9797596e08755e` |
| `modules/detection/tests/test_mb6_windows.py` | 50 tests | `cc0fbb9a34c7d963490582ac1d67f6541dc4109066d6e6a5c4731fdf19386db4` |

**Correction to an earlier claim in this index.** It previously said `FeatureWindowSpecificationV2` was reusable unchanged for MB6. That is true only for its `namespace`, which is a free `UUID`. The specification itself hard-locks five M-chain values as `Literal`: `milestone = "m6"`, `operational_source = "m4_canonical.flow_end_events"`, `evidence_source = "frozen_m2_conn_log_via_m3_v2_protocol"`, `FeatureWindowPersistencePolicyV2.operational_projection = "postgresql_schema_m6_canonical"`, and `FeatureWindowOrderingPolicyV2.partition_order = "m3_replay_report_binding_order"`. MB6 therefore derives its own specification, ordering, persistence and governance policies.

**Reuse is nonetheless extensive and semantic equivalence is enforced, not assumed.** `FeatureWindowBuilderV2`, `SourceEventRow`, `window_identity`, `canonical_window_bytes`, `entity_key_for`, `window_start_unscaled`, `FeatureWindowV2`, `WindowDataQuality`, `EventProvenance`, `FeatureWindowPartitionReportV2` and every cardinality-agnostic policy sub-model are used unchanged. The MB6 manifest **reuses the frozen M6 manifest's policy blocks verbatim** — `window_contract_versions`, `temporal`, `window`, `entity`, `features`, `provenance`, `labels`, `deferred`, `authoritative_sources` — read read-only and never modified, and a test asserts block-by-block equality so MB6 window semantics cannot drift from M6.

**MB4 is the only source.** MB6 reads `mb4_canonical.flow_end_events` with `SELECT` only. It never opens the PCAP and never reads a Zeek log; a test asserts the MB6 sources contain neither `conn.log` nor `.pcap` in executable code.

**The database question, resolved without moving anything.** MB6 reads MB4 and writes MB6, both inside `cybersentinel_test`. **MB6 never needs M6 or `m4_canonical`**, so no cross-database access arises at this milestone and nothing was moved or re-materialized. Co-locating M and MB remains a purely future ML-dataset concern.

**Results:**

| Metric | Value |
|---|---|
| Source events consumed | 368,202 — exactly MB4's persisted count |
| Windows produced | **70,921** |
| Distinct entities | 27,788 |
| Lineage rows | 368,202 — bijective with MB4, 0 orphans |
| Events rejected | **0** |
| Events per window | min 1, max 824 |

**Verified in the database, read-only:** all 70,921 rows satisfy `window_end - window_start = 60`, `prediction_time = window_end_time`, `mod(window_start_time, 60) = 0`, `event_count = source_event_count`, `late_event_count = dropped_event_count = 0`, `is_final AND NOT is_revision`, and scale 22 on all four temporal columns. One distinct partition. Two foreign keys, both inside `mb6_canonical`.

**Complete collision proof, not a sample.** Full set intersections computed in memory with no writes:

| Sets | Intersection |
|---|---|
| MB6 `window_id` (70,921) ∩ M6 `window_id` (172,748) | **0** |
| MB6 `source_event_id` (368,202) ∩ M6 `source_event_id` (1,353,467) | **0** |
| MB4 `event_id` (368,202) ∩ M4 `event_id` (1,353,467) | **0** |
| MB6 `window_id` ∩ MB4 `event_id` | **0** |

The third row is the first exhaustive confirmation of MB3/M3 identity separation; earlier turns could only check the two boundary event IDs.

**Idempotence**: a second materialization was refused with `MondayBenignDuplicateVerifiedWindowRunError`. Because `run_id` is deterministic, the run-table primary key is a second independent barrier, and the runner also refuses to overwrite a prior non-verified attempt rather than silently reusing its identity.

**P1 reproduced as expected**: `distinct_source_ips` and `distinct_destination_ips` equal 1.0 in all 70,921 windows, exactly as in M6 and for the same structural reason — both IPs are part of the entity key. This is a documented modelling characteristic, not a defect.

**A report-publication failure occurred and was recovered without re-materializing.** The first invocation materialized all 70,921 windows and marked the run `verified`, then failed constructing the report because `bound.run_id` and `bound.mb4_run_id` are `str` while the contract demands `UUID`. Rather than re-running the write, a `--publish-from-verified-run` mode was added: it recomputes every window read-only, cross-checks the recomputed window count, event count and stream digest against the stored verified row, and only then publishes. All three matched.

### MB4 canonical persistence — EXECUTED / VERIFIED (2026-08-13)

Four files created; one existing MB3 test repurposed.

| File | Role | SHA-256 |
|---|---|---|
| `modules/detection/src/persistence/schema_mb.sql` | `mb4_canonical` DDL | `19769be84e8bfd07b8a42b9a60da8dfc6f39dfa0a1bd3e38c06320fc10dfdc44` |
| `modules/detection/src/persistence/monday_benign_persistence.py` | gate, guard, adapter, report | `0ccee7244a05f886a4d6802d5d0640780362bad13f2d85abf39de29ae9d995d1` |
| `scripts/materialize_monday_benign_events.py` | MB4 entrypoint | `6062a48e49d4b065651ec6ba40bd75fe99ba0a8c35d824ffec43c06dcf2e0009` |
| `modules/detection/tests/test_mb4_materialization.py` | 33 tests | `750573d63551ab31e68a06e5d7016e26a77c1c698285d1ce2ce511e5289eb223` |

**No event was copied.** The adapter re-invokes `StrictZeekJsonLineParserV2` and `StrictZeekConnFlowEndNormalizerV2` over the MB2 Monday `conn.log` under the frozen MB3 protocol, regenerating every `event_id` through the same UUID5 derivation. Identity with MB3 is then *proven*, not assumed: the independently recomputed event-stream digest must equal `ed558ab3…` or the run is marked `failed` and the report contract refuses to validate.

**Safety ordering, in this order, before any write:**

1. `assert_expected_database` compares `current_database()` against a name the caller must pass explicitly — the entrypoint has **no default database**, so no invocation can silently target production. Verified: connecting to `cybersentinel` while expecting `cybersentinel_test` raises.
2. `verify_mb4_schema` proves the four tables exist, that the five temporal columns are `NUMERIC(38,22)`, that the five required event constraints are present, and that **no foreign key leaves `mb4_canonical`**.
3. `verify_frozen_mb3_report` proves the published MB3 report is intact, verified, Monday-only, and namespace-correct.
4. The partial unique index `ux_mb4_runs_verified_report` makes a second verified materialization of the same MB3 report a storage-level error; the adapter also raises `MondayBenignDuplicateVerifiedRunError` first.

**MB-only hardening absent from M4**: `CHECK (output_partition = '2017-07-03_Monday-WorkingHours')` on all three partition-bearing tables. A row from any other capture day cannot be stored even by a buggy writer — the isolation invariant expressed by the database itself.

**Verified in the database, read-only after the run:**

| Check | Result |
|---|---|
| Rows / distinct `event_id` / distinct line numbers | 368,202 / 368,202 / 368,202 |
| Distinct partitions | 1 — `2017-07-03_Monday-WorkingHours` |
| UUID version 5 rows | 368,202 of 368,202 |
| `event_end_time = event_start_time + event_duration` | 368,202 of 368,202 |
| `event_end_time <= record_available_time <= ingested_at` | 368,202 of 368,202 |
| `scale() = 22` on all three temporal columns | 368,202 of 368,202 |
| `termination_reason IS NULL`, transport in tcp/udp, counters ≥ 0 | 368,202 each |
| Rejection counts total vs span coverage | 7,230 = 7,230 |
| MB3 boundary `event_id`s present | both |
| Constraints on `mb4_canonical` | 33 (PK, UNIQUE, CHECK, FK) |
| Foreign keys leaving `mb4_canonical` | **0** |
| `mb*` tables in `cybersentinel` | **0** |

A sample row shows the canonical scale surviving storage intact: `event_start_time = 1499082958.5983080000000000000000`, `event_duration = 0.0000100135803222656250`, `event_end_time = 1499082958.5983180135803222656250` — exact addition, 22 decimals, no float anywhere.

**Idempotence / double publication**: a second invocation was refused with `MondayBenignDuplicateVerifiedRunError`, naming the existing `run_id`, and MB4 counts were unchanged afterwards (1 run, 368,202 events, 3,580 spans, 3 counts, 1 verified run).

**A guard of mine misfired and was corrected.** `ensure_mb4_schema` initially rejected the DDL because the file's comment header *names* `m4_canonical` to document that it never touches it. The check now strips `--` comments and tests executable statements only, which is what it always should have done.

### MB3 exact-time normalization — EXECUTED / VERIFIED (2026-08-13)

Five files were created; nothing existing was modified.

| File | Role | SHA-256 |
|---|---|---|
| `modules/detection/src/schemas/monday_benign_normalization.py` | MB3 contracts, namespace, evidence profile | `f76e9fd3b873bbbb3ae8d4cf58f0d01a792ae3d64182823ce16de4e83353cd69` |
| `modules/detection/src/lineage/monday_benign_normalization.py` | MB1 → MB2 → MB3 binding | `f5953709e3a2f50e169dd7744a39f555490a4e356e57ea032b439fa6de3a6c29` |
| `modules/detection/src/normalization/monday_benign_pipeline.py` | MB3 runner + immutable publisher | `a7b2932b1cef0309dbf2047e0427722ed416609312e81ba93161f66d40c36893` |
| `scripts/normalize_monday_benign_events.py` | pre-scan, freeze, run, publish | `9a863879e7b4d190615bd5360f37bd2e1bfb7bfbd50a2c497652d17574928454` |
| `modules/detection/tests/test_mb3_normalization.py` | 44 tests | `ad4462050131874dc2f14c253b83102470436c06968c188db75e475227684b23` |

**Reuse is extensive.** `ZeekConnNormalizationRunnerV2` is **subclassed, never modified**; MB3 inherits `_source_path`, `_preflight_verify`, `process_partition`, `_append_rejection_span`, `_build_partition_report`, `RunAccumulator` and `PartitionResult`, and overrides only `from_repository` and `_build_run_report`. `StrictZeekJsonLineParserV2` and `StrictZeekConnFlowEndNormalizerV2` are used unchanged, so MB3 events carry identical conn.log → `FlowEndV2` semantics. Every cardinality-agnostic policy sub-model is reused verbatim: `ZeekConnLogMappingV2`, `ZeekTemporalPolicyV2`, `ZeekEventEnvelopePolicyV2`, `ZeekUnsupportedRecordPolicyV2`, `ZeekOrderingPolicy`, `ZeekParserBoundaryPolicyV2`, `ZeekReplayReportBinding`, `ZeekSourceCoordinate`, `ZeekNormalizationContextV2`, and the whole partition-report family including `ZeekPartitionNormalizationReportV2`.

Only two contracts were derived, and `ZeekNormalizationSpecificationV2` could not have been subclassed because Pydantic would re-run all seven of its M-chain locks: three replay reports, the literal `frozen_at`, the M3 v2 namespace, the M3 v1 supersession hash, the fixed revision reason, the `Literal` record counts, and the M2-root path prefix.

**`m2_output_root` is a read-only property alias.** The inherited runner resolves source logs through `specification.m2_output_root`; the MB3 field is named `mb2_output_root` so no manifest can imply the frozen M2 tree, and the alias keeps the inherited code working untouched.

#### Deliberate departure: the evidence profile declares measurements, not predictions

M3 v2 baked *predicted* accept/reject counts into its protocol as `Literal` values. Reproducing that for MB3 would have been circular — the counts are only knowable by running the normalizer, which needs the protocol hash, which would change if the counts changed. `MondayBenignEvidenceProfile` therefore declares only what a **read-only lexical pre-scan** can measure, with no normalizer involved:

| Measurement | Value |
|---|---|
| `scanned_record_count` | 375,432 — equals the MB2 replay record count |
| `records_with_duration` | 368,708 |
| `timestamp` max significant / fractional digits | 17 / 7 |
| `duration` max significant / fractional digits | 22 / **22** |
| `exact_end` max significant / fractional digits | 28 / 18 |

All within `DECIMAL(38,22)`. `duration` sits exactly at the scale limit, which is precisely why the M3 v1 microsecond representation failed and why exactness is non-negotiable. Accept and reject counts live solely in the run report, where they are observed.

#### Results and internal cross-check

Processed 375,432, accepted **368,202**, rejected **7,230** — a 98.074% acceptance rate, within 0.001 points of the M chain's 98.073%. Rejections:

| Reason | Count |
|---|---|
| `missing_required_field` | 6,724 |
| `unsupported_service_cardinality` | 343 |
| `unsupported_transport` | 163 |

These reconcile exactly against the independent pre-scan: `375,432 − 368,708 = 6,724`, so **every record lacking a duration is a missing-field rejection**, and of the 368,708 records carrying a duration, `343 + 163 = 506` were rejected on service or transport, leaving `368,708 − 506 = 368,202` accepted. Two independent measurements agree to the record.

#### Determinism, proven twice

A full `--recompute-only` re-run with the identical protocol and temporal context reproduced **every** value: protocol hash, canonical event stream digest, rejection audit digest, both boundary `event_id`s, all three counts, and the report `content_sha256`. Unlike the M6 report — whose digest is knowingly irreproducible because it embeds a `uuid4` — the MB3 report contains no random or wall-clock-at-hash-time field, so its identity is reproducible given the same `record_available_time` and `ingested_at`, both of which are explicit inputs.

A test additionally recomputes the first accepted `event_id` end to end from published bytes, streaming the real `conn.log` to the first acceptance and comparing against `uuid5(MB3_NS, protocol|replay_report|source_log|partition|conn.log|line)`. It matches the published report, and the same name under either M-chain namespace yields a different identity.

#### Collision impossibility

Verified read-only against the live database: neither MB3 boundary `event_id` appears in `m4_canonical.flow_end_events` or `m6_canonical.feature_window_sources` — **0 collisions**. Structurally, collision is impossible before the namespace is even considered: four of the six name components differ from any M chain event, since the MB3 protocol hash, the MB2 replay report hash, the Monday `conn.log` hash and the partition name are all MB-specific. A test asserts each of those four against the published M3 v2 report.

#### What MB3 did not do

No event was persisted **by MB3**. MB3 hashes and discards exactly as M3 v2 does, and no MB3 source imports the persistence layer, a database driver, or `mb4_canonical` — a test asserts all four. Persistence arrived separately in MB4 on the same day; the MB3 stage itself remains write-free.

### MB2 replay — EXECUTED / VERIFIED (2026-08-13)

The real replay ran on 2026-08-13 in **764 s** through the `zeek-replay-mb` service only. Two files were created for it:

| File | Role | SHA-256 |
|---|---|---|
| `scripts/replay_monday_benign.py` | MB2 production entrypoint | `2a1133b5a87078fd82f21f97498c7fc6e30b5033f78dd7efcdffee7750a4b217` |
| `datasets/manifests/monday_benign_zeek_replay.yaml` | MB2 specification, published immutably | `a0863a5e46200c8a85504605c43dfbea996a5b0d991147e3002aa6676dc261bf` |

The entrypoint declares the Zeek runtime pin, determinism policy and output policy **explicitly from MB-track constants**; it reads no M chain manifest. Identity with the M2 runtime is nevertheless guaranteed, because `MondayBenignReplaySpecification` validates the image and platform digests against the frozen M2 values.

Published output: `artifacts/canonical/cicids2017/mb2/zeek-8.0.9/2017-07-03_Monday-WorkingHours/` — 31 files, 508,773,282 bytes, no staging directory left behind. The three operational logs (`packet_filter.log`, `stats.log`, `telemetry.log`) were correctly relocated under `operational/`, and `conn.log` yielded **375,432 records**.

**Anomalies and rejections: none.** Exit code 0, `verification_status = verified`, every required log present and non-empty, all 30 logs valid JSON Lines.

Verified after the run:

- the frozen M2 tree still holds exactly **95 files** at inventory digest `fc3b3c68…`;
- `docker-compose.yml` unchanged at `58a3bb94…`;
- the Monday PCAP is **byte-identical**: same size 10,822,507,416, same `st_mtime_ns`, and a full re-hash reproduced `f6eac599…`;
- PostgreSQL untouched: `m4_events = 1,353,467`, `m6_windows = 172,748`, `mb_schemas = 0`, `mb_tables = 0`.

> **Empirical answer to risk R3.** Zeek produced 375,432 `conn.log` records against the official CSV's 529,918 CICFlowMeter rows — 70.8%. This confirms the documented position that the two counts measure different flow abstractions and must never be equated. The corroboration criteria that matter remain the temporal span and the label outcome, both of which are MB-LABEL concerns.

> **Risk R9 is now unblocked.** The Monday `conn.log` exists, so the MB3 evidence profile can be measured by a read-only pre-scan.

### Planned files — remaining

Manifests:
```
datasets/manifests/monday_benign_pcap_freeze.yaml            <-- CREATED 2026-08-13
datasets/manifests/monday_benign_zeek_replay.yaml            <-- CREATED 2026-08-13
datasets/manifests/monday_benign_zeek_normalization.yaml     <-- CREATED 2026-08-13
datasets/manifests/monday_benign_feature_window.yaml         <-- CREATED 2026-08-13
```

Contracts:
```
modules/detection/src/schemas/monday_benign_protocol.py
modules/detection/src/lineage/monday_benign_binding.py
```

Persistence:
```
modules/detection/src/persistence/schema_mb.sql               <-- CREATED 2026-08-13
modules/detection/src/persistence/monday_benign_persistence.py <-- CREATED 2026-08-13
```

Scripts:
```
scripts/freeze_monday_benign_pcap.py                         <-- CREATED 2026-08-13
scripts/replay_monday_benign.py                              <-- CREATED 2026-08-13
scripts/materialize_monday_benign_events.py                  <-- CREATED 2026-08-13
scripts/materialize_monday_benign_windows.py                 <-- CREATED 2026-08-13
```

Tests:
```
modules/detection/tests/test_mb1_freeze.py   <-- CREATED 2026-08-13
modules/detection/tests/test_mb3_normalization.py   <-- CREATED 2026-08-13
modules/detection/tests/test_mb6_windows.py         <-- CREATED 2026-08-13
modules/detection/tests/test_mb_isolation.py
```

**Accounting as of 2026-08-13.** Seven files now exist. Four were created for MB2 and none of them appear in the lists above, because MB2 needed a replay contract, a replay binding, a runner and a test suite; the original design had folded those into `monday_benign_protocol.py`, `monday_benign_binding.py` and `replay_monday_benign.py`, and did not name a derived runner at all. Three were created for MB1 and two of those *were* on the planned lists.

| Created for MB2 | Relates to |
|---|---|
| `modules/detection/src/schemas/monday_benign_replay.py` | MB2 share of the planned `monday_benign_protocol.py` |
| `modules/detection/src/lineage/monday_benign_replay.py` | MB2 share of the planned `monday_benign_binding.py` |
| `modules/detection/src/ingestion/monday_benign_replay.py` | new — the derived MB runner the design did not name |
| `modules/detection/tests/test_mb2_replay.py` | new — MB2 test suite |

| Created for MB1 | Relates to |
|---|---|
| `scripts/freeze_monday_benign_pcap.py` | the planned MB1 entrypoint |
| `modules/detection/tests/test_mb1_freeze.py` | the planned MB1 test suite |
| `datasets/manifests/monday_benign_pcap_freeze.yaml` | the planned MB1 manifest — **published artifact** |
| `artifacts/canonical/cicids2017/mb1/dataset_freeze_verification.json` | not on the list; required by the JSON report convention |

Consequently the planned `monday_benign_protocol.py` and `monday_benign_binding.py` were **never created under those names**: MB3 shipped as `monday_benign_normalization.py` in both `schemas/` and `lineage/`, plus `normalization/monday_benign_pipeline.py` for the derived runner, which the design had not named. MB3 created five files in total.

| Created for MB3 | Relates to |
|---|---|
| `modules/detection/src/schemas/monday_benign_normalization.py` | MB3 share of the planned `monday_benign_protocol.py` |
| `modules/detection/src/lineage/monday_benign_normalization.py` | MB3 share of the planned `monday_benign_binding.py` |
| `modules/detection/src/normalization/monday_benign_pipeline.py` | new — the derived MB3 runner |
| `scripts/normalize_monday_benign_events.py` | new — MB3 entrypoint |
| `modules/detection/tests/test_mb3_normalization.py` | the planned MB3 test suite |
| `datasets/manifests/monday_benign_zeek_normalization.yaml` | the planned MB3 manifest — **published artifact** |
| `artifacts/reports/mb3_monday_benign_normalization_run.json` | not on the list; the MB3 run report |

Still **PLANNED — NOT CREATED YET**: `datasets/manifests/monday_benign_feature_window.yaml`, `modules/detection/src/persistence/schema_mb.sql`, `modules/detection/src/persistence/monday_benign_persistence.py`, `scripts/materialize_monday_benign_events.py`, `scripts/materialize_monday_benign_windows.py`, `modules/detection/tests/test_mb6_windows.py` and `modules/detection/tests/test_mb_isolation.py`.

### Reused WITHOUT modification

**VERIFIED**: the M1 and M2 contracts already accept a single partition (`min_length=1`). Only the normalization-specification and report layer imposes three.

| Component | Cardinality |
|---|---|
| `DatasetFreezeManifest`, `PcapEvidenceFile`, `DatasetFreezeVerificationReport` | `min_length=1` — reusable |
| dataset freeze lineage utilities (`lineage/dataset_freeze.py`) | reusable |
| `ZeekReplaySpecification`, `ZeekReplayRunReport`, `ZeekRuntimePin` | `inputs min_length=1` — reusable |
| `ZeekReplayRunner` (`replay(relative_path)`) | per-PCAP — **partially reusable, and now actually reused**: input selection, verification, staging, log validation and atomic publication are inherited by `MondayBenignReplayRunner`; `_compose_command`, `replay` and `_evidence` are overridden. `ZeekReplayRunner` itself is unmodified. |
| replay lineage/binding utilities (`lineage/replay.py`) | reusable |
| `StrictZeekJsonLineParserV2` | per-line — reusable |
| `StrictZeekConnFlowEndNormalizerV2` | reusable by attribute surface |
| `FlowEndV2` | no partition constraint |
| exact-time schemas (`schemas/exact_time_v2.py`) | reusable |
| `FeatureWindowV2` | no partition constraint |
| `FeatureWindowSpecificationV2` | declares no partitions; `namespace` is a free `UUID`, so a distinct MB6 namespace needs no derived contract |
| `FeatureWindowBuilderV2` / `derive_window_id` | per-partition, namespace is a parameter — reusable |
| M5 v1 / `LabelLedger` + `monday-benign-reference` | reusable as-is (`any_network`) |
| `ExactTimeLabelAdapterV2` | reusable |
| DB connection conventions (`persistence/db.py`) | reusable |
| Docker `zeek-replay` service | **NOT reusable for MB** — its `/output` is the frozen M2 tree. MB uses the separate additive `zeek-replay-mb` service. |

**Reuse means import and call. It does not mean edit.** No file in the list above may be modified for MB.

### Contracts requiring additive derivation (must NOT be modified)

| Source | Reason |
|---|---|
| `ZeekNormalizationSpecificationV2` | `!= 3 → raise` |
| `ZeekNormalizationRunReportV2` | `!= 3 → raise` |
| `M4MaterializationReportV2` (where applicable) | `!= 3 → raise` |
| `FeatureWindowRunReportV2` | `!= 3 → raise` |
| `lineage/feature_window_v2.py` | requires `== 3`; binds M3/M4 identities |
| `scripts/freeze_cicids2017_pcaps.py` approved capture-date list | excludes Monday |

The MB implementation must **derive dedicated contracts that accept one partition**, leaving every original untouched.

### Lineage and identity rules

```text
Monday PCAP
    → MB1 manifest hash
    → MB2 specification hash
    → MB2 replay report
    → MB3 normalization identity
    → MB3 event IDs
    → MB6 protocol hash
    → MB6 window IDs
    → EventLabel via event_id VALUE
```

> **MANDATORY**: do not reuse the existing M3 v2 namespace (`f7dad188-04cb-5859-81a0-014329de2899`) or the M6 namespace (`f787c08a-290e-5b79-a8cb-5bc19ae633dc`). MB3 and MB6 must each use a **distinct deterministic namespace**, declared in their manifests.

Partition name: **`2017-07-03_Monday-WorkingHours`** — follows the validated `{capture_date}_{stem}` convention and collides with none of the three existing partitions.

### Validation protocol note

The 529,918 CSV rows are **CICFlowMeter** flows; `conn.log` uses a different flow abstraction. A 1:1 correspondence is **impossible** and must **not** be an acceptance criterion. Verifiable criteria: all CSV rows `BENIGN` (already verified), Zeek temporal span inside 12:00→20:01Z, source IPs a subset of the 25 bench hosts, and — the decisive one — **the replay yielding 100% `benign_reference` with 0 attack**.

---

## Scientific risks

### 🔴 R1 — Day-level confounder (HIGH / RED)

Monday is a **complete benign day**, while Tuesday/Wednesday/Friday contain the attacks. This creates a possible day-level confounder:

> A model could learn **"Monday = benign"** rather than learning network attack characteristics.

Adding Monday solves the missing-negative-class problem **technically**, but does **not** automatically make the ML dataset scientifically valid. A model could latch onto any day-correlated artefact (active host set, service mix, hourly volumetry, background traffic version) instead of attack signal, producing excellent but scientifically empty metrics.

This risk **cannot be eliminated by architecture.** Mitigations identified but **NOT decided**:

- pair Monday windows with comparable entity/service windows from attack days;
- use selected `unknown` windows outside attack intervals as complementary negatives;
- use Monday primarily for calibration rather than training.

**Do not choose a mitigation without explicit approval.**

### 🟡 R5 — `172.16.0.1` dual role (feature-design / split concern)

`172.16.0.1` is:

- **attacker** during Tuesday/Wednesday/Friday attack windows;
- **benign** on Monday.

This is temporally correct and is **not itself label leakage**. However, `entity_key` contains the source IP, so a model consuming `entity_key` directly could learn an identity correlation rather than behaviour.

Note precisely: the **eight M6 model features do not include the raw source IP**, but `entity_key` exists in the window representation and is persisted. Treat this as a feature-design and split-design concern.

### 🟠 R8 — "100% benign" is not guaranteed (MB-LABEL)

The `monday-benign-reference` rule covers only the compiled interval **12:00:00Z → 20:01:00Z**. If the Monday `conn.log` contains flows whose `event_start_time` falls outside that interval — plausible, since the capture may span more than the scheduled working hours — those events resolve to `unknown`, not benign.

The correct expected outcome is therefore: **100% of events inside the compiled interval labelled `benign_reference`, zero attack, and any event outside the interval left `unknown`.** Never convert `unknown` to `benign` to reach a round number.

### 🟢 R9 — MB3 evidence profile — RESOLVED (2026-08-13)

`ZeekTemporalEvidenceProfileV2` in the M chain hard-codes its record counts as `Literal` values (1,380,057 / 1,353,467 / 26,590). The MB3 derived contract needs its own counts, which are unknowable until the Monday `conn.log` exists. The MB3 manifest can therefore only be frozen **after** MB2 completes and a read-only pre-scan has measured the counts — mirroring how M3 v2 was built.

**Resolved 2026-08-13.** MB3 declined to repeat the M3 v2 pattern. `MondayBenignEvidenceProfile` declares only read-only lexical measurements — 375,432 lines, 368,708 with a duration, and the observed decimal widths — and the accept/reject counts live solely in the run report where they are observed. The measured pre-scan and the executed run reconcile to the record: `375,432 − 368,708 = 6,724` equals the `missing_required_field` count exactly. The ordering rule this risk describes must still be respected for MB6: **never author an evidence profile from estimates.**

### 🟢 R10 — MB2 spec ↔ service pairing — **RESOLVED IN CODE (2026-08-13)**

`ZeekReplayRunner` derives the host staging path from the specification, while the container's `/output` comes from `docker-compose.yml`. Nothing paired them, so running the M2 specification through `zeek-replay-mb`, or an MB specification through `zeek-replay`, would have written Zeek logs into the wrong tree. It was mitigated only by a Compose comment.

Now enforced by `MondayBenignReplayRunner._verify_compose_pairing()`, which runs before any container invocation and refuses to proceed unless the `zeek-replay-mb` service exists, declares its profile, has exactly one `/output` mount equal to the specification's `output_root`, that path is outside the frozen M2 tree, and its single `/input` mount is read-only. Six tests cover the failure modes. Retained here because the guard must be preserved, not because the risk is still open.

### Other risks

| # | Risk | Level |
|---|---|---|
| R2 | Replaying a 10.08 GiB PCAP requires Docker + the frozen Zeek image — **measured 2026-08-13: 764 s**, image present locally at 766 MB, no pull needed | Resolved |
| R3 | CSV/Zeek flow counts cannot be reconciled exactly — **measured 2026-08-13**: 375,432 Zeek `conn.log` records vs 529,918 CSV rows (70.8%). Confirmed, not a defect; never equate the two | Confirmed |
| R4 | Three derived contract clones will diverge from originals over time | Low |
| R6 | MB is unusable until the whole chain reaches MB6 | Low |
| R7 | Additional PostgreSQL volume (~500 k events, ~60 k windows estimated) | Negligible |

---

## Repository layout

```text
modules/
├── backend/app/          Legacy FastAPI + scoring (frozen)
├── detection/
│   ├── src/
│   │   ├── contracts/    Strict base models
│   │   ├── schemas/      Canonical event/protocol contracts (v1 + v2 public)
│   │   ├── lineage/      Provenance, freeze, replay, normalization binding,
│   │   │                 exact-time label adapter, M5 v2 policy
│   │   ├── ingestion/    Abstract adapters + private concrete parsers
│   │   ├── normalization/ Abstract boundary + private normalizers, runners (v1 + v2)
│   │   ├── persistence/  M4 + M6 schemas, adapters, reports, publication
│   │   └── feature_engineering/  FeatureWindow contracts + M6 window builder
│   └── tests/
├── storage/              Legacy PostgreSQL schema (frozen legacy track)
datasets/
├── manifests/            M1, M2, M5, M3 v1, M3 v2, M6 YAML specifications
├── cicids2017/           Official PCAPs (5 days), md5/, legacy ISCX CSVs
artifacts/
├── canonical/cicids2017/
│   ├── m1/              Frozen dataset-freeze verification
│   ├── m2/zeek-8.0.9/  Frozen M2 replay output, 3 partitions, 95 files (DO NOT MODIFY)
│   └── mb2/zeek-8.0.9/ MB2 replay output root — DOES NOT EXIST YET; mounted by
│                        the zeek-replay-mb service, created on first MB2 run
├── reports/             M3 v1, M3 v2, M4, M6 published immutable reports
models/                  Legacy XGBoost joblib files
scripts/                 Freeze, audit, alert-generation, M4 + M6 entrypoints
docs/                    All project documentation (see below)
```

### PostgreSQL schemas

| Schema | Contents | Status |
|---|---|---|
| `public` | Legacy `alerts`, `assets`, `threat_intel`, `genai_audit` | Frozen legacy track |
| `m4_canonical` | `materialization_runs`, `flow_end_events` (1,353,467), `rejection_spans`, `rejection_counts` | **DONE** |
| `m6_canonical` | `materialization_runs`, `feature_windows` (172,748), `feature_window_sources` (1,353,467) | **DONE** |
| `mb4_canonical` (in **`cybersentinel_test`**) | `materialization_runs` (1), `flow_end_events` (368,202), `rejection_spans` (3,580), `rejection_counts` (3) | **DONE** |
| `mb6_canonical` (in **`cybersentinel_test`**) | `materialization_runs` (1), `feature_windows` (70,921), `feature_window_sources` (368,202) | **DONE** |
| `mb7_canonical` (in **`cybersentinel_test`**) | `labeling_runs` (1), `event_labels` (368,202), `window_labels` (70,921) | **DONE** |
| `cybersentinel_test` (database) | Isolated integration-test database | **DONE** |

---

## Package-export policy

- `schemas` publicly exports v1 and v2 contracts, exact-time primitives, event models, and M6 window/protocol contracts.
- `lineage` publicly exports v1 and v2 loaders and bound specifications. The M6 binder, the exact-time label adapter, and the M5 v2 policy remain private submodules accessed by direct import (avoids the TD-003 import cycle).
- `ingestion` exports abstract adapters and the M2 replay runner only. Concrete parsers remain private.
- `normalization` exports only the abstract `EventNormalizer`. Concrete normalizers and runners (v1 and v2) remain private.
- `persistence` exports the M4 gate, contracts, and publication helpers. The M6 persistence layer remains private.

---

## Implementation boundaries

- M1 and M2 artifacts are **never** regenerated or modified.
- M3 v1 protocol and report are preserved for audit; they are not inputs to v2.
- M3 v2, M4, M5 v1, and M6 are **frozen**. Their published reports and hashes are immutable.
- Concrete parsers, normalizers, runners, window builders, and persistence layers are private submodules.
- **Labels are never a field of any event or window contract.** Enforced by `tests/test_label_contract.py` for `NetworkEvent`, `FeatureWindow`, and `FeatureWindowV2`.
- The M6 feature set is frozen at exactly eight features. Downstream transformation is a dataset concern.
- No watermark or late-arrival policy exists anywhere. Deliberately deferred.
- Integration tests that touch PostgreSQL must run against the isolated `cybersentinel_test` database with a hard `current_database()` guard. **Never against production tables.**

---

## Test inventory (all passing at last run)

| Suite | Tests |
|---|---|
| `test_zeek_normalization_v2.py` | 30 |
| `test_zeek_conn_normalizer_v2.py` | 12 |
| `test_zeek_pipeline_v2.py` | 21 (10 long full-run tests usually deselected) |
| `test_m4_report_verification.py` | 13 |
| `test_m4_materialization.py` | 13 |
| `test_m4_report_publication.py` | 21 |
| `test_m4_production_entrypoint.py` | 17 |
| `test_m6_feature_window_contract.py` | 55 |
| `test_m7_exact_time_labeling.py` | 34 |
| `test_m5_policy_v2.py` | 27 |
| `test_mb1_freeze.py` | **22 passed, 1 skipped** — MB1 Monday-only freeze, integrity, immutability, read-only access |
| `test_mb2_replay.py` | **41** — MB2 specification, runner, provenance, isolation |
| `test_mb3_normalization.py` | **44** — namespace separation, contract locks, evidence profile, binding, event_id determinism, isolation |
| `test_mb4_materialization.py` | **33** — DDL mirror, MB3 gate, report contract, database guard, read-only DB assertions, M chain isolation |
| `test_mb6_windows.py` | **50** — namespace separation, protocol locks, M6 semantic equivalence, deterministic run identity, binding, collision proof, isolation |
| `test_p3_anomaly.py` | **22** — benign-only training, temporal split, FPR versus alert-rate terminology, total botnet blindness |
| `test_p4_conservative.py` | **21** — exclusion by removal, two types deleted, ssh artefact guard, P1 reproducibility |
| `test_p2_temporal_matched.py` | **20** — single-change guarantee, identical test sets, matching rule, R1 result, confound documentation |
| `test_p1_supervised.py` | **29** — dataset composition, feature budget, fold leakage, threshold regression, episode bootstrap, model determinism, limitation recording |
| `test_mb_label.py` | **47** — namespace separation, ratified policy semantics, deterministic identity, exact counts, interval partition, isolation |
| Contract/legacy suites (`test_label_contract`, `test_feature_window`, `test_events`, `test_versions`, `test_provenance`, `test_interfaces`, `test_cicids_labeling`, freeze/replay suites) | 137 combined at last full run |

Long-running note: the ten deselected `test_zeek_pipeline_v2.py` tests each execute a full three-partition M3 v2 run (~36 minutes combined). They were verified at the M3 v2 freeze.

### MB2 routing verification (2026-08-11)

| Check | Result |
|---|---|
| YAML parsing (PyYAML) | **OK** |
| `docker compose config --services`, both profiles | **OK** — validated by the official Docker client parser |
| Service count | **7** (`elasticsearch`, `grafana`, `kibana`, `postgres`, `redis`, `zeek-replay`, `zeek-replay-mb`) |
| M2/MB2 profiles disjoint | **OK** |
| `/output` volumes isolated | **OK** |
| `/input` read-only in both | **OK** |
| Zeek image / digest identical | **OK** |
| M2 and MB2 paths not nested | **OK** — neither is an ancestor of the other |
| `test_zeek_replay_runner.py`, `test_zeek_replay_contract.py`, `test_dataset_freeze.py`, `test_dataset_freeze_workflow.py` | **75 passed, 1 skipped** |

> **Critical caveat for a new agent.** Those 75 tests do **not** consume the real `docker-compose.yml`. `_prepare_repository` in `test_zeek_replay_runner.py` writes its own minimal `services: {}` compose file inside `tmp_path`. The suite therefore proves **no regression** in the M2 runner, but it is **not** evidence that an MB runner correctly invokes `zeek-replay-mb`. That evidence does not exist yet and must be produced by the MB2 runner tests.

### MB2 implementation verification (2026-08-13)

| Suite | Result |
|---|---|
| `test_mb1_freeze.py` | **22 passed, 1 skipped** (the skip needs OS symlink privileges; a monkeypatched test covers the same rejection branch) |
| `test_mb2_replay.py` | **41 passed** |
| `test_mb3_normalization.py` | **44 passed** |
| `test_mb4_materialization.py` | **33 passed** |
| `test_mb6_windows.py` | **50 passed** |
| `test_mb_label.py` | **47 passed** |
| `test_p1_supervised.py` | **29 passed** |
| `test_p2_temporal_matched.py` | **20 passed** |
| `test_p3_anomaly.py` | **22 passed** |
| `test_p4_conservative.py` | **21 passed** |
| `test_zeek_replay_runner.py`, `test_zeek_replay_contract.py`, `test_dataset_freeze.py`, `test_dataset_freeze_workflow.py` | **75 passed, 1 skipped** — no M1/M2 regression |
| Whole `modules/detection/tests` tree, excluding the long `test_zeek_pipeline_v2.py` full runs and the two obsolete `test_no_production...` guards | **815 passed, 2 skipped, 2 deselected** (2026-08-17, after P4/C) |

The skip count fell from 6 to 2 between the pre-replay and post-replay runs only because the PostgreSQL container was started, so the database integration tests execute instead of skipping.

> **One MB2 guard was repurposed after the replay.** `test_no_mb2_replay_artifact_exists_in_the_repository` asserted that `artifacts/canonical/cicids2017/mb2/` did not exist. That was correct before MB2 ran and false by design afterwards — the same failure mode as the two obsolete `test_no_production...` M4 guards. Rather than deleting it or leaving it red, it became `test_repository_mb2_tree_holds_only_the_monday_partition`, which defends the surviving intent: the MB2 tree may contain at most the single Monday partition and never a leftover staging directory. Every test in the module still replays under `tmp_path`.

The 41 MB2 tests cover: single Monday input; rejection of a second input; rejection of every non-MB2 output root including the M2 tree and a partition inside it; rejection of the frozen M1 manifest path; rejection of non-Monday evidence; runtime pin equality with M2 and rejection of a divergent digest; MB1 binding hash equality and Monday-only manifest; MB service and profile actually invoked with `zeek-replay` never present as a command element; the real repository `docker-compose.yml` pairing correctly; four cross-pairing rejections; writable `/input` rejection; missing service and missing profile rejection; atomic publication under the MB2 root; nothing ever created under the M2 root; PCAP byte-identical after a replay; existing-partition and staging refusal; container-failure cleanup; recorded command equal to the command executed; report identity independent of timestamps but sensitive to evidence; per-log hashes and record counts; and static assertions that MB2 sources never mention `m4_canonical`, `m6_canonical`, `psycopg`, `INSERT` or `CREATE SCHEMA`.

Every replay exercised in these tests runs against a tiny synthetic capture under `tmp_path` with an injected executor. **No container is started and the real 10 GiB Monday PCAP is never opened.**

### Integrity and safety certification for the MB2 routing step

- No replay was launched; no MB container was started.
- The Monday PCAP was **not opened**.
- No PostgreSQL write of any kind.
- No `mb*` schema created — verified: `mb_schemas = 0`.
- Counters unchanged: M4 events **1,353,467**; M6 windows **172,748**; M6 lineage **1,353,467**.
- Only `docker-compose.yml` was modified, verified repository-wide by modification timestamp.

---

## Known technical debt

See [TECHNICAL_DEBT.md](canonical/TECHNICAL_DEBT.md) for the complete register. Key items:

- TD-001: stale CMD venv path
- TD-002: absent Git metadata (no `.git` directory — integrity relies on manifests and hashes, not version control)
- TD-003: circular import (partially resolved — type-only import repair applied)
- TD-004–008: M2 publication hardening
- TD-009: development-history structural gaps
- TD-010: Grafana datasource credentials
- TD-011: FastAPI lacks authentication

Additional items observed during M4/M6 work, not yet in the register:

- **Script invocation gap** — `python scripts/<name>.py` fails repository-wide with `ModuleNotFoundError: No module named 'modules'` because no `pyproject.toml`, `setup.py`, or root `conftest.py` puts the repository root on `sys.path`. Use `python -m scripts.<name>` instead. This affects every script, including the pre-existing M1 freeze script.
- **M4 has no frozen YAML protocol manifest**, unlike M1, M2, M3 v2, and M6. Two competing governance precedents now exist.
- **TD-004 now applies to M4 and M6 as well**: row immutability is procedural (test isolation guard), not enforced by storage controls.
- Two obsolete pre-production guard tests assert that the M4/M6 production reports do **not** exist; they were correct before publication and are now false by design.

---

## Consolidated benchmark synthesis (PUBLISHED 2026-08-17)

The experimental protocol `P1/A -> P2/B -> P3/D -> P4/C` is **complete and
consolidated**. No benchmark was re-executed to produce the synthesis, no label was
modified, no artifact was deleted, and zero PostgreSQL writes occurred.

| Artifact | SHA-256 (first 16) |
|---|---|
| `artifacts/experiments/final/FINAL_BENCHMARK_REPORT.md` | `344cb5b14e81aa64` |
| `artifacts/experiments/final/final_benchmark_metrics.json` | `9954d0cb1b41134c` |
| `artifacts/experiments/final/FEATURE_AUDIT_REPORT.md` | `2e472216aaa1eb19` |
| `artifacts/experiments/final/feature_audit_raw.json` | `29710b9c8af4f624` |

Full identity of the consolidated metrics:
`9954d0cb1b41134cc7413cda7b733b508e927f1ae82ec1f023e6ba3d0f78ecbd`.
Produced by `scripts/consolidate_benchmarks.py`, which passes **15 cross-benchmark
consistency checks** and refuses to write on any disagreement.

### Central conclusion

With the five volume features currently admitted, the system detects some attacks
when similar volume signatures are present in training, but it is **blind to
low-intensity Ares C2 traffic, which is 47.1% of the positives**. P1's strongest
volumetric results therefore **do not** demonstrate a general ability to detect
unknown attacks: P4 shows that at least part of that performance depends on other
volumetric attacks being present in training.

### Confidence tiers

**Robust** - botnet/ares undetectable by volume features (ROC 0.5037 / 0.5195 /
0.5035, and exactly 0.0000 recall in P3 at both thresholds); no convincing evidence
of an hour-of-day effect on recall; detection depends on volume signatures being
present in training (ftp ROC 0.9866 -> 0.6037 on an **identical** test set).

**Partially supported** - ftp_patator (1 test episode), ssh_patator (0.111 at
episode level; its P4 value of 1.000 is an **exclusion artefact**, not a gain),
ddos/loit and dos/hulk (2 episodes each, **untested by P4**, which deletes them).

**Not demonstrable with this dataset** - generalisation to new attacks, new hosts or
new days; separation of behaviour from host-pair memorisation; true performance on
the 172,372 `unknown` windows; definitive absence of a temporal confounder.

### ?? R11 - Low attack diversity (MAJOR, OPEN)

5 attack types, 9 entities, **6 host pairs**, 54 episodes. All 199 `target_attack`
windows come from the single pair `172.16.0.1 -> 192.168.10.50`, so the four
volumetric types test four mechanics of one attacker against one victim. Only
`botnet/ares` interrogates other pairs - and it is exactly the case the current
features cannot see. **47.1% of positives sit below the benign density.** No design
creates diversity that does not exist.

### ?? R1 - Day-level confounder: FINAL STATUS = NOT RESOLVED

P2 is an **informative ablation, not proof of absence**. Episode recall is unchanged
on 4 of 5 types on identical test sets, so there is **no evidence** that P1's recall
depended on the time-of-day covariate. It cannot establish absence because it rests
on 54 episodes, because composition **and** size of the negative set changed
together, and because failing to find an effect is not showing there is none. The
PR-AUC decline (ftp 0.301 -> 0.135, ssh 0.354 -> 0.152, loit 0.592 -> 0.382) is a
**coverage and sample-size effect on an identical test set**, and is explicitly
**not** attributable to R1.

## Feature audit (COMPLETE, no feature selected)

`FEATURE_AUDIT_REPORT.md` audits 17 candidates derivable from columns already
persisted in M4/MB4. Reconstruction validated exactly against the frozen evidence:
376 attack, 70,578 benign, 177 botnet windows.

**No candidate separates the classes perfectly** - the audit found no new leakage
channel of the kind that disqualified `entity_service`, `entity_transport` and
`distinct_destination_ports`.

Strongest candidates for the botnet gap, all with zero identity and zero day
encoding: `interarrival_cv` (botnet 0.425 vs benign 1.154 - beaconing regularity),
`interarrival_mean` (8.498 vs 0.167, a 51x gap), `duration_mean` (0.083 vs 5.868, a
71x gap, zero missingness), `bytes_per_packet_destination` (32.0 vs 232.3) and
`byte_direction_ratio` (0.605 vs 0.273).

Rejected: `distinct_source_ports` and `distinct_conversations` (near-duplicates of
`event_count`), `distinct_connection_states`, `zero_response_fraction` and
`empty_flow_fraction` (near-degenerate), `packet_asymmetry` (redundant with volume).
Deferred as **NEEDS REVIEW**: per-state `connection_state` fractions - `RSTO`
dominates the attack events but only for the single host pair, so under R11 it
cannot be distinguished from host-pair memorisation.

Three cross-cutting risks recorded: the **completed-flow assumption** (duration and
inter-arrival presume flows have ended, which fails for a real online detector);
**non-random missingness** (inter-arrival availability is exactly `event_count >= 2`,
so 58.7% of benign windows lack it); and a **0.18% label-induced selection effect**
on duration, since the 127 `ambiguous` windows were excluded precisely because their
flows crossed a time boundary.

## CURRENT STATUS

- **Experimental phase**: `P1/A -> P2/B -> P3/D -> P4/C` complete, consolidated and
  published. Feature audit complete; **no feature adopted, no new model trained.**
- **M chain and MB track**: complete and frozen. Regression **815 passed, 2 skipped,
  2 deselected**.
- **M5 v2**: implemented and validated (27 tests).
- **Monday PCAP**: verified and available (MD5 matches).
- **Monday official CSV**: verified 529,918 rows, all `BENIGN`.
- **Existing M chain (M1–M6)**: untouched and frozen. No existing hash invalidated.
- **MB1**: **IMPLEMENTED / VERIFIED** — Monday PCAP frozen, manifest and verification report published, idempotence and immutability proven against the real artifacts.
- **MB2**: **EXECUTED / VERIFIED** — specification published, real replay completed in 764 s, 31 files published, `conn.log` with **375,432 records**, zero anomalies.
- **MB3**: **EXECUTED / VERIFIED** — protocol frozen from a measured pre-scan, 375,432 processed / **368,202 accepted** / 7,230 rejected, determinism proven by full recompute, report published.
- **MB4**: **EXECUTED / VERIFIED** — 368,202 events persisted into `mb4_canonical` in **`cybersentinel_test`**, recomputed digests equal to MB3, double publication refused.
- **MB6**: **EXECUTED / VERIFIED** — 70,921 windows and 368,202 lineage rows in mb6_canonical, deterministic run identity, 0 collisions with M6.
- **MB-LABEL (MB7)**: **EXECUTED / VERIFIED** — 368,202 event labels and 70,921 window labels in `mb7_canonical`, strict sidecar, **0 attack**, deterministic run identity, complete M5 provenance on every row.
- **P1/A supervised benchmark**: **EXECUTED / VERIFIED** — 376 positives vs 70 578 negatives, 5 leave-one-attack-type-out folds, 0 leakage failures, 0 PostgreSQL writes. Botnet blindness confirmed at ROC-AUC 0.5037.
- **P2/B temporal-matched ablation**: **EXECUTED / VERIFIED** — episode recall unchanged on 4 of 5 types on identical test sets; the R1 ablation found no effect on recall. PR-AUC declined on three folds, attributable to training on 26–40% of P1's negatives, not to R1.
- **P3/D anomaly benchmark**: **EXECUTED / VERIFIED** — fitted on 35 289 Monday benign windows only, zero positives; botnet recall exactly 0.0000 at both thresholds. Measured FPR 1.59% on held-out benign versus an alert rate of 1.46% on the 172 372 unknown windows, the latter never called an error rate.
- **P4/C conservative control**: **EXECUTED / VERIFIED** — excluding the two multi-family entities deletes `ddos/loit` and `dos/hulk` entirely, leaving 3 types and 290 positives. The botnet conclusion is robust; `ftp_patator` ROC collapses 0.9866 → 0.6037 on an identical test set, showing P1's transfer result depended on high-volume attacks being in training.
- **Production ML dataset / deployment**: **NOT IMPLEMENTED**.
- **The M chain database is untouched**: `m4_canonical` still 1 run / 1,353,467 events / 8,618 spans / 9 counts; `m6_canonical` still 1 run / 172,748 windows / 1,353,467 lineage rows; **0** `mb*` tables in `cybersentinel`.

Repository files changed for the MB track: `docker-compose.yml` (additive), plus MB1–MB7 sources, tests, entrypoints, and nine published artifacts. Nothing in the M chain has been touched: the M2 tree still holds 95 files at `fc3b3c68…`, the M3 v2 report file hash is still `62426406…`, and the frozen M5 v1 manifest is still `e9d9b00f…` on disk.

## 🔴 R11 — attack-class entity disjunction and effective sample size ≈ 9

Opened 2026-08-13, measured from published artifacts. **MB-LABEL does not and cannot correct it.**

Applying M5 v2 to the 172,748 M6 windows yields **376 attack windows** (199 `target_attack`, 177 `known_other_attack`) — 0.218%. Those 376 windows are drawn from only **9 distinct entities**. The 70,578 Monday benign windows come from 27,788 entities, and **not one of the 9 attack entities appears among them**. Entity identity therefore separates the classes perfectly, and the effective attack sample size is of the order of nine, not 376. No sampling, weighting or split technique corrects that.

Related measurement: `172.16.0.1` is the source entity of 359 M6 windows (0.208%) and of **zero** MB6 windows. `entity_key` is persisted in both window tables, so any entity-derived feature leaks the day and partially the class. The eight model features do not include the raw source IP.

## NEXT DECISION

MB1 through MB-LABEL are complete and verified. The MB track now holds Monday evidence labelled with full provenance, and the M chain holds attack-day evidence. Nothing further can be built without a scientific decision.

**The next step is not an implementation step. It is the R1 + R11 decision.** Before any dataset:

1. decide how the attack class is used at all, given 9 entities and 376 windows (R11);
2. decide the R1 mitigation: entity-group split, offset-of-day matching, exclusion of `entity_key` and derivatives, Monday as calibration rather than training, or anomaly detection trained on Monday alone;
3. decide the treatment of the 216 `unknown` and 127 `ambiguous` Monday windows, plus the 172,372 `unknown` M6 windows. **None of them is benign.**
4. decide the database location: MB4/MB6/MB7 are in `cybersentinel_test` by instruction, the M chain in `cybersentinel`. A dataset needs both from one connection. Re-materialising MB into `cybersentinel` is deterministic and costs a few minutes.

Measured facts that should inform the R1 decision, and which downgrade it from 🔴 to 🟠: feature medians are near-identical between MB6 and M6 (five of eight identical, two within 14%); no single feature separates the sets; time-of-day support overlaps 100%; the events-per-window distribution is indistinguishable (58.67% vs 58.59% single-event); and Monday's density 5.19 is within 2.7% of Tuesday's 5.33. The earlier "5.2 vs 7.8" figure was an aggregation artefact across three days of differing density.

Do **not** build a dataset, split, sample, balance, weight, or train until items 1–4 are decided.

## NEXT DECISION

MB1 through MB4 are complete and verified. 368,202 Monday events are persisted, identity-bound to MB3, and provably reproducible.

The next implementation step, **after explicit approval**, is **MB-LABEL**:

1. reuse **M5 v1 unchanged** — the `monday-benign-reference` rule uses `any_network`, so no policy correction and no MB-specific policy is needed;
2. reuse `ExactTimeLabelAdapterV2` unchanged, because `LabelLedger.assign()` is datetime-typed and cannot consume `FlowEndV2` directly;
3. label as a **sidecar**: never add a field to `FeatureWindowV2`, never write into `mb6_canonical.feature_windows`; a live test forbids the former;
4. expect the **R8** outcome: `benign_reference` for events inside 12:00:00Z→20:01:00Z, `unknown` outside it, and **never** convert `unknown` to `benign` to reach a round number;
5. run a read-only preview first and report the disposition histogram before materializing anything.

### Ratifications owed before MB-LABEL

- **R1, the day-level confounder** — still the gating scientific decision, and now the last one standing before a dataset becomes technically possible. MB6 produced 70,921 benign-day windows against M6's 172,748 attack-day windows; the moment those are unioned, day and class are perfectly correlated. **This must be decided before the dataset, not after.**
- **Database location** — MB4 and MB6 both live in `cybersentinel_test` by instruction. Nothing was moved. The ML dataset needs M6 and MB6 reachable from one connection, so either both MB milestones are re-materialized into `cybersentinel` (deterministic, roughly 2 minutes total, loses nothing), or the dataset step reads two databases. Decide before the dataset step.
- **Window-count asymmetry** — 70,921 MB6 windows for 368,202 events (5.2 events/window) versus 172,748 M6 windows for 1,353,467 events (7.8 events/window). The entity/window density differs materially between Monday and the attack days. This is an input to the R1 mitigation choice, not a defect.

Do **not** jump to dataset creation or model training.

## Non-negotiable isolation constraints

A new agent must treat these as invariants, not preferences:

1. Never modify M1, M2, M3 v1/v2, M4, M5 v1/v2, or M6 — code, manifests, reports, or hashes.
2. Never write anything into `artifacts/canonical/cicids2017/m2/` — it must stay at exactly 95 files.
3. Never modify the `zeek-replay` compose service.
4. Never point an MB `/output` at an M path, or an M `/output` at an MB path.
5. Never create a foreign key from `mb4_canonical` / `mb6_canonical` into `m4_canonical` / `m6_canonical`.
6. Never reuse the M3 v2 namespace `f7dad188-04cb-5859-81a0-014329de2899` or the M6 namespace `f787c08a-290e-5b79-a8cb-5bc19ae633dc`.
7. Never convert `unknown` or `ambiguous` into `benign`.
8. Never put a label field inside `FeatureWindow` or `FeatureWindowV2` — a live test forbids it.
9. Never let M and MB converge before dataset construction, and then only by read-only selection.
10. Run every PostgreSQL integration test against `cybersentinel_test`, never production tables.

---

## Minimal synchronization set for a new chat

A future session should read **at most** these files to synchronize:

1. **`docs/PROJECT_INDEX.md`** (this file) — always read first
2. **`docs/canonical/M3_READINESS.md`** — only if working on M3
3. **`docs/canonical/TECHNICAL_DEBT.md`** — only if resolving debt

Everything else is reference material retrieved on demand.

> **Note for a new agent**: `docs/canonical/M3_READINESS.md` may still describe M3 v2 as awaiting artifact publication. That is stale. M3 v2, M4, and M6 are all complete and published; this index is authoritative.
