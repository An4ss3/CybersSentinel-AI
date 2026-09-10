# CyberSentinel

CyberSentinel contains two deliberately preserved tracks:

- a frozen legacy ML/API/dashboard proof of concept used for comparison, reproduction, and demonstration;
- a canonical evidence and data-contract track built incrementally from immutable CICIDS2017 packet evidence.

`docs/PROJECT_INDEX.md` is the authoritative status index. This file summarises it.

---

## Current scientific status — September 2026

This section is the entry point for the current state. The historical July and
August record is preserved unchanged below it.

### Which work carries the scientific claim

**CORE PFA SCIENTIFIC TRACK.** The seven priority attack families and the
pre-registered leave-one-family-out transfer evaluation constitute the main
scientific evidence of this PFA. Their supporting artifacts are the M5 v3 label
correction, the Thursday independent capture used as the conservative benign
control, the frozen pre-registration protocol and the transfer results reported
below.

**SECONDARY / EXPLORATORY ARM F / Ares TRACK.** The ARM F and Ares experiments —
the payload-content benchmarks, ARM F ratification, Phase 2 tuning, temporal
persistence and the zero-day Ares protocols of the five-step final validation —
are retained as secondary methodological and exploratory work. They concern
`botnet/ares`, a single non-priority family that is excluded from the transfer
experiment, and they are **not the primary basis for this PFA's generalisation
claim**. They are preserved because they establish a methodological point about
the feature budget, and because their negative results are part of the record.

### Canonical scientific pipeline

```text
PCAP evidence (frozen, digest-pinned)
  → Zeek 8.0.9 deterministic replay
  → M3 v2 exact-time normalization (DECIMAL(38,22))
  → canonical FlowEndV2 events
  → 60-second tumbling windows on event_start_time
  → sidecar labeling (M5 ledger, applied without mutating events)
  → supervised ML dataset
  → pre-registered evaluation, frozen before the holdout is opened
```

### Dataset correction — M5 v3

A read-only coverage audit established that three Wednesday DoS families were
described by the frozen M5 v1 ledger but matched nothing, because their declared
attacker `205.174.165.73` never appears as a source in the canonical events while
the observable NAT gateway `172.16.0.1` does. Their windows had therefore stayed
`unknown`. **M5 v3** extends the attacker realignment to those three rules:

- `dos/slowloris`
- `dos/slowhttptest`
- `dos/goldeneye`

Verified consequence, published in `artifacts/production/ml_dataset_v2/`:
**464 attack windows and 68 attack episodes**, up from 376 and 54, over the same
9 attack entities. 88 windows changed disposition, every one of them from
`unknown` to an attack disposition; no window ever moved towards benign.

The two datasets are distinct and both preserved. **Production Finale v1**
(`artifacts/production/ml_dataset_v1/`) remains the dataset of record for every
experiment published before 27 August, with its 70,954 rows. **Production Finale
v2** (`artifacts/production/ml_dataset_v2/`) applies M5 v3 and totals 71,042 rows.
M5 v1 and M5 v2 are not modified.

### Thursday track — independent capture

Thursday was the only CICIDS2017 working-hours capture never entered into the
canonical chain. It is now frozen and replayed additively.

| Stage | Result |
|---|---|
| TH1 evidence freeze | `Thursday-WorkingHours.pcap`, 8,302,500,180 bytes, SHA-256 `38f8b1bb…`, cross-checked against the publisher MD5 |
| TH2 replay | Zeek 8.0.9 digest-pinned, dedicated `zeek-replay-th` service, isolated `th2` tree |
| `conn.log` records | **363,788** |
| M3 v2 admission contract | **357,563 admitted**, **6,225 rejected** |
| M6-compatible windows | **55,759 definitive Thursday windows** |
| Conservative negatives | **32,813 `benign_reference` windows** |

TH2 produces 363,788 `conn.log` records. The M3 v2 admission contract accepts
357,563 and rejects 6,225. Under the M6-compatible 60-second `event_start_time`
windowing protocol, these produce 55,759 Thursday windows. Of these, 32,813
satisfy the conservative `benign_reference` policy and constitute the frozen
negative holdout.

An earlier figure of 64,197 appears in `scripts/audit_thursday_replay.py`. It is
the **exploratory audit candidate count**, based on `ts + duration` as the
windowing basis and applying no admission contract. It is not the number of
Thursday windows and must not be quoted as such.

Negative population, exactly:

```text
55,759  definitive Thursday windows
 −  123  known_other_attack   (web brute force 79, XSS 41, SQL injection 3)
 − 22,823  unknown            (17,615 inside a declared attack interval;
                               5,155 compromised hosts .8 and .25, whole capture;
                                  50 gateway → web server;
                                   3 declared-attacker endpoint)
 = 32,813  benign_reference
```

`unknown` and `ambiguous` windows were **excluded, never converted to benign**.
Uncertainty is removed from the denominator rather than absorbed into it, which
makes the reported false-positive rate conservative. The frozen negative
population is `artifacts/production/thursday_audit_v1/thursday_benign_windows.csv`,
SHA-256 `9cd046d46829ac9ef67fbd1df6d40dcd75fc1236c04cf433eceecf60abd278f9`.

The two Thursday Infiltration rules were deliberately **not** labelled:
`infiltration-mac` matched zero flows, and `infiltration-vista` shows traffic
sourced by eight internal hosts, which contradicts the declared attacker. No
label was forced.

### Pre-registered transfer experiment

Seven leave-one-family-out folds over the priority families: **FTP-Patator,
SSH-Patator, DoS Hulk, DoS Slowloris, DoS SlowHTTPTest, DoS GoldenEye and
DDoS LOIT**. `botnet/ares` and the Thursday web families are out of scope and
contribute to no population.

Protocol discipline, all machine-checkable:

- the threshold was calibrated on a benign validation partition that is
  **entity-disjoint from the benign training partition** (Monday entity fold 4
  against folds 0–3);
- the model and the threshold were **frozen before the holdout was opened**; all
  seven freeze records were written with `holdout_opened: false`;
- the Thursday `benign_reference` population was used **only** as the frozen
  negative control population, never for calibration or selection;
- hyperparameters are P1's, adopted unchanged, with no tuning and no model
  comparison.

### Transfer results

| Family | Episodes | Windows | Thursday FPR |
|---|---:|---:|---:|
| FTP-Patator | 1/1 | 61/61 | 0.366 % |
| SSH-Patator | **1/9** | **9/60** | 0.576 % |
| DoS Hulk | 2/2 | 35/36 | 0.357 % |
| DoS Slowloris | 2/2 | 43/46 | 0.375 % |
| DoS SlowHTTPTest | 7/8 | 21/26 | 0.570 % |
| DoS GoldenEye | 4/4 | 13/16 | 0.494 % |
| DDoS LOIT | 2/2 | 42/42 | 0.643 % |

Pooled: **19 of 28 held-out episodes were detected**, Wilson 95 % interval
**[0.493388, 0.820668]**. The 28 episodes are not independent statistical
replicates, since the folds share entity structure and a common benign
calibration framework.

### Interpretation

Six families fall in the pre-registered category *results compatible with
transfer*: FTP-Patator, Hulk, Slowloris, SlowHTTPTest, GoldenEye and DDoS LOIT.
**SSH-Patator is limited and inconclusive**, detecting 1 of 9 episodes with a
near-chance ROC-AUC of 0.5859, and it is retained as a visible counterexample. No
family shows an absence of evidence.

**All seven Thursday false-positive rates remain below 1 %**, in the range
0.357 % to 0.643 %, inside the pre-registered 2 % ceiling and below the 1 %
calibration target.

This is **preliminary evidence of cross-family transfer on frozen CICIDS2017
evidence, not proof of universal IDS generalisation.**

### Scientific limitations of the transfer experiment

1. The experiment is **not entity-disjoint as a whole**; entity-disjointness holds
   only between the benign training and validation partitions.
2. The priority families share the same source and victim IP structure: four
   entity keys, one attacker IP, one victim IP, differing only by service.
3. Thursday shares **three of the four** priority entity keys, so it is an
   independent capture and day, not independent infrastructure.
4. Only **28 held-out episodes** in total.
5. Several families have very few episodes: five of seven have four or fewer.
6. **FTP-Patator has a single episode**; its 1/1 result must not be generalised.
7. Thursday contains **no priority-family positive**, so it serves only as a
   negative control.
8. `unknown` and `ambiguous` Thursday windows were excluded rather than treated as
   benign.
9. This is CICIDS2017, a synthetic 2017 environment, not production traffic.
10. **No new-infrastructure generalisation** is claimed or supported.
11. **No universal or general-purpose IDS performance** is claimed or supported.

### September documentation map

| Document | Contents |
|---|---|
| [Transfer experiment report](docs/canonical/TRANSFER_EXPERIMENT_REPORT.md) | full scientific report of the seven-fold experiment |
| [Pre-registration protocol](docs/canonical/PROTOCOL_PREREGISTRATION_V1.md) | protocol frozen before any holdout was opened |
| `artifacts/production/ml_dataset_v2/LABEL_COVERAGE_REPORT.md` | M5 v3 correction, before and after |
| `artifacts/production/ml_dataset_v2/label_policy_v3.json` | per-rule diff and additivity proof of M5 v3 |
| `artifacts/production/thursday_audit_v1/THURSDAY_WINDOW_LABEL_AUDIT.json` | Thursday windows, dispositions and exclusion counts |
| `artifacts/canonical/cicids2017/th2/thursday_replay_audit.json` | Thursday NAT resolution from observed traffic |
| `artifacts/experiments/final_validation/FINAL_VALIDATION_REPORT.md` | five-step final validation, ARM F secondary track |

---

## Authoritative milestone status

### Attack chain (Tuesday, Wednesday, Friday)

| Milestone | Status | Evidence |
|---|---|---|
| M1 — PCAP acquisition and dataset freeze | Complete and frozen | `artifacts/canonical/cicids2017/m1/dataset_freeze_verification.json` |
| M2 — deterministic Zeek replay | Complete and frozen | three `replay_run.json`; 1,380,057 `conn.log` records |
| M3 v1 — microsecond Zeek normalization | Executed and verified, then superseded; preserved unchanged | `artifacts/reports/cicids2017_m3_step2_normalization.json` |
| M3 v2 — exact-time Zeek normalization | **Complete and frozen** | `artifacts/reports/m3_v2_normalization_run.json`; 1,353,467 accepted, 26,590 rejected |
| M4 — canonical event persistence | **Complete and frozen** | `artifacts/reports/m4_v2_materialization_run.json`; 1,353,467 events persisted |
| M5 — sidecar label ledger (v1) | Complete and frozen | `datasets/manifests/cicids2017_labels.yaml`; 16 rules, 45 intervals, 0 overlaps |
| M5 v2 — observable-attacker policy | Complete, additive; v1 untouched | `docs/PROJECT_INDEX.md` |
| M6 — canonical feature windows | **Complete and frozen** | `artifacts/reports/m6_v2_feature_window_run.json`; 172,748 windows |
| Label materialization on the main chain | **Complete, out of band** | `artifacts/production/ml_dataset_v1/label_materialization_report.json`; 172,748 window labels, no `m7_*` schema, zero PostgreSQL writes |

### Monday-benign reference chain

| Milestone | Status | Evidence |
|---|---|---|
| MB1 — Monday benign freeze | Complete and frozen | `artifacts/canonical/cicids2017/mb1/dataset_freeze_verification.json` |
| MB2 — Monday benign Zeek replay | Executed and verified | `replay_run.json`; 375,432 `conn.log` records |
| MB3 — exact-time normalization | Executed and verified | 368,202 accepted, 7,230 rejected |
| MB4 — canonical persistence | Executed and verified | 368,202 events in `cybersentinel_test` |
| MB5 | Deliberately does not exist | the MB track reuses frozen M5 v1 |
| MB6 — feature windows | Executed and verified | 70,921 windows |
| MB7 / MB-LABEL — sidecar labeling | Executed and verified | 70,578 `benign_reference` window labels |

### Supervised experiments

P1–P6, the one-feature XGBoost baseline, the four-arm A–D feature benchmark, the six-arm payload-content benchmark, ARM F ratification, and the leak-free Phase 2 ARM F tuning experiment are executed and verified under `artifacts/experiments/`. Their identities are pinned by per-experiment manifests. The final Phase 1 feature budget is ARM F (`distinct_payload_ratio` plus source/destination non-printable ratios). Phase 2 selected the smaller R006 XGBoost model on known-family surrogate validation, but its one-shot Ares transfer did not improve episode recall; the frozen Phase 1 ARM F model remains the general reference.

An additive ARM F temporal-persistence experiment is also published under `artifacts/experiments/temporal_persistence/`. Its pre-registered rule selected the highest admissible persistence threshold, which left the additive branch inactive: Ares stayed at 21/40 episodes and the window false-positive count stayed at 99/13,774. It is preserved as a negative methodological result.

### Production Finale v1

| Item | Status | Evidence |
|---|---|---|
| Canonical supervised ML dataset | **Published and frozen** | `artifacts/production/ml_dataset_v1/`; 70,954 rows = 376 attack + 70,578 benign |
| M-chain window labels | **Materialised out of band** | `window_labels.csv`; 172,748 windows, 199 `target_attack` + 177 `known_other_attack` + 172,372 `unknown` |
| Label policy | Ratified | attack → 1, `benign_reference` → 0, `unknown` and `ambiguous` **excluded, never negative** |
| Feature budget | VOL5, five volume features in canonical order | `p1_dataset.FEATURE_NAMES` |
| Parity | Byte-identical to the ratified P1 population | `ml_dataset.csv` = `e95aed008d994510e4c649c287feb8fe8f49a785bec144d7e83aa15804b6c062` |

No `m7_*` schema was created and PostgreSQL received zero writes.

### Final scientific validation

Five additive steps are published under `artifacts/experiments/final_validation/`, with `FINAL_VALIDATION_REPORT.md` generated from the artifacts and gated by 61 cross-artifact consistency checks.

| Protocol | Question | Headline result |
|---|---|---|
| **A** | family novelty; deterministic reimplementation, **not** a reproduction of P1 | 9/54 episodes |
| **B** | entity novelty, entity-disjoint on all 9 folds | 46/54 episodes |
| **C Ares** | episode novelty inside a known family | 40/40 episodes |
| **D1 / D2** | zero-day Ares, re-fitted / frozen-model anchor | 3/40 both; D2 reproduces the published stream exactly |
| **A′** | shared-entity removal diagnostic, no causal attribution | heterogeneous across folds 2–4 |
| **VOL5 vs ARM F** | feature-budget effect at constant learner | zero-day: VOL5 **0/40**, ARM F **21/40** |

Two findings matter. With the family present in training, VOL5 detects Ares almost perfectly even under strict entity-disjointness. With the family absent, VOL5 collapses to chance while the ARM F content budget reaches ROC-AUC 0.9713 and 21/40 episodes at a comparable false-positive rate. The observed ceiling was therefore both a family-transfer limit and a representational limit of the volume features. The zero-day evidence rests on a single family, 40 episodes and 5 entities, and is not a generalisation claim.

## Frozen and current identities

| Item | Formatting-independent identity |
|---|---|
| M1 dataset manifest | `feab8d4fbd8454cd12723368704e1e7311853a4316efec7f94bf11726ebb984e` |
| M2 replay specification | `e52c183a315c1ac38cbf1e64155489f5f041e95aa5d2e5cbb82e31f03ac4c455` |
| M2 published tree fingerprint | `22df7f5a0e3b1ff42b0dad45090fce3647fc1640013401b806d416da5656fcb5` |
| M3 v1 protocol | `99ab724a3d245a352e888e2f4771b5a354b5855180af4a72c36980c9296897d4` |
| M3 v2 protocol, authoritative after consistency repair | `5286ddde937ad132afdeb8814e0e0af01745afbb7d1d446ae8860b7701fea210` |
| P1 frozen population `p1_dataset.csv` | `e95aed008d994510e4c649c287feb8fe8f49a785bec144d7e83aa15804b6c062` |
| P1 frozen folds `p1_folds.json` | `57e688fd3da90911707d7a172c161686d852094121eda1ac49e0221fc0529fa1` |
| Four-arm feature benchmark manifest | `2b6e65e658297dd1d96d3f4d3afce9798a5cf9e99279a70253dbbb022315af88` |

The pre-repair M3 v2 identity `617298f5dfa0940cbf1f0c1d1a5730e8ee83c43160c29b4b2bfb9e6fc56914d4` is retained only as audit history. It is not the current protocol identity.

## Architectural boundary

```text
Frozen M1 PCAP evidence
        ↓ digest-pinned Zeek 8.0.9 replay
Frozen M2 conn.log + replay_run.json
        ↓ StrictZeekJsonLineParserV2
raw sensor record or explicit rejection
        ↓ M3 v2 exact-time normalization
FlowEndV2 or explicit rejection
        ↓ M4 canonical persistence
1,353,467 persisted events
        ↓ M6 windowing
172,748 canonical feature windows
        ↓ M5 sidecar label ledger, applied without mutating events
P1 supervised population, 70,954 windows
```

Label materialization on the main chain is complete **out of band**, as files under `artifacts/production/ml_dataset_v1/`. No `m7_*` schema exists and PostgreSQL received zero writes. The canonical supervised ML dataset is published there and is byte-identical to the ratified P1 population.

## Repository and data layout

The raw CICIDS2017 captures (~49 GB) and the ~2.2 GB of frozen Zeek replay logs are **not** tracked in Git. Their identity is preserved by the frozen manifests and, for M2, by the published tree fingerprint; the logs are regenerable byte-for-byte from the digest-pinned Zeek image. Data contracts under `datasets/manifests/` and all experimental evidence under `artifacts/experiments/` and `artifacts/reports/` **are** tracked.

End-of-line conversion is disabled in `.gitattributes`. This is deliberate: project integrity rests on SHA-256 digests over exact file bytes, and any normalisation would silently invalidate every published identity.

## Documentation

- [Authoritative project index](docs/PROJECT_INDEX.md)
- [Development history and current state](docs/CYBERSENTINEL_DEVELOPMENT_HISTORY.md)
- [M2 summary](docs/canonical/M2_SUMMARY.md)
- [M2 frozen verification](docs/canonical/M2_VERIFICATION.md)
- [M3 v2 status and continuation boundary](docs/canonical/M3_READINESS.md)
- [M3 v2 synchronization record](docs/canonical/M3_V2_SYNCHRONIZATION.md)
- [Technical debt](docs/canonical/TECHNICAL_DEBT.md)
- [Historical July progress report](docs/archive/PROGRESS_REPORT_2026-07-08.md)

`docs/canonical/M3_READINESS.md` and `docs/canonical/M3_V2_SYNCHRONIZATION.md` were written before M3 v2, M4 and M6 were executed. They are preserved as audit history and are superseded in fact by the verified run reports listed above.

## Preservation policy

Do not regenerate, overwrite, or reinterpret frozen M1–M6 or MB artifacts, the P1–P6 experiments, the published XGBoost baseline, or the four-arm feature benchmark. The superseded M3 v1 protocol and report also remain preserved for audit. New work must be additive, must not modify a frozen population, fold assignment, threshold rule, or published metric, and must not be described as complete until it has produced independently verified evidence.
