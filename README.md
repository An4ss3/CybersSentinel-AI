# CyberSentinel

CyberSentinel contains two deliberately preserved tracks:

- a frozen legacy ML/API/dashboard proof of concept used for comparison, reproduction, and demonstration;
- a canonical evidence and data-contract track built incrementally from immutable CICIDS2017 packet evidence.

`docs/PROJECT_INDEX.md` is the authoritative status index. This file summarises it.

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
| Label materialization on the main chain | **Not implemented** | — |

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

P1–P6, the one-feature XGBoost baseline, and the four-arm A–D feature benchmark are executed, verified, and frozen under `artifacts/experiments/`. Their identities are pinned by per-experiment manifests. A first-wave payload-content feature extraction (arms A/E/F/G/H/I) is in progress and is strictly additive.

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

Label materialization on the main chain and any ML dataset beyond the P1 population are **not implemented**. No package export implies that either exists.

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
