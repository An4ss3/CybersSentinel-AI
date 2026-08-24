# CyberSentinel — Development History

## Purpose

Historical narrative of the project's scientific evolution: legacy experiments, findings, architectural decisions, and the canonical-track milestones in chronological order.

## Authoritative scope

History and scientific rationale only. For current status, identities, and architecture, see [PROJECT_INDEX.md](PROJECT_INDEX.md). For M3 implementation state, see [canonical/M3_READINESS.md](canonical/M3_READINESS.md).

## Related documents

- [Project index](PROJECT_INDEX.md)
- [M3 v2 status](canonical/M3_READINESS.md)
- [Technical debt](canonical/TECHNICAL_DEBT.md)

---

# Part 1 — Existing Completed Work and Current Project State

## 1. Current Project State

CyberSentinel is **not a new project starting from an empty repository**. It is an existing, working proof-of-concept whose software integration, legacy machine-learning experiments, evaluation artifacts, and dashboard stack remain valuable. The current work is a scientific continuation: it preserves the functioning MVP and adds a more defensible data and evaluation path alongside it.

The repository currently contains two coexisting tracks:

1. a **frozen legacy track**, which remains executable for comparison, reproduction, demonstration, and historical benchmarking;
2. an emerging **canonical track**, which now includes strict event contracts, the completed sidecar label ledger, completed and frozen M1 packet evidence, completed and frozen M2 Zeek replay, preserved M3 v1 audit evidence, and synchronized but partial M3 v2 contracts. It has not replaced the legacy runtime.

The central engineering principle is therefore:

> Extend the project without erasing its history, breaking its current demonstration, or pretending that unimplemented canonical milestones already exist.

### 1.1 Current repository and runtime foundation

The existing software foundation is:

- Python detection and evaluation code;
- XGBoost binary classifiers;
- FastAPI scoring API;
- PostgreSQL alert and asset schema;
- Redis service intended for future stream processing;
- Elasticsearch and Kibana services;
- Grafana dashboards;
- Docker Compose infrastructure;
- offline alert-generation and reporting scripts;
- legacy CICIDS2017 MachineLearningCVE data and artifacts;
- a strict canonical schema foundation;
- a completed M5 sidecar label ledger;
- a completed and frozen M1 freeze of the official Tuesday, Wednesday, and Friday CICIDS2017 PCAP evidence;
- a completed and frozen M2 deterministic Zeek replay;
- a preserved, superseded M3 v1 full-run report;
- synchronized M3 v2 exact-time contracts, parser, lineage binding, exports, and tests, without a concrete v2 normalizer or runner.

The main repository areas are:

```text
modules/
├── backend/
│   ├── app/
│   │   ├── main.py
│   │   ├── predictor.py
│   │   ├── schemas.py
│   │   ├── scoring.py
│   │   └── db.py
│   └── tests/
├── detection/
│   ├── config.yaml
│   ├── requirements.txt
│   ├── src/
│   │   ├── data_loader.py
│   │   ├── train.py
│   │   ├── cross_variant_cv.py
│   │   ├── threshold_analysis.py
│   │   ├── contracts/
│   │   ├── schemas/
│   │   ├── lineage/
│   │   ├── ingestion/
│   │   ├── normalization/
│   │   └── feature_engineering/
│   └── tests/
└── storage/
    └── schema.sql

scripts/
infra/
datasets/
models/
artifacts/
docs/
docker-compose.yml
```

### 1.2 Original CyberSentinel MVP architecture

The original MVP demonstrated an end-to-end integration path:

```text
CICIDS2017 MachineLearningCVE flow CSVs
        ↓
Legacy preprocessing and binary target creation
        ↓
XGBoost brute-force and DoS/DDoS classifiers
        ↓
FastAPI / offline batch scoring
        ↓
Composite risk score
        ↓
Alert generation
        ↓
PostgreSQL or JSONL fallback
        ↓
Grafana dashboard
```

Docker Compose provides the surrounding infrastructure:

```text
Elasticsearch ── Kibana
PostgreSQL    ── Grafana
Redis
```

This foundation is a legitimate proof-of-concept. Its limitations concern scientific interpretation, provenance, continuous telemetry, strict contracts, and deployment readiness—not the fact that the integration exists.

### 1.3 Existing CICIDS2017 MachineLearningCVE pipeline

The populated dataset directory contains CICIDS2017 MachineLearningCVE CSV files. A read-only audit counted:

| Label | Rows |
|---|---:|
| BENIGN | 2,273,097 |
| FTP-Patator | 7,938 |
| SSH-Patator | 5,897 |
| DDoS | 128,027 |
| DoS Hulk | 231,073 |
| DoS GoldenEye | 10,293 |
| DoS slowloris | 5,796 |
| DoS Slowhttptest | 5,499 |
| **Total** | **2,830,743** |

`modules/detection/src/data_loader.py` performs the legacy loading path:

1. concatenates configured CSV files;
2. strips column names;
3. detects and extracts labels;
4. coerces feature columns to numeric;
5. replaces infinities with missing values;
6. fills missing values with zero;
7. calculates global column cardinality;
8. removes globally constant columns.

`modules/detection/src/train.py` then:

1. selects benign plus one target family;
2. downsamples benign traffic to at most 200,000 rows;
3. excludes every non-target attack family;
4. applies a random or attack-variant split;
5. applies SMOTE after the split;
6. trains fixed-parameter XGBoost;
7. evaluates at threshold `0.5`;
8. exports global mean-absolute SHAP feature importance;
9. stores a joblib bundle.

The current legacy bundle contains only:

```text
model
features
attack
protocol
```

Each current model uses 68 features.

### 1.4 Existing XGBoost models

The model directory includes historical, random, holdout, and production-named artifacts:

```text
models/xgboost_brute_force_v1.joblib
models/xgboost_brute_force_random.joblib
models/xgboost_brute_force_holdout.joblib
models/xgboost_brute_force_production.joblib
models/xgboost_ddos_v1.joblib
models/xgboost_ddos_random.joblib
models/xgboost_ddos_holdout.joblib
models/xgboost_ddos_production.joblib
```

Two broad attack families are represented:

- `brute_force`: FTP-Patator and SSH-Patator;
- `ddos`: Friday DDoS plus Wednesday DoS variants.

The second family is heterogeneous. It combines distributed volumetric DDoS, fast application DoS, and slow application resource-exhaustion behavior.

A read-only raw-booster comparison established that the `production` artifacts are identical to the `random` artifacts. The cause is visible in `train.py`:

```python
if protocol in ("random", "production"):
    X_train, X_test, y_train, y_test = split_random(...)
```

Therefore, the word `production` currently identifies an artifact/report role, not a distinct production-training methodology. This finding does not delete those artifacts; it corrects how they must be described.

### 1.5 Random split experiments already completed

The project already implemented random row-level experiments. They produced near-perfect results:

| Model family | Approximate recall |
|---|---:|
| Brute force | 0.9993 |
| DoS/DDoS | 0.9998 |

These experiments remain useful as historical upper-bound baselines. They prove that XGBoost can separate randomly partitioned CICIDS2017 flow rows under the legacy preprocessing protocol.

They do **not** prove future-campaign, independent-capture, live-network, or UM6P performance because related rows may occur in both partitions.

### 1.6 Cross-variant holdout already implemented

The repository also contains a cross-variant holdout protocol:

- train on SSH and test on FTP for brute force;
- train on Wednesday DoS and test on Friday DDoS for the combined family.

The resulting recall collapsed:

| Experiment | Recall at threshold 0.5 |
|---|---:|
| SSH → FTP | approximately 0.3090 |
| Wednesday DoS → Friday DDoS | approximately 0.0002 |

This was an important contribution: it demonstrated that the random results did not transfer across important attack variants.

The protocol is accurately described as **attack-variant-disjoint**. It is not fully leakage-free because benign rows were randomly partitioned from pooled multi-day traffic, and the CSVs do not permit host, campaign, session, or temporal grouping.

### 1.7 Leave-one-variant-out evaluation already implemented

`modules/detection/src/cross_variant_cv.py` implements leave-one-variant-out evaluation. Historical mean recalls are:

| Family | Mean held-out recall |
|---|---:|
| Brute force | approximately 0.1552 |
| DoS/DDoS | approximately 0.4603 |

LOVO remains a valuable open-set stress experiment. It should not be described as direct evaluation of the persisted production-named bundle because each fold trains a separate all-but-one-variant model.

### 1.8 Threshold experiments already completed

`modules/detection/src/threshold_analysis.py` performs threshold sweeps over the holdout predictions and reports best-F1 and target-recall operating points.

The decisive corrected result is:

| Threshold | Approximate brute-force holdout recall |
|---|---:|
| 0.5 | 0.309 |
| 0.1 | 0.309 |
| 0.01 | 0.3103 |
| approximately `3.59613e-05` | 0.9569 |

The earlier assumption that threshold `0.01` recovered approximately 96% recall was incorrect. The real threshold was approximately `3.59613e-05`, which appeared as `0.0` because threshold reports rounded to four decimal places. At that extreme threshold, the experiment generated 952 false positives.

Furthermore, that threshold was selected by sweeping the same holdout labels used for evaluation. The apparent 96% recall is therefore:

- an exploratory property of one holdout score distribution;
- obtained by test-set optimization;
- associated with a large false-positive cost;
- not evidence of true cross-variant generalization;
- not an unbiased calibration result;
- not a deployment threshold.

The cross-variant problem remains.

### 1.9 PR curves and confusion matrices already produced

The repository contains:

- brute-force and DoS/DDoS PR curves;
- random and holdout confusion matrices;
- threshold-analysis JSON reports;
- recall-comparison figures;
- per-variant LOVO figures.

Important files include:

```text
artifacts/reports/brute_force_pr_curve_holdout.png
artifacts/reports/ddos_pr_curve_holdout.png
artifacts/reports/brute_force_threshold_analysis_holdout.json
artifacts/reports/ddos_threshold_analysis_holdout.json
artifacts/reports/figures/confusion_matrices.png
artifacts/reports/figures/recall_comparison.png
artifacts/reports/figures/lovo_recall.png
```

A high PR-AUC did not imply a useful threshold. Ranking can remain good while probabilities collapse near zero, leaving poor recall at any operationally tolerable threshold.

### 1.10 Existing SHAP, alert, and dashboard artifacts

The training code exports global mean-absolute SHAP rankings. These are valid global model summaries. They are not local explanations of individual alerts.

`scripts/generate_alerts.py` demonstrates the integration loop by sampling legacy CSV rows, scoring them, computing the composite score, and writing alerts to PostgreSQL or JSONL.

Historical evidence includes a run that reportedly generated 4,291 PostgreSQL alerts. The current live database could not be reverified because Docker Desktop's Linux engine was unavailable during the frozen audit. The repository's JSONL file contained 266 stale holdout alerts at that time:

- 259 brute-force alerts;
- 7 DoS/DDoS alerts.

The Grafana dashboard and report figures remain useful demonstration artifacts. Their risk distributions must be described as synthetic because alert generation assigned random asset criticality and hardcoded CVE severity to zero.

### 1.11 Current FastAPI architecture

FastAPI remains implemented under `modules/backend/app/`.

Current components include:

- `main.py`: application and routes;
- `predictor.py`: legacy model discovery and inference;
- `schemas.py`: request/response models;
- `scoring.py`: composite risk calculation and level mapping;
- `db.py`: PostgreSQL insertion.

The existing `/score` route remains a working legacy demonstration. Its Predictor silently fills missing model features with zero and ignores unknown fields. That behavior is scientifically weak for the canonical path, but it is preserved unchanged until a future additive v2 API is separately approved.

### 1.12 Current PostgreSQL, Redis, Elasticsearch, Kibana, Grafana, and Compose architecture

The current Compose stack defines:

- PostgreSQL;
- Redis;
- Elasticsearch;
- Kibana;
- Grafana.

PostgreSQL contains a useful prototype schema for alerts, assets, threat intelligence, and audit data. The current insertion path does not yet populate all available provenance fields.

Redis and Elasticsearch are provisioned but are not used by the inspected legacy Python runtime. This does not justify removing them: they remain the approved transport and investigation foundations for later integration.

Grafana remains the operational dashboard. Existing queries require later correction to use `$__timeFilter(detected_at)`, and datasource credentials must be aligned with environment configuration.

Docker Compose remains the local infrastructure foundation. It is not evidence of production availability, and the current application code is not yet containerized as a complete sensor-to-alert runtime.

### 1.13 Existing tests and infrastructure validation

Before canonical work, four backend tests passed:

```text
score bounds
level thresholds
escalation behavior
FastAPI scoring smoke test
```

Compose syntax validated successfully with:

```text
docker compose config --quiet
```

The Docker daemon was unavailable for current live service verification.

### 1.14 Completed strict canonical data foundation

The project has already added a strict Phase 1 data foundation under `modules/detection/src/`:

```text
contracts/
ingestion/
normalization/
feature_engineering/
schemas/
lineage/
```

Implemented Pydantic models include:

- `NetworkEvent`;
- `FlowStart`;
- `FlowUpdate`;
- `FlowEnd`;
- `SignatureEvent`;
- `SensorHealthEvent`;
- `FeatureWindow`;
- `EventProvenance`;
- four-part version contracts.

All canonical models are strict and immutable:

- unknown fields are forbidden;
- silent type coercion is disabled;
- NaN and infinity are rejected;
- UTC-aware timestamps are mandatory;
- temporal ordering is validated;
- missing nullable fields must still be explicitly present;
- numeric IP representations are rejected rather than silently converted.

The abstract-only interfaces `ZeekAdapter`, `SuricataAdapter`, and `EventNormalizer` also exist. No concrete parsing was added in this phase.

The final Phase 1 test state was:

```text
55 new data-foundation tests passed
59 total tests passed including the existing backend suite
```

### 1.15 Completed M5 sidecar label ledger

M5 was explicitly implemented ahead of M1–M4 at the user's direction. It was the first numbered roadmap milestone completed chronologically; M1 was subsequently implemented through the approved acquisition-and-freeze workflow.

Implemented files include:

```text
modules/detection/src/schemas/labels.py
modules/detection/src/lineage/labeling.py
modules/detection/src/lineage/label_reports.py
datasets/manifests/cicids2017_labels.yaml
scripts/audit_label_manifest.py
```

The label ontology is:

```text
target_attack
known_other_attack
benign_reference
unknown
ambiguous
```

The final manifest contains:

```text
16 rules
45 official schedule intervals
5 target rules
10 known-other rules
1 explicit benign-reference rule
0 role-compatible overlaps
58,560 scheduled seconds
```

Final manifest hash:

```text
7ff2e52bf3485929b6a4260a7f4451fbaa8119273500f0b9a27f5a1c5b48c676
```

M5 generated:

```text
artifacts/reports/cicids2017_label_manifest_coverage.json
artifacts/reports/cicids2017_label_manifest_ambiguity.json
```

The reports explicitly state that they cover the manifest schedule, not canonical event rows, because M3/M4 event partitions do not yet exist.

Final validation state:

```text
48 targeted M5 tests passed
107 full detection and backend tests passed
Independent final review: APPROVED
```

### 1.16 Completed M1 PCAP acquisition and dataset freeze

M1 was completed and validated on 28 July 2026. It froze the primary packet evidence required by the canonical pipeline without starting Zeek replay, packet parsing, canonical event generation, feature engineering, or machine learning.

The evidence was acquired through the official Canadian Institute for Cybersecurity sources:

```text
https://www.unb.ca/cic/datasets/ids-2017.html
https://cicresearch.ca/CICDataset/CIC-IDS-2017/
```

All five downloaded PCAPs were first verified against their publisher-provided MD5 sidecars. Every MD5 matched. The complete locally retained source inventory is:

| Official PCAP | Exact bytes | SHA-256 | M1 disposition |
|---|---:|---|---|
| `Monday-WorkingHours.pcap` | 10,822,507,416 | `f6eac599358f216b074338813a1cf7be3cc4e91d116e13efc0dc71f2cca11972` | retained with official evidence; not selected by the initial manifest |
| `Tuesday-WorkingHours.pcap` | 11,048,283,608 | `080c2250154c5a174c03660ed0f75a3858d41a27511ba716e780d7bcb1ec4c57` | frozen canonical evidence |
| `Wednesday-workingHours.pcap` | 13,420,789,612 | `cd2674db7559a53f24bc03be3239b315700174ccaef72d10f5edc4c1a08f6186` | frozen canonical evidence |
| `Thursday-WorkingHours.pcap` | 8,302,500,180 | `38f8b1bb276849bf1721f7c4de22bebfa7f59a74e52286d4c0a37edbb118fe01` | retained with official evidence; not selected by the initial manifest |
| `Friday-WorkingHours.pcap` | 8,839,309,056 | `beff0dcce1eebc9b2454582f4dc8ed0ba0112b2c619a710bf03af93147254cd0` | frozen canonical evidence |

The approved initial canonical scope is exactly Tuesday (brute force), Wednesday (DoS), and Friday (DDoS). Its manifest-selected inventory contains three files totaling `33,308,382,276` bytes. All five publisher PCAPs and their MD5 sidecars remain together under the official `pcap/` and `md5/` directories. Monday and Thursday remain available for future approved experiments, while selection is controlled exclusively by the immutable dataset freeze manifest rather than by moving or duplicating primary evidence.

M1 added or populated:

```text
modules/detection/src/schemas/datasets.py
modules/detection/src/lineage/dataset_freeze.py
modules/detection/tests/test_dataset_manifest.py
modules/detection/tests/test_dataset_freeze.py
modules/detection/tests/test_dataset_freeze_workflow.py
scripts/freeze_cicids2017_pcaps.py
datasets/manifests/cicids2017_pcap_freeze.yaml
artifacts/canonical/cicids2017/m1/dataset_freeze_verification.json
```

The freeze manifest records the official source, retrieval and freeze timestamps, explicit capture-day selection, exact byte sizes, and SHA-256 values. Its formatting-independent identity is:

```text
feab8d4fbd8454cd12723368704e1e7311853a4316efec7f94bf11726ebb984e
```

The immutable verification report records a successful complete manifest-selected inventory, size, and SHA-256 verification. Unselected official PCAPs may coexist under the evidence root but are never consumed unless a future approved manifest names them. The report content identity is:

```text
e51b72f2f25e49372cdf036b34dc9291a5f563b0fdd3c0b1b36e702e741eafe9
```

Independent manifest reload and byte verification succeeded. Re-running the immutable writers with identical content left artifact timestamps unchanged; replacement with different content is rejected. Final M1 validation produced:

```text
45 focused M1 tests passed, 1 platform-dependent symlink test skipped
152 full detection and backend tests passed, 1 platform-dependent test skipped
Static diagnostics: no issues
```

M1 is therefore **completed**. M2 pinned Zeek replay was completed and frozen on 29 July 2026.

### 1.17 Current status in one diagram

```text
LEGACY TRACK — IMPLEMENTED AND FROZEN

MachineLearningCVE CSV
        ↓
data_loader.py / train.py
        ↓
Random + holdout + LOVO + threshold experiments
        ↓
Current XGBoost artifacts
        ↓
Predictor / FastAPI / batch alert demo
        ↓
PostgreSQL / JSONL / Grafana


CANONICAL TRACK — PARTIALLY IMPLEMENTED

Strict event/version/provenance contracts       ✅ implemented
Abstract adapters and normalizer interfaces      ✅ implemented
M1 PCAP acquisition and dataset freeze            ✅ completed and frozen
M2 pinned deterministic Zeek replay               ✅ completed and frozen
  Step 1 — replay specification/runtime freeze    ✅ completed
  Step 2 — deterministic replay runner            ✅ completed
  Step 3 — three selected PCAP replays             ✅ completed and verified
M3 v1 microsecond normalization                  ✅ executed/verified; superseded and preserved as historical evidence
M3 v2 exact-time contracts/parser/binding          ✅ current active implementation; synchronized and partial
M3 v2 concrete normalizer/runner/verified output   ⏳ not implemented
M4 canonical event persistence                     ⏳ not started
M5 sidecar label ledger                           ✅ implemented
M6–M13 windows, splits, models, reproducibility   ⏳ planned
```

### 1.18 M2 freeze policy

M2 is **FROZEN**. The artifacts under `artifacts/canonical/cicids2017/m2/zeek-8.0.9/` are the canonical replay reference. Future work must never regenerate, replace, or overwrite them unless one of these conditions is intentionally approved:

1. the replay specification changes; or
2. a new dataset version is intentionally introduced.

Any approved future replay must use a new identity and artifact namespace so the existing M2 reference remains preserved. The final inventory and verification evidence are recorded in `docs/canonical/M2_SUMMARY.md` and `docs/canonical/M2_VERIFICATION.md`.

### 1.19 M3 v1-to-v2 chronology and current boundary

M3 v1 protocol identity `99ab724a3d245a352e888e2f4771b5a354b5855180af4a72c36980c9296897d4` implemented private concrete parsing, normalization, and report generation. Its verified full-source report processed 1,380,057 records, accepted 100, and rejected 1,379,957. That result demonstrated that the v1 microsecond temporal representation was incompatible with the exact frozen M2 values. V1 is superseded but remains preserved unchanged as historical audit evidence.

M3 v2 protocol `2.0.0` replaces that temporal representation with exact `DECIMAL(38,22)` seconds and `FlowEndV2`. After the 3 August 2026 repository-wide consistency repair, its authoritative formatting-independent identity is `5286ddde937ad132afdeb8814e0e0af01745afbb7d1d446ae8860b7701fea210`. The earlier identity `617298f5dfa0940cbf1f0c1d1a5730e8ee83c43160c29b4b2bfb9e6fc56914d4` is retained only as pre-repair audit history.

The current active v2 implementation includes exact-time, event, and report contracts; a strict private JSON-line parser; M1/M2 lineage binding; public schema and lineage exports; and focused tests. It does not include a concrete v2 normalizer, runner, persisted event stream, or verified v2 run report. Manifest counts of 1,353,467 expected accepted and 26,590 expected rejected records are analytical projections, not observed output. M3 v2 therefore remains partial and M4 remains not started.

M1 and M2 remain complete and frozen. The synchronized architecture and identity ledger are maintained in `docs/canonical/M3_READINESS.md` and `docs/canonical/M3_V2_SYNCHRONIZATION.md`.

---

## Document Navigation

- [Part 1 — Existing Completed Work and Current Project State](#part-1--existing-completed-work-and-current-project-state)
- [Part 2 — Scientific Findings and Identified Limitations](#part-2--scientific-findings-and-identified-limitations)
- [Part 3 — Architectural Redesign Rationale](#part-3--architectural-redesign-rationale)
- [Part 4 — Continuation Roadmap M1–M13](#part-4--continuation-roadmap-m1m13)

## 2. Frozen Legacy Baseline

The architectural pivot does not invalidate or delete the previous work. The legacy track is preserved for four explicit purposes:

1. **Comparison:** quantify how conclusions change between random row splits and grouped canonical evaluation.
2. **Reproducibility:** preserve the exact experiments and artifacts that produced the initial findings.
3. **Demonstration:** retain a working FastAPI-to-alert-to-dashboard proof-of-concept while canonical work proceeds.
4. **Historical benchmark:** document the project's sc==================================================
IMPLEMENTATION PHILOSOPHY
==================================================

For every milestone, always prefer small, reviewable increments over large implementations.

Each milestone may be divided into several internal implementation steps if necessary.

For each step:

- explain the objective
- implement one coherent piece
- generate tests
- validate it
- stop

Do not generate thousands of lines of code in one response if the milestone can reasonably be implemented in smaller validated increments.

The objective is correctness, scientific rigor and maintainability, not speed.ientific evolution rather than rewriting history.

The following components are frozen and preserved unchanged unless a future phase explicitly introduces an additive replacement:

```text
modules/detection/src/train.py
modules/detection/src/data_loader.py
modules/detection/src/threshold_analysis.py
modules/detection/src/cross_variant_cv.py
modules/detection/config.yaml
current XGBoost model files
current random/holdout/LOVO reports
current threshold reports
current PR curves
current confusion matrices
current SHAP global reports
current alert artifacts
modules/backend/app/main.py
modules/backend/app/predictor.py
modules/backend/app/schemas.py
modules/backend/app/scoring.py
modules/backend/app/db.py
modules/storage/schema.sql
Redis service
PostgreSQL service
Elasticsearch service
Kibana service
Grafana service and dashboards
docker-compose.yml, except a future additive opt-in Zeek profile
```

No canonical model may overwrite names such as:

```text
models/xgboost_brute_force_production.joblib
models/xgboost_ddos_production.joblib
```

Future artifacts must use a separate namespace such as:

```text
models/canonical/<snapshot>/<profile>/<run>/
artifacts/canonical/<snapshot>/<run>/
```

## 3. Scientific Evolution of the Project

CyberSentinel initially relied entirely on the CICIDS2017 MachineLearningCVE CSV files and a conventional supervised-learning workflow. The first XGBoost experiments used random row-level train/test splits and achieved near-perfect recall—approximately `0.9993` for brute force and `0.9998` for DoS/DDoS. These results demonstrated that the selected models could separate randomly partitioned rows under the legacy representation, but they initially appeared stronger than the evidence could support.

To approximate a more demanding deployment scenario, the project then introduced attack-variant-disjoint holdout experiments. The brute-force model was trained on SSH-Patator and tested on FTP-Patator, while the combined DoS/DDoS model was trained on Wednesday DoS variants and tested on Friday DDoS. Recall fell to approximately `0.3090` and `0.0002`, respectively. Leave-one-variant-out experiments confirmed the broader pattern, with mean recall of approximately `0.1552` for brute force and `0.4603` for DoS/DDoS. The contrast with the random results showed that the models generalized poorly to unseen attack variants and that random row-level splitting was not a sufficient proxy for deployment.

Threshold analysis was subsequently performed to determine whether an inappropriate decision threshold explained the recall collapse. It did not. A threshold of `0.01` produced only approximately `0.3103` brute-force recall. Recovering approximately `0.9569` recall required an extreme threshold near `3.59613e-05` and produced 952 false positives. That threshold was selected by sweeping labels from the same holdout rows on which it was reported, so it did not constitute unbiased calibration or evidence of generalization. Threshold tuning was therefore recognized as a response to collapsed score distributions—not a repair for the underlying scientific problem.

This evidence redirected the investigation away from simply changing XGBoost parameters or selecting ever-smaller thresholds. The repository audit showed that the principal limitations lay in the dataset representation and evaluation protocol: MachineLearningCVE lacks timestamps, endpoint identities, flow/session lineage, campaign identifiers, and the provenance required for causal feature construction and defensible grouped splits. Additional weaknesses included heterogeneous target definitions, exclusion of other attack families from detector negatives, silent zero-filling at inference, and selection of thresholds on evaluation data.

The project consequently evolved from tuning a legacy classifier into constructing a canonical and reproducible detection pipeline. That continuation introduces pinned Zeek replay, strict `NetworkEvent` contracts, a sidecar Label Ledger, causal `FeatureWindow` generation, immutable snapshots, and grouped temporal evaluation. The original MVP is deliberately retained as a frozen baseline for comparison, reproducibility, demonstration, historical benchmarking, and architecture validation; the canonical track extends the project rather than rewriting or discarding it.

## 4. Conclusions already obtained from the legacy work

The completed work established several real findings:

1. XGBoost can fit randomly partitioned CICIDS2017 flow rows extremely well.
2. Random row-level performance is an optimistic upper bound, not production evidence.
3. Cross-variant transfer is weak, especially SSH/FTP asymmetry and Wednesday-to-Friday DoS/DDoS transfer.
4. High PR-AUC can coexist with unusable recall at practical thresholds.
5. Threshold sweeping on holdout data does not prove generalization or calibration.
6. The combined `ddos` target contains scientifically different mechanisms.
7. The core limitation is not simply model choice; it is the representation, labels, grouping metadata, prevalence, and evaluation protocol.
8. The existing software stack remains useful and should be evolved, not replaced.
