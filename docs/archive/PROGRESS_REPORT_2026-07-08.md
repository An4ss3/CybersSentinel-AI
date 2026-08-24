# CyberSentinel AI — Progress Report

**Author:** HARKI Anasse
**Date:** 2026-07-15 (revised — corrects the evaluation narrative of the 2026-07-08 draft)
**Phase:** Weeks 1–3 (cadrage, environnement, détection, évaluation rigoureuse)

---

## 0. Correction notice (important)

An earlier draft claimed that "tuning the decision threshold to ~0.01 recovered
96% recall" on the cross-variant holdout. **That was incorrect.** Verification
showed:
- At any usable threshold (≥ 0.01), brute-force holdout recall stays ≈ **31%**.
- 96% recall only appears at a threshold ≈ **3.6 × 10⁻⁵** (which merely rounds
  to `0.0` in the JSON), and it flags almost everything (952 false positives).
- So it is **not** a calibration knob — it is a **real cross-variant
  generalisation limit**.

This report reflects the corrected analysis and a revised model strategy.

---

## 1. Executive summary

We have a working end-to-end pipeline for the 2 MVP attack families (brute
force + DDoS): real CICIDS2017 flows → ML detection → §6.3 scoring → alerts in
PostgreSQL → **live Grafana dashboard**.

Following expert advice, we now maintain **two models per family**:
1. a **scientific evaluation** (cross-variant holdout + leave-one-variant-out CV)
   that honestly measures generalisation, and
2. a **production model** trained on **all variants**, used by the API and the
   alert pipeline.

The headline is methodological honesty: random-split scores (~99.9%) are
optimistic; true cross-variant generalisation is limited and quantified.

---

## 2. Scope (after advisor feedback)

2 attack families (brute force + DDoS; malware-CNN & UEBA = extensions) ·
one of XAI/GenAI in iteration 1 · Grafana/Kibana dashboard (no Blazor) ·
FastAPI + Redis Streams + Docker Compose (no AWS) · rigorous evaluation
methodology instead of fixed KPI thresholds · attack tools confined to the
isolated lab.

---

## 3. Architecture & repository

7-layer architecture, mono-repo by module:

```
modules/storage/     Couche 2 — PostgreSQL schema (alerts, assets, threat_intel)
modules/detection/   Couche 3 — XGBoost models + evaluation (train, threshold, LOVO)
modules/backend/     Couche 7 — FastAPI scoring API + alert sink
infra/               docker-compose + Grafana provisioning (datasource + dashboard)
scripts/             dataset acquisition, alert pipeline, figures
```

Stack: Python 3.12 (uv venv), XGBoost, scikit-learn, imbalanced-learn (SMOTE),
SHAP, FastAPI, PostgreSQL, Grafana, Docker Compose.

---

## 4. Datasets

CICIDS2017 (MachineLearningCVE, 8 labelled flow CSVs). Tuesday → brute force
(FTP/SSH-Patator); Wednesday → DoS variants (Hulk, GoldenEye, slowloris,
Slowhttptest); Friday → DDoS; Monday → benign. Public data only — no UM6P
network traffic (§9).

---

## 5. Evaluation methodology (the core contribution)

Two hardening measures + a dual-model strategy.

**Hardening**
1. **Leaky-feature removal** — `Destination Port` (the only identifier column)
   is dropped so the model cannot memorise lab port assignments.
2. **Cross-variant evaluation** — instead of a random split, test on attack
   variants the model never saw.

**Dual-model strategy (expert advice)**
- **Scientific experiment** — *cross-variant holdout* (train one variant, test
  another) and *leave-one-variant-out (LOVO) CV* (rotate the held-out variant,
  average). Measures honest generalisation, no single-source leakage.
- **Production model** — trained on **all variants** of a family; this is the
  model deployed in the API and alert pipeline.
- LOVO is the leakage-aware generalisation estimate of that all-variants model.

*Constraint noted honestly:* CICIDS2017 confines each attack variant to one day
and provides no session IDs, so a perfect "different-day, leakage-free" split of
an all-variants model is impossible within one family. LOVO is the closest
rigorous substitute; the production held-out (random-split) metrics are reported
as an optimistic upper bound.

---

## 6. Results

### 6.1 Production model — held-out (random split, optimistic)

| Model | Recall | Precision | AUC-PR |
|---|---|---|---|
| brute_force (all variants) | 0.9993 | 0.9996 | 1.000 |
| ddos (all variants) | 0.9998 | 0.9998 | 1.000 |

These are the deployed models. Metrics are optimistic (random split may leak
sessions) — hence the honest measures below.

### 6.2 Cross-variant holdout @0.5 (one unseen variant)

| Model | Setup | Recall | Precision | AUC-PR |
|---|---|---|---|---|
| brute_force | train SSH → test FTP | 0.309 | 1.000 | 0.932 |
| ddos | train Wed-DoS → test Fri-DDoS | 0.0002 | 0.540 | 0.966 |

### 6.3 Threshold analysis (corrected)

For brute-force holdout, sweeping the threshold does **not** rescue recall at any
usable operating point:

| Threshold | Recall |
|---|---|
| 0.5 | 0.309 |
| 0.1 | 0.309 |
| 0.01 | 0.310 |
| ≈ 3.6e-5 (rounds to 0.0) | 0.957 — but 952 FP (FPR 2.4%), not usable |

69% of unseen FTP flows get probabilities in the 1e-6…1e-4 range — barely above
benign. High AUC-PR (0.93) reflects ranking, not a usable threshold. **Real
generalisation limit, not a calibration issue.**

### 6.4 Leave-one-variant-out CV @0.5 (honest generalisation)

| Family | Per-variant recall (held out) | Average recall | Avg AUC-PR |
|---|---|---|---|
| brute_force | FTP 0.31 · **SSH 0.001** | **0.155** | 0.66 |
| ddos | DDoS 0.0002 · Hulk 0.50 · GoldenEye 0.53 · slowloris 0.91 · Slowhttptest 0.36 | **0.460** | 0.99 |

**Reading:**
- **Brute force generalises poorly** across tools (avg 16%); the FTP→SSH
  direction is near-random (AUC-PR 0.40). With only 2 tools, little shared
  behavioural signal remains after removing the port.
- **DDoS**: ranking is excellent (avg AUC-PR 0.99) but recall @0.5 is moderate
  (46%); Friday's volumetric **DDoS is the hard outlier** (distribution shift),
  while slowloris transfers well (0.91).

### 6.5 Runtime alert pipeline (production model, 20 000 flows)

- **4 291 alerts** (435 brute_force, 3 856 ddos), written to **PostgreSQL**.
- By criticality: **Critical 218 · High 2 351 · Medium 1 722 · Low 0**.
- Visualised live in Grafana (auto-provisioned dashboard).

---

## 7. Figures (artifacts/reports/figures/)

| File | Shows |
|---|---|
| `recall_comparison.png` | production vs holdout@0.5 vs LOVO-avg (honest) |
| `lovo_recall.png` | per-variant recall on each unseen variant |
| `confusion_matrices.png` | production vs cross-variant holdout |
| `alert_levels.png` | 4 291 alerts by criticality (production model) |
| `*_pr_curve_holdout.png` | precision-recall curves |

---

## 8. Current stage (10-week plan)

| Phase | Status |
|---|---|
| 1. Cadrage & environnement | ✅ |
| 2. Collecte / stockage | ◑ storage + dataset ingestion done |
| 3. Modèles de détection | ✅ 2 families + dual-model + rigorous eval |
| 4. Scoring, XAI & Threat Intel | ◑ scoring done, SHAP wired; threat intel pending |
| 5. GenAI SOC Assistant | ⏳ pending (iteration decision) |
| 6. Dashboard & API | ✅ FastAPI + Grafana live |
| 7. DevOps | ◑ Docker Compose done; CI/CD pending |

---

## 9. Talking points

1. **Corrected methodology** — random-split 99.9% is optimistic; honest
   cross-variant generalisation is limited and now quantified (LOVO).
2. **Two-model strategy** — a *production* model (all variants) for the API, and
   a *scientific* evaluation (holdout + LOVO) for honest reporting.
3. **Genuine findings** — brute-force cross-tool transfer is weak (16%);
   DDoS shows real distribution shift (Friday DDoS is the outlier).
4. **Full loop works** — real attacks detected, §6.3-scored, stored, and
   visualised live in Grafana (4 291 alerts).

---

## 10. Next steps

1. **Threshold calibration** (Platt/isotonic) per attack — likely lifts DDoS
   recall given its 0.99 AUC-PR.
2. **More diverse training** to improve cross-variant generalisation (or accept
   and document it as an inherent CICIDS2017 limit).
3. Decide **XAI vs GenAI** (recommendation: XAI — SHAP already integrated).
4. **Lab security procedure** doc for confined attack tools.

---

## 11. Honest limitations

- Public dataset; not representative of real UM6P traffic (by design).
- Cross-variant generalisation is limited — especially brute force (2 tools
  only) and Friday DDoS.
- Production held-out metrics are optimistic (no session IDs to guarantee a
  leak-free split); LOVO is the honest generalisation estimate.
- API has no authentication yet (lab-only; RBAC required before deployment).
