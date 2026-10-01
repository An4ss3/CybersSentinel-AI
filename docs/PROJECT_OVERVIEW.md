# CyberSentinel AI — project overview

This page goes one level deeper than the [README](../README.md). The complete
scientific record is in [`SCIENTIFIC_STATUS.md`](SCIENTIFIC_STATUS.md) and
[`PROJECT_INDEX.md`](PROJECT_INDEX.md).

## Context

CyberSentinel AI was carried out during an engineering internship at Mohammed
VI Polytechnic University (UM6P, Rabat), within the Computer Science, AI and
Digital Trust programme of ENSA Fès. The [initial specification](specification/README.md)
described a broad SOC platform; the scope was narrowed to network intrusion
detection so that the evaluation could be made rigorous.

## Problem

Machine-learning IDS papers often report near-perfect scores on CICIDS2017.
This project reproduced that pattern first: an XGBoost model on the published
CSV features reached 0.9993 brute-force recall on a random split, then 0.3090
when the attack tool was held out, and 0.0002 on a DDoS hold-out. A random
split mostly measures how well a model recognises traffic it has already seen.

The question therefore became: **does a detector transfer to an attack family
absent from both its training data and its threshold calibration?**

## Approach

1. **Rebuild the data from raw PCAPs.** Five captures (~48.8 GiB) are frozen by
   SHA-256 and replayed offline with a digest-pinned Zeek 8.0.9 container.
2. **Normalise strictly.** Zeek `conn.log` records pass an admission contract;
   incomplete records are rejected and counted, never filled with defaults.
   Timestamps are kept in exact decimal arithmetic.
3. **Window per entity.** Events are aggregated into 60-second windows per
   (source, destination, transport, service).
4. **Label conservatively.** Windows are matched against the declared attack
   schedule. Uncertain windows are **excluded, never treated as benign**.
5. **Correct coverage, additively.** An audit found three DoS campaigns
   unlabelled because of NAT on the capture path. The M5 v3 policy realigned
   them (+88 windows, +14 episodes) without changing any existing label.
6. **Fix the protocol before opening the holdout.** Populations, model,
   threshold rule and metrics were written down and hashed first.

## Evaluation protocol

Seven leave-one-family-out folds (FTP-Patator, SSH-Patator, DoS Hulk,
Slowloris, SlowHTTPTest, GoldenEye, DDoS LOIT):

- **Train**: six families + Monday benign windows of entity folds 0–3.
- **Validation**: Monday benign windows of entity fold 4 only, used solely to
  set the threshold at a 1 % false-positive target.
- **Holdout**: the seventh family + 32,813 Thursday benign windows, opened once
  after the model and threshold were frozen.

Model: `RandomForestClassifier(n_estimators=200, random_state=0, class_weight=None)`
on five volume features (VOL5). Primary metric: episode recall.

## Results

- 19 of 28 held-out episodes detected (Wilson 95 % CI [0.493, 0.821]).
- Thursday false-positive rate between 0.357 % and 0.643 % on all folds.
- Strong per-family heterogeneity; SSH-Patator detected on 1 of 9 episodes.
- Re-executed from a fresh clone with byte-identical models.

Exploratory, outside the main protocol: on a held-out botnet family (Ares),
volume features detect 0/40 episodes while payload-content features (ARM F)
detect 21/40 at a 0.7187 % false-positive rate. One family only; ARM F was not
evaluated on the main holdouts.

Full tables: [README — Experimental results](../README.md#experimental-results)
and [`canonical/TRANSFER_EXPERIMENT_REPORT.md`](canonical/TRANSFER_EXPERIMENT_REPORT.md).

## What the results do not show

- Generalisation to other datasets, networks or production traffic.
- Separation of attack behaviour from network identity: the seven families
  share one attacker address and one victim address.
- Detection of genuinely unknown attacks: a family held out of a split is not
  an unknown attack in operation.

## Engineering components

A demonstration layer sits outside the experimental protocol: a FastAPI
scoring service (`/health`, `/score`), a composite alert score, a PostgreSQL
alert table and a provisioned Grafana dashboard. It uses the legacy XGBoost
models and has no authentication.

## Perspectives

- Evaluate on captures with the same families from other attackers and
  victims (e.g. CSE-CIC-IDS2018).
- Test content-based features inside the main protocol, under a new
  pre-specified protocol.
- Study the 60-second window length.
- Connect the API to the canonical models and a streaming source.
