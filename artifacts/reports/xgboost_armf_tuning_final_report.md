# Phase 2 — production-grade XGBoost tuning on frozen ARM F

Status: **executed, leak-free, reproducible; zero-day transfer does not improve Ares recall.**
Pre-registration identity: `623e7521ecfefc7f60533f9e187c0880ae08295e22f4a21178e6a557f39c7ca6`
Evidence: `artifacts/experiments/xgboost_armf_tuning/`
Reproduction: `python -m scripts.run_armf_tuning --execute`

## 1. Scientific boundary

The five frozen P1 folds are leave-one-attack-type-out, not temporal folds. Every
one of folds 1–4 places all 13,951 rows of the final Ares fold in its training
set, including 177 Ares positives and 13,774 final negatives. Using the five
folds as a tuning cross-validation would therefore leak the complete final test.

The authorised nested protocol prevents that leakage:

- outer test: frozen `fold0.test`, 13,951 rows, held-out Ares;
- tuning pool: frozen `fold0.train`, 57,003 rows, **zero Ares**;
- internal validation k: `fold_k.test ∩ fold0.train`, k=1..4;
- internal training k: `fold0.train − validation_k`;
- zero outer-test overlap in every training and validation set;
- Ares unavailable to fitting, early stopping, threshold calibration and
  selection;
- outer Ares opened only after selection and final refit.

Consequently, this is **surrogate tuning on four known attack families followed
by a one-shot zero-day transfer test**. It is not direct Ares optimisation and
must never be reported as such.

## 2. Immutable search registration

Before any model was fitted, `PRE_REGISTRATION.json` and `SEARCH_SPACE.md` fixed:

- 48 random configurations without replacement, seed `20260826`;
- one fixed Phase-1 control, for 49 candidates × 4 folds = 196 internal fits;
- ARM F features only: `distinct_payload_ratio`,
  `source_non_printable_ratio`, `destination_non_printable_ratio`;
- early stopping on validation AUCPR, 50 rounds;
- primary candidate metric: unweighted macro episode recall over FTP, SSH, DDOS
  and Hulk at `target_train_fpr=0.005`;
- hard constraints: pooled validation FPR ≤ 0.005 and each fold FPR ≤ 0.01;
- fixed lexicographic tie-breaks;
- five outer reporting points: 1%, 0.5%, 0.2%, 0.1%, 0.05%;
- no post-hoc candidate, constraint or threshold change.

Search space:

| Parameter | Registered values |
|---|---|
| `max_depth` | 2, 3, 4, 5 |
| `learning_rate` | 0.025, 0.05, 0.1 |
| max `n_estimators` | 300, 600, 1000 |
| `reg_alpha` | 0, 0.01, 0.1, 1 |
| `reg_lambda` | 1, 3, 10, 30 |
| `min_child_weight` | 1, 3, 5, 10 |
| `subsample` | 0.70, 0.85, 1.00 |
| `colsample_bytree` | 0.67, 1.00 |

All 49 candidates happened to satisfy both FPR constraints. This fact was not
used to loosen or replace the registered objective.

## 3. Selected model and parameters

R006 won the registered lexicographic selection. Eleven candidates tied at the
maximum macro episode recall of 0.7778; R006 then had the highest registered
macro PR-AUC tie-break (0.7617).

| Parameter | Phase 1 | R006 final refit |
|---|---:|---:|
| `max_depth` | 3 | **2** |
| `learning_rate` | 0.1 | 0.1 |
| `n_estimators` | 200 | **31** |
| `reg_alpha` | 0 | **0.01** |
| `reg_lambda` | 1 | 1 |
| `min_child_weight` | 1 | **10** |
| `subsample` | 1.0 | **0.85** |
| `colsample_bytree` | 1.0 | 1.0 |

The final 31 trees are the pre-registered round-half-up median of 32, 2, 30 and
57 trees selected across the four internal folds.

The result is a much smaller, shallower and more conservative model: 84.5% fewer
trees, depth reduced from 3 to 2, tenfold child-weight floor and light L1 plus
row subsampling.

Final gain shares remain consistent with Phase 1:

| Feature | Normalised gain |
|---|---:|
| `distinct_payload_ratio` | 0.4792 |
| `source_non_printable_ratio` | 0.1169 |
| `destination_non_printable_ratio` | 0.4039 |

## 4. Known-family surrogate validation

| Model | Macro episode recall | Minimum family recall | Macro PR-AUC | Pooled FPR | Max fold FPR |
|---|---:|---:|---:|---:|---:|
| Phase-1 control | 0.5000 | 0.0000 | 0.4853 | 0.002975 | 0.006826 |
| **R006** | **0.7778** | **0.1111** | **0.7617** | **0.001549** | **0.002923** |

Per family:

| Validation family | Control recall | R006 recall | Control → R006 PR-AUC | Control → R006 FPR |
|---|---:|---:|---:|---:|
| ftp_patator | 0/1 | **1/1** | 0.2052 → 0.7574 | 0.001359 → 0.001645 |
| ssh_patator | 0/9 | **1/9** | 0.1568 → 0.7008 | 0.006826 → **0.000498** |
| ddos/loit | 2/2 | 2/2 | 0.9937 → 0.9994 | 0.001697 → 0.001154 |
| dos/hulk | 2/2 | 2/2 | 0.5856 → 0.5890 | 0.002067 → 0.002923 |

On the exact surrogate objective, tuning is successful: it recovers both the FTP
and the single detectable SSH episode while approximately halving pooled FPR.
This validates the optimisation machinery on known attack families. It does not
imply transfer to Ares.

## 5. One-shot zero-day Ares transfer

Global discrimination becomes worse:

| Metric | Phase 1 | R006 | Delta |
|---|---:|---:|---:|
| ROC-AUC | **0.9713** | 0.9624 | −0.0089 |
| PR-AUC | **0.4570** | 0.3742 | −0.0828 |

Operating points:

| Target training FPR | Phase-1 episodes | Phase-1 test FPR | R006 episodes | R006 test FPR | Paired 95% delta CI |
|---:|---:|---:|---:|---:|---:|
| 1% | **21/40** | **0.007187** | 17/40 | 0.009583 | **[−0.2000, −0.0250]** |
| **0.5% primary** | **17/40** | 0.003122 | **17/40** | **0.002251** | [0.0000, 0.0000] |
| 0.2% | 15/40 | 0.002033 | 17/40 | 0.002251 | [0.0000, 0.1250] |
| 0.1% | **14/40** | 0.001597 | 0/40 | 0.000000 | **[−0.5000, −0.2000]** |
| 0.05% | **12/40** | 0.000145 | 0/40 | 0.000000 | **[−0.4500, −0.1750]** |

### Primary transfer result

At the pre-registered 0.5% target, R006 detects **exactly the same 17 episodes**
as Phase 1 — no new episode and none lost — while reducing realised FPR from
0.003122 to 0.002251. This is a local Pareto improvement in alert efficiency,
but **not a recall improvement**.

At 1%, R006 is significantly worse: four Ares episodes lost, all on
`192.168.10.15`, with the paired interval strictly below zero. At 0.2%, R006 gains
two episodes on `192.168.10.9`, but the interval touches zero and its FPR is also
slightly higher, so no superiority is demonstrated.

At the two strictest targets it collapses to zero detections. The shallow 31-tree
model emits only **16 distinct score levels** over 13,951 test windows. This
quantisation creates threshold plateaus:

- 0.5% and 0.2% select the same threshold `0.3430818021`, the same 17 episodes
  and the same FPR 0.002251;
- 0.1% and 0.05% jump to `0.8820853829`, above every positive test score, and
  produce zero alerts and zero recall.

This is a production-relevant failure: a smaller regularised model is efficient
at one target but cannot provide smooth control in the ultra-low-FPR regime.

## 6. Entity robustness and the `.15` concentration

At the primary 0.5% point, Phase 1 and R006 detect the **same episode set**, hence
the same per-entity distribution:

| Entity | Phase 1 | R006 |
|---|---:|---:|
| `192.168.10.14` | 4/8 | 4/8 |
| `192.168.10.15` | 4/8 | 4/8 |
| `192.168.10.5` | 3/7 | 3/7 |
| `192.168.10.8` | 2/2 | 2/2 |
| `192.168.10.9` | 4/15 | 4/15 |

Therefore, tuning **does not redistribute** Ares detections at its registered
primary point. The severe `.15` concentration observed at Phase 1's 1% point is
reduced only because both Phase 1 and R006 become stricter; R006 does not discover
new entities. At 1%, its four lost episodes all come from `.15`. At 0.2%, its two
non-significant gains come from `.9`.

The persistent weakness is `.9` (4/15 at the primary point), not solved by
hyperparameter optimisation.

## 7. Scientific verdict

### Did tuning improve production robustness?

**Yes on the known-family surrogate, narrowly at the 0.5% transfer point.** It
raises known-family macro episode recall from 0.5000 to 0.7778, recovers FTP and
SSH, approximately halves pooled FPR, and preserves the same 17 Ares episodes at
a lower FPR.

### Did tuning improve zero-day Ares detection?

**No.** It gains no Ares episode at the primary point, worsens ROC-AUC and PR-AUC,
is significantly worse at 1%, and collapses at 0.1% and below. The only apparent
gain, +2 episodes at 0.2%, is not statistically distinguishable and carries a
slightly higher FPR.

### Were Phase-1 hyperparameters already at the feature ceiling?

For transferable Ares recall, **the evidence says essentially yes**. The search
finds a better regularisation regime for known attacks but cannot extract new,
robust zero-day information from the same three ARM F features. The limitation is
representational, not merely an untuned XGBoost decision boundary.

## 8. Deployment recommendation

Do **not** replace the Phase-1 ARM F model unconditionally with R006.

- If deployment is permanently locked at the 0.5% training-FPR point and known
  family robustness/model size dominate, R006 is a defensible operational
  candidate: same 17 Ares episodes, lower Ares FPR, stronger internal transfer,
  31 shallow trees.
- If production requires stable ranking, flexible thresholds or operation at
  0.1% FPR and below, retain Phase-1 ARM F: its ROC/PR are better and it preserves
  12–14 Ares episodes where R006 detects none.

For the PFA scientific conclusion, retain **Phase-1 ARM F as the reference final
model** and present R006 as a specialised low-complexity candidate for the fixed
0.5% operating point, not as a universally improved successor.

## 9. R11 and integrity

R11 remains fully applicable: five Ares entities, one destination host
`205.174.165.73`, one capture, and no evidence of generalisation to another
victim, attacker or botnet family. A one-shot transfer result cannot establish
production generalisation.

Integrity evidence:

- 54 frozen/protocol checks, 24 feature checks and 20 leakage checks passed;
- zero Ares rows and zero outer-test overlap during 196 internal fits;
- 49/49 registered candidates evaluated; no post-hoc candidate or constraint;
- one final model refit, 0 PostgreSQL writes;
- immutable pre-registration and SHA-256 manifest;
- full second execution reproduced all artifacts byte-for-byte;
- 17 targeted regression tests cover protocol identity, leakage boundary,
  selection priority and artifact digests.
