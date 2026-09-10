# Temporal persistence — independent audit addendum

This addendum is additive. It does not replace or modify the six immutable artifacts published by the final temporal run. It records issues found by an independent read-only audit and narrows the scientific claim accordingly.

## Verified result

- Baseline reproduced exactly: ARM F threshold `0.0024790484458208084`, Ares `21/40`, `99/13,774` benign false-positive windows, FPR `0.007187454624655147`.
- Calibration calculation used 56,804 benign OOF windows from folds 1–4 and zero attack rows in any metric or threshold decision.
- Frozen persistence threshold: `0.8922511339`, selected literally as the highest admissible observed pair-minimum score.
- Calibration: 306/56,804 false positives (`0.005386944581367509`); maximum fold FPR `0.006257110352673493`; fold spread `0.002252533693634591`.
- Final Ares result: `21/40 -> 21/40`; zero new episodes, zero lost episodes, zero percentage-point gain.
- Final benign result: `99 -> 99` false-positive windows; zero incremental false positives; 61 pseudoepisodes alerted by the baseline union, but zero persistence hits.
- Host and episode-length strata are unchanged. The adjacent observed thresholds `0.8286380768`, `0.8922511339`, and `nextafter(0.8922511339)` all produce `21/40` and 99 false positives.
- A single-window diagnostic at the same false-positive count also produces `21/40`.

## Audit corrections

1. **Fold0 access accounting.** In the executed version, `--calibrate` reran the baseline guard and therefore physically read fold0 predictions before computing the benign folds 1–4 calibration. Fold0 values did not enter the candidate set, FPR metrics, selection rule or threshold, so the numerical calibration remains uncontaminated. Nevertheless, the original claim that the calibration command never opened fold0 was too strong. The script has been corrected for future clean runs: calibration now verifies the baseline evidence embedded in the immutable pre-registration and does not reopen fold0; final evaluation performs one fold0 load and checks the baseline from that same load.

2. **STOP publication.** The original no-feasible-threshold exception could occur before a STOP manifest was written. The script now catches this path, publishes `calibration_manifest.json` with status `STOP`, input hashes, access counts and the reason, then refuses final evaluation.

3. **Meaning of `entity_key`.** There is no hard-coded IP, service-specific branch, attack label or attack family in the decision. However, the frozen `entity_key` is a network-flow tuple and contains endpoints, transport and service. Equality of that tuple therefore influences sequence membership indirectly. The accurate claim is “no IP/service-specific condition”, not “no use of IP or service identity whatsoever”.

4. **Meaning of two hits.** The implementation uses sliding adjacent pairs. For three qualifying consecutive windows, the second and third windows each alert as the second member of `(t1,t2)` and `(t2,t3)`. This follows the literal `ALERTE(t)` rule but is not a one-alert latch. A regression test now pins this behavior.

5. **Presentation figure.** The original figure is preserved under its published hash. `temporal_persistence_summary_presentation.png` is an additive rendering of the same frozen `results.json` with shortened host labels; it changes no metric.

## Scientific interpretation

The negative result is valid for the exact frozen protocol: its deterministic selection rule chose the maximum observed admissible score, making the additive branch effectively inactive. This establishes that **this pre-registered selection procedure did not alter ARM F**.

It does **not** establish that every active two-hit persistence rule is ineffective. Because higher persistence thresholds monotonically reduce alerts, choosing the highest admissible candidate is intrinsically conservative and does not use the available FPR budget. Retuning now would be post-hoc and is prohibited. The correct action is to preserve this result as a negative methodological experiment and move to the pre-declared feature-ablation backup rather than rerun temporal variants.
