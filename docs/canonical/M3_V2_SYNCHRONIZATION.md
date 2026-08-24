# M3 v2 Synchronization Record — 3 August 2026

## Purpose

Factual record of the repository-wide consistency repair. Captures what changed, why identities shifted, and which integrity checks were strengthened.

## Authoritative scope

Repair facts only. For current status and next steps, see [M3_READINESS.md](M3_READINESS.md). For identities and architecture, see [PROJECT_INDEX.md](../PROJECT_INDEX.md).

## Related documents

- [Project index](../PROJECT_INDEX.md)
- [M3 v2 status](M3_READINESS.md)

---

## Identity transition

| State | Identity |
|---|---|
| Pre-repair | `617298f5dfa0940cbf1f0c1d1a5730e8ee83c43160c29b4b2bfb9e6fc56914d4` |
| Authoritative after repair | `5286ddde937ad132afdeb8814e0e0af01745afbb7d1d446ae8860b7701fea210` |

The semantic identity changed because the boundary token was corrected from `FlowEnd_or_explicit_rejection` to `FlowEndV2_or_explicit_rejection` and additional integrity validations were added. Protocol version remains `2.0.0`.

## What was repaired

### Boundary terminology
- Manifest and schema now declare `FlowEndV2_or_explicit_rejection` as the v2 normalizer output.
- New `ZeekParserBoundaryPolicyV2` subclass enforces the corrected literal.

### Lineage binding
- V2 binder now checks: report M2 identity, M1 identity, runtime, duplicated input claim.
- Specification validator now enforces unique/ordered replay-report paths within the frozen M2 root.

### Run-report contract
- `ZeekNormalizationRunReportV2` now rejects `ingested_at < record_available_time`.
- Partition reports must be unique and in deterministic order.

### Event contract
- `FlowEndV2` now enforces `sensor_id=zeek`, normalizer/pipeline `2.0.0`, and explicit-null model release.

### Import cycle
- Type-only import for `NetworkEvent` in `lineage/labeling.py` removed the circular initialization dependency.

### Package exports
- `schemas.__init__` and `lineage.__init__` now publicly export all existing v2 contracts.
- Concrete parsers and normalizers remain private.

## Artifact inventory after repair

```text
datasets/manifests/cicids2017_zeek_normalization_v2.yaml
modules/detection/src/schemas/exact_time_v2.py
modules/detection/src/schemas/events_v2.py
modules/detection/src/schemas/zeek_normalization_v2.py
modules/detection/src/schemas/zeek_normalization_run_v2.py
modules/detection/src/ingestion/zeek_json_v2.py
modules/detection/src/lineage/zeek_normalization_v2.py
modules/detection/tests/test_zeek_normalization_v2.py
```

## Frozen identities preserved (verified unchanged)

| Item | Identity |
|---|---|
| M1 dataset manifest | `feab8d4fbd8454cd12723368704e1e7311853a4316efec7f94bf11726ebb984e` |
| M2 replay specification | `e52c183a315c1ac38cbf1e64155489f5f041e95aa5d2e5cbb82e31f03ac4c455` |
| M2 tree fingerprint | `22df7f5a0e3b1ff42b0dad45090fce3647fc1640013401b806d416da5656fcb5` |
| M3 v1 protocol | `99ab724a3d245a352e888e2f4771b5a354b5855180af4a72c36980c9296897d4` |
| M3 v1 report content | `a6be7f9c86f4476a7746fef2b025a0311e514ce7145e2c3a470d04d65620f4d0` |

## Explicit non-claims

This repair does not claim M3 v2 is complete, does not produce observed acceptance counts, does not create M4, and does not modify M1/M2/v1 artifacts.
