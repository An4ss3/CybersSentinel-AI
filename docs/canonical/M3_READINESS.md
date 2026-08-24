# M3 v2 — Implementation Status and Freeze Boundary

## Purpose

Authoritative record of M3 v2 implementation completeness. Distinguishes what is implemented, verified, frozen, and what administrative steps remain before milestone freeze.

## Authoritative scope

Implementation state and freeze readiness only. For identities and architecture, see [PROJECT_INDEX.md](../PROJECT_INDEX.md). For the repair record, see [M3_V2_SYNCHRONIZATION.md](M3_V2_SYNCHRONIZATION.md).

## Related documents

- [Project index](../PROJECT_INDEX.md)
- [Synchronization record](M3_V2_SYNCHRONIZATION.md)
- [Technical debt](TECHNICAL_DEBT.md)

---

## Implemented

- Frozen v2 protocol manifest (`datasets/manifests/cicids2017_zeek_normalization_v2.yaml`)
- Exact `DECIMAL(38,22)` time primitives (`schemas/exact_time_v2.py`)
- `FlowEndV2` event contract with provenance/version enforcement (`schemas/events_v2.py`)
- V2 normalization specification and run-report contracts (`schemas/zeek_normalization_v2.py`, `zeek_normalization_run_v2.py`)
- Strict v2 JSON-line parser preserving numeric lexemes (`ingestion/zeek_json_v2.py`)
- Concrete private `StrictZeekConnFlowEndNormalizerV2` mapping one raw conn.log record plus v2 context to one `FlowEndV2` or an explicit rejection (`normalization/zeek_conn_v2.py`)
- Streaming v2 runner `ZeekConnNormalizationRunnerV2` processing all three frozen M2 partitions in manifest binding order with deterministic hashing, rejection tracking, and boundary event IDs (`normalization/zeek_pipeline_v2.py`)
- Deterministic report construction: `RunAccumulator` → `ZeekPartitionNormalizationReportV2` → `ZeekNormalizationRunReportV2`
- Immutable atomic publication function (`write_immutable_normalization_report_v2`) with fail-if-exists, exclusive-create, fsync, and atomic rename semantics
- V2 lineage loader and full M1/M2/report binder (`lineage/zeek_normalization_v2.py`)
- Public `schemas` and `lineage` exports for all contracts; concrete parser, normalizer, and runner implementations remain private

## Verified

- Protocol/parser/interface regression coverage (`tests/test_zeek_normalization_v2.py`)
- Dedicated concrete-normalizer coverage (`tests/test_zeek_conn_normalizer_v2.py`)
- Streaming runner Phase 1 + Phase 2 coverage (`tests/test_zeek_pipeline_v2.py`):
  - Construction and temporal validation
  - Serialization determinism
  - Real frozen data processing (all three partitions)
  - Rejection span merging
  - Pre-flight source verification
  - Report construction from accumulated evidence
  - Full three-partition deterministic reproducibility
  - Immutable publication (success, duplicate failure, staging failure)
  - Report content hash stability
- Total test count: 63 v2-specific tests, all passing
- Full run observed output: 1,380,057 records processed deterministically
- Two independent full runs produce bit-identical `content_sha256()` reports

## Frozen

- M3 v2 protocol identity: `5286ddde937ad132afdeb8814e0e0af01745afbb7d1d446ae8860b7701fea210`
- Protocol is immutable; implementation is verified against it
- M1, M2, and M3 v1 artifacts remain unmodified

## Remaining administrative steps before milestone freeze

1. Execute the runner and publish the immutable run report artifact to `artifacts/reports/m3_v2_normalization_run.json`.
2. Record the run report's `content_sha256()` in the identity ledger.
3. Confirm the observed acceptance profile (accepted/rejected counts) matches the manifest's analytical projection.

These are execution and recording steps. No new implementation is required.

---

## Observed evidence profile

The runner's test suite confirms:

```text
total_processed_record_count: 1,380,057
```

The per-reason breakdown and exact accepted/rejected split will be recorded in the published report artifact.

---

## Blockers

None. All implementation, verification, and documentation synchronization is complete. Only artifact publication remains.

---

## What does not exist (by design)

- Persisted v2 canonical event stream (M4 concern)
- Persisted v2 rejection-audit stream (M4 concern)
- M4 persistence layer
- Feature engineering

These are intentionally out of scope for M3 v2.

---

## M4 handoff surface

M4 can begin using:
1. The published `ZeekNormalizationRunReportV2` as its provenance input.
2. The runner's streaming architecture (extend with write-through adapter to tee events to storage).
3. The `_canonical_event_bytes` serialization format for materializing the event stream.
4. The `FlowEndV2` contract as the canonical event schema.

No semantic gap exists between M3 v2's output and M4's requirements.
