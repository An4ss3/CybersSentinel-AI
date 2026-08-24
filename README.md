# CyberSentinel

CyberSentinel contains two deliberately preserved tracks:

- a frozen legacy ML/API/dashboard proof of concept used for comparison, reproduction, and demonstration;
- a canonical evidence and data-contract track built incrementally from immutable CICIDS2017 packet evidence.

## Authoritative milestone status

| Milestone | Status |
|---|---|
| M1 — PCAP acquisition and dataset freeze | Complete and frozen |
| M2 — deterministic Zeek replay | Complete and frozen |
| M3 v1 — microsecond Zeek normalization | Executed and verified, then superseded; preserved unchanged |
| M3 v2 — exact-time Zeek normalization | Protocol, contracts, parser, lineage binding, exports, and tests synchronized; no concrete v2 normalizer, runner, persisted event stream, or verified v2 run report |
| M4 — canonical event persistence | Not started |
| M5 — sidecar label ledger | Complete |

M3 v2 is **partially implemented**, not milestone-complete. Its current code can validate the frozen protocol, exact-time/event/report contracts, parse strict Zeek JSON lines, and bind lineage to M1/M2. It cannot execute full v2 normalization. The manifest acceptance counts are an analytical projection, not a run result.

## Frozen and current identities

| Item | Formatting-independent identity |
|---|---|
| M1 dataset manifest | `feab8d4fbd8454cd12723368704e1e7311853a4316efec7f94bf11726ebb984e` |
| M2 replay specification | `e52c183a315c1ac38cbf1e64155489f5f041e95aa5d2e5cbb82e31f03ac4c455` |
| M2 published tree fingerprint | `22df7f5a0e3b1ff42b0dad45090fce3647fc1640013401b806d416da5656fcb5` |
| M3 v1 protocol | `99ab724a3d245a352e888e2f4771b5a354b5855180af4a72c36980c9296897d4` |
| M3 v2 protocol, authoritative after consistency repair | `5286ddde937ad132afdeb8814e0e0af01745afbb7d1d446ae8860b7701fea210` |

The pre-repair M3 v2 identity `617298f5dfa0940cbf1f0c1d1a5730e8ee83c43160c29b4b2bfb9e6fc56914d4` is retained only as audit history. It is not the current protocol identity.

## Architectural boundary

```text
Frozen M2 conn.log + replay_run.json
        ↓
StrictZeekJsonLineParserV2
        ↓ raw sensor record or explicit rejection
Future concrete v2 normalizer — not implemented
        ↓ FlowEndV2 or explicit rejection
Future v2 run/persistence — not implemented
```

Public `schemas` and `lineage` packages export existing v2 contracts and binders. Concrete v1/v2 parsers and the preserved v1 normalizer/runner remain private submodule implementations. No package export implies that a v2 normalizer or runner exists.

## Documentation

- [Development history and current state](docs/CYBERSENTINEL_DEVELOPMENT_HISTORY.md)
- [M2 summary](docs/canonical/M2_SUMMARY.md)
- [M2 frozen verification](docs/canonical/M2_VERIFICATION.md)
- [M3 v2 status and continuation boundary](docs/canonical/M3_READINESS.md)
- [M3 v2 synchronization record](docs/canonical/M3_V2_SYNCHRONIZATION.md)
- [Technical debt](docs/canonical/TECHNICAL_DEBT.md)
- [Historical July progress report](docs/archive/PROGRESS_REPORT_2026-07-08.md)

## Preservation policy

Do not regenerate, overwrite, or reinterpret M1 or M2 artifacts during M3 work. The superseded M3 v1 protocol and report also remain preserved for audit. Any future M3 v2 implementation must remain additive and must not be described as complete until a concrete normalizer/runner has processed all three frozen M2 partitions and produced independently verified evidence.
