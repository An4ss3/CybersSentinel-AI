# CyberSentinel M2 Summary

## Purpose

M2 converts the immutable M1 CICIDS2017 packet evidence into reproducible, version-pinned Zeek JSON telemetry. It freezes the replay runtime and command, verifies every selected PCAP before execution, validates every emitted log, separates operational runtime logs, and atomically publishes one immutable partition per PCAP with a bound verification report.

M2 produces raw sensor telemetry only. It does not parse records into canonical `NetworkEvent` objects, perform normalization, apply event labels, create feature windows, or train models.

## Inputs

### Official CICIDS2017 PCAPs

The evidence originates from the Canadian Institute for Cybersecurity CICIDS2017 release. M1 retains all official packet evidence, while the initial canonical replay scope selects exactly three PCAPs:

| Capture | Capture date | Bytes | SHA-256 |
|---|---|---:|---|
| `Tuesday-WorkingHours.pcap` | 2017-07-04 | 11,048,283,608 | `080c2250154c5a174c03660ed0f75a3858d41a27511ba716e780d7bcb1ec4c57` |
| `Wednesday-workingHours.pcap` | 2017-07-05 | 13,420,789,612 | `cd2674db7559a53f24bc03be3239b315700174ccaef72d10f5edc4c1a08f6186` |
| `Friday-WorkingHours.pcap` | 2017-07-07 | 8,839,309,056 | `beff0dcce1eebc9b2454582f4dc8ed0ba0112b2c619a710bf03af93147254cd0` |

Selected input total: **33,308,382,276 bytes**.

### Selected partitions

```text
2017-07-04_Tuesday-WorkingHours
2017-07-05_Wednesday-workingHours
2017-07-07_Friday-WorkingHours
```

### Pinned runtime and identities

| Item | Value |
|---|---|
| Zeek | `8.0.9` |
| Container platform | `linux/amd64` |
| Image index digest | `sha256:c7dfad9ab8296b2994d113222e77a22ebc9c8963b2b1200b798484ac923bc94f` |
| Platform manifest digest | `sha256:65c79e9e641a90488e303a464bf063288b3f656fa73cd7d6aefe6d119c0bf9d5` |
| Replay specification hash | `e52c183a315c1ac38cbf1e64155489f5f041e95aa5d2e5cbb82e31f03ac4c455` |
| M1 manifest hash | `feab8d4fbd8454cd12723368704e1e7311853a4316efec7f94bf11726ebb984e` |

The replay used offline single-process execution, UTC, locale `C`, invalid-checksum tolerance, JSON logs, no rotation, no external Zeek packages, and the frozen command template in `datasets/manifests/cicids2017_zeek_replay.yaml`.

## Outputs

### Published directory structure

```text
artifacts/canonical/cicids2017/m2/zeek-8.0.9/
├── 2017-07-04_Tuesday-WorkingHours/
│   ├── *.log
│   ├── operational/
│   │   ├── packet_filter.log
│   │   ├── stats.log
│   │   └── telemetry.log
│   └── replay_run.json
├── 2017-07-05_Wednesday-workingHours/
│   ├── *.log
│   ├── operational/
│   └── replay_run.json
└── 2017-07-07_Friday-WorkingHours/
    ├── *.log
    ├── operational/
    └── replay_run.json
```

### Global inventory

| Measure | Frozen value |
|---|---:|
| Published partitions | 3 |
| Unique Zeek log types | 32 |
| Log types common to every partition | 29 |
| Published Zeek log files | 92 |
| Replay reports | 3 |
| Total published files | 95 |
| Total records across all Zeek logs | 4,370,028 |
| Total `conn.log` records | 1,380,057 |
| Zeek log bytes | 1,798,473,094 |
| Total storage, including reports | **1,798,498,182 bytes** (approximately 1.675 GiB) |

Per-partition totals are:

| Partition | Logs | Records | `conn.log` records | Published bytes |
|---|---:|---:|---:|---:|
| Tuesday | 31 | 1,095,343 | 323,342 | 448,775,646 |
| Wednesday | 32 | 1,731,238 | 509,362 | 729,817,098 |
| Friday | 29 | 1,543,447 | 547,353 | 619,905,438 |

## Verification

The final audit:

- strictly loaded and bound the M2 specification to the M1 manifest;
- validated all three `replay_run.json` contracts and their input, runtime, command, partition, log-policy, M1, and M2 identities;
- required exactly the three selected partitions and no other output-root entries;
- compared every recursive partition inventory with its report;
- parsed all 4,370,028 published JSON lines and required each root value to be an object;
- recomputed and matched every reported record count, file size, and SHA-256;
- confirmed required `conn.log` and all protocol logs of interest in every partition;
- confirmed exact operational-log classification and placement;
- rejected symlinks and checked for unpublished files and extra directories;
- confirmed no staging output and no replay containers;
- revalidated the Docker Compose profile.

The audit found zero issues. Detailed evidence, report hashes, and the whole-tree fingerprint are recorded in [`M2_VERIFICATION.md`](M2_VERIFICATION.md).

## Reproducibility

An independent researcher reproduces M2 in a separate clean repository copy or separate experimental output tree; the frozen canonical tree in this repository must not be deleted or overwritten.

Required conditions are:

1. Obtain the exact three CICIDS2017 PCAPs and verify them against the M1 manifest.
2. Use the exact M1 manifest and M2 specification identities listed above.
3. Use a Linux `amd64` Docker runtime and the exact pinned Zeek image digest.
4. Preserve the Compose service security, mounts, UTC timezone, `C` locale, and disabled network.
5. Use the frozen runner and execute each manifest-selected relative path from the repository root.
6. Start with an empty M2 output root. The runner deliberately refuses an existing final or staging partition.
7. Compare the resulting reports, file inventories, sizes, hashes, record counts, report hashes, and whole-tree fingerprint with the frozen values.

The runner invocation pattern is:

```powershell
@'
from pathlib import Path
from modules.detection.src.ingestion.zeek_replay import ZeekReplayRunner

runner = ZeekReplayRunner.from_repository(Path.cwd())
for pcap in (
    "Tuesday-WorkingHours.pcap",
    "Wednesday-workingHours.pcap",
    "Friday-WorkingHours.pcap",
):
    runner.replay(pcap)
'@ | .\.venv\Scripts\python.exe -
```

This command is documentation for independent reproduction, not authorization to regenerate the canonical artifacts in the current repository.

## Acceptance criteria

M2 is accepted as complete because:

- the replay specification and runtime are immutable and bound to M1;
- every selected PCAP has exactly one final published partition;
- every replay completed under pinned Zeek `8.0.9`;
- every report validates and declares `verification_status: verified`;
- every reported log exists, is valid JSON Lines, and matches its recorded count, size, and SHA-256;
- all required and expected protocol logs are present;
- no staging, temporary output, unpublished file, or replay container remains;
- the final complete audit found zero issues.

**M2 is complete and frozen.** These artifacts are the canonical reference. They must never be regenerated unless the replay specification intentionally changes or a new dataset version is intentionally introduced.