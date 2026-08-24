# M2 Frozen Replay Verification

## Verification status

**VERIFIED — 29 July 2026**

This report records the final read-only consistency audit of the published M2 Zeek replay artifacts. The audit did not modify or regenerate any replay artifact.

## Scope

The audited root was:

```text
artifacts/canonical/cicids2017/m2/zeek-8.0.9/
```

The expected and observed partitions were exactly:

```text
2017-07-04_Tuesday-WorkingHours/
2017-07-05_Wednesday-workingHours/
2017-07-07_Friday-WorkingHours/
```

No other root entry, staging directory, temporary output, or unpublished partition was present.

## Frozen identities

| Item | Identity |
|---|---|
| M1 dataset freeze manifest | `feab8d4fbd8454cd12723368704e1e7311853a4316efec7f94bf11726ebb984e` |
| M2 replay specification | `e52c183a315c1ac38cbf1e64155489f5f041e95aa5d2e5cbb82e31f03ac4c455` |
| Zeek version | `8.0.9` |
| Image index digest | `sha256:c7dfad9ab8296b2994d113222e77a22ebc9c8963b2b1200b798484ac923bc94f` |
| Platform manifest digest | `sha256:65c79e9e641a90488e303a464bf063288b3f656fa73cd7d6aefe6d119c0bf9d5` |
| Platform | `linux/amd64` |

## Verification method

The final audit performed all of the following checks:

1. Loaded and strictly validated the M1 manifest and M2 replay specification.
2. Bound the M2 specification to the exact M1 content identity and complete selected input inventory.
3. Required the M2 root to contain exactly the three specified final partitions.
4. Loaded every `replay_run.json` through the strict `ZeekReplayRunReport` contract.
5. Verified every report's partition name, input identity, runtime pin, command, required-log declaration, operational-log declaration, M1 hash, and M2 hash.
6. Compared each partition's complete recursive file and directory inventory with its report. Only reported Zeek logs and `replay_run.json` were accepted.
7. Re-read every reported Zeek log in full. Every line was required to be non-blank JSON whose root value was an object.
8. Recounted every JSON record and compared the result with the report.
9. Recomputed every reported log's byte size and SHA-256 and compared both with the report.
10. Rejected symlinks, missing files, extra files, extra directories, and misplaced operational logs.
11. Confirmed that `conn.log` was present and non-empty in every partition.
12. Confirmed that `packet_filter.log`, `stats.log`, and `telemetry.log` were the exact operational logs and were stored under each partition's `operational/` directory.
13. Revalidated the Docker Compose `zeek-replay` profile.
14. Confirmed that no replay or temporary replay container remained.

## Partition results

| Partition | Zeek logs | Records | `conn.log` records | Log bytes | Report bytes | Total published bytes | Report SHA-256 |
|---|---:|---:|---:|---:|---:|---:|---|
| `2017-07-04_Tuesday-WorkingHours` | 31 | 1,095,343 | 323,342 | 448,767,213 | 8,433 | 448,775,646 | `e8908003c583fd5fb148521266b065289f17ba9003d701ea5323208e6534e00b` |
| `2017-07-05_Wednesday-workingHours` | 32 | 1,731,238 | 509,362 | 729,808,415 | 8,683 | 729,817,098 | `56f49ee0c9abda9f9cf05346b8db91f82b7de67c9f65701f35cfb10c34079bb0` |
| `2017-07-07_Friday-WorkingHours` | 29 | 1,543,447 | 547,353 | 619,897,466 | 7,972 | 619,905,438 | `f59ed149e2582fc93a51667b70b4791f5ba0cb2f3e1df4d0bb133b51d7f8f8ae` |
| **Total** | **92** | **4,370,028** | **1,380,057** | **1,798,473,094** | **25,088** | **1,798,498,182** | — |

The published inventory contains exactly **95 files**: 92 Zeek logs and 3 replay reports.

## Expected Zeek logs

There are **32 unique Zeek log types** across M2. Twenty-nine are common to all three partitions:

```text
analyzer.log
capture_loss.log
conn.log
dce_rpc.log
dns.log
files.log
ftp.log
http.log
kerberos.log
known_hosts.log
known_services.log
ldap.log
ldap_search.log
loaded_scripts.log
notice.log
ntlm.log
ntp.log
ocsp.log
packet_filter.log
pe.log
smb_files.log
smb_mapping.log
software.log
ssh.log
ssl.log
stats.log
telemetry.log
weird.log
x509.log
```

Partition-specific emitted types are:

- `known_certs.log`: Tuesday and Wednesday.
- `websocket.log`: Tuesday and Wednesday.
- `mqtt_connect.log`: Wednesday only.

This produces the exact reported inventories of 31, 32, and 29 logs. All required logs and every protocol log of interest (`conn`, `dns`, `files`, `http`, `ssh`, and `ssl`) are present in every partition.

## Whole-tree fingerprint

For independent freeze comparison, the final tree fingerprint is:

```text
22df7f5a0e3b1ff42b0dad45090fce3647fc1640013401b806d416da5656fcb5
```

It is the SHA-256 of compact, key-sorted JSON containing the lexicographically sorted list of all 95 published files, where each entry has exactly:

```text
path
size
sha256
```

Paths are relative to `artifacts/canonical/cicids2017/m2/zeek-8.0.9/`. This fingerprint includes all Zeek logs and all three `replay_run.json` files.

## Audit conclusion

The audit found **zero integrity, inventory, binding, publication, staging, or container issues**. The existing M2 tree is the verified canonical replay reference and is accepted as frozen.