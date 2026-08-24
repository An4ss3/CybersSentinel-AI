"""Streaming payload-content extraction over frozen M1 PCAPs.

Security boundary
-----------------
Raw payload bytes are delivered only inside the pinned, network-disabled Zeek
process. They are reduced immediately to six aggregate metrics. The Zeek output
contains only a salted window pseudonym, numeric aggregates, and audit counts.
The salt and temporary directory are destroyed after the join to frozen P1 row ids.
No payload, URI, hostname, header value, IP address, port, per-flow fingerprint, or
header-template fingerprint is persisted.
"""
from __future__ import annotations

from dataclasses import dataclass
import csv
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import tempfile
from typing import Any, Final


FEATURE_NAMES: Final[tuple[str, ...]] = (
    "source_payload_entropy_normalized",
    "destination_payload_entropy_normalized",
    "source_non_printable_ratio",
    "destination_non_printable_ratio",
    "payload_prefix_repeat_ratio",
    "normalized_header_template_repeat_ratio",
)

ARM_FEATURES: Final[dict[str, tuple[str, ...]]] = {
    "A": ("distinct_payload_ratio",),
    "E": (
        "distinct_payload_ratio",
        "source_payload_entropy_normalized",
        "destination_payload_entropy_normalized",
    ),
    "F": (
        "distinct_payload_ratio",
        "source_non_printable_ratio",
        "destination_non_printable_ratio",
    ),
    "G": ("distinct_payload_ratio", "payload_prefix_repeat_ratio"),
    "H": (
        "distinct_payload_ratio",
        "normalized_header_template_repeat_ratio",
    ),
    # Pre-registered before extraction. Never selected adaptively from E--H.
    "I": ("distinct_payload_ratio",) + FEATURE_NAMES,
}

FEATURE_DEFINITIONS: Final[dict[str, str]] = {
    "source_payload_entropy_normalized": (
        "mean over source-payload-bearing flows of Shannon bits/byte divided by "
        "log2(min(256, payload_bytes)); undefined for windows without a qualifying flow"
    ),
    "destination_payload_entropy_normalized": (
        "same normalized per-flow Shannon mean for destination payload"
    ),
    "source_non_printable_ratio": (
        "source payload bytes outside ASCII 0x20-0x7e and TAB/CR/LF divided by all "
        "source payload bytes"
    ),
    "destination_non_printable_ratio": (
        "same byte-weighted ratio for destination payload"
    ),
    "payload_prefix_repeat_ratio": (
        "1 - distinct SHA-256 fingerprints of the first up-to-64 source payload "
        "bytes / source-payload-bearing flows; fingerprints never leave Zeek memory"
    ),
    "normalized_header_template_repeat_ratio": (
        "1 - distinct normalized HTTP request templates / requests, where a template "
        "contains only bounded method class, version class and ordered header names; "
        "URI, host and all values are discarded before hashing"
    ),
}

ONLINE_VALIDITY: Final[dict[str, str]] = {
    "source_payload_entropy_normalized": "online incremental; final at window close",
    "destination_payload_entropy_normalized": "online incremental; final at window close",
    "source_non_printable_ratio": "online incremental",
    "destination_non_printable_ratio": "online incremental",
    "payload_prefix_repeat_ratio": "online after first up-to-64 source payload bytes per flow",
    "normalized_header_template_repeat_ratio": "online after request headers complete",
}

ZEEK_IMAGE: Final[str] = (
    "zeek/zeek@sha256:65c79e9e641a90488e303a464bf063288b3f656fa73cd7d6aefe6d119c0bf9d5"
)
ZEEK_IMAGE_INDEX_SHA256: Final[str] = (
    "c7dfad9ab8296b2994d113222e77a22ebc9c8963b2b1200b798484ac923bc94f"
)

PARTITIONS: Final[tuple[dict[str, Any], ...]] = (
    {
        "partition": "2017-07-03_Monday-WorkingHours",
        "pcap": "Monday-WorkingHours.pcap",
        "size": 10_822_507_416,
        "sha256": "f6eac599358f216b074338813a1cf7be3cc4e91d116e13efc0dc71f2cca11972",
    },
    {
        "partition": "2017-07-04_Tuesday-WorkingHours",
        "pcap": "Tuesday-WorkingHours.pcap",
        "size": 11_048_283_608,
        "sha256": "080c2250154c5a174c03660ed0f75a3858d41a27511ba716e780d7bcb1ec4c57",
    },
    {
        "partition": "2017-07-05_Wednesday-workingHours",
        "pcap": "Wednesday-workingHours.pcap",
        "size": 13_420_789_612,
        "sha256": "cd2674db7559a53f24bc03be3239b315700174ccaef72d10f5edc4c1a08f6186",
    },
    {
        "partition": "2017-07-07_Friday-WorkingHours",
        "pcap": "Friday-WorkingHours.pcap",
        "size": 8_839_309_056,
        "sha256": "beff0dcce1eebc9b2454582f4dc8ed0ba0112b2c619a710bf03af93147254cd0",
    },
)

ALLOWED_ZEEK_FIELDS: Final[set[str]] = {
    "window_key",
    *FEATURE_NAMES,
    "source_entropy_flows",
    "destination_entropy_flows",
    "source_payload_bytes",
    "destination_payload_bytes",
    "source_prefixes",
    "header_templates",
}
AUDIT_COUNT_FIELDS: Final[tuple[str, ...]] = (
    "source_entropy_flows",
    "destination_entropy_flows",
    "source_payload_bytes",
    "destination_payload_bytes",
    "source_prefixes",
    "header_templates",
)
HEX64 = re.compile(r"^[0-9a-f]{64}$")

#: The two entropy means are float divisions; the four ratios are exact quotients.
ENTROPY_FEATURES: Final[frozenset[str]] = frozenset(
    {
        "source_payload_entropy_normalized",
        "destination_payload_entropy_normalized",
    }
)
ENTROPY_FLOAT_TOLERANCE: Final[float] = 1e-9

#: Zeek stderr lines known to be benign. Only counts and a boolean derived from
#: this allowlist are ever persisted; the text itself is never published.
EXPECTED_STDERR_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(r"received termination signal\s*$"),
)

#: Engineering guards, not inference thresholds. They exist to make a systematic
#: join or extraction defect fail loudly instead of publishing a near-empty
#: artifact, which is exactly how the first extraction attempt silently produced
#: an all-missing header-template column.
MINIMUM_PARTITION_MATCH_RATE: Final[float] = 0.90

#: The pre-registered primary endpoint of every arm comparison. All 177 of its
#: windows carry service "http", so the header-template metric is the one whose
#: availability decides whether ARM H can say anything about it at all.
PRIMARY_ENDPOINT: Final[str] = "botnet/ares"


class ContentExtractionError(RuntimeError):
    """The content extraction failed a protocol, privacy, or integrity guard."""


@dataclass(frozen=True, slots=True)
class FrozenWindow:
    row_id: str
    partition: str
    source: str
    destination: str
    transport: str
    service: str
    window_start_epoch: int
    label: int = 0
    attack_type: str = ""

    def canonical_key(self) -> str:
        """The join key. Label and attack type are metadata and never enter it."""
        return "\x1f".join(
            (
                self.partition,
                self.source,
                self.destination,
                self.transport,
                self.service,
                str(self.window_start_epoch),
            )
        )

    @property
    def population(self) -> str:
        if self.label == 0:
            return "benign"
        return "botnet_ares" if self.attack_type == PRIMARY_ENDPOINT else "other_attack"


@dataclass(slots=True)
class ExtractionResult:
    features_by_row_id: dict[str, dict[str, float]]
    audit: dict[str, Any]


def file_sha256(path: Path, chunk_size: int = 8 * 1024 * 1024) -> str:
    digest = sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def load_frozen_windows(dataset_path: Path) -> list[FrozenWindow]:
    windows: list[FrozenWindow] = []
    with dataset_path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            pieces = row["entity_key"].split("|", 3)
            if len(pieces) != 4:
                raise ContentExtractionError(f"invalid frozen entity_key: {row['entity_key']!r}")
            source, destination, transport, service = pieces
            windows.append(
                FrozenWindow(
                    row_id=row["row_id"],
                    partition=row["partition"],
                    source=source,
                    destination=destination,
                    transport=transport,
                    service=service,
                    window_start_epoch=int(row["window_start_epoch"]),
                    label=int(row["label"]),
                    attack_type=row.get("attack_type") or "",
                )
            )
    if len(windows) != 70_954 or len({w.row_id for w in windows}) != len(windows):
        raise ContentExtractionError(f"unexpected P1 population size or duplicate: {len(windows)}")
    return windows


def pseudonym(salt: str, canonical_key: str) -> str:
    """Exactly matches Zeek ``sha256_hash(salt, key)``."""
    return sha256((salt + canonical_key).encode("utf-8")).hexdigest()


def pseudonym_map(windows: list[FrozenWindow], salt: str) -> dict[str, str]:
    result = {pseudonym(salt, w.canonical_key()): w.row_id for w in windows}
    if len(result) != len(windows):
        raise ContentExtractionError("pseudonym collision or duplicate canonical P1 key")
    return result


def verify_pcaps(
    pcap_dir: Path, *, full_hash: bool, progress: Any = None
) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    for entry in PARTITIONS:
        path = pcap_dir / entry["pcap"]
        if progress:
            progress(f"verifying {entry['pcap']} ({entry['size']:,} bytes)")
        if not path.is_file():
            raise ContentExtractionError(f"missing frozen PCAP: {path}")
        size = path.stat().st_size
        if size != entry["size"]:
            raise ContentExtractionError(
                f"PCAP size mismatch for {path.name}: {size} != {entry['size']}"
            )
        actual_hash = file_sha256(path) if full_hash else None
        if full_hash and actual_hash != entry["sha256"]:
            raise ContentExtractionError(
                f"PCAP SHA-256 mismatch for {path.name}: {actual_hash}"
            )
        checks.append(
            {
                "pcap": entry["pcap"],
                "size_bytes": size,
                "expected_sha256": entry["sha256"],
                "sha256_verified": bool(full_hash),
                "actual_sha256": actual_hash,
            }
        )
    return checks


def _config_text(partition: str, salt: str, stop_after_seconds: int) -> str:
    stop = f"{stop_after_seconds}secs" if stop_after_seconds else "0secs"
    return (
        f'redef ContentFeature::partition = "{partition}";\n'
        f'redef ContentFeature::pseudonym_salt = "{salt}";\n'
        f"redef ContentFeature::stop_after = {stop};\n"
    )


def _docker_command(
    *, repo_root: Path, pcap_dir: Path, work_dir: Path, pcap_name: str
) -> list[str]:
    return [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=64m",
        "-v",
        f"{pcap_dir}:/pcap:ro",
        "-v",
        f"{repo_root}:/repo:ro",
        "-v",
        f"{work_dir}:/out:rw",
        "-w",
        "/out",
        "--entrypoint",
        "/usr/local/zeek/bin/zeek",
        ZEEK_IMAGE,
        "-D",
        "-C",
        "-r",
        f"/pcap/{pcap_name}",
        "local",
        "LogAscii::use_json=T",
        "Log::default_rotation_interval=0secs",
        "/repo/modules/detection/src/experiments/content_features.zeek",
        "/out/config.zeek",
    ]


def _validate_zeek_record(record: dict[str, Any], clamps: dict[str, int] | None = None) -> None:
    """Enforce the published schema exactly, in place.

    Ratio features are exact quotients of counts and must satisfy ``0 <= v <= 1``
    with no tolerance. The two entropy means are floating-point divisions whose
    result may land a few ulps above 1.0; those are clamped to 1.0 and counted so
    the correction is visible in the audit instead of being silently accepted.
    """
    extra = set(record) - ALLOWED_ZEEK_FIELDS
    if extra:
        raise ContentExtractionError(f"forbidden Zeek output fields: {sorted(extra)}")
    window_key = record.get("window_key")
    if type(window_key) is not str or not HEX64.fullmatch(window_key):
        raise ContentExtractionError(
            f"window_key is not a 64-character hexadecimal pseudonym string: {window_key!r}"
        )
    for name in FEATURE_NAMES:
        if name not in record:
            continue
        value = record[name]
        if type(value) not in (int, float) or type(value) is bool:
            raise ContentExtractionError(f"invalid numeric feature {name}: {value!r}")
        numeric = float(value)
        if not math.isfinite(numeric):
            raise ContentExtractionError(f"invalid numeric feature {name}: {value!r}")
        if numeric < 0.0:
            raise ContentExtractionError(f"out-of-range feature {name}: {value!r}")
        if numeric > 1.0:
            if name in ENTROPY_FEATURES and numeric <= 1.0 + ENTROPY_FLOAT_TOLERANCE:
                record[name] = 1.0
                if clamps is not None:
                    clamps[name] += 1
            else:
                raise ContentExtractionError(f"out-of-range feature {name}: {value!r}")
    for name in AUDIT_COUNT_FIELDS:
        value = record.get(name)
        if type(value) is not int or type(value) is bool or value < 0:
            raise ContentExtractionError(f"invalid audit count {name}: {value!r}")


def _purge_secret_file(path: Path) -> bool:
    """Overwrite then unlink a salt-bearing file; report whether it is gone.

    The overwrite is a best-effort defence-in-depth measure. On journalling or
    flash-translated storage it does not guarantee the previous bytes are
    unrecoverable, so the guarantee claimed in the audit is deliberately limited
    to "the file no longer exists", which is what the return value reports.
    """
    try:
        if path.is_file():
            size = path.stat().st_size
            if size:
                with path.open("r+b", buffering=0) as stream:
                    stream.write(b"\x00" * size)
                    stream.flush()
                    os.fsync(stream.fileno())
            path.unlink()
    except OSError:
        pass
    return not path.exists()


def run_partition(
    *,
    repo_root: Path,
    pcap_dir: Path,
    entry: dict[str, Any],
    salt: str,
    row_by_pseudonym: dict[str, str],
    stop_after_seconds: int = 0,
    timeout_seconds: int | None = None,
    progress: Any = None,
) -> tuple[dict[str, dict[str, float]], dict[str, Any]]:
    """Run one isolated Zeek process and destroy all temporary logs afterward."""
    temp_parent = Path(tempfile.mkdtemp(prefix="cybersentinel-content-"))
    output: dict[str, dict[str, float]] = {}
    try:
        config = temp_parent / "config.zeek"
        config.write_text(
            _config_text(entry["partition"], salt, stop_after_seconds),
            encoding="ascii",
        )
        command = _docker_command(
            repo_root=repo_root,
            pcap_dir=pcap_dir,
            work_dir=temp_parent,
            pcap_name=entry["pcap"],
        )
        completed = subprocess.run(
            command,
            cwd=repo_root,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        if completed.returncode != 0:
            raise ContentExtractionError(
                f"Zeek failed for {entry['partition']} ({completed.returncode}): "
                f"{completed.stderr[-2000:]}"
            )

        log_path = temp_parent / "content_features.log"
        if not log_path.is_file():
            raise ContentExtractionError(
                f"Zeek produced no content_features.log for {entry['partition']}"
            )

        emitted = matched = ignored = 0
        emitted_availability = {name: 0 for name in FEATURE_NAMES}
        clamps = {name: 0 for name in ENTROPY_FEATURES}
        with log_path.open(encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as error:
                    raise ContentExtractionError(
                        f"invalid JSON output line {line_number}"
                    ) from error
                if type(record) is not dict:
                    raise ContentExtractionError("Zeek output root is not an object")
                _validate_zeek_record(record, clamps)
                emitted += 1
                for feature_name in FEATURE_NAMES:
                    emitted_availability[feature_name] += int(feature_name in record)
                row_id = row_by_pseudonym.get(record["window_key"])
                if row_id is None:
                    ignored += 1
                    continue
                if row_id in output:
                    raise ContentExtractionError(f"duplicate extracted P1 row {row_id}")
                output[row_id] = {
                    name: float(record[name])
                    for name in FEATURE_NAMES
                    if name in record
                }
                matched += 1

        names = {path.name for path in temp_parent.iterdir()}
        allowed_temp = {
            "config.zeek",
            "content_features.log",
            "packet_filter.log",
            "reporter.log",
        }
        unexpected = names - allowed_temp
        if unexpected:
            raise ContentExtractionError(
                f"unexpected Zeek temporary outputs: {sorted(unexpected)}"
            )
        stderr_lines = [
            line for line in (completed.stderr or "").splitlines() if line.strip()
        ]
        unexpected_stderr = [
            line
            for line in stderr_lines
            if not any(pattern.search(line) for pattern in EXPECTED_STDERR_PATTERNS)
        ]
        if unexpected_stderr and progress:
            # Shown to the operator for debugging; never written to an artifact.
            progress(
                f"  note: {len(unexpected_stderr)} unexpected Zeek stderr line(s) "
                f"for {entry['partition']} (not persisted)"
            )
        return output, {
            "partition": entry["partition"],
            "pcap": entry["pcap"],
            "bounded_seconds": stop_after_seconds,
            "zeek_rows_emitted": emitted,
            "zeek_feature_availability_rows": emitted_availability,
            "entropy_values_clamped_to_one": dict(sorted(clamps.items())),
            "p1_rows_matched": matched,
            "non_p1_rows_ignored": ignored,
            "zeek_stderr_lines": len(stderr_lines),
            "zeek_stderr_unexpected_lines": len(unexpected_stderr),
            "zeek_stderr_text_persisted": False,
            "temporary_output_fields": sorted(ALLOWED_ZEEK_FIELDS),
            "unexpected_temporary_files": [],
        }
    finally:
        # The salt-bearing config is purged first and independently of rmtree, so
        # that a failure to remove any other temporary file cannot leave the
        # ephemeral salt on disk.
        salt_purged = _purge_secret_file(temp_parent / "config.zeek")
        cleanup_error: str | None = None
        try:
            shutil.rmtree(temp_parent)
        except OSError as error:
            cleanup_error = type(error).__name__
        residue: list[str] = []
        if temp_parent.exists():
            try:
                residue = sorted(item.name for item in temp_parent.iterdir())
            except OSError:
                residue = ["<unreadable>"]
        if residue or not salt_purged:
            # Raised unconditionally. A surviving temporary file must never be
            # silent, even while another exception is already propagating: Python
            # keeps the original error chained as __context__.
            raise ContentExtractionError(
                f"temporary extraction directory was not fully removed "
                f"({cleanup_error or 'residue present'}): {temp_parent}; "
                f"ephemeral salt file purged: {salt_purged}; residue: {residue}"
            )


def check_join_completeness(
    *, partition: str, matched: int, expected: int, enforce: bool
) -> dict[str, Any]:
    """Refuse to continue when a partition matched too few frozen P1 rows.

    A bounded preflight reads only part of a capture, so its match rate carries no
    information and the floor is recorded but not enforced.
    """
    rate = matched / expected if expected else float("nan")
    check = {
        "partition": partition,
        "expected": expected,
        "matched": matched,
        "rate": rate,
        "floor": MINIMUM_PARTITION_MATCH_RATE,
        "enforced": enforce,
    }
    if enforce and not rate >= MINIMUM_PARTITION_MATCH_RATE:
        raise ContentExtractionError(
            f"join completeness guard failed for {partition}: matched "
            f"{matched}/{expected} frozen P1 rows ({rate:.4f} < "
            f"{MINIMUM_PARTITION_MATCH_RATE}); refusing to publish"
        )
    return check


def check_metric_availability(
    availability: dict[str, int], *, enforce: bool
) -> list[str]:
    """Refuse to publish a pre-registered metric that no frozen row ever carried.

    This is the guard the first extraction attempt lacked: the normalized header
    template metric was absent from all 70,954 rows and would have entered the
    benchmark as an all-missing column instead of failing.
    """
    missing = sorted(name for name in FEATURE_NAMES if availability.get(name, 0) == 0)
    if enforce and missing:
        raise ContentExtractionError(
            "pre-registered metrics were never observed on any frozen P1 row: "
            f"{missing}; refusing to publish"
        )
    return missing


def extract(
    *,
    repo_root: Path,
    preflight: bool,
    timeout_seconds: int | None = None,
    preflight_seconds: int = 30,
    progress: Any = None,
) -> ExtractionResult:
    dataset_path = repo_root / "artifacts/experiments/p1/p1_dataset.csv"
    pcap_dir = repo_root / "datasets/cicids2017/pcap"
    windows = load_frozen_windows(dataset_path)
    pcap_checks = verify_pcaps(
        pcap_dir, full_hash=not preflight, progress=progress
    )

    salt = secrets.token_hex(32)
    row_by_hash = pseudonym_map(windows, salt)
    selected = PARTITIONS[1:2] if preflight else PARTITIONS
    expected_by_partition: dict[str, int] = {}
    for window in windows:
        expected_by_partition[window.partition] = (
            expected_by_partition.get(window.partition, 0) + 1
        )
    all_features: dict[str, dict[str, float]] = {}
    runs = []
    join_checks = []
    for entry in selected:
        if progress:
            progress(f"replaying {entry['partition']} with isolated Zeek")
        found, audit = run_partition(
            repo_root=repo_root,
            pcap_dir=pcap_dir,
            entry=entry,
            salt=salt,
            row_by_pseudonym=row_by_hash,
            stop_after_seconds=preflight_seconds if preflight else 0,
            timeout_seconds=timeout_seconds,
            progress=progress,
        )
        expected = expected_by_partition.get(entry["partition"], 0)
        audit["p1_rows_expected"] = expected
        if progress:
            progress(
                f"completed {entry['partition']}: {audit['zeek_rows_emitted']} aggregate windows, "
                f"{audit['p1_rows_matched']}/{expected} P1 matches"
            )
        check = check_join_completeness(
            partition=entry["partition"],
            matched=audit["p1_rows_matched"],
            expected=expected,
            enforce=not preflight,
        )
        audit["p1_match_rate"] = check["rate"]
        join_checks.append(check)
        overlap = set(all_features) & set(found)
        if overlap:
            raise ContentExtractionError(
                f"rows emitted by multiple partitions: {sorted(overlap)[:3]}"
            )
        all_features.update(found)
        runs.append(audit)

    availability = {
        name: sum(name in values for values in all_features.values())
        for name in FEATURE_NAMES
    }
    # Availability split by population. The global guard below cannot see that a
    # metric is present on benign HTTP traffic yet absent from every Ares window,
    # which would make the corresponding arm vacuous on the primary endpoint.
    population_of = {window.row_id: window.population for window in windows}
    population_totals: dict[str, int] = {}
    for window in windows:
        population_totals[window.population] = (
            population_totals.get(window.population, 0) + 1
        )
    availability_by_population: dict[str, dict[str, int]] = {
        group: {name: 0 for name in FEATURE_NAMES} for group in population_totals
    }
    for row_id, values in all_features.items():
        group = population_of[row_id]
        for name in values:
            availability_by_population[group][name] += 1
    absent_on_primary_endpoint = sorted(
        name
        for name in FEATURE_NAMES
        if availability_by_population.get("botnet_ares", {}).get(name, 0) == 0
    )
    if absent_on_primary_endpoint and progress:
        progress(
            "  warning: metrics absent from every "
            f"{PRIMARY_ENDPOINT} window: {absent_on_primary_endpoint}. "
            "Their arms cannot inform the primary endpoint and must be reported as such."
        )

    # The guard that the first extraction attempt lacked.
    never_observed = check_metric_availability(availability, enforce=not preflight)
    return ExtractionResult(
        features_by_row_id=all_features,
        audit={
            "mode": "preflight" if preflight else "full",
            "p1_rows": len(windows),
            "rows_with_any_content_feature": len(all_features),
            "availability_rows": availability,
            "availability_by_population": availability_by_population,
            "population_totals": population_totals,
            "primary_endpoint": PRIMARY_ENDPOINT,
            "metrics_absent_on_primary_endpoint": absent_on_primary_endpoint,
            "metrics_never_observed": never_observed,
            "join_completeness_checks": join_checks,
            "minimum_partition_match_rate": MINIMUM_PARTITION_MATCH_RATE,
            "guard_rationale": (
                "match-rate and metric-availability guards are engineering "
                "sanity checks against a systematic extraction or join defect; "
                "they are not inference thresholds and select nothing"
            ),
            "pcap_checks": pcap_checks,
            "partition_runs": runs,
            "zeek_image": ZEEK_IMAGE,
            "zeek_image_index_sha256": ZEEK_IMAGE_INDEX_SHA256,
            "ephemeral_pseudonym_salt_persisted": False,
            "temporary_directories_removed": True,
            "raw_payload_persisted": False,
            "per_flow_fingerprints_persisted": False,
            "network_access": False,
            "feature_names": list(FEATURE_NAMES),
            "feature_definitions": FEATURE_DEFINITIONS,
            "online_validity": ONLINE_VALIDITY,
        },
    )



def _atomic_publish(path: Path, payload: bytes) -> str:
    """Write once atomically; permit only a byte-identical idempotent rerun."""
    path.parent.mkdir(parents=True, exist_ok=True)
    digest = sha256(payload).hexdigest()
    if path.exists():
        if path.read_bytes() != payload:
            raise FileExistsError(f"immutable artifact differs: {path}")
        return digest
    temporary = path.with_name(f".{path.name}.tmp")
    try:
        with temporary.open("xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return digest


def write_extraction_artifacts(
    *, repo_root: Path, result: ExtractionResult
) -> dict[str, str]:
    """Publish only anonymous P1 row ids and the six pre-registered aggregates."""
    if result.audit.get("mode") != "full":
        raise ContentExtractionError("a bounded preflight may not publish artifacts")
    dataset_path = repo_root / "artifacts/experiments/p1/p1_dataset.csv"
    folds_path = repo_root / "artifacts/experiments/p1/p1_folds.json"
    expected = {
        dataset_path: "e95aed008d994510e4c649c287feb8fe8f49a785bec144d7e83aa15804b6c062",
        folds_path: "57e688fd3da90911707d7a172c161686d852094121eda1ac49e0221fc0529fa1",
    }
    for path, digest in expected.items():
        observed = file_sha256(path)
        if observed != digest:
            raise ContentExtractionError(f"frozen input changed: {path} ({observed})")

    windows = load_frozen_windows(dataset_path)
    import io
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(
        stream, fieldnames=("row_id", *FEATURE_NAMES), lineterminator="\n"
    )
    writer.writeheader()
    for window in windows:
        values = result.features_by_row_id.get(window.row_id, {})
        writer.writerow(
            {
                "row_id": window.row_id,
                **{
                    name: format(values[name], ".17g") if name in values else ""
                    for name in FEATURE_NAMES
                },
            }
        )
    csv_payload = stream.getvalue().encode("utf-8")

    out_dir = repo_root / "artifacts/experiments/xgboost_content_benchmark"
    csv_digest = _atomic_publish(out_dir / "content_features.csv", csv_payload)
    audit = dict(result.audit)
    audit.update(
        {
            "published_rows": len(windows),
            "published_columns": ["row_id", *FEATURE_NAMES],
            "p1_dataset_file_sha256": expected[dataset_path],
            "p1_folds_file_sha256": expected[folds_path],
            "content_features_csv_sha256": csv_digest,
            "zeek_script_sha256": file_sha256(
                repo_root / "modules/detection/src/experiments/content_features.zeek"
            ),
            "extractor_module_sha256": file_sha256(Path(__file__)),
            "persistent_identifiers": "frozen P1 UUID row_id only",
            "forbidden_persistent_fields": [
                "salt",
                "IP address",
                "port",
                "URI",
                "hostname",
                "cookie",
                "header value",
                "payload",
                "payload fingerprint",
                "header-template fingerprint",
            ],
        }
    )
    audit_payload = (
        json.dumps(audit, indent=2, sort_keys=True, allow_nan=False).encode("utf-8")
        + b"\n"
    )
    audit_digest = _atomic_publish(
        out_dir / "content_extraction_audit.json", audit_payload
    )
    manifest = {
        "experiment": "first-wave PCAP content feature extraction",
        "existing_milestones_modified": False,
        "p1_population_or_folds_modified": False,
        "published_artifacts": {
            "content_features.csv": csv_digest,
            "content_extraction_audit.json": audit_digest,
        },
        "source_inputs": {
            "p1_dataset.csv": expected[dataset_path],
            "p1_folds.json": expected[folds_path],
            **{entry["pcap"]: entry["sha256"] for entry in PARTITIONS},
        },
        "excluded_pcap": "Thursday-WorkingHours.pcap",
        "arms_pre_registered": {
            arm: list(features) for arm, features in ARM_FEATURES.items()
        },
        "arm_i_adaptive_selection": False,
        "raw_payload_persisted": False,
        "ephemeral_salt_persisted": False,
    }
    manifest_payload = (
        json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    )
    manifest_digest = _atomic_publish(
        out_dir / "content_extraction_manifest.json", manifest_payload
    )
    return {
        "content_features.csv": csv_digest,
        "content_extraction_audit.json": audit_digest,
        "content_extraction_manifest.json": manifest_digest,
    }
