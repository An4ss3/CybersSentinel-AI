"""Publish the MB2 specification and execute the real Monday Benign Zeek replay.

Thin production entrypoint over ``MondayBenignReplayRunner``. It performs no
integrity logic of its own: every guarantee comes from the already-tested MB2
contracts, the MB2 binding, and the inherited M2 runner internals.

Sequence
--------
1. Load the published MB1 manifest and take its real ``content_sha256``.
2. Construct the MB2 specification. The Zeek runtime pin, determinism policy and
   output policy are declared explicitly from MB-track constants; **no M chain
   manifest is read**, so MB2 is textually independent of M2 while remaining
   provably identical on the runtime digest, which the contract enforces.
3. Publish the specification YAML under the existing immutability policy
   (``_write_immutable_bytes``: exclusive create, ``fsync``, idempotent on
   identical content, ``FileExistsError`` on divergent content).
4. Reload the published YAML, bind it to the MB1 manifest, and let the runner
   verify the Compose pairing before any container starts.
5. Execute the replay through the ``zeek-replay-mb`` service only.

The frozen M2 tree and the ``zeek-replay`` service are never referenced. The
Monday PCAP is opened in binary read mode only.
"""
from __future__ import annotations

import argparse
from collections.abc import Sequence
from datetime import datetime, timezone
import json
from pathlib import Path

import yaml

from modules.detection.src.ingestion.monday_benign_replay import (
    MondayBenignReplayRunner,
)
from modules.detection.src.lineage.dataset_freeze import (
    _write_immutable_bytes,
    load_dataset_freeze_manifest,
)
from modules.detection.src.schemas.monday_benign_replay import (
    M2_ZEEK_IMAGE_INDEX_DIGEST,
    M2_ZEEK_PLATFORM_MANIFEST_DIGEST,
    M2_ZEEK_VERSION,
    MB1_MANIFEST_RELATIVE_PATH,
    MB2_OUTPUT_ROOT,
    MB2_SPECIFICATION_RELATIVE_PATH,
    MONDAY_PCAP_RELATIVE_PATH,
    MondayBenignReplaySpecification,
)
from modules.detection.src.schemas.replay import (
    ZeekDeterminismPolicy,
    ZeekOutputPolicy,
    ZeekRuntimePin,
)


REPO_ROOT = Path(__file__).resolve().parents[1]

AUTHORITATIVE_SOURCES = (
    "https://community.zeek.org/t/deterministic-uids/3838",
    "https://docs.zeek.org/en/lts/quickstart.html",
    "https://hub.docker.com/r/zeek/zeek",
)


def parse_utc_datetime(value: str) -> datetime:
    """Parse an explicit UTC timestamp without silently converting timezones."""
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"invalid ISO-8601 timestamp: {value}"
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(None):
        raise argparse.ArgumentTypeError(
            "timestamp must be explicit UTC, for example 2026-08-13T12:00:00Z"
        )
    return parsed


def build_monday_benign_replay_specification(
    repository_root: Path,
    *,
    frozen_at: datetime,
    specification_version: str = "1.0.0",
) -> MondayBenignReplaySpecification:
    """Build the MB2 specification from the published MB1 manifest."""
    manifest = load_dataset_freeze_manifest(
        repository_root / MB1_MANIFEST_RELATIVE_PATH
    )
    return MondayBenignReplaySpecification(
        specification_version=specification_version,
        frozen_at=frozen_at,
        m1_manifest_path=MB1_MANIFEST_RELATIVE_PATH,
        m1_manifest_sha256=manifest.content_sha256(),
        dataset_name=manifest.dataset_name,
        inputs=manifest.files,
        runtime=ZeekRuntimePin(
            zeek_version=M2_ZEEK_VERSION,
            image_repository="zeek/zeek",
            image_tag=M2_ZEEK_VERSION,
            image_index_digest=M2_ZEEK_IMAGE_INDEX_DIGEST,
            platform="linux/amd64",
            platform_manifest_digest=M2_ZEEK_PLATFORM_MANIFEST_DIGEST,
        ),
        determinism=ZeekDeterminismPolicy(
            execution_mode="offline_single_process",
            process_count=1,
            random_seed=1,
            checksum_policy="ignore_invalid_checksums",
            timezone="UTC",
            locale="C",
            loaded_scripts=("local",),
            external_packages=(),
            json_logs=True,
            log_rotation_interval_seconds=0,
            command_template=(
                "zeek",
                "-D",
                "-C",
                "-r",
                "{pcap}",
                "local",
                "LogAscii::use_json=T",
                "Log::default_rotation_interval=0secs",
            ),
        ),
        output=ZeekOutputPolicy(
            output_root=MB2_OUTPUT_ROOT,
            partitioning="one_directory_per_pcap",
            existing_output_policy="fail_if_exists",
            log_format="json_lines",
            retention="all_emitted_logs",
            canonical_log_policy="all_emitted_except_operational_runtime",
            excluded_operational_logs=(
                "packet_filter.log",
                "stats.log",
                "telemetry.log",
            ),
            operational_log_directory="operational",
            required_logs=("conn.log",),
            protocol_logs_of_interest=(
                "conn.log",
                "dns.log",
                "files.log",
                "http.log",
                "ssh.log",
                "ssl.log",
            ),
            artifact_hash_algorithm="sha256",
            immutable_after_validation=True,
        ),
        authoritative_sources=AUTHORITATIVE_SOURCES,
    )


def publish_specification(
    specification: MondayBenignReplaySpecification,
    path: Path,
) -> str:
    """Write the MB2 specification once and return its content identity."""
    payload = yaml.safe_dump(
        specification.model_dump(mode="json"),
        sort_keys=False,
        allow_unicode=False,
    ).encode("utf-8")
    _write_immutable_bytes(path, payload)
    return specification.content_sha256()


def main(argv: Sequence[str] | None = None) -> int:
    """Publish the MB2 specification, replay Monday, print a JSON summary."""
    parser = argparse.ArgumentParser(
        description="Publish the MB2 specification and replay the Monday PCAP."
    )
    parser.add_argument("--frozen-at", type=parse_utc_datetime, required=True)
    parser.add_argument(
        "--specification-only",
        action="store_true",
        help="publish and verify the specification without running Zeek",
    )
    args = parser.parse_args(argv)

    specification_path = REPO_ROOT / MB2_SPECIFICATION_RELATIVE_PATH
    specification = build_monday_benign_replay_specification(
        REPO_ROOT,
        frozen_at=args.frozen_at,
    )
    specification_sha256 = publish_specification(specification, specification_path)

    runner = MondayBenignReplayRunner.from_repository(REPO_ROOT)
    runner._verify_compose_pairing()

    summary: dict[str, object] = {
        "specification_path": MB2_SPECIFICATION_RELATIVE_PATH,
        "specification_sha256": specification_sha256,
        "m1_manifest_sha256": runner.mb2_bound.m1_manifest_sha256,
        "output_root": specification.output.output_root,
        "output_partition": specification.output_partition,
        "compose_pairing": "verified",
    }
    if args.specification_only:
        summary["status"] = "specification_published"
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0

    started = datetime.now(timezone.utc)
    report = runner.replay(MONDAY_PCAP_RELATIVE_PATH)
    summary.update(
        {
            "status": "verified",
            "report_content_sha256": report.content_sha256(),
            "compose_service": report.compose_service,
            "compose_profile": report.compose_profile,
            "image_index_digest": report.runtime.image_index_digest,
            "log_count": len(report.logs),
            "canonical_log_count": len(report.canonical_logs),
            "operational_log_count": len(report.operational_logs),
            "logs": [
                {
                    "log_name": item.log_name,
                    "classification": item.classification,
                    "size_bytes": item.size_bytes,
                    "record_count": item.record_count,
                    "sha256": item.sha256,
                }
                for item in report.logs
            ],
            "started_at": report.started_at.isoformat(),
            "completed_at": report.completed_at.isoformat(),
            "elapsed_seconds": round(
                (report.completed_at - started).total_seconds(), 1
            ),
        }
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
