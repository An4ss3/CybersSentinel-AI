"""Run the TH2 deterministic Zeek replay for the Thursday capture.

Additive counterpart of ``scripts/replay_monday_benign.py``. It executes only the
opt-in ``zeek-replay-th`` Compose service and publishes into the independent TH2
tree. The frozen M2 and MB2 trees are never opened for writing.

Usage::

    python -m scripts.replay_thursday
"""
from __future__ import annotations

import argparse
from collections.abc import Sequence
import json
from pathlib import Path

from modules.detection.src.ingestion.thursday_replay import (
    TH2_SPECIFICATION_RELATIVE_PATH,
    replay_thursday,
)


REPO_ROOT = Path(__file__).resolve().parents[1]


def build_parser() -> argparse.ArgumentParser:
    """Return the TH2 replay command-line interface."""
    parser = argparse.ArgumentParser(
        description="Deterministic Zeek replay of the Thursday CICIDS2017 capture."
    )
    parser.add_argument("--repository-root", type=Path, default=REPO_ROOT)
    parser.add_argument(
        "--specification-path",
        type=Path,
        default=Path(TH2_SPECIFICATION_RELATIVE_PATH),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Execute the replay and print a deterministic JSON summary."""
    args = build_parser().parse_args(argv)
    report = replay_thursday(
        args.repository_root,
        specification_path=args.specification_path,
    )
    summary = {
        "status": report.verification_status,
        "output_partition": report.output_partition,
        "specification_sha256": report.specification_sha256,
        "m1_manifest_sha256": report.m1_manifest_sha256,
        "command": list(report.command),
        "canonical_logs": sorted(
            item.log_name
            for item in report.logs
            if item.classification == "canonical_telemetry"
        ),
        "conn_log_records": next(
            item.record_count
            for item in report.logs
            if item.log_name == "conn.log"
        ),
        "total_logs": len(report.logs),
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
