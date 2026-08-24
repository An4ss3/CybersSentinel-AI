"""Run the isolated first-wave PCAP content feature extraction."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

from modules.detection.src.experiments.content_extractor import (
    extract,
    write_extraction_artifacts,
)


REPO_ROOT = Path(__file__).resolve().parents[1]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Extract six pre-registered aggregate content metrics from frozen M1 PCAPs"
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--preflight", action="store_true")
    mode.add_argument("--execute", action="store_true")
    parser.add_argument(
        "--preflight-seconds",
        type=int,
        default=2400,
        help="bounded Tuesday network-time interval; 2400 reaches frozen P1 FTP windows",
    )
    parser.add_argument("--timeout-seconds", type=int, default=None)
    args = parser.parse_args(argv)
    if args.preflight_seconds < 1:
        parser.error("--preflight-seconds must be positive")

    def progress(message: str) -> None:
        print(message, flush=True)

    result = extract(
        repo_root=REPO_ROOT,
        preflight=args.preflight,
        preflight_seconds=args.preflight_seconds,
        timeout_seconds=args.timeout_seconds,
        progress=progress,
    )
    if args.preflight:
        print(json.dumps(result.audit, indent=2, sort_keys=True))
        print("PREFLIGHT ONLY: no artifact, database row, salt, or payload was persisted.")
        return 0

    digests = write_extraction_artifacts(repo_root=REPO_ROOT, result=result)
    print("published anonymous aggregate artifacts:")
    for name, digest in digests.items():
        print(f"  {name}: {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
