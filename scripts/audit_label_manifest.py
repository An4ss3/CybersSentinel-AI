"""Generate CICIDS2017 M5 manifest schedule and overlap audit reports."""
from __future__ import annotations

import argparse
from pathlib import Path

from modules.detection.src.lineage.label_reports import (
    build_manifest_audit,
    write_reports,
)
from modules.detection.src.lineage.labeling import LabelLedger


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path("datasets/manifests/cicids2017_labels.yaml"),
    )
    parser.add_argument(
        "--output-directory",
        type=Path,
        default=Path("artifacts/reports"),
    )
    args = parser.parse_args()

    ledger = LabelLedger.from_yaml(args.manifest)
    coverage, ambiguity = build_manifest_audit(ledger)
    coverage_path, ambiguity_path = write_reports(
        coverage,
        ambiguity,
        args.output_directory,
        "cicids2017_label_manifest",
    )
    print(f"coverage_report={coverage_path}")
    print(f"ambiguity_report={ambiguity_path}")


if __name__ == "__main__":
    main()
