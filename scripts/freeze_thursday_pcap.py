"""Freeze and verify the Thursday CICIDS2017 capture for TH1 (Thursday track).

This is the TH-track counterpart of ``scripts/freeze_cicids2017_pcaps.py`` and
``scripts/freeze_monday_benign_pcap.py``. It is a **new script**, not a
modification: the frozen M1 script excludes Thursday by design through its
``APPROVED_CAPTURE_DATES`` allowlist, and the MB1 script requires exactly Monday.
Neither exclusion is touched, and neither script is imported.

Why Thursday is frozen
----------------------
Thursday is the only CICIDS2017 working-hours capture that has never entered the
canonical chain. The audited role of this freeze is twofold and strictly scoped:

1. it is the candidate source of **capture-disjoint benign negatives**, so that a
   future holdout can measure a false-positive rate on a day that never
   contributed to threshold calibration;
2. it carries two attack families absent from the M chain, ``web_attack`` and
   ``infiltration``, which are *not* part of the seven priority families.

Freezing the evidence is a prerequisite for answering the still-open empirical
question recorded in ``label_policy_v3.json``: whether the NAT behaviour observed
elsewhere on the M chain, where the logical attacker ``205.174.165.73`` is never
a source and the gateway ``172.16.0.1`` is, also holds on Thursday. That question
is deliberately **not** answered here; this script only fixes the bytes.

Integrity primitives
--------------------
Every primitive is reused from ``lineage/dataset_freeze.py`` exactly as it
exists, with no wrapper reimplementation:

* ``build_dataset_freeze_manifest`` -> measures size and SHA-256 via
  ``inventory_pcap_evidence``;
* ``verify_dataset_freeze`` -> containment, symlink, regular-file, size,
  SHA-256, and stability-during-hash checks;
* ``build_dataset_verification_report`` -> binds totals to the inventory;
* ``write_immutable_dataset_manifest`` / ``write_immutable_verification_report``
  -> exclusive create, ``fsync``, idempotent on identical content, refusal on
  divergent content.

The publish-then-reload-then-verify ordering of the M1 and MB1 scripts is
reproduced exactly, so the TH1 report is bound to the serialized repository bytes
rather than to the in-memory manifest.

Additional cross-check
----------------------
Beyond the SHA-256 inventory, this script also verifies the capture against the
**publisher-provided MD5** already present in the repository at
``datasets/cicids2017/md5/Thursday-WorkingHours.md5``. SHA-256 proves *which*
bytes were used; the MD5 comparison independently corroborates that those bytes
are the ones the Canadian Institute for Cybersecurity published. A mismatch
aborts the freeze before anything is written.

The Thursday PCAP is only ever opened in binary read mode. No byte under
``datasets/cicids2017/pcap/`` is written, copied, or moved. No frozen artifact of
M1, M2, M3, M4, M5, M6 or the MB track is read for mutation or written.

Usage
-----
``retrieved_at`` and ``frozen_at`` are mandatory and explicit, exactly as in the
M1 and MB1 scripts, so a freeze is never silently stamped with an incidental
clock read::

    python -m scripts.freeze_thursday_pcap \
        --retrieved-at 2026-07-28T13:08:25.402744Z \
        --frozen-at 2026-09-03T21:15:00Z

The Thursday capture was acquired in the same publisher-gate session as the three
M1 captures and the MB1 Monday capture, so passing the M1 manifest's
``retrieved_at`` is the accurate provenance statement.
"""
from __future__ import annotations

import argparse
from collections.abc import Sequence
from datetime import date, datetime, timezone
from hashlib import md5
import json
from pathlib import Path

from modules.detection.src.lineage.dataset_freeze import (
    build_dataset_freeze_manifest,
    build_dataset_verification_report,
    load_dataset_freeze_manifest,
    verify_dataset_freeze,
    write_immutable_dataset_manifest,
    write_immutable_verification_report,
)
from modules.detection.src.schemas import DatasetSource


REPO_ROOT = Path(__file__).resolve().parents[1]

#: Thursday capture identity. Declared here so no existing module is edited.
THURSDAY_CAPTURE_DATE = date(2017, 7, 6)
THURSDAY_PCAP_RELATIVE_PATH = "Thursday-WorkingHours.pcap"

TH1_MANIFEST_RELATIVE_PATH = "datasets/manifests/thursday_pcap_freeze.yaml"
TH1_VERIFICATION_REPORT_RELATIVE_PATH = (
    "artifacts/canonical/cicids2017/th1/dataset_freeze_verification.json"
)
OFFICIAL_MD5_RELATIVE_PATH = "datasets/cicids2017/md5/Thursday-WorkingHours.md5"

DEFAULT_DATASET_ROOT = REPO_ROOT / "datasets" / "cicids2017" / "pcap"
DEFAULT_MANIFEST_PATH = REPO_ROOT / TH1_MANIFEST_RELATIVE_PATH
DEFAULT_REPORT_PATH = REPO_ROOT / TH1_VERIFICATION_REPORT_RELATIVE_PATH
DEFAULT_OFFICIAL_MD5_PATH = REPO_ROOT / OFFICIAL_MD5_RELATIVE_PATH

# Identical official provenance strings as the M1 and MB1 freezes: same
# publisher, same landing page, same download gate. Referenced by value; no M1
# or MB1 file is read.
OFFICIAL_PUBLISHER = "Canadian Institute for Cybersecurity"
OFFICIAL_LANDING_PAGE = "https://www.unb.ca/cic/datasets/ids-2017.html"
OFFICIAL_DOWNLOAD_GATE = "https://cicresearch.ca/CICDataset/CIC-IDS-2017/"

APPROVED_TH1_CAPTURE_DATES = frozenset((THURSDAY_CAPTURE_DATE,))
SELECTION_RATIONALE = (
    "Complete Thursday CICIDS2017 capture frozen as an independent, previously "
    "unused capture of the parallel Thursday track. Its audited purpose is to "
    "supply capture-disjoint benign reference traffic for a future holdout and "
    "to carry the web_attack and infiltration families, which are absent from "
    "the M chain and are not among the seven priority families. This freeze is "
    "additive: it fixes the evidence bytes only, resolves no labelling or NAT "
    "question, and leaves the M1 three-day canonical freeze and the MB1 Monday "
    "freeze unchanged."
)

MD5_READ_CHUNK_BYTES = 8 * 1024 * 1024


class ThursdayFreezeScopeError(ValueError):
    """Raised when a freeze request is not exactly the Thursday capture."""


class ThursdayFreezeIntegrityError(RuntimeError):
    """Raised when the capture does not match the publisher-provided MD5."""


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
            "timestamp must be explicit UTC, for example 2026-09-03T21:15:00Z"
        )
    return parsed


def read_official_md5(md5_path: Path, expected_filename: str) -> str:
    """Return the lowercase MD5 the publisher declared for ``expected_filename``."""
    text = md5_path.read_text(encoding="ascii")
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        parts = stripped.split()
        if len(parts) < 2:
            raise ThursdayFreezeIntegrityError(
                f"malformed MD5 record in {md5_path}: {stripped!r}"
            )
        digest, name = parts[0], parts[-1].lstrip("*")
        if name == expected_filename:
            return digest.lower()
    raise ThursdayFreezeIntegrityError(
        f"{md5_path} declares no digest for {expected_filename}"
    )


def compute_md5(path: Path) -> str:
    """Stream the file in binary read mode and return its lowercase MD5."""
    digest = md5()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(MD5_READ_CHUNK_BYTES)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest().lower()


def cross_check_official_md5(
    *, pcap_path: Path, official_md5_path: Path, expected_filename: str
) -> dict[str, str]:
    """Corroborate the frozen bytes against the publisher-provided MD5."""
    declared = read_official_md5(official_md5_path, expected_filename)
    observed = compute_md5(pcap_path)
    if declared != observed:
        raise ThursdayFreezeIntegrityError(
            "Thursday PCAP does not match the publisher MD5: "
            f"declared {declared}, observed {observed}"
        )
    return {
        "official_md5_path": str(official_md5_path),
        "declared_md5": declared,
        "observed_md5": observed,
        "md5_matches": "true",
    }


def freeze_thursday_pcap(
    *,
    dataset_root: Path,
    manifest_path: Path,
    report_path: Path,
    official_md5_path: Path,
    file_capture_dates: dict[str, date],
    retrieved_at: datetime,
    frozen_at: datetime,
) -> dict[str, object]:
    """Build, verify, and immutably persist the TH1 Thursday evidence freeze.

    The scope guard mirrors the M1 and MB1 guards: M1 requires exactly Tuesday,
    Wednesday and Friday; MB1 requires exactly Monday; TH1 requires exactly
    Thursday. No track can silently ingest another's evidence.
    """
    if set(file_capture_dates.values()) != APPROVED_TH1_CAPTURE_DATES:
        raise ThursdayFreezeScopeError(
            "TH1 freeze scope must contain exactly the Thursday "
            f"{THURSDAY_CAPTURE_DATE.isoformat()} capture"
        )
    if len(file_capture_dates) != 1:
        raise ThursdayFreezeScopeError(
            "TH1 freeze scope must contain exactly one PCAP"
        )
    if tuple(file_capture_dates) != (THURSDAY_PCAP_RELATIVE_PATH,):
        raise ThursdayFreezeScopeError(
            f"TH1 freeze scope must be {THURSDAY_PCAP_RELATIVE_PATH}"
        )

    # Corroborate against the publisher digest before anything is written.
    md5_cross_check = cross_check_official_md5(
        pcap_path=dataset_root / THURSDAY_PCAP_RELATIVE_PATH,
        official_md5_path=official_md5_path,
        expected_filename=THURSDAY_PCAP_RELATIVE_PATH,
    )

    source = DatasetSource(
        publisher=OFFICIAL_PUBLISHER,
        landing_page_url=OFFICIAL_LANDING_PAGE,
        download_url=OFFICIAL_DOWNLOAD_GATE,
        retrieved_at=retrieved_at,
    )
    manifest = build_dataset_freeze_manifest(
        dataset_root=dataset_root,
        file_capture_dates=file_capture_dates,
        source=source,
        frozen_at=frozen_at,
        selection_rationale=SELECTION_RATIONALE,
    )

    # Verify before persistence, then reload and verify the exact serialized
    # manifest so the final report is bound to repository bytes.
    verify_dataset_freeze(manifest, dataset_root)
    manifest_sha256 = write_immutable_dataset_manifest(manifest, manifest_path)
    persisted_manifest = load_dataset_freeze_manifest(manifest_path)
    verification = verify_dataset_freeze(persisted_manifest, dataset_root)
    report = build_dataset_verification_report(persisted_manifest, verification)
    report_sha256 = write_immutable_verification_report(report, report_path)

    return {
        "status": "verified",
        "track": "thursday",
        "dataset_root": str(dataset_root),
        "manifest_path": str(manifest_path),
        "manifest_sha256": manifest_sha256,
        "report_path": str(report_path),
        "report_sha256": report_sha256,
        "selected_capture_days": [
            item.isoformat() for item in persisted_manifest.selected_capture_days
        ],
        "verified_file_count": report.verified_file_count,
        "verified_total_size_bytes": report.verified_total_size_bytes,
        "pcap_sha256": persisted_manifest.files[0].sha256,
        "md5_cross_check": md5_cross_check,
    }


def build_parser() -> argparse.ArgumentParser:
    """Return the TH1 command-line interface."""
    parser = argparse.ArgumentParser(
        description=(
            "Freeze and verify the Thursday CICIDS2017 capture for the TH track."
        )
    )
    parser.add_argument("--dataset-root", type=Path, default=DEFAULT_DATASET_ROOT)
    parser.add_argument("--manifest-path", type=Path, default=DEFAULT_MANIFEST_PATH)
    parser.add_argument("--report-path", type=Path, default=DEFAULT_REPORT_PATH)
    parser.add_argument(
        "--official-md5-path", type=Path, default=DEFAULT_OFFICIAL_MD5_PATH
    )
    parser.add_argument(
        "--capture",
        default=THURSDAY_PCAP_RELATIVE_PATH,
        help="relative path of the Thursday PCAP under the dataset root",
    )
    parser.add_argument("--retrieved-at", type=parse_utc_datetime, required=True)
    parser.add_argument("--frozen-at", type=parse_utc_datetime, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the TH1 freeze and print a deterministic JSON summary."""
    args = build_parser().parse_args(argv)
    result = freeze_thursday_pcap(
        dataset_root=args.dataset_root,
        manifest_path=args.manifest_path,
        report_path=args.report_path,
        official_md5_path=args.official_md5_path,
        file_capture_dates={args.capture: THURSDAY_CAPTURE_DATE},
        retrieved_at=args.retrieved_at,
        frozen_at=args.frozen_at,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
