"""Dataset acquisition helper for CyberSentinel AI (§8).

Most SOC/IDS research datasets are large and gated behind a registration or
license click-through, so they cannot be blindly wget-ed. This script:

  * creates the local datasets/ layout,
  * prints the official source + instructions for each dataset,
  * downloads the ones that expose a direct, license-clear URL.

Usage:
    python scripts/download_datasets.py            # show all + create dirs
    python scripts/download_datasets.py --list     # just print the sources
    python scripts/download_datasets.py nsl_kdd    # attempt an auto-download
"""
from __future__ import annotations

import argparse
import sys
import urllib.request
from pathlib import Path

# Windows consoles default to cp1252/cp437 and choke on the "§"/"—" markers
# used below. Force UTF-8 so the script prints correctly everywhere.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, ValueError):  # pragma: no cover
    pass

REPO_ROOT = Path(__file__).resolve().parents[1]
DATASETS_DIR = REPO_ROOT / "datasets"

# name -> (subdir, description, source_url, auto_download_url|None)
DATASETS = {
    "cicids2017": (
        "cicids2017",
        "Labelled network flows, multi-attack (incl. FTP/SSH-Patator brute force).",
        "https://www.unb.ca/cic/datasets/ids-2017.html",
        None,  # requires accepting UNB terms; download the MachineLearningCSV.zip
    ),
    "cicids2018": (
        "cicids2018",
        "CSE-CIC-IDS2018 — larger successor to CICIDS2017 (AWS-hosted).",
        "https://www.unb.ca/cic/datasets/ids-2018.html",
        None,
    ),
    "nsl_kdd": (
        "nsl_kdd",
        "Classic intrusion-detection benchmark (cleaned KDD'99).",
        "https://www.unb.ca/cic/datasets/nsl.html",
        None,
    ),
    "unsw_nb15": (
        "unsw_nb15",
        "Modern IDS benchmark with realistic normal + attack traffic.",
        "https://research.unsw.edu.au/projects/unsw-nb15-dataset",
        None,
    ),
    "loghub": (
        "loghub",
        "Real anonymised system logs (Linux, Hadoop, ...) for log normalisation.",
        "https://github.com/logpai/loghub",
        None,
    ),
    "malimg": (
        "malimg",
        "Malware-as-image dataset for the CNN classifier (§6.2 malware).",
        "https://www.kaggle.com/datasets/manmandes/malimg",
        None,
    ),
}


def ensure_dirs() -> None:
    DATASETS_DIR.mkdir(parents=True, exist_ok=True)
    (DATASETS_DIR / ".gitkeep").touch()
    for subdir, *_ in DATASETS.values():
        (DATASETS_DIR / subdir).mkdir(parents=True, exist_ok=True)


def print_sources() -> None:
    print("\nCyberSentinel AI — datasets (§8)\n" + "=" * 40)
    for name, (subdir, desc, url, auto) in DATASETS.items():
        flag = "auto-download" if auto else "manual download"
        print(f"\n[{name}]  ({flag})")
        print(f"  {desc}")
        print(f"  Source : {url}")
        print(f"  Place files in: datasets/{subdir}/")
    print(
        "\nNote: CICIDS2017 is the entry point for the brute-force model. "
        "Download 'MachineLearningCSV.zip', unzip it, and put the *.csv files "
        "in datasets/cicids2017/."
    )


def download(name: str) -> None:
    if name not in DATASETS:
        print(f"Unknown dataset '{name}'. Options: {', '.join(DATASETS)}")
        sys.exit(1)
    subdir, desc, url, auto = DATASETS[name]
    if not auto:
        print(f"'{name}' needs manual download (license/registration).")
        print(f"  Source: {url}")
        print(f"  Then place the files in datasets/{subdir}/")
        return
    dest = DATASETS_DIR / subdir / Path(auto).name
    print(f"Downloading {name} -> {dest} ...")
    urllib.request.urlretrieve(auto, dest)  # noqa: S310 (trusted, license-clear URL)
    print("Done.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Acquire CyberSentinel datasets.")
    parser.add_argument("dataset", nargs="?", help="dataset name to auto-download")
    parser.add_argument("--list", action="store_true", help="print sources only")
    args = parser.parse_args()

    if args.list:
        print_sources()
        return

    ensure_dirs()
    if args.dataset:
        download(args.dataset)
    else:
        print_sources()
        print(f"\nCreated datasets/ layout under {DATASETS_DIR}")


if __name__ == "__main__":
    main()
