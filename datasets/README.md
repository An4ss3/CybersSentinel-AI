# Data

Raw datasets are **not committed**: CICIDS2017 is about 50 GB and is
distributed by the Canadian Institute for Cybersecurity (CIC) under its own
terms. Only the frozen data contracts in `manifests/` are versioned. They pin
the exact size and SHA-256 of every capture, so a locally downloaded copy can
be checked byte for byte.

## What is needed

| Purpose | Files | Expected location |
|---|---|---|
| Main experiment (re-run from frozen artifacts) | none | — |
| Full pipeline rebuild (Zeek replay onward) | the five working-day PCAPs | `datasets/cicids2017/pcap/` |
| Legacy demonstration models only | the `*.pcap_ISCX.csv` files | `datasets/cicids2017/` |

The main experiment and the test suite run **without any dataset**: they read
the frozen artifacts committed under `artifacts/`.

## Where to obtain CICIDS2017

- Official page: <https://www.unb.ca/cic/datasets/ids-2017.html>
- Download (registration may be required): <https://cicresearch.ca/CICDataset/CIC-IDS-2017/>

`python scripts/download_datasets.py --list` prints the sources and creates the
local directory layout.

## Verifying a local copy

The expected size and SHA-256 of each capture are recorded in
`manifests/cicids2017_pcap_freeze.yaml`, `manifests/monday_benign_pcap_freeze.yaml`
and `manifests/thursday_pcap_freeze.yaml`. Any mismatch means a different file
and invalidates comparison with the published results.
