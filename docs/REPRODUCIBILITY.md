# Reproducibility guide

Every command below was run on a fresh clone of this repository. Outputs quoted
here are the ones observed.

## Requirements

| Tool | Version | Needed for |
|---|---|---|
| Python | 3.12 | everything |
| Docker + Docker Compose | recent | demonstration services and Zeek replay only |
| CICIDS2017 PCAPs | see [`datasets/README.md`](../datasets/README.md) | full pipeline rebuild only |

No dataset and no Docker service is needed to run the tests or to re-execute
the main experiment.

## Installation

```bash
git clone <repository-url> cybersentinel-ai
cd cybersentinel-ai
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r modules/detection/requirements.txt -r modules/backend/requirements.txt
```

All dependencies are pinned to exact versions.

## Tests

```bash
python -m pytest -q
```

Observed on a fresh clone: **1199 passed, 77 skipped** (about 2 minutes).
In the full local workspace: **1212 passed, 64 skipped**. The difference is
explained by the skip reasons, which pytest prints with `-rs`:

| Skip reason | Count | How to enable |
|---|---:|---|
| PostgreSQL test database unreachable | 62 | start PostgreSQL and create `cybersentinel_test` |
| Frozen Zeek replay logs not distributed | 13 | regenerate them with the Zeek replay service |
| Symbolic links unavailable (Windows only) | 2 | run on Linux/macOS or with symlink privileges |

## Re-running the main experiment

```bash
python -m scripts.run_transfer_experiment
```

Runs the seven leave-one-family-out folds in about 2.5 minutes, from the frozen
datasets in `artifacts/production/`. **It overwrites
`artifacts/experiments/transfer_v1/`**; use `git diff` afterwards to compare.

Observed result: all seven model digests, thresholds and episode, window and
false-positive counts are identical to the committed artifact. The only
differences are the `executed_at` / `frozen_at` timestamps and, as a
consequence, the freeze-record digests. Restore the committed state with
`git checkout -- artifacts/experiments/transfer_v1`.

## Integrity verification

```bash
python scripts/verify_preregistration.py
```

Recomputes the pinned SHA-256 digests and checks 83 protocol properties. On a
fresh clone, 82 of 83 pass and the script exits with code 1: the remaining
check requires the Thursday Zeek `conn.log` (~139 MB), which is not
distributed. With the full local workspace, all 83 pass.

## Results figure

```bash
python scripts/plot_transfer_results.py
```

Writes `assets/figures/transfer-results.png`, reading only the frozen
`transfer_results.json`.

## Demonstration services (optional)

```bash
cp .env.example .env                 # then replace every change_me value
docker compose up -d postgres grafana
uvicorn modules.backend.app.main:app --reload
```

`docker compose` refuses to start without the passwords defined in `.env`.
The API answers `GET /health`. `POST /score` needs the legacy XGBoost models,
which are not committed; train them first from the CICIDS2017 CSV files, e.g.
`python -m modules.detection.src.train --attack brute_force --protocol production`.

The API has **no authentication** and must not be exposed outside a local lab.
It uses the legacy models, not the models evaluated in the main experiment.

## Full pipeline rebuild (advanced)

Rebuilding from raw PCAPs requires the five CICIDS2017 captures in
`datasets/cicids2017/pcap/` (sizes and digests checked against
`datasets/manifests/`), the digest-pinned Zeek replay services
(`docker compose --profile zeek-replay ...`) and a PostgreSQL instance for the
canonical event tables. Each stage has its own script under `scripts/` and its
own frozen run report under `artifacts/reports/`; see
[`PROJECT_INDEX.md`](PROJECT_INDEX.md) for the order of the stages.
