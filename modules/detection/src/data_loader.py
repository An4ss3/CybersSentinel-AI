"""CICIDS2017 loader and cleaning utilities (Couche 3).

The CICIDS2017 CSVs (CICFlowMeter output) have well-known quirks:
  * column names carry leading/trailing whitespace,
  * some numeric columns contain Infinity / NaN,
  * the label column is named "Label" (sometimes " Label").

This module concatenates the per-day CSVs and returns a clean numeric
feature matrix plus the raw string labels.
"""
from __future__ import annotations

import glob
import os
from typing import Tuple

import numpy as np
import pandas as pd

LABEL_CANDIDATES = ("Label", "label", " Label")


def _find_label_column(df: pd.DataFrame) -> str:
    for name in LABEL_CANDIDATES:
        if name in df.columns:
            return name
    raise KeyError(
        f"No label column found. Columns seen: {list(df.columns)[:8]}..."
    )


def load_cicids2017(
    data_dir: str, filenames: list[str] | None = None
) -> Tuple[pd.DataFrame, pd.Series]:
    """Load and concatenate CICIDS2017 CSVs under ``data_dir``.

    Parameters
    ----------
    data_dir : str
        Directory containing the CICIDS2017 CSVs.
    filenames : list[str] | None
        If given, only these files (relative to ``data_dir``) are loaded.
        Useful to load a subset (e.g. one day) instead of all 8 CSVs.

    Returns
    -------
    features : pd.DataFrame
        Numeric feature matrix (inf/nan handled, non-informative cols dropped).
    labels : pd.Series
        Raw string labels (e.g. "BENIGN", "SSH-Patator").
    """
    if filenames:
        csv_files = [os.path.join(data_dir, f) for f in filenames]
        missing = [p for p in csv_files if not os.path.exists(p)]
        if missing:
            raise FileNotFoundError(f"Requested CSV(s) not found: {missing}")
    else:
        pattern = os.path.join(data_dir, "*.csv")
        csv_files = sorted(glob.glob(pattern))
    if not csv_files:
        raise FileNotFoundError(
            f"No CSV files found in '{data_dir}'. "
            "Run scripts/download_datasets.py first (see its output for the "
            "CICIDS2017 download instructions)."
        )

    frames = []
    for path in csv_files:
        df = pd.read_csv(path, low_memory=False)
        df.columns = df.columns.str.strip()  # fix leading/trailing spaces
        frames.append(df)

    data = pd.concat(frames, ignore_index=True)

    label_col = _find_label_column(data)
    labels = data[label_col].astype(str).str.strip()
    features = data.drop(columns=[label_col])

    # Drop identifier / non-predictive columns if present.
    drop_cols = [
        c for c in features.columns
        if c.lower() in {
            "flow id", "source ip", "src ip", "destination ip", "dst ip",
            "timestamp", "fwd header length.1",
        }
    ]
    features = features.drop(columns=drop_cols, errors="ignore")

    # Keep numeric columns only, then sanitise inf/nan.
    features = features.apply(pd.to_numeric, errors="coerce")
    features = features.replace([np.inf, -np.inf], np.nan)
    features = features.fillna(0.0)

    # Drop constant (zero-variance) columns — they carry no signal.
    nunique = features.nunique()
    constant_cols = nunique[nunique <= 1].index.tolist()
    features = features.drop(columns=constant_cols, errors="ignore")

    return features, labels


def make_binary_target(
    labels: pd.Series, positive_labels: list[str], benign_label: str
) -> pd.Series:
    """Map raw labels to 1 (attack of interest) / 0 (benign).

    Rows whose label is neither in ``positive_labels`` nor ``benign_label``
    are dropped by the caller via the returned NaN marker.
    """
    positive = set(positive_labels)
    target = pd.Series(np.nan, index=labels.index, dtype="float")
    target[labels.isin(positive)] = 1.0
    target[labels == benign_label] = 0.0
    return target
