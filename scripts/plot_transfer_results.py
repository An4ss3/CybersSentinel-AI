"""Render the README results figure from the frozen transfer artifact.

Reads ``artifacts/experiments/transfer_v1/transfer_results.json`` and nothing
else. No model is loaded, no score is recomputed and no threshold is touched:
every plotted value is copied from the frozen artifact, so the figure can be
regenerated and audited by anyone.

Usage (from the repository root):
    python scripts/plot_transfer_results.py
"""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
RESULTS = REPO_ROOT / "artifacts" / "experiments" / "transfer_v1" / "transfer_results.json"
OUTPUT = REPO_ROOT / "docs" / "assets" / "transfer_results.png"

# Display names, in the protocol order of the frozen artifact (not a ranking).
LABELS = {
    "brute_force/ftp_patator": "FTP-Patator",
    "brute_force/ssh_patator": "SSH-Patator",
    "dos/hulk": "DoS Hulk",
    "dos/slowloris": "DoS Slowloris",
    "dos/slowhttptest": "DoS SlowHTTPTest",
    "dos/goldeneye": "DoS GoldenEye",
    "ddos/loit": "DDoS LOIT",
}
CALIBRATION_TARGET = 0.01  # FPR target applied on the Monday validation benign set
TOLERANCE = 0.02           # pre-registered descriptive tolerance on Thursday


def main() -> int:
    data = json.loads(RESULTS.read_text(encoding="utf-8"))
    folds = data["folds"]
    names = [LABELS[f["family"]] for f in folds]
    y = list(range(len(folds)))[::-1]  # first fold at the top

    fig, (ax_r, ax_f) = plt.subplots(
        1, 2, figsize=(11, 3.9), sharey=True, gridspec_kw={"width_ratios": [1.15, 1]}
    )

    # Panel A: episode recall with the Wilson 95 % interval from the artifact.
    for yi, f in zip(y, folds):
        lo, hi = f["episode_recall_wilson_95"]
        ax_r.plot([lo, hi], [yi, yi], color="#444444", lw=1.6, solid_capstyle="butt")
        ax_r.plot([lo, lo], [yi - 0.13, yi + 0.13], color="#444444", lw=1.2)
        ax_r.plot([hi, hi], [yi - 0.13, yi + 0.13], color="#444444", lw=1.2)
        ax_r.plot(f["episode_recall"], yi, "o", color="#1f4e79", ms=6, zorder=3)
        ax_r.text(1.04, yi, f"{f['episode_detected']}/{f['episode_total']}",
                  va="center", fontsize=9)
    ax_r.set_xlim(0, 1.13)
    ax_r.set_yticks(y, names)
    ax_r.set_xlabel("Episode recall at the frozen threshold (Wilson 95 % CI)")
    ax_r.set_title("A. Held-out family detection", loc="left", fontsize=10)

    # Panel B: Thursday false-positive rate, measured (not calibrated).
    for yi, f in zip(y, folds):
        ax_f.barh(yi, f["thursday_fpr"] * 100, color="#9db4c8", height=0.55)
        ax_f.text(f["thursday_fpr"] * 100 + 0.04, yi,
                  f"{f['thursday_fpr'] * 100:.4f} %  ({f['thursday_false_positives']} FP)",
                  va="center", fontsize=8.5, zorder=3,
                  bbox={"facecolor": "white", "edgecolor": "none", "pad": 0.5})
    ax_f.axvline(CALIBRATION_TARGET * 100, color="#555555", ls="--", lw=1, zorder=1)
    ax_f.axvline(TOLERANCE * 100, color="#555555", ls=":", lw=1, zorder=1)
    ax_f.text(CALIBRATION_TARGET * 100 + 0.03, len(folds) - 0.45, "calibration target 1 %",
              ha="left", fontsize=8)
    ax_f.text(TOLERANCE * 100 - 0.03, len(folds) - 1.5, "tolerance 2 %",
              ha="right", fontsize=8)
    ax_f.set_xlim(0, 2.1)
    ax_f.set_xlabel(f"Thursday false-positive rate (%), n = {folds[0]['thursday_benign_windows']:,}")
    ax_f.set_title("B. False alarms on an independent capture day", loc="left", fontsize=10)

    for ax in (ax_r, ax_f):
        ax.spines[["top", "right"]].set_visible(False)
        ax.set_ylim(-0.6, len(folds) - 0.2)

    pooled = data["pooled"]
    lo, hi = pooled["episode_recall_wilson_95"]
    fig.text(
        0.01, -0.02,
        f"Pooled: {pooled['episode_detected']}/{pooled['episode_total']} held-out episodes detected "
        f"(Wilson 95 % CI [{lo:.3f}, {hi:.3f}]; folds are not independent, so the interval is indicative). "
        "Families are listed in protocol order, not ranked.",
        fontsize=8, color="#333333",
    )
    fig.tight_layout()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(OUTPUT, dpi=150, bbox_inches="tight")
    print(f"wrote {OUTPUT.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
