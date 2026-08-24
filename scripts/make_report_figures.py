"""Generate advisor-ready figures from saved results (corrected + expert model).

Writes PNG figures to artifacts/reports/figures/:
  * confusion_matrices.png  — production (all variants) vs cross-variant holdout
  * recall_comparison.png   — production vs holdout@0.5 vs LOVO-average (HONEST)
  * lovo_recall.png         — per-variant recall under leave-one-variant-out CV
  * alert_levels.png        — distribution of scored alerts by criticality

Run from the repo root:
    python scripts/make_report_figures.py
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
REPORTS = REPO_ROOT / "artifacts" / "reports"
FIGS = REPORTS / "figures"
ATTACKS = ["brute_force", "ddos"]


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def confusion_matrices() -> None:
    protocols = ["production", "holdout"]
    fig, axes = plt.subplots(len(ATTACKS), len(protocols), figsize=(9, 8))
    for r, attack in enumerate(ATTACKS):
        for c, proto in enumerate(protocols):
            m = _load(REPORTS / f"{attack}_metrics_{proto}.json")
            cm = m["confusion_matrix"]
            grid = np.array([[cm["tn"], cm["fp"]], [cm["fn"], cm["tp"]]])
            ax = axes[r][c]
            ax.imshow(grid, cmap="Blues")
            for (i, j), v in np.ndenumerate(grid):
                ax.text(j, i, f"{v:,}", ha="center", va="center", fontsize=11)
            ax.set_xticks([0, 1]); ax.set_xticklabels(["pred benign", "pred attack"])
            ax.set_yticks([0, 1]); ax.set_yticklabels(["true benign", "true attack"])
            tag = "all variants (random split)" if proto == "production" else "1 unseen variant"
            ax.set_title(f"{attack} — {proto}\n{tag}  (recall={m['recall']:.3f})", fontsize=9)
    fig.suptitle("Confusion matrices: production (all variants) vs cross-variant holdout",
                 fontsize=12)
    fig.tight_layout(); fig.savefig(FIGS / "confusion_matrices.png", dpi=120); plt.close(fig)


def recall_comparison() -> None:
    """HONEST comparison — no threshold-tuning claim."""
    prod, hold, lovo = [], [], []
    for attack in ATTACKS:
        prod.append(_load(REPORTS / f"{attack}_metrics_production.json")["recall"])
        hold.append(_load(REPORTS / f"{attack}_metrics_holdout.json")["recall"])
        lovo.append(_load(REPORTS / f"{attack}_lovo.json")["average"]["recall"])

    x = np.arange(len(ATTACKS)); w = 0.25
    fig, ax = plt.subplots(figsize=(9, 5.5))
    b1 = ax.bar(x - w, prod, w, label="production — all variants, random split (optimistic)", color="#8ecae6")
    b2 = ax.bar(x, hold, w, label="cross-variant holdout @0.5 (1 unseen variant)", color="#fb8500")
    b3 = ax.bar(x + w, lovo, w, label="leave-one-variant-out avg @0.5 (honest generalisation)", color="#219ebc")
    for bars in (b1, b2, b3):
        for b in bars:
            ax.text(b.get_x() + b.get_width() / 2, b.get_height() + 0.02,
                    f"{b.get_height():.2f}", ha="center", fontsize=8)
    ax.set_xticks(x); ax.set_xticklabels(ATTACKS)
    ax.set_ylabel("Recall (detection rate)"); ax.set_ylim(0, 1.12)
    ax.set_title("Detection recall @0.5: optimistic vs honest generalisation")
    ax.legend(fontsize=8, loc="upper right"); ax.grid(axis="y", alpha=0.3)
    fig.tight_layout(); fig.savefig(FIGS / "recall_comparison.png", dpi=120); plt.close(fig)


def lovo_recall() -> None:
    """Per-variant recall under leave-one-variant-out CV."""
    fig, axes = plt.subplots(1, len(ATTACKS), figsize=(12, 5))
    for ax, attack in zip(axes, ATTACKS):
        data = _load(REPORTS / f"{attack}_lovo.json")
        folds = data["folds"]
        names = [f["held_out"] for f in folds]
        recalls = [f["recall"] for f in folds]
        avg = data["average"]["recall"]
        colors = ["#2a9d8f" if r >= 0.5 else "#e76f51" for r in recalls]
        ax.barh(names, recalls, color=colors)
        for i, r in enumerate(recalls):
            ax.text(r + 0.01, i, f"{r:.2f}", va="center", fontsize=8)
        ax.axvline(avg, color="black", linestyle="--", linewidth=1, label=f"avg = {avg:.2f}")
        ax.set_xlim(0, 1.1); ax.set_xlabel("Recall on the held-out (unseen) variant @0.5")
        ax.set_title(f"{attack} — leave-one-variant-out")
        ax.legend(fontsize=8)
    fig.suptitle("Cross-variant generalisation: recall on each unseen variant", fontsize=12)
    fig.tight_layout(); fig.savefig(FIGS / "lovo_recall.png", dpi=120); plt.close(fig)


def _alert_level_counts() -> Counter:
    """Prefer PostgreSQL (current state); fall back to JSONL."""
    try:
        from modules.backend.app import db
        conn = db.get_connection()
        if conn is not None:
            with conn.cursor() as cur:
                cur.execute("SELECT level, count(*) FROM alerts GROUP BY level;")
                rows = cur.fetchall()
            conn.close()
            if rows:
                return Counter({lvl: n for lvl, n in rows})
    except Exception:
        pass
    path = REPO_ROOT / "artifacts" / "alerts.jsonl"
    if path.exists():
        return Counter(json.loads(l)["level"] for l in path.read_text(encoding="utf-8").splitlines())
    return Counter()


def alert_levels() -> None:
    counts = _alert_level_counts()
    if not counts:
        print("[skip] no alerts found (Postgres or JSONL)")
        return
    order = ["Critical", "High", "Medium", "Low"]
    colors = {"Critical": "#d00000", "High": "#f48c06", "Medium": "#ffba08", "Low": "#95d5b2"}
    vals = [counts.get(k, 0) for k in order]
    fig, ax = plt.subplots(figsize=(7, 4.5))
    bars = ax.bar(order, vals, color=[colors[k] for k in order])
    for b, v in zip(bars, vals):
        ax.text(b.get_x() + b.get_width() / 2, v + max(vals) * 0.01, str(v), ha="center")
    ax.set_ylabel("Number of alerts")
    ax.set_title(f"Scored alerts by criticality (§6.3) — {sum(vals)} alerts (production model)")
    fig.tight_layout(); fig.savefig(FIGS / "alert_levels.png", dpi=120); plt.close(fig)


def main() -> None:
    FIGS.mkdir(parents=True, exist_ok=True)
    confusion_matrices()
    recall_comparison()
    lovo_recall()
    alert_levels()
    print(f"Figures written to {FIGS.relative_to(REPO_ROOT)}:")
    for p in sorted(FIGS.glob("*.png")):
        print(f"  - {p.name}")


if __name__ == "__main__":
    main()
