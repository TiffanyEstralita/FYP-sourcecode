#!/usr/bin/env python3
"""
SCRIPT #3e: Sensitivity of personalized PageRank to alpha
Purpose: Re-run personalized PageRank for several damping factors and record
         how well it ranks the known vulnerable functions.

alpha = probability that a random walk keeps following calls at each step
        (1 - alpha = probability it jumps back to a seed). Higher alpha lets
        the score spread deeper into the code behind the entry points.

alpha should be CHOSEN on the tuning CVEs only; the test CVEs are reported
alongside so the choice can be checked, not to pick the best value.

Output: results/processed/alpha_sensitivity.csv (+ _summary.txt)
        results/visualizations/8_alpha_sensitivity.png
"""

import csv
import json
import sys
from pathlib import Path

import matplotlib.pyplot as plt
import networkx as nx

# Windows terminals use a non-UTF-8 encoding by default and crash on emoji output
sys.stdout.reconfigure(encoding="utf-8")

PROJECT_ROOT = Path(__file__).resolve().parents[2]

GROUND_TRUTH_FILE = PROJECT_ROOT / "validation/cve_data/vulnerable_functions.json"
SEEDS_FILE = PROJECT_ROOT / "results/processed/seeds.json"
OUTPUT_PATH = PROJECT_ROOT / "results/processed"
CHART_PATH = PROJECT_ROOT / "results/visualizations"

ALPHAS = [0.5, 0.6, 0.7, 0.8, 0.85, 0.9, 0.95]
SPLITS = ("tuning", "test")

sys.path.insert(0, str(PROJECT_ROOT / "analysis"))
from callgraph import load_call_graph
from metrics import behind_entry_points, evaluate, load_ground_truth


def main():
    print("=" * 70)
    print("🎚️  ALPHA SENSITIVITY (personalized PageRank)")
    print("=" * 70)

    cves, splits = load_ground_truth(GROUND_TRUTH_FILE)
    with open(SEEDS_FILE, "r") as f:
        seeds = list(json.load(f)["seeds"])
    behind, _ = behind_entry_points(cves, set(seeds))
    subsets = {s: {"all": {c: f for c, f in cves.items() if splits[c] == s},
                   "non_seed": {c: f for c, f in behind.items() if splits[c] == s}}
               for s in SPLITS}

    graph = load_call_graph()
    personalization = {s: 1.0 for s in seeds}

    rows = []
    for alpha in ALPHAS:
        scores = nx.pagerank(graph, alpha=alpha, personalization=personalization,
                             max_iter=500, tol=1e-08)
        for split in SPLITS:
            for scope, exclude in (("all", ()), ("non_seed", seeds)):
                ev = evaluate(scores, subsets[split][scope], exclude=exclude)
                rows.append({"alpha": alpha, "split": split, "scope": scope,
                             "mrr": round(ev["mrr"], 5), "median_rank": ev["median_rank"],
                             **{f"recall@{k}": round(v, 3) for k, v in ev["recall"].items()}})
        tun = next(r for r in rows if r["alpha"] == alpha and r["split"] == "tuning" and r["scope"] == "all")
        tst = next(r for r in rows if r["alpha"] == alpha and r["split"] == "test" and r["scope"] == "all")
        print(f"   alpha={alpha:<5} tuning: MRR={tun['mrr']:.4f} median=#{tun['median_rank']:.0f}   "
              f"test: MRR={tst['mrr']:.4f} median=#{tst['median_rank']:.0f}")

    best = max((r for r in rows if r["split"] == "tuning" and r["scope"] == "all"),
               key=lambda r: (r["mrr"], -r["median_rank"]))
    print(f"\n✅ Best alpha on the TUNING CVEs (by MRR): {best['alpha']}")

    OUTPUT_PATH.mkdir(parents=True, exist_ok=True)
    out_csv = OUTPUT_PATH / "alpha_sensitivity.csv"
    with open(out_csv, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    with open(OUTPUT_PATH / "alpha_sensitivity_summary.txt", "w") as f:
        f.write("ALPHA SENSITIVITY - personalized PageRank (CVE rank = best vulnerable function)\n")
        f.write(f"Best alpha on the tuning CVEs (by MRR): {best['alpha']}\n\n")
        f.write(f"{'alpha':>6s} {'split':>7s} {'scope':>9s} {'MRR':>8s} {'median':>8s} "
                f"{'R@100':>6s} {'R@500':>6s}\n")
        for r in rows:
            f.write(f"{r['alpha']:>6} {r['split']:>7s} {r['scope']:>9s} {r['mrr']:>8.4f} "
                    f"{r['median_rank']:>8.0f} {r['recall@100']:>6.2f} {r['recall@500']:>6.2f}\n")
    print(f"💾 Saved: {out_csv} (+ _summary.txt)")

    fig, axes = plt.subplots(1, 2, figsize=(13, 5))
    for split, style in (("tuning", "-"), ("test", "--")):
        sel = [r for r in rows if r["split"] == split and r["scope"] == "all"]
        axes[0].plot(ALPHAS, [r["mrr"] for r in sel], style, marker="o", label=f"{split} CVEs")
        axes[1].plot(ALPHAS, [r["median_rank"] for r in sel], style, marker="o", label=f"{split} CVEs")
    for ax in axes:
        ax.axvline(0.85, color="grey", linestyle=":", alpha=0.6, label="default alpha 0.85")
        ax.set_xlabel("alpha (damping factor)")
        ax.legend(fontsize=8)
    axes[0].set_ylabel("MRR (higher = better)")
    axes[1].set_ylabel("Median CVE rank (lower = better)")
    fig.suptitle("Personalized PageRank vs alpha (choose on tuning CVEs only)",
                 fontsize=13, fontweight="bold")
    plt.tight_layout()
    CHART_PATH.mkdir(parents=True, exist_ok=True)
    out = CHART_PATH / "8_alpha_sensitivity.png"
    plt.savefig(out, dpi=200, bbox_inches="tight")
    plt.close()
    print(f"💾 Saved: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
