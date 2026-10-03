#!/usr/bin/env python3
"""
SCRIPT #3e: Sensitivity of personalized PageRank to alpha
Purpose: Re-run personalized PageRank for several damping factors and record
         how the known vulnerable functions' ranks change.

alpha = probability that a random walk keeps following calls at each step
        (1 - alpha = probability it jumps back to a seed). Higher alpha lets
        the score spread deeper into the code behind the entry points.

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

sys.path.insert(0, str(PROJECT_ROOT / "analysis"))
from callgraph import load_call_graph
from metrics import evaluate


def main():
    print("=" * 70)
    print("🎚️  ALPHA SENSITIVITY (personalized PageRank)")
    print("=" * 70)

    with open(GROUND_TRUTH_FILE, "r") as f:
        ground_truth = json.load(f)
    with open(SEEDS_FILE, "r") as f:
        seeds = list(json.load(f)["seeds"])
    targets = [vf["name"] for data in ground_truth.values()
               for vf in data["vulnerable_functions"] if vf.get("verified")]

    graph = load_call_graph()
    personalization = {s: 1.0 for s in seeds}

    rows = []
    for alpha in ALPHAS:
        scores = nx.pagerank(graph, alpha=alpha, personalization=personalization,
                             max_iter=500, tol=1e-08)
        for scope, exclude in (("all", ()), ("non_seed", seeds)):
            ev = evaluate(scores, targets, exclude=exclude)
            row = {"alpha": alpha, "scope": scope, "mrr": round(ev["mrr"], 4),
                   **{f"recall@{k}": v for k, v in ev["recall"].items()},
                   **{fn: ev["ranks"][fn] for fn in targets}}
            rows.append(row)
            ranks = "  ".join(f"{fn}=#{ev['ranks'][fn]:.0f}" for fn in targets)
            print(f"   alpha={alpha:<5} {scope:9s} {ranks}")

    OUTPUT_PATH.mkdir(parents=True, exist_ok=True)
    out_csv = OUTPUT_PATH / "alpha_sensitivity.csv"
    with open(out_csv, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    print(f"\n💾 Saved: {out_csv}")

    with open(OUTPUT_PATH / "alpha_sensitivity_summary.txt", "w") as f:
        f.write("ALPHA SENSITIVITY - rank of each vulnerable function (personalized PageRank)\n\n")
        for scope in ("all", "non_seed"):
            f.write(f"Scope: {scope}\n   {'alpha':>6s}" + "".join(f"{t:>26s}" for t in targets) + f"{'MRR':>8s}\n")
            for row in rows:
                if row["scope"] == scope:
                    f.write(f"   {row['alpha']:>6}" + "".join(f"{row[t]:>26.0f}" for t in targets)
                            + f"{row['mrr']:>8.3f}\n")
            f.write("\n")

    fig, axes = plt.subplots(1, 2, figsize=(13, 5), sharey=True)
    for ax, scope in zip(axes, ("all", "non_seed")):
        for t in targets:
            ax.plot(ALPHAS, [r[t] for r in rows if r["scope"] == scope], marker="o", label=t)
        ax.axvline(0.85, color="grey", linestyle="--", alpha=0.6, label="default alpha 0.85")
        ax.set_yscale("log")
        ax.set_xlabel("alpha (damping factor)")
        ax.set_title(f"Scope: {scope.replace('_', '-')} functions")
    axes[0].set_ylabel("Rank (log scale, lower = better)")
    axes[0].legend(fontsize=8)
    fig.suptitle("Personalized PageRank: rank of vulnerable functions vs alpha",
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
