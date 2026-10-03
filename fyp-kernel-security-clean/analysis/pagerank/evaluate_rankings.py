#!/usr/bin/env python3
"""
SCRIPT #3d: Compare rankings on the known CVEs
Purpose: Put every ranking side by side and measure how early each one
         ranks the known vulnerable functions.

Rankings compared (skipped if the file does not exist):
  baseline      - Phase 0 standard PageRank on the original call graph
  standard      - standard PageRank on the improved call graph (Phase 1)
  personalized  - personalized PageRank from the seeds (Phase 3)

Each is evaluated twice:
  all        - rank among all functions
  non_seed   - rank among functions that are not seeds. Seeds (entry points)
               get a high personalized score by construction, so this shows
               how well the method ranks code BEHIND the entry points.

Metrics (see analysis/metrics.py): rank, recall@K, MRR.
Output: results/processed/evaluation.json, evaluation.csv, evaluation_summary.txt
        results/visualizations/7_ranking_comparison.png
"""

import csv
import json
import sys
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np

# Windows terminals use a non-UTF-8 encoding by default and crash on emoji output
sys.stdout.reconfigure(encoding="utf-8")

PROJECT_ROOT = Path(__file__).resolve().parents[2]

GROUND_TRUTH_FILE = PROJECT_ROOT / "validation/cve_data/vulnerable_functions.json"
SEEDS_FILE = PROJECT_ROOT / "results/processed/seeds.json"
OUTPUT_PATH = PROJECT_ROOT / "results/processed"
CHART_PATH = PROJECT_ROOT / "results/visualizations"

RANKINGS = {
    "baseline": PROJECT_ROOT / "results/baseline/pagerank_scores.json",
    "standard": PROJECT_ROOT / "results/processed/pagerank_scores.json",
    "personalized": PROJECT_ROOT / "results/processed/ppr_scores.json",
}

sys.path.insert(0, str(PROJECT_ROOT / "analysis"))
from metrics import evaluate


def load_json(path):
    with open(path, "r") as f:
        return json.load(f)


def main():
    print("=" * 70)
    print("📏 EVALUATE RANKINGS ON KNOWN CVEs")
    print("=" * 70)

    ground_truth = load_json(GROUND_TRUTH_FILE)
    targets = {vf["name"]: cve_id
               for cve_id, data in ground_truth.items()
               for vf in data["vulnerable_functions"] if vf.get("verified")}
    seeds = set(load_json(SEEDS_FILE)["seeds"]) if SEEDS_FILE.exists() else set()

    results = {}
    for name, path in RANKINGS.items():
        if not path.exists():
            print(f"⚠️  {name}: {path.name} not found - skipped")
            continue
        scores = load_json(path)
        results[name] = {
            "all": evaluate(scores, targets),
            "non_seed": evaluate(scores, targets, exclude=seeds),
        }

    # ---- print + text summary ----
    lines = []
    for scope in ("all", "non_seed"):
        lines.append(f"\nRank of each vulnerable function - scope: {scope}")
        header = f"   {'CVE / function':45s}" + "".join(f"{n:>14s}" for n in results)
        lines.append(header)
        for fn, cve_id in targets.items():
            row = f"   {cve_id + ' ' + fn:45s}"
            for name in results:
                r = results[name][scope]["ranks"][fn]
                n = results[name][scope]["ranked_functions"]
                row += f"{(f'{r:.0f}/{n}' if r else 'n/a'):>14s}"
            lines.append(row)
        for metric in ("recall@10", "recall@20", "recall@100", "MRR"):
            row = f"   {metric:45s}"
            for name in results:
                ev = results[name][scope]
                value = ev["mrr"] if metric == "MRR" else ev["recall"][int(metric.split("@")[1])]
                row += f"{value:>14.3f}"
            lines.append(row)
    for line in lines:
        print(line)

    OUTPUT_PATH.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_PATH / "evaluation.json", "w") as f:
        json.dump({"targets": targets, "seed_count": len(seeds), "results": results}, f, indent=2)
    with open(OUTPUT_PATH / "evaluation_summary.txt", "w") as f:
        f.write("=" * 70 + "\nEVALUATION: RANK OF KNOWN VULNERABLE FUNCTIONS\n" + "=" * 70 + "\n")
        f.write("Rankings: " + ", ".join(results) + f"   (seeds excluded in non_seed scope: {len(seeds)})\n")
        f.write("Ties share the average position. Lower rank = found earlier.\n")
        f.write("\n".join(lines) + "\n")
    with open(OUTPUT_PATH / "evaluation.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["ranking", "scope", "cve", "function", "rank", "ranked_functions"])
        for name, scopes in results.items():
            for scope, ev in scopes.items():
                for fn, cve_id in targets.items():
                    writer.writerow([name, scope, cve_id, fn, ev["ranks"][fn], ev["ranked_functions"]])
    print(f"\n💾 Saved: {OUTPUT_PATH / 'evaluation.json'} (+ .csv, _summary.txt)")

    # ---- chart: rank per CVE per ranking (log scale, lower = better) ----
    fig, axes = plt.subplots(1, 2, figsize=(14, 5), sharey=True)
    width = 0.8 / max(1, len(results))
    x = np.arange(len(targets))
    for ax, scope in zip(axes, ("all", "non_seed")):
        for i, name in enumerate(results):
            ranks = [results[name][scope]["ranks"][fn] or np.nan for fn in targets]
            bars = ax.bar(x + i * width, ranks, width, label=name)
            for bar, r in zip(bars, ranks):
                ax.text(bar.get_x() + bar.get_width() / 2, r * 1.08, f"{r:.0f}",
                        ha="center", fontsize=8)
        ax.set_yscale("log")
        ax.set_xticks(x + width * (len(results) - 1) / 2)
        ax.set_xticklabels([f"{c}\n{fn}" for fn, c in targets.items()], fontsize=8)
        ax.axhline(10, color="green", linestyle=":", label="top 10")
        ax.axhline(100, color="orange", linestyle=":", label="top 100")
        ax.set_title(f"Scope: {scope.replace('_', '-')} functions", fontsize=11)
        ax.set_ylabel("Rank (log scale, lower = better)")
    axes[0].legend(fontsize=8)
    fig.suptitle("Rank of each known vulnerable function by ranking method",
                 fontsize=13, fontweight="bold")
    plt.tight_layout()
    CHART_PATH.mkdir(parents=True, exist_ok=True)
    out = CHART_PATH / "7_ranking_comparison.png"
    plt.savefig(out, dpi=200, bbox_inches="tight")
    plt.close()
    print(f"💾 Saved: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
