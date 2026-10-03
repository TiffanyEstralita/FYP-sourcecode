#!/usr/bin/env python3
"""
SCRIPT #3d: Compare rankings on the known CVEs
Purpose: Put every ranking side by side and measure how early each one
         ranks the known vulnerable functions.

Rankings compared (skipped if the file does not exist):
  baseline      - Phase 0 standard PageRank on the original call graph
  standard      - standard PageRank on the improved call graph (Phase 1)
  personalized  - personalized PageRank from the seeds (Phase 3)

A CVE's rank is the rank of its best-ranked vulnerable function.
Results are reported for the whole evaluation set and for its tuning and
test parts, each in two scopes:
  all        - rank among all functions
  non_seed   - rank among functions that are not seeds. Seeds (entry points)
               get a high personalized score by construction, so this shows
               how well the method ranks code BEHIND the entry points.
               Vulnerable functions that are seeds are left out; a CVE whose
               vulnerable functions are ALL seeds is not scored in this scope.

Metrics (see analysis/metrics.py): rank, recall@K, MRR, median rank.
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
SPLITS = ("all", "tuning", "test")
SCOPES = ("all", "non_seed")
REPORT_KS = (10, 20, 100, 500)

sys.path.insert(0, str(PROJECT_ROOT / "analysis"))
from metrics import behind_entry_points, evaluate, load_ground_truth


def load_json(path):
    with open(path, "r") as f:
        return json.load(f)


def fmt_rank(r):
    return f"{r:.0f}" if r is not None else "n/a"


def main():
    print("=" * 70)
    print("📏 EVALUATE RANKINGS ON KNOWN CVEs")
    print("=" * 70)

    cves, splits = load_ground_truth(GROUND_TRUTH_FILE)
    seeds = set(load_json(SEEDS_FILE)["seeds"]) if SEEDS_FILE.exists() else set()
    behind, entry_only = behind_entry_points(cves, seeds)
    subsets = {}
    for split in SPLITS:
        pick = lambda pool: {c: f for c, f in pool.items() if split == "all" or splits[c] == split}
        subsets[split] = {"all": pick(cves), "non_seed": pick(behind)}
    print(f"   {len(cves)} CVEs: " + ", ".join(f"{s}={len(subsets[s]['all'])}" for s in SPLITS[1:]))
    if entry_only:
        print(f"   vulnerable functions are all entry points (not scored in non_seed scope): {entry_only}")

    results = {}
    for name, path in RANKINGS.items():
        if not path.exists():
            print(f"⚠️  {name}: {path.name} not found - skipped")
            continue
        scores = load_json(path)
        results[name] = {split: {scope: evaluate(scores, subsets[split][scope],
                                                 exclude=seeds if scope == "non_seed" else ())
                                 for scope in SCOPES}
                         for split in SPLITS}
    names = list(results)

    # ---- per-CVE table (rank among all functions) ----
    lines = ["\nRank of each CVE (best-ranked vulnerable function, among all functions)",
             f"   {'CVE':16s} {'split':7s}" + "".join(f"{n:>14s}" for n in names)]
    for cve_id in cves:
        lines.append(f"   {cve_id:16s} {splits[cve_id]:7s}" + "".join(
            f"{fmt_rank(results[n]['all']['all']['ranks'][cve_id]):>14s}" for n in names))

    # ---- summary metrics ----
    if entry_only:
        lines.append(f"\nCVEs whose vulnerable functions are all entry points (seeds), "
                     f"not scored in the non_seed scope: {', '.join(entry_only)}")
    for split in SPLITS:
        for scope in SCOPES:
            lines.append(f"\nSummary - {split} CVEs ({len(subsets[split][scope])}), scope: {scope}")
            for metric in [f"recall@{k}" for k in REPORT_KS] + ["MRR", "median rank"]:
                row = f"   {metric:16s}{'':8s}"
                for n in names:
                    ev = results[n][split][scope]
                    if metric == "MRR":
                        row += f"{ev['mrr']:>14.4f}"
                    elif metric == "median rank":
                        row += f"{fmt_rank(ev['median_rank']):>14s}"
                    else:
                        row += f"{ev['recall'][int(metric.split('@')[1])]:>14.2f}"
                lines.append(row)
    for line in lines:
        print(line)

    OUTPUT_PATH.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_PATH / "evaluation.json", "w") as f:
        json.dump({"cves": cves, "splits": splits, "seed_count": len(seeds), "results": results},
                  f, indent=2)
    with open(OUTPUT_PATH / "evaluation_summary.txt", "w") as f:
        f.write("=" * 70 + "\nEVALUATION: RANK OF KNOWN VULNERABLE FUNCTIONS\n" + "=" * 70 + "\n")
        f.write(f"Rankings: {', '.join(names)}   (seeds excluded in non_seed scope: {len(seeds)})\n")
        f.write("A CVE's rank = rank of its best-ranked vulnerable function. "
                "Ties share the average position. Lower = found earlier.\n")
        f.write("\n".join(lines) + "\n")
    with open(OUTPUT_PATH / "evaluation.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["ranking", "scope", "cve", "split", "rank", "ranked_functions"])
        for n in names:
            for scope in SCOPES:
                ev = results[n]["all"][scope]
                for cve_id in cves:
                    writer.writerow([n, scope, cve_id, splits[cve_id], ev["ranks"].get(cve_id),
                                     ev["ranked_functions"]])
    print(f"\n💾 Saved: {OUTPUT_PATH / 'evaluation.json'} (+ .csv, _summary.txt)")

    # ---- chart: rank of each CVE per ranking (log scale, lower = better) ----
    order = sorted(cves, key=lambda c: (splits[c], c))
    fig, ax = plt.subplots(figsize=(16, 6))
    width = 0.8 / max(1, len(names))
    x = np.arange(len(order))
    for i, n in enumerate(names):
        ranks = [results[n]["all"]["all"]["ranks"][c] or np.nan for c in order]
        ax.bar(x + i * width, ranks, width, label=n)
    ax.set_yscale("log")
    ax.set_xticks(x + width * (len(names) - 1) / 2)
    ax.set_xticklabels([f"{c[4:]}\n({splits[c]})" for c in order], fontsize=7, rotation=60)
    for k, color in ((10, "green"), (100, "orange"), (500, "red")):
        ax.axhline(k, color=color, linestyle=":", label=f"top {k}")
    ax.set_ylabel("Rank (log scale, lower = better)")
    ax.set_title("Rank of each CVE's best vulnerable function, by ranking method",
                 fontsize=13, fontweight="bold")
    ax.legend(fontsize=8, ncol=2)
    plt.tight_layout()
    CHART_PATH.mkdir(parents=True, exist_ok=True)
    out = CHART_PATH / "7_ranking_comparison.png"
    plt.savefig(out, dpi=200, bbox_inches="tight")
    plt.close()
    print(f"💾 Saved: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
