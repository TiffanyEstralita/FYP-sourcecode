#!/usr/bin/env python3
"""
SCRIPT #3f: Seed weighting experiment for personalized PageRank

How much "starting weight" each seed gets (decided BEFORE testing; chosen on
the tuning CVEs only, all variants reported):
  uniform        every seed gets the same weight (what Phase 3 used). The
                 path with more seeds dominates: 151 packet vs 151 config
                 seeds overall, but e.g. 198 of the 304 are iptables functions.
  path_balanced  each attack path (packet / config) gets half of the weight,
                 shared equally by that path's seeds; a seed on both paths
                 gets both shares. Follows the brief's two kinds of input.
  group_balanced each seed GROUP in configs/seeds.yaml (netfilter_hooks,
                 nfnetlink_handlers, ...) gets an equal share, so no single
                 subsystem's many entry points dominate.

Output: results/processed/seed_weighting.csv (+ _summary.txt)
"""

import csv
import json
import sys
from pathlib import Path

import networkx as nx

# Windows terminals use a non-UTF-8 encoding by default and crash on emoji output
sys.stdout.reconfigure(encoding="utf-8")

PROJECT_ROOT = Path(__file__).resolve().parents[2]

GROUND_TRUTH_FILE = PROJECT_ROOT / "validation/cve_data/vulnerable_functions.json"
SEEDS_FILE = PROJECT_ROOT / "results/processed/seeds.json"
OUTPUT_PATH = PROJECT_ROOT / "results/processed"
ALPHA = 0.85

sys.path.insert(0, str(PROJECT_ROOT / "analysis"))
from callgraph import load_call_graph
from metrics import behind_entry_points, evaluate, load_ground_truth


def weightings(seeds_data):
    seeds = seeds_data["seeds"]
    uniform = {s: 1.0 for s in seeds}

    path_balanced = {}
    for path, nodes in seeds_data["by_path"].items():
        for s in nodes:
            path_balanced[s] = path_balanced.get(s, 0) + 0.5 / len(nodes)

    group_balanced = {}
    enabled = {g: d for g, d in seeds_data["groups"].items() if d["enabled"] and d["functions"]}
    for g, data in enabled.items():
        for s in data["functions"]:
            group_balanced[s] = group_balanced.get(s, 0) + 1 / len(enabled) / len(data["functions"])

    return {"uniform": uniform, "path_balanced": path_balanced, "group_balanced": group_balanced}


def main():
    print("=" * 70)
    print("⚖️  SEED WEIGHTING EXPERIMENT (personalized PageRank)")
    print("=" * 70)

    cves, splits = load_ground_truth(GROUND_TRUTH_FILE)
    with open(SEEDS_FILE, "r") as f:
        seeds_data = json.load(f)
    seeds = set(seeds_data["seeds"])
    behind, _ = behind_entry_points(cves, seeds)
    graph = load_call_graph()

    rows, ranks = [], {}
    for name, weights in weightings(seeds_data).items():
        scores = nx.pagerank(graph, alpha=ALPHA, personalization=weights, max_iter=500, tol=1e-08)
        ranks[name] = evaluate(scores, cves)["ranks"]
        for split in ("tuning", "test"):
            for scope, pool, exclude in (("all", cves, ()), ("non_seed", behind, seeds)):
                subset = {c: fns for c, fns in pool.items() if splits[c] == split}
                ev = evaluate(scores, subset, exclude=exclude, ks=(100, 500, 1000))
                rows.append({"weighting": name, "split": split, "scope": scope,
                             "mrr": round(ev["mrr"], 5), "median_rank": ev["median_rank"],
                             **{f"recall@{k}": round(v, 3) for k, v in ev["recall"].items()}})

    tuning_rows = [r for r in rows if r["split"] == "tuning" and r["scope"] == "all"]
    best = max(tuning_rows, key=lambda r: (r["mrr"], -r["median_rank"]))
    print(f"   {'weighting':15s} {'split':7s} {'MRR':>8s} {'median':>7s} {'R@500':>6s} {'R@1000':>7s}")
    for r in rows:
        if r["scope"] == "all":
            print(f"   {r['weighting']:15s} {r['split']:7s} {r['mrr']:>8.4f} {r['median_rank']:>7.0f} "
                  f"{r['recall@500']:>6.2f} {r['recall@1000']:>7.2f}")
    print(f"\n✅ Best on the TUNING CVEs (by MRR): {best['weighting']}")

    print("\n   rank of each CVE:   " + "".join(f"{n:>16s}" for n in ranks))
    for c in cves:
        print(f"   {c:16s} {splits[c]:7s}" + "".join(f"{ranks[n][c]:>16.0f}" for n in ranks))

    with open(OUTPUT_PATH / "seed_weighting.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    with open(OUTPUT_PATH / "seed_weighting_summary.txt", "w") as f:
        f.write(f"SEED WEIGHTING EXPERIMENT (personalized PageRank, alpha={ALPHA})\n")
        f.write(f"Best on the tuning CVEs (by MRR): {best['weighting']}\n\n")
        for r in rows:
            f.write(f"{r['weighting']:15s} {r['split']:7s} {r['scope']:9s} MRR={r['mrr']:.4f} "
                    f"median={r['median_rank']:.0f} R@500={r['recall@500']:.2f} R@1000={r['recall@1000']:.2f}\n")
        f.write("\nRank of each CVE:\n")
        for c in cves:
            f.write(f"   {c:16s} {splits[c]:7s}" + "".join(f"{n}={ranks[n][c]:.0f}  " for n in ranks) + "\n")
    print(f"\n💾 Saved: {OUTPUT_PATH / 'seed_weighting.csv'} (+ _summary.txt)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
