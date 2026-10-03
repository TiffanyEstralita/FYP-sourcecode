#!/usr/bin/env python3
"""
SCRIPT #3c: Reachability sanity check
Purpose: For each CVE, check that the vulnerable function can be reached in
         the call graph from where attacker input enters the kernel (the
         seeds from build_seeds.py). If it cannot, personalized PageRank
         (Phase 3) can never rank it.

Checked twice - with direct calls only, and with direct + function-pointer
(indirect) calls - to show what extract_indirect_calls.py adds.
"""

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

sys.path.insert(0, str(PROJECT_ROOT / "analysis"))
from callgraph import load_call_graph


def shortest_path_from(graph, sources, target):
    """Shortest path from any of `sources` to `target`, or None"""
    sources = [s for s in sources if s in graph]
    if not sources or target not in graph:
        return None
    try:
        _, path = nx.multi_source_dijkstra(graph, sources, target)
        return path
    except nx.NetworkXNoPath:
        return None


def main():
    print("=" * 70)
    print("🧭 REACHABILITY CHECK: seeds -> vulnerable functions")
    print("=" * 70)

    if not SEEDS_FILE.exists():
        print(f"❌ {SEEDS_FILE} not found - run build_seeds.py first")
        return 1

    with open(GROUND_TRUTH_FILE, "r") as f:
        ground_truth = json.load(f)
    with open(SEEDS_FILE, "r") as f:
        entry_points = json.load(f)["by_path"]

    for path, seeds in entry_points.items():
        print(f"   {path} seeds: {len(seeds)}")

    graphs = {
        "direct_only": load_call_graph(include_indirect=False),
        "with_indirect": load_call_graph(include_indirect=True),
    }

    results = {}
    for cve_id, cve_data in ground_truth.items():
        for vf in cve_data["vulnerable_functions"]:
            target = vf["name"]
            print(f"\n{cve_id}: {target}")
            entry = {}
            for graph_name, graph in graphs.items():
                entry[graph_name] = {}
                for kind, sources in entry_points.items():
                    path = shortest_path_from(graph, sources, target)
                    entry[graph_name][kind] = path
                    shown = " -> ".join(path) if path else "NO PATH"
                    print(f"   {graph_name:13s} {kind:8s} {shown}")
            results[f"{cve_id}:{target}"] = entry

    reachable = sum(1 for e in results.values() if any(e["with_indirect"].values()))
    print(f"\n✅ Reachable from at least one seed (with indirect calls): "
          f"{reachable}/{len(results)}")
    if reachable < len(results):
        print("⚠️  Unreachable vulnerable functions get no personalized PageRank score!")

    OUTPUT_PATH.mkdir(parents=True, exist_ok=True)
    out_json = OUTPUT_PATH / "reachability.json"
    with open(out_json, "w") as f:
        json.dump({"seed_counts": {p: len(s) for p, s in entry_points.items()},
                   "results": results}, f, indent=2)
    print(f"\n💾 Saved: {out_json}")

    out_txt = OUTPUT_PATH / "reachability_summary.txt"
    with open(out_txt, "w") as f:
        f.write("=" * 70 + "\n")
        f.write("REACHABILITY CHECK: seeds -> vulnerable functions\n")
        f.write("=" * 70 + "\n\n")
        for path, seeds in entry_points.items():
            f.write(f"{path} seeds: {len(seeds)} (see seeds_summary.txt)\n")
        for key, entry in results.items():
            f.write(f"\n{key}\n")
            for graph_name, paths in entry.items():
                for kind, path in paths.items():
                    shown = " -> ".join(path) if path else "NO PATH"
                    f.write(f"   {graph_name:13s} {kind:8s} {shown}\n")
    print(f"💾 Saved: {out_txt}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
