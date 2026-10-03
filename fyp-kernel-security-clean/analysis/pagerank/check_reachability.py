#!/usr/bin/env python3
"""
SCRIPT #3c: Reachability sanity check
Purpose: For each CVE, check that the vulnerable function can be reached in
         the call graph from where attacker input enters the kernel.
         If it cannot, personalized PageRank (Phase 3) can never rank it.

Checked twice - with direct calls only, and with direct + function-pointer
(indirect) calls - to show what extract_indirect_calls.py adds.

The entry points below are PROVISIONAL: Phase 2 replaces them with a proper
seed configuration.
"""

import json
import sys
from pathlib import Path

import networkx as nx

# Windows terminals use a non-UTF-8 encoding by default and crash on emoji output
sys.stdout.reconfigure(encoding="utf-8")

PROJECT_ROOT = Path(__file__).resolve().parents[2]

GROUND_TRUTH_FILE = PROJECT_ROOT / "validation/cve_data/vulnerable_functions.json"
OUTPUT_PATH = PROJECT_ROOT / "results/processed"

sys.path.insert(0, str(PROJECT_ROOT / "analysis"))
from callgraph import load_call_graph

ENTRY_POINTS = {
    # a network packet passing through netfilter hooks / nf_tables rules
    "packet": ["nf_hook_slow", "nft_do_chain"],
    # a netlink (configuration) message sent from a userspace program
    "netlink": ["nfnetlink_rcv_msg", "nfnetlink_rcv_batch"],
}


def shortest_path_from(graph, sources, target):
    """Shortest path from any of `sources` to `target`, or None"""
    best = None
    for source in sources:
        if source not in graph or target not in graph:
            continue
        try:
            path = nx.shortest_path(graph, source, target)
        except nx.NetworkXNoPath:
            continue
        if best is None or len(path) < len(best):
            best = path
    return best


def main():
    print("=" * 70)
    print("🧭 REACHABILITY CHECK: entry points -> vulnerable functions")
    print("=" * 70)

    with open(GROUND_TRUTH_FILE, "r") as f:
        ground_truth = json.load(f)

    graphs = {
        "direct_only": load_call_graph(include_indirect=False),
        "with_indirect": load_call_graph(include_indirect=True),
    }

    for kind, sources in ENTRY_POINTS.items():
        missing = [s for s in sources if s not in graphs["with_indirect"]]
        if missing:
            print(f"⚠️  {kind} entry point(s) not in graph: {missing}")

    results = {}
    for cve_id, cve_data in ground_truth.items():
        for vf in cve_data["vulnerable_functions"]:
            target = vf["name"]
            print(f"\n{cve_id}: {target}")
            entry = {}
            for graph_name, graph in graphs.items():
                entry[graph_name] = {}
                for kind, sources in ENTRY_POINTS.items():
                    path = shortest_path_from(graph, sources, target)
                    entry[graph_name][kind] = path
                    shown = " -> ".join(path) if path else "NO PATH"
                    print(f"   {graph_name:13s} {kind:8s} {shown}")
            results[f"{cve_id}:{target}"] = entry

    reachable = sum(1 for e in results.values() if any(e["with_indirect"].values()))
    print(f"\n✅ Reachable from at least one entry point (with indirect calls): "
          f"{reachable}/{len(results)}")

    OUTPUT_PATH.mkdir(parents=True, exist_ok=True)
    out_json = OUTPUT_PATH / "reachability.json"
    with open(out_json, "w") as f:
        json.dump({"entry_points": ENTRY_POINTS, "results": results}, f, indent=2)
    print(f"\n💾 Saved: {out_json}")

    out_txt = OUTPUT_PATH / "reachability_summary.txt"
    with open(out_txt, "w") as f:
        f.write("=" * 70 + "\n")
        f.write("REACHABILITY CHECK: entry points -> vulnerable functions\n")
        f.write("=" * 70 + "\n\n")
        for kind, sources in ENTRY_POINTS.items():
            f.write(f"{kind} entry points: {', '.join(sources)}\n")
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
