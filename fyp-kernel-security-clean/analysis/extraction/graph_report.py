#!/usr/bin/env python3
"""
Phase 3 check: what did the typed call graph change?

Compares two graphs of the SAME kernel version:
  old  = direct calls + function pointers matched by field NAME only
         (the method used until now)
  new  = direct calls + function pointers matched by struct TYPE
         + callbacks handed to core kernel APIs (configs/callgraph.yaml)
and reports
  - edges added / removed, and how the new edges were found
  - for every CVE in the ground truth: can a seed (entry point) reach a
    vulnerable function in the old graph? in the new graph? (shortest path)
This is a quick graph check, not an evaluation: no ranks are computed.

Output: results/processed/graph_report.json, graph_report.txt
"""

import json
import sys
from collections import Counter
from pathlib import Path

import networkx as nx

sys.stdout.reconfigure(encoding="utf-8")

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "analysis"))
from callgraph import INDIRECT_CALLS_FILE, load_call_graph
from config import PATHS, kernel_info

NAME_ONLY_FILE = PATHS.raw / "indirect_calls_name_only.json"
SEEDS_FILE = PATHS.processed / "seeds.json"
GROUND_TRUTH_FILE = PATHS.validation / "vulnerable_functions.json"


def old_graph():
    graph = load_call_graph(include_indirect=False)
    with open(NAME_ONLY_FILE) as f:
        for caller, targets in json.load(f)["edges"].items():
            for target in targets:
                if not graph.has_edge(caller, target):
                    graph.add_edge(caller, target, kind="indirect", how="name_only")
    return graph


def path_from(graph, sources, target):
    sources = [s for s in sources if s in graph]
    if target not in graph or not sources:
        return None
    try:
        return nx.multi_source_dijkstra(graph, sources, target)[1]
    except nx.NetworkXNoPath:
        return None


def reachable(graph, sources):
    seen = set()
    for s in sources:
        if s in graph and s not in seen:
            seen |= nx.descendants(graph, s) | {s}
    return seen


def main():
    print("=" * 70)
    print("🔎 CALL GRAPH CHECK: name-only vs typed function pointers")
    print("=" * 70)
    for required in (NAME_ONLY_FILE, INDIRECT_CALLS_FILE, SEEDS_FILE):
        if not required.exists():
            print(f"❌ {required} not found - run the earlier stages first")
            return 1
    with open(SEEDS_FILE) as f:
        seeds = list(json.load(f)["seeds"])
    with open(INDIRECT_CALLS_FILE) as f:
        stats = json.load(f)["stats"]

    old, new = old_graph(), load_call_graph()
    old_edges, new_edges = set(old.edges()), set(new.edges())
    added, removed = new_edges - old_edges, old_edges - new_edges
    added_how = Counter(new.edges[e].get("how", "direct") for e in added)
    reach_old, reach_new = reachable(old, seeds), reachable(new, seeds)

    cves = {}
    if GROUND_TRUTH_FILE.exists():
        with open(GROUND_TRUTH_FILE) as f:
            cves = json.load(f)["cves"]
    per_cve = {}
    for cve_id, cve in cves.items():
        functions = {}
        for vf in cve["vulnerable_functions"]:
            fn = vf["name"]
            functions[fn] = {"old": path_from(old, seeds, fn), "new": path_from(new, seeds, fn)}
        per_cve[cve_id] = {
            "split": cve["split"],
            "path_old": any(v["old"] for v in functions.values()),
            "path_new": any(v["new"] for v in functions.values()),
            "functions": functions,
        }

    report = {
        "kernel": kernel_info(),
        "nodes": new.number_of_nodes(),
        "edges_old": len(old_edges), "edges_new": len(new_edges),
        "edges_added": len(added), "edges_removed": len(removed),
        "added_by_how": dict(added_how),
        "name_fallback_share_of_dispatch_sites": stats.get("name_fallback_share_of_dispatch_sites"),
        "dispatch_sites": {k[15:]: v for k, v in stats.items() if k.startswith("dispatch_sites_")},
        "reachable_from_seeds_old": len(reach_old), "reachable_from_seeds_new": len(reach_new),
        "cves_with_path_old": sum(c["path_old"] for c in per_cve.values()),
        "cves_with_path_new": sum(c["path_new"] for c in per_cve.values()),
        "per_cve": per_cve,
    }
    with open(PATHS.processed / "graph_report.json", "w") as f:
        json.dump(report, f, indent=1)

    n = new.number_of_nodes()
    lines = ["=" * 70, "CALL GRAPH CHECK: name-only (old) vs typed (new) function pointers", "=" * 70,
             f"Kernel: {kernel_info()['tag']} ({kernel_info()['commit']})", "",
             f"Edges        old {len(old_edges):6d}   new {len(new_edges):6d}",
             f"Added   {len(added):6d}   by: {dict(added_how)}",
             f"Removed {len(removed):6d}   (name-only links whose struct types do not match)",
             f"Dispatch sites: {report['dispatch_sites']}",
             f"Name-only fallback used for {100 * (report['name_fallback_share_of_dispatch_sites'] or 0):.1f}% "
             "of dispatch sites (struct type unknown)",
             f"Functions reachable from a seed: old {len(reach_old)} / {n}   new {len(reach_new)} / {n}", ""]
    if per_cve:
        lines.append(f"CVEs with a path seed -> vulnerable function: old {report['cves_with_path_old']} / "
                     f"{len(per_cve)}   new {report['cves_with_path_new']} / {len(per_cve)}\n")
        for cve_id, c in per_cve.items():
            lines.append(f"{cve_id:16s} {c['split']:7s} old {'yes' if c['path_old'] else 'NO ':3s}  "
                         f"new {'yes' if c['path_new'] else 'NO '}")
            for fn, p in c["functions"].items():
                shown = " -> ".join(p["new"]) if p["new"] else "no path in the new graph"
                lines.append(f"   {fn}: {shown}")
    else:
        lines.append("(no ground truth yet - run build_cve_set.py, then this check again)")
    (PATHS.processed / "graph_report.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines[4:]))
    print(f"\n💾 Saved: {PATHS.processed / 'graph_report.json'}, graph_report.txt")
    return 0


if __name__ == "__main__":
    sys.exit(main())
