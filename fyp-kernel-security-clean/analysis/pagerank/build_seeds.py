#!/usr/bin/env python3
"""
SCRIPT #3a: Build the seed list for personalized PageRank
Purpose: Turn the seed RULES in configs/seeds.yaml into a concrete list of
         seed functions ("front doors" where attacker input enters), and
         report how much of the call graph each attack path reaches.

Usage:
    python analysis/pagerank/build_seeds.py                         # groups enabled in the config
    python analysis/pagerank/build_seeds.py --include ipset_uadt    # also a disabled group
                                                                    # (for an extra experiment)

Output: results/processed/seeds.json (+ seeds_summary.txt)
"""

import argparse
import json
import sys
from pathlib import Path

import networkx as nx
import yaml

# Windows terminals use a non-UTF-8 encoding by default and crash on emoji output
sys.stdout.reconfigure(encoding="utf-8")

PROJECT_ROOT = Path(__file__).resolve().parents[2]

CONFIG_FILE = PROJECT_ROOT / "configs/seeds.yaml"
INDIRECT_CALLS_FILE = PROJECT_ROOT / "results/raw/indirect_calls.json"
GROUND_TRUTH_FILE = PROJECT_ROOT / "validation/cve_data/vulnerable_functions.json"
OUTPUT_PATH = PROJECT_ROOT / "results/processed"

sys.path.insert(0, str(PROJECT_ROOT / "analysis"))
from callgraph import load_call_graph


def as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def group_functions(group, field_targets, graph):
    """Seed functions selected by one group's rule -> (found, missing names)"""
    found = set()
    for slot in as_list(group.get("slot")):
        found |= set(field_targets.get(slot, []))
    missing = []
    for name in as_list(group.get("functions")):
        if name in graph:
            found.add(name)
        else:
            missing.append(name)
    return sorted(found), missing


def reachable_from(graph, sources):
    """Every node reachable from any of `sources` (including the sources)"""
    seen = set()
    for source in sources:
        if source not in seen:
            seen |= nx.descendants(graph, source) | {source}
    return seen


def main():
    parser = argparse.ArgumentParser(description="Build the personalized PageRank seed list")
    parser.add_argument("--include", nargs="*", default=[],
                        help="also use these groups even if disabled in the config")
    args = parser.parse_args()

    print("=" * 70)
    print("🚪 BUILD SEEDS (attacker entry points)")
    print("=" * 70)

    with open(CONFIG_FILE, "r") as f:
        config = yaml.safe_load(f)
    with open(INDIRECT_CALLS_FILE, "r") as f:
        field_targets = json.load(f)["field_targets"]
    with open(GROUND_TRUTH_FILE, "r") as f:
        ground_truth = json.load(f)

    unknown = [g for g in args.include if g not in config["groups"]]
    if unknown:
        print(f"❌ Unknown group(s) in --include: {unknown}")
        return 1

    graph = load_call_graph()

    groups = {}
    seeds = {}   # node -> {"paths": [...], "groups": [...]}
    warnings = []
    for name, group in config["groups"].items():
        enabled = group.get("enabled", True) or name in args.include
        functions, missing = group_functions(group, field_targets, graph)
        groups[name] = {
            "path": group["path"],
            "enabled": enabled,
            "reason": " ".join(group.get("reason", "").split()),
            "count": len(functions),
            "functions": functions,
        }
        status = "ON " if enabled else "off"
        print(f"   [{status}] {name:22s} {group['path']:7s} {len(functions):4d} functions")
        for m in missing:
            warnings.append(f"group '{name}': function '{m}' not found in the call graph")
        if not enabled:
            continue
        for node in functions:
            entry = seeds.setdefault(node, {"paths": [], "groups": []})
            if group["path"] not in entry["paths"]:
                entry["paths"].append(group["path"])
            entry["groups"].append(name)

    by_path = {}
    for node, entry in seeds.items():
        for path in entry["paths"]:
            by_path.setdefault(path, []).append(node)
    by_path = {p: sorted(nodes) for p, nodes in sorted(by_path.items())}

    # How much of the graph each attack path can reach
    total = graph.number_of_nodes()
    reach = {p: reachable_from(graph, nodes) for p, nodes in by_path.items()}
    reach["any"] = set().union(*reach.values()) if reach else set()
    coverage = {p: {"reachable": len(r), "percent": round(100 * len(r) / total, 1)}
                for p, r in reach.items()}

    # Vulnerable functions: never a seed (circular), ideally reachable
    cve_check = {}
    for cve_id, cve_data in ground_truth.items():
        for vf in cve_data["vulnerable_functions"]:
            fn = vf["name"]
            is_seed = fn in seeds
            if is_seed:
                warnings.append(f"CIRCULAR: {cve_id} vulnerable function {fn} is itself a seed "
                                f"(groups: {', '.join(seeds[fn]['groups'])})")
            cve_check[f"{cve_id}:{fn}"] = {
                "is_seed": is_seed,
                "reachable_from": [p for p in by_path if fn in reach[p]],
            }

    print(f"\n✅ Seeds: {len(seeds)} unique functions  "
          + "  ".join(f"{p}={len(n)}" for p, n in by_path.items()))
    print("✅ Reachable from the seeds:")
    for p, c in coverage.items():
        print(f"   {p:7s} {c['reachable']:5d} of {total} functions ({c['percent']}%)")
    print("✅ Vulnerable functions:")
    for key, c in cve_check.items():
        print(f"   {key:45s} seed={c['is_seed']!s:5s} reachable from: {c['reachable_from'] or 'NOTHING'}")
    for w in warnings:
        print(f"⚠️  {w}")

    OUTPUT_PATH.mkdir(parents=True, exist_ok=True)
    out_json = OUTPUT_PATH / "seeds.json"
    with open(out_json, "w") as f:
        json.dump({
            "config": str(CONFIG_FILE.relative_to(PROJECT_ROOT)),
            "included_disabled_groups": args.include,
            "groups": groups,
            "seeds": dict(sorted(seeds.items())),
            "by_path": by_path,
            "coverage": coverage,
            "vulnerable_functions": cve_check,
            "warnings": warnings,
        }, f, indent=2)
    print(f"\n💾 Saved: {out_json}")

    out_txt = OUTPUT_PATH / "seeds_summary.txt"
    with open(out_txt, "w") as f:
        f.write("=" * 70 + "\nSEEDS (attacker entry points) FOR PERSONALIZED PAGERANK\n" + "=" * 70 + "\n\n")
        for name, g in groups.items():
            f.write(f"[{'ON ' if g['enabled'] else 'off'}] {name} ({g['path']}, {g['count']} functions)\n")
            f.write(f"      {g['reason']}\n")
        f.write(f"\nUnique seeds: {len(seeds)}\n")
        for p, c in coverage.items():
            f.write(f"Reachable from {p:7s} seeds: {c['reachable']} of {total} ({c['percent']}%)\n")
        f.write("\nVulnerable functions:\n")
        for key, c in cve_check.items():
            f.write(f"   {key:45s} seed={c['is_seed']}  reachable from: {c['reachable_from'] or 'NOTHING'}\n")
        if warnings:
            f.write("\nWarnings:\n" + "".join(f"   {w}\n" for w in warnings))
        f.write("\nSeed list by path:\n")
        for p, nodes in by_path.items():
            f.write(f"\n{p} ({len(nodes)}):\n" + "".join(f"   {n}\n" for n in nodes))
    print(f"💾 Saved: {out_txt}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
