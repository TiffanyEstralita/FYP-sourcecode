#!/usr/bin/env python3
"""
Phase 4: combined shortlist (no training).

Plain idea: instead of trusting one measure (PageRank), give every function
a place in five different "suspicion" rankings and reward functions that
are near the top of several of them - like combining several judges' lists.

Signals (configs/shortlist.yaml chooses which ones are combined):
  1. pagerank                standard PageRank on the call graph
  2. personalized_pagerank   PageRank whose random walks start at the seeds
                             (where attacker input enters)
  3. betweenness_from_seeds  how often a function lies on the shortest
                             paths from a seed to other functions
                             (nx.betweenness_centrality_subset)
  4. size                    lines of code
  5. risky_operations        count of memcpy, kfree, nla_*, array
                             indexing, locking, ... (fixed list in the config)
Combination: reciprocal rank fusion, score = sum 1 / (rrf_k + rank).
Shortlist = the top K functions (K in the config) - these are the ones the
LLM reads in the later phases.

Output: results/processed/signals.json        every signal + rank per function
        results/processed/rankings/*.json     {function: score} per ranking
        results/processed/shortlist.json      the top K
        results/processed/shortlist_summary.txt
"""

import json
import re
import sys
from pathlib import Path

import networkx as nx
import numpy as np
import pandas as pd

sys.stdout.reconfigure(encoding="utf-8")

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "analysis"))
from callgraph import count_edges, load_call_graph
from config import PATHS, kernel_info, load_yaml
from sources import find_source

SETTINGS = load_yaml("shortlist.yaml")
SEEDS_FILE = PATHS.processed / "seeds.json"
RANKINGS_DIR = PATHS.processed / "rankings"
SIGNALS = ["pagerank", "personalized_pagerank", "betweenness_from_seeds", "size", "risky_operations"]


def function_bodies(graph):
    """{node: source text of the function} (comments and strings removed)"""
    cache, bodies = {}, {}
    for node, info in graph.nodes(data=True):
        if info["file"] not in cache:
            path = find_source(info["file"])
            cache[info["file"]] = path.read_text(errors="ignore").split("\n") if path else []
        lines = cache[info["file"]][info["line"] - 1:info.get("end_line") or info["line"]]
        text = re.sub(r"/\*.*?\*/", " ", "\n".join(lines), flags=re.S)
        text = re.sub(r"//[^\n]*", "", text)
        bodies[node] = re.sub(r'"(?:\\.|[^"\\\n])*"', '""', text)
    return bodies


def risky_counts(bodies):
    patterns = {name: re.compile(p) for name, p in SETTINGS["risky_operations"].items()}
    per_op = {node: {name: len(p.findall(text)) for name, p in patterns.items()}
              for node, text in bodies.items()}
    return per_op


def rrf(ranks, signals, k):
    """Reciprocal rank fusion of the chosen signals"""
    return sum(1.0 / (k + ranks[s]) for s in signals)


def compute_signals(graph, seeds, alpha):
    personalization = {s: 1.0 for s in seeds if s in graph}
    bodies = function_bodies(graph)
    risky = risky_counts(bodies)
    print("   standard PageRank...", flush=True)
    pr = nx.pagerank(graph, alpha=alpha, max_iter=200, tol=1e-08)
    print("   personalized PageRank...", flush=True)
    ppr = nx.pagerank(graph, alpha=alpha, personalization=personalization, max_iter=200, tol=1e-08)
    print(f"   betweenness from {len(personalization)} seeds (about a minute)...", flush=True)
    bc = nx.betweenness_centrality_subset(graph, sources=list(personalization), targets=list(graph.nodes),
                                          normalized=True)
    table = pd.DataFrame({
        "pagerank": pd.Series(pr),
        "personalized_pagerank": pd.Series(ppr),
        "betweenness_from_seeds": pd.Series(bc),
        "size": pd.Series({n: graph.nodes[n].get("loc", 0) for n in graph}),
        "risky_operations": pd.Series({n: sum(c.values()) for n, c in risky.items()}),
    })
    return table, risky


def main():
    print("=" * 70)
    print("🧮 COMBINED SHORTLIST (5 structural signals + reciprocal rank fusion)")
    print("=" * 70)
    unknown = [s for s in SETTINGS["signals"] if s not in SIGNALS]
    if unknown:
        print(f"❌ unknown signal(s) in configs/shortlist.yaml: {unknown}; choose from {SIGNALS}")
        return 1
    if not SEEDS_FILE.exists():
        print(f"❌ {SEEDS_FILE} not found - run build_seeds.py first")
        return 1
    with open(SEEDS_FILE) as f:
        seeds = set(json.load(f)["seeds"])

    graph = load_call_graph()
    direct, indirect = count_edges(graph)
    print(f"   graph: {graph.number_of_nodes()} functions, {direct} direct + {indirect} indirect edges")

    table, risky = compute_signals(graph, seeds, SETTINGS["pagerank_alpha"])
    table["is_seed"] = table.index.isin(seeds)
    ranked = table[~table["is_seed"]] if SETTINGS["exclude_seeds"] else table
    ranks = ranked[SIGNALS].rank(ascending=False, method="average")
    combined = pd.Series({n: rrf(ranks.loc[n], SETTINGS["signals"], SETTINGS["rrf_k"]) for n in ranks.index})
    order = combined.sort_values(ascending=False, kind="mergesort").index.tolist()
    k = SETTINGS["k"]
    shortlist = order[:k]
    print(f"   ranked {len(ranked)} functions ({'seeds excluded' if SETTINGS['exclude_seeds'] else 'incl. seeds'})"
          f"; signals combined: {', '.join(SETTINGS['signals'])}")

    # ---- save ----
    PATHS.processed.mkdir(parents=True, exist_ok=True)
    RANKINGS_DIR.mkdir(parents=True, exist_ok=True)
    meta = {"kernel": kernel_info(), "settings": {k_: v for k_, v in SETTINGS.items() if k_ != "risky_operations"},
            "risky_operations": SETTINGS["risky_operations"]}
    nodes = {}
    for n in table.index:
        row = {s: float(table.at[n, s]) for s in SIGNALS}
        row["is_seed"] = bool(table.at[n, "is_seed"])
        row["risky_by_operation"] = {op: c for op, c in risky[n].items() if c}
        if n in ranks.index:
            row["ranks"] = {s: float(ranks.at[n, s]) for s in SIGNALS}
            row["combined_score"] = float(combined[n])
        nodes[n] = row
    with open(PATHS.processed / "signals.json", "w") as f:
        json.dump({**meta, "functions": nodes}, f, indent=1)

    # one {node: score} file per ranking, used by the evaluation and LLM scripts
    rankings = {"standard_pagerank": ranked["pagerank"], "personalized_pagerank": ranked["personalized_pagerank"],
                "combined": combined}
    for s in SIGNALS[2:]:
        rankings[s] = ranked[s]
    for name, scores in rankings.items():
        with open(RANKINGS_DIR / f"{name}.json", "w") as f:
            json.dump({**meta, "ranking": name, "scores": {n: float(v) for n, v in scores.items()}}, f, indent=0)

    with open(PATHS.processed / "shortlist.json", "w") as f:
        json.dump({**meta, "k": k, "shortlist": [
            {"rank": i + 1, "node": n, "combined_score": float(combined[n]),
             "file": graph.nodes[n]["file"], "line": graph.nodes[n]["line"],
             "ranks": {s: float(ranks.at[n, s]) for s in SIGNALS}} for i, n in enumerate(shortlist)]}, f, indent=1)

    # how similar the signals are (Spearman correlation of the ranks)
    corr = ranks[SIGNALS].corr(method="spearman").round(2)
    lines = ["=" * 70, "COMBINED SHORTLIST", "=" * 70,
             f"Kernel: {kernel_info()['tag']} ({kernel_info()['commit']})",
             f"Signals combined: {', '.join(SETTINGS['signals'])}   RRF k={SETTINGS['rrf_k']}   shortlist K={k}",
             f"Functions ranked: {len(ranked)} ({len(seeds)} seeds {'excluded' if SETTINGS['exclude_seeds'] else 'included'})",
             "", "Rank correlation between signals (Spearman, 1 = same order):", corr.to_string(), "",
             f"How many of the top {k} of each single signal are also in the combined shortlist:"]
    for s in SIGNALS:
        top = set(ranks[s].sort_values().index[:k])
        lines.append(f"   {s:24s} {len(top & set(shortlist)):4d} / {k}")
    lines += ["", f"Top 30 of the combined shortlist:",
              f"{'#':>4s}  {'function':45s} " + " ".join(f"{s[:8]:>8s}" for s in SIGNALS)]
    for i, n in enumerate(shortlist[:30], 1):
        lines.append(f"{i:4d}. {n[:45]:45s} " + " ".join(f"{ranks.at[n, s]:8.0f}" for s in SIGNALS))
    (PATHS.processed / "shortlist_summary.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines[4:]))
    print(f"\n💾 Saved: signals.json, rankings/*.json, shortlist.json, shortlist_summary.txt in {PATHS.processed}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
