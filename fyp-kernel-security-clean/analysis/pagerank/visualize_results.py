#!/usr/bin/env python3
"""
SCRIPT #4: Visualize CVE PageRank Results
Purpose: Draw charts for EVERY CVE in the function-level CVE analysis
         (results/processed/cve_function_analysis.json, written by
         analyze_cve_functions.py). No CVE is hardcoded - add a CVE to
         validation/cve_data/vulnerable_functions.json and it gets charts.

Charts:
  1_pagerank_distribution.png - histogram of all PageRank scores
  2_top_20_functions.png - the 20 highest-PageRank functions overall
  3_<cve>_top_30.png     - functions in the vulnerable file, ranked by PageRank,
                           with the vulnerable function highlighted
  4_cve_rank_summary.png - every CVE's vulnerable function and its overall rank
  6_<cve>_callgraph.png  - who calls / is called by the vulnerable function
"""

import sys
import json
from pathlib import Path

import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import networkx as nx

# Windows terminals use a non-UTF-8 encoding by default and crash on emoji output
sys.stdout.reconfigure(encoding="utf-8")

PROJECT_ROOT = Path(__file__).resolve().parents[2]

PAGERANK_FILE = PROJECT_ROOT / "results/processed/pagerank_scores.json"
CVE_ANALYSIS_FILE = PROJECT_ROOT / "results/processed/cve_function_analysis.json"
FUNCTIONS_FILE = PROJECT_ROOT / "results/raw/functions_v2.json"
OUTPUT_PATH = PROJECT_ROOT / "results/visualizations"

sys.path.insert(0, str(PROJECT_ROOT / "analysis"))
from callgraph import load_call_graph

VULN_COLOR = "#d62728"   # red - the known vulnerable function
OTHER_COLOR = "#9e9e9e"  # grey - everything else

sns.set_style("whitegrid")
plt.rcParams["figure.dpi"] = 300
plt.rcParams["savefig.dpi"] = 300
plt.rcParams["font.size"] = 10


def cve_slug(cve_id):
    """'CVE-2023-0179' -> 'cve_2023_0179' (used in output filenames)"""
    return cve_id.lower().replace("-", "_")


class Visualizer:
    def __init__(self):
        self.pagerank = {}
        self.rank_of = {}
        self.functions = {}
        self.cves = {}
        self.graph = None
        OUTPUT_PATH.mkdir(parents=True, exist_ok=True)

    def load_data(self):
        print("📂 Loading data...")

        with open(PAGERANK_FILE, "r") as f:
            self.pagerank = json.load(f)
        with open(FUNCTIONS_FILE, "r") as f:
            self.functions = json.load(f)
        with open(CVE_ANALYSIS_FILE, "r") as f:
            self.cves = json.load(f)

        # Overall rank of every function (1 = highest PageRank)
        ordered = sorted(self.pagerank.items(), key=lambda x: x[1], reverse=True)
        self.rank_of = {name: i for i, (name, _) in enumerate(ordered, 1)}

        # Same call graph that calculate_pagerank.py builds
        self.graph = load_call_graph()

        print(f"✅ Loaded PageRank for {len(self.pagerank)} functions")
        print(f"✅ Loaded {len(self.cves)} CVEs: {', '.join(self.cves)}")

    def ok_entries(self):
        """Yield (cve_id, entry) for every vulnerable function that was ranked"""
        for cve_id, data in self.cves.items():
            for entry in data["functions"]:
                if entry["status"] == "OK":
                    yield cve_id, entry
                else:
                    print(f"⚠️  Skipping {cve_id} {entry['function']}: {entry['status']}")

    # ----------------------------
    # Chart 1: distribution of all PageRank scores
    # ----------------------------
    def plot_pagerank_distribution(self):
        print("\n📊 Chart 1: PageRank score distribution...")

        scores = np.array(list(self.pagerank.values()))

        fig, ax = plt.subplots(figsize=(12, 6))
        ax.hist(scores, bins=50, edgecolor="black", alpha=0.7)
        ax.set_yscale("log")  # most scores are tiny - log scale keeps the tail visible

        for pct, style in ((90, ":"), (95, "--"), (99, "-.")):
            ax.axvline(np.percentile(scores, pct), color="tab:red", linestyle=style,
                       linewidth=2, label=f"{pct}th percentile")

        ax.set_xlabel("PageRank Score", fontsize=12)
        ax.set_ylabel("Number of Functions (log scale)", fontsize=12)
        ax.set_title(f"PageRank Score Distribution - Netfilter ({len(scores)} functions)",
                     fontsize=14, fontweight="bold")
        ax.legend()

        plt.tight_layout()
        out = OUTPUT_PATH / "1_pagerank_distribution.png"
        plt.savefig(out, bbox_inches="tight")
        plt.close()
        print(f"   ✅ Saved: {out}")

    # ----------------------------
    # Chart 2: top 20 functions overall
    # ----------------------------
    def plot_top_20(self):
        print("\n📊 Chart 2: top 20 functions by PageRank...")

        top = sorted(self.pagerank.items(), key=lambda x: x[1], reverse=True)[:20]
        names = [name for name, _ in top]
        scores = [score for _, score in top]

        fig, ax = plt.subplots(figsize=(12, 10))
        y = np.arange(len(top))
        ax.barh(y, scores, alpha=0.85)
        ax.set_yticks(y)
        ax.set_yticklabels(names)
        ax.invert_yaxis()
        ax.set_xlabel("PageRank Score", fontsize=12)
        ax.set_title("Top 20 Functions by PageRank", fontsize=14, fontweight="bold")

        plt.tight_layout()
        out = OUTPUT_PATH / "2_top_20_functions.png"
        plt.savefig(out, bbox_inches="tight")
        plt.close()
        print(f"   ✅ Saved: {out}")

    # ----------------------------
    # Chart 3: functions in the vulnerable file, ranked
    # ----------------------------
    def plot_file_ranking(self, cve_id, entry):
        vuln = entry["function"]
        file_name = entry["file"]

        in_file = [node for node, info in self.graph.nodes(data=True)
                   if info.get("file") == file_name and node in self.pagerank]
        in_file.sort(key=lambda name: self.pagerank[name], reverse=True)

        # Show the top 30, but always include the vulnerable function
        shown = in_file[:30]
        if vuln not in shown:
            shown.append(vuln)
        n = len(shown)

        scores = [self.pagerank[name] for name in shown]
        colors = [VULN_COLOR if name == vuln else OTHER_COLOR for name in shown]

        fig, ax = plt.subplots(figsize=(12, max(3.5, 0.35 * n + 1.5)))
        y = np.arange(n)
        ax.barh(y, scores, color=colors, alpha=0.9)
        ax.set_yticks(y)
        ax.set_yticklabels(shown, fontsize=10 if n <= 10 else 8)
        ax.invert_yaxis()
        ax.set_xlabel("PageRank Score", fontsize=12)
        ax.set_title(
            f"{cve_id} – Functions in {file_name} ranked by PageRank\n"
            f"(red = vulnerable function {vuln}; showing {n} of {len(in_file)})",
            fontsize=13,
            fontweight="bold",
        )

        total = len(self.pagerank)
        xpad = max(scores) * 0.02
        for i, name in enumerate(shown):
            rank = self.rank_of[name]
            ax.text(scores[i] + xpad, i, f"#{rank} (top {rank / total * 100:.1f}%)",
                    va="center", fontsize=8)

        plt.tight_layout()
        out = OUTPUT_PATH / f"3_{cve_slug(cve_id)}_top_30.png"
        plt.savefig(out, bbox_inches="tight")
        plt.close()
        print(f"   ✅ Saved: {out}")

    # ----------------------------
    # Chart 4: one bar per CVE - where did the vulnerable function rank?
    # ----------------------------
    def plot_rank_summary(self):
        print("\n📊 Chart 4: rank summary across CVEs...")

        rows = list(self.ok_entries())
        if not rows:
            print("⚠️  No ranked CVE functions - cannot plot summary")
            return

        labels = [f"{cve_id}\n{entry['function']}" for cve_id, entry in rows]
        percentiles = [entry["percentile_top"] for _, entry in rows]

        fig, ax = plt.subplots(figsize=(11, max(3.5, 1.0 * len(rows) + 1.5)))
        y = np.arange(len(rows))
        ax.barh(y, percentiles, color=VULN_COLOR, alpha=0.85)
        ax.set_yticks(y)
        ax.set_yticklabels(labels)
        ax.invert_yaxis()

        ax.axvline(10, color="green", linestyle=":", label="Top 10%")
        ax.axvline(20, color="orange", linestyle=":", label="Top 20%")
        ax.axvline(50, color="black", linestyle="--", alpha=0.5, label="Random (expected 50%)")

        for i, (_, entry) in enumerate(rows):
            ax.text(entry["percentile_top"] + 1, i,
                    f"#{entry['overall_rank']} of {entry['total_functions']}",
                    va="center", fontsize=9)

        ax.set_xlim(0, 100)
        ax.set_xlabel("Rank percentile (lower = ranked higher = better)", fontsize=12)
        ax.set_title("Where each CVE's vulnerable function ranks (standard PageRank)",
                     fontsize=13, fontweight="bold")
        ax.legend(loc="lower right")

        plt.tight_layout()
        out = OUTPUT_PATH / "4_cve_rank_summary.png"
        plt.savefig(out, bbox_inches="tight")
        plt.close()
        print(f"   ✅ Saved: {out}")

    # ----------------------------
    # Chart 6: call-graph neighbourhood of the vulnerable function
    # ----------------------------
    def plot_call_graph(self, cve_id, entry):
        vuln = entry["function"]
        if vuln not in self.graph:
            print(f"   ⚠️  {vuln} has no call edges at all - skipping call graph")
            return

        callers = list(self.graph.predecessors(vuln))
        callees = list(self.graph.successors(vuln))
        G = self.graph.subgraph([vuln] + callers + callees).copy()

        fig, ax = plt.subplots(figsize=(14, 10))
        pos = nx.spring_layout(G, k=1.6, iterations=80, seed=42)

        others = [n for n in G.nodes() if n != vuln]
        scores = [self.pagerank.get(n, 0.0) for n in others]
        vmin, vmax = (min(scores), max(scores)) if scores else (0, 1)

        nx.draw_networkx_nodes(G, pos, nodelist=others, node_color=scores, cmap="YlOrRd",
                               vmin=vmin, vmax=vmax, node_size=900, alpha=0.9, ax=ax)
        nx.draw_networkx_nodes(G, pos, nodelist=[vuln], node_color=VULN_COLOR,
                               node_size=1600, edgecolors="black", linewidths=2, ax=ax)
        nx.draw_networkx_labels(G, pos, font_size=8, font_weight="bold", ax=ax)
        for kind, style in (("direct", "solid"), ("indirect", "dashed")):
            edgelist = [(u, v) for u, v, d in G.edges(data=True) if d.get("kind") == kind]
            nx.draw_networkx_edges(G, pos, edgelist=edgelist, edge_color="black", style=style,
                                   arrows=True, arrowsize=20, arrowstyle="->", alpha=0.6,
                                   width=1.5, connectionstyle="arc3,rad=0.12", ax=ax)

        sm = plt.cm.ScalarMappable(cmap="YlOrRd", norm=plt.Normalize(vmin=vmin, vmax=vmax))
        sm.set_array([])
        plt.colorbar(sm, ax=ax).set_label("PageRank Score", fontsize=11)

        caller_note = (f"{len(callers)} caller(s)" if callers
                       else "NO callers found - probably reached via a function pointer")
        ax.set_title(
            f"{cve_id} – Call graph around {vuln} (red)\n"
            f"{caller_note}, {len(callees)} callee(s); arrows point caller → callee, "
            f"dashed = via function pointer",
            fontsize=13,
            fontweight="bold",
        )
        ax.axis("off")

        plt.tight_layout()
        out = OUTPUT_PATH / f"6_{cve_slug(cve_id)}_callgraph.png"
        plt.savefig(out, bbox_inches="tight")
        plt.close()
        print(f"   ✅ Saved: {out}")

    def create_all(self):
        print("=" * 70)
        print("🎨 CVE VISUALIZATIONS")
        print("=" * 70)

        self.plot_pagerank_distribution()
        self.plot_top_20()

        for cve_id, entry in self.ok_entries():
            print(f"\n📊 {cve_id} ({entry['function']})")
            self.plot_file_ranking(cve_id, entry)
            self.plot_call_graph(cve_id, entry)

        self.plot_rank_summary()

        print("\n" + "=" * 70)
        print(f"✅ DONE! Saved to: {OUTPUT_PATH}")
        print("=" * 70)


def main():
    for required in (PAGERANK_FILE, CVE_ANALYSIS_FILE, FUNCTIONS_FILE):
        if not required.exists():
            print(f"❌ Missing required input: {required}")
            print("Run calculate_pagerank.py and analyze_cve_functions.py first!")
            return 1

    viz = Visualizer()
    viz.load_data()
    viz.create_all()
    return 0


if __name__ == "__main__":
    sys.exit(main())
