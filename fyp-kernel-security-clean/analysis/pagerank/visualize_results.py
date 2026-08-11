#!/usr/bin/env python3
"""
FYP SCRIPT #4 (REDO): Visualize PageRank Results (CVE-2024-53141)
Purpose: Create nice, consistent graphs (same "look" as 2023)
Fixes:
- No overwriting old graphs (adds CVE id into filename)
- Graph 3 looks OK even if only 4 functions
- Callgraph works even when the CVE file has 0 internal calls
Date: Feb 2026
"""

import sys
import json
from pathlib import Path

import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import networkx as nx

# ----------------------------
# CONFIG (edit these only)
# ----------------------------
CVE_ID = "2024_53141"
CVE_TITLE = "CVE-2024-53141"
CVE_FILE = "ip_set_bitmap_ip.c"

PAGERANK_FILE = Path.home() / "fyp-kernel-security/results/processed/pagerank_scores.json"
TOP_100_FILE = Path.home() / "fyp-kernel-security/results/processed/top_100_functions.json"

# IMPORTANT: use your renamed 2024 analysis json
CVE_ANALYSIS_FILE = Path.home() / "fyp-kernel-security/results/processed/cve_2024_53141_pagerank_analysis.json"

CALLS_FILE = Path.home() / "fyp-kernel-security/results/raw/function_calls_v2.json"
OUTPUT_PATH = Path.home() / "fyp-kernel-security/results/visualizations"

# ----------------------------
# STYLE (match 2023 vibe)
# ----------------------------
sns.set_style("whitegrid")
plt.rcParams["figure.dpi"] = 300
plt.rcParams["savefig.dpi"] = 300
plt.rcParams["font.size"] = 10


class Visualizer:
    def __init__(self):
        self.pagerank = {}
        self.top_100 = []
        self.cve = {}
        OUTPUT_PATH.mkdir(parents=True, exist_ok=True)

    def load_data(self):
        print("📂 Loading data...")

        with open(PAGERANK_FILE, "r") as f:
            self.pagerank = json.load(f)

        with open(TOP_100_FILE, "r") as f:
            self.top_100 = json.load(f)

        with open(CVE_ANALYSIS_FILE, "r") as f:
            self.cve = json.load(f)

        print(f"✅ Loaded PageRank for {len(self.pagerank)} functions")
        print(f"✅ Loaded CVE analysis: {CVE_TITLE} ({CVE_FILE})")

    # ----------------------------
    # Graph 3: CVE functions ranked
    # ----------------------------
    def plot_cve_file_functions(self):
        print("\n📊 Graph 3: CVE file functions ranked...")

        cve_ranks = self.cve.get("cve_ranks", [])
        if not cve_ranks:
            print("⚠️  cve_ranks empty — check CVE_ANALYSIS_FILE path")
            return

        total_funcs = len(self.pagerank)
        n = min(30, len(cve_ranks))
        subset = cve_ranks[:n]

        functions = [x[0] for x in subset]
        scores = [x[1] for x in subset]
        ranks = [x[2] for x in subset]
        percentiles = [(r / total_funcs) * 100 for r in ranks]

        # If only 4 functions, make a compact nice plot (not ugly giant blocks)
        fig_h = max(3.5, 0.7 * n + 1.5)
        fig, ax = plt.subplots(figsize=(12, fig_h))

        y = np.arange(n)
        bars = ax.barh(y, scores, alpha=0.9)

        # same gradient style as 2023
        colors = plt.cm.RdYlGn_r(np.linspace(0.2, 0.8, n))
        for bar, color in zip(bars, colors):
            bar.set_color(color)

        ax.set_yticks(y)
        ax.set_yticklabels(functions, fontsize=10 if n <= 10 else 8)
        ax.invert_yaxis()
        ax.set_xlabel("PageRank Score", fontsize=12)

        ax.set_title(
            f"{CVE_TITLE} – Functions in {CVE_FILE} ranked by PageRank (n={n})",
            fontsize=14,
            fontweight="bold",
        )
        ax.grid(True, axis="x", alpha=0.3)

        # annotate BOTH rank and percentile (percentile makes it feel less “crazy big”)
        xpad = max(scores) * 0.03 if max(scores) > 0 else 0.0001
        for i in range(n):
            ax.text(
                scores[i] + xpad,
                i,
                f"Rank #{ranks[i]} (Top {percentiles[i]:.1f}%)",
                va="center",
                fontsize=9,
                alpha=0.9,
            )

        # add a small note if only a few functions
        if len(cve_ranks) <= 6:
            ax.text(
                0.98,
                0.02,
                f"Note: Only {len(cve_ranks)} functions extracted from this file",
                transform=ax.transAxes,
                ha="right",
                va="bottom",
                fontsize=9,
                bbox=dict(boxstyle="round,pad=0.3", facecolor="white", alpha=0.8),
            )

        plt.tight_layout()
        out = OUTPUT_PATH / f"3_cve_{CVE_ID}_top_30.png"
        plt.savefig(out, dpi=300, bbox_inches="tight")
        plt.close()
        print(f"   ✅ Saved: {out}")

    # ----------------------------
    # Graph 4: Percentile distribution (same style as 2023)
    # ----------------------------
    def plot_cve_percentile_distribution(self):
        print("\n📊 Graph 4: CVE percentile distribution...")

        total_funcs = len(self.pagerank)
        cve_ranks = [r[2] for r in self.cve.get("cve_ranks", [])]
        total_cve = len(cve_ranks)

        if total_cve == 0:
            print("⚠️  No CVE ranks found — cannot plot Graph 4")
            return

        bins = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
        counts = []
        labels = []

        for threshold in bins:
            thr_rank = (threshold / 100) * total_funcs
            count = sum(1 for r in cve_ranks if r <= thr_rank)
            counts.append(count)
            labels.append(f"Top {threshold}%")

        fig, ax = plt.subplots(figsize=(12, 7))

        colors = plt.cm.RdYlGn_r(np.linspace(0.2, 0.8, len(counts)))
        bars = ax.bar(labels, counts, color=colors, alpha=0.85, edgecolor="black", linewidth=1.2)

        for bar in bars:
            h = bar.get_height()
            ax.text(
                bar.get_x() + bar.get_width() / 2.0,
                h + 0.1,
                f"{int(h)}",
                ha="center",
                va="bottom",
                fontsize=11,
                fontweight="bold",
            )

        ax.set_xlabel("PageRank Percentile Threshold", fontsize=12)
        ax.set_ylabel("Cumulative CVE Functions Found", fontsize=12)
        ax.set_title(
            f"{CVE_TITLE} – Cumulative CVE Functions by PageRank Threshold\n(Total functions in file: {total_cve})",
            fontsize=14,
            fontweight="bold",
        )
        ax.grid(True, axis="y", alpha=0.3)

        # Random baseline (same concept as 2023)
        random_line = [(b / 100) * total_cve for b in bins]
        ax.plot(range(len(bins)), random_line, "r--", linewidth=3, label="Random baseline", alpha=0.8)

        # improvement shading
        ax.fill_between(
            range(len(bins)),
            random_line,
            counts,
            where=[c > r for c, r in zip(counts, random_line)],
            alpha=0.2,
            color="green",
            label="PageRank better than random",
        )

        ax.legend(fontsize=11, loc="upper left")
        ax.set_ylim(0, total_cve + 2)

        plt.tight_layout()
        out = OUTPUT_PATH / f"4_cve_{CVE_ID}_percentile.png"
        plt.savefig(out, dpi=300, bbox_inches="tight")
        plt.close()
        print(f"   ✅ Saved: {out}")

    # ----------------------------
    # Graph 5: Coverage curve (same style as 2023)
    # ----------------------------
    def plot_cumulative_coverage(self):
        print("\n📊 Graph 5: Cumulative coverage curve...")

        total_funcs = len(self.pagerank)
        cve_ranks = sorted([r[2] for r in self.cve.get("cve_ranks", [])])
        total_cve = len(cve_ranks)

        if total_cve == 0:
            print("⚠️  No CVE ranks found — cannot plot Graph 5")
            return

        percentiles = range(0, 101, 5)
        coverage = []
        for p in percentiles:
            thr = (p / 100) * total_funcs
            covered = sum(1 for r in cve_ranks if r <= thr)
            coverage.append((covered / total_cve) * 100)

        fig, ax = plt.subplots(figsize=(12, 7))

        ax.plot(
            percentiles,
            coverage,
            "b-",
            linewidth=3,
            marker="o",
            markersize=6,
            label="PageRank-based coverage",
        )
        ax.plot(percentiles, percentiles, "r--", linewidth=2, alpha=0.7, label="Random baseline")

        ax.axvline(10, color="green", linestyle=":", alpha=0.5, label="Top 10%")
        ax.axvline(20, color="orange", linestyle=":", alpha=0.5, label="Top 20%")

        ax.set_xlabel("% of Functions Reviewed (by PageRank)", fontsize=12)
        ax.set_ylabel("% of CVE File Functions Found", fontsize=12)
        ax.set_title(
            f"{CVE_TITLE} – Cumulative Coverage (PageRank vs Random)\n(File functions: {total_cve})",
            fontsize=14,
            fontweight="bold",
        )
        ax.legend(fontsize=11, loc="lower right")
        ax.grid(True, alpha=0.3)
        ax.set_xlim(0, 100)
        ax.set_ylim(0, 100)

        # annotate at 20% (more meaningful for small n than 10%)
        idx_20 = list(percentiles).index(20)
        ax.annotate(
            f"{coverage[idx_20]:.1f}% found\nin top 20%",
            xy=(20, coverage[idx_20]),
            xytext=(35, max(0, coverage[idx_20] - 20)),
            arrowprops=dict(arrowstyle="->", color="orange", lw=2),
            fontsize=11,
            fontweight="bold",
            color="orange",
        )

        plt.tight_layout()
        out = OUTPUT_PATH / f"5_cve_{CVE_ID}_coverage.png"
        plt.savefig(out, dpi=300, bbox_inches="tight")
        plt.close()
        print(f"   ✅ Saved: {out}")

    # ----------------------------
    # Graph 6: Call graph (FIXED for 2024)
    # - If CVE file has 0 internal calls, we still build a graph:
    #   show who calls these CVE functions across the subsystem (reverse edges)
    # ----------------------------
    def plot_call_graph(self):
        print("\n📊 Graph 6: Call graph visualization...")

        with open(CALLS_FILE, "r") as f:
            calls = json.load(f)

        cve_funcs = self.cve.get("cve_functions", [])
        if not cve_funcs:
            print("⚠️  No cve_functions found — cannot plot call graph")
            return

        G = nx.DiGraph()

        # 1) internal calls from CVE file (might be empty for 2024)
        internal = calls.get(CVE_FILE, {})
        for caller, callees in internal.items():
            for callee in callees:
                if callee in self.pagerank:  # keep only known functions
                    G.add_edge(caller, callee)

        # 2) if internal is empty, build reverse edges: who calls CVE functions?
        if G.number_of_edges() == 0:
            for fname, file_calls in calls.items():
                for caller, callees in file_calls.items():
                    for callee in callees:
                        if callee in cve_funcs:
                            G.add_edge(caller, callee)

        if G.number_of_nodes() == 0:
            print("⚠️  No edges found for call graph (even reverse).")
            return

        # Keep it readable: top 30 nodes by degree
        if G.number_of_nodes() > 30:
            deg = dict(G.degree())
            top_nodes = sorted(deg.items(), key=lambda x: x[1], reverse=True)[:30]
            keep = [n for n, _ in top_nodes]
            G = G.subgraph(keep).copy()

        fig, ax = plt.subplots(figsize=(16, 12))

        pos = nx.spring_layout(G, k=1.6, iterations=80, seed=42)

        node_colors = [self.pagerank.get(n, 0.0) for n in G.nodes()]
        vmin, vmax = min(node_colors), max(node_colors)

        nx.draw_networkx_nodes(
            G,
            pos,
            node_color=node_colors,
            node_size=900,
            cmap="YlOrRd",
            vmin=vmin,
            vmax=vmax,
            alpha=0.9,
            ax=ax,
        )

        nx.draw_networkx_labels(G, pos, font_size=8, font_weight="bold", ax=ax)

        nx.draw_networkx_edges(
            G,
            pos,
            edge_color="black",
            arrows=True,
            arrowsize=22,
            arrowstyle="->",
            alpha=0.65,
            width=2.0,
            connectionstyle="arc3,rad=0.12",
            ax=ax,
        )

        sm = plt.cm.ScalarMappable(cmap="YlOrRd", norm=plt.Normalize(vmin=vmin, vmax=vmax))
        sm.set_array([])
        cbar = plt.colorbar(sm, ax=ax)
        cbar.set_label("PageRank Score", fontsize=11)

        ax.set_title(
            f"{CVE_TITLE} – Call Graph (Top connected nodes)\n(Node color = PageRank)",
            fontsize=14,
            fontweight="bold",
        )
        ax.axis("off")

        plt.tight_layout()
        out = OUTPUT_PATH / f"6_cve_{CVE_ID}_callgraph.png"
        plt.savefig(out, dpi=300, bbox_inches="tight")
        plt.close()
        print(f"   ✅ Saved: {out}")

    def create_all(self):
        print("=" * 70)
        print(f"🎨 REDO VISUALIZATIONS: {CVE_TITLE}")
        print("=" * 70)

        # Only the CVE graphs (3–6) — because you already have general graphs 1–2
        self.plot_cve_file_functions()
        self.plot_cve_percentile_distribution()
        self.plot_cumulative_coverage()
        self.plot_call_graph()

        print("\n" + "=" * 70)
        print("✅ DONE! (Graphs 3–6 regenerated with better 2024 handling)")
        print("=" * 70)
        print(f"Saved to: {OUTPUT_PATH}")
        print(f"Files start with: 3_cve_{CVE_ID}_..., 4_cve_{CVE_ID}_..., 5_cve_{CVE_ID}_..., 6_cve_{CVE_ID}_...")


def main():
    viz = Visualizer()
    viz.load_data()
    viz.create_all()
    return 0


if __name__ == "__main__":
    sys.exit(main())
