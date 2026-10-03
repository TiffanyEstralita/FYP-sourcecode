#!/usr/bin/env python3
"""
SCRIPT #3: Build Graph and Calculate PageRank
Purpose: Identify critical functions using PageRank algorithm

Two versions are computed:
  standard     - every function is an equally likely starting point
                 -> pagerank_scores.json, top_100_functions.json, pagerank_summary.txt
  personalized - random walks start only at the seeds (attacker entry points
                 from build_seeds.py), so a function scores high when attacker
                 input can flow into it
                 -> ppr_scores.json, ppr_top_100_functions.json, ppr_summary.txt
"""

import argparse
import json
import networkx as nx
import matplotlib.pyplot as plt
from pathlib import Path
import sys

# Windows terminals use a non-UTF-8 encoding by default and crash on emoji output
sys.stdout.reconfigure(encoding="utf-8")

# Paths
PROJECT_ROOT = Path(__file__).resolve().parents[2]

INPUT_FUNCTIONS = PROJECT_ROOT / "results/raw/functions_v2.json"
INPUT_CALLS = PROJECT_ROOT / "results/raw/function_calls_v2.json"
SEEDS_FILE = PROJECT_ROOT / "results/processed/seeds.json"
OUTPUT_PATH = PROJECT_ROOT / "results/processed"
GRAPHS_PATH = PROJECT_ROOT / "results/visualizations"

# output file names for each version
OUTPUTS = {
    "standard": {"scores": "pagerank_scores.json", "top_100": "top_100_functions.json",
                 "summary": "pagerank_summary.txt", "title": "PAGERANK (STANDARD)"},
    "personalized": {"scores": "ppr_scores.json", "top_100": "ppr_top_100_functions.json",
                     "summary": "ppr_summary.txt", "title": "PERSONALIZED PAGERANK (SEEDS)"},
}


def load_seeds():
    """Seed functions from build_seeds.py, as a uniform personalization vector"""
    with open(SEEDS_FILE, 'r') as f:
        seeds = list(json.load(f)["seeds"])
    return {node: 1.0 for node in seeds}   # networkx normalises these to sum to 1

sys.path.insert(0, str(PROJECT_ROOT / "analysis"))
from callgraph import load_call_graph, count_edges

class PageRankAnalyzer:
    """Build graph and calculate PageRank"""
    
    def __init__(self):
        self.graph = nx.DiGraph()
        self.functions = {}
        self.calls = {}
    
    def load_data(self):
        """Load functions and calls"""
        print("📂 Loading data...")
        
        # Load functions
        with open(INPUT_FUNCTIONS, 'r') as f:
            self.functions = json.load(f)
        
        # Load calls
        with open(INPUT_CALLS, 'r') as f:
            self.calls = json.load(f)
        
        total_funcs = sum(len(funcs) for funcs in self.functions.values())
        total_calls = sum(
            sum(len(callees) for callees in file_calls.values())
            for file_calls in self.calls.values()
        )
        
        print(f"✅ Loaded {total_funcs} functions from {len(self.functions)} files")
        print(f"✅ Loaded {total_calls} call relationships")
    
    def build_graph(self, include_indirect=True):
        """Build NetworkX directed graph (shared builder in analysis/callgraph.py)"""
        print("\n🔨 Building graph...")

        self.graph = load_call_graph(include_indirect=include_indirect)
        direct, indirect = count_edges(self.graph)

        print(f"✅ Graph built:")
        print(f"   Nodes (functions): {self.graph.number_of_nodes()}")
        print(f"   Edges (calls):     {self.graph.number_of_edges()}")
        print(f"      direct:         {direct}")
        print(f"      indirect:       {indirect}" +
              ("" if include_indirect else "  (disabled with --no-indirect)"))
    
    def calculate_pagerank(self, alpha=0.85, personalization=None):
        """Calculate PageRank scores (personalized when a seed vector is given)"""
        kind = "personalized PageRank" if personalization else "PageRank"
        print(f"\n📊 Calculating {kind} (alpha={alpha})...")

        try:
            pagerank = nx.pagerank(
                self.graph,
                alpha=alpha,                      # Damping factor (0.85 is standard)
                personalization=personalization,  # None = standard PageRank
                max_iter=100,                     # Maximum iterations
                tol=1e-06                         # Convergence tolerance
            )
            print(f"✅ {kind} calculation complete!")
            return pagerank
        except Exception as e:
            print(f"❌ Error calculating {kind}: {e}")
            return None
    
    def analyze_pagerank(self, pagerank):
        """Analyze PageRank results"""
        print("\n🔍 Analyzing PageRank results...")
        
        # Sort by PageRank score
        sorted_pr = sorted(pagerank.items(), key=lambda x: x[1], reverse=True)
        
        # Statistics
        scores = list(pagerank.values())
        stats = {
            'total_functions': len(pagerank),
            'mean_pagerank': sum(scores) / len(scores),
            'max_pagerank': max(scores),
            'min_pagerank': min(scores),
            'top_100': sorted_pr[:100],
            'top_50': sorted_pr[:50],
            'top_20': sorted_pr[:20]
        }
        
        print(f"✅ Statistics:")
        print(f"   Functions ranked:   {stats['total_functions']}")
        print(f"   Mean PageRank:      {stats['mean_pagerank']:.6f}")
        print(f"   Max PageRank:       {stats['max_pagerank']:.6f}")
        print(f"   Min PageRank:       {stats['min_pagerank']:.6f}")
        
        return stats
    
    def save_results(self, pagerank, stats, mode, alpha):
        """Save all results for one version ('standard' or 'personalized')"""
        OUTPUT_PATH.mkdir(parents=True, exist_ok=True)
        names = OUTPUTS[mode]

        print("\n💾 Saving results...")

        # Save PageRank scores
        pr_file = OUTPUT_PATH / names["scores"]
        with open(pr_file, 'w') as f:
            json.dump(pagerank, f, indent=2)
        print(f"   ✅ Saved PageRank scores: {pr_file}")
        
        # Save top 100 with metadata
        top_100_detailed = []
        for node, score in stats['top_100']:
            # File and line are stored on the graph node (see analysis/callgraph.py)
            info = self.graph.nodes[node]
            top_100_detailed.append({
                'rank': len(top_100_detailed) + 1,
                'function': info['name'],
                'node': node,
                'pagerank': score,
                'file': info['file'],
                'line': info['line']
            })
        
        top_100_file = OUTPUT_PATH / names["top_100"]
        with open(top_100_file, 'w') as f:
            json.dump(top_100_detailed, f, indent=2)
        print(f"   ✅ Saved top 100 functions: {top_100_file}")
        
        # Create human-readable summary
        summary_file = OUTPUT_PATH / names["summary"]
        with open(summary_file, 'w') as f:
            f.write("=" * 70 + "\n")
            f.write(f"{names['title']} SUMMARY\n")
            f.write("=" * 70 + "\n\n")
            f.write(f"alpha (damping factor):    {alpha}\n")
            f.write(f"Total functions analyzed:  {stats['total_functions']}\n")
            f.write(f"Mean PageRank score:       {stats['mean_pagerank']:.6f}\n")
            f.write(f"Max PageRank score:        {stats['max_pagerank']:.6f}\n")
            f.write(f"Min PageRank score:        {stats['min_pagerank']:.6f}\n")
            
            f.write("\n" + "=" * 70 + "\n")
            f.write("TOP 50 FUNCTIONS BY PAGERANK\n")
            f.write("=" * 70 + "\n\n")
            for i, (node, score) in enumerate(stats['top_50'], 1):
                info = self.graph.nodes[node]
                f.write(f"{i:3d}. {info['name']:45s} {score:.6f} ({info['file']})\n")

        print(f"   ✅ Saved summary: {summary_file}")


def main():
    """Main execution"""

    parser = argparse.ArgumentParser(description="Build the call graph and run PageRank")
    parser.add_argument("--no-indirect", action="store_true",
                        help="ignore function-pointer edges (reproduces the Phase 0 baseline)")
    parser.add_argument("--mode", choices=["standard", "personalized", "both"], default="both",
                        help="which PageRank version(s) to compute (default: both)")
    parser.add_argument("--alpha", type=float, default=0.85,
                        help="damping factor (default: 0.85)")
    args = parser.parse_args()

    print("=" * 70)
    print("🚀 PAGERANK ANALYSIS")
    print("=" * 70)

    # Initialize analyzer
    analyzer = PageRankAnalyzer()

    # Load data
    analyzer.load_data()

    # Build graph
    analyzer.build_graph(include_indirect=not args.no_indirect)

    modes = ["standard", "personalized"] if args.mode == "both" else [args.mode]
    for mode in modes:
        personalization = None
        if mode == "personalized":
            if not SEEDS_FILE.exists():
                print(f"❌ {SEEDS_FILE} not found - run build_seeds.py first")
                return 1
            personalization = load_seeds()
            print(f"\n🚪 Using {len(personalization)} seed functions from {SEEDS_FILE.name}")

        # Calculate PageRank
        pagerank = analyzer.calculate_pagerank(args.alpha, personalization)
        if not pagerank:
            return 1

        # Analyze results
        stats = analyzer.analyze_pagerank(pagerank)

        # Print top 20
        print(f"\n📈 TOP 20 FUNCTIONS ({OUTPUTS[mode]['title']}):")
        for i, (func, score) in enumerate(stats['top_20'], 1):
            print(f"   {i:2d}. {func:45s} {score:.6f}")

        # Save results
        analyzer.save_results(pagerank, stats, mode, args.alpha)

    print("\n" + "=" * 70)
    print("✅ PAGERANK ANALYSIS COMPLETE!")
    print("=" * 70)
    print("\nNext step: run evaluate_rankings.py to compare the rankings on the CVEs")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())