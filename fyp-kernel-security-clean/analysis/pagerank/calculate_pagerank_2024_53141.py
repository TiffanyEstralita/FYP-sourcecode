#!/usr/bin/env python3
"""
SCRIPT #3: Build Graph and Calculate PageRank
Purpose: Identify critical functions using PageRank algorithm
Date: November 2025
"""

import json
import networkx as nx
import matplotlib.pyplot as plt
from pathlib import Path
import sys

# Paths
INPUT_FUNCTIONS = Path.home() / "fyp-kernel-security/results/raw/functions_v2.json"
INPUT_CALLS = Path.home() / "fyp-kernel-security/results/raw/function_calls_v2.json"
OUTPUT_PATH = Path.home() / "fyp-kernel-security/results/processed"
GRAPHS_PATH = Path.home() / "fyp-kernel-security/results/visualizations"

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
    
    def build_graph(self):
        """Build NetworkX directed graph"""
        print("\n🔨 Building graph...")
        
        # Add all functions as nodes
        for filename, funcs in self.functions.items():
            for func in funcs:
                func_name = func['name']
                self.graph.add_node(
                    func_name,
                    file=filename,
                    line=func['line']
                )
        
        # Add all calls as edges
        for filename, file_calls in self.calls.items():
            for caller, callees in file_calls.items():
                for callee in callees:
                    # Add edge: caller → callee
                    self.graph.add_edge(caller, callee)
        
        print(f"✅ Graph built:")
        print(f"   Nodes (functions): {self.graph.number_of_nodes()}")
        print(f"   Edges (calls):     {self.graph.number_of_edges()}")
    
    def calculate_pagerank(self):
        """Calculate PageRank scores"""
        print("\n📊 Calculating PageRank...")
        
        try:
            pagerank = nx.pagerank(
                self.graph,
                alpha=0.85,      # Damping factor (standard)
                max_iter=100,    # Maximum iterations
                tol=1e-06        # Convergence tolerance
            )
            print("✅ PageRank calculation complete!")
            return pagerank
        except Exception as e:
            print(f"❌ Error calculating PageRank: {e}")
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
    
    def check_cve_file(self, pagerank):
        """Check PageRank of CVE file functions"""
        print("\n🎯 CVE-2024-53141 FILE ANALYSIS:") 
        #for 2024 cve
        
        cve_file = "ip_set_bitmap_ip.c"
        #change from nf table api to ip set bitmap ip cve 2024-53141
        
        if cve_file not in self.functions:
            print(f"   ❌ {cve_file} not found!")
            return None
        
        # Get all functions from CVE file
        cve_functions = [f['name'] for f in self.functions[cve_file]]
        
        # Get PageRank scores for CVE functions
        cve_scores = []
        for func in cve_functions:
            if func in pagerank:
                cve_scores.append((func, pagerank[func]))
        
        # Sort by PageRank
        cve_scores_sorted = sorted(cve_scores, key=lambda x: x[1], reverse=True)
        
        # Overall rank of CVE functions
        all_sorted = sorted(pagerank.items(), key=lambda x: x[1], reverse=True)
        cve_ranks = []
        for func, score in cve_scores:
            rank = next(i for i, (f, s) in enumerate(all_sorted, 1) if f == func)
            cve_ranks.append((func, score, rank))
        
        cve_ranks_sorted = sorted(cve_ranks, key=lambda x: x[1], reverse=True)
        
        print(f"   Total functions in CVE file: {len(cve_functions)}")
        print(f"   Functions with PageRank:     {len(cve_scores)}")
        print(f"\n   Top 20 CVE functions by PageRank:")
        for i, (func, score, rank) in enumerate(cve_ranks_sorted[:20], 1):
            percentile = (rank / len(all_sorted)) * 100
            print(f"      {i:2d}. {func:40s} PR: {score:.6f} (Rank #{rank:4d}, Top {percentile:.1f}%)")
        
        # Count how many CVE functions are in top 10%, 20%, etc.
        top_10_pct = len([r for _, _, r in cve_ranks if r <= len(all_sorted) * 0.1])
        top_20_pct = len([r for _, _, r in cve_ranks if r <= len(all_sorted) * 0.2])
        
        print(f"\n   CVE functions in top 10%: {top_10_pct}/{len(cve_scores)}")
        print(f"   CVE functions in top 20%: {top_20_pct}/{len(cve_scores)}")
        
        return {
            'cve_functions': cve_functions,
            'cve_scores': cve_scores_sorted,
            'cve_ranks': cve_ranks_sorted,
            'top_10_pct': top_10_pct,
            'top_20_pct': top_20_pct
        }
    
    def save_results(self, pagerank, stats, cve_analysis):
        """Save all results"""
        OUTPUT_PATH.mkdir(parents=True, exist_ok=True)
        
        print("\n💾 Saving results...")
        
        # Save PageRank scores
        pr_file = OUTPUT_PATH / "pagerank_scores.json"
        with open(pr_file, 'w') as f:
            json.dump(pagerank, f, indent=2)
        print(f"   ✅ Saved PageRank scores: {pr_file}")
        
        # Save top 100 with metadata
        top_100_detailed = []
        for func, score in stats['top_100']:
            # Find which file this function is in
            for filename, funcs in self.functions.items():
                if any(f['name'] == func for f in funcs):
                    func_info = next(f for f in funcs if f['name'] == func)
                    top_100_detailed.append({
                        'rank': len(top_100_detailed) + 1,
                        'function': func,
                        'pagerank': score,
                        'file': filename,
                        'line': func_info['line']
                    })
                    break
        
        top_100_file = OUTPUT_PATH / "top_100_functions.json"
        with open(top_100_file, 'w') as f:
            json.dump(top_100_detailed, f, indent=2)
        print(f"   ✅ Saved top 100 functions: {top_100_file}")
        
        # Save CVE analysis
        if cve_analysis:
            cve_file = OUTPUT_PATH / "cve_pagerank_analysis.json"
            with open(cve_file, 'w') as f:
                json.dump(cve_analysis, f, indent=2, default=str)
            print(f"   ✅ Saved CVE analysis: {cve_file}")
        
        # Create human-readable summary
        summary_file = OUTPUT_PATH / "pagerank_summary.txt"
        with open(summary_file, 'w') as f:
            f.write("=" * 70 + "\n")
            f.write("PAGERANK ANALYSIS SUMMARY\n")
            f.write("=" * 70 + "\n\n")
            f.write(f"Total functions analyzed:  {stats['total_functions']}\n")
            f.write(f"Mean PageRank score:       {stats['mean_pagerank']:.6f}\n")
            f.write(f"Max PageRank score:        {stats['max_pagerank']:.6f}\n")
            f.write(f"Min PageRank score:        {stats['min_pagerank']:.6f}\n")
            
            f.write("\n" + "=" * 70 + "\n")
            f.write("TOP 50 FUNCTIONS BY PAGERANK\n")
            f.write("=" * 70 + "\n\n")
            for i, (func, score) in enumerate(stats['top_50'], 1):
                # Find file
                for filename, funcs in self.functions.items():
                    if any(f['name'] == func for f in funcs):
                        f.write(f"{i:3d}. {func:45s} {score:.6f} ({filename})\n")
                        break
            
            if cve_analysis:
                f.write("\n" + "=" * 70 + "\n")
                f.write("CVE-2024-53141 FILE ANALYSIS\n") #change to 2024 cve
                f.write("=" * 70 + "\n\n")
                f.write(f"Total CVE functions:       {len(cve_analysis['cve_functions'])}\n")
                f.write(f"Functions in top 10%:      {cve_analysis['top_10_pct']}\n")
                f.write(f"Functions in top 20%:      {cve_analysis['top_20_pct']}\n")
                f.write("\nTop 30 CVE functions:\n\n")
                for i, (func, score, rank) in enumerate(cve_analysis['cve_ranks'][:30], 1):
                    f.write(f"{i:3d}. {func:45s} {score:.6f} (Overall rank: #{rank})\n")
        
        print(f"   ✅ Saved summary: {summary_file}")


def main():
    """Main execution"""
    
    print("=" * 70)
    print("🚀 PAGERANK ANALYSIS")
    print("=" * 70)
    
    # Initialize analyzer
    analyzer = PageRankAnalyzer()
    
    # Load data
    analyzer.load_data()
    
    # Build graph
    analyzer.build_graph()
    
    # Calculate PageRank
    pagerank = analyzer.calculate_pagerank()
    if not pagerank:
        return 1
    
    # Analyze results
    stats = analyzer.analyze_pagerank(pagerank)
    
    # Print top 20
    print("\n📈 TOP 20 FUNCTIONS BY PAGERANK:")
    for i, (func, score) in enumerate(stats['top_20'], 1):
        print(f"   {i:2d}. {func:45s} {score:.6f}")
    
    # Check CVE file
    cve_analysis = analyzer.check_cve_file(pagerank)
    
    # Save results
    analyzer.save_results(pagerank, stats, cve_analysis)
    
    print("\n" + "=" * 70)
    print("✅ PAGERANK ANALYSIS COMPLETE!")
    print("=" * 70)
    print("\nNext step: Use LLM to explain why high-ranking functions are critical")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())