#!/usr/bin/env python3
"""Test that environment is set up correctly"""

import sys
import networkx as nx
import pandas as pd
import git

print("=" * 60)
print("🧪 FYP Environment Test")
print("=" * 60)

print(f"\n🐍 Python version: {sys.version.split()[0]}")

try:
    print(f"✅ NetworkX {nx.__version__}")
    print(f"✅ Pandas {pd.__version__}")
    print(f"✅ GitPython {git.__version__}")
except Exception as e:
    print(f"❌ Error: {e}")

# Test NetworkX
G = nx.DiGraph()
G.add_edges_from([("A", "B"), ("B", "C"), ("A", "C")])
pr = nx.pagerank(G)
print(f"\n📊 PageRank test: {pr}")

print("\n" + "=" * 60)
print("🎉 Environment setup complete!")
print("=" * 60)
