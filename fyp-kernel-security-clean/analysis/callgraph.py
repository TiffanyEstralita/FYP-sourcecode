"""
Shared helper: build the netfilter call graph from the extraction results.

Every script that needs the call graph uses load_call_graph(), so they all
see exactly the same graph.

Each edge has a 'kind' attribute:
    'direct'   - a call by name, foo(...)       (extract_function_calls.py)
    'indirect' - a call through a function pointer, ops->eval(...)
                                                 (extract_indirect_calls.py)

Usage from a script in analysis/<folder>/:
    sys.path.insert(0, str(PROJECT_ROOT / "analysis"))
    from callgraph import load_call_graph
"""

import json
from pathlib import Path

import networkx as nx

PROJECT_ROOT = Path(__file__).resolve().parents[1]

FUNCTIONS_FILE = PROJECT_ROOT / "results/raw/functions_v2.json"
DIRECT_CALLS_FILE = PROJECT_ROOT / "results/raw/function_calls_v2.json"
INDIRECT_CALLS_FILE = PROJECT_ROOT / "results/raw/indirect_calls.json"


def load_call_graph(include_indirect=True):
    """Return a networkx DiGraph: nodes = functions, edges = caller -> callee"""
    graph = nx.DiGraph()

    with open(FUNCTIONS_FILE, "r") as f:
        functions = json.load(f)
    for filename, funcs in functions.items():
        for func in funcs:
            graph.add_node(func["name"], file=filename, line=func["line"])

    with open(DIRECT_CALLS_FILE, "r") as f:
        direct = json.load(f)
    for file_calls in direct.values():
        for caller, callees in file_calls.items():
            for callee in callees:
                graph.add_edge(caller, callee, kind="direct")

    if include_indirect:
        if not INDIRECT_CALLS_FILE.exists():
            raise FileNotFoundError(
                f"{INDIRECT_CALLS_FILE} not found - run extract_indirect_calls.py first"
            )
        with open(INDIRECT_CALLS_FILE, "r") as f:
            indirect = json.load(f)
        for caller, targets in indirect["edges"].items():
            for target in targets:
                if not graph.has_edge(caller, target):
                    graph.add_edge(caller, target, kind="indirect")

    return graph


def count_edges(graph):
    """Return (direct, indirect) edge counts"""
    kinds = [data.get("kind") for _, _, data in graph.edges(data=True)]
    return kinds.count("direct"), kinds.count("indirect")
