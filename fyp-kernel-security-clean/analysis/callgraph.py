"""
Shared helper: build the netfilter call graph from the extraction results.

Every script that needs the call graph uses load_call_graph(), so they all
see exactly the same graph.

Node names: a function's name, e.g. "nft_payload_eval". When several files
each define their own `static` function with the same name (e.g. six
different `help` functions), each gets its file attached so they stay
separate nodes: "help [nf_conntrack_ftp.c]". Node attributes: name, file, line.

Each edge has a 'kind' attribute:
    'direct'   - a call by name, foo(...)       (extract_function_calls.py)
    'indirect' - a call through a function pointer, ops->eval(...)
                                                 (extract_indirect_calls.py)

Usage from a script in analysis/<folder>/:
    sys.path.insert(0, str(PROJECT_ROOT / "analysis"))
    from callgraph import load_call_graph
"""

import json
from collections import Counter
from pathlib import Path

import networkx as nx

PROJECT_ROOT = Path(__file__).resolve().parents[1]

FUNCTIONS_FILE = PROJECT_ROOT / "results/raw/functions_v2.json"
DIRECT_CALLS_FILE = PROJECT_ROOT / "results/raw/function_calls_v2.json"
INDIRECT_CALLS_FILE = PROJECT_ROOT / "results/raw/indirect_calls.json"


class FunctionIndex:
    """Turns (function name, file) into graph node names, following C's rule
    that a `static` function is only visible inside its own file."""

    def __init__(self, functions):
        self.functions = functions
        self.name_count = Counter(f["name"] for funcs in functions.values() for f in funcs)
        self.defined_in = {file: {f["name"] for f in funcs} for file, funcs in functions.items()}

    def node_id(self, name, file):
        """Node name for the function `name` defined in `file`"""
        if self.name_count[name] > 1:
            return f"{name} [{file}]"
        return name

    def resolve(self, name, from_file):
        """
        Node that a use of `name` inside `from_file` refers to, or None.
        Same-file definition first (static functions are file-local);
        otherwise the one definition elsewhere. A name defined in several
        OTHER files is ambiguous (they are all static), so return None.
        """
        if name in self.defined_in.get(from_file, ()):
            return self.node_id(name, from_file)
        if self.name_count[name] == 1:
            return name
        return None


def load_functions():
    with open(FUNCTIONS_FILE, "r") as f:
        return json.load(f)


def load_call_graph(include_indirect=True):
    """Return a networkx DiGraph: nodes = functions, edges = caller -> callee"""
    graph = nx.DiGraph()

    functions = load_functions()
    index = FunctionIndex(functions)
    for filename, funcs in functions.items():
        for func in funcs:
            graph.add_node(index.node_id(func["name"], filename),
                           name=func["name"], file=filename, line=func["line"])

    with open(DIRECT_CALLS_FILE, "r") as f:
        direct = json.load(f)
    for filename, file_calls in direct.items():
        for caller, callees in file_calls.items():
            source = index.resolve(caller, filename)
            for callee in callees:
                target = index.resolve(callee, filename)
                if source and target and source != target:
                    graph.add_edge(source, target, kind="direct")

    if include_indirect:
        if not INDIRECT_CALLS_FILE.exists():
            raise FileNotFoundError(
                f"{INDIRECT_CALLS_FILE} not found - run extract_indirect_calls.py first"
            )
        with open(INDIRECT_CALLS_FILE, "r") as f:
            indirect = json.load(f)
        # indirect_calls.json already stores node names (it uses FunctionIndex too)
        for caller, targets in indirect["edges"].items():
            for target in targets:
                if not graph.has_edge(caller, target):
                    graph.add_edge(caller, target, kind="indirect")

    return graph


def count_edges(graph):
    """Return (direct, indirect) edge counts"""
    kinds = [data.get("kind") for _, _, data in graph.edges(data=True)]
    return kinds.count("direct"), kinds.count("indirect")
