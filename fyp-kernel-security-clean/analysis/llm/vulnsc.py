#!/usr/bin/env python3
"""
Phase 6: VulnSC-style LLM reranker (after Wu et al., ISSTA 2025,
"Enhancing Vulnerability Detection via Inter-procedural Semantic Completion").

Plain idea: a bug often only makes sense when you know what the called
functions do ("is the length checked inside the helper?"). So before the
model reviews a function, it first gets short summaries of the functions
it calls - like giving a reviewer a cheat-sheet of the helpers.

For one function under review:
  1. collect its callees up to depth 2 (callees of callees), at most 8 in
     total, in the order they appear in the code; a callee already in the
     tree is skipped (DFS tree, so loops/recursion cannot repeat forever)
  2. summarise them BOTTOM-UP (deepest first) as
         input: ... | output: ... | behaviour: ...
     a callee's summary is written with its own callees' summaries in view,
     so information flows up the tree; summaries are cached by a hash of
     the code (+ the child summaries), so a helper is summarised once
  3. review: target code + the direct callees' summaries as comments +
     a checklist -> the model answers with JSON findings
     [{"type", "evidence", "severity": low|medium|high}]
  4. the SCORE is computed in code, not by the model:
         sum of severity points (high 3, medium 2, low 1), capped,
         divided by the cap -> 0..1      (configs/llm.yaml)
Temperature 0. Answers are validated; failures are counted, not cached.

Usage (quick test of one or two functions, needs Ollama):
    python analysis/llm/vulnsc.py nft_payload_eval nf_tables_newrule
"""

import re
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "analysis"))
sys.path.insert(0, str(PROJECT_ROOT / "analysis/llm"))
from config import load_yaml
from llm_client import cached_json_answer, function_code, load_prompts

SEVERITIES = ("low", "medium", "high")


class VulnSC:
    def __init__(self, graph, settings=None, prompts=None):
        self.graph = graph
        self.settings = settings or load_yaml("llm.yaml")["vulnsc"]
        self.prompts = (prompts or load_prompts())["vulnsc"]
        self.code_cache = {}
        self.failures = {"summary": 0, "review": 0}
        self.calls = {"summary": 0, "review": 0, "cached": 0}

    # ------------------------------------------------------------ callees
    def code(self, node):
        if node not in self.code_cache:
            info = self.graph.nodes[node]
            self.code_cache[node] = function_code(info["file"], info["line"])
        return self.code_cache[node]

    def ordered_callees(self, node):
        """Callees of `node` in the order they first appear in its code"""
        code = self.code(node)
        callees = []
        for target in self.graph.successors(node):
            edge = self.graph.edges[node, target]
            if edge.get("kind") != "direct" and not self.settings["include_indirect_callees"]:
                continue
            m = re.search(r"\b%s\s*\(" % re.escape(self.graph.nodes[target]["name"]), code)
            callees.append((m.start() if m else len(code), target))
        return [t for _, t in sorted(callees)]

    def callee_tree(self, root):
        """{node: [children]} - DFS tree below root, depth and size limited"""
        max_depth, max_total = self.settings["callee_depth"], self.settings["max_callees"]
        tree, visited = {root: []}, {root}

        def visit(node, depth):
            for child in self.ordered_callees(node):
                if len(visited) - 1 >= max_total:
                    return
                if child in visited:        # already in the tree: skip (no loops)
                    continue
                visited.add(child)
                tree[node].append(child)
                tree[child] = []
                if depth + 1 < max_depth:
                    visit(child, depth + 1)

        visit(root, 0)
        return tree

    # ------------------------------------------------------------ summaries
    def summarise(self, node, tree):
        """Summary line of `node`, after summarising its children (bottom-up)"""
        children = [self.summarise(c, tree) for c in tree.get(node, [])]
        info = self.graph.nodes[node]
        context = ""
        if children:
            context = ("It calls these functions (summaries):\n" +
                       "".join(f"- {line}\n" for line in children) + "\n")
        prompt = self.prompts["summary_template"].format(
            name=info["name"], file=info["file"], code=self.code(node), callee_summaries=context)
        result, cached = cached_json_answer("vulnsc_summary", prompt, validate_summary)
        self.calls["cached" if cached else "summary"] += 1
        if "error" in result:
            self.failures["summary"] += 1
            return f"{info['name']}: (summary unavailable)"
        return (f"{info['name']}: input: {result['input']} | output: {result['output']} | "
                f"behaviour: {result['behaviour']}")

    # ------------------------------------------------------------ review
    def review(self, node):
        """Review one function -> {"score", "risk" (0..1), "findings", ...}"""
        tree = self.callee_tree(node)
        summaries = [self.summarise(c, tree) for c in tree[node]]
        info = self.graph.nodes[node]
        comments = "".join(f"// callee {line}\n" for line in summaries)
        checklist = "\n".join(f"- {t}" for t in self.settings["finding_types"])
        prompt = self.prompts["review_template"].format(
            name=info["name"], file=info["file"], code=self.code(node),
            callee_comments=comments, checklist=checklist)
        result, cached = cached_json_answer(
            "vulnsc_review", prompt, lambda d: validate_findings(d, self.settings["finding_types"]))
        self.calls["cached" if cached else "review"] += 1
        out = {"node": node, "callees": sum(len(v) for v in tree.values()),
               "callee_tree": {k: v for k, v in tree.items() if v}}
        if "error" in result:
            self.failures["review"] += 1
            out.update({"error": result["error"], "raw_answer": result.get("raw_answer", "")})
            return out
        points = self.settings["severity_points"]
        total = sum(points[f["severity"]] for f in result["findings"])
        cap = self.settings["score_cap"]
        out.update({"findings": result["findings"], "invalid_findings": result["invalid_findings"],
                    "points": total, "score": min(total, cap), "risk": min(total, cap) / cap})
        return out


def validate_summary(data):
    out = {}
    for key in ("input", "output", "behaviour"):
        value = data.get(key) if isinstance(data, dict) else None
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"summary field {key!r} missing")
        out[key] = " ".join(value.split())[:300]
    return out


def validate_findings(data, finding_types):
    """Clean list of findings; findings with a bad severity are dropped and counted"""
    if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
        raise ValueError("no 'findings' list")
    lookup = {normal(t): t for t in finding_types}
    clean, invalid = [], 0
    for f in data["findings"]:
        if not isinstance(f, dict):
            invalid += 1
            continue
        severity = str(f.get("severity", "")).strip().lower()
        if severity not in SEVERITIES:
            invalid += 1
            continue
        kind = lookup.get(normal(str(f.get("type", ""))), "other")
        clean.append({"type": kind, "severity": severity,
                      "evidence": " ".join(str(f.get("evidence", "")).split())[:500]})
    return {"findings": clean, "invalid_findings": invalid}


def normal(text):
    return re.sub(r"[^a-z]", "", text.lower())


def main():
    sys.path.insert(0, str(PROJECT_ROOT / "analysis"))
    from callgraph import load_call_graph
    from llm_client import MODEL, ollama_available
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    if not ollama_available():
        print(f"❌ Ollama is not running or model {MODEL} is missing.")
        return 1
    graph = load_call_graph()
    reviewer = VulnSC(graph)
    for node in sys.argv[1:]:
        if node not in graph:
            print(f"❌ {node} is not a function in the call graph")
            continue
        result = reviewer.review(node)
        print(f"\n=== {node}: callee tree {result['callee_tree']}")
        print({k: v for k, v in result.items() if k not in ("callee_tree", "node")})
    print(f"\nLLM calls {reviewer.calls}, failures {reviewer.failures}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
