"""
Shared helper for the long LLM jobs (llm_check.py, score_shortlist.py).

  Scorer(graph, prompt)        prompt "v3" (old one-shot risk score, kept for
                               comparison) or "vulnsc" (Phase 6 reranker);
                               .score(node) -> {"risk": 0..1, ...} or {"error": ...}
  run_job(nodes, scorer, ...)  scores the nodes in order and saves progress
                               every few functions. Resumable: answers are
                               cached, so a restart skips what is done.
                               Stops by itself after max_hours_per_run
                               (configs/llm.yaml) or on Ctrl+C.
"""

import json
import sys
import time
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "analysis"))
sys.path.insert(0, str(PROJECT_ROOT / "analysis/llm"))
from config import kernel_info
from llm_client import MODEL, TimeBudget, load_prompts, score_function
from vulnsc import VulnSC

PROMPTS = ("v3", "vulnsc")
SAVE_EVERY = 10


class Scorer:
    def __init__(self, graph, prompt):
        if prompt not in PROMPTS:
            raise ValueError(f"prompt must be one of {PROMPTS}")
        self.graph, self.prompt = graph, prompt
        self.prompts = load_prompts()
        self.reviewer = VulnSC(graph, prompts=self.prompts) if prompt == "vulnsc" else None
        self.failures = 0

    def score(self, node):
        if self.prompt == "v3":
            result = score_function(self.graph, node, "v3", self.prompts)
        else:
            result = self.reviewer.review(node)
        self.failures += "error" in result
        return result

    def failure_counts(self):
        if self.reviewer:
            return {"review_json_failures": self.reviewer.failures["review"],
                    "summary_json_failures": self.reviewer.failures["summary"]}
        return {"json_failures": self.failures}


def run_job(nodes, scorer, out_file, label, max_hours=None, extra=None):
    """Score `nodes` in order; returns (results {node: answer}, finished?)"""
    budget = TimeBudget(max_hours)
    results, newly_asked, finished = {}, 0, False
    status = "running"
    print(f"   {label}: {len(nodes)} functions, prompt {scorer.prompt}, model {MODEL}, "
          f"time cap {budget.max_hours} h", flush=True)

    def save(status):
        progress = {"kernel": kernel_info(), "model": MODEL, "prompt": scorer.prompt, "label": label,
                    "done": len(results), "total": len(nodes), "status": status,
                    "updated": datetime.now().strftime("%Y-%m-%d %H:%M"),
                    "hours_this_run": round(budget.hours(), 2),
                    "failures": scorer.failure_counts(), **(extra or {})}
        out_file.parent.mkdir(parents=True, exist_ok=True)
        with open(out_file, "w") as f:
            json.dump({"progress": progress, "results": results}, f, indent=1)

    try:
        for i, node in enumerate(nodes, 1):
            if budget.expired():
                status = (f"stopped after the {budget.max_hours} h cap - run the same command "
                          "again to continue")
                print(f"\n⏸️  Time cap reached ({budget.max_hours} h). Saved; run again to continue.")
                break
            started = time.time()
            results[node] = scorer.score(node)
            newly_asked += time.time() - started > 0.5      # cached answers come back instantly
            if i % SAVE_EVERY == 0 or i == len(nodes):
                save("running")
                rate = budget.hours() * 3600 / newly_asked if newly_asked else 0
                print(f"   {i:4d}/{len(nodes)}  failures {scorer.failure_counts()}  "
                      f"~{rate:4.1f} s/function  {budget.hours():.2f} h so far", flush=True)
        else:
            finished, status = True, "finished"
    except KeyboardInterrupt:
        status = "stopped by user - run the same command again to continue"
        print("\n⏸️  Stopped. Everything so far is saved; run the same command to continue.")
    save(status)
    return results, finished
