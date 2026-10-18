#!/usr/bin/env python3
"""
Score the combined shortlist with the LLM (input for the final evaluation).

The top K functions of the combined shortlist (Phase 4,
results/processed/shortlist.json) are scored in shortlist order, so if a
run stops early, what is done is always "the top N" for some N.

    python analysis/llm/score_shortlist.py --prompt v3       # old prompt (comparison)
    python analysis/llm/score_shortlist.py --prompt vulnsc   # Phase 6 reranker

Resumable and time-capped (configs/llm.yaml): just run it again to continue.
Output: results/processed/llm_scores_shortlist_<prompt>.json
"""

import argparse
import json
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "analysis"))
sys.path.insert(0, str(PROJECT_ROOT / "analysis/llm"))
from callgraph import load_call_graph
from config import PATHS
from jobs import PROMPTS, Scorer, run_job
from llm_client import MODEL, ollama_available


def main():
    parser = argparse.ArgumentParser(description="LLM-score the combined shortlist (resumable)")
    parser.add_argument("--prompt", choices=PROMPTS, required=True)
    parser.add_argument("--max-hours", type=float, help="override max_hours_per_run")
    parser.add_argument("--limit", type=int, help="only the first N shortlist functions (quick test)")
    args = parser.parse_args()

    print("=" * 70)
    print(f"🤖 LLM SCORING OF THE SHORTLIST ({args.prompt}) - resumable, safe to stop")
    print("=" * 70)
    if not ollama_available():
        print(f"❌ Ollama is not running or model {MODEL} is missing. Start Ollama and retry.")
        return 1
    with open(PATHS.processed / "shortlist.json") as f:
        shortlist = json.load(f)
    nodes = [row["node"] for row in shortlist["shortlist"]][:args.limit]
    graph = load_call_graph()
    out_file = PATHS.processed / f"llm_scores_shortlist_{args.prompt}.json"
    results, finished = run_job(nodes, Scorer(graph, args.prompt), out_file,
                                f"shortlist top {len(nodes)}", args.max_hours,
                                extra={"k": shortlist["k"]})
    print(f"\n{'✅ finished' if finished else '⏸️  not finished yet'}: {len(results)}/{len(nodes)} scored")
    print(f"💾 Saved: {out_file}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
