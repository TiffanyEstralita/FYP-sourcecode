#!/usr/bin/env python3
"""
Risk-score many functions with the LLM - designed to run unattended.

Functions are scored in ORDER OF IMPORTANCE: alternately the next function
from the personalized PageRank ranking and from the standard ranking. So if
the run is stopped at any point, what has been scored is a complete
"top K" shortlist of both rankings for whatever K was reached.

Safe to stop (Ctrl+C) and restart: every answer is cached the moment it
arrives (results/llm_cache/<version>/), and a restart skips cached answers.

Usage (from the fyp-kernel-security-clean folder):
    .venv\\Scripts\\python.exe analysis\\llm\\score_functions.py --version best            # all functions
    .venv\\Scripts\\python.exe analysis\\llm\\score_functions.py --version best --top 500  # first 500 only
    .venv\\Scripts\\python.exe analysis\\llm\\score_functions.py --version v2

--version best = the version with the highest CVE-level separation in
results/processed/prompt_tuning.csv (chosen on the tuning CVEs only).

Output:
    results/processed/llm_scoring_progress.json   updated while running
    results/processed/llm_scores_<version>.json   {node: answer} for everything scored so far
"""

import argparse
import csv
import json
import sys
import time
from datetime import datetime
from pathlib import Path

# Windows terminals use a non-UTF-8 encoding by default and crash on emoji output
sys.stdout.reconfigure(encoding="utf-8")

PROJECT_ROOT = Path(__file__).resolve().parents[2]

TUNING_FILE = PROJECT_ROOT / "results/processed/prompt_tuning.csv"
RANKINGS = [PROJECT_ROOT / "results/processed/ppr_scores.json",
            PROJECT_ROOT / "results/processed/pagerank_scores.json"]
OUTPUT_PATH = PROJECT_ROOT / "results/processed"
SAVE_EVERY = 25   # write the results file every N functions

sys.path.insert(0, str(PROJECT_ROOT / "analysis"))
sys.path.insert(0, str(PROJECT_ROOT / "analysis/llm"))
from callgraph import load_call_graph
from llm_client import MODEL, load_prompts, ollama_available, score_function


def best_version():
    """Prompt version with the best CVE-level separation on the tuning CVEs"""
    with open(TUNING_FILE, newline="") as f:
        rows = list(csv.DictReader(f))
    best = max(rows, key=lambda r: (float(r["separation_cve"]), float(r["separation_function"])))
    return best["version"], best


def scoring_order(graph):
    """Alternate between the rankings, best first, skipping repeats"""
    lists = []
    for path in RANKINGS:
        with open(path, "r") as f:
            scores = json.load(f)
        lists.append(sorted((n for n in scores if n in graph), key=scores.get, reverse=True))
    order, seen = [], set()
    for i in range(max(len(l) for l in lists)):
        for l in lists:
            if i < len(l) and l[i] not in seen:
                seen.add(l[i])
                order.append(l[i])
    order += sorted(n for n in graph if n not in seen)   # anything not in a ranking goes last
    return order


def save(results, version, progress):
    with open(OUTPUT_PATH / f"llm_scores_{version}.json", "w") as f:
        json.dump(results, f, indent=1)
    with open(OUTPUT_PATH / "llm_scoring_progress.json", "w") as f:
        json.dump(progress, f, indent=2)


def main():
    parser = argparse.ArgumentParser(description="Risk-score functions with the LLM (resumable)")
    parser.add_argument("--version", default="best",
                        help="prompt version, or 'best' = winner of tune_prompt.py (default)")
    parser.add_argument("--top", type=int, default=None,
                        help="only score this many functions (in importance order)")
    args = parser.parse_args()

    print("=" * 70)
    print("🤖 LLM RISK SCORING (resumable - safe to stop with Ctrl+C)")
    print("=" * 70)

    if not ollama_available():
        print(f"❌ Ollama is not running or model {MODEL} is missing. Start Ollama and retry.")
        return 1

    version = args.version
    if version == "best":
        if not TUNING_FILE.exists():
            print("❌ No prompt tuning results yet - run analysis/llm/tune_prompt.py first")
            return 1
        version, row = best_version()
        print(f"   best prompt on the tuning CVEs: {version} "
              f"(CVE-level separation {row['separation_cve']})")

    prompts = load_prompts()
    graph = load_call_graph()
    order = scoring_order(graph)[:args.top] if args.top else scoring_order(graph)
    print(f"   prompt {version}, model {MODEL}, {len(order)} functions to score")

    results, errors = {}, 0
    started = time.time()
    newly_asked = 0
    progress = {}
    try:
        for i, node in enumerate(order, 1):
            t = time.time()
            answer = score_function(graph, node, version, prompts)
            asked = time.time() - t > 0.5   # cached answers come back instantly
            newly_asked += asked
            results[node] = answer
            errors += "error" in answer

            elapsed = time.time() - started
            rate = elapsed / newly_asked if newly_asked else 0
            left = (len(order) - i) * rate
            progress = {
                "version": version, "model": MODEL, "done": i, "total": len(order),
                "errors": errors, "status": "running",
                "started": datetime.fromtimestamp(started).strftime("%Y-%m-%d %H:%M"),
                "updated": datetime.now().strftime("%Y-%m-%d %H:%M"),
                "seconds_per_function": round(rate, 1),
                "estimated_hours_left": round(left / 3600, 1),
            }
            if i % SAVE_EVERY == 0 or i == len(order):
                save(results, version, progress)
                print(f"   {i:5d}/{len(order)}  errors {errors}  "
                      f"~{rate:4.1f} s/function  ~{left / 3600:4.1f} h left", flush=True)
        progress["status"] = "finished"
    except KeyboardInterrupt:
        progress["status"] = "stopped by user (restart to continue)"
        print("\n⏸️  Stopped. Everything scored so far is saved; run the same command to continue.")
    save(results, version, progress)
    print(f"\n💾 Saved: {OUTPUT_PATH / f'llm_scores_{version}.json'} ({len(results)} functions)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
