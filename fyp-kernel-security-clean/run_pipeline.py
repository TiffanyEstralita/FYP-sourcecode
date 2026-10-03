#!/usr/bin/env python3
"""
Run the whole analysis pipeline, one stage after another.

Usage (from the fyp-kernel-security-clean folder):
    python run_pipeline.py                  # all stages except the slow LLM stage
    python run_pipeline.py --llm            # also run the (old) LLM explanation stage
    python run_pipeline.py --report         # also fusion + final results (needs saved LLM
                                            # scores from RUN_LLM_OVERNIGHT.bat)
    python run_pipeline.py --from pagerank  # start part-way (reuse earlier outputs)
    python run_pipeline.py --only visualize # run a single stage
    python run_pipeline.py --list           # show the stages

Each stage is an ordinary script that reads the previous stage's output files
from results/ and writes its own, so stages can also be run by hand.
"""

import argparse
import subprocess
import sys
import time
from pathlib import Path

# Windows terminals use a non-UTF-8 encoding by default and crash on emoji output
sys.stdout.reconfigure(encoding="utf-8")

PROJECT_ROOT = Path(__file__).resolve().parent

# (stage name, script, what it does) - in the order they must run
STAGES = [
    ("functions", "analysis/extraction/extract_all_functions.py",
     "find every function defined in net/netfilter"),
    ("calls", "analysis/extraction/extract_function_calls.py",
     "find which function calls which (the call graph edges)"),
    ("indirect", "analysis/extraction/extract_indirect_calls.py",
     "add calls made through function pointers (ops->eval etc.)"),
    ("seeds", "analysis/pagerank/build_seeds.py",
     "turn configs/seeds.yaml into the list of attacker entry points"),
    ("pagerank", "analysis/pagerank/calculate_pagerank.py",
     "rank functions with standard and personalized PageRank"),
    ("reach", "analysis/pagerank/check_reachability.py",
     "check each vulnerable function is reachable from the seeds"),
    ("cve", "analysis/pagerank/analyze_cve_functions.py",
     "look up where each CVE's vulnerable function ranks"),
    ("evaluate", "analysis/pagerank/evaluate_rankings.py",
     "compare baseline / standard / personalized rankings on the CVEs"),
    ("alpha", "analysis/pagerank/alpha_sensitivity.py",
     "re-run personalized PageRank for several alpha values"),
    ("visualize", "analysis/pagerank/visualize_results.py",
     "draw charts 1-4 and 6 for every CVE"),
    ("graph", "analysis/pagerank/create_directional_graph.py",
     "draw the top-30 directional call graph"),
    ("llm", "analysis/llm/explain_critical_functions.py",
     "ask the local Ollama model to explain the top functions (slow)"),
    # report stages: use the LLM risk scores saved by RUN_LLM_OVERNIGHT.bat
    # (results/processed/llm_scores_v3.json); no LLM calls
    ("fusion", "analysis/fusion/fuse_scores.py",
     "combine PageRank shortlist + saved LLM scores; ablation and efficiency curve"),
    ("final", "analysis/report/final_results.py",
     "final tables, random baseline, uncertainty, results/RESULTS.md"),
]
REPORT_STAGES = {"fusion", "final"}
STAGE_NAMES = [name for name, _, _ in STAGES]


def parse_args():
    parser = argparse.ArgumentParser(description="Run the FYP analysis pipeline")
    parser.add_argument("--from", dest="start", choices=STAGE_NAMES,
                        help="start at this stage and run everything after it")
    parser.add_argument("--only", choices=STAGE_NAMES, help="run just this one stage")
    parser.add_argument("--llm", action="store_true",
                        help="include the LLM stage (needs Ollama running)")
    parser.add_argument("--llm-limit", type=int, default=20,
                        help="how many top functions the LLM stage explains (default: 20)")
    parser.add_argument("--report", action="store_true",
                        help="also run the report stages (fusion, final); need saved LLM scores")
    parser.add_argument("--list", action="store_true", help="list the stages and exit")
    return parser.parse_args()


def stages_to_run(args):
    if args.only:
        return [s for s in STAGES if s[0] == args.only]

    start = STAGE_NAMES.index(args.start) if args.start else 0
    selected = STAGES[start:]
    if not args.llm:
        selected = [s for s in selected if s[0] != "llm"]
    if not args.report:
        selected = [s for s in selected if s[0] not in REPORT_STAGES]
    return selected


def run_stage(name, script, extra_args):
    print("\n" + "#" * 70)
    print(f"# STAGE: {name}  ({script})")
    print("#" * 70, flush=True)

    started = time.time()
    # sys.executable = the same Python that is running this file (e.g. the .venv one)
    result = subprocess.run([sys.executable, str(PROJECT_ROOT / script)] + extra_args,
                            cwd=PROJECT_ROOT)
    return result.returncode, time.time() - started


def main():
    args = parse_args()

    if args.list:
        for i, (name, script, what) in enumerate(STAGES, 1):
            print(f"{i}. {name:10s} {what}\n   {'':10s} ({script})")
        return 0

    selected = stages_to_run(args)
    print("Running stages: " + " -> ".join(name for name, _, _ in selected))

    timings = []
    for name, script, _ in selected:
        extra = ["--limit", str(args.llm_limit)] if name == "llm" else []
        code, seconds = run_stage(name, script, extra)
        timings.append((name, seconds))

        if code != 0:
            print(f"\n❌ Stage '{name}' failed (exit code {code}). Stopping here.")
            print(f"   Fix the problem, then resume with: python run_pipeline.py --from {name}")
            return code

    print("\n" + "=" * 70)
    print("✅ PIPELINE COMPLETE")
    print("=" * 70)
    for name, seconds in timings:
        print(f"   {name:10s} {seconds:6.1f}s")
    print("\nResults are in results/raw, results/processed and results/visualizations")
    return 0


if __name__ == "__main__":
    sys.exit(main())
