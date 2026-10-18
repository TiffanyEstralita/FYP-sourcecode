#!/usr/bin/env python3
"""
Phase 5: LLM check - can the LLM tell buggy functions from ordinary ones?

Plain idea: mix the known buggy functions with N randomly chosen ordinary
ones, shuffle them (so the order gives nothing away), let the LLM score
every one, and see whether the buggy ones end up near the top.

  positives  the ground-truth functions of the chosen CVEs
             (configs/llm.yaml llm_check.split; default: tuning CVEs only,
             so the test CVEs stay unseen until the final evaluation)
  negatives  N random functions (fixed seed) that are not seeds and not
             changed by ANY collected CVE fix (those might be buggy too)

Reported:
  median rank of the buggy functions among everything scored (1 = top)
  AUC = chance a buggy function scores higher than an ordinary one
        (ties count half; 0.5 = coin flip, 1.0 = perfect)
  also per CVE (its best-scored function), and the JSON failure count

Resumable and time-capped (answers cached; see configs/llm.yaml).

Usage:
    python analysis/llm/llm_check.py --prompt v3
    python analysis/llm/llm_check.py --prompt vulnsc
    python analysis/llm/llm_check.py --prompt vulnsc --limit 3    # quick test
Output: results/processed/llm_check_<prompt>.json (+ _summary.txt)
"""

import argparse
import json
import random
import statistics
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "analysis"))
sys.path.insert(0, str(PROJECT_ROOT / "analysis/llm"))
from callgraph import load_call_graph
from config import PATHS, kernel_info, load_yaml
from jobs import PROMPTS, Scorer, run_job
from llm_client import MODEL, ollama_available

SETTINGS = load_yaml("llm.yaml")["llm_check"]


def auc(pos, neg):
    if not pos or not neg:
        return None
    wins = sum((p > n) + 0.5 * (p == n) for p in pos for n in neg)
    return wins / (len(pos) * len(neg))


def average_ranks(scores):
    """{node: rank} with 1 = highest score, ties share the average rank"""
    ordered = sorted(scores.values(), reverse=True)
    first = {}
    for i, s in enumerate(ordered, 1):
        first.setdefault(s, [i, i])[1] = i
    return {n: (first[s][0] + first[s][1]) / 2 for n, s in scores.items()}


def main():
    parser = argparse.ArgumentParser(description="LLM check: buggy vs random functions")
    parser.add_argument("--prompt", choices=PROMPTS, required=True)
    parser.add_argument("--split", choices=["tuning", "test", "all"], default=SETTINGS["split"])
    parser.add_argument("--max-hours", type=float, help="override max_hours_per_run")
    parser.add_argument("--limit", type=int, help="only score the first N items (quick test)")
    args = parser.parse_args()

    print("=" * 70)
    print(f"🧪 LLM CHECK ({args.prompt}): buggy functions of the {args.split} CVEs + "
          f"{SETTINGS['random_functions']} random functions")
    print("=" * 70)
    if not ollama_available():
        print(f"❌ Ollama is not running or model {MODEL} is missing. Start Ollama and retry.")
        return 1

    with open(PATHS.validation / "vulnerable_functions.json") as f:
        cves = json.load(f)["cves"]
    with open(PATHS.validation / "candidates.json") as f:
        maybe_buggy = {n for c in json.load(f)["candidates"] for n in c["functions"] + c["seed_functions_removed"]}
    with open(PATHS.processed / "seeds.json") as f:
        seeds = set(json.load(f)["seeds"])
    graph = load_call_graph()

    chosen = {c: d for c, d in cves.items() if args.split == "all" or d["split"] == args.split}
    positives = sorted({v["name"] for d in chosen.values() for v in d["vulnerable_functions"]})
    pool = sorted(n for n in graph if n not in maybe_buggy and n not in seeds)
    negatives = random.Random(SETTINGS["seed"]).sample(pool, SETTINGS["random_functions"])
    items = positives + negatives
    random.Random(SETTINGS["seed"] + 1).shuffle(items)
    if args.limit:
        items = items[:args.limit]
    print(f"   {len(chosen)} CVEs -> {len(positives)} buggy functions; {len(negatives)} random functions")

    out_file = PATHS.processed / f"llm_check_{args.prompt}.json"
    scorer = Scorer(graph, args.prompt)
    results, finished = run_job(items, scorer, out_file, f"llm check ({args.split})", args.max_hours)

    # ---- metrics on whatever has been scored ----
    scores = {n: r["risk"] for n, r in results.items() if "risk" in r}
    ranks = average_ranks(scores)
    pos_scored = [n for n in positives if n in scores]
    neg_scored = [n for n in negatives if n in scores]
    per_cve = {}
    for c, d in chosen.items():
        mine = [scores[v["name"]] for v in d["vulnerable_functions"] if v["name"] in scores]
        if mine:
            per_cve[c] = {"best_score": max(mine),
                          "auc": auc([max(mine)], [scores[n] for n in neg_scored]),
                          "best_rank": min(ranks[v["name"]] for v in d["vulnerable_functions"]
                                           if v["name"] in ranks)}
    summary = {
        "kernel": kernel_info(), "prompt": args.prompt, "model": MODEL, "split": args.split,
        "complete": finished and not args.limit,
        "scored": len(scores), "items": len(items), "failures": scorer.failure_counts(),
        "buggy_scored": len(pos_scored), "random_scored": len(neg_scored),
        "median_rank_buggy": statistics.median([ranks[n] for n in pos_scored]) if pos_scored else None,
        "median_rank_expected_if_random": (len(scores) + 1) / 2 if scores else None,
        "auc_function": auc([scores[n] for n in pos_scored], [scores[n] for n in neg_scored]),
        "auc_cve_mean": statistics.mean([v["auc"] for v in per_cve.values()]) if per_cve else None,
        "distinct_scores": len(set(scores.values())),
        "per_cve": per_cve,
        "buggy_function_ranks": {n: ranks[n] for n in pos_scored},
    }
    with open(out_file) as f:
        saved = json.load(f)
    with open(out_file, "w") as f:
        json.dump({**saved, "summary": summary}, f, indent=1)

    lines = [f"LLM CHECK - prompt {args.prompt}, model {MODEL}, {kernel_info()['tag']} "
             f"({kernel_info()['commit'][:12]})",
             f"status: {'complete' if summary['complete'] else 'PARTIAL (run again to continue)'}; "
             f"scored {len(scores)}/{len(items)} ({len(pos_scored)} buggy, {len(neg_scored)} random); "
             f"failures {summary['failures']}",
             f"median rank of buggy functions: {summary['median_rank_buggy']} "
             f"(random order would give ~{summary['median_rank_expected_if_random']})",
             f"AUC (functions): {summary['auc_function']}   AUC (per CVE, mean): {summary['auc_cve_mean']}",
             f"distinct score values: {summary['distinct_scores']}"]
    (out_file.with_name(f"llm_check_{args.prompt}_summary.txt")).write_text("\n".join(lines) + "\n",
                                                                            encoding="utf-8")
    print("\n" + "\n".join(lines))
    print(f"💾 Saved: {out_file}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
