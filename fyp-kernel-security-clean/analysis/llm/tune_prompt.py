#!/usr/bin/env python3
"""
Choose the LLM prompt version on the TUNING CVEs only (the "practice exam").

Practice pool:
  positives - the vulnerable functions of the tuning CVEs
  negatives - randomly chosen ordinary functions (fixed seed), excluding every
              function changed by ANY collected CVE fix (they may be buggy)
              Test CVEs are never used here.

Each prompt version in configs/prompts.yaml scores the whole pool; we then
measure how well its scores SEPARATE the buggy functions from ordinary ones:
  separation (CVE level)  - for each tuning CVE, the chance that its best-scored
                            vulnerable function scores higher than a random
                            ordinary function (ties count half), averaged over
                            CVEs. 0.5 = no better than a coin flip, 1.0 = perfect.
  separation (function)   - the same per vulnerable function
  distinct scores         - how many different score values were used (more = fewer ties)

Usage:
    python analysis/llm/tune_prompt.py                  # all versions
    python analysis/llm/tune_prompt.py --versions v1 v2

Output: results/processed/prompt_tuning.csv, prompt_tuning_details.json,
        prompt_tuning_summary.txt   (answers are cached in results/llm_cache/)
"""

import argparse
import csv
import json
import random
import sys
import time
from pathlib import Path

# Windows terminals use a non-UTF-8 encoding by default and crash on emoji output
sys.stdout.reconfigure(encoding="utf-8")

PROJECT_ROOT = Path(__file__).resolve().parents[2]

GROUND_TRUTH_FILE = PROJECT_ROOT / "validation/cve_data/vulnerable_functions.json"
CANDIDATES_FILE = PROJECT_ROOT / "validation/cve_data/candidate_cves_6.1.6.json"
OUTPUT_PATH = PROJECT_ROOT / "results/processed"

NEGATIVES = 60
SEED = 7

sys.path.insert(0, str(PROJECT_ROOT / "analysis"))
sys.path.insert(0, str(PROJECT_ROOT / "analysis/llm"))
from callgraph import load_call_graph
from llm_client import load_prompts, ollama_available, score_function, MODEL
from metrics import load_ground_truth


def separation(positive_scores, negative_scores):
    """Chance a positive scores higher than a negative (ties count half)"""
    if not positive_scores or not negative_scores:
        return None
    wins = sum((p > n) + 0.5 * (p == n) for p in positive_scores for n in negative_scores)
    return wins / (len(positive_scores) * len(negative_scores))


def practice_pool(graph):
    cves, splits = load_ground_truth(GROUND_TRUTH_FILE)
    tuning = {c: fns for c, fns in cves.items() if splits[c] == "tuning"}
    with open(CANDIDATES_FILE, "r") as f:
        known_buggy = {n for c in json.load(f)["candidates"] for n in c["vulnerable_functions"]}
    known_buggy |= {n for fns in cves.values() for n in fns}
    ordinary = sorted(n for n in graph if n not in known_buggy)
    negatives = random.Random(SEED).sample(ordinary, NEGATIVES)
    return tuning, negatives


def main():
    parser = argparse.ArgumentParser(description="Compare prompt versions on the tuning CVEs")
    parser.add_argument("--versions", nargs="*", help="prompt versions to run (default: all)")
    args = parser.parse_args()

    print("=" * 70)
    print("🧪 PROMPT TUNING (tuning CVEs only)")
    print("=" * 70)

    if not ollama_available():
        print(f"❌ Ollama is not running or model {MODEL} is missing. Start Ollama and retry.")
        return 1

    prompts = load_prompts()
    versions = args.versions or list(prompts["versions"])
    graph = load_call_graph()
    tuning, negatives = practice_pool(graph)
    positives = sorted({n for fns in tuning.values() for n in fns})
    pool = positives + negatives
    print(f"   practice pool: {len(positives)} vulnerable functions from {len(tuning)} tuning CVEs "
          f"+ {len(negatives)} ordinary functions")

    rows, details = [], {}
    for version in versions:
        print(f"\n▶ {version}: {prompts['versions'][version]['description']}")
        started = time.time()
        results = {}
        for i, node in enumerate(pool, 1):
            results[node] = score_function(graph, node, version, prompts)
            elapsed = time.time() - started
            if i % 10 == 0 or i == len(pool):
                print(f"   {i:3d}/{len(pool)}  elapsed {elapsed / 60:4.1f} min  "
                      f"(~{elapsed / i * (len(pool) - i) / 60:4.1f} min left)", flush=True)

        risk = {n: r["risk"] for n, r in results.items() if "risk" in r}
        errors = [n for n, r in results.items() if "error" in r]
        neg = [risk[n] for n in negatives if n in risk]
        pos = [risk[n] for n in positives if n in risk]
        cve_best = [max(risk[n] for n in fns if n in risk) for fns in tuning.values()
                    if any(n in risk for n in fns)]
        row = {
            "version": version,
            "separation_cve": round(separation(cve_best, neg), 3),
            "separation_function": round(separation(pos, neg), 3),
            "mean_risk_vulnerable": round(sum(pos) / len(pos), 3) if pos else None,
            "mean_risk_ordinary": round(sum(neg) / len(neg), 3) if neg else None,
            "distinct_scores": len({r for r in risk.values()}),
            "errors": len(errors),
            "minutes": round((time.time() - started) / 60, 1),
        }
        rows.append(row)
        details[version] = {
            "per_cve_best": {c: max((risk[n] for n in fns if n in risk), default=None)
                             for c, fns in tuning.items()},
            "scores": {n: {k: results[n].get(k) for k in ("risk_score", "pattern", "justification", "error")}
                       for n in pool},
        }
        print(f"   separation: CVE level {row['separation_cve']}, function level "
              f"{row['separation_function']}   mean risk vulnerable {row['mean_risk_vulnerable']} "
              f"vs ordinary {row['mean_risk_ordinary']}   distinct scores {row['distinct_scores']}   "
              f"errors {row['errors']}")

    OUTPUT_PATH.mkdir(parents=True, exist_ok=True)
    # keep results of versions run earlier (re-running a version replaces its row)
    csv_file = OUTPUT_PATH / "prompt_tuning.csv"
    previous = []
    if csv_file.exists():
        with open(csv_file, newline="") as f:
            previous = [r for r in csv.DictReader(f) if r["version"] not in versions]
    all_rows = sorted(previous + rows, key=lambda r: r["version"])
    with open(csv_file, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(all_rows)

    details_file = OUTPUT_PATH / "prompt_tuning_details.json"
    old = json.load(open(details_file)) if details_file.exists() else {}
    old.update(details)
    with open(details_file, "w") as f:
        json.dump({k: old[k] for k in sorted(old)}, f, indent=2)

    with open(OUTPUT_PATH / "prompt_tuning_summary.txt", "w") as f:
        f.write("PROMPT TUNING on the tuning CVEs only\n")
        f.write(f"model: {MODEL}; pool: {len(positives)} vulnerable functions "
                f"({len(tuning)} CVEs) + {len(negatives)} ordinary (seed {SEED})\n")
        f.write("separation: 0.5 = coin flip, 1.0 = every buggy function scores above every ordinary one\n\n")
        f.write(f"{'version':8s} {'sep_cve':>8s} {'sep_fn':>8s} {'risk_vuln':>10s} {'risk_ord':>9s} "
                f"{'distinct':>9s} {'errors':>7s} {'min':>6s}\n")
        for r in all_rows:
            f.write(f"{r['version']:8s} {float(r['separation_cve']):>8.3f} {float(r['separation_function']):>8.3f} "
                    f"{float(r['mean_risk_vulnerable']):>10.3f} {float(r['mean_risk_ordinary']):>9.3f} "
                    f"{int(r['distinct_scores']):>9d} {int(r['errors']):>7d} {float(r['minutes']):>6.1f}\n")
        f.write("\nVersion descriptions:\n")
        for v, data in prompts["versions"].items():
            f.write(f"   {v}: {data['description']}\n")
    print(f"\n💾 Saved: {csv_file} (+ _details.json, _summary.txt)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
