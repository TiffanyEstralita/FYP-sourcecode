#!/usr/bin/env python3
"""
Build the evaluation set (ground truth) from the collected CVE candidates.

Selection rule (fixed in advance, so the set is not hand-picked):
  1. always include the hand-verified CVEs in manual_cves.json, and the
     brief's CVEs that are valid on Linux 6.1.6 (ALWAYS_INCLUDE)
  2. add randomly chosen CVEs from the usable candidates (at least one
     changed function found in 6.1.6) until there are SET_SIZE CVEs
  3. randomly split the set: TUNING_SIZE CVEs for choosing settings
     (alpha, shortlist size, fusion weight), the rest for the final test

The random choices use a fixed seed, so re-running gives the same set.

Input:  validation/cve_data/candidate_cves_6.1.6.json  (collect_cves.py)
        validation/cve_data/manual_cves.json
Output: validation/cve_data/vulnerable_functions.json  (+ _summary.txt)
"""

import json
import random
import sys
from pathlib import Path

# Windows terminals use a non-UTF-8 encoding by default and crash on emoji output
sys.stdout.reconfigure(encoding="utf-8")

PROJECT_ROOT = Path(__file__).resolve().parents[2]

CVE_DATA = PROJECT_ROOT / "validation/cve_data"
CANDIDATES_FILE = CVE_DATA / "candidate_cves_6.1.6.json"
MANUAL_FILE = CVE_DATA / "manual_cves.json"
OUTPUT_FILE = CVE_DATA / "vulnerable_functions.json"

SET_SIZE = 20
TUNING_SIZE = 6
SEED = 2026
ALWAYS_INCLUDE = ["CVE-2024-53141"]   # from the project brief, valid on 6.1.6

sys.path.insert(0, str(PROJECT_ROOT / "analysis"))
from callgraph import FunctionIndex, load_functions


def entry(function, file, node, source):
    return {"name": node, "function": function, "file": file, "verified": True, "source": source}


def main():
    print("=" * 70)
    print(f"🎯 BUILD EVALUATION SET ({SET_SIZE} CVEs, seed {SEED})")
    print("=" * 70)

    with open(CANDIDATES_FILE, "r") as f:
        candidates = {c["cve_id"]: c for c in json.load(f)["candidates"]}
    with open(MANUAL_FILE, "r") as f:
        manual = json.load(f)
    functions = load_functions()
    index = FunctionIndex(functions)
    node_file = {index.node_id(fn["name"], file): (fn["name"], file)
                 for file, funcs in functions.items() for fn in funcs}

    chosen = {}

    # 1. hand-verified CVEs and the brief's CVEs
    for cve_id, data in manual["include"].items():
        chosen[cve_id] = {
            "cve_id": cve_id, "subject": data["subject"], "description": data["description"],
            "bug_type": data["bug_type"], "selected_by": "manual (hand-verified)",
            "vulnerable_functions": [entry(v["function"], v["file"], index.node_id(v["function"], v["file"]),
                                           data["source"]) for v in data["vulnerable_functions"]],
        }
    for cve_id in ALWAYS_INCLUDE:
        chosen[cve_id] = None   # filled from the candidates below

    # 2. random sample of the usable candidates
    usable = sorted(c for c, data in candidates.items()
                    if data["vulnerable_functions"] and c not in chosen
                    and c not in manual["exclude"])
    rng = random.Random(SEED)
    for cve_id in rng.sample(usable, SET_SIZE - len(chosen)):
        chosen[cve_id] = None

    for cve_id in chosen:
        if chosen[cve_id] is not None:
            continue
        c = candidates[cve_id]
        chosen[cve_id] = {
            "cve_id": cve_id, "subject": c["subject"], "description": c["subject"],
            "bug_type": c["bug_type"],
            "selected_by": "project brief" if cve_id in ALWAYS_INCLUDE else f"random sample (seed {SEED})",
            "fix_commit": c["fix_commit"], "fix_date": c["fix_date"], "mapping_status": c["status"],
            "vulnerable_functions": [entry(*node_file[node], node, c["source"])
                                     for node in c["vulnerable_functions"]],
        }

    # 3. tuning / test split
    ids = sorted(chosen)
    tuning = set(random.Random(SEED + 1).sample(ids, TUNING_SIZE))
    for cve_id in ids:
        chosen[cve_id]["split"] = "tuning" if cve_id in tuning else "test"

    result = {cve_id: chosen[cve_id] for cve_id in ids}
    with open(OUTPUT_FILE, "w") as f:
        json.dump(result, f, indent=2)

    lines = [f"EVALUATION SET: {len(result)} netfilter CVEs present in Linux 6.1.6",
             f"Selection: hand-verified + brief CVEs, then random sample (seed {SEED}) "
             f"from {len(usable)} usable candidates",
             f"Split: {TUNING_SIZE} tuning / {len(result) - TUNING_SIZE} test (seed {SEED + 1})",
             f"Excluded: " + "; ".join(f"{k} ({v['reason'][:60]}...)" for k, v in manual["exclude"].items()),
             ""]
    for cve_id, c in result.items():
        names = ", ".join(v["name"] for v in c["vulnerable_functions"])
        lines.append(f"{cve_id:16s} {c['split']:7s} {c['bug_type']:15s} {c['subject'][:70]}")
        lines.append(f"{'':16s} functions: {names}")
    with open(OUTPUT_FILE.with_name("vulnerable_functions_summary.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print("\n".join(lines))
    print(f"\n💾 Saved: {OUTPUT_FILE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
