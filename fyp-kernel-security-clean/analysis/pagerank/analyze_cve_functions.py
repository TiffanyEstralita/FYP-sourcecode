#!/usr/bin/env python3
"""
SCRIPT #3b: CVE-Specific Function-Level PageRank Analysis
Purpose: For each CVE, report where its actual known vulnerable function(s)
         (not the whole file) rank within the full-codebase PageRank results.
Ground truth: validation/cve_data/vulnerable_functions.json
"""

import json
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[2]

GROUND_TRUTH_FILE = PROJECT_ROOT / "validation/cve_data/vulnerable_functions.json"
FUNCTIONS_FILE = PROJECT_ROOT / "results/raw/functions_v2.json"
PAGERANK_FILE = PROJECT_ROOT / "results/processed/pagerank_scores.json"
OUTPUT_PATH = PROJECT_ROOT / "results/processed"


def load_json(path):
    with open(path, 'r') as f:
        return json.load(f)


def find_function_location(functions, name):
    """Find (file, line) for a function name anywhere in the extracted codebase"""
    for filename, funcs in functions.items():
        for func in funcs:
            if func['name'] == name:
                return filename, func['line']
    return None, None


def analyze_function(name, vf, functions, pagerank, all_sorted, total):
    entry = {
        'function': name,
        'expected_file': vf['file'],
        'verified': vf.get('verified', False),
        'source': vf.get('source'),
    }

    if not vf.get('verified', False):
        entry['status'] = 'SKIPPED - not verified against a primary source. Confirm before including in analysis.'
        return entry

    actual_file, line = find_function_location(functions, name)
    if actual_file is None:
        entry['status'] = 'NOT FOUND in results/raw/functions_v2.json - extraction may not have captured this function'
        return entry

    entry['file'] = actual_file
    entry['line'] = line
    if actual_file != vf['file']:
        entry['file_mismatch_warning'] = (
            f"Ground truth expected '{vf['file']}' but function was found in '{actual_file}'"
        )

    if name not in pagerank:
        entry['status'] = 'Function found in source but has no PageRank score (isolated node / no call edges)'
        return entry

    score = pagerank[name]
    rank = next(i for i, (f, s) in enumerate(all_sorted, 1) if f == name)
    percentile_top = (rank / total) * 100

    entry.update({
        'pagerank_score': score,
        'overall_rank': rank,
        'total_functions': total,
        'percentile_top': percentile_top,
        'in_top_1_pct': rank <= total * 0.01,
        'in_top_5_pct': rank <= total * 0.05,
        'in_top_10_pct': rank <= total * 0.10,
        'in_top_20_pct': rank <= total * 0.20,
        'status': 'OK',
    })
    return entry


def print_entry(entry):
    if entry['status'] == 'OK':
        print(f"   {entry['function']:35s} rank #{entry['overall_rank']:<5d} of {entry['total_functions']}  "
              f"(top {entry['percentile_top']:.2f}%)  PR={entry['pagerank_score']:.6f}")
    else:
        print(f"   {entry['function']:35s} -> {entry['status']}")


def write_summary(f, cve_id, cve_data, entries):
    f.write(f"{cve_id}\n" + "-" * 70 + "\n")
    f.write(f"{cve_data.get('description', '')}\n\n")
    for entry in entries:
        f.write(f"Function:   {entry['function']}\n")
        f.write(f"Verified:   {entry['verified']}")
        if entry.get('source'):
            f.write(f"  (source: {entry['source']})")
        f.write("\n")

        if entry['status'] != 'OK':
            f.write(f"Status:     {entry['status']}\n\n")
            continue

        f.write(f"File:       {entry['file']}, line {entry['line']}\n")
        if 'file_mismatch_warning' in entry:
            f.write(f"WARNING:    {entry['file_mismatch_warning']}\n")
        f.write(f"PageRank:   {entry['pagerank_score']:.6f}\n")
        f.write(f"Rank:       #{entry['overall_rank']} of {entry['total_functions']}\n")
        f.write(f"Percentile: top {entry['percentile_top']:.2f}%\n")
        f.write(
            f"Top 1%: {entry['in_top_1_pct']}   Top 5%: {entry['in_top_5_pct']}   "
            f"Top 10%: {entry['in_top_10_pct']}   Top 20%: {entry['in_top_20_pct']}\n\n"
        )


def main():
    print("=" * 70)
    print("CVE-SPECIFIC FUNCTION-LEVEL PAGERANK ANALYSIS")
    print("(ground truth: exact vulnerable function per CVE, not whole file)")
    print("=" * 70)

    for required in (GROUND_TRUTH_FILE, FUNCTIONS_FILE, PAGERANK_FILE):
        if not required.exists():
            print(f"Missing required input: {required}")
            return 1

    ground_truth = load_json(GROUND_TRUTH_FILE)
    functions = load_json(FUNCTIONS_FILE)
    pagerank = load_json(PAGERANK_FILE)

    all_sorted = sorted(pagerank.items(), key=lambda x: x[1], reverse=True)
    total = len(all_sorted)

    all_results = {}
    for cve_id, cve_data in ground_truth.items():
        print(f"\n{cve_id}")
        entries = [
            analyze_function(vf['name'], vf, functions, pagerank, all_sorted, total)
            for vf in cve_data['vulnerable_functions']
        ]
        all_results[cve_id] = {
            'description': cve_data.get('description', ''),
            'functions': entries,
        }
        for entry in entries:
            print_entry(entry)

    OUTPUT_PATH.mkdir(parents=True, exist_ok=True)

    out_json = OUTPUT_PATH / "cve_function_analysis.json"
    with open(out_json, 'w') as f:
        json.dump(all_results, f, indent=2)
    print(f"\n💾 Saved: {out_json}")

    out_txt = OUTPUT_PATH / "cve_function_summary.txt"
    with open(out_txt, 'w') as f:
        f.write("=" * 70 + "\n")
        f.write("CVE-SPECIFIC FUNCTION-LEVEL PAGERANK ANALYSIS\n")
        f.write("Ground truth: exact vulnerable function(s) per CVE, not whole file\n")
        f.write("=" * 70 + "\n\n")
        for cve_id, data in all_results.items():
            write_summary(f, cve_id, data, data['functions'])
    print(f"💾 Saved: {out_txt}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
