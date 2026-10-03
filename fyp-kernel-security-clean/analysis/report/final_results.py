#!/usr/bin/env python3
"""
SCRIPT #7: Final results for the report (Phase 6)

Reads only saved results (no LLM calls) and produces:
  - the final ablation table at a fixed LLM budget, with a RANDOM baseline
    (expected result of checking functions in a random order)
  - per-CVE ranks in every setup, with bug type, attack path and whether
    the LLM could have seen the fix during training
  - breakdowns by attack path, bug type and LLM-memorisation risk
  - uncertainty: bootstrap 95% confidence intervals over the test CVEs for
    "with LLM" minus "without LLM", and how many CVEs improved / got worse
  - results/RESULTS.md, a plain-language summary generated from the numbers

Setups (all with the same shortlist size K, i.e. the same LLM time):
  random                      functions in random order (expected value)
  baseline                    standard PageRank
  A                           personalized PageRank
  B                           standard PageRank shortlist + LLM rerank
  full                        personalized PageRank shortlist + LLM rerank
  hybrid                      alternate personalized/standard + LLM rerank (extra)
  LLM-only is not reported: it needs every function scored (~18 h), which
  this project chose not to run for efficiency reasons.

Output: results/processed/final_results.json, final_per_cve.csv,
        results/visualizations/11_final_comparison.png, results/RESULTS.md
"""

import csv
import json
import random
import sys
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np

# Windows terminals use a non-UTF-8 encoding by default and crash on emoji output
sys.stdout.reconfigure(encoding="utf-8")

PROJECT_ROOT = Path(__file__).resolve().parents[2]

GROUND_TRUTH_FILE = PROJECT_ROOT / "validation/cve_data/vulnerable_functions.json"
PROCESSED = PROJECT_ROOT / "results/processed"
CHART_PATH = PROJECT_ROOT / "results/visualizations"
RESULTS_MD = PROJECT_ROOT / "results/RESULTS.md"

LLM_VERSION = "v3"
# qwen3-coder:30b was released at the end of July 2025; a fix written after
# this date cannot be in its training data.
MODEL_RELEASE = datetime(2025, 8, 1, tzinfo=timezone.utc)
RANDOM_TRIALS = 2000
BOOTSTRAP_SAMPLES = 10000
SEED = 2026

sys.path.insert(0, str(PROJECT_ROOT / "analysis"))
sys.path.insert(0, str(PROJECT_ROOT / "analysis/fusion"))
from callgraph import load_call_graph
from fuse_scores import (SECONDS_PER_FUNCTION, choose_weight, complete_shortlist_size,
                         fused_scores, interleave, ordered)
from metrics import evaluate, load_ground_truth

KS = (10, 20, 50, 100)


def load_json(path):
    with open(path, "r") as f:
        return json.load(f)


def random_baseline(cves, nodes, k, rng):
    """Average metrics over many random orderings of all functions"""
    totals = {"mrr": 0.0, **{f"R@{x}": 0.0 for x in KS + (k,)}}
    ranks_sum = {c: 0.0 for c in cves}
    for _ in range(RANDOM_TRIALS):
        shuffled = nodes[:]
        rng.shuffle(shuffled)
        scores = {n: len(shuffled) - i for i, n in enumerate(shuffled)}
        ev = evaluate(scores, cves, ks=KS + (k,))
        totals["mrr"] += ev["mrr"]
        for x in KS + (k,):
            totals[f"R@{x}"] += ev["recall"][x]
        for c, r in ev["ranks"].items():
            ranks_sum[c] += r
    return ({key: v / RANDOM_TRIALS for key, v in totals.items()},
            {c: v / RANDOM_TRIALS for c, v in ranks_sum.items()})


def bootstrap_difference(rr_with, rr_without, rng):
    """95% CI of mean(reciprocal rank with) - mean(without), resampling CVEs"""
    diffs = [a - b for a, b in zip(rr_with, rr_without)]
    means = []
    for _ in range(BOOTSTRAP_SAMPLES):
        sample = [diffs[rng.randrange(len(diffs))] for _ in diffs]
        means.append(sum(sample) / len(sample))
    means.sort()
    return (sum(diffs) / len(diffs), means[int(0.025 * len(means))], means[int(0.975 * len(means))])


def cve_attack_paths(ground_truth):
    """packet / config / both / none: which seeds can reach any vulnerable function"""
    reach = load_json(PROCESSED / "reachability.json")["results"]
    paths = {}
    for cve_id in ground_truth:
        found = set()
        for key, entry in reach.items():
            if key.split(":", 1)[0] == cve_id:
                found |= {p for p, path in entry["with_indirect"].items() if path}
        paths[cve_id] = ("both" if len(found) == 2 else found.pop() if found else "none")
    return paths


def main():
    print("=" * 70)
    print("📊 FINAL RESULTS (Phase 6)")
    print("=" * 70)
    rng = random.Random(SEED)

    ground_truth = load_json(GROUND_TRUTH_FILE)
    cves, splits = load_ground_truth(GROUND_TRUTH_FILE)
    llm = {n: a["risk"] for n, a in load_json(PROCESSED / f"llm_scores_{LLM_VERSION}.json").items()
           if "risk" in a}
    orders = {"standard": ordered(load_json(PROCESSED / "pagerank_scores.json")),
              "personalized": ordered(load_json(PROCESSED / "ppr_scores.json"))}
    orders["hybrid"] = interleave(orders["personalized"], orders["standard"])
    k = min(complete_shortlist_size(o, llm) for o in orders.values())
    weights = {name: choose_weight(order, llm, k, cves, splits)[0] for name, order in orders.items()}
    print(f"   shortlist K={k} for every setup (LLM time {k * SECONDS_PER_FUNCTION / 3600:.1f} h); "
          f"w chosen on tuning CVEs: {weights}")

    setups = {
        "baseline: standard PageRank": fused_scores(orders["standard"], llm, k, 1.0),
        "A: personalized PageRank": fused_scores(orders["personalized"], llm, k, 1.0),
        "B: standard + LLM": fused_scores(orders["standard"], llm, k, weights["standard"]),
        "full: personalized + LLM": fused_scores(orders["personalized"], llm, k, weights["personalized"]),
        "hybrid + LLM (extra)": fused_scores(orders["hybrid"], llm, k, weights["hybrid"]),
    }

    # ---- metrics per split, plus the random baseline ----
    nodes = sorted(load_call_graph())
    table, random_ranks = {}, {}
    for split in ("test", "tuning", "all"):
        subset = {c: f for c, f in cves.items() if split == "all" or splits[c] == split}
        rand, rand_ranks = random_baseline(subset, nodes, k, rng)
        random_ranks.update(rand_ranks)
        table[split] = {"random (expected)": rand}
        for name, scores in setups.items():
            ev = evaluate(scores, subset, ks=KS + (k,))
            table[split][name] = {"mrr": ev["mrr"], **{f"R@{x}": ev["recall"][x] for x in KS + (k,)},
                                  "median_rank": ev["median_rank"]}
    ranks = {name: evaluate(scores, cves, ks=KS)["ranks"] for name, scores in setups.items()}

    # ---- per-CVE facts ----
    paths = cve_attack_paths(ground_truth)
    per_cve = []
    for c in cves:
        g = ground_truth[c]
        date = parsedate_to_datetime(g["fix_date"]) if g.get("fix_date") else datetime(2023, 1, 13, tzinfo=timezone.utc)
        per_cve.append({
            "cve": c, "split": splits[c], "bug_type": g["bug_type"], "attack_path": paths[c],
            "fix_written": date.strftime("%Y-%m-%d"),
            "llm_could_have_seen_fix": date < MODEL_RELEASE,
            "functions": len(cves[c]),
            "random_expected_rank": round(random_ranks[c]),
            **{name: ranks[name][c] for name in setups},
        })

    # ---- uncertainty: with vs without LLM on the test CVEs ----
    test = [r for r in per_cve if r["split"] == "test"]
    comparisons = {}
    for with_llm, without in (("full: personalized + LLM", "A: personalized PageRank"),
                              ("B: standard + LLM", "baseline: standard PageRank"),
                              ("full: personalized + LLM", "baseline: standard PageRank")):
        rw = [1 / r[with_llm] for r in test]
        ro = [1 / r[without] for r in test]
        mean, lo, hi = bootstrap_difference(rw, ro, rng)
        comparisons[f"{with_llm}  vs  {without}"] = {
            "mrr_difference": mean, "ci95": [lo, hi],
            "improved": sum(1 for r in test if r[with_llm] < r[without]),
            "worse": sum(1 for r in test if r[with_llm] > r[without]),
            "same": sum(1 for r in test if r[with_llm] == r[without]),
        }

    # ---- breakdowns (all 20 CVEs; median rank per group) ----
    def group_medians(key):
        out = {}
        for value in sorted({r[key] for r in per_cve}, key=str):
            rows = [r for r in per_cve if r[key] == value]
            out[str(value)] = {"cves": len(rows), **{name: float(np.median([r[name] for r in rows]))
                                                     for name in setups}}
        return out
    breakdowns = {"attack_path": group_medians("attack_path"),
                  "bug_type": group_medians("bug_type"),
                  "llm_could_have_seen_fix": group_medians("llm_could_have_seen_fix")}

    # ---- save data ----
    PROCESSED.mkdir(parents=True, exist_ok=True)
    with open(PROCESSED / "final_results.json", "w") as f:
        json.dump({"k": k, "llm_version": LLM_VERSION, "weights": weights,
                   "llm_hours_for_shortlist": k * SECONDS_PER_FUNCTION / 3600,
                   "llm_hours_all_functions": len(nodes) * SECONDS_PER_FUNCTION / 3600,
                   "table": table, "comparisons": comparisons, "breakdowns": breakdowns,
                   "per_cve": per_cve}, f, indent=2, default=float)
    with open(PROCESSED / "final_per_cve.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(per_cve[0]))
        writer.writeheader()
        writer.writerows(per_cve)

    # ---- chart: test-set metrics per setup ----
    names = list(table["test"])
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    axes[0].bar(range(len(names)), [table["test"][n]["mrr"] for n in names],
                color=["grey", "tab:orange", "tab:blue", "gold", "tab:green", "tab:purple"])
    axes[0].set_ylabel("MRR on the 14 test CVEs (higher = better)")
    width = 0.2
    for i, x in enumerate((20, 50, 100, k)):
        axes[1].bar(np.arange(len(names)) + i * width, [table["test"][n][f"R@{x}"] for n in names],
                    width, label=f"in top {x}")
    axes[1].set_ylabel("Share of test CVEs found")
    axes[1].legend(fontsize=8)
    for ax in axes:
        ax.set_xticks(np.arange(len(names)) + (0.3 if ax is axes[1] else 0))
        ax.set_xticklabels([n.split(":")[0].replace(" (expected)", "\n(expected)") for n in names],
                           fontsize=8)
    fig.suptitle(f"Final comparison on the test CVEs (same LLM budget: shortlist K={k}, "
                 f"{k * SECONDS_PER_FUNCTION / 3600:.1f} h)", fontweight="bold")
    plt.tight_layout()
    CHART_PATH.mkdir(parents=True, exist_ok=True)
    plt.savefig(CHART_PATH / "11_final_comparison.png", dpi=200, bbox_inches="tight")
    plt.close()

    write_results_md(k, weights, table, comparisons, breakdowns, per_cve, setups, len(nodes))
    print(RESULTS_MD.read_text(encoding="utf-8"))
    print(f"💾 Saved: {PROCESSED / 'final_results.json'}, final_per_cve.csv, chart 11, {RESULTS_MD}")
    return 0


def write_results_md(k, weights, table, comparisons, breakdowns, per_cve, setups, n_functions):
    hours_k = k * SECONDS_PER_FUNCTION / 3600
    hours_all = n_functions * SECONDS_PER_FUNCTION / 3600
    md = []
    md.append("# Results summary\n")
    md.append(f"_Generated by `analysis/report/final_results.py` on {datetime.now():%Y-%m-%d %H:%M} "
              "from saved results; rerun it to refresh the numbers._\n")
    md.append("## Set-up\n")
    md.append(f"- Kernel: Linux 6.1.6, `net/netfilter` ({n_functions} functions in the call graph).")
    md.append(f"- Ground truth: {len(per_cve)} netfilter CVEs present in 6.1.6 "
              f"({sum(r['split'] == 'tuning' for r in per_cve)} tuning / "
              f"{sum(r['split'] == 'test' for r in per_cve)} test); a CVE's rank is the rank of its "
              "best-ranked vulnerable function.")
    md.append(f"- LLM: `qwen3-coder:30b` (local), prompt `{LLM_VERSION}` chosen on the tuning CVEs.")
    md.append(f"- Every setup uses the same shortlist size **K = {k}** = **{hours_k:.1f} h** of LLM time "
              f"(scoring all {n_functions} functions would take ~{hours_all:.0f} h, "
              f"{hours_all / hours_k:.0f}x more).")
    md.append(f"- Fusion weight w chosen on the tuning CVEs: {weights}.\n")

    md.append("## Main result (14 test CVEs)\n")
    md.append(f"| Setup | top 10 | top 20 | top 50 | top 100 | in shortlist (top {k}) | MRR |")
    md.append("|---|---|---|---|---|---|---|")
    for name, m in table["test"].items():
        md.append(f"| {name} | {m['R@10']:.2f} | {m['R@20']:.2f} | {m['R@50']:.2f} | {m['R@100']:.2f} | "
                  f"{m[f'R@{k}']:.2f} | {m['mrr']:.4f} |")
    md.append("\nValues are the share of CVEs found within the top N. The random row is the "
              f"average of {RANDOM_TRIALS} random orderings.\n")
    md.append("Tuning and all-CVE tables are in `results/processed/final_results.json`.\n")

    md.append("## Does adding the LLM help? (test CVEs, with uncertainty)\n")
    md.append("| Comparison | MRR difference | 95% interval (bootstrap) | CVEs better / worse / same |")
    md.append("|---|---|---|---|")
    for name, c in comparisons.items():
        md.append(f"| {name} | {c['mrr_difference']:+.4f} | [{c['ci95'][0]:+.4f}, {c['ci95'][1]:+.4f}] | "
                  f"{c['improved']} / {c['worse']} / {c['same']} |")
    md.append("\nIf the interval includes 0, the difference is not statistically reliable with this "
              "many CVEs.\n")

    md.append("## Rank of every CVE\n")
    cols = ["random (expected)"] + list(setups)
    md.append("| CVE | split | bug type | attack path | LLM could have seen fix | " +
              " | ".join(c.split(":")[0] for c in cols) + " |")
    md.append("|" + "---|" * (5 + len(cols)))
    for r in per_cve:
        md.append(f"| {r['cve']} | {r['split']} | {r['bug_type']} | {r['attack_path']} | "
                  f"{'yes' if r['llm_could_have_seen_fix'] else 'no'} | {r['random_expected_rank']} | " +
                  " | ".join(f"{r[c]:.0f}" for c in setups) + " |")
    md.append("")

    md.append("## Breakdowns (median rank, all 20 CVEs; lower = better)\n")
    for key, groups in breakdowns.items():
        md.append(f"**By {key.replace('_', ' ')}**\n")
        md.append("| group | CVEs | " + " | ".join(n.split(":")[0] for n in setups) + " |")
        md.append("|" + "---|" * (2 + len(setups)))
        for g, vals in groups.items():
            md.append(f"| {g} | {vals['cves']} | " + " | ".join(f"{vals[n]:.0f}" for n in setups) + " |")
        md.append("")

    md.append("## Threats to validity (see the numbers above)\n")
    seen = sum(r["llm_could_have_seen_fix"] for r in per_cve)
    md.append(f"- **LLM memorisation:** {seen} of {len(per_cve)} fixes were written before the model's "
              f"release (end of July 2025) and could be in its training data; {len(per_cve) - seen} were "
              "written after it and cannot be. See the breakdown above.")
    md.append("- **Call graph incompleteness:** function-pointer calls are matched by field name only "
              "(over-approximation); calls hidden in macros and callbacks handed to core-kernel APIs are "
              "not captured; about 2 functions with real callers remain unconnected.")
    md.append(f"- **Small sample:** {len(per_cve)} CVEs ({sum(r['split'] == 'test' for r in per_cve)} test); "
              "per-CVE results are reported and confidence intervals are wide.")
    md.append("- **Ground truth = functions changed by the fix:** some fixes change helper or "
              "init/exit functions rather than the code where the bug is triggered.")
    md.append("- **Tuning set size:** settings (prompt, w) were chosen on only 6 CVEs, of which 1-2 fall "
              "inside the shortlist, so the choices are weakly supported.")
    RESULTS_MD.write_text("\n".join(md) + "\n", encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
