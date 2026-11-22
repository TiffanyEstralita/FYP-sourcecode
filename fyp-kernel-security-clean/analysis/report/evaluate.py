#!/usr/bin/env python3
"""
Phase 7: evaluation - how early does each method find the known bugs?

Reads only saved results (no LLM calls, about a minute) and compares:
  random                    functions in random order (exact expected value)
  standard PageRank
  personalized PageRank
  combined shortlist        5 signals + reciprocal rank fusion (Phase 4)
  combined + prompt v3      shortlist re-ordered with the old one-shot LLM score
  combined + VulnSC         shortlist re-ordered with the Phase 6 reranker
For the two LLM rows: final = w * shortlist score + (1 - w) * LLM score
(both 0..1) inside the top K; everything below K keeps the combined order.
w is chosen on the TUNING CVEs (best MRR; ties -> the w closest to 0.5)
and then used unchanged on the TEST CVEs.

A CVE's rank = rank of its best-ranked vulnerable function (a tester who
checks any one of them finds the bug). Seeds are not ranked (leakage rule).

Metrics: shortlist recall (in top K), top 10 / 20 / 50, MRR, median rank,
bootstrap 95% intervals (resampling CVEs), rank of every CVE, and the same
split by fixes committed before / after the model release (July 2025).

Rows whose LLM scores are missing or incomplete are marked; run
analysis/llm/score_shortlist.py first (see the run guide in README.md).

Output: results/RESULTS.md, results/processed/evaluation.json, evaluation_per_cve.csv,
        results/visualizations/evaluation.png
"""

import csv
import json
import random
import statistics
import sys
from datetime import datetime
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

sys.stdout.reconfigure(encoding="utf-8")

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "analysis"))
from config import PATHS, kernel_info, load_yaml, model_release_date
from metrics import evaluate, load_ground_truth

LLM = load_yaml("llm.yaml")
K = load_yaml("shortlist.yaml")["k"]
TOPS = (10, 20, 50)
BOOTSTRAP = 10000
SEED = 2026
GROUND_TRUTH_FILE = PATHS.validation / "vulnerable_functions.json"
RANKINGS = PATHS.processed / "rankings"
RESULTS_MD = PATHS.results / "RESULTS.md"
LEGACY_MD = "results/legacy_6.1.6/RESULTS.md"

ROWS = ["random (expected)", "standard PageRank", "personalized PageRank", "combined shortlist",
        "combined + prompt v3", "combined + VulnSC"]


def load_json(path):
    with open(path) as f:
        return json.load(f)


def ordered(scores):
    return sorted(scores, key=lambda n: (-scores[n], n))


def as_scores(order):
    """ranked list -> {node: score}, first = highest"""
    return {n: len(order) - i for i, n in enumerate(order)}


def llm_scores(prompt, shortlist):
    """({node: risk 0..1}, note) for the top-K shortlist; None if not run"""
    path = PATHS.processed / f"llm_scores_shortlist_{prompt}.json"
    if not path.exists():
        return None, "not run yet"
    results = load_json(path)["results"]
    done = 0
    for n in shortlist:
        if n not in results:
            break
        done += 1
    if done == 0:
        return None, "not run yet"
    risks = {n: results[n].get("risk", 0.0) for n in shortlist[:done]}   # failed answer -> 0
    failed = sum("error" in results[n] for n in shortlist[:done])
    note = "" if done == len(shortlist) else f"PARTIAL: only the top {done} of {len(shortlist)} scored"
    if failed:
        note = (note + "; " if note else "") + f"{failed} failed answers counted as 0"
    return risks, note


def fused_order(combined_order, combined_scores, risks, w):
    """Re-order the top K (the part with LLM scores) by w*shortlist + (1-w)*LLM"""
    top = [n for n in combined_order[:K] if n in risks]
    values = [combined_scores[n] for n in top]
    lo, hi = min(values), max(values)
    norm = {n: (combined_scores[n] - lo) / (hi - lo) if hi > lo else 1.0 for n in top}
    position = {n: i for i, n in enumerate(combined_order)}
    rerank = sorted(top, key=lambda n: (-(w * norm[n] + (1 - w) * risks[n]), position[n]))
    rest = [n for n in combined_order if n not in set(top)]
    return rerank + rest


def choose_w(combined_order, combined_scores, risks, tuning_cves):
    best = None
    for w in LLM["fusion_weights"]:
        mrr = evaluate(as_scores(fused_order(combined_order, combined_scores, risks, w)), tuning_cves)["mrr"]
        key = (mrr, -abs(w - 0.5))
        if best is None or key > best[0]:
            best = (key, w)
    return best[1]


def metrics_for(ranks, n_cves):
    hits = [r for r in ranks.values() if r is not None]
    count = max(1, n_cves)
    return {"shortlist_recall": sum(r <= K for r in hits) / count,
            **{f"top{t}": sum(r <= t for r in hits) / count for t in TOPS},
            "mrr": sum(1 / r for r in hits) / count,
            "median_rank": statistics.median(hits) if hits else None}


def bootstrap_ci(values, rng):
    """95% interval of the mean of `values` (resampling CVEs)"""
    if not values:
        return None
    means = sorted(statistics.fmean(rng.choices(values, k=len(values))) for _ in range(BOOTSTRAP))
    return [means[int(0.025 * BOOTSTRAP)], means[int(0.975 * BOOTSTRAP)]]


def random_expectation(n, m):
    """
    Exact expected values when n functions are put in a random order and a
    CVE has m vulnerable functions among them (its rank = the first one found):
    returns (expected rank, expected 1/rank, {t: chance found within top t}).
    P(first found after position r) = C(n-m, r) / C(n, r).
    """
    beyond = [1.0]                       # beyond[r] = P(rank > r)
    for r in range(1, n + 1):
        beyond.append(beyond[-1] * max(0, n - m - r + 1) / (n - r + 1))
    expected_rank = sum(beyond[:n])      # E[rank] = sum_r P(rank > r)
    expected_rr = sum((beyond[r - 1] - beyond[r]) / r for r in range(1, n + 1))
    found = {t: 1 - beyond[min(t, n)] for t in TOPS + (K,)}
    return expected_rank, expected_rr, found


def random_ranks(cves, n):
    """({cve: expected rank}, metrics) for a random order of n functions"""
    ranks, rr, found = {}, [], []
    for c, functions in cves.items():
        er, err, f = random_expectation(n, len(functions))
        ranks[c], rr, found = er, rr + [err], found + [f]
    count = max(1, len(cves))
    m = {"shortlist_recall": sum(f[K] for f in found) / count,
         **{f"top{t}": sum(f[t] for f in found) / count for t in TOPS},
         "mrr": sum(rr) / count,
         "median_rank": statistics.median(ranks.values()) if ranks else None}
    return ranks, m


def main():
    print("=" * 70)
    print("📊 EVALUATION (Phase 7)")
    print("=" * 70)
    rng = random.Random(SEED)
    data = load_json(GROUND_TRUTH_FILE)["cves"]
    cves, splits = load_ground_truth(GROUND_TRUTH_FILE)
    after = {c: data[c]["after_model_release"] for c in cves}
    tuning = {c: f for c, f in cves.items() if splits[c] == "tuning"}

    rankings = {name: load_json(RANKINGS / f"{name}.json")["scores"]
                for name in ("standard_pagerank", "personalized_pagerank", "combined")}
    nodes = sorted(rankings["combined"])
    combined_order = ordered(rankings["combined"])
    shortlist = combined_order[:K]

    setups, notes, weights = {}, {}, {}
    setups["standard PageRank"] = rankings["standard_pagerank"]
    setups["personalized PageRank"] = rankings["personalized_pagerank"]
    setups["combined shortlist"] = rankings["combined"]
    for row, prompt in (("combined + prompt v3", "v3"), ("combined + VulnSC", "vulnsc")):
        risks, note = llm_scores(prompt, shortlist)
        notes[row] = note
        if risks is None:
            continue
        w = choose_w(combined_order, rankings["combined"], risks, tuning)
        weights[row] = w
        setups[row] = as_scores(fused_order(combined_order, rankings["combined"], risks, w))
        print(f"   {row}: w = {w} (chosen on {len(tuning)} tuning CVEs) {note}")

    # ---- ranks of every CVE in every setup ----
    rand_ranks, _ = random_ranks(cves, len(nodes))
    ranks = {"random (expected)": rand_ranks}
    for name, scores in setups.items():
        ranks[name] = evaluate(scores, cves)["ranks"]

    groups = {
        "test": [c for c in cves if splits[c] == "test"],
        "tuning": [c for c in cves if splits[c] == "tuning"],
        "all": list(cves),
        "test, fix after model release": [c for c in cves if splits[c] == "test" and after[c]],
        "test, fix before model release": [c for c in cves if splits[c] == "test" and not after[c]],
        "all, fix after model release": [c for c in cves if after[c]],
        "all, fix before model release": [c for c in cves if not after[c]],
    }
    tables = {}
    for group, ids in groups.items():
        sub = {c: cves[c] for c in ids}
        table = {}
        for row in ROWS:
            if row not in ranks:
                continue
            if row == "random (expected)":
                table[row] = random_ranks(sub, len(nodes))[1]
                continue
            r = {c: ranks[row][c] for c in ids}
            m = metrics_for(r, len(ids))
            rr = [1 / v if v else 0.0 for v in r.values()]
            m["mrr_ci95"] = bootstrap_ci(rr, rng)
            m["shortlist_recall_ci95"] = bootstrap_ci([1.0 if v and v <= K else 0.0 for v in r.values()], rng)
            table[row] = m
        tables[group] = {"cves": len(ids), "rows": table}

    # paired comparisons on the test CVEs (difference in reciprocal rank)
    comparisons = {}
    test = groups["test"]
    for a, b in (("combined shortlist", "standard PageRank"), ("combined shortlist", "personalized PageRank"),
                 ("combined + prompt v3", "combined shortlist"), ("combined + VulnSC", "combined shortlist"),
                 ("combined + VulnSC", "combined + prompt v3")):
        if a in ranks and b in ranks and test:
            def rr(v):
                return 1 / v if v else 0.0          # not ranked = not found
            diffs = [rr(ranks[a][c]) - rr(ranks[b][c]) for c in test]
            comparisons[f"{a} vs {b}"] = {
                "mrr_difference": statistics.fmean(diffs), "ci95": bootstrap_ci(diffs, rng),
                "better": sum(ranks[a][c] < ranks[b][c] for c in test),
                "worse": sum(ranks[a][c] > ranks[b][c] for c in test),
                "same": sum(ranks[a][c] == ranks[b][c] for c in test)}

    per_cve = []
    for c in cves:
        per_cve.append({"cve": c, "split": splits[c], "bug_type": data[c]["bug_type"],
                        "fix_date": data[c]["fix_date"][:10],
                        "fix_after_model_release": after[c], "functions": len(cves[c]),
                        **{row: round(ranks[row][c], 1) for row in ROWS if row in ranks}})

    PATHS.processed.mkdir(parents=True, exist_ok=True)
    with open(PATHS.processed / "evaluation.json", "w") as f:
        json.dump({"kernel": kernel_info(), "k": K, "weights": weights, "notes": notes,
                   "tables": tables, "comparisons": comparisons, "per_cve": per_cve}, f, indent=1)
    with open(PATHS.processed / "evaluation_per_cve.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(per_cve[0]))
        writer.writeheader()
        writer.writerows(per_cve)

    chart(tables["test"])
    write_md(tables, comparisons, per_cve, weights, notes, len(nodes))
    print(RESULTS_MD.read_text(encoding="utf-8"))
    print(f"💾 Saved: {RESULTS_MD}, {PATHS.processed / 'evaluation.json'}, evaluation_per_cve.csv")
    return 0


def chart(test_table):
    rows = list(test_table["rows"])
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    axes[0].bar(range(len(rows)), [test_table["rows"][r]["mrr"] for r in rows], color="tab:blue")
    axes[0].set_ylabel("MRR on the test CVEs (higher = better)")
    width = 0.2
    for i, key in enumerate(["top10", "top20", "top50", "shortlist_recall"]):
        axes[1].bar([x + i * width for x in range(len(rows))], [test_table["rows"][r][key] for r in rows],
                    width, label=key.replace("shortlist_recall", f"in shortlist (top {K})"))
    axes[1].set_ylabel("Share of test CVEs found")
    axes[1].legend(fontsize=8)
    for ax in axes:
        ax.set_xticks([x + (0.3 if ax is axes[1] else 0) for x in range(len(rows))])
        ax.set_xticklabels([r.replace(" + ", "\n+ ").replace(" (expected)", "\n(expected)") for r in rows],
                           fontsize=8)
    fig.suptitle(f"{kernel_info()['tag']}: test CVEs, shortlist K={K}", fontweight="bold")
    plt.tight_layout()
    PATHS.charts.mkdir(parents=True, exist_ok=True)
    plt.savefig(PATHS.charts / "evaluation.png", dpi=200, bbox_inches="tight")
    plt.close()


def fmt_ci(ci):
    return f"[{ci[0]:.3f}, {ci[1]:.3f}]" if ci else "-"


def write_md(tables, comparisons, per_cve, weights, notes, n_functions):
    info = kernel_info()
    test = tables["test"]
    md = ["# Results summary\n",
          f"_Generated by `analysis/report/evaluate.py` on {datetime.now():%Y-%m-%d %H:%M} from saved results; "
          "rerun it to refresh the numbers._\n",
          f"_Earlier results (Linux 6.1.6, 20 CVEs, PageRank shortlist K=266) are kept unchanged in "
          f"[`{LEGACY_MD}`](legacy_6.1.6/RESULTS.md) for comparison._\n",
          "## Set-up\n",
          f"- Kernel: Linux **{info['tag']}** (commit `{info['commit']}`), `net/netfilter`, "
          f"{n_functions} functions ranked (seeds/entry points excluded).",
          f"- Ground truth: {len(per_cve)} netfilter CVEs whose bug is present in {info['tag']} "
          f"({tables['tuning']['cves']} tuning / {test['cves']} test; split fixed in `configs/cve_split.yaml` "
          f"before any results). {sum(r['fix_after_model_release'] for r in per_cve)} fixes were committed "
          f"after the model release ({model_release_date()}), {sum(not r['fix_after_model_release'] for r in per_cve)} before.",
          f"- Shortlist: top **K = {K}** of the combined ranking (5 structural signals, reciprocal rank fusion).",
          "- LLM: `qwen3-coder:30b` (local, temperature 0). Fusion weight w chosen on the tuning CVEs: "
          + (", ".join(f"{k}: w = {v}" for k, v in weights.items()) or "no LLM scores yet") + ".",
          ""]
    for row, note in notes.items():
        if note:
            md.append(f"- **{row}: {note}.**")
    md.append("")

    def table(group):
        t = tables[group]
        out = [f"| Method | in shortlist (top {K}) | top 10 | top 20 | top 50 | MRR | MRR 95% CI | median rank |",
               "|---|---|---|---|---|---|---|---|"]
        for row, m in t["rows"].items():
            out.append(f"| {row} | {m['shortlist_recall']:.2f} | {m['top10']:.2f} | {m['top20']:.2f} | "
                       f"{m['top50']:.2f} | {m['mrr']:.4f} | {fmt_ci(m.get('mrr_ci95'))} | "
                       f"{m['median_rank']:.0f} |" if m.get("median_rank") is not None else
                       f"| {row} | - | - | - | - | - | - | - |")
        return out

    md.append(f"## Main result ({test['cves']} test CVEs)\n")
    md += table("test")
    md.append("\nValues are the share of CVEs found within the top N. The random row is the exact "
              f"expected value of a random order. Intervals: bootstrap over CVEs ({BOOTSTRAP} resamples).\n")

    md.append("## By fix date (test CVEs)\n")
    md.append("Fixes committed after the model release cannot be in its training data.\n")
    for group in ("test, fix after model release", "test, fix before model release"):
        md.append(f"**{group} ({tables[group]['cves']} CVEs)**\n")
        md += table(group) if tables[group]["cves"] else ["(none)"]
        md.append("")

    md.append("## Paired comparisons (test CVEs)\n")
    md.append("| Comparison | MRR difference | 95% interval | CVEs better / worse / same |")
    md.append("|---|---|---|---|")
    for name, c in comparisons.items():
        md.append(f"| {name} | {c['mrr_difference']:+.4f} | {fmt_ci(c['ci95'])} | "
                  f"{c['better']} / {c['worse']} / {c['same']} |")
    md.append("\nIf the interval includes 0, the difference is not reliable with this many CVEs.\n")

    md.append("## Rank of every CVE\n")
    rows = [r for r in ROWS if r in per_cve[0]]
    md.append("| CVE | split | bug type | fix date | after model release | " + " | ".join(rows) + " |")
    md.append("|" + "---|" * (5 + len(rows)))
    for r in per_cve:
        md.append(f"| {r['cve']} | {r['split']} | {r['bug_type']} | {r['fix_date']} | "
                  f"{'yes' if r['fix_after_model_release'] else 'no'} | " +
                  " | ".join(f"{r[row]:.0f}" for row in rows) + " |")
    md.append("")
    md.append("Tuning and all-CVE tables: `results/processed/evaluation.json`.\n")

    md.append("## Threats to validity\n")
    md.append("- **Ground truth = functions changed by the fix**, mapped by name into the base version; "
              "some fixes change helpers rather than the code where the bug is triggered. "
              "Functions that are seeds are removed from the ground truth (leakage rule).")
    md.append("- **Call graph is text-based:** function-pointer calls are matched by struct type where it "
              "can be worked out, by field name otherwise (share reported in `results/processed/graph_report.txt`).")
    md.append(f"- **Small sample:** {len(per_cve)} CVEs; intervals are wide, per-CVE ranks are given above.")
    md.append("- **LLM memorisation:** fixes before the model release may be in its training data; see the "
              "split by fix date.")
    RESULTS_MD.write_text("\n".join(md) + "\n", encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
