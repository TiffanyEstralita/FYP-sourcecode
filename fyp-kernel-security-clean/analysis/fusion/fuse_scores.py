#!/usr/bin/env python3
"""
SCRIPT #6: Combine PageRank and LLM scores (retrieve-then-rerank)

For a structural ranking R (standard or personalized PageRank), a shortlist
size K and a weight w:
  1. shortlist = the top K functions of R          (cheap: no LLM)
  2. each shortlisted function gets
        position = 1 - (rank in R - 1) / K          (1.0 for rank 1 ... ~0 for rank K)
        llm      = LLM risk score / scale           (0..1, from score_functions.py)
     final = w * position + (1 - w) * llm
  3. the shortlist is re-ordered by `final` (ties keep R's order) and placed
     first; every other function follows in R's order.
w = 1 gives R unchanged; w = 0 orders the shortlist by the LLM alone.

Position (rank) is used instead of the raw PageRank value because PageRank
values are extremely skewed: a few functions have huge scores and the rest
are tiny, so raw values would let the LLM decide almost everything.

The weight w is CHOSEN ON THE TUNING CVEs only (best MRR; ties -> the w
closest to 0.5, decided in advance), then applied unchanged to the test CVEs.

Ablation (project brief), all at the same shortlist size K:
  baseline       standard PageRank, no LLM
  A              personalized PageRank, no LLM
  B              standard PageRank + LLM rerank
  full           personalized PageRank + LLM rerank

Output: results/processed/fusion_*.{json,csv,txt}
        results/visualizations/9_weight_sensitivity.png, 10_efficiency_curve.png
"""

import argparse
import csv
import json
import sys
from pathlib import Path

import matplotlib.pyplot as plt

# Windows terminals use a non-UTF-8 encoding by default and crash on emoji output
sys.stdout.reconfigure(encoding="utf-8")

PROJECT_ROOT = Path(__file__).resolve().parents[2]

GROUND_TRUTH_FILE = PROJECT_ROOT / "validation/cve_data/vulnerable_functions.json"
PROCESSED = PROJECT_ROOT / "results/processed"
CHART_PATH = PROJECT_ROOT / "results/visualizations"
RANKING_FILES = {"standard": PROCESSED / "pagerank_scores.json",
                 "personalized": PROCESSED / "ppr_scores.json"}
SECONDS_PER_FUNCTION = 14.9      # measured for prompt v3 on this laptop
WEIGHTS = [round(i / 10, 1) for i in range(11)]
SPLITS = ("all", "tuning", "test")

sys.path.insert(0, str(PROJECT_ROOT / "analysis"))
from metrics import evaluate, load_ground_truth


def load_json(path):
    with open(path, "r") as f:
        return json.load(f)


def ordered(scores):
    return sorted(scores, key=lambda n: (-scores[n], n))


def interleave(first, second):
    """Hybrid ranking: alternately the next function from each ranking, skipping repeats"""
    out, seen = [], set()
    for a, b in zip(first, second):
        for node in (a, b):
            if node not in seen:
                seen.add(node)
                out.append(node)
    return out


def complete_shortlist_size(order, llm):
    """Largest K such that the top K of `order` all have LLM scores"""
    for i, node in enumerate(order):
        if node not in llm:
            return i
    return len(order)


def fused_scores(order, llm, k, w):
    """Final ranking as a {node: score} dict (higher = check earlier)"""
    total = len(order)
    scores = {}
    for i, node in enumerate(order):
        if i < k:
            position = 1 - i / k
            final = w * position + (1 - w) * llm[node]
            scores[node] = 2 + final - i * 1e-9          # shortlist first; ties keep R's order
        else:
            scores[node] = (total - i) / total           # rest: R's order, below the shortlist
    return scores


def evaluate_splits(scores, cves, splits):
    out = {}
    for split in SPLITS:
        subset = {c: f for c, f in cves.items() if split == "all" or splits[c] == split}
        out[split] = evaluate(scores, subset, ks=(10, 20, 50, 100))
    return out


def choose_weight(order, llm, k, cves, splits):
    """Best w on the tuning CVEs by MRR; ties -> closest to 0.5"""
    tuning = {c: f for c, f in cves.items() if splits[c] == "tuning"}
    results = {w: evaluate(fused_scores(order, llm, k, w), tuning)["mrr"] for w in WEIGHTS}
    best = max(results.values())
    return min((w for w, v in results.items() if v == best), key=lambda w: abs(w - 0.5)), results


def main():
    parser = argparse.ArgumentParser(description="Combine PageRank and LLM scores")
    parser.add_argument("--llm", default="v3", help="LLM prompt version whose scores to use (default v3)")
    parser.add_argument("--k", type=int, help="shortlist size (default: largest complete one)")
    args = parser.parse_args()

    print("=" * 70)
    print("🔀 FUSION: PageRank shortlist + LLM rerank")
    print("=" * 70)

    cves, splits = load_ground_truth(GROUND_TRUTH_FILE)
    llm_answers = load_json(PROCESSED / f"llm_scores_{args.llm}.json")
    llm = {n: a["risk"] for n, a in llm_answers.items() if "risk" in a}
    orders = {name: ordered(load_json(path)) for name, path in RANKING_FILES.items()}
    # hybrid: alternate personalized and standard (the order score_functions.py scored in)
    orders["hybrid"] = interleave(orders["personalized"], orders["standard"])

    complete = {name: complete_shortlist_size(o, llm) for name, o in orders.items()}
    max_k = min(complete.values())
    k = min(args.k or max_k, max_k)
    print(f"   LLM scores ({args.llm}) for {len(llm)} functions -> complete shortlists: "
          + ", ".join(f"{n} K<={c}" for n, c in complete.items()))
    print(f"   comparing all rankings at the SAME budget K={k} "
          f"(LLM time {k * SECONDS_PER_FUNCTION / 3600:.1f} h)")

    # ---- choose w on the tuning CVEs, per structural ranking ----
    chosen, sweeps = {}, {}
    for name, order in orders.items():
        chosen[name], _ = choose_weight(order, llm, k, cves, splits)
        sweeps[name] = {w: evaluate_splits(fused_scores(order, llm, k, w), cves, splits) for w in WEIGHTS}
        print(f"   w chosen on tuning CVEs for {name}: {chosen[name]}")

    # ---- ablation table ----
    setups = {
        "baseline (standard, no LLM)": fused_scores(orders["standard"], llm, k, 1.0),
        "A (personalized, no LLM)": fused_scores(orders["personalized"], llm, k, 1.0),
        "C (hybrid, no LLM)": fused_scores(orders["hybrid"], llm, k, 1.0),
        f"B (standard + LLM, w={chosen['standard']})": fused_scores(orders["standard"], llm, k, chosen["standard"]),
        f"full (personalized + LLM, w={chosen['personalized']})": fused_scores(orders["personalized"], llm, k, chosen["personalized"]),
        f"hybrid + LLM (w={chosen['hybrid']})": fused_scores(orders["hybrid"], llm, k, chosen["hybrid"]),
    }
    # the hybrid shortlist can also use every function scored so far
    big_k = complete["hybrid"]
    w_big, _ = choose_weight(orders["hybrid"], llm, big_k, cves, splits)
    setups[f"hybrid + LLM, K={big_k} (w={w_big})"] = fused_scores(orders["hybrid"], llm, big_k, w_big)
    table = {name: evaluate_splits(scores, cves, splits) for name, scores in setups.items()}

    lines = [f"FUSION RESULTS  (shortlist K={k}, LLM prompt {args.llm}, "
             f"LLM time {k * SECONDS_PER_FUNCTION / 3600:.1f} h; w chosen on tuning CVEs)", ""]
    for split in SPLITS:
        n = sum(1 for c in cves if split == "all" or splits[c] == split)
        lines.append(f"{split} CVEs ({n}):")
        lines.append(f"   {'setup':42s} {'R@10':>5s} {'R@20':>5s} {'R@50':>5s} {f'R@{k}':>5s} {'MRR':>7s}")
        for name, ev in table.items():
            e = ev[split]
            in_k = sum(1 for r in e["ranks"].values() if r and r <= k) / max(1, n)
            lines.append(f"   {name:42s} {e['recall'][10]:5.2f} {e['recall'][20]:5.2f} "
                         f"{e['recall'][50]:5.2f} {in_k:5.2f} {e['mrr']:7.4f}")
        lines.append("")
    short = {s: f"S{i}" for i, s in enumerate(table, 1)}
    lines.append("Rank of each CVE that is inside a shortlist in any setup "
                 "(columns S1.. = setups in the order listed above):")
    lines.append(f"   {'CVE':16s} {'split':7s}" + "".join(f"{short[s]:>8s}" for s in table))
    for c in cves:
        ranks = [table[s]["all"]["ranks"][c] for s in table]
        if any(r and r <= big_k for r in ranks):
            lines.append(f"   {c:16s} {splits[c]:7s}" + "".join(f"{r:>8.0f}" for r in ranks))
    lines.append("   " + "; ".join(f"{short[s]} = {s}" for s in table))
    for line in lines:
        print(line)

    # ---- efficiency curve: shortlist size vs CVEs found vs LLM time ----
    # each ranking only up to the shortlist size for which every function has an LLM score
    curve = []
    sizes = sorted({s for s in (10, 25, 50, 100, 150, 200, 250, 300, 400, k, big_k)
                    if s <= max(complete.values())})
    for size in sizes:
        row = {"K": size, "llm_hours": round(size * SECONDS_PER_FUNCTION / 3600, 2)}
        for name in orders:
            if size > complete[name]:
                continue
            ev = evaluate(fused_scores(orders[name], llm, size, chosen[name]), cves, ks=(10, 20, size))
            plain = evaluate(fused_scores(orders[name], llm, size, 1.0), cves, ks=(10, 20, size))
            row[f"{name}_in_shortlist"] = round(ev["recall"][size] * len(cves))
            row[f"{name}_top20_without_llm"] = round(plain["recall"][20] * len(cves))
            row[f"{name}_top20_with_llm"] = round(ev["recall"][20] * len(cves))
        curve.append(row)
    lines.append(f"\nEfficiency curve (all {len(cves)} CVEs; number found) - "
                 "for each ranking: inside shortlist / top 20 without LLM / top 20 with LLM")
    lines.append(f"   {'K':>5s} {'LLM h':>6s}" + "".join(f" | {n:>17s}" for n in orders))
    for r in curve:
        cells = []
        for n in orders:
            if f"{n}_in_shortlist" in r:
                cells.append(f"{r[f'{n}_in_shortlist']:>5d} {r[f'{n}_top20_without_llm']:>5d} "
                             f"{r[f'{n}_top20_with_llm']:>5d}")
            else:
                cells.append(f"{'(not scored)':>17s}")
        lines.append(f"   {r['K']:>5d} {r['llm_hours']:>6.2f}" + "".join(f" | {c}" for c in cells))
    for line in lines[-len(curve) - 2:]:
        print(line)

    # ---- save ----
    PROCESSED.mkdir(parents=True, exist_ok=True)
    with open(PROCESSED / "fusion_results.json", "w") as f:
        json.dump({"k": k, "llm_version": args.llm, "chosen_w": chosen, "setups": table,
                   "weight_sweep": {n: {str(w): v for w, v in s.items()} for n, s in sweeps.items()},
                   "efficiency_curve": curve}, f, indent=2)
    with open(PROCESSED / "fusion_summary.txt", "w") as f:
        f.write("\n".join(lines) + "\n")
    with open(PROCESSED / "fusion_efficiency_curve.csv", "w", newline="") as f:
        fields = list(dict.fromkeys(key for row in curve for key in row))
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(curve)

    # weight sensitivity chart (MRR vs w; tuning solid, test dashed)
    colors = {"personalized": "tab:blue", "standard": "tab:orange", "hybrid": "tab:green"}
    fig, ax = plt.subplots(figsize=(9, 5))
    for name, color in colors.items():
        for split, style in (("tuning", "-"), ("test", "--")):
            ax.plot(WEIGHTS, [sweeps[name][w][split]["mrr"] for w in WEIGHTS], style, color=color,
                    marker="o", label=f"{name}, {split} CVEs")
        ax.axvline(chosen[name], color=color, linestyle=":", alpha=0.6)
    ax.set_xlabel("w  (0 = LLM only within the shortlist, 1 = PageRank only)")
    ax.set_ylabel("MRR (higher = better)")
    ax.set_title(f"Effect of the fusion weight w (shortlist K={k})", fontweight="bold")
    ax.legend(fontsize=8)
    plt.tight_layout()
    CHART_PATH.mkdir(parents=True, exist_ok=True)
    plt.savefig(CHART_PATH / "9_weight_sensitivity.png", dpi=200, bbox_inches="tight")
    plt.close()

    # efficiency chart: CVEs in top 20 vs LLM hours
    fig, ax = plt.subplots(figsize=(10, 5.5))
    for name, color in colors.items():
        rows = [r for r in curve if f"{name}_in_shortlist" in r]
        hours = [r["llm_hours"] for r in rows]
        ax.plot(hours, [r[f"{name}_top20_with_llm"] for r in rows], "-", color=color, marker="o",
                label=f"{name} + LLM: CVEs in top 20")
        ax.plot(hours, [r[f"{name}_in_shortlist"] for r in rows], "--", color=color, alpha=0.5,
                label=f"{name}: CVEs inside the shortlist (upper limit)")
    ax.axhline(0, color="grey", linestyle=":", label="any ranking alone: 0 CVEs in top 20")
    ax.set_xlabel("LLM time (hours) = shortlist size K x seconds per function")
    ax.set_ylabel(f"CVEs found (of {len(cves)})")
    ax.set_title("Efficiency: bugs found vs LLM effort", fontweight="bold")
    ax.legend(fontsize=8)
    plt.tight_layout()
    plt.savefig(CHART_PATH / "10_efficiency_curve.png", dpi=200, bbox_inches="tight")
    plt.close()
    print(f"\n💾 Saved: {PROCESSED / 'fusion_summary.txt'} (+ .json, efficiency_curve.csv, charts 9 and 10)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
