#!/usr/bin/env python3
"""
SCRIPT #8: Report charts (easier-to-read versions of the final results)

Chart 12 - "Where did each test bug end up?"
    one row per test CVE; dots = rank given by each method (left = found
    earlier); an arrow shows what the LLM rerank changed.
Chart 13 - "How many bugs do you find if you read the top N functions?"
    one line per method + random; lines that rise earlier are better.

Reads results/processed/final_results.json (from final_results.py).
Colours: the dataviz reference palette in its validated order; the same
method has the same colour in both charts.
"""

import json
import sys
from math import comb
from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib.ticker import FixedLocator, FuncFormatter, NullLocator

# Windows terminals use a non-UTF-8 encoding by default and crash on emoji output
sys.stdout.reconfigure(encoding="utf-8")

PROJECT_ROOT = Path(__file__).resolve().parents[2]
RESULTS_FILE = PROJECT_ROOT / "results/processed/final_results.json"
CHART_PATH = PROJECT_ROOT / "results/visualizations"

# reference palette (light mode)
SURFACE = "#fcfcfb"
TEXT = "#0b0b0b"
TEXT_2 = "#52514e"
MUTED = "#8a8985"
GRID = "#e4e3df"
BAND_TOP = "#dbe9fa"      # top-20 zone (sequential blue, very light)
BAND_SHORT = "#f0efec"    # shortlist zone (neutral)

FULL, PERSONALIZED, STANDARD, STANDARD_LLM = "#2a78d6", "#eb6834", "#1baf7a", "#eda100"
METHODS = [  # (key in final_results.json, label, colour)
    ("full: personalized + LLM", "Personalized PageRank + LLM (proposed)", FULL),
    ("A: personalized PageRank", "Personalized PageRank alone", PERSONALIZED),
    ("baseline: standard PageRank", "Standard PageRank alone (baseline)", STANDARD),
    ("B: standard + LLM", "Standard PageRank + LLM", STANDARD_LLM),
]

plt.rcParams.update({
    "font.family": "DejaVu Sans", "font.size": 10, "text.color": TEXT,
    "axes.edgecolor": GRID, "axes.labelcolor": TEXT_2, "axes.facecolor": SURFACE,
    "figure.facecolor": SURFACE, "xtick.color": TEXT_2, "ytick.color": TEXT_2,
    "axes.spines.top": False, "axes.spines.right": False,
})


def rank_axis(ax, n_functions):
    ax.set_xscale("log")
    ax.set_xlim(0.8, n_functions * 1.3)
    ticks = [1, 10, 20, 100, 266, 1000, n_functions]
    ax.xaxis.set_major_locator(FixedLocator(ticks))
    ax.xaxis.set_minor_locator(NullLocator())
    ax.xaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{int(v):,}"))
    ax.grid(axis="x", color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)


def zones(ax, k, top=20, label_y=None):
    ax.axvspan(0.8, top, color=BAND_TOP, zorder=0)
    ax.axvspan(top, k, color=BAND_SHORT, zorder=0)
    if label_y is not None:
        ax.text(4, label_y, "top 20", color=TEXT_2, fontsize=9, ha="center", va="bottom")
        ax.text((top * k) ** 0.5, label_y, f"rest of the LLM shortlist\n(top {k})",
                color=TEXT_2, fontsize=9, ha="center", va="bottom")


def chart_where_bugs_landed(data, out):
    k, n = data["k"], 4353
    rows = [r for r in data["per_cve"] if r["split"] == "test"]
    rows.sort(key=lambda r: (r["full: personalized + LLM"], r["baseline: standard PageRank"]))

    fig, ax = plt.subplots(figsize=(11, 7.2))
    rank_axis(ax, n)
    ax.set_ylim(len(rows) - 0.4, -1.4)
    zones(ax, k, label_y=-0.75)

    for y, r in enumerate(rows):
        ax.axhline(y, color=GRID, linewidth=0.6, zorder=1)
        ax.scatter(r["random_expected_rank"], y, marker="D", s=40, facecolor="none",
                   edgecolor=MUTED, linewidth=1.2, zorder=2)
        before, after = r["A: personalized PageRank"], r["full: personalized + LLM"]
        if after < before:   # the LLM moved this bug up
            ax.annotate("", xy=(after * 1.12, y), xytext=(before / 1.12, y), zorder=3,
                        arrowprops=dict(arrowstyle="-|>", color=FULL, lw=1.6, mutation_scale=12))
        for key, _, colour in METHODS[2::-1]:   # standard, personalized, full (full on top)
            ax.scatter(r[key], y, s=70, color=colour, edgecolor=SURFACE, linewidth=1.5, zorder=4)
        ax.text(after * 0.82 if after > 30 else after * 1.25, y - 0.32, f"#{after:.0f}",
                color=TEXT, fontsize=8, ha="center", zorder=5)

    path_names = {"both": "packet+config", "none": "unreachable", "packet": "packet", "config": "config"}
    ax.set_yticks(range(len(rows)))
    ax.set_yticklabels([f"{r['cve']}   {path_names[r['attack_path']]}, {r['bug_type']}" for r in rows],
                       fontsize=9)
    ax.tick_params(axis="y", length=0)
    ax.set_xlabel("Rank given to the bug's function  (log scale - further left = found earlier)")

    labels = {METHODS[1][0]: METHODS[1][1] + " (hidden under blue when the LLM did not move the bug)"}
    handles = [plt.Line2D([], [], marker="o", linestyle="", markersize=9, color=c,
                          markeredgecolor=SURFACE, label=labels.get(key, label))
               for key, label, c in METHODS[:3]]
    handles.append(plt.Line2D([], [], marker="D", linestyle="", markersize=7, markerfacecolor="none",
                              markeredgecolor=MUTED, label="Random order (expected)"))
    handles.append(plt.Line2D([], [], color=FULL, marker=">", markersize=6, lw=1.6,
                              label="Move made by the LLM rerank"))
    ax.legend(handles=handles, loc="upper left", bbox_to_anchor=(0.0, -0.09), ncol=2,
              frameon=False, fontsize=9)
    ax.text(1.0, -0.2, "Attack path = which front doors can reach the bug's function in the call graph.",
            transform=ax.transAxes, ha="right", va="top", fontsize=8.5, color=TEXT_2)
    fig.suptitle("Where did each test bug end up?", x=0.01, ha="left", fontsize=14,
                 fontweight="bold", color=TEXT)
    ax.set_title(f"14 test CVEs. Only bugs inside the LLM's shortlist (top {k}) can be moved by the LLM; "
                 "here one was: CVE-2023-52620, from #156 to #12.",
                 loc="left", fontsize=9.5, color=TEXT_2, pad=10)
    plt.tight_layout()
    plt.savefig(out, dpi=200, bbox_inches="tight", facecolor=SURFACE)
    plt.close()


def expected_random_found(rows, n_functions, read):
    """Expected number of bugs found when reading `read` functions in random order"""
    total = 0.0
    for r in rows:
        m = r["functions"]
        miss = comb(n_functions - m, read) / comb(n_functions, read) if read <= n_functions - m else 0.0
        total += 1 - miss
    return total


def chart_bugs_vs_read(data, out):
    k, n = data["k"], 4353
    rows = [r for r in data["per_cve"] if r["split"] == "test"]
    xs = sorted({1, n} | {int(v) for v in (1.2 ** i for i in range(48)) if v <= n})

    fig, ax = plt.subplots(figsize=(11, 6.2))
    rank_axis(ax, n)
    ax.set_ylim(-0.3, len(rows) + 1.6)
    zones(ax, k, label_y=len(rows) + 0.5)

    random_line, = ax.plot(xs, [expected_random_found(rows, n, x) for x in xs], color=MUTED, lw=2,
                           linestyle=(0, (4, 3)), zorder=2)
    random_20 = expected_random_found(rows, n, 20)
    random_k = expected_random_found(rows, n, k)

    handles = []
    for key, label, colour in reversed(METHODS):   # proposed method drawn last (on top)
        ranks = sorted(r[key] for r in rows)
        ys = [sum(1 for v in ranks if v <= x) for x in xs]
        line, = ax.step(xs, ys, where="post", color=colour, lw=2.6 if colour == FULL else 2, zorder=3)
        in_20 = sum(1 for v in ranks if v <= 20)
        in_k = sum(1 for v in ranks if v <= k)
        line.set_label(f"{label}  -  top 20: {in_20},  top {k}: {in_k}")
        handles.insert(0, line)
    random_line.set_label(f"Random order (expected)  -  top 20: {random_20:.1f},  top {k}: {random_k:.1f}")
    handles.append(random_line)
    legend = ax.legend(handles=handles, loc="upper left", bbox_to_anchor=(0.005, 0.87), fontsize=9,
                       frameon=True, title=f"Test bugs found (of {len(rows)})", title_fontsize=9)
    legend.get_frame().set_facecolor(SURFACE)
    legend.get_frame().set_edgecolor(GRID)
    ax.text(0.0, -0.13, "Where two lines have the same values, one hides the other "
            "(personalized alone under blue; standard + LLM under green).",
            transform=ax.transAxes, ha="left", va="top", fontsize=8.5, color=TEXT_2)

    ax.set_yticks(range(0, len(rows) + 1, 2))
    ax.grid(axis="y", color=GRID, linewidth=0.8)
    ax.set_xlabel("Number of functions read, in ranked order  (log scale)")
    ax.set_ylabel(f"Test bugs found (of {len(rows)})")
    fig.suptitle("How many bugs do you find if you read the top N functions?", x=0.01, ha="left",
                 fontsize=14, fontweight="bold", color=TEXT)
    ax.set_title("Lines that rise further left are better. Only the proposed method finds a test bug "
                 "within the top 20.", loc="left", fontsize=9.5, color=TEXT_2, pad=10)
    plt.tight_layout()
    plt.savefig(out, dpi=200, bbox_inches="tight", facecolor=SURFACE)
    plt.close()


def main():
    with open(RESULTS_FILE, "r") as f:
        data = json.load(f)
    CHART_PATH.mkdir(parents=True, exist_ok=True)
    a = CHART_PATH / "12_where_each_bug_landed.png"
    b = CHART_PATH / "13_bugs_found_vs_functions_read.png"
    chart_where_bugs_landed(data, a)
    chart_bugs_vs_read(data, b)
    print(f"💾 Saved: {a}\n💾 Saved: {b}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
