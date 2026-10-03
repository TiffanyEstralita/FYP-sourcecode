# Vulnerability Prioritization in the Linux Kernel Using Personalized PageRank and LLM-Based Reranking

NTU Final Year Project. The goal is to rank the functions of the Linux kernel's
**netfilter** subsystem by how likely they are to contain a vulnerability, so that
testing and fuzzing effort goes to the riskiest code first — without training a
model (no GNN), using a lightweight *retrieve-then-rerank* design:

1. **Retrieve (cheap, structural):** build the netfilter call graph and rank functions
   with **personalized PageRank**, biased towards the entry points where attacker
   input arrives (network packets and netlink configuration messages).
2. **Rerank (expensive, semantic):** a local LLM reads only the top-K shortlisted
   functions and gives each a risk score; the final ranking combines both.

Results: see **[results/RESULTS.md](results/RESULTS.md)** (generated).

## Pipeline

| Stage | Script | What it does |
|---|---|---|
| functions | `analysis/extraction/extract_all_functions.py` | find every function defined in `net/netfilter` (incl. ipset templates) |
| calls | `analysis/extraction/extract_function_calls.py` | direct calls `foo(...)` |
| indirect | `analysis/extraction/extract_indirect_calls.py` | calls through function pointers (`ops->eval(...)`), slot tables, callbacks passed as arguments |
| seeds | `analysis/pagerank/build_seeds.py` | attacker entry points from the rules in `configs/seeds.yaml` |
| pagerank | `analysis/pagerank/calculate_pagerank.py` | standard and personalized PageRank |
| reach | `analysis/pagerank/check_reachability.py` | can each vulnerable function be reached from an entry point? |
| cve / evaluate / alpha | `analysis/pagerank/*.py` | rank of the known vulnerable functions; alpha sensitivity |
| visualize / graph | `analysis/pagerank/visualize_results.py`, `create_directional_graph.py` | charts |
| *(LLM, run separately)* | `RUN_LLM_OVERNIGHT.bat` → `run_llm_unattended.py` | prompt practice round (`tune_prompt.py`) then risk-score the top-K functions (`score_functions.py`); answers cached in `results/llm_cache/` |
| fusion | `analysis/fusion/fuse_scores.py` | combine PageRank shortlist + LLM scores; ablation and efficiency curve |
| final | `analysis/report/final_results.py` | final tables, random baseline, confidence intervals, `results/RESULTS.md` |

Shared helpers: `analysis/callgraph.py` (the one call graph every script uses),
`analysis/sources.py` (source files incl. expanded ipset templates),
`analysis/metrics.py` (rank, recall@K, MRR).

## Ground truth

20 netfilter CVEs whose bug is present in the analysed kernel (Linux 6.1.6), in
`validation/cve_data/vulnerable_functions.json` (6 tuning / 14 test):

- `analysis/validation/collect_cves.py` selects, from the Linux kernel CNA's official CVE
  database, every netfilter CVE that affects 6.1.6, downloads its fix and finds the
  function(s) it changed in our source (203 candidates, 175 mapped).
- `analysis/validation/build_evaluation_set.py` takes the hand-verified CVEs
  (`manual_cves.json`) plus a fixed-seed random sample, and splits tuning/test.

Settings (prompt version, fusion weight) are chosen on the **tuning** CVEs only;
the **test** CVEs are used only for the final numbers.

## Setup

Requires Python 3.11 and [Ollama](https://ollama.com) with the model in
`configs/ollama.yaml` (`ollama pull qwen3-coder:30b`).

```powershell
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe scripts\test_environment.py      # check the setup
```

Data (not in git, too large):

```powershell
# kernel source: Linux 6.1.6 in data/kernel/linux-shallow (git submodule)
# kernel CVE database (only needed to rebuild the CVE set):
git clone --depth 1 https://git.kernel.org/pub/scm/linux/security/vulns.git data/vulns
```

## Running

```powershell
.venv\Scripts\python.exe run_pipeline.py --list        # show the stages
.venv\Scripts\python.exe run_pipeline.py               # structural stages (~10 s)
.venv\Scripts\python.exe run_pipeline.py --report      # + fusion and final results
```

The LLM stage takes hours, so it runs separately and unattended: double-click
`RUN_LLM_OVERNIGHT.bat` (the shortlist size is set by `--top` inside it). It can be
stopped and restarted; answers are cached. Watch it live with
`.venv\Scripts\python.exe analysis\llm\watch_llm.py`.

## Folders

```
analysis/     code (extraction, pagerank, llm, fusion, validation, report)
configs/      seeds.yaml (entry points), prompts.yaml (LLM prompts), ollama.yaml (model)
data/         kernel source, CVE database, downloaded fix patches
results/      baseline/ (frozen Phase 0), raw/, processed/, visualizations/, llm_cache/
validation/   CVE ground truth
docs/         reading notes
```
