# Run guide

All commands are run from this folder (`fyp-kernel-security-clean`) in PowerShell.
Times are for this laptop; the LLM times use the speeds in `configs/llm.yaml`
(`seconds_per_call`: v3 15 s, VulnSC summary 8 s, VulnSC review 20 s).

## 0. Before you start (once)

```powershell
ollama serve                         # in its own window, or start the Ollama app
ollama pull qwen3-coder:30b          # if not downloaded yet
.venv\Scripts\python.exe scripts\test_environment.py
```

## 1. Structural pipeline (no LLM) - already done, only rerun if something changed

Already run on v6.12 and committed: kernel clone, functions, call graph,
seeds, CVE set, graph report, combined shortlist. Rerun only after changing
a config (e.g. `base_tag`, `configs/callgraph.yaml`, `configs/shortlist.yaml`).

| Command | What | Time |
|---|---|---|
| `.venv\Scripts\python.exe run_pipeline.py` | all structural stages | ~5-10 min (most of it the CVE set: `git show` for every fix) |
| `.venv\Scripts\python.exe run_pipeline.py --only graphcheck` | call graph report only | ~2 s |
| `.venv\Scripts\python.exe run_pipeline.py --only shortlist` | combined shortlist only | ~6 s |

Never edit `configs/cve_split.yaml` by hand (the tuning/test split is fixed).

## 2. Quick LLM smoke tests (a few minutes) - do these first

Checks that the model answers in the right JSON format before the long runs.

```powershell
.venv\Scripts\python.exe analysis\llm\vulnsc.py nft_payload_eval nf_tables_newrule     # ~3-5 min
.venv\Scripts\python.exe analysis\llm\llm_check.py --prompt v3 --limit 3               # ~1 min
.venv\Scripts\python.exe analysis\llm\llm_check.py --prompt vulnsc --limit 3           # ~3-5 min
```

Look for `failures 0` (or close to it). Answers are cached, so this work is
reused by the long runs.

## 3. Long LLM jobs (~4.8 h in total -> two runs of max 3 h)

Double-click **`RUN_LLM_OVERNIGHT.bat`** (or run
`.venv\Scripts\python.exe run_llm_unattended.py`). It runs these jobs in order:

| Job | What | Size | Time |
|---|---|---|---|
| `check-v3` | Phase 5 LLM check, prompt v3 | 178 functions (28 buggy from tuning CVEs + 150 random) | ~45 min |
| `shortlist-v3` | score the top-150 shortlist, prompt v3 | 150 functions | ~40 min |
| `check-vulnsc` | Phase 5 LLM check, VulnSC reranker | 178 reviews + ~290 callee summaries | ~1 h 40 min |
| `shortlist-vulnsc` | score the top-150 shortlist, VulnSC | 150 reviews + ~460 new summaries | ~1 h 50 min |

- Each run stops by itself after 3 h (`max_hours_per_run`). **Run it again**:
  finished jobs are skipped in seconds and the unfinished one continues from
  the cache. Repeat until the log says "All jobs finished" (expect 2 runs).
- If Ollama stops mid-run, the job saves and stops; start Ollama and run again.
- Progress/log: `results\processed\llm_run.log`.
- One job only: `run_llm_unattended.py --jobs shortlist-vulnsc`.

Then look at the Phase 5 results (median rank of buggy functions, AUC):
`results\processed\llm_check_v3_summary.txt` and `llm_check_vulnsc_summary.txt`.

## 4. Evaluation (~10 s, no LLM)

```powershell
.venv\Scripts\python.exe run_pipeline.py --only evaluate
```

Writes `results\RESULTS.md`, `results\processed\evaluation.json`,
`evaluation_per_cve.csv` and `results\visualizations\evaluation.png`.
The fusion weight w is chosen on the tuning CVEs and then used on the test
CVEs. If an LLM job is unfinished, its row is marked PARTIAL; it can be run
at any time to see the structural rows.
