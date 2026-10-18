# Baseline: standard PageRank (Phase 0)

Frozen copy of the original pipeline's results. Do not overwrite these files;
later phases (personalized PageRank, LLM reranking) are compared against them.

## How it was produced

- Command: `python run_pipeline.py` (stages functions -> graph, no LLM stage)
- Code: commit `e01865c` ("Add run_pipeline.py; restore charts 1 and 2")
- Kernel source: Linux 6.1.6 (`data/kernel/linux-shallow`), `net/netfilter` only
- PageRank: standard (not personalized), `alpha=0.85`, `max_iter=100`, `tol=1e-6`
- Date: 2026-10-03, Windows 11, Python 3.11.9, networkx 3.4.2
- Reproduces the earlier macOS run exactly (same functions, edges and ranks;
  only file ordering and ~1e-17 floating-point noise differ)

## Call graph

| | |
|---|---|
| C files scanned | 241 |
| Function definitions extracted | 4,087 |
| Graph nodes (unique function names) | 3,815 |
| Graph edges (unique caller -> callee) | 8,522 |

## Where each CVE's vulnerable function ranks

| CVE | Vulnerable function | Rank | Top % |
|---|---|---|---|
| CVE-2023-0179 | `nft_payload_copy_vlan` | 1540 / 3815 | 40.4% |
| CVE-2024-53141 | `bitmap_ip_uadt` | 2082 / 3815 | 54.6% |
| CVE-2025-22064 | `nf_tables_updchain` | 1883 / 3815 | 49.4% |

None is in the top 20% - roughly what random ordering would give.

## Known limitations (to address in Phase 1)

- Calls made through function pointers (e.g. `.eval = nft_payload_eval`) are
  not captured, so `nft_payload_eval` and `bitmap_ip_uadt` have no callers.
- Kernel helpers/macros (`kfree`, `mutex_lock`, `ARRAY_SIZE`, `memset`, ...)
  are counted as functions and dominate the top of the ranking.
- Functions are identified by name only, so same-named `static` functions in
  different files are merged into one node (4,087 definitions -> 3,815 nodes).
