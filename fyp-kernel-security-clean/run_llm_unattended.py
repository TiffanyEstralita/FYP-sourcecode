#!/usr/bin/env python3
"""
Run the LLM jobs unattended. Started by double-clicking RUN_LLM_OVERNIGHT.bat, or:

    .venv\\Scripts\\python.exe run_llm_unattended.py                       # all jobs, in order
    .venv\\Scripts\\python.exe run_llm_unattended.py --jobs check-v3       # one job
    .venv\\Scripts\\python.exe run_llm_unattended.py --max-hours 1         # shorter run

Jobs (in this order):
  check-v3          Phase 5 LLM check with the old prompt v3        (~45 min)
  shortlist-v3      score the top-K shortlist with prompt v3        (~40 min)
  check-vulnsc      Phase 5 LLM check with the VulnSC reranker      (~1 h 40 min)
  shortlist-vulnsc  score the top-K shortlist with VulnSC           (~1 h 50 min)
  (total ~4.8 h = two runs; see RUN_GUIDE.md)

- ONE run lasts at most max_hours_per_run (configs/llm.yaml, 3 h) in total;
  then it stops by itself. Every answer is cached the moment it arrives, so
  just start it again: finished jobs are skipped in seconds and the
  unfinished one continues. Repeat until the log says "All jobs finished".
- keeps Windows awake while running (laptop must stay plugged in)
- everything printed is also written to results/processed/llm_run.log
"""

import argparse
import ctypes
import json
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT / "analysis"))
sys.path.insert(0, str(PROJECT_ROOT / "analysis/llm"))
from config import PATHS, load_yaml
from llm_client import MODEL, ollama_available

LOG_FILE = PATHS.processed / "llm_run.log"
JOBS = {
    "check-v3": (["analysis/llm/llm_check.py", "--prompt", "v3"], "llm_check_v3.json"),
    "shortlist-v3": (["analysis/llm/score_shortlist.py", "--prompt", "v3"], "llm_scores_shortlist_v3.json"),
    "check-vulnsc": (["analysis/llm/llm_check.py", "--prompt", "vulnsc"], "llm_check_vulnsc.json"),
    "shortlist-vulnsc": (["analysis/llm/score_shortlist.py", "--prompt", "vulnsc"],
                         "llm_scores_shortlist_vulnsc.json"),
}

# Windows: ask the system not to sleep while this program runs
ES_CONTINUOUS, ES_SYSTEM_REQUIRED = 0x80000000, 0x00000001


def keep_awake(on):
    if sys.platform == "win32":
        flags = ES_CONTINUOUS | (ES_SYSTEM_REQUIRED if on else 0)
        ctypes.windll.kernel32.SetThreadExecutionState(flags)


def log(log_file, text):
    stamped = f"[{datetime.now():%Y-%m-%d %H:%M:%S}] {text}"
    print(stamped, flush=True)
    log_file.write(stamped + "\n")
    log_file.flush()


def run_step(log_file, title, args):
    log(log_file, f"===== {title} =====")
    process = subprocess.Popen([sys.executable, "-u"] + args, cwd=PROJECT_ROOT,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               text=True, encoding="utf-8", errors="replace")
    for line in process.stdout:
        line = line.rstrip()
        print(line, flush=True)
        log_file.write(line + "\n")
        log_file.flush()
    process.wait()
    log(log_file, f"===== {title}: exit code {process.returncode} =====")
    return process.returncode


def job_finished(output_name):
    path = PATHS.processed / output_name
    if not path.exists():
        return False
    with open(path) as f:
        return json.load(f)["progress"]["status"] == "finished"


def main():
    parser = argparse.ArgumentParser(description="Run the LLM jobs unattended (resumable, time-capped)")
    parser.add_argument("--jobs", nargs="*", choices=list(JOBS), default=list(JOBS))
    parser.add_argument("--max-hours", type=float, default=load_yaml("llm.yaml")["max_hours_per_run"],
                        help="total time for this run (default: max_hours_per_run in configs/llm.yaml)")
    args = parser.parse_args()

    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(LOG_FILE, "a", encoding="utf-8") as log_file:
        log(log_file, f"LLM unattended run started (model {MODEL}, at most {args.max_hours} h): "
                      f"{', '.join(args.jobs)}")
        for _ in range(24):          # wait up to 2 minutes for Ollama (may still be starting)
            if ollama_available():
                break
            log(log_file, "waiting for Ollama... (is the llama icon in the system tray?)")
            time.sleep(5)
        else:
            log(log_file, "❌ Ollama is not running. Open the Ollama app, then start this again.")
            return 1

        started = time.time()
        keep_awake(True)
        try:
            for name in args.jobs:
                script, output = JOBS[name]
                left = args.max_hours - (time.time() - started) / 3600
                if left <= 0.01:
                    log(log_file, f"⏸️  Time cap of {args.max_hours} h reached before job {name}. "
                                  "Start again to continue.")
                    return 0
                code = run_step(log_file, f"JOB {name} (up to {left:.2f} h)", script + ["--max-hours", f"{left:.3f}"])
                if code != 0:
                    log(log_file, f"❌ Job {name} failed - see the messages above. Start again to retry.")
                    return code
                if not job_finished(output):
                    log(log_file, f"⏸️  Job {name} not finished (time cap). Start again to continue.")
                    return 0
        except KeyboardInterrupt:
            log(log_file, "⏸️  Stopped by user. Start again to continue where it stopped.")
            return 1
        finally:
            keep_awake(False)
        log(log_file, "✅ All jobs finished. Next: .venv\\Scripts\\python.exe run_pipeline.py --only evaluate")
        return 0


if __name__ == "__main__":
    sys.exit(main())
