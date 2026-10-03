#!/usr/bin/env python3
"""
Run the whole LLM stage unattended (e.g. overnight). Started by double-clicking
RUN_LLM_OVERNIGHT.bat, or:

    .venv\\Scripts\\python.exe run_llm_unattended.py              # all functions
    .venv\\Scripts\\python.exe run_llm_unattended.py --top 500    # first 500 only

Steps:
  1. prompt practice round  (analysis/llm/tune_prompt.py)
  2. score functions with the winning prompt, most important first
     (analysis/llm/score_functions.py --version best)

- keeps Windows awake while running (laptop must stay plugged in)
- every answer is saved as it arrives; if the run is interrupted, just start
  it again and it continues where it stopped
- everything printed is also written to results/processed/llm_run.log
"""

import argparse
import ctypes
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

# Windows terminals use a non-UTF-8 encoding by default and crash on emoji output
sys.stdout.reconfigure(encoding="utf-8")

PROJECT_ROOT = Path(__file__).resolve().parent
LOG_FILE = PROJECT_ROOT / "results/processed/llm_run.log"

sys.path.insert(0, str(PROJECT_ROOT / "analysis"))
sys.path.insert(0, str(PROJECT_ROOT / "analysis/llm"))
from llm_client import MODEL, ollama_available

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
    log(log_file, f"===== {title}: finished with exit code {process.returncode} =====")
    return process.returncode


def main():
    parser = argparse.ArgumentParser(description="Run the LLM stage unattended")
    parser.add_argument("--top", type=int, help="only score this many functions (most important first)")
    parser.add_argument("--skip-tuning", action="store_true", help="skip the prompt practice round")
    args = parser.parse_args()

    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(LOG_FILE, "a", encoding="utf-8") as log_file:
        log(log_file, f"LLM unattended run started (model {MODEL})")

        # wait up to 2 minutes for Ollama (it may still be starting after a reboot)
        for _ in range(24):
            if ollama_available():
                break
            log(log_file, "waiting for Ollama... (is the llama icon in the system tray?)")
            time.sleep(5)
        else:
            log(log_file, "❌ Ollama is not running. Open the Ollama app, then start this again.")
            return 1

        keep_awake(True)
        try:
            if not args.skip_tuning:
                if run_step(log_file, "STEP 1/2: prompt practice round",
                            ["analysis/llm/tune_prompt.py"]) != 0:
                    log(log_file, "❌ Step 1 failed - see the messages above. Start again to retry.")
                    return 1
            score_args = ["analysis/llm/score_functions.py", "--version", "best"]
            if args.top:
                score_args += ["--top", str(args.top)]
            code = run_step(log_file, "STEP 2/2: score functions with the best prompt", score_args)
        except KeyboardInterrupt:
            log(log_file, "⏸️  Stopped by user. Start again to continue where it stopped.")
            return 1
        finally:
            keep_awake(False)

        log(log_file, "✅ All done." if code == 0 else "❌ Step 2 failed - start again to retry.")
        log(log_file, "Results: results/processed/prompt_tuning_summary.txt, "
                      "llm_scoring_progress.json, llm_scores_<version>.json")
        return code


if __name__ == "__main__":
    sys.exit(main())
