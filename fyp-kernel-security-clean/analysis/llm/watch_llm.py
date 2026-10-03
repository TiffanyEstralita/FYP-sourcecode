#!/usr/bin/env python3
"""
Watch the LLM scoring live: prints each function the model was shown
(the input) and its answer (the output) as soon as the answer is saved.

It only reads the answer cache (results/llm_cache/<version>/), so it never
interferes with a running scoring job. Run it in a second terminal:

    .venv\\Scripts\\python.exe analysis\\llm\\watch_llm.py              # newest prompt version
    .venv\\Scripts\\python.exe analysis\\llm\\watch_llm.py --version v3
    .venv\\Scripts\\python.exe analysis\\llm\\watch_llm.py --no-code    # answers only
    .venv\\Scripts\\python.exe analysis\\llm\\watch_llm.py --last 5     # also show the 5 latest so far

Stop it with Ctrl+C.
"""

import argparse
import json
import sys
import time
from pathlib import Path

# Windows terminals use a non-UTF-8 encoding by default and crash on emoji output
sys.stdout.reconfigure(encoding="utf-8")

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CACHE_PATH = PROJECT_ROOT / "results/llm_cache"
MAX_CODE_LINES = 40   # longer functions are shortened on screen (the model sees all of it)

sys.path.insert(0, str(PROJECT_ROOT / "analysis"))
sys.path.insert(0, str(PROJECT_ROOT / "analysis/llm"))
from callgraph import load_call_graph
from llm_client import function_code


def newest_version():
    folders = [p for p in CACHE_PATH.iterdir() if p.is_dir()] if CACHE_PATH.exists() else []
    return max(folders, key=lambda p: p.stat().st_mtime).name if folders else None


def show(path, graph, with_code, label):
    with open(path, "r") as f:
        answer = json.load(f)
    node = answer["node"]
    info = graph.nodes[node] if node in graph else {}
    print("=" * 78)
    print(f"{label}  {node}   ({info.get('file', '?')}, line {info.get('line', '?')})   "
          f"{answer.get('seconds', '?')} s")
    if with_code and info:
        lines = function_code(info["file"], info["line"]).split("\n")
        print("-" * 30 + " INPUT (code shown to the model) " + "-" * 15)
        for line in lines[:MAX_CODE_LINES]:
            print("   " + line)
        if len(lines) > MAX_CODE_LINES:
            print(f"   ... ({len(lines) - MAX_CODE_LINES} more lines)")
    print("-" * 30 + " OUTPUT (model's answer) " + "-" * 23)
    if answer.get("analysis"):
        print(f"   analysis:      {answer['analysis']}")
    print(f"   risk_score:    {answer.get('risk_score')}   (pattern: {answer.get('pattern')})")
    print(f"   justification: {answer.get('justification')}")
    sys.stdout.flush()


def main():
    parser = argparse.ArgumentParser(description="Watch LLM inputs and outputs live")
    parser.add_argument("--version", help="prompt version folder to watch (default: newest)")
    parser.add_argument("--no-code", action="store_true", help="show answers only")
    parser.add_argument("--last", type=int, default=0, help="first show the N latest answers")
    args = parser.parse_args()

    graph = load_call_graph()
    version = args.version or newest_version()
    print(f"👀 Watching {CACHE_PATH / str(version)}  (Ctrl+C to stop)")

    seen = set()
    count = 0
    first = True
    try:
        while True:
            # follow the newest version automatically unless one was given
            current = args.version or newest_version() or version
            if current != version:
                version = current
                count = 0   # each prompt version scores the same functions again, so restart
                print(f"\n👀 Now watching prompt version {version} (same functions, new prompt)")
            folder = CACHE_PATH / str(version)
            files = sorted(folder.glob("*.json"), key=lambda p: p.stat().st_mtime) if folder.exists() else []
            new = [p for p in files if p not in seen]
            if first:
                seen.update(new[:len(new) - args.last] if args.last else new)
                new = new[len(new) - args.last:] if args.last else []
                count = len(seen)
                print(f"   {count} answers already saved for {version}")
                first = False
            for path in new:
                seen.add(path)
                count += 1
                show(path, graph, not args.no_code, f"{version} #{count}")
            time.sleep(2)
    except KeyboardInterrupt:
        print("\nStopped watching.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
