"""
Shared helper: ask the local Ollama model to risk-score one function.

  score_function(graph, node, version)  ->  {"risk_score": ..., "pattern": ..., ...}

- the function's full source is cut out of the kernel file (or the expanded
  ipset template) by brace counting, starting at its definition line
- the prompt comes from configs/prompts.yaml (one template per version)
- temperature 0 and a fixed seed, so the answer is repeatable
- the answer must be JSON with a valid risk_score and pattern; one retry
  on a bad answer, then it is recorded as an error
- every answer is CACHED in results/llm_cache/<version>/, keyed by a hash of
  model + prompt text, so the same question is never asked twice and reruns
  are instant. `repeat` > 0 asks again with a different seed (stability check).
"""

import hashlib
import json
import sys
import time
from pathlib import Path

import requests
import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]

PROMPTS_FILE = PROJECT_ROOT / "configs/prompts.yaml"
OLLAMA_CONFIG_FILE = PROJECT_ROOT / "configs/ollama.yaml"
CACHE_PATH = PROJECT_ROOT / "results/llm_cache"

with open(OLLAMA_CONFIG_FILE, "r") as _f:
    _ollama = yaml.safe_load(_f)
MODEL = _ollama["model"]
OLLAMA_HOST = _ollama["host"].rstrip("/")
OLLAMA_URL = f"{OLLAMA_HOST}/api/chat"
CONTEXT_TOKENS = 16384        # room for long functions + the answer
MAX_CODE_CHARS = 40000        # ~10k tokens; longer functions are cut (and marked)

sys.path.insert(0, str(PROJECT_ROOT / "analysis"))
from sources import find_source


def load_prompts():
    with open(PROMPTS_FILE, "r") as f:
        return yaml.safe_load(f)


def function_code(file, line):
    """Full source of the function defined at `line` (1-based) in `file`"""
    lines = find_source(file).read_text(errors="ignore").split("\n")
    out, depth, opened = [], 0, False
    for text in lines[line - 1:]:
        out.append(text)
        clean = text.split("//")[0]
        depth += clean.count("{") - clean.count("}")
        opened = opened or "{" in clean
        if opened and depth <= 0:
            break
    code = "\n".join(out)
    if len(code) > MAX_CODE_CHARS:
        code = code[:MAX_CODE_CHARS] + "\n/* ... function truncated for length ... */"
    return code


def build_prompt(prompts, version, name, file, code):
    template = prompts["versions"][version]["template"]
    return template.format(name=name, file=file, code=code,
                           patterns=" | ".join(prompts["patterns"]))


def validate(answer, scale, patterns):
    """Return a clean result dict, or raise ValueError"""
    data = json.loads(answer)
    score = data.get("risk_score")
    if isinstance(score, str) and score.strip().isdigit():
        score = int(score)
    if not isinstance(score, (int, float)) or not 0 <= score <= scale:
        raise ValueError(f"risk_score missing or out of range: {score!r}")
    pattern = str(data.get("pattern", "")).strip()
    if pattern not in patterns:
        pattern = "other"
    return {"risk_score": float(score), "risk": float(score) / scale, "pattern": pattern,
            "justification": str(data.get("justification", "")).strip(),
            "analysis": str(data.get("analysis", "")).strip()}


def ask_ollama(prompt, seed):
    response = requests.post(OLLAMA_URL, timeout=900, json={
        "model": MODEL, "stream": False, "format": "json",
        "options": {"temperature": 0, "seed": seed, "num_ctx": CONTEXT_TOKENS},
        "messages": [{"role": "user", "content": prompt}],
    })
    response.raise_for_status()
    return response.json()["message"]["content"]


def score_function(graph, node, version, prompts=None, repeat=0):
    """Risk-score one function (graph node). Uses the cache when possible."""
    prompts = prompts or load_prompts()
    info = graph.nodes[node]
    code = function_code(info["file"], info["line"])
    prompt = build_prompt(prompts, version, info["name"], info["file"], code)
    scale = prompts["versions"][version]["scale"]

    key = hashlib.sha256(f"{MODEL}\n{repeat}\n{prompt}".encode()).hexdigest()[:24]
    cache_file = CACHE_PATH / version / f"{key}.json"
    if cache_file.exists():
        with open(cache_file, "r") as f:
            return json.load(f)

    result = {"node": node, "version": version, "model": MODEL, "repeat": repeat}
    started = time.time()
    for attempt in range(2):   # one retry on a bad answer
        try:
            answer = ask_ollama(prompt, seed=42 + repeat + 1000 * attempt)
            result.update(validate(answer, scale, prompts["patterns"]))
            result.pop("error", None)
            break
        except (ValueError, json.JSONDecodeError) as e:
            result["error"] = f"bad answer: {e}"
            result["raw_answer"] = answer[:500]
    result["seconds"] = round(time.time() - started, 1)
    result["code_chars"] = len(code)

    if "error" not in result:   # bad answers are not cached, so a rerun retries them
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        with open(cache_file, "w") as f:
            json.dump(result, f, indent=2)
    return result


def ollama_available():
    try:
        tags = requests.get(f"{OLLAMA_HOST}/api/tags", timeout=5).json()
        return any(m["name"] == MODEL for m in tags.get("models", []))
    except requests.RequestException:
        return False
