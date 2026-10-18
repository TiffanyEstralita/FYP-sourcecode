"""
Shared helper: read the settings in configs/*.yaml and turn their paths into
real paths.

    from config import CONFIG, PATHS, kernel_info, load_yaml

CONFIG       - configs/project.yaml as a dict
PATHS        - the folders every script uses (kernel clone, results/raw, ...)
load_yaml()  - read another config file, e.g. load_yaml("shortlist.yaml")
kernel_info() - {"tag": "v6.12", "commit": "<full hash>"} of the analysed
               kernel; written into every output file so results can always
               be traced back to the exact source code

Paths in the configs are relative to the project folder
(fyp-kernel-security-clean), so nothing depends on this computer.
"""

import json
import subprocess
from datetime import date
from pathlib import Path
from types import SimpleNamespace

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CONFIG_DIR = PROJECT_ROOT / "configs"


def load_yaml(name):
    with open(CONFIG_DIR / name, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def project_path(relative):
    return (PROJECT_ROOT / relative).resolve()


CONFIG = load_yaml("project.yaml")

_results = project_path(CONFIG["results_dir"])
_kernel = project_path(CONFIG["kernel"]["clone_dir"])
PATHS = SimpleNamespace(
    kernel=_kernel,
    analysed=_kernel / CONFIG["kernel"]["analysed_path"],
    vulns_db=project_path(CONFIG["vulns_db"]),
    results=_results,
    raw=_results / "raw",
    processed=_results / "processed",
    charts=_results / "visualizations",
    llm_cache=_results / "llm_cache",
    validation=project_path(CONFIG["validation_dir"]),
)
KERNEL_VERSION_FILE = PATHS.raw / "kernel_version.json"


def model_release_date():
    value = CONFIG["model_release_date"]
    return value if isinstance(value, date) else date.fromisoformat(str(value))


def git(*args, check=True):
    """Run git inside the kernel clone and return its output (stripped)"""
    result = subprocess.run(["git", "-C", str(PATHS.kernel), *args],
                            capture_output=True, text=True, encoding="utf-8", errors="replace")
    if check and result.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def missing_objects(object_ids):
    """The ids (file contents) not downloaded yet in the blobless clone"""
    if not object_ids:
        return []
    result = subprocess.run(["git", "-C", str(PATHS.kernel), "cat-file", "--batch-check"],
                            input="\n".join(object_ids) + "\n", capture_output=True, text=True)
    return [line.split()[0] for line in result.stdout.splitlines() if line.endswith(" missing")]


def prefetch_objects(object_ids, what="file contents"):
    """
    Download many missing file contents in ONE request. A blobless clone
    otherwise fetches each one separately when first needed, and every
    request to GitHub for the Linux repository takes minutes.
    """
    missing = missing_objects(sorted(set(object_ids)))
    if not missing:
        return 0
    print(f"   downloading {len(missing)} {what} in one batch (GitHub can take ~10 minutes "
          "to start sending)...", flush=True)
    subprocess.run(["git", "-C", str(PATHS.kernel), "-c", "fetch.negotiationAlgorithm=noop", "fetch", "origin",
                    "--no-tags", "--no-write-fetch-head", "--recurse-submodules=no", "--filter=blob:none",
                    "--stdin"], input="\n".join(missing) + "\n", text=True, check=True)
    return len(missing)


def kernel_info():
    """Tag + commit of the analysed kernel (saved by setup_kernel.py)"""
    if KERNEL_VERSION_FILE.exists():
        with open(KERNEL_VERSION_FILE, "r") as f:
            return json.load(f)
    tag = CONFIG["kernel"]["base_tag"]
    return {"tag": tag, "commit": git("rev-parse", f"{tag}^{{commit}}")}


def kernel_label():
    info = kernel_info()
    return f"Linux {info['tag']} (commit {info['commit'][:12]})"
