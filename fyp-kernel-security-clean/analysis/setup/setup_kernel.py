#!/usr/bin/env python3
"""
Phase 1: get the kernel source from git (one version).

Plain idea: instead of a copied folder of one kernel, we keep a real git
clone of the official Linux repository. It is
  - "blobless": the full history (every commit) is downloaded, but file
    contents only when they are actually needed, so it stays small;
  - "sparse":   only the netfilter folders are checked out as files.
Then the one release tag from configs/project.yaml (base_tag) is checked out.
Having the history lets the CVE script ask git questions such as "is this
fix already in v6.12?".

Safe to run again: an existing clone is reused (only the tag is checked out
again). The clone is placed OUTSIDE the project's own git repository
(kernel.clone_dir in configs/project.yaml).

Output: results/raw/kernel_version.json  {"tag", "commit", "date", ...}
"""

import json
import subprocess
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "analysis"))
from config import CONFIG, KERNEL_VERSION_FILE, PATHS, git


def run(cmd):
    print("   $ " + " ".join(cmd), flush=True)
    subprocess.run(cmd, check=True)


def main():
    settings = CONFIG["kernel"]
    tag = settings["base_tag"]
    print("=" * 70)
    print(f"🐧 KERNEL SOURCE: {settings['repo_url']} @ {tag}")
    print(f"   clone folder: {PATHS.kernel}")
    print("=" * 70)

    if not (PATHS.kernel / ".git").exists():
        print("Cloning (blobless + sparse). The first time this downloads the commit")
        print("history (~1-2 GB) and can take 10-30 minutes...")
        PATHS.kernel.parent.mkdir(parents=True, exist_ok=True)
        run(["git", "clone", "--filter=blob:none", "--sparse", "--no-checkout",
             settings["repo_url"], str(PATHS.kernel)])
        # index of the history: makes "is commit X in v6.12?" questions fast
        run(["git", "-C", str(PATHS.kernel), "commit-graph", "write", "--reachable"])
    else:
        print("Existing clone found - reusing it.")

    if sys.platform == "win32":
        # Windows forbids file names such as "aux". The kernel has
        # drivers/.../aux.c, outside our sparse folders (never written to
        # disk), but git refuses the whole checkout unless this check is off.
        run(["git", "-C", str(PATHS.kernel), "config", "core.protectNTFS", "false"])
    run(["git", "-C", str(PATHS.kernel), "sparse-checkout", "set", *settings["sparse_paths"]])
    if not git("tag", "-l", tag):
        print(f"Tag {tag} not in the clone yet - fetching tags...")
        run(["git", "-C", str(PATHS.kernel), "fetch", "--tags", "origin"])
    run(["git", "-C", str(PATHS.kernel), "-c", "advice.detachedHead=false", "checkout", "--force", tag])

    commit = git("rev-parse", f"{tag}^{{commit}}")
    head = git("rev-parse", "HEAD")
    if head != commit:
        print(f"❌ HEAD {head} is not {tag} ({commit})")
        return 1
    if not PATHS.analysed.exists():
        print(f"❌ {PATHS.analysed} missing after checkout")
        return 1

    info = {"tag": tag, "commit": commit,
            "date": git("log", "-1", "--format=%cI", commit),
            "repo_url": settings["repo_url"],
            "sparse_paths": settings["sparse_paths"]}
    KERNEL_VERSION_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(KERNEL_VERSION_FILE, "w") as f:
        json.dump(info, f, indent=2)

    c_files = len(list(PATHS.analysed.rglob("*.c")))
    print(f"\n✅ {tag} = commit {commit} ({info['date']})")
    print(f"✅ {c_files} .c files in {settings['analysed_path']}")
    print(f"💾 Saved: {KERNEL_VERSION_FILE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
