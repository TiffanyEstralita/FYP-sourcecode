#!/usr/bin/env python3
"""
Phase 2: build the CVE evaluation set for the base kernel version.

Plain idea: for every netfilter CVE we ask git three questions -
  "Which commit fixed it?"          (from the official kernel CVE database)
  "Is the fix already in v6.12?"    (if yes, v6.12 no longer has the bug)
  "Is the bug already in v6.12?"    (the commit named in the fix's
                                     `Fixes:` line must be in v6.12)
Only CVEs whose bug is really present in the analysed code are kept. The
ground truth for each CVE = the functions its fix changes, found in the fix
itself (`git show <fix>`) and then looked up in the base version.

The rules and sizes are in configs/cves.yaml. Everything that cannot be
mapped is listed in the summary, nothing is guessed.

Needs: the kernel clone (setup_kernel.py), the CVE database (data/vulns),
       functions.json and seeds.json (earlier pipeline stages).
       The first run downloads the fix diffs from GitHub (a few minutes);
       they are cached in results/raw/cve_fixes/.

Usage:
    python analysis/validation/build_cve_set.py            # build (reuses the saved split)
    python analysis/validation/build_cve_set.py --resplit  # make a NEW tuning/test split

Output: <validation_dir>/candidates.json, vulnerable_functions.json, summary.txt
        configs/cve_split.yaml (only when it does not exist yet)
"""

import argparse
import json
import random
import re
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime
from pathlib import Path

import yaml

sys.stdout.reconfigure(encoding="utf-8")

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "analysis"))
sys.path.insert(0, str(PROJECT_ROOT / "analysis/extraction"))
from callgraph import FunctionIndex, load_functions
from config import (CONFIG, PATHS, git, kernel_info, load_yaml, model_release_date, prefetch_objects,
                    project_path)
from extract_all_functions import extract_functions
from sources import TEMPLATE_HEADERS, template_uses

SETTINGS = load_yaml("cves.yaml")
SPLIT_FILE = project_path(SETTINGS["split_file"])
SEEDS_FILE = PATHS.processed / "seeds.json"
FIX_CACHE = PATHS.raw / "cve_fixes"
ANALYSED = CONFIG["kernel"]["analysed_path"].rstrip("/") + "/"
GIT_EPOCH = "1da177e4c3f41524e886b7f1b8a0c1fc7321cac2"   # first commit in Linux git history

# Bug type from the official description (first match wins, checked in this order)
BUG_TYPES = [
    ("use-after-free", r"use[- ]after[- ]free|\bUAF\b|double[- ]free"),
    ("out-of-bounds", r"out[- ]of[- ]bounds|\bOOB\b|overflow|underflow|overrun|beyond"),
    ("null-deref", r"null[- ]?(pointer|ptr)?[- ]deref|NULL pointer"),
    ("uninitialized", r"uninit"),
    ("memory-leak", r"memory leak|\bleak"),
    ("race/locking", r"\brace\b|lockdep|deadlock|lock\b|RCU"),
]


def bug_type(text):
    for name, pattern in BUG_TYPES:
        if re.search(pattern, text, re.IGNORECASE):
            return name
    return "other"


# ------------------------------------------------------------------ git questions

def resolve(commit):
    """Full hash of a (possibly short) commit id, or None if not in the clone"""
    out = git("rev-parse", "--verify", "--quiet", f"{commit}^{{commit}}", check=False)
    return out or None


def is_ancestor(commit, tag):
    """True if `commit` is part of `tag` (git merge-base --is-ancestor)"""
    return subprocess.run(["git", "-C", str(PATHS.kernel), "merge-base", "--is-ancestor", commit, tag],
                          capture_output=True).returncode == 0


def fixes_tags(message):
    return re.findall(r"^\s*Fixes:\s*([0-9a-fA-F]{8,40})\b", message, flags=re.M)


def introduced_from_record(dyad_path):
    """Mainline commit(s) that introduced the bug according to the CVE record"""
    if not dyad_path.exists():
        return []
    out = []
    for line in dyad_path.read_text(encoding="utf-8").splitlines():
        if line.startswith("#") or line.count(":") != 3:
            continue
        version, commit, _, _ = line.split(":")
        if version == "0":
            out.append(GIT_EPOCH)
        elif version.count(".") == 1:          # a mainline release such as 6.2
            out.append(commit)
    return out


def cached_git(name, *args):
    """git output, saved in results/raw/cve_fixes/ so later runs need no network"""
    path = FIX_CACHE / name
    if path.exists():
        return path.read_text(encoding="utf-8")
    text = git(*args)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return text


# ------------------------------------------------------------------ ground truth

def changed_old_lines(diff_text):
    """{file path: set of changed line numbers in the PARENT version} from a -U0 diff"""
    changed, current = {}, None
    for line in diff_text.split("\n"):
        if line.startswith("diff --git "):
            current = line.split(" b/", 1)[-1]
            changed.setdefault(current, set())
        m = re.match(r"^@@ -(\d+)(?:,(\d+))? \+\d+(?:,\d+)? @@", line)
        if m and current:
            start, count = int(m.group(1)), int(m.group(2) if m.group(2) is not None else 1)
            if count == 0:      # pure insertion after line `start`
                changed[current].update({start, start + 1})
            else:
                changed[current].update(range(start, start + count))
    return changed


def map_fix(fix, functions, index, template_mtypes):
    """
    Functions of the BASE version changed by the fix.
    Returns (nodes, report). The changed lines are located in the fix's
    parent version (the code the fix was written against), the enclosing
    functions are found there, and their names are looked up in the base.
    """
    diff = cached_git(f"{fix[:12]}.diff", "show", "--format=", "-U0", "--no-color", fix, "--", ANALYSED)
    report = {"files": [], "hunks_outside_function": 0, "functions_not_in_base": [], "skipped_files": []}
    nodes = []
    for path, lines in changed_old_lines(diff).items():
        name = Path(path).name
        if not (path.endswith(".c") or name in TEMPLATE_HEADERS):
            report["skipped_files"].append(path)
            continue
        report["files"].append(path)
        try:
            parent = cached_git(f"{fix[:12]}^__{path.replace('/', '__')}", "show", f"{fix}^:{path}")
        except RuntimeError:
            report["skipped_files"].append(path + " (new file)")
            continue
        tmp = FIX_CACHE / f"{fix[:12]}^__{path.replace('/', '__')}"
        ranges = [(f["line"], f["end_line"], f["name"]) for f in extract_functions(tmp)]
        hit_names = set()
        for ln in lines:
            hits = [n for a, b, n in ranges if a <= ln <= b]
            if hits:
                hit_names.update(hits)
            else:
                report["hunks_outside_function"] += 1
        for fn in sorted(hit_names):
            if name in TEMPLATE_HEADERS:
                # ipset template: mtype_add -> bitmap_ip_add, bitmap_port_add, ...
                found = [index.node_id(fn.replace("mtype_", m + "_", 1), f"{m}@{name}")
                         for m in template_mtypes.get(name, [])
                         if fn.replace("mtype_", m + "_", 1) in index.defined_in.get(f"{m}@{name}", ())]
            else:
                found = [index.node_id(fn, name)] if fn in index.defined_in.get(name, ()) else []
            if not found:
                report["functions_not_in_base"].append(f"{fn} ({name})")
            for node in found:
                if node not in nodes:
                    nodes.append(node)
    return nodes, report


# ------------------------------------------------------------------ main

def main():
    parser = argparse.ArgumentParser(description="Build the CVE evaluation set")
    parser.add_argument("--resplit", action="store_true", help="write a NEW tuning/test split")
    args = parser.parse_args()

    tag = kernel_info()["tag"]
    print("=" * 70)
    print(f"🗂️  CVE SET FOR {tag}  (fix not in {tag}, bug in {tag})")
    print("=" * 70)
    published = PATHS.vulns_db / "cve/published"
    if not published.exists():
        print(f"❌ {published} not found. Download the kernel CVE database first:")
        print("   git clone --depth 1 https://git.kernel.org/pub/scm/linux/security/vulns.git data/vulns")
        return 1
    if not SEEDS_FILE.exists():
        print(f"❌ {SEEDS_FILE} not found - run build_seeds.py first")
        return 1
    with open(SEEDS_FILE) as f:
        seeds = set(json.load(f)["seeds"])

    functions = load_functions()
    index = FunctionIndex(functions)
    template_mtypes = {}
    for _, mtype, header in template_uses():
        template_mtypes.setdefault(header, []).append(mtype)
    release = model_release_date()

    candidates, rejected, unmappable, pending = [], Counter(), [], []
    records = sorted(published.rglob("CVE-*.json"))
    started = time.time()
    print("   step 1/3: which netfilter CVEs have their bug in the base version (local git)...", flush=True)
    for record_path in records:
        record = json.loads(record_path.read_text(encoding="utf-8"))
        cna = record["containers"]["cna"]
        files = sorted({f for a in cna.get("affected", []) for f in a.get("programFiles", [])})
        if not any(f.startswith(ANALYSED) for f in files):
            continue
        cve_id = record_path.stem
        rejected["netfilter CVEs in database"] += 1

        sha_file = record_path.with_suffix(".sha1")
        shas = sha_file.read_text().split() if sha_file.exists() else []
        fix = next((full for full in map(resolve, shas) if full), None)
        if fix is None:
            unmappable.append({"cve_id": cve_id, "reason": "fix commit not found"
                               if shas else "no fix commit in the CVE record", "shas": shas})
            continue
        if is_ancestor(fix, tag):
            rejected["fix already in base (bug gone)"] += 1
            continue

        message = git("log", "-1", "--format=%B", fix)
        tags = fixes_tags(message)
        if tags:
            source = "Fixes: tag"
            introduced = [resolve(t) for t in tags]
            if not any(introduced):
                unmappable.append({"cve_id": cve_id, "reason": "Fixes: commit not found", "fixes": tags})
                continue
        else:
            source = "CVE record (no Fixes: tag)"
            introduced = [resolve(c) for c in introduced_from_record(record_path.with_suffix(".dyad"))]
            if not any(introduced):
                unmappable.append({"cve_id": cve_id, "reason": "no Fixes: tag and no introducing commit"})
                continue
        in_base = [c for c in introduced if c and is_ancestor(c, tag)]
        if not in_base:
            rejected["bug introduced after base"] += 1
            continue
        pending.append((cve_id, cna, files, fix, source, in_base))
    print(f"   step 1/3 done in {time.time() - started:.0f} s: {rejected['netfilter CVEs in database']} "
          f"netfilter CVEs checked, {len(pending)} have their bug in {tag}", flush=True)

    # step 2: download the changed files of ALL these fixes in ONE request
    # (fetching them one by one costs minutes per fix with GitHub)
    step = time.time()
    object_ids = []
    for _, _, _, fix, _, _ in pending:
        for line in git("diff-tree", "-r", "--no-commit-id", f"{fix}^", fix, "--", ANALYSED).splitlines():
            old_id, new_id = line.split()[2:4]
            object_ids += [i for i in (old_id, new_id) if set(i) != {"0"}]
    fetched = prefetch_objects(object_ids, "changed files of the fixes")
    print(f"   step 2/3 done in {time.time() - step:.0f} s: {fetched} files downloaded", flush=True)

    # step 3: map each fix to functions of the base version (local, fast)
    step = time.time()
    for i, (cve_id, cna, files, fix, source, in_base) in enumerate(pending, 1):
        commit_date = datetime.fromisoformat(git("log", "-1", "--format=%cI", fix))
        nodes, report = map_fix(fix, functions, index, template_mtypes)
        seed_nodes = [n for n in nodes if n in seeds]
        kept = [n for n in nodes if n not in seeds]
        description = cna["descriptions"][0]["value"]
        lines = description.split("\n")
        subject = (lines[2] if len(lines) > 2 else lines[0]).strip()
        status = ("usable" if kept and len(kept) <= SETTINGS["max_functions_per_cve"] else
                  "too many functions" if kept else
                  "all changed functions are seeds" if seed_nodes else "no function mapped")
        rejected[f"candidate: {status}"] += 1
        candidates.append({
            "cve_id": cve_id, "subject": subject, "bug_type": bug_type(description),
            "fix_commit": fix, "fix_date": commit_date.isoformat(),
            "after_model_release": commit_date.date() >= release,
            "introduced_by": in_base[0], "introduced_source": source,
            "files": [f for f in files if f.startswith(ANALYSED)],
            "functions": kept, "seed_functions_removed": seed_nodes,
            "mapping": report, "status": status,
            "source": f"https://git.kernel.org/pub/scm/linux/security/vulns.git/tree/cve/published/"
                      f"{cve_id[4:8]}/{cve_id}.json",
        })
        print(f"   [{i:3d}/{len(pending)}] {cve_id:16s} {status:30s} "
              f"{'after ' if candidates[-1]['after_model_release'] else 'before'} {', '.join(kept)[:45]}",
              flush=True)
    print(f"   step 3/3 done in {time.time() - step:.0f} s", flush=True)

    # ---- selection (rule-based, fixed seed) ----
    usable = [c for c in candidates if c["status"] == "usable"]
    after = sorted(c["cve_id"] for c in usable if c["after_model_release"])
    before = sorted(c["cve_id"] for c in usable if not c["after_model_release"])
    size = SETTINGS["target_size"]
    n_before = min(len(before), round(size * SETTINGS["before_share"]))
    n_after = min(len(after), size - n_before)
    n_before = min(len(before), size - n_after)            # fill up if too few "after"
    rng = random.Random(SETTINGS["selection_seed"])
    chosen = sorted(rng.sample(after, n_after) + rng.sample(before, n_before))

    # ---- tuning / test split: written once, before any results exist ----
    if SPLIT_FILE.exists() and not args.resplit:
        with open(SPLIT_FILE) as f:
            split_cfg = yaml.safe_load(f)
        split = {c: "tuning" for c in split_cfg.get("tuning", [])}
        split.update({c: "test" for c in split_cfg.get("test", [])})
        missing = [c for c in chosen if c not in split]
        stale = [c for c in split if c not in chosen]
        if missing or stale:
            print(f"⚠️  {SPLIT_FILE.name} does not match the chosen CVEs "
                  f"(new: {missing}, no longer chosen: {stale}).")
            print("   Kept the saved split for the old CVEs; new ones go to TEST. "
                  "Use --resplit only if no results exist yet.")
            for c in missing:
                split[c] = "test"
        print(f"   using the saved split in {SPLIT_FILE.relative_to(PROJECT_ROOT)}")
    else:
        split_rng = random.Random(SETTINGS["selection_seed"] + 1)
        split = {}
        for group in (sorted(set(chosen) & set(after)), sorted(set(chosen) & set(before))):
            tuning = set(split_rng.sample(group, round(len(group) * SETTINGS["tuning_share"])))
            split.update({c: "tuning" if c in tuning else "test" for c in group})
        with open(SPLIT_FILE, "w", encoding="utf-8") as f:
            f.write("# Tuning / test split of the CVE set - written ONCE by build_cve_set.py\n"
                    f"# on {datetime.now():%Y-%m-%d %H:%M}, before any results existed.\n"
                    "# Settings (fusion weight w, prompt) are chosen on TUNING only;\n"
                    "# TEST is used only for the final numbers. Do not edit by hand.\n")
            f.write(f"# kernel: {kernel_info()['tag']} ({kernel_info()['commit']})\n")
            yaml.safe_dump({"tuning": sorted(c for c in split if split[c] == "tuning"),
                            "test": sorted(c for c in split if split[c] == "test")}, f, sort_keys=False)
        print(f"   NEW split written to {SPLIT_FILE.relative_to(PROJECT_ROOT)}")

    by_id = {c["cve_id"]: c for c in candidates}
    node_info = {index.node_id(fn["name"], file): (fn["name"], file)
                 for file, funcs in functions.items() for fn in funcs}
    cves = {}
    for cve_id in chosen:
        c = by_id[cve_id]
        cves[cve_id] = {
            **{k: c[k] for k in ("cve_id", "subject", "bug_type", "fix_commit", "fix_date",
                                 "after_model_release", "introduced_by", "introduced_source",
                                 "seed_functions_removed", "source")},
            "split": split[cve_id],
            "vulnerable_functions": [{"name": n, "function": node_info[n][0], "file": node_info[n][1],
                                      "verified": True, "how": "changed by the fix"}
                                     for n in c["functions"]],
        }

    # final leakage check (never a seed)
    leaks = [(c, v["name"]) for c, d in cves.items() for v in d["vulnerable_functions"] if v["name"] in seeds]
    if leaks:
        print(f"❌ LEAKAGE: ground-truth functions that are seeds: {leaks}")
        return 1

    PATHS.validation.mkdir(parents=True, exist_ok=True)
    meta = {"kernel": kernel_info(), "built": datetime.now().isoformat(timespec="minutes"),
            "rules": SETTINGS, "model_release_date": str(release)}
    with open(PATHS.validation / "candidates.json", "w") as f:
        json.dump({**meta, "counts": dict(rejected), "candidates": candidates,
                   "unmappable": unmappable}, f, indent=1)
    with open(PATHS.validation / "vulnerable_functions.json", "w") as f:
        json.dump({**meta, "cves": cves}, f, indent=1)

    lines = [f"CVE SET for {kernel_info()['tag']} ({kernel_info()['commit']})", ""]
    lines += [f"{k:45s} {v}" for k, v in rejected.items()]
    lines += ["", f"usable: {len(usable)} ({len(after)} after / {len(before)} before the model release "
              f"{release})", f"chosen: {len(chosen)} ({n_after} after / {n_before} before), "
              f"split {sum(v == 'tuning' for v in split.values())} tuning / "
              f"{sum(v == 'test' for v in split.values())} test", ""]
    for cve_id, c in cves.items():
        lines.append(f"{cve_id:16s} {c['split']:7s} {'after ' if c['after_model_release'] else 'before'} "
                     f"{c['bug_type']:15s} {c['subject'][:60]}")
        lines.append(f"{'':16s} functions: {', '.join(v['name'] for v in c['vulnerable_functions'])}")
    lines += ["", f"CVEs that could not be mapped to a fix commit ({len(unmappable)}):"]
    lines += [f"   {u['cve_id']:16s} {u['reason']}" for u in unmappable]
    not_in_base = [(c["cve_id"], f) for c in candidates for f in c["mapping"]["functions_not_in_base"]]
    lines += ["", f"Changed functions that do not exist in {kernel_info()['tag']} ({len(not_in_base)}):"]
    lines += [f"   {c:16s} {f}" for c, f in not_in_base]
    removed = [(c["cve_id"], s) for c in candidates for s in c["seed_functions_removed"]]
    lines += ["", f"Ground-truth functions removed because they are seeds (leakage rule) ({len(removed)}):"]
    lines += [f"   {c:16s} {s}" for c, s in removed]
    (PATHS.validation / "summary.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines[:8 + 2 * len(cves)]))
    print(f"\n💾 Saved: {PATHS.validation / 'vulnerable_functions.json'} (+ candidates.json, summary.txt)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
