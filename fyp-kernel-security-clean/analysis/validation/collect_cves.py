#!/usr/bin/env python3
"""
Collect netfilter CVEs that are present in the analysed kernel (Linux 6.1.6)
and find the function(s) each fix changed - the ground truth for evaluation.

Source: the Linux kernel CNA's official CVE database
    git clone --depth 1 https://git.kernel.org/pub/scm/linux/security/vulns.git data/vulns

Selection rules (fixed before looking at any ranking results):
  1. the CVE record lists a file under net/netfilter/ as affected
  2. the record's vulnerable:fixed version pairs (.dyad file) show that
     Linux 6.1.6 is affected - introduced before it, fixed after it
  3. the fix changes code inside at least one function of a net/netfilter
     .c file, and that code can be found in our 6.1.6 source

For each CVE the fix patch is downloaded (6.1 stable branch version when one
exists, as it is closest to 6.1.6) and cached in data/vulns_patches/. Each
changed piece of code ("hunk") is located in our 6.1.6 source by matching its
text, and the function around it is recorded. Nothing is guessed: a hunk that
cannot be found is reported as unmapped.

Output: validation/cve_data/candidate_cves_6.1.6.json (+ _summary.txt)
"""

import json
import re
import sys
import time
import urllib.request
from collections import Counter
from pathlib import Path

# Windows terminals use a non-UTF-8 encoding by default and crash on emoji output
sys.stdout.reconfigure(encoding="utf-8")

PROJECT_ROOT = Path(__file__).resolve().parents[2]

VULNS_PATH = PROJECT_ROOT / "data/vulns/cve/published"
PATCH_CACHE = PROJECT_ROOT / "data/vulns_patches"
KERNEL_PATH = PROJECT_ROOT / "data/kernel/linux-shallow"
OUTPUT_PATH = PROJECT_ROOT / "validation/cve_data"

TARGET_VERSION = (6, 1, 6)
PATCH_URL = "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/patch/?id={}"
USER_AGENT = "fyp-kernel-security-research/1.0 (student project; python urllib)"

sys.path.insert(0, str(PROJECT_ROOT / "analysis"))
from callgraph import FunctionIndex, load_functions

# Bug type from the official description (first match wins, checked in this order)
BUG_TYPES = [
    ("use-after-free", r"use[- ]after[- ]free|\bUAF\b|double[- ]free"),
    ("out-of-bounds", r"out[- ]of[- ]bounds|\bOOB\b|overflow|underflow|overrun|beyond"),
    ("null-deref", r"null[- ]?(pointer|ptr)?[- ]deref|NULL pointer"),
    ("uninitialized", r"uninit"),
    ("memory-leak", r"memory leak|\bleak"),
    ("race/locking", r"\brace\b|lockdep|deadlock|lock\b|RCU"),
]


def version(text):
    """'6.1.120' -> (6, 1, 120); '0' (unknown / not fixed) -> (0,)"""
    text = re.sub(r"-rc\d+", "", text)
    if not text or text == "0":
        return (0,)
    return tuple(int(part) for part in text.split("."))


def dyad_pairs(path):
    """[(introduced version, introduced commit, fixed version, fixed commit)]"""
    pairs = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("#") or line.count(":") != 3:
            continue
        v, vc, f, fc = line.split(":")
        pairs.append((version(v), vc, version(f), fc))
    return pairs


def affects_target(pairs):
    """
    Is TARGET_VERSION (6.1.6) vulnerable? Returns (bool, fix commit to use).

    Each .dyad pair is "introduced in version v, fixed in version f" for one
    kernel branch. Versions with two parts (5.11) are main releases; three
    parts (6.1.120) are stable-branch releases. An "introduced" version only
    tells us about 6.1.6 if it is a main release up to 6.1, or a 6.1.x
    release up to 6.1.6 - e.g. "5.4.99 -> 0" (a backport into the old 5.4
    branch, never fixed there) says nothing about 6.1.
    """
    series = TARGET_VERSION[:2]

    def is_main_release(v):
        # 5.11, 6.2 ... and before Linux 3.0 three parts: 2.6.39 (its stable releases were 2.6.39.4)
        return len(v) == 2 or (v[0] == 2 and len(v) == 3)

    def introduced_before_target(v):
        if v == (0,):                 # vulnerable since the code was added
            return True
        if is_main_release(v):
            return v <= series
        return v[:2] == series and v <= TARGET_VERSION

    relevant = [p for p in pairs if introduced_before_target(p[0])]
    same_series = [p for p in pairs if p[2][:2] == series and not is_main_release(p[2])]
    if same_series:   # fixed somewhere in the 6.1.x stable series
        for v, _, f, fc in same_series:
            if introduced_before_target(v) and v <= TARGET_VERSION < f:
                return True, fc
        return False, None
    # never fixed in 6.1.x: vulnerable if introduced before TARGET_VERSION;
    # use the earliest main-release fix commit
    fixes = sorted((p for p in relevant if is_main_release(p[2]) and p[2] > series),
                   key=lambda p: p[2])
    if fixes:
        return True, fixes[0][3]
    return False, None


def bug_type(text):
    for name, pattern in BUG_TYPES:
        if re.search(pattern, text, re.IGNORECASE):
            return name
    return "other"


def fetch_patch(cve_id, commit):
    """Download (once) and return the fix patch text"""
    PATCH_CACHE.mkdir(parents=True, exist_ok=True)
    cached = PATCH_CACHE / f"{cve_id}_{commit[:12]}.patch"
    if not cached.exists():
        # git.kernel.org rejects Python's default user agent
        request = urllib.request.Request(PATCH_URL.format(commit), headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(request, timeout=60) as response:
            cached.write_bytes(response.read())
        time.sleep(0.5)   # be polite to git.kernel.org
    return cached.read_text(encoding="utf-8", errors="ignore")


def parse_patch(text):
    """{file path: [hunk]} where hunk = (old start line, [(kind, text)]),
    kind ' ' = unchanged context, '-' = removed, '+' = added"""
    files = {}
    current = None
    hunk = None
    for line in text.split("\n"):
        if line.startswith("diff --git "):
            current = line.split(" b/", 1)[-1]
            files[current] = []
            hunk = None
        elif line.startswith("@@") and current:
            m = re.match(r"@@ -(\d+)", line)
            hunk = (int(m.group(1)), [])
            files[current].append(hunk)
        elif hunk is not None and line[:1] in (" ", "-", "+") and not line.startswith(("---", "+++")):
            hunk[1].append((line[0], line[1:]))
        elif line.startswith("-- ") or line == "--":
            hunk = None   # end of the patch body
    return files


def locate_hunk(source, hunk):
    """
    Find the hunk's old code (context + removed lines) in `source` (list of
    lines). Returns the 0-based source line numbers of the CHANGED spots, or
    None. Like `patch`, allows dropping up to 3 context lines at each end.
    """
    start, lines = hunk
    old = [(kind, text.rstrip()) for kind, text in lines if kind != "+"]
    # changed spots, as indexes into `old`: removed lines, and for pure
    # additions the old line just before the insertion point
    changed, old_index = set(), -1
    for kind, _ in lines:
        if kind == "+":
            changed.add(max(old_index, 0))
        else:
            old_index += 1
            if kind == "-":
                changed.add(old_index)
    stripped = [line.rstrip() for line in source]

    for fuzz in range(4):
        lo = min(fuzz, len(old))
        hi = len(old) - min(fuzz, len(old) - lo)
        block = [text for _, text in old[lo:hi]]
        if not block or not any(lo <= c < hi for c in changed):
            break
        matches = [i for i in range(len(stripped) - len(block) + 1)
                   if stripped[i:i + len(block)] == block]
        if matches:
            best = min(matches, key=lambda i: abs(i - (start - 1 + lo)))
            return sorted(best + c - lo for c in changed if lo <= c < hi)
    return None


def function_ranges(path, funcs):
    """[(first line, last line, function name)] using brace counting (0-based)"""
    lines = path.read_text(errors="ignore").split("\n")
    ranges = []
    for func in funcs:
        start = func["line"] - 1
        depth, opened = 0, False
        for i in range(start, len(lines)):
            clean = lines[i].split("//")[0]
            depth += clean.count("{") - clean.count("}")
            opened = opened or "{" in clean
            if opened and depth <= 0:
                ranges.append((start, i, func["name"]))
                break
    return ranges


def map_fix(patch_text, functions, index):
    """Which of our 6.1.6 functions does the fix change?"""
    changed = []        # node names
    report = {"hunks": 0, "mapped": 0, "outside_function": 0, "unmapped": 0, "skipped_files": []}
    for path, hunks in parse_patch(patch_text).items():
        name = Path(path).name
        if not (path.startswith("net/netfilter/") and path.endswith(".c")):
            report["skipped_files"].append(path)
            continue
        source_path = KERNEL_PATH / path
        if not source_path.exists() or name not in functions:
            report["unmapped"] += len(hunks)
            report["hunks"] += len(hunks)
            continue
        source = source_path.read_text(errors="ignore").split("\n")
        ranges = function_ranges(source_path, functions[name])
        for hunk in hunks:
            report["hunks"] += 1
            spots = locate_hunk(source, hunk)
            if spots is None:
                report["unmapped"] += 1
                continue
            hits = {fn for spot in spots for (a, b, fn) in ranges if a <= spot <= b}
            if not hits:
                report["outside_function"] += 1
                continue
            report["mapped"] += 1
            for fn in sorted(hits):
                node = index.node_id(fn, name)
                if node not in changed:
                    changed.append(node)
    return changed, report


def main():
    print("=" * 70)
    print(f"🗂️  COLLECT NETFILTER CVEs PRESENT IN LINUX {'.'.join(map(str, TARGET_VERSION))}")
    print("=" * 70)

    if not VULNS_PATH.exists():
        print(f"❌ {VULNS_PATH} not found. Download the kernel CVE database first:")
        print("   git clone --depth 1 https://git.kernel.org/pub/scm/linux/security/vulns.git data/vulns")
        return 1

    functions = load_functions()
    index = FunctionIndex(functions)

    candidates = []
    download_failures = []
    netfilter_total = 0
    for record_path in sorted(VULNS_PATH.rglob("CVE-*.json")):
        record = json.loads(record_path.read_text(encoding="utf-8"))
        cna = record["containers"]["cna"]
        files = sorted({f for a in cna.get("affected", []) for f in a.get("programFiles", [])})
        if not any(f.startswith("net/netfilter/") for f in files):
            continue
        netfilter_total += 1

        dyad = record_path.with_suffix(".dyad")
        if not dyad.exists():
            continue
        affected, fix_commit = affects_target(dyad_pairs(dyad))
        if not affected:
            continue

        cve_id = record_path.stem
        description = cna["descriptions"][0]["value"]
        lines = description.split("\n")
        subject = lines[2] if len(lines) > 2 else lines[0]
        try:
            patch_text = fetch_patch(cve_id, fix_commit)
        except Exception as e:
            print(f"   ⚠️  {cve_id}: could not download fix {fix_commit[:12]}: {e}")
            download_failures.append(cve_id)
            continue
        date = re.search(r"^Date: (.*)$", patch_text, re.MULTILINE)
        changed, report = map_fix(patch_text, functions, index)

        status = "ok" if changed and report["unmapped"] == 0 else \
                 "partial" if changed else \
                 "outside_function" if report["outside_function"] else "unmapped"
        candidates.append({
            "cve_id": cve_id,
            "subject": subject.strip(),
            "bug_type": bug_type(description),
            "fix_commit": fix_commit,
            "fix_date": date.group(1) if date else None,
            "files": [f for f in files if f.startswith("net/netfilter/")],
            "vulnerable_functions": changed,
            "status": status,
            "mapping": report,
            "source": f"https://git.kernel.org/pub/scm/linux/security/vulns.git/tree/cve/published/"
                      f"{cve_id[4:8]}/{cve_id}.json",
        })
        print(f"   {cve_id:16s} {status:16s} {bug_type(description):15s} {', '.join(changed)[:60]}")

    counts = Counter(c["status"] for c in candidates)
    usable = [c for c in candidates if c["vulnerable_functions"]]
    print(f"\n✅ netfilter CVEs in the database:        {netfilter_total}")
    print(f"✅ present in Linux 6.1.6:                {len(candidates) + len(download_failures)}")
    if download_failures:
        print(f"⚠️  fix download failed (rerun to retry):  {len(download_failures)}")
    print(f"   status: " + ", ".join(f"{k}={v}" for k, v in counts.most_common()))
    print(f"✅ usable (at least one function found):  {len(usable)}")
    print(f"   bug types: " + ", ".join(f"{k}={v}" for k, v in
                                       Counter(c['bug_type'] for c in usable).most_common()))

    OUTPUT_PATH.mkdir(parents=True, exist_ok=True)
    out_json = OUTPUT_PATH / "candidate_cves_6.1.6.json"
    with open(out_json, "w") as f:
        json.dump({"kernel_version": ".".join(map(str, TARGET_VERSION)),
                   "netfilter_cves_in_database": netfilter_total,
                   "candidates": candidates}, f, indent=2)
    print(f"\n💾 Saved: {out_json}")

    out_txt = OUTPUT_PATH / "candidate_cves_6.1.6_summary.txt"
    with open(out_txt, "w", encoding="utf-8") as f:
        f.write(f"NETFILTER CVEs PRESENT IN LINUX 6.1.6\n\n")
        f.write(f"netfilter CVEs in database: {netfilter_total}\npresent in 6.1.6: {len(candidates)}\n")
        f.write("status: " + ", ".join(f"{k}={v}" for k, v in counts.most_common()) + "\n\n")
        for c in candidates:
            f.write(f"{c['cve_id']:16s} {c['status']:16s} {c['bug_type']:15s} {c['subject']}\n")
            f.write(f"{'':16s} functions: {', '.join(c['vulnerable_functions']) or '-'}\n")
    print(f"💾 Saved: {out_txt}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
