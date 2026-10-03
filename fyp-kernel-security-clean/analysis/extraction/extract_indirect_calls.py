#!/usr/bin/env python3
"""
SCRIPT #2b: Extract Indirect Calls (function pointers)
Purpose: Add the call-graph edges that extract_function_calls.py cannot see.

Netfilter often calls functions through a "switchboard" instead of by name:

  1. A function is REGISTERED in a struct field:
         static const struct nft_expr_ops nft_payload_ops = {
             .eval = nft_payload_eval,
  2. Other code later DISPATCHES through that field without naming it:
         expr->ops->eval(expr, regs, pkt);

For every function that contains a dispatch `->eval(`, we add an edge to
every function registered in an `.eval` field. This is "field-based"
resolution: it matches on the field NAME only, not the struct type, so it
can add some edges that never happen at runtime (an over-approximation),
but it does not miss real ones.

ipset special case: generic code in ip_set_*_gen.h registers `mtype_uadt`,
and each .c file that includes the header sets `#define MTYPE bitmap_ip`,
so `mtype_uadt` really means `bitmap_ip_uadt`. We resolve that here.

Output: results/raw/indirect_calls.json (+ indirect_calls_summary.txt)
"""

import json
import re
import sys
from collections import defaultdict
from pathlib import Path

# Windows terminals use a non-UTF-8 encoding by default and crash on emoji output
sys.stdout.reconfigure(encoding="utf-8")

PROJECT_ROOT = Path(__file__).resolve().parents[2]

KERNEL_PATH = PROJECT_ROOT / "data/kernel/linux-shallow"
NETFILTER_PATH = KERNEL_PATH / "net/netfilter"
FUNCTIONS_FILE = PROJECT_ROOT / "results/raw/functions_v2.json"
DIRECT_CALLS_FILE = PROJECT_ROOT / "results/raw/function_calls_v2.json"
OUTPUT_PATH = PROJECT_ROOT / "results/raw"

# `.eval = nft_payload_eval,`  (struct initializer, one per line in kernel style)
INIT_PATTERN = re.compile(r'^\s*\.(\w+)\s*=\s*&?(\w+)\s*,?\s*(?:/[*/].*)?$')
# `ops->eval = nft_payload_eval;`  (assigned at runtime)
RUNTIME_PATTERN = re.compile(r'(?:->|\.)(\w+)\s*=\s*&?(\w+)\s*;')
# `expr->ops->eval(`  (call through a field)
DISPATCH_PATTERN = re.compile(r'->\s*(\w+)\s*\(')
MTYPE_PATTERN = re.compile(r'#define\s+MTYPE\s+(\w+)')
INCLUDE_PATTERN = re.compile(r'#include\s+"([\w.]+\.h)"')


def read_lines(path):
    return path.read_text(errors="ignore").split("\n")


def strip_comment(line):
    return line.split("//")[0]


def find_registrations(known):
    """
    Return {field: set(function names)} for every `.field = function`.
    Template names (mtype_*) found in headers are returned separately as
    {header file name: [(field, template name)]} so they can be resolved
    per .c file afterwards.
    """
    field_targets = defaultdict(set)
    templates = defaultdict(list)

    for path in sorted(NETFILTER_PATH.rglob("*.[ch]")):
        for line in read_lines(path):
            line = strip_comment(line)
            matches = []
            m = INIT_PATTERN.match(line)
            if m:
                matches.append(m.groups())
            matches.extend(RUNTIME_PATTERN.findall(line))

            for field, target in matches:
                if target.startswith("mtype_"):
                    templates[path.name].append((field, target))
                elif target in known:
                    field_targets[field].add(target)

    return field_targets, templates


def resolve_templates(field_targets, templates, known):
    """mtype_uadt + `#define MTYPE bitmap_ip` -> bitmap_ip_uadt"""
    resolved = 0
    for path in sorted(NETFILTER_PATH.rglob("*.c")):
        text = path.read_text(errors="ignore")
        mtypes = MTYPE_PATTERN.findall(text)
        if not mtypes:
            continue
        for header in INCLUDE_PATTERN.findall(text):
            for field, template in templates.get(Path(header).name, []):
                for mtype in mtypes:
                    real = mtype + template[len("mtype"):]
                    if real in known and real not in field_targets[field]:
                        field_targets[field].add(real)
                        resolved += 1
    return resolved


def function_body(lines, start_index):
    """Lines of a function body, found by brace counting (same idea as SCRIPT #2)"""
    body = []
    depth = 0
    opened = False
    for line in lines[start_index:]:
        clean = strip_comment(line)
        depth += clean.count("{") - clean.count("}")
        if "{" in clean:
            opened = True
        if opened:
            body.append(clean)
            if depth <= 0:
                break
    return body


def find_dispatches(functions, field_targets):
    """Return {caller: set(fields)} for every `->field(` whose field has registrations"""
    dispatches = defaultdict(set)
    for filename, funcs in functions.items():
        matches = list(NETFILTER_PATH.rglob(filename))
        if not matches:
            continue
        lines = read_lines(matches[0])
        for func in funcs:
            for line in function_body(lines, func["line"] - 1):
                for field in DISPATCH_PATTERN.findall(line):
                    if field in field_targets:
                        dispatches[func["name"]].add(field)
    return dispatches


def load_direct_edges():
    with open(DIRECT_CALLS_FILE, "r") as f:
        calls = json.load(f)
    return {(caller, callee)
            for file_calls in calls.values()
            for caller, callees in file_calls.items()
            for callee in callees}


def main():
    print("=" * 70)
    print("🔀 INDIRECT CALL EXTRACTION (function pointers)")
    print("=" * 70)

    for required in (FUNCTIONS_FILE, DIRECT_CALLS_FILE):
        if not required.exists():
            print(f"❌ Missing required input: {required}")
            return 1

    with open(FUNCTIONS_FILE, "r") as f:
        functions = json.load(f)
    known = {func["name"] for funcs in functions.values() for func in funcs}

    field_targets, templates = find_registrations(known)
    template_count = resolve_templates(field_targets, templates, known)
    dispatches = find_dispatches(functions, field_targets)
    direct_edges = load_direct_edges()

    # caller -> every function registered in a field the caller dispatches through
    edges = defaultdict(set)
    for caller, fields in dispatches.items():
        for field in fields:
            for target in field_targets[field]:
                if target != caller and (caller, target) not in direct_edges:
                    edges[caller].add(target)

    total_edges = sum(len(t) for t in edges.values())
    registrations = sum(len(t) for t in field_targets.values())
    biggest = sorted(field_targets.items(), key=lambda x: len(x[1]), reverse=True)[:15]

    stats = {
        "fields_with_registrations": len(field_targets),
        "registrations": registrations,
        "ipset_template_registrations_resolved": template_count,
        "functions_with_dispatch": len(dispatches),
        "new_indirect_edges": total_edges,
        "direct_edges": len(direct_edges),
        "largest_fields": [[field, len(t)] for field, t in biggest],
    }

    print(f"✅ Registrations (.field = function):   {registrations} across {len(field_targets)} fields")
    print(f"   of which ipset mtype_* templates:     {template_count}")
    print(f"✅ Functions that dispatch (->field()): {len(dispatches)}")
    print(f"✅ NEW indirect edges:                   {total_edges}  (direct edges: {len(direct_edges)})")

    OUTPUT_PATH.mkdir(parents=True, exist_ok=True)
    out_json = OUTPUT_PATH / "indirect_calls.json"
    with open(out_json, "w") as f:
        json.dump({
            "stats": stats,
            "edges": {c: sorted(t) for c, t in sorted(edges.items())},
            "dispatches": {c: sorted(fl) for c, fl in sorted(dispatches.items())},
            "field_targets": {fl: sorted(t) for fl, t in sorted(field_targets.items())},
        }, f, indent=2)
    print(f"\n💾 Saved: {out_json}")

    out_txt = OUTPUT_PATH / "indirect_calls_summary.txt"
    with open(out_txt, "w") as f:
        f.write("=" * 70 + "\n")
        f.write("INDIRECT CALL EXTRACTION (function pointers)\n")
        f.write("=" * 70 + "\n\n")
        f.write("Field-based resolution: a call through ->field() is linked to every\n")
        f.write("function registered as .field = fn (matched on field name only).\n\n")
        f.write(f"Registrations (.field = function):  {registrations} across {len(field_targets)} fields\n")
        f.write(f"ipset mtype_* templates resolved:   {template_count}\n")
        f.write(f"Functions that dispatch:            {len(dispatches)}\n")
        f.write(f"New indirect edges:                 {total_edges}\n")
        f.write(f"Direct edges (for comparison):      {len(direct_edges)}\n")
        f.write("\nFields with the most registered functions (biggest fan-out):\n")
        for field, targets in biggest:
            f.write(f"   .{field:20s} {len(targets):4d} functions\n")
    print(f"💾 Saved: {out_txt}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
