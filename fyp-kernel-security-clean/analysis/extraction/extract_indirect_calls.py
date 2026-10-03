#!/usr/bin/env python3
"""
SCRIPT #2b: Extract Indirect Calls (function pointers)
Purpose: Add the call-graph edges that extract_function_calls.py cannot see.

Netfilter often calls functions through a "switchboard" instead of by name:

  1. A function is REGISTERED in a struct field ("slot"):
         static const struct nft_expr_ops nft_payload_ops = {
             .eval = nft_payload_eval,
  2. Other code later DISPATCHES through that field without naming it:
         expr->ops->eval(expr, regs, pkt);

For every function that dispatches through `->eval(`, we add an edge to
every function registered in an `.eval` slot. This is "field-based"
resolution: it matches on the field NAME only, not the struct type, so it
can add some edges that never happen at runtime (an over-approximation),
but it does not miss real ones.

Registrations are found in four forms:
  - struct initializer     .eval = nft_payload_eval,
  - runtime assignment     ops->eval = nft_payload_eval;
  - slot table             .adt = { [IPSET_ADD] = bitmap_ip_add, ... }
                           (dispatched as  set->variant->adt[adt] )
  - hand-off via argument  nf_ct_helper_init(..., help, ...)  where
                           nf_ct_helper_init does  helper->help = help;
A function that directly calls a function pointer it was handed
(  iter(...)  where iter is a parameter) gets an edge to every function
passed in that argument position - also when it reaches it through a chain
of helpers that pass the parameter on.

ipset templates (ip_set_*_gen.h, `mtype_add` -> `bitmap_ip_add`) are read
from the expanded copies made by analysis/sources.py.

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

FUNCTIONS_FILE = PROJECT_ROOT / "results/raw/functions_v2.json"
DIRECT_CALLS_FILE = PROJECT_ROOT / "results/raw/function_calls_v2.json"
OUTPUT_PATH = PROJECT_ROOT / "results/raw"

sys.path.insert(0, str(PROJECT_ROOT / "analysis"))
from callgraph import FunctionIndex, load_functions, load_call_graph
from sources import (NETFILTER_PATH, TEMPLATE_HEADERS, all_source_files, compilation_units,
                     find_source)

# `.eval = nft_payload_eval,`  (struct initializer, one per line in kernel style)
INIT_PATTERN = re.compile(r'^\s*\.(\w+)\s*=\s*&?(\w+)\s*,?\s*(?:/[*/].*)?$')
# `ops->eval = nft_payload_eval;`  (assigned at runtime)
RUNTIME_PATTERN = re.compile(r'(?:->|\.)(\w+)\s*=\s*&?(\w+)\s*;')
# `.adt = {`  opens a slot table; `[IPSET_ADD] = bitmap_ip_add,` is one entry
TABLE_OPEN_PATTERN = re.compile(r'^\s*\.(\w+)\s*=\s*\{\s*$')
TABLE_ENTRY_PATTERN = re.compile(r'^\s*\[[^\]]+\]\s*=\s*&?(\w+)\s*,?\s*$')
# `expr->ops->eval(` or `set->variant->adt[`  (use of a slot)
DISPATCH_PATTERN = re.compile(r'->\s*(\w+)\s*[(\[]')
# ipset: `set->variant->adt[` - a set type's own code only ever handles sets of
# its own type, so this means the slot of the caller's own set type
VARIANT_DISPATCH_PATTERN = re.compile(r'->\s*variant\s*->\s*(\w+)\s*[(\[]')
CALL_PATTERN = re.compile(r'\b(\w+)\s*\(')
IDENTIFIER = re.compile(r'^&?\s*(\w+)$')


def read_lines(path):
    return path.read_text(errors="ignore").split("\n")


def strip_comment(line):
    return line.split("//")[0]


def registration_files():
    """.c files, expanded ipset templates, and other netfilter headers"""
    headers = [p for p in sorted(NETFILTER_PATH.rglob("*.h")) if p.name not in TEMPLATE_HEADERS]
    return all_source_files() + headers


def find_registrations(index):
    """Return {field: set(node names)} for struct initializers, runtime assignments
    and slot tables"""
    field_targets = defaultdict(set)

    for path in registration_files():
        table_field = None
        for line in read_lines(path):
            line = strip_comment(line)

            opened = TABLE_OPEN_PATTERN.match(line)
            if opened:
                table_field = opened.group(1)
                continue

            matches = []
            entry = TABLE_ENTRY_PATTERN.match(line)
            if table_field and entry:
                matches.append((table_field, entry.group(1)))
            elif "}" in line:
                table_field = None

            m = INIT_PATTERN.match(line)
            if m:
                matches.append(m.groups())
            matches.extend(RUNTIME_PATTERN.findall(line))

            for field, target in matches:
                # `.help = help` in nf_conntrack_ftp.c means THAT file's help()
                node = index.resolve(target, path.name)
                if node:
                    field_targets[field].add(node)

    return field_targets


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


def split_top_level(text):
    """Split 'a, f(b, c), d' on commas that are not inside brackets"""
    parts, depth, current = [], 0, ""
    for ch in text:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(current)
            current = ""
        else:
            current += ch
    parts.append(current)
    return [p.strip() for p in parts]


def bracket_contents(text, open_pos):
    """Text between the '(' at open_pos and its matching ')' (None if unbalanced)"""
    depth = 0
    for pos in range(open_pos, len(text)):
        if text[pos] == "(":
            depth += 1
        elif text[pos] == ")":
            depth -= 1
            if depth == 0:
                return text[open_pos + 1:pos]
    return None


def parameter_names(lines, start_index):
    """Parameter names of the function defined at start_index"""
    signature = ""
    for line in lines[start_index:start_index + 12]:
        signature += " " + strip_comment(line)
        if "{" in line:
            break
    inside = bracket_contents(signature, signature.find("("))
    if inside is None:
        return []
    names = []
    for param in split_top_level(inside):
        pointer = re.search(r'\(\s*\*\s*(\w+)\s*\)', param)   # int (*help)(...)
        words = re.findall(r'\w+', re.sub(r'\[.*?\]', '', param))
        names.append(pointer.group(1) if pointer else (words[-1] if words else ""))
    return names


class SourceFunctions:
    """Body text and parameter names of every extracted function"""

    def __init__(self, index):
        self.items = []   # (node, file, body lines, parameter names)
        for filename, funcs in index.functions.items():
            path = find_source(filename)
            if path is None:
                continue
            lines = read_lines(path)
            for func in funcs:
                self.items.append((index.node_id(func["name"], filename), filename,
                                   function_body(lines, func["line"] - 1),
                                   parameter_names(lines, func["line"] - 1)))


def find_dispatches(functions, field_targets):
    """
    Return ({caller node: set(fields)}, set of (caller node, field)) for every
    `->field(` / `->field[` whose field has registrations. The second value
    lists the ipset `->variant->field` uses (see VARIANT_DISPATCH_PATTERN).
    """
    dispatches = defaultdict(set)
    variant = set()
    for node, _, body, _ in functions.items:
        for line in body:
            for field in DISPATCH_PATTERN.findall(line):
                if field in field_targets:
                    dispatches[node].add(field)
            for field in VARIANT_DISPATCH_PATTERN.findall(line):
                variant.add((node, field))
    return dispatches, variant


def dispatch_targets(caller, field, field_targets, variant, unit_of):
    """Functions a dispatch through `field` inside `caller` may reach"""
    targets = field_targets[field]
    if (caller, field) in variant:
        own = {t for t in targets if unit_of[t] == unit_of[caller]}
        if own:   # the caller's own set type registers this slot -> only those
            return own
    return targets


def call_sites(index, functions):
    """Yield (caller node, callee node, [arguments]) for every call in every body"""
    for node, filename, body, _ in functions.items:
        text = "\n".join(body)
        for m in CALL_PATTERN.finditer(text):
            callee = index.resolve(m.group(1), filename)
            if callee is None:
                continue
            inside = bracket_contents(text, m.end() - 1)
            if inside is not None:
                yield node, filename, callee, split_top_level(inside)


def find_handoffs(index, functions):
    """
    For functions that take a function pointer as a parameter, record what
    they do with it:
        stores[node][i]   = {fields}       parameter i is stored:  x->help = help;
        calls[node]       = {i, ...}       parameter i is called:  iter(...);
        forwards[node][i] = {(g, j), ...}  parameter i is passed on as
                                           argument j of g:  g(..., iter, ...)
    """
    stores = defaultdict(lambda: defaultdict(set))
    calls = defaultdict(set)
    forwards = defaultdict(lambda: defaultdict(set))
    params_of = {}
    for node, _, body, params in functions.items:
        params_of[node] = params
        text = "\n".join(body)
        for i, param in enumerate(params):
            if not param:
                continue
            for field, value in RUNTIME_PATTERN.findall(text):
                if value == param:
                    stores[node][i].add(field)
            if re.search(r'(?<![\w.>])%s\s*\(' % re.escape(param), text):
                calls[node].add(i)

    for caller, _, callee, args in call_sites(index, functions):
        params = params_of.get(caller, [])
        for j, arg in enumerate(args):
            ident = IDENTIFIER.match(arg)
            if ident and ident.group(1) in params:
                forwards[caller][params.index(ident.group(1))].add((callee, j))
    return stores, calls, forwards


def apply_handoffs(index, functions, stores, calls, forwards, field_targets):
    """
    At every call site `f(a, b, c)`, if an argument is a function, follow
    where f sends that parameter (stored, called, or passed on through a
    chain of helpers) and register the function in the slot (stored) or add
    an edge from the helper that finally calls it (called).
    Returns (number of slot registrations added, set of direct-callback edges).
    """
    registered = 0
    callback_edges = set()
    for _, filename, callee, args in call_sites(index, functions):
        for i, arg in enumerate(args):
            ident = IDENTIFIER.match(arg)
            target = index.resolve(ident.group(1), filename) if ident else None
            if not target:
                continue
            # walk the chain of helpers the argument is passed through
            todo, seen = [(callee, i)], set()
            while todo:
                f, k = todo.pop()
                if (f, k) in seen:
                    continue
                seen.add((f, k))
                for field in stores.get(f, {}).get(k, ()):
                    if target not in field_targets[field]:
                        field_targets[field].add(target)
                        registered += 1
                if k in calls.get(f, ()):
                    callback_edges.add((f, target))
                todo.extend(forwards.get(f, {}).get(k, ()))
    return registered, callback_edges


def main():
    print("=" * 70)
    print("🔀 INDIRECT CALL EXTRACTION (function pointers)")
    print("=" * 70)

    for required in (FUNCTIONS_FILE, DIRECT_CALLS_FILE):
        if not required.exists():
            print(f"❌ Missing required input: {required}")
            return 1

    index = FunctionIndex(load_functions())
    functions = SourceFunctions(index)

    field_targets = find_registrations(index)
    slot_registrations = sum(len(t) for t in field_targets.values())
    stores, calls, forwards = find_handoffs(index, functions)
    handoff_registrations, callback_edges = apply_handoffs(index, functions, stores, calls,
                                                           forwards, field_targets)
    dispatches, variant = find_dispatches(functions, field_targets)
    direct_edges = set(load_call_graph(include_indirect=False).edges())

    # node -> the .c file it is compiled in (ipset template copies -> their .c file)
    units = compilation_units()
    unit_of = {node: units.get(filename, filename) for node, filename, _, _ in functions.items}

    # caller -> every function registered in a field the caller dispatches through
    candidate = {(caller, target)
                 for caller, fields in dispatches.items()
                 for field in fields
                 for target in dispatch_targets(caller, field, field_targets, variant, unit_of)}
    candidate |= callback_edges
    edges = defaultdict(set)
    for caller, target in candidate:
        if caller != target and (caller, target) not in direct_edges:
            edges[caller].add(target)

    total_edges = sum(len(t) for t in edges.values())
    registrations = sum(len(t) for t in field_targets.values())
    biggest = sorted(field_targets.items(), key=lambda x: len(x[1]), reverse=True)[:15]

    stats = {
        "fields_with_registrations": len(field_targets),
        "registrations": registrations,
        "registrations_from_slots": slot_registrations,
        "registrations_from_argument_handoff": handoff_registrations,
        "callback_edges_from_argument_handoff": len(callback_edges),
        "functions_with_dispatch": len(dispatches),
        "new_indirect_edges": total_edges,
        "direct_edges": len(direct_edges),
        "largest_fields": [[field, len(t)] for field, t in biggest],
    }

    print(f"✅ Registrations:                       {registrations} across {len(field_targets)} fields")
    print(f"   from slots / slot tables:             {slot_registrations}")
    print(f"   from hand-off via argument:           {handoff_registrations}")
    print(f"✅ Callbacks called by the receiver:     {len(callback_edges)}")
    print(f"✅ Functions that dispatch (->field):    {len(dispatches)}")
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
        f.write("Field-based resolution: a use of ->field( or ->field[ is linked to every\n")
        f.write("function registered in a .field slot (matched on field name only).\n\n")
        f.write(f"Registrations:                       {registrations} across {len(field_targets)} fields\n")
        f.write(f"   from slots / slot tables:          {slot_registrations}\n")
        f.write(f"   from hand-off via argument:        {handoff_registrations}\n")
        f.write(f"Callbacks called by the receiver:    {len(callback_edges)}\n")
        f.write(f"Functions that dispatch:             {len(dispatches)}\n")
        f.write(f"New indirect edges:                  {total_edges}\n")
        f.write(f"Direct edges (for comparison):       {len(direct_edges)}\n")
        f.write("\nFields with the most registered functions (biggest fan-out):\n")
        for field, targets in biggest:
            f.write(f"   .{field:20s} {len(targets):4d} functions\n")
    print(f"💾 Saved: {out_txt}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
