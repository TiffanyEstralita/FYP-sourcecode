#!/usr/bin/env python3
"""
SCRIPT #2b: Extract Indirect Calls (function pointers) - TYPED version
Purpose: Add the call-graph edges that extract_function_calls.py cannot see.

Netfilter often calls functions through a "switchboard" instead of by name:

  1. A function is REGISTERED in a field of a struct:
         static const struct nft_expr_ops nft_payload_ops = {
             .eval = nft_payload_eval,
  2. Other code later DISPATCHES through that field without naming it:
         expr->ops->eval(expr, regs, pkt);

Old rule (until v3 of the brief): link `->eval(` to EVERY function in ANY
`.eval` field - many edges that can never happen.
New rule: work out the struct type of `expr->ops` (expr is a
`struct nft_expr *`, its field `ops` is a `struct nft_expr_ops *`) and link
only to functions registered in `.eval` of a `struct nft_expr_ops`. Only if
the type cannot be worked out, fall back to the old name-only rule; how
often that happens is counted and reported.

Registrations are found in these forms:
  - struct initializer     .eval = nft_payload_eval,   (incl. arrays of
                           structs and slot tables .adt = { [IPSET_ADD] = f })
  - runtime assignment     ops->eval = nft_payload_eval;
  - copy between fields    entry->hook = reg->hook;    (the first field gets
                           everything registered in the second)
  - hand-off via argument  nf_ct_helper_init(..., help, ...)  where
                           nf_ct_helper_init does  helper->help = help;
A function that calls a function pointer it was handed (iter(...), iter a
parameter) gets an edge to every function passed in that position.
Callbacks given to core kernel APIs (nf_register_net_hook, nfnetlink
callback tables, netlink dump callbacks, timers, work items) are added by
the rules in configs/callgraph.yaml.

For comparison the old name-only edges are saved too
(indirect_calls_name_only.json, used by analysis/callgraph/graph_report.py).

Output: results/raw/indirect_calls.json (+ indirect_calls_summary.txt,
        indirect_calls_name_only.json)
"""

import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

# Windows terminals use a non-UTF-8 encoding by default and crash on emoji output
sys.stdout.reconfigure(encoding="utf-8")

PROJECT_ROOT = Path(__file__).resolve().parents[2]

sys.path.insert(0, str(PROJECT_ROOT / "analysis"))
sys.path.insert(0, str(PROJECT_ROOT / "analysis/extraction"))
from c_types import (Scope, StructTable, body_variables, expression_type, initializer_registrations,
                     match_forward, operand_before, parameter_variables, return_struct_type,
                     split_top_level, strip_comments, strip_strings)
from callgraph import (DIRECT_CALLS_FILE, FUNCTIONS_FILE, INDIRECT_CALLS_FILE, FunctionIndex,
                       load_call_graph, load_functions)
from config import CONFIG, PATHS, git, kernel_info, load_yaml, prefetch_objects
from sources import NETFILTER_PATH, TEMPLATE_HEADERS, all_source_files, compilation_units, find_source

OUTPUT_PATH = PATHS.raw
NAME_ONLY_FILE = OUTPUT_PATH / "indirect_calls_name_only.json"
HEADER_CACHE = OUTPUT_PATH / "extra_headers"

# `->eval(`  `.eval(`  `->adt[`  (use of a field holding a function pointer)
DISPATCH_PATTERN = re.compile(r"(->|\.)\s*(\w+)\s*([(\[])")
# `lhs->field = value;`  (runtime assignment or copy between fields)
ASSIGN_PATTERN = re.compile(r"(->|\.)\s*(\w+)\s*(?:\[[^\]]*\]\s*)?=(?!=)\s*([^;]+);")
CALL_PATTERN = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
IDENTIFIER = re.compile(r"^&?\s*([A-Za-z_]\w*)$")
CHAIN_END = re.compile(r"^(.*?)(->|\.)\s*(\w+)\s*$", flags=re.S)
# when one caller -> target pair is found in several ways, keep the most precise
HOW_PRIORITY = ["typed", "handoff", "api_callback", "untyped_registration", "name_fallback"]


def read(path):
    return path.read_text(errors="ignore")


def header_files():
    """Headers from the sparse checkout + the extra ones in configs/callgraph.yaml"""
    paths = []
    for folder in CONFIG["kernel"]["sparse_paths"]:
        paths += sorted((PATHS.kernel / folder).rglob("*.h"))
    paths = [p for p in paths if p.name not in TEMPLATE_HEADERS]
    HEADER_CACHE.mkdir(parents=True, exist_ok=True)
    tag = kernel_info()["tag"]
    extra = load_yaml("callgraph.yaml").get("extra_headers", [])
    todo = [rel for rel in extra if not (HEADER_CACHE / rel.replace("/", "__")).exists()]
    if todo:   # download all missing headers in one request (see config.prefetch_objects)
        listing = git("ls-tree", tag, "--", *todo).splitlines()
        prefetch_objects([line.split()[2] for line in listing], "extra headers")
    for rel in extra:
        cached = HEADER_CACHE / rel.replace("/", "__")
        if not cached.exists():
            try:
                cached.write_text(git("show", f"{tag}:{rel}"), encoding="utf-8")
            except RuntimeError as e:
                print(f"⚠️  extra header {rel} not available: {e}")
                continue
        paths.append(cached)
    return paths


class Function:
    """One function: node name, file, cleaned body text and its variable scope"""

    def __init__(self, node, name, filename, text, file_scope, start_line):
        self.node, self.name, self.file, self.start_line = node, name, filename, start_line
        self.text = strip_strings(strip_comments(text))
        brace = self.text.find("{")
        self.signature = self.text[:brace] if brace >= 0 else self.text
        self.param_names = parameter_names(self.signature)
        variables = parameter_variables(self.signature)
        variables.update(body_variables(self.text[brace + 1:] if brace >= 0 else ""))
        self.scope = Scope(variables, file_scope)


def parameter_names(signature):
    open_pos = signature.find("(")
    if open_pos < 0:
        return []
    close = match_forward(signature, open_pos)
    inside = signature[open_pos + 1:close] if close else ""
    names = []
    for param in split_top_level(inside):
        pointer = re.search(r"\(\s*\*\s*(\w+)\s*\)", param)   # int (*help)(...)
        words = re.findall(r"\w+", re.sub(r"\[.*?\]", "", param))
        names.append(pointer.group(1) if pointer else (words[-1] if words else ""))
    return names


def call_sites(text):
    """Yield (called name, [argument texts]) for every call in `text`"""
    for m in CALL_PATTERN.finditer(text):
        close = match_forward(text, m.end() - 1)
        if close is not None:
            yield m.group(1), split_top_level(text[m.end():close])


class Extractor:
    def __init__(self):
        self.index = FunctionIndex(load_functions())
        self.structs = StructTable()
        self.returns = {}
        self.functions = []
        # registrations: (struct or None, field) -> {function node}
        self.reg = defaultdict(set)
        self.aliases = defaultdict(set)          # (struct, field) <- {(struct, field)}
        self.local_inits = []                    # (container node, struct, field, target node)
        self.stats = Counter()

    # ------------------------------------------------------------ reading
    def load(self):
        sources = all_source_files()
        headers = header_files() + [p for p in sorted(NETFILTER_PATH.rglob("*.h"))
                                    if p.name not in TEMPLATE_HEADERS]
        for path in headers + sources:
            self.structs.add_text(read(path))
        self.stats["structs_parsed"] = len(self.structs.fields)
        # functions returning a struct pointer (definitions + static inline in headers)
        for path in headers:
            text = strip_comments(read(path))
            for m in re.finditer(r"\bstruct\s+(\w+)\s*\*+\s*(\w+)\s*\(", text):
                self.returns.setdefault(m.group(2), m.group(1))

        header_globals = {}
        for path in headers:
            header_globals.update(body_variables(re.sub(r"\{[^{}]*\}", ";", strip_comments(read(path)))))
        for filename, funcs in self.index.functions.items():
            path = find_source(filename)
            if path is None:
                continue
            lines = read(path).split("\n")
            inside = set()
            for func in funcs:
                inside.update(range(func["line"] - 1, func.get("end_line", func["line"])))
            outside = "\n".join(l for i, l in enumerate(lines) if i not in inside)
            file_scope = dict(header_globals)
            file_scope.update(body_variables(strip_comments(outside)))
            for func in funcs:
                text = "\n".join(lines[func["line"] - 1:func.get("end_line", func["line"])])
                node = self.index.node_id(func["name"], filename)
                f = Function(node, func["name"], filename, text, file_scope, func["line"])
                self.functions.append(f)
                ret = return_struct_type(f.signature, func["name"])
                if ret:
                    self.returns.setdefault(func["name"], ret)
        self.by_node = {f.node: f for f in self.functions}

    def type_of(self, expr, func):
        return expression_type(expr, func.scope, self.structs, self.returns)

    # ------------------------------------------------------------ registrations
    def find_initializers(self):
        for path in all_source_files():
            filename = path.name
            ranges = [(f.start_line, f.start_line + f.text.count("\n"), f.node)
                      for f in self.functions if f.file == filename]
            for struct, field, value, line in initializer_registrations(read(path), self.structs):
                target = self.index.resolve(value, filename)
                if not target:
                    continue
                self.reg[(struct, field)].add(target)
                self.stats["registrations_initializer"] += 1
                self.stats["registrations_initializer_untyped" if struct is None else
                           "registrations_initializer_typed"] += 1
                container = next((n for a, b, n in ranges if a <= line <= b), None)
                if container:
                    self.local_inits.append((container, struct, field, target))

    def find_assignments(self):
        """ops->eval = fn;   entry->hook = reg->hook;   x->help = help (param)"""
        self.stores = defaultdict(lambda: defaultdict(set))   # node -> param index -> {(struct, field)}
        for f in self.functions:
            for m in ASSIGN_PATTERN.finditer(f.text):
                field, value = m.group(2), m.group(3).strip()
                struct = self.type_of(operand_before(f.text, m.start()), f)
                ident = IDENTIFIER.match(value)
                if ident:
                    name = ident.group(1)
                    if name in f.param_names:
                        self.stores[f.node][f.param_names.index(name)].add((struct, field))
                    target = self.index.resolve(name, f.file)
                    if target:
                        self.reg[(struct, field)].add(target)
                        self.stats["registrations_runtime"] += 1
                    continue
                chain = CHAIN_END.match(value)
                if chain and struct is not None:
                    source_struct = self.type_of(chain.group(1), f)
                    if source_struct is not None:
                        self.aliases[(struct, field)].add((source_struct, chain.group(3)))

    def find_handoffs(self):
        """Callbacks passed as arguments: stored (x->help = help) or called (iter(...))"""
        self.calls = defaultdict(set)        # node -> {param index called directly}
        self.forwards = defaultdict(lambda: defaultdict(set))   # node -> i -> {(callee, j)}
        for f in self.functions:
            for i, param in enumerate(f.param_names):
                if param and re.search(r"(?<![\w.>])%s\s*\(" % re.escape(param), f.text):
                    self.calls[f.node].add(i)
            for name, args in call_sites(f.text):
                callee = self.index.resolve(name, f.file)
                if not callee:
                    continue
                for j, arg in enumerate(args):
                    ident = IDENTIFIER.match(arg)
                    if ident and ident.group(1) in f.param_names:
                        self.forwards[f.node][f.param_names.index(ident.group(1))].add((callee, j))

        callback_edges = set()
        for f in self.functions:
            for name, args in call_sites(f.text):
                callee = self.index.resolve(name, f.file)
                if not callee:
                    continue
                for i, arg in enumerate(args):
                    ident = IDENTIFIER.match(arg)
                    target = self.index.resolve(ident.group(1), f.file) if ident else None
                    if not target:
                        continue
                    todo, seen = [(callee, i)], set()
                    while todo:
                        g, k = todo.pop()
                        if (g, k) in seen:
                            continue
                        seen.add((g, k))
                        for key in self.stores.get(g, {}).get(k, ()):
                            if target not in self.reg[key]:
                                self.reg[key].add(target)
                                self.stats["registrations_handoff"] += 1
                        if k in self.calls.get(g, ()):
                            callback_edges.add((g, target))
                        todo.extend(self.forwards.get(g, {}).get(k, ()))
        return callback_edges

    def apply_aliases(self):
        changed = True
        while changed:
            changed = False
            for key, sources in self.aliases.items():
                for src in sources:
                    new = self.reg.get(src, set()) - self.reg[key]
                    if new:
                        self.reg[key] |= new
                        changed = True
        self.stats["field_copies"] = sum(len(s) for s in self.aliases.values())

    def by_field(self):
        out = defaultdict(set)
        for (_, field), targets in self.reg.items():
            out[field] |= targets
        return out

    # ------------------------------------------------------------ dispatches
    def find_dispatches(self, units):
        """Return (typed edges, name-only edges) as {(caller, target): how}"""
        names = self.by_field()
        typed, name_only = {}, {}
        sites = Counter()
        for f in self.functions:
            for m in DISPATCH_PATTERN.finditer(f.text):
                field = m.group(2)
                if field not in names:
                    continue
                if m.group(3) == "[":       # ->adt[i](...) : must be followed by a call
                    close = match_forward(f.text, m.end() - 1)
                    if close is None or not f.text[close + 1:].lstrip().startswith("("):
                        continue
                prefix = operand_before(f.text, m.start())
                for target in names[field]:
                    name_only[(f.node, target)] = "name_only"
                struct = self.type_of(prefix, f) if prefix else None
                if struct is not None:
                    exact = self.reg.get((struct, field), set())
                    untyped = self.reg.get((None, field), set())
                    if exact:
                        sites["typed"] += 1
                    elif untyped:
                        sites["typed_only_untyped_registrations"] += 1
                    else:
                        sites["typed_no_registrations"] += 1
                    found = [(t, "typed") for t in exact] + [(t, "untyped_registration") for t in untyped]
                else:
                    sites["name_fallback"] += 1
                    found = [(t, "name_fallback") for t in names[field]]
                if "variant" in prefix:     # ipset: a set type only handles its own sets
                    own = [(t, h) for t, h in found if units.get(t) == units.get(f.node)]
                    found = own or found
                for target, how in found:
                    add_edge(typed, f.node, target, how)
        self.stats.update({f"dispatch_sites_{k}": v for k, v in sites.items()})
        return typed, name_only

    # ------------------------------------------------------------ API callbacks
    def api_callbacks(self):
        rules = load_yaml("callgraph.yaml").get("api_callbacks", {})
        edges = {}
        counts = Counter()
        for rule in rules.get("dispatchers", []):
            targets = self.reg.get((rule["struct"], rule["field"]), set())
            for caller in rule["called_by"]:
                if caller not in self.by_node:
                    print(f"⚠️  api rule: dispatcher {caller} not found")
                    continue
                for t in targets:
                    add_edge(edges, caller, t, "api_callback")
                    counts[f"{rule['struct']}.{rule['field']}"] += 1
        for rule in rules.get("local_structs", []):
            for container, struct, field, target in self.local_inits:
                if struct == rule["struct"] and field in rule["fields"]:
                    add_edge(edges, container, target, "api_callback")
                    counts[f"{struct} (local)"] += 1
        arg_rules = {r["function"]: r["arg"] for r in rules.get("call_arguments", [])}
        for f in self.functions:
            for name, args in call_sites(f.text):
                if name in arg_rules and len(args) > arg_rules[name]:
                    ident = IDENTIFIER.match(args[arg_rules[name]])
                    target = self.index.resolve(ident.group(1), f.file) if ident else None
                    if target:
                        add_edge(edges, f.node, target, "api_callback")
                        counts[f"{name}()"] += 1
        return edges, dict(counts)


def add_edge(edges, caller, target, how):
    if caller == target:
        return
    old = edges.get((caller, target))
    if old is None or HOW_PRIORITY.index(how) < HOW_PRIORITY.index(old):
        edges[(caller, target)] = how


def main():
    print("=" * 70)
    print("🔀 INDIRECT CALL EXTRACTION (function pointers, matched by struct type)")
    print("=" * 70)
    for required in (FUNCTIONS_FILE, DIRECT_CALLS_FILE):
        if not required.exists():
            print(f"❌ Missing required input: {required}")
            return 1

    ex = Extractor()
    ex.load()
    ex.find_initializers()
    ex.find_assignments()
    callback_edges = ex.find_handoffs()
    ex.apply_aliases()

    units = compilation_units()
    unit_of = {f.node: units.get(f.file, f.file) for f in ex.functions}
    typed, name_only = ex.find_dispatches(unit_of)
    api_edges, api_counts = ex.api_callbacks()

    edges = dict(typed)
    for (c, t) in callback_edges:
        add_edge(edges, c, t, "handoff")
        name_only[(c, t)] = "name_only"      # the old method had hand-offs too
    for (c, t), how in api_edges.items():
        add_edge(edges, c, t, how)

    direct = set(load_call_graph(include_indirect=False).edges())
    edges = {k: v for k, v in edges.items() if k not in direct}
    name_only = {k: v for k, v in name_only.items() if k not in direct and k[0] != k[1]}

    def nested(pairs):
        out = defaultdict(dict)
        for (c, t), how in sorted(pairs.items()):
            out[c][t] = how
        return dict(out)

    how_counts = Counter(edges.values())
    field_targets = {field: sorted(t) for field, t in sorted(ex.by_field().items())}
    typed_targets = {f"{s}.{field}": sorted(t) for (s, field), t in sorted(
        ex.reg.items(), key=lambda kv: (str(kv[0][0]), kv[0][1])) if s is not None}
    stats = {
        **dict(sorted(ex.stats.items())),
        "edges_total": len(edges),
        "edges_by_how": dict(how_counts),
        "api_callback_edges_by_rule": api_counts,
        "name_only_edges (old method)": len(name_only),
        "direct_edges": len(direct),
    }
    dispatch_total = sum(v for k, v in ex.stats.items() if k.startswith("dispatch_sites_"))
    fallback = ex.stats.get("dispatch_sites_name_fallback", 0)
    stats["name_fallback_share_of_dispatch_sites"] = round(fallback / dispatch_total, 3) if dispatch_total else 0

    print(f"✅ Struct types parsed:                 {ex.stats['structs_parsed']}")
    print(f"✅ Registrations (initializers):        {ex.stats['registrations_initializer']} "
          f"(typed {ex.stats['registrations_initializer_typed']}, "
          f"untyped {ex.stats['registrations_initializer_untyped']})")
    print(f"   runtime / hand-off / field copies:   {ex.stats['registrations_runtime']} / "
          f"{ex.stats['registrations_handoff']} / {ex.stats['field_copies']}")
    print(f"✅ Dispatch sites:                      {dispatch_total}")
    for k, v in sorted(ex.stats.items()):
        if k.startswith("dispatch_sites_"):
            print(f"   {k[15:]:36s} {v}")
    print(f"   -> name-only fallback used for {100 * stats['name_fallback_share_of_dispatch_sites']:.1f}% "
          f"of dispatch sites (type unknown)")
    print(f"✅ API callback edges:                  {sum(api_counts.values())}  {api_counts}")
    print(f"✅ NEW indirect edges:                  {len(edges)}  {dict(how_counts)}")
    print(f"   old name-only method would give:     {len(name_only)}")

    OUTPUT_PATH.mkdir(parents=True, exist_ok=True)
    with open(INDIRECT_CALLS_FILE, "w") as f:
        json.dump({"kernel": kernel_info(), "stats": stats, "edges": nested(edges),
                   "field_targets": field_targets, "typed_targets": typed_targets}, f, indent=1)
    with open(NAME_ONLY_FILE, "w") as f:
        json.dump({"kernel": kernel_info(), "edges": nested(name_only)}, f, indent=1)
    print(f"\n💾 Saved: {INDIRECT_CALLS_FILE}\n💾 Saved: {NAME_ONLY_FILE}")

    out_txt = OUTPUT_PATH / "indirect_calls_summary.txt"
    with open(out_txt, "w", encoding="utf-8") as f:
        f.write("=" * 70 + "\nINDIRECT CALL EXTRACTION (typed function pointers)\n" + "=" * 70 + "\n")
        f.write(f"Kernel: {kernel_info()['tag']} ({kernel_info()['commit']})\n\n")
        f.write("A use of ->field( is linked to functions registered in that field of the\n"
                "SAME struct type; name-only matching is used only when the type is unknown.\n\n")
        f.write(json.dumps(stats, indent=2) + "\n")
        biggest = sorted(ex.reg.items(), key=lambda kv: len(kv[1]), reverse=True)[:20]
        f.write("\nStruct fields with the most registered functions:\n")
        for (s, field), t in biggest:
            f.write(f"   {str(s) + '.' + field:45s} {len(t):4d}\n")
    print(f"💾 Saved: {out_txt}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
