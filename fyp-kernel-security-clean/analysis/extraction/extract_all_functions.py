#!/usr/bin/env python3
"""
SCRIPT #1: Extract ALL functions from Netfilter subsystem
Purpose: Foundation for call graph construction
Date: November 2025
"""

import re
import json
from pathlib import Path
import sys

# Windows terminals use a non-UTF-8 encoding by default and crash on emoji output
sys.stdout.reconfigure(encoding="utf-8")

# KERNEL_PATH = Path.home() / "fyp-kernel-security/data/kernel/linux-shallow"
# NETFILTER_PATH = KERNEL_PATH / "net/netfilter"
# OUTPUT_PATH = Path.home() / "fyp-kernel-security/results/raw"

PROJECT_ROOT = Path(__file__).resolve().parents[2]

KERNEL_PATH = PROJECT_ROOT / "data/kernel/linux-shallow"
NETFILTER_PATH = KERNEL_PATH / "net/netfilter"
OUTPUT_PATH = PROJECT_ROOT / "results/raw"

sys.path.insert(0, str(PROJECT_ROOT / "analysis"))
from sources import all_source_files, expand_ipset_templates, template_prefix

def opens_body(joined, lines, end_index):
    """
    Check that the signature is followed by a function body: after the ')'
    that closes the parameter list, a '{' must come BEFORE any ';'.
    A ';' first means a call statement or a prototype, not a definition.
    `joined` is the signature text, which ends on line `end_index`.
    """
    # find the ')' that closes the parameter list
    depth = 0
    close = None
    for pos, ch in enumerate(joined):
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
            if depth == 0:
                close = pos
                break
    if close is None:
        return False

    # text after the signature: rest of its last line + the next 3 lines
    tail = joined[close + 1:] + ' ' + ' '.join(lines[end_index + 1:end_index + 4])
    tail = re.sub(r'/\*.*?\*/', '', tail)  # remove /* */ comments
    tail = re.sub(r'//[^\n]*', '', tail)   # remove // comments

    brace = tail.find('{')
    semicolon = tail.find(';')
    return brace != -1 and (semicolon == -1 or brace < semicolon)

KEYWORDS = {
    'if', 'for', 'while', 'switch', 'return', 'do', 'else',
    'case', 'break', 'continue', 'goto', 'sizeof', 'typeof',
    'list_for_each_entry', 'list_for_each_entry_safe',
    'list_for_each_entry_rcu', 'list_for_each_entry_reverse',
    'hlist_for_each_entry', 'lockdep_is_held', 'likely', 'unlikely',
    'BUG_ON', 'WARN_ON', 'pr_debug', 'pr_err', 'printk',
    'module_init', 'module_exit', 'MODULE_LICENSE',
    'EXPORT_SYMBOL', 'EXPORT_SYMBOL_GPL'
}

# type/name on one line, opening paren present (rest of params may wrap).
# The separator before the name may be '*' as well as spaces, so functions
# returning a pointer ("static void *foo(") are found too.
SIG_START_PATTERN = re.compile(r'^([\w\s\*]+?)[\s\*]+(\w+)\s*\(')
# a line that is ONLY a return type / modifiers, e.g. "static int" or
# "static bool" or "static struct foo *" - no parens, no semicolon
BARE_TYPE_PATTERN = re.compile(r'^[\w\s\*]+$')
# a line starting directly with an identifier and '(' - used to catch the
# kernel style where the return type is on the previous line and the
# function name starts the next line, e.g.:
#   static int
#   bitmap_ip_uadt(struct ip_set *set, struct nlattr *tb[],
BARE_NAME_PATTERN = re.compile(r'^(\w+)\s*\(')


def is_noise_line(line):
    return any(keyword in line for keyword in
               ['#define', '#include', 'typedef', 'struct {', 'if (', 'for (', 'while ('])


def extract_functions(file_path):
    """
    Extract real function definitions, including ones whose signature
    spans multiple lines (return type on its own line, and/or parameters
    wrapping across lines) - both very common in Linux kernel style.
    """
    try:
        content = file_path.read_text(errors='ignore')
    except:
        return []

    functions = []
    lines = content.split('\n')
    seen = set()

    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        stripped = line.strip()

        if not stripped or stripped.startswith(('#', '//', '/*', '*', '}')):
            i += 1
            continue

        if is_noise_line(line):
            i += 1
            continue

        # Kernel style: a function definition always starts at the left
        # margin. Indented lines are statements INSIDE a function, e.g.
        # "\treturn ERR_PTR(-EINVAL);" or "\tmutex_lock(&lock);" - without
        # this check those were mistaken for definitions of ERR_PTR etc.
        if line[:1].isspace():
            i += 1
            continue

        sig_line_idx = i
        sig_text = line
        func_name = None
        consumed_next = False

        m = SIG_START_PATTERN.match(line)
        if m:
            func_name = m.group(2)
        elif BARE_TYPE_PATTERN.match(stripped) and '(' not in line and i + 1 < n:
            # Candidate "return type on its own line" - check next line for
            # a bare function name immediately followed by '('
            next_line = lines[i + 1]
            nm = BARE_NAME_PATTERN.match(next_line)  # must also start at the left margin
            if nm:
                func_name = nm.group(1)
                sig_text = line + ' ' + next_line
                consumed_next = True

        if func_name is None or func_name in KEYWORDS:
            i += 1
            continue

        # Join forward lines until parentheses balance, to handle
        # parameter lists that wrap across multiple lines
        j = i + 1 if consumed_next else i
        joined = sig_text
        max_lookahead = 20
        while joined.count('(') > joined.count(')') and (j - sig_line_idx) < max_lookahead and j + 1 < n:
            j += 1
            joined += ' ' + lines[j]

        if joined.count('(') == 0 or joined.count('(') != joined.count(')'):
            i += 1
            continue

        # Must be followed by a body '{' (real definition, not a call or prototype)
        if opens_body(joined, lines, j) and func_name not in seen:
            functions.append({
                'name': func_name,
                'file': file_path.name,
                'line': sig_line_idx + 1
            })
            seen.add(func_name)

        i = j + 1

    return functions

def main():
    print("=" * 70)
    print("🔍 IMPROVED EXTRACTION (v2) - Only Real Functions")
    print("=" * 70)
    print(f"\nScanning: {NETFILTER_PATH}\n")
    
    # ipset template headers -> filled-in copies such as "bitmap_ip@ip_set_bitmap_gen.h"
    expanded = expand_ipset_templates()
    c_files = all_source_files()
    print(f"Found {len(c_files) - len(expanded)} C files + {len(expanded)} expanded ipset templates\n")

    all_funcs = {}
    total = 0

    for f in c_files:
        funcs = extract_functions(f)
        prefix = template_prefix(f.name)
        if prefix:
            # From a template copy keep only the templated functions (bitmap_ip_add, ...).
            # The few shared helpers in it are not per-set code.
            funcs = [func for func in funcs if func['name'].startswith(prefix)]
        if funcs:
            all_funcs[f.name] = funcs
            total += len(funcs)
            print(f"✅ {f.name:45s} {len(funcs):4d} functions")
    
    # Save
    OUTPUT_PATH.mkdir(parents=True, exist_ok=True)
    output_file = OUTPUT_PATH / "functions_v2.json"
    with open(output_file, 'w') as out:
        json.dump(all_funcs, out, indent=2)
    
    print("\n" + "=" * 70)
    print(f"📊 RESULTS (ALL FILES)")
    print("=" * 70)
    print(f"Files analyzed:  {len(all_funcs)}")
    print(f"Total functions: {total}")
    
    # Check CVE file
    print("\n🎯 CVE-2023-0179 FILE:")
    if 'nf_tables_api.c' in all_funcs:
        count = len(all_funcs['nf_tables_api.c'])
        print(f"   ✅ nf_tables_api.c: {count} functions")
        print(f"\n   First 20 functions (should be REAL functions now):")
        for i, func in enumerate(all_funcs['nf_tables_api.c'][:20], 1):
            print(f"      {i:2d}. {func['name']:35s} (line {func['line']})")
    else:
        print("   ⚠️  Not in first 50 files")
    
    print(f"\n💾 Saved to: {output_file}")
    print("=" * 70)

if __name__ == "__main__":
    main()