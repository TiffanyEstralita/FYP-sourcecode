#!/usr/bin/env python3
"""
SCRIPT #1: Extract ALL functions from Netfilter subsystem
Purpose: Foundation for call graph construction
Date: November 2025
"""

import re
import json
from pathlib import Path

# KERNEL_PATH = Path.home() / "fyp-kernel-security/data/kernel/linux-shallow"
# NETFILTER_PATH = KERNEL_PATH / "net/netfilter"
# OUTPUT_PATH = Path.home() / "fyp-kernel-security/results/raw"

PROJECT_ROOT = Path(__file__).resolve().parents[2]

KERNEL_PATH = PROJECT_ROOT / "data/kernel/linux-shallow"
NETFILTER_PATH = KERNEL_PATH / "net/netfilter"
OUTPUT_PATH = PROJECT_ROOT / "results/raw"

def is_function_definition(lines, index):
    """
    Check if line at index is actually a function definition
    Look for { on same line or next few lines
    """
    # Check current line and next 3 lines for opening brace
    for i in range(index, min(index + 4, len(lines))):
        if '{' in lines[i]:
            # Make sure it's not just in a comment or string
            line = lines[i].split('//')[0]  # Remove // comments
            line = re.sub(r'/\*.*?\*/', '', line)  # Remove /* */ comments
            if '{' in line:
                return True
    return False

def extract_functions(file_path):
    """Extract only real function definitions"""
    try:
        content = file_path.read_text(errors='ignore')
    except:
        return []
    
    functions = []
    lines = content.split('\n')
    seen = set()
    
    # Pattern: return_type function_name(params)
    # Must have ( and ) and typically starts at beginning of line
    pattern = re.compile(r'^[\w\s\*]+\s+(\w+)\s*\([^)]*\)')
    
    for i, line in enumerate(lines):
        # Skip obvious non-function lines
        stripped = line.strip()
        if not stripped or stripped.startswith(('#', '//', '/*', '*', '}')):
            continue
        
        # Skip lines that are clearly not function definitions
        if any(keyword in line for keyword in ['#define', '#include', 'typedef', 'struct {', 'if (', 'for (', 'while (']):
            continue
        
        match = pattern.match(line)
        if match:
            func_name = match.group(1)
            
            # Filter out keywords and common macros
            keywords = {
                'if', 'for', 'while', 'switch', 'return', 'do', 'else',
                'case', 'break', 'continue', 'goto', 'sizeof', 'typeof',
                'list_for_each_entry', 'list_for_each_entry_safe',
                'list_for_each_entry_rcu', 'list_for_each_entry_reverse',
                'hlist_for_each_entry', 'lockdep_is_held', 'likely', 'unlikely',
                'BUG_ON', 'WARN_ON', 'pr_debug', 'pr_err', 'printk',
                'module_init', 'module_exit', 'MODULE_LICENSE',
                'EXPORT_SYMBOL', 'EXPORT_SYMBOL_GPL'
            }
            
            if func_name in keywords:
                continue
            
            # Must have opening brace nearby (real function definition)
            if is_function_definition(lines, i) and func_name not in seen:
                functions.append({
                    'name': func_name,
                    'file': file_path.name,
                    'line': i + 1
                })
                seen.add(func_name)
    
    return functions

def main():
    print("=" * 70)
    print("🔍 IMPROVED EXTRACTION (v2) - Only Real Functions")
    print("=" * 70)
    print(f"\nScanning: {NETFILTER_PATH}\n")
    
    c_files = sorted(NETFILTER_PATH.rglob("*.c")) #we add to rglob, previously was glob
    print(f"Found {len(c_files)} C files\n")
    
    all_funcs = {}
    total = 0
    
    for f in c_files:  # First 50 files for now
        funcs = extract_functions(f)
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