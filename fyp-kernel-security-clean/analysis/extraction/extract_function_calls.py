#!/usr/bin/env python3
"""
SCRIPT #2: Extract Function Calls
Purpose: Find which functions call which other functions
Date: November 2025
"""
"""
IMPROVED CALL EXTRACTION - Cross-file calls
Finds ALL function calls, not just within same file
"""

from fileinput import filename
import re
import json
from pathlib import Path
from typing import Dict, List, Set
import sys

# Paths
KERNEL_PATH = Path.home() / "fyp-kernel-security/data/kernel/linux-shallow"
NETFILTER_PATH = KERNEL_PATH / "net/netfilter"
INPUT_FILE = Path.home() / "fyp-kernel-security/results/raw/functions_v2.json"
OUTPUT_PATH = Path.home() / "fyp-kernel-security/results/raw"

class ImprovedCallExtractor:
    """Extract ALL function calls including cross-file"""
    
    def __init__(self, all_functions: Dict[str, List]):
        # Create mapping: function_name -> file
        self.function_to_file = {}
        self.known_functions = set()
        
        for filename, funcs in all_functions.items():
            for func in funcs:
                func_name = func['name']
                self.known_functions.add(func_name)
                # Track which file defines this function
                if func_name not in self.function_to_file:
                    self.function_to_file[func_name] = filename
        
        print(f"📋 Loaded {len(self.known_functions)} known functions")
        print(f"📋 Mapped functions to their source files")
    
    def extract_calls_from_function(self, content: str, start_line: int, 
                                   func_name: str, lines: List[str]) -> List[str]:
        """
        Extract calls from a specific function
        Tracks braces to know when function ends
        """
        calls = []
        brace_count = 0
        in_function = False
        
        for i in range(start_line, len(lines)):
            line = lines[i]
            
            # Count braces
            brace_count += line.count('{') - line.count('}')
            
            if not in_function and '{' in line:
                in_function = True
            
            if in_function:
                # Find function calls: word(
                # Skip lines that are comments
                clean_line = line.split('//')[0]  # Remove // comments
                
                if not clean_line.strip().startswith('/*'):
                    call_pattern = r'\b(\w+)\s*\('
                    for match in re.finditer(call_pattern, clean_line):
                        called = match.group(1)
                        
                        # Filter out obvious non-functions
                        if called in {'if', 'for', 'while', 'switch', 'sizeof', 
                                     'typeof', 'return', 'case', '__builtin_expect',
                                     'likely', 'unlikely', 'BUG_ON', 'WARN_ON',
                                     'container_of', 'offsetof', 'BUILD_BUG_ON'}:
                            continue
                        
                        # Only add if it's a known function and not calling itself
                        if called in self.known_functions and called != func_name:
                            if called not in calls:
                                calls.append(called)
                
                # End of function
                if brace_count == 0 and in_function:
                    break
        
        return calls
    
    def extract_calls_from_file(self, file_path: Path, 
                                defined_functions: List[Dict]) -> Dict[str, List[str]]:
        """Extract all calls from a file"""
        try:
            content = file_path.read_text(errors='ignore')
            lines = content.split('\n')
        except:
            return {}
        
        calls = {}
        
        # For each function defined in this file
        for func_info in defined_functions:
            func_name = func_info['name']
            start_line = func_info['line'] - 1  # 0-indexed
            
            # Extract calls from this function
            called_funcs = self.extract_calls_from_function(
                content, start_line, func_name, lines
            )
            
            if called_funcs:
                calls[func_name] = called_funcs
        
        return calls
    
    def extract_all_calls(self, all_functions: Dict[str, List]) -> Dict:
        """Extract calls from all files"""
        
        all_calls = {}
        total_edges = 0
        
        print("\n" + "=" * 70)
        print("🔗 EXTRACTING FUNCTION CALLS (Cross-File)")
        print("=" * 70)
        print("Now detecting ALL calls including cross-file...\n")
        
        for filename, funcs in all_functions.items():
            file_path = KERNEL_PATH / "net/netfilter" / filename

            matches = []
            if not file_path.exists():
                matches = list((KERNEL_PATH / "net/netfilter").rglob(filename))
            if matches:
                file_path = matches[0]

            if not file_path.exists():
                print(f"⚠️  {filename:45s} not found")
                continue


            
            # Extract calls
            calls = self.extract_calls_from_file(file_path, funcs)
            
           # Always store file key (even if 0 calls) so downstream CVE analysis can find it
            all_calls[filename] = calls

            edge_count = sum(len(callees) for callees in calls.values()) if calls else 0
            total_edges += edge_count

            if edge_count > 0:
                print(f"✅ {filename:45s} {edge_count:5d} calls")
            else:
                print(f"⚠️  {filename:45s}     0 calls")

        
        print(f"\n{'='*70}")
        print(f"Total call relationships found: {total_edges}")
        print(f"{'='*70}")
        
        return all_calls


def analyze_call_graph(all_calls: Dict) -> Dict:
    """Generate detailed statistics"""
    
    # Count callers and callees
    all_callers = set()
    all_callees = set()
    total_calls = 0
    
    # Track in-degree (how many times each function is called)
    in_degree = {}
    
    # Track out-degree (how many functions each calls)
    out_degree = {}
    
    for file_calls in all_calls.values():
        for caller, callees in file_calls.items():
            all_callers.add(caller)
            out_degree[caller] = len(callees)
            
            for callee in callees:
                all_callees.add(callee)
                in_degree[callee] = in_degree.get(callee, 0) + 1
                total_calls += 1
    
    # Top by in-degree (most called)
    top_in_degree = sorted(in_degree.items(), key=lambda x: x[1], reverse=True)[:30]
    
    # Top by out-degree (calls most others)
    top_out_degree = sorted(out_degree.items(), key=lambda x: x[1], reverse=True)[:30]
    
    stats = {
        'total_callers': len(all_callers),
        'total_callees': len(all_callees),
        'total_call_edges': total_calls,
        'unique_functions_involved': len(all_callers | all_callees),
        'avg_calls_per_function': total_calls / len(all_callers) if all_callers else 0,
        'top_30_in_degree': top_in_degree,
        'top_30_out_degree': top_out_degree
    }
    
    return stats


def save_results(all_calls: Dict, stats: Dict):
    """Save all results"""
    
    OUTPUT_PATH.mkdir(parents=True, exist_ok=True)
    
    # Save complete call graph
    calls_file = OUTPUT_PATH / "function_calls_v2.json"
    with open(calls_file, 'w') as f:
        json.dump(all_calls, f, indent=2)
    print(f"\n💾 Saved call graph to: {calls_file}")
    
    # Save statistics
    stats_file = OUTPUT_PATH / "call_graph_stats_v2.json"
    with open(stats_file, 'w') as f:
        json.dump(stats, f, indent=2)
    print(f"💾 Saved statistics to: {stats_file}")
    
    # Create detailed summary
    summary_file = OUTPUT_PATH / "call_graph_summary_v2.txt"
    with open(summary_file, 'w') as f:
        f.write("=" * 70 + "\n")
        f.write("NETFILTER CALL GRAPH ANALYSIS (IMPROVED)\n")
        f.write("=" * 70 + "\n\n")
        f.write(f"Functions that call others:        {stats['total_callers']}\n")
        f.write(f"Functions that are called:         {stats['total_callees']}\n")
        f.write(f"Total call relationships (edges):  {stats['total_call_edges']}\n")
        f.write(f"Unique functions in graph:         {stats['unique_functions_involved']}\n")
        f.write(f"Average calls per function:        {stats['avg_calls_per_function']:.2f}\n")
        
        f.write("\n" + "=" * 70 + "\n")
        f.write("TOP 30 MOST CALLED FUNCTIONS (High In-Degree)\n")
        f.write("=" * 70 + "\n")
        f.write("These are the most critical/central functions\n\n")
        for i, (func, count) in enumerate(stats['top_30_in_degree'], 1):
            f.write(f"{i:3d}. {func:50s} called {count:5d} times\n")
        
        f.write("\n" + "=" * 70 + "\n")
        f.write("TOP 30 FUNCTIONS WITH HIGHEST OUT-DEGREE\n")
        f.write("=" * 70 + "\n")
        f.write("These functions call many others (high complexity)\n\n")
        for i, (func, count) in enumerate(stats['top_30_out_degree'], 1):
            f.write(f"{i:3d}. {func:50s} calls {count:5d} functions\n")
    
    print(f"💾 Saved detailed summary to: {summary_file}")


def load_functions():
    """Load previously extracted functions"""
    if not INPUT_FILE.exists():
        print(f"❌ Error: {INPUT_FILE} not found!")
        sys.exit(1)
    
    with open(INPUT_FILE, 'r') as f:
        return json.load(f)


def main():
    """Main execution"""
    
    print("=" * 70)
    print("IMPROVED CALL EXTRACTION ")
    print("=" * 70)
    print("Detecting ALL function calls (including cross-file)")
    
    # Load functions
    print("\n📂 Loading function list...")
    all_functions = load_functions()
    print(f"✅ Loaded {len(all_functions)} files")
    
    # Initialize improved extractor
    extractor = ImprovedCallExtractor(all_functions)
    
    # Extract all calls
    all_calls = extractor.extract_all_calls(all_functions)
    
    if not all_calls:
        print("\n❌ No calls extracted!")
        return 1
    
    # Analyze
    print("\n" + "=" * 70)
    print("📊 ANALYZING CALL GRAPH")
    print("=" * 70)
    
    stats = analyze_call_graph(all_calls)
    
    print(f"\n✅ Functions that call others:      {stats['total_callers']}")
    print(f"✅ Functions that are called:       {stats['total_callees']}")
    print(f"✅ Total call relationships (edges): {stats['total_call_edges']}")
    print(f"✅ Average calls per function:      {stats['avg_calls_per_function']:.2f}")
    
    print("\n📈 Top 15 Most Called Functions (Highest Centrality):")
    for i, (func, count) in enumerate(stats['top_30_in_degree'][:15], 1):
        print(f"   {i:2d}. {func:45s} called {count:4d} times")
    
    # Check CVE file
    print("\n🎯 CVE-2023-0179 FILE:")
    if 'nf_tables_api.c' in all_calls:
        cve_calls = all_calls['nf_tables_api.c']
        total_calls_in_cve = sum(len(v) for v in cve_calls.values())
        print(f"   ✅ {len(cve_calls)} functions make calls")
        print(f"   ✅ Total {total_calls_in_cve} call relationships")
        
        # Show example
        if cve_calls:
            first_func = list(cve_calls.keys())[0]
            print(f"\n   Example - {first_func} calls:")
            for callee in cve_calls[first_func][:8]:
                print(f"      → {callee}")
            if len(cve_calls[first_func]) > 8:
                print(f"      ... and {len(cve_calls[first_func]) - 8} more")
    else:
        print("   ⚠️  nf_tables_api.c has no calls detected")
    
    # Save results
    print("\n" + "=" * 70)
    print("💾 SAVING RESULTS")
    print("=" * 70)
    save_results(all_calls, stats)
    
    print("\n" + "=" * 70)
    print("✅ IMPROVED CALL EXTRACTION COMPLETE!")
    print("=" * 70)
    print(f"\nQuality Check:")
    print(f"  - Total edges: {stats['total_call_edges']}")
    print(f"  - Expected: 2000-4000 (depends on code complexity)")
    if stats['total_call_edges'] < 500:
        print(f"  ⚠️  Still seems low - may need further refinement")
    elif stats['total_call_edges'] > 1500:
        print(f"  ✅ Good coverage!")
    else:
        print(f"  ✅ Reasonable coverage")
    
    print("\nNext step: Build NetworkX graph and calculate PageRank")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())