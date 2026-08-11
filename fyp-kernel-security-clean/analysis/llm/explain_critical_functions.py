#!/usr/bin/env python3
"""
REAL FYP SCRIPT #5: LLM Analysis of Critical Functions
Purpose: Use AI to explain WHY high-PageRank functions are security-critical
Date: November 2025
"""

import json
import time
from pathlib import Path
from openai import OpenAI
import sys

# Paths
CONFIG_FILE = Path.home() / "fyp-kernel-security/config/api_keys.json"
TOP_100_FILE = Path.home() / "fyp-kernel-security/results/processed/top_100_functions.json"
KERNEL_PATH = Path.home() / "fyp-kernel-security/data/kernel/linux-shallow"
OUTPUT_PATH = Path.home() / "fyp-kernel-security/results/processed"

class LLMAnalyzer:
    """Use LLM to analyze security implications of functions"""
    
    def __init__(self, api_key: str):
        self.client = OpenAI(api_key=api_key)
        self.model = "gpt-4o-mini"  # Cheaper model, good quality
        # Use "gpt-4o" for best quality but higher cost
    
    def read_function_code(self, file_path: Path, function_name: str, 
                          line_number: int, context_lines: int = 30) -> str:
        """
        Read function code from source file
        Gets function + surrounding context
        """
        try:
            content = file_path.read_text(errors='ignore')
            lines = content.split('\n')
            
            # Get function and surrounding context
            start = max(0, line_number - 5)
            end = min(len(lines), line_number + context_lines)
            
            function_code = '\n'.join(lines[start:end])
            return function_code
            
        except Exception as e:
            print(f"   ⚠️  Error reading {file_path.name}: {e}")
            return ""
    
    def analyze_function(self, function_name: str, file_name: str, 
                        line_number: int, pagerank_score: float) -> dict:
        """
        Send function to LLM for security analysis
        """
        # Read the actual code
        file_path = KERNEL_PATH / "net/netfilter" / file_name
        function_code = self.read_function_code(file_path, function_name, line_number)
        
        if not function_code:
            return {
                'function': function_name,
                'error': 'Could not read function code'
            }
        
        # Create prompt for LLM
        prompt = f"""You are a Linux kernel security expert analyzing the Netfilter subsystem.

Function: {function_name}
File: {file_name}
PageRank Score: {pagerank_score:.6f} (indicates high centrality/importance)

Code:
```c
{function_code}
```

Analyze this function for security implications. Provide:
1. What this function does (brief, 1-2 sentences)
2. Why it might be security-critical (consider: buffer operations, input validation, privilege checks)
3. Potential vulnerability types (e.g., buffer overflow, use-after-free, integer overflow)
4. Risk assessment (Low/Medium/High)

Be concise and specific. Focus on concrete security concerns."""

        try:
            # Call OpenAI API
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a security expert analyzing Linux kernel code."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,  # Lower = more focused
                max_tokens=500
            )
            
            analysis = response.choices[0].message.content
            
            return {
                'function': function_name,
                'file': file_name,
                'line': line_number,
                'pagerank': pagerank_score,
                'code_snippet': function_code[:500],  # First 500 chars
                'llm_analysis': analysis,
                'model': self.model
            }
            
        except Exception as e:
            print(f"   ❌ LLM API error for {function_name}: {e}")
            return {
                'function': function_name,
                'error': str(e)
            }
    
    def analyze_top_functions(self, top_functions: list, limit: int = 20):
        """
        Analyze top N functions with LLM
        """
        results = []
        
        print(f"\n🤖 Analyzing top {limit} functions with LLM...")
        print("=" * 70)
        
        for i, func_data in enumerate(top_functions[:limit], 1):
            print(f"\n[{i}/{limit}] Analyzing: {func_data['function']}")
            print(f"   File: {func_data['file']}")
            print(f"   PageRank: {func_data['pagerank']:.6f}")
            print(f"   Calling LLM...", end=" ")
            
            # Analyze
            analysis = self.analyze_function(
                func_data['function'],
                func_data['file'],
                func_data['line'],
                func_data['pagerank']
            )
            
            results.append(analysis)
            
            if 'error' in analysis:
                print(f"❌ Error")
            else:
                print(f"✅ Done")
                # Show preview
                preview = analysis['llm_analysis'][:150] + "..."
                print(f"   Preview: {preview}")
            
            # Rate limiting - be nice to API
            if i < limit:
                time.sleep(1)  # Wait 1 second between calls
        
        return results


def load_config():
    """Load API key from config"""
    if not CONFIG_FILE.exists():
        print(f"❌ Config file not found: {CONFIG_FILE}")
        print("\nCreate config/api_keys.json with:")
        print('{\n  "openai_api_key": "sk-your-key-here"\n}')
        sys.exit(1)
    
    with open(CONFIG_FILE, 'r') as f:
        config = json.load(f)
    
    if 'openai_api_key' not in config:
        print("❌ openai_api_key not found in config file!")
        sys.exit(1)
    
    return config['openai_api_key']


def load_top_functions():
    """Load top 100 functions"""
    if not TOP_100_FILE.exists():
        print(f"❌ Top 100 file not found: {TOP_100_FILE}")
        print("Run calculate_pagerank.py first!")
        sys.exit(1)
    
    with open(TOP_100_FILE, 'r') as f:
        return json.load(f)


def save_results(results: list):
    """Save LLM analysis results"""
    OUTPUT_PATH.mkdir(parents=True, exist_ok=True)
    
    # Save complete results
    results_file = OUTPUT_PATH / "llm_analysis_results.json"
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\n💾 Saved LLM analysis: {results_file}")
    
    # Create human-readable summary
    summary_file = OUTPUT_PATH / "llm_analysis_summary.txt"
    with open(summary_file, 'w') as f:
        f.write("=" * 70 + "\n")
        f.write("LLM SECURITY ANALYSIS OF TOP FUNCTIONS\n")
        f.write("=" * 70 + "\n\n")
        
        for i, result in enumerate(results, 1):
            if 'error' in result:
                f.write(f"\n{i}. {result['function']} - ERROR\n")
                f.write(f"   {result['error']}\n")
            else:
                f.write(f"\n{i}. {result['function']} (PageRank: {result['pagerank']:.6f})\n")
                f.write(f"   File: {result['file']}, Line: {result['line']}\n")
                f.write(f"   LLM Analysis:\n")
                for line in result['llm_analysis'].split('\n'):
                    f.write(f"   {line}\n")
                f.write("\n" + "-" * 70 + "\n")
    
    print(f"💾 Saved summary: {summary_file}")


def main():
    """Main execution"""
    
    print("=" * 70)
    print("🚀 LLM ANALYSIS OF CRITICAL FUNCTIONS")
    print("=" * 70)
    
    # Load API key
    print("\n🔑 Loading API configuration...")
    api_key = load_config()
    print("✅ API key loaded")
    
    # Load top functions
    print("\n📂 Loading top 100 functions...")
    top_functions = load_top_functions()
    print(f"✅ Loaded {len(top_functions)} functions")
    
    # Initialize LLM analyzer
    analyzer = LLMAnalyzer(api_key)
    
    # Analyze top 20 functions (start small, can increase later)
    print("Press Ctrl+C within 5 seconds to cancel...")
    time.sleep(5)
    
    results = analyzer.analyze_top_functions(top_functions, limit=20)
    
    # Save results
    print("\n" + "=" * 70)
    print("💾 SAVING RESULTS")
    print("=" * 70)
    save_results(results)
    
    # Summary
    successful = sum(1 for r in results if 'error' not in r)
    print("\n" + "=" * 70)
    print("✅ LLM ANALYSIS COMPLETE!")
    print("=" * 70)
    print(f"   Successfully analyzed: {successful}/{len(results)} functions")
    print(f"   Results saved to: {OUTPUT_PATH}")
    print("\nNext step: Validate LLM explanations against known CVEs")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())