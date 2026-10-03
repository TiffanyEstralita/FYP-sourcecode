#!/usr/bin/env python3
"""
REAL FYP SCRIPT #5: LLM Analysis of Critical Functions
Purpose: Use AI to explain WHY high-PageRank functions are security-critical
Date: November 2025
"""

import argparse
import json
import time
from pathlib import Path
import requests
import sys
import yaml

# Windows terminals use a non-UTF-8 encoding by default and crash on emoji output
sys.stdout.reconfigure(encoding="utf-8")

# Paths
PROJECT_ROOT = Path(__file__).resolve().parents[2]

CONFIG_FILE = PROJECT_ROOT / "configs/ollama.yaml"
TOP_100_FILE = PROJECT_ROOT / "results/processed/top_100_functions.json"
OUTPUT_PATH = PROJECT_ROOT / "results/processed"

sys.path.insert(0, str(PROJECT_ROOT / "analysis"))
from sources import find_source

class LLMAnalyzer:
    """Use LLM to analyze security implications of functions"""
    
    def __init__(self, model: str = "llama3.1", host: str = "http://localhost:11434"):
        self.model = model
        self.host = host.rstrip('/')
    
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

        file_path = find_source(file_name)

        if file_path is None:
            print(f"   ⚠️  Could not find {file_name} anywhere in kernel source")
            return {
                'function': function_name,
                'file': file_name,
                'line': line_number,
                'pagerank': pagerank_score,
                'error': f'Could not find source file: {file_name}'
            }

        function_code = self.read_function_code(
            file_path,
            function_name,
            line_number
        )

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
            # Call local Ollama API
            response = requests.post(
                f"{self.host}/api/chat",
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": "You are a security expert analyzing Linux kernel code."},
                        {"role": "user", "content": prompt}
                    ],
                    "stream": False,
                    "options": {
                        "temperature": 0.3,  # Lower = more focused
                        "num_predict": 350
                    }
                },
                timeout=240
            )
            response.raise_for_status()
            analysis = response.json()['message']['content']

            return {
                'function': function_name,
                'file': file_name,
                'line': line_number,
                'pagerank': pagerank_score,
                'code_snippet': function_code[:500],  # First 500 chars
                'llm_analysis': analysis,
                'model': self.model
            }

        except requests.exceptions.ConnectionError:
            print(f"   ❌ Could not connect to Ollama at {self.host} for {function_name}")
            return {
                'function': function_name,
                'error': f"Could not connect to Ollama at {self.host}. Is 'ollama serve' running?"
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
    """Load Ollama model/host from configs/ollama.yaml (shared with the scoring stage)"""
    with open(CONFIG_FILE, 'r') as f:
        config = yaml.safe_load(f)
    return config['model'], config['host']


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


def parse_args():
    """Parse command-line arguments"""
    parser = argparse.ArgumentParser(
        description="LLM analysis of critical kernel functions via Ollama"
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Number of top functions to analyze (default: 20)"
    )
    return parser.parse_args()


def main():
    """Main execution"""

    args = parse_args()

    print("=" * 70)
    print("🚀 LLM ANALYSIS OF CRITICAL FUNCTIONS")
    print("=" * 70)

    # Load Ollama configuration
    print("\n🔑 Loading Ollama configuration...")
    model, host = load_config()
    print(f"✅ Using model '{model}' at {host}")

    # Load top functions
    print("\n📂 Loading top 100 functions...")
    top_functions = load_top_functions()
    print(f"✅ Loaded {len(top_functions)} functions")

    # Initialize LLM analyzer
    analyzer = LLMAnalyzer(model=model, host=host)
    
    # Analyze top N functions (configurable via --limit, default 20)
    print(f"About to analyze {args.limit} function(s). Press Ctrl+C within 5 seconds to cancel...")
    time.sleep(5)

    results = analyzer.analyze_top_functions(top_functions, limit=args.limit)
    
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