"""
MITM Proxy Log Analyzer

This script analyzes mitmproxy logs using various AI models for security analysis.
Supported models: Gemini, OpenAI, Claude
"""

import json
import argparse
import time
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional, Type
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

# Import analyzers
from model.analyzer_factory import AnalyzerFactory

def load_mitm_logs(log_file: str, max_logs: int = 10) -> List[Dict]:
    """Load and parse mitmproxy log file."""
    logs = []
    with open(log_file, 'r', encoding='utf-8') as f:
        for i, line in enumerate(f, 1):
            try:
                logs.append(json.loads(line.strip()))
            except json.JSONDecodeError:
                continue
            if i >= max_logs:
                break
    return logs

def analyze_logs(logs: List[Dict], analyzer, output_file: Optional[str] = None):
    """Analyze logs and print/save results."""
    results = []
    
    for i, log in enumerate(logs, 1):
        print(f"\nAnalyzing request {i}/{len(logs)}")
        print(f"{log['request']['method']} {log['request']['host']}{log['request']['path']}")
        
        # Prepare content for analysis
        content = {
            "request": {
                "method": log['request']['method'],
                "url": f"{log['request']['scheme']}://{log['request']['host']}{log['request']['path']}",
                "headers": log['request']['headers'],
                "body": log['request']['body'] if log['request']['body_is_text'] else "[binary data]"
            },
            "response": {
                "status": log['response']['status_code'],
                "headers": log['response']['headers'],
                "body": log['response']['body'] if log['response']['body_is_text'] else "[binary data]"
            }
        }
        
        # Analyze with analyzer
        analysis = analyzer.analyze_content(json.dumps(content, indent=2))
        
        # Add metadata to results
        result = {
            "timestamp": log.get("timestamp", datetime.utcnow().isoformat()),
            "request": f"{log['request']['method']} {log['request']['host']}{log['request']['path']}",
            "analysis": analysis,
            "severity": analysis.get("severity", 0)
        }
        
        # Print summary
        print(f"  Severity: {result['severity']}/10")
        print(f"  Decision: {analysis.get('decision', 'unknown').upper()}")
        print(f"  Reason: {analysis.get('reason', 'No reason provided')}")
        
        results.append(result)
    
    # Save results if output file is specified
    if output_file:
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\nResults saved to {output_file}")
    
    return results

def print_available_analyzers():
    """Print available analyzer types and their configurations."""
    print("\nAvailable Analyzers:")
    print("-" * 40)
    for analyzer_type, config in AnalyzerFactory.get_analyzer_config("").items():
        print(f"Type: {analyzer_type}")
        print(f"  Model: {config['model']}")
        print(f"  Env Var: {config['env_var']}")
        print(f"  {config['description']}")
        print()

def main():
    parser = argparse.ArgumentParser(description='Analyze mitmproxy logs with AI models')
    parser.add_argument('log_file', help='Path to mitmproxy log file (JSONL format)')
    parser.add_argument('--output', '-o', default='analysis_results.json', 
                       help='Output file for analysis results (JSON format)')
    parser.add_argument('--analyzer', '-a', default='gemini', 
                       help='Analyzer type to use (gemini, openai, claude)')
    parser.add_argument('--model', help='Specific model to use (overrides default for analyzer)')
    parser.add_argument('--max-logs', type=int, default=10,
                       help='Maximum number of logs to process (default: 10)')
    parser.add_argument('--list-analyzers', action='store_true',
                       help='List available analyzer types and exit')
    
    args = parser.parse_args()
    
    if args.list_analyzers:
        print_available_analyzers()
        return 0
    
    try:
        # Initialize analyzer
        print(f"Initializing {args.analyzer} analyzer...")
        
        # Get model configuration
        config = AnalyzerFactory.get_analyzer_config(args.analyzer)
        if not config:
            print(f"Error: Unsupported analyzer type: {args.analyzer}")
            print_available_analyzers()
            return 1
            
        # Use provided model or default
        model_name = args.model if args.model else config['model']
        
        # Check for required API key
        env_var = config['env_var']
        api_key = os.getenv(env_var)
        
        # Debug: Show which environment variables are loaded (without values)
        print(f"\nEnvironment Variables Check:")
        print(f"- {env_var}: {'Set' if api_key and api_key != 'your_api_key_here' else 'Not set'}")
        
        if not api_key or api_key == "your_api_key_here":
            print(f"\nError: {env_var} environment variable not set or is using default value")
            print("Please do one of the following:")
            print("1. Create/update .env file with your API key:")
            print(f"   {env_var}=your_actual_api_key_here")
            print("2. Or set it temporarily in your terminal:")
            print(f"   set {env_var}=your_actual_api_key_here  # Windows")
            print(f"   export {env_var}=your_actual_api_key_here  # Linux/Mac")
            return 1
            
        print(f"Using {env_var} for authentication")
        
        # Create analyzer
        analyzer = AnalyzerFactory.create_analyzer(args.analyzer, model_name=model_name)
        
        # Load logs
        print(f"Loading up to {args.max_logs} logs from {args.log_file}...")
        logs = load_mitm_logs(args.log_file, max_logs=args.max_logs)
        print(f"Loaded {len(logs)} log entries")
        
        if not logs:
            print("No valid log entries found")
            return 0
        
        # Analyze logs
        print(f"\nStarting analysis with {analyzer.get_model_name()}...")
        results = analyze_logs(logs, analyzer, args.output)
        
        if not results:
            print("No results to analyze")
            return 0
        
        # Print summary
        severity_scores = [r['severity'] for r in results if r is not None]
        avg_severity = sum(severity_scores) / len(severity_scores) if severity_scores else 0
        high_severity = sum(1 for s in severity_scores if s >= 7)
        
        print("\n=== Analysis Complete ===")
        print(f"Analyzer: {analyzer.get_model_name()}")
        print(f"Total requests analyzed: {len(results)}")
        print(f"Average severity: {avg_severity:.2f}/10")
        print(f"High severity findings (≥7): {high_severity}")
        
        # Save summary
        if args.output:
            summary = {
                "analyzer": analyzer.get_model_name(),
                "timestamp": datetime.utcnow().isoformat(),
                "total_requests": len(results),
                "average_severity": round(avg_severity, 2),
                "high_severity_findings": high_severity,
                "details_file": args.output
            }
            
            summary_file = f"{Path(args.output).stem}_summary.json"
            with open(summary_file, 'w', encoding='utf-8') as f:
                json.dump(summary, f, indent=2, ensure_ascii=False)
            print(f"\nSummary saved to {summary_file}")
        
    except KeyboardInterrupt:
        print("\nAnalysis interrupted by user")
        return 1
    except Exception as e:
        print(f"Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
