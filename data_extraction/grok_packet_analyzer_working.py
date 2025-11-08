"""
MITM Proxy Log Analyzer

This script analyzes mitmproxy logs using various AI models for security analysis.
Supported models: Gemini, OpenAI, Claude, Grok (LLaMA)

Usage for log data: python -m data_extraction.grok_packet_analyzer logs/mitm_logs/mitm-2025-11-08.jsonl --analyzer grok --model llama-3.1-8b-instant --max-logs 10
"""

import json
import argparse
import time
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

# Import analyzers and database manager
from model.analyzer_factory import AnalyzerFactory
from src.database import DatabaseManager


def load_mitm_logs(log_file: str, max_logs: int = 10) -> List[Dict]:
    """Load and parse mitmproxy log file."""
    logs = []
    with open(log_file, "r", encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            try:
                logs.append(json.loads(line.strip()))
            except json.JSONDecodeError:
                continue
            if i >= max_logs:
                break
    return logs


def analyze_logs(logs: List[Dict], analyzer, db: DatabaseManager, output_file: Optional[str] = None):
    """Analyze logs, print results, and store them in both JSON and SQLite."""
    results = []

    for i, log in enumerate(logs, 1):
        try:
            print(f"\nAnalyzing request {i}/{len(logs)}")

            req = log.get("request", {})
            res = log.get("response", {})

            method = req.get("method", "UNKNOWN")
            host = req.get("host", "")
            path = req.get("path", "")
            full_url = f"{req.get('scheme', 'https')}://{host}{path}"

            print(f"{method} {full_url}")

            # Create detailed packet text for model
            request_info = (
                f"=== HTTP REQUEST ===\n"
                f"Method: {method}\n"
                f"URL: {full_url}\n"
                f"\n--- HEADERS ---\n{json.dumps(req.get('headers', {}), indent=2)}\n"
                f"\n--- BODY (first 4000 chars) ---\n"
                f"{(req.get('body', '') if req.get('body_is_text', True) else '[binary data]')[:4000]}\n"
                f"\n=== HTTP RESPONSE ===\n"
                f"Status: {res.get('status_code', 'UNKNOWN')}\n"
                f"\n--- HEADERS ---\n{json.dumps(res.get('headers', {}), indent=2)}\n"
                f"\n--- BODY (first 4000 chars) ---\n"
                f"{(res.get('body', '') if res.get('body_is_text', True) else '[binary data]')[:4000]}"
            )

            print(f"\n🧾 Sending to model (first 300 chars):\n{request_info[:300]}...\n")

            # Analyze packet via AI model
            analysis = analyzer.analyze_content(request_info)

            # Build structured result
            result = {
                "timestamp": log.get("timestamp", datetime.now(timezone.utc).isoformat()),
                "method": method,
                "url": full_url,
                "host": host,
                "path": path,
                "severity": analysis.get("severity", 0),
                "tags": analysis.get("tags", []),
                "decision": analysis.get("decision", "alert"),
                "reason": analysis.get("reason", "No reason provided"),
            }

            print(f"  Severity: {result['severity']}/10")
            print(f"  Decision: {result['decision'].upper()}")
            print(f"  Reason: {result['reason'][:300]}")

            # Save in memory for JSON export
            results.append(result)

            # ✅ Store in SQLite DB
            db.store_event({
                "ts": datetime.now().timestamp(),
                "id": f"pkt_{i:03d}",
                "host": host,
                "path": path,
                "direction": "outbound",
                "severity": result["severity"],
                "tags": result["tags"],
                "decision": result["decision"].upper(),
                "reason": result["reason"],
            })

            time.sleep(2)  # avoid API rate limits

        except Exception as e:
            print(f"⚠️  Error analyzing request {i}: {str(e)}")
            continue

    # Save all results to JSON
    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"\n💾 Results saved to {output_file}")

    return results


def print_available_analyzers():
    """Print available analyzer types and their configurations."""
    print("\nAvailable Analyzers:")
    print("-" * 40)
    analyzers = AnalyzerFactory.list_available_analyzers()
    for analyzer_type, analyzer_class in analyzers.items():
        config = AnalyzerFactory.get_analyzer_config(analyzer_type)
        print(f"Type: {analyzer_type}")
        print(f"  Model: {config.get('model', 'unknown')}")
        print(f"  Env Var: {config.get('env_var', 'N/A')}")
        print(f"  Description: {config.get('description', 'No description available')}")
        print()


def main():
    parser = argparse.ArgumentParser(description="Analyze mitmproxy logs with AI models")
    parser.add_argument("log_file", help="Path to mitmproxy log file (JSONL format)")
    parser.add_argument("--output", "-o", default="analysis_results.json", help="Output file for analysis results")
    parser.add_argument("--analyzer", "-a", default="gemini", help="Analyzer type (gemini, openai, claude, grok)")
    parser.add_argument("--model", help="Specific model to use (overrides default for analyzer)")
    parser.add_argument("--max-logs", type=int, default=10, help="Maximum number of logs to process (default: 10)")
    parser.add_argument("--list-analyzers", action="store_true", help="List available analyzer types and exit")

    args = parser.parse_args()

    if args.list_analyzers:
        print_available_analyzers()
        return 0

    try:
        print(f"Initializing {args.analyzer} analyzer...")

        config = AnalyzerFactory.get_analyzer_config(args.analyzer)
        if not config:
            print(f"Error: Unsupported analyzer type '{args.analyzer}'")
            print_available_analyzers()
            return 1

        model_name = args.model if args.model else config["model"]

        # Validate API key
        env_var = config["env_var"]
        api_key = os.getenv(env_var)
        print("\nEnvironment Variables Check:")
        print(f"- {env_var}: {'Set' if api_key else 'Not set'}")

        if not api_key:
            print(f"\n❌ Missing API key: {env_var}")
            print("Add it to your .env file or export it:")
            print(f"   export {env_var}=your_api_key_here")
            return 1

        print(f"✅ Using {env_var} for authentication")

        # Create analyzer
        analyzer = AnalyzerFactory.create_analyzer(args.analyzer, model_name=model_name)

        # Initialize database
        db = DatabaseManager(db_path="events.db")
        print("✅ Connected to SQLite database (events.db)")

        # Load logs
        print(f"\nLoading up to {args.max_logs} logs from {args.log_file}...")
        logs = load_mitm_logs(args.log_file, max_logs=args.max_logs)
        print(f"Loaded {len(logs)} log entries")

        if not logs:
            print("⚠️  No valid log entries found")
            return 0

        # Run analysis
        print(f"\n🚀 Starting analysis with {analyzer.get_model_name()}...")
        results = analyze_logs(logs, analyzer, db=db, output_file=args.output)

        if not results:
            print("⚠️  No analysis results returned")
            return 0

        # Summary
        severity_scores = [r["severity"] for r in results if r is not None]
        avg_severity = sum(severity_scores) / len(severity_scores) if severity_scores else 0
        high_severity = sum(1 for s in severity_scores if s >= 7)

        print("\n=== Analysis Complete ===")
        print(f"Analyzer: {analyzer.get_model_name()}")
        print(f"Total requests analyzed: {len(results)}")
        print(f"Average severity: {avg_severity:.2f}/10")
        print(f"High severity findings (≥7): {high_severity}")

        # DB stats
        stats = db.get_stats()
        print("\n📊 Database Summary:")
        print(f"  Total Events: {stats['total_events']}")
        print(f"  Recent (24h): {stats['recent_events']}")
        print("  By Decision:")
        for decision, count in stats['decisions'].items():
            print(f"    {decision}: {count}")

        # Save summary JSON
        summary = {
            "analyzer": analyzer.get_model_name(),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_requests": len(results),
            "average_severity": round(avg_severity, 2),
            "high_severity_findings": high_severity,
            "details_file": args.output,
        }
        summary_file = f"{Path(args.output).stem}_summary.json"
        with open(summary_file, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)
        print(f"\n🗂️ Summary saved to {summary_file}")

    except KeyboardInterrupt:
        print("\n⏹️  Analysis interrupted by user")
        return 1
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    exit(main())
