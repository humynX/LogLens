#!/usr/bin/env python3
"""
LogLens CLI
============
AI-Powered Security Log Analysis from the command line.

Usage:
    loglens query "show me failed logins" /var/log/auth.log
    loglens analyze /var/log/
    loglens hunt /var/log/syslog
    loglens investigate /var/log/

Author: HUMYNX Team
"""

import sys
import json
import argparse
import logging
from pathlib import Path
from typing import Optional

from loglens import __version__
from loglens.core.engine import LogLensEngine
from loglens.utils.llm import LLMConfig
from loglens.utils.output import (
    Colors, print_banner, print_status, print_header,
    print_subheader, print_key_value, print_log_event,
    print_threat_summary, print_query_result, print_hunt_result,
    print_json, print_progress
)


def setup_logging(verbose: bool = False):
    """Configure logging."""
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser."""
    parser = argparse.ArgumentParser(
        prog='loglens',
        description='AI-Powered Security Log Analysis',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  loglens query "show me failed logins" /var/log/auth.log
  loglens analyze /var/log/syslog --max-lines 1000
  loglens hunt /var/log/ --output results.json
  loglens investigate /var/log/auth.log

For more information, visit: https://github.com/humynx/loglens
        """
    )
    
    parser.add_argument(
        '-v', '--version',
        action='version',
        version=f'LogLens v{__version__}'
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    parser.add_argument(
        '--json',
        action='store_true',
        help='Output results as JSON'
    )
    
    # LLM configuration
    parser.add_argument(
        '--ollama-url',
        default='http://localhost:11434',
        help='Ollama server URL (default: http://localhost:11434)'
    )
    
    parser.add_argument(
        '--model',
        default='llama3.2',
        help='LLM model to use (default: llama3.2)'
    )
    
    # Subcommands
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Query command
    query_parser = subparsers.add_parser(
        'query',
        help='Query logs with natural language'
    )
    query_parser.add_argument(
        'question',
        help='Natural language question'
    )
    query_parser.add_argument(
        'path',
        help='Path to log file or directory'
    )
    query_parser.add_argument(
        '--max-lines',
        type=int,
        help='Maximum lines to load'
    )
    query_parser.add_argument(
        '--limit',
        type=int,
        default=100,
        help='Maximum results to return (default: 100)'
    )
    query_parser.add_argument(
        '--output', '-o',
        help='Export results to file (JSON, CSV, or TXT)'
    )
    query_parser.add_argument(
        '--show-all',
        action='store_true',
        help='Show all matching results in terminal (not just first 10)'
    )
    
    # Analyze command
    analyze_parser = subparsers.add_parser(
        'analyze',
        help='Analyze logs for threats'
    )
    analyze_parser.add_argument(
        'path',
        help='Path to log file or directory'
    )
    analyze_parser.add_argument(
        '--max-lines',
        type=int,
        help='Maximum lines to analyze'
    )
    
    # Hunt command
    hunt_parser = subparsers.add_parser(
        'hunt',
        help='Threat hunt across logs'
    )
    hunt_parser.add_argument(
        'path',
        help='Path to log file or directory'
    )
    hunt_parser.add_argument(
        '--max-lines',
        type=int,
        help='Maximum lines to hunt through'
    )
    hunt_parser.add_argument(
        '--output', '-o',
        help='Output file for results (JSON)'
    )
    
    # Investigate command (interactive)
    investigate_parser = subparsers.add_parser(
        'investigate',
        help='Interactive investigation mode'
    )
    investigate_parser.add_argument(
        'path',
        help='Path to log file or directory'
    )
    investigate_parser.add_argument(
        '--max-lines',
        type=int,
        help='Maximum lines to load'
    )
    
    # Parse command
    parse_parser = subparsers.add_parser(
        'parse',
        help='Parse and show log structure'
    )
    parse_parser.add_argument(
        'path',
        help='Path to log file'
    )
    parse_parser.add_argument(
        '--max-lines',
        type=int,
        default=10,
        help='Lines to parse'
    )
    
    # Summary command
    summary_parser = subparsers.add_parser(
        'summary',
        help='Show summary of log data'
    )
    summary_parser.add_argument(
        'path',
        help='Path to log file or directory'
    )
    summary_parser.add_argument(
        '--max-lines',
        type=int,
        help='Maximum lines to analyze'
    )
    
    return parser


def cmd_query(args, engine: LogLensEngine):
    """Execute query command."""
    # Load logs
    print_status(f"Loading logs from {args.path}...", "loading")
    count = engine.load(args.path, args.max_lines)
    print_status(f"Loaded {count} logs", "success")
    
    # Execute query
    print_status("Executing query...", "loading")
    result = engine.query(args.question)
    result_dict = result.to_dict()
    
    # Handle export if requested
    if args.output:
        export_results(result_dict, args.output)
        print_status(f"Results exported to {args.output}", "success")
    
    if args.json:
        print_json(result_dict)
    else:
        print()
        # Pass show_all flag to control display
        print_query_result(result_dict, show_all=getattr(args, 'show_all', False))


def export_results(result: dict, output_path: str):
    """Export query results to file."""
    matches = result.get("matches", [])
    
    # Determine format from extension
    path = Path(output_path)
    ext = path.suffix.lower()
    
    if ext == '.json':
        # Full JSON export
        with open(output_path, 'w') as f:
            json.dump(result, f, indent=2, default=str)
    
    elif ext == '.csv':
        # CSV export
        import csv
        with open(output_path, 'w', newline='') as f:
            if matches:
                # Get all unique field names
                fieldnames = ['raw', 'timestamp']
                for match in matches:
                    for key in match.get('fields', {}).keys():
                        if key not in fieldnames:
                            fieldnames.append(key)
                    for key in match.get('normalized', {}).keys():
                        if key not in fieldnames:
                            fieldnames.append(key)
                
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                
                for match in matches:
                    row = {
                        'raw': match.get('raw', ''),
                        'timestamp': match.get('timestamp', ''),
                    }
                    row.update(match.get('fields', {}))
                    row.update(match.get('normalized', {}))
                    writer.writerow(row)
    
    elif ext == '.txt':
        # Plain text export (just raw logs)
        with open(output_path, 'w') as f:
            f.write(f"# Query: {result.get('query', '')}\n")
            f.write(f"# Total matches: {result.get('total_found', len(matches))}\n")
            f.write(f"# Exported: {len(matches)} results\n")
            f.write("#" + "=" * 60 + "\n\n")
            
            for match in matches:
                f.write(match.get('raw', '') + '\n')
    
    else:
        # Default to JSON
        with open(output_path, 'w') as f:
            json.dump(result, f, indent=2, default=str)


def cmd_analyze(args, engine: LogLensEngine):
    """Execute analyze command."""
    # Load logs
    print_status(f"Loading logs from {args.path}...", "loading")
    count = engine.load(args.path, args.max_lines)
    print_status(f"Loaded {count} logs", "success")
    
    # Get summary
    print_status("Analyzing...", "loading")
    summary = engine.summary()
    
    if args.json:
        print_json(summary)
    else:
        print_header("LOG ANALYSIS")
        print_key_value("Total logs", summary["total_logs"])
        
        if summary.get("source"):
            print_subheader("Source Detection")
            print_key_value("Type", summary["source"]["type"])
            print_key_value("Platform", summary["source"]["platform"])
            print_key_value("Product", summary["source"]["product"])
            print_key_value("Format", summary["source"]["format"])
        
        if summary.get("time_range"):
            print_subheader("Time Range")
            print_key_value("Earliest", summary["time_range"]["earliest"])
            print_key_value("Latest", summary["time_range"]["latest"])
        
        if summary.get("top_fields"):
            print_subheader("Top Fields")
            for field in summary["top_fields"][:10]:
                print_key_value(field["name"], f"{field['count']} occurrences")
        
        # Quick threat check
        print_subheader("Security Summary")
        print_key_value("Threats in sample", f"{summary['threats_in_sample']}/{summary['sample_size']}")
        
        if summary["threats_in_sample"] > 0:
            print_status("Potential threats detected. Run 'loglens hunt' for details.", "warning")


def cmd_hunt(args, engine: LogLensEngine):
    """Execute hunt command."""
    # Load logs
    print_status(f"Loading logs from {args.path}...", "loading")
    count = engine.load(args.path, args.max_lines)
    print_status(f"Loaded {count} logs", "success")
    
    # Run hunt
    print_status("Threat hunting...", "loading")
    result = engine.hunt()
    
    if args.json or args.output:
        result_dict = result.to_dict()
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(result_dict, f, indent=2, default=str)
            print_status(f"Results saved to {args.output}", "success")
        
        if args.json:
            print_json(result_dict)
    else:
        print()
        print_hunt_result(result.to_dict())


def cmd_investigate(args, engine: LogLensEngine):
    """Execute investigate command (interactive)."""
    # Load logs
    print_status(f"Loading logs from {args.path}...", "loading")
    count = engine.load(args.path, args.max_lines)
    print_status(f"Loaded {count} logs", "success")
    
    # Start interactive mode
    engine.interactive()


def cmd_parse(args, engine: LogLensEngine):
    """Execute parse command."""
    # Load limited logs
    count = engine.load(args.path, args.max_lines)
    
    if args.json:
        logs_data = [log.to_dict() for log in engine.logs[:args.max_lines]]
        print_json(logs_data)
    else:
        print_header("PARSED LOGS")
        
        # Show source detection
        if engine.source:
            print_subheader("Detected Source")
            print_key_value("Type", engine.source.source_type)
            print_key_value("Platform", engine.source.source_platform)
            print_key_value("Format", engine.source.log_format)
        
        print_subheader(f"Parsed Events ({len(engine.logs)})")
        
        for i, log in enumerate(engine.logs[:args.max_lines]):
            print(f"\n{Colors.BOLD}Event {i+1}:{Colors.END}")
            print(f"  {Colors.DIM}Raw:{Colors.END} {log.raw[:100]}...")
            print(f"  {Colors.DIM}Fields:{Colors.END}")
            for field, value in list(log.fields.items())[:10]:
                print(f"    {field}: {str(value)[:50]}")


def cmd_summary(args, engine: LogLensEngine):
    """Execute summary command."""
    # Load logs
    print_status(f"Loading logs from {args.path}...", "loading")
    count = engine.load(args.path, args.max_lines)
    
    summary = engine.summary()
    
    if args.json:
        print_json(summary)
    else:
        print_header("LOG SUMMARY")
        print_key_value("Total logs", summary["total_logs"])
        print_key_value("Files loaded", len(summary.get("files_loaded", [])))
        
        if summary.get("learner_stats"):
            stats = summary["learner_stats"]
            print_key_value("Fields discovered", stats.get("fields_discovered", 0))
            print_key_value("Users baselined", stats.get("users_baselined", 0))
            print_key_value("Hosts baselined", stats.get("hosts_baselined", 0))


def main():
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()
    
    # Setup
    setup_logging(args.verbose)
    
    # Show banner for interactive commands
    if args.command in ['investigate', None]:
        print_banner()
    
    # No command specified
    if not args.command:
        parser.print_help()
        return 0
    
    # Create engine with config
    config = LLMConfig(
        ollama_url=args.ollama_url,
        ollama_model=args.model,
    )
    
    try:
        engine = LogLensEngine(config)
        
        # Check LLM availability
        if not engine.llm.is_available:
            print_status(
                "No LLM available. Install Ollama or set GROQ_API_KEY for full functionality.",
                "warning"
            )
        
        # Dispatch command
        if args.command == 'query':
            cmd_query(args, engine)
        elif args.command == 'analyze':
            cmd_analyze(args, engine)
        elif args.command == 'hunt':
            cmd_hunt(args, engine)
        elif args.command == 'investigate':
            cmd_investigate(args, engine)
        elif args.command == 'parse':
            cmd_parse(args, engine)
        elif args.command == 'summary':
            cmd_summary(args, engine)
        else:
            parser.print_help()
        
        return 0
        
    except FileNotFoundError as e:
        print_status(f"File not found: {e}", "error")
        return 1
    except KeyboardInterrupt:
        print_status("\nInterrupted.", "warning")
        return 130
    except Exception as e:
        if args.verbose:
            raise
        print_status(f"Error: {e}", "error")
        return 1


if __name__ == '__main__':
    sys.exit(main())
