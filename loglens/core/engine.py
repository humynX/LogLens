"""
LogLens - Main Engine
======================
Orchestrates all LogLens components into a unified interface.

Usage:
    engine = LogLensEngine()
    engine.load("/var/log/auth.log")
    
    # Query with natural language
    result = engine.query("show me failed logins from admin users")
    
    # Threat hunt
    threats = engine.hunt()

Author: HUMYNX Team
"""

import os
import json
import logging
from typing import Optional, Dict, List, Any, Union
from pathlib import Path
from datetime import datetime

from loglens.utils.llm import LLMInterface, LLMConfig, get_llm
from loglens.core.detector import SourceDetector, DetectedSource
from loglens.core.parser import LogParser, ParsedLog
from loglens.core.analyzer import SecurityAnalyzer, SecurityContext, ThreatHuntResult
from loglens.core.learner import PatternLearner
from loglens.core.query import QueryEngine, QueryResult, QueryUnderstanding

logger = logging.getLogger("loglens.engine")


class LogLensEngine:
    """
    Main LogLens engine.
    
    The LogLensEngine provides a unified interface to all LogLens
    capabilities:
    
    - Log Loading: Load logs from files, directories, or programmatically
    - Source Detection: Auto-detect log formats
    - Parsing: Extract fields from any log format
    - Security Analysis: Identify threats and suspicious activity
    - Natural Language Queries: Ask questions in plain English
    - Pattern Learning: Build baselines from your data
    - Threat Hunting: Proactively search for threats
    
    All components use LLM for intelligence, with zero hardcoded rules.
    """
    
    def __init__(self, config: LLMConfig = None):
        """
        Initialize LogLens engine.
        
        Args:
            config: Optional LLM configuration
        """
        # Core LLM
        self.llm = LLMInterface(config) if config else get_llm()
        
        # Components
        self.detector = SourceDetector(self.llm)
        self.parser = LogParser(self.llm, self.detector)
        self.analyzer = SecurityAnalyzer(self.llm)
        self.learner = PatternLearner()
        self.query_engine = QueryEngine(self.llm, self.learner)
        
        # State
        self._logs: List[ParsedLog] = []
        self._source: Optional[DetectedSource] = None
        self._loaded_files: List[str] = []
        
        # Statistics
        self.stats = {
            "files_loaded": 0,
            "logs_processed": 0,
            "queries_executed": 0,
            "hunts_performed": 0,
        }
        
        logger.info(f"LogLens Engine initialized (LLM: {self.llm.active_provider_name})")
    
    # =========================================================================
    # Loading Methods
    # =========================================================================
    
    def load(self, path: str, max_lines: int = None) -> int:
        """
        Load logs from a file or directory.
        
        Args:
            path: Path to log file or directory
            max_lines: Maximum lines to load (per file)
            
        Returns:
            Number of logs loaded
        """
        path = Path(path)
        
        if path.is_file():
            return self._load_file(str(path), max_lines)
        elif path.is_dir():
            return self._load_directory(str(path), max_lines)
        else:
            raise FileNotFoundError(f"Path not found: {path}")
    
    def _load_file(self, filepath: str, max_lines: int = None) -> int:
        """Load logs from a single file."""
        logger.info(f"Loading: {filepath}")
        
        # Parse file
        parsed_logs = self.parser.parse_file(filepath, max_lines)
        
        if parsed_logs:
            # Store source info
            self._source = parsed_logs[0].source
            
            # Add to logs
            self._logs.extend(parsed_logs)
            
            # Learn from logs
            for log in parsed_logs:
                self.learner.learn(log)
            
            # Add to query engine
            self.query_engine.add_logs(parsed_logs)
        
        self._loaded_files.append(filepath)
        self.stats["files_loaded"] += 1
        self.stats["logs_processed"] += len(parsed_logs)
        
        logger.info(f"Loaded {len(parsed_logs)} logs from {filepath}")
        return len(parsed_logs)
    
    def _load_directory(self, dirpath: str, max_lines: int = None) -> int:
        """Load logs from all files in a directory."""
        total = 0
        
        for root, _, files in os.walk(dirpath):
            for filename in files:
                # Skip hidden files and common non-log files
                if filename.startswith('.'):
                    continue
                if filename.endswith(('.py', '.pyc', '.md', '.yml', '.yaml')):
                    continue
                
                filepath = os.path.join(root, filename)
                try:
                    total += self._load_file(filepath, max_lines)
                except Exception as e:
                    logger.warning(f"Failed to load {filepath}: {e}")
        
        return total
    
    def add_logs(self, logs: Union[List[str], List[Dict], List[ParsedLog]]):
        """
        Add logs programmatically.
        
        Args:
            logs: List of raw log strings, dicts, or ParsedLog objects
        """
        for log in logs:
            if isinstance(log, ParsedLog):
                parsed = log
            elif isinstance(log, dict):
                parsed = ParsedLog(
                    raw=json.dumps(log),
                    fields=log,
                    source=None,
                )
            else:
                parsed = self.parser.parse(str(log))
            
            self._logs.append(parsed)
            self.learner.learn(parsed)
        
        self.query_engine.add_logs(self._logs[-len(logs):])
        self.stats["logs_processed"] += len(logs)
    
    def clear(self):
        """Clear all loaded logs."""
        self._logs = []
        self._source = None
        self._loaded_files = []
        self.query_engine.clear_logs()
    
    # =========================================================================
    # Query Methods
    # =========================================================================
    
    def query(self, question: str) -> QueryResult:
        """
        Query logs with natural language.
        
        Args:
            question: Natural language question
            
        Returns:
            QueryResult with matches and analysis
            
        Examples:
            >>> engine.query("show me failed logins")
            >>> engine.query("what did user admin do yesterday?")
            >>> engine.query("find PowerShell commands that download files")
        """
        self.stats["queries_executed"] += 1
        return self.query_engine.query(question)
    
    def search(self, keyword: str) -> List[ParsedLog]:
        """
        Simple keyword search (no LLM).
        
        Args:
            keyword: Keyword to search for
            
        Returns:
            List of matching logs
        """
        keyword_lower = keyword.lower()
        return [
            log for log in self._logs
            if keyword_lower in log.raw.lower()
        ]
    
    def suggest_queries(self) -> List[str]:
        """Get suggested queries based on the loaded data."""
        return self.query_engine.suggest_queries()
    
    # =========================================================================
    # Analysis Methods
    # =========================================================================
    
    def analyze(self, log: Union[str, Dict, ParsedLog] = None) -> SecurityContext:
        """
        Analyze a log for security implications.
        
        Args:
            log: Log to analyze (uses last loaded log if not provided)
            
        Returns:
            SecurityContext with risk assessment
        """
        if log is None:
            if not self._logs:
                raise ValueError("No logs loaded")
            parsed = self._logs[-1]
        elif isinstance(log, ParsedLog):
            parsed = log
        elif isinstance(log, dict):
            parsed = ParsedLog(raw=json.dumps(log), fields=log, source=None)
        else:
            parsed = self.parser.parse(str(log))
        
        return self.analyzer.analyze(parsed)
    
    def hunt(self) -> ThreatHuntResult:
        """
        Perform threat hunting across all loaded logs.
        
        Returns:
            ThreatHuntResult with findings
        """
        self.stats["hunts_performed"] += 1
        return self.analyzer.hunt(self._logs)
    
    def get_threats(self) -> List[Dict]:
        """
        Get all detected threats from loaded logs.
        
        Returns:
            List of threat findings
        """
        hunt_result = self.hunt()
        
        all_threats = []
        all_threats.extend(hunt_result.critical_findings)
        all_threats.extend(hunt_result.high_findings)
        all_threats.extend(hunt_result.medium_findings)
        
        return all_threats
    
    # =========================================================================
    # Summary Methods
    # =========================================================================
    
    def summary(self) -> Dict:
        """
        Get a summary of the loaded logs.
        
        Returns:
            Dictionary with summary statistics
        """
        if not self._logs:
            return {"status": "No logs loaded"}
        
        # Basic counts
        total_logs = len(self._logs)
        
        # Time range
        timestamps = [log.timestamp for log in self._logs if log.timestamp]
        time_range = {}
        if timestamps:
            time_range = {
                "earliest": min(timestamps).isoformat(),
                "latest": max(timestamps).isoformat(),
            }
        
        # Source info
        source_info = {}
        if self._source:
            source_info = {
                "type": self._source.source_type,
                "platform": self._source.source_platform,
                "product": self._source.source_product,
                "format": self._source.log_format,
            }
        
        # Field summary
        top_fields = [
            {"name": f.field_name, "count": f.occurrence_count}
            for f in self.learner.get_common_fields(10)
        ]
        
        # Quick threat scan (limited for performance)
        sample_size = min(100, len(self._logs))
        sample_logs = self._logs[:sample_size]
        threat_count = 0
        for log in sample_logs:
            ctx = self.analyzer.analyze(log, include_context=False)
            if ctx.is_suspicious or ctx.is_malicious:
                threat_count += 1
        
        return {
            "total_logs": total_logs,
            "files_loaded": self._loaded_files,
            "time_range": time_range,
            "source": source_info,
            "top_fields": top_fields,
            "threats_in_sample": threat_count,
            "sample_size": sample_size,
            "learner_stats": self.learner.get_stats(),
        }
    
    def get_timeline(self, limit: int = 100) -> List[Dict]:
        """
        Get a timeline of events.
        
        Args:
            limit: Maximum events to return
            
        Returns:
            List of events sorted by timestamp
        """
        # Sort by timestamp
        sorted_logs = sorted(
            [log for log in self._logs if log.timestamp],
            key=lambda x: x.timestamp,
        )
        
        timeline = []
        for log in sorted_logs[:limit]:
            timeline.append({
                "timestamp": log.timestamp.isoformat(),
                "summary": log.raw[:200],
                "source": log.source.source_type if log.source else "unknown",
            })
        
        return timeline
    
    # =========================================================================
    # Interactive Mode
    # =========================================================================
    
    def interactive(self):
        """
        Start interactive query mode.
        
        Allows continuous querying from the command line.
        """
        from loglens.utils.output import (
            print_banner, print_status, print_query_result,
            Colors
        )
        
        print_banner()
        print_status(f"Loaded {len(self._logs)} logs", "success")
        print_status(f"LLM: {self.llm.active_provider_name}", "info")
        print(f"\n{Colors.DIM}Type your queries in natural language. Type 'exit' to quit.{Colors.END}\n")
        
        while True:
            try:
                query = input(f"{Colors.CYAN}You:{Colors.END} ").strip()
                
                if not query:
                    continue
                
                if query.lower() in ['exit', 'quit', 'q']:
                    print_status("Goodbye!", "info")
                    break
                
                if query.lower() == 'help':
                    self._print_help()
                    continue
                
                if query.lower() == 'summary':
                    self._print_summary()
                    continue
                
                if query.lower() == 'hunt':
                    self._run_hunt()
                    continue
                
                # Execute query
                print()
                result = self.query(query)
                print_query_result(result.to_dict())
                print()
                
            except KeyboardInterrupt:
                print("\n")
                print_status("Interrupted. Type 'exit' to quit.", "warning")
            except Exception as e:
                print_status(f"Error: {e}", "error")
    
    def _print_help(self):
        """Print help for interactive mode."""
        from loglens.utils.output import Colors
        
        print(f"""
{Colors.BOLD}Interactive Mode Commands:{Colors.END}
  
  {Colors.CYAN}Natural language queries:{Colors.END}
    Just type your question, e.g.:
    • "show me failed logins"
    • "what did user admin do?"
    • "find PowerShell executions"
  
  {Colors.CYAN}Special commands:{Colors.END}
    summary  - Show data summary
    hunt     - Run threat hunt
    help     - Show this help
    exit     - Exit interactive mode
""")
    
    def _print_summary(self):
        """Print summary in interactive mode."""
        from loglens.utils.output import print_header, print_key_value
        
        summary = self.summary()
        print_header("DATA SUMMARY")
        print_key_value("Total logs", summary["total_logs"])
        print_key_value("Files loaded", len(summary.get("files_loaded", [])))
        
        if summary.get("source"):
            print_key_value("Source type", summary["source"]["type"])
            print_key_value("Platform", summary["source"]["platform"])
    
    def _run_hunt(self):
        """Run threat hunt in interactive mode."""
        from loglens.utils.output import print_hunt_result, print_status
        
        print_status("Running threat hunt...", "loading")
        result = self.hunt()
        print_hunt_result(result.to_dict())
    
    # =========================================================================
    # Utility Methods
    # =========================================================================
    
    def get_stats(self) -> Dict:
        """Get comprehensive statistics."""
        return {
            "engine_stats": self.stats,
            "llm": self.llm.get_stats(),
            "detector": self.detector.get_stats(),
            "parser": self.parser.get_stats(),
            "analyzer": self.analyzer.get_stats(),
            "learner": self.learner.get_stats(),
            "query_engine": self.query_engine.get_stats(),
        }
    
    @property
    def logs(self) -> List[ParsedLog]:
        """Get all loaded logs."""
        return self._logs
    
    @property
    def log_count(self) -> int:
        """Get number of loaded logs."""
        return len(self._logs)
    
    @property
    def source(self) -> Optional[DetectedSource]:
        """Get detected source information."""
        return self._source
    
    @property
    def is_ready(self) -> bool:
        """Check if engine is ready (has logs loaded)."""
        return len(self._logs) > 0
