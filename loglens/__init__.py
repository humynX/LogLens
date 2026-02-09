"""
LogLens - AI-Powered Security Log Analysis
============================================
Natural language queries for security logs.
Zero-hardcoding architecture - all intelligence from ML/LLM.

Copyright (c) 2024 HUMYNX
License: Apache 2.0
"""

__version__ = "0.1.0"
__author__ = "HUMYNX"
__license__ = "Apache-2.0"

from loglens.core.engine import LogLensEngine
from loglens.core.query import QueryEngine, QueryResult
from loglens.core.parser import LogParser, ParsedLog
from loglens.core.detector import SourceDetector, DetectedSource
from loglens.core.analyzer import SecurityAnalyzer, SecurityContext
from loglens.core.learner import PatternLearner

__all__ = [
    "LogLensEngine",
    "QueryEngine",
    "QueryResult", 
    "LogParser",
    "ParsedLog",
    "SourceDetector",
    "DetectedSource",
    "SecurityAnalyzer",
    "SecurityContext",
    "PatternLearner",
]

# Quick access functions
def analyze(log_path: str, query: str = None) -> dict:
    """
    Quick analysis of a log file.
    
    Args:
        log_path: Path to log file
        query: Optional natural language query
        
    Returns:
        Analysis results dictionary
    """
    engine = LogLensEngine()
    engine.load(log_path)
    
    if query:
        return engine.query(query)
    else:
        return engine.hunt()


def query(logs: list, question: str) -> dict:
    """
    Query logs with natural language.
    
    Args:
        logs: List of log entries (dicts or strings)
        question: Natural language question
        
    Returns:
        Query results dictionary
    """
    engine = LogLensEngine()
    engine.add_logs(logs)
    return engine.query(question)
