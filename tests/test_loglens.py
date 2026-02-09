"""
LogLens Test Suite
==================
Comprehensive tests for all LogLens components.

Run with: pytest tests/ -v
"""

import pytest
import json
import tempfile
import os
from datetime import datetime
from pathlib import Path

# Import LogLens components
from loglens import LogLensEngine, analyze, query
from loglens.core.detector import SourceDetector, DetectedSource
from loglens.core.parser import LogParser, ParsedLog
from loglens.core.analyzer import SecurityAnalyzer, SecurityContext
from loglens.core.learner import PatternLearner, Baseline, AnomalyScore
from loglens.core.query import QueryEngine, QueryResult
from loglens.utils.llm import LLMInterface, LLMConfig


# =============================================================================
# Test Data
# =============================================================================

SAMPLE_SYSLOG = """Jan 15 03:42:01 webserver sshd[12901]: Failed password for admin from 185.220.101.34 port 44521 ssh2
Jan 15 03:42:03 webserver sshd[12903]: Failed password for admin from 185.220.101.34 port 44523 ssh2
Jan 15 08:30:15 webserver sshd[14001]: Accepted password for admin from 10.0.1.25 port 55123 ssh2"""

SAMPLE_JSON_LOG = '{"timestamp": "2024-01-15T10:15:00.000Z", "EventID": 4624, "LogonType": 10, "TargetUserName": "admin", "IpAddress": "203.0.113.50"}'

SAMPLE_ATTACK_SEQUENCE = [
    {"timestamp": "2024-01-15T10:15:00Z", "event": "login", "user": "admin", "source_ip": "203.0.113.50", "status": "success"},
    {"timestamp": "2024-01-15T10:15:30Z", "event": "process", "user": "admin", "command": "powershell.exe -enc BASE64STRING", "status": "started"},
    {"timestamp": "2024-01-15T10:16:00Z", "event": "process", "user": "admin", "command": "whoami /all", "status": "started"},
    {"timestamp": "2024-01-15T10:16:30Z", "event": "process", "user": "admin", "command": "net user /domain", "status": "started"},
]


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def llm_config():
    """Create test LLM config."""
    return LLMConfig(
        ollama_url="http://localhost:11434",
        ollama_model="llama3.2",
    )


@pytest.fixture
def engine(llm_config):
    """Create LogLens engine."""
    return LogLensEngine(llm_config)


@pytest.fixture
def detector(llm_config):
    """Create source detector."""
    llm = LLMInterface(llm_config)
    return SourceDetector(llm)


@pytest.fixture
def parser(detector):
    """Create log parser."""
    return LogParser(detector=detector)


@pytest.fixture
def analyzer():
    """Create security analyzer."""
    return SecurityAnalyzer()


@pytest.fixture
def learner():
    """Create pattern learner."""
    return PatternLearner()


@pytest.fixture
def temp_log_file():
    """Create temporary log file."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
        f.write(SAMPLE_SYSLOG)
        temp_path = f.name
    
    yield temp_path
    
    # Cleanup
    os.unlink(temp_path)


# =============================================================================
# Source Detector Tests
# =============================================================================

class TestSourceDetector:
    """Tests for source detection."""
    
    def test_detect_syslog(self, detector):
        """Test syslog format detection."""
        log = "Jan 15 03:42:01 webserver sshd[12901]: Failed password for admin"
        result = detector.detect(log)
        
        assert isinstance(result, DetectedSource)
        assert result.log_format in ["syslog", "text"]
        assert result.confidence > 0
    
    def test_detect_json(self, detector):
        """Test JSON format detection."""
        result = detector.detect(SAMPLE_JSON_LOG)
        
        assert isinstance(result, DetectedSource)
        assert result.log_format == "json"
        assert result.confidence > 0.5
    
    def test_detect_batch(self, detector):
        """Test batch detection."""
        logs = SAMPLE_SYSLOG.strip().split('\n')
        result = detector.detect_batch(logs)
        
        assert isinstance(result, DetectedSource)
    
    def test_signature_caching(self, detector):
        """Test that signatures are cached."""
        log = "Jan 15 03:42:01 webserver sshd[12901]: Test log"
        
        # First detection
        detector.detect(log)
        initial_llm_calls = detector.stats.get("llm_detections", 0)
        
        # Second detection should use cache
        detector.detect(log)
        
        # Cache should have been hit
        assert detector.stats.get("cache_hits", 0) > 0


# =============================================================================
# Log Parser Tests
# =============================================================================

class TestLogParser:
    """Tests for log parsing."""
    
    def test_parse_syslog(self, parser):
        """Test syslog parsing."""
        log = "Jan 15 03:42:01 webserver sshd[12901]: Failed password for admin from 185.220.101.34"
        result = parser.parse(log)
        
        assert isinstance(result, ParsedLog)
        assert result.raw == log
        assert len(result.fields) > 0
    
    def test_parse_json(self, parser):
        """Test JSON log parsing."""
        result = parser.parse(SAMPLE_JSON_LOG)
        
        assert isinstance(result, ParsedLog)
        assert result.parse_method == "json"
        assert result.parse_confidence == 1.0
        assert "EventID" in result.fields
        assert result.fields["EventID"] == 4624
    
    def test_parse_batch(self, parser):
        """Test batch parsing."""
        logs = SAMPLE_SYSLOG.strip().split('\n')
        results = parser.parse_batch(logs)
        
        assert len(results) == 3
        assert all(isinstance(r, ParsedLog) for r in results)
    
    def test_parse_file(self, parser, temp_log_file):
        """Test file parsing."""
        results = parser.parse_file(temp_log_file)
        
        assert len(results) == 3
        assert all(isinstance(r, ParsedLog) for r in results)
    
    def test_timestamp_extraction(self, parser):
        """Test timestamp extraction."""
        result = parser.parse(SAMPLE_JSON_LOG)
        
        # JSON log has ISO timestamp
        assert result.timestamp is not None
        assert isinstance(result.timestamp, datetime)


# =============================================================================
# Security Analyzer Tests
# =============================================================================

class TestSecurityAnalyzer:
    """Tests for security analysis."""
    
    def test_analyze_normal_event(self, analyzer, parser):
        """Test analysis of normal event."""
        log = '{"timestamp": "2024-01-15T08:30:00Z", "event": "login", "user": "jdoe", "source_ip": "10.0.1.50", "status": "success"}'
        parsed = parser.parse(log)
        
        result = analyzer.analyze(parsed)
        
        assert isinstance(result, SecurityContext)
        assert result.risk_level in ["info", "low", "medium", "high", "critical"]
    
    def test_analyze_suspicious_event(self, analyzer, parser):
        """Test analysis of suspicious event."""
        log = '{"timestamp": "2024-01-15T03:00:00Z", "event": "login", "user": "admin", "source_ip": "185.220.101.34", "status": "failed", "failure_count": 50}'
        parsed = parser.parse(log)
        
        result = analyzer.analyze(parsed)
        
        assert isinstance(result, SecurityContext)
        # Should detect some level of suspicion
        # Note: Actual detection depends on LLM availability
    
    def test_hunt(self, analyzer, parser):
        """Test threat hunting."""
        logs = [parser.parse(json.dumps(e)) for e in SAMPLE_ATTACK_SEQUENCE]
        
        result = analyzer.hunt(logs)
        
        assert result.total_events == len(logs)
        # Hunt result should have findings structure
        assert hasattr(result, 'critical_findings')
        assert hasattr(result, 'high_findings')


# =============================================================================
# Pattern Learner Tests
# =============================================================================

class TestPatternLearner:
    """Tests for pattern learning."""
    
    def test_learn_from_log(self, learner, parser):
        """Test learning from a single log."""
        log = '{"user": "jdoe", "action": "login", "host": "server01"}'
        parsed = parser.parse(log)
        
        learner.learn(parsed)
        
        assert learner.total_events_learned == 1
        assert len(learner.field_stats) > 0
    
    def test_learn_batch(self, learner, parser):
        """Test batch learning."""
        logs = [parser.parse(json.dumps(e)) for e in SAMPLE_ATTACK_SEQUENCE]
        
        learner.learn_batch(logs)
        
        assert learner.total_events_learned == len(logs)
    
    def test_field_stats(self, learner, parser):
        """Test field statistics collection."""
        logs = [
            '{"user": "jdoe", "action": "login"}',
            '{"user": "jdoe", "action": "logout"}',
            '{"user": "admin", "action": "login"}',
        ]
        parsed = [parser.parse(log) for log in logs]
        learner.learn_batch(parsed)
        
        user_stats = learner.get_field_stats("user")
        
        assert user_stats is not None
        assert user_stats.occurrence_count == 3
        assert user_stats.unique_values == 2
    
    def test_anomaly_scoring(self, learner, parser):
        """Test anomaly scoring."""
        # Learn normal patterns
        normal_logs = [
            '{"user": "jdoe", "action": "login", "hour": 9}',
            '{"user": "jdoe", "action": "login", "hour": 10}',
            '{"user": "jdoe", "action": "login", "hour": 14}',
        ] * 10  # Repeat to build baseline
        
        for log in normal_logs:
            learner.learn(parser.parse(log))
        
        # Score an anomalous log
        anomalous = '{"user": "unknown_user", "action": "admin_command", "hour": 3}'
        anomaly_score = learner.score_anomaly(parser.parse(anomalous))
        
        assert isinstance(anomaly_score, AnomalyScore)
        assert 0 <= anomaly_score.score <= 1


# =============================================================================
# Query Engine Tests
# =============================================================================

class TestQueryEngine:
    """Tests for natural language queries."""
    
    def test_simple_query(self, parser, learner):
        """Test simple query execution."""
        query_engine = QueryEngine(learner=learner)
        
        logs = [parser.parse(json.dumps(e)) for e in SAMPLE_ATTACK_SEQUENCE]
        query_engine.add_logs(logs)
        
        result = query_engine.query("show me all events")
        
        assert isinstance(result, QueryResult)
        assert result.total_found > 0
    
    def test_filtered_query(self, parser, learner):
        """Test filtered query."""
        query_engine = QueryEngine(learner=learner)
        
        logs = [parser.parse(json.dumps(e)) for e in SAMPLE_ATTACK_SEQUENCE]
        query_engine.add_logs(logs)
        
        result = query_engine.query("show events from user admin")
        
        assert isinstance(result, QueryResult)
        # All our sample events are from admin
        assert result.total_found > 0


# =============================================================================
# Engine Integration Tests
# =============================================================================

class TestLogLensEngine:
    """Integration tests for the main engine."""
    
    def test_engine_creation(self, engine):
        """Test engine can be created."""
        assert engine is not None
        assert engine.log_count == 0
    
    def test_add_logs(self, engine):
        """Test adding logs programmatically."""
        logs = [json.dumps(e) for e in SAMPLE_ATTACK_SEQUENCE]
        engine.add_logs(logs)
        
        assert engine.log_count == len(logs)
    
    def test_load_file(self, engine, temp_log_file):
        """Test loading logs from file."""
        count = engine.load(temp_log_file)
        
        assert count == 3
        assert engine.log_count == 3
    
    def test_query(self, engine):
        """Test query method."""
        logs = [json.dumps(e) for e in SAMPLE_ATTACK_SEQUENCE]
        engine.add_logs(logs)
        
        result = engine.query("show all events")
        
        assert isinstance(result, QueryResult)
    
    def test_search(self, engine):
        """Test simple keyword search."""
        logs = [json.dumps(e) for e in SAMPLE_ATTACK_SEQUENCE]
        engine.add_logs(logs)
        
        results = engine.search("admin")
        
        assert len(results) > 0
    
    def test_summary(self, engine):
        """Test summary generation."""
        logs = [json.dumps(e) for e in SAMPLE_ATTACK_SEQUENCE]
        engine.add_logs(logs)
        
        summary = engine.summary()
        
        assert "total_logs" in summary
        assert summary["total_logs"] == len(logs)
    
    def test_clear(self, engine):
        """Test clearing logs."""
        logs = [json.dumps(e) for e in SAMPLE_ATTACK_SEQUENCE]
        engine.add_logs(logs)
        
        assert engine.log_count > 0
        
        engine.clear()
        
        assert engine.log_count == 0


# =============================================================================
# API Function Tests
# =============================================================================

class TestAPIFunctions:
    """Tests for top-level API functions."""
    
    def test_query_function(self):
        """Test the quick query function."""
        logs = [{"event": "test", "value": i} for i in range(5)]
        
        result = query(logs, "show all events")
        
        assert isinstance(result, dict)
    
    def test_analyze_function(self, temp_log_file):
        """Test the quick analyze function."""
        result = analyze(temp_log_file)
        
        assert isinstance(result, dict)


# =============================================================================
# Edge Cases and Error Handling
# =============================================================================

class TestEdgeCases:
    """Tests for edge cases and error handling."""
    
    def test_empty_log(self, parser):
        """Test parsing empty log."""
        result = parser.parse("")
        
        assert isinstance(result, ParsedLog)
    
    def test_malformed_json(self, parser):
        """Test parsing malformed JSON."""
        result = parser.parse("{not valid json")
        
        # Should fall back to text parsing
        assert isinstance(result, ParsedLog)
        assert result.parse_method != "json"
    
    def test_very_long_log(self, parser):
        """Test parsing very long log line."""
        long_log = "A" * 10000
        result = parser.parse(long_log)
        
        assert isinstance(result, ParsedLog)
    
    def test_unicode_log(self, parser):
        """Test parsing log with unicode."""
        log = '{"message": "Error: 文件未找到", "user": "用户"}'
        result = parser.parse(log)
        
        assert isinstance(result, ParsedLog)
    
    def test_query_no_logs(self):
        """Test querying with no logs loaded."""
        engine = LogLensEngine()
        
        result = engine.query("show all events")
        
        assert result.total_found == 0


# =============================================================================
# Performance Tests (Optional - mark as slow)
# =============================================================================

@pytest.mark.slow
class TestPerformance:
    """Performance tests."""
    
    def test_large_batch_parsing(self, parser):
        """Test parsing large batch of logs."""
        import time
        
        # Generate 1000 logs
        logs = [f'{{"event": "test", "index": {i}}}' for i in range(1000)]
        
        start = time.time()
        results = parser.parse_batch(logs)
        elapsed = time.time() - start
        
        assert len(results) == 1000
        # Should complete in reasonable time (< 10 seconds without LLM)
        # With LLM this may be slower
    
    def test_learner_scalability(self, learner, parser):
        """Test learner with many events."""
        # Learn from 1000 events
        for i in range(1000):
            log = f'{{"user": "user{i % 10}", "action": "action{i % 5}", "value": {i}}}'
            learner.learn(parser.parse(log))
        
        assert learner.total_events_learned == 1000
        assert len(learner.field_stats) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
