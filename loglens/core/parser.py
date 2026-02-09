"""
LogLens - Efficient Log Parser
===============================
Universal log parser with EFFICIENT batch processing.

Key Innovation: Learn Once, Apply Many
--------------------------------------
Instead of sending each log to LLM (which would be O(n) LLM calls),
we:
1. Sample a small number of logs (10-50)
2. Send sample to LLM to learn the extraction pattern
3. Apply the learned pattern to ALL logs (no LLM needed)
4. Only fall back to LLM for logs that don't match the pattern

This makes 1 million logs take ~1-2 LLM calls, not 1 million.

Economics:
- Old approach: 1M logs × $0.003/call = $3,000 and 5+ days
- New approach: 1M logs × 1 call = $0.003 and seconds

Author: HUMYNX Team
"""

import json
import re
import logging
from typing import Optional, Dict, List, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from loglens.utils.llm import LLMInterface, get_llm
from loglens.core.detector import SourceDetector, DetectedSource

logger = logging.getLogger("loglens.parser")


@dataclass
class ParsedLog:
    """A parsed log entry with extracted fields."""
    raw: str                              # Original raw log
    fields: Dict[str, Any]                # Extracted fields
    timestamp: Optional[datetime] = None  # Parsed timestamp
    source: Optional[DetectedSource] = None
    
    # Standard normalized fields (when available)
    normalized: Dict[str, Any] = field(default_factory=dict)
    
    # Parsing metadata
    parse_method: str = "pattern"  # pattern, json, llm, fallback
    parse_confidence: float = 0.0
    
    def to_dict(self) -> Dict:
        return {
            "raw": self.raw,
            "fields": self.fields,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "source": self.source.to_dict() if self.source else None,
            "normalized": self.normalized,
            "parse_method": self.parse_method,
            "parse_confidence": self.parse_confidence,
        }
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get a field value (checks fields, then normalized)."""
        if key in self.fields:
            return self.fields[key]
        return self.normalized.get(key, default)


@dataclass
class ExtractionPattern:
    """
    A learned extraction pattern that can be applied without LLM.
    
    This is the key to efficiency - the LLM generates this ONCE,
    then we apply it to millions of logs without any LLM calls.
    """
    # The regex pattern with named capture groups
    regex_pattern: str
    
    # Field names and their semantic meanings
    field_semantics: Dict[str, str]  # {"group1": "source_ip", "group2": "user", ...}
    
    # Which field contains the timestamp
    timestamp_field: Optional[str] = None
    timestamp_format: Optional[str] = None
    
    # Compiled regex for performance
    _compiled: Any = None
    
    # Statistics
    match_count: int = 0
    fail_count: int = 0
    
    def __post_init__(self):
        """Compile the regex pattern."""
        try:
            self._compiled = re.compile(self.regex_pattern)
        except re.error as e:
            logger.warning(f"Invalid regex pattern: {e}")
            self._compiled = None
    
    def apply(self, log: str) -> Optional[Dict[str, Any]]:
        """
        Apply this pattern to a log line.
        Returns extracted fields or None if no match.
        """
        if not self._compiled:
            return None
        
        match = self._compiled.search(log)
        if not match:
            self.fail_count += 1
            return None
        
        self.match_count += 1
        
        # Extract named groups
        fields = match.groupdict()
        
        # Apply semantic mappings (with safety check)
        normalized = {}
        if isinstance(self.field_semantics, dict):
            for group_name, semantic_name in self.field_semantics.items():
                if group_name in fields and fields[group_name]:
                    normalized[semantic_name] = fields[group_name]
        
        return {
            "fields": fields,
            "normalized": normalized,
        }
    
    @property
    def success_rate(self) -> float:
        """Get the pattern match success rate."""
        total = self.match_count + self.fail_count
        if total == 0:
            return 0.0
        return self.match_count / total


class LogParser:
    """
    Efficient Universal Log Parser using LLM-generated patterns.
    
    Architecture:
    -------------
    Traditional:  Log → LLM → Fields  (for EACH log = disaster at scale)
    
    LogLens:
        1. Sample logs → LLM → Extraction Pattern (ONE call)
        2. All logs → Apply Pattern → Fields (NO LLM, pure regex)
        3. Failed logs → LLM fallback (rare, only exceptions)
    
    This achieves:
    - O(1) LLM calls instead of O(n)
    - Seconds instead of hours for large files
    - $0.01 instead of $1000s for batch processing
    """
    
    SAMPLE_SIZE = 20  # Number of logs to sample for pattern learning
    PATTERN_FAILURE_THRESHOLD = 0.3  # Re-learn if >30% logs fail pattern
    
    def __init__(self, llm: LLMInterface = None, detector: SourceDetector = None):
        self.llm = llm or get_llm()
        self.detector = detector or SourceDetector(self.llm)
        
        # Learned extraction patterns by source signature
        self._patterns: Dict[str, ExtractionPattern] = {}
        
        # Statistics
        self.stats = {
            "total_parsed": 0,
            "json_parsed": 0,
            "pattern_parsed": 0,
            "llm_parsed": 0,
            "fallback_parsed": 0,
            "patterns_learned": 0,
        }
    
    def parse(self, log: str, source: DetectedSource = None) -> ParsedLog:
        """
        Parse a single log entry.
        For batch processing, use parse_batch() which is much more efficient.
        """
        self.stats["total_parsed"] += 1
        
        # Detect source if not provided
        if source is None:
            source = self.detector.detect(log)
        
        # Try JSON parsing first (fastest, no LLM needed)
        if source.log_format == "json" or log.strip().startswith('{'):
            result = self._parse_json(log, source)
            if result:
                self.stats["json_parsed"] += 1
                return result
        
        # Check for existing pattern
        pattern_key = self._get_pattern_key(source, log)
        if pattern_key in self._patterns:
            result = self._apply_pattern(log, self._patterns[pattern_key], source)
            if result:
                self.stats["pattern_parsed"] += 1
                return result
        
        # Learn new pattern from this single log (less efficient, but works)
        pattern = self._learn_pattern_from_sample([log], source)
        if pattern:
            self._patterns[pattern_key] = pattern
            result = self._apply_pattern(log, pattern, source)
            if result:
                self.stats["pattern_parsed"] += 1
                return result
        
        # Final fallback
        self.stats["fallback_parsed"] += 1
        return self._fallback_parse(log, source)
    
    def parse_batch(self, logs: List[str], show_progress: bool = False) -> List[ParsedLog]:
        """
        EFFICIENT batch parsing - learns pattern once, applies to all.
        
        This is the key method for production use.
        
        Process:
        1. Sample N logs from the batch
        2. Detect source format (1 LLM call)
        3. Learn extraction pattern (1 LLM call)
        4. Apply pattern to ALL logs (0 LLM calls)
        5. Handle exceptions with fallback
        
        For 1 million logs, this makes ~2 LLM calls total.
        """
        if not logs:
            return []
        
        results = []
        
        # Step 1: Sample logs for learning
        sample_indices = self._get_sample_indices(len(logs), self.SAMPLE_SIZE)
        sample_logs = [logs[i] for i in sample_indices]
        
        # Step 2: Detect source from sample (1 LLM call)
        source = self.detector.detect_batch(sample_logs)
        
        # Step 3: Check if all JSON (fast path, no pattern learning needed)
        if source.log_format == "json":
            return self._parse_all_json(logs, source, show_progress)
        
        # Step 4: Learn extraction pattern from sample (1 LLM call)
        pattern_key = self._get_pattern_key(source, sample_logs[0])
        
        if pattern_key not in self._patterns:
            pattern = self._learn_pattern_from_sample(sample_logs, source)
            if pattern:
                self._patterns[pattern_key] = pattern
                self.stats["patterns_learned"] += 1
        
        pattern = self._patterns.get(pattern_key)
        
        # Step 5: Apply pattern to ALL logs (0 LLM calls!)
        failed_logs = []
        failed_indices = []
        
        for i, log in enumerate(logs):
            if show_progress and i % 10000 == 0:
                logger.info(f"Parsing progress: {i}/{len(logs)}")
            
            self.stats["total_parsed"] += 1
            
            # Try JSON first
            if log.strip().startswith('{'):
                result = self._parse_json(log, source)
                if result:
                    self.stats["json_parsed"] += 1
                    results.append(result)
                    continue
            
            # Apply learned pattern
            if pattern:
                result = self._apply_pattern(log, pattern, source)
                if result:
                    self.stats["pattern_parsed"] += 1
                    results.append(result)
                    continue
            
            # Collect failures for batch fallback
            failed_logs.append(log)
            failed_indices.append(i)
            results.append(None)  # Placeholder
        
        # Step 6: Handle failures with fallback parsing
        if failed_logs:
            logger.info(f"Pattern matched {len(logs) - len(failed_logs)}/{len(logs)} logs. "
                       f"Processing {len(failed_logs)} exceptions.")
            
            # Use fallback for failed logs (no additional LLM calls)
            for i, log in zip(failed_indices, failed_logs):
                self.stats["fallback_parsed"] += 1
                results[i] = self._fallback_parse(log, source)
        
        # Step 7: Check if pattern needs re-learning
        if pattern and pattern.success_rate < (1 - self.PATTERN_FAILURE_THRESHOLD):
            logger.warning(f"Pattern success rate is {pattern.success_rate:.1%}. "
                          f"Consider re-learning with more diverse samples.")
        
        return results
    
    def parse_file(self, filepath: str, max_lines: int = None) -> List[ParsedLog]:
        """Parse a log file efficiently."""
        logs = []
        encoding = self._detect_encoding(filepath)
        
        with open(filepath, 'r', encoding=encoding, errors='replace') as f:
            buffer = []
            
            for i, line in enumerate(f):
                if max_lines and i >= max_lines:
                    break
                
                line = line.rstrip('\n\r')
                if not line:
                    continue
                
                # Handle multi-line logs
                if self._is_continuation(line) and buffer:
                    buffer.append(line)
                else:
                    if buffer:
                        logs.append('\n'.join(buffer))
                    buffer = [line]
            
            if buffer:
                logs.append('\n'.join(buffer))
        
        # Use efficient batch parsing
        return self.parse_batch(logs, show_progress=len(logs) > 10000)
    
    def _learn_pattern_from_sample(self, sample_logs: List[str], source: DetectedSource) -> Optional[ExtractionPattern]:
        """
        Have the LLM analyze sample logs and generate an extraction pattern.
        
        This is the ONE LLM call that enables parsing millions of logs.
        The LLM outputs a regex pattern that we apply to all future logs.
        """
        if not self.llm or not self.llm.is_available:
            return None
        
        # Prepare sample for LLM - use fewer samples for cleaner output
        sample_text = "\n".join(sample_logs[:5])
        
        # Simplified prompt that encourages JSON-only output
        prompt = f'''Create a regex to parse these logs. Return ONLY a JSON object, no other text.

LOGS:
{sample_text}

JSON format needed:
{{"regex_pattern": "(?P<field>pattern)...", "field_semantics": {{"field": "meaning"}}, "confidence": 0.8}}

Use (?P<name>...) for named capture groups. Match the actual log structure.'''
        
        response = self.llm.generate_json(prompt)
        
        if not response:
            return None
        
        # Validate response is a dict (LLM might return a list)
        if not isinstance(response, dict):
            logger.warning(f"LLM returned {type(response).__name__} instead of dict")
            return None
        
        try:
            # Ensure field_semantics is a dict
            field_semantics = response.get("field_semantics", {})
            if isinstance(field_semantics, list):
                # Convert list to dict if possible
                field_semantics = {f"field_{i}": v for i, v in enumerate(field_semantics)} if field_semantics else {}
            elif not isinstance(field_semantics, dict):
                field_semantics = {}
            
            regex_pattern = response.get("regex_pattern", "")
            if not regex_pattern or not isinstance(regex_pattern, str):
                logger.warning("No valid regex_pattern in LLM response")
                return None
            
            pattern = ExtractionPattern(
                regex_pattern=regex_pattern,
                field_semantics=field_semantics,
                timestamp_field=response.get("timestamp_field"),
                timestamp_format=response.get("timestamp_format"),
            )
            
            # Validate the pattern works on at least some samples
            matches = sum(1 for log in sample_logs if pattern.apply(log))
            if matches < len(sample_logs) * 0.5:
                logger.warning(f"Learned pattern only matches {matches}/{len(sample_logs)} samples")
                # Still return it, might work better on full dataset
            
            return pattern
            
        except Exception as e:
            logger.error(f"Failed to create extraction pattern: {e}")
            return None
    def _apply_pattern(self, log: str, pattern: ExtractionPattern, source: DetectedSource) -> Optional[ParsedLog]:
        """Apply a learned pattern to a log line."""
        result = pattern.apply(log)
        if not result:
            return None
        
        # Parse timestamp if available
        timestamp = None
        if pattern.timestamp_field and pattern.timestamp_format:
            ts_value = result["fields"].get(pattern.timestamp_field)
            if ts_value:
                timestamp = self._parse_timestamp(ts_value, pattern.timestamp_format)
        
        # Try to extract timestamp from common patterns
        if not timestamp:
            timestamp = self._extract_timestamp_from_fields(result["fields"])
        
        return ParsedLog(
            raw=log,
            fields=result["fields"],
            timestamp=timestamp,
            source=source,
            normalized=result["normalized"],
            parse_method="pattern",
            parse_confidence=0.85,
        )
    
    def _parse_json(self, log: str, source: DetectedSource) -> Optional[ParsedLog]:
        """Parse JSON log - no LLM needed."""
        try:
            data = json.loads(log.strip())
            if not isinstance(data, dict):
                return None
            
            # Extract timestamp
            timestamp = self._extract_timestamp_from_fields(data)
            
            # Normalize fields
            normalized = self._normalize_fields(data)
            
            return ParsedLog(
                raw=log,
                fields=data,
                timestamp=timestamp,
                source=source,
                normalized=normalized,
                parse_method="json",
                parse_confidence=1.0,
            )
        except json.JSONDecodeError:
            return None
    
    def _parse_all_json(self, logs: List[str], source: DetectedSource, show_progress: bool = False) -> List[ParsedLog]:
        """Fast path for JSON logs - no LLM needed at all."""
        results = []
        
        for i, log in enumerate(logs):
            if show_progress and i % 10000 == 0:
                logger.info(f"JSON parsing progress: {i}/{len(logs)}")
            
            self.stats["total_parsed"] += 1
            
            result = self._parse_json(log, source)
            if result:
                self.stats["json_parsed"] += 1
                results.append(result)
            else:
                self.stats["fallback_parsed"] += 1
                results.append(self._fallback_parse(log, source))
        
        return results
    
    def _fallback_parse(self, log: str, source: DetectedSource) -> ParsedLog:
        """
        Fallback parsing without LLM.
        Extracts universal patterns (IPs, timestamps) that work for any log.
        """
        fields = {"raw": log[:500]}  # Truncate for display
        normalized = {}
        
        # Extract IP addresses (universal pattern)
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', log)
        if ips:
            fields["ip_addresses"] = ips
            if len(ips) >= 1:
                normalized["source_ip"] = ips[0]
            if len(ips) >= 2:
                normalized["dest_ip"] = ips[1]
        
        # Extract ports (universal pattern)
        ports = re.findall(r'\bport\s+(\d+)\b', log, re.IGNORECASE)
        if ports:
            fields["ports"] = ports
        
        # Extract usernames (common patterns)
        user_match = re.search(r'\b(?:user|username|account)[=:\s]+["\']?(\w+)["\']?', log, re.IGNORECASE)
        if user_match:
            normalized["user"] = user_match.group(1)
        
        # Try to parse timestamp
        timestamp = self._extract_timestamp_from_string(log)
        
        return ParsedLog(
            raw=log,
            fields=fields,
            timestamp=timestamp,
            source=source,
            normalized=normalized,
            parse_method="fallback",
            parse_confidence=0.3,
        )
    
    def _get_pattern_key(self, source: DetectedSource, sample_log: str) -> str:
        """Generate a key for caching patterns."""
        # Use source info + structural signature
        struct_sig = self._get_structural_signature(sample_log)
        return f"{source.source_type}:{source.source_platform}:{struct_sig}"
    
    def _get_structural_signature(self, log: str) -> str:
        """Get a structural signature for a log line."""
        # Replace variable content with placeholders
        sig = log[:200]
        sig = re.sub(r'\d+\.\d+\.\d+\.\d+', '<IP>', sig)
        sig = re.sub(r'\d{4}[-/]\d{2}[-/]\d{2}', '<DATE>', sig)
        sig = re.sub(r'\d{2}:\d{2}:\d{2}', '<TIME>', sig)
        sig = re.sub(r'\b\d{4,}\b', '<NUM>', sig)
        sig = re.sub(r'[a-f0-9]{32,}', '<HASH>', sig, flags=re.IGNORECASE)
        return sig[:100]
    
    def _get_sample_indices(self, total: int, sample_size: int) -> List[int]:
        """Get well-distributed sample indices."""
        if total <= sample_size:
            return list(range(total))
        
        # Take samples from beginning, middle, and end
        step = total // sample_size
        return [min(i * step, total - 1) for i in range(sample_size)]
    
    def _extract_timestamp_from_fields(self, data: Dict) -> Optional[datetime]:
        """Extract timestamp from field dictionary."""
        ts_fields = ["timestamp", "time", "@timestamp", "eventTime", "created_at", 
                     "date", "datetime", "logged_at", "event_time"]
        
        for field in ts_fields:
            if field in data and data[field]:
                ts = self._parse_timestamp(data[field])
                if ts:
                    return ts
        
        return None
    
    def _extract_timestamp_from_string(self, log: str) -> Optional[datetime]:
        """Try to extract timestamp from raw log string."""
        # ISO format
        match = re.search(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}', log)
        if match:
            return self._parse_timestamp(match.group())
        
        # Syslog format (Jan 15 03:42:01)
        match = re.search(r'([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})', log)
        if match:
            # Construct approximate datetime (current year)
            try:
                month_str, day, time_str = match.groups()
                ts_str = f"{datetime.now().year} {month_str} {day} {time_str}"
                return datetime.strptime(ts_str, "%Y %b %d %H:%M:%S")
            except:
                pass
        
        return None
    
    def _parse_timestamp(self, ts_value: Any, format_hint: str = None) -> Optional[datetime]:
        """Parse timestamp from various formats."""
        if isinstance(ts_value, datetime):
            return ts_value
        
        if not isinstance(ts_value, str):
            try:
                return datetime.fromtimestamp(float(ts_value))
            except:
                return None
        
        # Try hint format first
        if format_hint:
            try:
                return datetime.strptime(ts_value, format_hint)
            except:
                pass
        
        # Try common formats
        formats = [
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
            "%Y/%m/%d %H:%M:%S",
            "%b %d %H:%M:%S",
            "%d/%b/%Y:%H:%M:%S",
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(ts_value, fmt)
            except:
                continue
        
        return None
    
    def _normalize_fields(self, data: Dict) -> Dict:
        """Normalize common fields to standard names."""
        normalized = {}
        
        mappings = {
            "source_ip": ["src_ip", "source_address", "srcip", "src", "sourceIp", 
                         "source_ip", "IpAddress", "client_ip", "remote_addr"],
            "dest_ip": ["dst_ip", "dest_address", "dstip", "dst", "destIp", 
                       "destination_ip", "destinationIp", "server_ip"],
            "user": ["username", "user_name", "userId", "user_id", "account",
                    "TargetUserName", "SubjectUserName", "login", "email"],
            "hostname": ["host", "computer", "machine", "server", "ComputerName",
                        "host_name", "device"],
            "process": ["process_name", "processName", "exe", "image", "Image",
                       "program", "application", "app"],
            "command": ["command_line", "commandLine", "cmd", "cmdline",
                       "CommandLine", "command", "args"],
            "action": ["event_type", "eventType", "action_type", "operation",
                      "Activity", "EventType"],
            "status": ["result", "outcome", "status_code", "Status", "Result"],
        }
        
        # Flatten nested dicts for easier access
        flat_data = self._flatten_dict(data)
        
        for norm_name, variants in mappings.items():
            for variant in variants:
                # Check both original and flattened
                for src in [data, flat_data]:
                    if variant in src and src[variant]:
                        normalized[norm_name] = src[variant]
                        break
                if norm_name in normalized:
                    break
        
        return normalized
    
    def _flatten_dict(self, d: Dict, parent_key: str = '', sep: str = '_') -> Dict:
        """Flatten nested dictionary."""
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key, sep).items())
            else:
                items.append((new_key, v))
                items.append((k, v))  # Also keep original key
        return dict(items)
    
    def _detect_encoding(self, filepath: str) -> str:
        """Detect file encoding."""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                f.read(1000)
            return 'utf-8'
        except:
            return 'latin-1'
    
    def _is_continuation(self, line: str) -> bool:
        """Check if line is a continuation of previous log."""
        if line.startswith((' ', '\t')):
            return True
        if re.match(r'^\d{4}[-/]', line):
            return False
        if re.match(r'^[A-Z][a-z]{2}\s+\d', line):
            return False
        return False
    
    def get_stats(self) -> Dict:
        """Get parsing statistics."""
        return {
            **self.stats,
            "patterns_cached": len(self._patterns),
            "pattern_success_rates": {
                k: p.success_rate for k, p in self._patterns.items()
            },
            "detector_stats": self.detector.get_stats() if self.detector else {},
        }
    
    def clear_patterns(self):
        """Clear learned patterns (useful for testing)."""
        self._patterns.clear()
        self.stats["patterns_learned"] = 0
