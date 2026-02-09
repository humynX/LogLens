"""
LogLens - Source Detector
==========================
Automatically detects log source type using LLM.
ZERO hardcoded patterns - all detection via LLM reasoning.

The key innovation: Instead of maintaining hundreds of regex patterns
for different log formats, we let the LLM identify the source type
by examining the log structure and content.

Author: HUMYNX Team
"""

import json
import hashlib
import logging
from typing import Optional, Dict, List, Any
from dataclasses import dataclass, field
from collections import defaultdict

from loglens.utils.llm import LLMInterface, get_llm

logger = logging.getLogger("loglens.detector")


@dataclass
class DetectedSource:
    """Result of log source detection."""
    source_type: str       # e.g., "authentication", "firewall", "web_server"
    source_platform: str   # e.g., "windows", "linux", "cisco", "aws"
    source_product: str    # e.g., "sysmon", "palo_alto", "cloudtrail"
    log_format: str        # e.g., "json", "syslog", "csv", "cef"
    confidence: float      # 0.0 to 1.0
    detection_method: str  # "llm", "learned", "fallback"
    
    # Additional metadata
    fields_detected: List[str] = field(default_factory=list)
    timestamp_format: str = ""
    
    def to_dict(self) -> Dict:
        return {
            "source_type": self.source_type,
            "source_platform": self.source_platform,
            "source_product": self.source_product,
            "log_format": self.log_format,
            "confidence": self.confidence,
            "detection_method": self.detection_method,
            "fields_detected": self.fields_detected,
            "timestamp_format": self.timestamp_format,
        }


class SourceDetector:
    """
    Detects log source type using LLM.
    
    Key Design Principle:
    ---------------------
    Traditional log parsers maintain hundreds of regex patterns for
    different log sources (Sysmon, Apache, CloudTrail, etc.). This is:
    - Brittle (breaks with version changes)
    - Incomplete (can't handle custom logs)
    - Expensive to maintain
    
    LogLens instead uses LLM to:
    1. Examine the log structure
    2. Identify patterns and field names
    3. Infer the source type
    4. Learn from each detection for faster future lookups
    """
    
    def __init__(self, llm: LLMInterface = None):
        self.llm = llm or get_llm()
        
        # Learning cache: log signature -> detection result
        self._cache: Dict[str, DetectedSource] = {}
        
        # Learned patterns (persisted)
        self._learned_signatures: Dict[str, Dict] = {}
        
        # Statistics
        self.stats = {
            "total_detections": 0,
            "cache_hits": 0,
            "llm_detections": 0,
            "learned_detections": 0,
        }
    
    def detect(self, log_sample: str, hint: str = "") -> DetectedSource:
        """
        Detect the source type of a log sample.
        
        Args:
            log_sample: Raw log string (single line or multi-line)
            hint: Optional hint about the source (e.g., filename)
            
        Returns:
            DetectedSource with identified source information
        """
        self.stats["total_detections"] += 1
        
        # Generate signature for caching
        signature = self._generate_signature(log_sample)
        
        # Check cache
        if signature in self._cache:
            self.stats["cache_hits"] += 1
            return self._cache[signature]
        
        # Check learned patterns
        if signature in self._learned_signatures:
            self.stats["learned_detections"] += 1
            learned = self._learned_signatures[signature]
            result = DetectedSource(
                source_type=learned["source_type"],
                source_platform=learned["source_platform"],
                source_product=learned["source_product"],
                log_format=learned["log_format"],
                confidence=learned.get("confidence", 0.9),
                detection_method="learned",
                fields_detected=learned.get("fields_detected", []),
                timestamp_format=learned.get("timestamp_format", ""),
            )
            self._cache[signature] = result
            return result
        
        # Use LLM for detection
        result = self._detect_with_llm(log_sample, hint)
        self.stats["llm_detections"] += 1
        
        # Cache result
        self._cache[signature] = result
        
        # Learn from this detection
        if result.confidence > 0.7:
            self._learn_signature(signature, result)
        
        return result
    
    def detect_batch(self, log_samples: List[str]) -> DetectedSource:
        """
        Detect source type from multiple log samples.
        More accurate as it can see patterns across logs.
        """
        # Combine samples for analysis
        combined = "\n".join(log_samples[:10])  # Limit for context
        return self.detect(combined)
    
    def _generate_signature(self, log: str) -> str:
        """
        Generate a structural signature for the log.
        This captures the FORMAT, not the content.
        """
        # Normalize: remove specific values, keep structure
        normalized = log[:500]  # First 500 chars
        
        # Replace common variable patterns with placeholders
        import re
        
        # IPs
        normalized = re.sub(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', '<IP>', normalized)
        # Timestamps (various formats)
        normalized = re.sub(r'\d{4}[-/]\d{2}[-/]\d{2}[T ]\d{2}:\d{2}:\d{2}', '<TS>', normalized)
        normalized = re.sub(r'\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}', '<TS>', normalized)
        # UUIDs
        normalized = re.sub(r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', '<UUID>', normalized)
        # Numbers
        normalized = re.sub(r'\b\d{5,}\b', '<NUM>', normalized)
        
        return hashlib.md5(normalized.encode()).hexdigest()[:16]
    
    def _detect_with_llm(self, log_sample: str, hint: str = "") -> DetectedSource:
        """Use LLM to detect log source type."""
        
        prompt = f"""Analyze this log sample and identify its source.

LOG SAMPLE:
```
{log_sample[:2000]}
```

{f"HINT: This log came from: {hint}" if hint else ""}

Analyze the log structure, field names, and content to determine:
1. What type of system generated this log (authentication, firewall, web server, etc.)
2. What platform/OS (Windows, Linux, AWS, etc.)
3. What specific product if identifiable (Sysmon, Apache, CloudTrail, etc.)
4. What format the log is in (JSON, syslog, CSV, CEF, etc.)
5. What fields are present
6. What timestamp format is used

Respond with ONLY valid JSON:
{{
    "source_type": "category of log source",
    "source_platform": "platform or OS",
    "source_product": "specific product if known, otherwise 'unknown'",
    "log_format": "json|syslog|csv|cef|evtx|text|other",
    "confidence": 0.0-1.0,
    "fields_detected": ["field1", "field2"],
    "timestamp_format": "ISO8601|epoch|syslog|custom",
    "reasoning": "brief explanation"
}}"""

        response = self.llm.generate_json(prompt)
        
        if response and isinstance(response, dict):
            return DetectedSource(
                source_type=response.get("source_type", "unknown") or "unknown",
                source_platform=response.get("source_platform", "unknown") or "unknown",
                source_product=response.get("source_product", "unknown") or "unknown",
                log_format=response.get("log_format", "text") or "text",
                confidence=float(response.get("confidence", 0.5) or 0.5),
                detection_method="llm",
                fields_detected=response.get("fields_detected", []) if isinstance(response.get("fields_detected"), list) else [],
                timestamp_format=response.get("timestamp_format", "") or "",
            )
        
        # Fallback detection without LLM
        return self._fallback_detect(log_sample)
    
    def _fallback_detect(self, log_sample: str) -> DetectedSource:
        """Simple heuristic fallback when LLM unavailable."""
        log_format = "text"
        
        # Basic format detection
        if log_sample.strip().startswith('{'):
            log_format = "json"
        elif '|' in log_sample and log_sample.count('|') > 3:
            log_format = "csv"  # Pipe-delimited
        elif 'CEF:' in log_sample:
            log_format = "cef"
        
        return DetectedSource(
            source_type="unknown",
            source_platform="unknown",
            source_product="unknown",
            log_format=log_format,
            confidence=0.3,
            detection_method="fallback",
            fields_detected=[],
            timestamp_format="",
        )
    
    def _learn_signature(self, signature: str, result: DetectedSource):
        """Learn from a detection for future lookups."""
        self._learned_signatures[signature] = {
            "source_type": result.source_type,
            "source_platform": result.source_platform,
            "source_product": result.source_product,
            "log_format": result.log_format,
            "confidence": result.confidence,
            "fields_detected": result.fields_detected,
            "timestamp_format": result.timestamp_format,
        }
    
    def save_learned(self, path: str):
        """Save learned patterns to file."""
        with open(path, 'w') as f:
            json.dump(self._learned_signatures, f, indent=2)
    
    def load_learned(self, path: str):
        """Load learned patterns from file."""
        try:
            with open(path, 'r') as f:
                self._learned_signatures = json.load(f)
        except FileNotFoundError:
            pass
    
    def get_stats(self) -> Dict:
        """Get detection statistics."""
        return {
            **self.stats,
            "cached_signatures": len(self._cache),
            "learned_patterns": len(self._learned_signatures),
            "llm_available": self.llm.is_available,
        }
