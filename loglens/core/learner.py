"""
LogLens - Pattern Learner
==========================
Learns patterns from your log data over time.
Builds baselines and detects anomalies without predefined rules.

The key innovation: Instead of defining what "normal" looks like
in advance, we learn it from YOUR data. This means:
- No false positives from generic rules
- Detects anomalies specific to YOUR environment
- Gets smarter over time

Author: HUMYNX Team
"""

import json
import math
import logging
from typing import Optional, Dict, List, Any, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict, Counter

from loglens.core.parser import ParsedLog

logger = logging.getLogger("loglens.learner")


@dataclass
class FieldStats:
    """Statistics about a field."""
    field_name: str
    occurrence_count: int = 0
    unique_values: int = 0
    sample_values: List[str] = field(default_factory=list)
    value_distribution: Dict[str, int] = field(default_factory=dict)
    
    # For numeric fields
    is_numeric: bool = False
    min_value: float = 0
    max_value: float = 0
    mean_value: float = 0
    
    def to_dict(self) -> Dict:
        return {
            "field_name": self.field_name,
            "occurrence_count": self.occurrence_count,
            "unique_values": self.unique_values,
            "sample_values": self.sample_values[:10],
            "is_numeric": self.is_numeric,
            "min_value": self.min_value if self.is_numeric else None,
            "max_value": self.max_value if self.is_numeric else None,
            "mean_value": self.mean_value if self.is_numeric else None,
        }


@dataclass
class Baseline:
    """Baseline for an entity or behavior."""
    entity_type: str  # user, host, process, etc.
    entity_id: str
    
    # Activity patterns
    typical_hours: List[int] = field(default_factory=list)  # Hours of day (0-23)
    typical_days: List[int] = field(default_factory=list)   # Days of week (0-6)
    typical_sources: List[str] = field(default_factory=list)
    typical_actions: List[str] = field(default_factory=list)
    
    # Volume patterns
    events_per_hour: Dict[int, float] = field(default_factory=dict)
    events_per_day: Dict[int, float] = field(default_factory=dict)
    
    # First/last seen
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    total_events: int = 0
    
    def to_dict(self) -> Dict:
        return {
            "entity_type": self.entity_type,
            "entity_id": self.entity_id,
            "typical_hours": self.typical_hours,
            "typical_days": self.typical_days,
            "typical_sources": self.typical_sources[:20],
            "typical_actions": self.typical_actions[:20],
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "total_events": self.total_events,
        }


@dataclass
class AnomalyScore:
    """Anomaly scoring result."""
    score: float  # 0.0 (normal) to 1.0 (highly anomalous)
    reasons: List[str] = field(default_factory=list)
    
    # Component scores
    time_anomaly: float = 0.0
    behavior_anomaly: float = 0.0
    frequency_anomaly: float = 0.0
    new_entity_score: float = 0.0
    
    def to_dict(self) -> Dict:
        return {
            "score": self.score,
            "reasons": self.reasons,
            "time_anomaly": self.time_anomaly,
            "behavior_anomaly": self.behavior_anomaly,
            "frequency_anomaly": self.frequency_anomaly,
            "new_entity_score": self.new_entity_score,
        }


class PatternLearner:
    """
    Learns patterns from log data.
    
    Key Capabilities:
    -----------------
    1. Field Discovery: Learns what fields exist in your logs
    2. Value Patterns: Learns typical values for each field
    3. Behavioral Baselines: Learns normal behavior for users/hosts/processes
    4. Anomaly Detection: Scores events against learned patterns
    
    All learning is automatic - no configuration required.
    """
    
    def __init__(self):
        # Field statistics
        self.field_stats: Dict[str, FieldStats] = {}
        
        # Entity baselines
        self.user_baselines: Dict[str, Baseline] = {}
        self.host_baselines: Dict[str, Baseline] = {}
        self.process_baselines: Dict[str, Baseline] = {}
        
        # Global patterns
        self.event_frequency: Dict[str, Counter] = defaultdict(Counter)
        self.sequence_patterns: List[List[str]] = []
        
        # Learning state
        self.total_events_learned = 0
        self.learning_started: Optional[datetime] = None
        self.last_learned: Optional[datetime] = None
    
    def learn(self, log: ParsedLog):
        """
        Learn from a single log entry.
        Updates field stats, baselines, and patterns.
        """
        self.total_events_learned += 1
        now = datetime.now()
        
        if self.learning_started is None:
            self.learning_started = now
        self.last_learned = now
        
        # Learn field patterns
        self._learn_fields(log)
        
        # Learn entity baselines
        self._learn_baselines(log)
        
        # Learn temporal patterns
        self._learn_temporal(log)
    
    def learn_batch(self, logs: List[ParsedLog]):
        """Learn from multiple logs."""
        for log in logs:
            self.learn(log)
    
    def score_anomaly(self, log: ParsedLog) -> AnomalyScore:
        """
        Score how anomalous a log entry is relative to learned patterns.
        
        Returns:
            AnomalyScore with overall score and breakdown
        """
        reasons = []
        scores = []
        
        # Time-based anomaly
        time_score = self._score_time_anomaly(log)
        if time_score > 0.5:
            reasons.append(f"Unusual time (score: {time_score:.2f})")
        scores.append(("time", time_score))
        
        # Behavior anomaly
        behavior_score = self._score_behavior_anomaly(log)
        if behavior_score > 0.5:
            reasons.append(f"Unusual behavior pattern (score: {behavior_score:.2f})")
        scores.append(("behavior", behavior_score))
        
        # New entity detection
        new_entity_score = self._score_new_entity(log)
        if new_entity_score > 0.5:
            reasons.append("New or rarely seen entity")
        scores.append(("new_entity", new_entity_score))
        
        # Field value anomaly
        field_score = self._score_field_anomaly(log)
        if field_score > 0.5:
            reasons.append(f"Unusual field values (score: {field_score:.2f})")
        scores.append(("field", field_score))
        
        # Calculate weighted overall score
        weights = {"time": 0.2, "behavior": 0.3, "new_entity": 0.2, "field": 0.3}
        overall = sum(weights.get(name, 0.25) * score for name, score in scores)
        
        return AnomalyScore(
            score=min(1.0, overall),
            reasons=reasons,
            time_anomaly=dict(scores).get("time", 0),
            behavior_anomaly=dict(scores).get("behavior", 0),
            new_entity_score=dict(scores).get("new_entity", 0),
        )
    
    def get_baseline(self, entity_type: str, entity_id: str) -> Optional[Baseline]:
        """Get baseline for an entity."""
        baselines = {
            "user": self.user_baselines,
            "host": self.host_baselines,
            "process": self.process_baselines,
        }
        return baselines.get(entity_type, {}).get(entity_id)
    
    def get_field_stats(self, field_name: str) -> Optional[FieldStats]:
        """Get statistics for a field."""
        return self.field_stats.get(field_name)
    
    def get_common_fields(self, top_n: int = 20) -> List[FieldStats]:
        """Get most common fields."""
        sorted_fields = sorted(
            self.field_stats.values(),
            key=lambda x: x.occurrence_count,
            reverse=True
        )
        return sorted_fields[:top_n]
    
    def _learn_fields(self, log: ParsedLog):
        """Learn field patterns from a log."""
        for field_name, value in log.fields.items():
            if field_name not in self.field_stats:
                self.field_stats[field_name] = FieldStats(field_name=field_name)
            
            stats = self.field_stats[field_name]
            stats.occurrence_count += 1
            
            # Track value distribution
            str_value = str(value)[:100]  # Truncate long values
            stats.value_distribution[str_value] = stats.value_distribution.get(str_value, 0) + 1
            stats.unique_values = len(stats.value_distribution)
            
            # Keep sample values
            if len(stats.sample_values) < 20 and str_value not in stats.sample_values:
                stats.sample_values.append(str_value)
            
            # Check if numeric
            try:
                num_value = float(value)
                if not stats.is_numeric:
                    stats.is_numeric = True
                    stats.min_value = num_value
                    stats.max_value = num_value
                else:
                    stats.min_value = min(stats.min_value, num_value)
                    stats.max_value = max(stats.max_value, num_value)
                # Update running mean
                stats.mean_value = (stats.mean_value * (stats.occurrence_count - 1) + num_value) / stats.occurrence_count
            except (ValueError, TypeError):
                pass
    
    def _learn_baselines(self, log: ParsedLog):
        """Learn entity baselines from a log."""
        # User baseline
        user = log.get("user") or log.get("username")
        if user:
            self._update_baseline(self.user_baselines, "user", str(user), log)
        
        # Host baseline
        host = log.get("hostname") or log.get("host") or log.get("computer_name")
        if host:
            self._update_baseline(self.host_baselines, "host", str(host), log)
        
        # Process baseline
        process = log.get("process") or log.get("process_name")
        if process:
            self._update_baseline(self.process_baselines, "process", str(process), log)
    
    def _update_baseline(self, baselines: Dict[str, Baseline], entity_type: str, entity_id: str, log: ParsedLog):
        """Update baseline for an entity."""
        if entity_id not in baselines:
            baselines[entity_id] = Baseline(entity_type=entity_type, entity_id=entity_id)
        
        baseline = baselines[entity_id]
        baseline.total_events += 1
        
        # Update timestamps
        now = log.timestamp or datetime.now()
        if baseline.first_seen is None:
            baseline.first_seen = now
        baseline.last_seen = now
        
        # Update temporal patterns
        hour = now.hour
        day = now.weekday()
        
        if hour not in baseline.typical_hours:
            baseline.typical_hours.append(hour)
        if day not in baseline.typical_days:
            baseline.typical_days.append(day)
        
        # Update activity patterns
        source = log.get("source_ip") or log.get("src")
        if source and str(source) not in baseline.typical_sources:
            baseline.typical_sources.append(str(source))
            baseline.typical_sources = baseline.typical_sources[-50:]  # Keep last 50
        
        action = log.get("action") or log.get("event_type")
        if action and str(action) not in baseline.typical_actions:
            baseline.typical_actions.append(str(action))
            baseline.typical_actions = baseline.typical_actions[-50:]
    
    def _learn_temporal(self, log: ParsedLog):
        """Learn temporal patterns."""
        timestamp = log.timestamp or datetime.now()
        
        # Hourly frequency
        hour = timestamp.hour
        self.event_frequency["hourly"][hour] += 1
        
        # Daily frequency
        day = timestamp.weekday()
        self.event_frequency["daily"][day] += 1
    
    def _score_time_anomaly(self, log: ParsedLog) -> float:
        """Score time-based anomaly."""
        if not self.event_frequency["hourly"]:
            return 0.0  # Not enough data
        
        timestamp = log.timestamp or datetime.now()
        hour = timestamp.hour
        
        # Calculate how unusual this hour is
        total_hourly = sum(self.event_frequency["hourly"].values())
        hour_freq = self.event_frequency["hourly"].get(hour, 0) / max(total_hourly, 1)
        
        # Low frequency hours are more anomalous
        if hour_freq < 0.01:  # Less than 1% of events
            return 0.8
        elif hour_freq < 0.05:
            return 0.5
        elif hour_freq < 0.1:
            return 0.3
        return 0.0
    
    def _score_behavior_anomaly(self, log: ParsedLog) -> float:
        """Score behavior-based anomaly."""
        scores = []
        
        # Check user behavior
        user = log.get("user") or log.get("username")
        if user and str(user) in self.user_baselines:
            baseline = self.user_baselines[str(user)]
            scores.append(self._compare_to_baseline(log, baseline))
        
        # Check host behavior
        host = log.get("hostname") or log.get("host")
        if host and str(host) in self.host_baselines:
            baseline = self.host_baselines[str(host)]
            scores.append(self._compare_to_baseline(log, baseline))
        
        if not scores:
            return 0.0
        
        return max(scores)  # Return highest anomaly score
    
    def _compare_to_baseline(self, log: ParsedLog, baseline: Baseline) -> float:
        """Compare a log to an entity baseline."""
        score = 0.0
        
        timestamp = log.timestamp or datetime.now()
        
        # Time deviation
        if baseline.typical_hours and timestamp.hour not in baseline.typical_hours:
            score += 0.3
        
        if baseline.typical_days and timestamp.weekday() not in baseline.typical_days:
            score += 0.2
        
        # Source deviation
        source = log.get("source_ip") or log.get("src")
        if source and baseline.typical_sources and str(source) not in baseline.typical_sources:
            score += 0.3
        
        # Action deviation
        action = log.get("action") or log.get("event_type")
        if action and baseline.typical_actions and str(action) not in baseline.typical_actions:
            score += 0.2
        
        return min(1.0, score)
    
    def _score_new_entity(self, log: ParsedLog) -> float:
        """Score based on whether entities are new."""
        new_count = 0
        total_checked = 0
        
        # Check user
        user = log.get("user") or log.get("username")
        if user:
            total_checked += 1
            if str(user) not in self.user_baselines:
                new_count += 1
        
        # Check host
        host = log.get("hostname") or log.get("host")
        if host:
            total_checked += 1
            if str(host) not in self.host_baselines:
                new_count += 1
        
        if total_checked == 0:
            return 0.0
        
        return new_count / total_checked
    
    def _score_field_anomaly(self, log: ParsedLog) -> float:
        """Score based on unusual field values."""
        anomalous_fields = 0
        total_fields = 0
        
        for field_name, value in log.fields.items():
            if field_name not in self.field_stats:
                continue
            
            stats = self.field_stats[field_name]
            total_fields += 1
            
            str_value = str(value)[:100]
            
            # Check if value is rare
            value_count = stats.value_distribution.get(str_value, 0)
            total_count = stats.occurrence_count
            
            if total_count > 100:  # Only score if we have enough data
                rarity = 1.0 - (value_count / total_count)
                if rarity > 0.99:  # Very rare value
                    anomalous_fields += 1
        
        if total_fields == 0:
            return 0.0
        
        return anomalous_fields / total_fields
    
    def save(self, path: str):
        """Save learned patterns to file."""
        data = {
            "field_stats": {k: v.to_dict() for k, v in self.field_stats.items()},
            "user_baselines": {k: v.to_dict() for k, v in self.user_baselines.items()},
            "host_baselines": {k: v.to_dict() for k, v in self.host_baselines.items()},
            "process_baselines": {k: v.to_dict() for k, v in self.process_baselines.items()},
            "total_events_learned": self.total_events_learned,
            "learning_started": self.learning_started.isoformat() if self.learning_started else None,
        }
        
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)
    
    def load(self, path: str):
        """Load learned patterns from file."""
        try:
            with open(path, 'r') as f:
                data = json.load(f)
            
            self.total_events_learned = data.get("total_events_learned", 0)
            # Note: Full deserialization would reconstruct dataclass objects
            # This is a simplified version
        except FileNotFoundError:
            pass
    
    def get_stats(self) -> Dict:
        """Get learner statistics."""
        return {
            "total_events_learned": self.total_events_learned,
            "fields_discovered": len(self.field_stats),
            "users_baselined": len(self.user_baselines),
            "hosts_baselined": len(self.host_baselines),
            "processes_baselined": len(self.process_baselines),
            "learning_started": self.learning_started.isoformat() if self.learning_started else None,
            "last_learned": self.last_learned.isoformat() if self.last_learned else None,
        }
