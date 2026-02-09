"""
LogLens - Query Engine
=======================
Natural language query engine for security logs.
ZERO hardcoded query patterns - all understanding via LLM.

The key innovation: Ask questions in plain English, get answers.
No query language to learn. No syntax to remember.

Examples:
- "Show me failed logins from admin users"
- "What did user jsmith do yesterday?"
- "Find PowerShell commands that download files"
- "Show suspicious network connections"

Author: HUMYNX Team
"""

import json
import re
import logging
from typing import Optional, Dict, List, Any, Callable
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta

from loglens.utils.llm import LLMInterface, get_llm
from loglens.core.parser import ParsedLog
from loglens.core.learner import PatternLearner

logger = logging.getLogger("loglens.query")


@dataclass
class QueryUnderstanding:
    """LLM's understanding of a natural language query."""
    original_query: str
    
    # What the user wants (natural language)
    intent: str
    search_strategy: str
    
    # Extracted filters
    filters: List[Dict] = field(default_factory=list)
    # Each filter: {field_hint, value_hint, operator, description}
    
    # Time context
    time_range: Dict = field(default_factory=dict)
    # {start, end, relative_description}
    
    # Result preferences
    limit: int = 100
    sort_by: str = ""
    sort_order: str = "desc"
    
    # Special handling
    query_type: str = "search"  # search, aggregate, timeline, compare
    
    # Confidence
    confidence: float = 0.0
    uncertainties: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class QueryResult:
    """Result of a natural language query."""
    query: str
    understanding: QueryUnderstanding
    
    # Results
    matches: List[Dict] = field(default_factory=list)
    total_found: int = 0
    returned_count: int = 0
    
    # Execution
    execution_time_ms: float = 0.0
    
    # LLM analysis of results
    result_summary: str = ""
    insights: List[str] = field(default_factory=list)
    suggested_next_queries: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        result = asdict(self)
        result['understanding'] = self.understanding.to_dict()
        return result


class QueryEngine:
    """
    Natural language query engine.
    
    Key Design Principle:
    ---------------------
    Traditional log query languages (SPL, KQL, Lucene) require:
    - Learning complex syntax
    - Knowing exact field names
    - Understanding the log schema
    
    LogLens instead:
    1. Uses LLM to understand natural language queries
    2. Automatically maps to actual fields in your data
    3. Executes the query and summarizes results
    4. Suggests follow-up queries
    
    This democratizes log analysis - anyone can query logs.
    """
    
    def __init__(self, llm: LLMInterface = None, learner: PatternLearner = None):
        self.llm = llm or get_llm()
        self.learner = learner or PatternLearner()
        
        # Loaded logs for querying
        self._logs: List[ParsedLog] = []
        
        # Query history for context
        self._query_history: List[Dict] = []
        
        # Statistics
        self.stats = {
            "queries_processed": 0,
            "successful_queries": 0,
            "llm_calls": 0,
        }
    
    def add_logs(self, logs: List[ParsedLog]):
        """Add logs to the query engine."""
        self._logs.extend(logs)
        
        # Learn from new logs
        for log in logs:
            self.learner.learn(log)
    
    def clear_logs(self):
        """Clear all loaded logs."""
        self._logs = []
    
    def query(self, question: str, logs: List[ParsedLog] = None) -> QueryResult:
        """
        Query logs with natural language.
        
        Args:
            question: Natural language question
            logs: Optional logs to query (uses loaded logs if not provided)
            
        Returns:
            QueryResult with matches and analysis
        """
        import time
        start_time = time.time()
        
        self.stats["queries_processed"] += 1
        
        # Use provided logs or loaded logs
        search_logs = logs if logs is not None else self._logs
        
        if not search_logs:
            return QueryResult(
                query=question,
                understanding=QueryUnderstanding(
                    original_query=question,
                    intent="Unable to search - no logs loaded",
                    search_strategy="",
                ),
                result_summary="No logs available to search.",
            )
        
        # Step 1: Understand the query
        understanding = self._understand_query(question, search_logs)
        
        # Step 2: Execute the search
        matches = self._execute_search(understanding, search_logs)
        
        # Step 3: Analyze results
        analysis = self._analyze_results(question, matches)
        
        execution_time = (time.time() - start_time) * 1000
        
        # Update history
        self._query_history.append({
            "query": question,
            "matches_found": len(matches),
            "timestamp": datetime.now().isoformat(),
        })
        
        self.stats["successful_queries"] += 1
        
        return QueryResult(
            query=question,
            understanding=understanding,
            matches=[self._log_to_dict(m) for m in matches[:understanding.limit]],
            total_found=len(matches),
            returned_count=min(len(matches), understanding.limit),
            execution_time_ms=execution_time,
            result_summary=analysis.get("summary", ""),
            insights=analysis.get("insights", []),
            suggested_next_queries=analysis.get("suggestions", []),
        )
    
    def _understand_query(self, question: str, logs: List[ParsedLog]) -> QueryUnderstanding:
        """Use LLM to understand the natural language query."""
        self.stats["llm_calls"] += 1
        
        # Build context about available data
        field_context = self._build_field_context()
        # Pass more logs to get diverse samples (up to 100)
        sample_context = self._build_sample_context(logs[:100])
        history_context = self._build_history_context()
        
        prompt = f"""Analyze the user's query and the ACTUAL LOG DATA to create search filters.

USER'S QUERY: "{question}"

SAMPLE LOG ENTRIES (from the actual data):
{sample_context}

CRITICAL INSTRUCTIONS:
1. Look at the ACTUAL vocabulary used in the sample logs above
2. Your filters MUST use the EXACT words/phrases that appear in these logs
3. Do NOT use generic terms - use the SPECIFIC terminology from the samples
4. For example: if logs say "authentication failure", use that exact phrase, NOT "failed" or "error"

Your task:
1. Understand what the user wants to find
2. Identify which sample logs match that intent
3. Extract the EXACT text patterns from those matching samples
4. Create filters using those exact patterns

{history_context}

Respond with ONLY valid JSON:
{{
    "intent": "What the user wants to find",
    "search_strategy": "How to find it using the exact vocabulary from the logs",
    "filters": [
        {{
            "description": "What this filter looks for",
            "field_hint": "*",
            "value_hint": "EXACT phrase from the sample logs",
            "operator": "contains"
        }}
    ],
    "limit": 100,
    "confidence": 0.0-1.0
}}

IMPORTANT: The value_hint MUST be copied exactly from the sample logs, not paraphrased."""

        response = self.llm.generate_json(prompt)
        
        if response and isinstance(response, dict):
            # Ensure filters is a list
            filters = response.get("filters", [])
            if not isinstance(filters, list):
                filters = [filters] if filters else []
            
            # Ensure time_range is a dict
            time_range = response.get("time_range", {})
            if not isinstance(time_range, dict):
                time_range = {}
            
            return QueryUnderstanding(
                original_query=question,
                intent=response.get("intent", "") or "",
                search_strategy=response.get("search_strategy", "") or "",
                filters=filters,
                time_range=time_range,
                limit=int(response.get("limit", 100) or 100),
                sort_by=response.get("sort_by", "") or "",
                sort_order=response.get("sort_order", "desc") or "desc",
                query_type=response.get("query_type", "search") or "search",
                confidence=float(response.get("confidence", 0.5) or 0.5),
                uncertainties=response.get("uncertainties", []) or [],
            )
        
        # Fallback: simple keyword search
        return QueryUnderstanding(
            original_query=question,
            intent="Keyword search (LLM unavailable)",
            search_strategy="Search all fields for query terms",
            filters=[{
                "description": "Keyword match",
                "field_hint": "*",
                "value_hint": question,
                "operator": "contains"
            }],
            confidence=0.3,
        )
    
    def _execute_search(self, understanding: QueryUnderstanding, logs: List[ParsedLog]) -> List[ParsedLog]:
        """Execute the search based on query understanding."""
        matches = []
        
        for log in logs:
            if self._matches_filters(log, understanding):
                matches.append(log)
        
        # Apply time filter
        time_range = understanding.time_range
        if time_range.get("start") or time_range.get("end") or time_range.get("relative"):
            matches = self._filter_by_time(matches, time_range)
        
        # Sort results
        if understanding.sort_by:
            matches = self._sort_results(matches, understanding.sort_by, understanding.sort_order)
        
        return matches
    
    def _matches_filters(self, log: ParsedLog, understanding: QueryUnderstanding) -> bool:
        """Check if a log matches ANY of the query filters (OR logic)."""
        if not understanding.filters:
            return True
        
        # OR logic: match if ANY filter matches
        # This is correct for search queries like "failed logins" where
        # the LLM generates multiple patterns that indicate the same thing:
        # - "authentication failure" OR "user unknown" OR "Failed password"
        for filter_spec in understanding.filters:
            field_hint = filter_spec.get("field_hint", "*")
            value_hint = filter_spec.get("value_hint", "")
            operator = filter_spec.get("operator", "contains")
            
            if self._matches_single_filter(log, field_hint, value_hint, operator):
                return True  # Found a match - include this log
        
        return False  # No filters matched
    
    def _matches_single_filter(self, log: ParsedLog, field_hint: str, value_hint: str, operator: str) -> bool:
        """Check if a log matches a single filter."""
        # Skip malformed time filters that can't be matched
        # LLMs often generate these incorrectly
        hint_lower = field_hint.lower()
        if any(t in hint_lower for t in ['timestamp', 'time', 'date']) and \
           any(o in operator.lower() for o in ['greater', 'less', 'before', 'after']):
            # Time-based comparison filter - only apply if we have a timestamp
            if log.timestamp is None:
                return True  # Skip filter, don't fail
        
        # Get fields to check
        if field_hint == "*":
            fields_to_check = list(log.fields.keys()) + list(log.normalized.keys())
        else:
            # Find matching fields
            fields_to_check = self._find_matching_fields(log, field_hint)
        
        if not fields_to_check:
            # Check raw log as fallback
            return self._apply_operator(log.raw, value_hint, operator)
        
        # Check each field
        for field_name in fields_to_check:
            value = log.get(field_name)
            if value is not None:
                if self._apply_operator(str(value), value_hint, operator):
                    return True
        
        return False
    
    def _find_matching_fields(self, log: ParsedLog, field_hint: str) -> List[str]:
        """Find fields that match the hint."""
        all_fields = list(log.fields.keys()) + list(log.normalized.keys())
        hint_lower = field_hint.lower()
        
        # Exact match
        for field in all_fields:
            if field.lower() == hint_lower:
                return [field]
        
        # Partial match
        matches = []
        for field in all_fields:
            if hint_lower in field.lower() or field.lower() in hint_lower:
                matches.append(field)
        
        return matches
    
    def _apply_operator(self, value: str, pattern: str, operator: str) -> bool:
        """Apply a filter operator."""
        value_lower = value.lower()
        pattern_lower = pattern.lower()
        
        if operator == "equals":
            return value_lower == pattern_lower
        elif operator == "contains":
            # Handle OR patterns (e.g., "authentication failure|Failed password")
            if '|' in pattern_lower:
                alternatives = [alt.strip() for alt in pattern_lower.split('|')]
                return any(alt in value_lower for alt in alternatives if alt)
            return pattern_lower in value_lower
        elif operator == "starts_with":
            return value_lower.startswith(pattern_lower)
        elif operator == "ends_with":
            return value_lower.endswith(pattern_lower)
        elif operator == "regex":
            try:
                return bool(re.search(pattern, value, re.IGNORECASE))
            except:
                return False
        elif operator == "exists":
            return bool(value)
        elif operator == "greater_than":
            try:
                return float(value) > float(pattern)
            except:
                return False
        elif operator == "less_than":
            try:
                return float(value) < float(pattern)
            except:
                return False
        else:
            return pattern_lower in value_lower
    
    def _filter_by_time(self, logs: List[ParsedLog], time_range: Dict) -> List[ParsedLog]:
        """Filter logs by time range."""
        start_time = None
        end_time = None
        
        # Parse explicit times
        if time_range.get("start"):
            try:
                start_time = datetime.fromisoformat(time_range["start"].replace("Z", "+00:00"))
            except:
                pass
        
        if time_range.get("end"):
            try:
                end_time = datetime.fromisoformat(time_range["end"].replace("Z", "+00:00"))
            except:
                pass
        
        # Handle relative times
        relative = time_range.get("relative")
        if relative:
            now = datetime.now()
            if relative == "last_hour":
                start_time = now - timedelta(hours=1)
            elif relative == "last_day" or relative == "yesterday":
                start_time = now - timedelta(days=1)
            elif relative == "last_week":
                start_time = now - timedelta(weeks=1)
            elif relative == "last_month":
                start_time = now - timedelta(days=30)
        
        # Filter logs
        filtered = []
        for log in logs:
            if log.timestamp is None:
                filtered.append(log)  # Include logs without timestamps
                continue
            
            if start_time and log.timestamp < start_time:
                continue
            if end_time and log.timestamp > end_time:
                continue
            
            filtered.append(log)
        
        return filtered
    
    def _sort_results(self, logs: List[ParsedLog], sort_by: str, sort_order: str) -> List[ParsedLog]:
        """Sort results."""
        reverse = sort_order.lower() == "desc"
        
        if sort_by.lower() in ["timestamp", "time", "@timestamp"]:
            return sorted(
                logs,
                key=lambda x: x.timestamp or datetime.min,
                reverse=reverse
            )
        
        # Sort by field value
        return sorted(
            logs,
            key=lambda x: str(x.get(sort_by, "")),
            reverse=reverse
        )
    
    def _analyze_results(self, question: str, matches: List[ParsedLog]) -> Dict:
        """Analyze query results with LLM."""
        if not matches:
            return {
                "summary": "No matching events found.",
                "insights": [],
                "suggestions": ["Try broadening your search", "Check for typos in your query"],
            }
        
        if not self.llm.is_available:
            return {
                "summary": f"Found {len(matches)} matching events.",
                "insights": [],
                "suggestions": [],
            }
        
        self.stats["llm_calls"] += 1
        
        # Build sample of results
        sample_results = []
        for log in matches[:10]:
            sample_results.append({
                "timestamp": log.timestamp.isoformat() if log.timestamp else None,
                "summary": log.raw[:200],
                "key_fields": {k: str(v)[:50] for k, v in list(log.fields.items())[:5]},
            })
        
        prompt = f"""Analyze these security log query results.

QUERY: "{question}"
TOTAL MATCHES: {len(matches)}

SAMPLE RESULTS:
{json.dumps(sample_results, indent=2)[:2000]}

Provide:
1. A concise summary of what was found
2. Key insights or patterns
3. Suggested follow-up queries

Respond with ONLY valid JSON:
{{
    "summary": "Concise summary of results",
    "insights": ["key insight 1", "key insight 2"],
    "suggestions": ["follow-up query 1", "follow-up query 2"]
}}"""

        response = self.llm.generate_json(prompt)
        
        return response or {
            "summary": f"Found {len(matches)} matching events.",
            "insights": [],
            "suggestions": [],
        }
    
    def _build_field_context(self) -> str:
        """Build context about available fields."""
        common_fields = self.learner.get_common_fields(15)
        
        if not common_fields:
            return "No field information available yet."
        
        lines = []
        for fs in common_fields:
            samples = ", ".join(fs.sample_values[:3])
            lines.append(f"  - {fs.field_name}: {fs.unique_values} unique values (e.g., {samples})")
        
        return "\n".join(lines)
    
    def _build_sample_context(self, logs: List[ParsedLog]) -> str:
        """
        Build DIVERSE sample log context showing different event types.
        
        Uses multiple strategies to ensure diversity WITHOUT hardcoded keywords:
        1. Positional sampling (beginning, middle, end of file)
        2. Structural diversity (different log lengths/patterns)
        3. Hash-based deduplication (avoid showing same event type twice)
        """
        if not logs:
            return "No sample logs available."
        
        diverse_samples = []
        seen_signatures = set()
        
        def get_structural_signature(raw: str) -> str:
            """
            Create a structural signature of a log line.
            This is language/vocabulary agnostic - looks at STRUCTURE, not words.
            """
            # Replace numbers with #, keep structure
            import re
            sig = raw[:150]  # First 150 chars
            sig = re.sub(r'\d+', '#', sig)  # Numbers -> #
            sig = re.sub(r'[a-f0-9]{8,}', 'HASH', sig, flags=re.IGNORECASE)  # Hex hashes
            sig = re.sub(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', 'IP', sig)  # IPs
            # Extract the "shape" - sequence of token types
            tokens = re.findall(r'[A-Za-z]+|[^\w\s]+', sig)
            return ' '.join(tokens[:15])  # First 15 tokens define the shape
        
        # Strategy 1: Sample from different positions in the file
        n = len(logs)
        positions = [0]  # First
        if n > 10:
            positions.extend([n//4, n//2, 3*n//4])  # Quarters
        if n > 5:
            positions.append(n - 1)  # Last
        
        for pos in positions:
            if pos < len(logs):
                log = logs[pos]
                sig = get_structural_signature(log.raw)
                if sig not in seen_signatures:
                    seen_signatures.add(sig)
                    diverse_samples.append(log.raw[:400])
        
        # Strategy 2: Scan for structurally different logs
        step = max(1, len(logs) // 20)  # Check ~20 evenly spaced logs
        for i in range(0, len(logs), step):
            if len(diverse_samples) >= 12:
                break
            log = logs[i]
            sig = get_structural_signature(log.raw)
            if sig not in seen_signatures:
                seen_signatures.add(sig)
                diverse_samples.append(log.raw[:400])
        
        # Strategy 3: If we still don't have enough, add random samples
        if len(diverse_samples) < 6 and len(logs) > len(diverse_samples):
            import random
            remaining = [l for l in logs if l.raw[:400] not in diverse_samples]
            for log in random.sample(remaining, min(6 - len(diverse_samples), len(remaining))):
                diverse_samples.append(log.raw[:400])
        
        return "\n---\n".join(diverse_samples[:12])  # Max 12 samples
    
    def _build_history_context(self) -> str:
        """Build query history context."""
        if not self._query_history:
            return ""
        
        recent = self._query_history[-3:]
        history_lines = ["RECENT QUERIES:"]
        for h in recent:
            history_lines.append(f"  - {h['query']} ({h['matches_found']} matches)")
        
        return "\n".join(history_lines)
    
    def _log_to_dict(self, log: ParsedLog) -> Dict:
        """Convert ParsedLog to dict for output."""
        return {
            "raw": log.raw,
            "timestamp": log.timestamp.isoformat() if log.timestamp else None,
            "fields": log.fields,
            "normalized": log.normalized,
        }
    
    def suggest_queries(self) -> List[str]:
        """Suggest useful queries based on the data."""
        if not self.llm.is_available:
            return [
                "Show me failed authentication attempts",
                "Find unusual process executions",
                "Show network connections to external IPs",
            ]
        
        self.stats["llm_calls"] += 1
        
        field_context = self._build_field_context()
        
        prompt = f"""Based on this security log data, suggest useful queries.

AVAILABLE FIELDS:
{field_context}

TOTAL LOGS: {len(self._logs)}

Suggest 5-7 practical security queries that would help with:
- Finding authentication issues
- Detecting suspicious activity
- Investigating anomalies
- Threat hunting

Respond with ONLY a JSON array of query strings:
["query 1", "query 2", ...]"""

        response = self.llm.generate_json(prompt)
        
        if isinstance(response, list):
            return response
        
        return [
            "Show me failed logins",
            "Find PowerShell executions",
            "Show suspicious network activity",
        ]
    
    def get_stats(self) -> Dict:
        """Get query engine statistics."""
        return {
            **self.stats,
            "logs_loaded": len(self._logs),
            "queries_in_history": len(self._query_history),
            "learner_stats": self.learner.get_stats(),
            "llm_available": self.llm.is_available,
        }
