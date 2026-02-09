"""
LogLens - Security Analyzer
============================
Adds security context to parsed logs using LLM.
ZERO hardcoded detection rules - all analysis via ML/LLM.

The key innovation: Instead of maintaining detection rules that
attackers can study and evade, we use LLM to understand the
SEMANTIC meaning of events and identify suspicious behavior.

Author: HUMYNX Team
"""

import json
import logging
from typing import Optional, Dict, List, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict

from loglens.utils.llm import LLMInterface, get_llm
from loglens.core.parser import ParsedLog

logger = logging.getLogger("loglens.analyzer")


@dataclass
class SecurityContext:
    """Security analysis result for a log entry."""
    # Risk assessment
    is_suspicious: bool = False
    is_malicious: bool = False
    risk_level: str = "low"  # critical, high, medium, low, info
    risk_score: float = 0.0  # 0.0 to 1.0
    
    # Classification
    event_category: str = ""  # authentication, execution, network, etc.
    attack_type: str = ""     # brute_force, lateral_movement, etc.
    
    # MITRE ATT&CK (inferred, not looked up)
    mitre_tactic: str = ""
    mitre_technique: str = ""
    
    # Analysis
    indicators: List[str] = field(default_factory=list)
    reasoning: str = ""
    recommendations: List[str] = field(default_factory=list)
    
    # Confidence
    confidence: float = 0.0
    analysis_method: str = "llm"
    
    def to_dict(self) -> Dict:
        return {
            "is_suspicious": self.is_suspicious,
            "is_malicious": self.is_malicious,
            "risk_level": self.risk_level,
            "risk_score": self.risk_score,
            "event_category": self.event_category,
            "attack_type": self.attack_type,
            "mitre_tactic": self.mitre_tactic,
            "mitre_technique": self.mitre_technique,
            "indicators": self.indicators,
            "reasoning": self.reasoning,
            "recommendations": self.recommendations,
            "confidence": self.confidence,
            "analysis_method": self.analysis_method,
        }


@dataclass
class ThreatHuntResult:
    """Result of a threat hunting analysis."""
    total_events: int = 0
    suspicious_events: int = 0
    malicious_events: int = 0
    
    # Findings by severity
    critical_findings: List[Dict] = field(default_factory=list)
    high_findings: List[Dict] = field(default_factory=list)
    medium_findings: List[Dict] = field(default_factory=list)
    low_findings: List[Dict] = field(default_factory=list)
    
    # Attack narrative
    attack_timeline: List[Dict] = field(default_factory=list)
    attack_summary: str = ""
    
    # Recommendations
    recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            "total_events": self.total_events,
            "suspicious_events": self.suspicious_events,
            "malicious_events": self.malicious_events,
            "critical_findings": self.critical_findings,
            "high_findings": self.high_findings,
            "medium_findings": self.medium_findings,
            "low_findings": self.low_findings,
            "attack_timeline": self.attack_timeline,
            "attack_summary": self.attack_summary,
            "recommendations": self.recommendations,
        }


class SecurityAnalyzer:
    """
    Security analyzer using LLM for threat detection.
    
    Key Design Principle:
    ---------------------
    Traditional security tools use rule-based detection:
    - Signature matching (detects known attacks)
    - Threshold alerts (noisy, many false positives)
    - IOC matching (lags behind attackers)
    
    LogLens instead uses LLM to:
    1. Understand the semantic meaning of events
    2. Identify suspicious BEHAVIOR, not just signatures
    3. Correlate across multiple events
    4. Explain findings in natural language
    
    This is harder for attackers to evade because we're not
    matching specific patterns - we're understanding intent.
    """
    
    def __init__(self, llm: LLMInterface = None):
        self.llm = llm or get_llm()
        
        # Context for multi-event analysis
        self._event_context: List[ParsedLog] = []
        self._context_window = 100  # Keep last N events for context
        
        # Statistics
        self.stats = {
            "events_analyzed": 0,
            "threats_detected": 0,
            "llm_calls": 0,
        }
    
    def analyze(self, log: ParsedLog, include_context: bool = True) -> SecurityContext:
        """
        Analyze a single log entry for security implications.
        
        Args:
            log: Parsed log entry
            include_context: Whether to include recent events for context
            
        Returns:
            SecurityContext with risk assessment
        """
        self.stats["events_analyzed"] += 1
        
        # Build context from recent events
        context_logs = []
        if include_context:
            context_logs = self._event_context[-10:]  # Last 10 events
        
        # Analyze with LLM
        result = self._analyze_with_llm(log, context_logs)
        
        # Update context
        self._event_context.append(log)
        if len(self._event_context) > self._context_window:
            self._event_context = self._event_context[-self._context_window:]
        
        # Update stats
        if result.is_suspicious or result.is_malicious:
            self.stats["threats_detected"] += 1
        
        return result
    
    def analyze_batch(self, logs: List[ParsedLog]) -> List[SecurityContext]:
        """Analyze multiple logs with shared context."""
        results = []
        for log in logs:
            result = self.analyze(log, include_context=True)
            results.append(result)
        return results
    
    def hunt(self, logs: List[ParsedLog]) -> ThreatHuntResult:
        """
        Perform threat hunting across a set of logs.
        
        This is different from analyze() - it looks for:
        - Attack chains and sequences
        - Subtle anomalies
        - Living-off-the-land techniques
        - Lateral movement patterns
        """
        result = ThreatHuntResult(total_events=len(logs))
        
        if not logs:
            return result
        
        # First pass: analyze individual events
        contexts = self.analyze_batch(logs)
        
        # Count findings
        for ctx in contexts:
            if ctx.is_malicious:
                result.malicious_events += 1
            elif ctx.is_suspicious:
                result.suspicious_events += 1
        
        # Group findings by severity
        for i, (log, ctx) in enumerate(zip(logs, contexts)):
            if ctx.risk_level == "critical":
                result.critical_findings.append(self._create_finding(log, ctx, i))
            elif ctx.risk_level == "high":
                result.high_findings.append(self._create_finding(log, ctx, i))
            elif ctx.risk_level == "medium":
                result.medium_findings.append(self._create_finding(log, ctx, i))
            elif ctx.is_suspicious:
                result.low_findings.append(self._create_finding(log, ctx, i))
        
        # Second pass: correlation analysis
        if len(logs) > 5:
            correlation_result = self._correlate_events(logs, contexts)
            result.attack_timeline = correlation_result.get("timeline", [])
            result.attack_summary = correlation_result.get("summary", "")
            result.recommendations = correlation_result.get("recommendations", [])
        
        return result
    
    def _analyze_with_llm(self, log: ParsedLog, context_logs: List[ParsedLog]) -> SecurityContext:
        """Analyze a log entry using LLM."""
        self.stats["llm_calls"] += 1
        
        # Build context string
        context_str = ""
        if context_logs:
            context_str = "RECENT EVENTS (for context):\n"
            for ctx_log in context_logs[-5:]:
                context_str += f"- {ctx_log.raw[:200]}\n"
        
        prompt = f"""Analyze this security log event for threats.

CURRENT EVENT:
```
{log.raw[:1500]}
```

PARSED FIELDS:
{json.dumps(log.fields, indent=2, default=str)[:1000]}

SOURCE: {log.source.source_type if log.source else 'unknown'} / {log.source.source_product if log.source else 'unknown'}

{context_str}

Analyze this event for security implications:
1. Is this suspicious or potentially malicious?
2. What category of security event is this?
3. What specific attack technique might this represent?
4. What MITRE ATT&CK tactic/technique does this align with?
5. What indicators make this suspicious (if any)?
6. What should a security analyst do about this?

Consider:
- Unusual process execution patterns
- Authentication anomalies
- Network connection anomalies
- Privilege escalation attempts
- Data exfiltration indicators
- Persistence mechanisms
- Lateral movement patterns

Respond with ONLY valid JSON:
{{
    "is_suspicious": true/false,
    "is_malicious": true/false,
    "risk_level": "critical|high|medium|low|info",
    "risk_score": 0.0-1.0,
    "event_category": "authentication|execution|network|file|registry|persistence|privilege_escalation|lateral_movement|collection|exfiltration|other",
    "attack_type": "specific attack type if detected, empty otherwise",
    "mitre_tactic": "tactic name if applicable",
    "mitre_technique": "technique ID and name if applicable",
    "indicators": ["list", "of", "suspicious", "indicators"],
    "reasoning": "brief explanation of your assessment",
    "recommendations": ["list", "of", "recommended", "actions"],
    "confidence": 0.0-1.0
}}"""

        response = self.llm.generate_json(prompt)
        
        if response and isinstance(response, dict):
            return SecurityContext(
                is_suspicious=bool(response.get("is_suspicious", False)),
                is_malicious=bool(response.get("is_malicious", False)),
                risk_level=response.get("risk_level", "info") or "info",
                risk_score=float(response.get("risk_score", 0.0) or 0.0),
                event_category=response.get("event_category", "") or "",
                attack_type=response.get("attack_type", "") or "",
                mitre_tactic=response.get("mitre_tactic", "") or "",
                mitre_technique=response.get("mitre_technique", "") or "",
                indicators=response.get("indicators", []) if isinstance(response.get("indicators"), list) else [],
                reasoning=response.get("reasoning", "") or "",
                recommendations=response.get("recommendations", []) if isinstance(response.get("recommendations"), list) else [],
                confidence=float(response.get("confidence", 0.5) or 0.5),
                analysis_method="llm",
            )
        
        # Fallback: no analysis
        return SecurityContext(
            risk_level="info",
            reasoning="Unable to analyze - LLM unavailable",
            analysis_method="fallback",
        )
    
    def _correlate_events(self, logs: List[ParsedLog], contexts: List[SecurityContext]) -> Dict:
        """Correlate multiple events to find attack patterns."""
        self.stats["llm_calls"] += 1
        
        # Build summary of events
        event_summary = []
        for i, (log, ctx) in enumerate(zip(logs, contexts)):
            if ctx.is_suspicious or ctx.is_malicious:
                event_summary.append({
                    "index": i,
                    "timestamp": log.timestamp.isoformat() if log.timestamp else "unknown",
                    "category": ctx.event_category,
                    "risk": ctx.risk_level,
                    "summary": log.raw[:200],
                    "technique": ctx.mitre_technique,
                })
        
        if not event_summary:
            return {"timeline": [], "summary": "No suspicious events detected.", "recommendations": []}
        
        prompt = f"""Analyze these security events for attack patterns and correlations.

SUSPICIOUS/MALICIOUS EVENTS:
{json.dumps(event_summary, indent=2)[:3000]}

TOTAL EVENTS ANALYZED: {len(logs)}

Look for:
1. Attack chains (reconnaissance -> initial access -> execution -> persistence -> etc.)
2. Lateral movement patterns
3. Coordinated activity
4. Living-off-the-land techniques
5. Timing patterns

Respond with ONLY valid JSON:
{{
    "timeline": [
        {{"timestamp": "...", "action": "description of attack step", "technique": "MITRE technique"}}
    ],
    "summary": "narrative description of the attack or suspicious activity",
    "attack_stage": "initial_access|execution|persistence|privilege_escalation|lateral_movement|collection|exfiltration|unknown",
    "recommendations": ["list", "of", "recommended", "responses"]
}}"""

        response = self.llm.generate_json(prompt)
        
        if response and isinstance(response, dict):
            return {
                "timeline": response.get("timeline", []) if isinstance(response.get("timeline"), list) else [],
                "summary": response.get("summary", "") or "",
                "recommendations": response.get("recommendations", []) if isinstance(response.get("recommendations"), list) else [],
            }
        
        return {"timeline": [], "summary": "", "recommendations": []}
    
    def _create_finding(self, log: ParsedLog, ctx: SecurityContext, index: int) -> Dict:
        """Create a finding dictionary."""
        return {
            "index": index,
            "timestamp": log.timestamp.isoformat() if log.timestamp else None,
            "raw": log.raw[:500],
            "risk_level": ctx.risk_level,
            "risk_score": ctx.risk_score,
            "category": ctx.event_category,
            "attack_type": ctx.attack_type,
            "technique": ctx.mitre_technique,
            "indicators": ctx.indicators,
            "reasoning": ctx.reasoning,
        }
    
    def get_stats(self) -> Dict:
        """Get analyzer statistics."""
        return {
            **self.stats,
            "context_window_size": len(self._event_context),
            "llm_available": self.llm.is_available,
        }
