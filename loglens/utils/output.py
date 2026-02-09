"""
LogLens - Output Utilities
===========================
Pretty terminal output for security log analysis.

Author: HUMYNX Team
"""

import json
import sys
from typing import Dict, List, Any, Optional
from datetime import datetime


class Colors:
    """ANSI color codes for terminal output."""
    # Basic colors
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    GRAY = '\033[90m'
    
    # Styles
    BOLD = '\033[1m'
    DIM = '\033[2m'
    UNDERLINE = '\033[4m'
    
    # Reset
    END = '\033[0m'
    
    @classmethod
    def disable(cls):
        """Disable colors for non-TTY output."""
        cls.RED = ''
        cls.GREEN = ''
        cls.YELLOW = ''
        cls.BLUE = ''
        cls.MAGENTA = ''
        cls.CYAN = ''
        cls.WHITE = ''
        cls.GRAY = ''
        cls.BOLD = ''
        cls.DIM = ''
        cls.UNDERLINE = ''
        cls.END = ''


# Auto-disable colors if not a TTY
if not sys.stdout.isatty():
    Colors.disable()


def severity_color(severity: str) -> str:
    """Get color for severity level."""
    severity = severity.upper()
    return {
        'CRITICAL': Colors.RED + Colors.BOLD,
        'HIGH': Colors.RED,
        'MEDIUM': Colors.YELLOW,
        'LOW': Colors.BLUE,
        'INFO': Colors.GRAY,
    }.get(severity, Colors.WHITE)


def print_banner():
    """Print LogLens banner."""
    banner = f"""
{Colors.CYAN}{Colors.BOLD}
    ╦  ╔═╗╔═╗╦  ╔═╗╔╗╔╔═╗
    ║  ║ ║║ ╦║  ║╣ ║║║╚═╗
    ╩═╝╚═╝╚═╝╩═╝╚═╝╝╚╝╚═╝
{Colors.END}
{Colors.DIM}    AI-Powered Security Log Analysis{Colors.END}
    {Colors.GRAY}v0.1.0 | Zero-Hardcoding Architecture{Colors.END}
"""
    print(banner)


def print_status(message: str, status: str = "info"):
    """Print status message with icon."""
    icons = {
        "info": f"{Colors.BLUE}ℹ{Colors.END}",
        "success": f"{Colors.GREEN}✓{Colors.END}",
        "warning": f"{Colors.YELLOW}⚠{Colors.END}",
        "error": f"{Colors.RED}✗{Colors.END}",
        "loading": f"{Colors.CYAN}◌{Colors.END}",
    }
    icon = icons.get(status, icons["info"])
    print(f"  {icon} {message}")


def print_header(title: str, width: int = 60):
    """Print section header."""
    print(f"\n{Colors.BOLD}{'─' * width}{Colors.END}")
    print(f"{Colors.BOLD}{title}{Colors.END}")
    print(f"{Colors.BOLD}{'─' * width}{Colors.END}")


def print_subheader(title: str):
    """Print subsection header."""
    print(f"\n{Colors.CYAN}{Colors.BOLD}{title}{Colors.END}")


def print_key_value(key: str, value: Any, indent: int = 2):
    """Print key-value pair."""
    prefix = " " * indent
    print(f"{prefix}{Colors.DIM}{key}:{Colors.END} {value}")


def print_table(headers: List[str], rows: List[List[Any]], max_width: int = 100):
    """Print simple table."""
    # Calculate column widths
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))
    
    # Truncate if too wide
    total_width = sum(widths) + len(widths) * 3
    if total_width > max_width:
        scale = max_width / total_width
        widths = [max(5, int(w * scale)) for w in widths]
    
    # Print header
    header_line = " │ ".join(h.ljust(widths[i])[:widths[i]] for i, h in enumerate(headers))
    print(f"{Colors.BOLD}  {header_line}{Colors.END}")
    print(f"  {'─┼─'.join('─' * w for w in widths)}")
    
    # Print rows
    for row in rows:
        row_line = " │ ".join(str(c).ljust(widths[i])[:widths[i]] for i, c in enumerate(row))
        print(f"  {row_line}")


def print_log_event(event: Dict, show_fields: List[str] = None, highlight_threats: bool = True):
    """Print a single log event with formatting."""
    # Determine if this is a threat
    is_threat = event.get("is_threat") or event.get("is_suspicious") or event.get("severity", "").upper() in ["CRITICAL", "HIGH"]
    
    if is_threat and highlight_threats:
        prefix = f"{Colors.RED}▶{Colors.END}"
    else:
        prefix = f"{Colors.DIM}▷{Colors.END}"
    
    # Get timestamp
    timestamp = event.get("timestamp") or event.get("time") or event.get("@timestamp") or ""
    if timestamp:
        timestamp = f"{Colors.DIM}{timestamp}{Colors.END} "
    
    # Get main message
    message = event.get("message") or event.get("raw") or str(event)[:100]
    
    # Severity coloring
    severity = event.get("severity") or event.get("risk_level") or ""
    if severity:
        color = severity_color(severity)
        severity = f" [{color}{severity}{Colors.END}]"
    
    print(f"  {prefix} {timestamp}{message}{severity}")
    
    # Show additional fields if requested
    if show_fields:
        for field in show_fields:
            if field in event and event[field]:
                print(f"      {Colors.DIM}{field}:{Colors.END} {event[field]}")


def print_threat_summary(threats: List[Dict]):
    """Print summary of detected threats."""
    if not threats:
        print_status("No threats detected", "success")
        return
    
    # Group by severity
    by_severity = {}
    for t in threats:
        sev = t.get("severity") or t.get("risk_level") or "UNKNOWN"
        sev = sev.upper()
        if sev not in by_severity:
            by_severity[sev] = []
        by_severity[sev].append(t)
    
    print_header("THREAT SUMMARY")
    
    # Show counts
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if sev in by_severity:
            color = severity_color(sev)
            count = len(by_severity[sev])
            print(f"  {color}■{Colors.END} {sev}: {count}")
    
    # Show top threats
    print_subheader("Top Threats")
    
    shown = 0
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if sev in by_severity and shown < 5:
            for threat in by_severity[sev][:3]:
                color = severity_color(sev)
                technique = threat.get("mitre_technique") or threat.get("technique") or ""
                technique_str = f" ({technique})" if technique else ""
                description = threat.get("description") or threat.get("message") or "Threat detected"
                print(f"  {color}▶{Colors.END} {description[:60]}{technique_str}")
                shown += 1
                if shown >= 5:
                    break


def print_query_result(result: Dict, show_all: bool = False):
    """Print query result with formatting."""
    understanding = result.get("understanding", {})
    matches = result.get("matches", [])
    
    # Print interpretation
    print_subheader("Query Interpretation")
    intent = understanding.get('intent') or understanding.get('what_user_wants', 'N/A')
    print(f"  {Colors.DIM}{intent}{Colors.END}")
    
    # Print summary
    print_subheader("Results")
    total = result.get("total_found", len(matches))
    returned = result.get("returned_count", len(matches))
    print_key_value("Total matches", total)
    print_key_value("Returned", returned)
    
    # Print result summary if available
    summary = result.get("result_summary")
    if summary:
        print(f"\n  {summary}")
    
    # Print matches
    if matches:
        print_subheader("Matching Events")
        display_limit = len(matches) if show_all else 10
        for event in matches[:display_limit]:
            print_log_event(event)
        
        if len(matches) > display_limit:
            print(f"\n  {Colors.DIM}... and {len(matches) - display_limit} more (use --show-all to display all, or -o to export){Colors.END}")
        elif not show_all and len(matches) > 10:
            print(f"\n  {Colors.DIM}Tip: Use --show-all to display all results, or -o results.json to export{Colors.END}")
    
    # Print insights
    insights = result.get("insights", [])
    if insights:
        print_subheader("Insights")
        for insight in insights[:5]:
            print(f"  {Colors.YELLOW}•{Colors.END} {insight}")
    
    # Print suggested queries
    suggestions = result.get("suggested_next_queries", [])
    if suggestions:
        print_subheader("Suggested Follow-up Queries")
        for i, suggestion in enumerate(suggestions[:3], 1):
            print(f"  {Colors.CYAN}{i}.{Colors.END} {suggestion}")


def print_hunt_result(result: Dict):
    """Print threat hunt result with formatting."""
    print_header("THREAT HUNT RESULTS")
    
    # Overall status
    threat_count = result.get("threat_count", 0)
    if threat_count == 0:
        print_status("No threats detected", "success")
    else:
        print_status(f"Found {threat_count} potential threats", "warning")
    
    # Print threats by severity
    threats = result.get("threats", [])
    print_threat_summary(threats)
    
    # Print timeline if available
    timeline = result.get("timeline", [])
    if timeline:
        print_subheader("Attack Timeline")
        for entry in timeline[:10]:
            timestamp = entry.get("timestamp", "")
            action = entry.get("action", "")
            print(f"  {Colors.DIM}{timestamp}{Colors.END} → {action}")
    
    # Print recommendations
    recommendations = result.get("recommendations", [])
    if recommendations:
        print_subheader("Recommendations")
        for rec in recommendations[:5]:
            print(f"  {Colors.GREEN}→{Colors.END} {rec}")


def format_json(data: Any, indent: int = 2) -> str:
    """Format data as pretty JSON."""
    return json.dumps(data, indent=indent, default=str)


def print_json(data: Any, indent: int = 2):
    """Print data as pretty JSON."""
    print(format_json(data, indent))


def progress_bar(current: int, total: int, width: int = 40, prefix: str = "") -> str:
    """Generate a progress bar string."""
    if total == 0:
        percent = 100
    else:
        percent = int(current / total * 100)
    
    filled = int(width * current / max(total, 1))
    bar = "█" * filled + "░" * (width - filled)
    
    return f"{prefix}[{bar}] {percent}% ({current}/{total})"


def print_progress(current: int, total: int, prefix: str = ""):
    """Print progress bar (overwrites line)."""
    bar = progress_bar(current, total, prefix=prefix)
    print(f"\r{bar}", end="", flush=True)
    if current >= total:
        print()  # New line when done
