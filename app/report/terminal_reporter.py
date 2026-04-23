"""Terminal/console report generator."""

from datetime import datetime
from typing import TextIO

from ..models import AuditSummary, Finding, SeverityLevel
from ..policy.severity import get_severity_color, get_severity_emoji


class TerminalReporter:
    """Generate terminal/console output for security audit reports."""
    
    # ANSI color codes
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    UNDERLINE = "\033[4m"
    
    # Severity colors
    COLORS = {
        SeverityLevel.CRITICAL: "\033[91m",  # Bright red
        SeverityLevel.HIGH: "\033[31m",      # Red
        SeverityLevel.MEDIUM: "\033[33m",    # Yellow
        SeverityLevel.LOW: "\033[32m",       # Green
        SeverityLevel.INFO: "\033[36m",      # Cyan
    }
    
    def __init__(self, use_colors: bool = True):
        self.use_colors = use_colors
    
    def generate(self, summary: AuditSummary, output: TextIO | None = None) -> str:
        """Generate and return terminal output."""
        lines: list[str] = []
        
        # Header
        lines.append(self._header("🔒 SECURITY AUDIT REPORT"))
        lines.append(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        lines.append("")
        
        # Executive Summary
        lines.append(self._section("EXECUTIVE SUMMARY"))
        lines.append(self._summary_line("Total Findings", str(len(summary.findings))))
        lines.append(self._summary_line("Targets Scanned", str(summary.target_count)))
        lines.append(self._summary_line("Scan Duration", f"{summary.duration_seconds:.1f}s"))
        lines.append(self._summary_line("Errors", str(len(summary.errors))))
        lines.append("")
        
        # Severity Breakdown
        lines.append(self._section("FINDINGS BY SEVERITY"))
        severity_counts = summary.count_by_severity()
        
        for sev in [SeverityLevel.CRITICAL, SeverityLevel.HIGH, SeverityLevel.MEDIUM, SeverityLevel.LOW, SeverityLevel.INFO]:
            count = severity_counts.get(sev, 0)
            if count > 0:
                lines.append(self._severity_line(sev, count))
        lines.append("")
        
        # Findings
        if summary.findings:
            lines.append(self._section("DETAILED FINDINGS"))
            lines.append("")
            
            # Sort findings by severity
            severity_order = {sev: i for i, sev in enumerate([
                SeverityLevel.CRITICAL, SeverityLevel.HIGH, SeverityLevel.MEDIUM, SeverityLevel.LOW, SeverityLevel.INFO
            ])}
            
            sorted_findings = sorted(
                summary.findings,
                key=lambda f: (severity_order.get(f.severity, 99), f.category.value)
            )
            
            for finding in sorted_findings:
                lines.append(self._format_finding(finding))
                lines.append("")
        else:
            lines.append(self._success("✅ No security findings detected!"))
            lines.append("")
        
        # Errors
        if summary.errors:
            lines.append(self._section("ERRORS"))
            for error in summary.errors:
                lines.append(f"  ⚠️  {error}")
            lines.append("")
        
        # Footer
        lines.append(self._dim("─" * 60))
        lines.append(self._dim("Security Audit Tool v1.0.0"))
        lines.append("")
        
        output_text = "\n".join(lines)
        
        if output:
            output.write(output_text + "\n")
        
        return output_text
    
    def _colorize(self, text: str, color: str) -> str:
        """Apply color to text if colors are enabled."""
        if self.use_colors:
            return f"{color}{text}{self.RESET}"
        return text
    
    def _header(self, text: str) -> str:
        """Format a header."""
        line = "═" * 60
        return f"""
{self._colorize(line, self.BOLD)}
{self._colorize(text.center(60), self.BOLD)}
{self._colorize(line, self.BOLD)}"""
    
    def _section(self, text: str) -> str:
        """Format a section header."""
        return self._colorize(f"▸ {text}", f"{self.BOLD}{self.UNDERLINE}")
    
    def _summary_line(self, label: str, value: str) -> str:
        """Format a summary line."""
        return f"  {label:.<20} {value}"
    
    def _severity_line(self, severity: SeverityLevel, count: int) -> str:
        """Format a severity count line."""
        emoji = get_severity_emoji(severity)
        color = self.COLORS.get(severity, "")
        label = severity.value.upper()
        
        if count > 0:
            text = f"  {emoji} {label:.<12} {count}"
            return self._colorize(text, color)
        return f"  {emoji} {label:.<12} {count}"
    
    def _format_finding(self, finding: Finding) -> str:
        """Format a single finding."""
        lines: list[str] = []
        
        emoji = get_severity_emoji(finding.severity)
        color = self.COLORS.get(finding.severity, "")
        
        # Header
        header = f"{emoji} [{finding.severity.value.upper()}] {finding.title}"
        lines.append(self._colorize(header, f"{self.BOLD}{color}"))
        
        # Meta
        lines.append(f"  ID: {finding.id} | Category: {finding.category.value} | Check: {finding.check_id}")
        
        # Target
        lines.append(f"  Target: {finding.target}")
        
        # Evidence
        lines.append("")
        lines.append(self._dim("  Evidence:"))
        for line in finding.evidence.split("\n")[:3]:  # Limit to 3 lines
            lines.append(f"    {line[:100]}")  # Truncate long lines
        
        # Remediation
        lines.append("")
        lines.append(self._dim("  Remediation:"))
        lines.append(f"    {finding.remediation}")
        
        return "\n".join(lines)
    
    def _success(self, text: str) -> str:
        """Format success message."""
        return self._colorize(text, f"{self.BOLD}\033[32m")
    
    def _dim(self, text: str) -> str:
        """Format dim text."""
        return self._colorize(text, self.DIM)
    
    def print_summary_only(self, summary: AuditSummary) -> str:
        """Print only the summary, not detailed findings."""
        lines: list[str] = []
        
        lines.append(self._header("🔒 SECURITY AUDIT COMPLETE"))
        lines.append("")
        
        severity_counts = summary.count_by_severity()
        total = len(summary.findings)
        
        lines.append(f"Total Findings: {total}")
        lines.append("")
        
        for sev in [SeverityLevel.CRITICAL, SeverityLevel.HIGH, SeverityLevel.MEDIUM, SeverityLevel.LOW, SeverityLevel.INFO]:
            count = severity_counts.get(sev, 0)
            lines.append(self._severity_line(sev, count))
        
        lines.append("")
        lines.append(f"Duration: {summary.duration_seconds:.1f}s")
        lines.append(f"Full report available in JSON/HTML output files")
        
        return "\n".join(lines)
