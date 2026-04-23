"""HTML report generator."""

from datetime import datetime
from pathlib import Path
from typing import Any

from ..models import AuditSummary, Finding, SeverityLevel
from ..policy.severity import get_severity_color, get_severity_emoji


class HTMLReporter:
    """Generate HTML format security audit reports."""
    
    def __init__(self):
        self.styles = self._get_styles()
    
    def generate(self, summary: AuditSummary) -> str:
        """Generate an HTML report from an audit summary."""
        html_parts = [
            self._generate_header(),
            self._generate_summary_section(summary),
            self._generate_findings_section(summary),
            self._generate_footer(summary),
        ]
        
        return "\n".join(html_parts)
    
    def write(self, summary: AuditSummary, output_path: Path) -> None:
        """Write HTML report to a file."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        html_content = self.generate(summary)
        
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)
    
    def _get_styles(self) -> str:
        """Get CSS styles for the report."""
        return """
        <style>
            * {
                box-sizing: border-box;
                margin: 0;
                padding: 0;
            }
            body {
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
                line-height: 1.6;
                color: #333;
                background-color: #f5f5f5;
                padding: 20px;
            }
            .container {
                max-width: 1200px;
                margin: 0 auto;
                background-color: white;
                padding: 30px;
                border-radius: 8px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }
            h1 {
                color: #2c3e50;
                margin-bottom: 10px;
                border-bottom: 3px solid #3498db;
                padding-bottom: 10px;
            }
            h2 {
                color: #34495e;
                margin-top: 30px;
                margin-bottom: 15px;
                border-bottom: 2px solid #ecf0f1;
                padding-bottom: 8px;
            }
            h3 {
                color: #7f8c8d;
                margin-top: 20px;
                margin-bottom: 10px;
            }
            .metadata {
                color: #7f8c8d;
                font-size: 0.9em;
                margin-bottom: 20px;
            }
            .summary-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 15px;
                margin: 20px 0;
            }
            .summary-card {
                background-color: #f8f9fa;
                padding: 15px;
                border-radius: 6px;
                border-left: 4px solid #3498db;
            }
            .summary-card h4 {
                font-size: 0.9em;
                color: #7f8c8d;
                margin-bottom: 5px;
            }
            .summary-card .value {
                font-size: 1.8em;
                font-weight: bold;
                color: #2c3e50;
            }
            .severity-counts {
                display: flex;
                gap: 10px;
                flex-wrap: wrap;
                margin: 20px 0;
            }
            .severity-badge {
                padding: 8px 15px;
                border-radius: 20px;
                font-weight: bold;
                font-size: 0.9em;
            }
            .severity-critical { background-color: #e74c3c; color: white; }
            .severity-high { background-color: #e67e22; color: white; }
            .severity-medium { background-color: #f39c12; color: white; }
            .severity-low { background-color: #27ae60; color: white; }
            .severity-info { background-color: #3498db; color: white; }
            .finding {
                background-color: #f8f9fa;
                border-left: 4px solid #3498db;
                padding: 20px;
                margin: 15px 0;
                border-radius: 4px;
            }
            .finding.critical { border-left-color: #e74c3c; }
            .finding.high { border-left-color: #e67e22; }
            .finding.medium { border-left-color: #f39c12; }
            .finding.low { border-left-color: #27ae60; }
            .finding.info { border-left-color: #3498db; }
            .finding-header {
                display: flex;
                justify-content: space-between;
                align-items: flex-start;
                margin-bottom: 10px;
            }
            .finding-title {
                font-size: 1.2em;
                font-weight: bold;
                color: #2c3e50;
                flex: 1;
            }
            .finding-severity {
                padding: 4px 12px;
                border-radius: 12px;
                font-size: 0.8em;
                font-weight: bold;
                text-transform: uppercase;
            }
            .finding-meta {
                color: #7f8c8d;
                font-size: 0.9em;
                margin-bottom: 10px;
            }
            .finding-section {
                margin: 10px 0;
            }
            .finding-section h4 {
                color: #34495e;
                font-size: 0.9em;
                margin-bottom: 5px;
            }
            .finding-section p, .finding-section pre {
                background-color: white;
                padding: 10px;
                border-radius: 4px;
                font-size: 0.95em;
            }
            .finding-section pre {
                overflow-x: auto;
                white-space: pre-wrap;
                word-wrap: break-word;
            }
            .references {
                margin-top: 10px;
            }
            .references a {
                color: #3498db;
                text-decoration: none;
                display: block;
                margin: 3px 0;
            }
            .references a:hover {
                text-decoration: underline;
            }
            .no-findings {
                text-align: center;
                padding: 40px;
                color: #27ae60;
            }
            .error-list {
                background-color: #fff5f5;
                border: 1px solid #feb2b2;
                padding: 15px;
                border-radius: 4px;
                margin: 15px 0;
            }
            .error-list li {
                color: #c53030;
                margin: 5px 0;
            }
            table {
                width: 100%;
                border-collapse: collapse;
                margin: 20px 0;
            }
            th, td {
                text-align: left;
                padding: 12px;
                border-bottom: 1px solid #e2e8f0;
            }
            th {
                background-color: #f7fafc;
                font-weight: bold;
                color: #4a5568;
            }
            tr:hover {
                background-color: #f7fafc;
            }
        </style>
        """
    
    def _generate_header(self) -> str:
        """Generate HTML header."""
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Audit Report</title>
    {self.styles}
</head>
<body>
    <div class="container">
        <h1>🔒 Security Audit Report</h1>
        <p class="metadata">Generated at: {datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")}</p>
"""
    
    def _generate_summary_section(self, summary: AuditSummary) -> str:
        """Generate the summary section."""
        severity_counts = summary.count_by_severity()
        category_counts = summary.count_by_category()
        
        duration = summary.duration_seconds
        duration_str = f"{duration:.1f}s" if duration < 60 else f"{duration/60:.1f}m"
        
        html = f"""
        <h2>Executive Summary</h2>
        <div class="summary-grid">
            <div class="summary-card">
                <h4>Total Findings</h4>
                <div class="value">{len(summary.findings)}</div>
            </div>
            <div class="summary-card">
                <h4>Targets Scanned</h4>
                <div class="value">{summary.target_count}</div>
            </div>
            <div class="summary-card">
                <h4>Scan Duration</h4>
                <div class="value">{duration_str}</div>
            </div>
            <div class="summary-card">
                <h4>Errors</h4>
                <div class="value">{len(summary.errors)}</div>
            </div>
        </div>
        
        <h3>Findings by Severity</h3>
        <div class="severity-counts">
"""
        
        # Severity order
        severities = [SeverityLevel.CRITICAL, SeverityLevel.HIGH, SeverityLevel.MEDIUM, SeverityLevel.LOW, SeverityLevel.INFO]
        
        for sev in severities:
            count = severity_counts.get(sev, 0)
            if count > 0:
                html += f'            <span class="severity-badge severity-{sev.value}">{sev.value.upper()}: {count}</span>\n'
        
        html += """        </div>
        
        <h3>Findings by Category</h3>
        <table>
            <thead>
                <tr>
                    <th>Category</th>
                    <th>Count</th>
                </tr>
            </thead>
            <tbody>
"""
        
        for cat, count in sorted(category_counts.items(), key=lambda x: x[1], reverse=True):
            if count > 0:
                html += f"""                <tr>
                    <td>{cat.value.replace('_', ' ').title()}</td>
                    <td>{count}</td>
                </tr>
"""
        
        html += """            </tbody>
        </table>
"""
        
        if summary.errors:
            html += """
        <h3>Errors</h3>
        <div class="error-list">
            <ul>
"""
            for error in summary.errors[:10]:  # Show first 10 errors
                html += f"                <li>{self._escape_html(error)}</li>\n"
            
            if len(summary.errors) > 10:
                html += f"                <li>... and {len(summary.errors) - 10} more errors</li>\n"
            
            html += """            </ul>
        </div>
"""
        
        return html
    
    def _generate_findings_section(self, summary: AuditSummary) -> str:
        """Generate the findings section."""
        if not summary.findings:
            return """
        <h2>Findings</h2>
        <div class="no-findings">
            <h3>✅ No security findings detected!</h3>
            <p>The audit completed successfully with no security issues found.</p>
        </div>
"""
        
        html = """
        <h2>Detailed Findings</h2>
"""
        
        # Sort findings by severity
        severity_order = {
            SeverityLevel.CRITICAL: 0,
            SeverityLevel.HIGH: 1,
            SeverityLevel.MEDIUM: 2,
            SeverityLevel.LOW: 3,
            SeverityLevel.INFO: 4,
        }
        
        sorted_findings = sorted(
            summary.findings,
            key=lambda f: (severity_order.get(f.severity, 5), f.category.value)
        )
        
        for finding in sorted_findings:
            html += self._generate_finding_card(finding)
        
        return html
    
    def _generate_finding_card(self, finding: Finding) -> str:
        """Generate HTML for a single finding."""
        emoji = get_severity_emoji(finding.severity)
        
        html = f"""
        <div class="finding {finding.severity.value}">
            <div class="finding-header">
                <div class="finding-title">{emoji} {self._escape_html(finding.title)}</div>
                <span class="finding-severity severity-{finding.severity.value}">{finding.severity.value.upper()}</span>
            </div>
            <div class="finding-meta">
                <strong>ID:</strong> {finding.id} | 
                <strong>Category:</strong> {finding.category.value.replace('_', ' ').title()} | 
                <strong>Confidence:</strong> {finding.confidence.value} |
                <strong>Check:</strong> {finding.check_id}
            </div>
            
            <div class="finding-section">
                <h4>Target</h4>
                <pre>{self._escape_html(finding.target)}</pre>
            </div>
            
            <div class="finding-section">
                <h4>Evidence</h4>
                <pre>{self._escape_html(finding.evidence)}</pre>
            </div>
            
            <div class="finding-section">
                <h4>Remediation</h4>
                <p>{self._escape_html(finding.remediation)}</p>
            </div>
"""
        
        if finding.references:
            html += """
            <div class="finding-section references">
                <h4>References</h4>
"""
            for ref in finding.references:
                html += f'                <a href="{self._escape_html(ref)}" target="_blank">{self._escape_html(ref)}</a>\n'
            html += """            </div>
"""
        
        html += """        </div>
"""
        
        return html
    
    def _generate_footer(self, summary: AuditSummary) -> str:
        """Generate HTML footer."""
        return f"""
        <div class="metadata" style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #ecf0f1; text-align: center;">
            <p>Report generated by Security Audit Tool v1.0.0</p>
            <p style="font-size: 0.8em; color: #95a5a6;">
                This report is intended for authorized security assessment purposes only.
            </p>
        </div>
    </div>
</body>
</html>
"""
    
    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters."""
        return (
            text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )
