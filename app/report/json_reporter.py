"""JSON report generator."""

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from ..models import AuditSummary, Finding


class JSONReporter:
    """Generate JSON format security audit reports."""
    
    def __init__(self, indent: int = 2):
        self.indent = indent
    
    def generate(self, summary: AuditSummary) -> str:
        """Generate a JSON report from an audit summary.
        
        Args:
            summary: The audit summary to report
        
        Returns:
            JSON formatted string
        """
        report = {
            "report_metadata": {
                "generated_at": datetime.utcnow().isoformat(),
                "version": "1.0.0",
                "format": "json",
            },
            "audit_summary": summary.to_dict(),
        }
        
        return json.dumps(report, indent=self.indent, default=self._json_serializer)
    
    def write(self, summary: AuditSummary, output_path: Path) -> None:
        """Write JSON report to a file.
        
        Args:
            summary: The audit summary to report
            output_path: Path to write the report
        """
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        json_content = self.generate(summary)
        
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(json_content)
    
    def _json_serializer(self, obj: Any) -> Any:
        """Custom JSON serializer for special types."""
        if isinstance(obj, datetime):
            return obj.isoformat()
        raise TypeError(f"Object of type {type(obj)} is not JSON serializable")
    
    @staticmethod
    def findings_to_json(findings: list[Finding]) -> list[dict[str, Any]]:
        """Convert a list of findings to JSON-serializable dictionaries."""
        return [f.to_dict() for f in findings]
    
    def generate_filtered(
        self,
        summary: AuditSummary,
        min_severity: str = "info",
        categories: list[str] | None = None,
    ) -> str:
        """Generate a JSON report with filtered findings.
        
        Args:
            summary: The audit summary
            min_severity: Minimum severity level to include
            categories: Optional list of categories to include
        
        Returns:
            JSON formatted string
        """
        # Severity order for filtering
        severity_order = ["info", "low", "medium", "high", "critical"]
        min_index = severity_order.index(min_severity.lower())
        allowed_severities = severity_order[min_index:]
        
        # Filter findings
        filtered_findings = [
            f for f in summary.findings
            if f.severity.value in allowed_severities
            and (categories is None or f.category.value in categories)
        ]
        
        # Create filtered summary
        filtered_summary = AuditSummary(
            start_time=summary.start_time,
            end_time=summary.end_time,
            target_count=summary.target_count,
            findings=filtered_findings,
            errors=summary.errors,
        )
        
        return self.generate(filtered_summary)
