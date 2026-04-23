"""PDF reporter for security audit findings."""

import time
from pathlib import Path
from fpdf import FPDF
from ..models import AuditSummary, SeverityLevel, Category

class PDF(FPDF):
    def header(self):
        # We handle header manually in the reporter for more control
        pass

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f"Page {self.page_no()}", align="C")

class PDFReporter:
    """Generates professional PDF reports for security audits."""

    def __init__(self):
        self.pdf = PDF()
        self.pdf.set_auto_page_break(auto=True, margin=15)
        
        # Define colors (RGB)
        self.colors = {
            SeverityLevel.CRITICAL: (220, 50, 50),
            SeverityLevel.HIGH: (255, 140, 0),
            SeverityLevel.MEDIUM: (255, 200, 0),
            SeverityLevel.LOW: (0, 150, 0),
            SeverityLevel.INFO: (0, 100, 255),
            "HEADER": (0, 100, 150),
            "GRAY": (128, 128, 128),
            "BLACK": (0, 0, 0),
            "WHITE": (255, 255, 255),
        }

    def _header(self, summary: AuditSummary | None = None):
        self.pdf.set_font("Helvetica", "B", 16)
        self.pdf.set_text_color(*self.colors["HEADER"])
        self.pdf.cell(0, 10, "SECURITY AUDIT REPORT", ln=True, align="C")
        
        self.pdf.set_font("Helvetica", "B", 12)
        self.pdf.set_text_color(*self.colors["INFO"])
        self.pdf.cell(0, 8, "Made by Somonor Hong", ln=True, align="C")

        self.pdf.set_font("Helvetica", "I", 10)
        self.pdf.set_text_color(*self.colors["GRAY"])
        self.pdf.cell(0, 8, "Authorized Use Only - Defensive Scanner", ln=True, align="C")
        
        if summary:
            self.pdf.ln(5)
            finding_text = f"FOUND {len(summary.findings)} SECURITY VULNERABILITIES"
            if len(summary.findings) == 0:
                finding_text = "NO SECURITY VULNERABILITIES FOUND"
            
            self.pdf.set_font("Helvetica", "B", 14)
            self.pdf.set_text_color(*self.colors[SeverityLevel.HIGH if len(summary.findings) > 0 else "GRAY"])
            self.pdf.cell(0, 10, finding_text, ln=True, align="C")

        self.pdf.ln(5)
        self.pdf.line(10, self.pdf.get_y(), 200, self.pdf.get_y())
        self.pdf.ln(5)

    def generate(self, summary: AuditSummary) -> bytes:
        """Generate PDF content as bytes."""
        self.pdf.add_page()
        self._header(summary)

        # Summary Section
        self.pdf.set_font("Helvetica", "B", 14)
        self.pdf.set_text_color(*self.colors["BLACK"])
        self.pdf.cell(0, 10, "1. Executive Summary", ln=True)
        self.pdf.set_font("Helvetica", "", 11)
        
        # Summary Grid
        data = [
            ["Start Time", summary.start_time.strftime("%Y-%m-%d %H:%M:%S")],
            ["Duration", f"{summary.duration_seconds:.2f}s"],
            ["Total Findings", str(len(summary.findings))],
            ["Targets Scanned", str(summary.target_count)],
            ["Errors Encountered", str(len(summary.errors))],
        ]
        
        for label, value in data:
            self.pdf.set_font("Helvetica", "B", 10)
            self.pdf.cell(40, 8, f"{label}:", border=0)
            self.pdf.set_font("Helvetica", "", 10)
            self.pdf.cell(0, 8, value, ln=True)
        
        self.pdf.ln(5)

        # Severity Breakdown
        self.pdf.set_font("Helvetica", "B", 12)
        self.pdf.cell(0, 10, "Severity Breakdown:", ln=True)
        counts = summary.count_by_severity()
        
        for sev in [SeverityLevel.CRITICAL, SeverityLevel.HIGH, SeverityLevel.MEDIUM, SeverityLevel.LOW, SeverityLevel.INFO]:
            count = counts.get(sev, 0)
            if count >= 0:
                color = self.colors.get(sev, self.colors["GRAY"])
                self.pdf.set_fill_color(*color)
                self.pdf.set_text_color(*self.colors["WHITE"])
                self.pdf.set_font("Helvetica", "B", 10)
                self.pdf.cell(30, 8, f" {sev.value.upper()} ", fill=True)
                self.pdf.set_text_color(*self.colors["BLACK"])
                self.pdf.cell(20, 8, f" : {count}", ln=True)
        
        self.pdf.ln(10)

        # Findings Section
        if summary.findings:
            self.pdf.set_font("Helvetica", "B", 14)
            self.pdf.cell(0, 10, "2. Detailed Findings", ln=True)
            self.pdf.ln(2)

            severity_order = {
                SeverityLevel.CRITICAL: 0,
                SeverityLevel.HIGH: 1,
                SeverityLevel.MEDIUM: 2,
                SeverityLevel.LOW: 3,
                SeverityLevel.INFO: 4,
            }

            sorted_findings = sorted(
                summary.findings,
                key=lambda f: (severity_order.get(f.severity, 99), f.category.value),
            )

            for i, finding in enumerate(sorted_findings, 1):
                # Finding Header
                color = self.colors.get(finding.severity, self.colors["GRAY"])
                self.pdf.set_font("Helvetica", "B", 11)
                self.pdf.set_text_color(*color)
                self.pdf.cell(0, 8, f"Finding #{i}: {finding.title}", ln=True)
                
                # Meta info
                self.pdf.set_font("Helvetica", "I", 9)
                self.pdf.set_text_color(100, 100, 100)
                meta = f"Severity: {finding.severity.value.upper()} | Category: {finding.category.value} | Target: {finding.target}"
                self.pdf.cell(0, 6, meta, ln=True)
                
                # Evidence
                self.pdf.set_font("Helvetica", "B", 9)
                self.pdf.set_text_color(*self.colors["BLACK"])
                self.pdf.cell(0, 6, "Evidence:", ln=True)
                self.pdf.set_font("Helvetica", "", 9)
                self.pdf.multi_cell(0, 5, finding.evidence or "No evidence provided.")
                
                # Remediation
                self.pdf.set_font("Helvetica", "B", 9)
                self.pdf.set_text_color(0, 128, 0) # Green for remediation
                self.pdf.cell(0, 6, "Remediation:", ln=True)
                self.pdf.set_font("Helvetica", "", 9)
                self.pdf.set_text_color(*self.colors["BLACK"])
                self.pdf.multi_cell(0, 5, finding.remediation or "No remediation recommended.")
                
                self.pdf.ln(5)
                self.pdf.line(15, self.pdf.get_y(), 195, self.pdf.get_y())
                self.pdf.ln(5)

        # Errors Section
        if summary.errors:
            self.pdf.add_page()
            self.pdf.set_font("Helvetica", "B", 14)
            self.pdf.set_text_color(200, 0, 0)
            self.pdf.cell(0, 10, "3. Errors Encountered", ln=True)
            self.pdf.set_font("Helvetica", "", 10)
            self.pdf.set_text_color(*self.colors["BLACK"])
            for err in summary.errors:
                self.pdf.multi_cell(0, 6, f"* {err}")
                self.pdf.ln(2)

        return self.pdf.output()

    def write(self, summary: AuditSummary, path: Path) -> None:
        """Write PDF report to file."""
        content = self.generate(summary)
        with open(path, "wb") as f:
            f.write(content)
