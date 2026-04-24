"""PDF reporter for security audit findings."""

from pathlib import Path

from fpdf import FPDF

from ..models import AuditSummary, SeverityLevel

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

    def _create_pdf(self) -> PDF:
        """Create a fresh PDF instance for each report generation."""
        pdf = PDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        return pdf

    def _header(self, pdf: PDF, summary: AuditSummary | None = None):
        pdf.set_font("Helvetica", "B", 16)
        pdf.set_text_color(*self.colors["HEADER"])
        pdf.cell(0, 10, "SECURITY AUDIT REPORT", ln=True, align="C")
        
        pdf.set_font("Helvetica", "B", 12)
        pdf.set_text_color(*self.colors["INFO"])
        pdf.cell(0, 8, "Made by Somonor Hong", ln=True, align="C")

        pdf.set_font("Helvetica", "I", 10)
        pdf.set_text_color(*self.colors["GRAY"])
        pdf.cell(0, 8, "Authorized Use Only - Defensive Scanner", ln=True, align="C")
        
        if summary:
            pdf.ln(5)
            finding_text = f"FOUND {len(summary.findings)} SECURITY VULNERABILITIES"
            if len(summary.findings) == 0:
                finding_text = "NO SECURITY VULNERABILITIES FOUND"
            
            pdf.set_font("Helvetica", "B", 14)
            pdf.set_text_color(*self.colors[SeverityLevel.HIGH if len(summary.findings) > 0 else "GRAY"])
            pdf.cell(0, 10, finding_text, ln=True, align="C")

        pdf.ln(5)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(5)

    def generate(self, summary: AuditSummary) -> bytes:
        """Generate PDF content as bytes."""
        pdf = self._create_pdf()
        pdf.add_page()
        self._header(pdf, summary)

        # Summary Section
        pdf.set_font("Helvetica", "B", 14)
        pdf.set_text_color(*self.colors["BLACK"])
        pdf.cell(0, 10, "1. Executive Summary", ln=True)
        pdf.set_font("Helvetica", "", 11)
        
        # Summary Grid
        data = [
            ["Start Time", summary.start_time.strftime("%Y-%m-%d %H:%M:%S")],
            ["Duration", f"{summary.duration_seconds:.2f}s"],
            ["Total Findings", str(len(summary.findings))],
            ["Targets Scanned", str(summary.target_count)],
            ["Errors Encountered", str(len(summary.errors))],
        ]
        
        for label, value in data:
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(40, 8, f"{label}:", border=0)
            pdf.set_font("Helvetica", "", 10)
            pdf.cell(0, 8, value, ln=True)
        
        pdf.ln(5)

        # Severity Breakdown
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 10, "Severity Breakdown:", ln=True)
        counts = summary.count_by_severity()
        
        for sev in [SeverityLevel.CRITICAL, SeverityLevel.HIGH, SeverityLevel.MEDIUM, SeverityLevel.LOW, SeverityLevel.INFO]:
            count = counts.get(sev, 0)
            if count >= 0:
                color = self.colors.get(sev, self.colors["GRAY"])
                pdf.set_fill_color(*color)
                pdf.set_text_color(*self.colors["WHITE"])
                pdf.set_font("Helvetica", "B", 10)
                pdf.cell(30, 8, f" {sev.value.upper()} ", fill=True)
                pdf.set_text_color(*self.colors["BLACK"])
                pdf.cell(20, 8, f" : {count}", ln=True)
        
        pdf.ln(10)

        # Findings Section
        if summary.findings:
            pdf.set_font("Helvetica", "B", 14)
            pdf.cell(0, 10, "2. Detailed Findings", ln=True)
            pdf.ln(2)

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
                pdf.set_font("Helvetica", "B", 11)
                pdf.set_text_color(*color)
                pdf.cell(0, 8, f"Finding #{i}: {finding.title}", ln=True)
                
                # Meta info
                pdf.set_font("Helvetica", "I", 9)
                pdf.set_text_color(100, 100, 100)
                meta = f"Severity: {finding.severity.value.upper()} | Category: {finding.category.value} | Target: {finding.target}"
                pdf.cell(0, 6, meta, ln=True)
                
                # Evidence
                pdf.set_font("Helvetica", "B", 9)
                pdf.set_text_color(*self.colors["BLACK"])
                pdf.cell(0, 6, "Evidence:", ln=True)
                pdf.set_font("Helvetica", "", 9)
                pdf.multi_cell(0, 5, finding.evidence or "No evidence provided.")
                
                # Remediation
                pdf.set_font("Helvetica", "B", 9)
                pdf.set_text_color(0, 128, 0)
                pdf.cell(0, 6, "Remediation:", ln=True)
                pdf.set_font("Helvetica", "", 9)
                pdf.set_text_color(*self.colors["BLACK"])
                pdf.multi_cell(0, 5, finding.remediation or "No remediation recommended.")
                
                pdf.ln(5)
                pdf.line(15, pdf.get_y(), 195, pdf.get_y())
                pdf.ln(5)

        # Errors Section
        if summary.errors:
            pdf.add_page()
            pdf.set_font("Helvetica", "B", 14)
            pdf.set_text_color(200, 0, 0)
            pdf.cell(0, 10, "3. Errors Encountered", ln=True)
            pdf.set_font("Helvetica", "", 10)
            pdf.set_text_color(*self.colors["BLACK"])
            for err in summary.errors:
                pdf.multi_cell(0, 6, f"* {err}")
                pdf.ln(2)

        return bytes(pdf.output())

    def write(self, summary: AuditSummary, path: Path) -> None:
        """Write PDF report to file."""
        path.parent.mkdir(parents=True, exist_ok=True)
        content = self.generate(summary)
        with open(path, "wb") as f:
            f.write(content)
