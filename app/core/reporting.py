"""Report generation service."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

from ..config import Config
from ..models import AuditSummary
from ..report import HTMLReporter, JSONReporter, PDFReporter, TerminalReporter


def generate_reports(
    summary: AuditSummary,
    config: Config,
    logger: logging.Logger,
    report_json_override: Path | None = None,
    report_html_override: Path | None = None,
    report_pdf_override: Path | None = None,
) -> None:
    """Generate all requested output formats for an audit summary."""
    if not config.output.quiet:
        terminal_reporter = TerminalReporter(use_colors=sys.stdout.isatty())
        print(terminal_reporter.generate(summary))

    json_path = report_json_override or config.output.json_report_path
    if json_path:
        JSONReporter().write(summary, json_path)
        logger.info("JSON report written to: %s", json_path)

    html_path = report_html_override or config.output.html_report_path
    if html_path:
        HTMLReporter().write(summary, html_path)
        logger.info("HTML report written to: %s", html_path)

    pdf_path = report_pdf_override or config.output.pdf_report_path
    if pdf_path:
        PDFReporter().write(summary, pdf_path)
        logger.info("PDF report written to: %s", pdf_path)
