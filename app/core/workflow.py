"""Top-level audit workflow orchestration."""

from __future__ import annotations

import logging
from pathlib import Path

from ..config import Config
from ..logging_setup import log_audit_end, log_audit_start
from ..scope import ScopeManager
from .check_runner import get_exit_code, run_checks
from .reporting import generate_reports


def run_audit_workflow(
    config: Config,
    scope_manager: ScopeManager,
    logger: logging.Logger,
    skip_checks: list[str] | None = None,
    only_checks: list[str] | None = None,
    report_json_override: Path | None = None,
    report_html_override: Path | None = None,
    report_pdf_override: Path | None = None,
) -> int:
    """Run the end-to-end audit workflow and return a process exit code."""
    scope_summary = scope_manager.get_scope_summary()
    log_audit_start(logger, scope_summary, config.to_dict())

    try:
        from ..tui import TUI

        tui = TUI()
        if not config.output.quiet:
            summary = tui.run_with_progress(
                run_checks,
                scope=scope_manager.scope,
                config=config,
                logger=logger,
                skip_checks=skip_checks,
                only_checks=only_checks,
                scope_summary=scope_summary,
            )
        else:
            summary = run_checks(
                scope=scope_manager.scope,
                config=config,
                logger=logger,
                skip_checks=skip_checks,
                only_checks=only_checks,
            )
    except Exception as exc:
        logger.exception("Audit failed: %s", exc)
        return 1

    log_audit_end(logger, summary.to_dict())

    try:
        generate_reports(
            summary=summary,
            config=config,
            logger=logger,
            report_json_override=report_json_override,
            report_html_override=report_html_override,
            report_pdf_override=report_pdf_override,
        )
    except Exception as exc:
        logger.exception("Error generating reports: %s", exc)
        return 1

    exit_code = get_exit_code(summary)
    if exit_code == 2:
        logger.info("Audit completed with critical/high findings")
    else:
        logger.info("Audit completed successfully")
    return exit_code
