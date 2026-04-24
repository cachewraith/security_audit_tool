"""Execution service for security checks."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Callable

from ..checks import BaseCheck
from ..config import Config
from ..models import AuditSummary, CheckExecution, Scope, SeverityLevel
from .check_registry import get_available_checks

CHECK_ENABLEMENT: dict[str, str] = {
    "permissions": "permissions_check",
    "services": "services_check",
    "firewall": "firewall_check",
    "hardening": "hardening_check",
    "secrets": "secrets_check",
    "dependencies": "dependencies_check",
    "tls": "tls_check",
    "containers": "containers_check",
    "webapp_config": "webapp_config_check",
    "performance": "performance_test",
    "load_test": "load_test",
    "vulnerability": "vulnerability_scan",
    "website_risk": "website_risk_check",
}

ProgressCallback = Callable[[dict[str, Any]], None]


def build_check_execution(check: BaseCheck, result: "CheckResult") -> CheckExecution:
    """Convert a check result into report-friendly execution metadata."""
    return CheckExecution(
        check_id=check.check_id,
        check_name=check.check_name,
        category=check.category.value,
        passed=result.passed,
        findings_count=result.findings_count,
        errors=list(result.errors),
        duration_seconds=result.duration_seconds,
        metadata=dict(result.metadata),
    )


def is_check_enabled(check_class: type[BaseCheck], config: Config) -> bool:
    """Return whether a check is enabled for the current configuration."""
    setting_name = CHECK_ENABLEMENT.get(check_class.check_id)
    if not setting_name:
        return True
    return bool(getattr(config.check, setting_name))


def select_checks(
    config: Config,
    skip_checks: list[str] | None = None,
    only_checks: list[str] | None = None,
) -> list[type[BaseCheck]]:
    """Return the filtered list of checks to execute."""
    selected: list[type[BaseCheck]] = []

    for check_class in get_available_checks(config):
        check_id = check_class.check_id

        if skip_checks and check_id in skip_checks:
            continue
        if only_checks and check_id not in only_checks:
            continue
        if not is_check_enabled(check_class, config):
            continue

        selected.append(check_class)

    return selected


def run_checks(
    scope: Scope,
    config: Config,
    logger: logging.Logger,
    skip_checks: list[str] | None = None,
    only_checks: list[str] | None = None,
    progress_callback: ProgressCallback | None = None,
) -> AuditSummary:
    """Run all selected checks and aggregate their findings."""
    summary = AuditSummary(
        start_time=datetime.utcnow(),
        target_count=(
            len(scope.project_paths)
            + (1 if scope.local_endpoint else 0)
            + len(scope.allowed_hosts)
            + len(scope.allowed_urls)
        ),
    )

    selected_checks = select_checks(config, skip_checks=skip_checks, only_checks=only_checks)

    if progress_callback:
        progress_callback({"event": "start", "total": len(selected_checks)})

    for index, check_class in enumerate(selected_checks, start=1):
        if progress_callback:
            progress_callback(
                {
                    "event": "check_start",
                    "current": index,
                    "total": len(selected_checks),
                    "check_id": check_class.check_id,
                    "check_name": check_class.check_name,
                }
            )
        try:
            logger.debug("Running check: %s", check_class.check_name)

            check = check_class(scope, config)
            result = check.run()

            summary.findings.extend(result.findings)
            summary.check_results.append(build_check_execution(check, result))

            for error in result.errors:
                message = f"{check_class.check_id}: {error}"
                summary.errors.append(message)
                logger.error("Check %s error: %s", check_class.check_id, error)

            logger.debug(
                "Check %s completed: %s findings",
                check_class.check_id,
                result.findings_count,
            )
            if progress_callback:
                progress_callback(
                    {
                        "event": "check_end",
                        "current": index,
                        "total": len(selected_checks),
                        "check_id": check_class.check_id,
                        "check_name": check_class.check_name,
                        "findings_count": result.findings_count,
                        "findings_count_total": len(summary.findings),
                        "errors_count": len(result.errors),
                        "errors_count_total": len(summary.errors),
                        "status": "ok",
                    }
                )
        except Exception as exc:
            error_message = f"Check {check_class.check_id} failed: {exc}"
            summary.errors.append(error_message)
            summary.check_results.append(
                CheckExecution(
                    check_id=check_class.check_id,
                    check_name=check_class.check_name,
                    category=check_class.category.value,
                    passed=False,
                    findings_count=0,
                    errors=[str(exc)],
                    duration_seconds=0.0,
                )
            )
            logger.exception(error_message)
            if progress_callback:
                progress_callback(
                    {
                        "event": "check_end",
                        "current": index,
                        "total": len(selected_checks),
                        "check_id": check_class.check_id,
                        "check_name": check_class.check_name,
                        "findings_count": 0,
                        "findings_count_total": len(summary.findings),
                        "errors_count": 1,
                        "errors_count_total": len(summary.errors),
                        "status": "failed",
                    }
                )

    summary.end_time = datetime.utcnow()

    if progress_callback:
        progress_callback(
            {
                "event": "complete",
                "total": len(selected_checks),
                "findings_count": len(summary.findings),
                "errors_count": len(summary.errors),
            }
        )

    return summary


def get_exit_code(summary: AuditSummary) -> int:
    """Return the process exit code for a completed audit summary."""
    critical_high = sum(
        1
        for finding in summary.findings
        if finding.severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH)
    )
    return 2 if critical_high > 0 else 0
