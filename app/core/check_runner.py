"""Execution service for security checks."""

from __future__ import annotations

import logging
from datetime import datetime

from ..checks import BaseCheck
from ..config import Config
from ..models import AuditSummary, Scope, SeverityLevel
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

    for check_class in select_checks(config, skip_checks=skip_checks, only_checks=only_checks):
        try:
            logger.debug("Running check: %s", check_class.check_name)

            check = check_class(scope, config)
            result = check.run()

            summary.findings.extend(result.findings)

            for error in result.errors:
                message = f"{check_class.check_id}: {error}"
                summary.errors.append(message)
                logger.error("Check %s error: %s", check_class.check_id, error)

            logger.debug(
                "Check %s completed: %s findings",
                check_class.check_id,
                result.findings_count,
            )
        except Exception as exc:
            error_message = f"Check {check_class.check_id} failed: {exc}"
            summary.errors.append(error_message)
            logger.exception(error_message)

    summary.end_time = datetime.utcnow()
    return summary


def get_exit_code(summary: AuditSummary) -> int:
    """Return the process exit code for a completed audit summary."""
    critical_high = sum(
        1
        for finding in summary.findings
        if finding.severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH)
    )
    return 2 if critical_high > 0 else 0
