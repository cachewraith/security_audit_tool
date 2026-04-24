"""Central registry for available security checks."""

from __future__ import annotations

from ..checks import (
    BaseCheck,
    ContainersCheck,
    DependenciesCheck,
    FirewallCheck,
    HardeningCheck,
    LoadTestCheck,
    PermissionsCheck,
    PerformanceCheck,
    SecretsCheck,
    ServicesCheck,
    TLSCheck,
    VulnerabilityCheck,
    WebsiteRiskCheck,
    WebAppConfigCheck,
)
from ..config import Config

BASE_CHECKS: tuple[type[BaseCheck], ...] = (
    PermissionsCheck,
    ServicesCheck,
    FirewallCheck,
    HardeningCheck,
    SecretsCheck,
    DependenciesCheck,
    TLSCheck,
    ContainersCheck,
    WebAppConfigCheck,
)

ACTIVE_CHECKS: tuple[type[BaseCheck], ...] = (
    WebsiteRiskCheck,
    PerformanceCheck,
    LoadTestCheck,
    VulnerabilityCheck,
)


def get_available_checks(config: Config) -> list[type[BaseCheck]]:
    """Return the checks available for the provided configuration."""
    checks = list(BASE_CHECKS)

    if config.check.website_risk_check:
        checks.append(WebsiteRiskCheck)
    if config.check.performance_test:
        checks.append(PerformanceCheck)
    if config.check.load_test:
        checks.append(LoadTestCheck)
    if config.check.vulnerability_scan:
        checks.append(VulnerabilityCheck)

    return checks


def get_check_map(config: Config) -> dict[str, type[BaseCheck]]:
    """Return available checks keyed by their stable identifier."""
    return {check.check_id: check for check in get_available_checks(config)}
