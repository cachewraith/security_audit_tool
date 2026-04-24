"""Shared scan-mode definitions for TUI and configuration."""

from __future__ import annotations

from dataclasses import dataclass

from ..config import Config
from ..models import ScanMode

CHECK_SETTING_BY_ID: dict[str, str] = {
    "permissions": "permissions_check",
    "services": "services_check",
    "firewall": "firewall_check",
    "hardening": "hardening_check",
    "secrets": "secrets_check",
    "dependencies": "dependencies_check",
    "tls": "tls_check",
    "containers": "containers_check",
    "webapp_config": "webapp_config_check",
    "website_risk": "website_risk_check",
    "performance": "performance_test",
    "load_test": "load_test",
    "vulnerability": "vulnerability_scan",
}


@dataclass(frozen=True)
class ScanModeDefinition:
    """Display and behavior metadata for a scan mode."""

    key: str
    mode: ScanMode
    label: str
    description: str


SCAN_MODE_DEFINITIONS: tuple[ScanModeDefinition, ...] = (
    ScanModeDefinition(
        key="1",
        mode=ScanMode.WEBSITE_REVIEW,
        label="Website Review",
        description="Live website headers, cookies, TLS, and page posture checks",
    ),
    ScanModeDefinition(
        key="2",
        mode=ScanMode.OWASP_TOP_10_REVIEW,
        label="OWASP Top 10 Review",
        description="Broad web risk review mapped to OWASP Top 10 with active probes",
    ),
    ScanModeDefinition(
        key="3",
        mode=ScanMode.API_REVIEW,
        label="API Review",
        description="Live API-oriented HTTP posture, TLS, and latency review",
    ),
    ScanModeDefinition(
        key="4",
        mode=ScanMode.CODEBASE_REVIEW,
        label="Codebase Review",
        description="Secrets, dependencies, web config, and container file review",
    ),
    ScanModeDefinition(
        key="5",
        mode=ScanMode.HOST_HARDENING,
        label="Host Hardening",
        description="Local permissions, services, firewall, and hardening checks",
    ),
    ScanModeDefinition(
        key="6",
        mode=ScanMode.CONTAINER_REVIEW,
        label="Container Review",
        description="Dockerfile, Compose, image, and running-container review",
    ),
    ScanModeDefinition(
        key="7",
        mode=ScanMode.RESILIENCE_TEST,
        label="Resilience Test",
        description="Performance and bounded load testing only",
    ),
    ScanModeDefinition(
        key="8",
        mode=ScanMode.CUSTOM,
        label="Custom",
        description="Choose a target type and tailor checks manually",
    ),
)


def reset_scan_profile(config: Config) -> None:
    """Reset mode-managed check settings to their safe defaults."""
    config.check.permissions_check = False
    config.check.services_check = False
    config.check.firewall_check = False
    config.check.hardening_check = False
    config.check.secrets_check = False
    config.check.dependencies_check = False
    config.check.tls_check = False
    config.check.containers_check = False
    config.check.webapp_config_check = False
    config.check.enable_banner_grabbing = False
    config.check.website_risk_check = False
    config.check.performance_test = False
    config.check.load_test = False
    config.check.vulnerability_scan = False
    config.output.verbose = False


def enable_checks(config: Config, check_ids: list[str] | tuple[str, ...]) -> None:
    """Enable the specified checks on a configuration object."""
    for check_id in check_ids:
        setting_name = CHECK_SETTING_BY_ID.get(check_id)
        if setting_name:
            setattr(config.check, setting_name, True)


def apply_scan_mode(config: Config, mode: ScanMode) -> None:
    """Apply a defensive scan profile to the provided config."""
    reset_scan_profile(config)
    config.scan.mode = mode.value

    if mode == ScanMode.WEBSITE_REVIEW:
        enable_checks(config, ["tls", "website_risk", "performance"])
        config.check.enable_banner_grabbing = True
        config.output.verbose = True
        return

    if mode == ScanMode.OWASP_TOP_10_REVIEW:
        enable_checks(config, ["tls", "website_risk", "vulnerability", "performance"])
        config.check.enable_banner_grabbing = True
        config.output.verbose = True
        return

    if mode == ScanMode.API_REVIEW:
        enable_checks(config, ["tls", "website_risk", "performance"])
        config.check.enable_banner_grabbing = True
        config.output.verbose = True
        return

    if mode == ScanMode.CODEBASE_REVIEW:
        enable_checks(config, ["secrets", "dependencies", "webapp_config", "containers"])
        return

    if mode == ScanMode.HOST_HARDENING:
        enable_checks(config, ["permissions", "services", "firewall", "hardening"])
        return

    if mode == ScanMode.CONTAINER_REVIEW:
        enable_checks(config, ["containers"])
        return

    if mode == ScanMode.RESILIENCE_TEST:
        enable_checks(config, ["performance", "load_test"])
        config.output.verbose = True
        return


def get_scan_mode_definition(mode: ScanMode) -> ScanModeDefinition:
    """Return the definition for a scan mode."""
    for definition in SCAN_MODE_DEFINITIONS:
        if definition.mode == mode:
            return definition
    raise ValueError(f"Unknown scan mode: {mode}")
