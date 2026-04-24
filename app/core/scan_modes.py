"""Shared scan-mode definitions for TUI and configuration."""

from __future__ import annotations

from dataclasses import dataclass

from ..config import Config
from ..models import ScanMode


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
        mode=ScanMode.PASSIVE_AUDIT,
        label="Passive Audit",
        description="Read-only discovery and configuration checks",
    ),
    ScanModeDefinition(
        key="2",
        mode=ScanMode.ACTIVE_VALIDATION,
        label="Active Validation",
        description="Live validation with TLS, banners, and response checks",
    ),
    ScanModeDefinition(
        key="3",
        mode=ScanMode.RESILIENCE_TEST,
        label="Resilience Test",
        description="Active validation plus bounded performance and load checks",
    ),
    ScanModeDefinition(
        key="4",
        mode=ScanMode.CUSTOM,
        label="Custom",
        description="Select specific checks and output behavior manually",
    ),
)


def reset_scan_profile(config: Config) -> None:
    """Reset mode-managed check settings to their safe defaults."""
    config.check.tls_check = False
    config.check.enable_banner_grabbing = False
    config.check.performance_test = False
    config.check.load_test = False
    config.check.vulnerability_scan = False
    config.output.verbose = False


def apply_scan_mode(config: Config, mode: ScanMode) -> None:
    """Apply a defensive scan profile to the provided config."""
    reset_scan_profile(config)
    config.scan.mode = mode.value

    if mode == ScanMode.PASSIVE_AUDIT:
        return

    if mode == ScanMode.ACTIVE_VALIDATION:
        config.check.tls_check = True
        config.check.enable_banner_grabbing = True
        config.check.performance_test = True
        return

    if mode == ScanMode.RESILIENCE_TEST:
        config.check.tls_check = True
        config.check.enable_banner_grabbing = True
        config.check.performance_test = True
        config.check.load_test = True
        config.output.verbose = True
        return


def get_scan_mode_definition(mode: ScanMode) -> ScanModeDefinition:
    """Return the definition for a scan mode."""
    for definition in SCAN_MODE_DEFINITIONS:
        if definition.mode == mode:
            return definition
    raise ValueError(f"Unknown scan mode: {mode}")
