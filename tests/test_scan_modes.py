"""Tests for defensive scan mode profiles."""

from app.config import Config
from app.core.scan_modes import apply_scan_mode, get_scan_mode_definition
from app.models import ScanMode


class TestScanModes:
    """Tests for predefined scan mode behavior."""

    def test_passive_audit_uses_read_only_defaults(self) -> None:
        """Passive Audit should keep active checks disabled."""
        config = Config()

        apply_scan_mode(config, ScanMode.PASSIVE_AUDIT)

        assert config.scan.mode == "passive_audit"
        assert config.check.tls_check is False
        assert config.check.enable_banner_grabbing is False
        assert config.check.performance_test is False
        assert config.check.load_test is False
        assert config.check.vulnerability_scan is False

    def test_active_validation_enables_live_validation_only(self) -> None:
        """Active Validation should enable bounded live checks."""
        config = Config()

        apply_scan_mode(config, ScanMode.ACTIVE_VALIDATION)

        assert config.scan.mode == "active_validation"
        assert config.check.tls_check is True
        assert config.check.enable_banner_grabbing is True
        assert config.check.performance_test is True
        assert config.check.load_test is False
        assert config.check.vulnerability_scan is False

    def test_resilience_test_enables_bounded_load_checks(self) -> None:
        """Resilience Test should add load testing without enabling probes."""
        config = Config()

        apply_scan_mode(config, ScanMode.RESILIENCE_TEST)

        assert config.scan.mode == "resilience_test"
        assert config.check.tls_check is True
        assert config.check.enable_banner_grabbing is True
        assert config.check.performance_test is True
        assert config.check.load_test is True
        assert config.check.vulnerability_scan is False
        assert config.output.verbose is True

    def test_definition_lookup_returns_expected_label(self) -> None:
        """Definitions should expose stable labels for the TUI."""
        definition = get_scan_mode_definition(ScanMode.ACTIVE_VALIDATION)

        assert definition.label == "Active Validation"
