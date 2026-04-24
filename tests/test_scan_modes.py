"""Tests for target-oriented scan mode profiles."""

from app.config import Config
from app.core.scan_modes import apply_scan_mode, get_scan_mode_definition
from app.models import ScanMode


class TestScanModes:
    """Tests for predefined scan mode behavior."""

    def test_website_review_enables_live_website_checks(self) -> None:
        """Website Review should enable live website posture checks."""
        config = Config()

        apply_scan_mode(config, ScanMode.WEBSITE_REVIEW)

        assert config.scan.mode == "website_review"
        assert config.check.tls_check is True
        assert config.check.enable_banner_grabbing is True
        assert config.check.website_risk_check is True
        assert config.check.performance_test is True
        assert config.check.load_test is False
        assert config.check.vulnerability_scan is False
        assert config.check.permissions_check is False
        assert config.output.verbose is True

    def test_api_review_uses_live_http_baseline(self) -> None:
        """API Review should use the live HTTP review baseline."""
        config = Config()

        apply_scan_mode(config, ScanMode.API_REVIEW)

        assert config.scan.mode == "api_review"
        assert config.check.tls_check is True
        assert config.check.enable_banner_grabbing is True
        assert config.check.website_risk_check is True
        assert config.check.performance_test is True
        assert config.check.load_test is False
        assert config.check.secrets_check is False
        assert config.output.verbose is True

    def test_owasp_top_10_review_enables_active_web_risk_checks(self) -> None:
        """OWASP mode should enable the broad live web-risk baseline."""
        config = Config()

        apply_scan_mode(config, ScanMode.OWASP_TOP_10_REVIEW)

        assert config.scan.mode == "owasp_top_10_review"
        assert config.check.tls_check is True
        assert config.check.enable_banner_grabbing is True
        assert config.check.website_risk_check is True
        assert config.check.performance_test is True
        assert config.check.vulnerability_scan is True
        assert config.check.load_test is False
        assert config.check.secrets_check is False
        assert config.output.verbose is True

    def test_codebase_review_enables_project_checks(self) -> None:
        """Codebase Review should focus on project files and configs."""
        config = Config()

        apply_scan_mode(config, ScanMode.CODEBASE_REVIEW)

        assert config.scan.mode == "codebase_review"
        assert config.check.secrets_check is True
        assert config.check.dependencies_check is True
        assert config.check.webapp_config_check is True
        assert config.check.containers_check is True
        assert config.check.permissions_check is False
        assert config.check.tls_check is False

    def test_host_hardening_enables_local_system_checks(self) -> None:
        """Host Hardening should enable local system checks only."""
        config = Config()

        apply_scan_mode(config, ScanMode.HOST_HARDENING)

        assert config.scan.mode == "host_hardening"
        assert config.check.permissions_check is True
        assert config.check.services_check is True
        assert config.check.firewall_check is True
        assert config.check.hardening_check is True
        assert config.check.secrets_check is False
        assert config.check.performance_test is False

    def test_container_review_focuses_on_container_checks(self) -> None:
        """Container Review should isolate container-specific checks."""
        config = Config()

        apply_scan_mode(config, ScanMode.CONTAINER_REVIEW)

        assert config.scan.mode == "container_review"
        assert config.check.containers_check is True
        assert config.check.dependencies_check is False
        assert config.check.permissions_check is False
        assert config.check.performance_test is False

    def test_resilience_test_isolated_to_performance_and_load(self) -> None:
        """Resilience Test should stay focused on performance and load."""
        config = Config()

        apply_scan_mode(config, ScanMode.RESILIENCE_TEST)

        assert config.scan.mode == "resilience_test"
        assert config.check.performance_test is True
        assert config.check.load_test is True
        assert config.check.tls_check is False
        assert config.check.website_risk_check is False
        assert config.check.permissions_check is False
        assert config.output.verbose is True

    def test_custom_starts_with_all_mode_managed_checks_disabled(self) -> None:
        """Custom should defer check selection to later user choices."""
        config = Config()

        apply_scan_mode(config, ScanMode.CUSTOM)

        assert config.scan.mode == "custom"
        assert config.check.permissions_check is False
        assert config.check.services_check is False
        assert config.check.secrets_check is False
        assert config.check.website_risk_check is False
        assert config.check.performance_test is False

    def test_definition_lookup_returns_expected_label(self) -> None:
        """Definitions should expose stable labels for the TUI."""
        definition = get_scan_mode_definition(ScanMode.API_REVIEW)

        assert definition.label == "API Review"
