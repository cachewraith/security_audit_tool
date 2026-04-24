"""Configuration management for the security audit tool."""

import os
import yaml
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


@dataclass
class RateLimitConfig:
    """Rate limiting configuration."""
    requests_per_second: float = 10.0
    max_concurrent: int = 5
    connection_timeout: float = 5.0
    read_timeout: float = 10.0
    retry_count: int = 2
    retry_delay: float = 1.0


@dataclass
class ScanConfig:
    """Scan behavior configuration."""
    mode: str = "custom"
    max_depth: int = 10
    follow_symlinks: bool = False
    max_file_size_mb: int = 10
    skip_hidden_files: bool = False
    include_patterns: list[str] = field(default_factory=list)
    exclude_patterns: list[str] = field(default_factory=lambda: [
        "*.log",
        "*.tmp",
        "*.bak",
        "node_modules/",
        "__pycache__/",
        ".git/",
        ".svn/",
        "*.pyc",
    ])


@dataclass
class CheckConfig:
    """Configuration for individual security checks."""
    # Enable/disable specific checks
    permissions_check: bool = True
    services_check: bool = True
    firewall_check: bool = True
    hardening_check: bool = True
    secrets_check: bool = True
    dependencies_check: bool = True
    tls_check: bool = False  # Disabled by default, requires explicit opt-in
    containers_check: bool = True
    webapp_config_check: bool = True
    website_risk_check: bool = False

    # Active tests - these send traffic to targets (pentest mode)
    performance_test: bool = False  # Response time testing
    load_test: bool = False  # DDoS/load testing simulation
    vulnerability_scan: bool = False  # SQLi, XSS, injection tests

    # Check-specific options
    enable_banner_grabbing: bool = False
    check_sudo_config: bool = True
    check_ssh_config: bool = True
    check_world_writable: bool = True
    check_suid_sgid: bool = True
    
    # Secret detection patterns (safe, pattern-based only)
    secret_patterns: list[str] = field(default_factory=lambda: [
        r"password\s*=\s*['\"][^'\"]+['\"]",
        r"api_key\s*=\s*['\"][^'\"]+['\"]",
        r"secret\s*=\s*['\"][^'\"]+['\"]",
        r"private_key\s*=\s*['\"][^'\"]+['\"]",
        r"AWS_ACCESS_KEY_ID\s*=\s*['\"]?[A-Z0-9]{20}['\"]?",
        r"AKIA[0-9A-Z]{16}",
    ])


@dataclass
class OutputConfig:
    """Output configuration."""
    verbose: bool = False
    quiet: bool = False
    show_passed_checks: bool = False
    include_evidence: bool = True
    max_findings_in_summary: int = 50
    
    # Report paths (None = don't generate)
    json_report_path: Optional[Path] = None
    html_report_path: Optional[Path] = None
    pdf_report_path: Optional[Path] = None
    log_path: Optional[Path] = None


@dataclass
class Config:
    """Main application configuration."""
    
    # Authorization confirmation
    authorization_confirmed: bool = False
    
    # Scope configuration
    scope_file: Optional[Path] = None
    
    # Sub-configurations
    rate_limit: RateLimitConfig = field(default_factory=RateLimitConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)
    check: CheckConfig = field(default_factory=CheckConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    
    @classmethod
    def from_yaml(cls, path: Path) -> "Config":
        """Load configuration from YAML file."""
        with open(path, 'r') as f:
            data = yaml.safe_load(f)
        
        return cls.from_dict(data or {})
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Config":
        """Create configuration from dictionary."""
        config = cls()
        
        # Load top-level settings
        config.authorization_confirmed = data.get("authorization_confirmed", False)
        scope_path = data.get("scope_file")
        if scope_path:
            config.scope_file = Path(scope_path)
        
        # Load rate limit config
        if "rate_limit" in data:
            rl = data["rate_limit"]
            config.rate_limit = RateLimitConfig(
                requests_per_second=rl.get("requests_per_second", 10.0),
                max_concurrent=rl.get("max_concurrent", 5),
                connection_timeout=rl.get("connection_timeout", 5.0),
                read_timeout=rl.get("read_timeout", 10.0),
                retry_count=rl.get("retry_count", 2),
                retry_delay=rl.get("retry_delay", 1.0),
            )
        
        # Load scan config
        if "scan" in data:
            sc = data["scan"]
            config.scan = ScanConfig(
                mode=sc.get("mode", "custom"),
                max_depth=sc.get("max_depth", 10),
                follow_symlinks=sc.get("follow_symlinks", False),
                max_file_size_mb=sc.get("max_file_size_mb", 10),
                skip_hidden_files=sc.get("skip_hidden_files", False),
                include_patterns=sc.get("include_patterns", []),
                exclude_patterns=sc.get("exclude_patterns", config.scan.exclude_patterns),
            )
        
        # Load check config
        if "check" in data:
            ch = data["check"]
            config.check = CheckConfig(
                permissions_check=ch.get("permissions_check", True),
                services_check=ch.get("services_check", True),
                firewall_check=ch.get("firewall_check", True),
                hardening_check=ch.get("hardening_check", True),
                secrets_check=ch.get("secrets_check", True),
                dependencies_check=ch.get("dependencies_check", True),
                tls_check=ch.get("tls_check", False),
                containers_check=ch.get("containers_check", True),
                webapp_config_check=ch.get("webapp_config_check", True),
                website_risk_check=ch.get("website_risk_check", False),
                enable_banner_grabbing=ch.get("enable_banner_grabbing", False),
                check_sudo_config=ch.get("check_sudo_config", True),
                check_ssh_config=ch.get("check_ssh_config", True),
                check_world_writable=ch.get("check_world_writable", True),
                check_suid_sgid=ch.get("check_suid_sgid", True),
                secret_patterns=ch.get("secret_patterns", config.check.secret_patterns),
            )
        
        # Load output config
        if "output" in data:
            out = data["output"]
            json_path = out.get("json_report_path")
            html_path = out.get("html_report_path")
            pdf_path = out.get("pdf_report_path")
            log_path = out.get("log_path")
            
            config.output = OutputConfig(
                verbose=out.get("verbose", False),
                quiet=out.get("quiet", False),
                show_passed_checks=out.get("show_passed_checks", False),
                include_evidence=out.get("include_evidence", True),
                max_findings_in_summary=out.get("max_findings_in_summary", 50),
                json_report_path=Path(json_path) if json_path else None,
                html_report_path=Path(html_path) if html_path else None,
                pdf_report_path=Path(pdf_path) if pdf_path else None,
                log_path=Path(log_path) if log_path else None,
            )
        
        return config
    
    def to_dict(self) -> dict[str, Any]:
        """Convert configuration to dictionary."""
        return {
            "authorization_confirmed": self.authorization_confirmed,
            "scope_file": str(self.scope_file) if self.scope_file else None,
            "rate_limit": {
                "requests_per_second": self.rate_limit.requests_per_second,
                "max_concurrent": self.rate_limit.max_concurrent,
                "connection_timeout": self.rate_limit.connection_timeout,
                "read_timeout": self.rate_limit.read_timeout,
                "retry_count": self.rate_limit.retry_count,
                "retry_delay": self.rate_limit.retry_delay,
            },
            "scan": {
                "mode": self.scan.mode,
                "max_depth": self.scan.max_depth,
                "follow_symlinks": self.scan.follow_symlinks,
                "max_file_size_mb": self.scan.max_file_size_mb,
                "skip_hidden_files": self.scan.skip_hidden_files,
                "include_patterns": self.scan.include_patterns,
                "exclude_patterns": self.scan.exclude_patterns,
            },
            "check": {
                "permissions_check": self.check.permissions_check,
                "services_check": self.check.services_check,
                "firewall_check": self.check.firewall_check,
                "hardening_check": self.check.hardening_check,
                "secrets_check": self.check.secrets_check,
                "dependencies_check": self.check.dependencies_check,
                "tls_check": self.check.tls_check,
                "containers_check": self.check.containers_check,
                "webapp_config_check": self.check.webapp_config_check,
                "website_risk_check": self.check.website_risk_check,
                "enable_banner_grabbing": self.check.enable_banner_grabbing,
                "check_sudo_config": self.check.check_sudo_config,
                "check_ssh_config": self.check.check_ssh_config,
                "check_world_writable": self.check.check_world_writable,
                "check_suid_sgid": self.check.check_suid_sgid,
            },
            "output": {
                "verbose": self.output.verbose,
                "quiet": self.output.quiet,
                "show_passed_checks": self.output.show_passed_checks,
                "include_evidence": self.output.include_evidence,
                "max_findings_in_summary": self.output.max_findings_in_summary,
                "json_report_path": str(self.output.json_report_path) if self.output.json_report_path else None,
                "html_report_path": str(self.output.html_report_path) if self.output.html_report_path else None,
                "pdf_report_path": str(self.output.pdf_report_path) if self.output.pdf_report_path else None,
                "log_path": str(self.output.log_path) if self.output.log_path else None,
            },
        }
    
    def save_yaml(self, path: Path) -> None:
        """Save configuration to YAML file."""
        with open(path, 'w') as f:
            yaml.dump(self.to_dict(), f, default_flow_style=False, sort_keys=True)


def get_default_config_path() -> Path:
    """Get the default configuration file path."""
    config_dir = Path.home() / ".config" / "security_audit_tool"
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir / "config.yaml"


def load_config(config_path: Optional[Path] = None) -> Config:
    """Load configuration from file or create default."""
    if config_path is None:
        config_path = get_default_config_path()
    
    if config_path.exists():
        return Config.from_yaml(config_path)
    
    return Config()
