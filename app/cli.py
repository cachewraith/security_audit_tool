"""Command-line interface for the security audit tool."""

import argparse
import sys
from pathlib import Path

from . import LEGAL_WARNING
from .config import Config


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser for the CLI."""
    parser = argparse.ArgumentParser(
        prog="security-audit",
        description="Security Audit Tool - Defensive security assessment for authorized use only",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Audit with scope file
  python -m app.main --scope-file scope.yml

  # Audit a project directory
  python -m app.main --path /approved/project --report-json findings.json

  # Audit with multiple outputs
  python -m app.main --path ./myapp --report-json out.json --report-html out.html

  # Network audit with host list
  python -m app.main --hosts approved_hosts.txt --enable-tls-checks

  # Local endpoint audit
  python -m app.main --local --verbose

For more information, see README.md
        """
    )
    
    # Scope arguments
    scope_group = parser.add_argument_group("Scope Definition (at least one required)")
    scope_group.add_argument(
        "--scope-file",
        type=Path,
        help="YAML file defining the audit scope",
    )
    scope_group.add_argument(
        "--local",
        action="store_true",
        help="Include local endpoint in scope",
    )
    scope_group.add_argument(
        "--path",
        type=Path,
        action="append",
        help="Add a project directory to scope (can be specified multiple times)",
    )
    scope_group.add_argument(
        "--hosts",
        type=Path,
        help="File containing list of allowed hosts (one per line)",
    )
    scope_group.add_argument(
        "--host",
        type=str,
        action="append",
        help="Add a single host to scope (can be specified multiple times)",
    )
    scope_group.add_argument(
        "--url",
        type=str,
        action="append",
        help="Add a URL to audit - extracts hostname automatically (can be specified multiple times)",
    )

    # Check selection
    check_group = parser.add_argument_group("Check Selection")
    check_group.add_argument(
        "--enable-tls-checks",
        action="store_true",
        help="Enable TLS/SSL certificate checks (disabled by default)",
    )
    check_group.add_argument(
        "--enable-banner-grabbing",
        action="store_true",
        help="Enable service banner grabbing (disabled by default)",
    )
    check_group.add_argument(
        "--enable-performance-test",
        action="store_true",
        help="Enable performance testing (response time measurement)",
    )
    check_group.add_argument(
        "--enable-load-test",
        action="store_true",
        help="Enable load testing (sends multiple requests - use with caution)",
    )
    check_group.add_argument(
        "--enable-vulnerability-scan",
        action="store_true",
        help="Enable vulnerability scanning (SQLi, XSS, injection tests)",
    )
    check_group.add_argument(
        "--pentest-mode",
        action="store_true",
        help="Enable all pentest features (performance, load, vulnerability tests)",
    )
    check_group.add_argument(
        "--skip-checks",
        type=str,
        help="Comma-separated list of check IDs to skip",
    )
    check_group.add_argument(
        "--only-checks",
        type=str,
        help="Comma-separated list of check IDs to run (all others skipped)",
    )
    
    # Output options
    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument(
        "--report-json",
        type=Path,
        help="Write JSON report to specified file",
    )
    output_group.add_argument(
        "--report-html",
        type=Path,
        help="Write HTML report to specified file",
    )
    output_group.add_argument(
        "--log-file",
        type=Path,
        help="Write structured logs to specified file",
    )
    output_group.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output",
    )
    output_group.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress non-error output",
    )
    output_group.add_argument(
        "--show-passed",
        action="store_true",
        help="Show passed checks in output",
    )
    
    # Rate limiting
    rate_group = parser.add_argument_group("Rate Limiting")
    rate_group.add_argument(
        "--max-concurrent",
        type=int,
        default=5,
        help="Maximum concurrent connections (default: 5)",
    )
    rate_group.add_argument(
        "--connection-timeout",
        type=float,
        default=5.0,
        help="Connection timeout in seconds (default: 5.0)",
    )
    
    # Authorization confirmation
    auth_group = parser.add_argument_group("Authorization")
    auth_group.add_argument(
        "--yes",
        action="store_true",
        help="Confirm authorization (skip interactive prompt)",
    )
    auth_group.add_argument(
        "--config",
        type=Path,
        help="Configuration file path",
    )
    
    # Convenience options
    parser.add_argument(
        "--full-scan",
        action="store_true",
        help="Enable all checks and generate reports (JSON + HTML)",
    )

    # Information
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 1.0.0",
    )
    parser.add_argument(
        "--list-checks",
        action="store_true",
        help="List available checks and exit",
    )
    parser.add_argument(
        "--generate-scope-example",
        action="store_true",
        help="Generate example scope YAML and exit",
    )
    
    return parser


def confirm_authorization() -> bool:
    """Display legal warning and confirm authorization interactively."""
    print(LEGAL_WARNING)
    
    while True:
        try:
            response = input("\nDo you have explicit authorization to audit these targets? (yes/no): ")
            response = response.strip().lower()
            
            if response in ["yes", "y"]:
                return True
            elif response in ["no", "n"]:
                print("Authorization denied. Exiting.")
                return False
            else:
                print("Please enter 'yes' or 'no'.")
        except (EOFError, KeyboardInterrupt):
            print("\nOperation cancelled.")
            return False


def list_available_checks() -> None:
    """Print list of available security checks."""
    checks = [
        ("permissions", "File and directory permission checks"),
        ("services", "Running service and port enumeration"),
        ("firewall", "Firewall status and configuration"),
        ("hardening", "OS hardening indicator checks"),
        ("secrets", "Hardcoded secrets and credential patterns"),
        ("dependencies", "Outdated and vulnerable dependencies"),
        ("tls", "TLS/SSL certificate inspection (opt-in)"),
        ("containers", "Container security configuration"),
        ("webapp_config", "Web application configuration checks"),
        ("performance", "Performance testing - response time measurement (opt-in)"),
        ("load_test", "Load testing - DDoS simulation (opt-in, intensive)"),
        ("vulnerability", "Vulnerability scanning - SQLi, XSS tests (opt-in)"),
    ]

    print("\nAvailable Security Checks:")
    print("-" * 60)
    print("  Read-only checks (safe, enabled by default):")
    for check_id, description in checks[:9]:
        print(f"    {check_id:20} - {description}")
    print("\n  Active tests (send traffic, requires --pentest-mode):")
    for check_id, description in checks[9:]:
        print(f"    {check_id:20} - {description}")
    print()


def generate_scope_example() -> None:
    """Generate and print example scope configuration."""
    from .scope import create_example_scope_yaml
    
    print(create_example_scope_yaml())


def parse_args(args: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = create_parser()
    return parser.parse_args(args)


def validate_args(args: argparse.Namespace) -> tuple[bool, list[str]]:
    """Validate CLI arguments and return (is_valid, error_messages)."""
    errors = []
    
    # Apply full-scan options first
    apply_full_scan_options(args)

    # Check that at least one scope-defining argument is provided
    has_scope = any([
        args.scope_file,
        args.local,
        args.path,
        args.hosts,
        args.host,
        args.url,
    ])
    
    if not has_scope:
        errors.append(
            "No scope defined. Use --scope-file, --local, --path, --hosts, or --host.\n"
            "Run with --help for more information."
        )
    
    # Validate file paths
    if args.scope_file and not args.scope_file.exists():
        errors.append(f"Scope file does not exist: {args.scope_file}")
    
    if args.hosts and not args.hosts.exists():
        errors.append(f"Hosts file does not exist: {args.hosts}")
    
    if args.path:
        for p in args.path:
            if not p.exists():
                errors.append(f"Project path does not exist: {p}")
            elif not p.is_dir():
                errors.append(f"Project path is not a directory: {p}")
    
    # Validate rate limiting
    if args.max_concurrent < 1:
        errors.append("--max-concurrent must be at least 1")
    
    if args.connection_timeout <= 0:
        errors.append("--connection-timeout must be positive")
    
    return len(errors) == 0, errors


def apply_full_scan_options(args: argparse.Namespace) -> None:
    """Apply full-scan defaults if --full-scan is enabled."""
    if args.full_scan:
        # Enable all check options
        args.enable_tls_checks = True
        args.enable_banner_grabbing = True
        # Also enable pentest features for comprehensive scan
        args.enable_performance_test = True
        args.enable_vulnerability_scan = True
        # Load test is intensive, don't auto-enable even in full-scan
        # User must explicitly use --pentest-mode for load testing

    # Apply pentest mode - enables all active tests including load test
    if getattr(args, 'pentest_mode', False):
        args.enable_performance_test = True
        args.enable_load_test = True
        args.enable_vulnerability_scan = True

        # Auto-generate report filenames if not specified
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        if not args.report_json:
            args.report_json = Path(f"security_audit_{timestamp}.json")
        if not args.report_html:
            args.report_html = Path(f"security_audit_{timestamp}.html")

        # Enable verbose output
        args.verbose = True

        # Auto-confirm authorization (still requires user to be responsible)
        args.yes = True


def build_config_from_args(args: argparse.Namespace) -> Config:
    """Build configuration object from CLI arguments."""
    # Load base config if provided
    if args.config and Path(args.config).exists():
        config = Config.from_yaml(Path(args.config))
    else:
        config = Config()
    
    # Apply CLI overrides
    config.authorization_confirmed = args.yes
    
    # Output settings
    config.output.verbose = args.verbose
    config.output.quiet = args.quiet
    config.output.show_passed_checks = args.show_passed
    
    if args.report_json:
        config.output.json_report_path = args.report_json
    
    if args.report_html:
        config.output.html_report_path = args.report_html
    
    if args.log_file:
        config.output.log_path = args.log_file
    
    # Check settings
    config.check.tls_check = args.enable_tls_checks
    config.check.enable_banner_grabbing = args.enable_banner_grabbing
    config.check.performance_test = args.enable_performance_test
    config.check.load_test = args.enable_load_test
    config.check.vulnerability_scan = args.enable_vulnerability_scan
    
    # Rate limiting
    config.rate_limit.max_concurrent = args.max_concurrent
    config.rate_limit.connection_timeout = args.connection_timeout
    
    return config
