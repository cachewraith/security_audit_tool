"""Main entry point for the security audit tool."""

import sys
from datetime import datetime
from pathlib import Path

from .cli import (
    parse_args,
    validate_args,
    confirm_authorization,
    list_available_checks,
    generate_scope_example,
    build_config_from_args,
)
from .config import Config
from .scope import ScopeManager, ScopeError
from .logging_setup import setup_logging, log_audit_start, log_audit_end
from .models import AuditSummary, Scope, SeverityLevel
from .checks import (
    PermissionsCheck,
    ServicesCheck,
    FirewallCheck,
    HardeningCheck,
    SecretsCheck,
    DependenciesCheck,
    TLSCheck,
    ContainersCheck,
    WebAppConfigCheck,
    PerformanceCheck,
    LoadTestCheck,
    VulnerabilityCheck,
    BaseCheck,
)
from .report import JSONReporter, HTMLReporter, TerminalReporter


def get_available_checks(config: Config) -> list[type[BaseCheck]]:
    """Get list of all available security checks based on config."""
    checks = [
        PermissionsCheck,
        ServicesCheck,
        FirewallCheck,
        HardeningCheck,
        SecretsCheck,
        DependenciesCheck,
        TLSCheck,
        ContainersCheck,
        WebAppConfigCheck,
    ]

    # Add active tests only if enabled (they send traffic to target)
    if config.check.performance_test:
        checks.append(PerformanceCheck)
    if config.check.load_test:
        checks.append(LoadTestCheck)
    if config.check.vulnerability_scan:
        checks.append(VulnerabilityCheck)

    return checks


def run_checks(
    scope: Scope,
    config: Config,
    logger,
    skip_checks: list[str] | None = None,
    only_checks: list[str] | None = None,
) -> AuditSummary:
    """Run all enabled security checks."""
    summary = AuditSummary(
        start_time=datetime.utcnow(),
        target_count=len(scope.project_paths) + (1 if scope.local_endpoint else 0) + len(scope.allowed_hosts),
    )
    
    # Filter checks based on configuration and CLI options
    available_checks = get_available_checks(config)
    checks_to_run: list[type[BaseCheck]] = []
    
    for check_class in available_checks:
        check_id = check_class.check_id
        
        # Skip if in skip list
        if skip_checks and check_id in skip_checks:
            continue
        
        # Skip if not in only list (when specified)
        if only_checks and check_id not in only_checks:
            continue
        
        # Check if enabled in config
        if check_id == "tls" and not config.check.tls_check:
            continue
        if check_id == "performance" and not config.check.performance_test:
            continue
        if check_id == "load_test" and not config.check.load_test:
            continue
        if check_id == "vulnerability" and not config.check.vulnerability_scan:
            continue

        checks_to_run.append(check_class)
    
    # Run each check
    for check_class in checks_to_run:
        try:
            logger.debug(f"Running check: {check_class.check_name}")
            
            check = check_class(scope, config)
            result = check.run()
            
            # Add findings to summary
            summary.findings.extend(result.findings)
            
            # Log any errors
            for error in result.errors:
                summary.errors.append(f"{check_class.check_id}: {error}")
                logger.error(f"Check {check_class.check_id} error: {error}")
            
            logger.debug(f"Check {check_class.check_id} completed: {result.findings_count} findings")
            
        except Exception as e:
            error_msg = f"Check {check_class.check_id} failed: {e}"
            summary.errors.append(error_msg)
            logger.error(error_msg)
    
    summary.end_time = datetime.utcnow()
    return summary


def main(args: list[str] | None = None) -> int:
    """Main entry point.
    
    Returns:
        Exit code (0 for success, 1 for failure)
    """
    # Parse CLI arguments
    parsed_args = parse_args(args)
    
    # Handle special commands
    if parsed_args.list_checks:
        list_available_checks()
        return 0
    
    if parsed_args.generate_scope_example:
        generate_scope_example()
        return 0
    
    # Validate arguments
    is_valid, errors = validate_args(parsed_args)
    if not is_valid:
        for error in errors:
            print(f"Error: {error}", file=sys.stderr)
        return 1
    
    # Build configuration
    config = build_config_from_args(parsed_args)
    
    # Setup logging
    logger = setup_logging(
        verbose=config.output.verbose,
        quiet=config.output.quiet,
        log_file=config.output.log_path,
    )
    
    # Confirm authorization
    if not config.authorization_confirmed:
        if not confirm_authorization():
            logger.info("Authorization not confirmed. Exiting.")
            return 1
    
    # Build scope
    try:
        if parsed_args.scope_file:
            scope_manager = ScopeManager.from_yaml_file(parsed_args.scope_file)
        else:
            scope_manager = ScopeManager.from_args(
                local=parsed_args.local,
                paths=parsed_args.path,
                hosts=parsed_args.host,
                host_file=parsed_args.hosts,
                urls=parsed_args.url,
            )
        
        # Validate scope
        if not scope_manager.validate():
            for error in scope_manager.validation_errors:
                logger.error(f"Scope validation error: {error}")
            return 1
        
        scope_manager.require_scope()
        
    except ScopeError as e:
        logger.error(f"Scope error: {e}")
        return 1
    except Exception as e:
        logger.error(f"Error building scope: {e}")
        return 1
    
    # Log scope summary
    scope_summary = scope_manager.get_scope_summary()
    log_audit_start(
        logger,
        scope_summary,
        config.to_dict(),
    )
    
    # Print scope summary to console
    if not config.output.quiet:
        print(scope_summary)
        print()
    
    # Parse skip/only checks
    skip_checks: list[str] | None = None
    only_checks: list[str] | None = None
    
    if parsed_args.skip_checks:
        skip_checks = [c.strip() for c in parsed_args.skip_checks.split(",")]
    
    if parsed_args.only_checks:
        only_checks = [c.strip() for c in parsed_args.only_checks.split(",")]
    
    # Run security checks
    try:
        summary = run_checks(
            scope=scope_manager.scope,
            config=config,
            logger=logger,
            skip_checks=skip_checks,
            only_checks=only_checks,
        )
    except Exception as e:
        logger.error(f"Audit failed: {e}")
        return 1
    
    # Log completion
    log_audit_end(logger, summary.to_dict())
    
    # Generate reports
    try:
        # Terminal report
        if not config.output.quiet:
            terminal_reporter = TerminalReporter(use_colors=sys.stdout.isatty())
            terminal_output = terminal_reporter.generate(summary)
            print(terminal_output)
        
        # JSON report
        if config.output.json_report_path or parsed_args.report_json:
            json_path = parsed_args.report_json or config.output.json_report_path
            if json_path:
                json_reporter = JSONReporter()
                json_reporter.write(summary, json_path)
                logger.info(f"JSON report written to: {json_path}")
        
        # HTML report
        if config.output.html_report_path or parsed_args.report_html:
            html_path = parsed_args.report_html or config.output.html_report_path
            if html_path:
                html_reporter = HTMLReporter()
                html_reporter.write(summary, html_path)
                logger.info(f"HTML report written to: {html_path}")
        
        # Also write JSON if path specified via CLI
        if parsed_args.report_json and parsed_args.report_json != config.output.json_report_path:
            json_reporter = JSONReporter()
            json_reporter.write(summary, parsed_args.report_json)
            logger.info(f"JSON report written to: {parsed_args.report_json}")
        
        if parsed_args.report_html and parsed_args.report_html != config.output.html_report_path:
            html_reporter = HTMLReporter()
            html_reporter.write(summary, parsed_args.report_html)
            logger.info(f"HTML report written to: {parsed_args.report_html}")
    
    except Exception as e:
        logger.error(f"Error generating reports: {e}")
        return 1
    
    # Return exit code based on findings
    critical_high = sum(
        1 for f in summary.findings
        if f.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]
    )
    
    if critical_high > 0:
        logger.info(f"Audit completed with {critical_high} critical/high findings")
        return 2  # Non-zero exit but not failure
    
    logger.info("Audit completed successfully")
    return 0


if __name__ == "__main__":
    sys.exit(main())
