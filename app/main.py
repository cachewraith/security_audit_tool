"""Main entry point for the security audit tool."""

import sys
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
from .core import get_available_checks, run_audit_workflow, run_checks
from .scope import ScopeManager, ScopeError
from .logging_setup import setup_logging
from .tui import TUI


def main(args: list[str] | None = None) -> int:
    """Main entry point.
    
    Returns:
        Exit code (0 for success, 1 for failure)
    """
    # Check if we should run in interactive TUI mode
    # Run TUI if no arguments are provided to the script
    actual_args = args if args is not None else sys.argv[1:]
    
    if not actual_args:
        tui = TUI()
        while True:
            tui_result = tui.run()
            if not tui_result:
                return 0
            
            config, scope_manager, extra_options = tui_result
            
            # Setup logging for TUI mode
            logger = setup_logging(
                verbose=config.output.verbose,
                quiet=config.output.quiet,
                log_file=config.output.log_path,
            )
            
            # Convert comma-separated strings to lists
            skip_checks = extra_options.get("skip_checks")
            if skip_checks and isinstance(skip_checks, str):
                skip_checks = [c.strip() for c in skip_checks.split(",")]
                
            only_checks = extra_options.get("only_checks")
            if only_checks and isinstance(only_checks, str):
                only_checks = [c.strip() for c in only_checks.split(",")]
            
            run_audit_workflow(
                config=config,
                scope_manager=scope_manager,
                logger=logger,
                skip_checks=skip_checks,
                only_checks=only_checks,
            )
            
            if not tui.wait_for_user():
                break
        return 0

    # Parse CLI arguments
    parsed_args = parse_args(actual_args)
    
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
    
    # Parse skip/only checks
    skip_checks: list[str] | None = None
    only_checks: list[str] | None = None
    
    if parsed_args.skip_checks:
        skip_checks = [c.strip() for c in parsed_args.skip_checks.split(",")]
    
    if parsed_args.only_checks:
        only_checks = [c.strip() for c in parsed_args.only_checks.split(",")]
    
    return run_audit_workflow(
        config=config,
        scope_manager=scope_manager,
        logger=logger,
        skip_checks=skip_checks,
        only_checks=only_checks,
        report_json_override=parsed_args.report_json,
        report_html_override=parsed_args.report_html,
        report_pdf_override=parsed_args.report_pdf,
    )


if __name__ == "__main__":
    sys.exit(main())
