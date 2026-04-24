# Technical Reference

## Purpose

This document describes the current technical structure of the project for maintainers and contributors. It focuses on how the application is organized, how checks are selected and executed, and where to extend the system safely.

## High-Level Architecture

The project is organized around five main layers:

1. Entry and interface layer
2. Scope and configuration layer
3. Check execution layer
4. Data collection and policy layer
5. Reporting layer

Core execution path:

`CLI/TUI -> Config + Scope -> Scan Mode -> Check Selection -> Check Execution -> AuditSummary -> Reports`

## Directory Structure

```text
app/
├── main.py
├── cli.py
├── tui.py
├── config.py
├── models.py
├── scope.py
├── logging_setup.py
├── core/
│   ├── __init__.py
│   ├── check_registry.py
│   ├── check_runner.py
│   ├── reporting.py
│   ├── scan_modes.py
│   └── workflow.py
├── checks/
│   ├── __init__.py
│   ├── base.py
│   ├── permissions_check.py
│   ├── services_check.py
│   ├── firewall_check.py
│   ├── hardening_check.py
│   ├── secrets_check.py
│   ├── dependencies_check.py
│   ├── tls_check.py
│   ├── containers_check.py
│   ├── webapp_config_check.py
│   ├── website_risk_check.py
│   ├── vulnerability_check.py
│   ├── performance_check.py
│   ├── load_test_check.py
│   └── website_risk/
│       ├── __init__.py
│       ├── analyzer.py
│       ├── fetcher.py
│       ├── models.py
│       └── parsers.py
├── collectors/
├── report/
├── policy/
└── utils/
```

## Main Execution Paths

### CLI Path

The CLI entry starts in [app/main.py](/mnt/storage/OwnProject/pentest-tool-python/security_audit_tool/app/main.py).

Flow:

1. Parse arguments in `app.cli`
2. Build `Config`
3. Confirm authorization
4. Build and validate scope via `ScopeManager`
5. Run `run_audit_workflow()`
6. Generate reports
7. Return exit code based on finding severity

### TUI Path

When the application starts with no arguments, it launches the interactive workspace in [app/tui.py](/mnt/storage/OwnProject/pentest-tool-python/security_audit_tool/app/tui.py).

Flow:

1. User selects a scan mode
2. The selected mode is applied to `Config`
3. The TUI collects an appropriate scope for that mode
4. Optional report and custom-check decisions are collected
5. The same TUI instance runs the scan with live progress
6. The completion screen shows the final findings list

## Configuration Model

Configuration is defined in [app/config.py](/mnt/storage/OwnProject/pentest-tool-python/security_audit_tool/app/config.py) using dataclasses.

Main groups:

- `RateLimitConfig`
- `ScanConfig`
- `CheckConfig`
- `OutputConfig`
- `Config`

Important `CheckConfig` flags:

- `tls_check`
- `website_risk_check`
- `performance_test`
- `load_test`
- `vulnerability_scan`
- `enable_banner_grabbing`
- `active_check_min_duration_seconds`
- `multi_stage_active_checks`
- `randomize_safe_requests`
- `performance_samples_per_stage`
- `load_test_concurrent`
- `load_test_requests_per_user`
- `load_test_duration_seconds`

These flags are controlled either directly by CLI options or indirectly through scan modes.

## Scope Model

Scope is defined in [app/models.py](/mnt/storage/OwnProject/pentest-tool-python/security_audit_tool/app/models.py) and managed by [app/scope.py](/mnt/storage/OwnProject/pentest-tool-python/security_audit_tool/app/scope.py).

Supported scope inputs:

- `local_endpoint`
- `project_paths`
- `allowed_hosts`
- `allowed_urls`
- `container_images`
- `container_ids`

`ScopeManager` is responsible for:

- creating scope from CLI args or YAML
- validating target values
- producing scope summaries for UI and logs
- enforcing non-empty scope

## Scan Modes

Mode definitions live in [app/core/scan_modes.py](/mnt/storage/OwnProject/pentest-tool-python/security_audit_tool/app/core/scan_modes.py).

Current modes:

- `WEBSITE_REVIEW`
- `OWASP_TOP_10_REVIEW`
- `API_REVIEW`
- `CODEBASE_REVIEW`
- `HOST_HARDENING`
- `CONTAINER_REVIEW`
- `RESILIENCE_TEST`
- `CUSTOM`

`apply_scan_mode()` first resets all mode-managed checks, then enables the correct subset for the chosen mode.

Example:

- `OWASP_TOP_10_REVIEW` enables `tls`, `website_risk`, `vulnerability`, and `performance`
- `RESILIENCE_TEST` enables `performance` and `load_test`
- `CODEBASE_REVIEW` enables `secrets`, `dependencies`, `webapp_config`, and `containers`

## Check Registration and Selection

Check discovery is split across two modules:

- [app/core/check_registry.py](/mnt/storage/OwnProject/pentest-tool-python/security_audit_tool/app/core/check_registry.py)
- [app/core/check_runner.py](/mnt/storage/OwnProject/pentest-tool-python/security_audit_tool/app/core/check_runner.py)

### Registry

`check_registry.py` exposes:

- `BASE_CHECKS`
- `ACTIVE_CHECKS`
- `get_available_checks()`
- `get_check_map()`

### Runner

`check_runner.py` handles:

- enablement filtering
- `skip_checks`
- `only_checks`
- progress callback events
- summary aggregation
- exit code selection

Progress events include:

- `start`
- `check_start`
- `check_end`
- `complete`

## Base Check Contract

All checks inherit from [app/checks/base.py](/mnt/storage/OwnProject/pentest-tool-python/security_audit_tool/app/checks/base.py).

Core pieces:

- `BaseCheck`
- `CheckResult`
- `_create_result()`
- `_finish_result()`
- `_create_finding()`

Each check class must define:

- `check_id`
- `check_name`
- `category`
- `run()`

Expected behavior:

1. Create a result object
2. Perform check logic
3. Append findings and errors
4. Finalize the result

## Data Models

Core domain models live in [app/models.py](/mnt/storage/OwnProject/pentest-tool-python/security_audit_tool/app/models.py).

Important models:

- `Finding`
- `AuditSummary`
- `Scope`
- `SeverityLevel`
- `ConfidenceLevel`
- `Category`
- `ScanMode`

`Finding` includes:

- title
- category
- severity
- confidence
- target
- evidence
- remediation
- references
- `check_id`
- metadata

`AuditSummary` aggregates all findings and errors for a run and is the object passed into reporters and the TUI completion screen.

`AuditSummary.check_results` now also records per-check execution details such as duration, pass/fail state, errors, and stage metadata for longer-running active checks.

## Website Risk Subsystem

The website risk check was recently refactored into an internal package:

- [app/checks/website_risk_check.py](/mnt/storage/OwnProject/pentest-tool-python/security_audit_tool/app/checks/website_risk_check.py)
- [app/checks/website_risk/fetcher.py](/mnt/storage/OwnProject/pentest-tool-python/security_audit_tool/app/checks/website_risk/fetcher.py)
- [app/checks/website_risk/parsers.py](/mnt/storage/OwnProject/pentest-tool-python/security_audit_tool/app/checks/website_risk/parsers.py)
- [app/checks/website_risk/analyzer.py](/mnt/storage/OwnProject/pentest-tool-python/security_audit_tool/app/checks/website_risk/analyzer.py)
- [app/checks/website_risk/models.py](/mnt/storage/OwnProject/pentest-tool-python/security_audit_tool/app/checks/website_risk/models.py)

### Responsibilities

`website_risk_check.py`

- orchestrates target iteration
- performs fallback URL candidate selection
- converts analyzer output into standard findings

`fetcher.py`

- executes bounded HTTP GET requests
- normalizes headers, cookies, and response bodies
- limits body size

`parsers.py`

- parses HTML forms
- extracts mixed-content URLs

`analyzer.py`

- applies rule-based risk detection
- emits structured finding specs
- attaches OWASP metadata where relevant

### Current Passive Detection Coverage

The analyzer currently checks for:

- HTTPS downgrade
- missing browser security headers
- clickjacking protection gaps
- risky CSP directives
- permissive CORS
- server version disclosure
- insecure cookie flags
- risky forms and likely CSRF gaps
- mixed content
- missing cache-control on sensitive pages
- directory listing
- debug and stack-trace disclosure

## Active Web Testing

Active testing lives in:

- [app/checks/vulnerability_check.py](/mnt/storage/OwnProject/pentest-tool-python/security_audit_tool/app/checks/vulnerability_check.py)
- [app/checks/performance_check.py](/mnt/storage/OwnProject/pentest-tool-python/security_audit_tool/app/checks/performance_check.py)
- [app/checks/load_test_check.py](/mnt/storage/OwnProject/pentest-tool-python/security_audit_tool/app/checks/load_test_check.py)

### Vulnerability Check

Current active probes include:

- SQL injection indicators
- reflected XSS indicators
- path traversal indicators

This check is heuristic and intentionally lightweight. It is designed for bounded, explicit, opt-in testing rather than deep exploit automation.

### Performance Check

Measures latency and assigns severity based on response time thresholds.

### Load Test Check

Runs a bounded multi-request concurrency test and reports service stability under load.

## Collectors

The `collectors/` package contains lower-level data gathering helpers used by checks.

Examples:

- network inspection
- package inventory
- filesystem scanning
- process enumeration
- system information collection

Collectors should remain read-only and focused on data gathering, not policy decisions.

## Policy Layer

Policy helpers live in:

- [app/policy/severity.py](/mnt/storage/OwnProject/pentest-tool-python/security_audit_tool/app/policy/severity.py)
- [app/policy/mappings.py](/mnt/storage/OwnProject/pentest-tool-python/security_audit_tool/app/policy/mappings.py)

Current responsibilities:

- severity normalization and mapping
- CWE and CVSS helpers
- compliance reference mappings
- ANSI color and UI helpers for severity display

This layer is supportive rather than authoritative. It helps reporting and classification, but it is not a full compliance engine.

## Reporting

Reporting is split between orchestration and formatters.

### Orchestration

[app/core/reporting.py](/mnt/storage/OwnProject/pentest-tool-python/security_audit_tool/app/core/reporting.py)

- dispatches report generation
- applies output-path overrides

### Formatters

- [app/report/terminal_reporter.py](/mnt/storage/OwnProject/pentest-tool-python/security_audit_tool/app/report/terminal_reporter.py)
- [app/report/json_reporter.py](/mnt/storage/OwnProject/pentest-tool-python/security_audit_tool/app/report/json_reporter.py)
- [app/report/html_reporter.py](/mnt/storage/OwnProject/pentest-tool-python/security_audit_tool/app/report/html_reporter.py)
- [app/report/pdf_reporter.py](/mnt/storage/OwnProject/pentest-tool-python/security_audit_tool/app/report/pdf_reporter.py)

The TUI now also renders the final findings list directly on the completion screen after a run finishes.

## TUI Notes

The TUI in [app/tui.py](/mnt/storage/OwnProject/pentest-tool-python/security_audit_tool/app/tui.py) is responsible for:

- mode selection
- guided target entry
- custom check selection
- report options
- live scan telemetry
- final findings display

It relies on:

- `prompt_toolkit`
- `rich`

The scan completion path now preserves the latest `AuditSummary` inside the active TUI instance so users can see what was found immediately after the run.

## Logging

[app/logging_setup.py](/mnt/storage/OwnProject/pentest-tool-python/security_audit_tool/app/logging_setup.py) handles:

- structured logging
- console/file handler setup
- audit start/end logging
- severity-aware event rendering

## Safety Model

The project’s safety posture is enforced through several layers:

- explicit authorization confirmation
- explicit scope validation
- passive and active check separation
- mode-managed enablement
- bounded timeouts and concurrency
- non-destructive defaults

This is especially important for `vulnerability`, `performance`, and `load_test`.

## Extending the Project

### Add a New Check

1. Create a new module in `app/checks/`
2. Inherit from `BaseCheck`
3. Implement `run()`
4. Export the check in `app/checks/__init__.py`
5. Register it in `app/core/check_registry.py`
6. Add enablement wiring in `app/core/check_runner.py` and `app/core/scan_modes.py` if needed
7. Add tests

### Add a New Scan Mode

1. Add the enum value to `ScanMode`
2. Add a `ScanModeDefinition` entry
3. Update `apply_scan_mode()`
4. Update TUI target collection if the mode needs unique scope behavior
5. Add tests in `tests/test_scan_modes.py`

### Add a New Website Risk Rule

1. Add the rule function in `website_risk/analyzer.py`
2. Attach it in the analyzer rule sequence
3. Return a `WebsiteFindingSpec`
4. Add focused unit coverage in `tests/test_website_risk_check.py`

## Tests

The test suite currently covers key areas such as:

- base check behavior
- check runner progress events
- models and scope validation
- scan mode behavior
- website risk analysis
- TUI prompt and completion behavior

Important files:

- [tests/test_base_check.py](/mnt/storage/OwnProject/pentest-tool-python/security_audit_tool/tests/test_base_check.py)
- [tests/test_check_runner.py](/mnt/storage/OwnProject/pentest-tool-python/security_audit_tool/tests/test_check_runner.py)
- [tests/test_models.py](/mnt/storage/OwnProject/pentest-tool-python/security_audit_tool/tests/test_models.py)
- [tests/test_scope.py](/mnt/storage/OwnProject/pentest-tool-python/security_audit_tool/tests/test_scope.py)
- [tests/test_scan_modes.py](/mnt/storage/OwnProject/pentest-tool-python/security_audit_tool/tests/test_scan_modes.py)
- [tests/test_website_risk_check.py](/mnt/storage/OwnProject/pentest-tool-python/security_audit_tool/tests/test_website_risk_check.py)
- [tests/test_tui.py](/mnt/storage/OwnProject/pentest-tool-python/security_audit_tool/tests/test_tui.py)

## Operational Dependencies

Important runtime dependencies from `pyproject.toml`:

- `pyyaml`
- `fpdf2`
- `rich`
- `prompt_toolkit`

Important dev dependencies:

- `pytest`
- `pytest-cov`
- `mypy`
- `ruff`

Some local validation flows may fail if optional runtime packages are missing from the environment, even when source files compile successfully.

## Known Technical Constraints

- active vulnerability detection is heuristic and intentionally narrow
- report generation depends on optional runtime packages
- some dependency intelligence is static rather than continuously updated
- compliance mappings are helper references, not a full compliance workflow
- the project is Linux-oriented in several local host checks

## Recommended Next Technical Improvements

- add richer OWASP coverage reporting in JSON/HTML/TUI
- isolate active web-testing HTTP logic into a dedicated shared client
- expand vulnerability checks with safer endpoint discovery heuristics
- improve dependency intelligence with feed-backed data sources
- add more unit tests around reporting and workflow integration
