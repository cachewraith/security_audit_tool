# Security Audit Tool Features

## Overview

Security Audit Tool is a defensive security scanner for authorized use. It supports:

- local host review
- project and codebase review
- website and API review
- container configuration review
- active web testing for approved targets
- multi-format reporting
- interactive TUI and CLI workflows

The tool is built around explicit scope, authorization confirmation, and mode-based check selection.

## Current Scan Modes

### Website Review

Passive website posture review for:

- TLS certificate and protocol inspection
- security header coverage
- cookie security flags
- CORS exposure
- form handling risks
- performance and latency review

### OWASP Top 10 Review

A stronger web-focused profile intended for real-world application risk discovery on approved targets.

Enabled by default:

- `tls`
- `website_risk`
- `vulnerability`
- `performance`

This mode combines passive posture analysis with active probes and maps findings to OWASP Top 10 categories where possible.

### API Review

API-oriented live HTTP review for:

- TLS posture
- website/API response hardening
- latency measurement
- staged, minimum-duration performance sampling with benign request variation

### Codebase Review

Project and repository checks for:

- hardcoded secrets
- dependency risk
- web application configuration issues
- container configuration files

### Host Hardening

Local endpoint review for:

- filesystem permissions
- exposed services
- firewall posture
- OS hardening settings
- mandatory access control status
- temporary mount hardening flags

### Container Review

Container-focused review for:

- Dockerfile security issues
- Compose misconfiguration
- running container privilege risks
- dangerous capabilities and runtime posture
- writable root filesystem, Docker socket, and PID limit checks
- mutable image tag hygiene

### Resilience Test

Active performance-focused mode for:

- multi-stage response time measurement
- bounded load testing with staged concurrency
- minimum-duration active checks, defaulting to 30 seconds
- randomized but benign request variation to better approximate real traffic

### Custom

Lets the operator choose a target family first, then select or trim checks manually.

## Check Catalog

### `permissions`

Reviews filesystem permission risks such as:

- world-writable files
- SUID and SGID binaries
- overly permissive sensitive files
- unsafe executable placement

### `services`

Reviews local listening services and exposed ports, including optional banner-based context.

### `firewall`

Checks firewall state and defensive posture across common Linux firewall tooling.

### `hardening`

Reviews hardening indicators such as:

- kernel security parameters
- update posture
- SSH settings
- password policy signals
- logging-related hardening
- mandatory access control state
- temporary mount protections

### `secrets`

Pattern-based source and file scanning for credentials and sensitive values. It is designed to detect likely secret exposure without trying to extract or abuse secrets.

### `dependencies`

Reviews dependency inventories for:

- known vulnerable packages
- risky packages
- hygiene issues around software composition

### `tls`

Live TLS inspection for allowed hosts, including:

- certificate expiration
- self-signed certificate detection
- deprecated TLS versions
- weak cipher indicators

### `containers`

Reviews container build and runtime security issues in files and local environments.

### `webapp_config`

Static project/config review for application security issues such as:

- debug mode
- unsafe secret handling
- weak CORS settings
- disabled CSRF protections
- open redirect patterns

### `website_risk`

Passive live website review for common real-world web exposure signals, including:

- missing security headers
- HTTPS downgrade to HTTP
- clickjacking gaps
- risky CSP directives
- permissive CORS
- server banner disclosure
- insecure session cookie flags
- risky forms and likely CSRF gaps
- mixed content on HTTPS pages
- weak cache behavior on sensitive pages
- directory listing indicators
- debug and stack-trace disclosure

### `performance`

Measures target responsiveness using staged latency sampling, percentile metrics, and longer-running benign traffic profiles.

### `load_test`

Runs bounded concurrent request simulations for resilience review. This is opt-in, stage-based, and intentionally separated from passive review modes.

### `vulnerability`

Active application probes for approved targets, currently including:

- SQL injection indicators
- reflected XSS indicators
- path traversal indicators

These checks are intentionally limited and do not attempt post-exploitation behavior.

## OWASP Top 10 Alignment

The project now includes an `OWASP Top 10 Review` mode and attaches OWASP metadata to relevant web findings where the mapping is clear. Current mappings mainly cover:

- `A01:2021-Broken Access Control`
- `A02:2021-Cryptographic Failures`
- `A03:2021-Injection`
- `A05:2021-Security Misconfiguration`
- `A07:2021-Identification and Authentication Failures`
- `A09:2021-Security Logging and Monitoring Failures`

This alignment is useful for reporting and triage, but it is not a guarantee of complete OWASP coverage.

## Interactive Workspace Features

The TUI provides:

- guided mode selection
- target-specific scope collection
- optional custom check selection
- live scan progress with current check and activity stream
- post-scan completion screen with findings list
- repeat-scan workflow inside the same workspace

## Reporting

### Terminal

- live progress workspace
- severity-aware output
- post-scan findings list in the TUI

### JSON

- machine-readable structured findings
- metadata and check identifiers
- suitable for automation and downstream processing

### HTML

- human-readable report with categorized findings
- severity grouping and visual summaries
- per-check execution summary with durations and stage notes

### PDF

- portable report output for review and sharing

## Safety and Scope Controls

The project is designed around controlled operation:

- explicit scope is required
- authorization confirmation is required
- passive and active checks are separated
- active checks are opt-in or mode-managed
- target allowlists are enforced through scope
- rate limits, timeouts, and bounded concurrency are configurable
- active resilience checks use randomized benign traffic only and do not implement rate-limit bypass or CAPTCHA evasion

## Performance and Maintainability Improvements Already Present

Recent project structure now includes:

- scan-mode based configuration in `app/core/scan_modes.py`
- shared check orchestration in `app/core/check_runner.py`
- dedicated workflow orchestration in `app/core/workflow.py`
- refactored website risk analysis package in `app/checks/website_risk/`
- reusable severity and policy helpers in `app/policy/`
- centralized models for findings, scope, and summaries

## Current Limitations

The project can surface many meaningful issues, but it does not guarantee discovery of all real-world risk. In particular:

- active web probes are intentionally limited
- vulnerability checks rely on lightweight heuristics
- some dependency intelligence is static rather than feed-driven
- compliance mappings are helper references, not a certification engine
- several optional runtime dependencies are required for the full UX and reporting stack

## Best Fit

This tool is a strong fit for:

- first-pass security reviews
- developer and DevOps self-audits
- OWASP-oriented website checks on approved targets
- codebase hygiene checks before release
- repeatable internal security baselines
