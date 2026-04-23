# Security Audit Tool - Features

## Overview

A defensive security assessment tool designed for authorized security testing on systems you own or have explicit permission to test.

## Security Checks

### 1. Permissions Check
- World-writable files detection
- SUID/SGID binary identification
- Overly permissive sensitive files
- Executable files in upload directories

### 2. Services Check
- Running service enumeration
- Listening port discovery
- Unencrypted protocol detection
- Optional banner grabbing

### 3. Firewall Check
- Firewall status verification (iptables/firewalld/ufw)
- Default-deny policy validation
- Connection tracking rules

### 4. Hardening Check
- Kernel security parameters (ASLR, pointer hiding)
- Automatic security updates status
- Security logging configuration
- SSH security settings
- Password policy enforcement

### 5. Secrets Check
- AWS credential pattern detection
- Private key block detection
- Password assignment patterns
- API key patterns
- Database connection string detection

**Note**: Pattern-based only - never extracts actual secret values

### 6. Dependencies Check
- Known vulnerable package detection (CVE-based)
- Version pinning verification
- Risky package identification

### 7. TLS Check (Opt-in)
- Certificate expiration check
- Weak protocol detection (TLS 1.0/1.1)
- Weak cipher suite detection
- Self-signed certificate identification

### 8. Containers Check
- Dockerfile best practices
- Docker Compose security
- Running container privilege detection
- Dangerous capability detection

### 9. WebApp Config Check
- Debug mode settings
- Secret key storage patterns
- CSRF protection check
- CORS configuration review
- Cookie security flags

### 10. Performance Test (Active/Pentest)
- Response time measurement
- Multiple request averaging
- Slow endpoint detection
- Server stability check

### 11. Load Test (Active/Pentest)
- Concurrent user simulation
- DDoS capacity testing
- Success rate measurement
- Performance under load

### 12. Vulnerability Scan (Active/Pentest)
- SQL Injection detection
- XSS (Cross-Site Scripting) testing
- Path traversal testing
- Input validation checking

## Output Formats

### Terminal
- Colorized console output
- Severity grouping (Critical → High → Medium → Low → Info)
- Summary statistics

### JSON
- Machine-readable format
- Structured findings with metadata
- CI/CD integration ready

### HTML
- Human-readable reports
- Detailed remediation guidance
- Professional formatting

## Safety Features

1. **Explicit Scope Required**: Tool refuses to run without defined scope
2. **Authorization Confirmation**: Legal warning and confirmation prompt
3. **Read-Only Checks**: No modification of target systems
4. **No Exploitation**: No exploit delivery, payloads, or brute force
5. **Rate Limiting**: Configurable concurrency and timeout limits
6. **Allowlist-Based**: Only scans explicitly approved targets
7. **Auditable**: All actions are logged

## Rate Limiting

- `--max-concurrent N`: Maximum concurrent connections (default: 5)
- `--connection-timeout S`: Connection timeout in seconds (default: 5.0)
- Built-in rate limiter for network requests

## Future Features

### Planned
- CIS Benchmark support (Ubuntu, RHEL, Docker, Kubernetes)
- SBOM generation (CycloneDX, SPDX)
- Compliance mapping (NIST 800-53, PCI DSS, HIPAA, SOC 2, ISO 27001)
- SELinux/AppArmor status checks
- Audit log configuration review
- File integrity monitoring detection
