# Security Audit Tool - Commands

## Quick Start

```bash
# Simple one-command full scan
security-audit --url https://example.com --full-scan

# Audit a website
security-audit --url https://example.com

# Audit a website with TLS checks
security-audit --url https://example.com --enable-tls-checks

# Audit local system
security-audit --local

# Audit a project directory
security-audit --path ./my-project

# Manual full audit with reports
security-audit --url https://api.example.com \
  --report-json results.json \
  --report-html report.html \
  --yes
```

## Full Scan (One Command)

Use `--full-scan` to enable all checks and auto-generate reports:

```bash
# Scan URL with everything enabled
security-audit --url https://example.com --full-scan

# Scan local system
security-audit --local --full-scan

# Scan project directory
security-audit --path ./my-project --full-scan

# Scan multiple URLs
security-audit --url https://api1.com --url https://api2.com --full-scan
```

**What `--full-scan` enables:**
- ✅ TLS/SSL certificate checks
- ✅ Service banner grabbing
- ✅ Performance testing
- ✅ Vulnerability scanning (SQLi, XSS)
- ✅ Verbose output
- ✅ Auto-generated JSON report (`security_audit_YYYYMMDD_HHMMSS.json`)
- ✅ Auto-generated HTML report (`security_audit_YYYYMMDD_HHMMSS.html`)
- ✅ Skip authorization prompt (still requires proper authorization)

## Pentest Mode (Active Testing)

**⚠️ Warning**: These tests send actual traffic to your target. Use only on systems you own or have explicit written permission to test.

```bash
# Full pentest mode (includes load testing)
./audit --url https://example.com --pentest-mode --full-scan

# Individual active tests
./audit --url https://example.com --enable-performance-test
./audit --url https://example.com --enable-vulnerability-scan
./audit --url https://example.com --enable-load-test  # Intensive!
```

**Pentest features:**
- **Performance test**: Measures response times, detects slow endpoints
- **Vulnerability scan**: Tests for SQL injection, XSS, path traversal
- **Load test**: Simulates multiple concurrent users (controlled DDoS test)

## Available Commands

### URL Auditing

| Command | Description |
|---------|-------------|
| `security-audit --url URL` | Audit a specific URL |
| `security-audit --url URL1 --url URL2` | Audit multiple URLs |
| `security-audit --url https://api.example.com --enable-tls-checks` | Audit with TLS checks |

### Local System Auditing

| Command | Description |
|---------|-------------|
| `security-audit --local` | Audit local system |
| `security-audit --local --verbose` | Audit with verbose output |

### Directory Auditing

| Command | Description |
|---------|-------------|
| `security-audit --path ./project` | Audit a directory |
| `security-audit --path ./app1 --path ./app2` | Audit multiple directories |

### Host Auditing

| Command | Description |
|---------|-------------|
| `security-audit --host example.com` | Audit a host |
| `security-audit --hosts hosts.txt` | Audit hosts from file |

### Report Generation

| Command | Description |
|---------|-------------|
| `--report-json output.json` | Save JSON report |
| `--report-html output.html` | Save HTML report |
| `--report-json out.json --report-html out.html` | Generate both reports |

### Other Options

| Flag | Description |
|------|-------------|
| `--yes` | Skip authorization prompt |
| `--verbose`, `-v` | Show detailed output |
| `--quiet`, `-q` | Suppress non-error output |
| `--list-checks` | List available checks |
| `--help` | Show help message |

## Examples by Use Case

### API Security Scan
```bash
security-audit --url https://api.myservice.com \
  --enable-tls-checks \
  --enable-banner-grabbing \
  --report-json api-scan.json
```

### Website Security Check
```bash
security-audit --url https://www.example.com \
  --enable-tls-checks \
  --report-html website-report.html \
  --yes
```

### Local Development Check
```bash
security-audit --local --path ./src --verbose
```

### CI/CD Integration
```bash
security-audit --url https://staging.example.com \
  --report-json security-report.json \
  --yes || echo "Security issues found"
```
