# 🔒 Security Audit Tool

> **One command to audit your website, API, or server. Built for business owners who care about security.**

**Python security scanner with defensive checks + active pentest mode. Find vulnerabilities, test performance, and generate professional reports for your business.**

A Python-based security assessment tool that helps you identify vulnerabilities, performance issues, and security misconfigurations in your own systems. Perfect for business owners, developers, and DevOps teams who want to proactively secure their infrastructure.

## ⚠️ Legal Notice

**For authorized security testing only.** Use exclusively on:
- Systems you **own**
- Systems you have **explicit written permission** to test

Unauthorized scanning may violate laws. By using this tool, you confirm proper authorization.

---

## 🚀 What This Tool Does

This tool performs **two types** of security assessments:

### 1. Defensive/Read-Only Checks (Safe)
- Scan file permissions, services, firewall rules
- Detect hardcoded secrets in code
- Check TLS certificates, container configs
- Analyze dependencies for known vulnerabilities

### 2. Active/Pentest Checks (Sends Traffic)
- **Performance testing**: Measure response times
- **Vulnerability scanning**: Test for SQL injection, XSS
- **Load testing**: Simulate traffic to test capacity

---

## 💡 Perfect For

| Use Case | What You Get |
|----------|--------------|
| **Business Owner** | Know if your website has security holes |
| **Developer** | Find secrets in code before committing |
| **DevOps/SRE** | Test if your servers can handle traffic spikes |
| **Security Team** | Quick first-line vulnerability assessment |
| **Compliance** | Generate audit reports for security reviews |

---

## 🛠️ Quick Start (5 minutes)

### 1. Install

```bash
# Clone the repository
git clone https://github.com/yourusername/security-audit-tool.git
cd security-audit-tool

# Create virtual environment and install
python -m venv venv
venv/bin/pip install -e .
```

### 2. Run Your First Scan

```bash
# Simple command - full security audit
./audit --url https://your-website.com --full-scan
```

This creates:
- `security_audit_20250423_184904.html` - Professional HTML report
- `security_audit_20250423_184904.json` - Machine-readable JSON
- Terminal output with colorized findings

### 3. View Results

```bash
# Open the HTML report
firefox security_audit_*.html
```

---

## 📋 Common Commands

### Basic Scanning

```bash
# Scan any website
./audit --url https://example.com --full-scan

# Scan your local system
./audit --local --full-scan

# Scan a project directory
./audit --path ./my-project --full-scan

# Scan multiple websites
./audit --url https://api1.com --url https://api2.com --full-scan
```

### Pentest Mode (Active Testing)

```bash
# Full pentest with performance, vulnerability, and load tests
./audit --url https://your-business.com --pentest-mode --full-scan

# Just vulnerability scan (SQLi, XSS tests)
./audit --url https://your-api.com --enable-vulnerability-scan

# Performance test only
./audit --url https://your-api.com --enable-performance-test

# Load test (simulates traffic - use with caution!)
./audit --url https://your-api.com --enable-load-test
```

**⚠️ Pentest features send actual traffic to your target. Only use on your own systems.**

---

## 🔍 What Gets Checked

### By Default (Safe, Read-Only)
- ✅ File/directory permissions
- ✅ Running services and open ports
- ✅ Firewall configuration
- ✅ Hardcoded secrets in code
- ✅ Outdated dependencies with known CVEs
- ✅ Docker/container security
- ✅ Web application configuration

### With `--full-scan`
- ✅ Everything above, plus:
- ✅ TLS/SSL certificate validation
- ✅ Performance testing
- ✅ Vulnerability scanning (SQLi, XSS)

### With `--pentest-mode`
- ✅ Everything above, plus:
- ✅ Load testing / DDoS simulation

---

## 📊 Output Formats

| Format | File Extension | Use Case |
|--------|---------------|----------|
| **Terminal** | - | Quick review during development |
| **HTML** | `.html` | Share with team, management, compliance |
| **JSON** | `.json` | CI/CD integration, automation, archiving |

---

## 🏗️ For Developers (Architecture)

Want to extend the tool? Here's how it's structured:

```
app/
├── cli.py              # Command-line interface
├── main.py             # Entry point and orchestration
├── config.py           # Configuration management
├── scope.py            # Target validation and scoping
├── checks/             # Security test implementations
│   ├── base.py         # Base class for all checks
│   ├── permissions_check.py
│   ├── vulnerability_check.py  # SQLi, XSS tests
│   ├── performance_check.py
│   └── load_test_check.py      # DDoS simulation
├── collectors/         # Data gathering modules
├── report/             # Output generators (JSON, HTML, Terminal)
└── utils/              # Rate limiting, timeouts, validators
```

### Adding a New Check

1. Create `app/checks/my_check.py`
2. Inherit from `BaseCheck`
3. Implement `run()` method
4. Register in `app/checks/__init__.py`

```python
from .base import BaseCheck, CheckResult
from ..models import SeverityLevel

class MyCheck(BaseCheck):
    check_id = "my_check"
    check_name = "My Security Check"

    def run(self) -> CheckResult:
        result = self._create_result()
        # Your check logic here
        finding = self._create_finding(
            title="Example issue",
            severity=SeverityLevel.MEDIUM,
            target="example.com",
            evidence="Found issue X",
            remediation="Fix by doing Y"
        )
        result.findings.append(finding)
        return self._finish_result(result)
```

### Running Tests

```bash
# Install dev dependencies
venv/bin/pip install -e ".[dev]"

# Run tests
venv/bin/pytest

# Run with coverage
venv/bin/pytest --cov=app
```

---

## 📚 Documentation

| Document | What's Inside |
|----------|---------------|
| `docs/RUN.md` | How to install and run the tool |
| `docs/COMMANDS.md` | All available commands and examples |
| `docs/PENTEST.md` | Pentest mode guide for active testing |
| `docs/FEATURES.md` | Feature list and what each check does |
| `docs/ARCHITECTURE.md` | Code structure for developers |
| `docs/TROUBLESHOOTING.md` | Common issues and solutions |

---

## 🔐 Safety Features

1. **Explicit Scope Required** - Tool won't run without defined targets
2. **Authorization Prompt** - Legal confirmation required
3. **Rate Limiting** - Built-in request throttling
4. **Read-Only by Default** - No modifications to target systems
5. **Opt-in Active Tests** - Pentest features must be explicitly enabled
6. **Auditable** - All actions logged

---

## 📝 CI/CD Integration

```yaml
# .github/workflows/security.yml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Setup
        run: |
          python -m venv venv
          venv/bin/pip install -e .
      - name: Run Security Audit
        run: ./audit --url https://staging.your-app.com --full-scan
      - name: Upload Report
        uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: security_audit_*.html
```

---

## 🎯 Roadmap

- [ ] CIS Benchmark compliance checks
- [ ] SBOM generation (CycloneDX, SPDX)
- [ ] Kubernetes security scanning
- [ ] API endpoint fuzzing
- [ ] Compliance mapping (NIST, PCI-DSS, SOC2)

---

## 🤝 Contributing

Contributions welcome! Please ensure:
1. All checks are defensive and non-destructive by default
2. Code includes type hints
3. Tests included for new functionality
4. Documentation updated

---

## 📄 License

MIT License - See LICENSE file for details.

---

**Built with ❤️ for business owners who take security seriously.**

Got questions? Open an issue or check the `docs/` folder.
