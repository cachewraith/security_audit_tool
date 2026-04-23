# How to Run Security Audit Tool

## Step 1: Setup (First Time Only)

### 1.1 Create Virtual Environment

```bash
python -m venv venv
```

### 1.2 Activate Virtual Environment

**Linux/Mac:**
```bash
source venv/bin/activate
```

**Windows:**
```bash
venv\Scripts\activate
```

### 1.3 Install the Tool

```bash
pip install -e .
```

> **Note**: If you get "externally-managed-environment" error, use the virtual environment method above.

---

## Step 2: Run the Tool (Custom Simple Command)

### Easy Way - Use the `audit` script (Recommended)

```bash
./audit --url https://example.com --full-scan
```

This uses the custom `audit` wrapper script that automatically calls the tool.

---

### Alternative Options (If you prefer)

#### Option A: Using venv path directly

```bash
venv/bin/security-audit --url https://example.com --full-scan
```

#### Option B: After activating venv

```bash
source venv/bin/activate
security-audit --url https://example.com --full-scan
```

#### Option C: Using Python module

```bash
venv/bin/python -m app.main --url https://example.com --full-scan
```

---

## Step 3: Common Commands (Using `./audit`)

### Scan a Website (Full Scan)

```bash
./audit --url https://hushstackcambodia.site --full-scan
```

This creates:
- `security_audit_YYYYMMDD_HHMMSS.json` - JSON report
- `security_audit_YYYYMMDD_HHMMSS.html` - HTML report

### Scan Local System

```bash
./audit --local --full-scan
```

### Scan a Project Directory

```bash
./audit --path ./my-project --full-scan
```

### Scan Multiple URLs

```bash
./audit --url https://site1.com --url https://site2.com --full-scan
```

### Simple Scan (No Reports)

```bash
./audit --url https://example.com --yes
```

---

## Step 4: View Results

### Terminal Output
Check the terminal for colorized output with findings.

### JSON Report
```bash
cat security_audit_20250423_183000.json
```

### HTML Report
Open in browser:
```bash
firefox security_audit_20250423_183000.html
# or
chrome security_audit_20250423_183000.html
```

---

## Quick Reference (Using `./audit`)

| Command | What it does |
|---------|-------------|
| `./audit --list-checks` | Show available checks |
| `./audit --url URL --full-scan` | Full scan with all reports |
| `./audit --url URL --pentest-mode --full-scan` | Full pentest (performance, vulnerability, load test) |
| `./audit --local --full-scan` | Scan local system |
| `./audit --path ./project --full-scan` | Scan directory |
| `./audit --help` | Show all options |

## Pentest Commands (Active Testing)

```bash
# Full pentest (includes performance, vulnerability, load tests)
./audit --url https://your-business.com --pentest-mode --full-scan

# Performance test only
./audit --url https://your-business.com --enable-performance-test

# Vulnerability scan only
./audit --url https://your-business.com --enable-vulnerability-scan

# Load test only (intensive)
./audit --url https://your-business.com --enable-load-test
```

**⚠️ Only use on your own systems!**

---

## Troubleshooting

### "command not found" error
Use `venv/bin/security-audit` instead of just `security-audit`

### Permission denied
Don't use `sudo` - the tool works without elevated permissions

### Import errors
Reinstall: `venv/bin/pip install -e . --force-reinstall --no-deps`

---

## Example Session

```bash
# 1. Go to project folder
cd /mnt/storage/OwnProject/pentest-tool-python/security_audit_tool

# 2. Run scan (simple command)
./audit --url https://hushstackcambodia.site --full-scan

# 3. View results
ls -la security_audit_*.html security_audit_*.json
```
