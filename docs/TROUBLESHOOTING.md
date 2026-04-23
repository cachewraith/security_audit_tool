# Security Audit Tool - Troubleshooting

## Common Issues

### Import Error: No module named 'app.utils.rate_limiter'

**Cause**: Missing rate_limiter.py file

**Fix**: 
```bash
# The file should exist at app/utils/rate_limiter.py
# If missing, reinstall the package:
rm -rf app/utils/__pycache__
pip install -e . --force-reinstall --no-deps
```

### Error: externally-managed-environment

**Cause**: System Python is managed by the OS

**Fix**:
```bash
# Use virtual environment
python -m venv venv
source venv/bin/activate
pip install -e .
```

### "No scope defined" Error

**Cause**: No target specified

**Fix**:
```bash
# Use at least one scope option:
security-audit --url https://example.com
security-audit --local
security-audit --path ./project
security-audit --host example.com
```

### Permission Denied Errors

**Cause**: Insufficient permissions for system checks

**Fix**:
```bash
# Run with appropriate permissions
sudo security-audit --local

# Or skip permission checks
security-audit --local --skip-checks permissions
```

### Connection Timeouts

**Cause**: Network checks taking too long

**Fix**:
```bash
# Increase timeout
security-audit --url https://example.com --connection-timeout 30

# Or reduce concurrent connections
security-audit --url https://example.com --max-concurrent 2
```

## Debug Mode

Enable verbose output for troubleshooting:

```bash
security-audit --url https://example.com --verbose
```

## Getting Help

```bash
# Show all options
security-audit --help

# List available checks
security-audit --list-checks

# Generate example scope file
security-audit --generate-scope-example
```

## Reporting Issues

When reporting issues, include:
1. Command you ran
2. Full error message
3. Python version: `python --version`
4. Tool version: `security-audit --version`
5. Operating system
