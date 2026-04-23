# Security Audit Tool - Architecture

## Project Structure

```
security_audit_tool/
├── app/                      # Main application code
│   ├── __init__.py
│   ├── main.py              # Entry point
│   ├── cli.py               # CLI argument parsing
│   ├── config.py            # Configuration management
│   ├── scope.py             # Scope validation
│   ├── logging_setup.py     # Logging configuration
│   ├── models.py            # Data models
│   ├── checks/              # Security checks
│   │   ├── base.py          # Base check class
│   │   ├── permissions_check.py
│   │   ├── services_check.py
│   │   ├── firewall_check.py
│   │   ├── hardening_check.py
│   │   ├── secrets_check.py
│   │   ├── dependencies_check.py
│   │   ├── tls_check.py
│   │   ├── containers_check.py
│   │   └── webapp_config_check.py
│   ├── collectors/          # Data collection
│   │   ├── system_info.py
│   │   ├── filesystem.py
│   │   ├── network.py
│   │   ├── packages.py
│   │   └── processes.py
│   ├── report/              # Output generators
│   │   ├── json_reporter.py
│   │   ├── html_reporter.py
│   │   └── terminal_reporter.py
│   ├── policy/              # Compliance mappings
│   │   ├── severity.py
│   │   └── mappings.py
│   └── utils/               # Utilities
│       ├── subprocess_safe.py
│       ├── validators.py
│       ├── timeouts.py
│       └── rate_limiter.py
├── tests/                   # Unit tests
├── docs/                    # Documentation
├── examples/                # Example files
├── README.md
└── pyproject.toml
```

## Key Components

### CLI (`app/cli.py`)
- Argument parsing with argparse
- Validation of scope and options
- Help text and examples

### Scope Management (`app/scope.py`)
- Defines what targets are allowed
- Validates scope configuration
- Supports URLs, hosts, paths, local endpoints

### Checks (`app/checks/`)
Each check inherits from `BaseCheck`:
- `check_id`: Unique identifier
- `check_name`: Human-readable name
- `category`: Type of check
- `run()`: Execute the check

### Collectors (`app/collectors/`)
- Gather system information safely
- Read-only operations only
- No system modifications

### Reporters (`app/report/`)
- Generate output in multiple formats
- JSON for automation
- HTML for human review
- Terminal for CLI display

## Data Flow

```
CLI Args → Config → Scope → Checks → Findings → Reports
              ↓         ↓        ↓
           Logger    Valid    Results
```

1. Parse CLI arguments
2. Build configuration
3. Define and validate scope
4. Run selected checks
5. Collect findings
6. Generate reports

## Adding a New Check

1. Create file in `app/checks/`
2. Inherit from `BaseCheck`
3. Implement `run()` method
4. Register in `app/checks/__init__.py`

Example:

```python
from .base import BaseCheck, CheckResult
from ..models import SeverityLevel, Category

class MyCheck(BaseCheck):
    check_id = "my_check"
    check_name = "My Security Check"
    category = Category.HARDENING

    def run(self) -> CheckResult:
        result = self._create_result()
        # ... perform checks ...
        return self._finish_result(result)
```
