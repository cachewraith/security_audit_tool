"""Secret detection and credential scanning checks.

IMPORTANT: This module only performs PATTERN-BASED detection.
It does NOT extract, decrypt, or exfiltrate any actual secrets.
It only flags locations where secret patterns are detected.
"""

import re
from pathlib import Path

from .base import BaseCheck, CheckResult
from ..models import SeverityLevel, ConfidenceLevel, Category


class SecretsCheck(BaseCheck):
    """Check for hardcoded secrets and credential patterns.
    
    This check uses pattern-based detection ONLY. It does not:
    - Extract or decrypt actual secrets
    - Connect to external services to verify credentials
    - Store or transmit any detected patterns
    
    It only reports file locations where secret-like patterns are found.
    """
    
    check_id = "secrets"
    check_name = "Hardcoded Secrets Detection"
    category = Category.SECRETS
    
    # File patterns that commonly contain secrets
    SECRET_FILE_PATTERNS = [
        "*.env*",
        "*.config",
        "*.json",
        "*.yaml",
        "*.yml",
        "*.xml",
        "*.properties",
        "*.ini",
        "*.cfg",
        "*.conf",
        "*.tf",
        "*.tfvars",
        "*.hcl",
        "*.tfstate*",
        "*.pkr.hcl",
        "Dockerfile*",
        "docker-compose*",
        "*.sh",
        "*.py",
        "*.js",
        "*.ts",
        "*.java",
        "*.go",
        "*.rb",
        "*.php",
    ]
    
    # Files to skip
    SKIP_FILES = [
        "*.min.js",
        "*.bundle.js",
        "node_modules/",
        "vendor/",
        ".git/",
        "__pycache__/",
        "*.pyc",
        "*.sample",
        "*.example",
        ".env.sample",
        ".env.example",
        ".env.template",
    ]
    
    # Secret detection patterns (high entropy strings that look like secrets)
    PATTERNS = {
        "aws_access_key": {
            "pattern": r'AKIA[0-9A-Z]{16}',
            "severity": SeverityLevel.HIGH,
            "description": "AWS Access Key ID pattern detected",
        },
        "aws_secret_key": {
            "pattern": r'["\']?(aws_secret_access_key|aws_secret|secret_key)\s*[:=]\s*["\']?[a-zA-Z0-9/+=]{40}["\']?',
            "severity": SeverityLevel.CRITICAL,
            "description": "Potential AWS Secret Access Key",
        },
        "private_key": {
            "pattern": r'-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----',
            "severity": SeverityLevel.CRITICAL,
            "description": "Private key block detected",
        },
        "password_assignment": {
            "pattern": r'(?i)(password|passwd|pwd)\s*[:=]\s*["\'][^"\']{4,}["\']',
            "severity": SeverityLevel.MEDIUM,
            "description": "Password assignment detected",
        },
        "api_key_generic": {
            "pattern": r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\'][a-zA-Z0-9_\-]{16,}["\']',
            "severity": SeverityLevel.MEDIUM,
            "description": "Potential API key",
        },
        "secret_assignment": {
            "pattern": r'(?i)(secret|token|auth_token)\s*[:=]\s*["\'][a-zA-Z0-9_\-\/+=]{8,}["\']',
            "severity": SeverityLevel.MEDIUM,
            "description": "Secret/token assignment detected",
        },
        "github_token": {
            "pattern": r'gh[pousr]_[A-Za-z0-9_]{36,}',
            "severity": SeverityLevel.CRITICAL,
            "description": "GitHub token pattern detected",
        },
        "slack_token": {
            "pattern": r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*',
            "severity": SeverityLevel.CRITICAL,
            "description": "Slack token pattern detected",
        },
        "jwt_token": {
            "pattern": r'eyJ[A-Za-z0-9_\-/]*\.eyJ[A-Za-z0-9_\-/]*\.[A-Za-z0-9._\-/]*',
            "severity": SeverityLevel.MEDIUM,
            "description": "Potential JWT token",
        },
        "database_connection_string": {
            "pattern": r'(?i)(mongodb(\+srv)?|mysql|postgres(ql)?|redis)://[^\s"\']+',
            "severity": SeverityLevel.HIGH,
            "description": "Database connection string with potential credentials",
        },
        "basic_auth_in_url": {
            "pattern": r'https?://[^:]+:[^@]+@[^\s"\']+',
            "severity": SeverityLevel.HIGH,
            "description": "URL with embedded credentials",
        },
    }
    
    def run(self) -> CheckResult:
        """Execute secret detection checks."""
        result = self._create_result()
        
        # Check project paths
        for project_path in self.scope.project_paths:
            self._scan_directory(project_path, result)
        
        # Optionally check home directory if local endpoint enabled
        if self.scope.local_endpoint:
            home_dir = Path.home()
            # Only check common secret locations
            secret_locations = [
                home_dir / ".ssh",
                home_dir / ".aws",
                home_dir / ".docker",
            ]
            for location in secret_locations:
                if location.exists():
                    self._scan_directory(location, result)
        
        return self._finish_result(result)
    
    def _scan_directory(self, path: Path, result: CheckResult) -> None:
        """Scan a directory for secret patterns."""
        for file_path in path.rglob("*"):
            # Skip directories
            if not file_path.is_file():
                continue
            
            # Skip excluded patterns
            if self._should_skip(file_path):
                continue
            
            # Check file extension
            if not self._is_interesting_file(file_path):
                continue
            
            # Check file size
            try:
                if file_path.stat().st_size > 1024 * 1024:  # Skip files > 1MB
                    continue
            except Exception:
                continue
            
            self._scan_file(file_path, result)
    
    def _should_skip(self, path: Path) -> bool:
        """Check if a path should be skipped."""
        path_str = str(path)
        
        for skip_pattern in self.SKIP_FILES:
            if skip_pattern.endswith("/"):
                if skip_pattern.rstrip("/") in path.parts:
                    return True
            else:
                # Simple pattern matching
                if skip_pattern.startswith("*"):
                    ext = skip_pattern.lstrip("*")
                    if path_str.endswith(ext):
                        return True
                elif skip_pattern in path_str:
                    return True
        
        # Skip .env.example and similar template files
        filename = path.name.lower()
        if any(x in filename for x in [".example", ".sample", ".template", ".dist"]):
            return True
        
        return False
    
    def _is_interesting_file(self, path: Path) -> bool:
        """Check if file extension is interesting for secret scanning."""
        filename = path.name
        
        for pattern in self.SECRET_FILE_PATTERNS:
            if pattern.startswith("*"):
                if filename.endswith(pattern[1:]):
                    return True
            elif pattern in filename:
                return True
        
        # Special files
        if ".env" in filename:
            return True
        
        if filename in ["id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".netrc", ".htpasswd"]:
            return True
        
        return False
    
    def _scan_file(self, file_path: Path, result: CheckResult) -> None:
        """Scan a single file for secret patterns."""
        try:
            # Read file content
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            
            lines = content.split("\n")
            
            for pattern_name, pattern_info in self.PATTERNS.items():
                for line_num, line in enumerate(lines, 1):
                    # Skip comments (simplified)
                    stripped = line.strip()
                    if stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("*"):
                        continue
                    
                    # Search for pattern
                    matches = list(re.finditer(pattern_info["pattern"], line))
                    
                    for match in matches:
                        # Don't include the actual matched secret in output
                        # Just indicate a pattern was found
                        finding = self._create_finding(
                            title=pattern_info["description"],
                            severity=pattern_info["severity"],
                            target=str(file_path),
                            evidence=f"Pattern '{pattern_name}' detected at line {line_num} (content redacted for security)",
                            remediation="Remove hardcoded secrets; use environment variables or a secrets manager",
                            confidence=ConfidenceLevel.MEDIUM,
                            references=[
                                "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
                                "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
                            ],
                            metadata={
                                "pattern_type": pattern_name,
                                "line_number": line_num,
                                "file_size": len(content),
                            },
                        )
                        result.findings.append(finding)
                        
                        # Only report first occurrence per pattern per file
                        break
                        
        except Exception as e:
            self._log_error(f"Error scanning file {file_path}", e)
    
    @classmethod
    def get_description(cls) -> str:
        return """
        Pattern-based detection of hardcoded secrets:
        - AWS credentials
        - Private keys
        - Password assignments
        - API keys
        - Database connection strings
        - JWT tokens
        - GitHub/Slack tokens
        
        IMPORTANT: This check only uses pattern detection and NEVER:
        - Extracts actual secret values
        - Verifies credentials against services
        - Stores or transmits detected patterns
        """
    
    @classmethod
    def get_requirements(cls) -> list[str]:
        return ["Read access to target files"]
