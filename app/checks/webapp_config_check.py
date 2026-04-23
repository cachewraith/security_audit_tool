"""Web application configuration security checks."""

import re
from pathlib import Path

from .base import BaseCheck, CheckResult
from ..models import SeverityLevel, ConfidenceLevel, Category


class WebAppConfigCheck(BaseCheck):
    """Check web application configuration for security issues."""
    
    check_id = "webapp_config"
    check_name = "Web Application Configuration"
    category = Category.WEBAPP_CONFIG
    
    # Dangerous configuration patterns by file type
    DANGEROUS_PATTERNS = {
        "python": {
            "debug_true": {
                "pattern": r'(?i)(debug\s*=\s*true|debug\s*=\s*1)',
                "severity": SeverityLevel.CRITICAL,
                "title": "Debug mode enabled in production configuration",
                "remediation": "Set DEBUG = False in production",
            },
            "secret_key_hardcoded": {
                "pattern": r'(?i)(secret_key\s*=\s*["\'][^"\']+["\'])',
                "severity": SeverityLevel.HIGH,
                "title": "Hardcoded SECRET_KEY detected",
                "remediation": "Use environment variable for SECRET_KEY: SECRET_KEY = os.environ.get('SECRET_KEY')",
            },
            "csrf_disabled": {
                "pattern": r'(?i)(csrf\s*=\s*false|csrf_enabled\s*=\s*false)',
                "severity": SeverityLevel.HIGH,
                "title": "CSRF protection disabled",
                "remediation": "Enable CSRF protection",
            },
            "cors_wildcard": {
                "pattern": r'(?i)(cors.*\*|access-control-allow-origin.*\*)',
                "severity": SeverityLevel.MEDIUM,
                "title": "Unsafe CORS configuration with wildcard",
                "remediation": "Specify explicit allowed origins instead of wildcard",
            },
        },
        "javascript": {
            "eval_usage": {
                "pattern": r'\beval\s*\(',
                "severity": SeverityLevel.MEDIUM,
                "title": "Dangerous eval() usage detected",
                "remediation": "Avoid eval(); use JSON.parse() for JSON data",
            },
            "inner_html": {
                "pattern": r'\binnerHTML\s*=',
                "severity": SeverityLevel.MEDIUM,
                "title": "Potential XSS via innerHTML assignment",
                "remediation": "Use textContent or sanitized HTML",
            },
            "document_write": {
                "pattern": r'\bdocument\.write\s*\(',
                "severity": SeverityLevel.LOW,
                "title": "document.write() usage detected",
                "remediation": "Avoid document.write(); use DOM manipulation methods",
            },
        },
        "php": {
            "display_errors": {
                "pattern": r'(?i)(display_errors\s*=\s*on|display_errors\s*=\s*1)',
                "severity": SeverityLevel.MEDIUM,
                "title": "PHP display_errors enabled",
                "remediation": "Set display_errors = Off in production",
            },
            "expose_php": {
                "pattern": r'(?i)(expose_php\s*=\s*on|expose_php\s*=\s*1)',
                "severity": SeverityLevel.LOW,
                "title": "PHP version exposure enabled",
                "remediation": "Set expose_php = Off",
            },
        },
    }
    
    # Configuration files to check
    CONFIG_FILES = {
        "*.py": "python",
        "settings.py": "python",
        "config.py": "python",
        "app.py": "python",
        "*.js": "javascript",
        "*.ts": "javascript",
        "*.php": "php",
        ".htaccess": "apache",
        "nginx.conf": "nginx",
        "php.ini": "php",
    }
    
    def run(self) -> CheckResult:
        """Execute web application configuration checks."""
        result = self._create_result()
        
        for project_path in self.scope.project_paths:
            self._scan_project_configs(project_path, result)
        
        return self._finish_result(result)
    
    def _scan_project_configs(self, project_path: Path, result: CheckResult) -> None:
        """Scan project for configuration files."""
        for file_path in project_path.rglob("*"):
            if not file_path.is_file():
                continue
            
            # Determine file type
            file_type = self._get_file_type(file_path)
            if not file_type:
                continue
            
            # Skip files that are too large
            try:
                if file_path.stat().st_size > 1024 * 1024:  # 1MB
                    continue
            except Exception:
                continue
            
            # Check the file
            self._check_config_file(file_path, file_type, result)
    
    def _get_file_type(self, file_path: Path) -> str:
        """Determine the type of configuration file."""
        filename = file_path.name.lower()
        
        # Check by exact name
        if filename in ["settings.py", "config.py", "app.py"]:
            return "python"
        
        if filename == ".htaccess":
            return "apache"
        
        if filename in ["nginx.conf", ".nginx.conf"]:
            return "nginx"
        
        if filename == "php.ini":
            return "php"
        
        # Check by extension
        suffix = file_path.suffix.lower()
        
        if suffix == ".py":
            return "python"
        
        if suffix in [".js", ".ts", ".jsx", ".tsx"]:
            return "javascript"
        
        if suffix == ".php":
            return "php"
        
        return ""
    
    def _check_config_file(self, file_path: Path, file_type: str, result: CheckResult) -> None:
        """Check a single configuration file."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            
            lines = content.split("\n")
            
            # Check dangerous patterns for this file type
            if file_type in self.DANGEROUS_PATTERNS:
                patterns = self.DANGEROUS_PATTERNS[file_type]
                
                for pattern_name, pattern_info in patterns.items():
                    for line_num, line in enumerate(lines, 1):
                        # Skip comments
                        stripped = line.strip()
                        if stripped.startswith("#") or stripped.startswith("//"):
                            continue
                        
                        matches = re.finditer(pattern_info["pattern"], line)
                        
                        for match in matches:
                            finding = self._create_finding(
                                title=pattern_info["title"],
                                severity=pattern_info["severity"],
                                target=str(file_path),
                                evidence=f"Line {line_num}: {line.strip()[:100]}",
                                remediation=pattern_info["remediation"],
                                confidence=ConfidenceLevel.HIGH,
                                references=[
                                    "https://owasp.org/www-project-top-ten/",
                                    "https://cheatsheetseries.owasp.org/",
                                ],
                                metadata={
                                    "file_type": file_type,
                                    "line": line_num,
                                    "pattern": pattern_name,
                                },
                            )
                            result.findings.append(finding)
                            break  # Only report first occurrence per pattern
            
            # Check cookie configuration in Python files
            if file_type == "python":
                self._check_cookie_config(file_path, content, lines, result)
            
            # Check session configuration
            if file_type == "python":
                self._check_session_config(file_path, content, lines, result)
            
            # Check for exposed admin interfaces
            self._check_admin_exposure(file_path, content, lines, result)
            
            # Check for open redirects
            if file_type in ["python", "javascript", "php"]:
                self._check_open_redirects(file_path, content, lines, result)
                
        except Exception as e:
            self._log_error(f"Error checking config file {file_path}", e)
    
    def _check_cookie_config(
        self,
        file_path: Path,
        content: str,
        lines: list[str],
        result: CheckResult,
    ) -> None:
        """Check cookie security configuration."""
        # Check for secure cookie flag
        if "SESSION_COOKIE_SECURE" in content or "CSRF_COOKIE_SECURE" in content:
            for line_num, line in enumerate(lines, 1):
                if "SESSION_COOKIE_SECURE = False" in line or "CSRF_COOKIE_SECURE = False" in line:
                    finding = self._create_finding(
                        title="Secure cookie flag is disabled",
                        severity=SeverityLevel.MEDIUM,
                        target=str(file_path),
                        evidence=f"Line {line_num}: {line.strip()}",
                        remediation="Set SESSION_COOKIE_SECURE = True and CSRF_COOKIE_SECURE = True",
                        confidence=ConfidenceLevel.CERTAIN,
                        references=["https://docs.djangoproject.com/en/stable/ref/settings/#session-cookie-secure"],
                        metadata={"line": line_num},
                    )
                    result.findings.append(finding)
        
        # Check for httponly cookie flag
        if "SESSION_COOKIE_HTTPONLY" in content:
            for line_num, line in enumerate(lines, 1):
                if "SESSION_COOKIE_HTTPONLY = False" in line:
                    finding = self._create_finding(
                        title="HttpOnly cookie flag is disabled",
                        severity=SeverityLevel.MEDIUM,
                        target=str(file_path),
                        evidence=f"Line {line_num}: {line.strip()}",
                        remediation="Set SESSION_COOKIE_HTTPONLY = True",
                        confidence=ConfidenceLevel.CERTAIN,
                        references=["https://docs.djangoproject.com/en/stable/ref/settings/#session-cookie-httponly"],
                        metadata={"line": line_num},
                    )
                    result.findings.append(finding)
        
        # Check for samesite cookie flag
        if "SESSION_COOKIE_SAMESITE" in content:
            for line_num, line in enumerate(lines, 1):
                if "SESSION_COOKIE_SAMESITE = 'None'" in line or 'SESSION_COOKIE_SAMESITE = "None"' in line:
                    finding = self._create_finding(
                        title="SameSite cookie set to None",
                        severity=SeverityLevel.MEDIUM,
                        target=str(file_path),
                        evidence=f"Line {line_num}: {line.strip()}",
                        remediation="Set SESSION_COOKIE_SAMESITE = 'Lax' or 'Strict' unless cross-site is required",
                        confidence=ConfidenceLevel.CERTAIN,
                        references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite"],
                        metadata={"line": line_num},
                    )
                    result.findings.append(finding)
    
    def _check_session_config(
        self,
        file_path: Path,
        content: str,
        lines: list[str],
        result: CheckResult,
    ) -> None:
        """Check session security configuration."""
        # Check session engine (should not be cache if sensitive)
        if "SESSION_ENGINE" in content:
            for line_num, line in enumerate(lines, 1):
                if "django.contrib.sessions.backends.cache" in line:
                    finding = self._create_finding(
                        title="Session backend uses cache only",
                        severity=SeverityLevel.LOW,
                        target=str(file_path),
                        evidence=f"Line {line_num}: {line.strip()}",
                        remediation="Consider using cached_db for session persistence",
                        confidence=ConfidenceLevel.TENTATIVE,
                        references=["https://docs.djangoproject.com/en/stable/topics/http/sessions/"],
                        metadata={"line": line_num},
                    )
                    result.findings.append(finding)
    
    def _check_admin_exposure(
        self,
        file_path: Path,
        content: str,
        lines: list[str],
        result: CheckResult,
    ) -> None:
        """Check for exposed admin interfaces."""
        # Check for Django admin URL without path restriction
        if "path('admin/'" in content or 'path("admin/"' in content:
            finding = self._create_finding(
                title="Django admin interface configured",
                severity=SeverityLevel.INFO,
                target=str(file_path),
                evidence="Django admin URL pattern detected",
                remediation="Ensure admin is protected by authentication and IP restrictions",
                confidence=ConfidenceLevel.MEDIUM,
                references=["https://docs.djangoproject.com/en/stable/ref/contrib/admin/"],
            )
            result.findings.append(finding)
    
    def _check_open_redirects(
        self,
        file_path: Path,
        content: str,
        lines: list[str],
        result: CheckResult,
    ) -> None:
        """Check for potential open redirect vulnerabilities."""
        # Python/Django patterns
        if file_path.suffix == ".py":
            redirect_patterns = [
                r'redirect\s*\(\s*request\.GET\.get\s*\(',
                r'HttpResponseRedirect\s*\(\s*request\.GET',
            ]
            
            for pattern in redirect_patterns:
                for line_num, line in enumerate(lines, 1):
                    if re.search(pattern, line):
                        finding = self._create_finding(
                            title="Potential open redirect vulnerability",
                            severity=SeverityLevel.MEDIUM,
                            target=str(file_path),
                            evidence=f"Line {line_num}: {line.strip()[:100]}",
                            remediation="Validate redirect URLs against an allowlist",
                            confidence=ConfidenceLevel.TENTATIVE,
                            references=["https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"],
                            metadata={"line": line_num},
                        )
                        result.findings.append(finding)
    
    @classmethod
    def get_description(cls) -> str:
        return """
        Checks web application configuration security:
        - Debug mode settings
        - Secret key storage
        - CSRF protection
        - CORS configuration
        - Cookie security flags (Secure, HttpOnly, SameSite)
        - Session configuration
        - Dangerous functions (eval, document.write)
        - Admin interface exposure
        - Open redirect patterns
        """
    
    @classmethod
    def get_requirements(cls) -> list[str]:
        return ["Read access to configuration files"]
