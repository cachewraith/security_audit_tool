"""Dependency vulnerability and configuration checks."""

from pathlib import Path

from .base import BaseCheck, CheckResult
from ..collectors.packages import PackageCollector
from ..models import SeverityLevel, ConfidenceLevel, Category


class DependenciesCheck(BaseCheck):
    """Check project dependencies for security issues."""
    
    check_id = "dependencies"
    check_name = "Dependency Security Check"
    category = Category.DEPENDENCIES
    
    # Known vulnerable package patterns (examples - would be updated with actual CVE data)
    KNOWN_VULNERABLE_PACKAGES = {
        # Format: "package_name": [("affected_versions", "cve_id", severity, "description")]
        "django": [
            ("<3.2.20", "CVE-2023-XXXX", SeverityLevel.HIGH, "Potential SQL injection vulnerability"),
            ("<4.2.5", "CVE-2023-YYYY", SeverityLevel.MEDIUM, "Cache poisoning vulnerability"),
        ],
        "flask": [
            ("<2.3.3", "CVE-2023-ZZZZ", SeverityLevel.MEDIUM, "Cookie security issue"),
        ],
        "requests": [
            ("<2.31.0", "CVE-2023-XXXX", SeverityLevel.MEDIUM, "Potential credential leak in redirect"),
        ],
        "urllib3": [
            ("<2.0.7", "CVE-2023-YYYY", SeverityLevel.MEDIUM, "Cookie security issue"),
        ],
        "pillow": [
            ("<10.0.1", "CVE-2023-ZZZZ", SeverityLevel.HIGH, "Buffer overflow in image processing"),
        ],
        "cryptography": [
            ("<41.0.3", "CVE-2023-AAAA", SeverityLevel.HIGH, "NULL pointer dereference"),
        ],
        "paramiko": [
            ("<3.3.1", "CVE-2023-BBBB", SeverityLevel.MEDIUM, "Host key verification bypass"),
        ],
    }
    
    # Packages with known security issues by default
    RISKY_PACKAGES = {
        "pycrypto": SeverityLevel.HIGH,
        "pycryptodome": SeverityLevel.LOW,  # Generally fine but worth noting
        "pickle": SeverityLevel.MEDIUM,  # Dangerous deserialization
        "yaml.load": SeverityLevel.MEDIUM,  # If used unsafely
        "eval": SeverityLevel.HIGH,
        "exec": SeverityLevel.HIGH,
        "input": SeverityLevel.LOW,  # In Python 2
        "subprocess.call": SeverityLevel.LOW,  # If shell=True
    }
    
    def run(self) -> CheckResult:
        """Execute dependency checks."""
        result = self._create_result()
        
        collector = PackageCollector()
        
        for project_path in self.scope.project_paths:
            try:
                inventories = collector.scan_project(project_path)
                
                for inventory in inventories:
                    self._check_inventory(inventory, result)
                    
            except Exception as e:
                self._log_error(f"Error scanning dependencies in {project_path}", e)
        
        return self._finish_result(result)
    
    def _check_inventory(self, inventory: "DependencyInventory", result: CheckResult) -> None:
        """Check a dependency inventory for issues."""
        for package in inventory.packages:
            # Check for known vulnerable packages
            self._check_known_vulnerabilities(package, result)
            
            # Check for risky packages
            self._check_risky_package(package, result)
            
            # Check for version pinning
            self._check_version_pinning(package, result)
    
    def _check_known_vulnerabilities(self, package: "PackageInfo", result: CheckResult) -> None:
        """Check if package version matches known vulnerable versions."""
        if package.name not in self.KNOWN_VULNERABLE_PACKAGES:
            return
        
        for affected_range, cve_id, severity, description in self.KNOWN_VULNERABLE_PACKAGES[package.name]:
            # Simple version check (would need proper semver comparison in production)
            if self._version_in_range(package.version, affected_range):
                finding = self._create_finding(
                    title=f"Known vulnerable dependency: {package.name}",
                    severity=severity,
                    target=f"{package.name}@{package.version}",
                    evidence=f"Package matches known vulnerability: {cve_id} - {description}",
                    remediation=f"Upgrade {package.name} to a version not affected by {cve_id}",
                    confidence=ConfidenceLevel.HIGH,
                    references=[
                        f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                        "https://pip.pypa.io/en/stable/cli/pip_install/",
                    ],
                    metadata={
                        "package": package.name,
                        "version": package.version,
                        "cve": cve_id,
                        "source": package.source,
                        "manager": package.manager,
                    },
                )
                result.findings.append(finding)
    
    def _check_risky_package(self, package: "PackageInfo", result: CheckResult) -> None:
        """Check if package is known to be risky."""
        if package.name in self.RISKY_PACKAGES:
            severity = self.RISKY_PACKAGES[package.name]
            
            finding = self._create_finding(
                title=f"Potentially risky dependency: {package.name}",
                severity=severity,
                target=f"{package.name}@{package.version}",
                evidence=f"Package '{package.name}' has known security considerations",
                remediation=f"Review usage of {package.name}; consider safer alternatives",
                confidence=ConfidenceLevel.MEDIUM,
                references=["https://owasp.org/www-project-dependency-check/"],
                metadata={
                    "package": package.name,
                    "version": package.version,
                    "manager": package.manager,
                },
            )
            result.findings.append(finding)
    
    def _check_version_pinning(self, package: "PackageInfo", result: CheckResult) -> None:
        """Check if dependencies are properly version-pinned."""
        # Only check pip requirements
        if package.manager not in ["pip", "poetry", "pipenv"]:
            return
        
        # Skip if version is already pinned
        if package.version not in ["unknown", "*", "latest"]:
            return
        
        # Check for unversioned/unpinned dependencies
        finding = self._create_finding(
            title=f"Unpinned dependency: {package.name}",
            severity=SeverityLevel.LOW,
            target=f"{package.name} (no version specified)",
            evidence=f"Package '{package.name}' has no version constraint specified",
            remediation=f"Pin dependency version: {package.name}==<version>",
            confidence=ConfidenceLevel.MEDIUM,
            references=[
                "https://pip.pypa.io/en/stable/topics/repeatable-installs/",
                "https://docs.python.org/3/tutorial/venv.html",
            ],
            metadata={
                "package": package.name,
                "manager": package.manager,
            },
        )
        result.findings.append(finding)
    
    def _version_in_range(self, version: str, range_spec: str) -> bool:
        """Check if version falls within a range spec.
        
        This is a simplified version - production code would use proper semver.
        """
        if version == "unknown":
            return False
        
        # Extract version numbers
        try:
            version_parts = self._parse_version(version)
        except Exception:
            return False
        
        range_spec = range_spec.strip()
        
        if range_spec.startswith("<"):
            # Less than
            spec_version = range_spec.lstrip("<=").strip()
            try:
                spec_parts = self._parse_version(spec_version)
                return version_parts < spec_parts
            except Exception:
                return False
        
        if range_spec.startswith(">"):
            # Greater than
            spec_version = range_spec.lstrip(">=").strip()
            try:
                spec_parts = self._parse_version(spec_version)
                return version_parts > spec_parts
            except Exception:
                return False
        
        # Default to checking equality
        return version in range_spec
    
    def _parse_version(self, version: str) -> tuple:
        """Parse a version string into a comparable tuple."""
        # Remove leading 'v' if present
        version = version.lstrip("vV")
        
        # Split by dots
        parts = version.split(".")
        
        # Convert to integers where possible
        result = []
        for part in parts:
            # Take just the numeric portion
            numeric = ""
            for char in part:
                if char.isdigit():
                    numeric += char
                else:
                    break
            
            if numeric:
                result.append(int(numeric))
            else:
                result.append(0)
        
        # Pad to at least 3 parts
        while len(result) < 3:
            result.append(0)
        
        return tuple(result)
    
    def _check_outdated_system_packages(self, result: CheckResult) -> None:
        """Check for outdated system packages (if local endpoint)."""
        if not self.scope.local_endpoint:
            return
        
        # This would integrate with the OS package manager
        # Placeholder for future implementation
        pass
    
    @classmethod
    def get_description(cls) -> str:
        return """
        Checks project dependencies for security issues:
        - Known vulnerable packages (based on CVE database)
        - Potentially risky packages
        - Unpinned/unversioned dependencies
        - Outdated system packages (when applicable)
        """
    
    @classmethod
    def get_requirements(cls) -> list[str]:
        return ["Read access to dependency manifest files (requirements.txt, package.json, etc.)"]
