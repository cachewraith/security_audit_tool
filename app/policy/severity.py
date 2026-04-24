"""Severity classification and mapping utilities."""

from enum import IntEnum
from typing import Optional

from ..models import SeverityLevel

SEVERITY_LEVEL_MAP = {
    "critical": SeverityLevel.CRITICAL,
    "high": SeverityLevel.HIGH,
    "medium": SeverityLevel.MEDIUM,
    "low": SeverityLevel.LOW,
    "info": SeverityLevel.INFO,
}
SEVERITY_ALIASES = {
    "informational": "info",
}
CVSS_THRESHOLDS = (
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (0.1, "low"),
)
SEVERITY_COLORS = {
    SeverityLevel.CRITICAL: "\033[91m",
    SeverityLevel.HIGH: "\033[31m",
    SeverityLevel.MEDIUM: "\033[33m",
    SeverityLevel.LOW: "\033[32m",
    SeverityLevel.INFO: "\033[36m",
}
SEVERITY_EMOJIS = {
    SeverityLevel.CRITICAL: "🔴",
    SeverityLevel.HIGH: "🟠",
    SeverityLevel.MEDIUM: "🟡",
    SeverityLevel.LOW: "🟢",
    SeverityLevel.INFO: "🔵",
}


class Severity(IntEnum):
    """Extended severity classifications with numeric values."""

    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1

    @property
    def level(self) -> SeverityLevel:
        """Map to standard SeverityLevel."""
        return SEVERITY_LEVEL_MAP[self.name.lower()]

    @classmethod
    def from_string(cls, value: str) -> "Severity":
        """Create severity from string."""
        normalized = value.lower().strip()
        value = SEVERITY_ALIASES.get(normalized, normalized)
        mapping = {
            "critical": cls.CRITICAL,
            "high": cls.HIGH,
            "medium": cls.MEDIUM,
            "low": cls.LOW,
            "info": cls.INFO,
        }
        return mapping.get(value, cls.INFO)

    @classmethod
    def from_cvss(cls, score: float) -> "Severity":
        """Map CVSS score to severity.

        CVSS v3.1 rating scale:
        - 0.0: None
        - 0.1-3.9: Low
        - 4.0-6.9: Medium
        - 7.0-8.9: High
        - 9.0-10.0: Critical
        """
        for threshold, name in CVSS_THRESHOLDS:
            if score >= threshold:
                return cls[name.upper()]
        return cls.INFO

    def __str__(self) -> str:
        return self.name


class SeverityMapper:
    """Maps various severity rating systems to standard severity levels."""

    # CWE severity mappings (simplified)
    CWE_SEVERITY = {
        # Injection
        "CWE-74": Severity.HIGH,  # Injection
        "CWE-78": Severity.CRITICAL, # OS Command Injection
        "CWE-79": Severity.HIGH,  # XSS
        "CWE-89": Severity.CRITICAL, # SQL Injection
        "CWE-91": Severity.HIGH,  # XML Injection

        # Cryptographic
        "CWE-310": Severity.HIGH,  # Cryptographic Issues
        "CWE-327": Severity.HIGH,  # Broken Crypto
        "CWE-330": Severity.MEDIUM,  # Insufficient Randomness

        # Authentication/Session
        "CWE-287": Severity.HIGH,  # Improper Authentication
        "CWE-306": Severity.CRITICAL,  # Missing Authentication
        "CWE-798": Severity.CRITICAL,  # Hardcoded Credentials

        # Authorization
        "CWE-284": Severity.HIGH,  # Improper Access Control
        "CWE-285": Severity.HIGH,  # Improper Authorization

        # Information Exposure
        "CWE-200": Severity.MEDIUM,  # Information Exposure
        "CWE-209": Severity.MEDIUM,  # Error Message Exposure
        "CWE-311": Severity.MEDIUM,  # Missing Encryption

        # Configuration
        "CWE-16": Severity.MEDIUM,  # Configuration
        "CWE-276": Severity.HIGH,  # Incorrect Default Permissions

        # Input Validation
        "CWE-20": Severity.MEDIUM,  # Input Validation
        "CWE-22": Severity.HIGH,  # Path Traversal
    }

    @classmethod
    def from_cwe(cls, cwe_id: str) -> Severity:
        """Get severity from CWE identifier."""
        return cls.CWE_SEVERITY.get(cwe_id, Severity.MEDIUM)

    @classmethod
    def from_cve_score(cls, score: float) -> Severity:
        """Map CVE/CVSS score to severity."""
        return Severity.from_cvss(score)

    @classmethod
    def from_nist_rating(cls, rating: str) -> Severity:
        """Map NIST 800-53 control impact ratings."""
        mapping = {
            "high": Severity.HIGH,
            "moderate": Severity.MEDIUM,
            "low": Severity.LOW,
        }
        return mapping.get(rating.lower().strip(), Severity.INFO)

    @staticmethod
    def combine_severities(severities: list[Severity]) -> Severity:
        """Combine multiple severities, returning the highest."""
        return max(severities, default=Severity.INFO)

    @staticmethod
    def downgrade_severity(
        severity: Severity,
        confidence: Optional[str] = None,
        mitigations: Optional[list[str]] = None,
    ) -> Severity:
        """Downgrade severity based on confidence and existing mitigations."""
        result = severity

        if confidence == "low":
            result = SeverityMapper._downgrade_once(result)

        if mitigations:
            result = SeverityMapper._downgrade_once(result)

        return result

    @staticmethod
    def _downgrade_once(severity: Severity) -> Severity:
        """Downgrade a severity level by a single step."""
        downgrade_map = {
            Severity.CRITICAL: Severity.HIGH,
            Severity.HIGH: Severity.MEDIUM,
            Severity.MEDIUM: Severity.LOW,
        }
        return downgrade_map.get(severity, severity)


def get_severity_color(severity: SeverityLevel) -> str:
    """Get ANSI color code for severity level."""
    return SEVERITY_COLORS.get(severity, "\033[0m")


def get_severity_emoji(severity: SeverityLevel) -> str:
    """Get emoji representation of severity."""
    return SEVERITY_EMOJIS.get(severity, "⚪")
