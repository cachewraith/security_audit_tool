"""Severity classification and mapping utilities."""

from enum import Enum
from typing import Optional

from ..models import SeverityLevel


class Severity(Enum):
    """Extended severity classifications with numeric values."""
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1
    
    @property
    def level(self) -> SeverityLevel:
        """Map to standard SeverityLevel."""
        mapping = {
            Severity.CRITICAL: SeverityLevel.CRITICAL,
            Severity.HIGH: SeverityLevel.HIGH,
            Severity.MEDIUM: SeverityLevel.MEDIUM,
            Severity.LOW: SeverityLevel.LOW,
            Severity.INFO: SeverityLevel.INFO,
        }
        return mapping[self]
    
    @classmethod
    def from_string(cls, value: str) -> "Severity":
        """Create severity from string."""
        value = value.lower().strip()
        mapping = {
            "critical": cls.CRITICAL,
            "high": cls.HIGH,
            "medium": cls.MEDIUM,
            "low": cls.LOW,
            "info": cls.INFO,
            "informational": cls.INFO,
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
        if score >= 9.0:
            return cls.CRITICAL
        elif score >= 7.0:
            return cls.HIGH
        elif score >= 4.0:
            return cls.MEDIUM
        elif score > 0.0:
            return cls.LOW
        return cls.INFO
    
    def __str__(self) -> str:
        return self.name
    
    def __lt__(self, other: "Severity") -> bool:
        return self.value < other.value
    
    def __le__(self, other: "Severity") -> bool:
        return self.value <= other.value
    
    def __gt__(self, other: "Severity") -> bool:
        return self.value > other.value
    
    def __ge__(self, other: "Severity") -> bool:
        return self.value >= other.value


class SeverityMapper:
    """Maps various severity rating systems to standard severity levels."""
    
    # CWE severity mappings (simplified)
    CWE_SEVERITY = {
        # Injection
        "CWE-74": Severity.HIGH,      # Injection
        "CWE-78": Severity.CRITICAL, # OS Command Injection
        "CWE-79": Severity.HIGH,       # XSS
        "CWE-89": Severity.CRITICAL, # SQL Injection
        "CWE-91": Severity.HIGH,       # XML Injection
        
        # Cryptographic
        "CWE-310": Severity.HIGH,      # Cryptographic Issues
        "CWE-327": Severity.HIGH,      # Broken Crypto
        "CWE-330": Severity.MEDIUM,    # Insufficient Randomness
        
        # Authentication/Session
        "CWE-287": Severity.HIGH,      # Improper Authentication
        "CWE-306": Severity.CRITICAL,  # Missing Authentication
        "CWE-798": Severity.CRITICAL,  # Hardcoded Credentials
        
        # Authorization
        "CWE-284": Severity.HIGH,      # Improper Access Control
        "CWE-285": Severity.HIGH,      # Improper Authorization
        
        # Information Exposure
        "CWE-200": Severity.MEDIUM,    # Information Exposure
        "CWE-209": Severity.MEDIUM,    # Error Message Exposure
        "CWE-311": Severity.MEDIUM,    # Missing Encryption
        
        # Configuration
        "CWE-16": Severity.MEDIUM,     # Configuration
        "CWE-276": Severity.HIGH,      # Incorrect Default Permissions
        
        # Input Validation
        "CWE-20": Severity.MEDIUM,     # Input Validation
        "CWE-22": Severity.HIGH,       # Path Traversal
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
        return mapping.get(rating.lower(), Severity.INFO)
    
    @staticmethod
    def combine_severities(severities: list[Severity]) -> Severity:
        """Combine multiple severities, returning the highest."""
        if not severities:
            return Severity.INFO
        return max(severities)
    
    @staticmethod
    def downgrade_severity(
        severity: Severity, 
        confidence: Optional[str] = None,
        mitigations: Optional[list[str]] = None
    ) -> Severity:
        """Downgrade severity based on confidence and existing mitigations."""
        # Start with the base severity
        result = severity
        
        # Downgrade based on confidence
        if confidence == "low":
            if result == Severity.CRITICAL:
                result = Severity.HIGH
            elif result == Severity.HIGH:
                result = Severity.MEDIUM
        
        # Downgrade if mitigations exist
        if mitigations and len(mitigations) > 0:
            if result == Severity.CRITICAL:
                result = Severity.HIGH
            elif result == Severity.HIGH:
                result = Severity.MEDIUM
            elif result == Severity.MEDIUM:
                result = Severity.LOW
        
        return result


def get_severity_color(severity: SeverityLevel) -> str:
    """Get ANSI color code for severity level."""
    colors = {
        SeverityLevel.CRITICAL: "\033[91m",  # Bright red
        SeverityLevel.HIGH: "\033[31m",      # Red
        SeverityLevel.MEDIUM: "\033[33m",    # Yellow
        SeverityLevel.LOW: "\033[32m",       # Green
        SeverityLevel.INFO: "\033[36m",      # Cyan
    }
    return colors.get(severity, "\033[0m")


def get_severity_emoji(severity: SeverityLevel) -> str:
    """Get emoji representation of severity."""
    emojis = {
        SeverityLevel.CRITICAL: "🔴",
        SeverityLevel.HIGH: "🟠",
        SeverityLevel.MEDIUM: "🟡",
        SeverityLevel.LOW: "🟢",
        SeverityLevel.INFO: "🔵",
    }
    return emojis.get(severity, "⚪")
