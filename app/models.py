"""Data models for security audit findings and configuration."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional
from pathlib import Path
import uuid


class SeverityLevel(Enum):
    """Severity classification for findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ConfidenceLevel(Enum):
    """Confidence level for findings."""
    CERTAIN = "certain"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    TENTATIVE = "tentative"


class Category(Enum):
    """Category of security check."""
    PERMISSIONS = "permissions"
    SERVICES = "services"
    FIREWALL = "firewall"
    HARDENING = "hardening"
    SECRETS = "secrets"
    DEPENDENCIES = "dependencies"
    TLS = "tls"
    CONTAINERS = "containers"
    WEBAPP_CONFIG = "webapp_config"
    NETWORK = "network"
    APPLICATION = "application"


@dataclass
class Finding:
    """Represents a single security finding.
    
    Attributes:
        id: Unique identifier for the finding
        title: Human-readable title
        category: Category of the finding
        severity: Severity level
        confidence: Confidence level
        target: The target being assessed
        evidence: Description of what was found
        remediation: Recommended fix
        references: List of reference URLs or documentation
        timestamp: When the finding was created
        check_id: Identifier of the check that produced this finding
        metadata: Additional structured data about the finding
    """
    title: str
    category: Category
    severity: SeverityLevel
    confidence: ConfidenceLevel
    target: str
    evidence: str
    remediation: str
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    references: list[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.utcnow)
    check_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert finding to dictionary for serialization."""
        return {
            "id": self.id,
            "title": self.title,
            "category": self.category.value,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "target": self.target,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "references": self.references,
            "timestamp": self.timestamp.isoformat(),
            "check_id": self.check_id,
            "metadata": self.metadata,
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        """Create finding from dictionary."""
        return cls(
            id=data.get("id", str(uuid.uuid4())[:8]),
            title=data["title"],
            category=Category(data["category"]),
            severity=SeverityLevel(data["severity"]),
            confidence=ConfidenceLevel(data["confidence"]),
            target=data["target"],
            evidence=data["evidence"],
            remediation=data["remediation"],
            references=data.get("references", []),
            timestamp=datetime.fromisoformat(data["timestamp"]) if "timestamp" in data else datetime.utcnow(),
            check_id=data.get("check_id", ""),
            metadata=data.get("metadata", {}),
        )


@dataclass
class AuditSummary:
    """Summary of an audit run."""
    start_time: datetime
    end_time: Optional[datetime] = None
    target_count: int = 0
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    
    @property
    def duration_seconds(self) -> float:
        """Calculate audit duration in seconds."""
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0
    
    def count_by_severity(self) -> dict[SeverityLevel, int]:
        """Count findings by severity level."""
        counts = {level: 0 for level in SeverityLevel}
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts
    
    def count_by_category(self) -> dict[Category, int]:
        """Count findings by category."""
        counts = {cat: 0 for cat in Category}
        for finding in self.findings:
            counts[finding.category] += 1
        return counts
    
    def to_dict(self) -> dict[str, Any]:
        """Convert summary to dictionary."""
        return {
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": self.duration_seconds,
            "target_count": self.target_count,
            "findings_count": len(self.findings),
            "errors_count": len(self.errors),
            "severity_counts": {k.value: v for k, v in self.count_by_severity().items()},
            "category_counts": {k.value: v for k, v in self.count_by_category().items()},
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
        }


@dataclass
class Scope:
    """Defines the scope of an audit.
    
    Attributes:
        local_endpoint: Whether to audit the local system
        project_paths: List of project directories to audit
        allowed_hosts: List of allowed hostnames/IPs for network checks
        container_images: List of container images to check
        container_ids: List of running container IDs to check
        exclude_paths: Paths to exclude from filesystem checks
        max_depth: Maximum recursion depth for directory traversal
    """
    local_endpoint: bool = False
    project_paths: list[Path] = field(default_factory=list)
    allowed_hosts: list[str] = field(default_factory=list)
    container_images: list[str] = field(default_factory=list)
    container_ids: list[str] = field(default_factory=list)
    exclude_paths: list[str] = field(default_factory=list)
    max_depth: int = 10
    
    def is_empty(self) -> bool:
        """Check if scope is empty (no targets defined)."""
        return not any([
            self.local_endpoint,
            self.project_paths,
            self.allowed_hosts,
            self.container_images,
            self.container_ids,
        ])
    
    def validate(self) -> list[str]:
        """Validate scope configuration and return list of errors."""
        errors = []
        
        if self.is_empty():
            errors.append("Scope is empty: no targets defined")
        
        for path in self.project_paths:
            if not path.exists():
                errors.append(f"Project path does not exist: {path}")
            elif not path.is_dir():
                errors.append(f"Project path is not a directory: {path}")
        
        # Basic host validation
        for host in self.allowed_hosts:
            if not host or len(host) > 253:
                errors.append(f"Invalid host in scope: {host}")
        
        return errors
    
    def to_dict(self) -> dict[str, Any]:
        """Convert scope to dictionary."""
        return {
            "local_endpoint": self.local_endpoint,
            "project_paths": [str(p) for p in self.project_paths],
            "allowed_hosts": self.allowed_hosts,
            "container_images": self.container_images,
            "container_ids": self.container_ids,
            "exclude_paths": self.exclude_paths,
            "max_depth": self.max_depth,
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Scope":
        """Create scope from dictionary."""
        return cls(
            local_endpoint=data.get("local_endpoint", False),
            project_paths=[Path(p) for p in data.get("project_paths", [])],
            allowed_hosts=data.get("allowed_hosts", []),
            container_images=data.get("container_images", []),
            container_ids=data.get("container_ids", []),
            exclude_paths=data.get("exclude_paths", []),
            max_depth=data.get("max_depth", 10),
        )
