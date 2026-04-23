"""Unit tests for data models."""

import pytest
from datetime import datetime
from pathlib import Path

from app.models import (
    Finding,
    AuditSummary,
    Scope,
    SeverityLevel,
    ConfidenceLevel,
    Category,
)


class TestFinding:
    """Tests for the Finding model."""
    
    def test_finding_creation(self) -> None:
        """Test creating a basic finding."""
        finding = Finding(
            title="Test Finding",
            category=Category.HARDENING,
            severity=SeverityLevel.MEDIUM,
            confidence=ConfidenceLevel.HIGH,
            target="/etc/passwd",
            evidence="World-readable permissions",
            remediation="Set appropriate permissions",
        )
        
        assert finding.title == "Test Finding"
        assert finding.category == Category.HARDENING
        assert finding.severity == SeverityLevel.MEDIUM
        assert finding.target == "/etc/passwd"
        assert finding.id is not None  # Auto-generated
        assert finding.timestamp is not None  # Auto-generated
    
    def test_finding_to_dict(self) -> None:
        """Test converting finding to dictionary."""
        finding = Finding(
            title="Test Finding",
            category=Category.PERMISSIONS,
            severity=SeverityLevel.HIGH,
            confidence=ConfidenceLevel.CERTAIN,
            target="/sensitive/file",
            evidence="Evidence here",
            remediation="Fix it",
            references=["https://example.com"],
            check_id="permissions",
        )
        
        data = finding.to_dict()
        
        assert data["title"] == "Test Finding"
        assert data["category"] == "permissions"
        assert data["severity"] == "high"
        assert data["confidence"] == "certain"
        assert data["references"] == ["https://example.com"]
        assert "id" in data
        assert "timestamp" in data
    
    def test_finding_from_dict(self) -> None:
        """Test creating finding from dictionary."""
        data = {
            "id": "abc123",
            "title": "Test Finding",
            "category": "secrets",
            "severity": "critical",
            "confidence": "high",
            "target": "config.py",
            "evidence": "Hardcoded password",
            "remediation": "Use environment variable",
            "references": ["https://owasp.org"],
            "timestamp": "2024-01-01T12:00:00",
            "check_id": "secrets",
            "metadata": {"line": 42},
        }
        
        finding = Finding.from_dict(data)
        
        assert finding.id == "abc123"
        assert finding.title == "Test Finding"
        assert finding.category == Category.SECRETS
        assert finding.severity == SeverityLevel.CRITICAL
        assert finding.metadata["line"] == 42


class TestAuditSummary:
    """Tests for the AuditSummary model."""
    
    def test_summary_creation(self) -> None:
        """Test creating an audit summary."""
        summary = AuditSummary(
            start_time=datetime.utcnow(),
            target_count=5,
        )
        
        assert summary.start_time is not None
        assert summary.end_time is None
        assert summary.target_count == 5
        assert len(summary.findings) == 0
    
    def test_duration_calculation(self) -> None:
        """Test duration calculation."""
        start = datetime(2024, 1, 1, 12, 0, 0)
        end = datetime(2024, 1, 1, 12, 0, 30)
        
        summary = AuditSummary(
            start_time=start,
            end_time=end,
        )
        
        assert summary.duration_seconds == 30.0
    
    def test_count_by_severity(self) -> None:
        """Test counting findings by severity."""
        summary = AuditSummary(start_time=datetime.utcnow())
        
        summary.findings = [
            Finding("Critical 1", Category.HARDENING, SeverityLevel.CRITICAL, ConfidenceLevel.CERTAIN, "t1", "e1", "r1"),
            Finding("Critical 2", Category.HARDENING, SeverityLevel.CRITICAL, ConfidenceLevel.CERTAIN, "t2", "e2", "r2"),
            Finding("High 1", Category.HARDENING, SeverityLevel.HIGH, ConfidenceLevel.CERTAIN, "t3", "e3", "r3"),
            Finding("Medium 1", Category.HARDENING, SeverityLevel.MEDIUM, ConfidenceLevel.CERTAIN, "t4", "e4", "r4"),
        ]
        
        counts = summary.count_by_severity()
        
        assert counts[SeverityLevel.CRITICAL] == 2
        assert counts[SeverityLevel.HIGH] == 1
        assert counts[SeverityLevel.MEDIUM] == 1
        assert counts[SeverityLevel.LOW] == 0
    
    def test_count_by_category(self) -> None:
        """Test counting findings by category."""
        summary = AuditSummary(start_time=datetime.utcnow())
        
        summary.findings = [
            Finding("F1", Category.PERMISSIONS, SeverityLevel.MEDIUM, ConfidenceLevel.CERTAIN, "t1", "e1", "r1"),
            Finding("F2", Category.PERMISSIONS, SeverityLevel.MEDIUM, ConfidenceLevel.CERTAIN, "t2", "e2", "r2"),
            Finding("F3", Category.SECRETS, SeverityLevel.HIGH, ConfidenceLevel.CERTAIN, "t3", "e3", "r3"),
        ]
        
        counts = summary.count_by_category()
        
        assert counts[Category.PERMISSIONS] == 2
        assert counts[Category.SECRETS] == 1
        assert counts[Category.HARDENING] == 0


class TestScope:
    """Tests for the Scope model."""
    
    def test_empty_scope(self) -> None:
        """Test that empty scope is correctly identified."""
        scope = Scope()
        
        assert scope.is_empty() is True
        assert scope.validate() == ["Scope is empty: no targets defined"]
    
    def test_scope_with_local_endpoint(self) -> None:
        """Test scope with local endpoint."""
        scope = Scope(local_endpoint=True)
        
        assert scope.is_empty() is False
        assert scope.validate() == []
    
    def test_scope_with_paths(self) -> None:
        """Test scope with project paths."""
        scope = Scope(project_paths=[Path("/tmp")])
        
        assert scope.is_empty() is False
    
    def test_scope_with_hosts(self) -> None:
        """Test scope with allowed hosts."""
        scope = Scope(allowed_hosts=["127.0.0.1", "localhost"])
        
        assert scope.is_empty() is False
    
    def test_scope_serialization(self) -> None:
        """Test scope to/from dictionary."""
        scope = Scope(
            local_endpoint=True,
            project_paths=[Path("/home/user/project")],
            allowed_hosts=["127.0.0.1"],
            max_depth=5,
        )
        
        data = scope.to_dict()
        
        assert data["local_endpoint"] is True
        assert data["project_paths"] == ["/home/user/project"]
        assert data["allowed_hosts"] == ["127.0.0.1"]
        assert data["max_depth"] == 5
        
        # Test deserialization
        restored = Scope.from_dict(data)
        assert restored.local_endpoint is True
        assert len(restored.project_paths) == 1
        assert restored.max_depth == 5


class TestEnumerations:
    """Tests for enumeration classes."""
    
    def test_severity_level_order(self) -> None:
        """Test severity levels are ordered correctly."""
        assert SeverityLevel.INFO.value < SeverityLevel.LOW.value
        assert SeverityLevel.LOW.value < SeverityLevel.MEDIUM.value
        assert SeverityLevel.MEDIUM.value < SeverityLevel.HIGH.value
        assert SeverityLevel.HIGH.value < SeverityLevel.CRITICAL.value
    
    def test_category_values(self) -> None:
        """Test category values are unique."""
        values = [c.value for c in Category]
        assert len(values) == len(set(values))
    
    def test_confidence_levels(self) -> None:
        """Test confidence levels."""
        assert ConfidenceLevel.CERTAIN.value == "certain"
        assert ConfidenceLevel.TENTATIVE.value == "tentative"
