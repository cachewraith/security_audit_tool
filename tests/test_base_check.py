"""Unit tests for the base check class."""

import pytest
from datetime import datetime
from pathlib import Path

from app.checks.base import BaseCheck, CheckResult
from app.models import (
    Scope,
    Config,
    Category,
    SeverityLevel,
    ConfidenceLevel,
    Finding,
)


class MockCheck(BaseCheck):
    """Mock check for testing."""
    
    check_id = "mock_check"
    check_name = "Mock Security Check"
    category = Category.HARDENING
    
    def run(self) -> CheckResult:
        result = self._create_result()
        
        # Add a test finding
        finding = self._create_finding(
            title="Test Finding",
            severity=SeverityLevel.MEDIUM,
            target="/test/path",
            evidence="Test evidence",
            remediation="Fix it",
        )
        result.findings.append(finding)
        
        return self._finish_result(result)


class TestBaseCheck:
    """Tests for BaseCheck class."""
    
    def test_check_creation(self) -> None:
        """Test creating a check instance."""
        scope = Scope(local_endpoint=True)
        config = Config()
        
        check = MockCheck(scope, config)
        
        assert check.check_id == "mock_check"
        assert check.check_name == "Mock Security Check"
        assert check.category == Category.HARDENING
    
    def test_run_returns_result(self) -> None:
        """Test that run() returns a CheckResult."""
        scope = Scope(local_endpoint=True)
        config = Config()
        check = MockCheck(scope, config)
        
        result = check.run()
        
        assert isinstance(result, CheckResult)
        assert result.check_id == "mock_check"
        assert result.passed is False  # Has findings
    
    def test_create_finding(self) -> None:
        """Test creating a finding."""
        scope = Scope(local_endpoint=True)
        config = Config()
        check = MockCheck(scope, config)
        
        finding = check._create_finding(
            title="Test",
            severity=SeverityLevel.HIGH,
            target="target",
            evidence="evidence",
            remediation="fix",
            confidence=ConfidenceLevel.CERTAIN,
            references=["https://example.com"],
            metadata={"key": "value"},
        )
        
        assert finding.title == "Test"
        assert finding.severity == SeverityLevel.HIGH
        assert finding.confidence == ConfidenceLevel.CERTAIN
        assert finding.check_id == "mock_check"
        assert finding.references == ["https://example.com"]
        assert finding.metadata == {"key": "value"}
    
    def test_create_result_initializes_timing(self) -> None:
        """Test that create_result initializes timing."""
        scope = Scope(local_endpoint=True)
        config = Config()
        check = MockCheck(scope, config)
        
        result = check._create_result()
        
        assert result.start_time is not None
        assert result.end_time is None
    
    def test_finish_result_sets_end_time(self) -> None:
        """Test that finish_result sets end time."""
        scope = Scope(local_endpoint=True)
        config = Config()
        check = MockCheck(scope, config)
        
        result = check._create_result()
        result = check._finish_result(result)
        
        assert result.end_time is not None
    
    def test_duration_calculation(self) -> None:
        """Test duration calculation."""
        result = CheckResult(
            check_id="test",
            check_name="Test",
            category=Category.HARDENING,
            passed=True,
            start_time=datetime(2024, 1, 1, 12, 0, 0),
            end_time=datetime(2024, 1, 1, 12, 0, 30),
        )
        
        assert result.duration_seconds == 30.0


class TestCheckResult:
    """Tests for CheckResult class."""
    
    def test_result_defaults(self) -> None:
        """Test default values."""
        result = CheckResult(
            check_id="test",
            check_name="Test Check",
            category=Category.PERMISSIONS,
            passed=True,
        )
        
        assert result.findings == []
        assert result.errors == []
        assert result.metadata == {}
    
    def test_findings_count(self) -> None:
        """Test findings count property."""
        result = CheckResult(
            check_id="test",
            check_name="Test",
            category=Category.HARDENING,
            passed=False,
        )
        
        result.findings = [
            Finding("F1", Category.HARDENING, SeverityLevel.MEDIUM, ConfidenceLevel.CERTAIN, "t1", "e1", "r1"),
            Finding("F2", Category.HARDENING, SeverityLevel.LOW, ConfidenceLevel.CERTAIN, "t2", "e2", "r2"),
        ]
        
        assert result.findings_count == 2
    
    def test_to_dict(self) -> None:
        """Test conversion to dictionary."""
        result = CheckResult(
            check_id="test",
            check_name="Test Check",
            category=Category.SECRETS,
            passed=False,
            findings=[
                Finding("F1", Category.SECRETS, SeverityLevel.HIGH, ConfidenceLevel.CERTAIN, "t1", "e1", "r1"),
            ],
            errors=["Error 1"],
            metadata={"key": "value"},
        )
        
        data = result.to_dict()
        
        assert data["check_id"] == "test"
        assert data["check_name"] == "Test Check"
        assert data["category"] == "secrets"
        assert data["passed"] is False
        assert data["findings_count"] == 1
        assert data["errors"] == ["Error 1"]
        assert data["metadata"] == {"key": "value"}


class TestCheckPathInScope:
    """Tests for path scope checking."""
    
    def test_path_in_scope(self) -> None:
        """Test path within scope."""
        scope = Scope(project_paths=[Path("/home/user/project")])
        config = Config()
        check = MockCheck(scope, config)
        
        assert check._is_path_in_scope(Path("/home/user/project/file.txt")) is True
        assert check._is_path_in_scope(Path("/home/user/project/src/code.py")) is True
    
    def test_path_outside_scope(self) -> None:
        """Test path outside scope."""
        scope = Scope(project_paths=[Path("/home/user/project")])
        config = Config()
        check = MockCheck(scope, config)
        
        assert check._is_path_in_scope(Path("/etc/passwd")) is False
        assert check._is_path_in_scope(Path("/home/other/project/file.txt")) is False


class TestCheckDescription:
    """Tests for check description."""
    
    def test_default_description(self) -> None:
        """Test default description."""
        assert "Security check" in MockCheck.get_description()
    
    def test_default_requirements(self) -> None:
        """Test default requirements."""
        assert MockCheck.get_requirements() == []
