"""Base class for security checks."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Any
from pathlib import Path

from ..models import Finding, Category, SeverityLevel, ConfidenceLevel, Scope
from ..config import Config


@dataclass
class CheckResult:
    """Result of a security check."""
    check_id: str
    check_name: str
    category: Category
    passed: bool
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    
    @property
    def duration_seconds(self) -> float:
        """Calculate check duration in seconds."""
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0
    
    @property
    def findings_count(self) -> int:
        """Get number of findings."""
        return len(self.findings)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "check_id": self.check_id,
            "check_name": self.check_name,
            "category": self.category.value,
            "passed": self.passed,
            "findings_count": self.findings_count,
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
            "metadata": self.metadata,
            "duration_seconds": self.duration_seconds,
        }


class BaseCheck(ABC):
    """Base class for all security checks.
    
    All security checks must inherit from this class and implement:
    - check_id: Unique identifier for the check
    - check_name: Human-readable name
    - category: Category of the check
    - run(): The main check logic
    
    Example:
        class MyCheck(BaseCheck):
            check_id = "my_check"
            check_name = "My Security Check"
            category = Category.HARDENING
            
            def run(self) -> CheckResult:
                result = self._create_result()
                # ... perform checks ...
                return result
    """
    
    check_id: str = ""
    check_name: str = ""
    category: Category = Category.HARDENING
    
    def __init__(
        self,
        scope: Scope,
        config: Config,
    ):
        self.scope = scope
        self.config = config
        self.result: CheckResult = CheckResult(
            check_id=self.check_id,
            check_name=self.check_name,
            category=self.category,
            passed=True,
        )
    
    @abstractmethod
    def run(self) -> CheckResult:
        """Execute the security check.
        
        This method must be implemented by all check classes.
        It should:
        1. Create a CheckResult
        2. Perform the security assessment
        3. Add findings for any issues discovered
        4. Set result.passed = False if issues found
        5. Return the result
        
        Returns:
            CheckResult containing findings and metadata
        """
        pass
    
    def _create_result(self) -> CheckResult:
        """Create a new CheckResult with timing initialized."""
        return CheckResult(
            check_id=self.check_id,
            check_name=self.check_name,
            category=self.category,
            passed=True,
            start_time=datetime.utcnow(),
        )
    
    def _finish_result(self, result: CheckResult) -> CheckResult:
        """Finalize a check result with end time."""
        result.end_time = datetime.utcnow()
        
        # Set passed to False if there are findings
        if result.findings:
            result.passed = False
        
        return result
    
    def _create_finding(
        self,
        title: str,
        severity: SeverityLevel,
        target: str,
        evidence: str,
        remediation: str,
        confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM,
        references: Optional[list[str]] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> Finding:
        """Create a new Finding with standard fields populated."""
        return Finding(
            title=title,
            category=self.category,
            severity=severity,
            confidence=confidence,
            target=target,
            evidence=evidence,
            remediation=remediation,
            references=references or [],
            check_id=self.check_id,
            metadata=metadata or {},
        )
    
    def _is_in_scope(self, target: str) -> bool:
        """Check if a target is within the defined scope."""
        # This would be implemented by the ScopeManager
        # For now, assume all targets are in scope
        return True
    
    def _is_path_in_scope(self, path: Path) -> bool:
        """Check if a filesystem path is within allowed scope."""
        resolved = path.resolve()
        for allowed_path in self.scope.project_paths:
            try:
                resolved.relative_to(allowed_path.resolve())
                return True
            except ValueError:
                pass
        return False
    
    def _log_error(self, message: str, exception: Optional[Exception] = None) -> None:
        """Log an error encountered during checking."""
        error_msg = message
        if exception:
            error_msg += f": {exception}"
        self.result.errors.append(error_msg)
    
    @classmethod
    def get_description(cls) -> str:
        """Get a description of what this check does.
        
        Subclasses should override this to provide meaningful documentation.
        """
        return f"Security check: {cls.check_name}"
    
    @classmethod
    def get_requirements(cls) -> list[str]:
        """Get list of requirements for running this check.
        
        Returns a list of required permissions, tools, etc.
        """
        return []
