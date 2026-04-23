"""Unit tests for scope management."""

import pytest
from pathlib import Path

from app.scope import ScopeManager, ScopeError, create_example_scope_yaml
from app.models import Scope


class TestScopeManager:
    """Tests for the ScopeManager class."""
    
    def test_empty_scope_validation(self) -> None:
        """Test that empty scope fails validation."""
        scope = Scope()
        manager = ScopeManager(scope)
        
        assert manager.validate() is False
        assert "empty" in manager.validation_errors[0].lower()
    
    def test_valid_scope(self) -> None:
        """Test validation of valid scope."""
        scope = Scope(
            local_endpoint=True,
            project_paths=[Path("/tmp")],
        )
        manager = ScopeManager(scope)
        
        assert manager.validate() is True
        assert manager.validation_errors == []
    
    def test_require_scope_raises(self) -> None:
        """Test that require_scope raises on empty scope."""
        scope = Scope()
        manager = ScopeManager(scope)
        
        with pytest.raises(ScopeError):
            manager.require_scope()
    
    def test_is_target_allowed_localhost(self) -> None:
        """Test localhost detection."""
        scope = Scope(local_endpoint=True)
        manager = ScopeManager(scope)
        
        assert manager.is_target_allowed("127.0.0.1") is True
        assert manager.is_target_allowed("localhost") is True
        assert manager.is_target_allowed("::1") is True
    
    def test_is_target_allowed_explicit(self) -> None:
        """Test explicit host matching."""
        scope = Scope(allowed_hosts=["192.168.1.10", "example.com"])
        manager = ScopeManager(scope)
        
        assert manager.is_target_allowed("192.168.1.10") is True
        assert manager.is_target_allowed("example.com") is True
        assert manager.is_target_allowed("192.168.1.11") is False
    
    def test_is_target_allowed_cidr(self) -> None:
        """Test CIDR notation matching."""
        scope = Scope(allowed_hosts=["192.168.1.0/24"])
        manager = ScopeManager(scope)
        
        assert manager.is_target_allowed("192.168.1.10") is True
        assert manager.is_target_allowed("192.168.1.1") is True
        assert manager.is_target_allowed("192.168.2.1") is False
    
    def test_is_path_allowed(self) -> None:
        """Test path scope checking."""
        scope = Scope(project_paths=[Path("/home/user/project")])
        manager = ScopeManager(scope)
        
        assert manager.is_path_allowed(Path("/home/user/project/file.txt")) is True
        assert manager.is_path_allowed(Path("/home/user/project/src/code.py")) is True
        assert manager.is_path_allowed(Path("/other/path/file.txt")) is False
    
    def test_is_excluded_path(self) -> None:
        """Test exclusion checking."""
        scope = Scope(exclude_paths=["node_modules/", ".git/"])
        manager = ScopeManager(scope)
        
        assert manager.is_excluded_path(Path("/project/node_modules/package.json")) is True
        assert manager.is_excluded_path(Path("/project/.git/config")) is True
        assert manager.is_excluded_path(Path("/project/src/main.py")) is False


class TestScopeManagerCreation:
    """Tests for creating ScopeManager from different sources."""
    
    def test_from_args_local(self) -> None:
        """Test creating from CLI args with local."""
        manager = ScopeManager.from_args(
            local=True,
            paths=None,
            hosts=None,
        )
        
        assert manager.scope.local_endpoint is True
        assert manager.scope.is_empty() is False
    
    def test_from_args_with_paths(self, tmp_path: Path) -> None:
        """Test creating from CLI args with paths."""
        test_dir = tmp_path / "test_project"
        test_dir.mkdir()
        
        manager = ScopeManager.from_args(
            local=False,
            paths=[test_dir],
            hosts=None,
        )
        
        assert len(manager.scope.project_paths) == 1
        assert manager.scope.is_empty() is False
    
    def test_from_args_with_hosts(self, tmp_path: Path) -> None:
        """Test creating from CLI args with host file."""
        host_file = tmp_path / "hosts.txt"
        host_file.write_text("192.168.1.1\n192.168.1.2\n# Comment\nexample.com\n")
        
        manager = ScopeManager.from_args(
            local=False,
            paths=None,
            host_file=host_file,
        )
        
        assert len(manager.scope.allowed_hosts) == 3
        assert "192.168.1.1" in manager.scope.allowed_hosts
        assert "example.com" in manager.scope.allowed_hosts
        assert "# Comment" not in manager.scope.allowed_hosts


class TestExampleScopeYAML:
    """Tests for example scope YAML generation."""
    
    def test_example_contains_local_endpoint(self) -> None:
        """Test example contains local_endpoint setting."""
        example = create_example_scope_yaml()
        assert "local_endpoint:" in example
    
    def test_example_contains_project_paths(self) -> None:
        """Test example contains project_paths."""
        example = create_example_scope_yaml()
        assert "project_paths:" in example
    
    def test_example_contains_allowed_hosts(self) -> None:
        """Test example contains allowed_hosts."""
        example = create_example_scope_yaml()
        assert "allowed_hosts:" in example
    
    def test_example_contains_comments(self) -> None:
        """Test example contains helpful comments."""
        example = create_example_scope_yaml()
        assert "#" in example
