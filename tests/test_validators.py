"""Unit tests for validators."""

import pytest
from pathlib import Path

from app.utils.validators import (
    validate_scope,
    validate_host,
    is_valid_hostname,
    validate_path,
    sanitize_input,
    is_safe_filename,
    get_downloads_path,
)


class TestValidateHost:
    """Tests for host validation."""
    
    def test_valid_ip_address(self) -> None:
        """Test valid IP addresses."""
        assert validate_host("192.168.1.1") == []
        assert validate_host("10.0.0.1") == []
        assert validate_host("127.0.0.1") == []
    
    def test_valid_hostname(self) -> None:
        """Test valid hostnames."""
        assert validate_host("example.com") == []
        assert validate_host("server.example.com") == []
        assert validate_host("localhost") == []
    
    def test_valid_cidr(self) -> None:
        """Test valid CIDR notation."""
        assert validate_host("192.168.1.0/24") == []
        assert validate_host("10.0.0.0/8") == []
    
    def test_invalid_empty_host(self) -> None:
        """Test empty host is invalid."""
        errors = validate_host("")
        assert any("empty" in e.lower() for e in errors)
    
    def test_invalid_characters(self) -> None:
        """Test hosts with dangerous characters."""
        errors = validate_host("example.com; rm -rf")
        assert len(errors) > 0
        
        errors = validate_host("example.com|cat /etc/passwd")
        assert len(errors) > 0
    
    def test_wildcard_hostname(self) -> None:
        """Test wildcard hostname patterns."""
        assert validate_host("*.example.com") == []
        assert validate_host("*example.com") == []


class TestIsValidHostname:
    """Tests for hostname validation."""
    
    def test_valid_hostnames(self) -> None:
        """Test valid hostname formats."""
        assert is_valid_hostname("example.com") is True
        assert is_valid_hostname("server.example.com") is True
        assert is_valid_hostname("a-b.example.com") is True
        assert is_valid_hostname("localhost") is True
    
    def test_invalid_hostnames(self) -> None:
        """Test invalid hostname formats."""
        assert is_valid_hostname("") is False
        assert is_valid_hostname("-example.com") is False
        assert is_valid_hostname("example-.com") is False
        assert is_valid_hostname("example..com") is False
    
    def test_hostname_length(self) -> None:
        """Test hostname length restrictions."""
        # 253 characters is max
        long_hostname = "a" * 250 + ".com"
        assert is_valid_hostname(long_hostname) is True
        
        # 254 characters is too long
        too_long = "a" * 251 + ".com"
        assert is_valid_hostname(too_long) is False


class TestValidatePath:
    """Tests for path validation."""
    
    def test_valid_path(self, tmp_path: Path) -> None:
        """Test valid path."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("test")
        
        assert validate_path(test_file, must_exist=True) == []
    
    def test_nonexistent_path(self, tmp_path: Path) -> None:
        """Test nonexistent path."""
        nonexistent = tmp_path / "does_not_exist.txt"
        
        errors = validate_path(nonexistent, must_exist=True)
        assert any("not exist" in e.lower() for e in errors)
    
    def test_null_bytes(self) -> None:
        """Test path with null bytes."""
        errors = validate_path(Path("/tmp/test\x00.txt"))
        assert any("null" in e.lower() for e in errors)


class TestSanitizeInput:
    """Tests for input sanitization."""
    
    def test_removes_control_characters(self) -> None:
        """Test that control characters are removed."""
        result = sanitize_input("hello\x00world")
        assert "\x00" not in result
    
    def test_preserves_whitespace(self) -> None:
        """Test that normal whitespace is preserved."""
        result = sanitize_input("hello\nworld\ttest")
        assert "\n" in result
        assert "\t" in result
    
    def test_truncates_long_input(self) -> None:
        """Test that long input is truncated."""
        long_input = "a" * 2000
        result = sanitize_input(long_input, max_length=1024)
        assert len(result) <= 1024


class TestIsSafeFilename:
    """Tests for safe filename validation."""
    
    def test_safe_filenames(self) -> None:
        """Test safe filename patterns."""
        assert is_safe_filename("test.txt") is True
        assert is_safe_filename("my-file.txt") is True
        assert is_safe_filename("file_123.txt") is True
    
    def test_path_traversal(self) -> None:
        """Test path traversal attempts."""
        assert is_safe_filename("../etc/passwd") is False
        assert is_safe_filename("../../etc/shadow") is False
        assert is_safe_filename("..\\windows\\system32") is False
    
    def test_directory_separators(self) -> None:
        """Test filenames with directory separators."""
        assert is_safe_filename("/etc/passwd") is False
        assert is_safe_filename("path/to/file.txt") is False
    
    def test_special_characters(self) -> None:
        """Test filenames with special characters."""
        assert is_safe_filename("file\x00.txt") is False
        assert is_safe_filename("file\n.txt") is False
        assert is_safe_filename("file\r.txt") is False


class TestValidateScope:
    """Tests for scope validation."""
    
    def test_empty_scope(self) -> None:
        """Test empty scope validation."""
        scope = {}
        errors = validate_scope(scope)
        assert any("target" in e.lower() for e in errors)
    
    def test_scope_with_local(self) -> None:
        """Test scope with local endpoint."""
        scope = {"local_endpoint": True}
        errors = validate_scope(scope)
        assert len(errors) == 0 or not any("target" in e.lower() for e in errors)

    def test_scope_with_allowed_urls(self) -> None:
        """Test scope with explicit HTTP targets."""
        scope = {"allowed_urls": ["https://example.com/login"]}
        errors = validate_scope(scope)
        assert not any("target" in e.lower() for e in errors)
    
    def test_scope_with_invalid_max_depth(self) -> None:
        """Test scope with invalid max_depth."""
        scope = {
            "local_endpoint": True,
            "max_depth": 0,
        }
        errors = validate_scope(scope)
        assert any("max_depth" in e.lower() for e in errors)


class TestGetDownloadsPath:
    """Tests for get_downloads_path function."""
    
    def test_returns_path_object(self) -> None:
        """Test that get_downloads_path returns a Path object."""
        result = get_downloads_path()
        assert isinstance(result, Path)
    
    def test_path_exists(self) -> None:
        """Test that the returned path exists."""
        result = get_downloads_path()
        assert result.exists()
    
    def test_path_is_directory(self) -> None:
        """Test that the returned path is a directory."""
        result = get_downloads_path()
        assert result.is_dir()
    
    def test_fallback_to_cwd(self, tmp_path: Path) -> None:
        """Test that function falls back to current directory if Downloads doesn't exist."""
        import os
        import platform
        from unittest.mock import patch
        
        # Mock the platform to simulate a system where Downloads doesn't exist
        with patch('app.utils.validators.platform.system', return_value='Linux'):
            with patch('app.utils.validators.Path.home', return_value=tmp_path):
                with patch('app.utils.validators.Path.cwd', return_value=tmp_path):
                    result = get_downloads_path()
                    assert result == tmp_path
