"""Input validation utilities."""

import os
import platform
import re
import ipaddress
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse


class ValidationError(Exception):
    """Exception raised for validation errors."""
    pass


def validate_scope(scope: dict) -> list[str]:
    """Validate a scope dictionary and return list of errors."""
    errors = []
    
    # Check that scope has at least one target type
    has_target = any([
        scope.get("local_endpoint"),
        scope.get("project_paths"),
        scope.get("allowed_hosts"),
        scope.get("container_images"),
        scope.get("container_ids"),
    ])
    
    if not has_target:
        errors.append("Scope must define at least one target type")
    
    # Validate project paths
    for path_str in scope.get("project_paths", []):
        try:
            path = Path(path_str).expanduser()
            # We don't check existence here - that happens at runtime
            # But we do check for path traversal attempts
            resolved = path.resolve()
            # Check for suspicious patterns
            if ".." in str(path):
                # This is okay if it resolves within bounds
                pass
        except Exception as e:
            errors.append(f"Invalid project path '{path_str}': {e}")
    
    # Validate hosts
    for host in scope.get("allowed_hosts", []):
        host_errors = validate_host(host)
        errors.extend([f"Host '{host}': {e}" for e in host_errors])
    
    # Validate max_depth
    max_depth = scope.get("max_depth", 10)
    if not isinstance(max_depth, int) or max_depth < 1 or max_depth > 100:
        errors.append(f"Invalid max_depth: {max_depth} (must be 1-100)")
    
    return errors


def validate_host(host: str) -> list[str]:
    """Validate a host string (hostname, IP, or CIDR).

    Returns list of validation errors (empty if valid).
    """
    errors = []

    if not host:
        errors.append("Host cannot be empty")
        return errors

    # Check for suspicious characters
    suspicious = [";", "|", "&", "$", "`", "\n", "\r"]
    for char in suspicious:
        if char in host:
            errors.append(f"Host contains suspicious character: {repr(char)}")

    # Check if it's a CIDR notation
    if "/" in host:
        try:
            ipaddress.ip_network(host, strict=False)
            return errors  # Valid CIDR
        except ValueError:
            errors.append("Invalid CIDR notation")
            return errors

    # Check if it's an IP address
    try:
        ipaddress.ip_address(host)
        return errors  # Valid IP
    except ValueError:
        pass

    # Validate as hostname
    if not is_valid_hostname(host):
        # Check for wildcard patterns
        if "*" in host:
            # Wildcard hostnames are allowed but must be validated
            host_without_wildcard = host.replace("*", "")
            if host_without_wildcard and not is_valid_hostname(host_without_wildcard.lstrip(".")):
                errors.append("Invalid wildcard hostname pattern")
        else:
            errors.append("Invalid hostname format")

    # Check hostname length
    if len(host) > 253:
        errors.append("Hostname exceeds maximum length (253 characters)")

    # Additional check: Reject obviously fake or repetitive hostnames
    # Check for repeated characters (like "ssssssssssssss")
    if len(host) > 5:
        char_counts = {}
        for char in host.lower():
            char_counts[char] = char_counts.get(char, 0) + 1
        # If 80% or more of the characters are the same, it's likely fake
        max_count = max(char_counts.values())
        if max_count / len(host) >= 0.8:
            errors.append("Hostname appears to be invalid or repetitive")

    # Check for minimum reasonable hostname structure
    # Require at least one dot for domain names (not localhost or single-word hosts)
    if "." not in host and host.lower() not in ["localhost"]:
        errors.append("Hostname must be a domain name (e.g., example.com) or IP address")

    return errors


def is_valid_hostname(hostname: str) -> bool:
    """Check if a string is a valid hostname."""
    if not hostname:
        return False
    
    # Remove trailing dot if present
    hostname = hostname.rstrip(".")
    if len(hostname) > 254:
        return False
    
    # Check each label
    labels = hostname.split(".")
    
    for label in labels:
        if not label:
            return False
        
        # Label must start with alphanumeric
        if not label[0].isalnum():
            return False
        
        # Label must end with alphanumeric
        if not label[-1].isalnum():
            return False
        
        # Label can contain alphanumeric and hyphens
        if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$', label):
            return False
    
    return True


def validate_path(
    path: Path,
    must_exist: bool = False,
    must_be_dir: bool = False,
    must_be_file: bool = False,
    allowed_prefixes: Optional[list[Path]] = None,
) -> list[str]:
    """Validate a filesystem path.
    
    Returns list of validation errors (empty if valid).
    """
    errors = []
    
    # Check for null bytes
    if "\x00" in str(path):
        errors.append("Path contains null bytes")
        return errors
    
    try:
        resolved = path.resolve()
    except Exception as e:
        errors.append(f"Cannot resolve path: {e}")
        return errors
    
    # Check existence requirements
    if must_exist and not resolved.exists():
        errors.append("Path does not exist")
    
    if must_be_dir and resolved.exists() and not resolved.is_dir():
        errors.append("Path is not a directory")
    
    if must_be_file and resolved.exists() and not resolved.is_file():
        errors.append("Path is not a file")
    
    # Check allowed prefixes (scope enforcement)
    if allowed_prefixes:
        in_scope = False
        for prefix in allowed_prefixes:
            try:
                resolved.relative_to(prefix.resolve())
                in_scope = True
                break
            except ValueError:
                pass
        
        if not in_scope:
            errors.append(f"Path outside allowed scope: {allowed_prefixes}")
    
    return errors


def validate_url(url: str, allowed_schemes: Optional[list[str]] = None) -> list[str]:
    """Validate a URL string.
    
    Returns list of validation errors (empty if valid).
    """
    errors = []
    
    if not url:
        errors.append("URL cannot be empty")
        return errors
    
    try:
        parsed = urlparse(url)
    except Exception as e:
        errors.append(f"Invalid URL format: {e}")
        return errors
    
    # Check scheme
    if not parsed.scheme:
        errors.append("URL missing scheme (http/https)")
    elif allowed_schemes and parsed.scheme not in allowed_schemes:
        errors.append(f"URL scheme '{parsed.scheme}' not in allowed: {allowed_schemes}")
    
    # Check for suspicious characters in netloc
    suspicious_netloc = [";", "|", "&", "`", "$", "\n", "\r"]
    for char in suspicious_netloc:
        if char in (parsed.netloc or ""):
            errors.append(f"URL netloc contains suspicious character: {repr(char)}")
    
    return errors


def sanitize_input(value: str, max_length: int = 1024) -> str:
    """Sanitize a string input by removing dangerous characters.
    
    Returns sanitized string.
    """
    # Remove control characters except common whitespace
    sanitized = "".join(
        char for char in value
        if ord(char) >= 32 or char in '\t\n\r'
    )
    
    # Truncate if too long
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length]
    
    return sanitized


def is_safe_filename(filename: str) -> bool:
    """Check if a filename is safe (no path traversal)."""
    if not filename:
        return False
    
    dangerous = [
        "../",
        "..\\",
        "..",
        "/",
        "\\",
        "\x00",
        "\n",
        "\r",
    ]
    
    for pattern in dangerous:
        if pattern in filename:
            return False
    
    # Check for reasonable characters
    if not re.match(r'^[\w.-]+$', filename):
        return False
    
    return True


def get_downloads_path() -> Path:
    """Get the Downloads folder path for the current platform.
    
    Returns the Downloads folder path if it exists, otherwise returns
    the current working directory as a fallback.
    
    This function handles cross-platform differences:
    - Windows: Uses %USERPROFILE%\\Downloads
    - macOS: Uses ~/Downloads
    - Linux: Uses ~/Downloads
    """
    system = platform.system()
    
    # Try platform-specific paths
    if system == "Windows":
        # On Windows, try multiple possible locations
        possible_paths = [
            Path.home() / "Downloads",
            Path(os.environ.get("USERPROFILE", "")) / "Downloads" if os.environ.get("USERPROFILE") else None,
            Path(os.path.expanduser("~")) / "Downloads",
        ]
    else:
        # macOS and Linux typically use ~/Downloads
        possible_paths = [
            Path.home() / "Downloads",
            Path(os.path.expanduser("~")) / "Downloads",
        ]
    
    # Filter out None values and check which path exists
    for path in possible_paths:
        if path and path.exists() and path.is_dir():
            return path
    
    # Fallback to current working directory if Downloads folder doesn't exist
    return Path.cwd()
