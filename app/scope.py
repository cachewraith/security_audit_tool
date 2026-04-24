"""Scope management and validation."""

import re
import yaml
from pathlib import Path
from typing import Optional
from ipaddress import ip_address, ip_network
from urllib.parse import urlparse

from .models import Scope


class ScopeError(Exception):
    """Exception raised for scope-related errors."""
    pass


class ScopeManager:
    """Manages audit scope validation and enforcement."""
    
    def __init__(self, scope: Scope):
        self.scope = scope
        self._validated = False
        self._validation_errors: list[str] = []
    
    def validate(self) -> bool:
        """Validate the scope and return True if valid."""
        self._validation_errors = self.scope.validate()
        self._validated = True
        return len(self._validation_errors) == 0
    
    @property
    def validation_errors(self) -> list[str]:
        """Get list of validation errors."""
        if not self._validated:
            self.validate()
        return self._validation_errors
    
    def is_target_allowed(self, target: str) -> bool:
        """Check if a target is within the defined scope."""
        # Check if it's a local endpoint target
        if target in ["localhost", "127.0.0.1", "::1"]:
            return self.scope.local_endpoint
        
        # Check if it's an allowed host
        if target in self.scope.allowed_hosts:
            return True
        
        # Check if it matches any allowed host pattern
        for allowed in self.scope.allowed_hosts:
            # Check for CIDR notation
            if "/" in allowed:
                try:
                    network = ip_network(allowed, strict=False)
                    try:
                        addr = ip_address(target)
                        if addr in network:
                            return True
                    except ValueError:
                        pass
                except ValueError:
                    pass
            
            # Check for wildcard patterns
            if "*" in allowed:
                pattern = allowed.replace(".", r"\.").replace("*", ".*")
                if re.match(pattern, target, re.IGNORECASE):
                    return True
        
        return False
    
    def is_path_allowed(self, path: Path) -> bool:
        """Check if a filesystem path is within allowed project paths."""
        path = path.resolve()
        
        for allowed_path in self.scope.project_paths:
            try:
                path.relative_to(allowed_path.resolve())
                return True
            except ValueError:
                pass
        
        return False
    
    def is_excluded_path(self, path: Path) -> bool:
        """Check if a path is in the exclusion list."""
        path_str = str(path)
        
        for exclude_pattern in self.scope.exclude_paths:
            # Simple string containment check
            if exclude_pattern in path_str:
                return True
            
            # Check if path matches excluded directory name
            if path.name == exclude_pattern or path.name == exclude_pattern.rstrip("/"):
                return True
        
        return False
    
    def is_container_allowed(self, container_id: str) -> bool:
        """Check if a container is in the allowed list."""
        return container_id in self.scope.container_ids
    
    def is_container_image_allowed(self, image: str) -> bool:
        """Check if a container image is in the allowed list."""
        return image in self.scope.container_images
    
    def require_scope(self) -> None:
        """Raise an error if scope is empty."""
        if self.scope.is_empty():
            raise ScopeError(
                "No scope defined. The tool requires an explicit scope before running.\n"
                "Define scope using --scope-file, or provide --path, --hosts, or --local options."
            )
    
    def get_scope_summary(self) -> str:
        """Get a human-readable summary of the scope."""
        lines = ["Audit Scope:"]
        
        if self.scope.local_endpoint:
            lines.append("  - Local endpoint: ENABLED")
        
        if self.scope.project_paths:
            lines.append(f"  - Project paths ({len(self.scope.project_paths)}):")
            for p in self.scope.project_paths:
                lines.append(f"    - {p}")
        
        if self.scope.allowed_hosts:
            lines.append(f"  - Allowed hosts ({len(self.scope.allowed_hosts)}):")
            for h in self.scope.allowed_hosts[:5]:  # Show first 5
                lines.append(f"    - {h}")
            if len(self.scope.allowed_hosts) > 5:
                lines.append(f"    ... and {len(self.scope.allowed_hosts) - 5} more")

        if self.scope.allowed_urls:
            lines.append(f"  - Allowed URLs ({len(self.scope.allowed_urls)}):")
            for url in self.scope.allowed_urls[:5]:
                lines.append(f"    - {url}")
            if len(self.scope.allowed_urls) > 5:
                lines.append(f"    ... and {len(self.scope.allowed_urls) - 5} more")
        
        if self.scope.container_ids:
            lines.append(f"  - Container IDs ({len(self.scope.container_ids)})")
        
        if self.scope.container_images:
            lines.append(f"  - Container images ({len(self.scope.container_images)})")
        
        if self.scope.exclude_paths:
            lines.append(f"  - Excluded paths ({len(self.scope.exclude_paths)})")
        
        return "\n".join(lines)
    
    @classmethod
    def from_yaml_file(cls, path: Path) -> "ScopeManager":
        """Load scope from YAML file."""
        with open(path, 'r') as f:
            data = yaml.safe_load(f)
        
        # Parse project paths
        project_paths = []
        for p in data.get("project_paths", []):
            project_paths.append(Path(p).expanduser().resolve())
        
        scope = Scope(
            local_endpoint=data.get("local_endpoint", False),
            project_paths=project_paths,
            allowed_hosts=data.get("allowed_hosts", []),
            allowed_urls=data.get("allowed_urls", []),
            container_images=data.get("container_images", []),
            container_ids=data.get("container_ids", []),
            exclude_paths=data.get("exclude_paths", []),
            max_depth=data.get("max_depth", 10),
        )
        
        return cls(scope)
    
    @classmethod
    def from_args(
        cls,
        local: bool = False,
        paths: Optional[list[Path]] = None,
        hosts: Optional[list[str]] = None,
        host_file: Optional[Path] = None,
        urls: Optional[list[str]] = None,
    ) -> "ScopeManager":
        """Create scope from CLI arguments."""
        project_paths = []
        if paths:
            for p in paths:
                project_paths.append(p.expanduser().resolve())

        allowed_hosts = list(hosts) if hosts else []
        allowed_urls: list[str] = []

        if host_file and host_file.exists():
            with open(host_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        allowed_hosts.append(line)

        # Extract hostnames from URLs
        if urls:
            for url in urls:
                if url not in allowed_urls:
                    allowed_urls.append(url)
                parsed = urlparse(url)
                hostname = parsed.hostname or url
                # Remove port if present in hostname
                if hostname and ':' in hostname:
                    hostname = hostname.split(':')[0]
                if hostname and hostname not in allowed_hosts:
                    allowed_hosts.append(hostname)

        scope = Scope(
            local_endpoint=local,
            project_paths=project_paths,
            allowed_hosts=allowed_hosts,
            allowed_urls=allowed_urls,
        )

        return cls(scope)


def create_example_scope_yaml() -> str:
    """Generate example scope configuration YAML."""
    return """# Security Audit Tool - Scope Configuration
# Define what targets are approved for auditing

# Enable local endpoint scanning
local_endpoint: true

# List of project directories to audit
project_paths:
  - /home/user/projects/myapp
  - ./relative/path/to/project

# List of allowed hosts for network checks
# Supports IP addresses, hostnames, CIDR notation, and wildcards
allowed_hosts:
  - 127.0.0.1
  - localhost
  - 192.168.1.0/24
  - *.example.com
  - 10.0.0.5

# Explicit URLs for HTTP-based checks
allowed_urls:
  - https://example.com/login
  - https://api.example.com/v1/health

# Container images to check
container_images:
  - myapp:latest
  - nginx:stable

# Running container IDs to check
container_ids:
  - abc123def456

# Paths to exclude from filesystem checks
exclude_paths:
  - node_modules/
  - __pycache__/
  - .git/
  - *.log

# Maximum recursion depth for directory traversal
max_depth: 10
"""
