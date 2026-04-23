"""Package dependency collector for vulnerability assessment."""

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ..utils.subprocess_safe import run_safe, SafeSubprocessError


@dataclass
class PackageInfo:
    """Information about a software package."""
    name: str
    version: str
    manager: str  # pip, npm, apt, etc.
    source: str  # Path to manifest file
    is_outdated: bool = False
    latest_version: Optional[str] = None
    vulnerabilities: list[dict] = field(default_factory=list)


@dataclass
class DependencyInventory:
    """Inventory of dependencies for a project."""
    manifest_path: Path
    manager: str
    packages: list[PackageInfo] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    
    @property
    def total_packages(self) -> int:
        return len(self.packages)
    
    @property
    def outdated_count(self) -> int:
        return sum(1 for p in self.packages if p.is_outdated)


class PackageCollector:
    """Collects package dependency information."""
    
    def __init__(self):
        self.managers = {
            "pip": self._parse_requirements_txt,
            "npm": self._parse_package_json,
            "pipenv": self._parse_pipfile,
            "poetry": self._parse_pyproject_toml,
            "docker": self._parse_dockerfile,
        }
    
    def scan_project(self, project_path: Path) -> list[DependencyInventory]:
        """Scan a project for dependency manifests."""
        inventories: list[DependencyInventory] = []
        
        # Check for requirements.txt
        req_txt = project_path / "requirements.txt"
        if req_txt.exists():
            inv = self._parse_requirements_txt(req_txt)
            if inv:
                inventories.append(inv)
        
        # Check for package.json
        pkg_json = project_path / "package.json"
        if pkg_json.exists():
            inv = self._parse_package_json(pkg_json)
            if inv:
                inventories.append(inv)
        
        # Check for pyproject.toml
        pyproject = project_path / "pyproject.toml"
        if pyproject.exists():
            inv = self._parse_pyproject_toml(pyproject)
            if inv:
                inventories.append(inv)
        
        # Check for Pipfile
        pipfile = project_path / "Pipfile"
        if pipfile.exists():
            inv = self._parse_pipfile(pipfile)
            if inv:
                inventories.append(inv)
        
        # Check for Dockerfile
        dockerfile = project_path / "Dockerfile"
        if dockerfile.exists():
            inv = self._parse_dockerfile(dockerfile)
            if inv:
                inventories.append(inv)
        
        # Check for docker-compose files
        for pattern in ["docker-compose.yml", "docker-compose.yaml"]:
            compose_file = project_path / pattern
            if compose_file.exists():
                inv = self._parse_docker_compose(compose_file)
                if inv:
                    inventories.append(inv)
        
        return inventories
    
    def _parse_requirements_txt(self, path: Path) -> Optional[DependencyInventory]:
        """Parse requirements.txt file."""
        inventory = DependencyInventory(
            manifest_path=path,
            manager="pip",
        )
        
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    
                    # Skip comments and empty lines
                    if not line or line.startswith("#"):
                        continue
                    
                    # Skip options and references
                    if line.startswith("-"):
                        continue
                    
                    # Parse package specification
                    # Handle various formats:
                    # package==1.0.0
                    # package>=1.0.0
                    # package~=1.0.0
                    # package[extra]==1.0.0
                    
                    match = re.match(
                        r'^([a-zA-Z0-9_-]+)(?:\[[^\]]+\])?(.*)',
                        line.split(";")[0].split("#")[0].strip()
                    )
                    
                    if match:
                        name = match.group(1)
                        version_spec = match.group(2).strip()
                        
                        # Extract version if pinned
                        version = "unknown"
                        if "==" in version_spec:
                            version = version_spec.split("==")[1].strip()
                        
                        inventory.packages.append(PackageInfo(
                            name=name,
                            version=version,
                            manager="pip",
                            source=str(path),
                        ))
        
        except Exception as e:
            inventory.errors.append(f"Error parsing {path}: {e}")
        
        return inventory if inventory.packages else None
    
    def _parse_package_json(self, path: Path) -> Optional[DependencyInventory]:
        """Parse package.json file."""
        inventory = DependencyInventory(
            manifest_path=path,
            manager="npm",
        )
        
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)
            
            # Parse dependencies
            deps = data.get("dependencies", {})
            dev_deps = data.get("devDependencies", {})
            
            for name, version in {**deps, **dev_deps}.items():
                # Clean version string
                clean_version = version.lstrip("^~>=<!").strip()
                
                inventory.packages.append(PackageInfo(
                    name=name,
                    version=clean_version,
                    manager="npm",
                    source=str(path),
                ))
        
        except json.JSONDecodeError as e:
            inventory.errors.append(f"JSON parse error in {path}: {e}")
        except Exception as e:
            inventory.errors.append(f"Error parsing {path}: {e}")
        
        return inventory if inventory.packages else None
    
    def _parse_pyproject_toml(self, path: Path) -> Optional[DependencyInventory]:
        """Parse pyproject.toml file."""
        inventory = DependencyInventory(
            manifest_path=path,
            manager="poetry",
        )
        
        try:
            # Try to use toml library if available
            try:
                import tomllib  # Python 3.11+
                with open(path, "rb") as f:
                    data = tomllib.load(f)
            except ImportError:
                try:
                    import toml
                    with open(path, "r", encoding="utf-8") as f:
                        data = toml.load(f)
                except ImportError:
                    # Manual parsing for basic cases
                    data = self._manual_toml_parse(path)
            
            # Extract Poetry dependencies
            if "tool" in data and "poetry" in data["tool"]:
                poetry = data["tool"]["poetry"]
                deps = poetry.get("dependencies", {})
                dev_deps = poetry.get("dev-dependencies", {})
                
                for name, version in {**deps, **dev_deps}.items():
                    if name == "python":
                        continue
                    
                    if isinstance(version, dict):
                        version_str = version.get("version", "unknown")
                    else:
                        version_str = str(version).lstrip("^~>=<!").strip()
                    
                    inventory.packages.append(PackageInfo(
                        name=name,
                        version=version_str,
                        manager="poetry",
                        source=str(path),
                    ))
            
            # Extract PEP 621 dependencies
            elif "project" in data:
                project = data["project"]
                deps = project.get("dependencies", [])
                
                for dep in deps:
                    # Parse PEP 508 format
                    match = re.match(r'^([a-zA-Z0-9_-]+)', dep.strip())
                    if match:
                        name = match.group(1)
                        version = "unknown"
                        
                        # Try to extract version specifier
                        version_match = re.search(r'==\s*([0-9][^;\s]*)', dep)
                        if version_match:
                            version = version_match.group(1)
                        
                        inventory.packages.append(PackageInfo(
                            name=name,
                            version=version,
                            manager="pip",
                            source=str(path),
                        ))
        
        except Exception as e:
            inventory.errors.append(f"Error parsing {path}: {e}")
        
        return inventory if inventory.packages else None
    
    def _manual_toml_parse(self, path: Path) -> dict:
        """Manual TOML parsing for basic cases (fallback)."""
        data: dict = {}
        
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            
            # Very basic parsing - just extract dependency lines
            # This is a fallback only
            data = {"_raw": content}
        except Exception:
            pass
        
        return data
    
    def _parse_pipfile(self, path: Path) -> Optional[DependencyInventory]:
        """Parse Pipfile."""
        inventory = DependencyInventory(
            manifest_path=path,
            manager="pipenv",
        )
        
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            
            # Basic parsing - look for package names in [packages] and [dev-packages]
            sections = ["packages", "dev-packages"]
            
            for section in sections:
                pattern = rf'\[{section}\](.*?)(?:\[|$)'
                match = re.search(pattern, content, re.DOTALL)
                if match:
                    section_content = match.group(1)
                    
                    # Extract package names
                    for line in section_content.split("\n"):
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        
                        # Match package name
                        pkg_match = re.match(r'^([a-zA-Z0-9_-]+)\s*=', line)
                        if pkg_match:
                            name = pkg_match.group(1)
                            
                            # Try to extract version
                            version = "unknown"
                            ver_match = re.search(r'version\s*=\s*"([^"]+)"', line)
                            if ver_match:
                                version = ver_match.group(1).lstrip("=<>~!").strip()
                            
                            inventory.packages.append(PackageInfo(
                                name=name,
                                version=version,
                                manager="pipenv",
                                source=str(path),
                            ))
        
        except Exception as e:
            inventory.errors.append(f"Error parsing {path}: {e}")
        
        return inventory if inventory.packages else None
    
    def _parse_dockerfile(self, path: Path) -> Optional[DependencyInventory]:
        """Parse Dockerfile for base images and installed packages."""
        inventory = DependencyInventory(
            manifest_path=path,
            manager="docker",
        )
        
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            
            # Extract FROM images
            from_pattern = r'^FROM\s+(\S+)(?:\s+as\s+\S+)?'
            for match in re.finditer(from_pattern, content, re.MULTILINE | re.IGNORECASE):
                image = match.group(1)
                name = image.split(":")[0]
                version = image.split(":")[1] if ":" in image else "latest"
                
                inventory.packages.append(PackageInfo(
                    name=f"docker:{name}",
                    version=version,
                    manager="docker",
                    source=str(path),
                ))
            
            # Note: We don't extract RUN commands to avoid flagging
            # build-time commands as vulnerabilities
        
        except Exception as e:
            inventory.errors.append(f"Error parsing {path}: {e}")
        
        return inventory if inventory.packages else None
    
    def _parse_docker_compose(self, path: Path) -> Optional[DependencyInventory]:
        """Parse docker-compose file for images."""
        inventory = DependencyInventory(
            manifest_path=path,
            manager="docker-compose",
        )
        
        try:
            # Try YAML parsing
            try:
                import yaml
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    data = yaml.safe_load(f)
            except ImportError:
                inventory.errors.append("PyYAML not available for parsing")
                return None
            
            # Extract services and their images
            services = data.get("services", {})
            
            for service_name, service_config in services.items():
                if isinstance(service_config, dict):
                    image = service_config.get("image")
                    if image:
                        name = image.split(":")[0]
                        version = image.split(":")[1] if ":" in image else "latest"
                        
                        inventory.packages.append(PackageInfo(
                            name=f"docker:{name}",
                            version=version,
                            manager="docker-compose",
                            source=str(path),
                        ))
        
        except Exception as e:
            inventory.errors.append(f"Error parsing {path}: {e}")
        
        return inventory if inventory.packages else None
    
    def get_system_packages(self) -> list[PackageInfo]:
        """Get list of system packages (Linux only, defensive read-only)."""
        packages: list[PackageInfo] = []
        
        # Try dpkg (Debian/Ubuntu)
        try:
            result = run_safe(["dpkg-query", "-W", "-f=${Package} ${Version}\n"], capture_output=True)
            if result.returncode == 0:
                for line in result.stdout.strip().split("\n"):
                    parts = line.split()
                    if len(parts) >= 2:
                        packages.append(PackageInfo(
                            name=parts[0],
                            version=parts[1],
                            manager="dpkg",
                            source="system",
                        ))
        except (SafeSubprocessError, FileNotFoundError):
            pass
        
        # Try rpm (RHEL/CentOS/Fedora)
        if not packages:
            try:
                result = run_safe(["rpm", "-qa", "--queryformat", "%{NAME} %{VERSION}-%{RELEASE}\n"], capture_output=True)
                if result.returncode == 0:
                    for line in result.stdout.strip().split("\n"):
                        parts = line.split()
                        if len(parts) >= 2:
                            packages.append(PackageInfo(
                                name=parts[0],
                                version=parts[1],
                                manager="rpm",
                                source="system",
                            ))
            except (SafeSubprocessError, FileNotFoundError):
                pass
        
        return packages
