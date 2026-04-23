"""Filesystem data collector for permission and configuration checks."""

import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Optional, Callable
from fnmatch import fnmatch


@dataclass
class FileInfo:
    """Information about a file or directory."""
    path: Path
    size: int
    mode: int
    uid: int
    gid: int
    is_dir: bool
    is_symlink: bool
    is_file: bool
    
    @property
    def permissions(self) -> str:
        """Get human-readable permissions string."""
        perms = ""
        
        # Owner
        perms += "r" if self.mode & stat.S_IRUSR else "-"
        perms += "w" if self.mode & stat.S_IWUSR else "-"
        perms += "x" if self.mode & stat.S_IXUSR else "-"
        
        # Group
        perms += "r" if self.mode & stat.S_IRGRP else "-"
        perms += "w" if self.mode & stat.S_IWGRP else "-"
        perms += "x" if self.mode & stat.S_IXGRP else "-"
        
        # Other
        perms += "r" if self.mode & stat.S_IROTH else "-"
        perms += "w" if self.mode & stat.S_IWOTH else "-"
        perms += "x" if self.mode & stat.S_IXOTH else "-"
        
        return perms
    
    @property
    def is_world_readable(self) -> bool:
        """Check if file is world-readable."""
        return bool(self.mode & stat.S_IROTH)
    
    @property
    def is_world_writable(self) -> bool:
        """Check if file is world-writable."""
        return bool(self.mode & stat.S_IWOTH)
    
    @property
    def is_world_executable(self) -> bool:
        """Check if file is world-executable."""
        return bool(self.mode & stat.S_IXOTH)
    
    @property
    def has_suid(self) -> bool:
        """Check if file has SUID bit set."""
        return bool(self.mode & stat.S_ISUID)
    
    @property
    def has_sgid(self) -> bool:
        """Check if file has SGID bit set."""
        return bool(self.mode & stat.S_ISGID)
    
    @property
    def has_sticky(self) -> bool:
        """Check if file has sticky bit set."""
        return bool(self.mode & stat.S_ISVTX)


@dataclass
class FilesystemScanResult:
    """Results of a filesystem scan."""
    scanned_paths: list[Path] = field(default_factory=list)
    files_found: list[FileInfo] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    total_size_scanned: int = 0


class FilesystemCollector:
    """Collects filesystem information for security assessment."""
    
    def __init__(
        self,
        max_depth: int = 10,
        follow_symlinks: bool = False,
        exclude_patterns: Optional[list[str]] = None,
        max_file_size_mb: int = 10,
    ):
        self.max_depth = max_depth
        self.follow_symlinks = follow_symlinks
        self.exclude_patterns = exclude_patterns or []
        self.max_file_size = max_file_size_mb * 1024 * 1024
    
    def scan_directory(
        self,
        path: Path,
        file_filter: Optional[Callable[[FileInfo], bool]] = None,
    ) -> FilesystemScanResult:
        """Scan a directory and collect file information."""
        result = FilesystemScanResult()
        
        if not path.exists():
            result.errors.append(f"Path does not exist: {path}")
            return result
        
        if not path.is_dir():
            result.errors.append(f"Path is not a directory: {path}")
            return result
        
        result.scanned_paths.append(path)
        
        for file_info in self._walk_directory(path, current_depth=0):
            if file_info is None:
                continue  # Excluded or error
            
            # Apply file filter if provided
            if file_filter and not file_filter(file_info):
                continue
            
            result.files_found.append(file_info)
            result.total_size_scanned += file_info.size
        
        return result
    
    def _walk_directory(
        self,
        path: Path,
        current_depth: int,
    ) -> Iterator[Optional[FileInfo]]:
        """Walk a directory and yield file information."""
        if current_depth > self.max_depth:
            return
        
        try:
            entries = list(os.scandir(path))
        except PermissionError:
            return
        except Exception:
            return
        
        for entry in entries:
            # Check exclusion patterns
            if self._is_excluded(entry.name):
                continue
            
            try:
                # Handle symlinks
                if entry.is_symlink():
                    if not self.follow_symlinks:
                        continue
                    # If following symlinks, stat the target
                    stat_info = os.stat(entry.path)
                    is_symlink = True
                else:
                    stat_info = entry.stat(follow_symlinks=self.follow_symlinks)
                    is_symlink = entry.is_symlink()
                
                file_info = FileInfo(
                    path=Path(entry.path),
                    size=stat_info.st_size,
                    mode=stat_info.st_mode,
                    uid=stat_info.st_uid,
                    gid=stat_info.st_gid,
                    is_dir=entry.is_dir(follow_symlinks=self.follow_symlinks),
                    is_symlink=is_symlink,
                    is_file=entry.is_file(follow_symlinks=self.follow_symlinks),
                )
                
                yield file_info
                
                # Recurse into directories
                if file_info.is_dir and not is_symlink:
                    yield from self._walk_directory(
                        Path(entry.path),
                        current_depth + 1
                    )
                    
            except (PermissionError, OSError):
                continue
            except Exception:
                continue
    
    def _is_excluded(self, name: str) -> bool:
        """Check if a file/directory name matches exclusion patterns."""
        for pattern in self.exclude_patterns:
            if fnmatch(name, pattern):
                return True
            # Also check without trailing slash
            if pattern.endswith("/"):
                if fnmatch(name, pattern[:-1]):
                    return True
        return False
    
    def find_world_writable_files(
        self,
        path: Path,
    ) -> list[FileInfo]:
        """Find files that are world-writable."""
        def is_world_writable(f: FileInfo) -> bool:
            return f.is_world_writable and not f.is_dir
        
        result = self.scan_directory(path, is_world_writable)
        return result.files_found
    
    def find_suid_sgid_files(
        self,
        path: Path,
    ) -> list[FileInfo]:
        """Find files with SUID or SGID bits set."""
        def has_special_bits(f: FileInfo) -> bool:
            return f.has_suid or f.has_sgid
        
        result = self.scan_directory(path, has_special_bits)
        return result.files_found
    
    def find_config_files(
        self,
        path: Path,
        patterns: Optional[list[str]] = None,
    ) -> list[Path]:
        """Find configuration files matching patterns."""
        default_patterns = [
            "*.conf",
            "*.config",
            "*.ini",
            "*.yaml",
            "*.yml",
            "*.json",
            "*.xml",
            ".env*",
            "Dockerfile*",
            "docker-compose*",
            "requirements*.txt",
            "package*.json",
            "pyproject.toml",
            "setup.py",
            "*.service",
        ]
        
        search_patterns = patterns or default_patterns
        config_files: list[Path] = []
        
        result = self.scan_directory(path)
        
        for file_info in result.files_found:
            if not file_info.is_file:
                continue
            
            for pattern in search_patterns:
                if fnmatch(file_info.path.name, pattern):
                    config_files.append(file_info.path)
                    break
        
        return config_files
    
    def read_file_safe(
        self,
        path: Path,
        max_size: Optional[int] = None,
        encoding: str = "utf-8",
        errors: str = "ignore",
    ) -> Optional[str]:
        """Safely read a file with size limits."""
        try:
            # Check file size first
            stat_info = path.stat()
            max_size = max_size or self.max_file_size
            
            if stat_info.st_size > max_size:
                return None  # File too large
            
            with open(path, "r", encoding=encoding, errors=errors) as f:
                return f.read()
                
        except Exception:
            return None
