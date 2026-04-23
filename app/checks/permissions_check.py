"""File and directory permission security checks."""

import stat
from pathlib import Path
from typing import Optional

from .base import BaseCheck, CheckResult
from ..collectors.filesystem import FilesystemCollector, FileInfo
from ..models import SeverityLevel, ConfidenceLevel, Category


class PermissionsCheck(BaseCheck):
    """Check file and directory permissions for security issues."""
    
    check_id = "permissions"
    check_name = "File and Directory Permissions"
    category = Category.PERMISSIONS
    
    # Sensitive paths to check
    SENSITIVE_PATHS = [
        Path("/etc"),
        Path("/var/log"),
        Path("/tmp"),
        Path("/var/tmp"),
        Path("/home"),
        Path("/root"),
    ]
    
    # SUID/SGID binaries that are commonly problematic
    KNOWN_SENSITIVE_SUIDS = [
        "mount", "umount", "su", "sudo", "passwd", "chsh", "chfn",
        "newgrp", "gpasswd", "wall", "write", "locate", "slock",
    ]
    
    def run(self) -> CheckResult:
        """Execute permission checks."""
        result = self._create_result()
        
        collector = FilesystemCollector(
            max_depth=self.scope.max_depth,
            follow_symlinks=False,
            exclude_patterns=self.scope.exclude_paths,
        )
        
        # Check world-writable files in sensitive paths
        if self.config.check.check_world_writable:
            self._check_world_writable(collector, result)
        
        # Check SUID/SGID binaries
        if self.config.check.check_suid_sgid:
            self._check_suid_sgid(collector, result)
        
        # Check sensitive files in project paths
        self._check_project_permissions(collector, result)
        
        return self._finish_result(result)
    
    def _check_world_writable(self, collector: FilesystemCollector, result: CheckResult) -> None:
        """Check for world-writable files."""
        paths_to_check: list[Path] = []
        
        # Add local endpoint paths if enabled
        if self.scope.local_endpoint:
            for path in self.SENSITIVE_PATHS:
                if path.exists():
                    paths_to_check.append(path)
        
        # Add project paths
        for project_path in self.scope.project_paths:
            paths_to_check.append(project_path)
        
        for path in paths_to_check:
            try:
                world_writable = collector.find_world_writable_files(path)
                
                for file_info in world_writable[:20]:  # Limit results
                    # Skip directories (sticky bit handling)
                    if file_info.is_dir:
                        continue
                    
                    severity = SeverityLevel.HIGH if "/etc/" in str(file_info.path) else SeverityLevel.MEDIUM
                    
                    finding = self._create_finding(
                        title="World-writable file found",
                        severity=severity,
                        target=str(file_info.path),
                        evidence=f"File permissions: {file_info.permissions} (mode: {oct(file_info.mode)})",
                        remediation="Remove world-writable permission: chmod o-w <file>",
                        confidence=ConfidenceLevel.CERTAIN,
                        references=["https://wiki.debian.org/Permissions"],
                    )
                    result.findings.append(finding)
                    
            except Exception as e:
                self._log_error(f"Error checking world-writable files in {path}", e)
    
    def _check_suid_sgid(self, collector: FilesystemCollector, result: CheckResult) -> None:
        """Check for SUID/SGID binaries."""
        # Only check system paths if local endpoint enabled
        if not self.scope.local_endpoint:
            return
        
        system_paths = [
            Path("/bin"),
            Path("/sbin"),
            Path("/usr/bin"),
            Path("/usr/sbin"),
            Path("/usr/local/bin"),
            Path("/usr/local/sbin"),
        ]
        
        for path in system_paths:
            if not path.exists():
                continue
            
            try:
                suid_files = collector.find_suid_sgid_files(path)
                
                for file_info in suid_files:
                    severity = SeverityLevel.LOW
                    confidence = ConfidenceLevel.HIGH
                    
                    # Check if it's a known sensitive binary
                    if file_info.path.name in self.KNOWN_SENSITIVE_SUIDS:
                        severity = SeverityLevel.INFO
                        confidence = ConfidenceLevel.CERTAIN
                    
                    # Unknown SUID binary is more concerning
                    if file_info.path.stat().st_uid == 0:
                        evidence = f"SUID binary owned by root: {file_info.permissions}"
                        if file_info.has_sgid:
                            evidence += " (also has SGID)"
                        
                        finding = self._create_finding(
                            title="SUID binary detected",
                            severity=severity,
                            target=str(file_info.path),
                            evidence=evidence,
                            remediation="Review if SUID bit is necessary; use sudo where possible",
                            confidence=confidence,
                            references=["https://www.redhat.com/sysadmin/suid-sgid-sticky-bit"],
                            metadata={
                                "owner_uid": file_info.uid,
                                "has_suid": file_info.has_suid,
                                "has_sgid": file_info.has_sgid,
                            },
                        )
                        result.findings.append(finding)
                        
            except Exception as e:
                self._log_error(f"Error checking SUID files in {path}", e)
    
    def _check_project_permissions(self, collector: FilesystemCollector, result: CheckResult) -> None:
        """Check permissions in project directories."""
        dangerous_patterns = [
            "*.pem", "*.key", "*.crt", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
            ".env", ".env.local", ".env.production",
        ]
        
        for project_path in self.scope.project_paths:
            try:
                scan_result = collector.scan_directory(project_path)
                
                for file_info in scan_result.files_found:
                    # Check for overly permissive sensitive files
                    if any(file_info.path.match(pattern) for pattern in dangerous_patterns):
                        if file_info.is_world_readable or file_info.is_world_writable:
                            finding = self._create_finding(
                                title="Sensitive file with dangerous permissions",
                                severity=SeverityLevel.HIGH,
                                target=str(file_info.path),
                                evidence=f"Permissions: {file_info.permissions} - sensitive file is accessible to other users",
                                remediation="Restrict permissions: chmod 600 <file>",
                                confidence=ConfidenceLevel.CERTAIN,
                                references=["https://wiki.debian.org/Permissions"],
                            )
                            result.findings.append(finding)
                    
                    # Check for executable files in upload directories
                    if "/uploads/" in str(file_info.path) or "/media/" in str(file_info.path):
                        if file_info.is_world_executable and file_info.is_file:
                            finding = self._create_finding(
                                title="Executable file in upload directory",
                                severity=SeverityLevel.HIGH,
                                target=str(file_info.path),
                                evidence=f"File is executable in potential upload directory: {file_info.permissions}",
                                remediation="Remove execute permission: chmod -x <file>",
                                confidence=ConfidenceLevel.MEDIUM,
                            )
                            result.findings.append(finding)
                            
            except Exception as e:
                self._log_error(f"Error checking project permissions in {project_path}", e)
    
    @classmethod
    def get_description(cls) -> str:
        return """
        Checks file and directory permissions for security issues:
        - World-writable files in sensitive locations
        - SUID/SGID binaries
        - Overly permissive sensitive files (keys, certs, .env files)
        - Executable files in upload directories
        """
    
    @classmethod
    def get_requirements(cls) -> list[str]:
        return ["Read access to target directories"]
