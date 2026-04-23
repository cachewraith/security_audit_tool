"""System information collector for local endpoint assessment."""

import os
import platform
import sys
from dataclasses import dataclass, field
from typing import Optional
from pathlib import Path

from ..utils.subprocess_safe import run_safe, SafeSubprocessError


@dataclass
class SystemInfo:
    """System information data."""
    os_name: str
    os_version: str
    arch: str
    hostname: str
    python_version: str
    is_docker: bool = False
    is_wsl: bool = False
    is_vm: bool = False
    kernel_version: str = ""
    uptime: Optional[str] = None
    environment: dict = field(default_factory=dict)


class SystemInfoCollector:
    """Collects system information for security assessment."""
    
    def __init__(self):
        self.info: Optional[SystemInfo] = None
    
    def collect(self) -> SystemInfo:
        """Collect system information."""
        self.info = SystemInfo(
            os_name=platform.system(),
            os_version=platform.release(),
            arch=platform.machine(),
            hostname=platform.node(),
            python_version=platform.python_version(),
        )
        
        # Detect container/virtualization
        self.info.is_docker = self._detect_docker()
        self.info.is_wsl = self._detect_wsl()
        self.info.is_vm = self._detect_vm()
        
        # Get kernel version
        self.info.kernel_version = self._get_kernel_version()
        
        # Get uptime (Linux only)
        self.info.uptime = self._get_uptime()
        
        # Get relevant environment variables (non-sensitive)
        self.info.environment = self._get_safe_environment()
        
        return self.info
    
    def _detect_docker(self) -> bool:
        """Detect if running inside a Docker container."""
        # Check for .dockerenv file
        if Path("/.dockerenv").exists():
            return True
        
        # Check cgroup
        try:
            cgroup_path = Path("/proc/self/cgroup")
            if cgroup_path.exists():
                content = cgroup_path.read_text()
                if "docker" in content.lower():
                    return True
        except Exception:
            pass
        
        return False
    
    def _detect_wsl(self) -> bool:
        """Detect if running in Windows Subsystem for Linux."""
        try:
            if Path("/proc/sys/kernel/osrelease").exists():
                content = Path("/proc/sys/kernel/osrelease").read_text()
                if "microsoft" in content.lower() or "wsl" in content.lower():
                    return True
            
            # Alternative: check /proc/version
            if Path("/proc/version").exists():
                content = Path("/proc/version").read_text()
                if "microsoft" in content.lower():
                    return True
        except Exception:
            pass
        
        return False
    
    def _detect_vm(self) -> bool:
        """Detect if running in a virtual machine."""
        try:
            # Check for hypervisor flag in CPU info
            cpuinfo_path = Path("/proc/cpuinfo")
            if cpuinfo_path.exists():
                content = cpuinfo_path.read_text()
                if "hypervisor" in content.lower():
                    return True
            
            # Check for common VM signatures in product_name
            sys_vendor = Path("/sys/class/dmi/id/sys_vendor")
            product_name = Path("/sys/class/dmi/id/product_name")
            
            vm_signatures = [
                "vmware", "virtualbox", "kvm", "qemu", "xen",
                "parallels", "hyper-v", "microsoft corporation"
            ]
            
            for path in [sys_vendor, product_name]:
                if path.exists():
                    try:
                        content = path.read_text().strip().lower()
                        for sig in vm_signatures:
                            if sig in content:
                                return True
                    except Exception:
                        pass
        except Exception:
            pass
        
        return False
    
    def _get_kernel_version(self) -> str:
        """Get kernel version string."""
        try:
            result = run_safe(["uname", "-r"], capture_output=True)
            if result.returncode == 0:
                return result.stdout.strip()
        except (SafeSubprocessError, FileNotFoundError):
            pass
        
        return platform.release()
    
    def _get_uptime(self) -> Optional[str]:
        """Get system uptime."""
        try:
            if Path("/proc/uptime").exists():
                with open("/proc/uptime", "r") as f:
                    uptime_seconds = float(f.read().split()[0])
                    
                    days = int(uptime_seconds // 86400)
                    hours = int((uptime_seconds % 86400) // 3600)
                    minutes = int((uptime_seconds % 3600) // 60)
                    
                    if days > 0:
                        return f"{days}d {hours}h {minutes}m"
                    elif hours > 0:
                        return f"{hours}h {minutes}m"
                    else:
                        return f"{minutes}m"
        except Exception:
            pass
        
        return None
    
    def _get_safe_environment(self) -> dict:
        """Get non-sensitive environment variables."""
        safe_vars = [
            "PATH", "HOME", "USER", "SHELL", "LANG", "TERM",
            "EDITOR", "PAGER", "TZ", "DISPLAY", "XDG_SESSION_TYPE",
        ]
        
        env = {}
        for var in safe_vars:
            value = os.environ.get(var)
            if value:
                # Truncate long values
                if len(value) > 200:
                    value = value[:200] + "..."
                env[var] = value
        
        return env
    
    def get_system_summary(self) -> dict:
        """Get a summary of system information."""
        if not self.info:
            self.collect()
        
        summary = {
            "os": f"{self.info.os_name} {self.info.os_version}",
            "architecture": self.info.arch,
            "hostname": self.info.hostname,
            "python": self.info.python_version,
        }
        
        if self.info.is_docker:
            summary["environment"] = "Docker"
        elif self.info.is_wsl:
            summary["environment"] = "WSL"
        elif self.info.is_vm:
            summary["environment"] = "Virtual Machine"
        else:
            summary["environment"] = "Physical"
        
        if self.info.uptime:
            summary["uptime"] = self.info.uptime
        
        return summary
