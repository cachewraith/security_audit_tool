"""Process information collector for local endpoint assessment."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class ProcessInfo:
    """Information about a running process."""
    pid: int
    name: str
    command: str
    user: str
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    status: str = "unknown"
    ppid: Optional[int] = None
    open_files: list[str] = field(default_factory=list)
    listening_ports: list[int] = field(default_factory=list)


class ProcessCollector:
    """Collects process information from /proc (Linux only, read-only)."""
    
    def __init__(self):
        self.proc_path = Path("/proc")
    
    def collect_all(self) -> list[ProcessInfo]:
        """Collect information about all running processes."""
        processes: list[ProcessInfo] = []
        
        if not self.proc_path.exists():
            return processes
        
        # Iterate through /proc/[pid] directories
        for entry in self.proc_path.iterdir():
            if not entry.name.isdigit():
                continue
            
            try:
                pid = int(entry.name)
                process = self._parse_process(pid)
                if process:
                    processes.append(process)
            except Exception:
                continue
        
        return processes
    
    def _parse_process(self, pid: int) -> Optional[ProcessInfo]:
        """Parse process information from /proc/[pid]."""
        proc_dir = self.proc_path / str(pid)
        
        if not proc_dir.exists():
            return None
        
        try:
            # Read status file
            status_info = self._read_status(pid)
            
            # Read cmdline
            cmdline = self._read_cmdline(pid)
            
            # Parse process info
            name = status_info.get("Name", "unknown")
            uid_line = status_info.get("Uid", "0")
            uid = int(uid_line.split()[0])
            
            # Convert UID to username (simplified)
            user = self._uid_to_username(uid)
            
            # Get parent PID
            ppid: Optional[int] = None
            ppid_str = status_info.get("PPid")
            if ppid_str:
                try:
                    ppid = int(ppid_str)
                except ValueError:
                    pass
            
            process = ProcessInfo(
                pid=pid,
                name=name,
                command=cmdline,
                user=user,
                status=status_info.get("State", "unknown").split()[0],
                ppid=ppid,
            )
            
            # Get listening ports for this process
            process.listening_ports = self._get_process_ports(pid)
            
            return process
            
        except (PermissionError, OSError):
            return None
        except Exception:
            return None
    
    def _read_status(self, pid: int) -> dict[str, str]:
        """Read /proc/[pid]/status file."""
        status_file = self.proc_path / str(pid) / "status"
        info: dict[str, str] = {}
        
        try:
            with open(status_file, "r") as f:
                for line in f:
                    if ":" in line:
                        key, value = line.split(":", 1)
                        info[key.strip()] = value.strip()
        except Exception:
            pass
        
        return info
    
    def _read_cmdline(self, pid: int) -> str:
        """Read /proc/[pid]/cmdline file."""
        cmdline_file = self.proc_path / str(pid) / "cmdline"
        
        try:
            with open(cmdline_file, "rb") as f:
                # cmdline uses null bytes as separators
                data = f.read()
                if not data:
                    # Kernel threads have empty cmdline
                    return f"[{self._read_status(pid).get('Name', 'kernel')}]"
                
                # Replace null bytes with spaces
                return data.replace(b"\x00", b" ").decode("utf-8", errors="ignore").strip()
        except Exception:
            return "unknown"
    
    def _uid_to_username(self, uid: int) -> str:
        """Convert UID to username (simplified)."""
        try:
            import pwd
            return pwd.getpwuid(uid).pw_name
        except (ImportError, KeyError):
            # Fallback for common UIDs
            if uid == 0:
                return "root"
            elif uid < 1000:
                return f"system-{uid}"
            else:
                return f"user-{uid}"
    
    def _get_process_ports(self, pid: int) -> list[int]:
        """Get listening ports for a process from /proc/[pid]/fd."""
        ports: list[int] = []
        
        fd_dir = self.proc_path / str(pid) / "fd"
        if not fd_dir.exists():
            return ports
        
        try:
            # This is complex in pure Python - simplified version
            # In practice, we'd parse /proc/net/tcp and match inodes
            pass
        except Exception:
            pass
        
        return ports
    
    def find_processes_by_name(self, name: str) -> list[ProcessInfo]:
        """Find processes matching a name pattern."""
        all_processes = self.collect_all()
        return [p for p in all_processes if name.lower() in p.name.lower()]
    
    def find_listening_processes(self) -> list[ProcessInfo]:
        """Find processes with listening network ports."""
        all_processes = self.collect_all()
        return [p for p in all_processes if p.listening_ports]
    
    def get_process_tree(self, pid: int) -> list[ProcessInfo]:
        """Get a process and all its descendants."""
        all_processes = self.collect_all()
        
        # Build tree
        children: dict[int, list[int]] = {}
        for p in all_processes:
            if p.ppid is not None:
                if p.ppid not in children:
                    children[p.ppid] = []
                children[p.ppid].append(p.pid)
        
        # Collect descendants
        result: list[ProcessInfo] = []
        to_process = [pid]
        processed: set[int] = set()
        
        pid_to_process = {p.pid: p for p in all_processes}
        
        while to_process:
            current = to_process.pop(0)
            if current in processed:
                continue
            processed.add(current)
            
            if current in pid_to_process:
                result.append(pid_to_process[current])
            
            # Add children
            for child_pid in children.get(current, []):
                if child_pid not in processed:
                    to_process.append(child_pid)
        
        return result
    
    def find_suspicious_processes(self) -> list[tuple[ProcessInfo, str]]:
        """Find potentially suspicious processes."""
        suspicious: list[tuple[ProcessInfo, str]] = []
        all_processes = self.collect_all()
        
        for process in all_processes:
            reasons: list[str] = []
            
            # Check for processes running as root
            if process.user == "root":
                # Only flag if also listening on network
                if process.listening_ports:
                    reasons.append(f"Root process listening on ports: {process.listening_ports}")
            
            # Check for processes in /tmp
            if "/tmp/" in process.command or "/var/tmp/" in process.command:
                reasons.append("Running from temp directory")
            
            # Check for hidden processes (name starts with .)
            if process.name.startswith("."):
                reasons.append("Hidden process name")
            
            if reasons:
                suspicious.append((process, "; ".join(reasons)))
        
        return suspicious
