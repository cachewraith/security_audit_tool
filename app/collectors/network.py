"""Network data collector for safe network checks."""

import socket
import ssl
from dataclasses import dataclass
from typing import Optional, Iterator
from pathlib import Path

from ..utils.rate_limiter import RateLimiter
from ..utils.timeouts import TimeoutManager


@dataclass
class PortInfo:
    """Information about a listening port."""
    port: int
    protocol: str
    state: str
    service: str
    pid: Optional[int] = None
    program: Optional[str] = None


@dataclass
class TLSInfo:
    """TLS/SSL certificate information."""
    host: str
    port: int
    protocol_version: Optional[str] = None
    cipher_suite: Optional[str] = None
    certificate_valid: bool = False
    certificate_expires: Optional[str] = None
    certificate_issuer: Optional[str] = None
    certificate_subject: Optional[str] = None
    certificate_days_remaining: Optional[int] = None
    errors: list[str] = None
    
    def __post_init__(self):
        if self.errors is None:
            self.errors = []


@dataclass
class ServiceBanner:
    """Service banner information."""
    host: str
    port: int
    banner: str
    service_type: Optional[str] = None


class NetworkCollector:
    """Collects network information for security assessment."""
    
    def __init__(
        self,
        connection_timeout: float = 5.0,
        read_timeout: float = 10.0,
        requests_per_second: float = 10.0,
        max_concurrent: int = 5,
    ):
        self.timeout_manager = TimeoutManager(
            connection_timeout=connection_timeout,
            read_timeout=read_timeout,
        )
        self.rate_limiter = RateLimiter(requests_per_second)
        self.max_concurrent = max_concurrent
    
    def get_listening_ports(self) -> list[PortInfo]:
        """Get list of listening ports on the local system.
        
        This uses /proc/net/tcp and /proc/net/tcp6 for safe read-only access.
        """
        ports: list[PortInfo] = []
        
        try:
            # Read TCP listening sockets
            ports.extend(self._parse_proc_net_tcp("/proc/net/tcp"))
            ports.extend(self._parse_proc_net_tcp("/proc/net/tcp6"))
        except Exception:
            pass
        
        return ports
    
    def _parse_proc_net_tcp(self, path: str) -> list[PortInfo]:
        """Parse /proc/net/tcp or /proc/net/tcp6 for listening ports."""
        ports: list[PortInfo] = []
        
        proc_file = Path(path)
        if not proc_file.exists():
            return ports
        
        try:
            with open(proc_file, "r") as f:
                lines = f.readlines()
            
            # Skip header line
            for line in lines[1:]:
                parts = line.split()
                if len(parts) < 4:
                    continue
                
                # Check if listening state (0A = TCP_LISTEN)
                state = parts[3]
                if state != "0A":
                    continue
                
                # Parse local address
                local_addr = parts[1]
                if ":" not in local_addr:
                    continue
                
                _, port_hex = local_addr.rsplit(":", 1)
                port = int(port_hex, 16)
                
                # Try to identify service
                service = self._identify_service(port)
                
                ports.append(PortInfo(
                    port=port,
                    protocol="tcp",
                    state="LISTEN",
                    service=service,
                ))
        
        except Exception:
            pass
        
        return ports
    
    def _identify_service(self, port: int) -> str:
        """Identify service name from port number."""
        common_ports = {
            21: "ftp",
            22: "ssh",
            23: "telnet",
            25: "smtp",
            53: "dns",
            80: "http",
            110: "pop3",
            143: "imap",
            443: "https",
            445: "smb",
            993: "imaps",
            995: "pop3s",
            3306: "mysql",
            3389: "rdp",
            5432: "postgresql",
            6379: "redis",
            8080: "http-alt",
            8443: "https-alt",
            9200: "elasticsearch",
            27017: "mongodb",
        }
        
        return common_ports.get(port, "unknown")
    
    def check_port_open(
        self,
        host: str,
        port: int,
        timeout: Optional[float] = None,
    ) -> bool:
        """Check if a port is open on a remote host.
        
        This performs a simple TCP connection check - no exploitation.
        """
        self.rate_limiter.wait()
        
        timeout = timeout or self.timeout_manager.connection_timeout
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except socket.timeout:
            return False
        except Exception:
            return False
    
    def grab_banner(
        self,
        host: str,
        port: int,
        timeout: Optional[float] = None,
    ) -> Optional[ServiceBanner]:
        """Safely grab service banner from an open port.
        
        Sends minimal data and reads response - no exploitation.
        """
        self.rate_limiter.wait()
        
        timeout = timeout or self.timeout_manager.read_timeout
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            
            # Try to trigger a response
            # Send a simple newline or protocol-specific probe
            probes = [b"\r\n", b"HEAD / HTTP/1.0\r\n\r\n", b"\x00"]
            
            banner = ""
            for probe in probes:
                try:
                    sock.send(probe)
                    data = sock.recv(1024)
                    if data:
                        banner = data.decode("utf-8", errors="ignore").strip()
                        break
                except Exception:
                    continue
            
            sock.close()
            
            if banner:
                service_type = self._guess_service_from_banner(banner)
                return ServiceBanner(
                    host=host,
                    port=port,
                    banner=banner[:500],  # Limit size
                    service_type=service_type,
                )
            
        except Exception:
            pass
        
        return None
    
    def _guess_service_from_banner(self, banner: str) -> Optional[str]:
        """Guess service type from banner content."""
        banner_lower = banner.lower()
        
        if "ssh" in banner_lower:
            return "ssh"
        elif "http" in banner_lower or "html" in banner_lower:
            return "http"
        elif "ftp" in banner_lower:
            return "ftp"
        elif "smtp" in banner_lower:
            return "smtp"
        elif "mysql" in banner_lower:
            return "mysql"
        elif "postgres" in banner_lower:
            return "postgresql"
        
        return None
    
    def check_tls_certificate(
        self,
        host: str,
        port: int = 443,
        timeout: Optional[float] = None,
    ) -> TLSInfo:
        """Check TLS certificate information."""
        self.rate_limiter.wait()
        
        info = TLSInfo(host=host, port=port)
        timeout = timeout or self.timeout_manager.connection_timeout
        
        try:
            context = ssl.create_default_context()
            
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    # Get certificate info
                    cert = ssock.getpeercert()
                    version = ssock.version()
                    cipher = ssock.cipher()
                    
                    info.protocol_version = version
                    info.cipher_suite = cipher[0] if cipher else None
                    
                    if cert:
                        import datetime
                        
                        info.certificate_valid = True
                        info.certificate_issuer = str(cert.get("issuer"))
                        info.certificate_subject = str(cert.get("subject"))
                        
                        # Parse expiration
                        not_after = cert.get("notAfter")
                        if not_after:
                            info.certificate_expires = not_after
                            
                            # Calculate days remaining
                            try:
                                expire_date = datetime.datetime.strptime(
                                    not_after, "%b %d %H:%M:%S %Y %Z"
                                )
                                now = datetime.datetime.utcnow()
                                info.certificate_days_remaining = (expire_date - now).days
                            except Exception:
                                pass
                    
                    # Check for weak protocols
                    if version in ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]:
                        info.errors.append(f"Weak TLS version: {version}")
        
        except ssl.SSLError as e:
            info.errors.append(f"SSL Error: {e}")
        except socket.timeout:
            info.errors.append("Connection timeout")
        except Exception as e:
            info.errors.append(f"Error: {e}")
        
        return info
    
    def scan_common_ports(
        self,
        host: str,
        ports: Optional[list[int]] = None,
    ) -> Iterator[PortInfo]:
        """Scan common ports on a host."""
        common_ports = ports or [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443]
        
        for port in common_ports:
            if self.check_port_open(host, port):
                yield PortInfo(
                    port=port,
                    protocol="tcp",
                    state="OPEN",
                    service=self._identify_service(port),
                )
