"""Service and port security checks."""

from pathlib import Path

from .base import BaseCheck, CheckResult
from ..collectors.network import NetworkCollector
from ..models import SeverityLevel, ConfidenceLevel, Category


class ServicesCheck(BaseCheck):
    """Check running services and listening ports for security issues."""
    
    check_id = "services"
    check_name = "Running Services and Ports"
    category = Category.SERVICES
    
    # Ports that should generally not be exposed
    DANGEROUS_PORTS = {
        21: ("FTP", SeverityLevel.MEDIUM, "Unencrypted file transfer - use SFTP/SCP instead"),
        23: ("Telnet", SeverityLevel.HIGH, "Unencrypted remote shell - use SSH instead"),
        25: ("SMTP", SeverityLevel.LOW, "Mail server - verify configuration"),
        53: ("DNS", SeverityLevel.LOW, "DNS server - verify recursion settings"),
        110: ("POP3", SeverityLevel.MEDIUM, "Unencrypted mail - use POP3S"),
        143: ("IMAP", SeverityLevel.MEDIUM, "Unencrypted mail - use IMAPS"),
        445: ("SMB", SeverityLevel.MEDIUM, "Windows file sharing - limit to internal networks"),
        3306: ("MySQL", SeverityLevel.MEDIUM, "Database - should not be exposed publicly"),
        3389: ("RDP", SeverityLevel.HIGH, "Remote Desktop - restrict access"),
        5432: ("PostgreSQL", SeverityLevel.MEDIUM, "Database - should not be exposed publicly"),
        6379: ("Redis", SeverityLevel.HIGH, "In-memory store - should not be exposed without auth"),
        9200: ("Elasticsearch", SeverityLevel.HIGH, "Search engine - should not be exposed without auth"),
        27017: ("MongoDB", SeverityLevel.HIGH, "Database - should not be exposed without auth"),
        5601: ("Kibana", SeverityLevel.MEDIUM, "Dashboard - should not be exposed publicly"),
    }
    
    # Services that shouldn't run as root
    SERVICES_NO_ROOT = [
        "nginx", "apache2", "httpd", "mysql", "mariadb", "postgres",
        "redis-server", "mongodb", "elasticsearch",
    ]
    
    def run(self) -> CheckResult:
        """Execute service checks."""
        result = self._create_result()
        
        # Only run on local endpoint
        if not self.scope.local_endpoint:
            return self._finish_result(result)
        
        collector = NetworkCollector(
            connection_timeout=self.config.rate_limit.connection_timeout,
            requests_per_second=self.config.rate_limit.requests_per_second,
        )
        
        # Check listening ports
        self._check_listening_ports(collector, result)
        
        # Check for banner information (if enabled)
        if self.config.check.enable_banner_grabbing:
            self._check_service_banners(collector, result)
        
        return self._finish_result(result)
    
    def _check_listening_ports(self, collector: NetworkCollector, result: CheckResult) -> None:
        """Check for listening ports and their security implications."""
        try:
            ports = collector.get_listening_ports()
            
            for port_info in ports:
                port = port_info.port
                
                # Check if it's a known dangerous port
                if port in self.DANGEROUS_PORTS:
                    service, severity, recommendation = self.DANGEROUS_PORTS[port]
                    
                    finding = self._create_finding(
                        title=f"Potentially risky service listening: {service}",
                        severity=severity,
                        target=f"0.0.0.0:{port}",
                        evidence=f"Port {port} ({service}) is listening on all interfaces",
                        remediation=recommendation,
                        confidence=ConfidenceLevel.CERTAIN,
                        references=["https://cisecurity.org/cis-benchmarks/"],
                        metadata={
                            "port": port,
                            "service": service,
                            "protocol": port_info.protocol,
                        },
                    )
                    result.findings.append(finding)
                
                # Check for unencrypted services
                unencrypted_services = [21, 23, 25, 110, 143, 993, 995]
                if port in unencrypted_services:
                    encrypted_alternatives = {
                        21: "SFTP/SCP",
                        23: "SSH",
                        110: "POP3S (995)",
                        143: "IMAPS (993)",
                    }
                    alt = encrypted_alternatives.get(port, "encrypted alternative")
                    
                    finding = self._create_finding(
                        title="Unencrypted service detected",
                        severity=SeverityLevel.MEDIUM,
                        target=f"port {port}",
                        evidence=f"Unencrypted protocol on port {port}",
                        remediation=f"Use {alt} instead",
                        confidence=ConfidenceLevel.CERTAIN,
                        references=["https://wiki.mozilla.org/Security/Server_Side_TLS"],
                    )
                    result.findings.append(finding)
                
                # Flag high ports with potential services
                if port > 1024 and port_info.service != "unknown":
                    # Non-privileged ports running services
                    finding = self._create_finding(
                        title=f"Service running on non-privileged port: {port_info.service}",
                        severity=SeverityLevel.INFO,
                        target=f"port {port}",
                        evidence=f"{port_info.service} listening on port {port}",
                        remediation="Ensure service is properly firewalled if not publicly needed",
                        confidence=ConfidenceLevel.MEDIUM,
                    )
                    result.findings.append(finding)
                    
        except Exception as e:
            self._log_error("Error checking listening ports", e)
    
    def _check_service_banners(self, collector: NetworkCollector, result: CheckResult) -> None:
        """Check service banners for information disclosure (opt-in)."""
        # Only check localhost
        localhost_ports = [22, 80, 443]
        
        for port in localhost_ports:
            try:
                banner = collector.grab_banner("127.0.0.1", port)
                
                if banner and banner.banner:
                    # Check for version information disclosure
                    version_indicators = ["version", "openssh", "apache", "nginx"]
                    banner_lower = banner.banner.lower()
                    
                    if any(indicator in banner_lower for indicator in version_indicators):
                        finding = self._create_finding(
                            title="Service banner reveals version information",
                            severity=SeverityLevel.LOW,
                            target=f"127.0.0.1:{port}",
                            evidence=f"Banner: {banner.banner[:100]}",
                            remediation="Configure service to hide version information",
                            confidence=ConfidenceLevel.CERTAIN,
                            references=["https://wiki.mozilla.org/Security/Server_Side_TLS"],
                        )
                        result.findings.append(finding)
                        
            except Exception as e:
                self._log_error(f"Error grabbing banner from port {port}", e)
    
    def _check_process_privileges(self, result: CheckResult) -> None:
        """Check if services are running with appropriate privileges."""
        # This would integrate with ProcessCollector
        # For now, this is a placeholder
        pass
    
    @classmethod
    def get_description(cls) -> str:
        return """
        Checks running services and listening ports:
        - Detects listening services on the local system
        - Identifies potentially dangerous exposed services
        - Flags unencrypted protocols
        - Checks for version information disclosure (opt-in)
        """
    
    @classmethod
    def get_requirements(cls) -> list[str]:
        return ["Read access to /proc/net/tcp and /proc/net/tcp6"]
