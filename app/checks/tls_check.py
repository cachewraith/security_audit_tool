"""TLS/SSL certificate and configuration checks.

IMPORTANT: These checks are OPT-IN (--enable-tls-checks) and only check
certificates and configurations for explicitly allowed hosts.
No exploit attempts are made.
"""

from .base import BaseCheck, CheckResult
from ..collectors.network import NetworkCollector
from ..models import SeverityLevel, ConfidenceLevel, Category


class TLSCheck(BaseCheck):
    """Check TLS/SSL certificates and configuration.
    
    This check is disabled by default and requires explicit opt-in.
    It only performs certificate inspection and configuration analysis.
    No exploit attempts or vulnerability testing is performed.
    """
    
    check_id = "tls"
    check_name = "TLS/SSL Certificate Check"
    category = Category.TLS
    
    # Weak cipher suites and protocols
    WEAK_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]
    
    # Certificate warning thresholds (days)
    EXPIRY_WARNING_DAYS = 30
    EXPIRY_CRITICAL_DAYS = 7
    
    def run(self) -> CheckResult:
        """Execute TLS certificate checks."""
        result = self._create_result()
        
        # Only run if enabled and there are hosts in scope
        if not self.config.check.tls_check:
            return self._finish_result(result)
        
        if not self.scope.allowed_hosts:
            return self._finish_result(result)
        
        collector = NetworkCollector(
            connection_timeout=self.config.rate_limit.connection_timeout,
            requests_per_second=self.config.rate_limit.requests_per_second,
        )
        
        for host in self.scope.allowed_hosts:
            # Skip wildcard patterns
            if "*" in host:
                continue
            
            # Skip CIDR notation
            if "/" in host:
                continue
            
            self._check_host_tls(host, collector, result)
        
        return self._finish_result(result)
    
    def _check_host_tls(
        self,
        host: str,
        collector: NetworkCollector,
        result: CheckResult,
    ) -> None:
        """Check TLS configuration for a specific host."""
        # Check standard HTTPS port
        ports = [443]
        
        for port in ports:
            try:
                tls_info = collector.check_tls_certificate(host, port)
                
                # Report connection errors
                if tls_info.errors:
                    for error in tls_info.errors:
                        if "Weak TLS version" in error:
                            # Extract version from error
                            version = error.split(":")[-1].strip()
                            finding = self._create_finding(
                                title=f"Weak TLS protocol version: {version}",
                                severity=SeverityLevel.HIGH,
                                target=f"{host}:{port}",
                                evidence=f"Server supports deprecated TLS version: {version}",
                                remediation="Disable support for TLS 1.0 and TLS 1.1; use TLS 1.2 or higher",
                                confidence=ConfidenceLevel.CERTAIN,
                                references=[
                                    "https://tools.ietf.org/html/rfc8996",
                                    "https://wiki.mozilla.org/Security/Server_Side_TLS",
                                ],
                            )
                            result.findings.append(finding)
                        elif "Connection" not in error and "timeout" not in error.lower():
                            # Don't report expected connection issues
                            finding = self._create_finding(
                                title="TLS certificate check encountered an error",
                                severity=SeverityLevel.INFO,
                                target=f"{host}:{port}",
                                evidence=error,
                                remediation="Verify TLS service is properly configured",
                                confidence=ConfidenceLevel.LOW,
                            )
                            result.findings.append(finding)
                
                # Check certificate validity
                if tls_info.certificate_valid:
                    self._check_certificate_validity(tls_info, host, port, result)
                    
            except Exception as e:
                self._log_error(f"Error checking TLS for {host}:{port}", e)
    
    def _check_certificate_validity(
        self,
        tls_info: "TLSInfo",
        host: str,
        port: int,
        result: CheckResult,
    ) -> None:
        """Check certificate validity and expiration."""
        # Check expiration
        if tls_info.certificate_days_remaining is not None:
            days = tls_info.certificate_days_remaining
            
            if days < 0:
                finding = self._create_finding(
                    title="TLS certificate has expired",
                    severity=SeverityLevel.CRITICAL,
                    target=f"{host}:{port}",
                    evidence=f"Certificate expired {-days} days ago",
                    remediation="Renew and replace the TLS certificate immediately",
                    confidence=ConfidenceLevel.CERTAIN,
                    references=["https://letsencrypt.org/getting-started/"],
                    metadata={
                        "days_remaining": days,
                        "expires": tls_info.certificate_expires,
                    },
                )
                result.findings.append(finding)
            
            elif days < self.EXPIRY_CRITICAL_DAYS:
                finding = self._create_finding(
                    title="TLS certificate expiring very soon",
                    severity=SeverityLevel.CRITICAL,
                    target=f"{host}:{port}",
                    evidence=f"Certificate expires in {days} days",
                    remediation="Renew and replace the TLS certificate immediately",
                    confidence=ConfidenceLevel.CERTAIN,
                    references=["https://letsencrypt.org/getting-started/"],
                    metadata={
                        "days_remaining": days,
                        "expires": tls_info.certificate_expires,
                    },
                )
                result.findings.append(finding)
            
            elif days < self.EXPIRY_WARNING_DAYS:
                finding = self._create_finding(
                    title="TLS certificate expiring soon",
                    severity=SeverityLevel.MEDIUM,
                    target=f"{host}:{port}",
                    evidence=f"Certificate expires in {days} days",
                    remediation="Schedule certificate renewal",
                    confidence=ConfidenceLevel.CERTAIN,
                    references=["https://letsencrypt.org/getting-started/"],
                    metadata={
                        "days_remaining": days,
                        "expires": tls_info.certificate_expires,
                    },
                )
                result.findings.append(finding)
        
        # Check protocol version
        if tls_info.protocol_version in self.WEAK_PROTOCOLS:
            finding = self._create_finding(
                title=f"Weak TLS protocol in use: {tls_info.protocol_version}",
                severity=SeverityLevel.HIGH,
                target=f"{host}:{port}",
                evidence=f"Server negotiated {tls_info.protocol_version}",
                remediation="Configure server to disable TLS 1.0 and 1.1; require TLS 1.2 or higher",
                confidence=ConfidenceLevel.CERTAIN,
                references=[
                    "https://tools.ietf.org/html/rfc8996",
                    "https://ssl-config.mozilla.org/",
                ],
                metadata={
                    "protocol": tls_info.protocol_version,
                    "cipher": tls_info.cipher_suite,
                },
            )
            result.findings.append(finding)
        
        # Check cipher suite
        if tls_info.cipher_suite:
            weak_ciphers = ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT"]
            cipher_upper = tls_info.cipher_suite.upper()
            
            for weak in weak_ciphers:
                if weak in cipher_upper:
                    finding = self._create_finding(
                        title=f"Weak cipher suite detected: {tls_info.cipher_suite}",
                        severity=SeverityLevel.HIGH,
                        target=f"{host}:{port}",
                        evidence=f"Server supports weak cipher: {tls_info.cipher_suite}",
                        remediation="Configure server to use only strong cipher suites",
                        confidence=ConfidenceLevel.CERTAIN,
                        references=["https://wiki.mozilla.org/Security/Server_Side_TLS"],
                    )
                    result.findings.append(finding)
                    break
        
        # Check issuer
        if tls_info.certificate_issuer:
            # Flag self-signed or untrusted issuers
            issuer_lower = tls_info.certificate_issuer.lower()
            if "self-signed" in issuer_lower or tls_info.certificate_issuer == tls_info.certificate_subject:
                finding = self._create_finding(
                    title="Self-signed certificate detected",
                    severity=SeverityLevel.MEDIUM,
                    target=f"{host}:{port}",
                    evidence="Certificate is self-signed",
                    remediation="Use a certificate from a trusted CA (Let's Encrypt, etc.)",
                    confidence=ConfidenceLevel.CERTAIN,
                    references=["https://letsencrypt.org/getting-started/"],
                )
                result.findings.append(finding)
    
    @classmethod
    def get_description(cls) -> str:
        return """
        Checks TLS/SSL certificates and configuration (opt-in):
        - Certificate expiration dates
        - TLS protocol version (flags TLS 1.0/1.1)
        - Cipher suite strength
        - Self-signed certificates
        
        IMPORTANT: This check is DISABLED by default. Enable with --enable-tls-checks.
        Only checks explicitly allowed hosts defined in scope.
        """
    
    @classmethod
    def get_requirements(cls) -> list[str]:
        return [
            "Network access to target hosts",
            "SSL/TLS certificate must be accessible",
        ]
