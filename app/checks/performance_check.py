"""Performance and load testing check."""

import time
import statistics
from typing import Optional
from urllib.parse import urlparse

import urllib.request
import urllib.error
import ssl

from .base import BaseCheck, CheckResult
from ..models import SeverityLevel, ConfidenceLevel, Category, Finding


class PerformanceCheck(BaseCheck):
    """Performance testing: response times, load capacity."""

    check_id = "performance"
    check_name = "Performance Test"
    category = Category.NETWORK
    description = "Tests website performance and response times"

    def run(self) -> CheckResult:
        """Run performance tests."""
        result = self._create_result()

        # Get target hosts from scope
        hosts = self.scope.allowed_hosts

        for host in hosts:
            self._test_host_performance(host, result)

        return self._finish_result(result)

    def _test_host_performance(self, host: str, result: CheckResult) -> None:
        """Test performance for a single host."""
        # Build URL
        url = f"https://{host}" if not host.startswith(('http://', 'https://')) else host

        # Test response time
        response_times = []
        errors = []

        # Make multiple requests
        for i in range(5):
            try:
                start = time.time()
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

                req = urllib.request.Request(
                    url,
                    headers={'User-Agent': 'SecurityAudit-PerformanceTest/1.0'},
                    method='GET'
                )

                with urllib.request.urlopen(req, timeout=10, context=ctx) as response:
                    _ = response.read()
                    elapsed = time.time() - start
                    response_times.append(elapsed)

            except Exception as e:
                errors.append(str(e))

        # Analyze results
        if response_times:
            avg_time = statistics.mean(response_times)
            max_time = max(response_times)
            min_time = min(response_times)

            # Determine severity based on response time
            severity = SeverityLevel.INFO
            if avg_time > 5.0:
                severity = SeverityLevel.HIGH
            elif avg_time > 2.0:
                severity = SeverityLevel.MEDIUM
            elif avg_time > 1.0:
                severity = SeverityLevel.LOW

            finding = self._create_finding(
                title=f"Performance Test: {host}",
                severity=severity,
                target=host,
                evidence=f"Avg: {avg_time:.2f}s, Min: {min_time:.2f}s, Max: {max_time:.2f}s, Requests: {len(response_times)}",
                remediation="Optimize server response time. Consider CDN, caching, or server upgrades." if severity != SeverityLevel.INFO else "Performance is acceptable.",
                confidence=ConfidenceLevel.HIGH,
            )
            result.findings.append(finding)

        if errors:
            finding = self._create_finding(
                title=f"Connection Errors: {host}",
                severity=SeverityLevel.MEDIUM,
                target=host,
                evidence=f"Errors: {len(errors)}, Examples: {errors[:2]}",
                remediation="Check server availability and network connectivity.",
                confidence=ConfidenceLevel.MEDIUM,
            )
            result.findings.append(finding)
