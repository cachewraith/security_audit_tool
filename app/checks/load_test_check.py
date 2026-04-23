"""Load testing and DDoS simulation check."""

import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional
import urllib.request
import urllib.error
import ssl

from .base import BaseCheck, CheckResult
from ..models import SeverityLevel, ConfidenceLevel, Category, Finding


class LoadTestCheck(BaseCheck):
    """Load testing: Simulates multiple concurrent users."""

    check_id = "load_test"
    check_name = "Load Test"
    category = Category.NETWORK
    description = "Tests server capacity under load (controlled test)"

    def run(self) -> CheckResult:
        """Run load tests."""
        result = self._create_result()

        hosts = self.scope.allowed_hosts
        config = self.config

        # Get load test settings from config or use safe defaults
        concurrent_users = getattr(config, 'load_test_concurrent', 10)
        requests_per_user = getattr(config, 'load_test_requests', 5)
        max_duration = getattr(config, 'load_test_duration', 30)

        for host in hosts:
            self._load_test_host(
                host, result,
                concurrent_users=concurrent_users,
                requests_per_user=requests_per_user,
                max_duration=max_duration
            )

        return self._finish_result(result)

    def _load_test_host(
        self,
        host: str,
        result: CheckResult,
        concurrent_users: int = 10,
        requests_per_user: int = 5,
        max_duration: int = 30
    ) -> None:
        """Run load test against a host."""
        url = f"https://{host}" if not host.startswith(('http://', 'https://')) else host

        results = {
            'successful': 0,
            'failed': 0,
            'response_times': [],
            'errors': []
        }
        lock = threading.Lock()

        def make_request(user_id: int, req_num: int) -> Optional[float]:
            """Make a single request, return response time or None."""
            try:
                start = time.time()
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

                req = urllib.request.Request(
                    url,
                    headers={'User-Agent': f'SecurityAudit-LoadTest/1.0 (User-{user_id})'},
                    method='GET'
                )

                with urllib.request.urlopen(req, timeout=10, context=ctx) as response:
                    _ = response.read()
                    elapsed = time.time() - start

                    with lock:
                        results['successful'] += 1
                        results['response_times'].append(elapsed)
                    return elapsed

            except Exception as e:
                with lock:
                    results['failed'] += 1
                    if len(results['errors']) < 10:
                        results['errors'].append(str(e))
                return None

        start_time = time.time()

        # Run concurrent requests
        with ThreadPoolExecutor(max_workers=concurrent_users) as executor:
            futures = []
            for user in range(concurrent_users):
                for req in range(requests_per_user):
                    # Check time limit
                    if time.time() - start_time > max_duration:
                        break
                    future = executor.submit(make_request, user, req)
                    futures.append(future)

            # Wait for completion with timeout
            completed = 0
            for future in as_completed(futures, timeout=max_duration + 5):
                try:
                    future.result()
                    completed += 1
                except Exception:
                    pass

        total_time = time.time() - start_time

        # Analyze results
        total_requests = results['successful'] + results['failed']
        success_rate = (results['successful'] / total_requests * 100) if total_requests > 0 else 0

        avg_response = 0
        if results['response_times']:
            avg_response = sum(results['response_times']) / len(results['response_times'])

        # Determine if server handled load well
        severity = SeverityLevel.INFO
        if success_rate < 50:
            severity = SeverityLevel.CRITICAL
        elif success_rate < 80:
            severity = SeverityLevel.HIGH
        elif avg_response > 3.0:
            severity = SeverityLevel.MEDIUM

        finding = self._create_finding(
            title=f"Load Test Results: {host}",
            severity=severity,
            target=host,
            evidence=(
                f"Concurrent users: {concurrent_users}, "
                f"Total requests: {total_requests}, "
                f"Success: {results['successful']}, "
                f"Failed: {results['failed']}, "
                f"Success rate: {success_rate:.1f}%, "
                f"Avg response: {avg_response:.2f}s, "
                f"Test duration: {total_time:.1f}s"
            ),
            remediation="" if severity == SeverityLevel.INFO else (
                "Server struggled under load. Consider: "
                "load balancing, rate limiting, server scaling, or optimization."
            ),
            confidence=ConfidenceLevel.HIGH,
        )
        result.findings.append(finding)
