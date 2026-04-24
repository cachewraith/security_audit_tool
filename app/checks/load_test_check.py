"""Controlled load testing with staged concurrency and bounded duration."""

from __future__ import annotations

import random
import ssl
import statistics
import threading
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from .base import BaseCheck, CheckResult
from ..models import SeverityLevel, ConfidenceLevel, Category


class LoadTestCheck(BaseCheck):
    """Simulate bounded concurrent user traffic for resilience review."""

    check_id = "load_test"
    check_name = "Load Test"
    category = Category.NETWORK
    description = "Tests server capacity under controlled load"

    USER_AGENTS = (
        "SecurityAudit-LoadTest/2.0",
        "SecurityAudit-LoadTest/2.0 (browser-profile)",
        "SecurityAudit-LoadTest/2.0 (api-profile)",
    )
    STAGES = (
        ("baseline", 0.5),
        ("ramp", 1.0),
        ("peak", 1.5),
    )

    def run(self) -> CheckResult:
        """Run bounded load tests."""
        result = self._create_result()

        targets = self.scope.allowed_urls or self.scope.allowed_hosts
        configured_duration = max(
            self.config.check.active_check_min_duration_seconds,
            self.config.check.load_test_duration_seconds,
        )
        base_concurrency = max(1, self.config.check.load_test_concurrent)
        requests_per_user = max(1, self.config.check.load_test_requests_per_user)

        result.metadata["traffic_profile"] = (
            "randomized_safe" if self.config.check.randomize_safe_requests else "static_safe"
        )
        result.metadata["minimum_duration_seconds"] = configured_duration
        result.metadata["targets"] = []

        stages = self.STAGES if self.config.check.multi_stage_active_checks else (("baseline", 1.0),)
        for target in targets:
            self._load_test_host(
                target=target,
                result=result,
                stages=stages,
                base_concurrency=base_concurrency,
                requests_per_user=requests_per_user,
                total_duration=configured_duration,
            )

        return self._finish_result(result)

    def _load_test_host(
        self,
        target: str,
        result: CheckResult,
        stages: tuple[tuple[str, float], ...],
        base_concurrency: int,
        requests_per_user: int,
        total_duration: int,
    ) -> None:
        """Run staged load test against a host."""
        url = self._normalize_url(target)
        timeout = max(
            self.config.rate_limit.connection_timeout,
            self.config.rate_limit.read_timeout,
        )
        stage_duration = max(1.0, total_duration / max(1, len(stages)))
        all_response_times: list[float] = []
        all_errors: list[str] = []
        total_successful = 0
        total_failed = 0
        stage_summaries: list[dict[str, object]] = []
        overall_start = time.time()

        for stage_name, multiplier in stages:
            concurrency = max(1, round(base_concurrency * multiplier))
            stage_summary = self._run_stage(
                url=url,
                target=target,
                stage_name=stage_name,
                concurrency=concurrency,
                requests_per_user=requests_per_user,
                stage_duration=stage_duration,
                timeout=timeout,
            )
            stage_summaries.append(stage_summary)
            all_response_times.extend(stage_summary["response_times"])
            all_errors.extend(stage_summary["error_examples"])
            total_successful += stage_summary["successful_requests"]
            total_failed += stage_summary["failed_requests"]

        total_time = time.time() - overall_start
        total_requests = total_successful + total_failed
        success_rate = (total_successful / total_requests * 100) if total_requests > 0 else 0.0
        avg_response = statistics.mean(all_response_times) if all_response_times else 0.0
        p95_response = self._percentile(all_response_times, 95) if all_response_times else 0.0

        severity = SeverityLevel.INFO
        if success_rate < 50 or p95_response > 8.0:
            severity = SeverityLevel.CRITICAL
        elif success_rate < 80 or p95_response > 5.0:
            severity = SeverityLevel.HIGH
        elif avg_response > 3.0 or total_failed > 0:
            severity = SeverityLevel.MEDIUM

        result.metadata["targets"].append(
            {
                "target": target,
                "duration_seconds": round(total_time, 2),
                "stages": [
                    {key: value for key, value in stage.items() if key != "response_times" and key != "error_examples"}
                    for stage in stage_summaries
                ],
                "traffic_profile": result.metadata["traffic_profile"],
            }
        )

        finding = self._create_finding(
            title=f"Load Test Results: {target}",
            severity=severity,
            target=target,
            evidence=(
                f"Duration: {total_time:.1f}s, Total requests: {total_requests}, "
                f"Success: {total_successful}, Failed: {total_failed}, "
                f"Success rate: {success_rate:.1f}%, Avg response: {avg_response:.2f}s, "
                f"P95 response: {p95_response:.2f}s"
            ),
            remediation=(
                "Review queue depth, worker pool sizing, autoscaling thresholds, rate limiting, "
                "and dependency latency under sustained traffic."
                if severity != SeverityLevel.INFO
                else "The service maintained acceptable behavior throughout the staged load profile."
            ),
            confidence=ConfidenceLevel.HIGH,
            metadata={
                "stages": [
                    {key: value for key, value in stage.items() if key != "response_times" and key != "error_examples"}
                    for stage in stage_summaries
                ],
                "traffic_profile": result.metadata["traffic_profile"],
                "duration_seconds": round(total_time, 2),
                "success_rate": round(success_rate, 2),
            },
        )
        result.findings.append(finding)

        if total_failed:
            result.findings.append(
                self._create_finding(
                    title=f"Load Test Errors Observed: {target}",
                    severity=SeverityLevel.MEDIUM,
                    target=target,
                    evidence=(
                        f"Observed {total_failed} failed requests during staged load testing. "
                        f"Examples: {all_errors[:3]}"
                    ),
                    remediation=(
                        "Correlate the failing stage with server and upstream logs, then tune timeout, "
                        "connection pool, and backpressure behavior."
                    ),
                    confidence=ConfidenceLevel.MEDIUM,
                    metadata={
                        "error_examples": all_errors[:5],
                        "stages": [
                            {key: value for key, value in stage.items() if key != "response_times" and key != "error_examples"}
                            for stage in stage_summaries
                        ],
                    },
                )
            )

    def _run_stage(
        self,
        url: str,
        target: str,
        stage_name: str,
        concurrency: int,
        requests_per_user: int,
        stage_duration: float,
        timeout: float,
    ) -> dict[str, object]:
        """Execute one concurrency stage using worker threads."""
        deadline = time.time() + stage_duration
        lock = threading.Lock()
        results = {
            "successful_requests": 0,
            "failed_requests": 0,
            "response_times": [],
            "error_examples": [],
        }

        def make_request(user_id: int, request_index: int) -> None:
            request_url, headers = self._build_request_profile(url, target, stage_name, user_id, request_index)

            try:
                start = time.time()
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                req = urllib.request.Request(request_url, headers=headers, method="GET")
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as response:
                    _ = response.read()
                elapsed = time.time() - start
                with lock:
                    results["successful_requests"] += 1
                    results["response_times"].append(elapsed)
            except Exception as exc:
                with lock:
                    results["failed_requests"] += 1
                    if len(results["error_examples"]) < 10:
                        results["error_examples"].append(str(exc))

        def worker(user_id: int) -> None:
            request_index = 0
            while time.time() < deadline or request_index < requests_per_user:
                make_request(user_id, request_index)
                request_index += 1
                self._sleep_with_jitter(deadline)

        stage_start = time.time()
        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            for user_id in range(concurrency):
                executor.submit(worker, user_id)

        response_times = results["response_times"]
        return {
            "stage": stage_name,
            "concurrency": concurrency,
            "duration_seconds": round(time.time() - stage_start, 2),
            "successful_requests": results["successful_requests"],
            "failed_requests": results["failed_requests"],
            "avg_response_seconds": round(statistics.mean(response_times), 3) if response_times else None,
            "p95_response_seconds": round(self._percentile(response_times, 95), 3) if response_times else None,
            "response_times": response_times,
            "error_examples": list(results["error_examples"]),
        }

    def _build_request_profile(
        self,
        url: str,
        target: str,
        stage_name: str,
        user_id: int,
        request_index: int,
    ) -> tuple[str, dict[str, str]]:
        """Build a benign but varied request for the simulated user."""
        parsed = urllib.parse.urlsplit(url)
        base_query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        rng = random.Random(f"{target}:{stage_name}:{user_id}:{request_index}")

        if self.config.check.randomize_safe_requests:
            base_query.extend(
                [
                    ("sat_stage", stage_name),
                    ("sat_user", str(user_id)),
                    ("sat_request", str(request_index)),
                    ("locale", rng.choice(("en-US", "en-GB", "id-ID"))),
                ]
            )

        request_url = urllib.parse.urlunsplit(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path or "/",
                urllib.parse.urlencode(base_query),
                parsed.fragment,
            )
        )
        headers = {
            "User-Agent": rng.choice(self.USER_AGENTS),
            "Accept": "text/html,application/json,application/xhtml+xml;q=0.9,*/*;q=0.8",
            "Accept-Language": rng.choice(("en-US,en;q=0.9", "en-GB,en;q=0.8", "id-ID,id;q=0.9")),
            "Cache-Control": rng.choice(("no-cache", "max-age=0", "no-store")),
        }
        return request_url, headers

    def _sleep_with_jitter(self, deadline: float) -> None:
        """Apply small pacing between requests to emulate user think time."""
        if time.time() >= deadline:
            return
        pause = 0.03
        if self.config.check.randomize_safe_requests:
            pause = min(0.2, max(0.03, deadline - time.time(), 0.08))
        time.sleep(pause)

    def _normalize_url(self, target: str) -> str:
        """Normalize a host or URL into an HTTPS URL."""
        if target.startswith(("http://", "https://")):
            return target
        return f"https://{target}"

    def _percentile(self, values: list[float], percentile: int) -> float:
        """Return a basic percentile from a non-empty list."""
        if not values:
            return 0.0
        ordered = sorted(values)
        index = max(0, min(len(ordered) - 1, round((percentile / 100) * (len(ordered) - 1))))
        return ordered[index]
