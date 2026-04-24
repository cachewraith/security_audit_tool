"""Performance testing with staged, benign traffic sampling."""

from __future__ import annotations

import random
import statistics
import time
import urllib.parse
import urllib.request
import ssl

from .base import BaseCheck, CheckResult
from ..models import SeverityLevel, ConfidenceLevel, Category


class PerformanceCheck(BaseCheck):
    """Measure responsiveness with a longer-running staged request profile."""

    check_id = "performance"
    check_name = "Performance Test"
    category = Category.NETWORK
    description = "Tests website performance and response times"

    USER_AGENTS = (
        "SecurityAudit-PerformanceTest/2.0",
        "SecurityAudit-PerformanceTest/2.0 (mobile-profile)",
        "SecurityAudit-PerformanceTest/2.0 (api-profile)",
    )
    ACCEPT_LANGUAGES = ("en-US,en;q=0.9", "en-GB,en;q=0.8", "id-ID,id;q=0.9,en;q=0.7")
    CACHE_POLICIES = ("no-cache", "max-age=0", "no-store")
    STAGES = ("warmup", "baseline", "sustained")

    def run(self) -> CheckResult:
        """Run performance tests."""
        result = self._create_result()

        targets = self.scope.allowed_urls or self.scope.allowed_hosts
        stage_names = self.STAGES if self.config.check.multi_stage_active_checks else ("baseline",)
        minimum_duration = max(1, self.config.check.active_check_min_duration_seconds)

        result.metadata["stage_names"] = list(stage_names)
        result.metadata["minimum_duration_seconds"] = minimum_duration
        result.metadata["traffic_profile"] = (
            "randomized_safe" if self.config.check.randomize_safe_requests else "static_safe"
        )
        result.metadata["targets"] = []

        for target in targets:
            self._test_host_performance(
                target=target,
                result=result,
                stage_names=stage_names,
                minimum_duration=minimum_duration,
            )

        return self._finish_result(result)

    def _test_host_performance(
        self,
        target: str,
        result: CheckResult,
        stage_names: tuple[str, ...],
        minimum_duration: int,
    ) -> None:
        """Test performance for a single host or URL."""
        url = self._normalize_url(target)
        timeout = max(
            self.config.rate_limit.connection_timeout,
            self.config.rate_limit.read_timeout,
        )
        samples_per_stage = max(1, self.config.check.performance_samples_per_stage)
        stage_duration = max(1.0, minimum_duration / max(1, len(stage_names)))

        response_times: list[float] = []
        errors: list[str] = []
        stage_summaries: list[dict[str, object]] = []
        overall_start = time.time()

        for stage_name in stage_names:
            stage_summary = self._run_stage(
                url=url,
                target=target,
                stage_name=stage_name,
                timeout=timeout,
                stage_duration=stage_duration,
                samples_per_stage=samples_per_stage,
                response_times=response_times,
                errors=errors,
            )
            stage_summaries.append(stage_summary)

        total_duration = time.time() - overall_start
        target_summary = {
            "target": target,
            "duration_seconds": round(total_duration, 2),
            "stages": stage_summaries,
            "errors_count": len(errors),
        }
        result.metadata["targets"].append(target_summary)

        if response_times:
            avg_time = statistics.mean(response_times)
            p95_time = self._percentile(response_times, 95)
            max_time = max(response_times)
            min_time = min(response_times)

            severity = SeverityLevel.INFO
            if avg_time > 5.0 or p95_time > 7.0:
                severity = SeverityLevel.HIGH
            elif avg_time > 2.0 or p95_time > 4.0:
                severity = SeverityLevel.MEDIUM
            elif avg_time > 1.0 or p95_time > 2.0:
                severity = SeverityLevel.LOW

            finding = self._create_finding(
                title=f"Performance Test: {target}",
                severity=severity,
                target=target,
                evidence=(
                    f"Duration: {total_duration:.1f}s, Samples: {len(response_times)}, "
                    f"Avg: {avg_time:.2f}s, P95: {p95_time:.2f}s, "
                    f"Min: {min_time:.2f}s, Max: {max_time:.2f}s"
                ),
                remediation=(
                    "Optimize response time under sustained usage. Review caching, database latency, "
                    "pool sizing, upstream dependencies, and timeout thresholds."
                    if severity != SeverityLevel.INFO
                    else "Performance remained within the configured thresholds."
                ),
                confidence=ConfidenceLevel.HIGH,
                metadata={
                    "stages": stage_summaries,
                    "traffic_profile": result.metadata["traffic_profile"],
                    "sample_count": len(response_times),
                    "duration_seconds": round(total_duration, 2),
                },
            )
            result.findings.append(finding)

        if errors:
            finding = self._create_finding(
                title=f"Connection Errors During Performance Test: {target}",
                severity=SeverityLevel.MEDIUM,
                target=target,
                evidence=(
                    f"Observed {len(errors)} request errors during staged sampling. "
                    f"Examples: {errors[:2]}"
                ),
                remediation=(
                    "Review ingress stability, upstream dependencies, and timeout handling. "
                    "Correlate the failing stage with server logs to isolate bottlenecks."
                ),
                confidence=ConfidenceLevel.MEDIUM,
                metadata={
                    "stages": stage_summaries,
                    "error_examples": errors[:5],
                },
            )
            result.findings.append(finding)

    def _run_stage(
        self,
        url: str,
        target: str,
        stage_name: str,
        timeout: float,
        stage_duration: float,
        samples_per_stage: int,
        response_times: list[float],
        errors: list[str],
    ) -> dict[str, object]:
        """Run a single performance stage until both time and sample goals are met."""
        stage_start = time.time()
        stage_deadline = stage_start + stage_duration
        stage_times: list[float] = []
        stage_errors: list[str] = []
        request_index = 0

        while time.time() < stage_deadline or request_index < samples_per_stage:
            request_url, headers = self._build_request_profile(url, target, stage_name, request_index)

            try:
                start = time.time()
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

                req = urllib.request.Request(request_url, headers=headers, method="GET")
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as response:
                    _ = response.read()

                elapsed = time.time() - start
                response_times.append(elapsed)
                stage_times.append(elapsed)
            except Exception as exc:
                message = str(exc)
                errors.append(message)
                stage_errors.append(message)

            request_index += 1
            self._sleep_with_jitter(stage_deadline)

        return {
            "stage": stage_name,
            "duration_seconds": round(time.time() - stage_start, 2),
            "requests": request_index,
            "successful_requests": len(stage_times),
            "errors": len(stage_errors),
            "avg_response_seconds": round(statistics.mean(stage_times), 3) if stage_times else None,
            "p95_response_seconds": round(self._percentile(stage_times, 95), 3) if stage_times else None,
        }

    def _build_request_profile(
        self,
        url: str,
        target: str,
        stage_name: str,
        request_index: int,
    ) -> tuple[str, dict[str, str]]:
        """Build a benign but varied request profile."""
        parsed = urllib.parse.urlsplit(url)
        base_query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        rng = random.Random(f"{target}:{stage_name}:{request_index}")

        if self.config.check.randomize_safe_requests:
            base_query.extend(
                [
                    ("sat_stage", stage_name),
                    ("sat_request", str(request_index)),
                    ("locale", rng.choice(("en-US", "en-GB", "id-ID"))),
                    ("view", rng.choice(("summary", "detail"))),
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
            "Accept-Language": rng.choice(self.ACCEPT_LANGUAGES),
            "Cache-Control": rng.choice(self.CACHE_POLICIES),
        }
        return request_url, headers

    def _sleep_with_jitter(self, deadline: float) -> None:
        """Apply a small client think time between benign requests."""
        if time.time() >= deadline:
            return
        pause = 0.05
        if self.config.check.randomize_safe_requests:
            pause = min(0.35, max(0.05, deadline - time.time(), 0.12))
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
