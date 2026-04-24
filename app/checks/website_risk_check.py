"""Live website posture checks for passive web exposure signals.

These checks intentionally stay non-destructive:
- They only make regular HTTP GET requests to in-scope hosts
- They inspect headers, redirects, cookies, and rendered HTML/forms
- They do not submit credentials, brute-force, or attempt exploitation
"""

from __future__ import annotations

from .base import BaseCheck, CheckResult
from .website_risk import WebsiteFetcher, WebsiteResponse, WebsiteRiskAnalyzer
from ..models import Category


class WebsiteRiskCheck(BaseCheck):
    """Check live website responses for common posture gaps."""

    check_id = "website_risk"
    check_name = "Website Risk Review"
    category = Category.WEBAPP_CONFIG

    def run(self) -> CheckResult:
        """Run live website posture checks for allowed hosts."""
        result = self._create_result()

        if not self.config.check.website_risk_check:
            return self._finish_result(result)

        targets = self.scope.allowed_urls or self.scope.allowed_hosts
        fetcher = WebsiteFetcher(self.config)
        analyzer = WebsiteRiskAnalyzer()

        for target in targets:
            if self._should_skip_target(target):
                continue

            for candidate_url in self._candidate_urls(target):
                response = self._fetch_url(fetcher, candidate_url)
                if response.status_code != 0 or target.startswith(("http://", "https://")):
                    break

            self._analyze_response(target, response, analyzer, result)

        return self._finish_result(result)

    def _normalize_url(self, host: str) -> str:
        """Normalize a host or URL into an HTTPS URL."""
        if host.startswith(("http://", "https://")):
            return host
        return f"https://{host}"

    def _candidate_urls(self, target: str) -> list[str]:
        """Return candidate URLs for a target, preferring explicit scope values."""
        if target.startswith(("http://", "https://")):
            return [target]
        normalized = self._normalize_url(target)
        return [normalized, f"http://{target}"]

    def _should_skip_target(self, target: str) -> bool:
        """Return whether a target cannot be safely treated as a single HTTP endpoint."""
        return "*" in target or ("/" in target and not target.startswith(("http://", "https://")))

    def _fetch_url(self, fetcher: WebsiteFetcher, url: str) -> WebsiteResponse:
        """Fetch a URL through the shared website fetcher."""
        return fetcher.fetch(url)

    def _analyze_response(
        self,
        host: str,
        response: WebsiteResponse,
        analyzer: WebsiteRiskAnalyzer,
        result: CheckResult,
    ) -> None:
        """Convert website posture observations into findings."""
        for finding in analyzer.analyze(response):
            result.findings.append(
                self._create_finding(
                    title=finding.title,
                    severity=finding.severity,
                    target=host,
                    evidence=finding.evidence,
                    remediation=finding.remediation,
                    confidence=finding.confidence,
                    references=finding.references,
                    metadata=finding.metadata,
                )
            )
