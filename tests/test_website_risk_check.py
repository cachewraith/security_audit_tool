"""Tests for live website posture analysis."""

from app.checks.website_risk import WebsiteRiskAnalyzer
from app.checks.website_risk_check import WebsiteResponse, WebsiteRiskCheck
from app.config import Config
from app.models import Scope


class TestWebsiteRiskCheck:
    """Website risk checks should stay descriptive and non-destructive."""

    def test_analyze_response_flags_common_website_risks(self) -> None:
        """Header, cookie, CORS, and form issues should become findings."""
        check = WebsiteRiskCheck(Scope(allowed_hosts=["example.com"]), Config())
        result = check._create_result()
        analyzer = WebsiteRiskAnalyzer()

        response = WebsiteResponse(
            requested_url="https://example.com",
            final_url="https://example.com/login",
            status_code=200,
            headers={
                "server": "nginx/1.24.0",
                "access-control-allow-origin": "*",
                "access-control-allow-credentials": "true",
            },
            cookies=["sessionid=abc123; Path=/"],
            body=(
                "<html><body>"
                "<form action='http://example.com/login' method='get'>"
                "<input type='password' name='password' />"
                "</form>"
                "</body></html>"
            ),
        )

        check._analyze_response("example.com", response, analyzer, result)

        titles = {finding.title for finding in result.findings}

        assert "Missing recommended website security headers" in titles
        assert "Clickjacking protection is missing" in titles
        assert "Permissive CORS policy detected" in titles
        assert "Server banner reveals stack version information" in titles
        assert "Session cookie protections are incomplete" in titles
        assert "Risky form handling detected" in titles

    def test_analyze_response_flags_higher_signal_transport_and_disclosure_risks(self) -> None:
        """Transport downgrade, mixed content, and stack traces should be reported."""
        check = WebsiteRiskCheck(Scope(allowed_hosts=["example.com"]), Config())
        result = check._create_result()
        analyzer = WebsiteRiskAnalyzer()

        response = WebsiteResponse(
            requested_url="https://example.com",
            final_url="http://example.com/login",
            status_code=500,
            headers={},
            body=(
                "<html><head><title>Error</title></head><body>"
                "<script src='http://cdn.example.com/app.js'></script>"
                "Traceback (most recent call last):"
                "</body></html>"
            ),
        )

        check._analyze_response("example.com", response, analyzer, result)

        titles = {finding.title for finding in result.findings}

        assert "HTTPS request downgraded to HTTP" in titles
        assert "Mixed content references detected on HTTPS page" not in titles
        assert "Debug or stack trace disclosure detected" in titles

    def test_analyzer_flags_mixed_content_on_https_pages(self) -> None:
        """HTTPS pages with HTTP subresources should produce a high-severity finding."""
        analyzer = WebsiteRiskAnalyzer()
        response = WebsiteResponse(
            requested_url="https://example.com",
            final_url="https://example.com/app",
            status_code=200,
            headers={"content-security-policy": "default-src 'self'"},
            body="<script src='http://cdn.example.com/app.js'></script>",
        )

        findings = analyzer.analyze(response)

        assert any(
            finding.title == "Mixed content references detected on HTTPS page"
            for finding in findings
        )

    def test_normalize_url_keeps_explicit_scheme(self) -> None:
        """Existing schemes should be preserved during normalization."""
        check = WebsiteRiskCheck(Scope(), Config())

        assert check._normalize_url("http://example.com") == "http://example.com"
        assert check._normalize_url("https://example.com") == "https://example.com"
        assert check._normalize_url("example.com") == "https://example.com"

    def test_run_prefers_explicit_urls_over_hosts(self, monkeypatch) -> None:
        """HTTP-based checks should use the exact approved URL when available."""
        scope = Scope(
            allowed_hosts=["example.com"],
            allowed_urls=["https://example.com/login"],
        )
        config = Config()
        config.check.website_risk_check = True
        check = WebsiteRiskCheck(scope, config)

        seen_targets = []

        monkeypatch.setattr(
            check,
            "_fetch_url",
            lambda fetcher, url: WebsiteResponse(
                requested_url=url,
                final_url=url,
                status_code=200,
                headers={},
                body="",
            ),
        )
        monkeypatch.setattr(
            check,
            "_analyze_response",
            lambda host, response, analyzer, result: seen_targets.append(host),
        )

        check.run()

        assert seen_targets == ["https://example.com/login"]

    def test_run_falls_back_to_http_when_https_connection_fails(self, monkeypatch) -> None:
        """Host-only targets should try HTTP if HTTPS is unreachable."""
        config = Config()
        config.check.website_risk_check = True
        check = WebsiteRiskCheck(Scope(allowed_hosts=["example.com"]), config)

        seen_urls = []

        def fake_fetch(fetcher, url):
            seen_urls.append(url)
            if url.startswith("https://"):
                return WebsiteResponse(
                    requested_url=url,
                    final_url=url,
                    status_code=0,
                    headers={},
                    body="",
                    error="connection refused",
                )
            return WebsiteResponse(
                requested_url=url,
                final_url=url,
                status_code=200,
                headers={},
                body="",
            )

        monkeypatch.setattr(check, "_fetch_url", fake_fetch)
        monkeypatch.setattr(check, "_analyze_response", lambda *args, **kwargs: None)

        check.run()

        assert seen_urls == ["https://example.com", "http://example.com"]
