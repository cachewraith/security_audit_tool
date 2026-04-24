"""Tests for live website posture analysis."""

from app.checks.website_risk_check import WebsiteResponse, WebsiteRiskCheck
from app.config import Config
from app.models import Scope


class TestWebsiteRiskCheck:
    """Website risk checks should stay descriptive and non-destructive."""

    def test_analyze_response_flags_common_website_risks(self) -> None:
        """Header, cookie, CORS, and form issues should become findings."""
        check = WebsiteRiskCheck(Scope(allowed_hosts=["example.com"]), Config())
        result = check._create_result()

        response = WebsiteResponse(
            requested_url="https://example.com",
            final_url="https://example.com/login",
            status_code=200,
            headers={
                "server": "nginx/1.24.0",
                "set-cookie": "sessionid=abc123; Path=/",
                "access-control-allow-origin": "*",
                "access-control-allow-credentials": "true",
            },
            body=(
                "<html><body>"
                "<form action='http://example.com/login' method='get'>"
                "<input type='password' name='password' />"
                "</form>"
                "</body></html>"
            ),
        )

        check._analyze_response("example.com", response, result)

        titles = {finding.title for finding in result.findings}

        assert "Missing recommended website security headers" in titles
        assert "Permissive CORS policy detected" in titles
        assert "Server banner reveals stack version information" in titles
        assert "Session cookie protections are incomplete" in titles
        assert "Risky form handling detected" in titles

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
        check = WebsiteRiskCheck(scope, Config())

        seen_targets = []

        monkeypatch.setattr(
            check,
            "_fetch_url",
            lambda url: WebsiteResponse(
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
            lambda host, response, result: seen_targets.append(host),
        )

        check.run()

        assert seen_targets == ["https://example.com/login"]
