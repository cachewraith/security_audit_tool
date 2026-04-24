"""Live website posture checks for common configuration risks.

These checks intentionally stay non-destructive:
- They only make regular HTTP GET requests to in-scope hosts
- They inspect headers, redirects, cookies, and rendered HTML forms
- They do not submit credentials, brute-force, or attempt exploitation
"""

from __future__ import annotations

import re
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import urlparse

from .base import BaseCheck, CheckResult
from ..models import Category, ConfidenceLevel, SeverityLevel


@dataclass
class WebsiteResponse:
    """Normalized HTTP response data for website posture checks."""

    requested_url: str
    final_url: str
    status_code: int
    headers: dict[str, str]
    body: str
    error: str | None = None


class _FormParser(HTMLParser):
    """Small HTML parser for detecting risky form patterns."""

    def __init__(self) -> None:
        super().__init__()
        self.forms: list[dict[str, object]] = []
        self._current_form: dict[str, object] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_dict = {key.lower(): (value or "") for key, value in attrs}

        if tag.lower() == "form":
            self._current_form = {
                "action": attrs_dict.get("action", ""),
                "method": attrs_dict.get("method", "get").lower(),
                "has_password": False,
            }
            self.forms.append(self._current_form)
            return

        if tag.lower() == "input" and self._current_form is not None:
            if attrs_dict.get("type", "").lower() == "password":
                self._current_form["has_password"] = True

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form":
            self._current_form = None


class WebsiteRiskCheck(BaseCheck):
    """Check live website responses for common posture gaps."""

    check_id = "website_risk"
    check_name = "Website Risk Review"
    category = Category.WEBAPP_CONFIG

    SECURITY_HEADERS = {
        "content-security-policy": SeverityLevel.MEDIUM,
        "strict-transport-security": SeverityLevel.MEDIUM,
        "x-content-type-options": SeverityLevel.LOW,
        "referrer-policy": SeverityLevel.LOW,
        "permissions-policy": SeverityLevel.LOW,
    }

    VERSION_DISCLOSURE_RE = re.compile(
        r"(apache|nginx|php|express|gunicorn|openresty|iis)[/ ]\d",
        re.IGNORECASE,
    )
    SEVERITY_ORDER = {
        SeverityLevel.INFO: 0,
        SeverityLevel.LOW: 1,
        SeverityLevel.MEDIUM: 2,
        SeverityLevel.HIGH: 3,
        SeverityLevel.CRITICAL: 4,
    }

    def run(self) -> CheckResult:
        """Run live website posture checks for allowed hosts."""
        result = self._create_result()

        if not self.config.check.website_risk_check:
            return self._finish_result(result)

        targets = self.scope.allowed_urls or self.scope.allowed_hosts

        for target in targets:
            if "*" in target or "/" in target and not target.startswith(("http://", "https://")):
                continue

            normalized_target = self._normalize_url(target)
            response = self._fetch_url(normalized_target)
            self._analyze_response(normalized_target, response, result)

        return self._finish_result(result)

    def _normalize_url(self, host: str) -> str:
        """Normalize a host or URL into an HTTPS URL."""
        if host.startswith(("http://", "https://")):
            return host
        return f"https://{host}"

    def _fetch_url(self, url: str) -> WebsiteResponse:
        """Fetch a URL and return normalized response details."""
        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": "SecurityAudit-WebsiteReview/1.0",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            },
            method="GET",
        )

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            with urllib.request.urlopen(
                request,
                timeout=self.config.rate_limit.connection_timeout,
                context=ctx,
            ) as response:
                body = response.read().decode("utf-8", errors="ignore")
                headers = {key.lower(): value for key, value in response.headers.items()}
                return WebsiteResponse(
                    requested_url=url,
                    final_url=response.geturl(),
                    status_code=response.status,
                    headers=headers,
                    body=body,
                )
        except urllib.error.HTTPError as exc:
            try:
                body = exc.read().decode("utf-8", errors="ignore")
            except Exception:
                body = ""
            return WebsiteResponse(
                requested_url=url,
                final_url=exc.geturl(),
                status_code=exc.code,
                headers={key.lower(): value for key, value in exc.headers.items()},
                body=body,
                error=f"HTTP {exc.code}",
            )
        except Exception as exc:
            return WebsiteResponse(
                requested_url=url,
                final_url=url,
                status_code=0,
                headers={},
                body="",
                error=str(exc),
            )

    def _analyze_response(
        self,
        host: str,
        response: WebsiteResponse,
        result: CheckResult,
    ) -> None:
        """Convert website posture observations into findings."""
        if response.error and response.status_code == 0:
            result.findings.append(
                self._create_finding(
                    title="Website risk review could not connect",
                    severity=SeverityLevel.MEDIUM,
                    target=host,
                    evidence=f"Connection failed for {response.requested_url}: {response.error}",
                    remediation="Verify the URL is reachable from the scanner and accepts HTTPS requests.",
                    confidence=ConfidenceLevel.MEDIUM,
                )
            )
            return

        self._check_missing_headers(host, response, result)
        self._check_cors(host, response, result)
        self._check_server_banner(host, response, result)
        self._check_cookies(host, response, result)
        self._check_form_exposure(host, response, result)

    def _check_missing_headers(
        self,
        host: str,
        response: WebsiteResponse,
        result: CheckResult,
    ) -> None:
        missing = []
        highest = SeverityLevel.INFO

        for header_name, severity in self.SECURITY_HEADERS.items():
            if header_name == "strict-transport-security" and not response.final_url.startswith("https://"):
                continue
            if header_name not in response.headers:
                missing.append(header_name)
                if self.SEVERITY_ORDER[severity] > self.SEVERITY_ORDER[highest]:
                    highest = severity

        if missing:
            result.findings.append(
                self._create_finding(
                    title="Missing recommended website security headers",
                    severity=highest,
                    target=host,
                    evidence=f"Missing headers: {', '.join(missing)}",
                    remediation=(
                        "Add baseline browser protections such as CSP, HSTS, "
                        "X-Content-Type-Options, Referrer-Policy, and Permissions-Policy."
                    ),
                    confidence=ConfidenceLevel.HIGH,
                    metadata={"missing_headers": missing, "final_url": response.final_url},
                )
            )

    def _check_cors(
        self,
        host: str,
        response: WebsiteResponse,
        result: CheckResult,
    ) -> None:
        allow_origin = response.headers.get("access-control-allow-origin", "")
        allow_credentials = response.headers.get("access-control-allow-credentials", "")

        if allow_origin == "*" and allow_credentials.lower() == "true":
            severity = SeverityLevel.HIGH
            evidence = "CORS allows any origin while also allowing credentials."
        elif allow_origin == "*":
            severity = SeverityLevel.MEDIUM
            evidence = "CORS allows any origin."
        else:
            return

        result.findings.append(
            self._create_finding(
                title="Permissive CORS policy detected",
                severity=severity,
                target=host,
                evidence=evidence,
                remediation="Restrict Access-Control-Allow-Origin to trusted origins and avoid wildcard policies.",
                confidence=ConfidenceLevel.CERTAIN,
            )
        )

    def _check_server_banner(
        self,
        host: str,
        response: WebsiteResponse,
        result: CheckResult,
    ) -> None:
        server_header = response.headers.get("server", "")
        powered_by = response.headers.get("x-powered-by", "")
        combined = " | ".join(value for value in [server_header, powered_by] if value)

        if combined and self.VERSION_DISCLOSURE_RE.search(combined):
            result.findings.append(
                self._create_finding(
                    title="Server banner reveals stack version information",
                    severity=SeverityLevel.LOW,
                    target=host,
                    evidence=f"Observed header disclosure: {combined[:120]}",
                    remediation="Reduce version disclosure in Server and X-Powered-By headers where possible.",
                    confidence=ConfidenceLevel.HIGH,
                )
            )

    def _check_cookies(
        self,
        host: str,
        response: WebsiteResponse,
        result: CheckResult,
    ) -> None:
        raw_cookie_header = response.headers.get("set-cookie", "")
        if not raw_cookie_header:
            return

        cookies = [cookie.strip() for cookie in raw_cookie_header.split(",") if "=" in cookie]
        issues: list[str] = []

        for cookie in cookies:
            lowered = cookie.lower()
            if "secure" not in lowered and response.final_url.startswith("https://"):
                issues.append("cookie missing Secure")
            if "httponly" not in lowered:
                issues.append("cookie missing HttpOnly")
            if "samesite" not in lowered:
                issues.append("cookie missing SameSite")

        if issues:
            unique_issues = sorted(set(issues))
            result.findings.append(
                self._create_finding(
                    title="Session cookie protections are incomplete",
                    severity=SeverityLevel.MEDIUM,
                    target=host,
                    evidence=f"Observed cookie flag issues: {', '.join(unique_issues)}",
                    remediation="Set Secure, HttpOnly, and SameSite on authentication or session cookies.",
                    confidence=ConfidenceLevel.MEDIUM,
                )
            )

    def _check_form_exposure(
        self,
        host: str,
        response: WebsiteResponse,
        result: CheckResult,
    ) -> None:
        if "<form" not in response.body.lower():
            return

        parser = _FormParser()
        parser.feed(response.body)

        risky_forms = []
        final_scheme = urlparse(response.final_url).scheme.lower()

        for form in parser.forms:
            action = str(form["action"]).strip()
            method = str(form["method"]).lower()
            has_password = bool(form["has_password"])

            if has_password and method == "get":
                risky_forms.append("password form submits with GET")

            if action.startswith("http://") and final_scheme == "https":
                risky_forms.append("HTTPS page posts to HTTP action")

        if risky_forms:
            issues = sorted(set(risky_forms))
            result.findings.append(
                self._create_finding(
                    title="Risky form handling detected",
                    severity=SeverityLevel.HIGH,
                    target=host,
                    evidence=f"Form issues: {', '.join(issues)}",
                    remediation="Use POST for credential forms and keep form submission on HTTPS endpoints only.",
                    confidence=ConfidenceLevel.HIGH,
                )
            )
