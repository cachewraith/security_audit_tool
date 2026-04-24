"""Rule-based passive analyzer for website posture findings."""

from __future__ import annotations

import re
from collections.abc import Iterable

from ...models import ConfidenceLevel, SeverityLevel
from .models import WebsiteFindingSpec, WebsitePageAnalysis, WebsiteResponse
from .parsers import extract_forms, find_mixed_content_urls

SEVERITY_ORDER = {
    SeverityLevel.INFO: 0,
    SeverityLevel.LOW: 1,
    SeverityLevel.MEDIUM: 2,
    SeverityLevel.HIGH: 3,
    SeverityLevel.CRITICAL: 4,
}


class WebsiteRiskAnalyzer:
    """Evaluate passive website responses for meaningful exposure signals."""

    SECURITY_HEADERS = {
        "content-security-policy": SeverityLevel.MEDIUM,
        "strict-transport-security": SeverityLevel.MEDIUM,
        "x-content-type-options": SeverityLevel.LOW,
        "referrer-policy": SeverityLevel.LOW,
        "permissions-policy": SeverityLevel.LOW,
    }
    VERSION_DISCLOSURE_RE = re.compile(
        r"(apache|nginx|php|express|gunicorn|openresty|iis|tomcat)[/ ]\d",
        re.IGNORECASE,
    )
    SENSITIVE_COOKIE_NAMES = (
        "session",
        "sess",
        "auth",
        "token",
        "jwt",
        "sid",
        "remember",
    )
    AUTH_PATH_MARKERS = (
        "/login",
        "/signin",
        "/auth",
        "/account",
        "/session",
        "/admin",
        "/dashboard",
        "/password",
    )
    DIRECTORY_LISTING_MARKERS = (
        "<title>index of /",
        "<h1>index of /",
        "parent directory</a>",
    )
    DEBUG_DISCLOSURE_PATTERNS = (
        re.compile(r"traceback \(most recent call last\):", re.IGNORECASE),
        re.compile(r"exception in thread", re.IGNORECASE),
        re.compile(r"\bat [a-z0-9_$.]+\(.*:\d+\)", re.IGNORECASE),
        re.compile(r"django (?:version )?debug", re.IGNORECASE),
        re.compile(r"werkzeug debugger", re.IGNORECASE),
        re.compile(r"whoops, looks like something went wrong", re.IGNORECASE),
        re.compile(r"sql syntax.*mysql", re.IGNORECASE),
    )

    def analyze(self, response: WebsiteResponse) -> list[WebsiteFindingSpec]:
        """Return passive findings extracted from the supplied response."""
        if response.error and response.status_code == 0:
            return [
                WebsiteFindingSpec(
                    title="Website risk review could not connect",
                    severity=SeverityLevel.MEDIUM,
                    evidence=f"Connection failed for {response.requested_url}: {response.error}",
                    remediation=(
                        "Verify the URL is reachable from the scanner and accepts HTTP or HTTPS requests."
                    ),
                    confidence=ConfidenceLevel.MEDIUM,
                )
            ]

        analysis = WebsitePageAnalysis.from_response(response, extract_forms(response.body))
        findings: list[WebsiteFindingSpec] = []

        for rule in (
            self._check_transport_downgrade,
            self._check_missing_headers,
            self._check_clickjacking_controls,
            self._check_csp_policy,
            self._check_cors,
            self._check_server_banner,
            self._check_cookie_security,
            self._check_form_handling,
            self._check_mixed_content,
            self._check_sensitive_cache_controls,
            self._check_directory_listing,
            self._check_debug_disclosure,
        ):
            findings.extend(rule(analysis))

        return findings

    def _check_transport_downgrade(
        self,
        analysis: WebsitePageAnalysis,
    ) -> list[WebsiteFindingSpec]:
        response = analysis.response
        requested_https = response.requested_url.lower().startswith("https://")
        downgraded_to_http = analysis.final_scheme == "http"
        if not requested_https or not downgraded_to_http:
            return []

        return [
            WebsiteFindingSpec(
                title="HTTPS request downgraded to HTTP",
                severity=SeverityLevel.HIGH,
                evidence=f"Requested {response.requested_url} but final URL was {response.final_url}",
                remediation="Keep the full redirect chain on HTTPS and avoid redirecting secure traffic to HTTP.",
                confidence=ConfidenceLevel.CERTAIN,
                metadata={
                    "requested_url": response.requested_url,
                    "final_url": response.final_url,
                    "owasp_top_10": ["A02:2021-Cryptographic Failures", "A05:2021-Security Misconfiguration"],
                },
            )
        ]

    def _check_missing_headers(
        self,
        analysis: WebsitePageAnalysis,
    ) -> list[WebsiteFindingSpec]:
        missing: list[str] = []
        highest = SeverityLevel.INFO

        for header_name, severity in self.SECURITY_HEADERS.items():
            if header_name == "strict-transport-security" and not analysis.is_https:
                continue
            if header_name in analysis.response.headers:
                continue

            missing.append(header_name)
            if SEVERITY_ORDER[severity] > SEVERITY_ORDER[highest]:
                highest = severity

        if not missing:
            return []

        return [
            WebsiteFindingSpec(
                title="Missing recommended website security headers",
                severity=highest,
                evidence=f"Missing headers: {', '.join(missing)}",
                remediation=(
                    "Add baseline browser protections such as CSP, HSTS, "
                    "X-Content-Type-Options, Referrer-Policy, and Permissions-Policy."
                ),
                confidence=ConfidenceLevel.HIGH,
                metadata={
                    "missing_headers": missing,
                    "final_url": analysis.response.final_url,
                    "owasp_top_10": ["A05:2021-Security Misconfiguration"],
                },
            )
        ]

    def _check_clickjacking_controls(
        self,
        analysis: WebsitePageAnalysis,
    ) -> list[WebsiteFindingSpec]:
        headers = analysis.response.headers
        x_frame_options = headers.get("x-frame-options", "").lower()
        csp = headers.get("content-security-policy", "").lower()

        if x_frame_options in {"deny", "sameorigin"} or "frame-ancestors" in csp:
            return []

        return [
            WebsiteFindingSpec(
                title="Clickjacking protection is missing",
                severity=SeverityLevel.MEDIUM,
                evidence="Neither X-Frame-Options nor CSP frame-ancestors was present in the response.",
                remediation="Set X-Frame-Options or a CSP frame-ancestors directive to restrict framing.",
                confidence=ConfidenceLevel.HIGH,
                metadata={"owasp_top_10": ["A05:2021-Security Misconfiguration"]},
            )
        ]

    def _check_csp_policy(
        self,
        analysis: WebsitePageAnalysis,
    ) -> list[WebsiteFindingSpec]:
        csp = analysis.response.headers.get("content-security-policy", "")
        if not csp:
            return []

        lowered = csp.lower()
        issues: list[str] = []
        severity = SeverityLevel.LOW

        if "'unsafe-inline'" in lowered:
            issues.append("script execution allows 'unsafe-inline'")
            severity = SeverityLevel.HIGH
        if "'unsafe-eval'" in lowered:
            issues.append("script execution allows 'unsafe-eval'")
            severity = SeverityLevel.HIGH
        if "script-src *" in lowered or "default-src *" in lowered:
            issues.append("policy uses wildcard script sources")
            if SEVERITY_ORDER[SeverityLevel.MEDIUM] > SEVERITY_ORDER[severity]:
                severity = SeverityLevel.MEDIUM
        if "frame-ancestors *" in lowered:
            issues.append("frame-ancestors allows any origin")
            if SEVERITY_ORDER[SeverityLevel.MEDIUM] > SEVERITY_ORDER[severity]:
                severity = SeverityLevel.MEDIUM

        if not issues:
            return []

        return [
            WebsiteFindingSpec(
                title="Content Security Policy contains risky allowances",
                severity=severity,
                evidence=f"CSP issues: {', '.join(sorted(set(issues)))}",
                remediation="Tighten CSP directives and remove unsafe-inline, unsafe-eval, and overly broad wildcards.",
                confidence=ConfidenceLevel.HIGH,
                metadata={
                    "policy": csp[:250],
                    "owasp_top_10": ["A03:2021-Injection", "A05:2021-Security Misconfiguration"],
                },
            )
        ]

    def _check_cors(self, analysis: WebsitePageAnalysis) -> list[WebsiteFindingSpec]:
        headers = analysis.response.headers
        allow_origin = headers.get("access-control-allow-origin", "")
        allow_credentials = headers.get("access-control-allow-credentials", "")

        if allow_origin == "*" and allow_credentials.lower() == "true":
            severity = SeverityLevel.HIGH
            evidence = "CORS allows any origin while also allowing credentials."
        elif allow_origin == "*":
            severity = SeverityLevel.MEDIUM
            evidence = "CORS allows any origin."
        else:
            return []

        return [
            WebsiteFindingSpec(
                title="Permissive CORS policy detected",
                severity=severity,
                evidence=evidence,
                remediation="Restrict Access-Control-Allow-Origin to trusted origins and avoid wildcard policies.",
                confidence=ConfidenceLevel.CERTAIN,
                metadata={"owasp_top_10": ["A05:2021-Security Misconfiguration"]},
            )
        ]

    def _check_server_banner(
        self,
        analysis: WebsitePageAnalysis,
    ) -> list[WebsiteFindingSpec]:
        headers = analysis.response.headers
        combined = " | ".join(
            value
            for value in (
                headers.get("server", ""),
                headers.get("x-powered-by", ""),
                headers.get("x-aspnet-version", ""),
            )
            if value
        )

        if not combined or not self.VERSION_DISCLOSURE_RE.search(combined):
            return []

        return [
            WebsiteFindingSpec(
                title="Server banner reveals stack version information",
                severity=SeverityLevel.LOW,
                evidence=f"Observed header disclosure: {combined[:120]}",
                remediation="Reduce version disclosure in Server and X-Powered-By headers where possible.",
                confidence=ConfidenceLevel.HIGH,
                metadata={"owasp_top_10": ["A05:2021-Security Misconfiguration"]},
            )
        ]

    def _check_cookie_security(
        self,
        analysis: WebsitePageAnalysis,
    ) -> list[WebsiteFindingSpec]:
        if not analysis.response.cookies:
            return []

        issues: list[str] = []
        severity = SeverityLevel.LOW

        for cookie in self._iter_relevant_cookies(analysis.response.cookies):
            lowered = cookie.lower()

            if analysis.is_https and "secure" not in lowered:
                issues.append("sensitive cookie missing Secure")
                severity = SeverityLevel.HIGH
            if "httponly" not in lowered:
                issues.append("sensitive cookie missing HttpOnly")
                if SEVERITY_ORDER[SeverityLevel.MEDIUM] > SEVERITY_ORDER[severity]:
                    severity = SeverityLevel.MEDIUM
            if "samesite" not in lowered:
                issues.append("sensitive cookie missing SameSite")
                if SEVERITY_ORDER[SeverityLevel.MEDIUM] > SEVERITY_ORDER[severity]:
                    severity = SeverityLevel.MEDIUM

        if not issues:
            return []

        return [
            WebsiteFindingSpec(
                title="Session cookie protections are incomplete",
                severity=severity,
                evidence=f"Observed cookie flag issues: {', '.join(sorted(set(issues)))}",
                remediation="Set Secure, HttpOnly, and SameSite on authentication or session cookies.",
                confidence=ConfidenceLevel.HIGH,
                metadata={"owasp_top_10": ["A01:2021-Broken Access Control", "A07:2021-Identification and Authentication Failures"]},
            )
        ]

    def _iter_relevant_cookies(self, cookies: list[str]) -> Iterable[str]:
        """Return session-like cookies first, falling back to all cookies if needed."""
        sensitive = []
        for cookie in cookies:
            cookie_name = cookie.split("=", 1)[0].strip().lower()
            if any(marker in cookie_name for marker in self.SENSITIVE_COOKIE_NAMES):
                sensitive.append(cookie)
        return sensitive or cookies

    def _check_form_handling(
        self,
        analysis: WebsitePageAnalysis,
    ) -> list[WebsiteFindingSpec]:
        if not analysis.forms:
            return []

        issues: list[str] = []
        severity = SeverityLevel.MEDIUM

        for form in analysis.forms:
            action = form.action.strip().lower()
            method = form.method.lower()

            if form.has_password and method == "get":
                issues.append("password form submits with GET")
                severity = SeverityLevel.HIGH
            if action.startswith("http://") and analysis.is_https:
                issues.append("HTTPS page posts to HTTP action")
                severity = SeverityLevel.HIGH
            if method == "post" and (form.has_password or self._looks_sensitive_form(action)) and not form.has_csrf_token():
                issues.append("sensitive POST form missing obvious CSRF token")

        if not issues:
            return []

        confidence = ConfidenceLevel.HIGH if severity == SeverityLevel.HIGH else ConfidenceLevel.MEDIUM
        return [
            WebsiteFindingSpec(
                title="Risky form handling detected",
                severity=severity,
                evidence=f"Form issues: {', '.join(sorted(set(issues)))}",
                remediation=(
                    "Use POST for credential forms, keep submissions on HTTPS, "
                    "and include anti-CSRF protections on sensitive state-changing forms."
                ),
                confidence=confidence,
                metadata={"owasp_top_10": ["A01:2021-Broken Access Control", "A05:2021-Security Misconfiguration"]},
            )
        ]

    def _looks_sensitive_form(self, action: str) -> bool:
        """Return whether a form action appears to handle auth or account changes."""
        if not action:
            return False
        return any(marker in action for marker in self.AUTH_PATH_MARKERS)

    def _check_mixed_content(
        self,
        analysis: WebsitePageAnalysis,
    ) -> list[WebsiteFindingSpec]:
        if not analysis.is_https:
            return []

        mixed_urls = find_mixed_content_urls(analysis.response.body)
        if not mixed_urls:
            return []

        preview = ", ".join(mixed_urls[:3])
        return [
            WebsiteFindingSpec(
                title="Mixed content references detected on HTTPS page",
                severity=SeverityLevel.HIGH,
                evidence=f"HTTPS page references HTTP resources: {preview}",
                remediation="Serve all scripts, media, stylesheets, and form actions over HTTPS only.",
                confidence=ConfidenceLevel.HIGH,
                metadata={
                    "mixed_content_urls": mixed_urls[:10],
                    "owasp_top_10": ["A02:2021-Cryptographic Failures", "A05:2021-Security Misconfiguration"],
                },
            )
        ]

    def _check_sensitive_cache_controls(
        self,
        analysis: WebsitePageAnalysis,
    ) -> list[WebsiteFindingSpec]:
        if not self._is_sensitive_page(analysis):
            return []

        cache_control = analysis.response.headers.get("cache-control", "").lower()
        pragma = analysis.response.headers.get("pragma", "").lower()

        if any(token in cache_control for token in ("no-store", "private", "no-cache")) or "no-cache" in pragma:
            return []

        return [
            WebsiteFindingSpec(
                title="Sensitive page missing cache-control hardening",
                severity=SeverityLevel.MEDIUM,
                evidence=(
                    "Response appears to contain authentication or account-related content "
                    "without restrictive cache-control headers."
                ),
                remediation="Use Cache-Control: no-store (or at minimum private, no-cache) on sensitive pages.",
                confidence=ConfidenceLevel.MEDIUM,
                metadata={
                    "final_url": analysis.response.final_url,
                    "owasp_top_10": ["A02:2021-Cryptographic Failures", "A05:2021-Security Misconfiguration"],
                },
            )
        ]

    def _is_sensitive_page(self, analysis: WebsitePageAnalysis) -> bool:
        """Return whether the response likely contains auth or account-sensitive content."""
        if any(marker in analysis.final_path for marker in self.AUTH_PATH_MARKERS):
            return True
        return any(form.has_password for form in analysis.forms)

    def _check_directory_listing(
        self,
        analysis: WebsitePageAnalysis,
    ) -> list[WebsiteFindingSpec]:
        matched_markers = sum(
            marker in analysis.lower_body
            for marker in self.DIRECTORY_LISTING_MARKERS
        )
        if matched_markers < 2:
            return []

        return [
            WebsiteFindingSpec(
                title="Directory listing appears to be enabled",
                severity=SeverityLevel.MEDIUM,
                evidence="Page content matched common auto-index signatures such as 'Index of /'.",
                remediation="Disable directory listing or require authorization for directory browsing endpoints.",
                confidence=ConfidenceLevel.HIGH,
                metadata={"owasp_top_10": ["A01:2021-Broken Access Control", "A05:2021-Security Misconfiguration"]},
            )
        ]

    def _check_debug_disclosure(
        self,
        analysis: WebsitePageAnalysis,
    ) -> list[WebsiteFindingSpec]:
        matches = []
        for pattern in self.DEBUG_DISCLOSURE_PATTERNS:
            match = pattern.search(analysis.response.body)
            if match:
                matches.append(match.group(0))

        if not matches:
            return []

        severity = SeverityLevel.HIGH if analysis.response.status_code >= 500 else SeverityLevel.MEDIUM
        preview = ", ".join(sorted(set(matches))[:3])
        return [
            WebsiteFindingSpec(
                title="Debug or stack trace disclosure detected",
                severity=severity,
                evidence=f"Response body exposed debug markers: {preview}",
                remediation="Disable debug output in production and replace stack traces with generic error responses.",
                confidence=ConfidenceLevel.HIGH,
                metadata={
                    "status_code": analysis.response.status_code,
                    "owasp_top_10": ["A05:2021-Security Misconfiguration", "A09:2021-Security Logging and Monitoring Failures"],
                },
            )
        ]
